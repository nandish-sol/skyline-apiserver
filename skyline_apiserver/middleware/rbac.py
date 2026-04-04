# Copyright 2021 99cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
from typing import Optional, Set

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from skyline_apiserver.log import LOG

SKIP_PREFIXES = (
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/profile",
    "/api/v1/switch_project",
    "/api/v1/rbac/",
    "/api/v1/policies",
    "/api/v1/setting",
    "/api/v1/settings",
    "/api/v1/query",
    "/api/v1/query_range",
    "/api/v1/sso",
    "/api/v1/contrib/",
    "/api/v1/license",
    "/docs",
    "/openapi.json",
)

EXTENSION_SERVICE_MAP = {
    "volumes": "cinder",
    "volume_snapshots": "cinder",
    "servers": "nova",
    "recycle_servers": "nova",
    "compute-services": "nova",
    "ports": "neutron",
}

# Maps extension resource to the specific permission required.
# If a resource is listed here, the user must have this exact
# permission (not just any service-level permission).
EXTENSION_ACTION_MAP = {
    "volumes": "cinder:volume:get_all",
    "volume_snapshots": "cinder:volume:get_all_snapshots",
    "servers": "nova:os_compute_api:servers:index",
    "recycle_servers": "nova:os_compute_api:servers:index",
    "compute-services": "nova:os_compute_api:os-services:list",
    "ports": "neutron:get_port",
}

def _get_all_rbac_services():
    """Lazy import to avoid circular imports at module load time."""
    from skyline_apiserver.api.v1.rbac import ALL_RBAC_SERVICES
    return ALL_RBAC_SERVICES


def _deny_json(detail: str) -> bytes:
    return json.dumps({
        "error": {"message": detail, "code": 403}
    }).encode("utf-8")


def _extract_extension_service(path: str) -> Optional[str]:
    prefix = "/api/v1/extension/"
    if not path.startswith(prefix):
        return None
    remainder = path[len(prefix):]
    resource = remainder.split("/")[0].split("?")[0]
    return EXTENSION_SERVICE_MAP.get(resource)


def _extract_resource_name(path: str) -> Optional[str]:
    prefix = "/api/v1/extension/"
    if not path.startswith(prefix):
        return None
    remainder = path[len(prefix):]
    return remainder.split("/")[0].split("?")[0]


async def _parse_roles_from_cookie(request: Request) -> Optional[Set[str]]:
    from skyline_apiserver.config import CONF
    from skyline_apiserver.core.security import (
        generate_profile_by_token,
        parse_access_token,
    )

    cookie_header = request.headers.get("cookie", "")
    session_name = CONF.default.session_name
    session_token = None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith(f"{session_name}="):
            session_token = part[len(session_name) + 1:]
            break
    if not session_token:
        return None

    # Check roles cache first (avoids Keystone API call per request)
    from skyline_apiserver.api.v1.rbac import _get_cached_roles, _set_cached_roles
    cached = _get_cached_roles(session_token)
    if cached is not None:
        return cached

    token = parse_access_token(session_token)
    profile = await generate_profile_by_token(token)
    roles = {
        r.name if hasattr(r, "name") else r.get("name", "")
        for r in (profile.roles or [])
    }
    _set_cached_roles(session_token, roles)
    return roles


async def _deny(send: Send, service_name: str, path: str, roles: Set[str]) -> None:
    LOG.info(
        "RBAC denied: service=%s path=%s roles=%s",
        service_name, path, roles,
    )
    body = _deny_json("Permission denied by RBAC policy")
    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [
            [b"content-type", b"application/json"],
            [b"content-length", str(len(body)).encode()],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


class RBACMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check enable_rbac at request time (config loaded in on_startup)
        try:
            from skyline_apiserver.config import CONF
            if not getattr(CONF.openstack, "enable_rbac", False):
                await self.app(scope, receive, send)
                return
        except Exception:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        if method in ("HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        for prefix in SKIP_PREFIXES:
            if path.startswith(prefix):
                await self.app(scope, receive, send)
                return

        service_name = _extract_extension_service(path)
        if not service_name or service_name not in _get_all_rbac_services():
            await self.app(scope, receive, send)
            return

        try:
            request = Request(scope, receive)
            roles = await _parse_roles_from_cookie(request)
        except Exception:
            await self.app(scope, receive, send)
            return

        if not roles:
            await self.app(scope, receive, send)
            return

        # Admin role bypass: admin users are not subject to RBAC restrictions
        if "admin" in roles:
            await self.app(scope, receive, send)
            return

        try:
            from skyline_apiserver.api.v1.rbac import (
                _get_cached_permissions,
                _get_enabled_services,
            )
            permissions = await _get_cached_permissions()
            enabled = await _get_enabled_services()
        except Exception:
            LOG.warning("RBAC middleware: failed to load permissions")
            await self.app(scope, receive, send)
            return

        if service_name not in enabled:
            await self.app(scope, receive, send)
            return

        has_custom = any(role in permissions for role in roles)
        if not has_custom:
            await self.app(scope, receive, send)
            return

        # Action-level check: use EXTENSION_ACTION_MAP for granular enforcement
        resource = _extract_resource_name(path)
        required_action = EXTENSION_ACTION_MAP.get(resource)

        if required_action:
            # Check if any role has the specific permission
            has_action = False
            for role in roles:
                role_perms = permissions.get(role, {})
                if role_perms.get(required_action, False):
                    has_action = True
                    break
            if not has_action:
                await _deny(send, service_name, path, roles)
                return
        else:
            # No action map entry — fall back to service-level check
            role_has_service_access = False
            for role in roles:
                role_perms = permissions.get(role, {})
                if any(
                    k.startswith(f"{service_name}:") and v
                    for k, v in role_perms.items()
                ):
                    role_has_service_access = True
                    break
            if not role_has_service_access:
                await _deny(send, service_name, path, roles)
                return

        await self.app(scope, receive, send)
