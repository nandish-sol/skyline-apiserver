# Copyright 2025-2026 Xloud Technologies Pvt Ltd
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

"""
ASGI middleware that blocks mutating Skyline management routes when
the license is expired.

Note: OpenStack CRUD (Nova/Cinder/Neutron create/delete) goes through
nginx, not through this API server. The frontend is the primary
enforcement for those operations. This middleware protects Skyline-
specific routes (settings, RBAC, policy, etc.).
"""

from __future__ import annotations

import json
import logging

from starlette.types import ASGIApp, Receive, Scope, Send

LOG = logging.getLogger(__name__)

# Paths that always bypass the license check
ALWAYS_ALLOWED_PREFIXES = (
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/profile",
    "/api/v1/switch_project",
    "/api/v1/license",
    "/api/v1/contrib",
    "/api/v1/sso",
    "/docs",
    "/openapi.json",
)


def _deny_json(detail: str) -> bytes:
    return json.dumps({
        "error": "LICENSE_EXPIRED",
        "message": detail,
        "restricted_mode": True,
    }).encode("utf-8")


class LicenseMiddleware:
    """ASGI middleware — outermost wrapper; runs before RBAC."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        LOG.info("License enforcement middleware initialized")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")

        # Allow all read-only methods
        if method in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        # Allow whitelisted paths
        for prefix in ALWAYS_ALLOWED_PREFIXES:
            if path.startswith(prefix):
                await self.app(scope, receive, send)
                return

        # Check license state (cached, fast)
        try:
            from skyline_apiserver.core.license import ComplianceValidator

            state = await ComplianceValidator.get_compliance_state()
        except Exception as exc:
            LOG.warning("License check failed in middleware: %s — allowing request", exc)
            await self.app(scope, receive, send)
            return

        is_expired = (
            state.get("expired", False)
            or state.get("days_remaining", 999) <= 0
            or state.get("status") == "expired"
        )

        if is_expired:
            LOG.warning("BLOCKED (license expired): %s %s", method, path)
            body = _deny_json(
                "License expired. This operation is not available. "
                "Please contact your administrator to renew the license."
            )
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
            return

        await self.app(scope, receive, send)
