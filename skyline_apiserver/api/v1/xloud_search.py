# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Global search API — search across OpenStack resources."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Query
from starlette.concurrency import run_in_threadpool

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.client import utils
from skyline_apiserver.client.utils import generate_session, get_system_session
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants
from skyline_apiserver.utils.roles import is_system_admin

router = APIRouter()

MAX_RESULTS_PER_TYPE = 5

# Simple in-memory rate limiter: {ip: [timestamps]}
_rate_limit_store: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_MAX = 20
RATE_LIMIT_WINDOW = 60


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    timestamps = _rate_limit_store[client_ip]
    # Prune old entries
    _rate_limit_store[client_ip] = [t for t in timestamps if t > window_start]
    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limit_store[client_ip].append(now)
    return True


def _match(name: str, query_lower: str) -> bool:
    """Case-insensitive substring match."""
    return query_lower in (name or "").lower()


async def _search_servers(
    nc: Any, query: str, is_admin: bool
) -> List[Dict[str, Any]]:
    """Search Nova servers by name."""
    results = []
    try:
        search_opts: Dict[str, Any] = {"name": query}
        if is_admin:
            search_opts["all_tenants"] = True
        servers = await run_in_threadpool(
            nc.servers.list, search_opts=search_opts
        )
        for s in servers[:MAX_RESULTS_PER_TYPE]:
            results.append({
                "type": "instance",
                "id": s.id,
                "name": s.name,
                "status": getattr(s, "status", ""),
                "url": f"/compute/instance/detail/{s.id}",
            })
    except Exception:
        LOG.debug("Global search: instances query failed", exc_info=True)
    return results


async def _search_volumes(
    cc: Any, query: str, is_admin: bool
) -> List[Dict[str, Any]]:
    """Search Cinder volumes by name."""
    results = []
    try:
        search_opts: Dict[str, Any] = {"name": query}
        if is_admin:
            search_opts["all_tenants"] = True
        volumes = await run_in_threadpool(
            cc.volumes.list, search_opts=search_opts
        )
        for v in volumes[:MAX_RESULTS_PER_TYPE]:
            results.append({
                "type": "volume",
                "id": v.id,
                "name": getattr(v, "name", None) or v.id,
                "status": getattr(v, "status", ""),
                "url": f"/storage/volume/detail/{v.id}",
            })
    except Exception:
        LOG.debug("Global search: volumes query failed", exc_info=True)
    return results


async def _search_networks(
    neutron_c: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Neutron networks by name."""
    results = []
    try:
        resp = await run_in_threadpool(neutron_c.list_networks)
        networks = resp.get("networks", [])
        count = 0
        for n in networks:
            name = n.get("name", "") or n.get("id", "")
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "network",
                    "id": n["id"],
                    "name": name,
                    "status": n.get("status", ""),
                    "url": f"/network/networks/detail/{n['id']}",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: networks query failed", exc_info=True)
    return results


async def _search_images(
    gc: Any, query: str
) -> List[Dict[str, Any]]:
    """Search Glance images by name."""
    results = []
    try:
        images = await run_in_threadpool(
            gc.images.list, filters={"name": query}
        )
        count = 0
        for img in images:
            if count >= MAX_RESULTS_PER_TYPE:
                break
            name = img.get("name", "") or img.get("id", "")
            results.append({
                "type": "image",
                "id": img["id"],
                "name": name,
                "status": img.get("status", ""),
                "url": f"/compute/image/detail/{img['id']}",
            })
            count += 1
    except Exception:
        LOG.debug("Global search: images query failed", exc_info=True)
    return results


async def _search_security_groups(
    neutron_c: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Neutron security groups by name."""
    results = []
    try:
        resp = await run_in_threadpool(neutron_c.list_security_groups)
        sgs = resp.get("security_groups", [])
        count = 0
        for sg in sgs:
            name = sg.get("name", "")
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "security_group",
                    "id": sg["id"],
                    "name": name,
                    "status": "",
                    "url": f"/network/security-group/detail/{sg['id']}",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: security groups query failed", exc_info=True)
    return results


async def _search_routers(
    neutron_c: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Neutron routers by name."""
    results = []
    try:
        resp = await run_in_threadpool(neutron_c.list_routers)
        routers = resp.get("routers", [])
        count = 0
        for r in routers:
            name = r.get("name", "") or r.get("id", "")
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "router",
                    "id": r["id"],
                    "name": name,
                    "status": r.get("status", ""),
                    "url": f"/network/router/detail/{r['id']}",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: routers query failed", exc_info=True)
    return results


async def _search_floating_ips(
    neutron_c: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Neutron floating IPs by address."""
    results = []
    try:
        resp = await run_in_threadpool(neutron_c.list_floatingips)
        fips = resp.get("floatingips", [])
        count = 0
        for fip in fips:
            ip_addr = fip.get("floating_ip_address", "")
            if _match(ip_addr, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "floating_ip",
                    "id": fip["id"],
                    "name": ip_addr,
                    "status": fip.get("status", ""),
                    "url": "/network/floatingip",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: floating IPs query failed", exc_info=True)
    return results


async def _search_keypairs(
    nc: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Nova key pairs by name."""
    results = []
    try:
        keypairs = await run_in_threadpool(nc.keypairs.list)
        count = 0
        for kp in keypairs:
            name = getattr(kp, "name", "") or ""
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "keypair",
                    "id": name,
                    "name": name,
                    "status": "",
                    "url": "/compute/keypair",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: key pairs query failed", exc_info=True)
    return results


async def _search_flavors(
    nc: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Nova flavors by name (admin only)."""
    results = []
    try:
        flavors = await run_in_threadpool(nc.flavors.list, is_public=True)
        count = 0
        for f in flavors:
            name = getattr(f, "name", "") or ""
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "flavor",
                    "id": f.id,
                    "name": name,
                    "status": f"{f.vcpus} vCPU / {f.ram} MB",
                    "url": "/compute/flavor-admin",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: flavors query failed", exc_info=True)
    return results


async def _search_projects(
    kc: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Keystone projects by name (admin only)."""
    results = []
    try:
        projects = await run_in_threadpool(kc.projects.list)
        count = 0
        for p in projects:
            name = getattr(p, "name", "") or ""
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "project",
                    "id": p.id,
                    "name": name,
                    "status": "enabled" if getattr(p, "enabled", False) else "disabled",
                    "url": f"/identity/project-admin/detail/{p.id}",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: projects query failed", exc_info=True)
    return results


async def _search_users(
    kc: Any, query_lower: str
) -> List[Dict[str, Any]]:
    """Search Keystone users by name (admin only)."""
    results = []
    try:
        users = await run_in_threadpool(kc.users.list)
        count = 0
        for u in users:
            name = getattr(u, "name", "") or ""
            if _match(name, query_lower) and count < MAX_RESULTS_PER_TYPE:
                results.append({
                    "type": "user",
                    "id": u.id,
                    "name": name,
                    "status": "enabled" if getattr(u, "enabled", False) else "disabled",
                    "url": f"/identity/user-admin/detail/{u.id}",
                })
                count += 1
    except Exception:
        LOG.debug("Global search: users query failed", exc_info=True)
    return results


@router.get(
    "/extension/xloud-search",
    description="Global search across OpenStack resources",
)
async def xloud_search(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
    q: str = Query("", description="Search query string"),
):
    query = (q or "").strip()
    if len(query) < 2:
        return {"results": []}

    # Rate limiting
    # Use profile user id as the rate limit key
    rate_key = profile.user.id if profile and profile.user else "anonymous"
    if not _check_rate_limit(rate_key):
        return {"results": [], "error": "Rate limit exceeded. Try again later."}

    admin = is_system_admin(profile)
    query_lower = query.lower()

    # Build sessions and clients
    session = await generate_session(profile=profile)
    rid = x_openstack_request_id

    nc = await utils.nova_client(
        region=profile.region,
        session=session,
        global_request_id=rid,
    )
    cc = await utils.cinder_client(
        region=profile.region,
        session=session,
        global_request_id=rid,
    )
    neutron_c = await utils.neutron_client(
        session=session,
        region=profile.region,
        global_request_id=rid,
    )
    gc = await utils.glance_client(
        session=session,
        region=profile.region,
        global_request_id=rid,
    )

    # Run all searches concurrently
    tasks = [
        _search_servers(nc, query, admin),
        _search_volumes(cc, query, admin),
        _search_networks(neutron_c, query_lower),
        _search_images(gc, query),
        _search_security_groups(neutron_c, query_lower),
        _search_routers(neutron_c, query_lower),
        _search_floating_ips(neutron_c, query_lower),
        _search_keypairs(nc, query_lower),
    ]

    if admin:
        kc = await utils.keystone_client(
            session=session,
            region=profile.region,
            global_request_id=rid,
        )
        tasks.extend([
            _search_flavors(nc, query_lower),
            _search_projects(kc, query_lower),
            _search_users(kc, query_lower),
        ])

    all_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: List[Dict[str, Any]] = []
    for r in all_results:
        if isinstance(r, list):
            results.extend(r)
        elif isinstance(r, Exception):
            LOG.debug("Global search task failed: %s", r)

    return {"results": results}
