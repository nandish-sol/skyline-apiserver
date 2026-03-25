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

"""Activity Log — aggregated instance-actions across all servers."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Query
from starlette.concurrency import run_in_threadpool

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.client import utils
from skyline_apiserver.client.utils import generate_session
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants
from skyline_apiserver.utils.roles import is_system_admin

router = APIRouter()

# Maximum instances to scan for actions in a single request
MAX_INSTANCES = 200


async def _list_servers(nc: Any, is_admin: bool, project_id: Optional[str] = None) -> list:
    """List servers — all tenants for admin, project-scoped otherwise."""
    search_opts: Dict[str, Any] = {}
    if is_admin:
        search_opts["all_tenants"] = True
    elif project_id:
        search_opts["project_id"] = project_id
    return await run_in_threadpool(
        nc.servers.list,
        search_opts=search_opts,
        limit=MAX_INSTANCES,
    )


async def _get_instance_actions(nc: Any, server_id: str) -> list:
    """Fetch os-instance-actions for a single server."""
    try:
        actions = await run_in_threadpool(
            nc.instance_action.list, server_id
        )
        return actions
    except Exception:
        LOG.debug("activity_log: failed to get actions for %s", server_id, exc_info=True)
        return []


@router.get(
    "/extension/activity-log",
    description="Aggregated activity log across Nova instances",
)
async def activity_log(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
    action: Optional[str] = Query(None, description="Filter by action type"),
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    start: Optional[str] = Query(None, description="Start time (ISO 8601)"),
    end: Optional[str] = Query(None, description="End time (ISO 8601)"),
    limit: int = Query(100, description="Maximum activities to return", ge=1, le=500),
    marker: Optional[str] = Query(None, description="Pagination marker (request_id)"),
):
    admin = is_system_admin(profile)
    session = await generate_session(profile=profile)
    rid = x_openstack_request_id

    nc = await utils.nova_client(
        region=profile.region,
        session=session,
        global_request_id=rid,
    )

    # List servers
    target_project = project_id if admin and project_id else None
    servers = await _list_servers(nc, admin, target_project)

    # Build server lookup: id -> {name, project_id}
    server_map: Dict[str, Dict[str, str]] = {}
    for s in servers:
        server_map[s.id] = {
            "name": getattr(s, "name", s.id),
            "project_id": getattr(s, "tenant_id", ""),
        }

    # Fetch actions for all servers concurrently
    action_tasks = [_get_instance_actions(nc, s.id) for s in servers]
    all_action_results = await asyncio.gather(*action_tasks, return_exceptions=True)

    # Flatten and enrich
    activities: List[Dict[str, Any]] = []
    for server, action_result in zip(servers, all_action_results):
        if isinstance(action_result, Exception):
            continue
        s_info = server_map.get(server.id, {})
        for a in action_result:
            act = getattr(a, "action", "") or ""
            a_user_id = getattr(a, "user_id", "") or ""
            a_project_id = getattr(a, "project_id", "") or s_info.get("project_id", "")
            a_start_time = getattr(a, "start_time", "") or ""
            a_request_id = getattr(a, "request_id", "") or ""
            a_message = getattr(a, "message", "") or ""

            # Apply filters
            if action and act != action:
                continue
            if user_id and a_user_id != user_id:
                continue
            if start and a_start_time and str(a_start_time) < start:
                continue
            if end and a_start_time and str(a_start_time) > end:
                continue

            activities.append({
                "action": act,
                "instance_id": server.id,
                "instance_name": s_info.get("name", server.id),
                "user_id": a_user_id,
                "project_id": a_project_id,
                "start_time": str(a_start_time),
                "request_id": a_request_id,
                "message": a_message,
                "status": getattr(a, "status", "completed") or "completed",
            })

    # Sort by start_time descending
    activities.sort(key=lambda x: x["start_time"], reverse=True)

    # Marker-based pagination
    if marker:
        found = False
        filtered = []
        for item in activities:
            if found:
                filtered.append(item)
            if item["request_id"] == marker:
                found = True
        activities = filtered

    # Apply limit
    activities = activities[:limit]

    return {"activities": activities}
