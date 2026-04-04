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

"""Activity Log — OpenSearch-backed audit trail across all OpenStack services.

Data flows from Fluentd (tailing OpenStack service logs) into OpenSearch
index pattern 'openstack-audit-*'. This endpoint queries that index with
server-side filtering, pagination, and aggregations.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, Header, Query
from starlette.concurrency import run_in_threadpool

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.client import utils
from skyline_apiserver.client.utils import generate_session
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants
from skyline_apiserver.utils.roles import is_system_admin

# Simple in-memory cache for user/project names (TTL: 10 minutes)
_name_cache: dict = {}
_cache_ttl = 600  # seconds


async def _resolve_names(
    profile: schemas.Profile, user_ids: set, project_ids: set
) -> tuple:
    """Resolve user_ids and project_ids to names using Keystone (admin session)."""
    import time

    now = time.time()
    user_map = {}
    project_map = {}

    # Check cache first
    uncached_users = set()
    uncached_projects = set()
    for uid in user_ids:
        if uid and uid != "system":
            cached = _name_cache.get(f"u:{uid}")
            if cached and now - cached[1] < _cache_ttl:
                user_map[uid] = cached[0]
            else:
                uncached_users.add(uid)

    for pid in project_ids:
        if pid:
            cached = _name_cache.get(f"p:{pid}")
            if cached and now - cached[1] < _cache_ttl:
                project_map[pid] = cached[0]
            else:
                uncached_projects.add(pid)

    # Fetch uncached names from Keystone using direct client (not async utils)
    if uncached_users or uncached_projects:
        try:
            from skyline_apiserver.client.utils import get_system_session
            from keystoneclient.v3 import client as ks_client

            session = get_system_session()
            kc = ks_client.Client(session=session)

            if uncached_users:
                users = await run_in_threadpool(kc.users.list)
                for u in users:
                    if u.id in uncached_users:
                        user_map[u.id] = u.name
                        _name_cache[f"u:{u.id}"] = (u.name, now)

            if uncached_projects:
                projects = await run_in_threadpool(kc.projects.list)
                for p in projects:
                    if p.id in uncached_projects:
                        project_map[p.id] = p.name
                        _name_cache[f"p:{p.id}"] = (p.name, now)
        except Exception as exc:
            LOG.warning("activity_log: name resolution failed: {}", exc)
            LOG.opt(exception=True).debug("name resolution traceback")

    return user_map, project_map

router = APIRouter()

# OpenSearch connection
OPENSEARCH_URL = os.environ.get(
    "OPENSEARCH_URL", "http://10.0.1.71:9200"
)
OPENSEARCH_INDEX = "openstack-audit-*"
OPENSEARCH_TIMEOUT = 10.0


# Normalize service names: backend log tags → user-friendly names
SERVICE_ALIASES = {
    "compute": "nova",
    "network": "neutron",
    "volume": "cinder",
    "snapshot": "cinder",
}

# Reverse map: when user selects "nova", also search "compute"
SERVICE_EXPAND = {
    "nova": ["nova", "compute"],
    "neutron": ["neutron", "network"],
    "cinder": ["cinder", "volume", "snapshot"],
}


def _build_query(
    *,
    is_admin: bool,
    profile_project_id: str,
    service: Optional[str] = None,
    action_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
    http_status: Optional[int] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Build OpenSearch bool query from filter parameters."""
    must = []
    filters = []
    must_not = []

    # Non-admin users only see their own project
    if not is_admin:
        filters.append({"term": {"tenant_id": profile_project_id}})
    elif project_id:
        filters.append({"term": {"tenant_id": project_id}})

    if service:
        # Expand service aliases: "nova" → ["nova", "compute"]
        expanded = SERVICE_EXPAND.get(service, [service])
        if len(expanded) == 1:
            filters.append({"term": {"service.keyword": expanded[0]}})
        else:
            filters.append({"terms": {"service.keyword": expanded}})
    else:
        # By default, exclude noisy keystone auth token events
        must_not.append({"bool": {"must": [
            {"term": {"service.keyword": "keystone"}},
            {"term": {"resource_type.keyword": "auth"}},
        ]}})

    if action_type:
        filters.append({"term": {"action_type.keyword": action_type}})
    if resource_type:
        filters.append({"term": {"resource_type.keyword": resource_type}})
    if user_id:
        filters.append({"term": {"user_id.keyword": user_id}})
    if http_status:
        filters.append({"term": {"http_status.keyword": str(http_status)}})

    # Time range
    time_range: Dict[str, str] = {}
    if start:
        time_range["gte"] = start
    if end:
        time_range["lte"] = end
    if time_range:
        filters.append({"range": {"@timestamp": time_range}})

    # Full-text search
    if search:
        must.append(
            {
                "multi_match": {
                    "query": search,
                    "fields": ["http_url", "Payload", "resource_id"],
                    "type": "phrase_prefix",
                }
            }
        )

    query = {
        "bool": {
            "must": must if must else [{"match_all": {}}],
            "filter": filters,
        }
    }
    if must_not:
        query["bool"]["must_not"] = must_not
    return query


@router.get(
    "/extension/activity-log",
    description="Aggregated activity log across all OpenStack services",
)
async def activity_log(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
    service: Optional[str] = Query(None, description="Filter by service"),
    action_type: Optional[str] = Query(
        None, description="Filter by action type (create/delete/update/action)"
    ),
    resource_type: Optional[str] = Query(
        None, description="Filter by resource type (servers/networks/volumes...)"
    ),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    project_id: Optional[str] = Query(
        None, description="Filter by project ID (admin only)"
    ),
    http_status: Optional[int] = Query(None, description="Filter by HTTP status"),
    start: Optional[str] = Query(None, description="Start time (ISO 8601)"),
    end: Optional[str] = Query(None, description="End time (ISO 8601)"),
    search: Optional[str] = Query(None, description="Full-text search"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    admin = is_system_admin(profile)

    query = _build_query(
        is_admin=admin,
        profile_project_id=profile.project.id,
        service=service,
        action_type=action_type,
        resource_type=resource_type,
        user_id=user_id,
        project_id=project_id,
        http_status=http_status,
        start=start,
        end=end,
        search=search,
    )

    body = {
        "query": query,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "from": offset,
        "size": limit,
        "aggs": {
            "by_service": {"terms": {"field": "service.keyword", "size": 20}},
            "by_action_type": {"terms": {"field": "action_type.keyword", "size": 10}},
            "by_resource_type": {"terms": {"field": "resource_type.keyword", "size": 20}},
            "by_status": {"terms": {"field": "http_status.keyword", "size": 10}},
        },
    }

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=OPENSEARCH_TIMEOUT
        ) as client:
            resp = await client.post(
                f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        LOG.error(
            "activity_log: OpenSearch query failed: %s", exc, exc_info=True
        )
        return {"activities": [], "total": 0, "aggregations": {}, "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)

    # Collect unique user/project IDs for name resolution
    raw_activities = []
    user_ids = set()
    project_ids = set()

    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        uid = src.get("user_id", "") or ""
        pid = src.get("tenant_id", "") or ""
        if uid and uid != "system":
            user_ids.add(uid)
        if pid:
            project_ids.add(pid)
        raw_activities.append(src)

    # Resolve names
    user_map, project_map = await _resolve_names(profile, user_ids, project_ids)

    activities = []
    for src in raw_activities:
        # Normalize response_time
        raw_time = src.get("response_time") or src.get("http_response_time_us") or 0
        try:
            time_val = float(raw_time)
            response_time_sec = time_val / 1000000 if time_val > 100 else time_val
        except (ValueError, TypeError):
            response_time_sec = 0

        uid = src.get("user_id", "") or "system"
        pid = src.get("tenant_id", "") or ""
        # Clean node: "network.xd1" → "xd1"
        node = src.get("node", "")
        if "." in node:
            node = node.split(".")[-1]

        raw_service = src.get("service", "")
        normalized_service = SERVICE_ALIASES.get(raw_service, raw_service)

        activities.append(
            {
                "timestamp": src.get("@timestamp", ""),
                "service": normalized_service,
                "action_type": src.get("action_type", ""),
                "resource_type": src.get("resource_type", ""),
                "resource_id": src.get("resource_id", ""),
                "resource_name": src.get("resource_name", ""),
                "event_type": src.get("event_type", ""),
                "http_method": src.get("http_method", ""),
                "http_url": src.get("http_url", ""),
                "http_status": src.get("http_status", 0),
                "response_time": round(response_time_sec, 4),
                "user_id": uid,
                "user_name": user_map.get(uid, ""),
                "project_id": pid,
                "project_name": project_map.get(pid, ""),
                "request_id": src.get("request_id", src.get("message_id", "")),
                "client_ip": src.get("client_ip", ""),
                "node": node,
                "log_level": src.get("log_level", ""),
            }
        )

    # Extract aggregations for filter dropdowns
    aggs = data.get("aggregations", {})
    aggregations = {}
    for agg_name in [
        "by_service",
        "by_action_type",
        "by_resource_type",
        "by_status",
    ]:
        agg = aggs.get(agg_name, {})
        buckets = agg.get("buckets", [])
        if agg_name == "by_service":
            # Merge aliased service names (compute→nova, network→neutron, etc.)
            merged = {}
            for b in buckets:
                key = SERVICE_ALIASES.get(b.get("key", ""), b.get("key", ""))
                merged[key] = merged.get(key, 0) + b.get("doc_count", 0)
            aggregations[agg_name] = [
                {"key": k, "count": v} for k, v in merged.items()
            ]
        else:
            aggregations[agg_name] = [
                {"key": b.get("key", ""), "count": b.get("doc_count", 0)}
                for b in buckets
            ]

    return {
        "activities": activities,
        "total": total,
        "aggregations": aggregations,
    }


@router.get(
    "/extension/activity-log/services",
    description="List available services and resource types in the audit log",
)
async def activity_log_services(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
):
    """Return distinct service and resource type names for filter dropdowns."""
    body = {
        "size": 0,
        "aggs": {
            "services": {"terms": {"field": "service.keyword", "size": 50}},
            "resource_types": {"terms": {"field": "resource_type.keyword", "size": 50}},
            "action_types": {"terms": {"field": "action_type.keyword", "size": 20}},
        },
    }

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=OPENSEARCH_TIMEOUT
        ) as client:
            resp = await client.post(
                f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return {"services": [], "resource_types": [], "action_types": []}

    aggs = data.get("aggregations", {})
    # Normalize and deduplicate service names
    raw_services = [b["key"] for b in aggs.get("services", {}).get("buckets", [])]
    normalized = list(dict.fromkeys(
        SERVICE_ALIASES.get(s, s) for s in raw_services
    ))
    return {
        "services": normalized,
        "resource_types": [
            b["key"]
            for b in aggs.get("resource_types", {}).get("buckets", [])
        ],
        "action_types": [
            b["key"]
            for b in aggs.get("action_types", {}).get("buckets", [])
        ],
    }
