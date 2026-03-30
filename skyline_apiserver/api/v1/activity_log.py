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

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants
from skyline_apiserver.utils.roles import is_system_admin

router = APIRouter()

# OpenSearch connection
OPENSEARCH_URL = os.environ.get(
    "OPENSEARCH_URL", "http://10.0.1.71:9200"
)
OPENSEARCH_INDEX = "openstack-audit-*"
OPENSEARCH_TIMEOUT = 10.0


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

    # Non-admin users only see their own project
    if not is_admin:
        filters.append({"term": {"tenant_id": profile_project_id}})
    elif project_id:
        filters.append({"term": {"tenant_id": project_id}})

    if service:
        filters.append({"term": {"service": service}})
    if action_type:
        filters.append({"term": {"action_type": action_type}})
    if resource_type:
        filters.append({"term": {"resource_type": resource_type}})
    if user_id:
        filters.append({"term": {"user_id": user_id}})
    if http_status:
        filters.append({"term": {"http_status": http_status}})

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

    return {
        "bool": {
            "must": must if must else [{"match_all": {}}],
            "filter": filters,
        }
    }


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
            "by_service": {"terms": {"field": "service", "size": 20}},
            "by_action_type": {"terms": {"field": "action_type", "size": 10}},
            "by_resource_type": {"terms": {"field": "resource_type", "size": 20}},
            "by_status": {
                "range": {
                    "field": "http_status",
                    "ranges": [
                        {"key": "success", "from": 200, "to": 300},
                        {"key": "client_error", "from": 400, "to": 500},
                        {"key": "server_error", "from": 500, "to": 600},
                    ],
                }
            },
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

    activities = []
    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        # Normalize response_time: Apache logs use microseconds, Python logs use seconds
        raw_time = src.get("response_time") or src.get("http_response_time_us") or 0
        try:
            time_val = float(raw_time)
            # If > 100, assume microseconds and convert to seconds
            response_time_sec = time_val / 1000000 if time_val > 100 else time_val
        except (ValueError, TypeError):
            response_time_sec = 0

        activities.append(
            {
                "timestamp": src.get("@timestamp", ""),
                "service": src.get("service", ""),
                "action_type": src.get("action_type", ""),
                "resource_type": src.get("resource_type", ""),
                "resource_id": src.get("resource_id", ""),
                "http_method": src.get("http_method", ""),
                "http_url": src.get("http_url", ""),
                "http_status": src.get("http_status", 0),
                "response_time": round(response_time_sec, 4),
                "user_id": src.get("user_id", "") or "system",
                "project_id": src.get("tenant_id", "") or "",
                "request_id": src.get("request_id", ""),
                "client_ip": src.get("client_ip", ""),
                "node": src.get("node", ""),
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
            "services": {"terms": {"field": "service", "size": 50}},
            "resource_types": {"terms": {"field": "resource_type", "size": 50}},
            "action_types": {"terms": {"field": "action_type", "size": 20}},
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
    return {
        "services": [
            b["key"] for b in aggs.get("services", {}).get("buckets", [])
        ],
        "resource_types": [
            b["key"]
            for b in aggs.get("resource_types", {}).get("buckets", [])
        ],
        "action_types": [
            b["key"]
            for b in aggs.get("action_types", {}).get("buckets", [])
        ],
    }
