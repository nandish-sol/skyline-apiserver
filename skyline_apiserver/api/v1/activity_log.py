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
import re
from typing import Any, Dict, List, Optional, Tuple

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

    # Fetch uncached names from Keystone
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

# OpenSearch connection — read lazily from skyline.yaml (populated by xavs-ansible).
# Must NOT evaluate at import time because CONF is not yet initialized.
def _get_opensearch_url():
    """Get OpenSearch URL from CONF (skyline.yaml) or env."""
    try:
        from skyline_apiserver.config import CONF
        return os.environ.get("OPENSEARCH_URL", CONF.openstack.opensearch_url)
    except Exception:
        return os.environ.get("OPENSEARCH_URL", "http://127.0.0.1:9200")
# Query notification index — contains structured events from oslo.messaging.
# HTTP access log index (flog-*) is excluded for now as it contains too much
# noise (health checks, internal calls). TODO: merge HTTP fields (status, IP,
# response_time) from flog-* by correlating on request_id.
OPENSEARCH_INDEX = "openstack-audit-*"
OPENSEARCH_TIMEOUT = 10.0


# Normalize service names: backend log tags → user-friendly names
SERVICE_ALIASES = {
    "compute": "nova",
    "network": "neutron",
    "volume": "cinder",
    "snapshot": "cinder",
    "api": "nova",            # Nova notifications use service="api"
    "scheduler": "nova",      # Nova scheduler notifications
    "conductor": "nova",      # Nova conductor notifications
    "compute_task": "nova",   # Nova compute task notifications
    "servergroup": "nova",    # Nova server group notifications
}

# Reverse map: when user selects "nova", also search "compute"
SERVICE_EXPAND = {
    "nova": ["nova", "compute", "api", "scheduler", "conductor", "compute_task", "servergroup"],
    "neutron": ["neutron", "network"],
    "cinder": ["cinder", "volume", "snapshot"],
}

# ---------------------------------------------------------------------------
# URL cleanup & resource extraction helpers
# ---------------------------------------------------------------------------

# Strip trailing " HTTP/1.1" or " HTTP/1.0" from URLs (Neutron log artefact)
_RE_HTTP_SUFFIX = re.compile(r"\s+HTTP/[\d.]+$")

# Extract resource type from URL path
_RESOURCE_TYPE_MAP = {
    "servers": "Instance",
    "volumes": "Volume",
    "snapshots": "Snapshot",
    "backups": "Backup",
    "networks": "Network",
    "subnets": "Subnet",
    "routers": "Router",
    "floatingips": "Floating IP",
    "security-groups": "Security Group",
    "security-group-rules": "SG Rule",
    "ports": "Port",
    "images": "Image",
    "stacks": "Stack",
    "zones": "DNS Zone",
    "recordsets": "DNS Record",
    "secrets": "Secret",
    "containers": "Container",
    "loadbalancers": "Load Balancer",
    "listeners": "Listener",
    "pools": "Pool",
    "healthmonitors": "Health Monitor",
    "members": "Pool Member",
    "shares": "Share",
    "os-keypairs": "Key Pair",
    "os-server-groups": "Server Group",
    "os-volume_attachments": "Volume Attachment",
    "os-interface": "Interface",
    "volume-transfers": "Volume Transfer",
    "firewall_groups": "Firewall Group",
    "firewall_policies": "Firewall Policy",
    "firewall_rules": "Firewall Rule",
    "vpnservices": "VPN Service",
    "remote-consoles": "Console",
}

# Notification resource_type values → human-readable labels
# (These come from oslo.messaging notifications, not URLs)
_NOTIFICATION_RESOURCE_MAP = {
    "instance": "Instance",
    "volume": "Volume",
    "snapshot": "Snapshot",
    "port": "Port",
    "network": "Network",
    "subnet": "Subnet",
    "router": "Router",
    "floatingip": "Floating IP",
    "security_group": "Security Group",
    "keypair": "Key Pair",
    "action_plans": "Action Plan",
    "audits": "Audit",
    "audit_templates": "Audit Template",
}

# UUID pattern
_RE_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# Parse HTTP info from raw Payload (Glance eventlet, etc.)
# Matches: "DELETE /v2/images/uuid HTTP/1.1" 204 189 0.039562
_RE_PAYLOAD_URL = re.compile(
    r'"(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<url>/\S+?)(?:\s+HTTP/[\d.]+)?"\s+'
    r"(?P<status>\d{3})\s+\d+\s+(?P<time>[\d.]+)"
)


def _clean_url(url: str) -> str:
    """Strip trailing HTTP/x.x and query strings from URL."""
    url = _RE_HTTP_SUFFIX.sub("", url)
    return url.split("?")[0]


def _extract_resource_label(url: str) -> str:
    """Extract a human-readable resource type from an API URL."""
    clean = _clean_url(url)
    parts = clean.strip("/").split("/")
    # Walk backwards to find a known resource segment
    for i in range(len(parts) - 1, -1, -1):
        seg = parts[i]
        # Skip UUIDs and version segments
        if _RE_UUID.match(seg) or seg.startswith("v"):
            continue
        # Skip 'action', 'detail', 'accept'
        if seg in ("action", "detail", "accept", "restore", "members"):
            continue
        label = _RESOURCE_TYPE_MAP.get(seg)
        if label:
            return label
    return ""


def _extract_resource_id(url: str) -> str:
    """Extract UUID from URL."""
    m = _RE_UUID.search(url)
    return m.group(0) if m else ""


# Action type labels for the UI
ACTION_LABELS = {
    "create": "Create",
    "delete": "Delete",
    "update": "Update",
    "associate": "Associate",
    "disassociate": "Disassociate",
    "start": "Start",
    "stop": "Stop",
    "reboot": "Reboot",
    "pause": "Pause",
    "unpause": "Unpause",
    "suspend": "Suspend",
    "resume": "Resume",
    "migrate": "Migrate",
    "attach": "Attach",
    "detach": "Detach",
    "snapshot": "Snapshot",
    "lock": "Lock",
    "unlock": "Unlock",
    "rescue": "Rescue",
    "shelve": "Shelve",
    "unshelve": "Unshelve",
    "action": "Action",
}

# Noisy events to filter by default (internal service chatter)
_DEFAULT_EXCLUDE = {
    "must_not": [
        # GET requests from HTTP access logs — read-only operations are not actions
        {"term": {"http_method.keyword": "GET"}},
        # HEAD/OPTIONS — internal health checks
        {"term": {"http_method.keyword": "HEAD"}},
        {"term": {"http_method.keyword": "OPTIONS"}},
        # Keystone token/auth noise (internal service auth + token validation)
        {"term": {"service.keyword": "keystone"}},
        # Horizon login page noise — Skyline login attempts hitting Horizon 404
        {"bool": {"must": [
            {"term": {"service.keyword": "horizon"}},
            {"terms": {"resource_type.keyword": ["login", "unknown"]}},
        ]}},
        # Nova scheduler/conductor internal events (no user-facing resource)
        {"wildcard": {"event_type.keyword": "scheduler.*"}},
        {"term": {"service.keyword": "conductor"}},
        # Service account internal operations (xms, heat, nova service users)
        {"bool": {"must": [
            {"terms": {"http_url.keyword": [
                "/v2.1/servers/fake-instance-id",
            ]}},
        ]}},
        # Binding events (internal neutron port binding)
        {"wildcard": {"event_type.keyword": "binding.*"}},
        # Skip .start events — keep only .end (avoids duplicate rows)
        {"wildcard": {"event_type.keyword": "*.start"}},
        # Internal compute.instance.update (state transition noise)
        {"term": {"event_type.keyword": "compute.instance.update"}},
    ]
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
        # Exclude noisy events by default (only when no service filter set)
        must_not.extend(_DEFAULT_EXCLUDE["must_not"])

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
                f"{_get_opensearch_url()}/{OPENSEARCH_INDEX}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        LOG.error(
            "activity_log: OpenSearch query failed: {}", exc
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
        if uid and uid != "system" and uid != "-":
            user_ids.add(uid)
        if pid and pid != "-":
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

        uid = src.get("user_id", "") or ""
        pid = src.get("tenant_id", "") or ""

        # Clean uid/pid: "-" means not available
        if uid == "-":
            uid = ""
        if pid == "-":
            pid = ""

        # Clean node: "network.xd1" → "xd1", "xd1@rbd-1#rbd-1" → "xd1"
        node = src.get("node", "") or src.get("Hostname", "")
        if "@" in node:
            node = node.split("@")[0]
        if "." in node:
            node = node.split(".")[-1]

        raw_service = src.get("service", "")
        normalized_service = SERVICE_ALIASES.get(raw_service, raw_service)

        # Clean URL: strip trailing HTTP/1.1 (Neutron artefact)
        raw_url = src.get("http_url", "")
        clean = _clean_url(raw_url)

        # For events without parsed http_url (Glance eventlet, etc.),
        # try extracting from the raw Payload field
        payload = src.get("Payload", "")
        if not clean and payload:
            m = _RE_PAYLOAD_URL.search(payload)
            if m:
                raw_url = m.group("url")
                clean = _clean_url(raw_url)
                if not src.get("http_method"):
                    src["http_method"] = m.group("method")
                if not src.get("http_status"):
                    src["http_status"] = m.group("status")
                if m.group("time"):
                    try:
                        response_time_sec = float(m.group("time"))
                    except (ValueError, TypeError):
                        pass

        # Extract resource info from URL if not in source
        resource_id = src.get("resource_id", "") or _extract_resource_id(clean)
        resource_label = _extract_resource_label(clean)
        resource_type_raw = src.get("resource_type", "")
        # Try URL-based label first, then notification map, then raw value
        notif_label = _NOTIFICATION_RESOURCE_MAP.get(resource_type_raw, "")
        display_resource = resource_label or notif_label or resource_type_raw

        # Fix action_type "unknown" by inferring from HTTP method
        action_type = src.get("action_type", "")
        if action_type in ("unknown", "") and src.get("http_method"):
            method = src["http_method"]
            if method == "DELETE":
                action_type = "delete"
            elif method == "POST":
                action_type = "create"
            elif method in ("PUT", "PATCH"):
                action_type = "update"

        # Client IP: strip leading space, pick first real IP
        client_ip = (src.get("client_ip", "") or "").strip()
        if client_ip:
            # Take first IP from comma-separated list
            first_ip = client_ip.split(",")[0].strip()
            # Skip internal IPs (10.0.x.x) — show external IP if present
            ips = [ip.strip() for ip in client_ip.split(",")]
            external = [ip for ip in ips if not ip.startswith("10.0.")]
            client_ip = external[0] if external else first_ip

        # User/project display — prefer notification context (already resolved)
        # over Keystone lookup (which requires API call + cache)
        user_name = (
            src.get("user_name", "")
            or user_map.get(uid, "")
        )
        project_name = (
            src.get("project_name", "")
            or project_map.get(pid, "")
        )

        activities.append(
            {
                "timestamp": src.get("@timestamp", ""),
                "service": normalized_service,
                "action_type": action_type or src.get("action_type", ""),
                "resource_type": display_resource,
                "resource_id": resource_id,
                "resource_name": src.get("resource_name", ""),
                "event_type": src.get("event_type", ""),
                "http_method": src.get("http_method", ""),
                "http_url": clean,
                "http_status": src.get("http_status", 0),
                "response_time": round(response_time_sec, 4),
                "user_id": uid,
                "user_name": user_name,
                "project_id": pid,
                "project_name": project_name,
                "request_id": src.get("request_id", src.get("message_id", "")),
                "client_ip": client_ip or src.get("client_ip", ""),
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
                f"{_get_opensearch_url()}/{OPENSEARCH_INDEX}/_search",
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
