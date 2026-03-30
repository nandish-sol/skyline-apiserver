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

"""XAVS Health — direct probes for OpenStack HA services."""

from __future__ import annotations

import asyncio
import os
import socket
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends

from skyline_apiserver.api import deps

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

router = APIRouter()

# ---- settings loader ----
# Mirrors Horizon's pattern: Ansible renders a YAML config at deploy time
# with passwords baked in. This file is deployed by kolla_set_configs into
# the container at /etc/skyline/xavs_health_settings.yaml.
# Fallback: env vars -> defaults (no runtime passwords.yml read).

_SETTINGS_PATHS = (
    "/etc/skyline/xavs_health_settings.yaml",
)

_settings_cache: Optional[Dict[str, Any]] = None


def _load_settings() -> Dict[str, Any]:
    """Load settings from the Ansible-rendered config file (cached)."""
    global _settings_cache
    if _settings_cache is not None:
        return _settings_cache
    for p in _SETTINGS_PATHS:
        try:
            if os.path.exists(p) and yaml:
                with open(p, "r") as fh:
                    data = yaml.safe_load(fh) or {}
                    if isinstance(data, dict):
                        _settings_cache = data
                        return _settings_cache
        except Exception:
            pass
    _settings_cache = {}
    return _settings_cache


def _get_setting(name: str, default: Any = None) -> Any:
    """Get a setting value. Priority: env var -> config file -> default."""
    env_val = os.environ.get(name.upper())
    if env_val is not None:
        return env_val
    settings = _load_settings()
    val = settings.get(name)
    if val is not None:
        return val
    return default


# ---- helpers ----

def _tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _http_check(host: str, port: int, timeout: float = 2.0) -> bool:
    if _requests:
        try:
            proto = "https" if port == 443 else "http"
            r = _requests.get(
                f"{proto}://{host}:{port}/",
                timeout=timeout, verify=False,
            )
            return r.status_code < 500
        except Exception:
            return _tcp_reachable(host, port, timeout)
    return _tcp_reachable(host, port, timeout)


def _http_json(
    url: str,
    auth: Optional[Tuple[str, str]] = None,
    timeout: float = 3.0,
):
    if _requests:
        try:
            r = _requests.get(url, auth=auth, timeout=timeout)
            if r.status_code == 200:
                return True, r.json()
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)
    return False, "requests not available"


def _format_bytes(b) -> str:
    try:
        b = int(b)
    except (ValueError, TypeError):
        return "Unknown"
    if b >= 1099511627776:
        return f"{b / 1099511627776:.2f} TB"
    if b >= 1073741824:
        return f"{b / 1073741824:.1f} GB"
    if b >= 1048576:
        return f"{b / 1048576:.0f} MB"
    if b >= 1024:
        return f"{b / 1024:.0f} KB"
    return f"{b} bytes"


def _format_uptime(s) -> str:
    try:
        s = int(s)
    except (ValueError, TypeError):
        return "Unknown"
    if s >= 86400:
        return f"{s // 86400}d {(s % 86400) // 3600}h"
    if s >= 3600:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    if s >= 60:
        return f"{s // 60}m"
    return f"{s}s"


# ---- config (from Ansible-rendered settings) ----

def _get_os_host() -> str:
    return str(_get_setting("xavs_os_host", "127.0.0.1"))


def _get_internal_host() -> str:
    return str(_get_setting("xavs_internal_host", "127.0.0.1"))


def _service_targets() -> Dict[str, Tuple[str, int, str]]:
    """Build service targets from Ansible-rendered config or defaults."""
    settings = _load_settings()
    configured = settings.get("service_targets")
    if isinstance(configured, dict) and configured:
        targets = {}
        for key, info in configured.items():
            if isinstance(info, dict):
                host = str(info.get("host", "127.0.0.1"))
                port = int(info.get("port", 0))
                label = str(info.get("label", key))
                targets[key] = (host, port, label)
        if targets:
            return targets

    # Fallback: hardcoded defaults
    os_host = _get_os_host()
    internal_host = _get_internal_host()
    return {
        "keystone_api": (os_host, 5000, "Keystone API"),
        "glance_api": (os_host, 9292, "Glance API"),
        "cinder_api": (os_host, 8776, "Cinder API"),
        "nova_api": (os_host, 8774, "Nova API"),
        "placement_api": (os_host, 8780, "Placement API"),
        "neutron_api": (os_host, 9696, "Neutron API"),
        "heat_api": (os_host, 8004, "Heat API"),
        "heat_api_cfn": (os_host, 8000, "Heat API CFN"),
        "horizon": (os_host, 443, "Horizon"),
        "skyline": (os_host, 9999, "Skyline Console"),
        "mariadb": (internal_host, 3306, "MariaDB"),
        "rabbitmq_mgmt": (internal_host, 15672, "RabbitMQ Mgmt"),
    }


# ---- collectors ----

def get_openstack_services() -> List[Dict[str, Any]]:
    rows = []
    for _name, (host, port, label) in _service_targets().items():
        if port in (3306, 5672):
            ok = _tcp_reachable(host, port, 2.0)
        else:
            ok = _http_check(host, port, 2.0)
        rows.append({
            "service": label,
            "host": f"{host}:{port}",
            "status": "up" if ok else "down",
        })
    return rows


def get_rabbitmq_status() -> Dict[str, Any]:
    status: Dict[str, Any] = {
        "cluster_up": False,
        "nodes": [],
        "object_totals": {},
        "queue_totals": {},
        "message_stats": {},
        "mgmt_version": None,
        "vhost_aliveness_ok": None,
        "warnings": [],
    }

    amqp_host = str(_get_setting("rabbitmq_host", _get_internal_host()))
    amqp_port = int(_get_setting("rabbitmq_port", 5672))
    if _tcp_reachable(amqp_host, amqp_port, 2.0):
        status["cluster_up"] = True

    mgmt_port = int(_get_setting("rabbitmq_mgmt_port", 15672))
    base = str(_get_setting(
        "rabbitmq_mgmt_url",
        f"http://{amqp_host}:{mgmt_port}",
    )).rstrip("/")
    user = str(_get_setting("rabbitmq_user", "openstack"))
    password = _get_setting("rabbitmq_password")

    if not password:
        return status

    def _get(path):
        return _http_json(f"{base}{path}", auth=(user, str(password)))

    ok, overview = _get("/api/overview")
    if ok and isinstance(overview, dict):
        status["object_totals"] = overview.get("object_totals") or {}
        status["queue_totals"] = overview.get("queue_totals") or {}
        ms = overview.get("message_stats") or {}
        for k in ("publish", "ack", "deliver_get", "confirm"):
            if k in ms:
                status["message_stats"][k] = ms[k]
        status["mgmt_version"] = (
            overview.get("management_version")
            or overview.get("rabbitmq_version")
        )

    ok, nodes = _get("/api/nodes")
    if ok and isinstance(nodes, list):
        status["nodes"] = []
        for n in nodes:
            uptime_ms = n.get("uptime")
            uptime_s = (
                int(float(uptime_ms) / 1000) if uptime_ms else None
            )
            status["nodes"].append({
                "name": n.get("name"),
                "type": n.get("type"),
                "up": bool(n.get("running", True)),
                "mem_used": _format_bytes(n.get("mem_used")),
                "mem_limit": _format_bytes(n.get("mem_limit")),
                "mem_alarm": bool(n.get("mem_alarm", False)),
                "fd_used": n.get("fd_used"),
                "fd_total": n.get("fd_total"),
                "sockets_used": n.get("sockets_used"),
                "sockets_total": n.get("sockets_total"),
                "disk_free": _format_bytes(n.get("disk_free")),
                "disk_free_alarm": bool(
                    n.get("disk_free_alarm", False)
                ),
                "uptime": (
                    _format_uptime(uptime_s) if uptime_s else None
                ),
            })

    ok, alive = _get("/api/aliveness-test/%2F")
    if ok and isinstance(alive, dict):
        status["vhost_aliveness_ok"] = alive.get("status") == "ok"

    return status


def get_mariadb_status() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ready": False,
        "cluster_size": None,
        "cluster_status": None,
        "local_state": None,
        "connected": None,
        "provider_version": None,
        "node_name": None,
        "uptime": None,
        "threads_connected": None,
        "nodes": [],
    }

    host = str(_get_setting("mariadb_host", _get_internal_host()))
    port = int(_get_setting("mariadb_port", 3306))
    user = str(_get_setting("mariadb_user", "root"))
    password = _get_setting("mariadb_password")

    if not _tcp_reachable(host, port, 2.0) or not password:
        return out

    try:
        import pymysql
        conn = pymysql.connect(
            host=host, port=port, user=user,
            password=str(password),
            connect_timeout=2, read_timeout=2,
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW STATUS LIKE 'wsrep_%'")
                ws = cur.fetchall()
                cur.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
                ws += cur.fetchall()
                cur.execute("SHOW GLOBAL STATUS LIKE 'Uptime'")
                ws += cur.fetchall()
        finally:
            conn.close()

        kv = {str(k): str(v) for k, v in ws if k}
        out["ready"] = kv.get(
            "wsrep_ready", ""
        ).lower() in ("on", "1", "true", "yes")
        try:
            out["cluster_size"] = int(
                kv.get("wsrep_cluster_size", "0")
            )
        except Exception:
            pass
        out["cluster_status"] = kv.get("wsrep_cluster_status")
        out["local_state"] = kv.get("wsrep_local_state_comment")
        out["connected"] = kv.get(
            "wsrep_connected", ""
        ).lower() in ("on", "1", "true", "yes")
        out["provider_version"] = kv.get("wsrep_provider_version")
        out["node_name"] = kv.get("wsrep_node_name")
        try:
            uptime = int(kv.get("Uptime", "0"))
            out["uptime"] = _format_uptime(uptime)
        except Exception:
            pass
        try:
            out["threads_connected"] = int(
                kv.get("Threads_connected", "0")
            )
        except Exception:
            pass

        addrs = [
            a.strip()
            for a in (
                kv.get("wsrep_incoming_addresses", "") or ""
            ).split(",")
            if a.strip()
        ]
        for a in addrs:
            h = a.split(":")[0] if ":" in a else a
            p = 4567
            out["nodes"].append({
                "node": a,
                "reachable": _tcp_reachable(h, p, 1.0),
            })

    except Exception:
        pass

    return out


# ---- API endpoint ----

@router.get(
    "/extension/xavs-health",
    description="XAVS Health Check — OpenStack HA services status",
)
async def xavs_health(profile=Depends(deps.get_profile_update_jwt)):
    loop = asyncio.get_event_loop()
    services, rabbitmq, mariadb = await asyncio.gather(
        loop.run_in_executor(None, get_openstack_services),
        loop.run_in_executor(None, get_rabbitmq_status),
        loop.run_in_executor(None, get_mariadb_status),
    )

    total = len(services)
    up = sum(1 for s in services if s["status"] == "up")
    down = total - up

    return {
        "summary": {
            "total": total,
            "up": up,
            "down": down,
            "rabbitmq_up": rabbitmq.get("cluster_up", False),
            "mariadb_ready": mariadb.get("ready", False),
            "mariadb_cluster_size": mariadb.get("cluster_size"),
        },
        "services": services,
        "rabbitmq": rabbitmq,
        "mariadb": mariadb,
    }
