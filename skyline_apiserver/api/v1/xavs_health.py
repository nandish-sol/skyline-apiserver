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

# ---- helpers ----

def _env(name: str, default: Any = None) -> Any:
    return os.environ.get(name, default)


def _read_passwords() -> Dict[str, Any]:
    for p in ("/etc/xavs/passwords.yml", "/etc/xavs/passwords.yaml"):
        try:
            if os.path.exists(p):
                if yaml:
                    data = yaml.safe_load(open(p)) or {}
                    return data if isinstance(data, dict) else {}
        except Exception:
            pass
    return {}


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
            r = _requests.get(f"{proto}://{host}:{port}/", timeout=timeout, verify=False)
            return r.status_code < 500
        except Exception:
            return _tcp_reachable(host, port, timeout)
    return _tcp_reachable(host, port, timeout)


def _http_json(url: str, auth: Optional[Tuple[str, str]] = None, timeout: float = 3.0):
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


# ---- config ----

OS_HOST = _env("XAVS_OS_HOST", "103.240.25.200")
# Use node's own IP, not VIP — VIP may not be reachable from container
_DEFAULT_LOCAL = None
try:
    import subprocess
    _ip_out = subprocess.check_output(
        ["hostname", "-I"], timeout=2
    ).decode().strip().split()
    # Pick the 10.x IP (internal network)
    # Prefer 10.0.1.x (internal API network) over other 10.x subnets
    _DEFAULT_LOCAL = next(
        (ip for ip in _ip_out if ip.startswith("10.0.1.") and not ip.endswith(".200")),
        next((ip for ip in _ip_out if ip.startswith("10.")), None),
    )
except Exception:
    pass
INTERNAL_HOST = _env("XAVS_INTERNAL_HOST", _DEFAULT_LOCAL or "10.0.1.71")
RABBITMQ_HOST = _env("XAVS_RABBITMQ_HOST", INTERNAL_HOST)


def _service_targets():
    return {
        "keystone_api": (OS_HOST, 5000, "Keystone API"),
        "glance_api": (OS_HOST, 9292, "Glance API"),
        "cinder_api": (OS_HOST, 8776, "Cinder API"),
        "nova_api": (OS_HOST, 8774, "Nova API"),
        "placement_api": (OS_HOST, 8780, "Placement API"),
        "neutron_api": (OS_HOST, 9696, "Neutron API"),
        "heat_api": (OS_HOST, 8004, "Heat API"),
        "heat_api_cfn": (OS_HOST, 8000, "Heat API CFN"),
        "horizon": (OS_HOST, 443, "Horizon"),
        "skyline": (OS_HOST, 9999, "Skyline Console"),
        "mariadb": (INTERNAL_HOST, 3306, "MariaDB"),
        "rabbitmq_mgmt": (INTERNAL_HOST, 15672, "RabbitMQ Mgmt"),
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

    amqp_host = _env("RABBITMQ_HOST", RABBITMQ_HOST)
    amqp_port = int(_env("RABBITMQ_PORT", "5672"))
    if _tcp_reachable(amqp_host, amqp_port, 2.0):
        status["cluster_up"] = True

    pwd = _read_passwords()
    base = (_env("RABBITMQ_MGMT_URL", f"http://{amqp_host}:15672") or "").rstrip("/")
    user = _env("RABBITMQ_USER", "openstack")
    password = _env("RABBITMQ_PASSWORD", pwd.get("rabbitmq_password"))

    if not password:
        return status

    def _get(path):
        return _http_json(f"{base}{path}", auth=(user, password))

    ok, overview = _get("/api/overview")
    if ok and isinstance(overview, dict):
        status["object_totals"] = overview.get("object_totals") or {}
        status["queue_totals"] = overview.get("queue_totals") or {}
        ms = overview.get("message_stats") or {}
        for k in ("publish", "ack", "deliver_get", "confirm"):
            if k in ms:
                status["message_stats"][k] = ms[k]
        status["mgmt_version"] = overview.get("management_version") or overview.get("rabbitmq_version")

    ok, nodes = _get("/api/nodes")
    if ok and isinstance(nodes, list):
        status["nodes"] = []
        for n in nodes:
            uptime_ms = n.get("uptime")
            uptime_s = int(float(uptime_ms) / 1000) if uptime_ms else None
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
                "disk_free_alarm": bool(n.get("disk_free_alarm", False)),
                "uptime": _format_uptime(uptime_s) if uptime_s else None,
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

    host = _env("MARIADB_HOST", INTERNAL_HOST)
    port = int(_env("MARIADB_PORT", "3306"))
    user = _env("MARIADB_USER", "root")
    pwd = _read_passwords()
    password = _env("MARIADB_PASSWORD") or pwd.get("mariadb_root_password") or pwd.get("database_password")

    if not _tcp_reachable(host, port, 2.0) or not password:
        return out

    try:
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=2, read_timeout=2)
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
        out["ready"] = kv.get("wsrep_ready", "").lower() in ("on", "1", "true", "yes")
        try:
            out["cluster_size"] = int(kv.get("wsrep_cluster_size", "0"))
        except Exception:
            pass
        out["cluster_status"] = kv.get("wsrep_cluster_status")
        out["local_state"] = kv.get("wsrep_local_state_comment")
        out["connected"] = kv.get("wsrep_connected", "").lower() in ("on", "1", "true", "yes")
        out["provider_version"] = kv.get("wsrep_provider_version")
        out["node_name"] = kv.get("wsrep_node_name")
        try:
            uptime = int(kv.get("Uptime", "0"))
            out["uptime"] = _format_uptime(uptime)
        except Exception:
            pass
        try:
            out["threads_connected"] = int(kv.get("Threads_connected", "0"))
        except Exception:
            pass

        addrs = [a.strip() for a in (kv.get("wsrep_incoming_addresses", "") or "").split(",") if a.strip()]
        for a in addrs:
            h = a.split(":")[0] if ":" in a else a
            p = 4567
            out["nodes"].append({"node": a, "reachable": _tcp_reachable(h, p, 1.0)})

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
