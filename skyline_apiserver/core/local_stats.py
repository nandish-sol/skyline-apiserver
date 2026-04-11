# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Local Prometheus shim for single-node deployments.

Answers the same `/query` and `/query_range` shapes that Skyline's
Prometheus handler produces, but reads data from /proc, /sys and
OpenStack APIs instead of a real Prometheus server.

The shim keeps a small in-memory ring buffer (~10 minutes @ 15s) so that
`/query_range` charts can render actual time-series curves.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from skyline_apiserver.core import hwinfo, node_exporter
from skyline_apiserver.log import LOG

# Sampling config
SAMPLE_INTERVAL_SECONDS = 15
RING_BUFFER_SECONDS = 600  # 10 minutes
RING_BUFFER_SAMPLES = RING_BUFFER_SECONDS // SAMPLE_INTERVAL_SECONDS

# Cache for OpenStack API answers (avoid hammering nova/cinder)
_OPENSTACK_CACHE_TTL = 30
_openstack_cache: Dict[str, Tuple[float, Any]] = {}

_sampler_lock = threading.Lock()
_sampler_started = False

# Ring buffer — each entry is (timestamp, metrics_dict)
_ring: Deque[Tuple[float, Dict[str, Any]]] = deque(maxlen=RING_BUFFER_SAMPLES)

# Previous /proc/stat and /proc/diskstats + /proc/net/dev, for rate deltas
_prev_stat: Optional[Dict[str, Any]] = None
_prev_diskstats: Optional[Dict[str, Any]] = None
_prev_netdev: Optional[Dict[str, Any]] = None
_prev_ts: float = 0.0


# ---------------------------------------------------------------------------
# /proc readers
# ---------------------------------------------------------------------------


def _read_proc_stat() -> Dict[str, Any]:
    """/proc/stat → {cpu_total: {user, system, idle, ...}, cpus: [per-core]}"""
    out: Dict[str, Any] = {"cpu_total": {}, "cpus": []}
    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if not line.startswith("cpu"):
                    continue
                parts = line.split()
                name = parts[0]
                fields = ["user", "nice", "system", "idle", "iowait",
                          "irq", "softirq", "steal", "guest", "guest_nice"]
                vals = {}
                for i, f in enumerate(fields):
                    if i + 1 < len(parts):
                        try:
                            vals[f] = int(parts[i + 1])
                        except ValueError:
                            vals[f] = 0
                vals["total"] = sum(vals.values())
                if name == "cpu":
                    out["cpu_total"] = vals
                else:
                    out["cpus"].append({"name": name, **vals})
    except OSError:
        pass
    return out


def _read_proc_diskstats() -> Dict[str, Dict[str, int]]:
    """/proc/diskstats → {device: {reads, writes, read_bytes, write_bytes}}"""
    out: Dict[str, Dict[str, int]] = {}
    try:
        with open("/proc/diskstats") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                # Skip loop/ram/dm-dupes and partitions when we have parent disk
                if name.startswith(("loop", "ram", "dm-")):
                    continue
                try:
                    reads = int(parts[3])
                    read_sectors = int(parts[5])
                    writes = int(parts[7])
                    write_sectors = int(parts[9])
                except ValueError:
                    continue
                out[name] = {
                    "reads": reads,
                    "writes": writes,
                    "read_bytes": read_sectors * 512,
                    "write_bytes": write_sectors * 512,
                }
    except OSError:
        pass
    return out


def _read_proc_netdev() -> Dict[str, Dict[str, int]]:
    """/proc/net/dev → {iface: {rx_bytes, tx_bytes, rx_errs, tx_errs, rx_drop, tx_drop}}"""
    out: Dict[str, Dict[str, int]] = {}
    try:
        with open("/proc/net/dev") as fh:
            lines = fh.readlines()
        for line in lines[2:]:
            if ":" not in line:
                continue
            name, _, data = line.partition(":")
            name = name.strip()
            if name == "lo":
                continue
            parts = data.split()
            if len(parts) < 16:
                continue
            try:
                out[name] = {
                    "rx_bytes": int(parts[0]),
                    "rx_packets": int(parts[1]),
                    "rx_errs": int(parts[2]),
                    "rx_drop": int(parts[3]),
                    "tx_bytes": int(parts[8]),
                    "tx_packets": int(parts[9]),
                    "tx_errs": int(parts[10]),
                    "tx_drop": int(parts[11]),
                }
            except ValueError:
                continue
    except OSError:
        pass
    return out


def _read_filesystems() -> List[Dict[str, Any]]:
    """Read /proc/mounts and statvfs each real mount.

    Skips pseudo-filesystems, duplicate bind mounts (same device seen
    twice — we keep the shortest mountpoint), and bind-mounts onto
    single files (like /etc/localtime or /etc/timezone, which show up
    in a container when the host's files are bind-mounted in).
    """
    raw: List[Dict[str, Any]] = []
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mount, fstype = parts[0], parts[1], parts[2]
                if fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "devpts",
                              "cgroup", "cgroup2", "pstore", "bpf", "overlay",
                              "tracefs", "debugfs", "mqueue", "securityfs",
                              "hugetlbfs", "configfs", "autofs", "binfmt_misc",
                              "fusectl", "fuse.lxcfs", "rpc_pipefs", "nsfs",
                              "none", "squashfs", "fuse"):
                    continue
                if not device.startswith("/"):
                    continue
                # Skip bind-mounts onto single files — they clutter the
                # filesystem card with fake entries for things like
                # /etc/localtime, /etc/timezone, /etc/host-os-release.
                try:
                    if not os.path.isdir(mount):
                        continue
                except OSError:
                    continue
                try:
                    st = os.statvfs(mount)
                    total = st.f_blocks * st.f_frsize
                    free = st.f_bavail * st.f_frsize
                    if total == 0:
                        continue
                    raw.append({
                        "device": device,
                        "mount": mount,
                        "fstype": fstype,
                        "size": total,
                        "avail": free,
                        "used": total - free,
                    })
                except OSError:
                    continue
    except OSError:
        pass

    # Deduplicate by device — keep the shortest mountpoint (usually "/")
    # so a single "/" entry wins over every bind re-mount of the same
    # root device.
    by_device: Dict[str, Dict[str, Any]] = {}
    for e in raw:
        existing = by_device.get(e["device"])
        if existing is None or len(e["mount"]) < len(existing["mount"]):
            by_device[e["device"]] = e

    # Relabel container-internal log/data mountpoints to something
    # meaningful to an operator of the Monitor Center page. Inside an
    # OpenStack service container we typically only see a single bind
    # mount backed by the host root disk, so surface it as "System
    # Disk" rather than leaking the deployment implementation detail.
    _RELABEL_PREFIXES = (
        "/var/log/kolla",
        "/var/lib/docker",
    )
    for e in by_device.values():
        m = e["mount"]
        for prefix in _RELABEL_PREFIXES:
            if m == prefix or m.startswith(prefix + "/"):
                e["mount"] = "System Disk"
                e["device"] = ""
                break

    out = sorted(by_device.values(), key=lambda e: e["mount"])
    return out


def _count_tcp_established() -> int:
    """Count lines in /proc/net/tcp with state 01 (ESTABLISHED)."""
    count = 0
    for p in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(p) as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "01":
                        count += 1
        except OSError:
            continue
    return count


# ---------------------------------------------------------------------------
# Sampler: called periodically, writes to ring buffer
# ---------------------------------------------------------------------------


def sample_once() -> Dict[str, Any]:
    """Take one snapshot of all metrics and store in ring buffer.

    Returns the snapshot for immediate use.
    """
    global _prev_stat, _prev_diskstats, _prev_netdev, _prev_ts
    now = time.time()

    stat = _read_proc_stat()
    disk = _read_proc_diskstats()
    net = _read_proc_netdev()
    mem = hwinfo.read_meminfo()
    load = hwinfo.read_loadavg()
    up = hwinfo.read_uptime()
    fs = _read_filesystems()
    tcp = _count_tcp_established()

    # Calculate rates against previous sample
    dt = max(now - _prev_ts, 1.0) if _prev_ts else 1.0

    cpu_pct_idle = 0.0
    cpu_pct_user = 0.0
    cpu_pct_system = 0.0
    cpu_pct_iowait = 0.0
    cpu_pct_used = 0.0
    if _prev_stat and stat["cpu_total"]:
        prev = _prev_stat["cpu_total"]
        cur = stat["cpu_total"]
        total_delta = cur.get("total", 0) - prev.get("total", 0)
        if total_delta > 0:
            idle_delta = (cur.get("idle", 0) + cur.get("iowait", 0)) - (
                prev.get("idle", 0) + prev.get("iowait", 0)
            )
            cpu_pct_idle = 100.0 * idle_delta / total_delta
            cpu_pct_user = 100.0 * (cur.get("user", 0) - prev.get("user", 0)) / total_delta
            cpu_pct_system = (
                100.0 * (cur.get("system", 0) - prev.get("system", 0)) / total_delta
            )
            cpu_pct_iowait = (
                100.0 * (cur.get("iowait", 0) - prev.get("iowait", 0)) / total_delta
            )
            cpu_pct_used = 100.0 - cpu_pct_idle

    disk_rates: Dict[str, Dict[str, float]] = {}
    if _prev_diskstats:
        for name, cur in disk.items():
            prev = _prev_diskstats.get(name)
            if not prev:
                continue
            disk_rates[name] = {
                "reads_per_sec": max(0.0, (cur["reads"] - prev["reads"]) / dt),
                "writes_per_sec": max(0.0, (cur["writes"] - prev["writes"]) / dt),
                "read_bytes_per_sec": max(
                    0.0, (cur["read_bytes"] - prev["read_bytes"]) / dt
                ),
                "write_bytes_per_sec": max(
                    0.0, (cur["write_bytes"] - prev["write_bytes"]) / dt
                ),
            }

    net_rates: Dict[str, Dict[str, float]] = {}
    if _prev_netdev:
        for name, cur in net.items():
            prev = _prev_netdev.get(name)
            if not prev:
                continue
            net_rates[name] = {
                "rx_bytes_per_sec": max(0.0, (cur["rx_bytes"] - prev["rx_bytes"]) / dt),
                "tx_bytes_per_sec": max(0.0, (cur["tx_bytes"] - prev["tx_bytes"]) / dt),
                "rx_errs_per_sec": max(0.0, (cur["rx_errs"] - prev["rx_errs"]) / dt),
                "tx_errs_per_sec": max(0.0, (cur["tx_errs"] - prev["tx_errs"]) / dt),
                "rx_drop_per_sec": max(0.0, (cur["rx_drop"] - prev["rx_drop"]) / dt),
                "tx_drop_per_sec": max(0.0, (cur["tx_drop"] - prev["tx_drop"]) / dt),
            }

    snapshot = {
        "ts": now,
        "cpu": {
            "idle_pct": cpu_pct_idle,
            "user_pct": cpu_pct_user,
            "system_pct": cpu_pct_system,
            "iowait_pct": cpu_pct_iowait,
            "used_pct": cpu_pct_used,
            "raw": stat,
        },
        "load": load,
        "mem": mem,
        "uptime": up,
        "filesystems": fs,
        "disk_rates": disk_rates,
        "net_rates": net_rates,
        "tcp_established": tcp,
        "disk_raw": disk,
        "net_raw": net,
    }

    _prev_stat = stat
    _prev_diskstats = disk
    _prev_netdev = net
    _prev_ts = now

    _ring.append((now, snapshot))
    return snapshot


def latest() -> Optional[Dict[str, Any]]:
    if not _ring:
        return None
    return _ring[-1][1]


def ring_samples() -> List[Tuple[float, Dict[str, Any]]]:
    return list(_ring)


# ---------------------------------------------------------------------------
# Background sampler task
# ---------------------------------------------------------------------------


async def sampler_loop() -> None:
    """Async sampler — runs forever, sample every SAMPLE_INTERVAL_SECONDS."""
    LOG.info("local_stats: sampler loop starting")
    # Prime with one immediate sample so latest() never returns None
    try:
        sample_once()
    except Exception as exc:
        LOG.warning("local_stats: initial sample failed: {}", exc)
    while True:
        try:
            await asyncio.sleep(SAMPLE_INTERVAL_SECONDS)
            sample_once()
        except asyncio.CancelledError:
            LOG.info("local_stats: sampler loop cancelled")
            raise
        except Exception as exc:
            LOG.warning("local_stats: sample error: {}", exc)


def start_sampler() -> None:
    """Called from main.on_startup. Safe to call multiple times."""
    global _sampler_started
    with _sampler_lock:
        if _sampler_started:
            return
        _sampler_started = True
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(sampler_loop())
        LOG.info("local_stats: background sampler task scheduled")
    except Exception as exc:
        LOG.warning("local_stats: start_sampler failed: {}", exc)


# ---------------------------------------------------------------------------
# Infra service probes: MariaDB / RabbitMQ / Memcached
# These replace per-service Prometheus exporters on single-node deployments
# by querying the service admin/status endpoints directly via the internal
# VIP credentials baked into /etc/skyline/xavs_health_settings.yaml.
# ---------------------------------------------------------------------------

_INFRA_CACHE_TTL = 15
_infra_cache: Dict[str, Tuple[float, Any]] = {}


def _load_xavs_health_settings() -> Dict[str, Any]:
    """Read the Ansible-rendered settings file once and cache it."""
    cache_key = "xavs_health_settings"
    cached = _infra_cache.get(cache_key)
    if cached:
        return cached[1]
    path = "/etc/skyline/xavs_health_settings.yaml"
    data: Dict[str, Any] = {}
    try:
        import yaml  # type: ignore
        if os.path.exists(path):
            with open(path, "r") as fh:
                loaded = yaml.safe_load(fh) or {}
                if isinstance(loaded, dict):
                    data = loaded
    except Exception as exc:
        LOG.debug("local_stats: cannot read xavs_health_settings: {}", exc)
    _infra_cache[cache_key] = (time.time(), data)
    return data


def _probe_mariadb_status() -> Dict[str, Any]:
    """Query `SHOW GLOBAL STATUS` on MariaDB and return selected counters.

    Cached for _INFRA_CACHE_TTL seconds. Empty dict on any failure.
    """
    cache_key = "mariadb_status"
    now = time.time()
    cached = _infra_cache.get(cache_key)
    if cached and now - cached[0] < _INFRA_CACHE_TTL:
        return cached[1]

    out: Dict[str, Any] = {}
    settings = _load_xavs_health_settings()
    host = str(settings.get("mariadb_host") or "10.0.1.73")
    port = int(settings.get("mariadb_port") or 3306)
    user = str(settings.get("mariadb_user") or "root")
    password = settings.get("mariadb_password")
    if not password:
        _infra_cache[cache_key] = (now, out)
        return out

    try:
        import pymysql  # type: ignore
        conn = pymysql.connect(
            host=host, port=port, user=user,
            password=str(password),
            connect_timeout=2, read_timeout=2,
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW GLOBAL STATUS")
                rows = cur.fetchall()
        finally:
            conn.close()
        kv = {str(k): str(v) for k, v in rows if k}

        def _i(name: str) -> int:
            try:
                return int(kv.get(name, "0"))
            except (TypeError, ValueError):
                return 0

        out = {
            "uptime": _i("Uptime"),
            "threads_connected": _i("Threads_connected"),
            "threads_running": _i("Threads_running"),
            "slow_queries": _i("Slow_queries"),
            "com_select": _i("Com_select"),
            "com_insert": _i("Com_insert"),
            "com_update": _i("Com_update"),
            "com_delete": _i("Com_delete"),
            "questions": _i("Questions"),
            "queries": _i("Queries"),
        }
    except Exception as exc:
        LOG.debug("local_stats: mariadb probe failed: {}", exc)
    _infra_cache[cache_key] = (now, out)
    return out


def _probe_memcached_stats() -> Dict[str, Any]:
    """Send `stats\\r\\n` to memcached via TCP and parse the response."""
    cache_key = "memcached_stats"
    now = time.time()
    cached = _infra_cache.get(cache_key)
    if cached and now - cached[0] < _INFRA_CACHE_TTL:
        return cached[1]

    import socket
    out: Dict[str, Any] = {}
    settings = _load_xavs_health_settings()
    host = str(settings.get("memcached_host") or settings.get("mariadb_host") or "10.0.1.73")
    port = int(settings.get("memcached_port") or 11211)
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(b"stats\r\n")
            buf = b""
            deadline = time.time() + 2
            while b"END\r\n" not in buf and time.time() < deadline:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
        kv: Dict[str, str] = {}
        for line in buf.decode("ascii", errors="replace").splitlines():
            parts = line.strip().split(" ", 2)
            if len(parts) >= 3 and parts[0] == "STAT":
                kv[parts[1]] = parts[2]

        def _i(name: str) -> int:
            try:
                return int(kv.get(name, "0"))
            except (TypeError, ValueError):
                return 0

        out = {
            "curr_connections": _i("curr_connections"),
            "total_connections": _i("total_connections"),
            "curr_items": _i("curr_items"),
            "total_items": _i("total_items"),
            "bytes_read": _i("bytes_read"),
            "bytes_written": _i("bytes_written"),
            "evictions": _i("evictions"),
            "get_hits": _i("get_hits"),
            "get_misses": _i("get_misses"),
            "cmd_get": _i("cmd_get"),
            "cmd_set": _i("cmd_set"),
        }
    except Exception as exc:
        LOG.debug("local_stats: memcached probe failed: {}", exc)
    _infra_cache[cache_key] = (now, out)
    return out


def _probe_rabbitmq_overview() -> Dict[str, Any]:
    """Fetch /api/overview from the RabbitMQ management API."""
    cache_key = "rabbitmq_overview"
    now = time.time()
    cached = _infra_cache.get(cache_key)
    if cached and now - cached[0] < _INFRA_CACHE_TTL:
        return cached[1]

    out: Dict[str, Any] = {}
    settings = _load_xavs_health_settings()
    host = str(settings.get("rabbitmq_host") or "10.0.1.73")
    mgmt_port = int(settings.get("rabbitmq_mgmt_port") or 15672)
    user = str(settings.get("rabbitmq_user") or "openstack")
    password = settings.get("rabbitmq_password")
    mgmt_url = settings.get("rabbitmq_mgmt_url") or f"http://{host}:{mgmt_port}"
    if not password:
        _infra_cache[cache_key] = (now, out)
        return out

    try:
        import requests  # type: ignore
        resp = requests.get(
            f"{mgmt_url}/api/overview",
            auth=(user, str(password)),
            timeout=3,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json() or {}
            totals = data.get("object_totals") or {}
            qtotals = data.get("queue_totals") or {}
            mstats = data.get("message_stats") or {}
            out = {
                "connections": int(totals.get("connections") or 0),
                "channels": int(totals.get("channels") or 0),
                "queues": int(totals.get("queues") or 0),
                "exchanges": int(totals.get("exchanges") or 0),
                "consumers": int(totals.get("consumers") or 0),
                "messages": int(qtotals.get("messages") or 0),
                "messages_ready": int(qtotals.get("messages_ready") or 0),
                "messages_unacknowledged": int(qtotals.get("messages_unacknowledged") or 0),
                "publish_total": int(mstats.get("publish") or 0),
                "confirm_total": int(mstats.get("confirm") or 0),
                "deliver_total": int(mstats.get("deliver") or 0),
                "cluster_name": data.get("cluster_name") or "rabbit",
                "rabbitmq_version": data.get("rabbitmq_version") or "",
            }
    except Exception as exc:
        LOG.debug("local_stats: rabbitmq probe failed: {}", exc)
    _infra_cache[cache_key] = (now, out)
    return out


# ---------------------------------------------------------------------------
# Ceph (best-effort; silent if unavailable)
# ---------------------------------------------------------------------------


def _try_openstack_stats() -> Dict[str, Any]:
    """Pull cluster-wide stats from Nova + Cinder using skyline's system session.

    Cached for _OPENSTACK_CACHE_TTL seconds to avoid hammering the APIs.
    Every individual call is wrapped; failures return partial data or {}.
    """
    cache_key = "openstack_stats"
    now = time.time()
    cached = _openstack_cache.get(cache_key)
    if cached and now - cached[0] < _OPENSTACK_CACHE_TTL:
        return cached[1]

    out: Dict[str, Any] = {
        "nova_statistics": None,
        "nova_hypervisors": [],
        "nova_services": [],
        "cinder_pools": [],
    }

    try:
        from skyline_apiserver.client import utils as os_utils
        from skyline_apiserver.config import CONF

        session = os_utils.get_system_session()
        region = CONF.openstack.default_region
    except Exception as exc:
        LOG.debug("local_stats: openstack session unavailable: {}", exc)
        _openstack_cache[cache_key] = (now, out)
        return out

    # Nova hypervisor statistics + list
    try:
        from novaclient import client as nova_client_mod

        nc = nova_client_mod.Client(
            version="2.1",
            session=session,
            region_name=region,
            endpoint_type="internal",
        )
        try:
            stats = nc.hypervisor_stats.statistics()
            out["nova_statistics"] = stats.to_dict() if hasattr(stats, "to_dict") else dict(stats._info)
        except Exception as exc:
            LOG.debug("local_stats: nova hypervisor_stats failed: {}", exc)

        try:
            hvs = nc.hypervisors.list(detailed=True)
            hv_list = []
            for hv in hvs:
                d = hv.to_dict() if hasattr(hv, "to_dict") else dict(hv._info)
                hv_list.append(d)
            out["nova_hypervisors"] = hv_list
        except Exception as exc:
            LOG.debug("local_stats: nova hypervisors.list failed: {}", exc)

        try:
            services = nc.services.list()
            out["nova_services"] = [
                s.to_dict() if hasattr(s, "to_dict") else dict(s._info)
                for s in services
            ]
        except Exception as exc:
            LOG.debug("local_stats: nova services.list failed: {}", exc)
    except Exception as exc:
        LOG.debug("local_stats: nova client failed: {}", exc)

    # Cinder pools
    try:
        from cinderclient import client as cinder_client_mod

        cc = cinder_client_mod.Client(
            version="3",
            session=session,
            region_name=region,
            endpoint_type="internal",
        )
        try:
            pools = cc.pools.list(detailed=True)
            out["cinder_pools"] = [
                p.to_dict() if hasattr(p, "to_dict") else dict(p._info)
                for p in pools
            ]
        except Exception as exc:
            LOG.debug("local_stats: cinder pools.list failed: {}", exc)
    except Exception as exc:
        LOG.debug("local_stats: cinder client failed: {}", exc)

    _openstack_cache[cache_key] = (now, out)
    return out


def _tcp_reach(host: str, port: int, timeout: float = 1.5) -> bool:
    """Lightweight TCP reachability probe. Cached briefly."""
    import socket
    cache_key = f"tcp:{host}:{port}"
    now = time.time()
    cached = _openstack_cache.get(cache_key)
    if cached and now - cached[0] < 10:
        return cached[1]
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            _openstack_cache[cache_key] = (now, True)
            return True
    except OSError:
        _openstack_cache[cache_key] = (now, False)
        return False


def _try_neutron_agents() -> List[Dict[str, Any]]:
    """Fetch neutron agent list via skyline's system session. Cached."""
    cache_key = "neutron_agents"
    now = time.time()
    cached = _openstack_cache.get(cache_key)
    if cached and now - cached[0] < _OPENSTACK_CACHE_TTL:
        return cached[1]

    out: List[Dict[str, Any]] = []
    try:
        from skyline_apiserver.client import utils as os_utils
        from skyline_apiserver.config import CONF
        from neutronclient.v2_0 import client as neutron_client_mod

        session = os_utils.get_system_session()
        nc = neutron_client_mod.Client(
            session=session,
            region_name=CONF.openstack.default_region,
            endpoint_type="internal",
        )
        resp = nc.list_agents() or {}
        out = resp.get("agents") or []
    except Exception as exc:
        LOG.debug("local_stats: neutron agents fetch failed: {}", exc)
    _openstack_cache[cache_key] = (now, out)
    return out


def _try_cinder_services() -> List[Dict[str, Any]]:
    """Fetch cinder service list via system session. Cached."""
    cache_key = "cinder_services"
    now = time.time()
    cached = _openstack_cache.get(cache_key)
    if cached and now - cached[0] < _OPENSTACK_CACHE_TTL:
        return cached[1]

    out: List[Dict[str, Any]] = []
    try:
        from skyline_apiserver.client import utils as os_utils
        from skyline_apiserver.config import CONF
        from cinderclient import client as cinder_client_mod

        session = os_utils.get_system_session()
        cc = cinder_client_mod.Client(
            version="3",
            session=session,
            region_name=CONF.openstack.default_region,
            endpoint_type="internal",
        )
        services = cc.services.list()
        out = [
            s.to_dict() if hasattr(s, "to_dict") else dict(s._info)
            for s in services
        ]
    except Exception as exc:
        LOG.debug("local_stats: cinder services fetch failed: {}", exc)
    _openstack_cache[cache_key] = (now, out)
    return out


def _try_ceph_status() -> Optional[Dict[str, Any]]:
    cache_key = "ceph_status"
    now = time.time()
    cached = _openstack_cache.get(cache_key)
    if cached and now - cached[0] < _OPENSTACK_CACHE_TTL:
        return cached[1]
    if not os.path.exists("/etc/ceph/ceph.conf"):
        _openstack_cache[cache_key] = (now, None)
        return None
    try:
        r = subprocess.run(
            ["ceph", "-s", "--format", "json"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            _openstack_cache[cache_key] = (now, None)
            return None
        import json
        data = json.loads(r.stdout)
        _openstack_cache[cache_key] = (now, data)
        return data
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        _openstack_cache[cache_key] = (now, None)
        return None


# ---------------------------------------------------------------------------
# PromQL query resolver
# ---------------------------------------------------------------------------


def _make_sample(metric: Dict[str, str], value: float, ts: float) -> Dict[str, Any]:
    return {"metric": metric, "value": [ts, str(value)]}


def _make_range_sample(
    metric: Dict[str, str],
    values: List[Tuple[float, float]],
) -> Dict[str, Any]:
    return {
        "metric": metric,
        "values": [[ts, str(v)] for ts, v in values],
    }


def _empty_vector_response() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {"resultType": "vector", "result": []},
    }


def _empty_matrix_response() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {"resultType": "matrix", "result": []},
    }


def _vector(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {"resultType": "vector", "result": results},
    }


def _matrix(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {"resultType": "matrix", "result": results},
    }


def _hostname_label() -> Dict[str, str]:
    h = hwinfo.read_hostname()
    return {"instance": h, "hostname": h, "node": h}


_METRIC_NAME_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)(\{[^}]*\})?(\[[^\]]*\])?$")
_LABEL_KV_RE = re.compile(r'(\w+)\s*(=~?)\s*"([^"]*)"')


def _extract_metric_name(q: str) -> str:
    """Strip label matchers and time-range from a bare metric expression.

    `node_load1{hostname="xd3"}`  → `node_load1`
    `node_cpu_seconds_total{mode=~"idle|user"}[5m]`  → `node_cpu_seconds_total`
    `sum(...)` or anything non-trivial  → returned unchanged (caller handles).
    """
    m = _METRIC_NAME_RE.match(q)
    if m:
        return m.group(1)
    return q


def _extract_hostname_label(q: str) -> Optional[str]:
    """Pull `hostname="xdN"` or `instance="xdN"` out of a query string."""
    m = _METRIC_NAME_RE.match(q)
    if not m:
        return None
    labels = m.group(2)
    if not labels:
        return None
    for match in _LABEL_KV_RE.finditer(labels):
        key = match.group(1)
        op = match.group(2)
        val = match.group(3)
        if key in ("hostname", "instance", "node") and op == "=":
            return val
    return None


def _is_local_host(hostname: str) -> bool:
    """True if the hostname resolves to the apiserver's own node."""
    if not hostname:
        return True
    local = hwinfo.read_hostname()
    if not local:
        return False
    return hostname == local or hostname == local.split(".")[0]


def _resolve_remote(query: str, time_ts: float) -> Optional[Dict[str, Any]]:
    """If the query references a non-local host with node_exporter, fetch + answer.

    Returns a Prometheus-shaped response dict on hit, None if we should fall
    through to local /proc reading.
    """
    hostname = _extract_hostname_label(query)
    if not hostname or _is_local_host(hostname):
        return None

    metrics = node_exporter.fetch_for_hostname(hostname)
    if not metrics:
        return None

    bare = _extract_metric_name(query)
    if not bare:
        return None

    series = node_exporter.value_for_query(metrics, bare)
    if not series:
        return _empty_vector_response()

    results = []
    for s in series:
        labels = dict(s.get("labels") or {})
        labels["__name__"] = bare
        results.append(_make_sample(labels, s["value"], time_ts))
    return _vector(results)


def resolve_query(query: str, time_ts: Optional[float] = None) -> Dict[str, Any]:
    """Match a PromQL query string to a local value.

    Returns a Prometheus-shaped response. Unknown queries return empty.
    """
    q = (query or "").strip()
    if not q:
        return _empty_vector_response()

    now = time_ts or time.time()

    # Multi-node path: if the query targets a non-local hostname and
    # node_exporter is reachable on that host, answer from there.
    remote = _resolve_remote(q, now)
    if remote is not None:
        return remote

    snap = latest() or {}
    host_labels = _hostname_label()

    # Normalize: strip label matchers so `node_load1{hostname="xd3"}` hits
    # the same branch as `node_load1`. Wrapped queries (sum/avg/topk/irate)
    # keep their original form and are handled at the bottom.
    bare = _extract_metric_name(q)

    try:
        # node_load{1,5,15}
        if bare == "node_load1":
            v = snap.get("load", {}).get("load1", 0.0)
            return _vector([_make_sample({"__name__": "node_load1", **host_labels}, v, now)])
        if bare == "node_load5":
            v = snap.get("load", {}).get("load5", 0.0)
            return _vector([_make_sample({"__name__": "node_load5", **host_labels}, v, now)])
        if bare == "node_load15":
            v = snap.get("load", {}).get("load15", 0.0)
            return _vector([_make_sample({"__name__": "node_load15", **host_labels}, v, now)])

        # Memory
        mem = snap.get("mem", {})
        if bare == "node_memory_MemTotal_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemTotal_bytes", **host_labels},
                mem.get("MemTotal", 0), now)])
        if bare == "node_memory_MemAvailable_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemAvailable_bytes", **host_labels},
                mem.get("MemAvailable", 0), now)])
        if bare == "node_memory_MemFree_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemFree_bytes", **host_labels},
                mem.get("MemFree", 0), now)])
        if bare == "node_memory_Cached_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_Cached_bytes", **host_labels},
                mem.get("Cached", 0), now)])
        if bare == "node_memory_Buffers_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_Buffers_bytes", **host_labels},
                mem.get("Buffers", 0), now)])

        # Node DMI info (used by Server Model card)
        if bare == "node_dmi_info":
            dmi = hwinfo.read_dmi()
            labels = {
                "__name__": "node_dmi_info",
                "product_name": dmi.get("model") or "",
                "system_vendor": dmi.get("manufacturer") or "",
                "bios_version": dmi.get("bios_version") or "",
                **host_labels,
            }
            return _vector([_make_sample(labels, 1.0, now)])

        # CPU count
        if q.startswith("count(node_cpu_seconds_total"):
            cpu_info = hwinfo.read_cpuinfo()
            n = cpu_info.get("logical_cores", 0) or os.cpu_count() or 1
            return _vector([
                _make_sample({"__name__": "node_cpu_count", "cpu": str(i), **host_labels}, 1.0, now)
                for i in range(n)
            ])

        # node_boot_time_seconds
        if bare == "node_boot_time_seconds":
            return _vector([_make_sample(
                {"__name__": "node_boot_time_seconds", **host_labels},
                snap.get("uptime", {}).get("boot_time", now), now)])

        # Filesystem (size / avail / free). Disk Usage % chart wraps
        # these in `(1 - free / size) * 100` — match on substring so
        # the arithmetic expression still routes here.
        fs_key = None
        if "node_filesystem_avail_bytes" in q or "node_filesystem_free_bytes" in q:
            fs_key = "avail"
        elif "node_filesystem_size_bytes" in q:
            fs_key = "size"
        if fs_key:
            name = (
                "node_filesystem_size_bytes" if fs_key == "size"
                else "node_filesystem_avail_bytes"
            )
            results = []
            for fs in snap.get("filesystems", []):
                results.append(_make_sample(
                    {
                        "__name__": name,
                        "device": fs["device"],
                        "mountpoint": fs["mount"],
                        "fstype": fs["fstype"],
                        **host_labels,
                    },
                    fs["avail"] if fs_key == "avail" else fs["size"], now))
            return _vector(results)

        # Monitor Overview 'topHostMemoryUsage' query:
        # `topk(5, (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100)`
        # → return USED percent (0-100), one series per host.
        if (
            "node_memory_MemAvailable_bytes" in q
            and "node_memory_MemTotal_bytes" in q
            and "/" in q
        ):
            total = int(mem.get("MemTotal", 0))
            avail = int(mem.get("MemAvailable", 0))
            used_pct = 0.0 if total == 0 else max(0.0, min(100.0, (1.0 - avail / total) * 100.0))
            return _vector([_make_sample(
                {"__name__": "node_memory_used_percent", **host_labels},
                used_pct, now)])

        # PhysicalNode memory chart: `MemTotal - MemAvailable` → 'used' bytes.
        if (
            "node_memory_MemTotal_bytes" in q
            and "node_memory_MemAvailable_bytes" in q
            and "-" in q
            and "/" not in q
        ):
            used = max(0, int(mem.get("MemTotal", 0)) - int(mem.get("MemAvailable", 0)))
            return _vector([_make_sample(
                {"__name__": "node_memory_MemUsed_bytes", **host_labels},
                used, now)])

        # CPU usage chart sends `avg by (mode)(irate(node_cpu_seconds_total
        # {mode=~"idle|system|user|iowait"}[30m])) * 100`. Always emit all
        # 4 modes as percent (0-100) — that's what the upstream Prometheus
        # `* 100` would produce.
        if "node_cpu_seconds_total" in q:
            cpu = snap.get("cpu", {})
            results = []
            for mode, key in (("user", "user_pct"), ("system", "system_pct"),
                              ("iowait", "iowait_pct"), ("idle", "idle_pct")):
                results.append(_make_sample(
                    {"mode": mode, **host_labels},
                    cpu.get(key, 0.0), now))
            return _vector(results)

        # Detect whether the query wants per-instance aggregation
        # (Monitor Overview uses `topk(5, avg(...) by (instance))` so the
        # card shows one bar per host) vs per-device (PhysicalNode charts
        # show one line per disk/interface).
        by_instance = ("by (instance)" in q) or ("by(instance)" in q)

        # Disk IOPS
        if "node_disk_reads_completed_total" in q:
            rates_map = snap.get("disk_rates", {})
            if by_instance:
                total = sum(r["reads_per_sec"] for r in rates_map.values()) if rates_map else 0.0
                return _vector([_make_sample(
                    {"__name__": "node_disk_reads_per_sec", **host_labels},
                    total, now)])
            results = []
            for dev, rates in rates_map.items():
                results.append(_make_sample(
                    {"device": dev, **host_labels},
                    rates["reads_per_sec"], now))
            return _vector(results)
        if "node_disk_writes_completed_total" in q:
            rates_map = snap.get("disk_rates", {})
            if by_instance:
                total = sum(r["writes_per_sec"] for r in rates_map.values()) if rates_map else 0.0
                return _vector([_make_sample(
                    {"__name__": "node_disk_writes_per_sec", **host_labels},
                    total, now)])
            results = []
            for dev, rates in rates_map.items():
                results.append(_make_sample(
                    {"device": dev, **host_labels},
                    rates["writes_per_sec"], now))
            return _vector(results)

        # Network
        if "node_network_receive_bytes_total" in q:
            rates_map = snap.get("net_rates", {})
            if by_instance:
                total = sum(r["rx_bytes_per_sec"] for r in rates_map.values()) if rates_map else 0.0
                return _vector([_make_sample(
                    {"__name__": "node_network_rx_bytes_per_sec", **host_labels},
                    total, now)])
            results = []
            for iface, rates in rates_map.items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["rx_bytes_per_sec"], now))
            return _vector(results)
        if "node_network_transmit_bytes_total" in q:
            rates_map = snap.get("net_rates", {})
            if by_instance:
                total = sum(r["tx_bytes_per_sec"] for r in rates_map.values()) if rates_map else 0.0
                return _vector([_make_sample(
                    {"__name__": "node_network_tx_bytes_per_sec", **host_labels},
                    total, now)])
            results = []
            for iface, rates in rates_map.items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["tx_bytes_per_sec"], now))
            return _vector(results)
        if "node_network_receive_errs_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["rx_errs_per_sec"], now))
            return _vector(results)
        if "node_network_transmit_errs_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["tx_errs_per_sec"], now))
            return _vector(results)
        if "node_network_receive_drop_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["rx_drop_per_sec"], now))
            return _vector(results)
        if "node_network_transmit_drop_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["tx_drop_per_sec"], now))
            return _vector(results)

        # TCP connections
        if bare == "node_netstat_Tcp_CurrEstab":
            return _vector([_make_sample(
                {"__name__": "node_netstat_Tcp_CurrEstab", **host_labels},
                snap.get("tcp_established", 0), now)])

        # Ceph metrics (best-effort) — if Ceph isn't available, synthesize
        # from Cinder pool aggregates so single-node deployments without
        # Ceph still show real storage usage on the Monitor Overview page.
        if bare.startswith("ceph_"):
            ceph = _try_ceph_status()
            if ceph:
                stats = ceph.get("pgmap", {})
                if bare == "ceph_cluster_total_bytes":
                    v = stats.get("bytes_total", 0)
                    return _vector([_make_sample({"__name__": bare, **host_labels}, v, now)])
                if bare == "ceph_cluster_total_used_bytes":
                    v = stats.get("bytes_used", 0)
                    return _vector([_make_sample({"__name__": bare, **host_labels}, v, now)])
                if bare == "ceph_health_status":
                    h = ceph.get("health", {}).get("status", "HEALTH_UNKNOWN")
                    v = {"HEALTH_OK": 0, "HEALTH_WARN": 1, "HEALTH_ERR": 2}.get(h, 3)
                    return _vector([_make_sample({"__name__": bare, "status": h, **host_labels}, v, now)])
                return _empty_vector_response()

            # No Ceph → derive from Cinder pool totals. Monitor Overview's
            # "Physical Storage Usage" card uses these two metrics; showing
            # Cinder LVM/iSCSI/Ceph-RBD pool usage here is accurate.
            pools = (_try_openstack_stats().get("cinder_pools") or [])
            total_gb = 0.0
            free_gb = 0.0
            for p in pools:
                caps = p.get("capabilities") or {}
                try:
                    t = float(caps.get("total_capacity_gb") or 0)
                except (TypeError, ValueError):
                    t = 0.0
                try:
                    f = float(caps.get("free_capacity_gb") or 0)
                except (TypeError, ValueError):
                    f = 0.0
                total_gb += t
                free_gb += f
            gib = 1024 ** 3
            total_bytes = int(total_gb * gib)
            used_bytes = int(max(0.0, total_gb - free_gb) * gib)
            if bare == "ceph_cluster_total_bytes":
                return _vector([_make_sample(
                    {"__name__": bare, "source": "cinder", **host_labels},
                    total_bytes, now)])
            if bare == "ceph_cluster_total_used_bytes":
                return _vector([_make_sample(
                    {"__name__": bare, "source": "cinder", **host_labels},
                    used_bytes, now)])
            if bare == "ceph_health_status":
                return _empty_vector_response()
            return _empty_vector_response()

        # Neutron / Cinder agent state — query OpenStack APIs directly via
        # the system session and return 1=up, 0=down per agent/service.
        if bare == "openstack_neutron_agent_state":
            agents = _try_neutron_agents()
            results = []
            for a in agents:
                state_val = 1.0 if a.get("alive") else 0.0
                results.append(_make_sample(
                    {
                        "__name__": bare,
                        "service": a.get("binary", ""),
                        "hostname": a.get("host", ""),
                        "adminState": "enabled" if a.get("admin_state_up") else "disabled",
                    },
                    state_val, now))
            return _vector(results)
        if bare == "openstack_cinder_agent_state":
            services = _try_cinder_services()
            results = []
            for s in services:
                state_val = 1.0 if s.get("state") == "up" else 0.0
                admin_state = "enabled" if s.get("state") == "up" else "disabled"
                results.append(_make_sample(
                    {
                        "__name__": bare,
                        "service": s.get("binary", ""),
                        "hostname": s.get("host", ""),
                        "adminState": admin_state,
                    },
                    state_val, now))
            return _vector(results)

        # Basic service up/down probes for Other Services page. Each
        # returns 1.0 if the backing service is TCP-reachable, else 0.
        if bare == "mysql_up":
            up = 1.0 if _tcp_reach("10.0.1.73", 3306) else 0.0
            return _vector([_make_sample(
                {"__name__": bare, "instance": "mariadb", **host_labels},
                up, now)])
        if bare == "memcached_up":
            up = 1.0 if _tcp_reach("10.0.1.73", 11211) else 0.0
            return _vector([_make_sample(
                {"__name__": bare, "instance": "memcached", **host_labels},
                up, now)])
        if bare == "rabbitmq_identity_info":
            up = 1.0 if _tcp_reach("10.0.1.73", 5672) else 0.0
            return _vector([_make_sample(
                {"__name__": bare, "rabbitmq_cluster": "rabbit", "rabbitmq_node": "rabbit@xd3", **host_labels},
                up, now)])

        # MySQL detail metrics — pull from live `SHOW GLOBAL STATUS` on the
        # internal VIP. Mapping matches mysqld_exporter metric names.
        if bare.startswith("mysql_global_status_"):
            m = _probe_mariadb_status()
            if not m:
                return _empty_vector_response()
            mysql_labels = {"instance": "mariadb", **host_labels}
            if bare == "mysql_global_status_uptime":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("uptime", 0), now)])
            if bare == "mysql_global_status_threads_connected":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("threads_connected", 0), now)])
            if bare == "mysql_global_status_threads_running":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("threads_running", 0), now)])
            if bare == "mysql_global_status_slow_queries":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("slow_queries", 0), now)])
            if bare == "mysql_global_status_commands_total":
                cmd_map = {
                    "select": "com_select",
                    "insert": "com_insert",
                    "update": "com_update",
                    "delete": "com_delete",
                }
                cmd_filter = None
                cmd_match = re.search(r'command\s*=\s*"([^"]+)"', q)
                if cmd_match:
                    cmd_filter = cmd_match.group(1)
                results = []
                for cmd, key in cmd_map.items():
                    if cmd_filter and cmd != cmd_filter:
                        continue
                    results.append(_make_sample(
                        {"__name__": bare, "command": cmd, **mysql_labels},
                        m.get(key, 0), now))
                return _vector(results)
            if bare == "mysql_global_status_questions":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("questions", 0), now)])
            if bare == "mysql_global_status_queries":
                return _vector([_make_sample(
                    {"__name__": bare, **mysql_labels}, m.get("queries", 0), now)])
            return _empty_vector_response()

        # Memcached detail metrics — pull from live `stats` TCP probe.
        if bare.startswith("memcached_") and bare != "memcached_up":
            mc = _probe_memcached_stats()
            if not mc:
                return _empty_vector_response()
            mc_labels = {"instance": "memcached", **host_labels}
            mapping = {
                "memcached_current_connections": "curr_connections",
                "memcached_connections_total": "total_connections",
                "memcached_current_items": "curr_items",
                "memcached_items_total": "total_items",
                "memcached_read_bytes_total": "bytes_read",
                "memcached_written_bytes_total": "bytes_written",
                "memcached_slab_items_evicted_unfetched_total": "evictions",
                "memcached_commands_total": "cmd_get",
            }
            key = mapping.get(bare)
            if key is None:
                return _empty_vector_response()
            return _vector([_make_sample(
                {"__name__": bare, **mc_labels}, mc.get(key, 0), now)])

        # RabbitMQ detail metrics — pull from /api/overview on the
        # management API. Mapping matches rabbitmq_exporter metric names.
        if (
            (bare.startswith("rabbitmq_") and bare != "rabbitmq_identity_info")
            or bare.startswith("erlang_mnesia_")
        ):
            rb = _probe_rabbitmq_overview()
            if not rb:
                return _empty_vector_response()
            rb_labels = {
                "rabbitmq_cluster": rb.get("cluster_name", "rabbit"),
                "rabbitmq_node": f"rabbit@{hwinfo.read_hostname()}",
                **host_labels,
            }
            mapping = {
                "rabbitmq_connections": "connections",
                "rabbitmq_connections_opened_total": "connections",
                "rabbitmq_channels": "channels",
                "rabbitmq_queues": "queues",
                "rabbitmq_queues_created_total": "queues",
                "rabbitmq_exchanges": "exchanges",
                "erlang_mnesia_tablewise_size": "exchanges",
                "rabbitmq_queue_consumers": "consumers",
                "rabbitmq_queue_messages": "messages",
                "rabbitmq_queue_messages_ready": "messages_ready",
                "rabbitmq_queue_messages_unacked": "messages_unacknowledged",
                "rabbitmq_channel_messages_published_total": "publish_total",
                "rabbitmq_channel_messages_confirmed_total": "confirm_total",
                "rabbitmq_channel_messages_delivered_total": "deliver_total",
            }
            key = mapping.get(bare)
            if key is None:
                return _empty_vector_response()
            return _vector([_make_sample(
                {"__name__": bare, **rb_labels}, rb.get(key, 0), now)])

        # OpenStack metrics — live from Nova hypervisor-statistics + services
        if bare.startswith("openstack_nova_") or bare.startswith("os_cinder"):
            os_stats = _try_openstack_stats()
            stats = os_stats.get("nova_statistics") or {}
            pools = os_stats.get("cinder_pools") or []
            services = os_stats.get("nova_services") or []

            if bare == "openstack_nova_vcpus_used":
                return _vector([_make_sample(
                    {"__name__": bare, **host_labels},
                    stats.get("vcpus_used", 0), now)])
            if bare == "openstack_nova_vcpus_available":
                total = stats.get("vcpus", 0)
                used = stats.get("vcpus_used", 0)
                return _vector([_make_sample(
                    {"__name__": bare, **host_labels},
                    max(0, total - used), now)])
            if bare == "openstack_nova_memory_used_bytes":
                mb = stats.get("memory_mb_used", 0)
                return _vector([_make_sample(
                    {"__name__": bare, **host_labels},
                    int(mb) * 1024 * 1024, now)])
            if bare == "openstack_nova_memory_available_bytes":
                mb = stats.get("free_ram_mb", 0)
                return _vector([_make_sample(
                    {"__name__": bare, **host_labels},
                    int(mb) * 1024 * 1024, now)])
            if bare == "openstack_nova_agent_state":
                results = []
                for s in services:
                    if s.get("binary") != "nova-compute":
                        continue
                    state_val = 1.0 if s.get("state") == "up" else 0.0
                    results.append(_make_sample(
                        {
                            "__name__": bare,
                            "service": s.get("binary", ""),
                            "hostname": s.get("host", ""),
                            "instance": s.get("host", ""),
                        },
                        state_val, now))
                return _vector(results)
            if bare == "os_cinder_volume_pools_total_capacity_gb":
                results = []
                for p in pools:
                    caps = p.get("capabilities") or {}
                    cap = caps.get("total_capacity_gb")
                    try:
                        v = float(cap) if cap is not None else 0.0
                    except (TypeError, ValueError):
                        v = 0.0
                    results.append(_make_sample(
                        {
                            "__name__": bare,
                            "pool": p.get("name", ""),
                            "backend": caps.get("volume_backend_name", ""),
                        },
                        v, now))
                return _vector(results)
            if bare == "os_cinder_volume_pools_free_capacity_gb":
                results = []
                for p in pools:
                    caps = p.get("capabilities") or {}
                    cap = caps.get("free_capacity_gb")
                    try:
                        v = float(cap) if cap is not None else 0.0
                    except (TypeError, ValueError):
                        v = 0.0
                    results.append(_make_sample(
                        {
                            "__name__": bare,
                            "pool": p.get("name", ""),
                            "backend": caps.get("volume_backend_name", ""),
                        },
                        v, now))
                return _vector(results)
            return _empty_vector_response()

        # topk / sum / avg / irate / rate wrappers — strip outer call and
        # recurse on the inner expression.
        m = re.match(
            r"(?:topk|sum|avg|irate|rate|increase|max|min)"
            r"\s*\(\s*(?:\d+\s*,\s*)?([^\[]+?)(?:\[[^\]]*\])?\s*\)",
            q,
        )
        if m:
            inner = m.group(1)
            return resolve_query(inner, now)

        LOG.debug("local_stats: unknown query: {}", q)
        return _empty_vector_response()
    except Exception as exc:
        LOG.warning("local_stats: resolve_query error for {}: {}", q, exc)
        return _empty_vector_response()


def resolve_query_range(
    query: str,
    start_ts: float,
    end_ts: float,
    step_seconds: float,
) -> Dict[str, Any]:
    """Build a time-series response from the ring buffer.

    For each known metric, walk the ring buffer and emit a point per sample
    whose timestamp is within [start_ts, end_ts]. Downsamples naturally
    because the ring buffer samples at SAMPLE_INTERVAL_SECONDS granularity.
    """
    q = (query or "").strip()
    if not q:
        return _empty_matrix_response()

    # Normalize: strip label matchers / time ranges so exact-match
    # branches below work the same way as resolve_query.
    bare = _extract_metric_name(q)

    samples = [s for s in ring_samples() if start_ts <= s[0] <= end_ts]
    if not samples:
        # No history yet — return current value as single-point series
        vec = resolve_query(q, end_ts)
        if not vec.get("data", {}).get("result"):
            return _empty_matrix_response()
        converted = []
        for r in vec["data"]["result"]:
            converted.append({
                "metric": r["metric"],
                "values": [r["value"]],
            })
        return _matrix(converted)

    host_labels = _hostname_label()

    def _series(extract: Callable[[Dict[str, Any]], float],
                metric_labels: Dict[str, str]) -> List[Dict[str, Any]]:
        values: List[List[Any]] = []
        for ts, snap in samples:
            try:
                values.append([ts, str(extract(snap))])
            except Exception:
                continue
        return [{"metric": metric_labels, "values": values}]

    try:
        if bare == "node_load1":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load1", 0.0),
                {"__name__": "node_load1", **host_labels}))
        if bare == "node_load5":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load5", 0.0),
                {"__name__": "node_load5", **host_labels}))
        if bare == "node_load15":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load15", 0.0),
                {"__name__": "node_load15", **host_labels}))

        # Memory Usage chart sends
        # `node_memory_MemTotal_bytes{...} - node_memory_MemAvailable_bytes{...}`
        # for the 'used' series and plain `node_memory_MemAvailable_bytes`
        # for the 'available' series. Match the subtraction pattern first.
        if (
            "node_memory_MemTotal_bytes" in q
            and "node_memory_MemAvailable_bytes" in q
            and "-" in q
        ):
            return _matrix(_series(
                lambda s: max(
                    0,
                    int(s.get("mem", {}).get("MemTotal", 0))
                    - int(s.get("mem", {}).get("MemAvailable", 0)),
                ),
                {"__name__": "node_memory_MemUsed_bytes", **host_labels}))

        if bare == "node_memory_MemTotal_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemTotal", 0),
                {"__name__": bare, **host_labels}))
        if bare == "node_memory_MemAvailable_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemAvailable", 0),
                {"__name__": bare, **host_labels}))
        if bare == "node_memory_MemFree_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemFree", 0),
                {"__name__": bare, **host_labels}))
        if bare == "node_memory_Cached_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("Cached", 0),
                {"__name__": bare, **host_labels}))
        if bare == "node_memory_Buffers_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("Buffers", 0),
                {"__name__": bare, **host_labels}))

        # CPU Usage chart query is
        # `avg by (mode)(irate(node_cpu_seconds_total{...}[30m])) * 100`.
        # Always emit all 4 modes — Prometheus would return a series per
        # mode label; the frontend treats it as percent (0-100).
        if "node_cpu_seconds_total" in q:
            out = []
            for mode, key in (
                ("user", "user_pct"),
                ("system", "system_pct"),
                ("iowait", "iowait_pct"),
                ("idle", "idle_pct"),
            ):
                out.extend(_series(
                    lambda s, k=key: s.get("cpu", {}).get(k, 0.0),
                    {"mode": mode, **host_labels}))
            return _matrix(out)

        # Filesystem (size/avail/free). Disk Usage % chart wraps these
        # in (1 - free / size) * 100 — so also match when the query
        # just CONTAINS one of these metric names.
        fs_flag = None
        if "node_filesystem_avail_bytes" in q or "node_filesystem_free_bytes" in q:
            fs_flag = "avail"
        elif "node_filesystem_size_bytes" in q:
            fs_flag = "size"
        if fs_flag:
            out = []
            fss = set()
            for _, snap in samples:
                for fs in snap.get("filesystems", []):
                    fss.add((fs["device"], fs["mount"], fs["fstype"]))
            for dev, mnt, fstype in fss:
                def _get(s, d=dev, m=mnt, which=fs_flag):
                    for fs in s.get("filesystems", []):
                        if fs["device"] == d and fs["mount"] == m:
                            return fs["avail"] if which == "avail" else fs["size"]
                    return 0
                out.extend(_series(
                    _get,
                    {
                        "__name__": (
                            "node_filesystem_size_bytes" if fs_flag == "size"
                            else "node_filesystem_avail_bytes"
                        ),
                        "device": dev,
                        "mountpoint": mnt,
                        "fstype": fstype,
                        **host_labels,
                    }))
            return _matrix(out)

        # Disk IOPS
        if "node_disk_reads_completed_total" in q:
            devs = set()
            for _, s in samples:
                devs.update(s.get("disk_rates", {}).keys())
            out = []
            for dev in devs:
                out.extend(_series(
                    lambda s, d=dev: s.get("disk_rates", {}).get(d, {}).get("reads_per_sec", 0.0),
                    {"device": dev, **host_labels}))
            return _matrix(out)
        if "node_disk_writes_completed_total" in q:
            devs = set()
            for _, s in samples:
                devs.update(s.get("disk_rates", {}).keys())
            out = []
            for dev in devs:
                out.extend(_series(
                    lambda s, d=dev: s.get("disk_rates", {}).get(d, {}).get("writes_per_sec", 0.0),
                    {"device": dev, **host_labels}))
            return _matrix(out)

        # Network
        for needle, rate_key in (
            ("node_network_receive_bytes_total", "rx_bytes_per_sec"),
            ("node_network_transmit_bytes_total", "tx_bytes_per_sec"),
            ("node_network_receive_errs_total", "rx_errs_per_sec"),
            ("node_network_transmit_errs_total", "tx_errs_per_sec"),
            ("node_network_receive_drop_total", "rx_drop_per_sec"),
            ("node_network_transmit_drop_total", "tx_drop_per_sec"),
        ):
            if needle in q:
                ifaces = set()
                for _, s in samples:
                    ifaces.update(s.get("net_rates", {}).keys())
                out = []
                for iface in ifaces:
                    out.extend(_series(
                        lambda s, i=iface, rk=rate_key:
                            s.get("net_rates", {}).get(i, {}).get(rk, 0.0),
                        {"device": iface, **host_labels}))
                return _matrix(out)

        if bare == "node_netstat_Tcp_CurrEstab":
            return _matrix(_series(
                lambda s: s.get("tcp_established", 0),
                {"__name__": q, **host_labels}))

        # MySQL / Memcached / RabbitMQ — no historical ring-buffer entries
        # for these (they're probed on demand, not sampled). Replay the
        # current value at each sample timestamp so the chart draws a line.
        if (
            bare.startswith("mysql_global_status_")
            or (bare.startswith("memcached_") and bare != "memcached_up")
            or (bare.startswith("rabbitmq_") and bare != "rabbitmq_identity_info")
            or bare.startswith("erlang_mnesia_")
        ):
            vec = resolve_query(q, end_ts)
            result = vec.get("data", {}).get("result") or []
            out = []
            for r in result:
                ts_values = [[ts, r["value"][1]] for ts, _ in samples]
                out.append({"metric": r["metric"], "values": ts_values})
            return _matrix(out)

        # Unwrap topk/sum/avg
        m = re.match(r"(?:topk|sum|avg)\s*\(\s*(?:\d+\s*,\s*)?(.+)\s*\)", q)
        if m:
            return resolve_query_range(m.group(1), start_ts, end_ts, step_seconds)

        LOG.debug("local_stats: unknown range query: {}", q)
        return _empty_matrix_response()
    except Exception as exc:
        LOG.warning("local_stats: resolve_query_range error for {}: {}", q, exc)
        return _empty_matrix_response()
