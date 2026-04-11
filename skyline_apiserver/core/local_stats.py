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

from skyline_apiserver.core import hwinfo
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
    """Read /proc/mounts and statvfs each real mount."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
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
                if mount in seen:
                    continue
                seen.add(mount)
                try:
                    st = os.statvfs(mount)
                    total = st.f_blocks * st.f_frsize
                    free = st.f_bavail * st.f_frsize
                    if total == 0:
                        continue
                    out.append({
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
# Ceph (best-effort; silent if unavailable)
# ---------------------------------------------------------------------------


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


def resolve_query(query: str, time_ts: Optional[float] = None) -> Dict[str, Any]:
    """Match a PromQL query string to a local value.

    Returns a Prometheus-shaped response. Unknown queries return empty.
    """
    q = (query or "").strip()
    if not q:
        return _empty_vector_response()

    now = time_ts or time.time()
    snap = latest() or {}
    host_labels = _hostname_label()

    try:
        # node_load{1,5,15}
        if q == "node_load1":
            v = snap.get("load", {}).get("load1", 0.0)
            return _vector([_make_sample({"__name__": "node_load1", **host_labels}, v, now)])
        if q == "node_load5":
            v = snap.get("load", {}).get("load5", 0.0)
            return _vector([_make_sample({"__name__": "node_load5", **host_labels}, v, now)])
        if q == "node_load15":
            v = snap.get("load", {}).get("load15", 0.0)
            return _vector([_make_sample({"__name__": "node_load15", **host_labels}, v, now)])

        # Memory
        mem = snap.get("mem", {})
        if q == "node_memory_MemTotal_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemTotal_bytes", **host_labels},
                mem.get("MemTotal", 0), now)])
        if q == "node_memory_MemAvailable_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemAvailable_bytes", **host_labels},
                mem.get("MemAvailable", 0), now)])
        if q == "node_memory_MemFree_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_MemFree_bytes", **host_labels},
                mem.get("MemFree", 0), now)])
        if q == "node_memory_Cached_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_Cached_bytes", **host_labels},
                mem.get("Cached", 0), now)])
        if q == "node_memory_Buffers_bytes":
            return _vector([_make_sample(
                {"__name__": "node_memory_Buffers_bytes", **host_labels},
                mem.get("Buffers", 0), now)])

        # Node DMI info (used by Server Model card)
        if q.startswith("node_dmi_info"):
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
        if q == "node_boot_time_seconds":
            return _vector([_make_sample(
                {"__name__": "node_boot_time_seconds", **host_labels},
                snap.get("uptime", {}).get("boot_time", now), now)])

        # Filesystem
        if q.startswith("node_filesystem_avail_bytes"):
            results = []
            for fs in snap.get("filesystems", []):
                results.append(_make_sample(
                    {
                        "__name__": "node_filesystem_avail_bytes",
                        "device": fs["device"],
                        "mountpoint": fs["mount"],
                        "fstype": fs["fstype"],
                        **host_labels,
                    },
                    fs["avail"], now))
            return _vector(results)
        if q.startswith("node_filesystem_size_bytes"):
            results = []
            for fs in snap.get("filesystems", []):
                results.append(_make_sample(
                    {
                        "__name__": "node_filesystem_size_bytes",
                        "device": fs["device"],
                        "mountpoint": fs["mount"],
                        "fstype": fs["fstype"],
                        **host_labels,
                    },
                    fs["size"], now))
            return _vector(results)

        # CPU usage (used by cpu chart)
        if "node_cpu_seconds_total" in q and "idle" in q:
            idle_frac = max(0.0, min(1.0, snap.get("cpu", {}).get("idle_pct", 100.0) / 100.0))
            return _vector([_make_sample(
                {"mode": "idle", **host_labels}, idle_frac, now)])
        if "node_cpu_seconds_total" in q:
            cpu = snap.get("cpu", {})
            results = []
            for mode, key in (("user", "user_pct"), ("system", "system_pct"),
                              ("iowait", "iowait_pct"), ("idle", "idle_pct")):
                results.append(_make_sample(
                    {"mode": mode, **host_labels}, cpu.get(key, 0.0) / 100.0, now))
            return _vector(results)

        # Disk IOPS
        if "node_disk_reads_completed_total" in q:
            results = []
            for dev, rates in snap.get("disk_rates", {}).items():
                results.append(_make_sample(
                    {"device": dev, **host_labels},
                    rates["reads_per_sec"], now))
            return _vector(results)
        if "node_disk_writes_completed_total" in q:
            results = []
            for dev, rates in snap.get("disk_rates", {}).items():
                results.append(_make_sample(
                    {"device": dev, **host_labels},
                    rates["writes_per_sec"], now))
            return _vector(results)

        # Network
        if "node_network_receive_bytes_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
                results.append(_make_sample(
                    {"device": iface, **host_labels},
                    rates["rx_bytes_per_sec"], now))
            return _vector(results)
        if "node_network_transmit_bytes_total" in q:
            results = []
            for iface, rates in snap.get("net_rates", {}).items():
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
        if q == "node_netstat_Tcp_CurrEstab":
            return _vector([_make_sample(
                {"__name__": "node_netstat_Tcp_CurrEstab", **host_labels},
                snap.get("tcp_established", 0), now)])

        # Ceph metrics (best-effort)
        if q.startswith("ceph_"):
            ceph = _try_ceph_status()
            if not ceph:
                return _empty_vector_response()
            stats = ceph.get("pgmap", {})
            if q == "ceph_cluster_total_bytes":
                v = stats.get("bytes_total", 0)
                return _vector([_make_sample({"__name__": q, **host_labels}, v, now)])
            if q == "ceph_cluster_total_used_bytes":
                v = stats.get("bytes_used", 0)
                return _vector([_make_sample({"__name__": q, **host_labels}, v, now)])
            if q == "ceph_health_status":
                h = ceph.get("health", {}).get("status", "HEALTH_UNKNOWN")
                # map to prometheus-style numeric
                v = {"HEALTH_OK": 0, "HEALTH_WARN": 1, "HEALTH_ERR": 2}.get(h, 3)
                return _vector([_make_sample({"__name__": q, "status": h, **host_labels}, v, now)])
            return _empty_vector_response()

        # OpenStack metrics — left for future; not wired into clients yet
        # because they need authenticated keystone session per-request.
        if q.startswith("openstack_") or q.startswith("os_cinder"):
            return _empty_vector_response()

        # topk / sum / avg wrappers — just strip and try inner if possible
        m = re.match(r"(?:topk|sum|avg)\s*\(\s*(?:\d+\s*,\s*)?(.+)\s*\)", q)
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
        if q == "node_load1":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load1", 0.0),
                {"__name__": "node_load1", **host_labels}))
        if q == "node_load5":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load5", 0.0),
                {"__name__": "node_load5", **host_labels}))
        if q == "node_load15":
            return _matrix(_series(
                lambda s: s.get("load", {}).get("load15", 0.0),
                {"__name__": "node_load15", **host_labels}))

        if q == "node_memory_MemTotal_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemTotal", 0),
                {"__name__": q, **host_labels}))
        if q == "node_memory_MemAvailable_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemAvailable", 0),
                {"__name__": q, **host_labels}))
        if q == "node_memory_MemFree_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("MemFree", 0),
                {"__name__": q, **host_labels}))
        if q == "node_memory_Cached_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("Cached", 0),
                {"__name__": q, **host_labels}))
        if q == "node_memory_Buffers_bytes":
            return _matrix(_series(
                lambda s: s.get("mem", {}).get("Buffers", 0),
                {"__name__": q, **host_labels}))

        if "node_cpu_seconds_total" in q and "idle" in q:
            return _matrix(_series(
                lambda s: max(0.0, min(1.0, s.get("cpu", {}).get("idle_pct", 100.0) / 100.0)),
                {"mode": "idle", **host_labels}))
        if "node_cpu_seconds_total" in q:
            # emit all 4 modes as separate series
            out = []
            for mode, key in (("user", "user_pct"), ("system", "system_pct"),
                              ("iowait", "iowait_pct"), ("idle", "idle_pct")):
                out.extend(_series(
                    lambda s, k=key: s.get("cpu", {}).get(k, 0.0) / 100.0,
                    {"mode": mode, **host_labels}))
            return _matrix(out)

        # Filesystem (just static over time)
        if q.startswith("node_filesystem_avail_bytes") or q.startswith("node_filesystem_size_bytes"):
            # Repeat latest value across the range
            vec = resolve_query(q, end_ts)
            converted = []
            for r in vec.get("data", {}).get("result", []):
                vals = [[ts, r["value"][1]] for ts, _ in samples]
                converted.append({"metric": r["metric"], "values": vals})
            return _matrix(converted)

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

        if q == "node_netstat_Tcp_CurrEstab":
            return _matrix(_series(
                lambda s: s.get("tcp_established", 0),
                {"__name__": q, **host_labels}))

        # Unwrap topk/sum/avg
        m = re.match(r"(?:topk|sum|avg)\s*\(\s*(?:\d+\s*,\s*)?(.+)\s*\)", q)
        if m:
            return resolve_query_range(m.group(1), start_ts, end_ts, step_seconds)

        LOG.debug("local_stats: unknown range query: {}", q)
        return _empty_matrix_response()
    except Exception as exc:
        LOG.warning("local_stats: resolve_query_range error for {}: {}", q, exc)
        return _empty_matrix_response()
