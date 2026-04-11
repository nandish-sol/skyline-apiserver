# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Fetch + parse Prometheus node_exporter metrics from cluster hosts.

On production clusters (XD1/XD2/XD5) every node runs node_exporter on
port 9100 (deployed by cephadm as part of the Ceph cluster). This module
lets skyline-apiserver answer PromQL queries by HTTP-fetching the target
host's /metrics endpoint and parsing the text format, avoiding the need
for a central Prometheus or a new per-node agent.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from skyline_apiserver.log import LOG

# Prometheus text-format line: metric{label="val",...} value [timestamp]
# Labels are optional. Value can be a float, NaN, +Inf, -Inf.
_METRIC_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+(?P<value>[-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?|NaN|[+-]?Inf))"
    r"(?:\s+\d+)?\s*$"
)

# label="val" — values may contain escaped quotes and backslashes
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')

# How long to cache a single host's /metrics response
_METRICS_CACHE_TTL = 15  # seconds
_HOST_MAP_CACHE_TTL = 300  # 5 minutes

_metrics_cache: Dict[str, Tuple[float, Dict[str, List[Dict[str, Any]]]]] = {}
_host_map_cache: Optional[Tuple[float, Dict[str, str]]] = None


# ---------------------------------------------------------------------------
# Text-format parser
# ---------------------------------------------------------------------------


def parse_prometheus_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parse Prometheus text format into {metric_name: [{labels, value}, ...]}.

    Comments (# HELP, # TYPE) are skipped. Non-finite values (NaN, +Inf,
    -Inf) are skipped because they can't be JSON-encoded in the response.
    """
    out: Dict[str, List[Dict[str, Any]]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _METRIC_LINE_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        labels_str = m.group("labels") or ""
        value_str = m.group("value")
        if value_str in ("NaN", "+Inf", "-Inf", "Inf"):
            continue
        try:
            value = float(value_str)
        except ValueError:
            continue
        labels = {}
        for lm in _LABEL_RE.finditer(labels_str):
            labels[lm.group(1)] = lm.group(2).replace('\\"', '"').replace("\\\\", "\\")
        out.setdefault(name, []).append({"labels": labels, "value": value})
    return out


# ---------------------------------------------------------------------------
# Host → IP resolver
# ---------------------------------------------------------------------------


def _resolve_host_map() -> Dict[str, str]:
    """Build a map of hostname → IP address.

    Priority order:
    1. Nova hypervisors.list() — `hypervisor_hostname` → `host_ip`
    2. /etc/hosts entries starting with 10.0.1.* (cluster internal net)
    3. Local hostname → 127.0.0.1 fallback

    Cached for _HOST_MAP_CACHE_TTL seconds.
    """
    global _host_map_cache
    now = time.time()
    if _host_map_cache and now - _host_map_cache[0] < _HOST_MAP_CACHE_TTL:
        return _host_map_cache[1]

    host_map: Dict[str, str] = {}

    # Nova hypervisors (the authoritative source for compute hosts)
    try:
        from skyline_apiserver.client import utils as os_utils
        from skyline_apiserver.config import CONF

        session = os_utils.get_system_session()
        from novaclient import client as nova_client_mod

        nc = nova_client_mod.Client(
            version="2.1",
            session=session,
            region_name=CONF.openstack.default_region,
            endpoint_type="internal",
        )
        hvs = nc.hypervisors.list(detailed=True)
        for hv in hvs:
            d = hv.to_dict() if hasattr(hv, "to_dict") else dict(hv._info)
            hostname = d.get("hypervisor_hostname") or (
                d.get("service") or {}
            ).get("host")
            ip = d.get("host_ip")
            if hostname and ip:
                host_map[hostname] = ip
                # Also register the short hostname
                short = hostname.split(".")[0]
                if short != hostname:
                    host_map[short] = ip
    except Exception as exc:
        LOG.debug("node_exporter: nova hypervisor list failed: {}", exc)

    # /etc/hosts — pick up cluster nodes that aren't compute hypervisors
    try:
        with open("/etc/hosts") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) < 2 or parts[0].startswith("#"):
                    continue
                ip = parts[0]
                if not ip.startswith("10.0.") and not ip.startswith("127."):
                    continue
                for name in parts[1:]:
                    if name and name not in host_map:
                        host_map[name] = ip
    except OSError:
        pass

    # Local hostname fallback
    try:
        import socket
        local = socket.gethostname()
        if local and local not in host_map:
            host_map[local] = "127.0.0.1"
        short = local.split(".")[0] if local else ""
        if short and short not in host_map:
            host_map[short] = "127.0.0.1"
    except OSError:
        pass

    _host_map_cache = (now, host_map)
    return host_map


def resolve_host_ip(hostname: str) -> Optional[str]:
    """Return the cluster-internal IP for a hostname, or None if unknown."""
    if not hostname:
        return None
    host_map = _resolve_host_map()
    return host_map.get(hostname) or host_map.get(hostname.split(".")[0])


# ---------------------------------------------------------------------------
# Metrics fetcher (with per-host cache)
# ---------------------------------------------------------------------------


def fetch_metrics(host_ip: str, port: int = 9100, timeout: float = 4.0
                  ) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch + parse /metrics from a node_exporter instance. Cached."""
    cache_key = f"{host_ip}:{port}"
    now = time.time()
    cached = _metrics_cache.get(cache_key)
    if cached and now - cached[0] < _METRICS_CACHE_TTL:
        return cached[1]

    url = f"http://{host_ip}:{port}/metrics"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                LOG.debug("node_exporter: {} returned {}", url, resp.status_code)
                _metrics_cache[cache_key] = (now, {})
                return {}
            parsed = parse_prometheus_text(resp.text)
            _metrics_cache[cache_key] = (now, parsed)
            return parsed
    except Exception as exc:
        LOG.debug("node_exporter: fetch {} failed: {}", url, exc)
        _metrics_cache[cache_key] = (now, {})
        return {}


def fetch_for_hostname(hostname: str) -> Dict[str, List[Dict[str, Any]]]:
    """Resolve hostname → IP → fetch /metrics. Empty dict on any failure."""
    ip = resolve_host_ip(hostname)
    if not ip:
        return {}
    return fetch_metrics(ip)


# ---------------------------------------------------------------------------
# Hardware info extraction (for /xavs-hardware)
# ---------------------------------------------------------------------------


def extract_hardware_blob(metrics: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Build a /xavs-hardware-shaped blob from parsed node_exporter metrics.

    Mirrors skyline_apiserver.core.hwinfo.collect_hardware_blob() but reads
    from remote node_exporter metrics instead of local /proc + /sys.
    """
    def _first(name: str) -> Optional[Dict[str, Any]]:
        return (metrics.get(name) or [None])[0]

    def _val(name: str, default: float = 0.0) -> float:
        s = _first(name)
        return s["value"] if s else default

    dmi = _first("node_dmi_info") or {}
    dmi_labels = dmi.get("labels", {}) if dmi else {}

    mem_total = int(_val("node_memory_MemTotal_bytes"))
    mem_available = int(_val("node_memory_MemAvailable_bytes"))

    boot = _val("node_boot_time_seconds")
    now = time.time()
    uptime = max(0.0, now - boot) if boot else 0.0

    # Aggregate CPU count from node_cpu_seconds_total (one series per cpu/mode)
    cpu_seconds = metrics.get("node_cpu_seconds_total") or []
    cpus = {s["labels"].get("cpu") for s in cpu_seconds if s["labels"].get("cpu")}
    logical_cores = len(cpus)

    # node_uname_info has nodename, machine, release — but model name is from DMI
    model = dmi_labels.get("product_name") or "Unknown"
    vendor = dmi_labels.get("system_vendor") or "Unknown"

    # OS info — node_exporter publishes node_os_info in newer releases
    os_info = _first("node_os_info")
    os_labels = os_info.get("labels", {}) if os_info else {}

    # Hostname — from any metric that has one, preferring node_uname_info
    uname = _first("node_uname_info")
    uname_labels = uname.get("labels", {}) if uname else {}
    hostname = uname_labels.get("nodename") or ""

    def _format_bytes(b: int) -> str:
        if b <= 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        f = float(b)
        for u in units:
            if f < 1024 or u == units[-1]:
                return f"{f:.2f} {u}"
            f /= 1024
        return f"{f:.2f} PB"

    return {
        "hardware": {
            "manufacturer": vendor,
            "model": model,
            "cpu": f"{logical_cores} CPUs" + (
                f" x {dmi_labels.get('product_family', '')}" if dmi_labels.get("product_family") else ""
            ),
            "cpu_detail": {
                "logical_cores": logical_cores,
                "sockets": None,
                "cores_per_socket": None,
                "model_name": None,
            },
            "memory_bytes": mem_total,
            "memory_display": _format_bytes(mem_total),
            "memory_available_bytes": mem_available,
            "virtual_flash": None,
        },
        "configuration": {
            "os_image": os_labels.get("pretty_name") or os_labels.get("name") or "Linux",
            "os_version": os_labels.get("version_id"),
            "ha_state": "Not configured",
            "live_migration": "Supported",
        },
        "system_information": {
            "host_time": time.strftime("%A, %B %d, %Y, %H:%M:%S UTC", time.gmtime(now)),
            "install_date": None,
            "asset_tag": dmi_labels.get("chassis_asset_tag") or dmi_labels.get("board_asset_tag"),
            "serial_number": dmi_labels.get("product_serial"),
            "bios_vendor": dmi_labels.get("bios_vendor"),
            "bios_version": dmi_labels.get("bios_version"),
            "bios_date": dmi_labels.get("bios_date"),
            "board_vendor": dmi_labels.get("board_vendor"),
            "board_name": dmi_labels.get("board_name"),
            "uuid": None,
            "product_family": dmi_labels.get("product_family"),
            "product_sku": dmi_labels.get("product_sku"),
        },
        "networking": {
            "hostname": hostname,
            "primary_ipv4": None,
            "default_gateway": None,
            "dns_servers": [],
            "nics": [],
        },
        "uptime": {
            "uptime_seconds": uptime,
            "boot_time": boot,
        },
        "meminfo_bytes": {
            "MemTotal": mem_total,
            "MemAvailable": mem_available,
        },
        "source": "node_exporter",
    }


def value_for_query(metrics: Dict[str, List[Dict[str, Any]]],
                    metric_name: str,
                    label_filter: Optional[Dict[str, str]] = None
                    ) -> List[Dict[str, Any]]:
    """Return matching series from parsed metrics. Empty list if none."""
    series = metrics.get(metric_name) or []
    if not label_filter:
        return series
    out = []
    for s in series:
        labels = s.get("labels", {})
        if all(labels.get(k) == v for k, v in label_filter.items()):
            out.append(s)
    return out
