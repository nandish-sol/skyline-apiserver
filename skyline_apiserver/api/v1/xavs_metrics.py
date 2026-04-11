# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""XAVS hardware + node metrics endpoints.

Provides a VMware-style hardware summary and a current metrics snapshot
without requiring Prometheus. Reads from /proc, /sys and psutil-free
stdlib helpers in core.hwinfo and core.local_stats.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from skyline_apiserver.api import deps
from skyline_apiserver.api.v1 import prometheus as prom_route
from skyline_apiserver.core import hwinfo, local_stats, node_exporter
from skyline_apiserver.log import LOG

router = APIRouter()


# PromQL expressions the Physical Nodes hardware card needs.
# `{host}` is substituted with the target hostname. Every query selects
# both `fqdn` (Prometheus scrape_config convention on this cluster) and
# `instance` (our local shim convention) so one expression works against
# both real Prometheus and the XD3 shim.
_HARDWARE_QUERIES = {
    "dmi": 'node_dmi_info{{fqdn="{host}"}} or node_dmi_info{{hostname="{host}"}}',
    "mem_total": 'node_memory_MemTotal_bytes{{fqdn="{host}"}} or node_memory_MemTotal_bytes{{hostname="{host}"}}',
    "mem_avail": 'node_memory_MemAvailable_bytes{{fqdn="{host}"}} or node_memory_MemAvailable_bytes{{hostname="{host}"}}',
    "boot_time": 'node_boot_time_seconds{{fqdn="{host}"}} or node_boot_time_seconds{{hostname="{host}"}}',
    "cpu_count": 'count(node_cpu_seconds_total{{fqdn="{host}",mode="idle"}}) or count(node_cpu_seconds_total{{hostname="{host}",mode="idle"}})',
    "os_info": 'node_os_info{{fqdn="{host}"}} or node_os_info{{hostname="{host}"}}',
    "uname": 'node_uname_info{{fqdn="{host}"}} or node_uname_info{{hostname="{host}"}}',
}


async def _run_promql(query: str, profile) -> List[Dict[str, Any]]:
    """Call /query internally and return the parsed result list.

    On production this hits the configured Prometheus endpoint. On XD3 it
    falls back to the local_stats shim. Any failure returns [].
    """
    try:
        resp = await prom_route.prometheus_query(
            query=query, time=None, timeout=None, profile=profile
        )
        if resp and resp.data and resp.data.result:
            return [
                {"metric": r.metric or {}, "value": r.value or [0, "0"]}
                for r in resp.data.result
            ]
    except Exception as exc:
        LOG.debug("xavs-hardware: prom query failed {}: {}", query, exc)
    return []


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


async def _collect_from_prometheus(host: str, profile) -> Dict[str, Any]:
    """Build a hardware blob using PromQL against whatever /query resolves to."""
    results: Dict[str, List[Dict[str, Any]]] = {}
    for key, tmpl in _HARDWARE_QUERIES.items():
        results[key] = await _run_promql(tmpl.format(host=host), profile)

    dmi_series = results.get("dmi") or []
    if not dmi_series:
        # No match at all — let caller try the next path.
        return {}

    dmi_labels = dmi_series[0].get("metric", {}) or {}

    def _first_val(key: str) -> float:
        series = results.get(key) or []
        if not series:
            return 0.0
        try:
            return float(series[0].get("value", [0, "0"])[1])
        except (TypeError, ValueError, IndexError):
            return 0.0

    mem_total = int(_first_val("mem_total"))
    mem_avail = int(_first_val("mem_avail"))
    boot_time = _first_val("boot_time")
    cpu_count = int(_first_val("cpu_count"))

    os_labels = {}
    if results.get("os_info"):
        os_labels = results["os_info"][0].get("metric", {}) or {}
    uname_labels = {}
    if results.get("uname"):
        uname_labels = results["uname"][0].get("metric", {}) or {}

    now = time.time()
    uptime = max(0.0, now - boot_time) if boot_time else 0.0

    return {
        "hardware": {
            "manufacturer": dmi_labels.get("system_vendor") or dmi_labels.get("board_vendor"),
            "model": dmi_labels.get("product_name"),
            "cpu": (f"{cpu_count} CPUs" if cpu_count else None),
            "cpu_detail": {"logical_cores": cpu_count},
            "memory_bytes": mem_total,
            "memory_display": _format_bytes(mem_total) if mem_total else None,
            "memory_available_bytes": mem_avail,
        },
        "configuration": {
            "os_image": os_labels.get("pretty_name") or os_labels.get("name"),
            "os_version": os_labels.get("version_id"),
            "kernel": uname_labels.get("release"),
            "ha_state": "Not configured",
            "live_migration": "Supported",
        },
        "system_information": {
            "host_time": time.strftime("%A, %B %d, %Y, %H:%M:%S UTC", time.gmtime(now)),
            "asset_tag": dmi_labels.get("chassis_asset_tag") or dmi_labels.get("board_asset_tag"),
            "serial_number": dmi_labels.get("product_serial"),
            "bios_vendor": dmi_labels.get("bios_vendor"),
            "bios_version": dmi_labels.get("bios_version"),
            "bios_date": dmi_labels.get("bios_date"),
            "bios_release": dmi_labels.get("bios_release"),
            "board_vendor": dmi_labels.get("board_vendor"),
            "board_name": dmi_labels.get("board_name"),
            "chassis_vendor": dmi_labels.get("chassis_vendor"),
            "product_family": dmi_labels.get("product_family"),
            "product_sku": dmi_labels.get("product_sku"),
        },
        "networking": {
            "hostname": uname_labels.get("nodename") or host,
        },
        "uptime": {"uptime_seconds": uptime, "boot_time": boot_time},
        "source": "prometheus",
    }


@router.get(
    "/xavs-hardware",
    description="Hardware, configuration and system info for the node (VMware-style).",
    response_description="Hardware info blob",
)
async def xavs_hardware(
    host: Optional[str] = Query(None, description="Target hostname. Omit for local host."),
    profile=Depends(deps.get_profile_update_jwt),
) -> Dict[str, Any]:
    """Return hardware/configuration/system_information/networking for a host.

    Lookup cascade:
      1. **Prometheus** (real upstream or local_stats shim) via an internal
         call to the existing /query logic. On production this hits the
         configured prometheus_endpoint; on XD3 it falls back to the local
         /proc shim. Returns full DMI when node_exporter is scraped.
      2. **Direct node_exporter fetch** when Prometheus is unreachable but
         the target host exposes :9100 (e.g. cephadm-deployed exporters).
      3. **Local /proc + /sys** as last resort for the apiserver's own host.

    Nova hypervisor data is merged on top in every case for
    vcpus/memory allocation + running_vms + state.
    """
    blob: Dict[str, Any] = {}
    local_hostname = hwinfo.read_hostname()
    local_short = (local_hostname or "").split(".")[0]
    target = host or local_short or local_hostname
    is_remote = bool(host and host != local_hostname and host != local_short)

    # Path 1: Prometheus (authoritative when available)
    blob = await _collect_from_prometheus(target, profile)

    # Path 2: Direct node_exporter fetch for remote hosts when Prometheus
    # returned empty (e.g. Prometheus down or scrape target missing)
    if is_remote and (not blob or not blob.get("hardware", {}).get("model")):
        metrics = node_exporter.fetch_for_hostname(target)
        if metrics:
            blob = node_exporter.extract_hardware_blob(metrics)
            blob.setdefault("networking", {}).setdefault("hostname", target)

    # Path 3: Local /proc + DMI fallback when host is local or all else failed
    if not is_remote and (not blob or not blob.get("hardware", {}).get("model")):
        try:
            blob = hwinfo.collect_hardware_blob()
        except Exception as exc:  # defensive — never 500 on the monitoring page
            blob = {"error": str(exc)}

    # Merge Nova hypervisor data (authoritative for CPU/Mem allocation, VM count,
    # and provides hypervisor_type / hypervisor_version).
    try:
        os_stats = local_stats._try_openstack_stats()
        hvs = os_stats.get("nova_hypervisors") or []
        hostname = blob.get("networking", {}).get("hostname")
        match = None
        if hostname and hvs:
            for hv in hvs:
                if hv.get("hypervisor_hostname") == hostname or (
                    hv.get("service", {}) or {}
                ).get("host") == hostname:
                    match = hv
                    break
            if match is None and len(hvs) == 1:
                match = hvs[0]
        if match:
            cpu_info = match.get("cpu_info") or {}
            if isinstance(cpu_info, str):
                try:
                    import json as _json
                    cpu_info = _json.loads(cpu_info)
                except Exception:
                    cpu_info = {}
            blob.setdefault("openstack", {})
            blob["openstack"]["hypervisor"] = {
                "hostname": match.get("hypervisor_hostname"),
                "host_ip": match.get("host_ip"),
                "state": match.get("state"),
                "status": match.get("status"),
                "type": match.get("hypervisor_type"),
                "version": match.get("hypervisor_version"),
                "vcpus": match.get("vcpus"),
                "vcpus_used": match.get("vcpus_used"),
                "memory_mb": match.get("memory_mb"),
                "memory_mb_used": match.get("memory_mb_used"),
                "local_gb": match.get("local_gb"),
                "local_gb_used": match.get("local_gb_used"),
                "free_disk_gb": match.get("free_disk_gb"),
                "running_vms": match.get("running_vms"),
                "current_workload": match.get("current_workload"),
                "cpu_arch": cpu_info.get("arch"),
                "cpu_model": cpu_info.get("model"),
                "cpu_vendor": cpu_info.get("vendor"),
                "cpu_topology": cpu_info.get("topology"),
            }
        blob.setdefault("openstack", {})
        blob["openstack"]["services"] = [
            {
                "binary": s.get("binary"),
                "host": s.get("host"),
                "state": s.get("state"),
                "status": s.get("status"),
                "updated_at": s.get("updated_at"),
            }
            for s in (os_stats.get("nova_services") or [])
        ]
        statistics = os_stats.get("nova_statistics") or {}
        if statistics:
            blob["openstack"]["cluster"] = {
                "count": statistics.get("count"),
                "vcpus": statistics.get("vcpus"),
                "vcpus_used": statistics.get("vcpus_used"),
                "memory_mb": statistics.get("memory_mb"),
                "memory_mb_used": statistics.get("memory_mb_used"),
                "local_gb": statistics.get("local_gb"),
                "local_gb_used": statistics.get("local_gb_used"),
                "running_vms": statistics.get("running_vms"),
                "free_ram_mb": statistics.get("free_ram_mb"),
                "free_disk_gb": statistics.get("free_disk_gb"),
            }
    except Exception as exc:  # pragma: no cover
        blob.setdefault("openstack", {})["error"] = str(exc)

    return blob


@router.get(
    "/xavs-metrics/node",
    description="Current node metrics snapshot (CPU, memory, disk, network, load).",
    response_description="Node metrics snapshot",
)
async def xavs_metrics_node(
    profile=Depends(deps.get_profile_update_jwt),
) -> Dict[str, Any]:
    snap = local_stats.latest()
    if snap is None:
        # Sampler hasn't fired yet — take a synchronous sample now
        try:
            snap = local_stats.sample_once()
        except Exception as exc:
            return {"error": str(exc), "ts": None}
    return snap
