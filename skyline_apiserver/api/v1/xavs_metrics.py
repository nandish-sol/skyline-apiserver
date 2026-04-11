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

from typing import Any, Dict

from fastapi import APIRouter, Depends

from skyline_apiserver.api import deps
from skyline_apiserver.core import hwinfo, local_stats

router = APIRouter()


@router.get(
    "/xavs-hardware",
    description="Hardware, configuration and system info for the node (VMware-style).",
    response_description="Hardware info blob",
)
async def xavs_hardware(profile=Depends(deps.get_profile_update_jwt)) -> Dict[str, Any]:
    """Return hardware/configuration/system_information/networking + Nova hypervisor data."""
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
