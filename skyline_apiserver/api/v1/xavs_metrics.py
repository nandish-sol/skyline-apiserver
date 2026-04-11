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
    """Return hardware/configuration/system_information/networking."""
    try:
        blob = hwinfo.collect_hardware_blob()
    except Exception as exc:  # defensive — never 500 on the monitoring page
        blob = {"error": str(exc)}
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
