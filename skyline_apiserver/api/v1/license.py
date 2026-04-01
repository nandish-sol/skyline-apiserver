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

"""License status endpoint — accessible to all authenticated users."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status

from skyline_apiserver import schemas
from skyline_apiserver.api import deps

LOG = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/license/status",
    description="Get current license/compliance status.",
    responses={
        200: {"model": schemas.LicenseStatus},
        401: {"model": schemas.UnauthorizedMessage},
        500: {"model": schemas.InternalServerErrorMessage},
    },
    response_model=schemas.LicenseStatus,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def license_status(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> schemas.LicenseStatus:
    from skyline_apiserver.core.license import ComplianceValidator

    state = await ComplianceValidator.get_compliance_state()

    is_expired = (
        state.get("expired", False)
        or state.get("days_remaining", 999) <= 0
        or state.get("status") == "expired"
    )

    source = "grace_period" if state.get("license_type") == "grace_period" else "file"

    return schemas.LicenseStatus(
        enabled=state.get("enabled", False),
        serial=state.get("serial", "UNKNOWN"),
        cluster_id=state.get("cluster_id", "UNKNOWN"),
        license_type=state.get("license_type", "unknown"),
        days_remaining=state.get("days_remaining", 0),
        days_elapsed=state.get("days_elapsed", 0),
        start_date=state.get("start_date", "N/A"),
        end_date=state.get("end_date", "N/A"),
        expired=state.get("expired", True),
        warning=state.get("warning", True),
        status=state.get("status", "unknown"),
        message=state.get("message", "No license information available"),
        max_sockets=state.get("max_sockets", 0),
        vendor=state.get("vendor", "N/A"),
        source=source,
        restricted_mode=is_expired,
    )
