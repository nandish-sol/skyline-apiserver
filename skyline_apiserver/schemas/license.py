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

from __future__ import annotations

from pydantic import BaseModel, Field


class LicenseStatus(BaseModel):
    enabled: bool = Field(..., description="Whether the license is currently valid")
    serial: str = Field(..., description="License serial number")
    cluster_id: str = Field(..., description="Cluster/node identifier")
    license_type: str = Field(..., description="License type (trial/production/grace_period)")
    days_remaining: int = Field(..., description="Days until license expires")
    days_elapsed: int = Field(default=0, description="Days since license started")
    start_date: str = Field(..., description="License start date (YYYY-MM-DD)")
    end_date: str = Field(..., description="License end date (YYYY-MM-DD)")
    expired: bool = Field(..., description="Whether the license has expired")
    warning: bool = Field(..., description="Whether expiry warning is active")
    status: str = Field(..., description="Status code (active/expired/grace_period/invalid_hardware)")
    message: str = Field(..., description="Human-readable status message")
    max_sockets: int = Field(default=0, description="Maximum licensed CPU sockets")
    vendor: str = Field(default="N/A", description="License vendor name")
    source: str = Field(default="file", description="License source (file/grace_period)")
    restricted_mode: bool = Field(..., description="Whether create/delete operations are blocked")
