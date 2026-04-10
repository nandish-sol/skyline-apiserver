# Copyright 2021 99cloud
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

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

METADATA = MetaData()


UserProfiles = Table(
    "user_profiles",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", String(length=64), nullable=False, unique=True, index=True),
    Column("username", String(length=100), nullable=False),
    Column("profile_image_base64", Text, nullable=True),
    Column("image_format", String(length=10), nullable=True, server_default="png"),
    Column("image_size_bytes", Integer, nullable=True, server_default="0"),
    Column("first_name", String(length=64), nullable=True),
    Column("last_name", String(length=64), nullable=True),
    Column("phone", String(length=32), nullable=True),
    Column("job_title", String(length=128), nullable=True),
    Column("department", String(length=128), nullable=True),
    Column("theme_color", String(length=16), nullable=True),
    Column("default_project_id", String(length=64), nullable=True),
    Column("created_at", DateTime, nullable=True),
    Column("updated_at", DateTime, nullable=True),
)


RevokedToken = Table(
    "revoked_token",
    METADATA,
    Column("uuid", String(length=128), nullable=False, index=True, unique=False),
    Column("expire", Integer, nullable=False),
)

Settings = Table(
    "settings",
    METADATA,
    Column("key", String(length=128), nullable=False, index=True, unique=True),
    Column("value", JSON, nullable=True),
)

RbacRolePermissions = Table(
    "rbac_role_permissions",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("role_name", String(length=255), nullable=False, index=True),
    Column("service", String(length=64), nullable=False),
    Column("action", String(length=255), nullable=False),
    Column("allowed", Integer, nullable=False, default=0),
    UniqueConstraint("role_name", "service", "action", name="uq_role_service_action"),
)

SkylineLicenses = Table(
    "skyline_licenses",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("serial", String(length=64), nullable=False, unique=True),
    Column("cluster_id", String(length=128), nullable=False, index=True),
    Column("license_type", String(length=32), nullable=False, server_default="trial"),
    Column("valid_from", DateTime, nullable=False),
    Column("valid_until", DateTime, nullable=False),
    Column("max_sockets", Integer, nullable=False, server_default="0"),
    Column("max_nodes", Integer, nullable=False, server_default="0"),
    Column("vendor", String(length=128), nullable=False, server_default="Xloud Technologies"),
    Column("is_active", Integer, nullable=False, server_default="0"),
    Column("applied_at", DateTime, nullable=True),
    Column("applied_by", String(length=255), nullable=False, server_default="system"),
    Column("applied_from", String(length=45), nullable=False, server_default="0.0.0.0"),
    Column("token_payload", Text, nullable=True),
    Column("token_signature", Text, nullable=True),
    Column("token_full_json", Text, nullable=True),
    Column("created_at", DateTime, nullable=True),
    Column("updated_at", DateTime, nullable=True),
)

SkylineLicenseEvents = Table(
    "skyline_license_events",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("license_id", Integer, ForeignKey("skyline_licenses.id", ondelete="CASCADE"), nullable=True),
    Column("event_type", String(length=32), nullable=False),
    Column("event_message", Text, nullable=True),
    Column("event_details", JSON, nullable=True),
    Column("user", String(length=255), nullable=True),
    Column("ip_address", String(length=45), nullable=True),
    Column("hostname", String(length=255), nullable=True),
    Column("created_at", DateTime, nullable=True),
)

SkylineSystemState = Table(
    "skyline_system_state",
    METADATA,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("cluster_id", String(length=128), nullable=False, unique=True),
    Column("active_license_id", Integer, ForeignKey("skyline_licenses.id", ondelete="SET NULL"), nullable=True),
    Column("grace_period_start", DateTime, nullable=True),
    Column("grace_period_locked", Integer, nullable=False, server_default="0"),
    Column("grace_period_days", Integer, nullable=False, server_default="15"),
    Column("grace_period_reason", String(length=64), nullable=True),
    Column("days_remaining", Integer, nullable=True, server_default="0"),
    Column("status", String(length=32), nullable=False, server_default="active"),
    Column("status_message", Text, nullable=True),
    Column("hardware_fingerprint", String(length=128), nullable=True),
    Column("total_nodes", Integer, nullable=True, server_default="0"),
    Column("total_sockets", Integer, nullable=True, server_default="0"),
    Column("last_checked", DateTime, nullable=True),
    Column("last_verified", DateTime, nullable=True),
    Column("created_at", DateTime, nullable=True),
    Column("updated_at", DateTime, nullable=True),
)
