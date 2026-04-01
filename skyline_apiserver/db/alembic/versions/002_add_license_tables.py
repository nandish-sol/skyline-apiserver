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

"""add license management tables

Revision ID: 002
Revises: 001
Create Date: 2026-04-01

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # skyline_licenses — core license records
    op.create_table(
        "skyline_licenses",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("serial", sa.String(length=64), nullable=False),
        sa.Column("cluster_id", sa.String(length=128), nullable=False),
        sa.Column(
            "license_type",
            sa.String(length=32),
            nullable=False,
            server_default="trial",
        ),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("valid_until", sa.DateTime(), nullable=False),
        sa.Column("max_sockets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_nodes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "vendor",
            sa.String(length=128),
            nullable=False,
            server_default="Xloud Technologies",
        ),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("applied_at", sa.DateTime(), nullable=True),
        sa.Column(
            "applied_by",
            sa.String(length=255),
            nullable=False,
            server_default="system",
        ),
        sa.Column(
            "applied_from",
            sa.String(length=45),
            nullable=False,
            server_default="0.0.0.0",
        ),
        sa.Column("token_payload", sa.Text(), nullable=True),
        sa.Column("token_signature", sa.Text(), nullable=True),
        sa.Column("token_full_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("serial", name="uq_license_serial"),
    )
    op.create_index("ix_skyline_licenses_active", "skyline_licenses", ["is_active"])
    op.create_index("ix_skyline_licenses_cluster", "skyline_licenses", ["cluster_id"])
    op.create_index(
        "ix_skyline_licenses_validity",
        "skyline_licenses",
        ["valid_from", "valid_until"],
    )

    # skyline_license_events — audit trail
    op.create_table(
        "skyline_license_events",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("license_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("event_message", sa.Text(), nullable=True),
        sa.Column("event_details", sa.JSON(), nullable=True),
        sa.Column("user", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["license_id"],
            ["skyline_licenses.id"],
            name="fk_event_license",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_license_events_created", "skyline_license_events", ["created_at"]
    )
    op.create_index(
        "ix_license_events_type", "skyline_license_events", ["event_type"]
    )

    # skyline_system_state — per-cluster compliance state
    op.create_table(
        "skyline_system_state",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("cluster_id", sa.String(length=128), nullable=False),
        sa.Column("active_license_id", sa.Integer(), nullable=True),
        sa.Column("grace_period_start", sa.DateTime(), nullable=True),
        sa.Column(
            "grace_period_locked", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "grace_period_days", sa.Integer(), nullable=False, server_default="15"
        ),
        sa.Column("grace_period_reason", sa.String(length=64), nullable=True),
        sa.Column("days_remaining", sa.Integer(), nullable=True, server_default="0"),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="active",
        ),
        sa.Column("status_message", sa.Text(), nullable=True),
        sa.Column("hardware_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("total_nodes", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("total_sockets", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("last_checked", sa.DateTime(), nullable=True),
        sa.Column("last_verified", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cluster_id", name="uq_system_state_cluster"),
        sa.ForeignKeyConstraint(
            ["active_license_id"],
            ["skyline_licenses.id"],
            name="fk_state_license",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_system_state_status", "skyline_system_state", ["status"]
    )
    op.create_index(
        "ix_system_state_grace",
        "skyline_system_state",
        ["grace_period_start", "grace_period_locked"],
    )


def downgrade() -> None:
    op.drop_table("skyline_license_events")
    op.drop_table("skyline_system_state")
    op.drop_table("skyline_licenses")
