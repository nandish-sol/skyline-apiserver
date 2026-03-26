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

"""add rbac_role_permissions table

Revision ID: 001
Revises: 000
Create Date: 2026-03-23

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "001"
down_revision = "000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rbac_role_permissions",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("role_name", sa.String(length=255), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("allowed", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "role_name", "service", "action", name="uq_role_service_action"
        ),
    )
    op.create_index(
        op.f("ix_rbac_role_permissions_role_name"),
        "rbac_role_permissions",
        ["role_name"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_rbac_role_permissions_role_name"),
        table_name="rbac_role_permissions",
    )
    op.drop_table("rbac_role_permissions")
