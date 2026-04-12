"""add dns ipam connection and pool tables

Revision ID: 003
Revises: 002
Create Date: 2026-04-12

"""
import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_ipam_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "provider_type",
            sa.String(length=32),
            nullable=False,
            server_default="infoblox",
        ),
        sa.Column("api_url", sa.String(length=512), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("password_encrypted", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "dns_view", sa.String(length=255), nullable=False, server_default="default"
        ),
        sa.Column(
            "network_view",
            sa.String(length=255),
            nullable=False,
            server_default="default",
        ),
        sa.Column("ns_group", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("grid_ref", sa.String(length=255), nullable=False, server_default=""),
        sa.Column(
            "site_name", sa.String(length=255), nullable=False, server_default=""
        ),
        sa.Column("ssl_verify", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="unknown"
        ),
        sa.Column("last_check", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_by", sa.String(length=64), nullable=False, server_default=""
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "dns_ipam_pools",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("designate_pool_id", sa.String(length=36), nullable=True),
        sa.Column("pool_name", sa.String(length=255), nullable=False),
        sa.Column(
            "ns_hostname", sa.String(length=255), nullable=False, server_default=""
        ),
        sa.Column(
            "nameserver_host", sa.String(length=255), nullable=False, server_default=""
        ),
        sa.Column(
            "mdns_host", sa.String(length=255), nullable=False, server_default=""
        ),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="draft"
        ),
        sa.Column("pools_yaml_snippet", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_by", sa.String(length=64), nullable=False, server_default=""
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["dns_ipam_connections.id"],
            ondelete="CASCADE",
        ),
    )


def downgrade() -> None:
    op.drop_table("dns_ipam_pools")
    op.drop_table("dns_ipam_connections")
