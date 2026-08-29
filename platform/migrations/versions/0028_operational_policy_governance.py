"""Govern mail and card policies and freeze runtime policy values.

Revision ID: 0028_operational_policy_governance
Revises: 0027_card_allocation_reason
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0028_operational_policy_governance"
down_revision: str | None = "0027_card_allocation_reason"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "operational_policy_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=16), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="draft", nullable=False),
        sa.Column("change_note", sa.String(length=500), nullable=False),
        sa.Column("session_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("code_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("poll_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("lease_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("reveal_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("allocation_order", sa.String(length=40), nullable=True),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("approved_by", sa.String(length=36), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "domain IN ('mail', 'card')",
            name="ck_operational_policy_versions_domain",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'approved', 'active', 'retired')",
            name="ck_operational_policy_versions_status",
        ),
        sa.CheckConstraint(
            "(domain = 'mail' AND session_ttl_seconds IS NOT NULL "
            "AND code_ttl_seconds IS NOT NULL AND poll_interval_seconds IS NOT NULL "
            "AND lease_ttl_seconds IS NULL AND reveal_ttl_seconds IS NULL "
            "AND allocation_order IS NULL) OR "
            "(domain = 'card' AND session_ttl_seconds IS NULL "
            "AND code_ttl_seconds IS NULL AND poll_interval_seconds IS NULL "
            "AND lease_ttl_seconds IS NOT NULL AND reveal_ttl_seconds IS NOT NULL "
            "AND allocation_order = 'oldest_available')",
            name="ck_operational_policy_versions_shape",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "domain",
            "version",
            name="uq_operational_policy_versions_tenant_domain_version",
        ),
    )
    for column in (
        "tenant_id",
        "domain",
        "version",
        "status",
        "created_by",
        "approved_by",
        "created_at",
    ):
        op.create_index(
            f"ix_operational_policy_versions_{column}",
            "operational_policy_versions",
            [column],
        )

    op.create_table(
        "operational_policy_deployments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=16), nullable=False),
        sa.Column("active_policy_id", sa.String(length=36), nullable=False),
        sa.Column("previous_policy_id", sa.String(length=36), nullable=True),
        sa.Column("rollout_percent", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=36), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "domain IN ('mail', 'card')",
            name="ck_operational_policy_deployments_domain",
        ),
        sa.CheckConstraint(
            "rollout_percent BETWEEN 1 AND 100",
            name="ck_operational_policy_deployments_rollout",
        ),
        sa.ForeignKeyConstraint(
            ["active_policy_id"], ["operational_policy_versions.id"]
        ),
        sa.ForeignKeyConstraint(
            ["previous_policy_id"], ["operational_policy_versions.id"]
        ),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "domain",
            name="uq_operational_policy_deployments_tenant_domain",
        ),
    )
    for column in (
        "tenant_id",
        "domain",
        "active_policy_id",
        "previous_policy_id",
        "updated_by",
        "updated_at",
    ):
        op.create_index(
            f"ix_operational_policy_deployments_{column}",
            "operational_policy_deployments",
            [column],
        )

    op.add_column(
        "mail_sessions",
        sa.Column(
            "policy_version",
            sa.String(length=80),
            server_default="settings-default",
            nullable=False,
        ),
    )
    op.add_column(
        "mail_sessions",
        sa.Column("code_ttl_seconds", sa.Integer(), server_default="60", nullable=False),
    )
    op.add_column(
        "mail_sessions",
        sa.Column("poll_interval_seconds", sa.Integer(), server_default="5", nullable=False),
    )
    op.add_column(
        "card_allocations",
        sa.Column(
            "policy_version",
            sa.String(length=80),
            server_default="settings-default",
            nullable=False,
        ),
    )
    op.add_column(
        "card_allocations",
        sa.Column("reveal_ttl_seconds", sa.Integer(), server_default="60", nullable=False),
    )


def downgrade() -> None:
    with op.batch_alter_table("card_allocations") as batch_op:
        batch_op.drop_column("reveal_ttl_seconds")
        batch_op.drop_column("policy_version")
    with op.batch_alter_table("mail_sessions") as batch_op:
        batch_op.drop_column("poll_interval_seconds")
        batch_op.drop_column("code_ttl_seconds")
        batch_op.drop_column("policy_version")
    op.drop_table("operational_policy_deployments")
    op.drop_table("operational_policy_versions")
