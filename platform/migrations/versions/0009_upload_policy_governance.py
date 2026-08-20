"""Add upload policy approval, rollout, and rollback state.

Revision ID: 0009_upload_policy_governance
Revises: 0008_upload_outbox
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0009_upload_policy_governance"
down_revision: str | None = "0008_upload_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "upload_policy_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="draft", nullable=False),
        sa.Column("change_note", sa.String(length=500), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("concurrency", sa.Integer(), nullable=False),
        sa.Column("proxy_ref", sa.String(length=512), nullable=True),
        sa.Column("credential_ref", sa.String(length=512), nullable=True),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("approved_by", sa.String(length=36), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "version",
            name="uq_upload_policy_versions_tenant_version",
        ),
    )
    for column in ("tenant_id", "version", "status", "created_by", "approved_by", "created_at"):
        op.create_index(
            f"ix_upload_policy_versions_{column}",
            "upload_policy_versions",
            [column],
        )

    op.create_table(
        "upload_policy_deployments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("active_policy_id", sa.String(length=36), nullable=False),
        sa.Column("previous_policy_id", sa.String(length=36), nullable=True),
        sa.Column("rollout_percent", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=36), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["active_policy_id"], ["upload_policy_versions.id"]),
        sa.ForeignKeyConstraint(["previous_policy_id"], ["upload_policy_versions.id"]),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_upload_policy_deployments_tenant"),
    )
    for column in (
        "tenant_id",
        "active_policy_id",
        "previous_policy_id",
        "updated_by",
        "updated_at",
    ):
        op.create_index(
            f"ix_upload_policy_deployments_{column}",
            "upload_policy_deployments",
            [column],
        )


def downgrade() -> None:
    for column in (
        "updated_at",
        "updated_by",
        "previous_policy_id",
        "active_policy_id",
        "tenant_id",
    ):
        op.drop_index(
            f"ix_upload_policy_deployments_{column}",
            table_name="upload_policy_deployments",
        )
    op.drop_table("upload_policy_deployments")
    for column in ("created_at", "approved_by", "created_by", "status", "version", "tenant_id"):
        op.drop_index(
            f"ix_upload_policy_versions_{column}",
            table_name="upload_policy_versions",
        )
    op.drop_table("upload_policy_versions")
