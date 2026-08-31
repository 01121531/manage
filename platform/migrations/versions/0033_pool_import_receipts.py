"""Add secret-free idempotency receipts for pool imports.

Revision ID: 0033_pool_import_receipts
Revises: 0032_upload_phase_tracking
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0033_pool_import_receipts"
down_revision: str | None = "0032_upload_phase_tracking"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pool_import_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("pool_type", sa.String(length=16), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("trace_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "pool_type IN ('card', 'mailbox')",
            name="ck_pool_import_receipts_pool_type",
        ),
        sa.CheckConstraint(
            "item_count >= 1 AND item_count <= 100",
            name="ck_pool_import_receipts_item_count",
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "pool_type",
            "idempotency_key",
            name="uq_pool_import_receipts_tenant_pool_key",
        ),
    )


def downgrade() -> None:
    op.drop_table("pool_import_receipts")
