"""Add target-issued secure pool import contexts.

Revision ID: 0036_pool_import_contexts
Revises: 0035_pool_list_pagination
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0036_pool_import_contexts"
down_revision: str | None = "0035_pool_list_pagination"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pool_import_contexts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("context_token_hash", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("audience", sa.String(length=160), nullable=False),
        sa.Column("pool_type", sa.String(length=16), nullable=False),
        sa.Column("ordered_manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("trace_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pool_import_receipt_id", sa.String(length=36), nullable=True),
        sa.CheckConstraint(
            "pool_type IN ('card', 'mailbox')",
            name="ck_pool_import_contexts_pool_type",
        ),
        sa.CheckConstraint(
            "item_count >= 1 AND item_count <= 100",
            name="ck_pool_import_contexts_item_count",
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(
            ["pool_import_receipt_id"], ["pool_import_receipts.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "context_token_hash", name="uq_pool_import_contexts_token_hash"
        ),
        sa.UniqueConstraint(
            "pool_import_receipt_id",
            name="uq_pool_import_contexts_local_receipt",
        ),
    )
    op.create_index(
        "ix_pool_import_contexts_tenant_id",
        "pool_import_contexts",
        ["tenant_id"],
    )
    op.create_index(
        "ix_pool_import_contexts_expires_at",
        "pool_import_contexts",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_pool_import_contexts_expires_at", table_name="pool_import_contexts"
    )
    op.drop_index(
        "ix_pool_import_contexts_tenant_id", table_name="pool_import_contexts"
    )
    op.drop_table("pool_import_contexts")
