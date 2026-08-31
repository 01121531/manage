"""Bind pool imports to one-time secure Vault receipts.

Revision ID: 0034_secure_pool_import_receipts
Revises: 0033_pool_import_receipts
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0034_secure_pool_import_receipts"
down_revision: str | None = "0033_pool_import_receipts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "secure_pool_import_consumptions",
        sa.Column("receipt_id", sa.String(length=36), nullable=False),
        sa.Column("pool_import_receipt_id", sa.String(length=36), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["pool_import_receipt_id"], ["pool_import_receipts.id"]
        ),
        sa.PrimaryKeyConstraint("receipt_id"),
        sa.UniqueConstraint(
            "pool_import_receipt_id",
            name="uq_secure_pool_import_consumptions_local_receipt",
        ),
    )


def downgrade() -> None:
    op.drop_table("secure_pool_import_consumptions")
