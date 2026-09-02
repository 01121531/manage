"""Add pre-Vault card identity claims for secure pool imports.

Revision ID: 0037_pool_import_card_identity_claims
Revises: 0036_pool_import_contexts
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0037_pool_import_card_identity_claims"
down_revision: str | None = "0036_pool_import_contexts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pool_import_card_identity_claims",
        sa.Column("context_id", sa.String(length=36), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("provider_ref", sa.String(length=160), nullable=False),
        sa.CheckConstraint(
            "position >= 0 AND position < 100",
            name="ck_pool_import_card_identity_claims_position",
        ),
        sa.ForeignKeyConstraint(["context_id"], ["pool_import_contexts.id"]),
        sa.PrimaryKeyConstraint("context_id", "position"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider_ref",
            name="uq_pool_import_card_identity_claims_tenant_provider",
        ),
    )
    op.create_index(
        "ix_pool_import_card_identity_claims_tenant_id",
        "pool_import_card_identity_claims",
        ["tenant_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_pool_import_card_identity_claims_tenant_id",
        table_name="pool_import_card_identity_claims",
    )
    op.drop_table("pool_import_card_identity_claims")
