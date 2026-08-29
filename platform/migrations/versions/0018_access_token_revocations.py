"""Persist exact bearer-token revocations for immediate logout.

Revision ID: 0018_access_token_revocations
Revises: 0017_mail_token_hash_unique
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0018_access_token_revocations"
down_revision: str | None = "0017_mail_token_hash_unique"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "revoked_access_tokens",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    for column in ("tenant_id", "user_id", "device_id", "expires_at"):
        op.create_index(
            f"ix_revoked_access_tokens_{column}",
            "revoked_access_tokens",
            [column],
        )


def downgrade() -> None:
    for column in ("expires_at", "device_id", "user_id", "tenant_id"):
        op.drop_index(
            f"ix_revoked_access_tokens_{column}",
            table_name="revoked_access_tokens",
        )
    op.drop_table("revoked_access_tokens")
