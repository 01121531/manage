"""Persist issuer-scoped OIDC session revocations.

Revision ID: 0025_oidc_session_revocations
Revises: 0024_schema_compatibility
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0025_oidc_session_revocations"
down_revision: str | None = "0024_schema_compatibility"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "revoked_oidc_sessions",
        sa.Column("session_hash", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("session_hash"),
    )
    for column in ("tenant_id", "user_id", "device_id", "expires_at"):
        op.create_index(
            f"ix_revoked_oidc_sessions_{column}",
            "revoked_oidc_sessions",
            [column],
        )


def downgrade() -> None:
    for column in ("expires_at", "device_id", "user_id", "tenant_id"):
        op.drop_index(
            f"ix_revoked_oidc_sessions_{column}",
            table_name="revoked_oidc_sessions",
        )
    op.drop_table("revoked_oidc_sessions")
