"""Persist worker-delivered message metadata.

Revision ID: 0026_mail_message_metadata
Revises: 0025_oidc_session_revocations
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0026_mail_message_metadata"
down_revision: str | None = "0025_oidc_session_revocations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_sessions",
        sa.Column(
            "delivered_message_id_hash",
            sa.String(length=64),
            nullable=True,
        )
    )


def downgrade() -> None:
    op.drop_column("mail_sessions", "delivered_message_id_hash")
