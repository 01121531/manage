"""Add mail worker delivery columns.

Revision ID: 0006_mail_worker_delivery
Revises: 0005_card_reveals
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_mail_worker_delivery"
down_revision: str | None = "0005_card_reveals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_sessions",
        sa.Column("delivered_code", sa.String(length=8), nullable=True),
    )
    op.add_column(
        "mail_sessions",
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_mail_sessions_delivered_at", "mail_sessions", ["delivered_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_mail_sessions_delivered_at", table_name="mail_sessions")
    op.drop_column("mail_sessions", "delivered_at")
    op.drop_column("mail_sessions", "delivered_code")
