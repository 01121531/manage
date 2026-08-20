"""Prevent concurrent mailbox leases and expire delivered codes.

Revision ID: 0011_mailbox_lease_and_code_ttl
Revises: 0010_card_reveal_step_up
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0011_mailbox_lease_and_code_ttl"
down_revision: str | None = "0010_card_reveal_step_up"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_sessions",
        sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_mail_sessions_code_expires_at",
        "mail_sessions",
        ["code_expires_at"],
    )
    op.create_index(
        "uq_active_mail_session_mailbox",
        "mail_sessions",
        ["mailbox_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('initializing', 'waiting', 'code_ready')"
        ),
        sqlite_where=sa.text(
            "status IN ('initializing', 'waiting', 'code_ready')"
        ),
    )


def downgrade() -> None:
    op.drop_index("uq_active_mail_session_mailbox", table_name="mail_sessions")
    op.drop_index("ix_mail_sessions_code_expires_at", table_name="mail_sessions")
    op.drop_column("mail_sessions", "code_expires_at")
