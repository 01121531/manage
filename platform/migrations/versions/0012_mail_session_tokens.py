"""Bind mail-session operations to an opaque session token.

Revision ID: 0012_mail_session_tokens
Revises: 0011_mailbox_lease_and_code_ttl
"""

import hashlib
import secrets
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0012_mail_session_tokens"
down_revision: str | None = "0011_mailbox_lease_and_code_ttl"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_sessions",
        sa.Column("session_token_hash", sa.String(length=64), nullable=True),
    )
    context = op.get_context()
    if context.as_sql:
        # Offline PostgreSQL review cannot fetch row ids. These values are
        # deliberately unissued: no client ever receives a matching token.
        # PostgreSQL's built-in md5 keeps the generated SQL extension-free.
        op.execute(
            sa.text(
                "UPDATE mail_sessions "
                "SET session_token_hash = md5(id) || md5(id || '-legacy-mail-session') "
                "WHERE session_token_hash IS NULL"
            )
        )
    else:
        connection = op.get_bind()
        session_ids = connection.execute(
            sa.text("SELECT id FROM mail_sessions WHERE session_token_hash IS NULL")
        ).scalars().all()
        for session_id in session_ids:
            token_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
            connection.execute(
                sa.text(
                    "UPDATE mail_sessions SET session_token_hash = :token_hash "
                    "WHERE id = :session_id"
                ),
                {"token_hash": token_hash, "session_id": session_id},
            )
    with op.batch_alter_table("mail_sessions") as batch_op:
        batch_op.alter_column(
            "session_token_hash",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("mail_sessions") as batch_op:
        batch_op.drop_column("session_token_hash")
