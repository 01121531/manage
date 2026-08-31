"""Add stable tenant-scoped indexes for pool list pagination.

Revision ID: 0035_pool_list_pagination
Revises: 0034_secure_pool_import_receipts
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0035_pool_list_pagination"
down_revision: str | None = "0034_secure_pool_import_receipts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_cards_tenant_created_at_id",
        "cards",
        ["tenant_id", "created_at", "id"],
    )
    op.create_index(
        "ix_mailboxes_tenant_created_at_id",
        "mailboxes",
        ["tenant_id", "created_at", "id"],
    )
    op.create_index(
        "ix_active_mail_sessions_tenant_mailbox_expires",
        "mail_sessions",
        ["tenant_id", "mailbox_id", "expires_at"],
        sqlite_where=sa.text(
            "status IN ('initializing', 'waiting', 'code_ready')"
        ),
        postgresql_where=sa.text(
            "status IN ('initializing', 'waiting', 'code_ready')"
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_active_mail_sessions_tenant_mailbox_expires",
        table_name="mail_sessions",
    )
    op.drop_index("ix_mailboxes_tenant_created_at_id", table_name="mailboxes")
    op.drop_index("ix_cards_tenant_created_at_id", table_name="cards")
