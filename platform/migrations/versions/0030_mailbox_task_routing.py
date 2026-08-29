"""Route task types to server-managed mailbox pools.

Revision ID: 0030_mailbox_task_routing
Revises: 0029_card_replacement
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0030_mailbox_task_routing"
down_revision: str | None = "0029_card_replacement"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mailboxes",
        sa.Column(
            "task_type",
            sa.String(length=80),
            server_default="mail_code",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_mailboxes_task_type",
        "mailboxes",
        ["task_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_mailboxes_task_type", table_name="mailboxes")
    op.drop_column("mailboxes", "task_type")
