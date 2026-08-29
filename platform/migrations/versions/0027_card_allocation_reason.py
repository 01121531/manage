"""Persist the reason that created each card allocation.

Revision ID: 0027_card_allocation_reason
Revises: 0026_mail_message_metadata
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0027_card_allocation_reason"
down_revision: str | None = "0026_mail_message_metadata"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "card_allocations",
        sa.Column(
            "allocation_reason_code",
            sa.String(length=80),
            nullable=False,
            server_default="task_assigned",
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("card_allocations") as batch_op:
        batch_op.drop_column("allocation_reason_code")
