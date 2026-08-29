"""Persist the last successful activity time for each device.

Revision ID: 0016_device_last_seen
Revises: 0015_mailbox_health
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0016_device_last_seen"
down_revision: str | None = "0015_mailbox_health"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.add_column(
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch_op:
        batch_op.drop_column("last_seen_at")
