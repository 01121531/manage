"""Add card quarantine markers.

Revision ID: 0022_card_quarantine
Revises: 0021_audit_archive_index
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0022_card_quarantine"
down_revision: str | None = "0021_audit_archive_index"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "cards",
        sa.Column("quarantine_reason_code", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "cards",
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    with op.batch_alter_table("cards") as batch_op:
        batch_op.drop_column("quarantined_at")
        batch_op.drop_column("quarantine_reason_code")
