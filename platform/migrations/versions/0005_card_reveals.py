"""Track one-time card reveals.

Revision ID: 0005_card_reveals
Revises: 0004_trace_ids
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0005_card_reveals"
down_revision: str | None = "0004_trace_ids"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "card_allocations",
        sa.Column("revealed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "card_allocations",
        sa.Column("reveal_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_card_allocations_revealed_at", "card_allocations", ["revealed_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_card_allocations_revealed_at", table_name="card_allocations")
    op.drop_column("card_allocations", "reveal_expires_at")
    op.drop_column("card_allocations", "revealed_at")
