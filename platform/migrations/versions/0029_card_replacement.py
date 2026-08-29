"""Persist one-to-one card allocation replacement links.

Revision ID: 0029_card_replacement
Revises: 0028_operational_policy_governance
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0029_card_replacement"
down_revision: str | None = "0028_operational_policy_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "card_allocation_replacements",
        sa.Column("original_allocation_id", sa.String(length=36), nullable=False),
        sa.Column("replacement_allocation_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["original_allocation_id"],
            ["card_allocations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["replacement_allocation_id"],
            ["card_allocations.id"],
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("original_allocation_id"),
        sa.UniqueConstraint(
            "replacement_allocation_id",
            name="uq_card_allocation_replacements_replacement_id",
        ),
    )
    for column in ("replacement_allocation_id", "tenant_id", "task_id", "created_at"):
        op.create_index(
            f"ix_card_allocation_replacements_{column}",
            "card_allocation_replacements",
            [column],
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("card_allocation_replacements")
