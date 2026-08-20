"""Require a hashed, actor-bound grant before revealing card PAN.

Revision ID: 0010_card_reveal_step_up
Revises: 0009_upload_policy_governance
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0010_card_reveal_step_up"
down_revision: str | None = "0009_upload_policy_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "card_reveal_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("allocation_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("required_acr", sa.String(length=255), nullable=False),
        sa.Column("grant_token_hash", sa.String(length=64), nullable=True),
        sa.Column("grant_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["allocation_id"], ["card_allocations.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("grant_token_hash"),
    )
    for column in (
        "allocation_id",
        "tenant_id",
        "user_id",
        "device_id",
        "grant_expires_at",
        "consumed_at",
        "expires_at",
        "created_at",
    ):
        op.create_index(
            f"ix_card_reveal_challenges_{column}",
            "card_reveal_challenges",
            [column],
        )


def downgrade() -> None:
    op.drop_table("card_reveal_challenges")
