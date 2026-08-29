"""Add the expand-only application compatibility floor.

Revision ID: 0024_schema_compatibility
Revises: 0023_card_events
"""

from alembic import op
import sqlalchemy as sa


revision = "0024_schema_compatibility"
down_revision = "0023_card_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = op.create_table(
        "platform_schema_compatibility",
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("minimum_app_revision", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("singleton_id"),
    )
    op.bulk_insert(
        table,
        [
            {
                "singleton_id": 1,
                "minimum_app_revision": revision,
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("platform_schema_compatibility")
