"""Prevent two cards from referencing the same tenant secret.

Revision ID: 0013_card_secret_ref_unique
Revises: 0012_mail_session_tokens
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0013_card_secret_ref_unique"
down_revision: str | None = "0012_mail_session_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("cards") as batch_op:
        batch_op.create_unique_constraint(
            "uq_cards_tenant_secret_ref", ["tenant_id", "secret_ref"]
        )


def downgrade() -> None:
    with op.batch_alter_table("cards") as batch_op:
        batch_op.drop_constraint(
            "uq_cards_tenant_secret_ref", type_="unique"
        )
