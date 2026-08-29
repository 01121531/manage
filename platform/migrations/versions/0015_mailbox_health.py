"""Persist safe mailbox connector health observations.

Revision ID: 0015_mailbox_health
Revises: 0014_audit_evidence_fields
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0015_mailbox_health"
down_revision: str | None = "0014_audit_evidence_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.add_column(
            sa.Column(
                "health_status",
                sa.String(length=32),
                nullable=False,
                server_default="unknown",
            )
        )
        batch_op.add_column(
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_error_code", sa.String(length=80), nullable=True)
        )
        batch_op.create_index(
            "ix_mailboxes_health_status", ["health_status"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("mailboxes") as batch_op:
        batch_op.drop_index("ix_mailboxes_health_status")
        batch_op.drop_column("last_error_code")
        batch_op.drop_column("last_checked_at")
        batch_op.drop_column("health_status")
