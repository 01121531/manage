"""Add durable upload phases and ordered phase events.

Revision ID: 0032_upload_phase_tracking
Revises: 0031_card_pool_routing
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0032_upload_phase_tracking"
down_revision: str | None = "0031_card_pool_routing"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    op.add_column(
        "upload_jobs",
        sa.Column(
            "phase",
            sa.String(length=40),
            server_default="legacy_unclassified",
            nullable=False,
        ),
    )
    op.add_column(
        "upload_jobs",
        sa.Column(
            "phase_sequence", sa.Integer(), server_default="0", nullable=False
        ),
    )
    op.add_column(
        "upload_jobs",
        sa.Column(
            "phase_updated_at",
            sa.DateTime(timezone=True),
            server_default=(
                sa.text("'1970-01-01 00:00:00+00:00'")
                if bind.dialect.name == "sqlite"
                else sa.text("CURRENT_TIMESTAMP")
            ),
            nullable=False,
        ),
    )
    op.execute(sa.text("UPDATE upload_jobs SET phase_updated_at = updated_at"))
    op.create_index("ix_upload_jobs_phase", "upload_jobs", ["phase"])
    op.create_index(
        "ix_upload_jobs_phase_updated_at", "upload_jobs", ["phase_updated_at"]
    )

    op.add_column(
        "audit_events",
        sa.Column("aggregate_sequence", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_audit_events_upload_phase_sequence",
        "audit_events",
        ["tenant_id", "entity_type", "entity_id", "aggregate_sequence"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_events_upload_phase_sequence", table_name="audit_events"
    )
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_column("aggregate_sequence")
    op.drop_index("ix_upload_jobs_phase_updated_at", table_name="upload_jobs")
    op.drop_index("ix_upload_jobs_phase", table_name="upload_jobs")
    with op.batch_alter_table("upload_jobs") as batch_op:
        batch_op.drop_column("phase_updated_at")
        batch_op.drop_column("phase_sequence")
        batch_op.drop_column("phase")
