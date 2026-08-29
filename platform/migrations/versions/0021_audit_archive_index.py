"""Add the audit archive keyset index.

Revision ID: 0021_audit_archive_index
Revises: 0020_audit_event_subject_binding
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0021_audit_archive_index"
down_revision: str | None = "0020_audit_event_subject_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_events_tenant_created_at_id",
        "audit_events",
        ["tenant_id", "created_at", "id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_events_tenant_created_at_id",
        table_name="audit_events",
    )
