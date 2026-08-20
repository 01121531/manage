"""Make audit events append-only at the database layer.

Revision ID: 0007_audit_append_only
Revises: 0006_mail_worker_delivery
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0007_audit_append_only"
down_revision: str | None = "0006_mail_worker_delivery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_events_prevent_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events are append-only';
        END;
        $$;
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;")
    op.execute(
        """
        CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_prevent_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_prevent_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS audit_events_prevent_mutation();")
