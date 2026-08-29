"""Enforce tenant-scoped audit event subject bindings.

Revision ID: 0020_audit_event_subject_binding
Revises: 0019_admin_role_change_approval
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0020_audit_event_subject_binding"
down_revision: str | None = "0019_admin_role_change_approval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INVALID_BINDING_QUERY = """
SELECT audit_events.id
FROM audit_events
LEFT JOIN users
  ON users.id = audit_events.user_id
 AND users.tenant_id = audit_events.tenant_id
LEFT JOIN devices
  ON devices.id = audit_events.device_id
 AND devices.tenant_id = audit_events.tenant_id
 AND devices.user_id = audit_events.user_id
WHERE
    (audit_events.user_id IS NOT NULL AND users.id IS NULL)
    OR
    (audit_events.device_id IS NOT NULL AND (
        audit_events.user_id IS NULL OR devices.id IS NULL
    ))
LIMIT 1
"""

_POSTGRES_PREFLIGHT_QUERY = """
SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM audit_events
        LEFT JOIN users
          ON users.id = audit_events.user_id
         AND users.tenant_id = audit_events.tenant_id
        LEFT JOIN devices
          ON devices.id = audit_events.device_id
         AND devices.tenant_id = audit_events.tenant_id
         AND devices.user_id = audit_events.user_id
        WHERE
            (audit_events.user_id IS NOT NULL AND users.id IS NULL)
            OR
            (audit_events.device_id IS NOT NULL AND (
                audit_events.user_id IS NULL OR devices.id IS NULL
            ))
    ) THEN 1 / 0 ELSE 1 END AS audit_event_subject_bindings_valid
"""

_SQLITE_TRIGGER = """
CREATE TRIGGER audit_events_subject_binding
BEFORE INSERT ON audit_events
WHEN
    (NEW.user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM users
        WHERE users.id = NEW.user_id
          AND users.tenant_id = NEW.tenant_id
    ))
    OR
    (NEW.device_id IS NOT NULL AND (
        NEW.user_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM devices
            WHERE devices.id = NEW.device_id
              AND devices.tenant_id = NEW.tenant_id
              AND devices.user_id = NEW.user_id
        )
    ))
BEGIN
    SELECT RAISE(ABORT, 'audit_events subject binding invalid');
END;
"""

_POSTGRES_FUNCTION = """
CREATE FUNCTION audit_events_validate_subject_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF
        (NEW.user_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM users
            WHERE users.id = NEW.user_id
              AND users.tenant_id = NEW.tenant_id
        ))
        OR
        (NEW.device_id IS NOT NULL AND (
            NEW.user_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM devices
                WHERE devices.id = NEW.device_id
                  AND devices.tenant_id = NEW.tenant_id
                  AND devices.user_id = NEW.user_id
            )
        ))
    THEN
        RAISE EXCEPTION 'audit_events subject binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""


def _preflight_subject_bindings() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # Keep offline release SQL fail-closed without dynamic SQL or a
        # temporary privileged function. PostgreSQL short-circuits CASE, so
        # any invalid historical binding aborts the migration.
        op.execute(_POSTGRES_PREFLIGHT_QUERY)
        return
    invalid = op.get_bind().execute(sa.text(_INVALID_BINDING_QUERY)).first()
    if invalid is not None:
        raise RuntimeError(
            "Invalid audit event subject bindings must be remediated before migration"
        )


def upgrade() -> None:
    _preflight_subject_bindings()
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_TRIGGER)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_FUNCTION)
        op.execute(
            "CREATE TRIGGER audit_events_subject_binding "
            "BEFORE INSERT ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION audit_events_validate_subject_binding()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_subject_binding")
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS audit_events_subject_binding ON audit_events"
        )
        op.execute("DROP FUNCTION IF EXISTS audit_events_validate_subject_binding()")
