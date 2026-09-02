"""Make secure pool import consumption records append-only.

Revision ID: 0043_secure_consumption_lock
Revises: 0042_pool_context_identity_lock
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0043_secure_consumption_lock"
down_revision: str | None = "0042_pool_context_identity_lock"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_UPDATE_GUARD = """
CREATE TRIGGER secure_pool_import_consumptions_update_forbidden
BEFORE UPDATE ON secure_pool_import_consumptions
BEGIN
    SELECT RAISE(ABORT, 'secure pool import consumption is append-only');
END;
"""

_SQLITE_DELETE_GUARD = """
CREATE TRIGGER secure_pool_import_consumptions_delete_forbidden
BEFORE DELETE ON secure_pool_import_consumptions
BEGIN
    SELECT RAISE(ABORT, 'secure pool import consumption is append-only');
END;
"""

_POSTGRES_MUTATION_GUARD_FUNCTION = """
CREATE FUNCTION secure_pool_import_consumptions_prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'secure pool import consumption is append-only'
        USING ERRCODE = '55000';
END;
$$;
"""


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_UPDATE_GUARD)
        op.execute(_SQLITE_DELETE_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_MUTATION_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER secure_pool_import_consumptions_append_only "
            "BEFORE UPDATE OR DELETE ON secure_pool_import_consumptions FOR "
            "EACH ROW EXECUTE FUNCTION "
            "secure_pool_import_consumptions_prevent_mutation()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "secure_pool_import_consumptions_update_forbidden"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "secure_pool_import_consumptions_delete_forbidden"
        )
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS secure_pool_import_consumptions_append_only "
            "ON secure_pool_import_consumptions"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "secure_pool_import_consumptions_prevent_mutation()"
        )
