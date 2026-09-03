"""Prevent deletion of target-issued pool import contexts.

Revision ID: 0046_pool_import_context_delete_guard
Revises: 0045_pool_import_receipt_append_only
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0046_pool_import_context_delete_guard"
down_revision: str | None = "0045_pool_import_receipt_append_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_DELETE_GUARD = """
CREATE TRIGGER pool_import_contexts_no_delete
BEFORE DELETE ON pool_import_contexts
BEGIN
    SELECT RAISE(ABORT, 'pool import context deletion is forbidden');
END;
"""

_POSTGRES_DELETE_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_contexts_prevent_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'pool import context deletion is forbidden'
        USING ERRCODE = '55000';
END;
$$;
"""


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_DELETE_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_DELETE_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_contexts_no_delete BEFORE DELETE ON "
            "pool_import_contexts FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_contexts_prevent_delete()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS pool_import_contexts_no_delete")
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_contexts_no_delete "
            "ON pool_import_contexts"
        )
        op.execute("DROP FUNCTION IF EXISTS pool_import_contexts_prevent_delete()")
