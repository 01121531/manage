"""Make local pool import receipts append-only.

Revision ID: 0045_pool_import_receipt_append_only
Revises: 0044_pool_context_consumption_terminal
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0045_pool_import_receipt_append_only"
down_revision: str | None = "0044_pool_context_consumption_terminal"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_UPDATE_GUARD = """
CREATE TRIGGER pool_import_receipts_update_forbidden
BEFORE UPDATE ON pool_import_receipts
BEGIN
    SELECT RAISE(ABORT, 'pool import receipt is append-only');
END;
"""

_SQLITE_DELETE_GUARD = """
CREATE TRIGGER pool_import_receipts_delete_forbidden
BEFORE DELETE ON pool_import_receipts
BEGIN
    SELECT RAISE(ABORT, 'pool import receipt is append-only');
END;
"""

_POSTGRES_MUTATION_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_receipts_prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'pool import receipt is append-only'
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
            "CREATE TRIGGER pool_import_receipts_append_only BEFORE UPDATE OR "
            "DELETE ON pool_import_receipts FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_receipts_prevent_mutation()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS pool_import_receipts_update_forbidden")
        op.execute("DROP TRIGGER IF EXISTS pool_import_receipts_delete_forbidden")
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_receipts_append_only "
            "ON pool_import_receipts"
        )
        op.execute("DROP FUNCTION IF EXISTS pool_import_receipts_prevent_mutation()")
