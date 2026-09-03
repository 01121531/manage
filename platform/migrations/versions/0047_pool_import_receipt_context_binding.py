"""Bind every new local pool import receipt to its exact target context.

Revision ID: 0047_pool_import_receipt_context_binding
Revises: 0046_pool_import_context_delete_guard
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0047_pool_import_receipt_context_binding"
down_revision: str | None = "0046_pool_import_context_delete_guard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_INSERT_GUARD = """
CREATE TRIGGER pool_import_receipts_context_binding
BEFORE INSERT ON pool_import_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM pool_import_contexts
    WHERE NEW.idempotency_key = 'spi:' || pool_import_contexts.id
      AND pool_import_contexts.id = substr(NEW.idempotency_key, 5)
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = NEW.pool_type
      AND pool_import_contexts.ordered_manifest_digest = NEW.request_digest
      AND pool_import_contexts.item_count = NEW.item_count
      AND pool_import_contexts.created_by = NEW.created_by
      AND pool_import_contexts.device_id = NEW.device_id
      AND pool_import_contexts.consumed_at IS NULL
      AND pool_import_contexts.pool_import_receipt_id IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'pool import receipt context binding invalid');
END;
"""

_POSTGRES_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_receipts_validate_context_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM pool_import_contexts
    WHERE NEW.idempotency_key = 'spi:' || pool_import_contexts.id
      AND pool_import_contexts.id = substring(NEW.idempotency_key from 5)
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = NEW.pool_type
      AND pool_import_contexts.ordered_manifest_digest = NEW.request_digest
      AND pool_import_contexts.item_count = NEW.item_count
      AND pool_import_contexts.created_by = NEW.created_by
      AND pool_import_contexts.device_id = NEW.device_id
      AND pool_import_contexts.consumed_at IS NULL
      AND pool_import_contexts.pool_import_receipt_id IS NULL
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pool import receipt context binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_INSERT_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_receipts_context_binding BEFORE INSERT "
            "ON pool_import_receipts FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_receipts_validate_context_binding()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS pool_import_receipts_context_binding")
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_receipts_context_binding "
            "ON pool_import_receipts"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_receipts_validate_context_binding()"
        )
