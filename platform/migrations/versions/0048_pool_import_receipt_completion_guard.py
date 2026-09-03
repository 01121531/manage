"""Require every new pool import receipt to finish in the same transaction.

Revision ID: 0048_pool_import_receipt_completion_guard
Revises: 0047_pool_import_receipt_context_binding
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0048_pool_import_receipt_completion_guard"
down_revision: str | None = "0047_pool_import_receipt_context_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POSTGRES_COMPLETION_FUNCTION = """
CREATE FUNCTION pool_import_receipts_validate_completion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM pool_import_contexts AS bound_context
    JOIN secure_pool_import_consumptions AS secure_consumption
      ON secure_consumption.pool_import_receipt_id = NEW.id
    WHERE bound_context.pool_import_receipt_id = NEW.id
      AND bound_context.id = substring(NEW.idempotency_key from 5)
      AND bound_context.tenant_id = NEW.tenant_id
      AND bound_context.pool_type = NEW.pool_type
      AND bound_context.ordered_manifest_digest = NEW.request_digest
      AND bound_context.item_count = NEW.item_count
      AND bound_context.created_by = NEW.created_by
      AND bound_context.device_id = NEW.device_id
      AND bound_context.consumed_at IS NOT NULL
    FOR KEY SHARE OF bound_context, secure_consumption;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pool import receipt completion invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(_POSTGRES_COMPLETION_FUNCTION)
    op.execute(
        "CREATE CONSTRAINT TRIGGER pool_import_receipts_completion_guard "
        "AFTER INSERT ON pool_import_receipts DEFERRABLE INITIALLY DEFERRED "
        "FOR EACH ROW EXECUTE FUNCTION "
        "pool_import_receipts_validate_completion()"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS pool_import_receipts_completion_guard "
        "ON pool_import_receipts"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS pool_import_receipts_validate_completion()"
    )
