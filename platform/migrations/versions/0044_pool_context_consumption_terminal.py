"""Make pool import context consumption a one-way terminal transition.

Revision ID: 0044_pool_context_consumption_terminal
Revises: 0043_secure_consumption_lock
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0044_pool_context_consumption_terminal"
down_revision: str | None = "0043_secure_consumption_lock"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INVALID_LIFECYCLE_QUERY = """
SELECT pool_import_contexts.id
FROM pool_import_contexts
WHERE
    (pool_import_contexts.consumed_at IS NULL)
        <> (pool_import_contexts.pool_import_receipt_id IS NULL)
    OR (
        pool_import_contexts.consumed_at IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM pool_import_receipts
            JOIN secure_pool_import_consumptions
              ON secure_pool_import_consumptions.pool_import_receipt_id
                 = pool_import_receipts.id
            WHERE pool_import_receipts.id
                    = pool_import_contexts.pool_import_receipt_id
              AND secure_pool_import_consumptions.receipt_id
                    = pool_import_contexts.id
              AND pool_import_receipts.tenant_id
                    = pool_import_contexts.tenant_id
              AND pool_import_receipts.pool_type
                    = pool_import_contexts.pool_type
              AND pool_import_receipts.request_digest
                    = pool_import_contexts.ordered_manifest_digest
              AND pool_import_receipts.item_count
                    = pool_import_contexts.item_count
              AND pool_import_receipts.created_by
                    = pool_import_contexts.created_by
              AND pool_import_receipts.device_id
                    = pool_import_contexts.device_id
        )
    )
LIMIT 1
"""

_POSTGRES_PREFLIGHT_QUERY = """
SELECT 1 / (1 - COUNT(*)) AS pool_context_consumption_lifecycle_valid
FROM (
    SELECT pool_import_contexts.id
    FROM pool_import_contexts
    WHERE
        (pool_import_contexts.consumed_at IS NULL)
            <> (pool_import_contexts.pool_import_receipt_id IS NULL)
        OR (
            pool_import_contexts.consumed_at IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM pool_import_receipts
                JOIN secure_pool_import_consumptions
                  ON secure_pool_import_consumptions.pool_import_receipt_id
                     = pool_import_receipts.id
                WHERE pool_import_receipts.id
                        = pool_import_contexts.pool_import_receipt_id
                  AND secure_pool_import_consumptions.receipt_id
                        = pool_import_contexts.id
                  AND pool_import_receipts.tenant_id
                        = pool_import_contexts.tenant_id
                  AND pool_import_receipts.pool_type
                        = pool_import_contexts.pool_type
                  AND pool_import_receipts.request_digest
                        = pool_import_contexts.ordered_manifest_digest
                  AND pool_import_receipts.item_count
                        = pool_import_contexts.item_count
                  AND pool_import_receipts.created_by
                        = pool_import_contexts.created_by
                  AND pool_import_receipts.device_id
                        = pool_import_contexts.device_id
            )
        )
    LIMIT 1
) AS invalid_pool_context_consumption_lifecycle
"""

_SQLITE_INSERT_GUARD = """
CREATE TRIGGER pool_import_contexts_consumption_lifecycle_insert
BEFORE INSERT ON pool_import_contexts
WHEN NEW.consumed_at IS NOT NULL
  OR NEW.pool_import_receipt_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'pool import context must start unconsumed');
END;
"""

_SQLITE_UPDATE_GUARD = """
CREATE TRIGGER pool_import_contexts_consumption_lifecycle_update
BEFORE UPDATE OF expires_at, consumed_at, pool_import_receipt_id
ON pool_import_contexts
WHEN
    (NEW.consumed_at IS NULL) <> (NEW.pool_import_receipt_id IS NULL)
    OR (
        (OLD.consumed_at IS NOT NULL
         OR OLD.pool_import_receipt_id IS NOT NULL)
        AND (
            NEW.expires_at IS NOT OLD.expires_at
            OR NEW.consumed_at IS NOT OLD.consumed_at
            OR NEW.pool_import_receipt_id IS NOT OLD.pool_import_receipt_id
        )
    )
    OR (
        OLD.consumed_at IS NULL
        AND OLD.pool_import_receipt_id IS NULL
        AND NEW.consumed_at IS NOT NULL
        AND NEW.pool_import_receipt_id IS NOT NULL
        AND (
            NEW.expires_at IS NOT OLD.expires_at
            OR NOT EXISTS (
                SELECT 1
                FROM pool_import_receipts
                JOIN secure_pool_import_consumptions
                  ON secure_pool_import_consumptions.pool_import_receipt_id
                     = pool_import_receipts.id
                WHERE pool_import_receipts.id = NEW.pool_import_receipt_id
                  AND secure_pool_import_consumptions.receipt_id = NEW.id
                  AND pool_import_receipts.tenant_id = NEW.tenant_id
                  AND pool_import_receipts.pool_type = NEW.pool_type
                  AND pool_import_receipts.request_digest
                        = NEW.ordered_manifest_digest
                  AND pool_import_receipts.item_count = NEW.item_count
                  AND pool_import_receipts.created_by = NEW.created_by
                  AND pool_import_receipts.device_id = NEW.device_id
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'pool import context consumption lifecycle invalid');
END;
"""

_POSTGRES_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_contexts_validate_consumption_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.consumed_at IS NOT NULL
           OR NEW.pool_import_receipt_id IS NOT NULL THEN
            RAISE EXCEPTION 'pool import context must start unconsumed'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.consumed_at IS NULL)
       <> (NEW.pool_import_receipt_id IS NULL) THEN
        RAISE EXCEPTION 'pool import context consumption lifecycle invalid'
            USING ERRCODE = '55000';
    END IF;

    IF (OLD.consumed_at IS NOT NULL
        OR OLD.pool_import_receipt_id IS NOT NULL) THEN
        IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
           OR NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
           OR NEW.pool_import_receipt_id
                IS DISTINCT FROM OLD.pool_import_receipt_id THEN
            RAISE EXCEPTION 'pool import context consumption is terminal'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.consumed_at IS NOT NULL THEN
        IF NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
            RAISE EXCEPTION 'pool import context expiry cannot change on consumption'
                USING ERRCODE = '55000';
        END IF;
        PERFORM 1
        FROM pool_import_receipts
        JOIN secure_pool_import_consumptions
          ON secure_pool_import_consumptions.pool_import_receipt_id
             = pool_import_receipts.id
        WHERE pool_import_receipts.id = NEW.pool_import_receipt_id
          AND secure_pool_import_consumptions.receipt_id = NEW.id
          AND pool_import_receipts.tenant_id = NEW.tenant_id
          AND pool_import_receipts.pool_type = NEW.pool_type
          AND pool_import_receipts.request_digest = NEW.ordered_manifest_digest
          AND pool_import_receipts.item_count = NEW.item_count
          AND pool_import_receipts.created_by = NEW.created_by
          AND pool_import_receipts.device_id = NEW.device_id
        FOR KEY SHARE OF pool_import_receipts,
                         secure_pool_import_consumptions;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'pool import context receipt binding invalid'
                USING ERRCODE = '23503';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
"""


def _preflight_consumption_lifecycle() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_POSTGRES_PREFLIGHT_QUERY)
        return
    invalid = op.get_bind().execute(sa.text(_INVALID_LIFECYCLE_QUERY)).first()
    if invalid is not None:
        raise RuntimeError(
            "Invalid pool import context consumption lifecycle must be "
            "remediated before migration"
        )


def upgrade() -> None:
    _preflight_consumption_lifecycle()
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_INSERT_GUARD)
        op.execute(_SQLITE_UPDATE_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_contexts_consumption_lifecycle BEFORE "
            "INSERT OR UPDATE OF expires_at, consumed_at, "
            "pool_import_receipt_id ON pool_import_contexts FOR EACH ROW "
            "EXECUTE FUNCTION "
            "pool_import_contexts_validate_consumption_lifecycle()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_contexts_consumption_lifecycle_insert"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_contexts_consumption_lifecycle_update"
        )
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_contexts_consumption_lifecycle "
            "ON pool_import_contexts"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_contexts_validate_consumption_lifecycle()"
        )
