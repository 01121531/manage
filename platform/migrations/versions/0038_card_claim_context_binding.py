"""Enforce card identity claim bindings to authoritative pool contexts.

Revision ID: 0038_card_claim_context_binding
Revises: 0037_pool_import_card_identity_claims
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0038_card_claim_context_binding"
down_revision: str | None = "0037_pool_import_card_identity_claims"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INVALID_BINDING_QUERY = """
SELECT pool_import_card_identity_claims.context_id
FROM pool_import_card_identity_claims
LEFT JOIN pool_import_contexts
  ON pool_import_contexts.id = pool_import_card_identity_claims.context_id
 AND pool_import_contexts.tenant_id = pool_import_card_identity_claims.tenant_id
 AND pool_import_contexts.pool_type = 'card'
WHERE pool_import_contexts.id IS NULL
LIMIT 1
"""

_POSTGRES_PREFLIGHT_QUERY = """
SELECT 1 / (1 - COUNT(*)) AS card_claim_context_bindings_valid
FROM (
    SELECT 1
    FROM pool_import_card_identity_claims
    LEFT JOIN pool_import_contexts
      ON pool_import_contexts.id = pool_import_card_identity_claims.context_id
     AND pool_import_contexts.tenant_id = pool_import_card_identity_claims.tenant_id
     AND pool_import_contexts.pool_type = 'card'
    WHERE pool_import_contexts.id IS NULL
    LIMIT 1
) AS invalid_card_claim_context_binding
"""

_SQLITE_CLAIM_INSERT_TRIGGER = """
CREATE TRIGGER pool_import_card_identity_claims_context_binding_insert
BEFORE INSERT ON pool_import_card_identity_claims
WHEN NOT EXISTS (
    SELECT 1 FROM pool_import_contexts
    WHERE pool_import_contexts.id = NEW.context_id
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = 'card'
)
BEGIN
    SELECT RAISE(ABORT, 'card identity claim context binding invalid');
END;
"""

_SQLITE_CLAIM_UPDATE_TRIGGER = """
CREATE TRIGGER pool_import_card_identity_claims_context_binding_update
BEFORE UPDATE OF context_id, tenant_id ON pool_import_card_identity_claims
WHEN NOT EXISTS (
    SELECT 1 FROM pool_import_contexts
    WHERE pool_import_contexts.id = NEW.context_id
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = 'card'
)
BEGIN
    SELECT RAISE(ABORT, 'card identity claim context binding invalid');
END;
"""

_SQLITE_CONTEXT_UPDATE_TRIGGER = """
CREATE TRIGGER pool_import_contexts_card_claim_binding
BEFORE UPDATE OF id, tenant_id, pool_type ON pool_import_contexts
WHEN (
    NEW.id IS NOT OLD.id
    OR NEW.tenant_id IS NOT OLD.tenant_id
    OR NEW.pool_type IS NOT OLD.pool_type
) AND EXISTS (
    SELECT 1 FROM pool_import_card_identity_claims
    WHERE pool_import_card_identity_claims.context_id = OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'card identity claim context binding invalid');
END;
"""

_POSTGRES_CLAIM_FUNCTION = """
CREATE FUNCTION pool_import_card_identity_claims_validate_context_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM pool_import_contexts
    WHERE pool_import_contexts.id = NEW.context_id
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = 'card'
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'card identity claim context binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""

_POSTGRES_CONTEXT_FUNCTION = """
CREATE FUNCTION pool_import_contexts_validate_card_claim_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (
        NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.pool_type IS DISTINCT FROM OLD.pool_type
    ) AND EXISTS (
        SELECT 1 FROM pool_import_card_identity_claims
        WHERE pool_import_card_identity_claims.context_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'card identity claim context binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""


def _preflight_card_claim_context_bindings() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_POSTGRES_PREFLIGHT_QUERY)
        return
    invalid = op.get_bind().execute(sa.text(_INVALID_BINDING_QUERY)).first()
    if invalid is not None:
        raise RuntimeError(
            "Invalid card claim context bindings must be remediated before migration"
        )


def upgrade() -> None:
    _preflight_card_claim_context_bindings()
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_CLAIM_INSERT_TRIGGER)
        op.execute(_SQLITE_CLAIM_UPDATE_TRIGGER)
        op.execute(_SQLITE_CONTEXT_UPDATE_TRIGGER)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_CLAIM_FUNCTION)
        op.execute(_POSTGRES_CONTEXT_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_card_identity_claims_context_binding_insert "
            "BEFORE INSERT ON pool_import_card_identity_claims FOR EACH ROW EXECUTE "
            "FUNCTION pool_import_card_identity_claims_validate_context_binding()"
        )
        op.execute(
            "CREATE TRIGGER pool_import_card_identity_claims_context_binding_update "
            "BEFORE UPDATE OF context_id, tenant_id ON "
            "pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_card_identity_claims_validate_context_binding()"
        )
        op.execute(
            "CREATE TRIGGER pool_import_contexts_card_claim_binding BEFORE UPDATE OF "
            "id, tenant_id, pool_type ON pool_import_contexts FOR EACH ROW EXECUTE "
            "FUNCTION pool_import_contexts_validate_card_claim_binding()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_context_binding_insert"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_context_binding_update"
        )
        op.execute("DROP TRIGGER IF EXISTS pool_import_contexts_card_claim_binding")
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_context_binding_insert "
            "ON pool_import_card_identity_claims"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_context_binding_update "
            "ON pool_import_card_identity_claims"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_contexts_card_claim_binding "
            "ON pool_import_contexts"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_card_identity_claims_validate_context_binding()"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_contexts_validate_card_claim_binding()"
        )
