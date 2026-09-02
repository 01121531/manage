"""Make target-issued pool import context identity immutable.

Revision ID: 0042_pool_context_identity_lock
Revises: 0041_card_claim_mutation_ledger
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0042_pool_context_identity_lock"
down_revision: str | None = "0041_card_claim_mutation_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_IDENTITY_GUARD = """
CREATE TRIGGER pool_import_contexts_identity_immutable
BEFORE UPDATE OF id, context_token_hash, tenant_id, audience, pool_type,
    ordered_manifest_digest, item_count, created_by, device_id, trace_id,
    created_at ON pool_import_contexts
WHEN NEW.id IS NOT OLD.id
  OR NEW.context_token_hash IS NOT OLD.context_token_hash
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.audience IS NOT OLD.audience
  OR NEW.pool_type IS NOT OLD.pool_type
  OR NEW.ordered_manifest_digest IS NOT OLD.ordered_manifest_digest
  OR NEW.item_count IS NOT OLD.item_count
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.device_id IS NOT OLD.device_id
  OR NEW.trace_id IS NOT OLD.trace_id
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'pool import context identity is immutable');
END;
"""

_POSTGRES_IDENTITY_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_contexts_prevent_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.context_token_hash IS DISTINCT FROM OLD.context_token_hash
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.pool_type IS DISTINCT FROM OLD.pool_type
       OR NEW.ordered_manifest_digest IS DISTINCT FROM OLD.ordered_manifest_digest
       OR NEW.item_count IS DISTINCT FROM OLD.item_count
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.device_id IS DISTINCT FROM OLD.device_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'pool import context identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
"""


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_IDENTITY_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_IDENTITY_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_contexts_identity_immutable BEFORE "
            "UPDATE OF id, context_token_hash, tenant_id, audience, pool_type, "
            "ordered_manifest_digest, item_count, created_by, device_id, "
            "trace_id, created_at ON pool_import_contexts FOR EACH ROW EXECUTE "
            "FUNCTION pool_import_contexts_prevent_identity_change()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_contexts_identity_immutable"
        )
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_contexts_identity_immutable "
            "ON pool_import_contexts"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_contexts_prevent_identity_change()"
        )
