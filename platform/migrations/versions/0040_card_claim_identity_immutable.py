"""Make card identity claim tenant and provider reference immutable.

Revision ID: 0040_card_claim_identity_immutable
Revises: 0039_card_claim_delete_guard
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0040_card_claim_identity_immutable"
down_revision: str | None = "0039_card_claim_delete_guard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_IDENTITY_GUARD = """
CREATE TRIGGER pool_import_card_identity_claims_identity_immutable
BEFORE UPDATE OF tenant_id, provider_ref ON pool_import_card_identity_claims
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.provider_ref IS NOT OLD.provider_ref
BEGIN
    SELECT RAISE(ABORT, 'card identity claim identity is immutable');
END;
"""

_POSTGRES_IDENTITY_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_card_identity_claims_prevent_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.provider_ref IS DISTINCT FROM OLD.provider_ref THEN
        RAISE EXCEPTION 'card identity claim identity is immutable'
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
            "CREATE TRIGGER pool_import_card_identity_claims_identity_immutable "
            "BEFORE UPDATE OF tenant_id, provider_ref ON "
            "pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_card_identity_claims_prevent_identity_change()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_identity_immutable"
        )
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "pool_import_card_identity_claims_identity_immutable "
            "ON pool_import_card_identity_claims"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_card_identity_claims_prevent_identity_change()"
        )
