"""Prevent deletion of card identity claims.

Revision ID: 0039_card_claim_delete_guard
Revises: 0038_card_claim_context_binding
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0039_card_claim_delete_guard"
down_revision: str | None = "0038_card_claim_context_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_DELETE_GUARD = """
CREATE TRIGGER pool_import_card_identity_claims_no_delete
BEFORE DELETE ON pool_import_card_identity_claims
BEGIN
    SELECT RAISE(ABORT, 'card identity claim deletion is forbidden');
END;
"""

_POSTGRES_DELETE_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_card_identity_claims_prevent_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'card identity claim deletion is forbidden'
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
            "CREATE TRIGGER pool_import_card_identity_claims_no_delete "
            "BEFORE DELETE ON pool_import_card_identity_claims FOR EACH ROW "
            "EXECUTE FUNCTION pool_import_card_identity_claims_prevent_delete()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_identity_claims_no_delete"
        )
        return
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_identity_claims_no_delete "
            "ON pool_import_card_identity_claims"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_card_identity_claims_prevent_delete()"
        )
