"""Record card claim context and position changes in an append-only ledger.

Revision ID: 0041_card_claim_mutation_ledger
Revises: 0040_card_claim_identity_immutable
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0041_card_claim_mutation_ledger"
down_revision: str | None = "0040_card_claim_identity_immutable"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_RECORD_TRIGGER = """
CREATE TRIGGER pool_import_card_claim_mutations_record
AFTER UPDATE OF context_id, position ON pool_import_card_identity_claims
WHEN NEW.context_id IS NOT OLD.context_id
  OR NEW.position IS NOT OLD.position
BEGIN
    INSERT INTO pool_import_card_claim_mutations (
        tenant_id,
        source_context_id,
        source_position,
        destination_context_id,
        destination_position,
        destination_trace_id,
        created_at
    ) VALUES (
        NEW.tenant_id,
        OLD.context_id,
        OLD.position,
        NEW.context_id,
        NEW.position,
        (
            SELECT trace_id
            FROM pool_import_contexts
            WHERE id = NEW.context_id
              AND tenant_id = NEW.tenant_id
              AND pool_type = 'card'
        ),
        CURRENT_TIMESTAMP
    );
END;
"""

_SQLITE_UPDATE_GUARD = """
CREATE TRIGGER pool_import_card_claim_mutations_no_update
BEFORE UPDATE ON pool_import_card_claim_mutations
BEGIN
    SELECT RAISE(ABORT, 'card claim mutation ledger is append-only');
END;
"""

_SQLITE_DELETE_GUARD = """
CREATE TRIGGER pool_import_card_claim_mutations_no_delete
BEFORE DELETE ON pool_import_card_claim_mutations
BEGIN
    SELECT RAISE(ABORT, 'card claim mutation ledger is append-only');
END;
"""

_POSTGRES_RECORD_FUNCTION = """
CREATE FUNCTION pool_import_card_claim_mutations_record()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.context_id IS NOT DISTINCT FROM OLD.context_id
       AND NEW.position IS NOT DISTINCT FROM OLD.position THEN
        RETURN NEW;
    END IF;
    INSERT INTO pool_import_card_claim_mutations (
        tenant_id,
        source_context_id,
        source_position,
        destination_context_id,
        destination_position,
        destination_trace_id
    )
    SELECT
        NEW.tenant_id,
        OLD.context_id,
        OLD.position,
        NEW.context_id,
        NEW.position,
        pool_import_contexts.trace_id
    FROM pool_import_contexts
    WHERE pool_import_contexts.id = NEW.context_id
      AND pool_import_contexts.tenant_id = NEW.tenant_id
      AND pool_import_contexts.pool_type = 'card';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'card claim mutation destination binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""

_POSTGRES_MUTATION_GUARD_FUNCTION = """
CREATE FUNCTION pool_import_card_claim_mutations_prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'card claim mutation ledger is append-only'
        USING ERRCODE = '55000';
END;
$$;
"""


def upgrade() -> None:
    op.create_table(
        "pool_import_card_claim_mutations",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                  autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("source_context_id", sa.String(length=36), nullable=False),
        sa.Column("source_position", sa.Integer(), nullable=False),
        sa.Column("destination_context_id", sa.String(length=36), nullable=False),
        sa.Column("destination_position", sa.Integer(), nullable=False),
        sa.Column("destination_trace_id", sa.String(length=36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "source_position >= 0 AND source_position < 100",
            name="ck_pool_import_card_claim_mutations_source_position",
        ),
        sa.CheckConstraint(
            "destination_position >= 0 AND destination_position < 100",
            name="ck_pool_import_card_claim_mutations_destination_position",
        ),
        sa.CheckConstraint(
            "source_context_id <> destination_context_id "
            "OR source_position <> destination_position",
            name="ck_pool_import_card_claim_mutations_changed",
        ),
        sa.ForeignKeyConstraint(
            ["source_context_id"], ["pool_import_contexts.id"]
        ),
        sa.ForeignKeyConstraint(
            ["destination_context_id"], ["pool_import_contexts.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_pool_import_card_claim_mutations_tenant_id",
        "pool_import_card_claim_mutations",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_pool_import_card_claim_mutations_destination_trace_id",
        "pool_import_card_claim_mutations",
        ["destination_trace_id"],
        unique=False,
    )
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_RECORD_TRIGGER)
        op.execute(_SQLITE_UPDATE_GUARD)
        op.execute(_SQLITE_DELETE_GUARD)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_RECORD_FUNCTION)
        op.execute(_POSTGRES_MUTATION_GUARD_FUNCTION)
        op.execute(
            "CREATE TRIGGER pool_import_card_claim_mutations_record "
            "AFTER UPDATE OF context_id, position ON "
            "pool_import_card_identity_claims FOR EACH ROW EXECUTE FUNCTION "
            "pool_import_card_claim_mutations_record()"
        )
        op.execute(
            "CREATE TRIGGER pool_import_card_claim_mutations_no_update "
            "BEFORE UPDATE ON pool_import_card_claim_mutations FOR EACH ROW "
            "EXECUTE FUNCTION pool_import_card_claim_mutations_prevent_mutation()"
        )
        op.execute(
            "CREATE TRIGGER pool_import_card_claim_mutations_no_delete "
            "BEFORE DELETE ON pool_import_card_claim_mutations FOR EACH ROW "
            "EXECUTE FUNCTION pool_import_card_claim_mutations_prevent_mutation()"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_record"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_no_update"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_no_delete"
        )
    elif dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_record "
            "ON pool_import_card_identity_claims"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_no_update "
            "ON pool_import_card_claim_mutations"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS pool_import_card_claim_mutations_no_delete "
            "ON pool_import_card_claim_mutations"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS pool_import_card_claim_mutations_record()"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "pool_import_card_claim_mutations_prevent_mutation()"
        )
    op.drop_index(
        "ix_pool_import_card_claim_mutations_destination_trace_id",
        table_name="pool_import_card_claim_mutations",
    )
    op.drop_index(
        "ix_pool_import_card_claim_mutations_tenant_id",
        table_name="pool_import_card_claim_mutations",
    )
    op.drop_table("pool_import_card_claim_mutations")
