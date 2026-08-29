"""Add masked card events and allocation release reasons.

Revision ID: 0023_card_events
Revises: 0022_card_quarantine
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0023_card_events"
down_revision: str | None = "0022_card_quarantine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_NO_UPDATE = """
CREATE TRIGGER card_events_no_update
BEFORE UPDATE ON card_events
BEGIN
    SELECT RAISE(ABORT, 'card_events are append-only');
END;
"""

_SQLITE_NO_DELETE = """
CREATE TRIGGER card_events_no_delete
BEFORE DELETE ON card_events
BEGIN
    SELECT RAISE(ABORT, 'card_events are append-only');
END;
"""

_SQLITE_BINDING = """
CREATE TRIGGER card_events_subject_binding
BEFORE INSERT ON card_events
WHEN
    NOT EXISTS (
        SELECT 1 FROM cards
        WHERE cards.id = NEW.card_id
          AND cards.tenant_id = NEW.tenant_id
    )
    OR (
        NEW.allocation_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM card_allocations
            WHERE card_allocations.id = NEW.allocation_id
              AND card_allocations.tenant_id = NEW.tenant_id
              AND card_allocations.card_id = NEW.card_id
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'card_events subject binding invalid');
END;
"""

_POSTGRES_APPEND_ONLY_FUNCTION = """
CREATE FUNCTION card_events_prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'card_events are append-only';
END;
$$;
"""

_POSTGRES_BINDING_FUNCTION = """
CREATE FUNCTION card_events_validate_subject_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF
        NOT EXISTS (
            SELECT 1 FROM cards
            WHERE cards.id = NEW.card_id
              AND cards.tenant_id = NEW.tenant_id
        )
        OR (
            NEW.allocation_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM card_allocations
                WHERE card_allocations.id = NEW.allocation_id
                  AND card_allocations.tenant_id = NEW.tenant_id
                  AND card_allocations.card_id = NEW.card_id
            )
        )
    THEN
        RAISE EXCEPTION 'card_events subject binding invalid'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;
"""


def _install_card_event_guards() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute(_SQLITE_NO_UPDATE)
        op.execute(_SQLITE_NO_DELETE)
        op.execute(_SQLITE_BINDING)
        return
    if dialect == "postgresql":
        op.execute(_POSTGRES_APPEND_ONLY_FUNCTION)
        op.execute(_POSTGRES_BINDING_FUNCTION)
        op.execute(
            "CREATE TRIGGER card_events_no_update BEFORE UPDATE ON card_events "
            "FOR EACH ROW EXECUTE FUNCTION card_events_prevent_mutation()"
        )
        op.execute(
            "CREATE TRIGGER card_events_no_delete BEFORE DELETE ON card_events "
            "FOR EACH ROW EXECUTE FUNCTION card_events_prevent_mutation()"
        )
        op.execute(
            "CREATE TRIGGER card_events_subject_binding BEFORE INSERT ON card_events "
            "FOR EACH ROW EXECUTE FUNCTION card_events_validate_subject_binding()"
        )


def upgrade() -> None:
    op.add_column(
        "card_allocations",
        sa.Column("release_reason_code", sa.String(length=80), nullable=True),
    )
    op.create_table(
        "card_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("card_id", sa.String(length=36), nullable=False),
        sa.Column("allocation_id", sa.String(length=36), nullable=True),
        sa.Column("actor_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=True),
        sa.Column("before_masked", sa.Text(), nullable=False),
        sa.Column("after_masked", sa.Text(), nullable=False),
        sa.Column("trace_id", sa.String(length=36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(["allocation_id"], ["card_allocations.id"]),
        sa.ForeignKeyConstraint(["card_id"], ["cards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_card_events_tenant_created_at_id",
        "card_events",
        ["tenant_id", "created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_card_events_tenant_card_created_at_id",
        "card_events",
        ["tenant_id", "card_id", "created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_card_events_tenant_allocation_created_at_id",
        "card_events",
        ["tenant_id", "allocation_id", "created_at", "id"],
        unique=False,
    )
    _install_card_event_guards()


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS card_events_subject_binding")
        op.execute("DROP TRIGGER IF EXISTS card_events_no_delete")
        op.execute("DROP TRIGGER IF EXISTS card_events_no_update")
    elif dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS card_events_subject_binding ON card_events")
        op.execute("DROP TRIGGER IF EXISTS card_events_no_delete ON card_events")
        op.execute("DROP TRIGGER IF EXISTS card_events_no_update ON card_events")
        op.execute("DROP FUNCTION IF EXISTS card_events_validate_subject_binding()")
        op.execute("DROP FUNCTION IF EXISTS card_events_prevent_mutation()")
    op.drop_table("card_events")
    with op.batch_alter_table("card_allocations") as batch_op:
        batch_op.drop_column("release_reason_code")
