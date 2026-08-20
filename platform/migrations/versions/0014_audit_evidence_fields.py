"""Add explicit audit evidence fields required for incident replay.

Revision ID: 0014_audit_evidence_fields
Revises: 0013_card_secret_ref_unique
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0014_audit_evidence_fields"
down_revision: str | None = "0013_card_secret_ref_unique"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _drop_update_guard() -> None:
    if _is_postgresql():
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;")


def _restore_update_guard() -> None:
    if _is_postgresql():
        op.execute(
            """
            CREATE TRIGGER audit_events_no_update
            BEFORE UPDATE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION audit_events_prevent_mutation();
            """
        )


def upgrade() -> None:
    # Revision 0007 makes this table append-only. Temporarily remove only the
    # UPDATE guard inside the migration transaction so legacy rows can be
    # backfilled; the DELETE guard remains active throughout.
    _drop_update_guard()
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.add_column(sa.Column("actor_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("action", sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column("result", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("ip_address", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("user_agent", sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column("policy_version", sa.String(length=80), nullable=True))

    op.execute("UPDATE audit_events SET actor_id = user_id WHERE actor_id IS NULL")
    op.execute("UPDATE audit_events SET action = event_type WHERE action IS NULL")
    op.execute(
        """
        UPDATE audit_events
        SET result = CASE
            WHEN lower(event_type) LIKE '%unknown%' THEN 'unknown'
            WHEN lower(event_type) LIKE '%failed%'
              OR lower(event_type) LIKE '%failure%'
              OR lower(event_type) LIKE '%denied%'
              OR lower(event_type) LIKE '%error%' THEN 'failure'
            ELSE 'success'
        END
        WHERE result IS NULL
        """
    )

    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.alter_column("action", existing_type=sa.String(length=80), nullable=False)
        batch_op.alter_column("result", existing_type=sa.String(length=32), nullable=False)
        batch_op.create_index("ix_audit_events_actor_id", ["actor_id"], unique=False)
        batch_op.create_index("ix_audit_events_action", ["action"], unique=False)
        batch_op.create_index("ix_audit_events_result", ["result"], unique=False)
    _restore_update_guard()


def downgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_index("ix_audit_events_result")
        batch_op.drop_index("ix_audit_events_action")
        batch_op.drop_index("ix_audit_events_actor_id")
        batch_op.drop_column("policy_version")
        batch_op.drop_column("user_agent")
        batch_op.drop_column("ip_address")
        batch_op.drop_column("result")
        batch_op.drop_column("action")
        batch_op.drop_column("actor_id")
