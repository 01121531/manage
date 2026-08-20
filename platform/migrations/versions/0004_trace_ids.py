"""Add trace ids to task-bound resources.

Revision ID: 0004_trace_ids
Revises: 0003_task_lifecycle
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0004_trace_ids"
down_revision: str | None = "0003_task_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLES = ("tasks", "mail_sessions", "card_allocations", "upload_jobs")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("trace_id", sa.String(length=36), nullable=True))

    op.execute("UPDATE tasks SET trace_id = id WHERE trace_id IS NULL")
    op.execute(
        """
        UPDATE mail_sessions
        SET trace_id = tasks.trace_id
        FROM tasks
        WHERE mail_sessions.task_id = tasks.id
          AND mail_sessions.trace_id IS NULL
        """
    )
    op.execute("UPDATE mail_sessions SET trace_id = id WHERE trace_id IS NULL")
    op.execute(
        """
        UPDATE card_allocations
        SET trace_id = tasks.trace_id
        FROM tasks
        WHERE card_allocations.task_id = tasks.id
          AND card_allocations.trace_id IS NULL
        """
    )
    op.execute("UPDATE card_allocations SET trace_id = id WHERE trace_id IS NULL")
    op.execute(
        """
        UPDATE upload_jobs
        SET trace_id = tasks.trace_id
        FROM tasks
        WHERE upload_jobs.task_id = tasks.id
          AND upload_jobs.trace_id IS NULL
        """
    )
    op.execute("UPDATE upload_jobs SET trace_id = id WHERE trace_id IS NULL")

    for table in _TABLES:
        op.alter_column(
            table,
            "trace_id",
            existing_type=sa.String(length=36),
            nullable=False,
        )
        op.create_index(f"ix_{table}_trace_id", table, ["trace_id"])


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_index(f"ix_{table}_trace_id", table_name=table)
        op.drop_column(table, "trace_id")
