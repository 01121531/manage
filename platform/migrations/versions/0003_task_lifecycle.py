"""Add explicit task expiry and close timestamps.

Revision ID: 0003_task_lifecycle
Revises: 0002_oidc_and_roles
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003_task_lifecycle"
down_revision: str | None = "0002_oidc_and_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("tasks", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_tasks_expires_at", "tasks", ["expires_at"])
    op.create_index("ix_tasks_closed_at", "tasks", ["closed_at"])


def downgrade() -> None:
    op.drop_index("ix_tasks_closed_at", table_name="tasks")
    op.drop_index("ix_tasks_expires_at", table_name="tasks")
    op.drop_column("tasks", "closed_at")
    op.drop_column("tasks", "expires_at")
