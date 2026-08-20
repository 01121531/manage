"""Add production OIDC identity mapping and RBAC roles.

Revision ID: 0002_oidc_and_roles
Revises: 0001_baseline
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0002_oidc_and_roles"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("role", sa.String(length=32), server_default="operator", nullable=False),
    )
    op.create_index("ix_users_role", "users", ["role"])
    op.add_column(
        "users", sa.Column("oidc_subject", sa.String(length=255), nullable=True)
    )
    op.create_unique_constraint(
        "uq_users_tenant_oidc_subject", "users", ["tenant_id", "oidc_subject"]
    )
    op.alter_column(
        "users",
        "password_hash",
        existing_type=sa.String(length=512),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "users",
        "password_hash",
        existing_type=sa.String(length=512),
        nullable=False,
    )
    op.drop_constraint("uq_users_tenant_oidc_subject", "users", type_="unique")
    op.drop_column("users", "oidc_subject")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_column("users", "role")
