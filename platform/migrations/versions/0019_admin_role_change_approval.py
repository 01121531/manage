"""Add four-eye approval state for administrator role changes.

Revision ID: 0019_admin_role_change_approval
Revises: 0018_access_token_revocations
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0019_admin_role_change_approval"
down_revision: str | None = "0018_access_token_revocations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_role_change_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("target_user_id", sa.String(length=36), nullable=False),
        sa.Column("expected_old_role", sa.String(length=32), nullable=False),
        sa.Column("new_role", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("requested_by", sa.String(length=36), nullable=False),
        sa.Column("approved_by", sa.String(length=36), nullable=True),
        sa.Column("request_trace_id", sa.String(length=36), nullable=False),
        sa.Column("approval_trace_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "expected_old_role IN ('operator', 'ops_admin', "
            "'security_auditor', 'platform_admin')",
            name="ck_admin_role_change_requests_expected_old_role",
        ),
        sa.CheckConstraint(
            "new_role IN ('operator', 'ops_admin', "
            "'security_auditor', 'platform_admin')",
            name="ck_admin_role_change_requests_new_role",
        ),
        sa.CheckConstraint(
            "expected_old_role <> new_role",
            name="ck_admin_role_change_requests_role_changes",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'applied', 'expired')",
            name="ck_admin_role_change_requests_status",
        ),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_admin_role_change_requests_four_eye",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND approved_by IS NULL AND "
            "approval_trace_id IS NULL AND applied_at IS NULL) OR "
            "(status = 'applied' AND approved_by IS NOT NULL AND "
            "approval_trace_id IS NOT NULL AND applied_at IS NOT NULL) OR "
            "(status = 'expired' AND approved_by IS NULL AND "
            "approval_trace_id IS NULL AND applied_at IS NULL)",
            name="ck_admin_role_change_requests_state_fields",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_admin_role_change_requests_expiry",
        ),
        sa.CheckConstraint(
            "applied_at IS NULL OR "
            "(applied_at >= created_at AND applied_at <= expires_at)",
            name="ck_admin_role_change_requests_applied_at",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_admin_role_change_requests_pending_target",
        "admin_role_change_requests",
        ["tenant_id", "target_user_id"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_admin_role_change_requests_tenant_status_created",
        "admin_role_change_requests",
        ["tenant_id", "status", "created_at"],
    )
    op.create_index(
        "ix_admin_role_change_requests_tenant_requested_by",
        "admin_role_change_requests",
        ["tenant_id", "requested_by"],
    )
    op.create_index(
        "ix_admin_role_change_requests_tenant_approved_by",
        "admin_role_change_requests",
        ["tenant_id", "approved_by"],
    )
    op.create_index(
        "ix_admin_role_change_requests_tenant_request_trace",
        "admin_role_change_requests",
        ["tenant_id", "request_trace_id"],
    )
    op.create_index(
        "ix_admin_role_change_requests_tenant_approval_trace",
        "admin_role_change_requests",
        ["tenant_id", "approval_trace_id"],
    )


def downgrade() -> None:
    for name in (
        "ix_admin_role_change_requests_tenant_approval_trace",
        "ix_admin_role_change_requests_tenant_request_trace",
        "ix_admin_role_change_requests_tenant_approved_by",
        "ix_admin_role_change_requests_tenant_requested_by",
        "ix_admin_role_change_requests_tenant_status_created",
        "uq_admin_role_change_requests_pending_target",
    ):
        op.drop_index(name, table_name="admin_role_change_requests")
    op.drop_table("admin_role_change_requests")
