"""Baseline platform schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-19

The migration deliberately stores only opaque secret-manager references for
mailboxes, cards and Sub2.  PAN, CVV, mailbox passwords and provider tokens
are not columns in this schema.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


_NOW = sa.text("CURRENT_TIMESTAMP")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "user_id", "name", name="uq_devices_tenant_user_name"
        ),
    )
    op.create_index("ix_devices_tenant_id", "devices", ["tenant_id"])
    op.create_index("ix_devices_user_id", "devices", ["user_id"])

    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("task_type", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("client_reference", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="created"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "user_id", "idempotency_key",
            name="uq_tasks_owner_idempotency_key",
        ),
    )
    op.create_index("ix_tasks_tenant_id", "tasks", ["tenant_id"])
    op.create_index("ix_tasks_user_id", "tasks", ["user_id"])
    op.create_index("ix_tasks_device_id", "tasks", ["device_id"])
    op.create_index("ix_tasks_created_at", "tasks", ["created_at"])

    op.create_table(
        "mailboxes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("email_masked", sa.String(length=320), nullable=False),
        sa.Column("connector_type", sa.String(length=80), nullable=False),
        sa.Column("secret_ref", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "secret_ref", name="uq_mailboxes_tenant_secret_ref"),
    )
    op.create_index("ix_mailboxes_tenant_id", "mailboxes", ["tenant_id"])
    op.create_index("ix_mailboxes_connector_type", "mailboxes", ["connector_type"])
    op.create_index("ix_mailboxes_is_active", "mailboxes", ["is_active"])

    op.create_table(
        "mail_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("mailbox_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="waiting"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("start_watermark", sa.String(length=512), nullable=True),
        sa.Column("last_message_hash", sa.String(length=64), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["mailbox_id"], ["mailboxes.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", name="uq_mail_sessions_task_id"),
    )
    op.create_index("ix_mail_sessions_tenant_id", "mail_sessions", ["tenant_id"])
    op.create_index("ix_mail_sessions_task_id", "mail_sessions", ["task_id"])
    op.create_index("ix_mail_sessions_user_id", "mail_sessions", ["user_id"])
    op.create_index("ix_mail_sessions_device_id", "mail_sessions", ["device_id"])
    op.create_index("ix_mail_sessions_status", "mail_sessions", ["status"])
    op.create_index("ix_mail_sessions_expires_at", "mail_sessions", ["expires_at"])
    op.create_index("ix_mail_sessions_created_at", "mail_sessions", ["created_at"])

    op.create_table(
        "cards",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("provider_ref", sa.String(length=160), nullable=False),
        sa.Column("brand", sa.String(length=40), nullable=False),
        sa.Column("last4", sa.String(length=4), nullable=False),
        sa.Column("expiry_month", sa.Integer(), nullable=True),
        sa.Column("expiry_year", sa.Integer(), nullable=True),
        sa.Column("secret_ref", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "provider_ref", name="uq_cards_tenant_provider_ref"),
    )
    op.create_index("ix_cards_tenant_id", "cards", ["tenant_id"])
    op.create_index("ix_cards_is_active", "cards", ["is_active"])
    op.create_index("ix_cards_created_at", "cards", ["created_at"])

    op.create_table(
        "card_allocations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("card_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["card_id"], ["cards.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_card_allocations_tenant_id", "card_allocations", ["tenant_id"])
    op.create_index("ix_card_allocations_task_id", "card_allocations", ["task_id"])
    op.create_index("ix_card_allocations_user_id", "card_allocations", ["user_id"])
    op.create_index("ix_card_allocations_device_id", "card_allocations", ["device_id"])
    op.create_index("ix_card_allocations_card_id", "card_allocations", ["card_id"])
    op.create_index("ix_card_allocations_status", "card_allocations", ["status"])
    op.create_index("ix_card_allocations_expires_at", "card_allocations", ["expires_at"])
    op.create_index("ix_card_allocations_released_at", "card_allocations", ["released_at"])
    op.create_index("ix_card_allocations_created_at", "card_allocations", ["created_at"])
    op.create_index(
        "uq_active_card_allocation_card",
        "card_allocations",
        ["card_id"],
        unique=True,
        postgresql_where=sa.text("released_at IS NULL"),
        sqlite_where=sa.text("released_at IS NULL"),
    )
    op.create_index(
        "uq_active_card_allocation_task",
        "card_allocations",
        ["task_id"],
        unique=True,
        postgresql_where=sa.text("released_at IS NULL"),
        sqlite_where=sa.text("released_at IS NULL"),
    )

    op.create_table(
        "upload_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("card_allocation_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("business_name", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.Column("external_ref", sa.String(length=160), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["card_allocation_id"], ["card_allocations.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "user_id", "idempotency_key",
            name="uq_upload_jobs_owner_idempotency_key",
        ),
    )
    op.create_index("ix_upload_jobs_tenant_id", "upload_jobs", ["tenant_id"])
    op.create_index("ix_upload_jobs_task_id", "upload_jobs", ["task_id"])
    op.create_index("ix_upload_jobs_user_id", "upload_jobs", ["user_id"])
    op.create_index("ix_upload_jobs_device_id", "upload_jobs", ["device_id"])
    op.create_index("ix_upload_jobs_card_allocation_id", "upload_jobs", ["card_allocation_id"])
    op.create_index("ix_upload_jobs_status", "upload_jobs", ["status"])
    op.create_index("ix_upload_jobs_created_at", "upload_jobs", ["created_at"])
    op.create_index("ix_upload_jobs_updated_at", "upload_jobs", ["updated_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("device_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("entity_type", sa.String(length=80), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=True),
        sa.Column("trace_id", sa.String(length=36), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_NOW),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_user_id", "audit_events", ["user_id"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_trace_id", "audit_events", ["trace_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_trace_id", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_index("ix_audit_events_user_id", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_id", table_name="audit_events")
    op.drop_table("audit_events")

    for name in (
        "ix_upload_jobs_updated_at",
        "ix_upload_jobs_created_at",
        "ix_upload_jobs_status",
        "ix_upload_jobs_card_allocation_id",
        "ix_upload_jobs_device_id",
        "ix_upload_jobs_user_id",
        "ix_upload_jobs_task_id",
        "ix_upload_jobs_tenant_id",
    ):
        op.drop_index(name, table_name="upload_jobs")
    op.drop_constraint("uq_upload_jobs_owner_idempotency_key", "upload_jobs", type_="unique")
    op.drop_table("upload_jobs")

    op.drop_index("uq_active_card_allocation_task", table_name="card_allocations")
    op.drop_index("uq_active_card_allocation_card", table_name="card_allocations")
    for name in (
        "ix_card_allocations_created_at",
        "ix_card_allocations_released_at",
        "ix_card_allocations_expires_at",
        "ix_card_allocations_status",
        "ix_card_allocations_card_id",
        "ix_card_allocations_device_id",
        "ix_card_allocations_user_id",
        "ix_card_allocations_task_id",
        "ix_card_allocations_tenant_id",
    ):
        op.drop_index(name, table_name="card_allocations")
    op.drop_table("card_allocations")

    for name in ("ix_cards_created_at", "ix_cards_is_active", "ix_cards_tenant_id"):
        op.drop_index(name, table_name="cards")
    op.drop_constraint("uq_cards_tenant_provider_ref", "cards", type_="unique")
    op.drop_table("cards")

    for name in (
        "ix_mail_sessions_created_at",
        "ix_mail_sessions_expires_at",
        "ix_mail_sessions_status",
        "ix_mail_sessions_device_id",
        "ix_mail_sessions_user_id",
        "ix_mail_sessions_task_id",
        "ix_mail_sessions_tenant_id",
    ):
        op.drop_index(name, table_name="mail_sessions")
    op.drop_constraint("uq_mail_sessions_task_id", "mail_sessions", type_="unique")
    op.drop_table("mail_sessions")

    for name in ("ix_mailboxes_is_active", "ix_mailboxes_connector_type", "ix_mailboxes_tenant_id"):
        op.drop_index(name, table_name="mailboxes")
    op.drop_constraint("uq_mailboxes_tenant_secret_ref", "mailboxes", type_="unique")
    op.drop_table("mailboxes")

    for name in ("ix_tasks_created_at", "ix_tasks_device_id", "ix_tasks_user_id", "ix_tasks_tenant_id"):
        op.drop_index(name, table_name="tasks")
    op.drop_constraint("uq_tasks_owner_idempotency_key", "tasks", type_="unique")
    op.drop_table("tasks")

    for name in ("ix_devices_user_id", "ix_devices_tenant_id"):
        op.drop_index(name, table_name="devices")
    op.drop_constraint("uq_devices_tenant_user_name", "devices", type_="unique")
    op.drop_table("devices")

    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_constraint("uq_users_tenant_email", "users", type_="unique")
    op.drop_table("users")
