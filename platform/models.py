"""Phase 1 persistence models."""

import hashlib
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from platform.database import Base


def new_id() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_session_token_hash() -> str:
    """Create an unissued token hash for internal/legacy session rows."""

    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Roles are intentionally coarse-grained.  Fine-grained checks belong in
    # the API dependency layer; keeping the role on the user means revoking or
    # changing a role takes effect for already-issued access tokens after the
    # next request (the database is the source of truth).
    role: Mapped[str] = mapped_column(
        String(32), default="operator", server_default="operator", index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "email"),
        UniqueConstraint("tenant_id", "oidc_subject", name="uq_users_tenant_oidc_subject"),
    )


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "idempotency_key",
            name="uq_tasks_owner_idempotency_key",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    task_type: Mapped[str] = mapped_column(String(80))
    idempotency_key: Mapped[str] = mapped_column(String(160))
    client_reference: Mapped[str | None] = mapped_column(String(160), nullable=True)
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    status: Mapped[str] = mapped_column(String(32), default="created")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class Mailbox(Base):
    __tablename__ = "mailboxes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "secret_ref", name="uq_mailboxes_tenant_secret_ref"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    email_masked: Mapped[str] = mapped_column(String(320))
    connector_type: Mapped[str] = mapped_column(String(80), index=True)
    secret_ref: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class MailSession(Base):
    __tablename__ = "mail_sessions"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_mail_sessions_task_id"),
        Index(
            "uq_active_mail_session_mailbox",
            "mailbox_id",
            unique=True,
            sqlite_where=text(
                "status IN ('initializing', 'waiting', 'code_ready')"
            ),
            postgresql_where=text(
                "status IN ('initializing', 'waiting', 'code_ready')"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    mailbox_id: Mapped[str] = mapped_column(ForeignKey("mailboxes.id"), index=True)
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    session_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, default=new_session_token_hash
    )
    status: Mapped[str] = mapped_column(String(32), default="waiting", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    start_watermark: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_message_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delivered_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    code_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class Card(Base):
    """A server-managed card reference; PAN/CVV are never stored here."""

    __tablename__ = "cards"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "provider_ref", name="uq_cards_tenant_provider_ref"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    provider_ref: Mapped[str] = mapped_column(String(160))
    brand: Mapped[str] = mapped_column(String(40))
    last4: Mapped[str] = mapped_column(String(4))
    expiry_month: Mapped[int | None] = mapped_column(nullable=True)
    expiry_year: Mapped[int | None] = mapped_column(nullable=True)
    secret_ref: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class CardAllocation(Base):
    """A user/task/device-bound card lease."""

    __tablename__ = "card_allocations"
    __table_args__ = (
        Index(
            "uq_active_card_allocation_card",
            "card_id",
            unique=True,
            sqlite_where=text("released_at IS NULL"),
            postgresql_where=text("released_at IS NULL"),
        ),
        Index(
            "uq_active_card_allocation_task",
            "task_id",
            unique=True,
            sqlite_where=text("released_at IS NULL"),
            postgresql_where=text("released_at IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    card_id: Mapped[str] = mapped_column(ForeignKey("cards.id"), index=True)
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    released_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revealed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    reveal_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class CardRevealChallenge(Base):
    """Short-lived, actor-bound proof used before a one-time PAN reveal."""

    __tablename__ = "card_reveal_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    allocation_id: Mapped[str] = mapped_column(
        ForeignKey("card_allocations.id"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    required_acr: Mapped[str] = mapped_column(String(255))
    grant_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True
    )
    grant_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    granted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class UploadPolicyVersion(Base):
    """Immutable server-side upload policy snapshot.

    Execution details are persisted for worker resolution but are never
    projected by the management API.
    """

    __tablename__ = "upload_policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "version", name="uq_upload_policy_versions_tenant_version"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="draft", server_default="draft", index=True
    )
    change_note: Mapped[str] = mapped_column(String(500))
    group_id: Mapped[int] = mapped_column(Integer)
    concurrency: Mapped[int] = mapped_column(Integer)
    proxy_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    credential_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class UploadPolicyDeployment(Base):
    """Current tenant rollout pointer with one-step rollback history."""

    __tablename__ = "upload_policy_deployments"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_upload_policy_deployments_tenant"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    active_policy_id: Mapped[str] = mapped_column(
        ForeignKey("upload_policy_versions.id"), index=True
    )
    previous_policy_id: Mapped[str | None] = mapped_column(
        ForeignKey("upload_policy_versions.id"), nullable=True, index=True
    )
    rollout_percent: Mapped[int] = mapped_column(Integer, default=100)
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True
    )


class UploadJob(Base):
    """Server-owned Sub2 upload job."""

    __tablename__ = "upload_jobs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "idempotency_key",
            name="uq_upload_jobs_owner_idempotency_key",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    card_allocation_id: Mapped[str] = mapped_column(
        ForeignKey("card_allocations.id"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(160))
    business_name: Mapped[str] = mapped_column(String(160))
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    policy_version: Mapped[str] = mapped_column(String(80))
    external_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True
    )


class OutboxEvent(Base):
    """Transactional signal consumed by a server-side worker.

    The row deliberately contains no provider payload or secret reference.  The
    worker resolves the aggregate from the database after claiming the event.
    """

    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint(
            "event_type",
            "aggregate_id",
            name="uq_outbox_events_type_aggregate",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    aggregate_type: Mapped[str] = mapped_column(String(64))
    aggregate_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="pending", server_default="pending", index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
