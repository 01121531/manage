"""Phase 1 persistence models."""

import hashlib
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
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
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class RevokedAccessToken(Base):
    """An irreversible digest of one logged-out bearer token."""

    __tablename__ = "revoked_access_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    reason: Mapped[str] = mapped_column(String(80), default="user_logout")


class RevokedOidcSession(Base):
    """An issuer-scoped digest of one logged-out OIDC session."""

    __tablename__ = "revoked_oidc_sessions"

    session_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    # Until the deployed identity provider's maximum session lifetime is
    # verified, NULL deliberately keeps the deny-list entry fail-closed.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    reason: Mapped[str] = mapped_column(String(80), default="user_logout")


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


class PoolImportReceipt(Base):
    """A secret-free idempotency receipt for one admin-managed pool import."""

    __tablename__ = "pool_import_receipts"
    __table_args__ = (
        CheckConstraint(
            "pool_type IN ('card', 'mailbox')",
            name="ck_pool_import_receipts_pool_type",
        ),
        CheckConstraint(
            "item_count >= 1 AND item_count <= 100",
            name="ck_pool_import_receipts_item_count",
        ),
        UniqueConstraint(
            "tenant_id",
            "pool_type",
            "idempotency_key",
            name="uq_pool_import_receipts_tenant_pool_key",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64))
    pool_type: Mapped[str] = mapped_column(String(16))
    idempotency_key: Mapped[str] = mapped_column(String(160))
    request_digest: Mapped[str] = mapped_column(String(64))
    item_count: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    trace_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class PoolImportContext(Base):
    """Target-issued authorization for one exact secret-free import manifest."""

    __tablename__ = "pool_import_contexts"
    __table_args__ = (
        CheckConstraint(
            "pool_type IN ('card', 'mailbox')",
            name="ck_pool_import_contexts_pool_type",
        ),
        CheckConstraint(
            "item_count >= 1 AND item_count <= 100",
            name="ck_pool_import_contexts_item_count",
        ),
        UniqueConstraint(
            "context_token_hash",
            name="uq_pool_import_contexts_token_hash",
        ),
        UniqueConstraint(
            "pool_import_receipt_id",
            name="uq_pool_import_contexts_local_receipt",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    context_token_hash: Mapped[str] = mapped_column(String(64))
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    audience: Mapped[str] = mapped_column(String(160))
    pool_type: Mapped[str] = mapped_column(String(16))
    ordered_manifest_digest: Mapped[str] = mapped_column(String(64))
    item_count: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    trace_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    pool_import_receipt_id: Mapped[str | None] = mapped_column(
        ForeignKey("pool_import_receipts.id"), nullable=True
    )


class SecurePoolImportConsumption(Base):
    """Atomic, globally one-time consumption of a signed Vault receipt."""

    __tablename__ = "secure_pool_import_consumptions"

    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    pool_import_receipt_id: Mapped[str] = mapped_column(
        ForeignKey("pool_import_receipts.id"), unique=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    key_version: Mapped[int] = mapped_column(Integer)
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class Mailbox(Base):
    __tablename__ = "mailboxes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "secret_ref", name="uq_mailboxes_tenant_secret_ref"
        ),
        Index(
            "ix_mailboxes_tenant_created_at_id",
            "tenant_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    email_masked: Mapped[str] = mapped_column(String(320))
    connector_type: Mapped[str] = mapped_column(String(80), index=True)
    task_type: Mapped[str] = mapped_column(
        String(80), default="mail_code", server_default="mail_code", index=True
    )
    secret_ref: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    health_status: Mapped[str] = mapped_column(
        String(32), default="unknown", server_default="unknown", index=True
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )


class MailSession(Base):
    __tablename__ = "mail_sessions"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_mail_sessions_task_id"),
        UniqueConstraint(
            "session_token_hash", name="uq_mail_sessions_session_token_hash"
        ),
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
        Index(
            "ix_active_mail_sessions_tenant_mailbox_expires",
            "tenant_id",
            "mailbox_id",
            "expires_at",
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
    policy_version: Mapped[str] = mapped_column(
        String(80), default="settings-default", server_default="settings-default"
    )
    code_ttl_seconds: Mapped[int] = mapped_column(
        Integer, default=60, server_default="60"
    )
    poll_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=5, server_default="5"
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    start_watermark: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_message_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delivered_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    delivered_message_id_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
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
        UniqueConstraint(
            "tenant_id", "secret_ref", name="uq_cards_tenant_secret_ref"
        ),
        Index("ix_cards_tenant_created_at_id", "tenant_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    provider_ref: Mapped[str] = mapped_column(String(160))
    pool_key: Mapped[str] = mapped_column(
        String(80), default="legacy-unclassified", server_default="legacy-unclassified", index=True
    )
    region: Mapped[str] = mapped_column(
        String(80), default="legacy-unclassified", server_default="legacy-unclassified", index=True
    )
    brand: Mapped[str] = mapped_column(String(40))
    last4: Mapped[str] = mapped_column(String(4))
    expiry_month: Mapped[int | None] = mapped_column(nullable=True)
    expiry_year: Mapped[int | None] = mapped_column(nullable=True)
    secret_ref: Mapped[str] = mapped_column(String(512))
    quarantine_reason_code: Mapped[str | None] = mapped_column(
        String(80), nullable=True
    )
    quarantined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
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
    release_reason_code: Mapped[str | None] = mapped_column(
        String(80), nullable=True
    )
    allocation_reason_code: Mapped[str] = mapped_column(
        String(80), default="task_assigned", server_default="task_assigned"
    )
    policy_version: Mapped[str] = mapped_column(
        String(80), default="settings-default", server_default="settings-default"
    )
    reveal_ttl_seconds: Mapped[int] = mapped_column(
        Integer, default=60, server_default="60"
    )
    selection_rule_json: Mapped[str] = mapped_column(
        Text,
        default=(
            '{"allocation_order":"oldest_available","brands":[],"minimum_validity_days":0,'
            '"pool_key":"legacy-unclassified","region":"legacy-unclassified",'
            '"task_type":"card_checkout"}'
        ),
        server_default=(
            '{"allocation_order":"oldest_available","brands":[],"minimum_validity_days":0,'
            '"pool_key":"legacy-unclassified","region":"legacy-unclassified",'
            '"task_type":"card_checkout"}'
        ),
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


class CardAllocationReplacement(Base):
    """Durable one-to-one link used for idempotent card replacement."""

    __tablename__ = "card_allocation_replacements"
    __table_args__ = (
        UniqueConstraint(
            "replacement_allocation_id",
            name="uq_card_allocation_replacements_replacement_id",
        ),
    )

    original_allocation_id: Mapped[str] = mapped_column(
        ForeignKey("card_allocations.id"), primary_key=True
    )
    replacement_allocation_id: Mapped[str] = mapped_column(
        ForeignKey("card_allocations.id"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )


class CardEvent(Base):
    """Append-only, masked card lifecycle fact."""

    __tablename__ = "card_events"
    __table_args__ = (
        Index(
            "ix_card_events_tenant_created_at_id",
            "tenant_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_card_events_tenant_card_created_at_id",
            "tenant_id",
            "card_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_card_events_tenant_allocation_created_at_id",
            "tenant_id",
            "allocation_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    card_id: Mapped[str] = mapped_column(ForeignKey("cards.id"), index=True)
    allocation_id: Mapped[str | None] = mapped_column(
        ForeignKey("card_allocations.id"), nullable=True, index=True
    )
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    before_masked: Mapped[str] = mapped_column(Text, default="{}")
    after_masked: Mapped[str] = mapped_column(Text, default="{}")
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
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


class OperationalPolicyVersion(Base):
    """Immutable, tenant-scoped mail or card policy snapshot."""

    __tablename__ = "operational_policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "domain",
            "version",
            name="uq_operational_policy_versions_tenant_domain_version",
        ),
        CheckConstraint(
            "domain IN ('mail', 'card')",
            name="ck_operational_policy_versions_domain",
        ),
        CheckConstraint(
            "status IN ('draft', 'approved', 'active', 'retired')",
            name="ck_operational_policy_versions_status",
        ),
        CheckConstraint(
            "(domain = 'mail' AND session_ttl_seconds IS NOT NULL "
            "AND code_ttl_seconds IS NOT NULL AND poll_interval_seconds IS NOT NULL "
            "AND lease_ttl_seconds IS NULL AND reveal_ttl_seconds IS NULL "
            "AND allocation_order IS NULL) OR "
            "(domain = 'card' AND session_ttl_seconds IS NULL "
            "AND code_ttl_seconds IS NULL AND poll_interval_seconds IS NULL "
            "AND lease_ttl_seconds IS NOT NULL AND reveal_ttl_seconds IS NOT NULL "
            "AND allocation_order = 'oldest_available')",
            name="ck_operational_policy_versions_shape",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    domain: Mapped[str] = mapped_column(String(16), index=True)
    version: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="draft", server_default="draft", index=True
    )
    change_note: Mapped[str] = mapped_column(String(500))
    session_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    poll_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lease_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reveal_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    allocation_order: Mapped[str | None] = mapped_column(String(40), nullable=True)
    selection_rules_json: Mapped[str | None] = mapped_column(Text, nullable=True)
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


class OperationalPolicyDeployment(Base):
    """Current mail/card rollout pointer with one-step rollback history."""

    __tablename__ = "operational_policy_deployments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "domain", name="uq_operational_policy_deployments_tenant_domain"
        ),
        CheckConstraint(
            "domain IN ('mail', 'card')",
            name="ck_operational_policy_deployments_domain",
        ),
        CheckConstraint(
            "rollout_percent BETWEEN 1 AND 100",
            name="ck_operational_policy_deployments_rollout",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    domain: Mapped[str] = mapped_column(String(16), index=True)
    active_policy_id: Mapped[str] = mapped_column(
        ForeignKey("operational_policy_versions.id"), index=True
    )
    previous_policy_id: Mapped[str | None] = mapped_column(
        ForeignKey("operational_policy_versions.id"), nullable=True, index=True
    )
    rollout_percent: Mapped[int] = mapped_column(Integer, default=100)
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True
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


class AdminRoleChangeRequest(Base):
    """Tenant-scoped four-eye approval state for an administrator role change."""

    __tablename__ = "admin_role_change_requests"
    __table_args__ = (
        CheckConstraint(
            "expected_old_role IN ('operator', 'ops_admin', "
            "'security_auditor', 'platform_admin')",
            name="ck_admin_role_change_requests_expected_old_role",
        ),
        CheckConstraint(
            "new_role IN ('operator', 'ops_admin', "
            "'security_auditor', 'platform_admin')",
            name="ck_admin_role_change_requests_new_role",
        ),
        CheckConstraint(
            "expected_old_role <> new_role",
            name="ck_admin_role_change_requests_role_changes",
        ),
        CheckConstraint(
            "status IN ('pending', 'applied', 'expired')",
            name="ck_admin_role_change_requests_status",
        ),
        CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_admin_role_change_requests_four_eye",
        ),
        CheckConstraint(
            "(status = 'pending' AND approved_by IS NULL AND "
            "approval_trace_id IS NULL AND applied_at IS NULL) OR "
            "(status = 'applied' AND approved_by IS NOT NULL AND "
            "approval_trace_id IS NOT NULL AND applied_at IS NOT NULL) OR "
            "(status = 'expired' AND approved_by IS NULL AND "
            "approval_trace_id IS NULL AND applied_at IS NULL)",
            name="ck_admin_role_change_requests_state_fields",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_admin_role_change_requests_expiry",
        ),
        CheckConstraint(
            "applied_at IS NULL OR "
            "(applied_at >= created_at AND applied_at <= expires_at)",
            name="ck_admin_role_change_requests_applied_at",
        ),
        Index(
            "uq_admin_role_change_requests_pending_target",
            "tenant_id",
            "target_user_id",
            unique=True,
            sqlite_where=text("status = 'pending'"),
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_admin_role_change_requests_tenant_status_created",
            "tenant_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_admin_role_change_requests_tenant_requested_by",
            "tenant_id",
            "requested_by",
        ),
        Index(
            "ix_admin_role_change_requests_tenant_approved_by",
            "tenant_id",
            "approved_by",
        ),
        Index(
            "ix_admin_role_change_requests_tenant_request_trace",
            "tenant_id",
            "request_trace_id",
        ),
        Index(
            "ix_admin_role_change_requests_tenant_approval_trace",
            "tenant_id",
            "approval_trace_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64))
    target_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    expected_old_role: Mapped[str] = mapped_column(String(32))
    new_role: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(
        String(32), default="pending", server_default="pending"
    )
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    request_trace_id: Mapped[str] = mapped_column(String(36))
    approval_trace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
    phase: Mapped[str] = mapped_column(
        String(40), default="queued", server_default="queued", index=True
    )
    phase_sequence: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1"
    )
    phase_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
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
    __table_args__ = (
        Index(
            "ix_audit_events_tenant_created_at_id",
            "tenant_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_audit_events_upload_phase_sequence",
            "tenant_id",
            "entity_type",
            "entity_id",
            "aggregate_sequence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id"), nullable=True
    )
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(80), default="unspecified", index=True)
    result: Mapped[str] = mapped_column(String(32), default="success", index=True)
    entity_type: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    aggregate_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
