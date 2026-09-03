"""Atomic one-time mail-code consumption primitives."""

from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import and_, case, exists, or_, select, update
from sqlalchemy.orm import Session

from platform.models import Device, MailSession, Task, User


_MESSAGE_ID_HASH_DOMAIN = b"email-platform:mail-message-id:v1\0"
_TERMINAL_TASK_STATUSES = ("closed", "expired", "cancelled", "completed")


def _matching_task_filters() -> tuple[object, ...]:
    return (
        Task.id == MailSession.task_id,
        Task.tenant_id == MailSession.tenant_id,
        Task.user_id == MailSession.user_id,
        Task.device_id == MailSession.device_id,
    )


def _open_task_query(now: datetime):
    return (
        select(Task)
        .join(
            User,
            and_(User.id == Task.user_id, User.tenant_id == Task.tenant_id),
        )
        .join(
            Device,
            and_(
                Device.id == Task.device_id,
                Device.user_id == Task.user_id,
                Device.tenant_id == Task.tenant_id,
            ),
        )
        .where(
            ~Task.status.in_(_TERMINAL_TASK_STATUSES),
            or_(Task.expires_at.is_(None), Task.expires_at > now),
            User.is_active.is_(True),
            User.role == "operator",
            Device.revoked_at.is_(None),
        )
    )


def mail_session_open_task_exists(now: datetime) -> object:
    """Return the atomic task and principal barrier for a MailSession mutation."""

    return exists(
        _open_task_query(now)
        .with_only_columns(Task.id)
        .where(*_matching_task_filters())
    )


def open_task_for_mail_session(
    db: Session,
    session: MailSession,
    *,
    now: datetime,
) -> Task | None:
    """Load the owning task only while its task and principal remain usable."""

    return db.scalar(
        _open_task_query(now).where(
            Task.id == session.task_id,
            Task.tenant_id == session.tenant_id,
            Task.user_id == session.user_id,
            Task.device_id == session.device_id,
        )
    )


def retire_mail_session_if_task_unavailable(
    db: Session,
    *,
    session_id: str,
    now: datetime,
) -> bool:
    """Clear a session whose owning task or principal is no longer usable."""

    task_is_expired = exists(
        select(Task.id).where(
            *_matching_task_filters(),
            or_(
                Task.status == "expired",
                (
                    ~Task.status.in_(_TERMINAL_TASK_STATUSES)
                    & Task.expires_at.is_not(None)
                    & (Task.expires_at <= now)
                ),
            ),
        )
    )
    retired = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session_id,
            MailSession.status.in_(("initializing", "waiting", "code_ready")),
            ~mail_session_open_task_exists(now),
        )
        .values(
            status=case((task_is_expired, "expired"), else_="revoked"),
            delivered_code=None,
            delivered_message_id_hash=None,
            delivered_at=None,
            code_expires_at=None,
            start_watermark=None,
            last_message_hash=None,
        )
        .execution_options(synchronize_session=False)
    )
    return retired.rowcount == 1


def hash_message_id(message_id: str) -> str:
    """Return the non-secret, code-independent digest exposed by the API."""

    return hashlib.sha256(
        _MESSAGE_ID_HASH_DOMAIN + message_id.encode("utf-8")
    ).hexdigest()


def claim_delivered_code(
    db: Session,
    *,
    session_id: str,
    expected_code: str,
    expected_message_id_hash: str,
    now: datetime,
) -> bool:
    """Atomically consume one worker-delivered code exactly once."""

    claimed = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session_id,
            MailSession.status == "code_ready",
            MailSession.consumed_at.is_(None),
            MailSession.delivered_code == expected_code,
            MailSession.delivered_message_id_hash == expected_message_id_hash,
            MailSession.code_expires_at.is_not(None),
            MailSession.code_expires_at > now,
            MailSession.expires_at > now,
            mail_session_open_task_exists(now),
        )
        .values(
            status="consumed",
            consumed_at=now,
            delivered_code=None,
            delivered_message_id_hash=None,
            delivered_at=None,
            code_expires_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    return claimed.rowcount == 1


def claim_connector_message(
    db: Session,
    *,
    session_id: str,
    message_hash: str,
    now: datetime,
) -> bool:
    """Atomically consume one connector message hash exactly once."""

    claimed = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session_id,
            MailSession.consumed_at.is_(None),
            MailSession.status.not_in(("consumed", "revoked", "expired")),
            MailSession.expires_at > now,
            mail_session_open_task_exists(now),
            or_(
                MailSession.last_message_hash.is_(None),
                MailSession.last_message_hash != message_hash,
            ),
        )
        .values(
            last_message_hash=message_hash,
            consumed_at=now,
            status="consumed",
        )
        .execution_options(synchronize_session=False)
    )
    return claimed.rowcount == 1


def expire_mail_session_if_due(
    db: Session,
    *,
    session_id: str,
    now: datetime,
) -> bool:
    """Atomically expire an active session after a potentially slow lookup."""

    expired = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session_id,
            MailSession.status.in_(("initializing", "waiting", "code_ready")),
            MailSession.expires_at <= now,
        )
        .values(
            status="expired",
            delivered_code=None,
            delivered_message_id_hash=None,
            delivered_at=None,
            code_expires_at=None,
            start_watermark=None,
            last_message_hash=None,
        )
        .execution_options(synchronize_session=False)
    )
    return expired.rowcount == 1


__all__ = [
    "claim_connector_message",
    "claim_delivered_code",
    "expire_mail_session_if_due",
    "hash_message_id",
    "mail_session_open_task_exists",
    "open_task_for_mail_session",
    "retire_mail_session_if_task_unavailable",
]
