"""Atomic one-time mail-code consumption primitives."""

from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from platform.models import MailSession


_MESSAGE_ID_HASH_DOMAIN = b"email-platform:mail-message-id:v1\0"


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
]
