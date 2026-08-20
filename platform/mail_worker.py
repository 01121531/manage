"""Background worker for mailbox watermarking and one-time code delivery."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from threading import Event

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.mail_connectors import MailboxAccess, MailConnector, MailConnectorUnavailable
from platform.models import Mailbox, MailSession, utc_now
from platform.uploads import write_worker_heartbeat
from platform.worker_metrics import WorkerMetrics


def _mailbox_access(mailbox: Mailbox) -> MailboxAccess:
    return MailboxAccess(mailbox_id=mailbox.id, secret_ref=mailbox.secret_ref)


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now


def process_mail_session(
    session_factory: sessionmaker[Session],
    session_id: str,
    *,
    connectors: Mapping[str, MailConnector],
    code_ttl_seconds: int = 60,
) -> str:
    """Advance one mail session without exposing mailbox credentials to the API."""

    now = utc_now()
    with session_factory() as db:
        session = db.get(MailSession, session_id)
        if session is None:
            return "missing"
        if code_ttl_seconds <= 0:
            raise ValueError("code_ttl_seconds must be positive")
        if session.status not in {"initializing", "waiting", "code_ready"}:
            return session.status
        if _is_expired(session.expires_at, now):
            session.status = "expired"
            session.delivered_code = None
            session.delivered_at = None
            session.code_expires_at = None
            record_audit(
                db,
                tenant_id=session.tenant_id,
                user_id=session.user_id,
                device_id=session.device_id,
                event_type="mail_session.expired",
                entity_type="mail_session",
                entity_id=session.id,
                trace_id=session.trace_id,
                details={"status": "expired"},
            )
            db.commit()
            return "expired"

        if session.status == "code_ready":
            if session.code_expires_at is not None and _is_expired(
                session.code_expires_at, now
            ):
                session.delivered_code = None
                session.delivered_at = None
                session.code_expires_at = None
                session.status = "waiting"
                record_audit(
                    db,
                    tenant_id=session.tenant_id,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    event_type="mail_session.code_expired",
                    entity_type="mail_session",
                    entity_id=session.id,
                    trace_id=session.trace_id,
                    details={"status": "waiting", "source": "worker"},
                )
                db.commit()
                return "code_expired"
            return "code_ready"

        mailbox = db.get(Mailbox, session.mailbox_id)
        if mailbox is None or not mailbox.is_active:
            return "mailbox_unavailable"
        connector = connectors.get(mailbox.connector_type)
        if connector is None:
            return "connector_unavailable"

        try:
            if session.status == "initializing":
                session.start_watermark = connector.current_watermark(
                    _mailbox_access(mailbox)
                )
                session.status = "waiting"
                record_audit(
                    db,
                    tenant_id=session.tenant_id,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    event_type="mail_session.watermark_initialized",
                    entity_type="mail_session",
                    entity_id=session.id,
                    trace_id=session.trace_id,
                    details={"status": "waiting", "connector_type": mailbox.connector_type},
                )
                db.commit()
                return "initialized"

            message = connector.find_code_after(
                _mailbox_access(mailbox), session.start_watermark
            )
        except MailConnectorUnavailable:
            return "connector_unavailable"

        if message is None or message.watermark == session.start_watermark:
            return "waiting"
        message_hash = hashlib.sha256(
            f"{mailbox.id}\0{message.message_id}\0{message.code}".encode("utf-8")
        ).hexdigest()
        if message_hash == session.last_message_hash:
            return "waiting"
        session.last_message_hash = message_hash
        session.start_watermark = message.watermark
        session.delivered_code = message.code
        session.delivered_at = now
        code_expires_at = now + timedelta(seconds=code_ttl_seconds)
        session_deadline = session.expires_at
        if session_deadline.tzinfo is None:
            session_deadline = session_deadline.replace(tzinfo=timezone.utc)
        session.code_expires_at = min(code_expires_at, session_deadline)
        session.status = "code_ready"
        record_audit(
            db,
            tenant_id=session.tenant_id,
            user_id=session.user_id,
            device_id=session.device_id,
            event_type="mail_session.code_ready",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "code_ready"},
        )
        db.commit()
        return "code_ready"


def process_mail_sessions(
    session_factory: sessionmaker[Session],
    *,
    connectors: Mapping[str, MailConnector],
    limit: int = 20,
    code_ttl_seconds: int = 60,
) -> dict[str, int]:
    """Process active worker-owned mail sessions and return result counts."""

    if limit <= 0:
        raise ValueError("limit must be positive")
    with session_factory() as db:
        session_ids = list(
            db.scalars(
                select(MailSession.id)
                .where(
                    MailSession.status.in_(("initializing", "waiting", "code_ready")),
                )
                .order_by(MailSession.created_at, MailSession.id)
                .limit(limit)
            )
        )
    counts: Counter[str] = Counter()
    for session_id in session_ids:
        counts[
            process_mail_session(
                session_factory,
                session_id,
                connectors=connectors,
                code_ttl_seconds=code_ttl_seconds,
            )
        ] += 1
    return dict(counts)


def run_mail_worker(
    session_factory: sessionmaker[Session],
    *,
    connectors: Mapping[str, MailConnector],
    stop_event: Event,
    poll_seconds: float = 2.0,
    heartbeat_path: str | None = None,
    batch_reporter: Callable[[dict[str, int]], None] | None = None,
    metrics: WorkerMetrics | None = None,
    code_ttl_seconds: int = 60,
) -> None:
    """Run the dedicated mail worker loop until ``stop_event`` is set."""

    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be positive")
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
    while not stop_event.is_set():
        counts = process_mail_sessions(
            session_factory,
            connectors=connectors,
            code_ttl_seconds=code_ttl_seconds,
        )
        if batch_reporter is not None:
            batch_reporter(counts)
        if metrics is not None:
            metrics.record_batch(counts)
        if heartbeat_path is not None:
            write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()
        if not counts:
            stop_event.wait(poll_seconds)
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
    if metrics is not None:
        metrics.mark_heartbeat()
