"""Background worker for mailbox watermarking and one-time code delivery."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from threading import Event, Thread

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.lifecycle import sweep_expired_lifecycle
from platform.mail_consumption import (
    expire_mail_session_if_due,
    hash_message_id,
    mail_session_open_task_exists,
    open_task_for_mail_session,
    retire_mail_session_if_task_unavailable,
)
from platform.mail_connectors import (
    MailboxAccess,
    MailConnector,
    MailConnectorUnavailable,
    call_mail_connector,
)
from platform.mail_health import (
    CONNECTOR_NOT_CONFIGURED,
    CONNECTOR_UNAVAILABLE,
    mark_mailbox_healthy,
    mark_mailbox_unavailable,
)
from platform.models import Mailbox, MailSession, utc_now
from platform.uploads import write_worker_heartbeat
from platform.worker_metrics import WorkerMetrics


def _mailbox_access(mailbox: Mailbox) -> MailboxAccess:
    return MailboxAccess(mailbox_id=mailbox.id, secret_ref=mailbox.secret_ref)


def _mailbox_for_session(db: Session, session: MailSession) -> Mailbox | None:
    return db.scalar(
        select(Mailbox).where(
            Mailbox.id == session.mailbox_id,
            Mailbox.tenant_id == session.tenant_id,
        )
    )


def _mailbox_observation_is_current(
    db: Session, mailbox: Mailbox, observed_access: MailboxAccess
) -> bool:
    db.expire(mailbox)
    db.refresh(mailbox, with_for_update=True)
    return mailbox.is_active and mailbox.secret_ref == observed_access.secret_ref


def _retire_mail_session_for_unavailable_task(
    db: Session,
    session: MailSession,
    *,
    now: datetime,
) -> str | None:
    if not retire_mail_session_if_task_unavailable(
        db,
        session_id=session.id,
        now=now,
    ):
        return None
    db.expire(session)
    db.refresh(session)
    record_audit(
        db,
        tenant_id=session.tenant_id,
        user_id=session.user_id,
        device_id=session.device_id,
        actor_id="worker-mail",
        event_type=(
            "mail_session.expired"
            if session.status == "expired"
            else "mail_session.revoked"
        ),
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={
            "status": session.status,
            "reason": "task_or_principal_unavailable_barrier",
        },
    )
    return session.status


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
        task = open_task_for_mail_session(db, session, now=now)
        if task is None:
            task_barrier_status = _retire_mail_session_for_unavailable_task(
                db,
                session,
                now=now,
            )
            db.commit()
            if task_barrier_status is not None:
                return task_barrier_status
            db.expire(session)
            db.refresh(session)
            return session.status
        if _is_expired(session.expires_at, now):
            expired_now = expire_mail_session_if_due(
                db,
                session_id=session.id,
                now=now,
            )
            if expired_now:
                record_audit(
                    db,
                    tenant_id=session.tenant_id,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    actor_id="worker-mail",
                    event_type="mail_session.expired",
                    entity_type="mail_session",
                    entity_id=session.id,
                    trace_id=session.trace_id,
                    details={"status": "expired"},
                )
            db.commit()
            if expired_now:
                return "expired"
            db.expire(session)
            db.refresh(session)
            return session.status

        if session.status == "code_ready":
            if session.code_expires_at is not None and _is_expired(
                session.code_expires_at, now
            ):
                expired_code = db.execute(
                    update(MailSession)
                    .where(
                        MailSession.id == session.id,
                        MailSession.status == "code_ready",
                        MailSession.delivered_code == session.delivered_code,
                        MailSession.code_expires_at == session.code_expires_at,
                        MailSession.code_expires_at <= now,
                        MailSession.expires_at > now,
                        mail_session_open_task_exists(now),
                    )
                    .values(
                        delivered_code=None,
                        delivered_message_id_hash=None,
                        delivered_at=None,
                        code_expires_at=None,
                        status="waiting",
                    )
                    .execution_options(synchronize_session=False)
                )
                if expired_code.rowcount != 1:
                    task_barrier_status = _retire_mail_session_for_unavailable_task(
                        db,
                        session,
                        now=utc_now(),
                    )
                    db.commit()
                    if task_barrier_status is not None:
                        return task_barrier_status
                    db.expire(session)
                    db.refresh(session)
                    return session.status
                record_audit(
                    db,
                    tenant_id=session.tenant_id,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    actor_id="worker-mail",
                    event_type="mail_session.code_expired",
                    entity_type="mail_session",
                    entity_id=session.id,
                    trace_id=session.trace_id,
                    details={"status": "waiting", "source": "worker"},
                )
                db.commit()
                return "code_expired"
            return "code_ready"

        mailbox = _mailbox_for_session(db, session)
        if mailbox is None or not mailbox.is_active:
            return "mailbox_unavailable"
        connector = connectors.get(mailbox.connector_type)
        if connector is None:
            mark_mailbox_unavailable(
                mailbox,
                checked_at=now,
                error_code=CONNECTOR_NOT_CONFIGURED,
                db=db,
                user_id=session.user_id,
                device_id=session.device_id,
                actor_id="worker-mail",
                trace_id=session.trace_id,
            )
            db.commit()
            return "connector_unavailable"

        mailbox_access = _mailbox_access(mailbox)
        try:
            if session.status == "initializing":
                start_watermark = call_mail_connector(
                    lambda: connector.watermark_at(
                        mailbox_access, task.created_at
                    )
                )
                if not isinstance(start_watermark, str) or not start_watermark.strip():
                    raise MailConnectorUnavailable("Mail API cursor is unavailable")
                transition_now = utc_now()
                if _mailbox_observation_is_current(db, mailbox, mailbox_access):
                    mark_mailbox_healthy(
                        mailbox,
                        checked_at=transition_now,
                        db=db,
                        user_id=session.user_id,
                        device_id=session.device_id,
                        actor_id="worker-mail",
                        trace_id=session.trace_id,
                    )
                initialized = db.execute(
                    update(MailSession)
                    .where(
                        MailSession.id == session.id,
                        MailSession.status == "initializing",
                        MailSession.expires_at > transition_now,
                        mail_session_open_task_exists(transition_now),
                    )
                    .values(start_watermark=start_watermark, status="waiting")
                    .execution_options(synchronize_session=False)
                )
                if initialized.rowcount != 1:
                    task_barrier_status = _retire_mail_session_for_unavailable_task(
                        db,
                        session,
                        now=utc_now(),
                    )
                    db.commit()
                    if task_barrier_status is not None:
                        return task_barrier_status
                    return "stale"
                record_audit(
                    db,
                    tenant_id=session.tenant_id,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    actor_id="worker-mail",
                    event_type="mail_session.watermark_initialized",
                    entity_type="mail_session",
                    entity_id=session.id,
                    trace_id=session.trace_id,
                    details={"status": "waiting", "connector_type": mailbox.connector_type},
                )
                db.commit()
                return "initialized"

            message = call_mail_connector(
                lambda: connector.find_code_after(
                    mailbox_access, session.start_watermark
                )
            )
            if message is not None and (
                message.received_at is None
                or message.received_at.tzinfo is None
                or message.received_at.utcoffset() is None
                or _as_utc(message.received_at) < _as_utc(task.created_at)
            ):
                raise MailConnectorUnavailable("Mail API returned invalid received_at")
        except MailConnectorUnavailable:
            if _mailbox_observation_is_current(db, mailbox, mailbox_access):
                mark_mailbox_unavailable(
                    mailbox,
                    checked_at=now,
                    error_code=CONNECTOR_UNAVAILABLE,
                    db=db,
                    user_id=session.user_id,
                    device_id=session.device_id,
                    actor_id="worker-mail",
                    trace_id=session.trace_id,
                )
            db.commit()
            return "connector_unavailable"

        transition_now = utc_now()
        if _mailbox_observation_is_current(db, mailbox, mailbox_access):
            mark_mailbox_healthy(
                mailbox,
                checked_at=transition_now,
                db=db,
                user_id=session.user_id,
                device_id=session.device_id,
                actor_id="worker-mail",
                trace_id=session.trace_id,
            )
        if message is None or message.watermark == session.start_watermark:
            db.commit()
            return "waiting"
        message_hash = hashlib.sha256(
            f"{mailbox.id}\0{message.message_id}\0{message.code}".encode("utf-8")
        ).hexdigest()
        if message_hash == session.last_message_hash:
            db.commit()
            return "waiting"
        effective_code_ttl_seconds = session.code_ttl_seconds or code_ttl_seconds
        code_expires_at = transition_now + timedelta(
            seconds=effective_code_ttl_seconds
        )
        session_deadline = session.expires_at
        if session_deadline.tzinfo is None:
            session_deadline = session_deadline.replace(tzinfo=timezone.utc)
        delivered = db.execute(
            update(MailSession)
            .where(
                MailSession.id == session.id,
                MailSession.status == "waiting",
                MailSession.expires_at > transition_now,
                mail_session_open_task_exists(transition_now),
                or_(
                    MailSession.last_message_hash.is_(None),
                    MailSession.last_message_hash != message_hash,
                ),
            )
            .values(
                last_message_hash=message_hash,
                start_watermark=message.watermark,
                delivered_code=message.code,
                delivered_message_id_hash=hash_message_id(message.message_id),
                delivered_at=_as_utc(message.received_at),
                code_expires_at=min(code_expires_at, session_deadline),
                status="code_ready",
            )
            .execution_options(synchronize_session=False)
        )
        if delivered.rowcount != 1:
            task_barrier_status = _retire_mail_session_for_unavailable_task(
                db,
                session,
                now=utc_now(),
            )
            db.commit()
            if task_barrier_status is not None:
                return task_barrier_status
            return "stale"
        record_audit(
            db,
            tenant_id=session.tenant_id,
            user_id=session.user_id,
            device_id=session.device_id,
            actor_id="worker-mail",
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
    heartbeat_stop = Event()
    heartbeat_thread: Thread | None = None
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()

        def maintain_heartbeat() -> None:
            interval = min(max(poll_seconds, 0.1), 5)
            while not heartbeat_stop.wait(interval):
                write_worker_heartbeat(heartbeat_path)
                if metrics is not None:
                    metrics.mark_heartbeat()

        heartbeat_thread = Thread(
            target=maintain_heartbeat,
            name="mail-worker-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
    try:
        while not stop_event.is_set():
            sweep_expired_lifecycle(session_factory)
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
            stop_event.wait(poll_seconds)
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1)
        if heartbeat_path is not None:
            write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()
