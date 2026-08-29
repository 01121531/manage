"""Shared task lifecycle transitions used by API and background workers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import exists, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.card_events import record_card_event
from platform.models import (
    CardAllocation,
    Device,
    MailSession,
    OutboxEvent,
    Task,
    UploadJob,
    User,
    utc_now,
)


ACTIVE_MAIL_SESSION_STATUSES = ("initializing", "waiting", "code_ready")
RELEASABLE_MAIL_SESSION_STATUSES = ACTIVE_MAIL_SESSION_STATUSES + ("consumed",)
TERMINAL_TASK_STATUSES = frozenset({"closed", "expired", "cancelled", "completed"})


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return value <= now


@dataclass(frozen=True)
class LifecycleSweepResult:
    """Aggregate, payload-free lifecycle transition counts for one sweep."""

    tasks_expired: int = 0
    tasks_cancelled: int = 0
    tasks_completed: int = 0
    card_allocations_expired: int = 0
    card_allocations_released: int = 0
    mail_sessions_expired: int = 0
    mail_codes_expired: int = 0
    uploads_cancelled: int = 0
    uploads_unknown: int = 0

    @property
    def total(self) -> int:
        return sum(self.__dict__.values())

    def __add__(self, other: "LifecycleSweepResult") -> "LifecycleSweepResult":
        return LifecycleSweepResult(
            **{
                field: getattr(self, field) + getattr(other, field)
                for field in self.__dataclass_fields__
            }
        )


def _finalize_upload_outbox(
    db: Session,
    upload: UploadJob,
    *,
    now: datetime,
    skip_locked: bool,
) -> None:
    events = list(
        db.scalars(
            select(OutboxEvent)
            .where(
                OutboxEvent.tenant_id == upload.tenant_id,
                OutboxEvent.event_type == "upload.requested",
                OutboxEvent.aggregate_id == upload.id,
                OutboxEvent.status.in_(("pending", "processing")),
            )
            .with_for_update(skip_locked=skip_locked)
        )
    )
    for event in events:
        event.status = "processed"
        event.processed_at = now
        event.last_error_code = upload.error_code


def release_task_resources(
    task: Task,
    db: Session,
    *,
    now: datetime,
    card_status: str,
    mail_status: str,
    release_reason: str,
    actor_user_id: str,
    actor_device_id: str | None,
    running_upload_status: str = "cancel_pending",
    upload_error_code: str | None = None,
    finalize_upload_outbox: bool = False,
    skip_locked: bool = False,
) -> LifecycleSweepResult:
    """Release every active resource for one task and append subject-bound audit."""

    del actor_device_id  # actor identity is stored separately from the subject device.
    cards_expired = 0
    cards_released = 0
    mail_sessions_expired = 0
    uploads_cancelled = 0
    uploads_unknown = 0

    allocations = list(
        db.scalars(
            select(CardAllocation).where(
                CardAllocation.task_id == task.id,
                CardAllocation.tenant_id == task.tenant_id,
                CardAllocation.released_at.is_(None),
            ).with_for_update(skip_locked=skip_locked)
        )
    )
    for allocation in allocations:
        previous_status = allocation.status
        allocation.status = card_status
        allocation.released_at = now
        allocation.release_reason_code = release_reason
        if card_status == "expired":
            cards_expired += 1
        else:
            cards_released += 1
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=task.user_id,
            device_id=allocation.device_id,
            actor_id=actor_user_id,
            event_type=(
                "card.released" if card_status == "released" else "card.expired"
            ),
            entity_type="card_allocation",
            entity_id=allocation.id,
            trace_id=allocation.trace_id,
            details={"task_id": task.id, "release_reason": release_reason},
        )
        record_card_event(
            db,
            tenant_id=allocation.tenant_id,
            card_id=allocation.card_id,
            allocation_id=allocation.id,
            actor_id=actor_user_id,
            action=(
                "allocation.released"
                if card_status == "released"
                else "allocation.expired"
            ),
            reason_code=release_reason,
            trace_id=allocation.trace_id,
            before_masked={
                "card_status": "allocated",
                "allocation_status": previous_status,
            },
            after_masked={
                "card_status": "available",
                "allocation_status": card_status,
            },
        )

    sessions = list(
        db.scalars(
            select(MailSession).where(
                MailSession.task_id == task.id,
                MailSession.tenant_id == task.tenant_id,
                MailSession.status.in_(RELEASABLE_MAIL_SESSION_STATUSES),
            ).with_for_update(skip_locked=skip_locked)
        )
    )
    for session in sessions:
        session.status = mail_status
        session.delivered_code = None
        session.delivered_message_id_hash = None
        session.delivered_at = None
        session.code_expires_at = None
        session.start_watermark = None
        session.last_message_hash = None
        mail_sessions_expired += 1
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=task.user_id,
            device_id=session.device_id,
            actor_id=actor_user_id,
            event_type=(
                "mail_session.revoked"
                if mail_status == "revoked"
                else "mail_session.expired"
            ),
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"task_id": task.id, "reason": release_reason},
        )

    uploads = list(
        db.scalars(
            select(UploadJob).where(
                UploadJob.task_id == task.id,
                UploadJob.tenant_id == task.tenant_id,
                UploadJob.status.in_(("queued", "running")),
            ).with_for_update(skip_locked=skip_locked)
        )
    )
    for upload in uploads:
        was_running = upload.status == "running"
        upload.status = running_upload_status if was_running else "cancelled"
        if upload.status == "cancel_pending" and finalize_upload_outbox:
            upload.status = "unknown"
        upload.error_code = "external_unknown" if upload.status == "unknown" else upload_error_code
        upload.updated_at = now
        if upload.status == "unknown":
            uploads_unknown += 1
            event_type = "upload.unknown"
        else:
            uploads_cancelled += 1
            event_type = (
                "upload.cancelled"
                if upload.status == "cancelled" and upload_error_code is not None
                else "upload.cancel_requested"
            )
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=task.user_id,
            device_id=upload.device_id,
            actor_id=actor_user_id,
            event_type=event_type,
            entity_type="upload_job",
            entity_id=upload.id,
            trace_id=upload.trace_id,
            details={"status": upload.status, "reason": release_reason},
        )
        if finalize_upload_outbox:
            _finalize_upload_outbox(
                db,
                upload,
                now=now,
                skip_locked=skip_locked,
            )

    return LifecycleSweepResult(
        card_allocations_expired=cards_expired,
        card_allocations_released=cards_released,
        mail_sessions_expired=mail_sessions_expired,
        uploads_cancelled=uploads_cancelled,
        uploads_unknown=uploads_unknown,
    )


def transition_task_to_terminal(
    task: Task,
    db: Session,
    *,
    now: datetime,
    task_status: str,
    card_status: str,
    mail_status: str,
    release_reason: str,
    actor_user_id: str,
    actor_device_id: str | None,
    running_upload_status: str = "cancel_pending",
    upload_error_code: str | None = None,
    finalize_upload_outbox: bool = False,
    skip_locked: bool = False,
) -> LifecycleSweepResult:
    """Atomically claim one open task, close it, and compensate all resources."""

    if task_status not in TERMINAL_TASK_STATUSES:
        raise ValueError("task_status must be terminal")

    claimed = db.execute(
        update(Task)
        .where(
            Task.id == task.id,
            Task.tenant_id == task.tenant_id,
            ~Task.status.in_(TERMINAL_TASK_STATUSES),
        )
        .values(status=task_status, closed_at=now)
        .execution_options(synchronize_session="fetch")
    )
    if claimed.rowcount != 1:
        db.expire(task)
        db.refresh(task)
        if task.status not in TERMINAL_TASK_STATUSES:
            return LifecycleSweepResult()
        winner_expired = task.status == "expired"
        return release_task_resources(
            task,
            db,
            now=now,
            card_status="expired" if winner_expired else "released",
            mail_status="expired" if winner_expired else "revoked",
            release_reason="terminal_task_recovery",
            actor_user_id=actor_user_id,
            actor_device_id=actor_device_id,
            running_upload_status="unknown",
            upload_error_code=(
                "task_expired" if winner_expired else "terminal_task_recovery"
            ),
            finalize_upload_outbox=True,
            skip_locked=skip_locked,
        )

    released = release_task_resources(
        task,
        db,
        now=now,
        card_status=card_status,
        mail_status=mail_status,
        release_reason=release_reason,
        actor_user_id=actor_user_id,
        actor_device_id=actor_device_id,
        running_upload_status=running_upload_status,
        upload_error_code=upload_error_code,
        finalize_upload_outbox=finalize_upload_outbox,
        skip_locked=skip_locked,
    )
    record_audit(
        db,
        tenant_id=task.tenant_id,
        user_id=task.user_id,
        device_id=task.device_id,
        actor_id=actor_user_id,
        event_type=f"task.{task_status}",
        entity_type="task",
        entity_id=task.id,
        trace_id=task.trace_id,
        details={"release_reason": release_reason},
    )
    return released + LifecycleSweepResult(
        tasks_expired=1 if task_status == "expired" else 0,
        tasks_cancelled=1 if task_status == "cancelled" else 0,
        tasks_completed=1 if task_status == "completed" else 0,
    )


def compensate_terminal_task_resources(
    db: Session,
    task_id: str,
    *,
    now: datetime,
    card_status: str,
    mail_status: str,
    release_reason: str,
    actor_user_id: str,
    actor_device_id: str | None,
    running_upload_status: str = "unknown",
    upload_error_code: str | None = "terminal_task_recovery",
) -> LifecycleSweepResult:
    """Finish resources skipped while a task was being made terminal.

    The first terminal transition may use ``SKIP LOCKED`` to avoid the
    UploadJob -> Task lock inversion used by the upload worker.  Callers invoke
    this only after committing that transition.  Locking active uploads first
    preserves the worker's prefix, while the terminal Task is the durable
    barrier preventing any new resource from being created.
    """

    list(
        db.scalars(
            select(UploadJob)
            .where(
                UploadJob.task_id == task_id,
                UploadJob.status.in_(("queued", "running")),
            )
            .order_by(UploadJob.id)
            .with_for_update()
        )
    )
    task = db.scalar(
        select(Task)
        .where(Task.id == task_id, Task.status.in_(TERMINAL_TASK_STATUSES))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if task is None:
        return LifecycleSweepResult()
    released = release_task_resources(
        task,
        db,
        now=now,
        card_status=card_status,
        mail_status=mail_status,
        release_reason=release_reason,
        actor_user_id=actor_user_id,
        actor_device_id=actor_device_id,
        running_upload_status=running_upload_status,
        upload_error_code=upload_error_code,
        finalize_upload_outbox=True,
    )
    terminal_uploads = list(
        db.scalars(
            select(UploadJob)
            .where(
                UploadJob.task_id == task.id,
                ~UploadJob.status.in_(("queued", "running")),
            )
            .order_by(UploadJob.id)
            .with_for_update()
        )
    )
    for upload in terminal_uploads:
        if upload.status == "cancel_pending":
            upload.status = "unknown"
            upload.error_code = "external_unknown"
            upload.updated_at = now
            record_audit(
                db,
                tenant_id=upload.tenant_id,
                user_id=upload.user_id,
                device_id=upload.device_id,
                actor_id=actor_user_id,
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=upload.id,
                trace_id=upload.trace_id,
                details={"status": "unknown", "reason": release_reason},
            )
            released += LifecycleSweepResult(uploads_unknown=1)
        _finalize_upload_outbox(db, upload, now=now, skip_locked=False)
    return released


def _terminal_tasks_with_resource_residue(
    db: Session, *, limit: int
) -> tuple[str, ...]:
    upload_ids = select(UploadJob.id).where(UploadJob.task_id == Task.id)
    return tuple(
        db.scalars(
            select(Task.id)
            .where(
                Task.status.in_(TERMINAL_TASK_STATUSES),
                or_(
                    exists().where(
                        CardAllocation.task_id == Task.id,
                        CardAllocation.released_at.is_(None),
                    ),
                    exists().where(
                        MailSession.task_id == Task.id,
                        MailSession.status.in_(RELEASABLE_MAIL_SESSION_STATUSES),
                    ),
                    exists().where(
                        UploadJob.task_id == Task.id,
                        UploadJob.status.in_(("queued", "running", "cancel_pending")),
                    ),
                    exists().where(
                        OutboxEvent.aggregate_id.in_(upload_ids),
                        OutboxEvent.event_type == "upload.requested",
                        OutboxEvent.status.in_(("pending", "processing")),
                    ),
                ),
            )
            .order_by(Task.closed_at, Task.id)
            .limit(limit)
        )
    )


def _compensate_terminal_task_residue(
    db: Session, *, task_id: str, now: datetime
) -> LifecycleSweepResult:
    status = db.scalar(select(Task.status).where(Task.id == task_id))
    if status is None:
        return LifecycleSweepResult()
    expired = status == "expired"
    return compensate_terminal_task_resources(
        db,
        task_id,
        now=now,
        card_status="expired" if expired else "released",
        mail_status="expired" if expired else "revoked",
        release_reason="terminal_task_recovery",
        actor_user_id="worker-lifecycle",
        actor_device_id=None,
    )


def _expire_mail_session(
    db: Session,
    session: MailSession,
    *,
    now: datetime,
) -> LifecycleSweepResult:
    expired = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session.id,
            MailSession.status.in_(ACTIVE_MAIL_SESSION_STATUSES),
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
        .execution_options(synchronize_session="fetch")
    )
    if expired.rowcount != 1:
        return LifecycleSweepResult()
    record_audit(
        db,
        tenant_id=session.tenant_id,
        user_id=session.user_id,
        device_id=session.device_id,
        actor_id="worker-lifecycle",
        event_type="mail_session.expired",
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={"status": "expired", "reason": "mail_session_ttl_expired"},
    )
    return LifecycleSweepResult(mail_sessions_expired=1)


def _expire_mail_code(
    db: Session,
    session: MailSession,
    *,
    now: datetime,
) -> LifecycleSweepResult:
    expired = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session.id,
            MailSession.status == "code_ready",
            MailSession.code_expires_at.is_not(None),
            MailSession.code_expires_at <= now,
            MailSession.expires_at > now,
        )
        .values(
            status="waiting",
            delivered_code=None,
            delivered_message_id_hash=None,
            delivered_at=None,
            code_expires_at=None,
        )
        .execution_options(synchronize_session="fetch")
    )
    if expired.rowcount != 1:
        return LifecycleSweepResult()
    record_audit(
        db,
        tenant_id=session.tenant_id,
        user_id=session.user_id,
        device_id=session.device_id,
        actor_id="worker-lifecycle",
        event_type="mail_session.code_expired",
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={"status": "waiting", "source": "lifecycle_sweep"},
    )
    return LifecycleSweepResult(mail_codes_expired=1)


def sweep_expired_lifecycle(
    session_factory: sessionmaker[Session],
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> LifecycleSweepResult:
    """Bounded, concurrency-safe TTL compensation independent of HTTP traffic."""

    if limit <= 0:
        raise ValueError("limit must be positive")
    sweep_now = now or utc_now()
    result = LifecycleSweepResult()
    with session_factory() as db:
        revoked_principal_tasks = list(
            db.scalars(
                select(Task)
                .where(
                    ~Task.status.in_(TERMINAL_TASK_STATUSES),
                    or_(
                        exists().where(
                            User.id == Task.user_id,
                            User.tenant_id == Task.tenant_id,
                            User.is_active.is_(False),
                        ),
                        exists().where(
                            Device.id == Task.device_id,
                            Device.tenant_id == Task.tenant_id,
                            Device.user_id == Task.user_id,
                            Device.revoked_at.is_not(None),
                        ),
                    ),
                )
                .order_by(Task.created_at, Task.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        for task in revoked_principal_tasks:
            result += transition_task_to_terminal(
                task,
                db,
                now=sweep_now,
                task_status="cancelled",
                card_status="released",
                mail_status="revoked",
                release_reason="principal_revoked_recovery",
                actor_user_id="worker-lifecycle",
                actor_device_id=None,
                finalize_upload_outbox=True,
                skip_locked=True,
            )

        expired_tasks = list(
            db.scalars(
                select(Task)
                .where(
                    ~Task.status.in_(TERMINAL_TASK_STATUSES),
                    Task.expires_at.is_not(None),
                    Task.expires_at <= sweep_now,
                )
                .order_by(Task.expires_at, Task.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        for task in expired_tasks:
            result += transition_task_to_terminal(
                task,
                db,
                now=sweep_now,
                task_status="expired",
                card_status="expired",
                mail_status="expired",
                release_reason="task_ttl_expired",
                actor_user_id="worker-lifecycle",
                actor_device_id=None,
                running_upload_status="unknown",
                upload_error_code="task_expired",
                finalize_upload_outbox=True,
                skip_locked=True,
            )

        stale_allocations = list(
            db.scalars(
                select(CardAllocation)
                .where(
                    CardAllocation.released_at.is_(None),
                    CardAllocation.expires_at <= sweep_now,
                )
                .order_by(CardAllocation.expires_at, CardAllocation.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        for allocation in stale_allocations:
            task = db.scalar(
                select(Task)
                .where(Task.id == allocation.task_id)
                .with_for_update(skip_locked=True)
            )
            if task is None:
                continue
            result += transition_task_to_terminal(
                task,
                db,
                now=sweep_now,
                task_status="cancelled",
                card_status="expired",
                mail_status="expired",
                release_reason="card_lease_expired",
                actor_user_id="worker-lifecycle",
                actor_device_id=None,
                running_upload_status="unknown",
                upload_error_code="card_lease_invalid",
                finalize_upload_outbox=True,
                skip_locked=True,
            )

        stale_sessions = list(
            db.scalars(
                select(MailSession)
                .where(
                    MailSession.status.in_(ACTIVE_MAIL_SESSION_STATUSES),
                    or_(
                        MailSession.expires_at <= sweep_now,
                        (
                            (MailSession.status == "code_ready")
                            & MailSession.code_expires_at.is_not(None)
                            & (MailSession.code_expires_at <= sweep_now)
                        ),
                    ),
                )
                .order_by(MailSession.expires_at, MailSession.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        for session in stale_sessions:
            if _is_expired(session.expires_at, sweep_now):
                result += _expire_mail_session(db, session, now=sweep_now)
            else:
                result += _expire_mail_code(db, session, now=sweep_now)
        db.commit()

        # A process can stop after the terminal Task commit but before rows
        # skipped above are compensated.  Terminal state is therefore also the
        # durable recovery marker for a bounded second phase on every sweep.
        residual_task_ids = _terminal_tasks_with_resource_residue(db, limit=limit)
        for task_id in residual_task_ids:
            result += _compensate_terminal_task_residue(
                db, task_id=task_id, now=sweep_now
            )
        db.commit()
    return result


def revoke_principal_resources(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    device_id: str | None,
    now: datetime,
    actor_user_id: str,
    actor_device_id: str | None,
    release_reason: str,
    mail_status: str = "expired",
    finalize_upload_outbox: bool = False,
) -> None:
    """Cancel a principal's tasks and release their resources with full audit."""

    task_filters = [Task.tenant_id == tenant_id, Task.user_id == user_id]
    if device_id is not None:
        task_filters.append(Task.device_id == device_id)
    # A caller may already have a dirty User/Device row.  Suppress autoflush
    # until the same UploadJob -> Task prefix used by the worker is locked.
    with db.no_autoflush:
        task_ids = tuple(db.scalars(select(Task.id).where(*task_filters)))
        if not task_ids:
            return

        list(
            db.scalars(
                select(UploadJob)
                .where(
                    UploadJob.task_id.in_(task_ids),
                    UploadJob.status.in_(("queued", "running")),
                )
                .order_by(UploadJob.id)
                .with_for_update()
            )
        )
        tasks = list(
            db.scalars(
                select(Task)
                .where(Task.id.in_(task_ids))
                .order_by(Task.id)
                .with_for_update()
            )
        )
    for task in tasks:
        if task.status not in TERMINAL_TASK_STATUSES:
            task.status = "cancelled"
            task.closed_at = now
            record_audit(
                db,
                tenant_id=task.tenant_id,
                user_id=task.user_id,
                device_id=task.device_id,
                actor_id=actor_user_id,
                event_type="task.cancelled",
                entity_type="task",
                entity_id=task.id,
                trace_id=task.trace_id,
                details={"release_reason": release_reason},
            )
        release_task_resources(
            task,
            db,
            now=now,
            card_status="released",
            mail_status=mail_status,
            release_reason=release_reason,
            actor_user_id=actor_user_id,
            actor_device_id=actor_device_id,
            finalize_upload_outbox=finalize_upload_outbox,
        )


__all__ = [
    "ACTIVE_MAIL_SESSION_STATUSES",
    "LifecycleSweepResult",
    "RELEASABLE_MAIL_SESSION_STATUSES",
    "TERMINAL_TASK_STATUSES",
    "release_task_resources",
    "revoke_principal_resources",
    "sweep_expired_lifecycle",
    "transition_task_to_terminal",
]
