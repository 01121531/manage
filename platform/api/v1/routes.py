"""Version 1 API routes for the Phase 1 platform slice."""

import hashlib
import asyncio
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import exists, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from platform import __version__
from platform.audit import record_audit, sanitize_audit_details
from platform.auth import (
    AuthPrincipal,
    ROLE_OPS_ADMIN,
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_AUDITOR,
    create_access_token,
    get_current_principal,
    require_roles,
    unauthorized,
    verify_password,
)
from platform.cards import CardSecretUnavailable
from platform.config import Settings
from platform.database import get_db
from platform.mail_connectors import (
    MailboxAccess,
    MailConnector,
    MailConnectorUnavailable,
    UnconfiguredMailConnector,
)
from platform.models import (
    Card,
    CardAllocation,
    CardRevealChallenge,
    Device,
    Mailbox,
    MailSession,
    OutboxEvent,
    Task,
    UploadPolicyDeployment,
    UploadPolicyVersion,
    UploadJob,
    User,
    AuditEvent,
    new_id,
)
from platform.schemas import (
    LoginRequest,
    MailCodeResponse,
    MailboxStatusResponse,
    MailSessionResponse,
    CardAllocationResponse,
    CardRevealChallengeResponse,
    CardRevealGrantRequest,
    CardRevealGrantResponse,
    CardRevealRequest,
    CardRevealResponse,
    DashboardSummaryResponse,
    UploadCreate,
    UploadDirectCreate,
    UploadJobResponse,
    UploadPolicyStatusResponse,
    UploadPolicyDeployRequest,
    UploadPolicyDeploymentResponse,
    UploadPolicyVersionCreate,
    UploadPolicyVersionResponse,
    UploadReconcileRequest,
    AdminAuditResponse,
    AdminCardResponse,
    AdminDeviceResponse,
    AdminUploadResponse,
    AdminUserResponse,
    AuthConfigResponse,
    MeResponse,
    TaskCreate,
    TaskResponse,
    TokenResponse,
)
from platform.policies import select_policy_for_task

router = APIRouter()
_unconfigured_mail_connector = UnconfiguredMailConnector()
_TENANT_DASHBOARD_ROLES = frozenset(
    {ROLE_OPS_ADMIN, ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN}
)
_ACTIVE_MAIL_SESSION_STATUSES = ("initializing", "waiting", "code_ready")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now


def _mail_connector(request: Request, connector_type: str) -> MailConnector:
    return request.app.state.mail_connectors.get(
        connector_type, _unconfigured_mail_connector
    )


def _mailbox_access(mailbox: Mailbox) -> MailboxAccess:
    return MailboxAccess(mailbox_id=mailbox.id, secret_ref=mailbox.secret_ref)


def _mail_poll_mode(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return settings.mail_poll_mode.strip().lower()


@router.get("/health", tags=["system"])
async def health(request: Request) -> dict[str, str]:
    """Return process health without making external service calls."""

    settings: Settings = request.app.state.settings
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
    }


@router.get("/version", tags=["system"])
async def version() -> dict[str, str]:
    """Return the API package version."""

    return {"version": __version__, "api_version": "v1"}


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    if request.app.state.settings.auth_mode.strip().lower() != "local":
        raise HTTPException(status_code=404, detail="Local login is unavailable")
    user = db.scalar(
        select(User).where(
            User.tenant_id == payload.tenant_id,
            User.email == payload.email,
            User.is_active.is_(True),
        )
    )
    if user is None or user.password_hash is None or not verify_password(payload.password, user.password_hash):
        raise unauthorized()
    device = db.scalar(
        select(Device).where(
            Device.id == payload.device_id,
            Device.tenant_id == payload.tenant_id,
            Device.user_id == user.id,
            Device.revoked_at.is_(None),
        )
    )
    if device is None:
        raise unauthorized()

    settings: Settings = request.app.state.settings
    access_token = create_access_token(
        secret=request.app.state.jwt_hmac_secret,
        user_id=user.id,
        tenant_id=user.tenant_id,
        device_id=device.id,
        ttl_seconds=settings.access_token_ttl_seconds,
        role=user.role,
    )
    record_audit(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        device_id=device.id,
        event_type="auth.login",
        entity_type="user",
        entity_id=user.id,
        trace_id=request.state.trace_id,
        details={"method": "local_account"},
    )
    db.commit()
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.get("/auth/config", response_model=AuthConfigResponse, tags=["auth"])
def auth_config(request: Request) -> AuthConfigResponse:
    settings: Settings = request.app.state.settings
    mode = settings.auth_mode.strip().lower()
    return AuthConfigResponse(
        mode=mode,
        issuer=settings.oidc_issuer_url if mode == "oidc" else None,
        client_id=settings.oidc_client_id if mode == "oidc" else None,
        desktop_client_id=settings.oidc_desktop_client_id if mode == "oidc" else None,
        audience=settings.oidc_audience if mode == "oidc" else None,
    )


@router.get("/me", response_model=MeResponse, tags=["auth"])
def me(principal: AuthPrincipal = Depends(get_current_principal)) -> MeResponse:
    return MeResponse(
        id=principal.user_id,
        tenant_id=principal.tenant_id,
        email=principal.email,
        device_id=principal.device_id,
        role=principal.role,
    )


def _status_counts(db: Session, model: Any, filters: list[Any]) -> dict[str, int]:
    rows = db.execute(
        select(model.status, func.count()).where(*filters).group_by(model.status)
    ).all()
    return {str(status): int(count) for status, count in rows}


@router.get(
    "/dashboard/summary",
    response_model=DashboardSummaryResponse,
    tags=["dashboard"],
)
def dashboard_summary(
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    """Return safe aggregate platform status for the current operator scope."""

    now = _utc_now()
    scope = "tenant" if principal.role in _TENANT_DASHBOARD_ROLES else "own"
    task_filters: list[Any] = [Task.tenant_id == principal.tenant_id]
    mail_filters: list[Any] = [MailSession.tenant_id == principal.tenant_id]
    card_filters: list[Any] = [CardAllocation.tenant_id == principal.tenant_id]
    upload_filters: list[Any] = [UploadJob.tenant_id == principal.tenant_id]
    if scope == "own":
        task_filters.append(Task.user_id == principal.user_id)
        mail_filters.append(MailSession.user_id == principal.user_id)
        card_filters.append(CardAllocation.user_id == principal.user_id)
        upload_filters.append(UploadJob.user_id == principal.user_id)

    active_tasks = db.scalar(
        select(func.count())
        .select_from(Task)
        .where(
            *task_filters,
            ~Task.status.in_(_TERMINAL_TASK_STATUSES),
            or_(Task.expires_at.is_(None), Task.expires_at > now),
        )
    )
    allocated_cards = db.scalar(
        select(func.count())
        .select_from(CardAllocation)
        .where(
            *card_filters,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
    )
    waiting_mail_sessions = db.scalar(
        select(func.count())
        .select_from(MailSession)
        .where(
            *mail_filters,
            MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            MailSession.expires_at > now,
        )
    )
    queued_uploads = db.scalar(
        select(func.count())
        .select_from(UploadJob)
        .where(*upload_filters, UploadJob.status == "queued")
    )
    unknown_uploads = db.scalar(
        select(func.count())
        .select_from(UploadJob)
        .where(*upload_filters, UploadJob.status == "unknown")
    )
    return DashboardSummaryResponse(
        scope=scope,
        generated_at=now,
        active_tasks=int(active_tasks or 0),
        allocated_cards=int(allocated_cards or 0),
        waiting_mail_sessions=int(waiting_mail_sessions or 0),
        queued_uploads=int(queued_uploads or 0),
        unknown_uploads=int(unknown_uploads or 0),
        task_statuses=_status_counts(db, Task, task_filters),
        mail_session_statuses=_status_counts(db, MailSession, mail_filters),
        card_allocation_statuses=_status_counts(db, CardAllocation, card_filters),
        upload_statuses=_status_counts(db, UploadJob, upload_filters),
    )


def _mailbox_status_response(
    mailbox: Mailbox, *, active_session_count: int
) -> MailboxStatusResponse:
    status = (
        "disabled"
        if not mailbox.is_active
        else "busy"
        if active_session_count > 0
        else "available"
    )
    return MailboxStatusResponse(
        id=mailbox.id,
        email_masked=mailbox.email_masked,
        connector_type=mailbox.connector_type,
        is_active=mailbox.is_active,
        status=status,
        active_session_count=active_session_count,
        created_at=mailbox.created_at,
    )


@router.get(
    "/mailboxes",
    response_model=list[MailboxStatusResponse],
    tags=["mail"],
)
def list_mailboxes(
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[MailboxStatusResponse]:
    """List safe masked mailbox connector status for the current tenant."""

    now = _utc_now()
    mailboxes = db.scalars(
        select(Mailbox)
        .where(Mailbox.tenant_id == principal.tenant_id)
        .order_by(Mailbox.created_at.desc(), Mailbox.id)
    ).all()
    responses: list[MailboxStatusResponse] = []
    for mailbox in mailboxes:
        active_session_count = db.scalar(
            select(func.count())
            .select_from(MailSession)
            .where(
                MailSession.mailbox_id == mailbox.id,
                MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
                MailSession.expires_at > now,
            )
        )
        responses.append(
            _mailbox_status_response(
                mailbox, active_session_count=int(active_session_count or 0)
            )
        )
    return responses


@router.post(
    "/devices/{device_id}/revoke",
    response_model=AdminDeviceResponse,
    tags=["devices"],
)
def revoke_owned_device(
    device_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AdminDeviceResponse:
    device = db.scalar(
        select(Device).where(
            Device.id == device_id,
            Device.tenant_id == principal.tenant_id,
            Device.user_id == principal.user_id,
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.revoked_at is None:
        now = _utc_now()
        device.revoked_at = now
        _revoke_principal_resources(
            db,
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.id,
            now=now,
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="device.revoked",
            entity_type="device",
            entity_id=device.id,
            trace_id=request.state.trace_id,
            details={"reason": "owner_requested"},
        )
        db.commit()
        db.refresh(device)
    return AdminDeviceResponse.model_validate(device, from_attributes=True)


def _find_idempotent_task(
    db: Session, principal: AuthPrincipal, idempotency_key: str
) -> Task | None:
    return db.scalar(
        select(Task).where(
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.idempotency_key == idempotency_key,
        )
    )


def _same_task_payload(task: Task, payload: TaskCreate) -> bool:
    return (
        task.task_type == payload.type
        and task.client_reference == payload.client_reference
    )


_TERMINAL_TASK_STATUSES = frozenset({"closed", "expired", "cancelled", "completed"})


def _release_task_resources(
    task: Task,
    db: Session,
    *,
    now: datetime,
    card_status: str,
    mail_status: str,
    release_reason: str,
    actor_user_id: str,
    actor_device_id: str,
) -> None:
    allocations = list(
        db.scalars(
            select(CardAllocation).where(
                CardAllocation.task_id == task.id,
                CardAllocation.tenant_id == task.tenant_id,
                CardAllocation.released_at.is_(None),
            )
        )
    )
    for allocation in allocations:
        allocation.status = card_status
        allocation.released_at = now
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=actor_user_id,
            device_id=actor_device_id,
            event_type="card.released" if card_status == "released" else "card.expired",
            entity_type="card_allocation",
            entity_id=allocation.id,
            trace_id=allocation.trace_id,
            details={"task_id": task.id, "release_reason": release_reason},
        )

    sessions = list(
        db.scalars(
            select(MailSession).where(
                MailSession.task_id == task.id,
                MailSession.tenant_id == task.tenant_id,
                MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            )
        )
    )
    for session in sessions:
        session.status = mail_status
        session.delivered_code = None
        session.delivered_at = None
        session.code_expires_at = None
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=actor_user_id,
            device_id=actor_device_id,
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
            )
        )
    )
    for upload in uploads:
        upload.status = "cancelled" if upload.status == "queued" else "cancel_pending"
        record_audit(
            db,
            tenant_id=task.tenant_id,
            user_id=actor_user_id,
            device_id=actor_device_id,
            event_type="upload.cancel_requested",
            entity_type="upload_job",
            entity_id=upload.id,
            trace_id=upload.trace_id,
            details={"status": upload.status, "reason": release_reason},
        )


def _revoke_principal_resources(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    device_id: str | None,
    now: datetime,
) -> None:
    task_filters = [
        Task.tenant_id == tenant_id,
        Task.user_id == user_id,
        ~Task.status.in_(_TERMINAL_TASK_STATUSES),
    ]
    card_filters = [
        CardAllocation.tenant_id == tenant_id,
        CardAllocation.user_id == user_id,
        CardAllocation.released_at.is_(None),
    ]
    mail_filters = [
        MailSession.tenant_id == tenant_id,
        MailSession.user_id == user_id,
        MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
    ]
    if device_id is not None:
        task_filters.append(Task.device_id == device_id)
        card_filters.append(CardAllocation.device_id == device_id)
        mail_filters.append(MailSession.device_id == device_id)
    db.query(Task).filter(*task_filters).update(
        {"status": "cancelled", "closed_at": now}, synchronize_session=False
    )
    db.query(CardAllocation).filter(*card_filters).update(
        {"status": "released", "released_at": now}, synchronize_session=False
    )
    db.query(MailSession).filter(*mail_filters).update(
        {
            "status": "expired",
            "delivered_code": None,
            "delivered_at": None,
            "code_expires_at": None,
        },
        synchronize_session=False,
    )


def _expire_task_if_needed(
    task: Task,
    db: Session,
    *,
    request: Request,
    principal: AuthPrincipal,
) -> bool:
    if task.status in _TERMINAL_TASK_STATUSES or task.expires_at is None:
        return False
    now = _utc_now()
    if not _is_expired(task.expires_at, now):
        return False
    task.status = "expired"
    task.closed_at = now
    _release_task_resources(
        task,
        db,
        now=now,
        card_status="expired",
        mail_status="expired",
        release_reason="task_ttl_expired",
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
    )
    record_audit(
        db,
        tenant_id=task.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="task.expired",
        entity_type="task",
        entity_id=task.id,
        trace_id=task.trace_id,
        details={"release_reason": "task_ttl_expired"},
    )
    return True


def _assert_task_open(
    task: Task,
    db: Session,
    *,
    request: Request,
    principal: AuthPrincipal,
) -> None:
    expired_now = _expire_task_if_needed(
        task, db, request=request, principal=principal
    )
    if expired_now:
        db.commit()
    if task.status in _TERMINAL_TASK_STATUSES:
        raise HTTPException(status_code=409, detail="Task is closed or expired")


@router.post(
    "/tasks",
    response_model=TaskResponse,
    status_code=201,
    responses={200: {"model": TaskResponse, "description": "Idempotent replay"}},
    tags=["tasks"],
)
def create_task(
    payload: TaskCreate,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Task:
    existing = _find_idempotent_task(db, principal, payload.idempotency_key)
    if existing is not None:
        if not _same_task_payload(existing, payload):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key was already used with different task data",
            )
        response.status_code = 200
        return existing

    task = Task(
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        task_type=payload.type,
        idempotency_key=payload.idempotency_key,
        client_reference=payload.client_reference,
        trace_id=request.state.trace_id,
        expires_at=_utc_now() + timedelta(seconds=request.app.state.settings.task_ttl_seconds),
    )
    db.add(task)
    try:
        db.flush()
    except IntegrityError:
        # The database constraint closes the race between the initial lookup
        # and insert when two identical requests arrive concurrently.
        db.rollback()
        existing = _find_idempotent_task(db, principal, payload.idempotency_key)
        if existing is not None and _same_task_payload(existing, payload):
            response.status_code = 200
            return existing
        raise HTTPException(
            status_code=409,
            detail="Idempotency key was already used with different task data",
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="task.created",
        entity_type="task",
        entity_id=task.id,
        trace_id=task.trace_id,
        details={
            "task_type": payload.type,
            "idempotency_key": payload.idempotency_key,
            "client_reference": payload.client_reference,
        },
    )
    db.commit()
    return task


@router.get("/tasks", response_model=list[TaskResponse], tags=["tasks"])
def list_tasks(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[Task]:
    tasks = list(
        db.scalars(
            select(Task)
            .where(
                Task.tenant_id == principal.tenant_id,
                Task.user_id == principal.user_id,
            )
            .order_by(Task.created_at.desc())
            .limit(limit)
        )
    )
    lifecycle_changed = False
    for task in tasks:
        lifecycle_changed = (
            _expire_task_if_needed(task, db, request=request, principal=principal)
            or lifecycle_changed
        )
    if lifecycle_changed:
        db.commit()
    return tasks


@router.get("/tasks/{task_id}", response_model=TaskResponse, tags=["tasks"])
def get_task(
    task_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Task:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if _expire_task_if_needed(task, db, request=request, principal=principal):
        db.commit()
        db.refresh(task)
    return task


@router.post("/tasks/{task_id}/close", response_model=TaskResponse, tags=["tasks"])
def close_task(
    task_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Task:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if _expire_task_if_needed(task, db, request=request, principal=principal):
        db.commit()
        db.refresh(task)
        return task
    if task.status not in _TERMINAL_TASK_STATUSES:
        now = _utc_now()
        task.status = "closed"
        task.closed_at = now
        _release_task_resources(
            task,
            db,
            now=now,
            card_status="released",
            mail_status="revoked",
            release_reason="task_closed",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="task.closed",
            entity_type="task",
            entity_id=task.id,
            trace_id=task.trace_id,
            details={"release_reason": "task_closed"},
        )
        db.commit()
        db.refresh(task)
    return task


@router.post(
    "/tasks/{task_id}/mail-sessions",
    response_model=MailSessionResponse,
    status_code=201,
    responses={200: {"model": MailSessionResponse, "description": "Existing session"}},
    tags=["mail"],
)
@router.post(
    "/tasks/{task_id}/mail-session",
    response_model=MailSessionResponse,
    status_code=201,
    responses={200: {"model": MailSessionResponse, "description": "Existing session"}},
    tags=["mail"],
)
def create_mail_session(
    task_id: str,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> MailSessionResponse:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_task_open(task, db, request=request, principal=principal)

    existing = db.scalar(
        select(MailSession).where(MailSession.task_id == task.id)
    )
    if existing is not None:
        if (
            existing.user_id != principal.user_id
            or existing.device_id != principal.device_id
        ):
            raise HTTPException(status_code=404, detail="Mail session not found")
        mailbox = db.get(Mailbox, existing.mailbox_id)
        if mailbox is None:
            raise HTTPException(status_code=503, detail="Assigned mailbox is unavailable")
        if _is_expired(existing.expires_at, _utc_now()) and existing.status in _ACTIVE_MAIL_SESSION_STATUSES:
            existing.status = "expired"
            existing.delivered_code = None
            existing.delivered_at = None
            existing.code_expires_at = None
            db.commit()
        response.status_code = 200
        return MailSessionResponse(
            id=existing.id,
            trace_id=existing.trace_id,
            email_masked=mailbox.email_masked,
            status=existing.status,
            expires_at=existing.expires_at,
        )

    now = _utc_now()
    # Reclaim stale leases before selecting.  The partial unique index remains
    # the database-level backstop, while the row lock prevents two PostgreSQL
    # transactions from choosing the same available mailbox.
    db.query(MailSession).filter(
        MailSession.tenant_id == principal.tenant_id,
        MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
        MailSession.expires_at <= now,
    ).update(
        {
            "status": "expired",
            "delivered_code": None,
            "delivered_at": None,
            "code_expires_at": None,
        },
        synchronize_session=False,
    )
    busy_mailbox = exists(
        select(MailSession.id).where(
            MailSession.mailbox_id == Mailbox.id,
            MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            MailSession.expires_at > now,
        )
    )
    mailbox = db.scalar(
        select(Mailbox)
        .where(
            Mailbox.tenant_id == principal.tenant_id,
            Mailbox.is_active.is_(True),
            ~busy_mailbox,
        )
        .order_by(Mailbox.created_at, Mailbox.id)
        .with_for_update(skip_locked=True)
    )
    if mailbox is None:
        raise HTTPException(status_code=503, detail="No active mailbox is available")

    settings: Settings = request.app.state.settings
    poll_mode = _mail_poll_mode(request)
    start_watermark = None
    status = "initializing"
    if poll_mode == "api":
        connector = _mail_connector(request, mailbox.connector_type)
        try:
            start_watermark = connector.current_watermark(_mailbox_access(mailbox))
        except MailConnectorUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        status = "waiting"
    session = MailSession(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        mailbox_id=mailbox.id,
        trace_id=task.trace_id,
        status=status,
        expires_at=now + timedelta(seconds=settings.mail_session_ttl_seconds),
        start_watermark=start_watermark,
    )
    db.add(session)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=503, detail="No active mailbox is available"
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="mail_session.created",
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={
            "task_id": task.id,
            "connector_type": mailbox.connector_type,
            "poll_mode": poll_mode,
        },
    )
    db.commit()
    return MailSessionResponse(
        id=session.id,
        trace_id=session.trace_id,
        email_masked=mailbox.email_masked,
        status=session.status,
        expires_at=session.expires_at,
    )


@router.get(
    "/mail-sessions/{session_id}/code",
    response_model=MailCodeResponse,
    tags=["mail"],
)
@router.get(
    "/mail-session/{session_id}/code",
    response_model=MailCodeResponse,
    tags=["mail"],
)
def get_mail_code(
    session_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> MailCodeResponse:
    session = db.scalar(
        select(MailSession).where(
            MailSession.id == session_id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
        )
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Mail session not found")

    now = _utc_now()
    if session.status == "revoked":
        return MailCodeResponse(status="revoked")
    if session.status == "expired" or _is_expired(session.expires_at, now):
        session.status = "expired"
        session.delivered_code = None
        session.delivered_at = None
        session.code_expires_at = None
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "expired"},
        )
        db.commit()
        return MailCodeResponse(status="expired")

    if session.consumed_at is not None or session.status == "consumed":
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "consumed"},
        )
        db.commit()
        return MailCodeResponse(status="consumed")

    if (
        session.status == "code_ready"
        and session.code_expires_at is not None
        and _is_expired(session.code_expires_at, now)
    ):
        session.delivered_code = None
        session.delivered_at = None
        session.code_expires_at = None
        session.status = "waiting"
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_expired",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "waiting", "source": "worker"},
        )
        db.commit()

    if session.status == "code_ready" and session.delivered_code is not None:
        delivered_code = session.delivered_code
        session.delivered_code = None
        session.delivered_at = None
        session.code_expires_at = None
        session.consumed_at = now
        session.status = "consumed"
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_consumed",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "consumed", "source": "worker"},
        )
        db.commit()
        return MailCodeResponse(status="consumed", code=delivered_code)

    if _mail_poll_mode(request) == "worker":
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": session.status, "source": "worker"},
        )
        db.commit()
        return MailCodeResponse(status="waiting")

    mailbox = db.get(Mailbox, session.mailbox_id)
    if mailbox is None or not mailbox.is_active:
        raise HTTPException(status_code=503, detail="Assigned mailbox is unavailable")
    connector = _mail_connector(request, mailbox.connector_type)
    try:
        message = connector.find_code_after(
            _mailbox_access(mailbox), session.start_watermark
        )
    except MailConnectorUnavailable as exc:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "connector_unavailable"},
        )
        db.commit()
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if message is None or message.watermark == session.start_watermark:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": "waiting"},
        )
        db.commit()
        return MailCodeResponse(status="waiting")

    message_hash = hashlib.sha256(
        f"{mailbox.id}\0{message.message_id}\0{message.code}".encode("utf-8")
    ).hexdigest()
    if message_hash == session.last_message_hash:
        return MailCodeResponse(status="waiting")

    session.last_message_hash = message_hash
    session.consumed_at = now
    session.status = "consumed"
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="mail_session.code_consumed",
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={"status": "consumed"},
    )
    db.commit()
    return MailCodeResponse(status="consumed", code=message.code)


@router.post(
    "/mail-sessions/{session_id}/revoke",
    response_model=MailSessionResponse,
    tags=["mail"],
)
@router.post(
    "/mail-session/{session_id}/revoke",
    response_model=MailSessionResponse,
    tags=["mail"],
)
def revoke_mail_session(
    session_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> MailSessionResponse:
    session = db.scalar(
        select(MailSession).where(
            MailSession.id == session_id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
        )
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Mail session not found")
    mailbox = db.get(Mailbox, session.mailbox_id)
    if mailbox is None:
        raise HTTPException(status_code=503, detail="Assigned mailbox is unavailable")
    if session.status in _ACTIVE_MAIL_SESSION_STATUSES:
        session.status = "revoked"
        session.delivered_code = None
        session.delivered_at = None
        session.code_expires_at = None
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.revoked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"task_id": session.task_id, "reason": "user_requested"},
        )
        db.commit()
    return MailSessionResponse(
        id=session.id,
        trace_id=session.trace_id,
        email_masked=mailbox.email_masked,
        status=session.status,
        expires_at=session.expires_at,
    )


@router.get(
    "/mail-sessions/{session_id}/events",
    tags=["mail"],
)
@router.get(
    "/mail-session/{session_id}/events",
    tags=["mail"],
)
async def mail_session_events(
    session_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    session = db.scalar(
        select(MailSession).where(
            MailSession.id == session_id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
        )
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Mail session not found")
    deadline = session.expires_at
    poll_seconds = min(5, max(1, request.app.state.settings.mail_poll_interval_seconds))

    async def stream():
        while True:
            if await request.is_disconnected():
                return
            with request.app.state.session_factory() as stream_db:
                try:
                    result = get_mail_code(
                        session_id, request, principal, stream_db
                    )
                except HTTPException as exc:
                    event = {
                        "status": "error",
                        "code": None,
                        "error_code": str(exc.status_code),
                    }
                    yield f"event: error\ndata: {json.dumps(event)}\n\n"
                    return
            event_name = result.status
            event = {"status": result.status, "code": result.code}
            yield f"event: {event_name}\ndata: {json.dumps(event)}\n\n"
            if result.status != "waiting":
                return
            if _is_expired(deadline, _utc_now()):
                return
            await asyncio.sleep(poll_seconds)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _card_masked(card: Card) -> str:
    brand = card.brand.strip() or "CARD"
    return f"{brand} •••• {card.last4}"


def _card_allocation_response(
    allocation: CardAllocation, card: Card
) -> CardAllocationResponse:
    return CardAllocationResponse(
        id=allocation.id,
        trace_id=allocation.trace_id,
        card_masked=_card_masked(card),
        brand=card.brand,
        expiry_month=card.expiry_month,
        expiry_year=card.expiry_year,
        status=allocation.status,
        expires_at=allocation.expires_at,
    )


def _owned_card_allocation(
    db: Session, allocation_id: str, principal: AuthPrincipal
) -> tuple[CardAllocation, Card] | None:
    allocation = db.scalar(
        select(CardAllocation).where(
            CardAllocation.id == allocation_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
    )
    if allocation is None:
        return None
    card = db.get(Card, allocation.card_id)
    return (allocation, card) if card is not None else None


def _assert_revealable(allocation: CardAllocation, now: datetime) -> None:
    if (
        allocation.status != "active"
        or allocation.released_at is not None
        or _is_expired(allocation.expires_at, now)
    ):
        raise HTTPException(status_code=409, detail="Card allocation is not active")
    if allocation.revealed_at is not None:
        raise HTTPException(status_code=409, detail="Card allocation was already revealed")


@router.post(
    "/tasks/{task_id}/card-allocations",
    response_model=CardAllocationResponse,
    status_code=201,
    responses={200: {"model": CardAllocationResponse, "description": "Existing lease"}},
    tags=["cards"],
)
@router.post(
    "/tasks/{task_id}/card-allocation",
    response_model=CardAllocationResponse,
    status_code=201,
    responses={200: {"model": CardAllocationResponse, "description": "Existing lease"}},
    tags=["cards"],
)
def allocate_card(
    task_id: str,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_task_open(task, db, request=request, principal=principal)

    now = _utc_now()
    stale = list(
        db.scalars(
            select(CardAllocation).where(
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.released_at.is_(None),
                CardAllocation.expires_at <= now,
            )
        )
    )
    for old in stale:
        old.status = "expired"
        old.released_at = now

    existing = db.scalar(
        select(CardAllocation).where(
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.released_at.is_(None),
        )
    )
    if existing is not None:
        card = db.get(Card, existing.card_id)
        if card is None:
            raise HTTPException(status_code=503, detail="Assigned card is unavailable")
        response.status_code = 200
        return _card_allocation_response(existing, card)

    active_card = exists(
        select(CardAllocation.id).where(
            CardAllocation.card_id == Card.id,
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
    )
    card = db.scalar(
        select(Card)
        .where(
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            ~active_card,
        )
        .order_by(Card.created_at, Card.id)
    )
    if card is None:
        raise HTTPException(status_code=503, detail="No active card is available")

    settings: Settings = request.app.state.settings
    allocation = CardAllocation(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        card_id=card.id,
        trace_id=task.trace_id,
        status="active",
        expires_at=now + timedelta(seconds=settings.card_lease_ttl_seconds),
    )
    db.add(allocation)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(CardAllocation).where(
                CardAllocation.task_id == task.id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.user_id == principal.user_id,
                CardAllocation.released_at.is_(None),
            )
        )
        if existing is not None:
            card = db.get(Card, existing.card_id)
            if card is not None:
                response.status_code = 200
                return _card_allocation_response(existing, card)
        raise HTTPException(status_code=503, detail="Card allocation is busy; retry") from None

    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.allocated",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"task_id": task.id, "card_id": card.id, "card_last4": card.last4},
    )
    db.commit()
    return _card_allocation_response(allocation, card)


@router.get(
    "/card-allocations/{allocation_id}",
    response_model=CardAllocationResponse,
    tags=["cards"],
)
def get_card_allocation(
    allocation_id: str,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, card = result
    return _card_allocation_response(allocation, card)


@router.post(
    "/card-allocations/{allocation_id}/release",
    response_model=CardAllocationResponse,
    tags=["cards"],
)
def release_card_allocation(
    allocation_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, card = result
    if allocation.released_at is None:
        allocation.released_at = _utc_now()
        allocation.status = "released"
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="card.released",
            entity_type="card_allocation",
            entity_id=allocation.id,
            trace_id=allocation.trace_id,
            details={"card_id": card.id},
        )
        db.commit()
    return _card_allocation_response(allocation, card)


@router.post(
    "/card-allocations/{allocation_id}/reveal-challenges",
    response_model=CardRevealChallengeResponse,
    status_code=201,
    tags=["cards"],
)
def create_card_reveal_challenge(
    allocation_id: str,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardRevealChallengeResponse:
    """Bind a short-lived step-up request to the current actor and lease."""

    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, _card = result
    now = _utc_now()
    _assert_revealable(allocation, now)
    settings: Settings = request.app.state.settings
    challenge = CardRevealChallenge(
        allocation_id=allocation.id,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        required_acr=settings.card_step_up_acr,
        expires_at=now
        + timedelta(seconds=settings.card_step_up_challenge_ttl_seconds),
    )
    db.add(challenge)
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.reveal_challenge_created",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"required_acr": challenge.required_acr},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return CardRevealChallengeResponse(
        challenge_id=challenge.id,
        acr_values=challenge.required_acr,
        expires_at=challenge.expires_at,
    )


@router.post(
    "/card-allocations/{allocation_id}/reveal-grants",
    response_model=CardRevealGrantResponse,
    tags=["cards"],
)
def create_card_reveal_grant(
    allocation_id: str,
    payload: CardRevealGrantRequest,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardRevealGrantResponse:
    """Exchange a fresh, required-ACR OIDC authentication for one reveal."""

    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, _card = result
    now = _utc_now()
    _assert_revealable(allocation, now)
    challenge = db.scalar(
        select(CardRevealChallenge)
        .where(
            CardRevealChallenge.id == payload.challenge_id,
            CardRevealChallenge.allocation_id == allocation.id,
            CardRevealChallenge.tenant_id == principal.tenant_id,
            CardRevealChallenge.user_id == principal.user_id,
            CardRevealChallenge.device_id == principal.device_id,
        )
        .with_for_update()
    )
    if challenge is None:
        raise HTTPException(status_code=404, detail="Reveal challenge not found")
    if (
        challenge.consumed_at is not None
        or challenge.grant_token_hash is not None
        or _is_expired(challenge.expires_at, now)
    ):
        raise HTTPException(status_code=409, detail="Reveal challenge is no longer active")
    # A browser prompt alone is not proof of step-up.  The API validates the
    # signed OIDC claims and requires authentication after challenge creation.
    if principal.identity_kind != "oidc":
        raise HTTPException(status_code=403, detail="OIDC step-up is required")
    auth_time = principal.auth_time
    challenge_created_at = challenge.created_at
    if challenge_created_at.tzinfo is None:
        challenge_created_at = challenge_created_at.replace(tzinfo=timezone.utc)
    if auth_time is None or auth_time + timedelta(seconds=5) < challenge_created_at:
        raise HTTPException(status_code=403, detail="Fresh step-up is required")
    if principal.acr != challenge.required_acr:
        raise HTTPException(status_code=403, detail="Required authentication level missing")

    grant = secrets.token_urlsafe(32)
    challenge.grant_token_hash = hashlib.sha256(grant.encode("ascii")).hexdigest()
    challenge.granted_at = now
    settings: Settings = request.app.state.settings
    challenge.grant_expires_at = now + timedelta(
        seconds=settings.card_step_up_grant_ttl_seconds
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.reveal_step_up_succeeded",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"acr": principal.acr},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return CardRevealGrantResponse(
        reveal_grant=grant,
        expires_at=challenge.grant_expires_at,
    )


@router.post(
    "/card-allocations/{allocation_id}/reveal",
    response_model=CardRevealResponse,
    tags=["cards"],
)
def reveal_card_allocation(
    allocation_id: str,
    payload: CardRevealRequest,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> CardRevealResponse:
    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, card = result
    now = _utc_now()
    _assert_revealable(allocation, now)
    grant_hash = hashlib.sha256(payload.reveal_grant.encode("utf-8")).hexdigest()
    challenge = db.scalar(
        select(CardRevealChallenge)
        .where(
            CardRevealChallenge.allocation_id == allocation.id,
            CardRevealChallenge.tenant_id == principal.tenant_id,
            CardRevealChallenge.user_id == principal.user_id,
            CardRevealChallenge.device_id == principal.device_id,
            CardRevealChallenge.grant_token_hash == grant_hash,
            CardRevealChallenge.consumed_at.is_(None),
        )
        .with_for_update()
    )
    if (
        challenge is None
        or challenge.grant_expires_at is None
        or _is_expired(challenge.grant_expires_at, now)
    ):
        raise HTTPException(status_code=403, detail="Valid reveal grant required")

    try:
        secret = request.app.state.card_secret_resolver.resolve(card.secret_ref)
    except CardSecretUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    settings: Settings = request.app.state.settings
    challenge.consumed_at = now
    challenge.grant_token_hash = None
    allocation.revealed_at = now
    allocation.reveal_expires_at = now + timedelta(
        seconds=settings.card_reveal_ttl_seconds
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.revealed",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={
            "card_id": card.id,
            "fields": payload.fields,
            "reveal_ttl_seconds": settings.card_reveal_ttl_seconds,
        },
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return CardRevealResponse(
        id=new_id(),
        allocation_id=allocation.id,
        trace_id=allocation.trace_id,
        card_masked=_card_masked(card),
        brand=card.brand,
        expiry_month=card.expiry_month if "expiry" in payload.fields else None,
        expiry_year=card.expiry_year if "expiry" in payload.fields else None,
        pan=secret.pan,
        reveal_expires_at=allocation.reveal_expires_at,
    )


def _upload_job_response(job: UploadJob) -> UploadJobResponse:
    return UploadJobResponse(
        id=job.id,
        task_id=job.task_id,
        status=job.status,
        business_name=job.business_name,
        trace_id=job.trace_id,
        policy_version=job.policy_version,
        external_ref=job.external_ref,
        error_code=job.error_code,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@router.post(
    "/uploads",
    response_model=UploadJobResponse,
    status_code=201,
    responses={200: {"model": UploadJobResponse, "description": "Existing upload job"}},
    tags=["uploads"],
)
def create_upload_job_direct(
    payload: UploadDirectCreate,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    return create_upload_job(
        payload.task_id,
        UploadCreate(
            business_name=payload.business_name,
            idempotency_key=payload.idempotency_key,
        ),
        request,
        response,
        principal,
        db,
    )


@router.post(
    "/tasks/{task_id}/uploads",
    response_model=UploadJobResponse,
    status_code=201,
    responses={200: {"model": UploadJobResponse, "description": "Existing upload job"}},
    tags=["uploads"],
)
def create_upload_job(
    task_id: str,
    payload: UploadCreate,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_task_open(task, db, request=request, principal=principal)

    existing = db.scalar(
        select(UploadJob).where(
            UploadJob.tenant_id == principal.tenant_id,
            UploadJob.user_id == principal.user_id,
            UploadJob.idempotency_key == payload.idempotency_key,
        )
    )
    if existing is not None:
        if (
            existing.task_id != task.id
            or existing.business_name != payload.business_name
        ):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key was already used with different upload data",
            )
        response.status_code = 200
        return _upload_job_response(existing)

    now = _utc_now()
    active_allocation = db.scalar(
        select(CardAllocation).where(
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
    )
    if active_allocation is None:
        raise HTTPException(
            status_code=409,
            detail="An active card allocation is required before upload",
        )

    selected_policy = select_policy_for_task(
        db,
        tenant_id=principal.tenant_id,
        task_id=task.id,
        fallback=request.app.state.sub2_policy,
    )
    job = UploadJob(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        card_allocation_id=active_allocation.id,
        idempotency_key=payload.idempotency_key,
        business_name=payload.business_name.strip(),
        trace_id=task.trace_id,
        status="queued",
        policy_version=selected_policy.version,
    )
    db.add(job)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(UploadJob).where(
                UploadJob.tenant_id == principal.tenant_id,
                UploadJob.user_id == principal.user_id,
                UploadJob.idempotency_key == payload.idempotency_key,
            )
        )
        if existing is not None and (
            existing.task_id == task.id and existing.business_name == payload.business_name
        ):
            response.status_code = 200
            return _upload_job_response(existing)
        raise HTTPException(status_code=409, detail="Upload idempotency key is busy") from None

    db.add(
        OutboxEvent(
            tenant_id=principal.tenant_id,
            event_type="upload.requested",
            aggregate_type="upload_job",
            aggregate_id=job.id,
            status="pending",
        )
    )

    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload.queued",
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        details={
            "task_id": task.id,
            "card_allocation_id": active_allocation.id,
            "policy_version": selected_policy.version,
        },
    )
    db.commit()
    return _upload_job_response(job)


@router.get(
    "/upload-jobs/{job_id}",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
@router.get(
    "/uploads/{job_id}",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
def get_upload_job(
    job_id: str,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    job = db.scalar(
        select(UploadJob).where(
            UploadJob.id == job_id,
            UploadJob.tenant_id == principal.tenant_id,
            UploadJob.user_id == principal.user_id,
            UploadJob.device_id == principal.device_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Upload job not found")
    return _upload_job_response(job)


@router.post(
    "/upload-jobs/{job_id}/cancel",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
@router.post(
    "/uploads/{job_id}/cancel",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
def cancel_upload_job(
    job_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    job = db.scalar(
        select(UploadJob).where(
            UploadJob.id == job_id,
            UploadJob.tenant_id == principal.tenant_id,
            UploadJob.user_id == principal.user_id,
            UploadJob.device_id == principal.device_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Upload job not found")
    if job.status == "queued":
        job.status = "cancelled"
    elif job.status == "running":
        job.status = "cancel_pending"
    elif job.status not in {"cancelled", "cancel_pending"}:
        raise HTTPException(
            status_code=409,
            detail="Only queued or running upload jobs can be cancelled",
        )
    else:
        return _upload_job_response(job)
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload.cancel_requested",
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        details={"status": job.status},
    )
    db.commit()
    db.refresh(job)
    return _upload_job_response(job)


@router.post(
    "/upload-jobs/{job_id}/reconcile",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
@router.post(
    "/uploads/{job_id}/reconcile",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
def reconcile_upload_job(
    job_id: str,
    payload: UploadReconcileRequest,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    job = db.scalar(
        select(UploadJob).where(
            UploadJob.id == job_id,
            UploadJob.tenant_id == principal.tenant_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Upload job not found")
    if job.status != "unknown":
        raise HTTPException(
            status_code=409,
            detail="Only upload jobs with unknown result can be reconciled",
        )
    if payload.status == "succeeded" and not payload.external_ref:
        raise HTTPException(
            status_code=422,
            detail="external_ref is required for a succeeded reconciliation",
        )
    job.status = payload.status
    job.external_ref = payload.external_ref
    job.error_code = (
        None
        if payload.status == "succeeded"
        else payload.error_code or f"reconciled_{payload.status}"
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload.reconciled",
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        details={
            "status": job.status,
            "error_code": job.error_code,
            "policy_version": job.policy_version,
        },
    )
    db.commit()
    db.refresh(job)
    return _upload_job_response(job)


def _safe_audit_details(event: AuditEvent) -> dict[str, object]:
    try:
        value = json.loads(event.details_json)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    sanitized = sanitize_audit_details(value)
    return sanitized if isinstance(sanitized, dict) else {}


@router.get(
    "/admin/users",
    response_model=list[AdminUserResponse],
    tags=["admin"],
)
def admin_list_users(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminUserResponse]:
    users = db.scalars(
        select(User)
        .where(User.tenant_id == principal.tenant_id)
        .order_by(User.created_at.desc())
    ).all()
    return [AdminUserResponse.model_validate(user, from_attributes=True) for user in users]


@router.post(
    "/admin/users/{user_id}/disable",
    response_model=AdminUserResponse,
    tags=["admin"],
)
def admin_disable_user(
    user_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    if user_id == principal.user_id:
        raise HTTPException(status_code=409, detail="Cannot disable the current user")
    user = db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == principal.tenant_id)
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    _revoke_principal_resources(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        device_id=None,
        now=_utc_now(),
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.user_disabled",
        entity_type="user",
        entity_id=user.id,
        trace_id=request.state.trace_id,
        details={"role": user.role},
    )
    db.commit()
    db.refresh(user)
    return AdminUserResponse.model_validate(user, from_attributes=True)


@router.get(
    "/admin/devices",
    response_model=list[AdminDeviceResponse],
    tags=["admin"],
)
def admin_list_devices(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminDeviceResponse]:
    devices = db.scalars(
        select(Device)
        .where(Device.tenant_id == principal.tenant_id)
        .order_by(Device.created_at.desc())
    ).all()
    return [
        AdminDeviceResponse.model_validate(device, from_attributes=True)
        for device in devices
    ]


@router.post(
    "/admin/devices/{device_id}/revoke",
    response_model=AdminDeviceResponse,
    tags=["admin"],
)
def admin_revoke_device(
    device_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminDeviceResponse:
    if device_id == principal.device_id:
        raise HTTPException(status_code=409, detail="Cannot revoke the current device")
    device = db.scalar(
        select(Device).where(
            Device.id == device_id, Device.tenant_id == principal.tenant_id
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.revoked_at is None:
        now = _utc_now()
        device.revoked_at = now
        _revoke_principal_resources(
            db,
            tenant_id=device.tenant_id,
            user_id=device.user_id,
            device_id=device.id,
            now=now,
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.device_revoked",
            entity_type="device",
            entity_id=device.id,
            trace_id=request.state.trace_id,
            details={"device_owner_id": device.user_id},
        )
        db.commit()
        db.refresh(device)
    return AdminDeviceResponse.model_validate(device, from_attributes=True)


@router.get(
    "/admin/audit",
    response_model=list[AdminAuditResponse],
    tags=["admin"],
)
def admin_list_audit(
    trace_id: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None, max_length=64),
    entity_id: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=200, ge=1, le=500),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminAuditResponse]:
    query = select(AuditEvent).where(AuditEvent.tenant_id == principal.tenant_id)
    if trace_id:
        query = query.where(AuditEvent.trace_id == trace_id.strip())
    if user_id:
        query = query.where(AuditEvent.user_id == user_id.strip())
    if entity_id:
        query = query.where(AuditEvent.entity_id == entity_id.strip())
    if event_type:
        query = query.where(AuditEvent.event_type == event_type.strip())
    events = db.scalars(
        query.order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()
    return [
        AdminAuditResponse(
            id=event.id,
            tenant_id=event.tenant_id,
            user_id=event.user_id,
            device_id=event.device_id,
            event_type=event.event_type,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            trace_id=event.trace_id,
            details=_safe_audit_details(event),
            created_at=event.created_at,
        )
        for event in events
    ]


@router.get(
    "/admin/cards",
    response_model=list[AdminCardResponse],
    tags=["admin"],
)
def admin_list_cards(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminCardResponse]:
    cards = db.scalars(
        select(Card)
        .where(Card.tenant_id == principal.tenant_id)
        .order_by(Card.created_at.desc())
    ).all()
    return [AdminCardResponse.model_validate(card, from_attributes=True) for card in cards]


@router.get(
    "/admin/uploads",
    response_model=list[AdminUploadResponse],
    tags=["admin"],
)
def admin_list_uploads(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminUploadResponse]:
    jobs = db.scalars(
        select(UploadJob)
        .where(UploadJob.tenant_id == principal.tenant_id)
        .order_by(UploadJob.created_at.desc())
        .limit(500)
    ).all()
    return [AdminUploadResponse.model_validate(job, from_attributes=True) for job in jobs]


@router.get(
    "/admin/policies/upload",
    response_model=UploadPolicyStatusResponse,
    tags=["admin"],
)
def admin_upload_policy_status(
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> UploadPolicyStatusResponse:
    """Return safe server-owned upload policy status without execution details."""

    settings: Settings = request.app.state.settings
    upload_endpoint_configured = bool(settings.sub2_upload_url)
    upload_secret_configured = bool(settings.sub2_credential_ref)
    network_route_configured = bool(settings.sub2_proxy_ref)
    ready = (
        upload_endpoint_configured
        and upload_secret_configured
        and network_route_configured
    )
    deployment = db.scalar(
        select(UploadPolicyDeployment).where(
            UploadPolicyDeployment.tenant_id == principal.tenant_id
        )
    )
    active = (
        db.get(UploadPolicyVersion, deployment.active_policy_id)
        if deployment is not None
        else None
    )
    previous = (
        db.get(UploadPolicyVersion, deployment.previous_policy_id)
        if deployment is not None and deployment.previous_policy_id is not None
        else None
    )
    return UploadPolicyStatusResponse(
        policy_version=active.version if active is not None else settings.sub2_policy_version,
        status="ready" if ready else "not_configured",
        upload_endpoint_configured=upload_endpoint_configured,
        upload_secret_configured=upload_secret_configured,
        network_route_configured=network_route_configured,
        governance_configured=deployment is not None,
        active_version=active.version if active is not None else None,
        previous_version=previous.version if previous is not None else None,
        rollout_percent=deployment.rollout_percent if deployment is not None else None,
    )


def _upload_policy_version_response(
    policy: UploadPolicyVersion,
) -> UploadPolicyVersionResponse:
    return UploadPolicyVersionResponse(
        id=policy.id,
        version=policy.version,
        status=policy.status,
        change_note=policy.change_note,
        created_by=policy.created_by,
        approved_by=policy.approved_by,
        approved_at=policy.approved_at,
        created_at=policy.created_at,
    )


def _upload_policy_deployment_response(
    db: Session, deployment: UploadPolicyDeployment
) -> UploadPolicyDeploymentResponse:
    active = db.get(UploadPolicyVersion, deployment.active_policy_id)
    previous = (
        db.get(UploadPolicyVersion, deployment.previous_policy_id)
        if deployment.previous_policy_id is not None
        else None
    )
    if active is None:
        raise HTTPException(status_code=409, detail="Active policy snapshot is missing")
    return UploadPolicyDeploymentResponse(
        active_version=active.version,
        previous_version=previous.version if previous is not None else None,
        rollout_percent=deployment.rollout_percent,
        updated_at=deployment.updated_at,
    )


@router.get(
    "/admin/policies/upload/versions",
    response_model=list[UploadPolicyVersionResponse],
    tags=["admin"],
)
def admin_list_upload_policy_versions(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[UploadPolicyVersionResponse]:
    policies = db.scalars(
        select(UploadPolicyVersion)
        .where(UploadPolicyVersion.tenant_id == principal.tenant_id)
        .order_by(UploadPolicyVersion.created_at.desc())
    ).all()
    return [_upload_policy_version_response(policy) for policy in policies]


@router.post(
    "/admin/policies/upload/versions",
    response_model=UploadPolicyVersionResponse,
    status_code=201,
    tags=["admin"],
)
def admin_register_upload_policy_version(
    payload: UploadPolicyVersionCreate,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> UploadPolicyVersionResponse:
    """Register an immutable snapshot of the current server-owned settings."""

    configured = request.app.state.sub2_policy
    policy = UploadPolicyVersion(
        tenant_id=principal.tenant_id,
        version=payload.version,
        status="draft",
        change_note=payload.change_note.strip(),
        group_id=configured.group_id,
        concurrency=configured.concurrency,
        proxy_ref=configured.proxy_ref,
        credential_ref=configured.credential_ref,
        created_by=principal.user_id,
    )
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Policy version already exists for this tenant"
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload_policy.registered",
        entity_type="upload_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return _upload_policy_version_response(policy)


@router.post(
    "/admin/policies/upload/versions/{policy_id}/approve",
    response_model=UploadPolicyVersionResponse,
    tags=["admin"],
)
def admin_approve_upload_policy_version(
    policy_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> UploadPolicyVersionResponse:
    policy = db.scalar(
        select(UploadPolicyVersion).where(
            UploadPolicyVersion.id == policy_id,
            UploadPolicyVersion.tenant_id == principal.tenant_id,
        ).with_for_update()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    if policy.status != "draft":
        raise HTTPException(status_code=409, detail="Only draft policies can be approved")
    if policy.created_by == principal.user_id:
        raise HTTPException(
            status_code=409, detail="Policy approval requires a different administrator"
        )
    policy.status = "approved"
    policy.approved_by = principal.user_id
    policy.approved_at = _utc_now()
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload_policy.approved",
        entity_type="upload_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return _upload_policy_version_response(policy)


@router.post(
    "/admin/policies/upload/versions/{policy_id}/deploy",
    response_model=UploadPolicyDeploymentResponse,
    tags=["admin"],
)
def admin_deploy_upload_policy_version(
    policy_id: str,
    payload: UploadPolicyDeployRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> UploadPolicyDeploymentResponse:
    policy = db.scalar(
        select(UploadPolicyVersion).where(
            UploadPolicyVersion.id == policy_id,
            UploadPolicyVersion.tenant_id == principal.tenant_id,
        ).with_for_update()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    if policy.status not in {"approved", "active"}:
        raise HTTPException(status_code=409, detail="Policy must be approved before deployment")

    deployment = db.scalar(
        select(UploadPolicyDeployment).where(
            UploadPolicyDeployment.tenant_id == principal.tenant_id
        ).with_for_update()
    )
    if deployment is None:
        if payload.rollout_percent != 100:
            raise HTTPException(
                status_code=409, detail="The first deployment must use 100 percent rollout"
            )
        deployment = UploadPolicyDeployment(
            tenant_id=principal.tenant_id,
            active_policy_id=policy.id,
            previous_policy_id=None,
            rollout_percent=100,
            updated_by=principal.user_id,
        )
        db.add(deployment)
    elif deployment.active_policy_id == policy.id:
        if deployment.previous_policy_id is None and payload.rollout_percent != 100:
            raise HTTPException(
                status_code=409, detail="No previous policy exists for a partial rollout"
            )
        deployment.rollout_percent = payload.rollout_percent
        deployment.updated_by = principal.user_id
        deployment.updated_at = _utc_now()
    else:
        if deployment.rollout_percent < 100:
            raise HTTPException(
                status_code=409,
                detail="Complete or rollback the current rollout before deploying another version",
            )
        current = db.get(UploadPolicyVersion, deployment.active_policy_id)
        deployment.previous_policy_id = deployment.active_policy_id
        deployment.active_policy_id = policy.id
        deployment.rollout_percent = payload.rollout_percent
        deployment.updated_by = principal.user_id
        deployment.updated_at = _utc_now()
        if current is not None:
            current.status = "active" if payload.rollout_percent < 100 else "retired"

    policy.status = "active"
    if payload.rollout_percent == 100 and deployment.previous_policy_id is not None:
        previous = db.get(UploadPolicyVersion, deployment.previous_policy_id)
        if previous is not None and previous.id != policy.id:
            previous.status = "retired"
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload_policy.deployed",
        entity_type="upload_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version, "rollout_percent": payload.rollout_percent},
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Upload policy deployment changed concurrently"
        ) from None
    db.refresh(deployment)
    return _upload_policy_deployment_response(db, deployment)


@router.post(
    "/admin/policies/upload/rollback",
    response_model=UploadPolicyDeploymentResponse,
    tags=["admin"],
)
def admin_rollback_upload_policy(
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> UploadPolicyDeploymentResponse:
    deployment = db.scalar(
        select(UploadPolicyDeployment).where(
            UploadPolicyDeployment.tenant_id == principal.tenant_id
        ).with_for_update()
    )
    if deployment is None or deployment.previous_policy_id is None:
        raise HTTPException(status_code=409, detail="No previous policy is available")
    current = db.get(UploadPolicyVersion, deployment.active_policy_id)
    previous = db.get(UploadPolicyVersion, deployment.previous_policy_id)
    if current is None or previous is None:
        raise HTTPException(status_code=409, detail="Policy rollback snapshot is missing")
    deployment.active_policy_id = previous.id
    deployment.previous_policy_id = current.id
    deployment.rollout_percent = 100
    deployment.updated_by = principal.user_id
    deployment.updated_at = _utc_now()
    current.status = "retired"
    previous.status = "active"
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="upload_policy.rolled_back",
        entity_type="upload_policy",
        entity_id=previous.id,
        trace_id=request.state.trace_id,
        details={"version": previous.version, "replaced_version": current.version},
    )
    db.commit()
    db.refresh(deployment)
    return _upload_policy_deployment_response(db, deployment)
