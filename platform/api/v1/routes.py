"""Version 1 API routes for the Phase 1 platform slice."""

import csv
import base64
import binascii
import hashlib
import asyncio
import io
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import and_, delete, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from platform import __version__
from platform.audit import (
    project_audit_event,
    record_audit,
)
from platform.card_events import record_card_event, safe_card_event_state
from platform.auth import (
    AuthPrincipal,
    INTERACTIVE_ROLES,
    ROLE_OPS_ADMIN,
    ROLE_OPERATOR,
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_AUDITOR,
    ROLE_WORKER_SERVICE,
    create_access_token,
    get_interactive_principal,
    get_logout_principal,
    get_operator_principal,
    require_roles,
    unauthorized,
    verify_password,
)
from platform.cards import CardSecretUnavailable
from platform.config import Settings
from platform.database import get_db
from platform.devices import (
    ActiveDeviceLimitReachedError,
    DeviceNameRetiredError,
    DeviceOwnerNotFoundError,
    register_device,
)
from platform.errors import BusinessHTTPException
from platform.mail_connectors import (
    MailboxAccess,
    MailConnector,
    MailConnectorUnavailable,
    UnconfiguredMailConnector,
    call_mail_connector,
)
from platform.mail_health import (
    CONNECTOR_NOT_CONFIGURED,
    CONNECTOR_UNAVAILABLE,
    mark_mailbox_healthy,
    mark_mailbox_unavailable,
    reset_mailbox_health,
)
from platform.mail_consumption import (
    claim_connector_message,
    claim_delivered_code,
    expire_mail_session_if_due,
    hash_message_id,
)
from platform.lifecycle import (
    ACTIVE_MAIL_SESSION_STATUSES as _ACTIVE_MAIL_SESSION_STATUSES,
    RELEASABLE_MAIL_SESSION_STATUSES as _RELEASABLE_MAIL_SESSION_STATUSES,
    TERMINAL_TASK_STATUSES as _TERMINAL_TASK_STATUSES,
    compensate_terminal_task_resources as _compensate_terminal_task_resources,
    revoke_principal_resources as _revoke_principal_resources,
    transition_task_to_terminal as _transition_task_to_terminal,
)
from platform.models import (
    Card,
    CardAllocation,
    CardAllocationReplacement,
    CardEvent,
    CardRevealChallenge,
    Device,
    Mailbox,
    MailSession,
    OutboxEvent,
    OperationalPolicyDeployment,
    OperationalPolicyVersion,
    PoolImportReceipt,
    AdminRoleChangeRequest,
    RevokedAccessToken,
    RevokedOidcSession,
    Task,
    UploadPolicyDeployment,
    UploadPolicyVersion,
    UploadJob,
    User,
    AuditEvent,
    new_id,
)
from platform.uploads import transition_upload_phase
from platform.schemas import (
    ApiErrorResponse,
    AdminCardCreate,
    AdminCardAllocationResponse,
    AdminCardEventResponse,
    AdminCardQuarantineRequest,
    AdminCardRecycleRequest,
    AdminCardStateUpdate,
    AdminCardTimelineResponse,
    AdminMailboxCreate,
    AdminMailboxSecretRotation,
    AdminMailboxStateUpdate,
    PoolImportReceiptResponse,
    LoginRequest,
    LogoutResponse,
    MailCodeResponse,
    MailboxStatusResponse,
    MailSessionCreateRequest,
    MailSessionCreateResponse,
    MailSessionResponse,
    CardAllocationResponse,
    CardRevealChallengeResponse,
    CardRevealGrantRequest,
    CardRevealGrantResponse,
    CardRevealRequest,
    CardRevealResponse,
    DashboardRecentTaskResponse,
    DashboardSummaryResponse,
    UploadCreate,
    UploadDirectCreate,
    UploadJobResponse,
    UploadPolicyStatusResponse,
    UploadPolicyDeployRequest,
    UploadPolicyDeploymentResponse,
    UploadPolicyVersionCreate,
    UploadPolicyVersionResponse,
    CardPolicyVersionCreate,
    CardPolicyVersionResponse,
    CardSelectionRule,
    MailPolicyVersionCreate,
    MailPolicyVersionResponse,
    OperationalPolicyDeploymentResponse,
    OperationalPolicyDeployRequest,
    OperationalPolicyStatusResponse,
    UploadReconcileRequest,
    AdminAuditResponse,
    AdminCardResponse,
    AdminDeviceCreate,
    AdminDeviceResponse,
    AdminUploadResponse,
    AdminUserBatchDisable,
    AdminUserResponse,
    AdminRoleChangeResponse,
    AdminUserRoleUpdate,
    AuthConfigResponse,
    MeResponse,
    TaskCreate,
    TaskResponse,
    TaskTimelineCardAllocationResponse,
    TaskTimelineEventResponse,
    TaskTimelineMailSessionResponse,
    TaskTimelineResponse,
    TaskTimelineUploadResponse,
    TokenResponse,
)
from platform.policies import select_policy_for_task
from platform.operational_policies import (
    canonical_card_selection_rule,
    parse_card_selection_rule,
    select_card_policy,
    select_mail_policy,
)

router = APIRouter(
    responses={
        "default": {
            "model": ApiErrorResponse,
            "description": "Stable platform error response",
        },
        422: {
            "model": ApiErrorResponse,
            "description": "Request validation failed",
        },
    }
)
_unconfigured_mail_connector = UnconfiguredMailConnector()
_TENANT_DASHBOARD_ROLES = frozenset(
    {ROLE_OPS_ADMIN, ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN}
)
_MAIL_SESSION_TOKEN_HEADER = "X-Mail-Session-Token"
_MAIL_SESSION_TOKEN_ATTEMPTS = 3
_CARD_LEASE_COMPENSATION_LIMIT = 25


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _revoke_access_token(
    db: Session,
    *,
    principal: AuthPrincipal,
    now: datetime,
) -> bool:
    """Claim the first logout for one bearer token without adding resource locks."""

    values = {
        "token_hash": principal.access_token_hash,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "device_id": principal.device_id,
        "expires_at": principal.access_token_expires_at,
        "revoked_at": now,
        "reason": "user_logout",
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgresql_insert(RevokedAccessToken).values(**values)
    elif dialect == "sqlite":
        statement = sqlite_insert(RevokedAccessToken).values(**values)
    else:
        raise RuntimeError("Access-token revocation requires PostgreSQL or SQLite")
    result = db.execute(
        statement.on_conflict_do_nothing(index_elements=["token_hash"])
    )
    if result.rowcount != 1:
        return False
    db.execute(
        delete(RevokedAccessToken).where(
            RevokedAccessToken.expires_at <= now,
            RevokedAccessToken.token_hash != principal.access_token_hash,
        )
    )
    return True


def _revoke_oidc_session(
    db: Session,
    *,
    principal: AuthPrincipal,
    now: datetime,
) -> bool:
    """Claim the first logout for one issuer-scoped OIDC session digest."""

    if principal.oidc_session_hash is None:
        return False
    values = {
        "session_hash": principal.oidc_session_hash,
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "device_id": principal.device_id,
        "revoked_at": now,
        "expires_at": None,
        "reason": "user_logout",
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgresql_insert(RevokedOidcSession).values(**values)
    elif dialect == "sqlite":
        statement = sqlite_insert(RevokedOidcSession).values(**values)
    else:
        raise RuntimeError("OIDC-session revocation requires PostgreSQL or SQLite")
    result = db.execute(
        statement.on_conflict_do_nothing(index_elements=["session_hash"])
    )
    return result.rowcount == 1


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


def _mailbox_observation_is_current(
    db: Session, mailbox: Mailbox, observed_access: MailboxAccess
) -> bool:
    db.expire(mailbox)
    db.refresh(mailbox, with_for_update=True)
    return mailbox.is_active and mailbox.secret_ref == observed_access.secret_ref


def _mail_poll_mode(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return settings.mail_poll_mode.strip().lower()


def _new_mail_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_unique_mail_session_token(
    db: Session,
) -> tuple[str, str]:
    """Generate an opaque token whose hash is not already persisted.

    The database unique constraint is still the concurrency backstop.  This
    bounded pre-check makes deterministic RNG failures fail closed without
    mutating an existing session or returning a colliding capability.
    """

    for _ in range(_MAIL_SESSION_TOKEN_ATTEMPTS):
        token, token_hash = _new_mail_session_token()
        if db.scalar(
            select(MailSession.id)
            .where(MailSession.session_token_hash == token_hash)
            .limit(1)
        ) is None:
            return token, token_hash
    raise BusinessHTTPException(
        status_code=503,
        code="mail_session_token_unavailable",
        message="Mail session capability is temporarily unavailable",
        recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
    )


def _mail_session_token_conflict() -> BusinessHTTPException:
    return BusinessHTTPException(
        status_code=503,
        code="mail_session_token_unavailable",
        message="Mail session capability is temporarily unavailable",
        recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
    )


def _require_mail_session_token(
    token: str | None,
    session: MailSession,
    *,
    db: Session,
    principal: AuthPrincipal,
) -> None:
    valid = False
    if token and len(token) <= 128:
        candidate_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        valid = secrets.compare_digest(candidate_hash, session.session_token_hash)
    if valid:
        return
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        actor_id=principal.user_id,
        event_type="mail_session.capability_denied",
        action="mail_session.access",
        result="failure",
        entity_type="mail_session",
        entity_id=session.id,
        trace_id=session.trace_id,
        details={"reason": "invalid_or_missing_session_token"},
    )
    db.commit()
    raise HTTPException(status_code=404, detail="Mail session not found")


def _lock_user(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
) -> User | None:
    return db.scalar(
        select(User)
        .where(User.id == user_id, User.tenant_id == tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _lock_device(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    device_id: str,
) -> Device | None:
    return db.scalar(
        select(Device)
        .where(
            Device.id == device_id,
            Device.tenant_id == tenant_id,
            Device.user_id == user_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _lock_task_creation_principal(
    db: Session,
    principal: AuthPrincipal,
) -> None:
    """Revalidate the mutable principal immediately before creating a root task."""

    user_claim = db.execute(
        update(User)
        .where(
            User.id == principal.user_id,
            User.tenant_id == principal.tenant_id,
        )
        .values(is_active=User.is_active)
        .execution_options(synchronize_session=False)
    )
    if user_claim.rowcount != 1:
        raise unauthorized()
    user = _lock_user(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
    )
    device = _lock_device(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
    )
    if (
        user is None
        or not user.is_active
        or device is None
        or device.revoked_at is not None
    ):
        raise unauthorized()
    if user.role != ROLE_OPERATOR:
        raise HTTPException(status_code=403, detail="Insufficient role")


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
    if (
        user is None
        or user.password_hash is None
        or not verify_password(payload.password, user.password_hash)
        or user.role not in INTERACTIVE_ROLES
    ):
        record_audit(
            db,
            tenant_id=payload.tenant_id,
            user_id=user.id if user is not None else None,
            device_id=None,
            actor_id="anonymous",
            event_type="auth.login_failed",
            entity_type="user",
            entity_id=user.id if user is not None else None,
            trace_id=request.state.trace_id,
            details={"method": "local_account", "reason": "authentication_failed"},
        )
        db.commit()
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
        record_audit(
            db,
            tenant_id=payload.tenant_id,
            user_id=user.id,
            device_id=None,
            actor_id="anonymous",
            event_type="auth.login_failed",
            entity_type="user",
            entity_id=user.id,
            trace_id=request.state.trace_id,
            details={"method": "local_account", "reason": "authentication_failed"},
        )
        db.commit()
        raise unauthorized()

    locked_user = _lock_user(
        db,
        tenant_id=payload.tenant_id,
        user_id=user.id,
    )
    locked_device = _lock_device(
        db,
        tenant_id=payload.tenant_id,
        user_id=user.id,
        device_id=device.id,
    )
    if (
        locked_user is None
        or not locked_user.is_active
        or locked_user.role not in INTERACTIVE_ROLES
        or locked_device is None
        or locked_device.revoked_at is not None
    ):
        record_audit(
            db,
            tenant_id=payload.tenant_id,
            user_id=user.id,
            device_id=None,
            actor_id="anonymous",
            event_type="auth.login_failed",
            entity_type="user",
            entity_id=user.id,
            trace_id=request.state.trace_id,
            details={"method": "local_account", "reason": "authentication_failed"},
        )
        db.commit()
        raise unauthorized()
    user = locked_user
    device = locked_device

    settings: Settings = request.app.state.settings
    device.last_seen_at = _utc_now()
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


@router.post("/auth/logout", response_model=LogoutResponse, tags=["auth"])
def logout(
    request: Request,
    principal: AuthPrincipal = Depends(get_logout_principal),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    now = _utc_now()
    token_claimed = _revoke_access_token(db, principal=principal, now=now)
    session_claimed = _revoke_oidc_session(db, principal=principal, now=now)
    owns_cleanup = (
        not principal.access_token_revoked
        and not principal.oidc_session_revoked
        and (
            session_claimed
            if principal.oidc_session_hash is not None
            else token_claimed
        )
    )
    if not owns_cleanup:
        # A different token from an already-revoked session may still add its
        # exact digest. Persist that without repeating resource cleanup/audit.
        db.commit()
        return LogoutResponse()
    _revoke_principal_resources(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        now=now,
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
        release_reason="user_logout",
        mail_status="revoked",
        finalize_upload_outbox=True,
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="auth.logout",
        entity_type="user",
        entity_id=principal.user_id,
        trace_id=request.state.trace_id,
        details={"reason": "user_logout"},
    )
    db.commit()
    return LogoutResponse()


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
        admin_role_change_acr=(
            settings.admin_role_change_acr if mode == "oidc" else None
        ),
    )


@router.get("/me", response_model=MeResponse, tags=["auth"])
def me(principal: AuthPrincipal = Depends(get_interactive_principal)) -> MeResponse:
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
    principal: AuthPrincipal = Depends(get_interactive_principal),
    db: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    """Return safe aggregate platform status for the current operator scope."""

    now = _utc_now()
    today_started_at = now.replace(hour=0, minute=0, second=0, microsecond=0)
    scope = "tenant" if principal.role in _TENANT_DASHBOARD_ROLES else "own"
    task_filters: list[Any] = [Task.tenant_id == principal.tenant_id]
    mail_filters: list[Any] = [MailSession.tenant_id == principal.tenant_id]
    card_filters: list[Any] = [CardAllocation.tenant_id == principal.tenant_id]
    upload_filters: list[Any] = [UploadJob.tenant_id == principal.tenant_id]
    if scope == "own":
        task_filters.extend(
            [Task.user_id == principal.user_id, Task.device_id == principal.device_id]
        )
        mail_filters.extend(
            [
                MailSession.user_id == principal.user_id,
                MailSession.device_id == principal.device_id,
            ]
        )
        card_filters.extend(
            [
                CardAllocation.user_id == principal.user_id,
                CardAllocation.device_id == principal.device_id,
            ]
        )
        upload_filters.extend(
            [
                UploadJob.user_id == principal.user_id,
                UploadJob.device_id == principal.device_id,
            ]
        )

    today_tasks = db.scalar(
        select(func.count())
        .select_from(Task)
        .where(*task_filters, Task.created_at >= today_started_at)
    )
    today_upload_statuses = _status_counts(
        db, UploadJob, [*upload_filters, UploadJob.created_at >= today_started_at]
    )
    today_succeeded_uploads = today_upload_statuses.get("succeeded", 0)
    today_completed_uploads = today_succeeded_uploads + today_upload_statuses.get(
        "failed", 0
    )

    available_cards: int | None = None
    if scope == "tenant":
        available_cards = int(
            db.scalar(
                select(func.count())
                .select_from(Card)
                .where(
                    Card.tenant_id == principal.tenant_id,
                    Card.is_active.is_(True),
                    Card.quarantined_at.is_(None),
                    ~exists().where(
                        CardAllocation.tenant_id == principal.tenant_id,
                        CardAllocation.card_id == Card.id,
                        CardAllocation.released_at.is_(None),
                    ),
                )
            )
            or 0
        )

    unavailable_mailboxes_query = (
        select(func.count())
        .select_from(Mailbox)
        .where(
            Mailbox.tenant_id == principal.tenant_id,
            Mailbox.is_active.is_(True),
            Mailbox.health_status == "unavailable",
        )
    )
    if scope == "own":
        unavailable_mailboxes_query = (
            select(func.count(func.distinct(Mailbox.id)))
            .select_from(Mailbox)
            .join(MailSession, MailSession.mailbox_id == Mailbox.id)
            .where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.is_active.is_(True),
                Mailbox.health_status == "unavailable",
                *mail_filters,
                MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
                MailSession.expires_at > now,
            )
        )
    unavailable_mailboxes = int(db.scalar(unavailable_mailboxes_query) or 0)

    recent_task_rows = list(
        db.scalars(
            select(Task)
            .where(*task_filters)
            .order_by(Task.created_at.desc(), Task.id.desc())
            .limit(5)
        )
    )

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
        today_started_at=today_started_at,
        today_tasks=int(today_tasks or 0),
        pending_exceptions=int(unknown_uploads or 0) + unavailable_mailboxes,
        available_cards=available_cards,
        today_succeeded_uploads=today_succeeded_uploads,
        today_completed_uploads=today_completed_uploads,
        unavailable_mailboxes=unavailable_mailboxes,
        recent_tasks=[
            DashboardRecentTaskResponse(
                id=task.id,
                type=task.task_type,
                status=task.status,
                trace_id=task.trace_id,
                created_at=task.created_at,
                expires_at=task.expires_at,
            )
            for task in recent_task_rows
        ],
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
        task_type=mailbox.task_type,
        is_active=mailbox.is_active,
        status=status,
        health_status=mailbox.health_status,
        last_checked_at=mailbox.last_checked_at,
        last_error_code=mailbox.last_error_code,
        active_session_count=active_session_count,
        created_at=mailbox.created_at,
    )


@router.get(
    "/mailboxes",
    response_model=list[MailboxStatusResponse],
    tags=["mail"],
)
def list_mailboxes(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
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
    principal: AuthPrincipal = Depends(get_interactive_principal),
    db: Session = Depends(get_db),
) -> AdminDeviceResponse:
    owner = _lock_user(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
    )
    device = _lock_device(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=device_id,
    )
    if owner is None or device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.revoked_at is None:
        now = _utc_now()
        device.revoked_at = now
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
    # Commit the irreversible principal-state barrier before taking the
    # UploadJob -> Task resource locks used by workers and lifecycle cleanup.
    db.commit()
    _revoke_principal_resources(
        db,
        tenant_id=device.tenant_id,
        user_id=device.user_id,
        device_id=device.id,
        now=_utc_now(),
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
        release_reason="owner_device_revoked",
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
            Task.device_id == principal.device_id,
            Task.idempotency_key == idempotency_key,
        )
    )


def _task_scope_filters(principal: AuthPrincipal) -> tuple[Any, ...]:
    filters: tuple[Any, ...] = (Task.tenant_id == principal.tenant_id,)
    if principal.role == ROLE_OPS_ADMIN:
        return filters
    return filters + (
        Task.user_id == principal.user_id,
        Task.device_id == principal.device_id,
    )


def _workbench_step(
    *,
    task_status: str = "created",
    has_card_allocation: bool = False,
    mail_status: str | None = None,
    upload_status: str | None = None,
) -> Literal[
    "logged_in",
    "card_allocated",
    "waiting_code",
    "code_received",
    "uploading",
    "completed",
]:
    """Project trusted resource state onto the six operator workbench stages."""

    if task_status == "completed" or upload_status == "succeeded":
        return "completed"
    if upload_status is not None:
        return "uploading"
    if mail_status == "consumed":
        return "code_received"
    if mail_status is not None:
        return "waiting_code"
    if has_card_allocation:
        return "card_allocated"
    return "logged_in"


def _same_task_payload(task: Task, payload: TaskCreate) -> bool:
    return (
        task.task_type == payload.type
        and task.client_reference == payload.client_reference
    )


def _expire_task_if_needed(
    task: Task,
    db: Session,
    *,
    request: Request,
    principal: AuthPrincipal,
    skip_locked: bool = False,
) -> bool:
    if task.status in _TERMINAL_TASK_STATUSES or task.expires_at is None:
        return False
    now = _utc_now()
    if not _is_expired(task.expires_at, now):
        return False
    result = _transition_task_to_terminal(
        task,
        db,
        now=now,
        task_status="expired",
        card_status="expired",
        mail_status="expired",
        release_reason="task_ttl_expired",
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
        skip_locked=skip_locked,
    )
    return result.tasks_expired == 1


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
        raise BusinessHTTPException(
            status_code=409,
            code="conflict",
            message="Task is closed or expired",
            recovery_hint="刷新当前状态后按页面提示继续",
        )


def _lock_owned_open_task(
    db: Session,
    task_id: str,
    *,
    request: Request,
    principal: AuthPrincipal,
) -> Task:
    task = db.scalar(
        select(Task)
        .where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    _assert_task_open(task, db, request=request, principal=principal)
    return task


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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> Task:
    _lock_task_creation_principal(db, principal)
    existing = _find_idempotent_task(db, principal, payload.idempotency_key)
    if existing is not None:
        if not _same_task_payload(existing, payload):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key was already used with different task data",
            )
        response.status_code = 200
        return existing

    now = _utc_now()
    active_task_id = db.scalar(
        select(Task.id)
        .where(
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            ~Task.status.in_(_TERMINAL_TASK_STATUSES),
            or_(Task.expires_at.is_(None), Task.expires_at > now),
        )
        .limit(1)
    )
    if active_task_id is not None:
        raise BusinessHTTPException(
            status_code=409,
            code="active_task_exists",
            message="Another task is already active for this user",
            recovery_hint="请先完成或关闭当前任务，再创建新任务",
        )

    task = Task(
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        task_type=payload.type,
        idempotency_key=payload.idempotency_key,
        client_reference=payload.client_reference,
        trace_id=request.state.trace_id,
        expires_at=now + timedelta(seconds=request.app.state.settings.task_ttl_seconds),
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
    status: str | None = Query(default=None, min_length=1, max_length=32),
    user_id: str | None = Query(default=None, min_length=1, max_length=36),
    trace_id: str | None = Query(default=None, min_length=1, max_length=36),
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPERATOR, ROLE_OPS_ADMIN)),
    db: Session = Depends(get_db),
) -> list[Task]:
    filters = list(_task_scope_filters(principal))
    if status is not None:
        filters.append(Task.status == status)
    if user_id is not None:
        filters.append(Task.user_id == user_id)
    if trace_id is not None:
        filters.append(Task.trace_id == trace_id)
    tasks = list(
        db.scalars(
            select(Task)
            .where(*filters)
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
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPERATOR, ROLE_OPS_ADMIN)),
    db: Session = Depends(get_db),
) -> Task:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            *_task_scope_filters(principal),
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if _expire_task_if_needed(task, db, request=request, principal=principal):
        db.commit()
        db.refresh(task)
    return task


@router.get(
    "/tasks/{task_id}/timeline",
    response_model=TaskTimelineResponse,
    tags=["tasks"],
)
def get_task_timeline(
    task_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPERATOR, ROLE_OPS_ADMIN)),
    db: Session = Depends(get_db),
) -> TaskTimelineResponse:
    task = db.scalar(
        select(Task).where(
            Task.id == task_id,
            *_task_scope_filters(principal),
        )
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if _expire_task_if_needed(task, db, request=request, principal=principal):
        db.commit()
        db.refresh(task)

    mail_row = db.execute(
        select(MailSession, Mailbox.email_masked)
        .join(Mailbox, Mailbox.id == MailSession.mailbox_id)
        .where(
            MailSession.task_id == task.id,
            MailSession.tenant_id == task.tenant_id,
            MailSession.user_id == task.user_id,
            MailSession.device_id == task.device_id,
        )
    ).first()
    mail_session = None
    if mail_row is not None:
        session, email_masked = mail_row
        mail_session = TaskTimelineMailSessionResponse(
            id=session.id,
            email_masked=email_masked,
            status=session.status,
            expires_at=session.expires_at,
            consumed_at=session.consumed_at,
            created_at=session.created_at,
        )

    allocation_rows = db.execute(
        select(CardAllocation, Card)
        .join(Card, Card.id == CardAllocation.card_id)
        .where(
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == task.tenant_id,
            CardAllocation.user_id == task.user_id,
            CardAllocation.device_id == task.device_id,
        )
        .order_by(CardAllocation.created_at, CardAllocation.id)
    ).all()
    allocations = [
        TaskTimelineCardAllocationResponse(
            id=allocation.id,
            card_masked=f"**** **** **** {card.last4}",
            brand=card.brand,
            status=allocation.status,
            expires_at=allocation.expires_at,
            released_at=allocation.released_at,
            created_at=allocation.created_at,
        )
        for allocation, card in allocation_rows
    ]

    upload_rows = list(
        db.scalars(
            select(UploadJob)
            .where(
                UploadJob.task_id == task.id,
                UploadJob.tenant_id == task.tenant_id,
                UploadJob.user_id == task.user_id,
                UploadJob.device_id == task.device_id,
            )
            .order_by(UploadJob.created_at, UploadJob.id)
        )
    )
    uploads = [
        TaskTimelineUploadResponse(
            id=upload.id,
            business_name=upload.business_name,
            status=upload.status,
            trace_id=upload.trace_id,
            phase=upload.phase,
            phase_sequence=upload.phase_sequence,
            phase_updated_at=upload.phase_updated_at,
            policy_version=upload.policy_version,
            external_ref=upload.external_ref,
            error_code=upload.error_code,
            created_at=upload.created_at,
            updated_at=upload.updated_at,
        )
        for upload in upload_rows
    ]

    timeline_entity_ids = [
        task.id,
        *([mail_session.id] if mail_session is not None else []),
        *(allocation.id for allocation in allocations),
        *(upload.id for upload in uploads),
    ]
    audit_rows = list(
        db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.tenant_id == task.tenant_id,
                AuditEvent.user_id == task.user_id,
                AuditEvent.device_id == task.device_id,
                AuditEvent.trace_id == task.trace_id,
                AuditEvent.entity_id.in_(timeline_entity_ids),
            )
            .order_by(AuditEvent.created_at, AuditEvent.id)
            .limit(500)
        )
    )
    events: list[TaskTimelineEventResponse] = []
    for event in audit_rows:
        projected = project_audit_event(event)
        details = projected["details"]
        phase = details.get("phase")
        phase_sequence = details.get("phase_sequence")
        events.append(
            TaskTimelineEventResponse(
                id=projected["id"],
                event_type=projected["event_type"],
                action=projected["action"],
                result=projected["result"],
                entity_type=projected["entity_type"],
                entity_id=projected["entity_id"],
                trace_id=projected["trace_id"],
                policy_version=projected["policy_version"],
                phase=phase if isinstance(phase, str) else None,
                phase_sequence=(
                    phase_sequence if isinstance(phase_sequence, int) else None
                ),
                created_at=event.created_at,
            )
        )
    return TaskTimelineResponse(
        task=TaskResponse.model_validate(task),
        workbench_step=_workbench_step(
            task_status=task.status,
            has_card_allocation=bool(allocations),
            mail_status=mail_session.status if mail_session is not None else None,
            upload_status=uploads[-1].status if uploads else None,
        ),
        mail_session=mail_session,
        card_allocations=allocations,
        uploads=uploads,
        events=events,
    )


@router.post("/tasks/{task_id}/close", response_model=TaskResponse, tags=["tasks"])
def close_task(
    task_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPERATOR, ROLE_OPS_ADMIN)),
    db: Session = Depends(get_db),
) -> Task:
    task = db.scalar(
        select(Task)
        .where(
            Task.id == task_id,
            *_task_scope_filters(principal),
        )
        .with_for_update()
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if _expire_task_if_needed(
        task,
        db,
        request=request,
        principal=principal,
        skip_locked=True,
    ):
        db.commit()
        _compensate_terminal_task_resources(
            db,
            task.id,
            now=_utc_now(),
            card_status="expired",
            mail_status="expired",
            release_reason="task_ttl_expired",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            upload_error_code="task_expired",
        )
        db.commit()
        db.refresh(task)
        return task
    if task.status not in _TERMINAL_TASK_STATUSES:
        unknown_upload_id = db.scalar(
            select(UploadJob.id)
            .where(
                UploadJob.task_id == task.id,
                UploadJob.tenant_id == task.tenant_id,
                UploadJob.status == "unknown",
            )
            .with_for_update()
        )
        if unknown_upload_id is not None:
            raise BusinessHTTPException(
                status_code=409,
                code="upload_result_unknown",
                message="Upload result must be reconciled before closing the task",
                recovery_hint="请联系管理员先核对未知上传结果，再关闭任务",
            )
        now = _utc_now()
        _transition_task_to_terminal(
            task,
            db,
            now=now,
            task_status="closed",
            card_status="released",
            mail_status="revoked",
            release_reason="task_closed",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            finalize_upload_outbox=True,
            skip_locked=True,
        )
        db.commit()
        _compensate_terminal_task_resources(
            db,
            task.id,
            now=_utc_now(),
            card_status="released",
            mail_status="revoked",
            release_reason="task_closed",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            running_upload_status="cancel_pending",
            upload_error_code=None,
        )
        db.commit()
        db.refresh(task)
    else:
        # A replay can arrive after the terminal Task commit but before the
        # original request's resource phase.  Release the Task lock, then use
        # the same durable terminal marker to finish that phase synchronously.
        terminal_status = task.status
        db.commit()
        expired = terminal_status == "expired"
        _compensate_terminal_task_resources(
            db,
            task.id,
            now=_utc_now(),
            card_status="expired" if expired else "released",
            mail_status="expired" if expired else "revoked",
            release_reason="terminal_task_recovery",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
        )
        db.commit()
        db.refresh(task)
    return task


@router.post(
    "/tasks/{task_id}/mail-sessions",
    response_model=MailSessionCreateResponse,
    status_code=201,
    responses={
        200: {
            "model": MailSessionCreateResponse,
            "description": "Existing session with a rotated token",
        }
    },
    tags=["mail"],
)
@router.post(
    "/tasks/{task_id}/mail-session",
    response_model=MailSessionCreateResponse,
    status_code=201,
    responses={
        200: {
            "model": MailSessionCreateResponse,
            "description": "Existing session with a rotated token",
        }
    },
    tags=["mail"],
)
def create_mail_session(
    task_id: str,
    request: Request,
    response: Response,
    _payload: MailSessionCreateRequest | None = Body(default=None),
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> MailSessionCreateResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
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

    def rotate_existing(existing: MailSession) -> MailSessionCreateResponse:
        if (
            existing.user_id != principal.user_id
            or existing.device_id != principal.device_id
        ):
            raise HTTPException(status_code=404, detail="Mail session not found")
        mailbox = db.get(Mailbox, existing.mailbox_id)
        if mailbox is None:
            raise HTTPException(status_code=503, detail="Assigned mailbox is unavailable")
        if (
            _is_expired(existing.expires_at, _utc_now())
            and existing.status in _ACTIVE_MAIL_SESSION_STATUSES
        ):
            expired_now = expire_mail_session_if_due(
                db,
                session_id=existing.id,
                now=_utc_now(),
            )
            if expired_now:
                record_audit(
                    db,
                    tenant_id=principal.tenant_id,
                    user_id=principal.user_id,
                    device_id=principal.device_id,
                    event_type="mail_session.expired",
                    entity_type="mail_session",
                    entity_id=existing.id,
                    trace_id=existing.trace_id,
                    details={
                        "status": "expired",
                        "reason": "mail_session_ttl_expired",
                    },
                )
            db.expire(existing)
            db.refresh(existing)
        session_token, existing.session_token_hash = _new_unique_mail_session_token(db)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise _mail_session_token_conflict() from None
        response.status_code = 200
        return MailSessionCreateResponse(
            id=existing.id,
            trace_id=existing.trace_id,
            email_masked=mailbox.email_masked,
            status=existing.status,
            expires_at=existing.expires_at,
            session_token=session_token,
            polling_interval=existing.poll_interval_seconds,
        )

    existing_id = db.scalar(
        select(MailSession.id).where(MailSession.task_id == task.id)
    )
    if existing_id is not None:
        task = _lock_owned_open_task(
            db, task_id, request=request, principal=principal
        )
        existing = db.scalar(
            select(MailSession)
            .where(MailSession.task_id == task.id)
            .with_for_update()
        )
        if existing is not None:
            return rotate_existing(existing)

    now = _utc_now()
    poll_mode = _mail_poll_mode(request)
    task_locked = False
    if poll_mode != "api":
        task = _lock_owned_open_task(
            db, task_id, request=request, principal=principal
        )
        task_locked = True
    # Expired leases do not make a mailbox busy.  Their state is normalized
    # only after the task lock is held, so API mode performs no database write
    # while waiting on the external connector.
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
            Mailbox.task_type == task.task_type,
            Mailbox.is_active.is_(True),
            ~busy_mailbox,
        )
        .order_by(Mailbox.created_at, Mailbox.id)
        .with_for_update(skip_locked=True)
    )
    if mailbox is None:
        raise HTTPException(status_code=503, detail="No active mailbox is available")

    settings: Settings = request.app.state.settings
    start_watermark = None
    status = "initializing"
    if poll_mode == "api":
        connector = _mail_connector(request, mailbox.connector_type)
        mailbox_access = _mailbox_access(mailbox)
        try:
            start_watermark = call_mail_connector(
                lambda: connector.watermark_at(mailbox_access, task.created_at)
            )
            if not isinstance(start_watermark, str) or not start_watermark.strip():
                raise MailConnectorUnavailable("Mail API cursor is unavailable")
        except MailConnectorUnavailable:
            error_code = (
                CONNECTOR_UNAVAILABLE
                if mailbox.connector_type in request.app.state.mail_connectors
                else CONNECTOR_NOT_CONFIGURED
            )
            mark_mailbox_unavailable(
                mailbox,
                checked_at=now,
                error_code=error_code,
                db=db,
                user_id=principal.user_id,
                device_id=principal.device_id,
                actor_id=principal.user_id,
                trace_id=task.trace_id,
            )
            db.commit()
            detail = (
                "Mail connector is temporarily unavailable"
                if error_code == CONNECTOR_UNAVAILABLE
                else "Mail connector is not configured"
            )
            raise BusinessHTTPException(
                status_code=503,
                code="service_unavailable",
                message=detail,
                recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
            ) from None
        status = "waiting"
    if not task_locked:
        task = _lock_owned_open_task(
            db, task_id, request=request, principal=principal
        )
    existing = db.scalar(
        select(MailSession)
        .where(MailSession.task_id == task.id)
        .with_for_update()
    )
    if existing is not None:
        return rotate_existing(existing)
    now = _utc_now()
    db.query(MailSession).filter(
        MailSession.tenant_id == principal.tenant_id,
        MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
        MailSession.expires_at <= now,
    ).update(
        {
            "status": "expired",
            "delivered_code": None,
            "delivered_message_id_hash": None,
            "delivered_at": None,
            "code_expires_at": None,
            "start_watermark": None,
            "last_message_hash": None,
        },
        synchronize_session=False,
    )
    if poll_mode == "api":
        mark_mailbox_healthy(
            mailbox,
            checked_at=now,
            db=db,
            user_id=principal.user_id,
            device_id=principal.device_id,
            actor_id=principal.user_id,
            trace_id=task.trace_id,
        )
    session_token, session_token_hash = _new_unique_mail_session_token(db)
    mail_policy = select_mail_policy(
        db,
        tenant_id=principal.tenant_id,
        task_id=task.id,
        settings=settings,
    )
    session = MailSession(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        mailbox_id=mailbox.id,
        trace_id=task.trace_id,
        session_token_hash=session_token_hash,
        status=status,
        policy_version=mail_policy.version,
        code_ttl_seconds=mail_policy.code_ttl_seconds,
        poll_interval_seconds=mail_policy.poll_interval_seconds,
        expires_at=now + timedelta(seconds=mail_policy.session_ttl_seconds),
        start_watermark=start_watermark,
    )
    db.add(session)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        if db.scalar(
            select(MailSession.id)
            .where(MailSession.session_token_hash == session_token_hash)
            .limit(1)
        ) is not None:
            raise _mail_session_token_conflict() from None
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
            "policy_version": session.policy_version,
            "session_ttl_seconds": mail_policy.session_ttl_seconds,
            "code_ttl_seconds": session.code_ttl_seconds,
            "poll_interval_seconds": session.poll_interval_seconds,
        },
    )
    db.commit()
    return MailSessionCreateResponse(
        id=session.id,
        trace_id=session.trace_id,
        email_masked=mailbox.email_masked,
        status=session.status,
        expires_at=session.expires_at,
        session_token=session_token,
        polling_interval=session.poll_interval_seconds,
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
    response: Response,
    mail_session_token: str | None = Header(
        default=None,
        alias=_MAIL_SESSION_TOKEN_HEADER,
        description="Opaque capability returned when the mail session is created or rotated",
    ),
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> MailCodeResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
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
    _require_mail_session_token(
        mail_session_token, session, db=db, principal=principal
    )

    now = _utc_now()
    if session.status == "revoked":
        return MailCodeResponse(status="revoked")
    if (
        session.status in _ACTIVE_MAIL_SESSION_STATUSES
        and _is_expired(session.expires_at, now)
    ):
        expired_now = expire_mail_session_if_due(
            db,
            session_id=session.id,
            now=now,
        )
        if expired_now:
            record_audit(
                db,
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
                device_id=principal.device_id,
                event_type="mail_session.expired",
                entity_type="mail_session",
                entity_id=session.id,
                trace_id=session.trace_id,
                details={
                    "status": "expired",
                    "reason": "mail_session_ttl_expired",
                },
            )
        db.expire(session)
        db.refresh(session)
    if session.status == "revoked":
        return MailCodeResponse(status="revoked")
    if session.status == "expired":
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
        expired_code = db.execute(
            update(MailSession)
            .where(
                MailSession.id == session.id,
                MailSession.status == "code_ready",
                MailSession.delivered_code == session.delivered_code,
                MailSession.code_expires_at == session.code_expires_at,
                MailSession.code_expires_at <= now,
                MailSession.expires_at > now,
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
        if expired_code.rowcount == 1:
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
        db.expire(session)
        db.refresh(session)

    if session.status == "code_ready" and session.delivered_code is not None:
        delivered_code = session.delivered_code
        delivered_at = session.delivered_at
        delivered_message_id_hash = session.delivered_message_id_hash
        if delivered_at is None or delivered_message_id_hash is None:
            return MailCodeResponse(status="waiting")
        if not claim_delivered_code(
            db,
            session_id=session.id,
            expected_code=delivered_code,
            expected_message_id_hash=delivered_message_id_hash,
            now=now,
        ):
            db.commit()
            return MailCodeResponse(status="consumed")
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
        return MailCodeResponse(
            status="consumed",
            code=delivered_code,
            received_at=_as_utc(delivered_at),
            message_id_hash=delivered_message_id_hash,
        )

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
    mailbox_access = _mailbox_access(mailbox)
    task = db.get(Task, session.task_id)
    if task is None:
        raise HTTPException(status_code=503, detail="Assigned task is unavailable")
    try:
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
        error_code = (
            CONNECTOR_UNAVAILABLE
            if mailbox.connector_type in request.app.state.mail_connectors
            else CONNECTOR_NOT_CONFIGURED
        )
        if _mailbox_observation_is_current(db, mailbox, mailbox_access):
            mark_mailbox_unavailable(
                mailbox,
                checked_at=_utc_now(),
                error_code=error_code,
                db=db,
                user_id=principal.user_id,
                device_id=principal.device_id,
                actor_id=principal.user_id,
                trace_id=session.trace_id,
            )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.code_checked",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"status": error_code},
        )
        db.commit()
        detail = (
            "Mail connector is temporarily unavailable"
            if error_code == CONNECTOR_UNAVAILABLE
            else "Mail connector is not configured"
        )
        raise BusinessHTTPException(
            status_code=503,
            code="service_unavailable",
            message=detail,
            recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
        ) from None

    transition_now = _utc_now()
    if _mailbox_observation_is_current(db, mailbox, mailbox_access):
        mark_mailbox_healthy(
            mailbox,
            checked_at=transition_now,
            db=db,
            user_id=principal.user_id,
            device_id=principal.device_id,
            actor_id=principal.user_id,
            trace_id=session.trace_id,
        )
    expired_after_lookup = expire_mail_session_if_due(
        db,
        session_id=session.id,
        now=transition_now,
    )
    if expired_after_lookup:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="mail_session.expired",
            entity_type="mail_session",
            entity_id=session.id,
            trace_id=session.trace_id,
            details={"reason": "mail_session_ttl_expired"},
        )
    db.expire(session)
    db.refresh(session)
    if session.status in {"consumed", "revoked", "expired"}:
        db.commit()
        return MailCodeResponse(status=session.status)

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

    if not claim_connector_message(
        db,
        session_id=session.id,
        message_hash=message_hash,
        now=transition_now,
    ):
        db.expire(session)
        db.refresh(session)
        db.commit()
        return MailCodeResponse(status=session.status)
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
    return MailCodeResponse(
        status="consumed",
        code=message.code,
        received_at=_as_utc(message.received_at),
        message_id_hash=hash_message_id(message.message_id),
    )


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
    mail_session_token: str | None = Header(
        default=None,
        alias=_MAIL_SESSION_TOKEN_HEADER,
        description="Opaque capability returned when the mail session is created or rotated",
    ),
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> MailSessionResponse:
    session_snapshot = db.scalar(
        select(MailSession).where(
            MailSession.id == session_id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
        )
    )
    if session_snapshot is None:
        raise HTTPException(status_code=404, detail="Mail session not found")
    _require_mail_session_token(
        mail_session_token,
        session_snapshot,
        db=db,
        principal=principal,
    )

    def refresh_after_lost_claim() -> MailSessionResponse:
        db.rollback()
        db.expire_all()
        current = db.scalar(
            select(MailSession).where(
                MailSession.id == session_id,
                MailSession.tenant_id == principal.tenant_id,
                MailSession.user_id == principal.user_id,
                MailSession.device_id == principal.device_id,
            )
        )
        if current is None:
            raise HTTPException(status_code=404, detail="Mail session not found")
        _require_mail_session_token(
            mail_session_token, current, db=db, principal=principal
        )
        current_mailbox = db.get(Mailbox, current.mailbox_id)
        if current_mailbox is None:
            raise HTTPException(
                status_code=503, detail="Assigned mailbox is unavailable"
            )
        if current.status not in _ACTIVE_MAIL_SESSION_STATUSES:
            return MailSessionResponse(
                id=current.id,
                trace_id=current.trace_id,
                email_masked=current_mailbox.email_masked,
                status=current.status,
                expires_at=current.expires_at,
            )
        raise BusinessHTTPException(
            status_code=409,
            code="mail_session_revoke_unavailable",
            message="Mail session can no longer be revoked",
            recovery_hint="刷新当前任务和邮箱会话状态后再试",
        )

    task_barrier = db.execute(
        update(Task)
        .where(
            Task.id == session_snapshot.task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .values(status=Task.status)
        .execution_options(synchronize_session=False)
    )
    if task_barrier.rowcount != 1:
        return refresh_after_lost_claim()
    task = db.scalar(
        select(Task)
        .where(
            Task.id == session_snapshot.task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .execution_options(populate_existing=True)
    )
    now = _utc_now()
    if (
        task is None
        or task.status in _TERMINAL_TASK_STATUSES
        or task.expires_at is None
        or _is_expired(task.expires_at, now)
    ):
        return refresh_after_lost_claim()

    session = db.scalar(
        select(MailSession)
        .where(
            MailSession.id == session_id,
            MailSession.task_id == task.id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if session is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Mail session not found")
    _require_mail_session_token(
        mail_session_token, session, db=db, principal=principal
    )
    mailbox = db.get(Mailbox, session.mailbox_id)
    if mailbox is None:
        db.rollback()
        raise HTTPException(status_code=503, detail="Assigned mailbox is unavailable")
    revoked = db.execute(
        update(MailSession)
        .where(
            MailSession.id == session.id,
            MailSession.task_id == task.id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
            MailSession.session_token_hash == session.session_token_hash,
            MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            MailSession.expires_at > now,
        )
        .values(
            status="revoked",
            delivered_code=None,
            delivered_message_id_hash=None,
            delivered_at=None,
            code_expires_at=None,
            start_watermark=None,
            last_message_hash=None,
        )
        .execution_options(synchronize_session=False)
    )
    if revoked.rowcount != 1:
        return refresh_after_lost_claim()
    db.expire(session)
    db.refresh(session)
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
def mail_session_events(
    session_id: str,
    request: Request,
    mail_session_token: str | None = Header(
        default=None,
        alias=_MAIL_SESSION_TOKEN_HEADER,
        description="Opaque capability returned when the mail session is created or rotated",
    ),
    principal: AuthPrincipal = Depends(get_operator_principal),
) -> StreamingResponse:
    with request.app.state.session_factory() as db:
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
        _require_mail_session_token(
            mail_session_token, session, db=db, principal=principal
        )
        deadline = session.expires_at
    poll_seconds = min(5, max(1, session.poll_interval_seconds))

    def poll_once() -> MailCodeResponse:
        with request.app.state.session_factory() as stream_db:
            return get_mail_code(
                session_id,
                request,
                Response(),
                mail_session_token,
                principal,
                stream_db,
            )

    async def stream():
        while True:
            if await request.is_disconnected():
                return
            try:
                result = await run_in_threadpool(poll_once)
            except HTTPException as exc:
                event = {
                    "status": "error",
                    "code": None,
                    "error_code": str(exc.status_code),
                }
                yield f"event: error\ndata: {json.dumps(event)}\n\n"
                return
            event_name = result.status
            event = result.model_dump(mode="json")
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
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
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
        allocation_reason_code=allocation.allocation_reason_code,
        expires_at=allocation.expires_at,
    )


def _card_selection_rule(card_policy: Any, task_type: str) -> CardSelectionRule:
    rule = card_policy.rule_for(task_type)
    if rule is None:
        raise HTTPException(
            status_code=503,
            detail="No card selection rule is configured for this task type",
        )
    return rule


def _card_selection_filters(
    rule: CardSelectionRule, *, now: datetime
) -> list[Any]:
    filters: list[Any] = [
        Card.pool_key == rule.pool_key,
        Card.region == rule.region,
    ]
    if rule.brands:
        filters.append(func.upper(Card.brand).in_(tuple(rule.brands)))

    threshold = now + timedelta(days=rule.minimum_validity_days)
    valid_expiry = or_(
        Card.expiry_year > threshold.year,
        and_(
            Card.expiry_year == threshold.year,
            Card.expiry_month >= threshold.month,
        ),
    )
    if rule.minimum_validity_days == 0:
        filters.append(
            or_(
                and_(Card.expiry_year.is_(None), Card.expiry_month.is_(None)),
                valid_expiry,
            )
        )
    else:
        filters.append(valid_expiry)
    return filters


def _card_selection_order(rule: CardSelectionRule) -> tuple[Any, ...]:
    if rule.allocation_order == "expiry_soonest":
        return (
            Card.expiry_year.is_(None),
            Card.expiry_year,
            Card.expiry_month,
            Card.created_at,
            Card.id,
        )
    return (Card.created_at, Card.id)


def _owned_card_allocation(
    db: Session,
    allocation_id: str,
    principal: AuthPrincipal,
    *,
    task_id: str | None = None,
) -> tuple[CardAllocation, Card] | None:
    ownership = [
            CardAllocation.id == allocation_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
    ]
    if task_id is not None:
        ownership.append(CardAllocation.task_id == task_id)
    allocation = db.scalar(select(CardAllocation).where(*ownership))
    if allocation is None:
        return None
    card = db.get(Card, allocation.card_id)
    return (allocation, card) if card is not None else None


def _card_reveal_unavailable() -> BusinessHTTPException:
    return BusinessHTTPException(
        status_code=409,
        code="card_reveal_unavailable",
        message="Card reveal is no longer available",
        recovery_hint="刷新当前任务并重新领取有效卡后再试",
    )


def _record_card_reveal_step_up_failure(
    db: Session,
    *,
    principal: AuthPrincipal,
    allocation: CardAllocation,
    reason: str,
) -> None:
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        actor_id=principal.user_id,
        event_type="card.reveal_step_up_failed",
        action="card.reveal_step_up",
        result="failure",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"reason": reason},
    )
    db.commit()


def _record_card_reveal_failure(
    db: Session,
    *,
    principal: AuthPrincipal,
    allocation: CardAllocation,
) -> None:
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        actor_id=principal.user_id,
        event_type="card.reveal_failed",
        action="card.reveal",
        result="failure",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"reason": "invalid_or_expired_grant"},
    )
    db.commit()


def _assert_revealable(allocation: CardAllocation, now: datetime) -> None:
    if (
        allocation.status != "active"
        or allocation.released_at is not None
        or _is_expired(allocation.expires_at, now)
    ):
        raise _card_reveal_unavailable()
    if allocation.revealed_at is not None:
        raise _card_reveal_unavailable()


def _owned_card_reveal_context(
    db: Session, allocation_id: str, principal: AuthPrincipal
) -> tuple[Task, CardAllocation, Card, datetime] | None:
    """Lock and validate reveal authority in Task -> allocation order."""

    task_id = db.scalar(
        select(CardAllocation.task_id).where(
            CardAllocation.id == allocation_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
    )
    if task_id is None:
        return None

    task = db.scalar(
        select(Task)
        .where(
            Task.id == task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .with_for_update()
    )
    if task is None:
        return None

    allocation = db.scalar(
        select(CardAllocation)
        .where(
            CardAllocation.id == allocation_id,
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
        .with_for_update()
    )
    if allocation is None:
        return None

    now = _utc_now()
    if (
        task.status in _TERMINAL_TASK_STATUSES
        or task.expires_at is None
        or _is_expired(task.expires_at, now)
    ):
        raise _card_reveal_unavailable()
    _assert_revealable(allocation, now)

    card = db.scalar(
        select(Card).where(
            Card.id == allocation.card_id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
        )
    )
    if card is None:
        raise _card_reveal_unavailable()
    return task, allocation, card, now


def _compensate_expired_card_leases(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
) -> None:
    """Close tasks whose expired card lease can be locked without waiting."""

    task_ids = tuple(
        db.scalars(
            select(CardAllocation.task_id)
            .where(
                CardAllocation.tenant_id == tenant_id,
                CardAllocation.released_at.is_(None),
                CardAllocation.expires_at <= now,
            )
            .distinct()
            .order_by(CardAllocation.task_id)
            .limit(_CARD_LEASE_COMPENSATION_LIMIT)
        )
    )
    if not task_ids:
        db.rollback()
        return

    tasks = list(
        db.scalars(
            select(Task)
            .where(Task.id.in_(task_ids), Task.tenant_id == tenant_id)
            .order_by(Task.id)
            .with_for_update(skip_locked=True)
        )
    )
    compensated = False
    for task in tasks:
        stale_allocation_id = db.scalar(
            select(CardAllocation.id)
            .where(
                CardAllocation.task_id == task.id,
                CardAllocation.tenant_id == tenant_id,
                CardAllocation.released_at.is_(None),
                CardAllocation.expires_at <= now,
            )
            .with_for_update(skip_locked=True)
        )
        if stale_allocation_id is None:
            continue
        _transition_task_to_terminal(
            task,
            db,
            now=now,
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
        compensated = True
    if compensated:
        db.commit()
    else:
        db.rollback()


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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    compensation_now = _utc_now()
    _compensate_expired_card_leases(
        db,
        tenant_id=principal.tenant_id,
        now=compensation_now,
    )
    now = _utc_now()
    task = _lock_owned_open_task(
        db,
        task_id,
        request=request,
        principal=principal,
    )

    existing = db.scalar(
        select(CardAllocation).where(
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
    )
    if existing is not None:
        card = db.get(Card, existing.card_id)
        if card is None or not card.is_active or card.quarantined_at is not None:
            raise HTTPException(status_code=503, detail="Assigned card is unavailable")
        response.status_code = 200
        return _card_allocation_response(existing, card)

    settings: Settings = request.app.state.settings
    card_policy = select_card_policy(
        db,
        tenant_id=principal.tenant_id,
        task_id=task.id,
        settings=settings,
    )
    selection_rule = _card_selection_rule(card_policy, task.task_type)
    selection_filters = _card_selection_filters(selection_rule, now=now)

    active_card = exists(
        select(CardAllocation.id).where(
            CardAllocation.card_id == Card.id,
            CardAllocation.released_at.is_(None),
        )
    )
    card = db.scalar(
        select(Card)
        .where(
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
            ~active_card,
            *selection_filters,
        )
        .order_by(*_card_selection_order(selection_rule))
        .with_for_update(skip_locked=True)
    )
    if card is None:
        raise HTTPException(status_code=503, detail="No active card is available")

    # PostgreSQL's row lock serializes allocation with an administrator's
    # disable barrier.  The conditional no-op update provides the same final
    # active-state recheck in SQLite, where SELECT FOR UPDATE is ignored.
    card_claim = db.execute(
        update(Card)
        .where(
            Card.id == card.id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
            *selection_filters,
        )
        .values(is_active=True)
        .execution_options(synchronize_session=False)
    )
    if card_claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=503, detail="No active card is available")
    db.expire(card)
    db.refresh(card)

    allocation = CardAllocation(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        card_id=card.id,
        trace_id=task.trace_id,
        status="active",
        allocation_reason_code="task_assigned",
        policy_version=card_policy.version,
        reveal_ttl_seconds=card_policy.reveal_ttl_seconds,
        selection_rule_json=canonical_card_selection_rule(selection_rule),
        expires_at=now + timedelta(seconds=card_policy.lease_ttl_seconds),
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
            if (
                card is not None
                and card.is_active
                and card.quarantined_at is None
            ):
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
        details={
            "task_id": task.id,
            "card_id": card.id,
            "card_last4": card.last4,
            "allocation_reason_code": allocation.allocation_reason_code,
            "policy_version": allocation.policy_version,
            "lease_ttl_seconds": card_policy.lease_ttl_seconds,
            "reveal_ttl_seconds": allocation.reveal_ttl_seconds,
            "selection_rule": selection_rule.model_dump(mode="json"),
        },
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=card.id,
        allocation_id=allocation.id,
        actor_id=principal.user_id,
        action="allocation.allocated",
        trace_id=allocation.trace_id,
        before_masked=_masked_card_state(card, status="available"),
        after_masked=_masked_card_state(
            card, status="allocated", allocation_status="active"
        ),
    )
    db.commit()
    return _card_allocation_response(allocation, card)


def _card_replacement_for(
    db: Session,
    original: CardAllocation,
    principal: AuthPrincipal,
) -> tuple[CardAllocation, Card] | None:
    replacement = db.scalar(
        select(CardAllocation)
        .join(
            CardAllocationReplacement,
            CardAllocationReplacement.replacement_allocation_id
            == CardAllocation.id,
        )
        .where(
            CardAllocationReplacement.original_allocation_id == original.id,
            CardAllocationReplacement.tenant_id == principal.tenant_id,
            CardAllocationReplacement.task_id == original.task_id,
            CardAllocation.task_id == original.task_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
    )
    if replacement is None:
        return None
    card = db.get(Card, replacement.card_id)
    return (replacement, card) if card is not None else None


@router.post(
    "/tasks/{task_id}/card-allocations/{allocation_id}/replace",
    response_model=CardAllocationResponse,
    status_code=201,
    responses={
        200: {
            "model": CardAllocationResponse,
            "description": "Idempotent replacement replay",
        }
    },
    tags=["cards"],
)
def replace_card_allocation(
    task_id: str,
    allocation_id: str,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    _compensate_expired_card_leases(
        db,
        tenant_id=principal.tenant_id,
        now=_utc_now(),
    )
    task = _lock_owned_open_task(
        db,
        task_id,
        request=request,
        principal=principal,
    )

    # SQLite ignores SELECT FOR UPDATE.  Claiming the task row keeps the same
    # task's replacement requests serialized in tests and local deployments.
    if db.get_bind().dialect.name == "sqlite":
        task_claim = db.execute(
            update(Task)
            .where(
                Task.id == task.id,
                Task.tenant_id == principal.tenant_id,
                Task.user_id == principal.user_id,
                Task.device_id == principal.device_id,
            )
            .values(status=Task.status)
            .execution_options(synchronize_session=False)
        )
        if task_claim.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=404, detail="Task not found")
        db.expire(task)
        db.refresh(task)
        _assert_task_open(task, db, request=request, principal=principal)

    original = db.scalar(
        select(CardAllocation)
        .where(
            CardAllocation.id == allocation_id,
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if original is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Card allocation not found")

    replay = _card_replacement_for(db, original, principal)
    if replay is not None:
        replacement, replacement_card = replay
        response.status_code = 200
        db.rollback()
        return _card_allocation_response(replacement, replacement_card)

    now = _utc_now()
    if (
        original.status != "active"
        or original.released_at is not None
        or _is_expired(original.expires_at, now)
    ):
        db.rollback()
        raise BusinessHTTPException(
            status_code=409,
            code="card_replacement_unavailable",
            message="Card allocation can no longer be replaced",
            recovery_hint="刷新当前任务和卡状态后再试",
        )

    original_card = db.scalar(
        select(Card).where(Card.id == original.card_id).with_for_update()
    )
    if original_card is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Card not found")

    selection_rule = parse_card_selection_rule(original.selection_rule_json)
    if selection_rule is None or selection_rule.task_type != task.task_type:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Frozen card selection rule is invalid for this task",
        )
    selection_filters = _card_selection_filters(selection_rule, now=now)

    active_card = exists(
        select(CardAllocation.id).where(
            CardAllocation.card_id == Card.id,
            CardAllocation.released_at.is_(None),
        )
    )
    replacement_card = db.scalar(
        select(Card)
        .where(
            Card.tenant_id == principal.tenant_id,
            Card.id != original.card_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
            ~active_card,
            *selection_filters,
        )
        .order_by(*_card_selection_order(selection_rule))
        .with_for_update(skip_locked=True)
    )
    if replacement_card is None:
        db.rollback()
        raise HTTPException(status_code=503, detail="No replacement card is available")

    replacement_claim = db.execute(
        update(Card)
        .where(
            Card.id == replacement_card.id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
            *selection_filters,
        )
        .values(is_active=True)
        .execution_options(synchronize_session=False)
    )
    if replacement_claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=503, detail="No replacement card is available")
    db.expire(replacement_card)
    db.refresh(replacement_card)

    released = db.execute(
        update(CardAllocation)
        .where(
            CardAllocation.id == original.id,
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
        .values(
            status="released",
            released_at=now,
            release_reason_code="replacement",
        )
        .execution_options(synchronize_session=False)
    )
    if released.rowcount != 1:
        db.rollback()
        raise BusinessHTTPException(
            status_code=409,
            code="card_replacement_unavailable",
            message="Card allocation can no longer be replaced",
            recovery_hint="刷新当前任务和卡状态后再试",
        )
    db.expire(original)
    db.refresh(original)

    replacement = CardAllocation(
        tenant_id=principal.tenant_id,
        task_id=task.id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        card_id=replacement_card.id,
        trace_id=task.trace_id,
        status="active",
        allocation_reason_code="replacement",
        policy_version=original.policy_version,
        reveal_ttl_seconds=original.reveal_ttl_seconds,
        selection_rule_json=original.selection_rule_json,
        expires_at=now + (original.expires_at - original.created_at),
    )
    db.add(replacement)
    try:
        db.flush()
        db.add(
            CardAllocationReplacement(
                original_allocation_id=original.id,
                replacement_allocation_id=replacement.id,
                tenant_id=principal.tenant_id,
                task_id=task.id,
            )
        )
        db.flush()
    except IntegrityError:
        db.rollback()
        original = db.scalar(
            select(CardAllocation).where(
                CardAllocation.id == allocation_id,
                CardAllocation.task_id == task_id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.user_id == principal.user_id,
                CardAllocation.device_id == principal.device_id,
            )
        )
        replay = (
            _card_replacement_for(db, original, principal)
            if original is not None
            else None
        )
        if replay is not None:
            replacement, replacement_card = replay
            response.status_code = 200
            return _card_allocation_response(replacement, replacement_card)
        raise HTTPException(
            status_code=503,
            detail="Card replacement is busy; retry",
        ) from None

    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.released",
        entity_type="card_allocation",
        entity_id=original.id,
        trace_id=original.trace_id,
        details={
            "card_id": original_card.id,
            "release_reason": "replacement",
            "replacement_allocation_id": replacement.id,
        },
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=original_card.id,
        allocation_id=original.id,
        actor_id=principal.user_id,
        action="allocation.released",
        reason_code="replacement",
        trace_id=original.trace_id,
        before_masked=_masked_card_state(
            original_card, status="allocated", allocation_status="active"
        ),
        after_masked=_masked_card_state(
            original_card, status="available", allocation_status="released"
        ),
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.allocated",
        entity_type="card_allocation",
        entity_id=replacement.id,
        trace_id=replacement.trace_id,
        details={
            "task_id": task.id,
            "card_id": replacement_card.id,
            "card_last4": replacement_card.last4,
            "allocation_reason_code": replacement.allocation_reason_code,
            "replaces_allocation_id": original.id,
            "policy_version": replacement.policy_version,
            "lease_ttl_seconds": int(
                (replacement.expires_at - now).total_seconds()
            ),
            "reveal_ttl_seconds": replacement.reveal_ttl_seconds,
            "selection_rule": selection_rule.model_dump(mode="json"),
        },
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=replacement_card.id,
        allocation_id=replacement.id,
        actor_id=principal.user_id,
        action="allocation.allocated",
        reason_code="replacement",
        trace_id=replacement.trace_id,
        before_masked=_masked_card_state(replacement_card, status="available"),
        after_masked=_masked_card_state(
            replacement_card, status="allocated", allocation_status="active"
        ),
    )
    db.commit()
    return _card_allocation_response(replacement, replacement_card)


@router.get(
    "/card-allocations/{allocation_id}",
    response_model=CardAllocationResponse,
    tags=["cards"],
)
def get_card_allocation(
    allocation_id: str,
    task_id: str,
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    result = _owned_card_allocation(
        db,
        allocation_id,
        principal,
        task_id=task_id,
    )
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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardAllocationResponse:
    result = _owned_card_allocation(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation_snapshot, card = result

    def refresh_after_lost_claim() -> CardAllocationResponse:
        db.rollback()
        db.expire_all()
        refreshed = _owned_card_allocation(db, allocation_id, principal)
        if refreshed is None:
            raise HTTPException(status_code=404, detail="Card allocation not found")
        current_allocation, current_card = refreshed
        if (
            current_allocation.status != "active"
            or current_allocation.released_at is not None
        ):
            return _card_allocation_response(current_allocation, current_card)
        raise BusinessHTTPException(
            status_code=409,
            code="card_release_unavailable",
            message="Card allocation can no longer be released",
            recovery_hint="刷新当前任务和卡状态后再试",
        )

    task_barrier = db.execute(
        update(Task)
        .where(
            Task.id == allocation_snapshot.task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .values(status=Task.status)
        .execution_options(synchronize_session=False)
    )
    if task_barrier.rowcount != 1:
        return refresh_after_lost_claim()
    task = db.scalar(
        select(Task)
        .where(
            Task.id == allocation_snapshot.task_id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
        )
        .execution_options(populate_existing=True)
    )
    now = _utc_now()
    if (
        task is None
        or task.status in _TERMINAL_TASK_STATUSES
        or task.expires_at is None
        or _is_expired(task.expires_at, now)
    ):
        return refresh_after_lost_claim()

    allocation = db.scalar(
        select(CardAllocation)
        .where(
            CardAllocation.id == allocation_id,
            CardAllocation.task_id == allocation_snapshot.task_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if allocation is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Card allocation not found")
    released = db.execute(
        update(CardAllocation)
        .where(
            CardAllocation.id == allocation.id,
            CardAllocation.task_id == allocation_snapshot.task_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
        .values(
            status="released",
            released_at=now,
            release_reason_code="user_released",
        )
        .execution_options(synchronize_session=False)
    )
    if released.rowcount != 1:
        return refresh_after_lost_claim()
    db.expire(allocation)
    db.refresh(allocation)
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="card.released",
        entity_type="card_allocation",
        entity_id=allocation.id,
        trace_id=allocation.trace_id,
        details={"card_id": card.id, "release_reason": "user_released"},
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=card.id,
        allocation_id=allocation.id,
        actor_id=principal.user_id,
        action="allocation.released",
        reason_code="user_released",
        trace_id=allocation.trace_id,
        before_masked=_masked_card_state(
            card, status="allocated", allocation_status="active"
        ),
        after_masked=_masked_card_state(
            card, status="available", allocation_status="released"
        ),
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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardRevealChallengeResponse:
    """Bind a short-lived step-up request to the current actor and lease."""

    result = _owned_card_reveal_context(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    _task, allocation, _card, now = result
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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardRevealGrantResponse:
    """Exchange a fresh, required-ACR OIDC authentication for one reveal."""

    result = _owned_card_reveal_context(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    _task, allocation, _card, now = result
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
        _record_card_reveal_step_up_failure(
            db,
            principal=principal,
            allocation=allocation,
            reason="oidc_required",
        )
        raise HTTPException(status_code=403, detail="OIDC step-up is required")
    auth_time = principal.auth_time
    challenge_created_at = challenge.created_at
    if challenge_created_at.tzinfo is None:
        challenge_created_at = challenge_created_at.replace(tzinfo=timezone.utc)
    if auth_time is None or auth_time + timedelta(seconds=5) < challenge_created_at:
        _record_card_reveal_step_up_failure(
            db,
            principal=principal,
            allocation=allocation,
            reason="stale_authentication",
        )
        raise HTTPException(status_code=403, detail="Fresh step-up is required")
    if principal.acr != challenge.required_acr:
        _record_card_reveal_step_up_failure(
            db,
            principal=principal,
            allocation=allocation,
            reason="insufficient_acr",
        )
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
    response_model_exclude_none=True,
    tags=["cards"],
)
def reveal_card_allocation(
    allocation_id: str,
    payload: CardRevealRequest,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> CardRevealResponse:
    result = _owned_card_reveal_context(db, allocation_id, principal)
    if result is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    task, allocation, card, now = result
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
        _record_card_reveal_failure(
            db,
            principal=principal,
            allocation=allocation,
        )
        raise HTTPException(status_code=403, detail="Valid reveal grant required")

    pan: str | None = None
    if "pan" in payload.fields:
        try:
            secret = request.app.state.card_secret_resolver.resolve(card.secret_ref)
        except CardSecretUnavailable:
            raise BusinessHTTPException(
                status_code=503,
                code="card_secret_unavailable",
                message="Card details are temporarily unavailable",
                recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
            ) from None
        pan = secret.pan

    claimed_at = _utc_now()
    reveal_expires_at = claimed_at + timedelta(
        seconds=allocation.reveal_ttl_seconds
    )
    task_claim = db.execute(
        update(Task)
        .where(
            Task.id == task.id,
            Task.tenant_id == principal.tenant_id,
            Task.user_id == principal.user_id,
            Task.device_id == principal.device_id,
            ~Task.status.in_(_TERMINAL_TASK_STATUSES),
            Task.expires_at.is_not(None),
            Task.expires_at > claimed_at,
        )
        .values(status=Task.status)
        .execution_options(synchronize_session=False)
    )
    if task_claim.rowcount != 1:
        db.rollback()
        raise _card_reveal_unavailable()
    allocation_claim = db.execute(
        update(CardAllocation)
        .where(
            CardAllocation.id == allocation.id,
            CardAllocation.task_id == task.id,
            CardAllocation.card_id == card.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > claimed_at,
            CardAllocation.revealed_at.is_(None),
            exists(
                select(Card.id).where(
                    Card.id == CardAllocation.card_id,
                    Card.tenant_id == principal.tenant_id,
                    Card.is_active.is_(True),
                    Card.quarantined_at.is_(None),
                )
            ),
        )
        .values(
            revealed_at=claimed_at,
            reveal_expires_at=reveal_expires_at,
        )
        .execution_options(synchronize_session=False)
    )
    if allocation_claim.rowcount != 1:
        db.rollback()
        raise _card_reveal_unavailable()
    challenge_claim = db.execute(
        update(CardRevealChallenge)
        .where(
            CardRevealChallenge.id == challenge.id,
            CardRevealChallenge.allocation_id == allocation.id,
            CardRevealChallenge.tenant_id == principal.tenant_id,
            CardRevealChallenge.user_id == principal.user_id,
            CardRevealChallenge.device_id == principal.device_id,
            CardRevealChallenge.grant_token_hash == grant_hash,
            CardRevealChallenge.consumed_at.is_(None),
            CardRevealChallenge.grant_expires_at.is_not(None),
            CardRevealChallenge.grant_expires_at > claimed_at,
        )
        .values(consumed_at=claimed_at, grant_token_hash=None)
        .execution_options(synchronize_session=False)
    )
    if challenge_claim.rowcount != 1:
        db.rollback()
        raise _card_reveal_unavailable()
    db.expire(allocation)
    db.refresh(allocation)
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
            "reveal_ttl_seconds": allocation.reveal_ttl_seconds,
            "policy_version": allocation.policy_version,
        },
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=card.id,
        allocation_id=allocation.id,
        actor_id=principal.user_id,
        action="card.revealed",
        trace_id=allocation.trace_id,
        before_masked=_masked_card_state(
            card, status="allocated", allocation_status="active"
        ),
        after_masked={
            **_masked_card_state(
                card, status="allocated", allocation_status="active"
            ),
            "revealed": True,
            "fields": payload.fields,
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
        pan=pan,
        reveal_expires_at=allocation.reveal_expires_at,
    )


def _upload_job_response(job: UploadJob) -> UploadJobResponse:
    return UploadJobResponse(
        id=job.id,
        task_id=job.task_id,
        status=job.status,
        phase=job.phase,
        phase_sequence=job.phase_sequence,
        phase_updated_at=job.phase_updated_at,
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
    principal: AuthPrincipal = Depends(get_operator_principal),
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
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    existing = db.scalar(
        select(UploadJob).where(
            UploadJob.tenant_id == principal.tenant_id,
            UploadJob.user_id == principal.user_id,
            UploadJob.device_id == principal.device_id,
            UploadJob.idempotency_key == payload.idempotency_key,
        )
    )
    if existing is not None:
        if (
            existing.task_id != task_id
            or existing.business_name != payload.business_name
        ):
            raise HTTPException(
                status_code=409,
                detail="Idempotency key was already used with different upload data",
            )
        response.status_code = 200
        return _upload_job_response(existing)

    task = _lock_owned_open_task(
        db,
        task_id,
        request=request,
        principal=principal,
    )

    sibling_statuses = set(
        db.scalars(
            select(UploadJob.status).where(
                UploadJob.task_id == task.id,
                UploadJob.tenant_id == principal.tenant_id,
                UploadJob.user_id == principal.user_id,
                UploadJob.device_id == principal.device_id,
                UploadJob.idempotency_key != payload.idempotency_key,
                UploadJob.status.in_(
                    ("queued", "running", "cancel_pending", "unknown")
                ),
            )
        )
    )
    if "unknown" in sibling_statuses:
        raise BusinessHTTPException(
            status_code=409,
            code="upload_reconciliation_required",
            message="An unknown upload result must be reconciled before retrying",
            recovery_hint="请联系管理员确认 Sub2 侧结果；核对为未创建后再重试",
        )
    if sibling_statuses:
        raise BusinessHTTPException(
            status_code=409,
            code="upload_in_progress",
            message="Another upload attempt is still active for this task",
            recovery_hint="请等待当前上传结束或取消完成后再重试",
        )

    now = _utc_now()
    active_allocation = db.scalar(
        select(CardAllocation).where(
            CardAllocation.task_id == task.id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.user_id == principal.user_id,
            CardAllocation.device_id == principal.device_id,
            CardAllocation.status == "active",
            CardAllocation.released_at.is_(None),
            CardAllocation.expires_at > now,
        )
    )
    if active_allocation is None:
        raise BusinessHTTPException(
            status_code=409,
            code="conflict",
            message="An active card allocation is required before upload",
            recovery_hint="刷新当前状态后按页面提示继续",
        )
    active_card = db.scalar(
        select(Card)
        .where(
            Card.id == active_allocation.card_id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
        )
        .with_for_update()
    )
    if active_card is None:
        raise BusinessHTTPException(
            status_code=409,
            code="conflict",
            message="An active card allocation is required before upload",
            recovery_hint="刷新当前状态后按页面提示继续",
        )
    card_claim = db.execute(
        update(Card)
        .where(
            Card.id == active_card.id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
            Card.quarantined_at.is_(None),
        )
        .values(is_active=True)
        .execution_options(synchronize_session=False)
    )
    if card_claim.rowcount != 1:
        db.rollback()
        raise BusinessHTTPException(
            status_code=409,
            code="conflict",
            message="An active card allocation is required before upload",
            recovery_hint="刷新当前状态后按页面提示继续",
        )

    verification = db.scalar(
        select(MailSession.id).where(
            MailSession.task_id == task.id,
            MailSession.tenant_id == principal.tenant_id,
            MailSession.user_id == principal.user_id,
            MailSession.device_id == principal.device_id,
            MailSession.status == "consumed",
            MailSession.consumed_at.is_not(None),
            MailSession.expires_at > now,
        )
    )
    if verification is None:
        raise BusinessHTTPException(
            status_code=409,
            code="verification_required",
            message="Verification must be completed before upload",
            recovery_hint="完成当前任务的验证码验证后重新提交",
        )

    selected_policy = select_policy_for_task(
        db,
        tenant_id=principal.tenant_id,
        task_id=task.id,
        fallback=request.app.state.sub2_policy,
        allow_fallback=request.app.state.settings.environment.strip().lower()
        in {"development", "test"},
    )
    if selected_policy is None:
        raise BusinessHTTPException(
            status_code=503,
            code="upload_policy_unavailable",
            message="An approved upload policy is required",
            recovery_hint="请联系平台管理员审批并发布上传策略后重试",
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
        phase="queued",
        phase_sequence=1,
        phase_updated_at=now,
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
                UploadJob.device_id == principal.device_id,
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
            "phase": job.phase,
            "phase_sequence": job.phase_sequence,
        },
        policy_version=job.policy_version,
        aggregate_sequence=job.phase_sequence,
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
    principal: AuthPrincipal = Depends(get_operator_principal),
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
def cancel_upload_job(
    job_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPERATOR, ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    ownership = [
        UploadJob.id == job_id,
        UploadJob.tenant_id == principal.tenant_id,
    ]
    if principal.role == ROLE_OPERATOR:
        ownership.extend(
            (
                UploadJob.user_id == principal.user_id,
                UploadJob.device_id == principal.device_id,
            )
        )
    now = _utc_now()
    cancellation_won = False
    for source_status, target_status in (
        ("queued", "cancelled"),
        ("running", "cancel_pending"),
    ):
        claimed = db.execute(
            update(UploadJob)
            .where(*ownership, UploadJob.status == source_status)
            .values(status=target_status, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount == 1:
            cancellation_won = True
            break

    job = db.scalar(select(UploadJob).where(*ownership))
    if job is None:
        raise HTTPException(status_code=404, detail="Upload job not found")
    if not cancellation_won:
        if job.status in {"cancelled", "cancel_pending"}:
            return _upload_job_response(job)
        raise BusinessHTTPException(
            status_code=409,
            code="upload_not_cancellable",
            message="Upload job can no longer be cancelled",
            recovery_hint="请刷新上传状态；如结果未知，请联系管理员核对",
        )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=job.user_id,
        device_id=job.device_id,
        actor_id=principal.user_id,
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
    "/uploads/{job_id}/cancel",
    response_model=UploadJobResponse,
    tags=["uploads"],
)
def cancel_upload_job_legacy(
    job_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_operator_principal),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    return cancel_upload_job(job_id, request, principal, db)


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
        require_roles(ROLE_OPS_ADMIN, ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> UploadJobResponse:
    job_task_id = db.scalar(
        select(UploadJob.task_id).where(
            UploadJob.id == job_id,
            UploadJob.tenant_id == principal.tenant_id,
        )
    )
    if job_task_id is None:
        raise HTTPException(status_code=404, detail="Upload job not found")
    task = db.scalar(
        select(Task)
        .where(
            Task.id == job_task_id,
            Task.tenant_id == principal.tenant_id,
        )
        .with_for_update()
    )
    if task is None:
        raise HTTPException(status_code=409, detail="Upload task is unavailable")
    job = db.scalar(
        select(UploadJob)
        .where(
            UploadJob.id == job_id,
            UploadJob.tenant_id == principal.tenant_id,
            UploadJob.task_id == task.id,
        )
        .with_for_update()
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
    transition_upload_phase(
        db,
        job,
        (
            "reconciliation_check"
            if payload.status == "unknown"
            else "reconciliation_result"
        ),
        actor_id=principal.user_id,
    )
    job.external_ref = payload.external_ref
    job.error_code = (
        None
        if payload.status == "succeeded"
        else payload.error_code or f"reconciled_{payload.status}"
    )
    record_audit(
        db,
        tenant_id=job.tenant_id,
        user_id=job.user_id,
        device_id=job.device_id,
        actor_id=principal.user_id,
        event_type=(
            "upload.reconciliation_checked"
            if payload.status == "unknown"
            else "upload.reconciled"
        ),
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        details={
            "status": job.status,
            "error_code": job.error_code,
            "policy_version": job.policy_version,
            "phase": job.phase,
            "phase_sequence": job.phase_sequence,
        },
    )
    if payload.status == "succeeded":
        _transition_task_to_terminal(
            task,
            db,
            now=_utc_now(),
            task_status="completed",
            card_status="released",
            mail_status="revoked",
            release_reason="upload_reconciled_succeeded",
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            finalize_upload_outbox=True,
            skip_locked=True,
        )
    db.commit()
    if payload.status == "succeeded":
        db.refresh(task)
        task_expired = task.status == "expired"
        terminal_recovery = task.status != "completed"
        _compensate_terminal_task_resources(
            db,
            task.id,
            now=_utc_now(),
            card_status="expired" if task_expired else "released",
            mail_status="expired" if task_expired else "revoked",
            release_reason=(
                "terminal_task_recovery"
                if terminal_recovery
                else "upload_reconciled_succeeded"
            ),
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            upload_error_code=(
                "task_expired"
                if task_expired
                else "terminal_task_recovery" if terminal_recovery else None
            ),
        )
        db.commit()
    db.refresh(job)
    return _upload_job_response(job)


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
    "/admin/users/batch-disable",
    response_model=list[AdminUserResponse],
    tags=["admin"],
)
def admin_batch_disable_users(
    payload: AdminUserBatchDisable,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminUserResponse]:
    if principal.user_id in payload.user_ids:
        raise HTTPException(status_code=409, detail="Cannot disable the current user")
    users = list(
        db.scalars(
            select(User)
            .where(
                User.tenant_id == principal.tenant_id,
                User.id.in_(payload.user_ids),
            )
            .order_by(User.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    )
    by_id = {user.id: user for user in users}
    if len(by_id) != len(payload.user_ids):
        raise HTTPException(status_code=404, detail="User not found")
    if principal.role != ROLE_PLATFORM_ADMIN and any(
        user.role == ROLE_PLATFORM_ADMIN for user in users
    ):
        raise HTTPException(status_code=403, detail="Cannot disable a platform administrator")
    for user_id in payload.user_ids:
        user = by_id[user_id]
        if not user.is_active:
            continue
        user.is_active = False
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.user_disabled",
            entity_type="user",
            entity_id=user.id,
            trace_id=request.state.trace_id,
            details={"role": user.role, "batch": True},
        )
    # Publish every user-state barrier before taking worker-owned resource locks.
    db.commit()
    for user_id in payload.user_ids:
        user = by_id[user_id]
        _revoke_principal_resources(
            db,
            tenant_id=user.tenant_id,
            user_id=user.id,
            device_id=None,
            now=_utc_now(),
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            release_reason="admin_user_batch_disabled",
        )
        db.commit()
    return [
        AdminUserResponse.model_validate(by_id[user_id], from_attributes=True)
        for user_id in payload.user_ids
    ]


@router.patch(
    "/admin/users/{user_id}/role",
    response_model=AdminUserResponse,
    tags=["admin"],
)
def admin_update_user_role(
    user_id: str,
    payload: AdminUserRoleUpdate,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    del user_id, payload, request, principal, db
    raise HTTPException(
        status_code=410,
        detail="Direct role changes are disabled; create a role-change request",
    )


def _admin_role_change_response(
    role_change: AdminRoleChangeRequest,
    *,
    now: datetime | None = None,
) -> AdminRoleChangeResponse:
    status = role_change.status
    if status == "pending" and _is_expired(role_change.expires_at, now or _utc_now()):
        status = "expired"
    return AdminRoleChangeResponse(
        id=role_change.id,
        tenant_id=role_change.tenant_id,
        target_user_id=role_change.target_user_id,
        expected_old_role=role_change.expected_old_role,
        new_role=role_change.new_role,
        status=status,
        requested_by=role_change.requested_by,
        approved_by=role_change.approved_by,
        request_trace_id=role_change.request_trace_id,
        approval_trace_id=role_change.approval_trace_id,
        created_at=role_change.created_at,
        expires_at=role_change.expires_at,
        applied_at=role_change.applied_at,
    )


def _claim_admin_role_change_target(
    db: Session,
    *,
    user_id: str,
    tenant_id: str,
) -> User | None:
    """Claim a target row before testing the pending-request uniqueness rule."""

    statement = (
        select(User)
        .where(User.id == user_id, User.tenant_id == tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    for attempt in range(2):
        # ``SELECT .. FOR UPDATE`` is a no-op on SQLite. The no-op write claims
        # the target before the partial unique pending-request index is tested.
        db.execute(
            update(User)
            .where(User.id == user_id, User.tenant_id == tenant_id)
            .values(role=User.role)
            .execution_options(synchronize_session=False)
        )
        user = db.scalar(statement)
        if user is not None:
            return user
        if attempt == 0:
            # Under concurrent SQLite requests a transaction can rarely expose
            # an empty read after the no-op claim. Restarting once distinguishes
            # that stale snapshot from a genuinely absent tenant-scoped target.
            db.rollback()
    return None


@router.post(
    "/admin/users/{user_id}/role-change-requests",
    response_model=AdminRoleChangeResponse,
    status_code=201,
    tags=["admin"],
)
def admin_request_user_role_change(
    user_id: str,
    payload: AdminUserRoleUpdate,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> AdminRoleChangeResponse:
    if user_id == principal.user_id:
        raise HTTPException(status_code=409, detail="Cannot change the current user role")
    user = _claim_admin_role_change_target(
        db,
        user_id=user_id,
        tenant_id=principal.tenant_id,
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == ROLE_WORKER_SERVICE:
        raise HTTPException(status_code=409, detail="Cannot change a service identity role")
    if not user.is_active:
        raise HTTPException(status_code=409, detail="Cannot change an inactive user role")
    if user.role == payload.role:
        raise HTTPException(status_code=409, detail="Requested role is already active")

    now = _utc_now().replace(microsecond=0)
    expired = db.scalar(
        select(AdminRoleChangeRequest)
        .where(
            AdminRoleChangeRequest.tenant_id == principal.tenant_id,
            AdminRoleChangeRequest.target_user_id == user.id,
            AdminRoleChangeRequest.status == "pending",
            AdminRoleChangeRequest.expires_at <= now,
        )
        .with_for_update()
    )
    if expired is not None:
        expired.status = "expired"
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.user_role_change_expired",
            entity_type="admin_role_change_request",
            entity_id=expired.id,
            trace_id=request.state.trace_id,
            details={"target_user_id": user.id, "reason": "request_expired"},
        )
    existing = db.scalar(
        select(AdminRoleChangeRequest).where(
            AdminRoleChangeRequest.tenant_id == principal.tenant_id,
            AdminRoleChangeRequest.target_user_id == user.id,
            AdminRoleChangeRequest.status == "pending",
            AdminRoleChangeRequest.expires_at > now,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="A pending role-change request exists")

    settings: Settings = request.app.state.settings
    role_change = AdminRoleChangeRequest(
        tenant_id=principal.tenant_id,
        target_user_id=user.id,
        expected_old_role=user.role,
        new_role=payload.role,
        status="pending",
        requested_by=principal.user_id,
        request_trace_id=request.state.trace_id,
        created_at=now,
        expires_at=now
        + timedelta(seconds=settings.admin_role_change_ttl_seconds),
    )
    db.add(role_change)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="A pending role-change request exists"
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.user_role_change_requested",
        entity_type="admin_role_change_request",
        entity_id=role_change.id,
        trace_id=request.state.trace_id,
        details={
            "target_user_id": user.id,
            "expected_old_role": user.role,
            "new_role": payload.role,
            "requested_by": principal.user_id,
        },
    )
    db.commit()
    db.refresh(role_change)
    return _admin_role_change_response(role_change, now=now)


@router.get(
    "/admin/role-change-requests",
    response_model=list[AdminRoleChangeResponse],
    tags=["admin"],
)
def admin_list_role_change_requests(
    status: Literal["pending", "applied", "expired"] | None = Query(default=None),
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> list[AdminRoleChangeResponse]:
    now = _utc_now()
    statement = select(AdminRoleChangeRequest).where(
        AdminRoleChangeRequest.tenant_id == principal.tenant_id
    )
    if status == "pending":
        statement = statement.where(
            AdminRoleChangeRequest.status == "pending",
            AdminRoleChangeRequest.expires_at > now,
        )
    elif status == "expired":
        statement = statement.where(
            or_(
                AdminRoleChangeRequest.status == "expired",
                (AdminRoleChangeRequest.status == "pending")
                & (AdminRoleChangeRequest.expires_at <= now),
            )
        )
    elif status == "applied":
        statement = statement.where(AdminRoleChangeRequest.status == "applied")
    role_changes = db.scalars(
        statement.order_by(AdminRoleChangeRequest.created_at.desc()).limit(100)
    ).all()
    return [_admin_role_change_response(item, now=now) for item in role_changes]


def _deny_role_change_approval(
    db: Session,
    *,
    role_change: AdminRoleChangeRequest,
    principal: AuthPrincipal,
    trace_id: str,
    reason: str,
    status_code: int,
    detail: str,
) -> None:
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.user_role_change_approval_denied",
        entity_type="admin_role_change_request",
        entity_id=role_change.id,
        trace_id=trace_id,
        result="failure",
        details={
            "reason": reason,
            "target_user_id": role_change.target_user_id,
            "requested_by": role_change.requested_by,
            "approver_id": principal.user_id,
        },
    )
    db.commit()
    contracts = {
        403: ("forbidden", "联系管理员确认账号角色和资源权限"),
        404: ("not_found", "刷新列表并确认资源仍然存在"),
        409: ("conflict", "刷新当前状态后按页面提示继续"),
    }
    code, recovery_hint = contracts.get(
        status_code, ("http_error", "携带 trace_id 联系管理员")
    )
    raise BusinessHTTPException(
        status_code=status_code,
        code=code,
        message=detail,
        recovery_hint=recovery_hint,
    )


@router.post(
    "/admin/role-change-requests/{role_change_id}/approve",
    response_model=AdminRoleChangeResponse,
    tags=["admin"],
)
def admin_approve_role_change_request(
    role_change_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> AdminRoleChangeResponse:
    role_change = db.scalar(
        select(AdminRoleChangeRequest)
        .where(
            AdminRoleChangeRequest.id == role_change_id,
            AdminRoleChangeRequest.tenant_id == principal.tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if role_change is None:
        raise HTTPException(status_code=404, detail="Role-change request not found")
    if role_change.status == "applied":
        target = db.scalar(
            select(User).where(
                User.id == role_change.target_user_id,
                User.tenant_id == principal.tenant_id,
            )
        )
        if (
            target is not None
            and target.role == role_change.new_role
            and role_change.new_role != ROLE_OPERATOR
        ):
            _revoke_principal_resources(
                db,
                tenant_id=target.tenant_id,
                user_id=target.id,
                device_id=None,
                now=_utc_now(),
                actor_user_id=principal.user_id,
                actor_device_id=principal.device_id,
                release_reason="admin_user_role_changed",
                mail_status="revoked",
                finalize_upload_outbox=True,
            )
            db.commit()
        raise HTTPException(status_code=409, detail="Role-change request is not pending")
    if role_change.status != "pending":
        raise HTTPException(status_code=409, detail="Role-change request is not pending")
    now = _utc_now()
    if _is_expired(role_change.expires_at, now):
        role_change.status = "expired"
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="request_expired",
            status_code=409,
            detail="Role-change request has expired",
        )
    if role_change.requested_by == principal.user_id:
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="same_administrator",
            status_code=409,
            detail="Approval requires a different administrator",
        )

    settings: Settings = request.app.state.settings
    created_at = role_change.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if principal.identity_kind != "oidc":
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="oidc_required",
            status_code=403,
            detail="OIDC fresh MFA is required",
        )
    if principal.auth_time is None or principal.auth_time < created_at:
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="stale_authentication",
            status_code=403,
            detail="Authentication must occur after the role-change request",
        )
    if principal.acr != settings.admin_role_change_acr:
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="insufficient_acr",
            status_code=403,
            detail="Required MFA authentication level is missing",
        )

    user = db.scalar(
        select(User)
        .where(
            User.id == role_change.target_user_id,
            User.tenant_id == principal.tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="target_missing",
            status_code=409,
            detail="Role-change target is unavailable",
        )
    if not user.is_active or user.role != role_change.expected_old_role:
        role_change.status = "expired"
        _deny_role_change_approval(
            db,
            role_change=role_change,
            principal=principal,
            trace_id=request.state.trace_id,
            reason="target_state_changed",
            status_code=409,
            detail="Target role state has changed",
        )

    target_user_id = user.id
    target_tenant_id = user.tenant_id
    new_role = role_change.new_role
    user_claim = db.execute(
        update(User)
        .where(
            User.id == target_user_id,
            User.tenant_id == target_tenant_id,
            User.is_active.is_(True),
            User.role == role_change.expected_old_role,
        )
        .values(role=new_role)
        .execution_options(synchronize_session=False)
    )
    if user_claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Target role state has changed")
    approval_claim = db.execute(
        update(AdminRoleChangeRequest)
        .where(
            AdminRoleChangeRequest.id == role_change.id,
            AdminRoleChangeRequest.tenant_id == principal.tenant_id,
            AdminRoleChangeRequest.status == "pending",
            AdminRoleChangeRequest.expires_at > now,
            AdminRoleChangeRequest.requested_by != principal.user_id,
        )
        .values(
            status="applied",
            approved_by=principal.user_id,
            approval_trace_id=request.state.trace_id,
            applied_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if approval_claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Role-change request is not pending")
    common_details = {
        "target_user_id": target_user_id,
        "previous_role": role_change.expected_old_role,
        "new_role": role_change.new_role,
        "requested_by": role_change.requested_by,
        "approved_by": principal.user_id,
    }
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.user_role_change_approved",
        entity_type="admin_role_change_request",
        entity_id=role_change.id,
        trace_id=request.state.trace_id,
        details=common_details,
    )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.user_role_changed",
        entity_type="user",
        entity_id=target_user_id,
        trace_id=request.state.trace_id,
        details=common_details,
    )
    # Publish the role barrier before lifecycle cleanup takes worker-owned locks.
    db.commit()
    if new_role != ROLE_OPERATOR:
        _revoke_principal_resources(
            db,
            tenant_id=target_tenant_id,
            user_id=target_user_id,
            device_id=None,
            now=_utc_now(),
            actor_user_id=principal.user_id,
            actor_device_id=principal.device_id,
            release_reason="admin_user_role_changed",
            mail_status="revoked",
            finalize_upload_outbox=True,
        )
        db.commit()
    db.refresh(role_change)
    return _admin_role_change_response(role_change)


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
        select(User)
        .where(User.id == user_id, User.tenant_id == principal.tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if principal.role != ROLE_PLATFORM_ADMIN and user.role == ROLE_PLATFORM_ADMIN:
        raise HTTPException(status_code=403, detail="Cannot disable a platform administrator")
    if user.is_active:
        user.is_active = False
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
    # Phase one is an irreversible state barrier.  Release the User lock before
    # lifecycle cleanup reacquires the existing UploadJob -> Task lock prefix.
    db.commit()
    _revoke_principal_resources(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        device_id=None,
        now=_utc_now(),
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
        release_reason="admin_user_disabled",
    )
    db.commit()
    db.refresh(user)
    return AdminUserResponse.model_validate(user, from_attributes=True)


@router.post(
    "/admin/users/{user_id}/devices",
    response_model=AdminDeviceResponse,
    status_code=201,
    tags=["admin"],
)
def admin_register_device(
    user_id: str,
    payload: AdminDeviceCreate,
    request: Request,
    response: Response,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> AdminDeviceResponse:
    try:
        registration = register_device(
            db,
            tenant_id=principal.tenant_id,
            user_id=user_id,
            name=payload.name,
            max_active_devices=request.app.state.settings.max_active_devices_per_user,
        )
    except DeviceOwnerNotFoundError:
        raise HTTPException(status_code=404, detail="User not found") from None
    except DeviceNameRetiredError:
        raise BusinessHTTPException(
            status_code=409,
            code="device_name_retired",
            message="Device name cannot be reused",
            recovery_hint="使用新的设备名称后重试",
        ) from None
    except ActiveDeviceLimitReachedError:
        raise BusinessHTTPException(
            status_code=409,
            code="device_limit_reached",
            message="Active device limit reached",
            recovery_hint="撤销不再使用的设备后重试",
        ) from None

    if registration.created:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.device_registered",
            entity_type="device",
            entity_id=registration.device.id,
            trace_id=request.state.trace_id,
            details={"target_user_id": user_id},
        )
    else:
        response.status_code = 200
    db.commit()
    db.refresh(registration.device)
    return AdminDeviceResponse.model_validate(
        registration.device, from_attributes=True
    )


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
    candidate = db.scalar(
        select(Device).where(
            Device.id == device_id, Device.tenant_id == principal.tenant_id
        )
    )
    if candidate is None:
        raise HTTPException(status_code=404, detail="Device not found")
    owner = _lock_user(
        db,
        tenant_id=principal.tenant_id,
        user_id=candidate.user_id,
    )
    device = _lock_device(
        db,
        tenant_id=principal.tenant_id,
        user_id=candidate.user_id,
        device_id=device_id,
    )
    if owner is None or device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.revoked_at is None:
        now = _utc_now()
        device.revoked_at = now
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
    _revoke_principal_resources(
        db,
        tenant_id=device.tenant_id,
        user_id=device.user_id,
        device_id=device.id,
        now=_utc_now(),
        actor_user_id=principal.user_id,
        actor_device_id=principal.device_id,
        release_reason="admin_device_revoked",
    )
    db.commit()
    db.refresh(device)
    return AdminDeviceResponse.model_validate(device, from_attributes=True)


def _normalized_audit_time(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _audit_query(
    *,
    tenant_id: str,
    task_id: str | None,
    card_id: str | None,
    trace_id: str | None,
    actor_id: str | None,
    user_id: str | None,
    device_id: str | None,
    entity_type: str | None,
    entity_id: str | None,
    event_type: str | None,
    action: str | None,
    result: str | None,
    created_from: datetime | None,
    created_to: datetime | None,
) -> Any:
    start = _normalized_audit_time(created_from)
    end = _normalized_audit_time(created_to)
    if action is not None and not action.strip():
        raise HTTPException(status_code=422, detail="action must not be empty")
    if start is not None and end is not None and start > end:
        raise HTTPException(
            status_code=422, detail="created_from must be earlier than created_to"
        )
    query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    if task_id:
        normalized_task_id = task_id.strip()
        task_exists = exists(
            select(Task.id).where(
                Task.id == normalized_task_id,
                Task.tenant_id == tenant_id,
            )
        )
        query = query.where(
            task_exists,
            or_(
                and_(
                    AuditEvent.entity_type == "task",
                    AuditEvent.entity_id == normalized_task_id,
                ),
                and_(
                    AuditEvent.entity_type == "mail_session",
                    AuditEvent.entity_id.in_(
                        select(MailSession.id).where(
                            MailSession.tenant_id == tenant_id,
                            MailSession.task_id == normalized_task_id,
                        )
                    ),
                ),
                and_(
                    AuditEvent.entity_type == "card_allocation",
                    AuditEvent.entity_id.in_(
                        select(CardAllocation.id).where(
                            CardAllocation.tenant_id == tenant_id,
                            CardAllocation.task_id == normalized_task_id,
                        )
                    ),
                ),
                and_(
                    AuditEvent.entity_type == "upload_job",
                    AuditEvent.entity_id.in_(
                        select(UploadJob.id).where(
                            UploadJob.tenant_id == tenant_id,
                            UploadJob.task_id == normalized_task_id,
                        )
                    ),
                ),
            ),
        )
    if card_id:
        normalized_card_id = card_id.strip()
        allocation_ids = select(CardAllocation.id).where(
            CardAllocation.tenant_id == tenant_id,
            CardAllocation.card_id == normalized_card_id,
        )
        card_exists = exists(
            select(Card.id).where(
                Card.id == normalized_card_id,
                Card.tenant_id == tenant_id,
            )
        )
        query = query.where(
            card_exists,
            or_(
                and_(
                    AuditEvent.entity_type == "card",
                    AuditEvent.entity_id == normalized_card_id,
                ),
                and_(
                    AuditEvent.entity_type == "card_allocation",
                    AuditEvent.entity_id.in_(allocation_ids),
                ),
                and_(
                    AuditEvent.entity_type == "upload_job",
                    AuditEvent.entity_id.in_(
                        select(UploadJob.id).where(
                            UploadJob.tenant_id == tenant_id,
                            UploadJob.card_allocation_id.in_(allocation_ids),
                        )
                    ),
                ),
            ),
        )
    filters = (
        (AuditEvent.trace_id, trace_id),
        (AuditEvent.actor_id, actor_id),
        (AuditEvent.user_id, user_id),
        (AuditEvent.device_id, device_id),
        (AuditEvent.entity_type, entity_type),
        (AuditEvent.entity_id, entity_id),
        (AuditEvent.event_type, event_type),
        (AuditEvent.action, action),
        (AuditEvent.result, result),
    )
    for column, value in filters:
        if value:
            query = query.where(column == value.strip())
    if start is not None:
        query = query.where(AuditEvent.created_at >= start)
    if end is not None:
        query = query.where(AuditEvent.created_at <= end)
    return query


def _admin_audit_response(event: AuditEvent) -> AdminAuditResponse:
    projected = project_audit_event(event)
    return AdminAuditResponse(
        id=projected["id"],
        tenant_id=projected["tenant_id"],
        user_id=projected["user_id"],
        device_id=projected["device_id"],
        actor_id=projected["actor_id"],
        event_type=projected["event_type"],
        action=projected["action"],
        result=projected["result"],
        entity_type=projected["entity_type"],
        entity_id=projected["entity_id"],
        trace_id=projected["trace_id"],
        ip_address=projected["ip_address"],
        user_agent=projected["user_agent"],
        policy_version=projected["policy_version"],
        details=projected["details"],
        created_at=projected["created_at"],
    )


def _audit_csv_cell(value: object) -> str:
    if value is None:
        return ""
    rendered = value.isoformat() if isinstance(value, datetime) else str(value)
    rendered = " ".join(rendered.split())
    if rendered.startswith(("=", "+", "-", "@")):
        rendered = "'" + rendered
    return rendered


@router.get(
    "/admin/audit/export",
    response_class=Response,
    responses={
        200: {
            "description": "Tenant-scoped redacted audit CSV",
            "content": {"text/csv": {"schema": {"type": "string"}}},
        }
    },
    tags=["admin"],
)
def admin_export_audit(
    request: Request,
    task_id: str | None = Query(default=None, min_length=1, max_length=36),
    card_id: str | None = Query(default=None, min_length=1, max_length=36),
    trace_id: str | None = Query(default=None, max_length=64),
    actor_id: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None, max_length=64),
    device_id: str | None = Query(default=None, min_length=1, max_length=36),
    entity_type: str | None = Query(default=None, max_length=80),
    entity_id: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=80),
    action: str | None = Query(default=None, min_length=1, max_length=80),
    result: str | None = Query(default=None, max_length=32),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    limit: int = Query(default=5_000, ge=1, le=10_000),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> Response:
    """Export bounded, redacted evidence; free-form details are intentionally omitted."""

    normalized_action = action.strip() if action is not None else None
    query = _audit_query(
        tenant_id=principal.tenant_id,
        task_id=task_id,
        card_id=card_id,
        trace_id=trace_id,
        actor_id=actor_id,
        user_id=user_id,
        device_id=device_id,
        entity_type=entity_type,
        entity_id=entity_id,
        event_type=event_type,
        action=normalized_action,
        result=result,
        created_from=created_from,
        created_to=created_to,
    )
    events = db.scalars(
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    ).all()
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="audit.exported",
        entity_type="audit_report",
        entity_id=None,
        trace_id=request.state.trace_id,
        details={
            "filters": {
                "task_id": task_id,
                "card_id": card_id,
                "trace_id": trace_id,
                "actor_id": actor_id,
                "user_id": user_id,
                "device_id": device_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "event_type": event_type,
                "action": normalized_action,
                "result": result,
                "created_from": created_from.isoformat() if created_from else None,
                "created_to": created_to.isoformat() if created_to else None,
            },
            "row_count": len(events),
            "limit": limit,
        },
    )
    db.commit()
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    columns = (
        "id",
        "tenant_id",
        "created_at",
        "actor_id",
        "user_id",
        "device_id",
        "action",
        "result",
        "entity_type",
        "entity_id",
        "trace_id",
        "policy_version",
        "ip_address",
        "user_agent",
    )
    writer.writerow(columns)
    for event in events:
        projected = project_audit_event(event)
        row = []
        for column in columns:
            value = projected[column]
            row.append(_audit_csv_cell(value))
        writer.writerow(row)
    return Response(
        content=("\ufeff" + output.getvalue()).encode("utf-8"),
        media_type="text/csv",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="audit-events.csv"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/admin/audit",
    response_model=list[AdminAuditResponse],
    tags=["admin"],
)
def admin_list_audit(
    task_id: str | None = Query(default=None, min_length=1, max_length=36),
    card_id: str | None = Query(default=None, min_length=1, max_length=36),
    trace_id: str | None = Query(default=None, max_length=64),
    actor_id: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None, max_length=64),
    device_id: str | None = Query(default=None, min_length=1, max_length=36),
    entity_type: str | None = Query(default=None, max_length=80),
    entity_id: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=80),
    action: str | None = Query(default=None, min_length=1, max_length=80),
    result: str | None = Query(default=None, max_length=32),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> list[AdminAuditResponse]:
    query = _audit_query(
        tenant_id=principal.tenant_id,
        task_id=task_id,
        card_id=card_id,
        trace_id=trace_id,
        actor_id=actor_id,
        user_id=user_id,
        device_id=device_id,
        entity_type=entity_type,
        entity_id=entity_id,
        event_type=event_type,
        action=action,
        result=result,
        created_from=created_from,
        created_to=created_to,
    )
    events = db.scalars(
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    ).all()
    return [_admin_audit_response(event) for event in events]


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
    allocated_card_ids = set(
        db.scalars(
            select(CardAllocation.card_id).where(
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.released_at.is_(None),
            )
        )
    )
    return [
        _admin_card_response(card, allocated=card.id in allocated_card_ids)
        for card in cards
    ]


def _admin_card_status(
    card: Card, *, allocated: bool = False
) -> Literal["available", "allocated", "disabled", "quarantined"]:
    if card.quarantined_at is not None:
        return "quarantined"
    if not card.is_active:
        return "disabled"
    return "allocated" if allocated else "available"


def _masked_card_state(
    card: Card,
    *,
    status: str,
    allocation_status: str | None = None,
) -> dict[str, Any]:
    return {
        "card_masked": f"**** **** **** {card.last4}",
        "brand": card.brand,
        "card_status": status,
        "allocation_status": allocation_status,
    }


def _admin_card_response(card: Card, *, allocated: bool = False) -> AdminCardResponse:
    status = _admin_card_status(card, allocated=allocated)
    return AdminCardResponse(
        id=card.id,
        tenant_id=card.tenant_id,
        provider_ref=card.provider_ref,
        pool_key=card.pool_key,
        region=card.region,
        brand=card.brand,
        last4=card.last4,
        expiry_month=card.expiry_month,
        expiry_year=card.expiry_year,
        status=status,
        quarantine_reason_code=card.quarantine_reason_code,
        quarantined_at=card.quarantined_at,
        is_active=card.is_active and card.quarantined_at is None,
        created_at=card.created_at,
    )


def _pool_import_digest(pool_type: Literal["card", "mailbox"], payload: list[Any]) -> str:
    canonical_payload = json.dumps(
        [item.model_dump(mode="json") for item in payload],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest_input = (
        f"email-platform:pool-import:v1\0{pool_type}\0{canonical_payload}"
    ).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


def _pool_import_receipt_response(
    receipt: PoolImportReceipt,
) -> PoolImportReceiptResponse:
    return PoolImportReceiptResponse(
        id=receipt.id,
        pool_type=receipt.pool_type,
        imported_count=receipt.item_count,
        trace_id=receipt.trace_id,
        created_at=receipt.created_at,
    )


def _replay_pool_import_receipt(
    db: Session,
    *,
    principal: AuthPrincipal,
    pool_type: Literal["card", "mailbox"],
    idempotency_key: str,
    request_digest: str,
    response: Response,
) -> PoolImportReceiptResponse | None:
    receipt = db.scalar(
        select(PoolImportReceipt).where(
            PoolImportReceipt.tenant_id == principal.tenant_id,
            PoolImportReceipt.pool_type == pool_type,
            PoolImportReceipt.idempotency_key == idempotency_key,
        )
    )
    if receipt is None:
        return None
    if (
        receipt.created_by != principal.user_id
        or receipt.device_id != principal.device_id
        or receipt.request_digest != request_digest
    ):
        raise HTTPException(
            status_code=409,
            detail="Idempotency key is already bound to another pool import",
        )
    response.status_code = 200
    return _pool_import_receipt_response(receipt)


def _admin_card_allocation_response(
    allocation: CardAllocation, card: Card
) -> AdminCardAllocationResponse:
    return AdminCardAllocationResponse(
        id=allocation.id,
        card_id=allocation.card_id,
        card_masked=f"**** **** **** {card.last4}",
        brand=card.brand,
        user_id=allocation.user_id,
        task_id=allocation.task_id,
        device_id=allocation.device_id,
        status=allocation.status,
        allocation_reason_code=allocation.allocation_reason_code,
        expires_at=allocation.expires_at,
        released_at=allocation.released_at,
        release_reason_code=allocation.release_reason_code,
        trace_id=allocation.trace_id,
        created_at=allocation.created_at,
    )


def _admin_card_event_response(event: CardEvent) -> AdminCardEventResponse:
    return AdminCardEventResponse(
        id=event.id,
        card_id=event.card_id,
        allocation_id=event.allocation_id,
        actor_id=event.actor_id,
        action=event.action,
        reason_code=event.reason_code,
        before_masked=safe_card_event_state(event.before_masked),
        after_masked=safe_card_event_state(event.after_masked),
        trace_id=event.trace_id,
        created_at=event.created_at,
    )


def _encode_card_timeline_cursor(created_at: datetime, row_id: str) -> str:
    normalized_time = (
        created_at.replace(tzinfo=timezone.utc)
        if created_at.tzinfo is None
        else created_at.astimezone(timezone.utc)
    )
    normalized = normalized_time.isoformat(timespec="microseconds")
    payload = json.dumps([1, normalized, row_id], separators=(",", ":")).encode(
        "utf-8"
    )
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_card_timeline_cursor(value: str) -> tuple[datetime, str]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        ).decode("utf-8")
        payload = json.loads(decoded)
        if not isinstance(payload, list) or len(payload) != 3 or payload[0] != 1:
            raise ValueError
        created_at = datetime.fromisoformat(str(payload[1]))
        row_id = payload[2]
        if created_at.tzinfo is None or not isinstance(row_id, str):
            raise ValueError
        if not 1 <= len(row_id) <= 36 or not all(
            character.isalnum() or character in "-_" for character in row_id
        ):
            raise ValueError
    except (
        binascii.Error,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        TypeError,
    ):
        raise HTTPException(
            status_code=422, detail="Invalid card timeline cursor"
        ) from None
    return created_at, row_id


@router.get(
    "/admin/cards/{card_id}/timeline",
    response_model=AdminCardTimelineResponse,
    tags=["admin"],
)
def admin_get_card_timeline(
    card_id: str,
    allocations_cursor: str | None = Query(default=None, min_length=1, max_length=512),
    events_cursor: str | None = Query(default=None, min_length=1, max_length=512),
    allocation_limit: int = Query(default=100, ge=1, le=100),
    event_limit: int = Query(default=200, ge=1, le=200),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminCardTimelineResponse:
    card = db.scalar(
        select(Card).where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
        )
    )
    if card is None:
        raise HTTPException(status_code=404, detail="Card not found")

    allocation_filters = [
        CardAllocation.card_id == card.id,
        CardAllocation.tenant_id == principal.tenant_id,
    ]
    if allocations_cursor is not None:
        cursor_created_at, cursor_id = _decode_card_timeline_cursor(
            allocations_cursor
        )
        allocation_filters.append(
            or_(
                CardAllocation.created_at < cursor_created_at,
                and_(
                    CardAllocation.created_at == cursor_created_at,
                    CardAllocation.id < cursor_id,
                ),
            )
        )
    allocation_rows = list(
        db.scalars(
            select(CardAllocation)
            .where(*allocation_filters)
            .order_by(CardAllocation.created_at.desc(), CardAllocation.id.desc())
            .limit(allocation_limit + 1)
        )
    )
    event_filters = [
        CardEvent.card_id == card.id,
        CardEvent.tenant_id == principal.tenant_id,
    ]
    if events_cursor is not None:
        cursor_created_at, cursor_id = _decode_card_timeline_cursor(events_cursor)
        event_filters.append(
            or_(
                CardEvent.created_at < cursor_created_at,
                and_(
                    CardEvent.created_at == cursor_created_at,
                    CardEvent.id < cursor_id,
                ),
            )
        )
    events = list(
        db.scalars(
            select(CardEvent)
            .where(*event_filters)
            .order_by(CardEvent.created_at.desc(), CardEvent.id.desc())
            .limit(event_limit + 1)
        )
    )
    allocation_page = allocation_rows[:allocation_limit]
    event_page = events[:event_limit]
    allocations_has_more = len(allocation_rows) > allocation_limit
    events_has_more = len(events) > event_limit
    allocated = bool(
        db.scalar(
            select(
                exists().where(
                    CardAllocation.card_id == card.id,
                    CardAllocation.tenant_id == principal.tenant_id,
                    CardAllocation.status == "active",
                    CardAllocation.released_at.is_(None),
                )
            )
        )
    )
    return AdminCardTimelineResponse(
        card=_admin_card_response(card, allocated=allocated),
        allocations=[
            _admin_card_allocation_response(allocation, card)
            for allocation in allocation_page
        ],
        events=[_admin_card_event_response(event) for event in event_page],
        allocations_has_more=allocations_has_more,
        events_has_more=events_has_more,
        allocations_next_cursor=(
            _encode_card_timeline_cursor(
                allocation_page[-1].created_at, allocation_page[-1].id
            )
            if allocations_has_more and allocation_page
            else None
        ),
        events_next_cursor=(
            _encode_card_timeline_cursor(event_page[-1].created_at, event_page[-1].id)
            if events_has_more and event_page
            else None
        ),
    )


@router.post(
    "/admin/cards",
    response_model=AdminCardResponse,
    status_code=201,
    tags=["admin"],
)
def admin_create_card(
    payload: AdminCardCreate,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminCardResponse:
    card = Card(
        tenant_id=principal.tenant_id,
        provider_ref=payload.provider_ref,
        pool_key=payload.pool_key,
        region=payload.region,
        brand=payload.brand,
        last4=payload.last4,
        expiry_month=payload.expiry_month,
        expiry_year=payload.expiry_year,
        secret_ref=payload.secret_ref,
        is_active=True,
    )
    db.add(card)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Card provider or secret reference already exists",
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.card_created",
        entity_type="card",
        entity_id=card.id,
        trace_id=request.state.trace_id,
        details={
            "provider_ref": card.provider_ref,
            "pool_key": card.pool_key,
            "region": card.region,
            "brand": card.brand,
            "last4": card.last4,
        },
    )
    record_card_event(
        db,
        tenant_id=principal.tenant_id,
        card_id=card.id,
        actor_id=principal.user_id,
        action="card.created",
        trace_id=request.state.trace_id,
        after_masked=_masked_card_state(card, status="available"),
    )
    db.commit()
    db.refresh(card)
    return _admin_card_response(card)


@router.post(
    "/admin/cards/imports",
    response_model=PoolImportReceiptResponse,
    status_code=201,
    tags=["admin"],
)
def admin_import_cards(
    request: Request,
    response: Response,
    payload: list[AdminCardCreate] = Body(min_length=1, max_length=100),
    idempotency_key: str = Header(
        alias="Idempotency-Key",
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> PoolImportReceiptResponse:
    request_digest = _pool_import_digest("card", payload)
    replay = _replay_pool_import_receipt(
        db,
        principal=principal,
        pool_type="card",
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        response=response,
    )
    if replay is not None:
        return replay
    receipt = PoolImportReceipt(
        tenant_id=principal.tenant_id,
        pool_type="card",
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        item_count=len(payload),
        created_by=principal.user_id,
        device_id=principal.device_id,
        trace_id=request.state.trace_id,
    )
    db.add(receipt)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        replay = _replay_pool_import_receipt(
            db,
            principal=principal,
            pool_type="card",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            response=response,
        )
        if replay is not None:
            return replay
        raise HTTPException(status_code=409, detail="Pool import conflict") from None
    cards = [
        Card(
            tenant_id=principal.tenant_id,
            provider_ref=item.provider_ref,
            pool_key=item.pool_key,
            region=item.region,
            brand=item.brand,
            last4=item.last4,
            expiry_month=item.expiry_month,
            expiry_year=item.expiry_year,
            secret_ref=item.secret_ref,
            is_active=True,
        )
        for item in payload
    ]
    db.add_all(cards)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Card provider or secret reference already exists",
        ) from None
    for card in cards:
        record_card_event(
            db,
            tenant_id=principal.tenant_id,
            card_id=card.id,
            actor_id=principal.user_id,
            action="card.created",
            trace_id=request.state.trace_id,
            after_masked=_masked_card_state(card, status="available"),
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.card_imported",
            entity_type="card",
            entity_id=card.id,
            trace_id=request.state.trace_id,
            details={
                "import_receipt_id": receipt.id,
                "provider_ref": card.provider_ref,
                "pool_key": card.pool_key,
                "region": card.region,
                "brand": card.brand,
                "last4": card.last4,
            },
        )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.cards_imported",
        entity_type="card_pool",
        entity_id=receipt.id,
        trace_id=request.state.trace_id,
        details={"count": len(cards), "pool_type": "card"},
    )
    db.commit()
    db.refresh(receipt)
    return _pool_import_receipt_response(receipt)


def _compensate_card_allocation(
    db: Session,
    *,
    allocation_id: str,
    card_id: str,
    principal: AuthPrincipal,
    release_reason: str,
    queued_error_code: str,
    admin_event_type: str | None = None,
) -> bool:
    """Drain one allocation and release it without scanning later leases."""

    for _ in range(3):
        upload_jobs = list(
            db.scalars(
                select(UploadJob)
                .where(
                    UploadJob.tenant_id == principal.tenant_id,
                    UploadJob.card_allocation_id == allocation_id,
                    UploadJob.status.in_(("queued", "running")),
                )
                .order_by(UploadJob.id)
            )
        )
        for upload in upload_jobs:
            source_status = upload.status
            now = _utc_now()
            was_running = source_status == "running"
            target_status = "unknown" if was_running else "cancelled"
            error_code = "external_unknown" if was_running else queued_error_code
            claimed = db.execute(
                update(UploadJob)
                .where(
                    UploadJob.id == upload.id,
                    UploadJob.tenant_id == principal.tenant_id,
                    UploadJob.card_allocation_id == allocation_id,
                    UploadJob.status == source_status,
                )
                .values(
                    status=target_status,
                    error_code=error_code,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                db.rollback()
                continue
            db.expire(upload)
            db.refresh(upload)
            record_audit(
                db,
                tenant_id=upload.tenant_id,
                user_id=upload.user_id,
                device_id=upload.device_id,
                actor_id=principal.user_id,
                event_type=(
                    "upload.unknown" if was_running else "upload.cancel_requested"
                ),
                entity_type="upload_job",
                entity_id=upload.id,
                trace_id=upload.trace_id,
                details={"status": target_status, "reason": release_reason},
            )
            outbox_events = list(
                db.scalars(
                    select(OutboxEvent).where(
                        OutboxEvent.aggregate_id == upload.id,
                        OutboxEvent.event_type == "upload.requested",
                        OutboxEvent.status.in_(("pending", "processing")),
                    )
                )
            )
            for event in outbox_events:
                event.status = "processed"
                event.processed_at = now
                event.last_error_code = None
            db.commit()

        active_uploads = db.scalar(
            select(func.count())
            .select_from(UploadJob)
            .where(
                UploadJob.tenant_id == principal.tenant_id,
                UploadJob.card_allocation_id == allocation_id,
                UploadJob.status.in_(("queued", "running")),
            )
        )
        db.rollback()
        if active_uploads:
            continue

        now = _utc_now()
        released = db.execute(
            update(CardAllocation)
            .where(
                CardAllocation.id == allocation_id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.card_id == card_id,
                CardAllocation.status.in_(("active", "recycle_pending")),
                CardAllocation.released_at.is_(None),
            )
            .values(
                status="released",
                released_at=now,
                release_reason_code=release_reason,
            )
            .execution_options(synchronize_session=False)
        )
        if released.rowcount != 1:
            db.rollback()
            return False
        allocation = db.get(CardAllocation, allocation_id)
        card = db.get(Card, card_id)
        if allocation is None or card is None:
            db.rollback()
            return False
        card_status = _admin_card_status(card)
        record_audit(
            db,
            tenant_id=allocation.tenant_id,
            user_id=allocation.user_id,
            device_id=allocation.device_id,
            actor_id=principal.user_id,
            event_type="card.released",
            entity_type="card_allocation",
            entity_id=allocation.id,
            trace_id=allocation.trace_id,
            details={
                "task_id": allocation.task_id,
                "card_id": card_id,
                "release_reason": release_reason,
            },
        )
        record_card_event(
            db,
            tenant_id=allocation.tenant_id,
            card_id=card_id,
            allocation_id=allocation.id,
            actor_id=principal.user_id,
            action="allocation.released",
            reason_code=release_reason,
            trace_id=allocation.trace_id,
            before_masked=_masked_card_state(
                card,
                status="allocated" if card_status == "available" else card_status,
                allocation_status="active",
            ),
            after_masked=_masked_card_state(
                card,
                status=card_status,
                allocation_status="released",
            ),
        )
        if admin_event_type is not None:
            record_audit(
                db,
                tenant_id=allocation.tenant_id,
                user_id=allocation.user_id,
                device_id=allocation.device_id,
                actor_id=principal.user_id,
                event_type=admin_event_type,
                entity_type="card_allocation",
                entity_id=allocation.id,
                trace_id=allocation.trace_id,
                details={
                    "card_id": card_id,
                    "release_reason": release_reason,
                },
            )
        db.commit()
        return True
    return False


@router.post(
    "/admin/cards/{card_id}/allocations/{allocation_id}/recycle",
    response_model=AdminCardAllocationResponse,
    tags=["admin"],
)
def admin_recycle_card_allocation(
    card_id: str,
    allocation_id: str,
    payload: AdminCardRecycleRequest,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminCardAllocationResponse:
    row = db.execute(
        select(CardAllocation, Card)
        .join(Card, Card.id == CardAllocation.card_id)
        .where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
            CardAllocation.id == allocation_id,
            CardAllocation.card_id == card_id,
            CardAllocation.tenant_id == principal.tenant_id,
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    allocation, card = row
    if allocation.released_at is not None:
        return _admin_card_allocation_response(allocation, card)
    if allocation.status not in {"active", "recycle_pending"}:
        raise BusinessHTTPException(
            status_code=409,
            code="card_recycle_unavailable",
            message="Card allocation cannot be recycled from its current state",
            recovery_hint="刷新卡分配记录后选择仍在活动中的租约",
        )

    if allocation.status == "active":
        claimed = db.execute(
            update(CardAllocation)
            .where(
                CardAllocation.id == allocation_id,
                CardAllocation.card_id == card_id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.status == "active",
                CardAllocation.released_at.is_(None),
            )
            .values(
                status="recycle_pending",
                release_reason_code=payload.reason_code,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount == 1:
            record_audit(
                db,
                tenant_id=allocation.tenant_id,
                user_id=allocation.user_id,
                device_id=allocation.device_id,
                actor_id=principal.user_id,
                event_type="admin.card_allocation_recycle_requested",
                entity_type="card_allocation",
                entity_id=allocation.id,
                trace_id=allocation.trace_id,
                details={
                    "card_id": card_id,
                    "release_reason": payload.reason_code,
                },
            )
            db.commit()
        else:
            db.rollback()

    db.expire_all()
    current = db.scalar(
        select(CardAllocation).where(
            CardAllocation.id == allocation_id,
            CardAllocation.card_id == card_id,
            CardAllocation.tenant_id == principal.tenant_id,
        )
    )
    if current is None:
        raise HTTPException(status_code=404, detail="Card allocation not found")
    if current.released_at is not None:
        return _admin_card_allocation_response(current, card)
    if current.status != "recycle_pending":
        raise BusinessHTTPException(
            status_code=409,
            code="card_recycle_unavailable",
            message="Card allocation can no longer be recycled",
            recovery_hint="刷新卡分配记录后选择仍在活动中的租约",
        )
    release_reason = current.release_reason_code or payload.reason_code
    released = _compensate_card_allocation(
        db,
        allocation_id=allocation_id,
        card_id=card_id,
        principal=principal,
        release_reason=release_reason,
        queued_error_code="card_recycled",
        admin_event_type="admin.card_allocation_recycled",
    )
    db.expire_all()
    current = db.scalar(
        select(CardAllocation).where(
            CardAllocation.id == allocation_id,
            CardAllocation.card_id == card_id,
            CardAllocation.tenant_id == principal.tenant_id,
        )
    )
    if current is not None and current.released_at is not None:
        return _admin_card_allocation_response(current, card)
    if released:
        raise HTTPException(status_code=500, detail="Released allocation could not be read")
    raise BusinessHTTPException(
        status_code=409,
        code="card_recycle_in_progress",
        message="Card allocation recycle is still in progress",
        recovery_hint="刷新卡分配记录后重试；回收屏障不会回退",
    )


def _compensate_unavailable_card(
    db: Session,
    *,
    card_id: str,
    principal: AuthPrincipal,
    release_reason: str = "admin_card_disabled",
    queued_error_code: str = "card_disabled",
    in_progress_code: str = "card_disable_in_progress",
    in_progress_message: str = "Card is disabled but resource cleanup is still in progress",
    recovery_hint: str = "刷新卡状态后重试停用；已停用状态不会回退",
) -> int:
    """Drain resources after an unavailable Card row is durably committed.

    Each conditional update commits independently, so this path never holds a
    Card lock while waiting on a Worker-owned UploadJob or allocation.
    """

    released_count = 0
    for _ in range(3):
        allocation_ids = list(
            db.scalars(
                select(CardAllocation.id)
                .where(
                    CardAllocation.card_id == card_id,
                    CardAllocation.tenant_id == principal.tenant_id,
                    CardAllocation.released_at.is_(None),
                )
                .order_by(CardAllocation.id)
            )
        )
        db.rollback()
        if not allocation_ids:
            return released_count

        for allocation_id in allocation_ids:
            upload_jobs = list(
                db.scalars(
                    select(UploadJob)
                    .where(
                        UploadJob.tenant_id == principal.tenant_id,
                        UploadJob.card_allocation_id.in_((allocation_id,)),
                        UploadJob.status.in_(("queued", "running")),
                    )
                    .order_by(UploadJob.id)
                )
            )
            for upload in upload_jobs:
                upload_id = upload.id
                source_status = upload.status
                now = _utc_now()
                was_running = source_status == "running"
                target_status = "unknown" if was_running else "cancelled"
                error_code = "external_unknown" if was_running else queued_error_code
                claimed = db.execute(
                    update(UploadJob)
                    .where(
                        UploadJob.id == upload_id,
                        UploadJob.tenant_id == principal.tenant_id,
                        UploadJob.card_allocation_id == allocation_id,
                        UploadJob.status == source_status,
                    )
                    .values(
                        status=target_status,
                        error_code=error_code,
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False)
                )
                if claimed.rowcount != 1:
                    db.rollback()
                    continue
                db.expire(upload)
                db.refresh(upload)
                record_audit(
                    db,
                    tenant_id=upload.tenant_id,
                    user_id=upload.user_id,
                    device_id=upload.device_id,
                    actor_id=principal.user_id,
                    event_type=(
                        "upload.unknown" if was_running else "upload.cancel_requested"
                    ),
                    entity_type="upload_job",
                    entity_id=upload.id,
                    trace_id=upload.trace_id,
                    details={
                        "status": target_status,
                        "reason": release_reason,
                    },
                )
                outbox_events = list(
                    db.scalars(
                        select(OutboxEvent).where(
                            OutboxEvent.aggregate_id == upload.id,
                            OutboxEvent.event_type == "upload.requested",
                            OutboxEvent.status.in_(("pending", "processing")),
                        )
                    )
                )
                for event in outbox_events:
                    event.status = "processed"
                    event.processed_at = now
                    event.last_error_code = None
                db.commit()

            active_uploads = db.scalar(
                select(func.count())
                .select_from(UploadJob)
                .where(
                    UploadJob.tenant_id == principal.tenant_id,
                    UploadJob.card_allocation_id == allocation_id,
                    UploadJob.status.in_(("queued", "running")),
                )
            )
            db.rollback()
            if active_uploads:
                continue

            now = _utc_now()
            released = db.execute(
                update(CardAllocation)
                .where(
                    CardAllocation.id == allocation_id,
                    CardAllocation.tenant_id == principal.tenant_id,
                    CardAllocation.card_id == card_id,
                    CardAllocation.released_at.is_(None),
                )
                .values(
                    status="released",
                    released_at=now,
                    release_reason_code=release_reason,
                )
                .execution_options(synchronize_session=False)
            )
            if released.rowcount != 1:
                db.rollback()
                continue
            allocation = db.get(CardAllocation, allocation_id)
            if allocation is None:
                db.rollback()
                continue
            record_audit(
                db,
                tenant_id=allocation.tenant_id,
                user_id=allocation.user_id,
                device_id=allocation.device_id,
                actor_id=principal.user_id,
                event_type="card.released",
                entity_type="card_allocation",
                entity_id=allocation.id,
                trace_id=allocation.trace_id,
                details={
                    "task_id": allocation.task_id,
                    "release_reason": release_reason,
                },
            )
            card_status = (
                "quarantined"
                if release_reason == "admin_card_quarantined"
                else "disabled"
            )
            record_card_event(
                db,
                tenant_id=allocation.tenant_id,
                card_id=card_id,
                allocation_id=allocation.id,
                actor_id=principal.user_id,
                action="allocation.released",
                reason_code=release_reason,
                trace_id=allocation.trace_id,
                before_masked={
                    "card_status": card_status,
                    "allocation_status": "active",
                },
                after_masked={
                    "card_status": card_status,
                    "allocation_status": "released",
                },
            )
            db.commit()
            released_count += 1

    remaining = db.scalar(
        select(func.count())
        .select_from(CardAllocation)
        .where(
            CardAllocation.card_id == card_id,
            CardAllocation.tenant_id == principal.tenant_id,
            CardAllocation.released_at.is_(None),
        )
    )
    db.rollback()
    if remaining:
        raise BusinessHTTPException(
            status_code=409,
            code=in_progress_code,
            message=in_progress_message,
            recovery_hint=recovery_hint,
        )
    return released_count


@router.patch(
    "/admin/cards/{card_id}",
    response_model=AdminCardResponse,
    tags=["admin"],
)
def admin_update_card_state(
    card_id: str,
    payload: AdminCardStateUpdate,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminCardResponse:
    card = db.scalar(
        select(Card).where(
            Card.id == card_id, Card.tenant_id == principal.tenant_id
        )
    )
    if card is None:
        raise HTTPException(status_code=404, detail="Card not found")

    if card.quarantined_at is not None:
        if payload.is_active:
            raise BusinessHTTPException(
                status_code=409,
                code="card_quarantined",
                message="Quarantined cards must be released before they can be enabled",
                recovery_hint="先由平台管理员解除隔离，再显式启用卡资源",
            )
        db.rollback()
        _compensate_unavailable_card(
            db,
            card_id=card_id,
            principal=principal,
            release_reason="admin_card_quarantined",
            queued_error_code="card_quarantined",
            in_progress_code="card_quarantine_in_progress",
            in_progress_message=(
                "Card is quarantined but resource cleanup is still in progress"
            ),
            recovery_hint="刷新卡状态后重试隔离；隔离屏障不会回退",
        )
        db.expire(card)
        db.refresh(card)
        return _admin_card_response(card)

    if payload.is_active:
        if not card.is_active:
            db.rollback()
            _compensate_unavailable_card(
                db, card_id=card_id, principal=principal
            )
            enabled = db.execute(
                update(Card)
                .where(
                    Card.id == card_id,
                    Card.tenant_id == principal.tenant_id,
                    Card.is_active.is_(False),
                    Card.quarantined_at.is_(None),
                )
                .values(is_active=True)
                .execution_options(synchronize_session=False)
            )
            if enabled.rowcount == 1:
                record_audit(
                    db,
                    tenant_id=principal.tenant_id,
                    user_id=principal.user_id,
                    device_id=principal.device_id,
                    event_type="admin.card_enabled",
                    entity_type="card",
                    entity_id=card_id,
                    trace_id=request.state.trace_id,
                    details={"released_allocation_count": 0},
                )
                record_card_event(
                    db,
                    tenant_id=principal.tenant_id,
                    card_id=card_id,
                    actor_id=principal.user_id,
                    action="card.enabled",
                    trace_id=request.state.trace_id,
                    before_masked=_masked_card_state(card, status="disabled"),
                    after_masked=_masked_card_state(card, status="available"),
                )
                db.commit()
            else:
                db.rollback()
        db.expire(card)
        db.refresh(card)
        return _admin_card_response(card)

    disabled = db.execute(
        update(Card)
        .where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
            Card.is_active.is_(True),
        )
        .values(is_active=False)
        .execution_options(synchronize_session=False)
    )
    if disabled.rowcount == 1:
        pending_release_count = db.scalar(
            select(func.count())
            .select_from(CardAllocation)
            .where(
                CardAllocation.card_id == card_id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.released_at.is_(None),
            )
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.card_disabled",
            entity_type="card",
            entity_id=card_id,
            trace_id=request.state.trace_id,
            details={"released_allocation_count": int(pending_release_count or 0)},
        )
        record_card_event(
            db,
            tenant_id=principal.tenant_id,
            card_id=card_id,
            actor_id=principal.user_id,
            action="card.disabled",
            reason_code="admin_card_disabled",
            trace_id=request.state.trace_id,
            before_masked=_masked_card_state(
                card,
                status="allocated" if pending_release_count else "available",
                allocation_status="active" if pending_release_count else None,
            ),
            after_masked=_masked_card_state(card, status="disabled"),
        )
        db.commit()
    else:
        db.rollback()

    _compensate_unavailable_card(db, card_id=card_id, principal=principal)
    db.expire(card)
    db.refresh(card)
    return _admin_card_response(card)


@router.post(
    "/admin/cards/{card_id}/quarantine",
    response_model=AdminCardResponse,
    tags=["admin"],
)
def admin_quarantine_card(
    card_id: str,
    payload: AdminCardQuarantineRequest,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> AdminCardResponse:
    card = db.scalar(
        select(Card).where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
        )
    )
    if card is None:
        raise HTTPException(status_code=404, detail="Card not found")

    was_active = card.is_active
    quarantined_at = _utc_now()
    quarantined = db.execute(
        update(Card)
        .where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
            Card.quarantined_at.is_(None),
        )
        .values(
            is_active=False,
            quarantined_at=quarantined_at,
            quarantine_reason_code=payload.reason_code,
        )
        .execution_options(synchronize_session=False)
    )
    if quarantined.rowcount == 1:
        pending_release_count = db.scalar(
            select(func.count())
            .select_from(CardAllocation)
            .where(
                CardAllocation.card_id == card_id,
                CardAllocation.tenant_id == principal.tenant_id,
                CardAllocation.released_at.is_(None),
            )
        )
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.card_quarantined",
            entity_type="card",
            entity_id=card_id,
            trace_id=request.state.trace_id,
            details={
                "reason_code": payload.reason_code,
                "released_allocation_count": int(pending_release_count or 0),
            },
        )
        previous_status = (
            "disabled"
            if not was_active
            else ("allocated" if pending_release_count else "available")
        )
        record_card_event(
            db,
            tenant_id=principal.tenant_id,
            card_id=card_id,
            actor_id=principal.user_id,
            action="card.quarantined",
            reason_code=payload.reason_code,
            trace_id=request.state.trace_id,
            before_masked=_masked_card_state(
                card,
                status=previous_status,
                allocation_status="active" if pending_release_count else None,
            ),
            after_masked=_masked_card_state(card, status="quarantined"),
        )
        db.commit()
    else:
        db.rollback()

    _compensate_unavailable_card(
        db,
        card_id=card_id,
        principal=principal,
        release_reason="admin_card_quarantined",
        queued_error_code="card_quarantined",
        in_progress_code="card_quarantine_in_progress",
        in_progress_message=(
            "Card is quarantined but resource cleanup is still in progress"
        ),
        recovery_hint="刷新卡状态后重试隔离；隔离屏障不会回退",
    )
    db.expire(card)
    db.refresh(card)
    return _admin_card_response(card)


@router.post(
    "/admin/cards/{card_id}/release-quarantine",
    response_model=AdminCardResponse,
    tags=["admin"],
)
def admin_release_card_quarantine(
    card_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> AdminCardResponse:
    card = db.scalar(
        select(Card).where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
        )
    )
    if card is None:
        raise HTTPException(status_code=404, detail="Card not found")
    if card.quarantined_at is None:
        if card.is_active:
            raise BusinessHTTPException(
                status_code=409,
                code="card_not_quarantined",
                message="Only quarantined cards can be released from quarantine",
                recovery_hint="刷新卡状态后选择适用的操作",
            )
        return _admin_card_response(card)

    db.rollback()
    _compensate_unavailable_card(
        db,
        card_id=card_id,
        principal=principal,
        release_reason="admin_card_quarantined",
        queued_error_code="card_quarantined",
        in_progress_code="card_quarantine_in_progress",
        in_progress_message=(
            "Card is quarantined but resource cleanup is still in progress"
        ),
        recovery_hint="刷新卡状态后重试解除隔离；隔离屏障不会提前清除",
    )
    released = db.execute(
        update(Card)
        .where(
            Card.id == card_id,
            Card.tenant_id == principal.tenant_id,
            Card.quarantined_at.is_not(None),
        )
        .values(
            is_active=False,
            quarantined_at=None,
            quarantine_reason_code=None,
        )
        .execution_options(synchronize_session=False)
    )
    if released.rowcount == 1:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.card_quarantine_released",
            entity_type="card",
            entity_id=card_id,
            trace_id=request.state.trace_id,
            details={"resulting_status": "disabled"},
        )
        record_card_event(
            db,
            tenant_id=principal.tenant_id,
            card_id=card_id,
            actor_id=principal.user_id,
            action="card.quarantine_released",
            reason_code="quarantine_released",
            trace_id=request.state.trace_id,
            before_masked=_masked_card_state(card, status="quarantined"),
            after_masked=_masked_card_state(card, status="disabled"),
        )
        db.commit()
    else:
        db.rollback()
    db.expire(card)
    db.refresh(card)
    return _admin_card_response(card)


@router.post(
    "/admin/mailboxes",
    response_model=MailboxStatusResponse,
    status_code=201,
    tags=["admin"],
)
def admin_create_mailbox(
    payload: AdminMailboxCreate,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> MailboxStatusResponse:
    mailbox = Mailbox(
        tenant_id=principal.tenant_id,
        email_masked=payload.email_masked,
        connector_type=payload.connector_type,
        task_type=payload.task_type,
        secret_ref=payload.secret_ref,
        is_active=True,
    )
    db.add(mailbox)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Mailbox secret reference already exists"
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.mailbox_created",
        entity_type="mailbox",
        entity_id=mailbox.id,
        trace_id=request.state.trace_id,
        details={
            "email_masked": mailbox.email_masked,
            "connector_type": mailbox.connector_type,
            "task_type": mailbox.task_type,
        },
    )
    db.commit()
    db.refresh(mailbox)
    return _mailbox_status_response(mailbox, active_session_count=0)


@router.post(
    "/admin/mailboxes/imports",
    response_model=PoolImportReceiptResponse,
    status_code=201,
    tags=["admin"],
)
def admin_import_mailboxes(
    request: Request,
    response: Response,
    payload: list[AdminMailboxCreate] = Body(min_length=1, max_length=100),
    idempotency_key: str = Header(
        alias="Idempotency-Key",
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> PoolImportReceiptResponse:
    request_digest = _pool_import_digest("mailbox", payload)
    replay = _replay_pool_import_receipt(
        db,
        principal=principal,
        pool_type="mailbox",
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        response=response,
    )
    if replay is not None:
        return replay
    receipt = PoolImportReceipt(
        tenant_id=principal.tenant_id,
        pool_type="mailbox",
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        item_count=len(payload),
        created_by=principal.user_id,
        device_id=principal.device_id,
        trace_id=request.state.trace_id,
    )
    db.add(receipt)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        replay = _replay_pool_import_receipt(
            db,
            principal=principal,
            pool_type="mailbox",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            response=response,
        )
        if replay is not None:
            return replay
        raise HTTPException(status_code=409, detail="Pool import conflict") from None
    mailboxes = [
        Mailbox(
            tenant_id=principal.tenant_id,
            email_masked=item.email_masked,
            connector_type=item.connector_type,
            task_type=item.task_type,
            secret_ref=item.secret_ref,
            is_active=True,
        )
        for item in payload
    ]
    db.add_all(mailboxes)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Mailbox secret reference already exists"
        ) from None
    for mailbox in mailboxes:
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.mailbox_imported",
            entity_type="mailbox",
            entity_id=mailbox.id,
            trace_id=request.state.trace_id,
            details={
                "import_receipt_id": receipt.id,
                "email_masked": mailbox.email_masked,
                "connector_type": mailbox.connector_type,
                "task_type": mailbox.task_type,
            },
        )
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type="admin.mailboxes_imported",
        entity_type="mailbox_pool",
        entity_id=receipt.id,
        trace_id=request.state.trace_id,
        details={"count": len(mailboxes), "pool_type": "mailbox"},
    )
    db.commit()
    db.refresh(receipt)
    return _pool_import_receipt_response(receipt)


@router.patch(
    "/admin/mailboxes/{mailbox_id}",
    response_model=MailboxStatusResponse,
    tags=["admin"],
)
def admin_update_mailbox_state(
    mailbox_id: str,
    payload: AdminMailboxStateUpdate,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> MailboxStatusResponse:
    mailbox = db.scalar(
        select(Mailbox)
        .where(
            Mailbox.id == mailbox_id,
            Mailbox.tenant_id == principal.tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if mailbox is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    revoked_count = 0
    if not payload.is_active:
        sessions = list(
            db.scalars(
                select(MailSession)
                .where(
                    MailSession.mailbox_id == mailbox.id,
                    MailSession.tenant_id == principal.tenant_id,
                    MailSession.status.in_(_RELEASABLE_MAIL_SESSION_STATUSES),
                )
                .order_by(MailSession.id)
                .with_for_update()
            )
        )
        for session in sessions:
            session.status = "revoked"
            session.delivered_code = None
            session.delivered_message_id_hash = None
            session.delivered_at = None
            session.code_expires_at = None
            session.start_watermark = None
            session.last_message_hash = None
            revoked_count += 1
            record_audit(
                db,
                tenant_id=session.tenant_id,
                user_id=session.user_id,
                device_id=session.device_id,
                actor_id=principal.user_id,
                event_type="mail_session.revoked",
                entity_type="mail_session",
                entity_id=session.id,
                trace_id=session.trace_id,
                details={
                    "task_id": session.task_id,
                    "reason": "admin_mailbox_disabled",
                },
            )
    state_changed = mailbox.is_active != payload.is_active
    if state_changed:
        mailbox.is_active = payload.is_active
        if payload.is_active:
            reset_mailbox_health(mailbox)
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type=(
                "admin.mailbox_enabled"
                if payload.is_active
                else "admin.mailbox_disabled"
            ),
            entity_type="mailbox",
            entity_id=mailbox.id,
            trace_id=request.state.trace_id,
            details={"revoked_session_count": revoked_count},
        )
    if state_changed or revoked_count:
        db.commit()
        db.refresh(mailbox)
    active_session_count = db.scalar(
        select(func.count())
        .select_from(MailSession)
        .where(
            MailSession.mailbox_id == mailbox.id,
            MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            MailSession.expires_at > _utc_now(),
        )
    )
    return _mailbox_status_response(
        mailbox, active_session_count=int(active_session_count or 0)
    )


@router.post(
    "/admin/mailboxes/{mailbox_id}/secret-rotations",
    response_model=MailboxStatusResponse,
    tags=["admin"],
)
def admin_rotate_mailbox_secret(
    mailbox_id: str,
    payload: AdminMailboxSecretRotation,
    request: Request,
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> MailboxStatusResponse:
    mailbox = db.scalar(
        select(Mailbox)
        .where(
            Mailbox.id == mailbox_id,
            Mailbox.tenant_id == principal.tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if mailbox is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    if mailbox.secret_ref != payload.secret_ref:
        sessions = list(
            db.scalars(
                select(MailSession)
                .where(
                    MailSession.mailbox_id == mailbox.id,
                    MailSession.tenant_id == principal.tenant_id,
                    MailSession.status.in_(_RELEASABLE_MAIL_SESSION_STATUSES),
                )
                .order_by(MailSession.id)
                .with_for_update()
            )
        )
        for session in sessions:
            session.status = "revoked"
            session.delivered_code = None
            session.delivered_message_id_hash = None
            session.delivered_at = None
            session.code_expires_at = None
            session.start_watermark = None
            session.last_message_hash = None
            record_audit(
                db,
                tenant_id=session.tenant_id,
                user_id=session.user_id,
                device_id=session.device_id,
                actor_id=principal.user_id,
                event_type="mail_session.revoked",
                entity_type="mail_session",
                entity_id=session.id,
                trace_id=session.trace_id,
                details={
                    "task_id": session.task_id,
                    "reason": "admin_mailbox_secret_rotated",
                },
            )
        mailbox.secret_ref = payload.secret_ref
        reset_mailbox_health(mailbox)
        record_audit(
            db,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            device_id=principal.device_id,
            event_type="admin.mailbox_secret_rotated",
            entity_type="mailbox",
            entity_id=mailbox.id,
            trace_id=request.state.trace_id,
            details={"rotation": "completed", "revoked_session_count": len(sessions)},
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Mailbox secret reference already exists"
            ) from None
        db.refresh(mailbox)
    active_session_count = db.scalar(
        select(func.count())
        .select_from(MailSession)
        .where(
            MailSession.mailbox_id == mailbox.id,
            MailSession.status.in_(_ACTIVE_MAIL_SESSION_STATUSES),
            MailSession.expires_at > _utc_now(),
        )
    )
    return _mailbox_status_response(
        mailbox, active_session_count=int(active_session_count or 0)
    )


@router.get(
    "/admin/uploads",
    response_model=list[AdminUploadResponse],
    tags=["admin"],
)
def admin_list_uploads(
    principal: AuthPrincipal = Depends(
        require_roles(ROLE_OPS_ADMIN, ROLE_SECURITY_AUDITOR, ROLE_PLATFORM_ADMIN)
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


def _operational_policy_record_response(
    policy: OperationalPolicyVersion,
) -> MailPolicyVersionResponse | CardPolicyVersionResponse:
    common = {
        "id": policy.id,
        "version": policy.version,
        "status": policy.status,
        "change_note": policy.change_note,
        "created_by": policy.created_by,
        "approved_by": policy.approved_by,
        "approved_at": policy.approved_at,
        "created_at": policy.created_at,
    }
    if policy.domain == "mail":
        if (
            policy.session_ttl_seconds is None
            or policy.code_ttl_seconds is None
            or policy.poll_interval_seconds is None
        ):
            raise HTTPException(status_code=409, detail="Mail policy snapshot is incomplete")
        return MailPolicyVersionResponse(
            **common,
            session_ttl_seconds=policy.session_ttl_seconds,
            code_ttl_seconds=policy.code_ttl_seconds,
            poll_interval_seconds=policy.poll_interval_seconds,
        )
    if (
        policy.lease_ttl_seconds is None
        or policy.reveal_ttl_seconds is None
        or policy.allocation_order != "oldest_available"
        or policy.selection_rules_json is None
    ):
        raise HTTPException(status_code=409, detail="Card policy snapshot is incomplete")
    try:
        selection_rules = [
            CardSelectionRule.model_validate(item)
            for item in json.loads(policy.selection_rules_json)
        ]
    except (json.JSONDecodeError, TypeError, ValueError):
        raise HTTPException(
            status_code=409, detail="Card policy selection rules are invalid"
        ) from None
    if not selection_rules or len({rule.task_type for rule in selection_rules}) != len(
        selection_rules
    ):
        raise HTTPException(
            status_code=409, detail="Card policy selection rules are invalid"
        )
    return CardPolicyVersionResponse(
        **common,
        lease_ttl_seconds=policy.lease_ttl_seconds,
        reveal_ttl_seconds=policy.reveal_ttl_seconds,
        allocation_order="oldest_available",
        selection_rules=selection_rules,
    )


def _operational_policy_status(
    db: Session, *, tenant_id: str, domain: Literal["mail", "card"]
) -> OperationalPolicyStatusResponse:
    deployment = db.scalar(
        select(OperationalPolicyDeployment).where(
            OperationalPolicyDeployment.tenant_id == tenant_id,
            OperationalPolicyDeployment.domain == domain,
        )
    )
    active = (
        db.get(OperationalPolicyVersion, deployment.active_policy_id)
        if deployment is not None
        else None
    )
    previous = (
        db.get(OperationalPolicyVersion, deployment.previous_policy_id)
        if deployment is not None and deployment.previous_policy_id is not None
        else None
    )
    return OperationalPolicyStatusResponse(
        domain=domain,
        governance_configured=deployment is not None,
        active_version=active.version if active is not None else None,
        previous_version=previous.version if previous is not None else None,
        rollout_percent=deployment.rollout_percent if deployment is not None else None,
    )


def _operational_policy_deployment_response(
    db: Session, deployment: OperationalPolicyDeployment
) -> OperationalPolicyDeploymentResponse:
    active = db.get(OperationalPolicyVersion, deployment.active_policy_id)
    previous = (
        db.get(OperationalPolicyVersion, deployment.previous_policy_id)
        if deployment.previous_policy_id is not None
        else None
    )
    if active is None:
        raise HTTPException(status_code=409, detail="Active policy snapshot is missing")
    return OperationalPolicyDeploymentResponse(
        domain=deployment.domain,
        active_version=active.version,
        previous_version=previous.version if previous is not None else None,
        rollout_percent=deployment.rollout_percent,
        updated_at=deployment.updated_at,
    )


def _list_operational_policy_versions(
    db: Session, *, tenant_id: str, domain: Literal["mail", "card"]
) -> list[MailPolicyVersionResponse | CardPolicyVersionResponse]:
    policies = db.scalars(
        select(OperationalPolicyVersion)
        .where(
            OperationalPolicyVersion.tenant_id == tenant_id,
            OperationalPolicyVersion.domain == domain,
        )
        .order_by(OperationalPolicyVersion.created_at.desc())
    ).all()
    return [_operational_policy_record_response(policy) for policy in policies]


def _register_operational_policy(
    *,
    domain: Literal["mail", "card"],
    payload: MailPolicyVersionCreate | CardPolicyVersionCreate,
    request: Request,
    principal: AuthPrincipal,
    db: Session,
) -> MailPolicyVersionResponse | CardPolicyVersionResponse:
    values: dict[str, Any] = {
        "tenant_id": principal.tenant_id,
        "domain": domain,
        "version": payload.version,
        "status": "draft",
        "change_note": payload.change_note.strip(),
        "created_by": principal.user_id,
    }
    if domain == "mail" and isinstance(payload, MailPolicyVersionCreate):
        values.update(
            session_ttl_seconds=payload.session_ttl_seconds,
            code_ttl_seconds=payload.code_ttl_seconds,
            poll_interval_seconds=payload.poll_interval_seconds,
        )
    elif domain == "card" and isinstance(payload, CardPolicyVersionCreate):
        values.update(
            lease_ttl_seconds=payload.lease_ttl_seconds,
            reveal_ttl_seconds=payload.reveal_ttl_seconds,
            allocation_order=payload.allocation_order,
            selection_rules_json=json.dumps(
                [rule.model_dump(mode="json") for rule in payload.selection_rules],
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    else:
        raise HTTPException(status_code=422, detail="Policy payload does not match domain")
    policy = OperationalPolicyVersion(**values)
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Policy version already exists for this tenant and domain"
        ) from None
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type=f"{domain}_policy.registered",
        entity_type=f"{domain}_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return _operational_policy_record_response(policy)


def _approve_operational_policy(
    *,
    domain: Literal["mail", "card"],
    policy_id: str,
    request: Request,
    principal: AuthPrincipal,
    db: Session,
) -> MailPolicyVersionResponse | CardPolicyVersionResponse:
    policy = db.scalar(
        select(OperationalPolicyVersion).where(
            OperationalPolicyVersion.id == policy_id,
            OperationalPolicyVersion.tenant_id == principal.tenant_id,
            OperationalPolicyVersion.domain == domain,
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
        event_type=f"{domain}_policy.approved",
        entity_type=f"{domain}_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return _operational_policy_record_response(policy)


def _deploy_operational_policy(
    *,
    domain: Literal["mail", "card"],
    policy_id: str,
    payload: OperationalPolicyDeployRequest,
    request: Request,
    principal: AuthPrincipal,
    db: Session,
) -> OperationalPolicyDeploymentResponse:
    policy = db.scalar(
        select(OperationalPolicyVersion).where(
            OperationalPolicyVersion.id == policy_id,
            OperationalPolicyVersion.tenant_id == principal.tenant_id,
            OperationalPolicyVersion.domain == domain,
        ).with_for_update()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    if policy.status not in {"approved", "active"}:
        raise HTTPException(status_code=409, detail="Policy must be approved before deployment")
    deployment = db.scalar(
        select(OperationalPolicyDeployment).where(
            OperationalPolicyDeployment.tenant_id == principal.tenant_id,
            OperationalPolicyDeployment.domain == domain,
        ).with_for_update()
    )
    if deployment is None:
        if payload.rollout_percent != 100:
            raise HTTPException(
                status_code=409, detail="The first deployment must use 100 percent rollout"
            )
        deployment = OperationalPolicyDeployment(
            tenant_id=principal.tenant_id,
            domain=domain,
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
        if payload.rollout_percent != 100:
            previous = db.get(OperationalPolicyVersion, deployment.previous_policy_id)
            if previous is None or previous.status != "active":
                raise HTTPException(
                    status_code=409,
                    detail="A completed rollout cannot be reopened; use rollback",
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
        current = db.get(OperationalPolicyVersion, deployment.active_policy_id)
        deployment.previous_policy_id = deployment.active_policy_id
        deployment.active_policy_id = policy.id
        deployment.rollout_percent = payload.rollout_percent
        deployment.updated_by = principal.user_id
        deployment.updated_at = _utc_now()
        if current is not None:
            current.status = "active" if payload.rollout_percent < 100 else "retired"
    policy.status = "active"
    if payload.rollout_percent == 100 and deployment.previous_policy_id is not None:
        previous = db.get(OperationalPolicyVersion, deployment.previous_policy_id)
        if previous is not None and previous.id != policy.id:
            previous.status = "retired"
    record_audit(
        db,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        device_id=principal.device_id,
        event_type=f"{domain}_policy.deployed",
        entity_type=f"{domain}_policy",
        entity_id=policy.id,
        trace_id=request.state.trace_id,
        details={"version": policy.version, "rollout_percent": payload.rollout_percent},
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy deployment changed concurrently") from None
    db.refresh(deployment)
    return _operational_policy_deployment_response(db, deployment)


def _rollback_operational_policy(
    *,
    domain: Literal["mail", "card"],
    request: Request,
    principal: AuthPrincipal,
    db: Session,
) -> OperationalPolicyDeploymentResponse:
    deployment = db.scalar(
        select(OperationalPolicyDeployment).where(
            OperationalPolicyDeployment.tenant_id == principal.tenant_id,
            OperationalPolicyDeployment.domain == domain,
        ).with_for_update()
    )
    if deployment is None or deployment.previous_policy_id is None:
        raise HTTPException(status_code=409, detail="No previous policy is available")
    current = db.get(OperationalPolicyVersion, deployment.active_policy_id)
    previous = db.get(OperationalPolicyVersion, deployment.previous_policy_id)
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
        event_type=f"{domain}_policy.rolled_back",
        entity_type=f"{domain}_policy",
        entity_id=previous.id,
        trace_id=request.state.trace_id,
        details={"version": previous.version, "replaced_version": current.version},
    )
    db.commit()
    db.refresh(deployment)
    return _operational_policy_deployment_response(db, deployment)


@router.get("/admin/policies/mail", response_model=OperationalPolicyStatusResponse, tags=["admin"])
def admin_mail_policy_status(
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyStatusResponse:
    return _operational_policy_status(db, tenant_id=principal.tenant_id, domain="mail")


@router.get("/admin/policies/mail/versions", response_model=list[MailPolicyVersionResponse], tags=["admin"])
def admin_list_mail_policy_versions(
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> list[MailPolicyVersionResponse]:
    return _list_operational_policy_versions(db, tenant_id=principal.tenant_id, domain="mail")  # type: ignore[return-value]


@router.post("/admin/policies/mail/versions", response_model=MailPolicyVersionResponse, status_code=201, tags=["admin"])
def admin_register_mail_policy_version(
    payload: MailPolicyVersionCreate,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> MailPolicyVersionResponse:
    return _register_operational_policy(domain="mail", payload=payload, request=request, principal=principal, db=db)  # type: ignore[return-value]


@router.post("/admin/policies/mail/versions/{policy_id}/approve", response_model=MailPolicyVersionResponse, tags=["admin"])
def admin_approve_mail_policy_version(
    policy_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> MailPolicyVersionResponse:
    return _approve_operational_policy(domain="mail", policy_id=policy_id, request=request, principal=principal, db=db)  # type: ignore[return-value]


@router.post("/admin/policies/mail/versions/{policy_id}/deploy", response_model=OperationalPolicyDeploymentResponse, tags=["admin"])
def admin_deploy_mail_policy_version(
    policy_id: str,
    payload: OperationalPolicyDeployRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyDeploymentResponse:
    return _deploy_operational_policy(domain="mail", policy_id=policy_id, payload=payload, request=request, principal=principal, db=db)


@router.post("/admin/policies/mail/rollback", response_model=OperationalPolicyDeploymentResponse, tags=["admin"])
def admin_rollback_mail_policy(
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyDeploymentResponse:
    return _rollback_operational_policy(domain="mail", request=request, principal=principal, db=db)


@router.get("/admin/policies/card", response_model=OperationalPolicyStatusResponse, tags=["admin"])
def admin_card_policy_status(
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyStatusResponse:
    return _operational_policy_status(db, tenant_id=principal.tenant_id, domain="card")


@router.get("/admin/policies/card/versions", response_model=list[CardPolicyVersionResponse], tags=["admin"])
def admin_list_card_policy_versions(
    principal: AuthPrincipal = Depends(require_roles(ROLE_OPS_ADMIN, ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> list[CardPolicyVersionResponse]:
    return _list_operational_policy_versions(db, tenant_id=principal.tenant_id, domain="card")  # type: ignore[return-value]


@router.post("/admin/policies/card/versions", response_model=CardPolicyVersionResponse, status_code=201, tags=["admin"])
def admin_register_card_policy_version(
    payload: CardPolicyVersionCreate,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> CardPolicyVersionResponse:
    return _register_operational_policy(domain="card", payload=payload, request=request, principal=principal, db=db)  # type: ignore[return-value]


@router.post("/admin/policies/card/versions/{policy_id}/approve", response_model=CardPolicyVersionResponse, tags=["admin"])
def admin_approve_card_policy_version(
    policy_id: str,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> CardPolicyVersionResponse:
    return _approve_operational_policy(domain="card", policy_id=policy_id, request=request, principal=principal, db=db)  # type: ignore[return-value]


@router.post("/admin/policies/card/versions/{policy_id}/deploy", response_model=OperationalPolicyDeploymentResponse, tags=["admin"])
def admin_deploy_card_policy_version(
    policy_id: str,
    payload: OperationalPolicyDeployRequest,
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyDeploymentResponse:
    return _deploy_operational_policy(domain="card", policy_id=policy_id, payload=payload, request=request, principal=principal, db=db)


@router.post("/admin/policies/card/rollback", response_model=OperationalPolicyDeploymentResponse, tags=["admin"])
def admin_rollback_card_policy(
    request: Request,
    principal: AuthPrincipal = Depends(require_roles(ROLE_PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
) -> OperationalPolicyDeploymentResponse:
    return _rollback_operational_policy(domain="card", request=request, principal=principal, db=db)


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
    governance_configured = bool(
        active is not None
        and active.tenant_id == principal.tenant_id
        and active.status == "active"
        and active.approved_by is not None
        and active.approved_at is not None
    )
    managed_environment = settings.environment.strip().lower() not in {
        "development",
        "test",
    }
    ready = ready and (governance_configured or not managed_environment)
    return UploadPolicyStatusResponse(
        policy_version=active.version if active is not None else settings.sub2_policy_version,
        status="ready" if ready else "not_configured",
        upload_endpoint_configured=upload_endpoint_configured,
        upload_secret_configured=upload_secret_configured,
        network_route_configured=network_route_configured,
        governance_configured=governance_configured,
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
        if payload.rollout_percent != 100:
            previous = db.get(UploadPolicyVersion, deployment.previous_policy_id)
            if previous is None or previous.status != "active":
                raise HTTPException(
                    status_code=409,
                    detail="A completed rollout cannot be reopened; use rollback",
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
