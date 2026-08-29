"""Safe persisted health transitions for mailbox connectors."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from platform.audit import record_audit
from platform.models import Mailbox


HEALTH_UNKNOWN = "unknown"
HEALTH_HEALTHY = "healthy"
HEALTH_UNAVAILABLE = "unavailable"

CONNECTOR_NOT_CONFIGURED = "connector_not_configured"
CONNECTOR_UNAVAILABLE = "connector_unavailable"
_SAFE_ERROR_CODES = frozenset({CONNECTOR_NOT_CONFIGURED, CONNECTOR_UNAVAILABLE})


def _record_health_transition(
    db: Session,
    mailbox: Mailbox,
    *,
    previous_status: str,
    previous_error_code: str | None,
    user_id: str | None,
    device_id: str | None,
    actor_id: str | None,
    trace_id: str,
) -> None:
    if (
        mailbox.health_status == previous_status
        and mailbox.last_error_code == previous_error_code
    ):
        return
    safe_previous_status = (
        previous_status
        if previous_status in {HEALTH_UNKNOWN, HEALTH_HEALTHY, HEALTH_UNAVAILABLE}
        else HEALTH_UNKNOWN
    )
    safe_previous_error_code = (
        previous_error_code if previous_error_code in _SAFE_ERROR_CODES else None
    )
    record_audit(
        db,
        tenant_id=mailbox.tenant_id,
        user_id=user_id,
        device_id=device_id,
        actor_id=actor_id,
        event_type="mailbox.health_changed",
        entity_type="mailbox",
        entity_id=mailbox.id,
        trace_id=trace_id,
        result=(
            "failure" if mailbox.health_status == HEALTH_UNAVAILABLE else "success"
        ),
        details={
            "previous_status": safe_previous_status,
            "previous_error_code": safe_previous_error_code,
            "status": mailbox.health_status,
            "error_code": mailbox.last_error_code,
        },
    )


def mark_mailbox_healthy(
    mailbox: Mailbox,
    *,
    checked_at: datetime,
    db: Session,
    user_id: str | None,
    device_id: str | None,
    actor_id: str | None,
    trace_id: str,
) -> None:
    previous_status = mailbox.health_status
    previous_error_code = mailbox.last_error_code
    mailbox.health_status = HEALTH_HEALTHY
    mailbox.last_checked_at = checked_at
    mailbox.last_error_code = None
    _record_health_transition(
        db,
        mailbox,
        previous_status=previous_status,
        previous_error_code=previous_error_code,
        user_id=user_id,
        device_id=device_id,
        actor_id=actor_id,
        trace_id=trace_id,
    )


def mark_mailbox_unavailable(
    mailbox: Mailbox,
    *,
    checked_at: datetime,
    error_code: str,
    db: Session,
    user_id: str | None,
    device_id: str | None,
    actor_id: str | None,
    trace_id: str,
) -> None:
    previous_status = mailbox.health_status
    previous_error_code = mailbox.last_error_code
    mailbox.health_status = HEALTH_UNAVAILABLE
    mailbox.last_checked_at = checked_at
    mailbox.last_error_code = (
        error_code if error_code in _SAFE_ERROR_CODES else CONNECTOR_UNAVAILABLE
    )
    _record_health_transition(
        db,
        mailbox,
        previous_status=previous_status,
        previous_error_code=previous_error_code,
        user_id=user_id,
        device_id=device_id,
        actor_id=actor_id,
        trace_id=trace_id,
    )


def reset_mailbox_health(mailbox: Mailbox) -> None:
    mailbox.health_status = HEALTH_UNKNOWN
    mailbox.last_checked_at = None
    mailbox.last_error_code = None


__all__ = [
    "CONNECTOR_NOT_CONFIGURED",
    "CONNECTOR_UNAVAILABLE",
    "HEALTH_HEALTHY",
    "HEALTH_UNAVAILABLE",
    "HEALTH_UNKNOWN",
    "mark_mailbox_healthy",
    "mark_mailbox_unavailable",
    "reset_mailbox_health",
]
