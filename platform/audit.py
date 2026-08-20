"""Minimal structured audit writer with defensive detail sanitization."""

import json
from typing import Any

from sqlalchemy.orm import Session

from platform.models import AuditEvent


_SENSITIVE_KEY_PARTS = (
    "authorization",
    "card_number",
    "cardnumber",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)
_SENSITIVE_EXACT_KEYS = frozenset({"pan", "cvv", "cvc", "security_code"})


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_EXACT_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): sanitize_audit_details(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, str) and value.lower().startswith("bearer "):
        return "[REDACTED]"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def record_audit(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    device_id: str | None,
    event_type: str,
    entity_type: str,
    entity_id: str | None,
    trace_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        device_id=device_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        trace_id=trace_id,
        details_json=json.dumps(
            sanitize_audit_details(details or {}),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )
    db.add(event)
    return event
