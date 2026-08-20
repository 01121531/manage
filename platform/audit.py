"""Structured, append-only audit writer with defensive sanitization."""

from contextvars import ContextVar, Token
import json
import re
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
_request_metadata: ContextVar[tuple[str | None, str | None]] = ContextVar(
    "audit_request_metadata", default=(None, None)
)
_PAN_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def _bounded_header(value: str | None, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    return normalized[:max_length] if normalized else None


def bind_audit_request_metadata(
    *, ip_address: str | None, user_agent: str | None
) -> Token[tuple[str | None, str | None]]:
    """Bind safe request metadata for audit calls executed in this context."""

    return _request_metadata.set(
        (
            _bounded_header(ip_address, max_length=64),
            _bounded_header(user_agent, max_length=512),
        )
    )


def reset_audit_request_metadata(
    token: Token[tuple[str | None, str | None]],
) -> None:
    _request_metadata.reset(token)


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_EXACT_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def _passes_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _sanitize_string(value: str) -> str:
    if value.lower().startswith("bearer "):
        return "[REDACTED]"
    return _PAN_CANDIDATE.sub(
        lambda match: "[REDACTED_CARD]" if _passes_luhn(match.group(0)) else match.group(0),
        value,
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
    if isinstance(value, str):
        return _sanitize_string(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)


def _result_for_event(event_type: str) -> str:
    normalized = event_type.lower()
    if "unknown" in normalized:
        return "unknown"
    if any(part in normalized for part in ("failed", "failure", "denied", "error")):
        return "failure"
    return "success"


def _policy_version(details: dict[str, Any]) -> str | None:
    candidate = details.get("policy_version")
    if candidate is None:
        candidate = details.get("version")
    if not isinstance(candidate, (str, int)):
        return None
    normalized = str(candidate).strip()
    return normalized[:80] if normalized else None


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
    actor_id: str | None = None,
    action: str | None = None,
    result: str | None = None,
    policy_version: str | None = None,
) -> AuditEvent:
    safe_details = sanitize_audit_details(details or {})
    assert isinstance(safe_details, dict)
    ip_address, user_agent = _request_metadata.get()
    event = AuditEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        device_id=device_id,
        actor_id=actor_id or user_id,
        event_type=event_type,
        action=(action or event_type)[:80],
        result=(result or _result_for_event(event_type))[:32],
        entity_type=entity_type,
        entity_id=entity_id,
        trace_id=trace_id,
        ip_address=ip_address,
        user_agent=user_agent,
        policy_version=(policy_version or _policy_version(safe_details)),
        details_json=json.dumps(
            safe_details,
            ensure_ascii=False,
            sort_keys=True,
        ),
    )
    db.add(event)
    return event


__all__ = [
    "bind_audit_request_metadata",
    "record_audit",
    "reset_audit_request_metadata",
    "sanitize_audit_details",
]
