"""Structured, append-only audit writer with defensive sanitization."""

from collections.abc import Mapping
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from math import isfinite
import re
from typing import Any, TypedDict

from sqlalchemy.orm import Session

from platform.json_boundary import JsonBoundaryError, parse_persisted_json_text
from platform.models import AuditEvent


AUDIT_ARCHIVE_SCHEMA_VERSION = "audit-event-archive.v1"
AUDIT_REDACTION_VERSION = "audit-read.v1"


class AuditArchiveRecordV1(TypedDict):
    schema_version: str
    redaction_version: str
    id: str
    tenant_id: str
    created_at: str
    actor_id: str | None
    user_id: str | None
    device_id: str | None
    event_type: str
    action: str
    result: str
    entity_type: str
    entity_id: str | None
    trace_id: str
    policy_version: str | None
    ip_address: str | None
    user_agent: str | None
    details: dict[str, Any]


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
_UUID_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])"
)
_AUDIT_STRING_SENSITIVE = re.compile(
    r"(?:\bauthorization\s*[:=]|\bbearer\b|\bvault://)", re.IGNORECASE
)


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
            sanitize_audit_ip_address(ip_address),
            sanitize_audit_user_agent(user_agent),
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


def _uuid_spans(value: str) -> tuple[tuple[int, int], ...]:
    return tuple(match.span() for match in _UUID_CANDIDATE.finditer(value))


def _is_inside_uuid(
    match: re.Match[str], uuid_spans: tuple[tuple[int, int], ...]
) -> bool:
    start, end = match.span()
    return any(uuid_start <= start and end <= uuid_end for uuid_start, uuid_end in uuid_spans)


def _contains_luhn_pan(value: str) -> bool:
    uuid_spans = _uuid_spans(value)
    return any(
        not _is_inside_uuid(match, uuid_spans) and _passes_luhn(match.group(0))
        for match in _PAN_CANDIDATE.finditer(value)
    )


def _redact_luhn_pans(value: str) -> str:
    uuid_spans = _uuid_spans(value)
    return _PAN_CANDIDATE.sub(
        lambda match: (
            match.group(0)
            if _is_inside_uuid(match, uuid_spans)
            else "[REDACTED_CARD]"
            if _passes_luhn(match.group(0))
            else match.group(0)
        ),
        value,
    )


def sanitize_audit_ip_address(value: str | None) -> str | None:
    normalized = _bounded_header(value, max_length=64)
    if normalized is None:
        return None
    try:
        return str(ip_address(normalized))
    except ValueError:
        return None


def sanitize_audit_user_agent(value: str | None) -> str | None:
    normalized = _bounded_header(value, max_length=512)
    if normalized is None:
        return None
    if _AUDIT_STRING_SENSITIVE.search(normalized) or _contains_luhn_pan(normalized):
        return "[REDACTED]"
    return normalized


def _sanitize_string(value: str) -> str:
    if _AUDIT_STRING_SENSITIVE.search(value):
        return "[REDACTED]"
    return _redact_luhn_pans(value)


def sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            _sanitize_string(str(key)): sanitize_audit_details(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, float):
        return value if isfinite(value) else None
    if value is None or isinstance(value, (int, bool)):
        return value
    return str(value)


def safe_audit_details(event: AuditEvent) -> dict[str, Any]:
    """Parse and sanitize persisted details, including legacy dirty rows."""

    try:
        value = parse_persisted_json_text(event.details_json)
        if not isinstance(value, dict):
            return {}
        sanitized = sanitize_audit_details(value)
    except (JsonBoundaryError, RecursionError):
        return {}
    return sanitized if isinstance(sanitized, dict) else {}


def _safe_audit_details_object(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    try:
        sanitized = sanitize_audit_details(value)
    except RecursionError:
        return {}
    return sanitized if isinstance(sanitized, dict) else {}


def _required_string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("audit archive string field must be a string")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _required_string(value)


def _archive_string(value: object) -> str:
    value = _required_string(value)
    return _sanitize_string(value)


def _archive_optional_string(value: object) -> str | None:
    value = _optional_string(value)
    return _archive_string(value) if value is not None else None


def _archive_timestamp(value: object) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise TypeError("audit archive created_at must be a datetime or ISO timestamp")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _audit_source_value(
    event: AuditEvent | Mapping[str, object], field: str
) -> object:
    if isinstance(event, Mapping):
        return event[field]
    return getattr(event, field)


def project_audit_event(
    event: AuditEvent | Mapping[str, object],
) -> AuditArchiveRecordV1:
    """Return the stable, read-sanitized audit archive v1 projection."""

    details = (
        _safe_audit_details_object(event["details"])
        if isinstance(event, Mapping)
        else safe_audit_details(event)
    )
    ip_address_value = _optional_string(_audit_source_value(event, "ip_address"))
    user_agent_value = _optional_string(_audit_source_value(event, "user_agent"))
    return {
        "schema_version": AUDIT_ARCHIVE_SCHEMA_VERSION,
        "redaction_version": AUDIT_REDACTION_VERSION,
        "id": _archive_string(_audit_source_value(event, "id")),
        "tenant_id": _archive_string(_audit_source_value(event, "tenant_id")),
        "created_at": _archive_timestamp(_audit_source_value(event, "created_at")),
        "actor_id": _archive_optional_string(_audit_source_value(event, "actor_id")),
        "user_id": _archive_optional_string(_audit_source_value(event, "user_id")),
        "device_id": _archive_optional_string(_audit_source_value(event, "device_id")),
        "event_type": _archive_string(_audit_source_value(event, "event_type")),
        "action": _archive_string(_audit_source_value(event, "action")),
        "result": _archive_string(_audit_source_value(event, "result")),
        "entity_type": _archive_string(_audit_source_value(event, "entity_type")),
        "entity_id": _archive_optional_string(_audit_source_value(event, "entity_id")),
        "trace_id": _archive_string(_audit_source_value(event, "trace_id")),
        "policy_version": _archive_optional_string(
            _audit_source_value(event, "policy_version")
        ),
        "ip_address": sanitize_audit_ip_address(ip_address_value),
        "user_agent": sanitize_audit_user_agent(user_agent_value),
        "details": details,
    }


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
    aggregate_sequence: int | None = None,
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
        aggregate_sequence=aggregate_sequence,
        details_json=json.dumps(
            safe_details,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
        ),
    )
    db.add(event)
    return event


__all__ = [
    "AUDIT_ARCHIVE_SCHEMA_VERSION",
    "AUDIT_REDACTION_VERSION",
    "AuditArchiveRecordV1",
    "bind_audit_request_metadata",
    "project_audit_event",
    "record_audit",
    "reset_audit_request_metadata",
    "safe_audit_details",
    "sanitize_audit_ip_address",
    "sanitize_audit_details",
    "sanitize_audit_user_agent",
]
