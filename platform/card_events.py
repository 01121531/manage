"""Masked, append-only card lifecycle event helpers."""

from collections.abc import Mapping
import json
import re
from typing import Any

from sqlalchemy.orm import Session

from platform.json_boundary import JsonBoundaryError, parse_persisted_json_text
from platform.models import CardEvent


_CARD_MASK_PATTERN = re.compile(r"^\*{4} \*{4} \*{4} \d{4}$")
_CARD_BRAND_PATTERN = re.compile(r"^[A-Za-z][A-Za-z ._-]{0,39}$")
_CARD_STATUSES = frozenset({"available", "allocated", "disabled", "quarantined"})
_ALLOCATION_STATUSES = frozenset({"active", "released", "expired"})
_REVEAL_FIELDS = frozenset({"pan", "expiry"})


def _project_masked_state(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep only the small, typed state vocabulary safe for card history."""

    if not isinstance(value, Mapping):
        return {}
    projected: dict[str, Any] = {}

    card_masked = value.get("card_masked")
    if isinstance(card_masked, str) and _CARD_MASK_PATTERN.fullmatch(card_masked):
        projected["card_masked"] = card_masked

    brand = value.get("brand")
    if isinstance(brand, str) and _CARD_BRAND_PATTERN.fullmatch(brand):
        projected["brand"] = brand

    card_status = value.get("card_status")
    if isinstance(card_status, str) and card_status in _CARD_STATUSES:
        projected["card_status"] = card_status

    allocation_status = value.get("allocation_status")
    if isinstance(allocation_status, str) and allocation_status in _ALLOCATION_STATUSES:
        projected["allocation_status"] = allocation_status

    revealed = value.get("revealed")
    if isinstance(revealed, bool):
        projected["revealed"] = revealed

    fields = value.get("fields")
    if isinstance(fields, list):
        safe_fields = [
            field for field in fields if isinstance(field, str) and field in _REVEAL_FIELDS
        ]
        if safe_fields:
            projected["fields"] = list(dict.fromkeys(safe_fields))

    return projected


def _masked_json(value: Mapping[str, Any] | None) -> str:
    projected = _project_masked_state(value)
    return json.dumps(projected, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def safe_card_event_state(value: str) -> dict[str, Any]:
    """Return a defensive masked projection for management responses."""

    try:
        parsed = parse_persisted_json_text(value)
    except JsonBoundaryError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return _project_masked_state(parsed)


def record_card_event(
    db: Session,
    *,
    tenant_id: str,
    card_id: str,
    action: str,
    trace_id: str,
    actor_id: str | None,
    allocation_id: str | None = None,
    reason_code: str | None = None,
    before_masked: Mapping[str, Any] | None = None,
    after_masked: Mapping[str, Any] | None = None,
) -> CardEvent:
    event = CardEvent(
        tenant_id=tenant_id,
        card_id=card_id,
        allocation_id=allocation_id,
        actor_id=actor_id,
        action=action,
        reason_code=reason_code,
        before_masked=_masked_json(before_masked),
        after_masked=_masked_json(after_masked),
        trace_id=trace_id,
    )
    db.add(event)
    return event


__all__ = ["record_card_event", "safe_card_event_state"]
