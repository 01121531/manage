"""Pure, secret-free execution records for secure pool imports."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from typing import Literal
from uuid import UUID


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROHIBITED_KEYS = {
    "contains_raw_input_hash",
    "contains_raw_input_path",
    "contains_pool_secret",
    "contains_vault_token",
    "contains_vault_response_body",
    "contains_transit_signature",
    "contains_receipt_token",
}
_PLAN_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "execution_id",
    "pool_type",
    "item_count",
    "vault_origin_sha256",
    "tenant_scope_sha256",
    "audience_sha256",
    "ordered_manifest_digest",
    "items",
    "created_at",
    "recovery_action",
    "prohibited_content",
}
_EVENT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "execution_id",
    "plan_payload_sha256",
    "event_type",
    "index",
    "artifact_sha256",
    "occurred_at",
    "prohibited_content",
}
_EVENT_TYPES = {
    "vault_write_intent",
    "vault_write_confirmed",
    "bundle_publish_intent",
    "execution_complete",
}


def canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_timestamp(value: str) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _prohibited_content() -> dict[str, object]:
    return {key: False for key in sorted(_PROHIBITED_KEYS)}


def seal_payload(payload: dict[str, object]) -> dict[str, object]:
    document = dict(payload)
    document["integrity"] = {
        "payload_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest()
    }
    return document


def _sealed_errors(document: object, expected_keys: set[str]) -> list[str]:
    if not isinstance(document, dict) or set(document) != expected_keys | {"integrity"}:
        return ["secure pool import execution schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    expected = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or integrity.get("payload_sha256") != expected
    ):
        return ["secure pool import execution integrity is invalid"]
    return []


def plan_payload_sha256(plan: dict[str, object]) -> str:
    integrity = plan.get("integrity")
    if not isinstance(integrity, dict):
        return ""
    value = integrity.get("payload_sha256")
    return value if isinstance(value, str) else ""


def build_execution_plan(
    *,
    execution_id: str,
    pool_type: Literal["card", "mailbox"],
    vault_origin: str,
    tenant_id: str,
    audience: str,
    ordered_manifest_digest: str,
    secret_refs: list[str],
    created_at: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "secure_pool_import_execution_plan",
        "production_acceptance": False,
        "execution_id": execution_id,
        "pool_type": pool_type,
        "item_count": len(secret_refs),
        "vault_origin_sha256": _sha256_text(vault_origin),
        "tenant_scope_sha256": _sha256_text(tenant_id),
        "audience_sha256": _sha256_text(audience),
        "ordered_manifest_digest": ordered_manifest_digest,
        "items": [
            {
                "index": index,
                "secret_ref_sha256": _sha256_text(secret_ref),
            }
            for index, secret_ref in enumerate(secret_refs)
        ],
        "created_at": created_at,
        "recovery_action": "read_only_assessment_no_automatic_resume",
        "prohibited_content": _prohibited_content(),
    }
    document = seal_payload(payload)
    if execution_plan_errors(document):
        raise ValueError("secure pool import execution plan is invalid")
    return document


def execution_plan_errors(document: object) -> list[str]:
    errors = _sealed_errors(document, _PLAN_KEYS)
    if errors or not isinstance(document, dict):
        return errors
    try:
        source_execution_id = document.get("execution_id")
        execution_id = str(UUID(str(source_execution_id)))
        if execution_id != source_execution_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        execution_id = ""
        errors.append("secure pool import execution identity is invalid")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "secure_pool_import_execution_plan"
        or document.get("production_acceptance") is not False
        or document.get("pool_type") not in {"card", "mailbox"}
        or document.get("recovery_action")
        != "read_only_assessment_no_automatic_resume"
    ):
        errors.append("secure pool import execution plan identity is invalid")
    item_count = document.get("item_count")
    if type(item_count) is not int or not 1 <= item_count <= 100:
        errors.append("secure pool import execution item count is invalid")
        item_count = 0
    for name in (
        "vault_origin_sha256",
        "tenant_scope_sha256",
        "audience_sha256",
        "ordered_manifest_digest",
    ):
        if not isinstance(document.get(name), str) or _SHA256.fullmatch(document[name]) is None:
            errors.append(f"secure pool import execution {name} is invalid")
    items = document.get("items")
    if (
        not isinstance(items, list)
        or len(items) != item_count
        or any(
            not isinstance(item, dict)
            or set(item) != {"index", "secret_ref_sha256"}
            or item.get("index") != index
            or not isinstance(item.get("secret_ref_sha256"), str)
            or _SHA256.fullmatch(item["secret_ref_sha256"]) is None
            for index, item in enumerate(items if isinstance(items, list) else [])
        )
    ):
        errors.append("secure pool import execution item inventory is invalid")
    if not _utc_timestamp(document.get("created_at")):
        errors.append("secure pool import execution created_at is invalid")
    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("secure pool import execution redaction claim is invalid")
    if not execution_id:
        return errors
    return errors


def build_execution_event(
    plan: dict[str, object],
    *,
    event_type: Literal[
        "vault_write_intent",
        "vault_write_confirmed",
        "bundle_publish_intent",
        "execution_complete",
    ],
    index: int | None,
    artifact_sha256: str | None,
    occurred_at: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "secure_pool_import_execution_event",
        "production_acceptance": False,
        "execution_id": plan["execution_id"],
        "plan_payload_sha256": plan_payload_sha256(plan),
        "event_type": event_type,
        "index": index,
        "artifact_sha256": artifact_sha256,
        "occurred_at": occurred_at,
        "prohibited_content": _prohibited_content(),
    }
    document = seal_payload(payload)
    if execution_event_errors(document, plan):
        raise ValueError("secure pool import execution event is invalid")
    return document


def execution_event_errors(
    document: object,
    plan: dict[str, object],
) -> list[str]:
    errors = _sealed_errors(document, _EVENT_KEYS)
    if errors or not isinstance(document, dict):
        return errors
    event_type = document.get("event_type")
    index = document.get("index")
    artifact = document.get("artifact_sha256")
    item_count = plan.get("item_count")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "secure_pool_import_execution_event"
        or document.get("production_acceptance") is not False
        or document.get("execution_id") != plan.get("execution_id")
        or document.get("plan_payload_sha256") != plan_payload_sha256(plan)
        or event_type not in _EVENT_TYPES
    ):
        errors.append("secure pool import execution event identity is invalid")
    if event_type in {"vault_write_intent", "vault_write_confirmed"}:
        if (
            type(index) is not int
            or type(item_count) is not int
            or not 0 <= index < item_count
            or artifact is not None
        ):
            errors.append("secure pool import execution write event is invalid")
    elif event_type == "bundle_publish_intent":
        if index is not None or artifact is not None:
            errors.append("secure pool import execution bundle intent is invalid")
    elif event_type == "execution_complete":
        if index is not None or not isinstance(artifact, str) or _SHA256.fullmatch(artifact) is None:
            errors.append("secure pool import execution completion is invalid")
    if not _utc_timestamp(document.get("occurred_at")):
        errors.append("secure pool import execution event time is invalid")
    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("secure pool import execution event redaction claim is invalid")
    return errors


def classify_execution(
    plan: dict[str, object],
    events: dict[str, dict[str, object]],
    *,
    bundle_state: Literal["absent", "valid", "invalid"],
    bundle_sha256: str | None,
) -> dict[str, object]:
    item_count = int(plan["item_count"])
    confirmed = 0
    for index in range(item_count):
        intent_name = f"write-{index:03d}.intent.json"
        confirmed_name = f"write-{index:03d}.confirmed.json"
        intent = events.get(intent_name)
        confirmation = events.get(confirmed_name)
        if confirmation is not None and intent is None:
            return _assessment("commit_unknown", "confirmation_without_intent", confirmed, index)
        if intent is None:
            if any(
                name in events
                for later in range(index + 1, item_count)
                for name in (
                    f"write-{later:03d}.intent.json",
                    f"write-{later:03d}.confirmed.json",
                )
            ):
                return _assessment("commit_unknown", "non_contiguous_write_records", confirmed, index)
            status = "unwritten" if confirmed == 0 else "partial_written"
            phase = "no_vault_mutation_attempted" if confirmed == 0 else "confirmed_prefix_only"
            return _assessment(status, phase, confirmed, None)
        if confirmation is None:
            return _assessment("commit_unknown", "vault_write_commit_unknown", confirmed, index)
        confirmed += 1

    bundle_intent = events.get("bundle.intent.json")
    completion = events.get("complete.json")
    if completion is not None and bundle_intent is None:
        return _assessment("commit_unknown", "completion_without_bundle_intent", confirmed, None)
    if bundle_intent is None:
        return _assessment(
            "partial_written",
            "all_vault_writes_confirmed_receipt_missing",
            confirmed,
            None,
        )
    if bundle_state != "valid" or completion is None:
        return _assessment("commit_unknown", "bundle_publication_commit_unknown", confirmed, None)
    if completion.get("artifact_sha256") != bundle_sha256:
        return _assessment("commit_unknown", "bundle_completion_binding_invalid", confirmed, None)
    return _assessment("completed", "bundle_and_execution_complete", confirmed, None)


def _assessment(
    status: str,
    phase: str,
    confirmed_count: int,
    unknown_index: int | None,
) -> dict[str, object]:
    return {
        "status": status,
        "phase": phase,
        "confirmed_count": confirmed_count,
        "unknown_index": unknown_index,
        "production_acceptance": False,
        "automatic_resume_allowed": False,
    }
