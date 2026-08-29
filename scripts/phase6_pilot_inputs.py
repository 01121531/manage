"""Validate the sealed, metadata-only Phase 6 pilot input inventory."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.training_evidence import REQUIRED_ROLES as TRAINING_ROLES


INVENTORY = (
    ROOT / "deploy" / "inventory-envelopes" / "phase6-pilot-inputs.synthetic.json"
)

REQUIRED_ROLE_RESPONSIBILITIES = {
    "operator": "execute_end_to_end_pilot",
    "ops_admin": "reconcile_ambiguous_uploads_without_blind_retry",
    "security_auditor": "independently_review_alerts_and_audit_traces",
    "platform_admin": "govern_deployment_rollback_and_device_controls",
}

_PAYLOAD_KEYS = {
    "schema_version",
    "record_type",
    "inventory_reference",
    "synthetic",
    "inventory_status",
    "review_reference",
    "production_acceptance",
    "environment",
    "bindings",
    "pilot_roles",
    "ownership",
    "maintenance_window",
    "prohibited_content",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_BINDING_KEYS = {
    "release_tag",
    "release_commit",
    "container_manifest_sha256",
    "target_platform_inventory_sha256",
}
_ROLE_KEYS = {"participant_reference", "roster_entry_reference", "responsibility"}
_OWNERSHIP_KEYS = {
    "pilot_coordinator_reference",
    "target_operator_owner_reference",
    "alert_receiver_owner_reference",
    "maintenance_owner_reference",
}
_WINDOW_KEYS = {
    "change_reference",
    "approval_reference",
    "starts_at",
    "rollback_decision_deadline",
    "finishes_at",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_names",
    "contains_email_addresses",
    "contains_phone_numbers",
    "contains_token_values",
    "contains_pan_or_cvv_values",
    "contains_verification_code_values",
}
_INTEGRITY_KEYS = {"payload_sha256"}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PLACEHOLDERS = {"example", "local", "placeholder", "tbd", "test", "todo", "unknown"}
_FORBIDDEN_REFERENCE_FRAGMENT = re.compile(
    r"(?:^|[._:-])(?:password|passwd|bearer|authorization|api[-_]?key|secret|"
    r"credential|cvv|pan|token|email|phone|name)(?:$|[._:-])",
    re.IGNORECASE,
)


def _canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
        and _FORBIDDEN_REFERENCE_FRAGMENT.search(value) is None
    )


def _typed_reference(value: Any, prefix: str) -> bool:
    if not _safe_reference(value) or not value.startswith(prefix):
        return False
    suffix = value.removeprefix(prefix)
    return any(character.isalpha() for character in suffix) and any(
        character.isdigit() for character in suffix
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _payload_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("record_type") != "phase6_pilot_inputs"
    ):
        errors.append("Phase 6 pilot input inventory identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Phase 6 pilot input inventory must not claim production acceptance")

    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("Phase 6 pilot input prohibited-content declaration is invalid")
    bindings = payload.get("bindings")
    roles = payload.get("pilot_roles")
    ownership = payload.get("ownership")
    window = payload.get("maintenance_window")
    if not _exact_mapping(bindings, _BINDING_KEYS):
        errors.append("Phase 6 pilot input binding schema is invalid")
    if not _exact_mapping(roles, set(REQUIRED_ROLE_RESPONSIBILITIES)):
        errors.append("Phase 6 pilot role roster is invalid")
    if not _exact_mapping(ownership, _OWNERSHIP_KEYS):
        errors.append("Phase 6 pilot ownership schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append("Phase 6 pilot maintenance window schema is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("inventory_reference")
    review_reference = payload.get("review_reference")
    environment = payload.get("environment")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append("Phase 6 pilot input inventory reference is invalid")
        return errors

    if synthetic:
        role_metadata_is_pending = isinstance(roles, dict) and all(
            _exact_mapping(role_record, _ROLE_KEYS)
            and role_record.get("participant_reference") is None
            and role_record.get("roster_entry_reference") is None
            and role_record.get("responsibility")
            == REQUIRED_ROLE_RESPONSIBILITIES.get(role)
            for role, role_record in roles.items()
        )
        if (
            not reference.startswith("synthetic-")
            or payload.get("inventory_status") != "pending"
            or review_reference is not None
            or environment != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or not role_metadata_is_pending
            or not isinstance(ownership, dict)
            or any(value is not None for value in ownership.values())
            or not isinstance(window, dict)
            or any(value is not None for value in window.values())
        ):
            errors.append("synthetic Phase 6 pilot input metadata is invalid")
        return errors

    if (
        not _typed_reference(reference, "pilot-input-inventory:")
        or payload.get("inventory_status") != "reviewed"
        or not _typed_reference(review_reference, "pilot-review-ref:")
        or reference == review_reference
    ):
        errors.append("reviewed Phase 6 pilot input metadata is invalid")
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed Phase 6 pilot input environment is invalid")

    if isinstance(bindings, dict):
        if (
            not isinstance(bindings.get("release_tag"), str)
            or _TAG.fullmatch(bindings["release_tag"]) is None
            or not isinstance(bindings.get("release_commit"), str)
            or _COMMIT.fullmatch(bindings["release_commit"]) is None
            or any(
                not isinstance(bindings.get(key), str)
                or _SHA256.fullmatch(bindings[key]) is None
                for key in (
                    "container_manifest_sha256",
                    "target_platform_inventory_sha256",
                )
            )
        ):
            errors.append("reviewed Phase 6 pilot release or intake binding is invalid")

    participant_references: list[str] = []
    roster_references: list[str] = []
    if isinstance(roles, dict):
        for role, responsibility in REQUIRED_ROLE_RESPONSIBILITIES.items():
            record = roles.get(role)
            if not _exact_mapping(record, _ROLE_KEYS):
                errors.append(f"Phase 6 pilot {role} roster entry schema is invalid")
                continue
            participant = record.get("participant_reference")
            roster_entry = record.get("roster_entry_reference")
            if (
                not _typed_reference(participant, "pilot-subject-ref:")
                or not _typed_reference(roster_entry, "pilot-roster-entry:")
                or record.get("responsibility") != responsibility
            ):
                errors.append(f"Phase 6 pilot {role} roster entry is invalid")
            if isinstance(participant, str):
                participant_references.append(participant)
            if isinstance(roster_entry, str):
                roster_references.append(roster_entry)
    if len(participant_references) != len(set(participant_references)):
        errors.append("Phase 6 pilot participants must be distinct")
    if len(roster_references) != len(set(roster_references)):
        errors.append("Phase 6 pilot roster entries must be distinct")

    owner_references: list[str] = []
    if isinstance(ownership, dict):
        owner_references = [
            value for value in ownership.values() if isinstance(value, str)
        ]
        if not all(
            _typed_reference(ownership.get(key), "pilot-owner-ref:")
            for key in _OWNERSHIP_KEYS
        ):
            errors.append("Phase 6 pilot ownership references are invalid")
        elif len(owner_references) != len(set(owner_references)):
            errors.append("Phase 6 pilot ownership responsibilities must be distinct")
    if review_reference in participant_references or review_reference in owner_references:
        errors.append("Phase 6 pilot input reviewer must be independent")

    if isinstance(window, dict):
        change_reference = window.get("change_reference")
        approval_reference = window.get("approval_reference")
        if (
            not _typed_reference(change_reference, "change-record:")
            or not _typed_reference(approval_reference, "change-approval:")
            or change_reference == approval_reference
        ):
            errors.append("Phase 6 pilot maintenance approval references are invalid")
        started_at = _parse_utc(window.get("starts_at"))
        deadline = _parse_utc(window.get("rollback_decision_deadline"))
        finished_at = _parse_utc(window.get("finishes_at"))
        if (
            started_at is None
            or deadline is None
            or finished_at is None
            or not started_at < deadline < finished_at
        ):
            errors.append("Phase 6 pilot maintenance window is invalid")
    return errors


def inventory_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Phase 6 pilot input inventory top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["Phase 6 pilot input inventory integrity is invalid"]
    return _payload_errors(payload)


def repository_contract_errors() -> list[str]:
    if tuple(REQUIRED_ROLE_RESPONSIBILITIES) != tuple(TRAINING_ROLES):
        return ["Phase 6 pilot role roster does not match the training role contract"]
    return []


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return ["Phase 6 pilot input bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["Phase 6 pilot input intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append("Phase 6 pilot inputs environment does not match this intake manifest")
    matches = [
        item
        for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == "target_platform_inventory"
    ]
    if (
        len(matches) != 1
        or matches[0].get("status") != "provided"
        or not isinstance(matches[0].get("sha256"), str)
        or _SHA256.fullmatch(matches[0]["sha256"]) is None
    ):
        errors.append(
            "Phase 6 pilot inputs target_platform_inventory binding target is not provided"
        )
    elif (
        document["bindings"].get("target_platform_inventory_sha256")
        != matches[0]["sha256"]
    ):
        errors.append(
            "Phase 6 pilot inputs target_platform_inventory binding does not match this intake manifest"
        )
    return errors


def _load(path: Path, *, max_bytes: int | None = None) -> Any:
    if max_bytes is None:
        return load_unique_json(path)
    return load_unique_json(path, max_bytes=max_bytes)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    check.add_argument("--intake-manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        try:
            document = _load(INVENTORY)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("phase6-pilot-input-inventory-invalid", file=sys.stderr)
            return 1
        errors = inventory_errors(document) + repository_contract_errors()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("phase6-pilot-input-inventory-ok status=pending production_acceptance=false")
        return 0
    try:
        document = _load(arguments.input)
        manifest = _load(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("phase6-pilot-input-inventory-invalid", file=sys.stderr)
        return 1
    errors = inventory_errors(document)
    if not errors and document.get("synthetic") is not False:
        errors.append("Phase 6 pilot input inventory must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = intake_binding_errors(document, manifest)
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("phase6-pilot-input-inventory-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
