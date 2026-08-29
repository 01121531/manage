"""Validate the Phase 0 boundary approval and its intake-manifest bindings."""

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

APPROVAL = (
    ROOT
    / "deploy"
    / "decision-envelopes"
    / "phase0-boundary-approval.synthetic.json"
)

_TOP_LEVEL_KEYS = {
    "schema_version",
    "record_type",
    "approval_reference",
    "synthetic",
    "approval_status",
    "review_reference",
    "reviewed_at",
    "valid_until",
    "production_acceptance",
    "data_classification",
    "data_classification_sha256",
    "bindings",
    "reviewers",
    "prohibited_content",
}
_BINDING_IDS = (
    "mail_contract",
    "sub2_contract",
    "card_pci_boundary",
    "oidc_deployment_identity",
    "target_platform_inventory",
)
_BINDING_KEYS = set(_BINDING_IDS) | {"target_intake_requirements_sha256"}
_REVIEWER_KEYS = {
    "security_reference",
    "privacy_reference",
    "platform_owner_reference",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_pan_values",
    "contains_cvv_values",
    "contains_token_values",
    "contains_verification_code_values",
}
_POLICY_KEYS = {"classification", "allowed_locations", "logs", "audit"}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PLACEHOLDERS = {"example", "placeholder", "tbd", "todo", "unknown"}

_DATA_CLASSIFICATION = {
    "live_credentials": {
        "classification": "secret",
        "allowed_locations": ["external_secret_manager"],
        "logs": "prohibited",
        "audit": "prohibited",
    },
    "oidc_tokens": {
        "classification": "secret",
        "allowed_locations": ["process_memory", "encrypted_os_session_store"],
        "logs": "prohibited",
        "audit": "prohibited",
    },
    "pan": {
        "classification": "restricted_cardholder_data",
        "allowed_locations": ["external_card_vault", "ephemeral_process_memory"],
        "logs": "prohibited",
        "audit": "prohibited",
    },
    "cvv": {
        "classification": "prohibited_sensitive_authentication_data",
        "allowed_locations": ["transient_process_memory"],
        "logs": "prohibited",
        "audit": "prohibited",
    },
    "verification_codes": {
        "classification": "ephemeral_secret",
        "allowed_locations": ["ephemeral_process_memory", "ttl_database_field"],
        "logs": "prohibited",
        "audit": "prohibited",
    },
    "masked_operational_metadata": {
        "classification": "internal",
        "allowed_locations": ["platform_database", "redacted_audit"],
        "logs": "redacted_only",
        "audit": "allowed",
    },
}


def _canonical_sha256(document: Any) -> str:
    rendered = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def approval_errors(
    document: Any,
    *,
    evaluated_at: datetime | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or _utc_now()
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL_KEYS:
        return ["phase0 approval top-level schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 2
        or document.get("record_type") != "phase0_boundary_approval"
    ):
        errors.append("phase0 approval identity is invalid")
    if document.get("production_acceptance") is not False:
        errors.append("phase0 approval must not claim production acceptance")

    classification = document.get("data_classification")
    classification_schema_is_invalid = not isinstance(classification, dict)
    if isinstance(classification, dict):
        classification_schema_is_invalid = (
            classification != _DATA_CLASSIFICATION
            or any(
                not isinstance(policy, dict) or set(policy) != _POLICY_KEYS
                for policy in classification.values()
            )
        )
    if classification_schema_is_invalid:
        errors.append("phase0 data classification policy is invalid")
    if (
        not isinstance(classification, dict)
        or document.get("data_classification_sha256")
        != _canonical_sha256(classification)
    ):
        errors.append("phase0 data classification digest is invalid")

    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("phase0 approval prohibited-content declaration is invalid")

    bindings = document.get("bindings")
    reviewers = document.get("reviewers")
    if not isinstance(bindings, dict) or set(bindings) != _BINDING_KEYS:
        errors.append("phase0 approval binding schema is invalid")
    if not isinstance(reviewers, dict) or set(reviewers) != _REVIEWER_KEYS:
        errors.append("phase0 approval reviewer schema is invalid")

    synthetic = document.get("synthetic")
    approval_reference = document.get("approval_reference")
    review_reference = document.get("review_reference")
    reviewed_at = document.get("reviewed_at")
    valid_until = document.get("valid_until")
    if not isinstance(synthetic, bool) or not _safe_reference(approval_reference):
        errors.append("phase0 approval reference is invalid")
        return errors
    if synthetic:
        if (
            not approval_reference.startswith("synthetic-")
            or document.get("approval_status") != "pending"
            or review_reference is not None
            or reviewed_at is not None
            or valid_until is not None
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or not isinstance(reviewers, dict)
            or any(value is not None for value in reviewers.values())
        ):
            errors.append("synthetic phase0 approval metadata is invalid")
        return errors

    references = [approval_reference, review_reference]
    if isinstance(reviewers, dict):
        references.extend(reviewers.values())
    if (
        approval_reference.startswith("synthetic-")
        or document.get("approval_status") != "approved"
        or not all(_safe_reference(value) for value in references)
        or len(set(references)) != len(references)
    ):
        errors.append("reviewed phase0 approval references are invalid or not independent")
    reviewed = _parse_utc(reviewed_at)
    expires = _parse_utc(valid_until)
    if reviewed is None or expires is None or reviewed >= expires:
        errors.append("reviewed phase0 approval validity window is invalid")
    elif reviewed > evaluation_time:
        errors.append("reviewed phase0 approval timestamp is in the future")
    elif expires <= evaluation_time:
        errors.append("reviewed phase0 approval is expired")
    if (
        not isinstance(bindings, dict)
        or any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in bindings.values()
        )
    ):
        errors.append("reviewed phase0 approval bindings are invalid")
    return errors


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    bindings = document.get("bindings") if isinstance(document, dict) else None
    if not isinstance(bindings, dict) or set(bindings) != _BINDING_KEYS:
        return ["phase0 approval bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["phase0 approval intake manifest is invalid"]

    errors: list[str] = []
    approval_reviewed_at = _parse_utc(document.get("reviewed_at"))
    for identifier in _BINDING_IDS:
        matches = [
            item
            for item in manifest["items"]
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        if (
            len(matches) != 1
            or matches[0].get("status") != "provided"
            or not isinstance(matches[0].get("sha256"), str)
            or _SHA256.fullmatch(matches[0]["sha256"]) is None
        ):
            errors.append(
                f"phase0 approval {identifier} binding target is not provided"
            )
        elif bindings.get(identifier) != matches[0]["sha256"]:
            errors.append(
                f"phase0 approval {identifier} binding does not match this intake manifest"
            )
        else:
            dependency_reviewed_at = _parse_utc(matches[0].get("reviewed_at"))
            if dependency_reviewed_at is None:
                errors.append(
                    f"phase0 approval {identifier} review time is invalid"
                )
            elif (
                approval_reviewed_at is not None
                and dependency_reviewed_at > approval_reviewed_at
            ):
                errors.append(
                    f"phase0 approval predates the reviewed {identifier} input"
                )
    approval_items = [
        item
        for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == "phase0_boundary_approval"
    ]
    if (
        len(approval_items) != 1
        or approval_items[0].get("status") != "provided"
        or approval_items[0].get("reviewed_by") != document.get("review_reference")
        or approval_items[0].get("reviewed_at") != document.get("reviewed_at")
    ):
        errors.append(
            "phase0 approval review metadata does not match this intake manifest"
        )
    requirements_sha = manifest.get("requirements_sha256")
    if (
        not isinstance(requirements_sha, str)
        or _SHA256.fullmatch(requirements_sha) is None
        or bindings.get("target_intake_requirements_sha256") != requirements_sha
    ):
        errors.append(
            "phase0 approval requirements binding does not match this intake manifest"
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
    evaluation_time = _utc_now()
    if arguments.command == "verify-repository":
        try:
            document = _load(APPROVAL)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("phase0-boundary-approval-invalid", file=sys.stderr)
            return 1
        errors = approval_errors(document, evaluated_at=evaluation_time)
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("phase0-boundary-approval-ok status=pending production_acceptance=false")
        return 0
    try:
        document = _load(arguments.input)
        manifest = _load(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("phase0-boundary-approval-invalid", file=sys.stderr)
        return 1
    errors = approval_errors(document, evaluated_at=evaluation_time)
    if not errors and document.get("synthetic") is not False:
        errors.append("phase0 approval must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = intake_binding_errors(document, manifest)
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("phase0-boundary-approval-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
