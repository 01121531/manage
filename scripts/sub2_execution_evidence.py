"""Validate a sealed, metadata-only Sub2 execution evidence index."""

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
from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    selector_errors as release_execution_selector_errors,
)

EVIDENCE_INDEX = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "sub2-execution.synthetic.json"
)

REQUIRED_SCENARIO_OBSERVATIONS = {
    "balance_check": "provider_submit_balance_check_observed",
    "authorization_exchange": "provider_submit_authorization_exchange_observed",
    "successful_create": "provider_submit_to_provider_result_succeeded",
    "definitive_failure": "provider_submit_to_provider_result_definitive_failure",
    "submission_timeout": "provider_submit_remained_unknown_without_automatic_retry",
    "status_succeeded": "reconciliation_check_to_result_succeeded",
    "status_failed": "reconciliation_check_to_result_failed",
    "status_processing": "reconciliation_check_remained_unknown_processing",
    "status_not_found": "reconciliation_check_remained_unknown_not_found",
    "status_unknown": "reconciliation_check_remained_unknown_unclassified",
    "duplicate_create_replay": "same_provider_key_returned_same_result_without_duplicate_create",
    "unknown_reconciliation": "unknown_reconciled_without_blind_retry",
}
_PAYLOAD_KEYS = {
    "schema_version",
    "record_type",
    "index_reference",
    "synthetic",
    "index_status",
    "review_reference",
    "reviewed_at",
    "valid_until",
    "production_acceptance",
    "environment",
    "bindings",
    "window",
    "release_execution",
    "scenarios",
    "prohibited_content",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_BINDING_KEYS = {
    "release_tag",
    "release_commit",
    "container_manifest_sha256",
    "sub2_contract_sha256",
    "target_platform_inventory_sha256",
}
_WINDOW_KEYS = {"started_at", "finished_at"}
_SCENARIO_KEYS = {
    "execution_reference",
    "executor_reference",
    "reviewer_reference",
    "trace_reference",
    "executed_at",
    "observation",
    "result",
    "evidence_object_reference",
    "evidence_sha256",
    "redaction_confirmed",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_provider_payloads",
    "contains_request_or_response_bodies",
    "contains_provider_urls",
    "contains_pan_values",
    "contains_cvv_values",
    "contains_verification_code_values",
    "contains_token_values",
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
    r"credential|cvv|pan|token)(?:$|[._:-])",
    re.IGNORECASE,
)


def _canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_index(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
        and _FORBIDDEN_REFERENCE_FRAGMENT.search(value) is None
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _payload_errors(payload: dict[str, Any], *, evaluated_at: datetime) -> list[str]:
    errors: list[str] = []
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 3
        or payload.get("record_type") != "sub2_execution_evidence_index"
    ):
        errors.append("Sub2 evidence index identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Sub2 evidence index must not claim production acceptance")

    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("Sub2 evidence prohibited-content declaration is invalid")
    bindings = payload.get("bindings")
    window = payload.get("window")
    scenarios = payload.get("scenarios")
    if not _exact_mapping(bindings, _BINDING_KEYS):
        errors.append("Sub2 evidence binding schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append("Sub2 evidence window schema is invalid")
    if not _exact_mapping(scenarios, set(REQUIRED_SCENARIO_OBSERVATIONS)):
        errors.append("Sub2 evidence scenario inventory is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("index_reference")
    review_reference = payload.get("review_reference")
    reviewed_at = payload.get("reviewed_at")
    valid_until = payload.get("valid_until")
    environment = payload.get("environment")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append("Sub2 evidence index reference is invalid")
        return errors

    if synthetic:
        if (
            not reference.startswith("synthetic-")
            or payload.get("index_status") != "pending"
            or review_reference is not None
            or reviewed_at is not None
            or valid_until is not None
            or environment != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or window != {"started_at": None, "finished_at": None}
            or release_execution_selector_errors(
                payload.get("release_execution"), synthetic=True
            )
            or not isinstance(scenarios, dict)
            or any(value is not None for value in scenarios.values())
        ):
            errors.append("synthetic Sub2 evidence index metadata is invalid")
        return errors

    if (
        reference.startswith("synthetic-")
        or payload.get("index_status") != "reviewed"
        or not _safe_reference(review_reference)
        or reference == review_reference
    ):
        errors.append("reviewed Sub2 evidence index metadata is invalid")
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed Sub2 evidence environment is invalid")

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
                    "sub2_contract_sha256",
                    "target_platform_inventory_sha256",
                )
            )
        ):
            errors.append("reviewed Sub2 evidence release or intake binding is invalid")

    errors.extend(
        f"Sub2 evidence {error}"
        for error in release_execution_selector_errors(
            payload.get("release_execution"),
            synthetic=False,
            environment=environment if isinstance(environment, str) else None,
        )
    )

    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    if started_at is None or finished_at is None or finished_at <= started_at:
        errors.append("reviewed Sub2 evidence window is invalid")
    reviewed = _parse_utc(reviewed_at)
    expires = _parse_utc(valid_until)
    if (
        reviewed is None
        or expires is None
        or finished_at is None
        or reviewed < finished_at
        or expires <= reviewed
    ):
        errors.append("reviewed Sub2 evidence review timestamp is invalid")
    elif not reviewed <= evaluated_at < expires:
        errors.append("reviewed Sub2 evidence is not currently valid")

    execution_references: list[str] = []
    trace_references: list[str] = []
    evidence_references: list[str] = []
    evidence_digests: list[str] = []
    if isinstance(scenarios, dict):
        for scenario, expected_observation in REQUIRED_SCENARIO_OBSERVATIONS.items():
            result = scenarios.get(scenario)
            if not _exact_mapping(result, _SCENARIO_KEYS):
                errors.append(f"Sub2 evidence {scenario} scenario schema is invalid")
                continue
            reference_fields = (
                "execution_reference",
                "executor_reference",
                "reviewer_reference",
                "trace_reference",
                "evidence_object_reference",
            )
            if not all(_safe_reference(result.get(key)) for key in reference_fields):
                errors.append(f"Sub2 evidence {scenario} references are invalid")
            elif result["executor_reference"] == result["reviewer_reference"]:
                errors.append(f"Sub2 evidence {scenario} reviewer is not independent")
            if (
                result.get("observation") != expected_observation
                or result.get("result") != "passed"
                or result.get("redaction_confirmed") is not True
            ):
                errors.append(f"Sub2 evidence {scenario} result is invalid")
            executed_at = _parse_utc(result.get("executed_at"))
            if (
                executed_at is None
                or started_at is None
                or finished_at is None
                or not started_at <= executed_at <= finished_at
            ):
                errors.append(f"Sub2 evidence {scenario} timestamp is outside the window")
            digest = result.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"Sub2 evidence {scenario} artifact digest is invalid")
            if all(isinstance(result.get(key), str) for key in reference_fields):
                execution_references.append(result["execution_reference"])
                trace_references.append(result["trace_reference"])
                evidence_references.append(result["evidence_object_reference"])
            if isinstance(digest, str):
                evidence_digests.append(digest)
    for values, label in (
        (execution_references, "execution references"),
        (trace_references, "trace references"),
        (evidence_references, "evidence object references"),
        (evidence_digests, "evidence artifact digests"),
    ):
        if len(values) != len(set(values)):
            errors.append(f"Sub2 evidence {label} must be unique")
    return errors


def index_errors(
    document: Any,
    *,
    evaluated_at: datetime | None = None,
) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Sub2 evidence index top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["Sub2 evidence index integrity is invalid"]
    return _payload_errors(
        payload,
        evaluated_at=evaluated_at or datetime.now(timezone.utc),
    )


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return ["Sub2 evidence bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["Sub2 evidence intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append("Sub2 evidence environment does not match this intake manifest")
    release_execution = document.get("release_execution")
    target_intake = (
        release_execution.get("target_intake")
        if isinstance(release_execution, dict)
        else None
    )
    if (
        not isinstance(target_intake, dict)
        or target_intake.get("environment") != manifest.get("environment")
        or target_intake.get("requirements_sha256")
        != manifest.get("requirements_sha256")
        or target_intake.get("checkpoint_phase") != 0
    ):
        errors.append(
            "Sub2 evidence release execution intake does not match this intake manifest"
        )
    for identifier, binding_key in (
        ("sub2_contract", "sub2_contract_sha256"),
        ("target_platform_inventory", "target_platform_inventory_sha256"),
    ):
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
            errors.append(f"Sub2 evidence {identifier} binding target is not provided")
        elif document["bindings"].get(binding_key) != matches[0]["sha256"]:
            errors.append(
                f"Sub2 evidence {identifier} binding does not match this intake manifest"
            )
    own_items = [
        item
        for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == "sub2_execution_evidence"
    ]
    if (
        len(own_items) != 1
        or own_items[0].get("status") != "provided"
        or own_items[0].get("reviewed_by") != document.get("review_reference")
        or own_items[0].get("reviewed_at") != document.get("reviewed_at")
    ):
        errors.append(
            "Sub2 evidence review metadata does not match this intake manifest"
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
    check.add_argument("--release-execution-evidence", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    evaluated_at = datetime.now(timezone.utc)
    if arguments.command == "verify-repository":
        try:
            document = _load(EVIDENCE_INDEX)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("sub2-execution-evidence-index-invalid", file=sys.stderr)
            return 1
        errors = index_errors(document, evaluated_at=evaluated_at)
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("sub2-execution-evidence-index-ok status=pending production_acceptance=false")
        return 0
    try:
        document = _load(arguments.input)
        manifest = _load(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("sub2-execution-evidence-index-invalid", file=sys.stderr)
        return 1
    errors = index_errors(document, evaluated_at=evaluated_at)
    if not errors and document.get("synthetic") is not False:
        errors.append("Sub2 evidence index must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = intake_binding_errors(document, manifest)
    bindings = document.get("bindings", {})
    binding_errors += release_execution_alignment_errors(
        document.get("release_execution"),
        arguments.release_execution_evidence,
        environment=document.get("environment"),
        release_tag=bindings.get("release_tag"),
        release_commit=bindings.get("release_commit"),
        container_manifest_sha256=bindings.get("container_manifest_sha256"),
        consumer_started_at=document.get("window", {}).get("started_at"),
    )
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("sub2-execution-evidence-index-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
