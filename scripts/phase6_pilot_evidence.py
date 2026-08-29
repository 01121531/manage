"""Validate the sealed, metadata-only Phase 6 target pilot evidence index."""

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

from scripts.external_json import load_unique_json
from scripts.phase6_pilot_inputs import inventory_errors
from scripts.phase6_rehearsal import _CHECK_KEYS
from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    release_execution_reviewed_at,
    selector_errors as release_execution_selector_errors,
)
from scripts.target_intake_manifest import (
    PinnedIntakeManifestError,
    load_pinned_intake_manifest,
)


EVIDENCE_INDEX = (
    ROOT / "deploy" / "evidence-index-envelopes" / "phase6-pilot.synthetic.json"
)

REQUIRED_SCENARIOS = {
    "authenticated_platform_session": {
        "actor_role": "operator",
        "observation": "target_oidc_session_authenticated",
    },
    "full_business_flow": {
        "actor_role": "operator",
        "observation": "login_task_card_mail_code_upload_close_completed",
    },
    "one_time_verification": {
        "actor_role": "operator",
        "observation": "verification_code_consumed_once",
    },
    "server_side_upload": {
        "actor_role": "operator",
        "observation": "sub2_submission_executed_server_side",
    },
    "resource_cleanup": {
        "actor_role": "operator",
        "observation": "task_completed_card_released_mail_revoked_outbox_processed",
    },
    "authorization_isolation": {
        "actor_role": "security_auditor",
        "observation": "cross_tenant_and_cross_device_access_denied",
    },
    "persistent_secret_scan": {
        "actor_role": "security_auditor",
        "observation": "no_live_secret_found_on_reviewed_persistent_surfaces",
    },
    "audit_trace_replay": {
        "actor_role": "security_auditor",
        "observation": "pilot_trace_replayed_end_to_end",
    },
    "audit_resource_replay": {
        "actor_role": "security_auditor",
        "observation": "task_card_user_and_trace_replay_consistent",
    },
}

EXECUTION_SCOPE = {
    "origin": "target_environment",
    "identity_mode": "oidc",
    "connector_mode": "reviewed_real_mail_and_sub2",
    "evidence_policy": "repository_external_worm_metadata_only",
}

_PAYLOAD_KEYS = {
    "schema_version", "record_type", "index_reference", "synthetic",
    "index_status", "review_reference", "reviewed_at", "valid_until",
    "production_acceptance", "environment",
    "execution_scope", "bindings", "pilot_subjects", "trace_set_reference",
    "window", "release_execution", "scenarios", "prohibited_content",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_BINDING_KEYS = {
    "release_tag", "release_commit", "container_manifest_sha256",
    "phase6_pilot_inputs_sha256", "sub2_execution_evidence_sha256",
    "target_platform_inventory_sha256",
}
_SUBJECT_KEYS = {"operator", "security_auditor"}
_WINDOW_KEYS = {"started_at", "finished_at"}
_SCENARIO_KEYS = {
    "execution_reference", "actor_role", "reviewer_reference", "executed_at",
    "observation", "result", "evidence_object_reference", "evidence_sha256",
    "redaction_confirmed",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials", "contains_personal_data",
    "contains_provider_payloads", "contains_request_or_response_bodies",
    "contains_provider_urls", "contains_raw_logs_or_mail_content",
    "contains_pan_or_cvv_values", "contains_verification_code_values",
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
    r"credential|cvv|pan|token|email|phone|name)(?:$|[._:-])",
    re.IGNORECASE,
)


def _canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_index(payload: dict[str, Any]) -> dict[str, Any]:
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


def _payload_errors(
    payload: dict[str, Any],
    *,
    evaluated_at: datetime,
) -> list[str]:
    errors: list[str] = []
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 4
        or payload.get("record_type") != "phase6_pilot_evidence_index"
    ):
        errors.append("Phase 6 pilot evidence index identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Phase 6 pilot evidence index must not claim production acceptance")
    if payload.get("execution_scope") != EXECUTION_SCOPE:
        errors.append("Phase 6 pilot evidence execution scope is invalid")

    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("Phase 6 pilot evidence prohibited-content declaration is invalid")
    bindings = payload.get("bindings")
    subjects = payload.get("pilot_subjects")
    window = payload.get("window")
    scenarios = payload.get("scenarios")
    release_execution = payload.get("release_execution")
    if not _exact_mapping(bindings, _BINDING_KEYS):
        errors.append("Phase 6 pilot evidence binding schema is invalid")
    if not _exact_mapping(subjects, _SUBJECT_KEYS):
        errors.append("Phase 6 pilot evidence subject schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append("Phase 6 pilot evidence window schema is invalid")
    if not _exact_mapping(scenarios, set(REQUIRED_SCENARIOS)):
        errors.append("Phase 6 pilot evidence scenario inventory is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("index_reference")
    review_reference = payload.get("review_reference")
    reviewed_at = payload.get("reviewed_at")
    valid_until = payload.get("valid_until")
    environment = payload.get("environment")
    if not isinstance(synthetic, bool) or not _typed_reference(reference, "pilot-evidence-index:"):
        errors.append("Phase 6 pilot evidence index reference is invalid")
        return errors
    if synthetic:
        release_errors = release_execution_selector_errors(
            release_execution,
            synthetic=True,
        )
        errors.extend(
            f"Phase 6 pilot evidence {error}" for error in release_errors
        )
        if (
            payload.get("index_status") != "pending"
            or review_reference is not None
            or reviewed_at is not None
            or valid_until is not None
            or environment != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or not isinstance(subjects, dict)
            or any(value is not None for value in subjects.values())
            or payload.get("trace_set_reference") is not None
            or window != {"started_at": None, "finished_at": None}
            or not isinstance(scenarios, dict)
            or any(value is not None for value in scenarios.values())
        ):
            errors.append("synthetic Phase 6 pilot evidence metadata is invalid")
        return errors

    if (
        payload.get("index_status") != "reviewed"
        or not _typed_reference(review_reference, "pilot-evidence-review:")
        or reference == review_reference
    ):
        errors.append("reviewed Phase 6 pilot evidence metadata is invalid")
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed Phase 6 pilot evidence environment is invalid")
    if not _typed_reference(payload.get("trace_set_reference"), "pilot-trace-set:"):
        errors.append("reviewed Phase 6 pilot trace-set reference is invalid")
    release_errors = release_execution_selector_errors(
        release_execution,
        synthetic=False,
        environment=environment if isinstance(environment, str) else None,
    )
    errors.extend(f"Phase 6 pilot evidence {error}" for error in release_errors)

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
                    "container_manifest_sha256", "phase6_pilot_inputs_sha256",
                    "sub2_execution_evidence_sha256",
                    "target_platform_inventory_sha256",
                )
            )
        ):
            errors.append("reviewed Phase 6 pilot evidence release or intake binding is invalid")

    subject_values: list[str] = []
    if isinstance(subjects, dict):
        for role in _SUBJECT_KEYS:
            value = subjects.get(role)
            if not _typed_reference(value, "pilot-subject-ref:"):
                errors.append(f"Phase 6 pilot evidence {role} subject is invalid")
            elif isinstance(value, str):
                subject_values.append(value)
        if len(subject_values) != len(set(subject_values)):
            errors.append("Phase 6 pilot evidence subjects must be distinct")

    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    if started_at is None or finished_at is None or finished_at <= started_at:
        errors.append("reviewed Phase 6 pilot evidence window is invalid")
    reviewed = _parse_utc(reviewed_at)
    expires = _parse_utc(valid_until)
    if (
        reviewed is None
        or expires is None
        or finished_at is None
        or reviewed < finished_at
        or expires <= reviewed
    ):
        errors.append("reviewed Phase 6 pilot evidence review validity is invalid")
    elif not reviewed <= evaluated_at < expires:
        errors.append("reviewed Phase 6 pilot evidence is not currently valid")

    executions: list[str] = []
    objects: list[str] = []
    digests: list[str] = []
    if isinstance(scenarios, dict):
        for scenario, contract in REQUIRED_SCENARIOS.items():
            result = scenarios.get(scenario)
            if not _exact_mapping(result, _SCENARIO_KEYS):
                errors.append(f"Phase 6 pilot evidence {scenario} scenario schema is invalid")
                continue
            execution_reference = result.get("execution_reference")
            reviewer_reference = result.get("reviewer_reference")
            object_reference = result.get("evidence_object_reference")
            if (
                not _typed_reference(execution_reference, "pilot-execution:")
                or not _typed_reference(reviewer_reference, "pilot-reviewer-ref:")
                or not _typed_reference(object_reference, "worm-pilot-evidence:")
            ):
                errors.append(f"Phase 6 pilot evidence {scenario} references are invalid")
            elif reviewer_reference in subject_values:
                errors.append(f"Phase 6 pilot evidence {scenario} reviewer is not independent")
            if (
                result.get("actor_role") != contract["actor_role"]
                or result.get("observation") != contract["observation"]
                or result.get("result") != "passed"
                or result.get("redaction_confirmed") is not True
            ):
                errors.append(f"Phase 6 pilot evidence {scenario} result is invalid")
            executed_at = _parse_utc(result.get("executed_at"))
            if (
                executed_at is None or started_at is None or finished_at is None
                or not started_at <= executed_at <= finished_at
            ):
                errors.append(f"Phase 6 pilot evidence {scenario} timestamp is outside the window")
            digest = result.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"Phase 6 pilot evidence {scenario} artifact digest is invalid")
            if isinstance(execution_reference, str):
                executions.append(execution_reference)
            if isinstance(object_reference, str):
                objects.append(object_reference)
            if isinstance(digest, str):
                digests.append(digest)
    for values, label in (
        (executions, "execution references"),
        (objects, "evidence object references"),
        (digests, "evidence artifact digests"),
    ):
        if len(values) != len(set(values)):
            errors.append(f"Phase 6 pilot evidence {label} must be unique")
    return errors


def index_errors(
    document: Any,
    *,
    evaluated_at: datetime | None = None,
) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Phase 6 pilot evidence index top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["Phase 6 pilot evidence index integrity is invalid"]
    evaluation_time = evaluated_at or datetime.now(timezone.utc)
    return _payload_errors(payload, evaluated_at=evaluation_time)


def repository_contract_errors() -> list[str]:
    if set(REQUIRED_SCENARIOS) != set(_CHECK_KEYS):
        return ["Phase 6 pilot evidence scenarios do not match the CI rehearsal dimensions"]
    return []


def pilot_input_alignment_errors(
    document: Any,
    pilot_inputs: Any,
    *,
    evaluated_at: datetime | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or datetime.now(timezone.utc)
    if index_errors(document, evaluated_at=evaluation_time):
        return ["Phase 6 pilot evidence index is invalid"]
    if inventory_errors(pilot_inputs, evaluated_at=evaluation_time):
        return ["Phase 6 pilot evidence pilot inputs are invalid"]
    if pilot_inputs.get("synthetic") is not False or pilot_inputs.get("inventory_status") != "reviewed":
        return ["Phase 6 pilot evidence requires reviewed non-synthetic pilot inputs"]
    errors: list[str] = []
    if document.get("environment") != pilot_inputs.get("environment"):
        errors.append("Phase 6 pilot evidence environment does not match the reviewed pilot inputs")
    roles = pilot_inputs.get("pilot_roles")
    expected = {
        role: roles.get(role, {}).get("participant_reference")
        for role in _SUBJECT_KEYS
    } if isinstance(roles, dict) else {}
    if document.get("pilot_subjects") != expected:
        errors.append("Phase 6 pilot evidence subjects do not match the reviewed pilot inputs")
    window = document.get("window")
    maintenance = pilot_inputs.get("maintenance_window")
    pilot_started = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    pilot_finished = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    pilot_reviewed = _parse_utc(document.get("reviewed_at"))
    maintenance_started = (
        _parse_utc(maintenance.get("starts_at")) if isinstance(maintenance, dict) else None
    )
    rollback_deadline = (
        _parse_utc(maintenance.get("rollback_decision_deadline"))
        if isinstance(maintenance, dict)
        else None
    )
    if (
        pilot_started is None
        or pilot_finished is None
        or pilot_reviewed is None
        or maintenance_started is None
        or rollback_deadline is None
        or not maintenance_started <= pilot_started < pilot_finished < rollback_deadline
        or pilot_reviewed > rollback_deadline
    ):
        errors.append(
            "Phase 6 pilot evidence window or review is outside the approved pre-rollback interval"
        )
    evidence_bindings = document.get("bindings")
    input_bindings = pilot_inputs.get("bindings")
    release_keys = ("release_tag", "release_commit", "container_manifest_sha256")
    if (
        not isinstance(evidence_bindings, dict)
        or not isinstance(input_bindings, dict)
        or any(
            evidence_bindings.get(key) != input_bindings.get(key)
            for key in release_keys
        )
    ):
        errors.append(
            "Phase 6 pilot evidence release identity does not match the reviewed pilot inputs"
        )
    return errors


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return ["Phase 6 pilot evidence bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["Phase 6 pilot evidence intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append("Phase 6 pilot evidence environment does not match this intake manifest")
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
            "Phase 6 pilot evidence release execution intake does not match this intake manifest"
        )
    for identifier, binding_key in (
        ("phase6_pilot_inputs", "phase6_pilot_inputs_sha256"),
        ("sub2_execution_evidence", "sub2_execution_evidence_sha256"),
        ("target_platform_inventory", "target_platform_inventory_sha256"),
    ):
        matches = [
            item for item in manifest["items"]
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        if (
            len(matches) != 1 or matches[0].get("status") != "provided"
            or not isinstance(matches[0].get("sha256"), str)
            or _SHA256.fullmatch(matches[0]["sha256"]) is None
        ):
            errors.append(f"Phase 6 pilot evidence {identifier} binding target is not provided")
        elif document["bindings"].get(binding_key) != matches[0]["sha256"]:
            errors.append(
                f"Phase 6 pilot evidence {identifier} binding does not match this intake manifest"
            )
    own_items = [
        item for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == "phase6_pilot_evidence"
    ]
    if (
        len(own_items) != 1 or own_items[0].get("status") != "provided"
        or own_items[0].get("reviewed_by") != document.get("review_reference")
        or own_items[0].get("reviewed_at") != document.get("reviewed_at")
    ):
        errors.append(
            "Phase 6 pilot evidence review metadata does not match this intake manifest"
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
    check.add_argument("--pilot-inputs", required=True, type=Path)
    check.add_argument("--intake-manifest", required=True, type=Path)
    check.add_argument(
        "--expected-intake-manifest-payload-sha256", required=True
    )
    check.add_argument("--expected-intake-manifest-file-sha256", required=True)
    check.add_argument("--release-execution-evidence", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    evaluated_at = datetime.now(timezone.utc)
    if arguments.command == "verify-repository":
        try:
            document = _load(EVIDENCE_INDEX)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("phase6-pilot-evidence-index-invalid", file=sys.stderr)
            return 1
        errors = index_errors(
            document,
            evaluated_at=evaluated_at,
        ) + repository_contract_errors()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("phase6-pilot-evidence-index-ok status=pending production_acceptance=false")
        return 0
    try:
        manifest = load_pinned_intake_manifest(
            arguments.intake_manifest,
            expected_payload_sha256=arguments.expected_intake_manifest_payload_sha256,
            expected_file_sha256=arguments.expected_intake_manifest_file_sha256,
        )
    except PinnedIntakeManifestError:
        print("phase6-pilot-evidence intake manifest caller binding is invalid", file=sys.stderr)
        return 2
    try:
        document = _load(arguments.input)
        pilot_inputs = _load(arguments.pilot_inputs)
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("phase6-pilot-evidence-index-invalid", file=sys.stderr)
        return 1
    errors = index_errors(document, evaluated_at=evaluated_at)
    if not errors and document.get("synthetic") is not False:
        errors.append("Phase 6 pilot evidence index must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = pilot_input_alignment_errors(
        document,
        pilot_inputs,
        evaluated_at=evaluated_at,
    )
    binding_errors += intake_binding_errors(document, manifest)
    bindings = document.get("bindings", {})
    binding_errors += release_execution_alignment_errors(
        document.get("release_execution"),
        arguments.release_execution_evidence,
        environment=document.get("environment"),
        release_tag=bindings.get("release_tag"),
        release_commit=bindings.get("release_commit"),
        container_manifest_sha256=bindings.get("container_manifest_sha256"),
        release_reviewed_at=release_execution_reviewed_at(
            manifest,
            document.get("release_execution"),
        ),
        consumer_started_at=document.get("window", {}).get("started_at"),
    )
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print(
        "phase6-pilot-evidence-index-bound production_acceptance=false "
        "intake-manifest-caller-pin=payload-and-file-matched "
        "intake-manifest-schema=closed-v2-inventory-exact "
        "intake-manifest-custody=unverified "
        "intake-manifest-pin-authority=unverified "
        "intake-manifest-rollback-protection=unverified "
        "release-review-selector-subject=manifest-exact "
        "release-reviewer-authentication=unverified "
        "release-review-trusted-time=unverified "
        "release-review-replay-protection=unverified "
        "release-storage-provider-native=unverified "
        "release-storage-retention=unverified "
        "release-storage-delete-denial=unverified "
        "release-storage-readback=unverified "
        "release-storage-namespace-authority=unverified "
        "release-storage-version-identity=unverified "
        "release-storage-cross-manifest-rebinding=unverified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
