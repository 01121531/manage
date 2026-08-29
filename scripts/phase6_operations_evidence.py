"""Validate the sealed, metadata-only Phase 6 target operations evidence index."""

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
from scripts.phase6_pilot_evidence import (
    index_errors as pilot_evidence_errors,
    pilot_input_alignment_errors,
)
from scripts.phase6_pilot_inputs import (
    REQUIRED_ROLE_RESPONSIBILITIES,
    inventory_errors as pilot_input_errors,
)
from scripts.rollback_release_evidence import TERMINAL_SUCCEEDED
from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    selector_errors as release_execution_selector_errors,
)
from scripts.training_evidence import (
    REQUIRED_ROLES as TRAINING_ROLES,
    REQUIRED_SCENARIOS as TRAINING_SCENARIOS,
)


EVIDENCE_INDEX = (
    ROOT / "deploy" / "evidence-index-envelopes" / "phase6-operations.synthetic.json"
)

REQUIRED_SCENARIOS = {
    "page_alert_firing_delivery": {
        "actor_role": "security_auditor",
        "observation": "approved_receiver_recorded_firing_delivery",
    },
    "page_alert_resolved_delivery": {
        "actor_role": "security_auditor",
        "observation": "approved_receiver_recorded_resolved_delivery",
    },
    "watchdog_delivery_continuity": {
        "actor_role": "security_auditor",
        "observation": "three_consecutive_watchdog_deliveries_observed",
    },
    "watchdog_missed_heartbeat_recovery": {
        "actor_role": "security_auditor",
        "observation": "missed_heartbeat_alarm_raised_then_resolved_after_recovery",
    },
    "postgres_redis_restore": {
        "actor_role": "platform_admin",
        "observation": "release_bound_postgresql_and_redis_recovery_set_restored",
    },
    "vault_restore": {
        "actor_role": "platform_admin",
        "observation": "vault_snapshot_restored_and_application_paths_verified",
    },
    "release_bound_rollback": {
        "actor_role": "platform_admin",
        "observation": "rollback_succeeded_edge_opened_only_after_all_checks",
    },
    "four_role_training": {
        "actor_role": "platform_admin",
        "observation": "four_roles_and_five_tabletop_scenarios_passed",
    },
    "alert_audit_trace_replay": {
        "actor_role": "security_auditor",
        "observation": "alert_to_tenant_scoped_redacted_audit_trace_replayed",
    },
}

REQUIRED_ARTIFACT_DIGESTS = (
    "alertmanager_configuration_sha256",
    "postgres_backup_manifest_sha256",
    "redis_backup_manifest_sha256",
    "vault_snapshot_sha256",
    "rollback_terminal_evidence_sha256",
    "role_training_evidence_sha256",
)

EXECUTION_SCOPE = {
    "origin": "target_environment",
    "alert_receiver": "approved_external_receiver",
    "restore_scope": "release_bound_postgresql_redis_and_vault",
    "rollback_mode": "executed_release_bound",
    "training_mode": "reviewed_four_role_target_session",
    "evidence_policy": "repository_external_worm_metadata_only",
}

_PAYLOAD_KEYS = {
    "schema_version", "record_type", "index_reference", "synthetic",
    "index_status", "review_reference", "reviewed_at", "production_acceptance", "environment",
    "execution_scope", "bindings", "role_subjects", "pilot_trace_set_reference",
    "window", "release_execution", "artifact_digests", "scenarios", "prohibited_content",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_BINDING_KEYS = {
    "release_tag", "release_commit", "container_manifest_sha256",
    "phase6_pilot_inputs_sha256", "phase6_pilot_evidence_sha256",
    "target_platform_inventory_sha256",
}
_ROLE_KEYS = {"operator", "ops_admin", "security_auditor", "platform_admin"}
_WINDOW_KEYS = {"started_at", "finished_at"}
_SCENARIO_KEYS = {
    "execution_reference", "actor_role", "reviewer_reference", "executed_at",
    "observation", "result", "evidence_object_reference", "evidence_sha256",
    "redaction_confirmed",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials", "contains_personal_data",
    "contains_receiver_urls", "contains_delivery_payloads",
    "contains_backup_or_vault_content", "contains_raw_logs_or_audit_exports",
    "contains_request_or_response_bodies", "contains_pan_or_cvv_values",
    "contains_verification_code_values", "contains_token_values",
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


def _payload_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 3
        or payload.get("record_type") != "phase6_operations_evidence_index"
    ):
        errors.append("Phase 6 operations evidence index identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Phase 6 operations evidence index must not claim production acceptance")
    if payload.get("execution_scope") != EXECUTION_SCOPE:
        errors.append("Phase 6 operations evidence execution scope is invalid")

    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("Phase 6 operations evidence prohibited-content declaration is invalid")
    bindings = payload.get("bindings")
    subjects = payload.get("role_subjects")
    window = payload.get("window")
    artifacts = payload.get("artifact_digests")
    scenarios = payload.get("scenarios")
    release_execution = payload.get("release_execution")
    if not _exact_mapping(bindings, _BINDING_KEYS):
        errors.append("Phase 6 operations evidence binding schema is invalid")
    if not _exact_mapping(subjects, _ROLE_KEYS):
        errors.append("Phase 6 operations evidence role-subject schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append("Phase 6 operations evidence window schema is invalid")
    if not _exact_mapping(artifacts, set(REQUIRED_ARTIFACT_DIGESTS)):
        errors.append("Phase 6 operations evidence artifact inventory is invalid")
    if not _exact_mapping(scenarios, set(REQUIRED_SCENARIOS)):
        errors.append("Phase 6 operations evidence scenario inventory is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("index_reference")
    review_reference = payload.get("review_reference")
    reviewed_at = payload.get("reviewed_at")
    environment = payload.get("environment")
    if (
        not isinstance(synthetic, bool)
        or not _typed_reference(reference, "operations-evidence-index:")
    ):
        errors.append("Phase 6 operations evidence index reference is invalid")
        return errors
    if synthetic:
        release_errors = release_execution_selector_errors(
            release_execution,
            synthetic=True,
        )
        errors.extend(
            f"Phase 6 operations evidence {error}" for error in release_errors
        )
        if (
            payload.get("index_status") != "pending"
            or review_reference is not None
            or reviewed_at is not None
            or environment != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or not isinstance(subjects, dict)
            or any(value is not None for value in subjects.values())
            or payload.get("pilot_trace_set_reference") is not None
            or window != {"started_at": None, "finished_at": None}
            or not isinstance(artifacts, dict)
            or any(value is not None for value in artifacts.values())
            or not isinstance(scenarios, dict)
            or any(value is not None for value in scenarios.values())
        ):
            errors.append("synthetic Phase 6 operations evidence metadata is invalid")
        return errors

    if (
        payload.get("index_status") != "reviewed"
        or not _typed_reference(review_reference, "operations-evidence-review:")
        or reference == review_reference
    ):
        errors.append("reviewed Phase 6 operations evidence metadata is invalid")
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed Phase 6 operations evidence environment is invalid")
    if not _typed_reference(
        payload.get("pilot_trace_set_reference"), "pilot-trace-set:"
    ):
        errors.append("reviewed Phase 6 operations trace-set reference is invalid")
    release_errors = release_execution_selector_errors(
        release_execution,
        synthetic=False,
        environment=environment if isinstance(environment, str) else None,
    )
    errors.extend(
        f"Phase 6 operations evidence {error}" for error in release_errors
    )

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
                    "phase6_pilot_evidence_sha256",
                    "target_platform_inventory_sha256",
                )
            )
        ):
            errors.append("reviewed Phase 6 operations evidence release or intake binding is invalid")

    subject_values: list[str] = []
    if isinstance(subjects, dict):
        for role in _ROLE_KEYS:
            value = subjects.get(role)
            if not _typed_reference(value, "pilot-subject-ref:"):
                errors.append(f"Phase 6 operations evidence {role} subject is invalid")
            elif isinstance(value, str):
                subject_values.append(value)
        if len(subject_values) != len(set(subject_values)):
            errors.append("Phase 6 operations evidence subjects must be distinct")

    artifact_values: list[str] = []
    if isinstance(artifacts, dict):
        for name in REQUIRED_ARTIFACT_DIGESTS:
            digest = artifacts.get(name)
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"Phase 6 operations evidence {name} digest is invalid")
            elif isinstance(digest, str):
                artifact_values.append(digest)
        if len(artifact_values) != len(set(artifact_values)):
            errors.append("Phase 6 operations evidence artifact digests must be unique")

    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    if started_at is None or finished_at is None or finished_at <= started_at:
        errors.append("reviewed Phase 6 operations evidence window is invalid")
    reviewed = _parse_utc(reviewed_at)
    if reviewed is None or finished_at is None or reviewed < finished_at:
        errors.append("reviewed Phase 6 operations evidence review timestamp is invalid")

    executions: list[str] = []
    objects: list[str] = []
    digests: list[str] = []
    if isinstance(scenarios, dict):
        for scenario, contract in REQUIRED_SCENARIOS.items():
            result = scenarios.get(scenario)
            if not _exact_mapping(result, _SCENARIO_KEYS):
                errors.append(f"Phase 6 operations evidence {scenario} scenario schema is invalid")
                continue
            execution_reference = result.get("execution_reference")
            reviewer_reference = result.get("reviewer_reference")
            object_reference = result.get("evidence_object_reference")
            if (
                not _typed_reference(execution_reference, "operations-execution:")
                or not _typed_reference(reviewer_reference, "operations-reviewer-ref:")
                or not _typed_reference(object_reference, "worm-operations-evidence:")
            ):
                errors.append(f"Phase 6 operations evidence {scenario} references are invalid")
            elif reviewer_reference in subject_values:
                errors.append(f"Phase 6 operations evidence {scenario} reviewer is not independent")
            if (
                result.get("actor_role") != contract["actor_role"]
                or result.get("observation") != contract["observation"]
                or result.get("result") != "passed"
                or result.get("redaction_confirmed") is not True
            ):
                errors.append(f"Phase 6 operations evidence {scenario} result is invalid")
            executed_at = _parse_utc(result.get("executed_at"))
            if (
                executed_at is None or started_at is None or finished_at is None
                or not started_at <= executed_at <= finished_at
            ):
                errors.append(f"Phase 6 operations evidence {scenario} timestamp is outside the window")
            digest = result.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"Phase 6 operations evidence {scenario} artifact digest is invalid")
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
            errors.append(f"Phase 6 operations evidence {label} must be unique")
    return errors


def index_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Phase 6 operations evidence index top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["Phase 6 operations evidence index integrity is invalid"]
    return _payload_errors(payload)


def repository_contract_errors() -> list[str]:
    errors: list[str] = []
    if tuple(TRAINING_ROLES) != tuple(REQUIRED_ROLE_RESPONSIBILITIES):
        errors.append("Phase 6 operations evidence roles do not match the training contract")
    if len(TRAINING_SCENARIOS) != 5 or TERMINAL_SUCCEEDED != "succeeded":
        errors.append("Phase 6 operations evidence source contracts have drifted")
    return errors


def phase6_alignment_errors(
    document: Any,
    pilot_inputs: Any,
    pilot_evidence: Any,
) -> list[str]:
    if pilot_input_errors(pilot_inputs):
        return ["Phase 6 operations evidence pilot inputs are invalid"]
    if pilot_inputs.get("synthetic") is not False or pilot_inputs.get("inventory_status") != "reviewed":
        return ["Phase 6 operations evidence requires reviewed non-synthetic pilot inputs"]
    if pilot_evidence_errors(pilot_evidence):
        return ["Phase 6 operations evidence pilot evidence is invalid"]
    if pilot_evidence.get("synthetic") is not False or pilot_evidence.get("index_status") != "reviewed":
        return ["Phase 6 operations evidence requires reviewed non-synthetic pilot evidence"]

    errors: list[str] = []
    dependency_alignment = pilot_input_alignment_errors(pilot_evidence, pilot_inputs)
    if dependency_alignment:
        errors.append("Phase 6 operations evidence reviewed dependencies are not aligned")
    environments = {
        document.get("environment"),
        pilot_inputs.get("environment"),
        pilot_evidence.get("environment"),
    }
    if len(environments) != 1:
        errors.append("Phase 6 operations evidence environment does not match its reviewed dependencies")
    roles = pilot_inputs.get("pilot_roles")
    expected_subjects = {
        role: roles.get(role, {}).get("participant_reference")
        for role in _ROLE_KEYS
    } if isinstance(roles, dict) else {}
    if document.get("role_subjects") != expected_subjects:
        errors.append("Phase 6 operations evidence subjects do not match the reviewed pilot inputs")
    if document.get("pilot_trace_set_reference") != pilot_evidence.get("trace_set_reference"):
        errors.append("Phase 6 operations evidence trace set does not match the reviewed pilot evidence")
    if document.get("release_execution") != pilot_evidence.get("release_execution"):
        errors.append(
            "Phase 6 operations evidence release execution does not match the reviewed pilot evidence"
        )

    document_bindings = document.get("bindings")
    input_bindings = pilot_inputs.get("bindings")
    evidence_bindings = pilot_evidence.get("bindings")
    release_keys = ("release_tag", "release_commit", "container_manifest_sha256")
    if (
        not isinstance(document_bindings, dict)
        or not isinstance(input_bindings, dict)
        or not isinstance(evidence_bindings, dict)
        or any(
            not (
                document_bindings.get(key)
                == input_bindings.get(key)
                == evidence_bindings.get(key)
            )
            for key in release_keys
        )
    ):
        errors.append(
            "Phase 6 operations evidence release identity does not match its reviewed dependencies"
        )
    if (
        isinstance(document_bindings, dict)
        and isinstance(input_bindings, dict)
        and isinstance(evidence_bindings, dict)
        and not (
            document_bindings.get("target_platform_inventory_sha256")
            == input_bindings.get("target_platform_inventory_sha256")
            == evidence_bindings.get("target_platform_inventory_sha256")
        )
    ):
        errors.append(
            "Phase 6 operations evidence target inventory does not match its reviewed dependencies"
        )
    return errors


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return ["Phase 6 operations evidence bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["Phase 6 operations evidence intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append("Phase 6 operations evidence environment does not match this intake manifest")
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
            "Phase 6 operations evidence release execution intake does not match this intake manifest"
        )
    for identifier, binding_key in (
        ("phase6_pilot_inputs", "phase6_pilot_inputs_sha256"),
        ("phase6_pilot_evidence", "phase6_pilot_evidence_sha256"),
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
            errors.append(f"Phase 6 operations evidence {identifier} binding target is not provided")
        elif document["bindings"].get(binding_key) != matches[0]["sha256"]:
            errors.append(
                f"Phase 6 operations evidence {identifier} binding does not match this intake manifest"
            )
    own_items = [
        item for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == "phase6_operations_evidence"
    ]
    if (
        len(own_items) != 1 or own_items[0].get("status") != "provided"
        or own_items[0].get("reviewed_by") != document.get("review_reference")
        or own_items[0].get("reviewed_at") != document.get("reviewed_at")
    ):
        errors.append(
            "Phase 6 operations evidence review metadata does not match this intake manifest"
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
    check.add_argument("--pilot-evidence", required=True, type=Path)
    check.add_argument("--intake-manifest", required=True, type=Path)
    check.add_argument("--release-execution-evidence", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        try:
            document = _load(EVIDENCE_INDEX)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("phase6-operations-evidence-index-invalid", file=sys.stderr)
            return 1
        errors = index_errors(document) + repository_contract_errors()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("phase6-operations-evidence-index-ok status=pending production_acceptance=false")
        return 0
    try:
        document = _load(arguments.input)
        pilot_inputs = _load(arguments.pilot_inputs)
        pilot_evidence = _load(arguments.pilot_evidence)
        manifest = _load(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("phase6-operations-evidence-index-invalid", file=sys.stderr)
        return 1
    errors = index_errors(document)
    if not errors and document.get("synthetic") is not False:
        errors.append("Phase 6 operations evidence index must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = phase6_alignment_errors(document, pilot_inputs, pilot_evidence)
    binding_errors += intake_binding_errors(document, manifest)
    bindings = document.get("bindings", {})
    binding_errors += release_execution_alignment_errors(
        document.get("release_execution"),
        arguments.release_execution_evidence,
        environment=document.get("environment"),
        release_tag=bindings.get("release_tag"),
        release_commit=bindings.get("release_commit"),
        container_manifest_sha256=bindings.get("container_manifest_sha256"),
    )
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("phase6-operations-evidence-index-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
