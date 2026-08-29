"""Validate typed, sealed target inputs and evidence for plan Phases 1/2/3/5."""

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

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    load_unique_json,
    load_unique_json_with_bytes,
)
from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    selector_errors as release_execution_selector_errors,
)


ARTIFACT_PATHS = {
    "phase1_platform_evidence": ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "phase1-platform.synthetic.json",
    "phase2_mail_evidence": ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "phase2-mail.synthetic.json",
    "phase3_card_evidence": ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "phase3-card.synthetic.json",
    "windows_pilot_inputs": ROOT
    / "deploy"
    / "inventory-envelopes"
    / "windows-pilot-inputs.synthetic.json",
    "phase5_windows_evidence": ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "phase5-windows.synthetic.json",
}

SCENARIO_CONTRACTS = {
    "phase1_platform_evidence": {
        "keycloak_login_authorization": "login_and_authorization_enforced",
        "keycloak_vault_audit": "audit_events_retained",
        "administrator_separation": "administrative_roles_separated",
        "postgres_redis_private_runtime": "private_data_services_reachable_only_as_approved",
        "internal_tls_secret_manager": "tls_and_secret_manager_controls_enforced",
        "backup_restore_readiness": "backup_restore_completed",
        "ci_release_candidate": "reviewed_release_candidate_promoted",
    },
    "phase2_mail_evidence": {
        "mail_concurrency": "reviewed_concurrency_limit_enforced",
        "mail_outage": "outage_failed_closed_without_code_disclosure",
        "mail_rate_limit": "provider_rate_limit_honored",
        "mail_stale_code": "stale_code_rejected",
        "worker_credential_isolation": "worker_only_credential_enforced",
        "worker_egress_enforcement": "mail_egress_allowlist_enforced",
    },
    "phase3_card_evidence": {
        "postgres_concurrent_allocation": "single_active_allocation_enforced",
        "target_migration": "target_migration_completed",
        "keycloak_step_up": "required_loa_step_up_enforced",
        "pci_scope_enforcement": "approved_pci_boundary_enforced",
    },
    "phase5_windows_evidence": {
        "windows_exe_login": "target_oidc_login_completed",
        "lock_logout_expiry_stop": "sensitive_action_stopped_after_session_loss",
        "offline_recovery": "offline_state_recovered_without_secret_persistence",
        "update_rollback": "signed_update_rollback_completed",
        "clipboard_continuous_paste": "continuous_paste_completed_in_approved_order",
        "business_field_order": "approved_business_field_sequence_preserved",
    },
}

_RECORD_TYPES = {
    identifier: f"{identifier}_index" for identifier in SCENARIO_CONTRACTS
}
_BINDING_TARGETS = {
    "phase1_platform_evidence": ("target_platform_inventory",),
    "phase2_mail_evidence": ("mail_contract", "target_platform_inventory"),
    "phase3_card_evidence": (
        "card_pci_boundary",
        "oidc_deployment_identity",
        "target_platform_inventory",
    ),
    "phase5_windows_evidence": (
        "windows_pilot_inputs",
        "target_platform_inventory",
    ),
}
_COMMON_BINDINGS = {"release_tag", "release_commit", "container_manifest_sha256"}
_EVIDENCE_PAYLOAD_KEYS = {
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
_WINDOW_KEYS = {"started_at", "finished_at"}
_SCENARIO_KEYS = {
    "execution_reference",
    "executor_reference",
    "reviewer_reference",
    "correlation_reference",
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
    "contains_request_or_response_bodies",
    "contains_provider_urls",
    "contains_pan_values",
    "contains_cvv_values",
    "contains_verification_code_values",
    "contains_token_values",
}
_WINDOWS_PAYLOAD_KEYS = {
    "schema_version",
    "record_type",
    "inventory_reference",
    "synthetic",
    "inventory_status",
    "review_reference",
    "reviewed_at",
    "valid_until",
    "production_acceptance",
    "environment",
    "bindings",
    "windows_target",
    "business_page",
    "prohibited_content",
}
_WINDOWS_TARGET_KEYS = {
    "environment_reference",
    "os_family",
    "architecture",
    "update_channel_reference",
}
_BUSINESS_PAGE_KEYS = {
    "page_reference",
    "field_sequence",
    "continuous_paste_required",
}
_SEALED_EXTRA_KEYS = {"integrity"}
_INTEGRITY_KEYS = {"payload_sha256"}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_FIELD_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
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


def seal_artifact(payload: dict[str, Any]) -> dict[str, Any]:
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


def _valid_environment(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _ENVIRONMENT.fullmatch(value) is not None
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


def _integrity_errors(document: Any, payload_keys: set[str], label: str) -> list[str]:
    if not isinstance(document, dict) or set(document) != payload_keys | _SEALED_EXTRA_KEYS:
        return [f"{label} top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return [f"{label} integrity is invalid"]
    return []


def _prohibited_errors(payload: dict[str, Any], label: str) -> list[str]:
    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        return [f"{label} prohibited-content declaration is invalid"]
    return []


def _evidence_errors(
    document: Any,
    identifier: str,
    *,
    evaluated_at: datetime,
) -> list[str]:
    label = identifier.replace("_", " ")
    errors = _integrity_errors(document, _EVIDENCE_PAYLOAD_KEYS, label)
    if errors:
        return errors
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 3
        or payload.get("record_type") != _RECORD_TYPES[identifier]
        or payload.get("production_acceptance") is not False
    ):
        errors.append(f"{label} identity is invalid")
    errors.extend(_prohibited_errors(payload, label))

    bindings = payload.get("bindings")
    expected_binding_keys = _COMMON_BINDINGS | {
        f"{target}_sha256" for target in _BINDING_TARGETS[identifier]
    }
    window = payload.get("window")
    scenarios = payload.get("scenarios")
    if not _exact_mapping(bindings, expected_binding_keys):
        errors.append(f"{label} binding schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append(f"{label} window schema is invalid")
    if not _exact_mapping(scenarios, set(SCENARIO_CONTRACTS[identifier])):
        errors.append(f"{label} scenario inventory is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("index_reference")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append(f"{label} index reference is invalid")
        return errors
    if synthetic:
        if (
            not reference.startswith("synthetic-")
            or payload.get("index_status") != "pending"
            or payload.get("review_reference") is not None
            or payload.get("reviewed_at") is not None
            or payload.get("valid_until") is not None
            or payload.get("environment") != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or window != {"started_at": None, "finished_at": None}
            or release_execution_selector_errors(
                payload.get("release_execution"), synthetic=True
            )
            or not isinstance(scenarios, dict)
            or any(value is not None for value in scenarios.values())
        ):
            errors.append(f"synthetic {label} metadata is invalid")
        return errors

    if (
        reference.startswith("synthetic-")
        or payload.get("index_status") != "reviewed"
        or not _safe_reference(payload.get("review_reference"))
        or payload.get("review_reference") == reference
        or not _valid_environment(payload.get("environment"))
    ):
        errors.append(f"reviewed {label} metadata is invalid")
    if isinstance(bindings, dict):
        if (
            not isinstance(bindings.get("release_tag"), str)
            or _TAG.fullmatch(bindings["release_tag"]) is None
            or not isinstance(bindings.get("release_commit"), str)
            or _COMMIT.fullmatch(bindings["release_commit"]) is None
            or any(
                not isinstance(bindings.get(key), str)
                or _SHA256.fullmatch(bindings[key]) is None
                for key in expected_binding_keys - {"release_tag", "release_commit"}
            )
        ):
            errors.append(f"reviewed {label} release or intake binding is invalid")
    errors.extend(
        f"{label} {error}"
        for error in release_execution_selector_errors(
            payload.get("release_execution"),
            synthetic=False,
            environment=(
                payload.get("environment")
                if isinstance(payload.get("environment"), str)
                else None
            ),
        )
    )
    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    if started_at is None or finished_at is None or finished_at <= started_at:
        errors.append(f"reviewed {label} window is invalid")
    reviewed_at = _parse_utc(payload.get("reviewed_at"))
    valid_until = _parse_utc(payload.get("valid_until"))
    if (
        reviewed_at is None
        or valid_until is None
        or finished_at is None
        or reviewed_at < finished_at
        or valid_until <= reviewed_at
    ):
        errors.append(f"reviewed {label} review validity is invalid")
    elif not reviewed_at <= evaluated_at < valid_until:
        errors.append(f"reviewed {label} is not currently valid")

    unique: dict[str, list[str]] = {
        "execution_reference": [],
        "correlation_reference": [],
        "evidence_object_reference": [],
        "evidence_sha256": [],
    }
    if isinstance(scenarios, dict):
        for scenario, observation in SCENARIO_CONTRACTS[identifier].items():
            result = scenarios.get(scenario)
            if not _exact_mapping(result, _SCENARIO_KEYS):
                errors.append(f"{label} {scenario} scenario schema is invalid")
                continue
            references = (
                "execution_reference",
                "executor_reference",
                "reviewer_reference",
                "correlation_reference",
                "evidence_object_reference",
            )
            if not all(_safe_reference(result.get(key)) for key in references):
                errors.append(f"{label} {scenario} references are invalid")
            elif result["executor_reference"] == result["reviewer_reference"]:
                errors.append(f"{label} {scenario} reviewer is not independent")
            if (
                result.get("observation") != observation
                or result.get("result") != "passed"
                or result.get("redaction_confirmed") is not True
            ):
                errors.append(f"{label} {scenario} result is invalid")
            executed_at = _parse_utc(result.get("executed_at"))
            if (
                executed_at is None
                or started_at is None
                or finished_at is None
                or not started_at <= executed_at <= finished_at
            ):
                errors.append(f"{label} {scenario} timestamp is outside the window")
            digest = result.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"{label} {scenario} artifact digest is invalid")
            for key in unique:
                value = result.get(key)
                if isinstance(value, str):
                    unique[key].append(value)
    for field, values in unique.items():
        if len(values) != len(set(values)):
            errors.append(f"{label} {field} values must be unique")
    return errors


def _windows_input_errors(document: Any, *, evaluated_at: datetime) -> list[str]:
    label = "windows pilot inputs"
    errors = _integrity_errors(document, _WINDOWS_PAYLOAD_KEYS, label)
    if errors:
        return errors
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 2
        or payload.get("record_type") != "windows_pilot_input_inventory"
        or payload.get("production_acceptance") is not False
    ):
        errors.append(f"{label} identity is invalid")
    errors.extend(_prohibited_errors(payload, label))
    bindings = payload.get("bindings")
    target = payload.get("windows_target")
    business = payload.get("business_page")
    if not _exact_mapping(bindings, {"target_platform_inventory_sha256"}):
        errors.append(f"{label} binding schema is invalid")
    if not _exact_mapping(target, _WINDOWS_TARGET_KEYS):
        errors.append(f"{label} target schema is invalid")
    if not _exact_mapping(business, _BUSINESS_PAGE_KEYS):
        errors.append(f"{label} business-page schema is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("inventory_reference")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append(f"{label} inventory reference is invalid")
        return errors
    if synthetic:
        if (
            not reference.startswith("synthetic-")
            or payload.get("inventory_status") != "pending"
            or payload.get("review_reference") is not None
            or payload.get("reviewed_at") is not None
            or payload.get("valid_until") is not None
            or payload.get("environment") != "production"
            or bindings != {"target_platform_inventory_sha256": None}
            or not isinstance(target, dict)
            or any(value is not None for value in target.values())
            or business
            != {
                "page_reference": None,
                "field_sequence": [],
                "continuous_paste_required": True,
            }
        ):
            errors.append(f"synthetic {label} metadata is invalid")
        return errors

    if (
        reference.startswith("synthetic-")
        or payload.get("inventory_status") != "reviewed"
        or not _safe_reference(payload.get("review_reference"))
        or payload.get("review_reference") == reference
        or not _valid_environment(payload.get("environment"))
    ):
        errors.append(f"reviewed {label} metadata is invalid")
    if isinstance(bindings, dict):
        digest = bindings.get("target_platform_inventory_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            errors.append(f"reviewed {label} binding is invalid")
    if isinstance(target, dict) and (
        not _safe_reference(target.get("environment_reference"))
        or target.get("os_family") != "windows"
        or target.get("architecture") not in {"x86_64", "arm64"}
        or not _safe_reference(target.get("update_channel_reference"))
    ):
        errors.append(f"reviewed {label} target is invalid")
    if isinstance(business, dict):
        fields = business.get("field_sequence")
        if (
            not _safe_reference(business.get("page_reference"))
            or not isinstance(fields, list)
            or not 2 <= len(fields) <= 32
            or any(
                not isinstance(field, str)
                or _FIELD_IDENTIFIER.fullmatch(field) is None
                for field in fields
            )
            or len(fields) != len(set(fields))
            or business.get("continuous_paste_required") is not True
        ):
            errors.append(f"reviewed {label} business-page contract is invalid")
    reviewed_at = _parse_utc(payload.get("reviewed_at"))
    valid_until = _parse_utc(payload.get("valid_until"))
    if reviewed_at is None or valid_until is None or valid_until <= reviewed_at:
        errors.append(f"reviewed {label} review validity is invalid")
    elif not reviewed_at <= evaluated_at < valid_until:
        errors.append(f"reviewed {label} is not currently valid")
    return errors


def artifact_errors(
    document: Any,
    *,
    expected_type: str,
    evaluated_at: datetime | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or datetime.now(timezone.utc)
    if expected_type == "windows_pilot_inputs":
        return _windows_input_errors(document, evaluated_at=evaluation_time)
    if expected_type in SCENARIO_CONTRACTS:
        return _evidence_errors(
            document,
            expected_type,
            evaluated_at=evaluation_time,
        )
    return ["target phase artifact type is invalid"]


def intake_binding_errors(document: Any, manifest: Any, *, expected_type: str) -> list[str]:
    label = expected_type.replace("_", " ")
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return [f"{label} bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return [f"{label} intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append(f"{label} environment does not match this intake manifest")
    if expected_type != "windows_pilot_inputs":
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
                f"{label} release execution intake does not match this intake manifest"
            )
    targets = (
        ("target_platform_inventory",)
        if expected_type == "windows_pilot_inputs"
        else _BINDING_TARGETS.get(expected_type, ())
    )
    for target in targets:
        matches = [
            item
            for item in manifest["items"]
            if isinstance(item, dict) and item.get("id") == target
        ]
        if (
            len(matches) != 1
            or matches[0].get("status") != "provided"
            or not isinstance(matches[0].get("sha256"), str)
            or _SHA256.fullmatch(matches[0]["sha256"]) is None
        ):
            errors.append(f"{label} {target} binding target is not provided")
        elif document["bindings"].get(f"{target}_sha256") != matches[0]["sha256"]:
            errors.append(f"{label} {target} binding does not match this intake manifest")
    own_items = [
        item
        for item in manifest["items"]
        if isinstance(item, dict) and item.get("id") == expected_type
    ]
    if (
        len(own_items) != 1
        or own_items[0].get("status") != "provided"
        or own_items[0].get("reviewed_by") != document.get("review_reference")
        or own_items[0].get("reviewed_at") != document.get("reviewed_at")
    ):
        errors.append(f"{label} review metadata does not match this intake manifest")
    return errors


def phase5_windows_alignment_errors(
    evidence: Any,
    windows_inputs: Any,
) -> list[str]:
    if not isinstance(evidence, dict) or not isinstance(windows_inputs, dict):
        return ["Phase 5 Windows evidence or pilot inputs are invalid"]
    window = evidence.get("window")
    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    inputs_reviewed_at = _parse_utc(windows_inputs.get("reviewed_at"))
    inputs_valid_until = _parse_utc(windows_inputs.get("valid_until"))
    if (
        started_at is None
        or finished_at is None
        or inputs_reviewed_at is None
        or inputs_valid_until is None
        or started_at < inputs_reviewed_at
        or finished_at >= inputs_valid_until
    ):
        return [
            "Phase 5 Windows evidence window is outside the pilot-input validity interval"
        ]
    return []


def repository_errors() -> list[str]:
    errors: list[str] = []
    for identifier, path in ARTIFACT_PATHS.items():
        try:
            document = load_unique_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(f"{identifier} synthetic artifact is unavailable")
            continue
        errors.extend(artifact_errors(document, expected_type=identifier))
        if isinstance(document, dict) and document.get("synthetic") is not True:
            errors.append(f"{identifier} repository artifact must remain synthetic")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    check.add_argument("--expected-type", required=True, choices=tuple(ARTIFACT_PATHS))
    check.add_argument("--intake-manifest", required=True, type=Path)
    check.add_argument("--release-execution-evidence", type=Path)
    check.add_argument("--windows-pilot-inputs", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        errors = repository_errors()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("target-phase-artifacts-ok status=pending production_acceptance=false")
        return 0
    try:
        document = load_unique_json(arguments.input)
        manifest = load_unique_json(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("target-phase-artifact-invalid", file=sys.stderr)
        return 1
    evaluated_at = datetime.now(timezone.utc)
    errors = artifact_errors(
        document,
        expected_type=arguments.expected_type,
        evaluated_at=evaluated_at,
    )
    if not errors and document.get("synthetic") is not False:
        errors.append("target phase artifact must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    binding_errors = intake_binding_errors(
        document,
        manifest,
        expected_type=arguments.expected_type,
    )
    if arguments.expected_type != "windows_pilot_inputs":
        if arguments.release_execution_evidence is None:
            binding_errors.append("target evidence requires release execution evidence")
        else:
            bindings = document.get("bindings", {})
            binding_errors += release_execution_alignment_errors(
                document.get("release_execution"),
                arguments.release_execution_evidence,
                environment=document.get("environment"),
                release_tag=bindings.get("release_tag"),
                release_commit=bindings.get("release_commit"),
                container_manifest_sha256=bindings.get(
                    "container_manifest_sha256"
                ),
            )
    if arguments.expected_type == "phase5_windows_evidence":
        if arguments.windows_pilot_inputs is None:
            binding_errors.append("Phase 5 evidence requires Windows pilot inputs")
        else:
            try:
                windows_inputs, windows_raw = load_unique_json_with_bytes(
                    arguments.windows_pilot_inputs
                )
            except (OSError, UnicodeError, json.JSONDecodeError):
                binding_errors.append("Phase 5 Windows pilot inputs are invalid")
            else:
                windows_errors = artifact_errors(
                    windows_inputs,
                    expected_type="windows_pilot_inputs",
                    evaluated_at=evaluated_at,
                )
                if windows_inputs.get("synthetic") is not False:
                    windows_errors.append(
                        "Phase 5 Windows pilot inputs must be reviewed non-synthetic material"
                    )
                if windows_errors:
                    binding_errors.append("Phase 5 Windows pilot inputs are invalid")
                elif hashlib.sha256(windows_raw).hexdigest() != document.get(
                    "bindings", {}
                ).get("windows_pilot_inputs_sha256"):
                    binding_errors.append(
                        "Phase 5 Windows pilot inputs do not match the evidence binding"
                    )
                else:
                    binding_errors.extend(
                        phase5_windows_alignment_errors(document, windows_inputs)
                    )
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("target-phase-artifact-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
