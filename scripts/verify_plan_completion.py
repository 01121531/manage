"""Audit chapter-12 repository progress without claiming target completion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "deploy" / "plan-completion-ledger.json"
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.external_text import load_stable_text
from scripts.verify_phase_acceptance_matrix import MATRIX, matrix_errors
from scripts.verify_chapter13_defaults import DECISIONS, decision_errors
from scripts.verify_chapter14_mvi import (
    CONTRACT as CHAPTER14_CONTRACT,
    contract_errors as chapter14_contract_errors,
)


EXPECTED_COMPLETION_CLASSES = {
    0: "repository_boundary_partial_external_inputs_and_target_evidence_pending",
    1: "repository_gate_passed_target_evidence_pending",
    2: "repository_gate_passed_external_inputs_and_target_evidence_pending",
    3: "repository_gate_passed_external_inputs_and_target_evidence_pending",
    4: "generic_adapter_gate_passed_external_inputs_and_target_evidence_pending",
    5: "repository_gate_passed_external_inputs_and_target_evidence_pending",
    6: "repository_preflight_target_execution_pending",
}
MAX_QUALITY_GATE_BYTES = 64 * 1024

_EXPECTED_ENTRYPOINTS = {
    0: {
        "gate_commands": (
            "python scripts/provider_contract_conformance.py verify-repository",
            "python scripts/decision_envelope_validation.py verify-repository",
            "python scripts/phase0_boundary_approval.py verify-repository",
            "python scripts/target_platform_inventory.py verify-repository",
            "python scripts/target_intake_preflight.py verify-requirements",
        ),
        "runbooks": ("deploy/runbooks/target-intake-preflight.md",),
        "test_modules": (
            "tests/test_provider_contract_conformance.py",
            "tests/test_decision_envelope_validation.py",
            "tests/test_phase0_boundary_approval.py",
            "tests/test_target_platform_inventory.py",
            "tests/test_target_intake_preflight.py",
        ),
    },
    1: {
        "gate_commands": (
            "python scripts/verify_compose_env.py",
            "python scripts/verify_runtime_secrets.py",
            "python scripts/verify_vault_isolation.py",
            "python scripts/verify_edge_assets.py",
            "python scripts/verify_internal_tls.py",
            "python scripts/private_secret_crash_evidence.py verify-repository",
            "python scripts/verify_private_secret_crash_evidence.py",
            "python scripts/private_secret_github_attestation.py verify-repository",
            "python scripts/private_secret_target_provenance.py verify-repository",
            "python scripts/verify_private_secret_provenance.py",
            "python scripts/private_secret_github_rest_collection.py verify-repository",
            "python scripts/private_secret_worm_collection.py verify-repository",
            "python scripts/verify_private_secret_collection.py",
            "python scripts/private_secret_collection_review_decision.py verify-repository",
            "python scripts/verify_private_secret_collection_review.py",
            "python scripts/private_secret_collection_archive_receipt.py verify-repository",
            "python scripts/verify_private_secret_collection_archive.py",
            "python scripts/verify_private_secret_collector_deployment.py",
            "python scripts/verify_keycloak_realm.py",
            "python scripts/verify_ci_workflow.py",
            "python scripts/verify_release_workflow.py",
        ),
        "runbooks": (
            "deploy/runbooks/runtime-secrets.md",
            "deploy/runbooks/private-secret-provenance.md",
            "deploy/runbooks/internal-tls.md",
            "deploy/runbooks/keycloak-mfa.md",
            "deploy/runbooks/deploy.md",
        ),
        "test_modules": (
            "tests/test_runtime_secrets.py",
            "tests/test_vault_isolation.py",
            "tests/test_edge_assets.py",
            "tests/test_internal_tls.py",
            "tests/test_private_secret_crash_evidence.py",
            "tests/test_verify_private_secret_crash_evidence.py",
            "tests/test_private_secret_github_attestation.py",
            "tests/test_private_secret_target_provenance.py",
            "tests/test_verify_private_secret_provenance.py",
            "tests/test_private_secret_github_rest_collection.py",
            "tests/test_private_secret_worm_collection.py",
            "tests/test_verify_private_secret_collection.py",
            "tests/test_private_secret_collection_backed_acceptance.py",
            "tests/test_private_secret_collection_review_decision.py",
            "tests/test_verify_private_secret_collection_review.py",
            "tests/test_private_secret_collection_archive_receipt.py",
            "tests/test_verify_private_secret_collection_archive.py",
            "tests/test_private_secret_collector_deployment.py",
            "tests/test_verify_private_secret_collector_deployment.py",
            "tests/test_keycloak_realm.py",
            "tests/test_ci_workflow.py",
            "tests/test_release_workflow.py",
        ),
    },
    2: {
        "gate_commands": (
            "python scripts/verify_service_boundaries.py",
            "python scripts/verify_http_error_boundary.py",
            "python scripts/verify_vault_broker_contract.py",
        ),
        "runbooks": ("deploy/runbooks/incident-response.md",),
        "test_modules": (
            "platform/tests/test_mail_sessions.py",
            "platform/tests/test_mail_http_connector.py",
            "tests/test_service_boundaries.py",
            "tests/test_vault_broker_contract.py",
        ),
    },
    3: {
        "gate_commands": (
            "python scripts/decision_envelope_validation.py verify-repository",
            "python scripts/verify_keycloak_realm.py",
            "python scripts/verify_migration_compatibility.py",
        ),
        "runbooks": (
            "deploy/runbooks/keycloak-mfa.md",
            "deploy/runbooks/migration-rollout.md",
        ),
        "test_modules": (
            "platform/tests/test_cards.py",
            "platform/tests/test_card_events_append_only.py",
            "tests/test_decision_envelope_validation.py",
            "tests/test_keycloak_realm.py",
            "tests/test_migration_compatibility.py",
        ),
    },
    4: {
        "gate_commands": (
            "python scripts/provider_contract_conformance.py verify-repository",
            "python scripts/sub2_execution_evidence.py verify-repository",
            "python scripts/vault_egress_evidence.py verify-repository",
        ),
        "runbooks": ("deploy/runbooks/target-intake-preflight.md",),
        "test_modules": (
            "platform/tests/test_sub2_http_adapter.py",
            "platform/tests/test_sub2_concurrency.py",
            "tests/test_provider_contract_conformance.py",
            "tests/test_sub2_execution_evidence.py",
            "tests/test_vault_egress_evidence.py",
        ),
    },
    5: {
        "gate_commands": (
            "python scripts/verify_desktop_package.py",
            "python scripts/verify_release_workflow.py",
        ),
        "runbooks": (
            "deploy/runbooks/deploy.md",
            "deploy/runbooks/device-revocation.md",
        ),
        "test_modules": (
            "tests/test_desktop_package_boundary.py",
            "tests/test_platform_desktop.py",
            "tests/test_platform_clipboard.py",
            "tests/test_update_client.py",
        ),
    },
    6: {
        "gate_commands": (
            "python scripts/phase6_rehearsal.py run",
            "python scripts/phase6_rehearsal.py verify",
            "python scripts/verify_monitoring_assets.py",
            "python scripts/verify_backup_tools.py",
            "python scripts/verify_rollback_assets.py",
            "python scripts/verify_training_assets.py",
            "python scripts/phase6_pilot_inputs.py verify-repository",
            "python scripts/phase6_pilot_evidence.py verify-repository",
            "python scripts/phase6_operations_evidence.py verify-repository",
        ),
        "runbooks": (
            "deploy/runbooks/phase6-rehearsal.md",
            "deploy/runbooks/alert-delivery.md",
            "deploy/runbooks/restore.md",
            "deploy/runbooks/vault-restore.md",
            "deploy/runbooks/rollback.md",
            "deploy/runbooks/role-training.md",
        ),
        "test_modules": (
            "tests/test_phase6_rehearsal.py",
            "tests/test_monitoring_assets.py",
            "tests/test_postgres_maintenance.py",
            "tests/test_redis_maintenance.py",
            "tests/test_rollback_release.py",
            "tests/test_training_evidence.py",
            "tests/test_phase6_pilot_inputs.py",
            "tests/test_phase6_pilot_evidence.py",
            "tests/test_phase6_operations_evidence.py",
        ),
    },
}

_PAYLOAD_KEYS = {
    "schema_version", "record_type", "plan_chapter", "audit_scope",
    "ledger_status", "external_evidence_policy", "production_acceptance",
    "phase_acceptance_matrix_sha256", "phases", "supplemental_chapters",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_PHASE_KEYS = {
    "phase", "repository_status", "completion_class", "production_acceptance",
    "target_evidence_state", "missing_input_state", "gate_commands", "runbooks",
    "test_modules",
}
_INTEGRITY_KEYS = {"payload_sha256"}
_SUPPLEMENTAL_KEYS = {
    "repository_status", "completion_class", "production_acceptance",
    "source_path", "source_sha256", "gate_commands", "test_modules",
    "external_confirmation_state",
}
_EXPECTED_SUPPLEMENTAL = {
    "13": {
        "repository_status": "defaults_locked_with_unvalidated_capacity",
        "completion_class": "repository_defaults_locked_external_confirmation_pending",
        "source_path": "deploy/chapter13-default-decisions.json",
        "gate_commands": ["python scripts/verify_chapter13_defaults.py"],
        "test_modules": ["tests/test_chapter13_defaults.py"],
    },
    "14": {
        "repository_status": "local_ci_rehearsal_only",
        "completion_class": "repository_mvi_rehearsal_passed_target_execution_pending",
        "source_path": "deploy/chapter14-mvi-contract.json",
        "gate_commands": ["python scripts/verify_chapter14_mvi.py"],
        "test_modules": ["tests/test_chapter14_mvi.py"],
    },
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_ledger(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def audit_errors(
    document: Any,
    matrix: Any,
    chapter13: Any | None = None,
    chapter14: Any | None = None,
) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["completion ledger top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["completion ledger integrity is invalid"]

    errors: list[str] = []
    if (
        payload.get("schema_version") != 1
        or payload.get("record_type") != "plan_completion_ledger"
        or payload.get("plan_chapter") != "12"
        or payload.get("audit_scope") != "phase_0_through_6"
        or payload.get("ledger_status")
        != "repository_and_preflight_evidence_only"
        or payload.get("external_evidence_policy")
        != "required_before_production_acceptance"
    ):
        errors.append("completion ledger identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("completion ledger must not claim production acceptance")
    if matrix_errors(matrix):
        errors.append("completion ledger acceptance matrix is invalid")
        return errors
    if payload.get("phase_acceptance_matrix_sha256") != _canonical_digest(matrix):
        errors.append(
            "completion ledger matrix digest does not match the acceptance matrix"
        )

    phases = payload.get("phases")
    matrix_phases = matrix.get("phases") if isinstance(matrix, dict) else None
    if not isinstance(phases, list) or len(phases) != 7:
        errors.append("completion ledger must contain exactly phases 0 through 6")
        return errors
    if not isinstance(matrix_phases, list) or len(matrix_phases) != 7:
        return errors
    for index, (phase, matrix_phase) in enumerate(
        zip(phases, matrix_phases, strict=True)
    ):
        if not _exact_mapping(phase, _PHASE_KEYS):
            errors.append(f"completion ledger phase {index} schema is invalid")
            continue
        expected_entrypoints = _EXPECTED_ENTRYPOINTS[index]
        if (
            phase.get("phase") != index
            or phase.get("repository_status")
            != matrix_phase.get("repository_status")
            or phase.get("completion_class")
            != EXPECTED_COMPLETION_CLASSES[index]
        ):
            errors.append(f"completion ledger phase {index} status is invalid")
        if phase.get("production_acceptance") is not False:
            errors.append(
                f"completion ledger phase {index} must not claim production acceptance"
            )
        if (
            not isinstance(matrix_phase.get("target_evidence_required"), list)
            or not matrix_phase["target_evidence_required"]
            or phase.get("target_evidence_state") != "required_external"
        ):
            errors.append(
                f"completion ledger phase {index} target-evidence state is invalid"
            )
        expected_missing_state = (
            "required_external" if matrix_phase.get("missing_inputs") else "none_declared"
        )
        if phase.get("missing_input_state") != expected_missing_state:
            errors.append(
                f"completion ledger phase {index} missing-input state is invalid"
            )
        for key in ("gate_commands", "runbooks", "test_modules"):
            if phase.get(key) != list(expected_entrypoints[key]):
                errors.append(
                    f"completion ledger phase {index} {key} inventory is invalid"
                )
    if chapter13 is None or chapter14 is None:
        try:
            chapter13 = load_unique_json(
                DECISIONS,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
            chapter14 = load_unique_json(
                CHAPTER14_CONTRACT,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append("completion ledger supplemental source is unavailable")
            return errors
    try:
        chapter13_errors = decision_errors(chapter13)
    except (OSError, UnicodeError, json.JSONDecodeError):
        chapter13_errors = ["Chapter 13 source is unavailable"]
    if chapter13_errors:
        errors.append("completion ledger Chapter 13 source contract is invalid")
    if chapter14_contract_errors(chapter14):
        errors.append("completion ledger Chapter 14 source contract is invalid")
    supplemental = payload.get("supplemental_chapters")
    if not isinstance(supplemental, dict) or set(supplemental) != {"13", "14"}:
        errors.append("completion ledger supplemental chapter inventory is invalid")
        return errors
    sources = {"13": chapter13, "14": chapter14}
    for chapter, expected in _EXPECTED_SUPPLEMENTAL.items():
        record = supplemental.get(chapter)
        if not _exact_mapping(record, _SUPPLEMENTAL_KEYS):
            errors.append(
                f"completion ledger Chapter {chapter} schema is invalid"
            )
            continue
        if (
            record.get("repository_status") != expected["repository_status"]
            or record.get("completion_class") != expected["completion_class"]
            or record.get("production_acceptance") is not False
            or record.get("source_path") != expected["source_path"]
            or record.get("gate_commands") != expected["gate_commands"]
            or record.get("test_modules") != expected["test_modules"]
            or record.get("external_confirmation_state") != "required_external"
        ):
            errors.append(
                f"completion ledger Chapter {chapter} status or entrypoint is invalid"
            )
        if record.get("source_sha256") != _canonical_digest(sources[chapter]):
            errors.append(
                f"completion ledger Chapter {chapter} source digest is invalid"
            )
    return errors


def repository_entrypoint_errors(document: Any) -> list[str]:
    phases = document.get("phases") if isinstance(document, dict) else None
    if not isinstance(phases, list):
        return ["completion ledger entrypoint inventory is invalid"]
    try:
        quality_gate = load_stable_text(
            QUALITY_GATE,
            max_bytes=MAX_QUALITY_GATE_BYTES,
        )
    except (OSError, UnicodeError):
        return ["completion ledger quality gate is unavailable"]
    errors: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict) or not isinstance(phase.get("phase"), int):
            errors.append("completion ledger entrypoint phase is invalid")
            continue
        number = phase["phase"]
        for command in phase.get("gate_commands", []):
            if not isinstance(command, str) or command not in quality_gate:
                errors.append(
                    f"completion ledger phase {number} gate command is not active"
                )
                continue
            match = re.match(r"^python (scripts/[A-Za-z0-9_.-]+\.py)", command)
            if match is None or not (ROOT / match.group(1)).is_file():
                errors.append(
                    f"completion ledger phase {number} verifier path is invalid"
                )
        for key, prefix in (
            ("runbooks", "deploy/runbooks/"),
            ("test_modules", ("tests/", "platform/tests/")),
        ):
            for value in phase.get(key, []):
                prefixes = (prefix,) if isinstance(prefix, str) else prefix
                if (
                    not isinstance(value, str)
                    or not value.startswith(prefixes)
                    or not (ROOT / value).is_file()
                ):
                    errors.append(
                        f"completion ledger phase {number} {key} path is invalid"
                    )
    supplemental = document.get("supplemental_chapters")
    if not isinstance(supplemental, dict):
        errors.append("completion ledger supplemental entrypoints are invalid")
        return errors
    for chapter, record in supplemental.items():
        if not isinstance(record, dict):
            errors.append(
                f"completion ledger Chapter {chapter} entrypoints are invalid"
            )
            continue
        source_path = record.get("source_path")
        if not isinstance(source_path, str) or not (ROOT / source_path).is_file():
            errors.append(
                f"completion ledger Chapter {chapter} source path is invalid"
            )
        for command in record.get("gate_commands", []):
            if not isinstance(command, str) or command not in quality_gate:
                errors.append(
                    f"completion ledger Chapter {chapter} gate command is not active"
                )
        for test_module in record.get("test_modules", []):
            if (
                not isinstance(test_module, str)
                or not test_module.startswith("tests/")
                or not (ROOT / test_module).is_file()
            ):
                errors.append(
                    f"completion ledger Chapter {chapter} test path is invalid"
                )
    return errors


def main() -> int:
    try:
        ledger = load_unique_json(
            LEDGER,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        matrix = load_unique_json(
            MATRIX,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        chapter13 = load_unique_json(
            DECISIONS,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        chapter14 = load_unique_json(
            CHAPTER14_CONTRACT,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("plan-completion-audit-invalid", file=sys.stderr)
        return 1
    errors = audit_errors(
        ledger,
        matrix,
        chapter13,
        chapter14,
    ) + repository_entrypoint_errors(ledger)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "plan-completion-audit-ok phases=7 chapters=12,13,14 production_acceptance=false "
        "external_evidence=pending"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
