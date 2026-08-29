"""Create and verify repository-external target-environment intake metadata."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
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

from scripts.verify_phase_acceptance_matrix import matrix_errors
from scripts.external_json import (
    MAX_EXTERNAL_JSON_BYTES as _MAX_ARTIFACT_BYTES,
    MAX_INTAKE_JSON_BYTES as _MAX_MANIFEST_BYTES,
    StableFileError as _StableFileError,
    has_link_or_reparse_ancestor as _has_link_or_reparse_ancestor,
    is_link_or_reparse as _is_link_or_reparse,
    parse_unique_json_bytes,
    read_stable_bytes as _read_stable_bytes,
)
from scripts.decision_envelope_validation import decision_errors
from scripts.phase0_boundary_approval import approval_errors, intake_binding_errors
from scripts.phase6_pilot_inputs import (
    intake_binding_errors as pilot_input_binding_errors,
    inventory_errors as pilot_input_errors,
)
from scripts.phase6_pilot_evidence import (
    index_errors as pilot_evidence_errors,
    intake_binding_errors as pilot_evidence_binding_errors,
    pilot_input_alignment_errors,
)
from scripts.phase6_operations_evidence import (
    index_errors as operations_evidence_errors,
    intake_binding_errors as operations_evidence_binding_errors,
    phase6_alignment_errors as operations_alignment_errors,
)
from scripts.provider_contract_conformance import (
    contract_errors,
    runtime_conformance_errors,
)
from scripts.release_execution_binding import (
    ReleaseExecutionBindingError,
    release_execution_identity,
    release_execution_identity_alignment_errors,
)
from scripts.sub2_execution_evidence import (
    index_errors as sub2_evidence_errors,
    intake_binding_errors as sub2_evidence_binding_errors,
)
from scripts.target_platform_inventory import inventory_errors
from scripts.target_phase_artifacts import (
    artifact_errors as target_phase_artifact_errors,
    intake_binding_errors as target_phase_binding_errors,
    phase5_windows_alignment_errors,
)
from scripts.vault_egress_evidence import (
    index_errors as vault_egress_evidence_errors,
    intake_binding_errors as vault_egress_binding_errors,
)


MATRIX = ROOT / "deploy" / "phase-acceptance-matrix.json"
REQUIREMENTS = ROOT / "deploy" / "target-intake-requirements.json"

_REQUIRED_IDS = (
    "sub2_contract",
    "mail_contract",
    "card_pci_boundary",
    "oidc_deployment_identity",
    "phase0_boundary_approval",
    "target_platform_inventory",
    "phase1_platform_evidence",
    "phase2_mail_evidence",
    "phase3_card_evidence",
    "sub2_execution_evidence",
    "vault_egress_evidence",
    "windows_pilot_inputs",
    "phase5_windows_evidence",
    "release_execution_evidence",
    "phase6_pilot_inputs",
    "phase6_pilot_evidence",
    "phase6_operations_evidence",
)
_TOP_LEVEL_KEYS = {
    "schema_version",
    "plan_chapters",
    "production_acceptance",
    "manifest_policy",
    "requirements",
}
_REQUIREMENT_KEYS = {
    "id",
    "phases",
    "purpose",
    "artifact_policy",
    "matrix_refs",
}
_REFERENCE_KEYS = {"phase", "category", "value"}
_MANIFEST_KEYS = {
    "schema_version",
    "environment",
    "production_acceptance",
    "requirements_sha256",
    "items",
}
_ITEM_KEYS = {
    "id",
    "status",
    "artifact_path",
    "sha256",
    "reviewed_by",
    "reviewed_at",
    "redaction_confirmed",
}
_ALLOWED_POLICIES = {
    "redacted_contract",
    "reviewed_decision",
    "reviewed_inventory",
    "redacted_evidence_index",
    "release_execution_ledger",
}
_SUPPLEMENTAL_MATRIX_REFS = {
    "release_execution_evidence": (
        (
            1,
            "target_evidence_required",
            "target PostgreSQL, Redis, TLS, secret-manager, backup and CI release evidence",
        ),
        (
            4,
            "target_evidence_required",
            "real Sub2 balance-check, authorization-exchange, create success/failure/timeout, five status outcomes, same-key replay and unknown-reconciliation evidence",
        ),
        (
            6,
            "target_evidence_required",
            "real pilot-user end-to-end evidence and independent review",
        ),
        (
            6,
            "target_evidence_required",
            "real alert delivery, backup restore, rollback, training and audit-trace evidence",
        ),
    )
}
_MATRIX_CATEGORIES = ("missing_inputs", "target_evidence_required")
_TARGET_PHASES = tuple(range(7))
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
@dataclass(frozen=True)
class PhaseCheckpointIdentity:
    environment: str
    manifest_payload_sha256: str
    requirements_sha256: str
    checkpoint_phase: int
    evaluated_at: str
    valid_from: str
    valid_until: str

    def as_evidence(self) -> dict[str, str | int]:
        return {
            "environment": self.environment,
            "manifest_payload_sha256": self.manifest_payload_sha256,
            "requirements_sha256": self.requirements_sha256,
            "checkpoint_phase": self.checkpoint_phase,
        }

    def contains_release_start(self, value: Any) -> bool:
        started_at = _parse_utc(value)
        valid_from = _parse_utc(self.valid_from)
        valid_until = _parse_utc(self.valid_until)
        return (
            started_at is not None
            and valid_from is not None
            and valid_until is not None
            and valid_from <= started_at < valid_until
        )


class PhaseCheckpointError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("target intake checkpoint is invalid")
        self.errors = tuple(errors)


class _IntakeJsonError(ValueError):
    """One intake JSON file could not be read without ambiguity."""


def _canonical_bytes(document: Any) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def requirements_sha256(document: Any) -> str:
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def phase_requirement_ids(requirements: Any, through_phase: int) -> tuple[str, ...]:
    """Return the registry-ordered strict checkpoint through one plan phase."""

    if through_phase not in _TARGET_PHASES or not isinstance(requirements, dict):
        return ()
    items = requirements.get("requirements")
    if not isinstance(items, list):
        return ()
    identifiers: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            return ()
        identifier = item.get("id")
        phases = item.get("phases")
        if (
            not isinstance(identifier, str)
            or not isinstance(phases, list)
            or not phases
            or any(phase not in _TARGET_PHASES for phase in phases)
        ):
            return ()
        if min(phases) <= through_phase:
            identifiers.append(identifier)
    return tuple(identifiers)


def _matrix_refs(matrix: Any) -> list[tuple[int, str, str]]:
    if not isinstance(matrix, dict) or not isinstance(matrix.get("phases"), list):
        return []
    references: list[tuple[int, str, str]] = []
    for phase in matrix["phases"]:
        if not isinstance(phase, dict) or phase.get("phase") not in _TARGET_PHASES:
            continue
        phase_number = phase["phase"]
        for category in _MATRIX_CATEGORIES:
            values = phase.get(category)
            if not isinstance(values, list):
                continue
            references.extend(
                (phase_number, category, value)
                for value in values
                if isinstance(value, str)
            )
    return references


def requirements_errors(document: Any, matrix: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL_KEYS:
        return ["target intake requirements top-level schema is invalid"]
    errors: list[str] = []
    if matrix_errors(matrix):
        errors.append("phase acceptance matrix is invalid")
    if document.get("schema_version") != 1 or document.get("plan_chapters") != ["12", "14"]:
        errors.append("target intake requirements identity is invalid")
    if document.get("production_acceptance") is not False:
        errors.append("target intake requirements must not claim production acceptance")
    if document.get("manifest_policy") != "repository_external_metadata_only":
        errors.append("target intake manifest policy is invalid")

    requirements = document.get("requirements")
    if not isinstance(requirements, list):
        errors.append("target intake requirements must be a list")
        return errors
    identifiers = [
        item.get("id") if isinstance(item, dict) else None for item in requirements
    ]
    if identifiers != list(_REQUIRED_IDS):
        errors.append("target intake requirement inventory is invalid")

    actual_refs: list[tuple[int, str, str]] = []
    for item in requirements:
        if not isinstance(item, dict) or set(item) != _REQUIREMENT_KEYS:
            errors.append("target intake requirement schema is invalid")
            continue
        identifier = item.get("id")
        purpose = item.get("purpose")
        policy = item.get("artifact_policy")
        references = item.get("matrix_refs")
        if (
            not isinstance(purpose, str)
            or not purpose
            or purpose.strip() != purpose
            or policy not in _ALLOWED_POLICIES
        ):
            errors.append(f"{identifier} requirement metadata is invalid")
        if not isinstance(references, list) or not references:
            errors.append(f"{identifier} matrix references are invalid")
            continue
        phases: list[int] = []
        for reference in references:
            if not isinstance(reference, dict) or set(reference) != _REFERENCE_KEYS:
                errors.append(f"{identifier} matrix reference schema is invalid")
                continue
            phase = reference.get("phase")
            category = reference.get("category")
            value = reference.get("value")
            if (
                phase not in _TARGET_PHASES
                or category not in _MATRIX_CATEGORIES
                or not isinstance(value, str)
                or not value
                or value.strip() != value
            ):
                errors.append(f"{identifier} matrix reference is invalid")
                continue
            phases.append(phase)
            if identifier not in _SUPPLEMENTAL_MATRIX_REFS:
                actual_refs.append((phase, category, value))
        if item.get("phases") != sorted(set(phases)):
            errors.append(f"{identifier} phase inventory is invalid")
        supplemental = _SUPPLEMENTAL_MATRIX_REFS.get(identifier)
        if supplemental is not None and Counter(
            (reference.get("phase"), reference.get("category"), reference.get("value"))
            for reference in references
            if isinstance(reference, dict)
        ) != Counter(supplemental):
            errors.append(f"{identifier} supplemental matrix references are invalid")

    expected_refs = _matrix_refs(matrix)
    if not expected_refs:
        errors.append("phase acceptance matrix references are unavailable")
    elif Counter(actual_refs) != Counter(expected_refs) or len(actual_refs) != len(
        expected_refs
    ):
        errors.append("target intake requirements do not exactly cover phases 0 through 6")
    return errors


def create_intake_manifest(environment: str, requirements: Any) -> dict[str, Any]:
    requirement_items = requirements.get("requirements", []) if isinstance(requirements, dict) else []
    return {
        "schema_version": 1,
        "environment": environment,
        "production_acceptance": False,
        "requirements_sha256": requirements_sha256(requirements),
        "items": [
            {
                "id": item.get("id"),
                "status": "missing",
                "artifact_path": None,
                "sha256": None,
                "reviewed_by": None,
                "reviewed_at": None,
                "redaction_confirmed": None,
            }
            for item in requirement_items
            if isinstance(item, dict)
        ],
    }


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _canonical_utc(value: Any) -> bool:
    return _parse_utc(value) is not None


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("UTC timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _reviewer_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 128
        and value.strip() == value
        and value.casefold() not in _PLACEHOLDERS
        and all(character.isprintable() for character in value)
    )


def _artifact_errors(
    item: dict[str, Any],
    *,
    repository_root: Path,
    evaluated_at: datetime,
) -> tuple[list[str], Any | None]:
    identifier = item["id"]
    errors: list[str] = []
    artifact_bytes: bytes | None = None
    validated_document: Any | None = None
    raw_path = item.get("artifact_path")
    artifact: Path | None = None
    if not isinstance(raw_path, str) or not raw_path or not Path(raw_path).is_absolute():
        errors.append(f"{identifier} artifact path must be absolute")
    else:
        candidate = Path(raw_path)
        try:
            resolved_artifact = candidate.resolve(strict=True)
        except OSError:
            errors.append(f"{identifier} artifact is unavailable")
        else:
            artifact = candidate
            repository = repository_root.resolve()
            if resolved_artifact.is_relative_to(repository):
                errors.append(f"{identifier} artifact must be outside the repository")
            if _has_link_or_reparse_ancestor(candidate):
                errors.append(f"{identifier} artifact must not use links or reparse points")
                artifact = None
            if not resolved_artifact.is_file():
                errors.append(f"{identifier} artifact must be a regular file")
                artifact = None

    supplied_sha = item.get("sha256")
    if not isinstance(supplied_sha, str) or not _SHA256.fullmatch(supplied_sha):
        errors.append(f"{identifier} artifact sha256 is invalid")
    if artifact is not None:
        try:
            artifact_bytes = _read_stable_bytes(
                artifact,
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
        except _StableFileError as error:
            if error.reason == "size":
                errors.append(f"{identifier} artifact size is invalid")
            else:
                errors.append(f"{identifier} artifact could not be read")
        else:
            actual_sha = hashlib.sha256(artifact_bytes).hexdigest()
            if actual_sha != supplied_sha:
                errors.append(f"{identifier} artifact sha256 does not match")
    artifact_document: Any | None = None
    if artifact_bytes is not None and identifier != "release_execution_evidence":
        try:
            artifact_document = _parse_json_bytes(artifact_bytes)
        except _IntakeJsonError:
            artifact_document = None
    expected_contract_type = {
        "mail_contract": "mail",
        "sub2_contract": "sub2",
    }.get(identifier)
    if expected_contract_type is not None and artifact_bytes is not None:
        contract = artifact_document
        if contract_errors(
            contract,
            expected_type=expected_contract_type,
            evaluated_at=evaluated_at,
        ):
            errors.append(f"{identifier} provider contract envelope is invalid")
        elif contract.get("synthetic") is not False:
            errors.append(
                f"{identifier} provider contract must be reviewed non-synthetic material"
            )
        else:
            validated_document = contract
    expected_decision_type = {
        "card_pci_boundary": "card_pci_boundary",
        "oidc_deployment_identity": "oidc_deployment_identity",
    }.get(identifier)
    if expected_decision_type is not None and artifact_bytes is not None:
        validated_document = artifact_document
        if decision_errors(
            validated_document,
            expected_type=expected_decision_type,
            evaluated_at=evaluated_at,
        ):
            errors.append(f"{identifier} decision envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                f"{identifier} decision envelope must be reviewed non-synthetic material"
            )
    if identifier == "phase0_boundary_approval" and artifact_bytes is not None:
        validated_document = artifact_document
        if approval_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("phase0_boundary_approval envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "phase0_boundary_approval must be reviewed non-synthetic material"
            )
    if identifier == "target_platform_inventory" and artifact_bytes is not None:
        validated_document = artifact_document
        if inventory_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("target_platform_inventory envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "target_platform_inventory must be reviewed non-synthetic material"
            )
    if identifier in {
        "phase1_platform_evidence",
        "phase2_mail_evidence",
        "phase3_card_evidence",
        "windows_pilot_inputs",
        "phase5_windows_evidence",
    } and artifact_bytes is not None:
        validated_document = artifact_document
        if target_phase_artifact_errors(
            validated_document,
            expected_type=identifier,
            evaluated_at=evaluated_at,
        ):
            errors.append(f"{identifier} envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(f"{identifier} must be reviewed non-synthetic material")
    if identifier == "sub2_execution_evidence" and artifact_bytes is not None:
        validated_document = artifact_document
        if sub2_evidence_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("sub2_execution_evidence envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "sub2_execution_evidence must be reviewed non-synthetic material"
            )
    if identifier == "vault_egress_evidence" and artifact_bytes is not None:
        validated_document = artifact_document
        if vault_egress_evidence_errors(
            validated_document,
            evaluated_at=evaluated_at,
        ):
            errors.append("vault_egress_evidence envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "vault_egress_evidence must be reviewed non-synthetic material"
            )
    if identifier == "phase6_pilot_inputs" and artifact_bytes is not None:
        validated_document = artifact_document
        if pilot_input_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("phase6_pilot_inputs envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "phase6_pilot_inputs must be reviewed non-synthetic material"
            )
    if identifier == "release_execution_evidence" and artifact_bytes is not None:
        try:
            validated_document = release_execution_identity(artifact_bytes)
        except ReleaseExecutionBindingError:
            validated_document = None
            errors.append("release_execution_evidence ledger is invalid")
        else:
            if not validated_document["successful"]:
                errors.append(
                    "release_execution_evidence terminal state is not successful"
                )
    if identifier == "phase6_pilot_evidence" and artifact_bytes is not None:
        validated_document = artifact_document
        if pilot_evidence_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("phase6_pilot_evidence envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "phase6_pilot_evidence must be reviewed non-synthetic material"
            )
    if identifier == "phase6_operations_evidence" and artifact_bytes is not None:
        validated_document = artifact_document
        if operations_evidence_errors(validated_document, evaluated_at=evaluated_at):
            errors.append("phase6_operations_evidence envelope is invalid")
        elif validated_document.get("synthetic") is not False:
            errors.append(
                "phase6_operations_evidence must be reviewed non-synthetic material"
            )
    if not _reviewer_reference(item.get("reviewed_by")):
        errors.append(f"{identifier} reviewer reference is invalid")
    reviewed_at = _parse_utc(item.get("reviewed_at"))
    if reviewed_at is None:
        errors.append(f"{identifier} reviewed_at must be canonical UTC")
    elif identifier == "release_execution_evidence" and isinstance(
        validated_document, dict
    ):
        finished_at = _parse_utc(validated_document.get("finished_at"))
        if finished_at is None or reviewed_at < finished_at:
            errors.append(
                "release_execution_evidence review must not predate ledger completion"
            )
        if reviewed_at > evaluated_at:
            errors.append(
                "release_execution_evidence review must not follow the evaluation time"
            )
    if item.get("redaction_confirmed") is not True:
        errors.append(f"{identifier} redaction must be explicitly confirmed")
    return errors, validated_document


def intake_errors(
    document: Any,
    requirements: Any,
    *,
    repository_root: Path = ROOT,
    require_complete: bool,
    required_ids: frozenset[str] | None = None,
    phase0_checkpoint_manifest: Path | None = None,
    evaluated_at: datetime | None = None,
    _phase0_windows: dict[str, tuple[str, str]] | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or _utc_now()
    if not isinstance(document, dict) or set(document) != _MANIFEST_KEYS:
        return ["intake manifest top-level schema is invalid"]
    errors: list[str] = []
    if required_ids is not None:
        valid_checkpoints = {
            frozenset(phase_requirement_ids(requirements, phase))
            for phase in _TARGET_PHASES
        }
        if required_ids not in valid_checkpoints:
            errors.append("intake checkpoint requirement inventory is invalid")
    if document.get("schema_version") != 1:
        errors.append("intake manifest identity is invalid")
    environment = document.get("environment")
    if (
        not isinstance(environment, str)
        or not _ENVIRONMENT.fullmatch(environment)
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("intake environment is invalid or a placeholder")
    if document.get("production_acceptance") is not False:
        errors.append("intake manifest must not claim production acceptance")
    if document.get("requirements_sha256") != requirements_sha256(requirements):
        errors.append("intake manifest is not bound to the current requirements")

    items = document.get("items")
    if not isinstance(items, list):
        errors.append("intake manifest items must be a list")
        return errors
    identifiers = [item.get("id") if isinstance(item, dict) else None for item in items]
    if identifiers != list(_REQUIRED_IDS):
        errors.append("intake manifest item inventory is invalid")
    phase0_approval: Any | None = None
    target_inventory: Any | None = None
    target_phase_artifacts: dict[str, Any] = {}
    provider_contracts: dict[str, Any] = {}
    decision_envelopes: dict[str, Any] = {}
    sub2_evidence: Any | None = None
    vault_egress_evidence: Any | None = None
    phase6_pilot_inputs: Any | None = None
    phase6_pilot_evidence: Any | None = None
    phase6_operations_evidence: Any | None = None
    release_execution: Any | None = None
    phase0_ids = frozenset(phase_requirement_ids(requirements, 0))
    for item in items:
        if not isinstance(item, dict) or set(item) != _ITEM_KEYS:
            errors.append("intake manifest item schema is invalid")
            continue
        identifier = item.get("id")
        status_value = item.get("status")
        if status_value == "missing":
            if any(
                item.get(key) is not None
                for key in (
                    "artifact_path",
                    "sha256",
                    "reviewed_by",
                    "reviewed_at",
                    "redaction_confirmed",
                )
            ):
                errors.append(f"{identifier} missing item must not carry artifact metadata")
            if require_complete and (
                required_ids is None or identifier in required_ids
            ):
                errors.append(f"{identifier} is incomplete")
        elif status_value == "provided":
            artifact_errors, validated_document = _artifact_errors(
                item,
                repository_root=repository_root,
                evaluated_at=evaluation_time,
            )
            errors.extend(artifact_errors)
            if (
                identifier in {"mail_contract", "sub2_contract"}
                and isinstance(validated_document, dict)
                and not contract_errors(
                    validated_document,
                    expected_type=identifier.removesuffix("_contract"),
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                provider_contracts[identifier] = validated_document
            if (
                identifier == "phase0_boundary_approval"
                and isinstance(validated_document, dict)
                and not approval_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                phase0_approval = validated_document
            if (
                identifier in {"card_pci_boundary", "oidc_deployment_identity"}
                and isinstance(validated_document, dict)
                and not decision_errors(
                    validated_document,
                    expected_type=identifier,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                decision_envelopes[identifier] = validated_document
            if (
                identifier == "target_platform_inventory"
                and isinstance(validated_document, dict)
                and not inventory_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                target_inventory = validated_document
            if (
                identifier
                in {
                    "phase1_platform_evidence",
                    "phase2_mail_evidence",
                    "phase3_card_evidence",
                    "windows_pilot_inputs",
                    "phase5_windows_evidence",
                }
                and isinstance(validated_document, dict)
                and not target_phase_artifact_errors(
                    validated_document,
                    expected_type=identifier,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                target_phase_artifacts[identifier] = validated_document
            if (
                identifier == "sub2_execution_evidence"
                and isinstance(validated_document, dict)
                and not sub2_evidence_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                sub2_evidence = validated_document
            if (
                identifier == "vault_egress_evidence"
                and isinstance(validated_document, dict)
                and not vault_egress_evidence_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                vault_egress_evidence = validated_document
            if (
                identifier == "release_execution_evidence"
                and isinstance(validated_document, dict)
            ):
                release_execution = validated_document
            if (
                identifier == "phase6_pilot_inputs"
                and isinstance(validated_document, dict)
                and not pilot_input_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                phase6_pilot_inputs = validated_document
            if (
                identifier == "phase6_pilot_evidence"
                and isinstance(validated_document, dict)
                and not pilot_evidence_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                phase6_pilot_evidence = validated_document
            if (
                identifier == "phase6_operations_evidence"
                and isinstance(validated_document, dict)
                and not operations_evidence_errors(
                    validated_document,
                    evaluated_at=evaluation_time,
                )
                and validated_document.get("synthetic") is False
            ):
                phase6_operations_evidence = validated_document
            if (
                _phase0_windows is not None
                and identifier in phase0_ids
                and isinstance(validated_document, dict)
            ):
                source = validated_document.get("source_provenance")
                valid_until = (
                    source.get("valid_until")
                    if identifier in {"mail_contract", "sub2_contract"}
                    and isinstance(source, dict)
                    else validated_document.get("valid_until")
                )
                reviewed_at = validated_document.get("reviewed_at")
                if _canonical_utc(reviewed_at) and _canonical_utc(valid_until):
                    _phase0_windows[identifier] = (reviewed_at, valid_until)
        else:
            errors.append(f"{identifier} status is invalid")
    if phase0_approval is not None:
        errors.extend(intake_binding_errors(phase0_approval, document))
    for identifier, contract in provider_contracts.items():
        source = contract.get("source_provenance")
        scope = source.get("provider_scope") if isinstance(source, dict) else None
        if (
            not isinstance(scope, dict)
            or scope.get("environment") != document.get("environment")
        ):
            errors.append(
                f"{identifier} provider scope does not match this intake manifest"
            )
        own_items = [
            item
            for item in document["items"]
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        if (
            len(own_items) != 1
            or own_items[0].get("status") != "provided"
            or own_items[0].get("reviewed_by")
            != contract.get("review_reference")
            or own_items[0].get("reviewed_at") != contract.get("reviewed_at")
        ):
            errors.append(
                f"{identifier} review metadata does not match this intake manifest"
            )
    for identifier, decision in decision_envelopes.items():
        own_items = [
            item
            for item in document["items"]
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        if (
            len(own_items) != 1
            or own_items[0].get("status") != "provided"
            or own_items[0].get("reviewed_by")
            != decision.get("review_reference")
            or own_items[0].get("reviewed_at") != decision.get("reviewed_at")
        ):
            errors.append(
                f"{identifier} review metadata does not match this intake manifest"
            )
    if (
        target_inventory is not None
        and target_inventory.get("environment") != document.get("environment")
    ):
        errors.append(
            "target_platform_inventory environment does not match this intake manifest"
        )
    if target_inventory is not None:
        own_items = [
            item
            for item in document["items"]
            if isinstance(item, dict)
            and item.get("id") == "target_platform_inventory"
        ]
        if (
            len(own_items) != 1
            or own_items[0].get("status") != "provided"
            or own_items[0].get("reviewed_by")
            != target_inventory.get("review_reference")
            or own_items[0].get("reviewed_at")
            != target_inventory.get("reviewed_at")
        ):
            errors.append(
                "target_platform_inventory review metadata does not match this intake manifest"
            )
    for identifier, artifact in target_phase_artifacts.items():
        errors.extend(
            target_phase_binding_errors(
                artifact,
                document,
                expected_type=identifier,
            )
        )
        if identifier != "windows_pilot_inputs" and release_execution is not None:
            bindings = artifact.get("bindings", {})
            errors.extend(
                release_execution_identity_alignment_errors(
                    artifact.get("release_execution"),
                    release_execution,
                    environment=artifact.get("environment"),
                    release_tag=bindings.get("release_tag"),
                    release_commit=bindings.get("release_commit"),
                    container_manifest_sha256=bindings.get(
                        "container_manifest_sha256"
                    ),
                    consumer_started_at=artifact.get("window", {}).get(
                        "started_at"
                    ),
                )
            )
    if {
        "windows_pilot_inputs",
        "phase5_windows_evidence",
    }.issubset(target_phase_artifacts):
        errors.extend(
            phase5_windows_alignment_errors(
                target_phase_artifacts["phase5_windows_evidence"],
                target_phase_artifacts["windows_pilot_inputs"],
            )
        )
    if sub2_evidence is not None:
        errors.extend(sub2_evidence_binding_errors(sub2_evidence, document))
        if release_execution is not None:
            bindings = sub2_evidence.get("bindings", {})
            errors.extend(
                release_execution_identity_alignment_errors(
                    sub2_evidence.get("release_execution"),
                    release_execution,
                    environment=sub2_evidence.get("environment"),
                    release_tag=bindings.get("release_tag"),
                    release_commit=bindings.get("release_commit"),
                    container_manifest_sha256=bindings.get(
                        "container_manifest_sha256"
                    ),
                    consumer_started_at=sub2_evidence.get("window", {}).get(
                        "started_at"
                    ),
                )
            )
    phase4_runtime_required = require_complete and (
        required_ids is None or "sub2_execution_evidence" in required_ids
    )
    if phase4_runtime_required and "sub2_contract" in provider_contracts:
        if runtime_conformance_errors(
            provider_contracts["sub2_contract"],
            evaluated_at=evaluation_time,
        ):
            errors.append(
                "sub2_contract runtime is not conformant with the reviewed provider contract"
            )
    if vault_egress_evidence is not None:
        errors.extend(vault_egress_binding_errors(vault_egress_evidence, document))
        if release_execution is not None:
            bindings = vault_egress_evidence.get("bindings", {})
            errors.extend(
                release_execution_identity_alignment_errors(
                    vault_egress_evidence.get("release_execution"),
                    release_execution,
                    environment=vault_egress_evidence.get("environment"),
                    release_tag=bindings.get("release_tag"),
                    release_commit=bindings.get("release_commit"),
                    container_manifest_sha256=bindings.get(
                        "container_manifest_sha256"
                    ),
                    consumer_started_at=vault_egress_evidence.get("window", {}).get(
                        "started_at"
                    ),
                )
            )
    if phase6_pilot_inputs is not None:
        errors.extend(pilot_input_binding_errors(phase6_pilot_inputs, document))
    if phase6_pilot_evidence is not None:
        errors.extend(pilot_evidence_binding_errors(phase6_pilot_evidence, document))
        if phase6_pilot_inputs is not None:
            errors.extend(
                pilot_input_alignment_errors(
                    phase6_pilot_evidence,
                    phase6_pilot_inputs,
                    evaluated_at=evaluation_time,
                )
            )
        if release_execution is not None:
            bindings = phase6_pilot_evidence.get("bindings", {})
            errors.extend(
                release_execution_identity_alignment_errors(
                    phase6_pilot_evidence.get("release_execution"),
                    release_execution,
                    environment=phase6_pilot_evidence.get("environment"),
                    release_tag=bindings.get("release_tag"),
                    release_commit=bindings.get("release_commit"),
                    container_manifest_sha256=bindings.get(
                        "container_manifest_sha256"
                    ),
                    consumer_started_at=phase6_pilot_evidence.get("window", {}).get(
                        "started_at"
                    ),
                )
            )
    if phase6_operations_evidence is not None:
        errors.extend(
            operations_evidence_binding_errors(
                phase6_operations_evidence,
                document,
            )
        )
        if phase6_pilot_inputs is not None and phase6_pilot_evidence is not None:
            errors.extend(
                operations_alignment_errors(
                    phase6_operations_evidence,
                    phase6_pilot_inputs,
                    phase6_pilot_evidence,
                    evaluated_at=evaluation_time,
                )
            )
        if release_execution is not None:
            bindings = phase6_operations_evidence.get("bindings", {})
            errors.extend(
                release_execution_identity_alignment_errors(
                    phase6_operations_evidence.get("release_execution"),
                    release_execution,
                    environment=phase6_operations_evidence.get("environment"),
                    release_tag=bindings.get("release_tag"),
                    release_commit=bindings.get("release_commit"),
                    container_manifest_sha256=bindings.get(
                        "container_manifest_sha256"
                    ),
                    consumer_started_at=phase6_operations_evidence.get(
                        "window", {}
                    ).get("started_at"),
                )
            )
    lineage_required = require_complete and (
        required_ids is None or "release_execution_evidence" in required_ids
    )
    if lineage_required:
        if phase0_checkpoint_manifest is None:
            errors.append("final intake requires a Phase 0 checkpoint snapshot")
        else:
            try:
                checkpoint_identity, checkpoint_manifest = (
                    _load_validated_phase_checkpoint(
                        phase0_checkpoint_manifest,
                        environment=document.get("environment"),
                        through_phase=0,
                        evaluated_at=evaluation_time,
                    )
                )
            except PhaseCheckpointError as error:
                errors.extend(
                    f"Phase 0 checkpoint snapshot {message}"
                    for message in error.errors
                )
            else:
                phase0_ids = frozenset(phase_requirement_ids(requirements, 0))
                current_phase0 = [
                    item
                    for item in document["items"]
                    if isinstance(item, dict) and item.get("id") in phase0_ids
                ]
                checkpoint_phase0 = [
                    item
                    for item in checkpoint_manifest["items"]
                    if isinstance(item, dict) and item.get("id") in phase0_ids
                ]
                if current_phase0 != checkpoint_phase0:
                    errors.append(
                        "current Phase 0 intake items do not match the release checkpoint snapshot"
                    )
                if (
                    release_execution is not None
                    and release_execution.get("target_intake")
                    != checkpoint_identity.as_evidence()
                ):
                    errors.append(
                        "release execution intake does not match the Phase 0 checkpoint snapshot"
                    )
                if (
                    release_execution is not None
                    and not checkpoint_identity.contains_release_start(
                        release_execution.get("started_at")
                    )
                ):
                    errors.append(
                        "release execution did not start inside the frozen Phase 0 validity window"
                    )
    return errors


def _parse_json_bytes(raw: bytes) -> Any:
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _IntakeJsonError("intake JSON file is invalid") from error


def _load_json(path: Path) -> Any:
    try:
        raw = _read_stable_bytes(path, max_bytes=_MAX_MANIFEST_BYTES)
    except _StableFileError as error:
        raise _IntakeJsonError("intake JSON file is invalid") from error
    return _parse_json_bytes(raw)


def _manifest_path_errors(path: Path, *, must_exist: bool) -> list[str]:
    if not path.is_absolute():
        return ["intake manifest path must be absolute"]
    candidate = path
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
    except OSError:
        return ["intake manifest parent directory is unavailable"]
    resolved = resolved_parent / candidate.name
    if resolved.is_relative_to(ROOT.resolve()):
        return ["intake manifest must be outside the repository"]
    if _has_link_or_reparse_ancestor(candidate.parent):
        return ["intake manifest path must not use links or reparse points"]
    if must_exist:
        if not candidate.exists() or not candidate.is_file() or _is_link_or_reparse(candidate):
            return ["intake manifest is unavailable or not a regular file"]
    elif candidate.exists():
        return ["intake manifest output already exists"]
    return []


def _load_validated_phase_checkpoint(
    manifest_path: Path,
    *,
    environment: str,
    through_phase: int,
    evaluated_at: datetime | None = None,
) -> tuple[PhaseCheckpointIdentity, dict[str, Any]]:
    """Read once, validate and identify one repository-external checkpoint."""

    if (
        not isinstance(environment, str)
        or not _ENVIRONMENT.fullmatch(environment)
        or environment.casefold() in _PLACEHOLDERS
    ):
        raise PhaseCheckpointError(["target environment is invalid or a placeholder"])
    if through_phase not in _TARGET_PHASES:
        raise PhaseCheckpointError(["intake checkpoint phase is invalid"])
    evaluation_time = evaluated_at or _utc_now()
    errors = _manifest_path_errors(manifest_path, must_exist=True)
    if errors:
        raise PhaseCheckpointError(errors)
    try:
        matrix = _load_json(MATRIX)
        requirements = _load_json(REQUIREMENTS)
        manifest = _load_json(manifest_path)
    except (OSError, UnicodeError, json.JSONDecodeError, _IntakeJsonError):
        raise PhaseCheckpointError(["target intake checkpoint material is invalid"])
    errors = requirements_errors(requirements, matrix)
    if not isinstance(manifest, dict) or manifest.get("environment") != environment:
        errors.append(
            "intake manifest environment does not match the target environment"
        )
    phase0_windows: dict[str, tuple[str, str]] = {}
    errors.extend(
        intake_errors(
            manifest,
            requirements,
            require_complete=True,
            required_ids=frozenset(
                phase_requirement_ids(requirements, through_phase)
            ),
            evaluated_at=evaluation_time,
            _phase0_windows=phase0_windows,
        )
    )
    expected_phase0_ids = frozenset(phase_requirement_ids(requirements, 0))
    if through_phase >= 0 and set(phase0_windows) != expected_phase0_ids:
        errors.append("Phase 0 validity window could not be reconstructed")
    if errors:
        raise PhaseCheckpointError(errors)
    valid_from_value = max(
        _parse_utc(window[0]) for window in phase0_windows.values()
    )
    valid_until_value = min(
        _parse_utc(window[1]) for window in phase0_windows.values()
    )
    if valid_from_value is None or valid_until_value is None:
        raise PhaseCheckpointError(["Phase 0 validity window could not be reconstructed"])
    identity = PhaseCheckpointIdentity(
        environment=environment,
        manifest_payload_sha256=requirements_sha256(manifest),
        requirements_sha256=manifest["requirements_sha256"],
        checkpoint_phase=through_phase,
        evaluated_at=_utc_timestamp(evaluation_time),
        valid_from=_utc_timestamp(valid_from_value),
        valid_until=_utc_timestamp(valid_until_value),
    )
    return identity, manifest


def load_phase_checkpoint(
    manifest_path: Path,
    *,
    environment: str,
    through_phase: int,
    evaluated_at: datetime | None = None,
) -> PhaseCheckpointIdentity:
    """Validate and identify one repository-external intake checkpoint."""

    identity, _ = _load_validated_phase_checkpoint(
        manifest_path,
        environment=environment,
        through_phase=through_phase,
        evaluated_at=evaluated_at,
    )
    return identity


def phase_checkpoint_errors(
    manifest_path: Path,
    *,
    environment: str,
    through_phase: int,
    evaluated_at: datetime | None = None,
) -> list[str]:
    """Return fixed validation errors for one strict intake checkpoint."""

    try:
        load_phase_checkpoint(
            manifest_path,
            environment=environment,
            through_phase=through_phase,
            evaluated_at=evaluated_at,
        )
    except PhaseCheckpointError as error:
        return list(error.errors)
    return []


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-requirements")
    initialize = commands.add_parser("init")
    initialize.add_argument("--output", required=True, type=Path)
    initialize.add_argument("--environment", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("--input", required=True, type=Path)
    snapshot.add_argument("--output", required=True, type=Path)
    snapshot.add_argument("--environment", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--input", required=True, type=Path)
    preflight.add_argument("--phase0-checkpoint-manifest", type=Path)
    completeness = preflight.add_mutually_exclusive_group()
    completeness.add_argument("--allow-incomplete", action="store_true")
    completeness.add_argument(
        "--through-phase", type=int, choices=_TARGET_PHASES, metavar="{0,1,2,3,4,5,6}"
    )
    return parser


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    evaluated_at = _utc_now()
    try:
        matrix = _load_json(MATRIX)
        requirements = _load_json(REQUIREMENTS)
    except (OSError, UnicodeError, json.JSONDecodeError, _IntakeJsonError):
        print("target-intake-requirements-invalid", file=sys.stderr)
        return 1
    errors = requirements_errors(requirements, matrix)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    if arguments.command == "verify-requirements":
        print("target-intake-requirements-ok phases=0-6 production_acceptance=false")
        return 0
    if arguments.command == "init":
        path_errors = _manifest_path_errors(arguments.output, must_exist=False)
        manifest = create_intake_manifest(arguments.environment, requirements)
        errors = path_errors + intake_errors(
            manifest,
            requirements,
            require_complete=False,
            evaluated_at=evaluated_at,
        )
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        try:
            with arguments.output.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(manifest, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
        except OSError:
            print("target-intake-init-failed", file=sys.stderr)
            return 1
        print("target-intake-created production_acceptance=false status=incomplete")
        return 0
    if arguments.command == "snapshot":
        output_errors = _manifest_path_errors(arguments.output, must_exist=False)
        if output_errors:
            print("; ".join(output_errors), file=sys.stderr)
            return 1
        try:
            identity, manifest = _load_validated_phase_checkpoint(
                arguments.input,
                environment=arguments.environment,
                through_phase=0,
                evaluated_at=evaluated_at,
            )
        except PhaseCheckpointError as error:
            errors = list(error.errors)
        else:
            errors = []
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        try:
            with arguments.output.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(manifest, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
        except OSError:
            print("target-intake-snapshot-failed", file=sys.stderr)
            return 1
        print(
            "target-intake-snapshot-created "
            "production_acceptance=false checkpoint_phase=0 "
            f"environment={identity.environment} "
            f"manifest_payload_sha256={identity.manifest_payload_sha256} "
            f"requirements_sha256={identity.requirements_sha256}"
        )
        return 0

    path_errors = _manifest_path_errors(arguments.input, must_exist=True)
    if path_errors:
        print("; ".join(path_errors), file=sys.stderr)
        return 1
    try:
        manifest = _load_json(arguments.input)
    except (OSError, UnicodeError, json.JSONDecodeError, _IntakeJsonError):
        print("target-intake-manifest-invalid", file=sys.stderr)
        return 1
    required_ids = None
    if arguments.through_phase is not None:
        required_ids = frozenset(
            phase_requirement_ids(requirements, arguments.through_phase)
        )
    errors = intake_errors(
        manifest,
        requirements,
        require_complete=not arguments.allow_incomplete,
        required_ids=required_ids,
        phase0_checkpoint_manifest=arguments.phase0_checkpoint_manifest,
        evaluated_at=evaluated_at,
    )
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    if arguments.allow_incomplete:
        status_value = "structurally-valid"
    elif arguments.through_phase is not None:
        status_value = f"complete-through-phase-{arguments.through_phase}"
    else:
        status_value = "complete"
    print(
        "target-intake-preflight-ok "
        f"status={status_value} production_acceptance=false "
        f"environment={manifest['environment']} "
        f"manifest_payload_sha256={requirements_sha256(manifest)} "
        f"requirements_sha256={manifest['requirements_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
