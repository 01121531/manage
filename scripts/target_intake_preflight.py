"""Create and verify repository-external target-environment intake metadata."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_phase_acceptance_matrix import matrix_errors
from scripts.backup_output_policy import (
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import (
    MAX_EXTERNAL_JSON_BYTES as _MAX_ARTIFACT_BYTES,
    MAX_INTAKE_JSON_BYTES as _MAX_MANIFEST_BYTES,
    StableFileError as _StableFileError,
    has_link_or_reparse_ancestor as _has_link_or_reparse_ancestor,
    is_link_or_reparse as _is_link_or_reparse,
    load_unique_json_with_bytes_and_metadata as _load_unique_json_with_bytes_and_metadata,
    parse_unique_json_bytes,
    read_stable_bytes as _read_stable_bytes,
    read_stable_bytes_with_metadata as _read_stable_bytes_with_metadata,
    recheck_stable_bytes as _recheck_stable_bytes,
)
from scripts.target_intake_manifest import (
    ITEM_KEYS as _ITEM_KEYS,
    MANIFEST_KEYS as _MANIFEST_KEYS,
    RELEASE_ITEM_KEYS as _RELEASE_ITEM_KEYS,
    REQUIRED_IDS as _REQUIRED_IDS,
    canonical_bytes as _canonical_bytes,
    canonical_payload_sha256,
)
from scripts.target_intake_generation import (
    GenerationLineageError,
    create_genesis_receipt,
    create_registration_receipt,
    load_generation_lineage,
    manifest_registration_item_id,
    receipt_bytes,
    recheck_generation_lineage,
)
from scripts.target_intake_acceptance import (
    AcceptanceReceiptError,
    acceptance_receipt_bytes,
    create_finalization_receipt,
    create_snapshot_receipt,
    load_finalization_acceptance,
    load_snapshot_acceptance,
    recheck_finalization_acceptance,
    recheck_snapshot_acceptance,
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
    release_execution_review_subject,
    release_execution_review_subject_errors,
    release_execution_reviewed_at,
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


def requirements_sha256(document: Any) -> str:
    return canonical_payload_sha256(document)


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
    if (
        document.get("manifest_policy")
        != "repository_external_immutable_generation_metadata_only"
    ):
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
        "schema_version": 2,
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
                **(
                    {"release_execution_review_subject": None}
                    if item.get("id") == "release_execution_evidence"
                    else {}
                ),
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
            review_subject = item.get("release_execution_review_subject")
            review_subject_errors = release_execution_review_subject_errors(
                review_subject
            )
            if review_subject_errors:
                errors.append(
                    "release_execution_evidence review subject is invalid"
                )
            else:
                reviewed_selector = review_subject["selector"]
                if (
                    reviewed_selector["ledger_type"]
                    != validated_document["ledger_type"]
                    or reviewed_selector["evidence_sha256"] != supplied_sha
                    or reviewed_selector["target_intake"]
                    != validated_document["target_intake"]
                ):
                    errors.append(
                        "release_execution_evidence review subject does not match its ledger"
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


def _release_execution_consumer_selector_errors(
    documents: list[Any],
    *,
    review_subject: Any,
) -> list[str]:
    """Require one exact reviewed selector claim within this intake."""

    selectors = [
        document.get("release_execution")
        for document in documents
        if isinstance(document, dict)
        and isinstance(document.get("release_execution"), dict)
    ]
    if len(selectors) > 1:
        baseline = selectors[0]
        if any(selector != baseline for selector in selectors[1:]):
            return [
                "release execution selector does not match the other consumers in this intake manifest"
            ]
    if selectors:
        try:
            expected_subject = release_execution_review_subject(selectors[0])
        except ReleaseExecutionBindingError:
            return ["release execution consumer selector is invalid"]
        if review_subject != expected_subject:
            return [
                "release execution review subject does not match its consumers in this intake manifest"
            ]
    return []


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
    if document.get("schema_version") != 2:
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
    release_review_subject: Any | None = None
    phase0_ids = frozenset(phase_requirement_ids(requirements, 0))
    for item in items:
        if not isinstance(item, dict):
            errors.append("intake manifest item schema is invalid")
            continue
        identifier = item.get("id")
        expected_item_keys = (
            _RELEASE_ITEM_KEYS
            if identifier == "release_execution_evidence"
            else _ITEM_KEYS
        )
        if set(item) != expected_item_keys:
            errors.append("intake manifest item schema is invalid")
            continue
        status_value = item.get("status")
        if status_value == "missing":
            metadata_keys = [
                "artifact_path",
                "sha256",
                "reviewed_by",
                "reviewed_at",
                "redaction_confirmed",
            ]
            if identifier == "release_execution_evidence":
                metadata_keys.append("release_execution_review_subject")
            if any(
                item.get(key) is not None
                for key in metadata_keys
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
                release_review_subject = item.get(
                    "release_execution_review_subject"
                )
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
                    release_reviewed_at=release_execution_reviewed_at(
                        document,
                        artifact.get("release_execution"),
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
                    release_reviewed_at=release_execution_reviewed_at(
                        document,
                        sub2_evidence.get("release_execution"),
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
                    release_reviewed_at=release_execution_reviewed_at(
                        document,
                        vault_egress_evidence.get("release_execution"),
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
                    release_reviewed_at=release_execution_reviewed_at(
                        document,
                        phase6_pilot_evidence.get("release_execution"),
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
                    release_reviewed_at=release_execution_reviewed_at(
                        document,
                        phase6_operations_evidence.get("release_execution"),
                    ),
                    consumer_started_at=phase6_operations_evidence.get(
                        "window", {}
                    ).get("started_at"),
                )
            )
    release_execution_consumers = [
        artifact
        for identifier, artifact in target_phase_artifacts.items()
        if identifier != "windows_pilot_inputs"
    ]
    release_execution_consumers.extend(
        consumer
        for consumer in (
            sub2_evidence,
            vault_egress_evidence,
            phase6_pilot_evidence,
            phase6_operations_evidence,
        )
        if consumer is not None
    )
    errors.extend(
        _release_execution_consumer_selector_errors(
            release_execution_consumers,
            review_subject=release_review_subject,
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
    _, document = _load_json_with_raw(path)
    return document


def _load_json_with_raw(path: Path) -> tuple[bytes, Any]:
    try:
        raw = _read_stable_bytes(path, max_bytes=_MAX_MANIFEST_BYTES)
    except _StableFileError as error:
        raise _IntakeJsonError("intake JSON file is invalid") from error
    return raw, _parse_json_bytes(raw)


def _final_manifest_bytes(document: Any) -> bytes:
    return _canonical_bytes(document) + b"\n"


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


def _snapshot_acceptance_identity_errors(acceptance: Any) -> list[str]:
    """Recompute the Phase 0 window recorded by one snapshot receipt."""

    receipt = acceptance.receipt
    evaluated_at = _parse_utc(receipt.get("evaluated_at"))
    if evaluated_at is None:
        return ["snapshot receipt Phase 0 evaluation is invalid"]
    checkpoint_path = Path(receipt["result_checkpoint"]["path"])
    try:
        identity, checkpoint = _load_validated_phase_checkpoint(
            checkpoint_path,
            environment=acceptance.checkpoint["environment"],
            through_phase=0,
            evaluated_at=evaluated_at,
        )
    except (KeyError, TypeError, PhaseCheckpointError):
        return ["snapshot receipt Phase 0 evaluation is invalid"]
    if (
        checkpoint != acceptance.checkpoint
        or identity.evaluated_at != receipt.get("evaluated_at")
        or identity.valid_from != receipt.get("valid_from")
        or identity.valid_until != receipt.get("valid_until")
    ):
        return ["snapshot receipt Phase 0 evaluation does not match checkpoint"]
    return []


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
    initialize.add_argument("--receipt-output", required=True, type=Path)
    initialize.add_argument("--environment", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("--input", required=True, type=Path)
    snapshot.add_argument("--input-receipt", required=True, type=Path)
    snapshot.add_argument(
        "--expected-input-receipt-payload-sha256", required=True
    )
    snapshot.add_argument(
        "--expected-input-receipt-file-sha256", required=True
    )
    snapshot.add_argument("--output", required=True, type=Path)
    snapshot.add_argument("--receipt-output", required=True, type=Path)
    snapshot.add_argument("--environment", required=True)
    register = commands.add_parser("register")
    register.add_argument("--input", required=True, type=Path)
    register.add_argument("--input-receipt", required=True, type=Path)
    register.add_argument("--candidate", required=True, type=Path)
    register.add_argument("--output", required=True, type=Path)
    register.add_argument("--receipt-output", required=True, type=Path)
    register.add_argument(
        "--expected-input-manifest-payload-sha256",
        required=True,
    )
    register.add_argument(
        "--expected-input-manifest-file-sha256",
        required=True,
    )
    register.add_argument(
        "--expected-input-receipt-payload-sha256",
        required=True,
    )
    register.add_argument(
        "--expected-input-receipt-file-sha256",
        required=True,
    )
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--input", required=True, type=Path)
    finalize.add_argument("--input-receipt", required=True, type=Path)
    finalize.add_argument(
        "--expected-input-receipt-payload-sha256", required=True
    )
    finalize.add_argument(
        "--expected-input-receipt-file-sha256", required=True
    )
    finalize.add_argument("--output", required=True, type=Path)
    finalize.add_argument("--receipt-output", required=True, type=Path)
    finalize.add_argument("--phase0-checkpoint-manifest", required=True, type=Path)
    finalize.add_argument("--phase0-checkpoint-receipt", required=True, type=Path)
    finalize.add_argument(
        "--expected-phase0-checkpoint-receipt-payload-sha256", required=True
    )
    finalize.add_argument(
        "--expected-phase0-checkpoint-receipt-file-sha256", required=True
    )
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--input", required=True, type=Path)
    preflight.add_argument("--input-receipt", type=Path)
    preflight.add_argument("--expected-input-receipt-payload-sha256")
    preflight.add_argument("--expected-input-receipt-file-sha256")
    preflight.add_argument("--phase0-checkpoint-manifest", type=Path)
    preflight.add_argument("--expected-manifest-payload-sha256")
    preflight.add_argument("--expected-manifest-file-sha256")
    preflight.add_argument("--finalization-receipt", type=Path)
    preflight.add_argument("--expected-finalization-receipt-payload-sha256")
    preflight.add_argument("--expected-finalization-receipt-file-sha256")
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
        path_errors = (
            _manifest_path_errors(arguments.output, must_exist=False)
            + _manifest_path_errors(arguments.receipt_output, must_exist=False)
        )
        if os.path.abspath(arguments.output) == os.path.abspath(
            arguments.receipt_output
        ):
            path_errors.append("manifest and receipt outputs must be distinct")
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
        manifest_raw = _final_manifest_bytes(manifest)
        temporary: Path | None = None
        receipt_temporary: Path | None = None
        generation_published = False
        receipt_published = False
        try:
            output = prepare_write_once_file(arguments.output)
            temporary = write_fsynced_temporary_bytes(output, manifest_raw)
            publish_write_once_file(temporary, output)
            generation_published = True
            temporary = None
            manifest_readback = _read_stable_bytes(
                output, max_bytes=_MAX_MANIFEST_BYTES
            )
            if not hmac.compare_digest(manifest_readback, manifest_raw):
                raise OSError("genesis manifest publication readback mismatch")
            receipt = create_genesis_receipt(output, manifest, manifest_readback)
            receipt_raw = receipt_bytes(receipt)
            receipt_output = prepare_write_once_file(arguments.receipt_output)
            receipt_temporary = write_fsynced_temporary_bytes(
                receipt_output, receipt_raw
            )
            publish_write_once_file(receipt_temporary, receipt_output)
            receipt_published = True
            receipt_temporary = None
            receipt_readback = _read_stable_bytes(
                receipt_output, max_bytes=_MAX_MANIFEST_BYTES
            )
            if not hmac.compare_digest(receipt_readback, receipt_raw):
                raise OSError("genesis receipt publication readback mismatch")
        except (OSError, ValueError, GenerationLineageError, _StableFileError):
            if receipt_published:
                print(
                    "target-intake-init-failed commit-state=unknown "
                    "verify-receipt-required",
                    file=sys.stderr,
                )
                return 2
            if generation_published:
                print(
                    "target-intake-init-failed "
                    "generation=orphaned-unaccepted receipt=absent-or-unverified",
                    file=sys.stderr,
                )
            else:
                print(
                    "target-intake-init-failed commit=not-established",
                    file=sys.stderr,
                )
            return 1
        finally:
            discard_claimed_temporary_file(temporary)
            discard_claimed_temporary_file(receipt_temporary)
        print(
            "target-intake-created production_acceptance=false status=incomplete "
            f"manifest_payload_sha256={requirements_sha256(manifest)} "
            f"manifest_file_sha256={hashlib.sha256(manifest_raw).hexdigest()} "
            f"generation_receipt_payload_sha256={requirements_sha256(receipt)} "
            f"generation_receipt_file_sha256={hashlib.sha256(receipt_raw).hexdigest()} "
            "generation-acceptance=write-once-receipt "
            "authoring-latest-head=unverified authoring-pin-authority=unverified "
            "authoring-receipt-authority=unverified"
        )
        return 0
    if arguments.command == "register":
        path_errors = (
            _manifest_path_errors(arguments.input, must_exist=True)
            + _manifest_path_errors(arguments.input_receipt, must_exist=True)
            + _manifest_path_errors(arguments.candidate, must_exist=True)
            + _manifest_path_errors(arguments.output, must_exist=False)
            + _manifest_path_errors(arguments.receipt_output, must_exist=False)
        )
        if os.path.abspath(arguments.output) == os.path.abspath(
            arguments.receipt_output
        ):
            path_errors.append("manifest and receipt outputs must be distinct")
        if path_errors:
            print("; ".join(path_errors), file=sys.stderr)
            return 1
        try:
            lineage = load_generation_lineage(
                arguments.input,
                arguments.input_receipt,
                expected_receipt_payload_sha256=(
                    arguments.expected_input_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_input_receipt_file_sha256
                ),
                expected_manifest_payload_sha256=(
                    arguments.expected_input_manifest_payload_sha256
                ),
                expected_manifest_file_sha256=(
                    arguments.expected_input_manifest_file_sha256
                ),
            )
        except GenerationLineageError:
            print("target-intake-register-lineage-invalid", file=sys.stderr)
            return 1
        base = lineage.manifest
        base_raw = lineage.manifest_raw
        errors = intake_errors(
            base,
            requirements,
            require_complete=False,
            evaluated_at=evaluated_at,
        )
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        try:
            candidate, candidate_raw, candidate_metadata = (
                _load_unique_json_with_bytes_and_metadata(
                    arguments.candidate,
                    max_bytes=_MAX_MANIFEST_BYTES,
                )
            )
        except (OSError, UnicodeError, json.JSONDecodeError, _StableFileError):
            print("target-intake-register-candidate-invalid", file=sys.stderr)
            return 1
        registered_item_id = manifest_registration_item_id(base, candidate)
        if registered_item_id is None:
            print("target-intake-register-transition-invalid", file=sys.stderr)
            return 1
        errors = intake_errors(
            candidate,
            requirements,
            require_complete=False,
            evaluated_at=evaluated_at,
        )
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        registered_item = next(
            item for item in candidate["items"] if item["id"] == registered_item_id
        )
        try:
            artifact_path = Path(registered_item["artifact_path"])
            artifact_raw, artifact_metadata = _read_stable_bytes_with_metadata(
                artifact_path,
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
            if not hmac.compare_digest(
                hashlib.sha256(artifact_raw).hexdigest(),
                registered_item["sha256"],
            ):
                raise _StableFileError("read")
        except (OSError, TypeError, _StableFileError):
            print("target-intake-register-artifact-invalid", file=sys.stderr)
            return 1
        output_bytes = _final_manifest_bytes(candidate)
        if len(output_bytes) > _MAX_MANIFEST_BYTES:
            print("target-intake-register-failed", file=sys.stderr)
            return 1
        temporary: Path | None = None
        receipt_temporary: Path | None = None
        generation_published = False
        receipt_published = False
        try:
            recheck_generation_lineage(lineage)
            _recheck_stable_bytes(
                arguments.candidate,
                candidate_raw,
                candidate_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
            _recheck_stable_bytes(
                artifact_path,
                artifact_raw,
                artifact_metadata,
                max_bytes=_MAX_ARTIFACT_BYTES,
                require_single_link=True,
            )
            output = prepare_write_once_file(arguments.output)
            temporary = write_fsynced_temporary_bytes(output, output_bytes)
            publish_write_once_file(temporary, output)
            generation_published = True
            temporary = None
            readback, output_metadata = _read_stable_bytes_with_metadata(
                output, max_bytes=_MAX_MANIFEST_BYTES
            )
            if not hmac.compare_digest(readback, output_bytes):
                raise OSError("authoring generation publication readback mismatch")
            recheck_generation_lineage(lineage)
            _recheck_stable_bytes(
                arguments.candidate,
                candidate_raw,
                candidate_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
            _recheck_stable_bytes(
                artifact_path,
                artifact_raw,
                artifact_metadata,
                max_bytes=_MAX_ARTIFACT_BYTES,
                require_single_link=True,
            )
            receipt = create_registration_receipt(
                manifest_path=output,
                manifest=candidate,
                manifest_raw=readback,
                predecessor=lineage,
                predecessor_manifest_path=arguments.input,
                predecessor_receipt_path=arguments.input_receipt,
                registered_item_id=registered_item_id,
                artifact_sha256=registered_item["sha256"],
                candidate_raw=candidate_raw,
            )
            receipt_raw = receipt_bytes(receipt)
            receipt_output = prepare_write_once_file(arguments.receipt_output)
            receipt_temporary = write_fsynced_temporary_bytes(
                receipt_output, receipt_raw
            )
            publish_write_once_file(receipt_temporary, receipt_output)
            receipt_published = True
            receipt_temporary = None
            receipt_readback, receipt_metadata = _read_stable_bytes_with_metadata(
                receipt_output, max_bytes=_MAX_MANIFEST_BYTES
            )
            if not hmac.compare_digest(receipt_readback, receipt_raw):
                raise OSError("generation receipt publication readback mismatch")
            recheck_generation_lineage(lineage)
            _recheck_stable_bytes(
                output,
                readback,
                output_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
            _recheck_stable_bytes(
                receipt_output,
                receipt_readback,
                receipt_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
        except (OSError, ValueError, GenerationLineageError, _StableFileError):
            if receipt_published:
                print(
                    "target-intake-register-failed commit-state=unknown "
                    "verify-receipt-required",
                    file=sys.stderr,
                )
                return 2
            if generation_published:
                print(
                    "target-intake-register-failed "
                    "generation=orphaned-unaccepted receipt=absent-or-unverified",
                    file=sys.stderr,
                )
            else:
                print(
                    "target-intake-register-failed commit=not-established",
                    file=sys.stderr,
                )
            return 1
        finally:
            discard_claimed_temporary_file(temporary)
            discard_claimed_temporary_file(receipt_temporary)
        print(
            "target-intake-generation-registered production_acceptance=false "
            f"registered_item={registered_item_id} "
            f"manifest_payload_sha256={requirements_sha256(candidate)} "
            f"manifest_file_sha256={hashlib.sha256(output_bytes).hexdigest()} "
            f"generation_receipt_payload_sha256={requirements_sha256(receipt)} "
            f"generation_receipt_file_sha256={hashlib.sha256(receipt_raw).hexdigest()} "
            "selected-lineage=caller-pinned-local-receipt-chain-validated "
            "generation-acceptance=write-once-receipt "
            "authoring-publication=local-no-replace-readback "
            "authoring-generation-fork-protection=unverified "
            "authoring-latest-head=unverified authoring-pin-authority=unverified "
            "authoring-receipt-authority=unverified "
            "authoring-post-publication-custody=unverified"
        )
        return 0
    if arguments.command == "snapshot":
        path_errors = (
            _manifest_path_errors(arguments.input, must_exist=True)
            + _manifest_path_errors(arguments.input_receipt, must_exist=True)
            + _manifest_path_errors(arguments.output, must_exist=False)
            + _manifest_path_errors(arguments.receipt_output, must_exist=False)
        )
        if os.path.abspath(arguments.output) == os.path.abspath(
            arguments.receipt_output
        ):
            path_errors.append("snapshot output and receipt output must be distinct")
        if path_errors:
            print("; ".join(path_errors), file=sys.stderr)
            return 1
        try:
            lineage = load_generation_lineage(
                arguments.input,
                arguments.input_receipt,
                expected_receipt_payload_sha256=(
                    arguments.expected_input_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_input_receipt_file_sha256
                ),
            )
        except GenerationLineageError:
            print("target-intake-snapshot-lineage-invalid", file=sys.stderr)
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
        if errors or manifest != lineage.manifest:
            if not errors:
                errors = ["target intake snapshot lineage changed"]
            print("; ".join(errors), file=sys.stderr)
            return 1
        snapshot_raw = _final_manifest_bytes(manifest)
        temporary: Path | None = None
        output_published = False
        receipt_published = False
        try:
            recheck_generation_lineage(lineage)
            output = prepare_write_once_file(arguments.output)
            receipt_output = prepare_write_once_file(arguments.receipt_output)
            temporary = write_fsynced_temporary_bytes(output, snapshot_raw)
            publish_write_once_file(temporary, output)
            temporary = None
            output_published = True
            checkpoint, readback, checkpoint_metadata = (
                _load_unique_json_with_bytes_and_metadata(
                    output,
                    max_bytes=_MAX_MANIFEST_BYTES,
                )
            )
            if checkpoint != manifest or not hmac.compare_digest(readback, snapshot_raw):
                raise OSError("snapshot publication readback mismatch")
            recheck_generation_lineage(lineage)
            _recheck_stable_bytes(
                output,
                readback,
                checkpoint_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
            receipt = create_snapshot_receipt(
                source_lineage=lineage,
                source_manifest_path=arguments.input,
                source_receipt_path=arguments.input_receipt,
                checkpoint_path=output,
                checkpoint=checkpoint,
                checkpoint_raw=readback,
                evaluated_at=identity.evaluated_at,
                valid_from=identity.valid_from,
                valid_until=identity.valid_until,
            )
            receipt_raw = acceptance_receipt_bytes(receipt)
            temporary = write_fsynced_temporary_bytes(receipt_output, receipt_raw)
            publish_write_once_file(temporary, receipt_output)
            temporary = None
            receipt_published = True
            acceptance = load_snapshot_acceptance(
                output,
                receipt_output,
                expected_receipt_payload_sha256=requirements_sha256(receipt),
                expected_receipt_file_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            )
            recheck_snapshot_acceptance(acceptance)
        except (
            OSError,
            ValueError,
            GenerationLineageError,
            AcceptanceReceiptError,
            _StableFileError,
        ):
            if receipt_published:
                print(
                    "target-intake-snapshot-commit-state=unknown "
                    "verify-receipt-required",
                    file=sys.stderr,
                )
                return 2
            if output_published:
                print(
                    "target-intake-snapshot-orphaned-unaccepted "
                    "receipt=absent-or-unverified",
                    file=sys.stderr,
                )
                return 1
            print("target-intake-snapshot-failed commit=not-established", file=sys.stderr)
            return 1
        finally:
            discard_claimed_temporary_file(temporary)
        print(
            "target-intake-snapshot-created "
            "production_acceptance=false checkpoint_phase=0 "
            f"environment={identity.environment} "
            f"manifest_payload_sha256={identity.manifest_payload_sha256} "
            f"manifest_file_sha256={hashlib.sha256(snapshot_raw).hexdigest()} "
            f"requirements_sha256={identity.requirements_sha256} "
            f"snapshot_receipt_payload_sha256={requirements_sha256(receipt)} "
            f"snapshot_receipt_file_sha256={hashlib.sha256(receipt_raw).hexdigest()} "
            "selected-lineage=caller-pinned-local-receipt-chain-validated "
            "snapshot-acceptance=write-once-receipt "
            "publication=local-no-replace-readback "
            "snapshot-receipt-authority=unverified "
            "snapshot-post-publication-custody=unverified"
        )
        return 0

    if arguments.command == "finalize":
        output_errors = (
            _manifest_path_errors(arguments.output, must_exist=False)
            + _manifest_path_errors(arguments.receipt_output, must_exist=False)
        )
        input_errors = (
            _manifest_path_errors(arguments.input, must_exist=True)
            + _manifest_path_errors(arguments.input_receipt, must_exist=True)
            + _manifest_path_errors(
                arguments.phase0_checkpoint_manifest,
                must_exist=True,
            )
            + _manifest_path_errors(
                arguments.phase0_checkpoint_receipt,
                must_exist=True,
            )
        )
        if os.path.abspath(arguments.output) == os.path.abspath(
            arguments.receipt_output
        ):
            output_errors.append("final output and receipt output must be distinct")
        if output_errors or input_errors:
            print("; ".join(output_errors + input_errors), file=sys.stderr)
            return 1
        try:
            lineage = load_generation_lineage(
                arguments.input,
                arguments.input_receipt,
                expected_receipt_payload_sha256=(
                    arguments.expected_input_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_input_receipt_file_sha256
                ),
            )
        except GenerationLineageError:
            print("target-intake-finalize-lineage-invalid", file=sys.stderr)
            return 1
        try:
            snapshot_acceptance = load_snapshot_acceptance(
                arguments.phase0_checkpoint_manifest,
                arguments.phase0_checkpoint_receipt,
                expected_receipt_payload_sha256=(
                    arguments.expected_phase0_checkpoint_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_phase0_checkpoint_receipt_file_sha256
                ),
            )
        except AcceptanceReceiptError:
            print("target-intake-finalize-snapshot-invalid", file=sys.stderr)
            return 1
        snapshot_identity_errors = _snapshot_acceptance_identity_errors(
            snapshot_acceptance
        )
        if snapshot_identity_errors:
            print("; ".join(snapshot_identity_errors), file=sys.stderr)
            return 1
        manifest = lineage.manifest
        errors = intake_errors(
            manifest,
            requirements,
            require_complete=True,
            phase0_checkpoint_manifest=arguments.phase0_checkpoint_manifest,
            evaluated_at=evaluated_at,
        )
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        final_bytes = _final_manifest_bytes(manifest)
        if len(final_bytes) > _MAX_MANIFEST_BYTES:
            print("target-intake-finalize-failed", file=sys.stderr)
            return 1
        temporary: Path | None = None
        output_published = False
        receipt_published = False
        try:
            recheck_generation_lineage(lineage)
            recheck_snapshot_acceptance(snapshot_acceptance)
            output = prepare_write_once_file(arguments.output)
            receipt_output = prepare_write_once_file(arguments.receipt_output)
            temporary = write_fsynced_temporary_bytes(output, final_bytes)
            publish_write_once_file(temporary, output)
            temporary = None
            output_published = True
            finalized, readback, finalized_metadata = (
                _load_unique_json_with_bytes_and_metadata(
                    output,
                    max_bytes=_MAX_MANIFEST_BYTES,
                )
            )
            if finalized != manifest or not hmac.compare_digest(readback, final_bytes):
                raise OSError("final manifest publication readback mismatch")
            recheck_generation_lineage(lineage)
            recheck_snapshot_acceptance(snapshot_acceptance)
            _recheck_stable_bytes(
                output,
                readback,
                finalized_metadata,
                max_bytes=_MAX_MANIFEST_BYTES,
                require_single_link=True,
            )
            receipt = create_finalization_receipt(
                source_lineage=lineage,
                source_manifest_path=arguments.input,
                source_receipt_path=arguments.input_receipt,
                phase0_snapshot=snapshot_acceptance,
                phase0_checkpoint_path=arguments.phase0_checkpoint_manifest,
                phase0_receipt_path=arguments.phase0_checkpoint_receipt,
                finalized_path=output,
                finalized_manifest=finalized,
                finalized_raw=readback,
            )
            receipt_raw = acceptance_receipt_bytes(receipt)
            temporary = write_fsynced_temporary_bytes(receipt_output, receipt_raw)
            publish_write_once_file(temporary, receipt_output)
            temporary = None
            receipt_published = True
            acceptance = load_finalization_acceptance(
                output,
                receipt_output,
                arguments.phase0_checkpoint_manifest,
                expected_receipt_payload_sha256=requirements_sha256(receipt),
                expected_receipt_file_sha256=hashlib.sha256(receipt_raw).hexdigest(),
                expected_manifest_payload_sha256=requirements_sha256(finalized),
                expected_manifest_file_sha256=hashlib.sha256(readback).hexdigest(),
            )
            recheck_finalization_acceptance(acceptance)
        except (
            OSError,
            ValueError,
            GenerationLineageError,
            AcceptanceReceiptError,
            _StableFileError,
        ):
            if receipt_published:
                print(
                    "target-intake-finalization-commit-state=unknown "
                    "verify-receipt-required",
                    file=sys.stderr,
                )
                return 2
            if output_published:
                print(
                    "target-intake-final-orphaned-unaccepted "
                    "receipt=absent-or-unverified",
                    file=sys.stderr,
                )
                return 1
            print("target-intake-finalize-failed commit=not-established", file=sys.stderr)
            return 1
        finally:
            discard_claimed_temporary_file(temporary)
        print(
            "target-intake-finalized production_acceptance=false "
            f"environment={manifest['environment']} "
            f"manifest_payload_sha256={requirements_sha256(manifest)} "
            f"manifest_file_sha256={hashlib.sha256(final_bytes).hexdigest()} "
            f"finalization_receipt_payload_sha256={requirements_sha256(receipt)} "
            f"finalization_receipt_file_sha256={hashlib.sha256(receipt_raw).hexdigest()} "
            "selected-lineage=caller-pinned-local-receipt-chain-validated "
            "phase0-snapshot-acceptance=caller-pinned-local-receipt-validated "
            "finalization-acceptance=write-once-receipt "
            "publication=local-no-replace-readback "
            "custody=unverified rollback-protection=unverified "
            "finalization-receipt-authority=unverified"
        )
        return 0

    final_strict = not arguments.allow_incomplete and arguments.through_phase is None
    path_errors = _manifest_path_errors(arguments.input, must_exist=True)
    if not final_strict and arguments.input_receipt is not None:
        path_errors += _manifest_path_errors(
            arguments.input_receipt, must_exist=True
        )
    if path_errors:
        print("; ".join(path_errors), file=sys.stderr)
        return 1
    receipt_arguments = (
        arguments.input_receipt,
        arguments.expected_input_receipt_payload_sha256,
        arguments.expected_input_receipt_file_sha256,
    )
    finalization_arguments = (
        arguments.finalization_receipt,
        arguments.expected_finalization_receipt_payload_sha256,
        arguments.expected_finalization_receipt_file_sha256,
    )
    expected_payload_sha256 = arguments.expected_manifest_payload_sha256
    expected_file_sha256 = arguments.expected_manifest_file_sha256
    pin_errors: list[str] = []
    if final_strict:
        if any(value is not None for value in receipt_arguments):
            print(
                "generation receipt pins are only valid for progress preflight",
                file=sys.stderr,
            )
            return 1
        if arguments.phase0_checkpoint_manifest is None:
            pin_errors.append("final intake requires a Phase 0 checkpoint snapshot")
        if arguments.finalization_receipt is None:
            pin_errors.append("finalization receipt path is required")
        if (
            not isinstance(expected_payload_sha256, str)
            or _SHA256.fullmatch(expected_payload_sha256) is None
        ):
            pin_errors.append("final manifest payload SHA-256 caller pin is required")
        if (
            not isinstance(expected_file_sha256, str)
            or _SHA256.fullmatch(expected_file_sha256) is None
        ):
            pin_errors.append("final manifest file SHA-256 caller pin is required")
        if (
            not isinstance(
                arguments.expected_finalization_receipt_payload_sha256,
                str,
            )
            or _SHA256.fullmatch(
                arguments.expected_finalization_receipt_payload_sha256
            )
            is None
        ):
            pin_errors.append(
                "finalization receipt payload SHA-256 caller pin is required"
            )
        if (
            not isinstance(
                arguments.expected_finalization_receipt_file_sha256,
                str,
            )
            or _SHA256.fullmatch(
                arguments.expected_finalization_receipt_file_sha256
            )
            is None
        ):
            pin_errors.append(
                "finalization receipt file SHA-256 caller pin is required"
            )
        if pin_errors:
            print("; ".join(pin_errors), file=sys.stderr)
            return 1
        path_errors += _manifest_path_errors(
            arguments.finalization_receipt,
            must_exist=True,
        )
        path_errors += _manifest_path_errors(
            arguments.phase0_checkpoint_manifest,
            must_exist=True,
        )
        if path_errors:
            print("; ".join(path_errors), file=sys.stderr)
            return 1
        try:
            finalization_acceptance = load_finalization_acceptance(
                arguments.input,
                arguments.finalization_receipt,
                arguments.phase0_checkpoint_manifest,
                expected_receipt_payload_sha256=(
                    arguments.expected_finalization_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_finalization_receipt_file_sha256
                ),
                expected_manifest_payload_sha256=expected_payload_sha256,
                expected_manifest_file_sha256=expected_file_sha256,
            )
        except AcceptanceReceiptError:
            print("target-intake-finalization-receipt-invalid", file=sys.stderr)
            return 1
        manifest = finalization_acceptance.finalized_manifest
        manifest_raw = finalization_acceptance.finalized_raw
        snapshot_identity_errors = _snapshot_acceptance_identity_errors(
            finalization_acceptance.phase0_snapshot
        )
        if snapshot_identity_errors:
            print("; ".join(snapshot_identity_errors), file=sys.stderr)
            return 1
        lineage = None
    else:
        if any(value is not None for value in finalization_arguments):
            print(
                "finalization receipt pins are only valid for final strict preflight",
                file=sys.stderr,
            )
            return 1
        if any(value is None for value in receipt_arguments):
            print(
                "caller-pinned terminal generation receipt is required",
                file=sys.stderr,
            )
            return 1
        try:
            lineage = load_generation_lineage(
                arguments.input,
                arguments.input_receipt,
                expected_receipt_payload_sha256=(
                    arguments.expected_input_receipt_payload_sha256
                ),
                expected_receipt_file_sha256=(
                    arguments.expected_input_receipt_file_sha256
                ),
            )
        except GenerationLineageError:
            print("target-intake-progress-lineage-invalid", file=sys.stderr)
            return 1
        manifest = lineage.manifest
        manifest_raw = lineage.manifest_raw
    if not final_strict and (
        expected_payload_sha256 is not None or expected_file_sha256 is not None
    ):
        pin_errors.append(
            "final manifest caller pins are only valid for final strict preflight"
        )
    if pin_errors:
        print("; ".join(pin_errors), file=sys.stderr)
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
    if lineage is not None:
        try:
            recheck_generation_lineage(lineage)
        except GenerationLineageError:
            print("target-intake-progress-lineage-invalid", file=sys.stderr)
            return 1
    else:
        try:
            recheck_finalization_acceptance(finalization_acceptance)
        except AcceptanceReceiptError:
            print("target-intake-finalization-receipt-invalid", file=sys.stderr)
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
        f"manifest_file_sha256={hashlib.sha256(manifest_raw).hexdigest()} "
        f"requirements_sha256={manifest['requirements_sha256']} "
        f"final-manifest-caller-pin={'matched' if final_strict else 'not-applicable'} "
        f"finalization-receipt-caller-pin={'matched' if final_strict else 'not-applicable'} "
        f"selected-generation-lineage={'not-applicable' if final_strict else 'caller-pinned-local-receipt-chain-validated'} "
        f"selected-finalization-lineage={'caller-pinned-local-receipt-chain-validated' if final_strict else 'not-applicable'} "
        "final-manifest-custody=unverified "
        "final-manifest-pin-authority=unverified "
        "final-manifest-rollback-protection=unverified "
        "finalization-receipt-authority=unverified "
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
