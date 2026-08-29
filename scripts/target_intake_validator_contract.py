"""Bind target-intake historical replay to one exact local verifier source set."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from scripts.external_json import StableFileError, read_stable_bytes_with_metadata


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_CONTRACT_KIND = "target_intake_generation_validator_contract_v1"
VALIDATOR_CONTRACT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "authoring_entrypoint",
    "replay_entrypoint",
    "source_files",
}
SOURCE_FILE_KEYS = {"path", "sha256"}
AUTHORING_ENTRYPOINT = "scripts.target_intake_preflight:intake_errors"
REPLAY_ENTRYPOINT = (
    "scripts.target_intake_preflight:_generation_semantic_replay_errors"
)
SOURCE_FILES = (
    "scripts/backup_output_policy.py",
    "scripts/check_internal_tls_expiry.py",
    "scripts/decision_envelope_validation.py",
    "scripts/deploy_release_evidence.py",
    "scripts/external_json.py",
    "scripts/external_text.py",
    "scripts/external_yaml.py",
    "scripts/phase0_boundary_approval.py",
    "scripts/phase6_operations_evidence.py",
    "scripts/phase6_pilot_evidence.py",
    "scripts/phase6_pilot_inputs.py",
    "scripts/phase6_rehearsal.py",
    "scripts/private_secret_file.py",
    "scripts/provider_contract_conformance.py",
    "scripts/release_execution_binding.py",
    "scripts/rollback_release_evidence.py",
    "scripts/rolling_release_evidence.py",
    "scripts/sub2_execution_evidence.py",
    "scripts/target_intake_acceptance.py",
    "scripts/target_intake_generation.py",
    "scripts/target_intake_manifest.py",
    "scripts/target_intake_preflight.py",
    "scripts/target_intake_validator_contract.py",
    "scripts/target_phase_artifacts.py",
    "scripts/target_platform_inventory.py",
    "scripts/tls_runtime_identity.py",
    "scripts/training_evidence.py",
    "scripts/vault_egress_evidence.py",
    "scripts/verify_phase_acceptance_matrix.py",
    "scripts/verify_vault_isolation.py",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_BYTES = 256 * 1024


class ValidatorContractError(ValueError):
    """The local verifier source set cannot establish one stable identity."""


def validator_contract_shape_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != VALIDATOR_CONTRACT_KEYS:
        return ["generation validator contract schema is invalid"]
    if (
        document.get("schema_version") != 1
        or document.get("kind") != VALIDATOR_CONTRACT_KIND
        or document.get("production_acceptance") is not False
        or document.get("authoring_entrypoint") != AUTHORING_ENTRYPOINT
        or document.get("replay_entrypoint") != REPLAY_ENTRYPOINT
    ):
        return ["generation validator contract identity is invalid"]
    sources = document.get("source_files")
    if not isinstance(sources, list) or len(sources) != len(SOURCE_FILES):
        return ["generation validator contract source inventory is invalid"]
    if [item.get("path") if isinstance(item, dict) else None for item in sources] != list(
        SOURCE_FILES
    ):
        return ["generation validator contract source inventory is invalid"]
    if any(
        not isinstance(item, dict)
        or set(item) != SOURCE_FILE_KEYS
        or _SHA256.fullmatch(item.get("sha256", "")) is None
        for item in sources
    ):
        return ["generation validator contract source inventory is invalid"]
    return []


def current_validator_contract() -> dict[str, Any]:
    sources: list[dict[str, str]] = []
    try:
        for relative_path in SOURCE_FILES:
            raw, metadata = read_stable_bytes_with_metadata(
                ROOT / relative_path,
                max_bytes=_MAX_SOURCE_BYTES,
            )
            if metadata.st_nlink != 1:
                raise ValidatorContractError(
                    "target intake validator source identity is unavailable"
                )
            sources.append(
                {"path": relative_path, "sha256": hashlib.sha256(raw).hexdigest()}
            )
    except (OSError, StableFileError) as error:
        raise ValidatorContractError(
            "target intake validator source identity is unavailable"
        ) from error
    document = {
        "schema_version": 1,
        "kind": VALIDATOR_CONTRACT_KIND,
        "production_acceptance": False,
        "authoring_entrypoint": AUTHORING_ENTRYPOINT,
        "replay_entrypoint": REPLAY_ENTRYPOINT,
        "source_files": sources,
    }
    if validator_contract_shape_errors(document):
        raise ValidatorContractError(
            "target intake validator source identity is unavailable"
        )
    return document


def validator_contract_errors(
    document: Any,
    expected: Any | None = None,
) -> list[str]:
    if validator_contract_shape_errors(document):
        return ["generation validator contract is invalid"]
    if expected is None:
        try:
            expected = current_validator_contract()
        except ValidatorContractError:
            return ["generation validator contract is invalid"]
    if validator_contract_shape_errors(expected):
        return ["generation validator contract is invalid"]
    return [] if document == expected else ["generation validator contract is invalid"]
