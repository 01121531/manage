"""Bind target-intake historical replay to one exact local verifier source set."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import platform as runtime_platform
from pathlib import Path
import re
import sys
from typing import Any

from scripts.external_json import StableFileError, read_stable_bytes_with_metadata


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_CONTRACT_KIND = "target_intake_generation_validator_contract_v2"
VALIDATOR_CONTRACT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "authoring_entrypoint",
    "replay_entrypoint",
    "source_files",
    "runtime_environment",
}
SOURCE_FILE_KEYS = {"path", "sha256"}
RUNTIME_ENVIRONMENT_KIND = "target_intake_generation_replay_runtime_v1"
RUNTIME_ENVIRONMENT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "python",
    "operating_system",
    "distributions",
}
PYTHON_RUNTIME_KEYS = {
    "implementation",
    "version",
    "cache_tag",
    "abi_flags",
    "byteorder",
    "executable_sha256",
}
OPERATING_SYSTEM_KEYS = {
    "os_name",
    "sys_platform",
    "system",
    "machine",
    "version",
}
DISTRIBUTION_KEYS = {
    "name",
    "import_name",
    "version",
    "recorded_file_count",
    "metadata_sha256",
    "record_sha256",
    "entrypoint_sha256",
}
AUTHORING_ENTRYPOINT = "scripts.target_intake_preflight:intake_errors"
REPLAY_ENTRYPOINT = (
    "scripts.target_intake_preflight:_generation_semantic_replay_errors"
)
SOURCE_FILES = (
    "platform/__init__.py",
    "platform/api/v1/routes.py",
    "platform/app.py",
    "platform/audit.py",
    "platform/auth.py",
    "platform/bootstrap.py",
    "platform/card_events.py",
    "platform/cards.py",
    "platform/config.py",
    "platform/database.py",
    "platform/devices.py",
    "platform/errors.py",
    "platform/file_boundary.py",
    "platform/json_boundary.py",
    "platform/lifecycle.py",
    "platform/mail_connectors.py",
    "platform/mail_consumption.py",
    "platform/mail_health.py",
    "platform/mail_worker.py",
    "platform/metrics.py",
    "platform/middleware.py",
    "platform/models.py",
    "platform/operational_policies.py",
    "platform/policies.py",
    "platform/rate_limit.py",
    "platform/schemas.py",
    "platform/secrets.py",
    "platform/uploads.py",
    "platform/worker_metrics.py",
    "scripts/__init__.py",
    "scripts/backup_crypto.py",
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
DEPENDENCY_DISTRIBUTIONS = (
    ("alembic", "alembic"),
    ("cryptography", "cryptography"),
    ("fastapi", "fastapi"),
    ("httpx", "httpx"),
    ("PyJWT", "jwt"),
    ("pydantic", "pydantic"),
    ("pydantic-settings", "pydantic_settings"),
    ("PyYAML", "yaml"),
    ("redis", "redis"),
    ("SQLAlchemy", "sqlalchemy"),
    ("starlette", "starlette"),
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024


class ValidatorContractError(ValueError):
    """The local verifier source set cannot establish one stable identity."""


def _runtime_environment_shape_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != RUNTIME_ENVIRONMENT_KEYS:
        return ["generation replay runtime schema is invalid"]
    if (
        document.get("schema_version") != 1
        or document.get("kind") != RUNTIME_ENVIRONMENT_KIND
        or document.get("production_acceptance") is not False
    ):
        return ["generation replay runtime identity is invalid"]
    python = document.get("python")
    if not isinstance(python, dict) or set(python) != PYTHON_RUNTIME_KEYS:
        return ["generation replay Python runtime is invalid"]
    if (
        any(
            not isinstance(python.get(key), str) or not python[key]
            for key in ("implementation", "version", "cache_tag", "byteorder")
        )
        or not isinstance(python.get("abi_flags"), str)
        or python.get("byteorder") not in {"little", "big"}
        or _SHA256.fullmatch(python.get("executable_sha256", "")) is None
    ):
        return ["generation replay Python runtime is invalid"]
    operating_system = document.get("operating_system")
    if (
        not isinstance(operating_system, dict)
        or set(operating_system) != OPERATING_SYSTEM_KEYS
        or any(
            not isinstance(operating_system.get(key), str)
            or not operating_system[key]
            for key in OPERATING_SYSTEM_KEYS
        )
    ):
        return ["generation replay operating-system selection is invalid"]
    distributions = document.get("distributions")
    if (
        not isinstance(distributions, list)
        or len(distributions) != len(DEPENDENCY_DISTRIBUTIONS)
        or [
            item.get("name") if isinstance(item, dict) else None
            for item in distributions
        ]
        != [name for name, _ in DEPENDENCY_DISTRIBUTIONS]
        or any(
            not isinstance(item, dict)
            or set(item) != DISTRIBUTION_KEYS
            or not isinstance(item.get("version"), str)
            or not item["version"]
            or item.get("import_name")
            != DEPENDENCY_DISTRIBUTIONS[index][1]
            or not isinstance(item.get("recorded_file_count"), int)
            or isinstance(item.get("recorded_file_count"), bool)
            or item["recorded_file_count"] < 1
            or any(
                _SHA256.fullmatch(item.get(key, "")) is None
                for key in (
                    "metadata_sha256",
                    "record_sha256",
                    "entrypoint_sha256",
                )
            )
            for index, item in enumerate(distributions)
        )
    ):
        return ["generation replay dependency inventory is invalid"]
    return []


def _distribution_fingerprint(name: str, import_name: str) -> dict[str, Any]:
    distribution = importlib.metadata.distribution(name)
    files = distribution.files
    if not files:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    metadata_entries = [
        entry
        for entry in files
        if Path(str(entry)).name == "METADATA"
        and Path(str(entry)).parent.name.endswith(".dist-info")
    ]
    record_entries = [
        entry
        for entry in files
        if Path(str(entry)).name == "RECORD"
        and Path(str(entry)).parent.name.endswith(".dist-info")
    ]
    specification = importlib.util.find_spec(import_name)
    if (
        len(metadata_entries) != 1
        or len(record_entries) != 1
        or specification is None
        or not specification.origin
        or specification.origin in {"built-in", "frozen"}
    ):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    metadata_raw, _ = read_stable_bytes_with_metadata(
        Path(distribution.locate_file(metadata_entries[0])),
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    record_raw, _ = read_stable_bytes_with_metadata(
        Path(distribution.locate_file(record_entries[0])),
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    entrypoint_raw, _ = read_stable_bytes_with_metadata(
        Path(specification.origin),
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    return {
        "name": name,
        "import_name": import_name,
        "version": distribution.version,
        "recorded_file_count": len(files),
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "entrypoint_sha256": hashlib.sha256(entrypoint_raw).hexdigest(),
    }


def _current_runtime_environment() -> dict[str, Any]:
    executable_raw, _ = read_stable_bytes_with_metadata(
        Path(sys.executable),
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    document = {
        "schema_version": 1,
        "kind": RUNTIME_ENVIRONMENT_KIND,
        "production_acceptance": False,
        "python": {
            "implementation": runtime_platform.python_implementation(),
            "version": runtime_platform.python_version(),
            "cache_tag": sys.implementation.cache_tag or "unavailable",
            "abi_flags": getattr(sys, "abiflags", ""),
            "byteorder": sys.byteorder,
            "executable_sha256": hashlib.sha256(executable_raw).hexdigest(),
        },
        "operating_system": {
            "os_name": os.name,
            "sys_platform": sys.platform,
            "system": runtime_platform.system(),
            "machine": runtime_platform.machine(),
            "version": runtime_platform.version(),
        },
        "distributions": [
            _distribution_fingerprint(name, import_name)
            for name, import_name in DEPENDENCY_DISTRIBUTIONS
        ],
    }
    if _runtime_environment_shape_errors(document):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return document


def validator_contract_shape_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != VALIDATOR_CONTRACT_KEYS:
        return ["generation validator contract schema is invalid"]
    if (
        document.get("schema_version") != 2
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
    if _runtime_environment_shape_errors(document.get("runtime_environment")):
        return ["generation validator contract runtime environment is invalid"]
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
        runtime_environment = _current_runtime_environment()
    except (
        OSError,
        StableFileError,
        importlib.metadata.PackageNotFoundError,
        ValidatorContractError,
    ) as error:
        raise ValidatorContractError(
            "target intake validator source identity is unavailable"
        ) from error
    document = {
        "schema_version": 2,
        "kind": VALIDATOR_CONTRACT_KIND,
        "production_acceptance": False,
        "authoring_entrypoint": AUTHORING_ENTRYPOINT,
        "replay_entrypoint": REPLAY_ENTRYPOINT,
        "source_files": sources,
        "runtime_environment": runtime_environment,
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
