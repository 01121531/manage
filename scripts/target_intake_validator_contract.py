"""Bind target-intake historical replay to one exact local verifier source set."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.metadata
import importlib.util
import os
import platform as runtime_platform
from pathlib import Path
import re
import sys
import sysconfig
from typing import Any, Iterator

from scripts.external_json import StableFileError, read_stable_bytes_with_metadata


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_CONTRACT_KIND = "target_intake_generation_validator_contract_v3"
VALIDATOR_CONTRACT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "authoring_entrypoint",
    "replay_entrypoint",
    "source_files",
    "runtime_environment",
    "execution_profile",
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
    "stdlib_platform_sha256",
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
    "platform/api/__init__.py",
    "platform/api/v1/__init__.py",
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
    "scripts/target_intake_snapshot_launcher.py",
    "scripts/target_intake_source_snapshot.py",
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
EXECUTION_PROFILE_KIND = "target_intake_generation_execution_profile_v1"
EXECUTION_PROFILE_KEYS = {
    "kind",
    "mode",
    "production_acceptance",
    "snapshot_manifest_payload_sha256",
    "snapshot_manifest_file_sha256",
    "isolated",
    "ignore_environment",
    "no_site",
    "safe_path",
    "dont_write_bytecode",
    "local_module_origins_rechecked",
    "snapshot_pre_and_post_recheck_required",
}
DIRECT_EXECUTION_MODE = "direct_in_process_unverified_v1"
SNAPSHOT_EXECUTION_MODE = "clean_isolated_external_snapshot_subprocess_v1"
_active_snapshot_execution_profile: dict[str, Any] | None = None


class ValidatorContractError(ValueError):
    """The local verifier source set cannot establish one stable identity."""


def _direct_execution_profile() -> dict[str, Any]:
    return {
        "kind": EXECUTION_PROFILE_KIND,
        "mode": DIRECT_EXECUTION_MODE,
        "production_acceptance": False,
        "snapshot_manifest_payload_sha256": None,
        "snapshot_manifest_file_sha256": None,
        "isolated": False,
        "ignore_environment": False,
        "no_site": False,
        "safe_path": False,
        "dont_write_bytecode": False,
        "local_module_origins_rechecked": False,
        "snapshot_pre_and_post_recheck_required": False,
    }


def _execution_profile_shape_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != EXECUTION_PROFILE_KEYS:
        return ["generation validator execution profile is invalid"]
    if (
        document.get("kind") != EXECUTION_PROFILE_KIND
        or document.get("production_acceptance") is not False
    ):
        return ["generation validator execution profile is invalid"]
    mode = document.get("mode")
    if mode == DIRECT_EXECUTION_MODE:
        return (
            []
            if document == _direct_execution_profile()
            else ["generation validator execution profile is invalid"]
        )
    if mode != SNAPSHOT_EXECUTION_MODE or any(
        _SHA256.fullmatch(document.get(key) or "") is None
        for key in (
            "snapshot_manifest_payload_sha256",
            "snapshot_manifest_file_sha256",
        )
    ):
        return ["generation validator execution profile is invalid"]
    if any(
        document.get(key) is not True
        for key in (
            "isolated",
            "ignore_environment",
            "no_site",
            "safe_path",
            "dont_write_bytecode",
            "local_module_origins_rechecked",
            "snapshot_pre_and_post_recheck_required",
        )
    ):
        return ["generation validator execution profile is invalid"]
    return []


@contextmanager
def snapshot_execution_profile(
    manifest_payload_sha256: str,
    manifest_file_sha256: str,
) -> Iterator[None]:
    """Bind one already-verified clean child to its caller-pinned snapshot."""

    global _active_snapshot_execution_profile
    flags = sys.flags
    if (
        _active_snapshot_execution_profile is not None
        or _SHA256.fullmatch(manifest_payload_sha256) is None
        or _SHA256.fullmatch(manifest_file_sha256) is None
        or flags.isolated != 1
        or flags.ignore_environment != 1
        or flags.no_site != 1
        or flags.no_user_site != 1
        or getattr(flags, "safe_path", False) is not True
        or flags.dont_write_bytecode != 1
    ):
        raise ValidatorContractError(
            "target intake validator snapshot execution is unavailable"
        )
    profile = {
        "kind": EXECUTION_PROFILE_KIND,
        "mode": SNAPSHOT_EXECUTION_MODE,
        "production_acceptance": False,
        "snapshot_manifest_payload_sha256": manifest_payload_sha256,
        "snapshot_manifest_file_sha256": manifest_file_sha256,
        "isolated": True,
        "ignore_environment": True,
        "no_site": True,
        "safe_path": True,
        "dont_write_bytecode": True,
        "local_module_origins_rechecked": True,
        "snapshot_pre_and_post_recheck_required": True,
    }
    if _execution_profile_shape_errors(profile):
        raise ValidatorContractError(
            "target intake validator snapshot execution is unavailable"
        )
    _active_snapshot_execution_profile = profile
    try:
        yield
    finally:
        _active_snapshot_execution_profile = None


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
        or _SHA256.fullmatch(python.get("stdlib_platform_sha256", "")) is None
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
    stdlib_platform_path = Path(sysconfig.get_path("stdlib")) / "platform.py"
    platform_code = getattr(runtime_platform.python_implementation, "__code__", None)
    if (
        platform_code is None
        or os.path.normcase(os.path.abspath(platform_code.co_filename))
        != os.path.normcase(os.path.abspath(stdlib_platform_path))
    ):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    stdlib_platform_raw, _ = read_stable_bytes_with_metadata(
        stdlib_platform_path,
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
            "stdlib_platform_sha256": hashlib.sha256(
                stdlib_platform_raw
            ).hexdigest(),
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
        document.get("schema_version") != 3
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
    if _execution_profile_shape_errors(document.get("execution_profile")):
        return ["generation validator contract execution profile is invalid"]
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
        "schema_version": 3,
        "kind": VALIDATOR_CONTRACT_KIND,
        "production_acceptance": False,
        "authoring_entrypoint": AUTHORING_ENTRYPOINT,
        "replay_entrypoint": REPLAY_ENTRYPOINT,
        "source_files": sources,
        "runtime_environment": runtime_environment,
        "execution_profile": (
            dict(_active_snapshot_execution_profile)
            if _active_snapshot_execution_profile is not None
            else _direct_execution_profile()
        ),
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
