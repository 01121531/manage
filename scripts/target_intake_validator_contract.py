"""Bind target-intake historical replay to one exact local verifier source set."""

from __future__ import annotations

from contextlib import contextmanager
import base64
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
import platform as runtime_platform
from pathlib import Path
import re
import stat
import sys
import sysconfig
from typing import Any, Iterator

from scripts.external_json import StableFileError, read_stable_bytes_with_metadata


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_CONTRACT_KIND = "target_intake_generation_validator_contract_v5"
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
RUNTIME_ENVIRONMENT_KIND = "target_intake_generation_replay_runtime_v3"
RUNTIME_ENVIRONMENT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "python",
    "operating_system",
    "distribution_closure",
    "distributions",
}
DISTRIBUTION_CLOSURE_KIND = (
    "fixed_roots_metadata_and_loaded_owner_distribution_closure_v1"
)
DISTRIBUTION_CLOSURE_KEYS = {
    "kind",
    "root_names",
    "metadata_closure_names",
    "loaded_owner_names",
    "union_names",
    "dependency_edges",
    "loaded_origin_file_count",
    "loaded_origin_map_sha256",
}
LOADED_DISTRIBUTION_SELECTION_KEYS = {
    "owner_names",
    "origin_file_count",
    "origin_map_sha256",
}
LOADED_RUNTIME_SELECTION_KEYS = {
    *LOADED_DISTRIBUTION_SELECTION_KEYS,
    "module_file_count",
    "module_tree_sha256",
    "native_file_count",
    "native_tree_sha256",
}
PYTHON_RUNTIME_KEYS = {
    "implementation",
    "version",
    "cache_tag",
    "abi_flags",
    "byteorder",
    "executable_sha256",
    "stdlib_payload_file_count",
    "stdlib_payload_size_bytes",
    "stdlib_payload_tree_sha256",
    "native_payload_file_count",
    "native_payload_size_bytes",
    "native_payload_tree_sha256",
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
    "import_names",
    "version",
    "recorded_file_count",
    "metadata_sha256",
    "record_sha256",
    "entrypoint_sha256",
    "payload_file_count",
    "payload_size_bytes",
    "payload_tree_sha256",
    "record_hash_verified_file_count",
    "record_unlisted_import_file_count",
    "import_tree_record_completeness",
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
    "platform/pool_import_contexts.py",
    "platform/pool_imports.py",
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
DEPENDENCY_ROOT_NAMES = tuple(
    re.sub(r"[-_.]+", "-", name).lower()
    for name, _ in DEPENDENCY_DISTRIBUTIONS
)
BOOTSTRAP_DISTRIBUTIONS = (("packaging", "packaging"),)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_PAYLOAD_FILES = 20_000
_MAX_RUNTIME_PAYLOAD_BYTES = 512 * 1024 * 1024
_MAX_RUNTIME_DISTRIBUTIONS = 128
_MAX_RUNTIME_DISTRIBUTION_FILES = 10_000
_MAX_RUNTIME_DISTRIBUTION_BYTES = 256 * 1024 * 1024
EXECUTION_PROFILE_KIND = "target_intake_generation_execution_profile_v2"
EXECUTION_PROFILE_KEYS = {
    "kind",
    "mode",
    "production_acceptance",
    "snapshot_manifest_payload_sha256",
    "snapshot_manifest_file_sha256",
    "launcher_interpreter_sha256",
    "isolated",
    "ignore_environment",
    "no_site",
    "safe_path",
    "dont_write_bytecode",
    "isolated_missing_pycache_prefix",
    "sourceless_loaders_rejected",
    "local_module_origins_rechecked",
    "snapshot_pre_and_post_recheck_required",
    "runtime_pre_and_post_recheck_required",
    "loaded_runtime_pre_and_post_recheck_required",
    "loaded_owner_names",
    "loaded_origin_file_count",
    "loaded_origin_map_sha256",
    "loaded_module_file_count",
    "loaded_module_tree_sha256",
    "loaded_native_file_count",
    "loaded_native_tree_sha256",
}
DIRECT_EXECUTION_MODE = "direct_in_process_unverified_v1"
SNAPSHOT_EXECUTION_MODE = "clean_isolated_external_snapshot_subprocess_v2"
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
        "launcher_interpreter_sha256": None,
        "isolated": False,
        "ignore_environment": False,
        "no_site": False,
        "safe_path": False,
        "dont_write_bytecode": False,
        "isolated_missing_pycache_prefix": False,
        "sourceless_loaders_rejected": False,
        "local_module_origins_rechecked": False,
        "snapshot_pre_and_post_recheck_required": False,
        "runtime_pre_and_post_recheck_required": False,
        "loaded_runtime_pre_and_post_recheck_required": False,
        "loaded_owner_names": [],
        "loaded_origin_file_count": None,
        "loaded_origin_map_sha256": None,
        "loaded_module_file_count": None,
        "loaded_module_tree_sha256": None,
        "loaded_native_file_count": None,
        "loaded_native_tree_sha256": None,
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
            "launcher_interpreter_sha256",
        )
    ):
        return ["generation validator execution profile is invalid"]
    if (
        not isinstance(document.get("loaded_owner_names"), list)
        or not document["loaded_owner_names"]
        or document["loaded_owner_names"]
        != sorted(set(document["loaded_owner_names"]))
        or any(
            not _is_canonical_distribution_name(name)
            for name in document["loaded_owner_names"]
        )
        or any(
            not isinstance(document.get(key), int)
            or isinstance(document.get(key), bool)
            or document[key] < 1
            for key in (
                "loaded_origin_file_count",
                "loaded_module_file_count",
                "loaded_native_file_count",
            )
        )
        or any(
            _SHA256.fullmatch(document.get(key, "")) is None
            for key in (
                "loaded_origin_map_sha256",
                "loaded_module_tree_sha256",
                "loaded_native_tree_sha256",
            )
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
            "isolated_missing_pycache_prefix",
            "sourceless_loaders_rejected",
            "local_module_origins_rechecked",
            "snapshot_pre_and_post_recheck_required",
            "runtime_pre_and_post_recheck_required",
            "loaded_runtime_pre_and_post_recheck_required",
        )
    ):
        return ["generation validator execution profile is invalid"]
    return []


@contextmanager
def snapshot_execution_profile(
    manifest_payload_sha256: str,
    manifest_file_sha256: str,
    launcher_interpreter_sha256: str,
    loaded_runtime_selection: dict[str, Any],
) -> Iterator[None]:
    """Bind one already-verified clean child to its caller-pinned snapshot."""

    global _active_snapshot_execution_profile
    flags = sys.flags
    if (
        _active_snapshot_execution_profile is not None
        or _SHA256.fullmatch(manifest_payload_sha256) is None
        or _SHA256.fullmatch(manifest_file_sha256) is None
        or _SHA256.fullmatch(launcher_interpreter_sha256) is None
        or _loaded_runtime_selection_errors(loaded_runtime_selection)
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
        "launcher_interpreter_sha256": launcher_interpreter_sha256,
        "isolated": True,
        "ignore_environment": True,
        "no_site": True,
        "safe_path": True,
        "dont_write_bytecode": True,
        "isolated_missing_pycache_prefix": True,
        "sourceless_loaders_rejected": True,
        "local_module_origins_rechecked": True,
        "snapshot_pre_and_post_recheck_required": True,
        "runtime_pre_and_post_recheck_required": True,
        "loaded_runtime_pre_and_post_recheck_required": True,
        "loaded_owner_names": list(loaded_runtime_selection["owner_names"]),
        "loaded_origin_file_count": loaded_runtime_selection["origin_file_count"],
        "loaded_origin_map_sha256": loaded_runtime_selection["origin_map_sha256"],
        "loaded_module_file_count": loaded_runtime_selection["module_file_count"],
        "loaded_module_tree_sha256": loaded_runtime_selection["module_tree_sha256"],
        "loaded_native_file_count": loaded_runtime_selection["native_file_count"],
        "loaded_native_tree_sha256": loaded_runtime_selection["native_tree_sha256"],
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


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse
    )


def _canonical_distribution_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    canonical = re.sub(r"[-_.]+", "-", name.strip()).lower()
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", canonical) is None:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return canonical


def _is_canonical_distribution_name(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return _canonical_distribution_name(value) == value
    except ValidatorContractError:
        return False


def _site_package_roots() -> tuple[Path, ...]:
    roots: dict[str, Path] = {}
    for key in ("purelib", "platlib"):
        value = sysconfig.get_path(key)
        if not value:
            continue
        path = Path(value).absolute()
        normalized = os.path.normcase(os.path.abspath(path))
        roots[normalized] = path
    if not roots:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return tuple(roots[key] for key in sorted(roots))


def _relative_to_roots(path: Path, roots: tuple[Path, ...]) -> tuple[int, str] | None:
    normalized_path = os.path.normcase(os.path.abspath(path))
    for index, root in enumerate(roots):
        normalized_root = os.path.normcase(os.path.abspath(root))
        try:
            relative = os.path.relpath(normalized_path, normalized_root)
        except ValueError:
            continue
        if relative == "." or (
            relative != ".." and not relative.startswith(f"..{os.sep}")
        ):
            return index, Path(relative).as_posix()
    return None


def _distribution_installation_index() -> dict[str, importlib.metadata.Distribution]:
    roots = _site_package_roots()
    index: dict[str, importlib.metadata.Distribution] = {}
    try:
        distributions = importlib.metadata.distributions(
            path=[str(root) for root in roots]
        )
        for distribution in distributions:
            raw_name = distribution.metadata.get("Name")
            canonical = _canonical_distribution_name(raw_name)
            if canonical in index:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            index[canonical] = distribution
    except (OSError, TypeError, ValueError) as error:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        ) from error
    return index


def _loaded_runtime_selection_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != LOADED_RUNTIME_SELECTION_KEYS:
        return ["generation validator loaded runtime selection is invalid"]
    owners = document.get("owner_names")
    if (
        not isinstance(owners, list)
        or not owners
        or owners != sorted(set(owners))
        or any(
            not _is_canonical_distribution_name(name)
            for name in owners
        )
        or any(
            not isinstance(document.get(key), int)
            or isinstance(document.get(key), bool)
            or document[key] < 1
            for key in (
                "origin_file_count",
                "module_file_count",
                "native_file_count",
            )
        )
        or any(
            _SHA256.fullmatch(document.get(key, "")) is None
            for key in (
                "origin_map_sha256",
                "module_tree_sha256",
                "native_tree_sha256",
            )
        )
    ):
        return ["generation validator loaded runtime selection is invalid"]
    return []


def _loaded_distribution_selection_errors(document: Any) -> list[str]:
    if (
        not isinstance(document, dict)
        or set(document) != LOADED_DISTRIBUTION_SELECTION_KEYS
    ):
        return ["generation validator loaded distribution selection is invalid"]
    owners = document.get("owner_names")
    if (
        not isinstance(owners, list)
        or not owners
        or owners != sorted(set(owners))
        or any(
            not _is_canonical_distribution_name(name)
            for name in owners
        )
        or not isinstance(document.get("origin_file_count"), int)
        or isinstance(document.get("origin_file_count"), bool)
        or document["origin_file_count"] < 1
        or _SHA256.fullmatch(document.get("origin_map_sha256", "")) is None
    ):
        return ["generation validator loaded distribution selection is invalid"]
    return []


def _loaded_distribution_selection() -> dict[str, Any]:
    roots = _site_package_roots()
    index = _distribution_installation_index()
    path_owners: dict[str, set[str]] = {}
    for canonical, distribution in index.items():
        files = distribution.files
        if not files:
            continue
        for entry in files:
            path = Path(distribution.locate_file(entry)).absolute()
            normalized = os.path.normcase(os.path.abspath(path))
            path_owners.setdefault(normalized, set()).add(canonical)

    records: list[dict[str, str]] = []
    owners: set[str] = set()
    for module_name, module in sorted(sys.modules.items()):
        specification = getattr(module, "__spec__", None)
        origin = getattr(specification, "origin", None)
        loader = getattr(specification, "loader", None)
        locations = getattr(specification, "submodule_search_locations", None)
        synthetic_extension = False
        if origin in {"built-in", "frozen"}:
            continue
        if origin is None:
            if locations:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            module_file = getattr(module, "__file__", None)
            if module_file is None:
                continue
            if (
                not isinstance(module_file, str)
                or not os.path.isabs(module_file)
                or Path(module_file).suffix.lower()
                not in {".py", ".pyi", ".pyd", ".so", ".dylib"}
            ):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            origin = module_file
            synthetic_extension = True
        if (
            not isinstance(origin, str)
            or not os.path.isabs(origin)
            or origin.lower().endswith((".pyc", ".pyo"))
            or (
                not synthetic_extension
                and not isinstance(
                loader,
                (
                    importlib.machinery.SourceFileLoader,
                    importlib.machinery.ExtensionFileLoader,
                ),
                )
            )
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        path = Path(origin).absolute()
        relative = _relative_to_roots(path, roots)
        if relative is None:
            continue
        normalized = os.path.normcase(os.path.abspath(path))
        candidates = path_owners.get(normalized, set())
        if len(candidates) != 1:
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        owner = next(iter(candidates))
        owners.add(owner)
        records.append(
            {
                "module": module_name,
                "origin": f"site/{relative[0]}/{relative[1]}",
                "owner": owner,
            }
        )
    if not records or not owners:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: (item["module"], item["origin"], item["owner"])):
        digest.update(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        digest.update(b"\n")
    document = {
        "owner_names": sorted(owners),
        "origin_file_count": len(records),
        "origin_map_sha256": digest.hexdigest(),
    }
    if _loaded_distribution_selection_errors(document):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return document


def _windows_loaded_native_paths() -> list[Path]:
    import ctypes
    import ctypes.wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
    kernel32.K32EnumProcessModules.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.HMODULE),
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    kernel32.K32EnumProcessModules.restype = ctypes.wintypes.BOOL
    kernel32.K32GetModuleFileNameExW.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.HMODULE,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
    ]
    kernel32.K32GetModuleFileNameExW.restype = ctypes.wintypes.DWORD

    def capture() -> list[Path]:
        modules = (ctypes.wintypes.HMODULE * 4096)()
        needed = ctypes.wintypes.DWORD()
        process = kernel32.GetCurrentProcess()
        if not kernel32.K32EnumProcessModules(
            process,
            modules,
            ctypes.sizeof(modules),
            ctypes.byref(needed),
        ) or needed.value > ctypes.sizeof(modules):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        paths: dict[str, Path] = {}
        count = needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
        for module in modules[:count]:
            buffer = ctypes.create_unicode_buffer(32768)
            length = kernel32.K32GetModuleFileNameExW(
                process, module, buffer, len(buffer)
            )
            if length < 1 or length >= len(buffer):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            path = Path(buffer.value).resolve(strict=True)
            paths[os.path.normcase(os.path.abspath(path))] = path
        return [paths[key] for key in sorted(paths)]

    first = capture()
    second = capture()
    if first != second:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return first


def _linux_loaded_native_paths() -> list[Path]:
    def capture() -> list[Path]:
        try:
            raw = Path("/proc/self/maps").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            ) from error
        paths: dict[str, Path] = {}
        for line in raw.splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) != 6 or "x" not in parts[1]:
                continue
            value = parts[5]
            if not value.startswith("/"):
                continue
            if value.endswith(" (deleted)"):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            path = Path(value).resolve(strict=True)
            paths[os.path.normcase(os.path.abspath(path))] = path
        return [paths[key] for key in sorted(paths)]

    first = capture()
    second = capture()
    if not first or first != second:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return first


def _darwin_loaded_native_paths() -> list[Path]:
    import ctypes

    process = ctypes.CDLL(None)
    image_count = process._dyld_image_count
    image_count.restype = ctypes.c_uint32
    image_name = process._dyld_get_image_name
    image_name.argtypes = [ctypes.c_uint32]
    image_name.restype = ctypes.c_char_p

    def capture() -> list[Path]:
        paths: dict[str, Path] = {}
        for index in range(image_count()):
            raw = image_name(index)
            if not raw:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            path = Path(os.fsdecode(raw)).resolve(strict=True)
            paths[os.path.normcase(os.path.abspath(path))] = path
        return [paths[key] for key in sorted(paths)]

    first = capture()
    second = capture()
    if not first or first != second:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return first


def _loaded_native_paths() -> list[Path]:
    if sys.platform == "win32":
        return _windows_loaded_native_paths()
    if sys.platform.startswith("linux"):
        return _linux_loaded_native_paths()
    if sys.platform == "darwin":
        return _darwin_loaded_native_paths()
    raise ValidatorContractError(
        "target intake validator runtime identity is unavailable"
    )


def _loaded_runtime_selection() -> dict[str, Any]:
    native_paths = _loaded_native_paths()
    distribution = _loaded_distribution_selection()
    module_files: dict[str, Path] = {}
    for module_name, module in sorted(sys.modules.items()):
        specification = getattr(module, "__spec__", None)
        origin = getattr(specification, "origin", None)
        loader = getattr(specification, "loader", None)
        synthetic_extension = False
        if origin in {"built-in", "frozen"}:
            continue
        if origin is None:
            module_file = getattr(module, "__file__", None)
            if module_file is None:
                continue
            if (
                not isinstance(module_file, str)
                or not os.path.isabs(module_file)
                or Path(module_file).suffix.lower()
                not in {".py", ".pyi", ".pyd", ".so", ".dylib"}
            ):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            origin = module_file
            synthetic_extension = True
        if (
            not isinstance(origin, str)
            or not os.path.isabs(origin)
            or origin.lower().endswith((".pyc", ".pyo"))
            or (
                not synthetic_extension
                and not isinstance(
                loader,
                (
                    importlib.machinery.SourceFileLoader,
                    importlib.machinery.ExtensionFileLoader,
                ),
                )
            )
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        path = Path(origin).resolve(strict=True)
        locator = (
            f"module/{module_name}/"
            f"{os.path.normcase(os.path.abspath(path)).replace(chr(92), '/')}"
        )
        module_files[locator] = path
    module_count, _, module_sha256, _ = _payload_fingerprint(
        list(module_files.items())
    )
    native_files = [
        (
            f"native/{os.path.normcase(os.path.abspath(path)).replace(chr(92), '/')}",
            path,
        )
        for path in native_paths
    ]
    native_count, _, native_sha256, _ = _payload_fingerprint(
        native_files,
        require_single_link=False,
    )
    document = {
        **distribution,
        "module_file_count": module_count,
        "module_tree_sha256": module_sha256,
        "native_file_count": native_count,
        "native_tree_sha256": native_sha256,
    }
    if _loaded_runtime_selection_errors(document):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return document


def _tree_files(
    root: Path,
    *,
    prefix: str,
    excluded_roots: tuple[Path, ...] = (),
) -> list[tuple[str, Path]]:
    root = root.absolute()
    if not root.is_dir() or _is_link_or_reparse(root):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    excluded = {
        os.path.normcase(os.path.abspath(path)) for path in excluded_roots
    }
    files: list[tuple[str, Path]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        if _is_link_or_reparse(directory_path):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            child = directory_path / name
            normalized = os.path.normcase(os.path.abspath(child))
            if normalized in excluded or name == "__pycache__":
                continue
            if _is_link_or_reparse(child):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in sorted(file_names):
            path = directory_path / name
            if name.endswith((".pyc", ".pyo")):
                continue
            if _is_link_or_reparse(path):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            relative = path.relative_to(root).as_posix()
            files.append((f"{prefix}/{relative}", path))
    return files


def _payload_fingerprint(
    files: list[tuple[str, Path]],
    *,
    expected_sha256: dict[str, str] | None = None,
    require_single_link: bool = True,
) -> tuple[int, int, str, int]:
    normalized: dict[str, Path] = {}
    for locator, path in files:
        if not locator or locator in normalized:
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        normalized[locator] = path
    if not normalized or len(normalized) > _MAX_RUNTIME_PAYLOAD_FILES:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    digest = hashlib.sha256()
    total_size = 0
    verified_hashes = 0
    validated_directories: set[str] = set()
    for locator in sorted(normalized):
        path = normalized[locator]
        current = path.parent.absolute()
        unchecked: list[Path] = []
        while os.path.normcase(os.path.abspath(current)) not in validated_directories:
            unchecked.append(current)
            if current.parent == current:
                break
            current = current.parent
        for directory in reversed(unchecked):
            if not directory.is_dir() or _is_link_or_reparse(directory):
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            validated_directories.add(
                os.path.normcase(os.path.abspath(directory))
            )
        raw, metadata = _read_runtime_payload_bytes(
            path,
            require_single_link=require_single_link,
        )
        total_size += len(raw)
        if total_size > _MAX_RUNTIME_PAYLOAD_BYTES:
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        record = {
            "path": locator,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "link_count": metadata.st_nlink,
        }
        expected = (expected_sha256 or {}).get(locator)
        if expected is not None:
            if record["sha256"] != expected:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            verified_hashes += 1
        digest.update(
            json.dumps(
                record,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return len(normalized), total_size, digest.hexdigest(), verified_hashes


def _read_runtime_payload_bytes(
    path: Path,
    *,
    require_single_link: bool = True,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(path)
            or before.st_nlink < 1
            or (require_single_link and before.st_nlink != 1)
            or before.st_size < 0
            or before.st_size > _MAX_RUNTIME_FILE_BYTES
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        raw = path.read_bytes()
        after = path.lstat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            stat.S_IMODE(before.st_mode),
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            stat.S_IMODE(after.st_mode),
        )
        if (
            len(raw) != before.st_size
            or before_identity != after_identity
            or not stat.S_ISREG(after.st_mode)
            or _is_link_or_reparse(path)
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        return raw, after
    except OSError as error:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        ) from error


def _python_payload_fingerprints() -> dict[str, int | str]:
    stdlib_root = Path(sysconfig.get_path("stdlib")).absolute()
    excluded = tuple(
        Path(value).absolute()
        for value in {
            sysconfig.get_path("purelib"),
            sysconfig.get_path("platlib"),
        }
        if value
    )
    stdlib_files = _tree_files(
        stdlib_root,
        prefix="stdlib",
        excluded_roots=excluded,
    )
    stdlib_count, stdlib_size, stdlib_sha256, _ = _payload_fingerprint(
        stdlib_files
    )

    executable = Path(sys.executable).absolute()
    runtime_root = executable.parent
    native_files: dict[str, Path] = {"runtime/executable": executable}
    native_suffixes = {".dll", ".dylib", ".pyd", ".so"}
    for path in sorted(runtime_root.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.suffix.lower() in native_suffixes:
            native_files[f"runtime/{path.name}"] = path
    dll_root = runtime_root / "DLLs"
    if dll_root.exists():
        for locator, path in _tree_files(dll_root, prefix="runtime/DLLs"):
            native_files[locator] = path
    destination_shared = sysconfig.get_config_var("DESTSHARED")
    if destination_shared:
        shared_root = Path(destination_shared).absolute()
        if shared_root.is_dir() and shared_root != dll_root:
            for locator, path in _tree_files(
                shared_root,
                prefix="runtime/dynload",
            ):
                native_files[locator] = path
    native_count, native_size, native_sha256, _ = _payload_fingerprint(
        list(native_files.items())
    )
    return {
        "stdlib_payload_file_count": stdlib_count,
        "stdlib_payload_size_bytes": stdlib_size,
        "stdlib_payload_tree_sha256": stdlib_sha256,
        "native_payload_file_count": native_count,
        "native_payload_size_bytes": native_size,
        "native_payload_tree_sha256": native_sha256,
    }


def _runtime_environment_shape_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != RUNTIME_ENVIRONMENT_KEYS:
        return ["generation replay runtime schema is invalid"]
    if (
        document.get("schema_version") != 3
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
        or any(
            not isinstance(python.get(key), int)
            or isinstance(python.get(key), bool)
            or python[key] < 1
            for key in (
                "stdlib_payload_file_count",
                "stdlib_payload_size_bytes",
                "native_payload_file_count",
                "native_payload_size_bytes",
            )
        )
        or any(
            _SHA256.fullmatch(python.get(key, "")) is None
            for key in (
                "executable_sha256",
                "stdlib_payload_tree_sha256",
                "native_payload_tree_sha256",
            )
        )
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
    closure = document.get("distribution_closure")
    if (
        not isinstance(closure, dict)
        or set(closure) != DISTRIBUTION_CLOSURE_KEYS
        or closure.get("kind") != DISTRIBUTION_CLOSURE_KIND
        or closure.get("root_names") != list(DEPENDENCY_ROOT_NAMES)
        or not isinstance(closure.get("metadata_closure_names"), list)
        or closure["metadata_closure_names"]
        != sorted(set(closure["metadata_closure_names"]))
        or not set(DEPENDENCY_ROOT_NAMES).issubset(
            closure["metadata_closure_names"]
        )
        or not isinstance(closure.get("loaded_owner_names"), list)
        or closure["loaded_owner_names"]
        != sorted(set(closure["loaded_owner_names"]))
        or not isinstance(closure.get("union_names"), list)
        or closure["union_names"] != sorted(set(closure["union_names"]))
        or set(closure["union_names"])
        != set(closure["metadata_closure_names"])
        | set(closure["loaded_owner_names"])
        | {_canonical_distribution_name(BOOTSTRAP_DISTRIBUTIONS[0][0])}
        or any(
            not _is_canonical_distribution_name(name)
            for key in (
                "metadata_closure_names",
                "loaded_owner_names",
                "union_names",
            )
            for name in closure[key]
        )
        or not isinstance(closure.get("dependency_edges"), list)
        or closure["dependency_edges"]
        != sorted(set(closure["dependency_edges"]))
        or any(
            not isinstance(edge, str)
            or re.fullmatch(r"[a-z0-9-]+->[a-z0-9-]+", edge) is None
            or any(
                endpoint not in closure["metadata_closure_names"]
                for endpoint in edge.split("->")
            )
            for edge in closure["dependency_edges"]
        )
        or not isinstance(closure.get("loaded_origin_file_count"), int)
        or isinstance(closure.get("loaded_origin_file_count"), bool)
        or closure["loaded_origin_file_count"] < 0
        or _SHA256.fullmatch(closure.get("loaded_origin_map_sha256", "")) is None
    ):
        return ["generation replay dependency closure is invalid"]
    distributions = document.get("distributions")
    if (
        not isinstance(distributions, list)
        or len(distributions) != len(closure["union_names"])
        or [
            item.get("name") if isinstance(item, dict) else None
            for item in distributions
        ]
        != closure["union_names"]
        or any(
            not isinstance(item, dict)
            or set(item) != DISTRIBUTION_KEYS
            or not _is_canonical_distribution_name(item.get("name"))
            or not isinstance(item.get("version"), str)
            or not item["version"]
            or not isinstance(item.get("import_names"), list)
            or not item["import_names"]
            or item["import_names"] != sorted(set(item["import_names"]))
            or any(
                not isinstance(import_name, str) or not import_name.isidentifier()
                for import_name in item["import_names"]
            )
            or not isinstance(item.get("recorded_file_count"), int)
            or isinstance(item.get("recorded_file_count"), bool)
            or item["recorded_file_count"] < 1
            or any(
                not isinstance(item.get(key), int)
                or isinstance(item.get(key), bool)
                or item[key] < minimum
                for key, minimum in (
                    ("payload_file_count", 1),
                    ("payload_size_bytes", 1),
                    ("record_hash_verified_file_count", 0),
                    ("record_unlisted_import_file_count", 0),
                )
            )
            or item.get("record_unlisted_import_file_count") != 0
            or item.get("import_tree_record_completeness")
            is not (item.get("name") in DEPENDENCY_ROOT_NAMES)
            or any(
                _SHA256.fullmatch(item.get(key, "")) is None
                for key in (
                    "metadata_sha256",
                    "record_sha256",
                    "entrypoint_sha256",
                    "payload_tree_sha256",
                )
            )
            for item in distributions
        )
    ):
        return ["generation replay dependency inventory is invalid"]
    return []


def _distribution_import_names(
    canonical_name: str,
    *,
    fallback: str | None = None,
    import_name_index: dict[str, set[str]] | None = None,
) -> tuple[str, ...]:
    if import_name_index is None:
        import_name_index = _distribution_import_name_index()
    names = set(import_name_index.get(canonical_name, set()))
    if fallback:
        names.add(fallback)
    if not names:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    return tuple(sorted(names))


def _distribution_import_name_index() -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for import_name, distribution_names in importlib.metadata.packages_distributions().items():
        if import_name == "__pycache__" or not import_name.isidentifier():
            continue
        for distribution_name in distribution_names:
            canonical = _canonical_distribution_name(distribution_name)
            index.setdefault(canonical, set()).add(import_name)
    return index


def _distribution_fingerprint(
    name: str,
    import_name: str | tuple[str, ...],
    *,
    distribution: importlib.metadata.Distribution | None = None,
    audit_import_tree: bool = True,
) -> dict[str, Any]:
    canonical_name = _canonical_distribution_name(name)
    if distribution is None:
        distribution = importlib.metadata.distribution(name)
    import_names = (
        (import_name,) if isinstance(import_name, str) else tuple(import_name)
    )
    if (
        not import_names
        or list(import_names) != sorted(set(import_names))
        or any(not value.isidentifier() for value in import_names)
    ):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
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
    if (
        len(metadata_entries) != 1
        or len(record_entries) != 1
    ):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    metadata_path = Path(distribution.locate_file(metadata_entries[0])).absolute()
    record_path = Path(distribution.locate_file(record_entries[0])).absolute()
    metadata_raw, _ = read_stable_bytes_with_metadata(
        metadata_path,
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    record_raw, _ = read_stable_bytes_with_metadata(
        record_path,
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    payload_files: list[tuple[str, Path]] = []
    expected_sha256: dict[str, str] = {}
    recorded_paths: set[str] = set()
    for entry in files:
        relative = str(entry).replace("\\", "/")
        locator = f"record/{relative}"
        path = Path(distribution.locate_file(entry)).absolute()
        normalized_path = os.path.normcase(os.path.abspath(path))
        if normalized_path in recorded_paths:
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        recorded_paths.add(normalized_path)
        payload_files.append((locator, path))
        declared_hash = getattr(entry, "hash", None)
        if declared_hash is not None:
            if declared_hash.mode != "sha256":
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            try:
                decoded = base64.urlsafe_b64decode(
                    declared_hash.value + "=" * (-len(declared_hash.value) % 4)
                )
            except (TypeError, ValueError) as error:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                ) from error
            if len(decoded) != hashlib.sha256().digest_size:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            expected_sha256[locator] = decoded.hex()

    import_files: list[tuple[str, Path]] = []
    entrypoint_path: Path | None = None
    for import_index, current_name in enumerate(import_names):
        package_directories: dict[str, Path] = {}
        module_files: dict[str, Path] = {}
        for entry in files:
            relative = Path(str(entry).replace("\\", "/"))
            if not relative.parts:
                continue
            first = relative.parts[0]
            if first == current_name and len(relative.parts) > 1:
                path = Path(distribution.locate_file(entry)).absolute()
                package = path
                for _ in relative.parts[1:]:
                    package = package.parent
                package_directories[
                    os.path.normcase(os.path.abspath(package))
                ] = package
            elif (
                first == current_name
                or first.startswith(f"{current_name}.")
            ) and Path(first).suffix.lower() in {
                ".py",
                ".pyi",
                ".pyd",
                ".so",
                ".dylib",
            }:
                path = Path(distribution.locate_file(entry)).absolute()
                module_files[os.path.normcase(os.path.abspath(path))] = path
        for location_index, path in enumerate(
            package_directories[key] for key in sorted(package_directories)
        ):
            if audit_import_tree:
                import_files.extend(
                    _tree_files(
                        path,
                        prefix=f"import/{current_name}/{import_index}/{location_index}",
                    )
                )
            else:
                recorded_candidates = [
                    candidate
                    for candidate in payload_files
                    if _relative_to_roots(candidate[1], (path,)) is not None
                ]
                import_files.extend(
                    (
                        f"import/{current_name}/{import_index}/{location_index}/record/{file_index}",
                        candidate,
                    )
                    for file_index, (_, candidate) in enumerate(recorded_candidates)
                )
        for file_index, path in enumerate(
            module_files[key] for key in sorted(module_files)
        ):
            import_files.append(
                (f"import/{current_name}/{import_index}/file/{file_index}", path)
            )
        candidates = [
            path for _, path in import_files if entrypoint_path is None
        ]
        if candidates:
            entrypoint_path = candidates[0]
    if entrypoint_path is None or not import_files:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    entrypoint_raw, _ = _read_runtime_payload_bytes(entrypoint_path)
    unlisted_import_files = [
        (locator, path)
        for locator, path in import_files
        if os.path.normcase(os.path.abspath(path)) not in recorded_paths
    ]
    if audit_import_tree and unlisted_import_files:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    payload_count, payload_size, payload_sha256, verified_hash_count = (
        _payload_fingerprint(
            payload_files,
            expected_sha256=expected_sha256,
        )
    )
    return {
        "name": canonical_name,
        "import_names": list(import_names),
        "version": distribution.version,
        "recorded_file_count": len(files),
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "entrypoint_sha256": hashlib.sha256(entrypoint_raw).hexdigest(),
        "payload_file_count": payload_count,
        "payload_size_bytes": payload_size,
        "payload_tree_sha256": payload_sha256,
        "record_hash_verified_file_count": verified_hash_count,
        "record_unlisted_import_file_count": 0,
        "import_tree_record_completeness": audit_import_tree,
    }


def _distribution_closure(
    loaded_owner_names: tuple[str, ...],
    *,
    loaded_origin_file_count: int = 0,
    loaded_origin_map_sha256: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    index = _distribution_installation_index()
    packaging_name = _canonical_distribution_name(BOOTSTRAP_DISTRIBUTIONS[0][0])
    packaging_distribution = index.get(packaging_name)
    if packaging_distribution is None:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    packaging_fingerprint = _distribution_fingerprint(
        packaging_name,
        BOOTSTRAP_DISTRIBUTIONS[0][1],
        distribution=packaging_distribution,
        audit_import_tree=False,
    )
    try:
        from packaging.requirements import InvalidRequirement, Requirement
        from packaging.version import InvalidVersion, Version
    except ImportError as error:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        ) from error

    root_names = list(DEPENDENCY_ROOT_NAMES)
    metadata_names: set[str] = set(root_names)
    edges: set[str] = set()
    queue = list(root_names)
    try:
        while queue:
            parent = queue.pop(0)
            distribution = index.get(parent)
            if distribution is None:
                raise ValidatorContractError(
                    "target intake validator runtime identity is unavailable"
                )
            for raw_requirement in distribution.requires or []:
                requirement = Requirement(raw_requirement)
                if requirement.marker is not None and not requirement.marker.evaluate(
                    environment={"extra": ""}
                ):
                    continue
                if requirement.url:
                    raise ValidatorContractError(
                        "target intake validator runtime identity is unavailable"
                    )
                child = _canonical_distribution_name(requirement.name)
                child_distribution = index.get(child)
                if child_distribution is None or (
                    requirement.specifier
                    and not requirement.specifier.contains(
                        Version(child_distribution.version),
                        prereleases=True,
                    )
                ):
                    raise ValidatorContractError(
                        "target intake validator runtime identity is unavailable"
                    )
                edges.add(f"{parent}->{child}")
                if child not in metadata_names:
                    metadata_names.add(child)
                    queue.append(child)
    except (InvalidRequirement, InvalidVersion, TypeError, ValueError) as error:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        ) from error

    loaded_names = sorted(
        {_canonical_distribution_name(name) for name in loaded_owner_names}
    )
    if any(name not in index for name in loaded_names):
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    union_names = sorted(metadata_names | set(loaded_names) | {packaging_name})
    if len(union_names) > _MAX_RUNTIME_DISTRIBUTIONS:
        raise ValidatorContractError(
            "target intake validator runtime identity is unavailable"
        )
    root_import_names = {
        _canonical_distribution_name(name): import_name
        for name, import_name in DEPENDENCY_DISTRIBUTIONS
    }
    import_name_index = _distribution_import_name_index()
    fingerprints: list[dict[str, Any]] = []
    total_files = 0
    total_bytes = 0
    for canonical_name in union_names:
        if canonical_name == packaging_name:
            fingerprint = packaging_fingerprint
        else:
            fingerprint = _distribution_fingerprint(
                canonical_name,
                _distribution_import_names(
                    canonical_name,
                    fallback=root_import_names.get(canonical_name),
                    import_name_index=import_name_index,
                ),
                distribution=index[canonical_name],
                audit_import_tree=canonical_name in DEPENDENCY_ROOT_NAMES,
            )
        total_files += fingerprint["payload_file_count"]
        total_bytes += fingerprint["payload_size_bytes"]
        if (
            total_files > _MAX_RUNTIME_DISTRIBUTION_FILES
            or total_bytes > _MAX_RUNTIME_DISTRIBUTION_BYTES
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        fingerprints.append(fingerprint)
    closure = {
        "kind": DISTRIBUTION_CLOSURE_KIND,
        "root_names": root_names,
        "metadata_closure_names": sorted(metadata_names),
        "loaded_owner_names": loaded_names,
        "union_names": union_names,
        "dependency_edges": sorted(edges),
        "loaded_origin_file_count": loaded_origin_file_count,
        "loaded_origin_map_sha256": (
            loaded_origin_map_sha256 or hashlib.sha256().hexdigest()
        ),
    }
    return closure, fingerprints


def _current_runtime_environment(
    loaded_distribution_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
    read_stable_bytes_with_metadata(
        stdlib_platform_path,
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
    )
    python_payload = _python_payload_fingerprints()
    if loaded_distribution_selection is not None:
        if _loaded_distribution_selection_errors(loaded_distribution_selection):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
        selected = loaded_distribution_selection
    elif _active_snapshot_execution_profile is not None:
        selected = {
            "owner_names": _active_snapshot_execution_profile["loaded_owner_names"],
            "origin_file_count": _active_snapshot_execution_profile[
                "loaded_origin_file_count"
            ],
            "origin_map_sha256": _active_snapshot_execution_profile[
                "loaded_origin_map_sha256"
            ],
        }
    else:
        selected = {
            "owner_names": [],
            "origin_file_count": 0,
            "origin_map_sha256": hashlib.sha256().hexdigest(),
        }
    distribution_closure, distributions = _distribution_closure(
        tuple(selected["owner_names"]),
        loaded_origin_file_count=selected["origin_file_count"],
        loaded_origin_map_sha256=selected["origin_map_sha256"],
    )
    document = {
        "schema_version": 3,
        "kind": RUNTIME_ENVIRONMENT_KIND,
        "production_acceptance": False,
        "python": {
            "implementation": runtime_platform.python_implementation(),
            "version": runtime_platform.python_version(),
            "cache_tag": sys.implementation.cache_tag or "unavailable",
            "abi_flags": getattr(sys, "abiflags", ""),
            "byteorder": sys.byteorder,
            "executable_sha256": hashlib.sha256(executable_raw).hexdigest(),
            **python_payload,
        },
        "operating_system": {
            "os_name": os.name,
            "sys_platform": sys.platform,
            "system": runtime_platform.system(),
            "machine": runtime_platform.machine(),
            "version": runtime_platform.version(),
        },
        "distribution_closure": distribution_closure,
        "distributions": distributions,
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
        document.get("schema_version") != 5
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
        if (
            _active_snapshot_execution_profile is not None
            and runtime_environment["python"]["executable_sha256"]
            != _active_snapshot_execution_profile["launcher_interpreter_sha256"]
        ):
            raise ValidatorContractError(
                "target intake validator runtime identity is unavailable"
            )
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
        "schema_version": 5,
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
