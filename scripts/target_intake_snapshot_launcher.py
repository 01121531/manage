"""Prepare and run target-intake validation from one pinned source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILENAME = "target-intake-validator-source-snapshot.json"
SNAPSHOT_KIND = "target_intake_validator_source_snapshot_v1"
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_INTERPRETER_BYTES = 64 * 1024 * 1024
_SHA256_LENGTH = 64
_CHILD_TIMEOUT_SECONDS = 600
_PREFLIGHT_COMMANDS = {
    "verify-requirements",
    "verify-generation-lineage",
    "verify-receipt",
    "init",
    "snapshot",
    "register",
    "finalize",
    "preflight",
}
_CHILD_BOOTSTRAP = (
    "import os,sys,sysconfig;"
    "r=os.path.abspath(sys.argv[1]);"
    "base=[p for p in sys.path if p and os.path.isabs(p) and "
    "os.path.normcase(os.path.abspath(p))!=os.path.normcase(r)];"
    "paths=sysconfig.get_paths();"
    "deps=[];"
    "[(deps.append(os.path.abspath(paths[k]))) for k in ('purelib','platlib') "
    "if paths.get(k) and os.path.abspath(paths[k]) not in deps];"
    "sys.path[:]=[r]+[p for p in base if p not in deps]+deps;"
    "from scripts.target_intake_snapshot_launcher import _child_main;"
    "raise SystemExit(_child_main(sys.argv[1:]))"
)


class SnapshotLaunchError(ValueError):
    """The selected snapshot cannot safely start the target-intake validator."""


def _invalid() -> SnapshotLaunchError:
    return SnapshotLaunchError("target intake validator snapshot launch is invalid")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _invalid()
        value[key] = item
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse
    )


def _has_link_or_reparse_ancestor(path: Path) -> bool:
    current = path.absolute()
    while True:
        if _is_link_or_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _read_stable_manifest(
    snapshot_root: Path,
    *,
    expected_payload_sha256: str,
    expected_file_sha256: str,
    expected_identity: tuple[int, int, int, int, int] | None = None,
) -> tuple[dict[str, Any], bytes, tuple[int, int, int, int, int]]:
    if (
        not snapshot_root.is_absolute()
        or _has_link_or_reparse_ancestor(snapshot_root)
        or not _is_sha256(expected_payload_sha256)
        or not _is_sha256(expected_file_sha256)
    ):
        raise _invalid()
    manifest_path = snapshot_root / MANIFEST_FILENAME
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(manifest_path, flags)
    except OSError as error:
        raise _invalid() from error
    try:
        opened = os.fstat(descriptor)
        named = manifest_path.lstat()
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        named_identity = (
            named.st_dev,
            named.st_ino,
            named.st_nlink,
            named.st_size,
            named.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or identity != named_identity
            or identity[2] != 1
            or identity[3] <= 0
            or identity[3] > _MAX_MANIFEST_BYTES
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise _invalid()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_MANIFEST_BYTES + 1)
        final_opened = os.fstat(descriptor)
        final_named = manifest_path.lstat()
        final_identity = (
            final_opened.st_dev,
            final_opened.st_ino,
            final_opened.st_nlink,
            final_opened.st_size,
            final_opened.st_mtime_ns,
        )
        final_named_identity = (
            final_named.st_dev,
            final_named.st_ino,
            final_named.st_nlink,
            final_named.st_size,
            final_named.st_mtime_ns,
        )
        if (
            len(raw) != identity[3]
            or final_identity != identity
            or final_named_identity != identity
        ):
            raise _invalid()
    except (OSError, SnapshotLaunchError):
        raise
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, SnapshotLaunchError) as error:
        raise _invalid() from error
    integrity = document.get("integrity") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("kind") != SNAPSHOT_KIND
        or document.get("production_acceptance") is not False
        or not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), expected_file_sha256
        )
        or not hmac.compare_digest(
            integrity.get("payload_sha256", ""), expected_payload_sha256
        )
    ):
        raise _invalid()
    return document, raw, identity


def _read_stable_binary(
    path: Path,
    *,
    max_bytes: int,
    expected_identity: tuple[int, int, int, int, int] | None = None,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    if (
        not path.is_absolute()
        or _has_link_or_reparse_ancestor(path)
        or max_bytes < 1
    ):
        raise _invalid()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _invalid() from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        named_identity = (
            named.st_dev,
            named.st_ino,
            named.st_nlink,
            named.st_size,
            named.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or identity != named_identity
            or identity[2] != 1
            or identity[3] <= 0
            or identity[3] > max_bytes
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise _invalid()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        final_opened = os.fstat(descriptor)
        final_named = path.lstat()
        final_identity = (
            final_opened.st_dev,
            final_opened.st_ino,
            final_opened.st_nlink,
            final_opened.st_size,
            final_opened.st_mtime_ns,
        )
        final_named_identity = (
            final_named.st_dev,
            final_named.st_ino,
            final_named.st_nlink,
            final_named.st_size,
            final_named.st_mtime_ns,
        )
        if (
            len(raw) != identity[3]
            or final_identity != identity
            or final_named_identity != identity
        ):
            raise _invalid()
        return raw, identity
    except OSError as error:
        raise _invalid() from error
    finally:
        os.close(descriptor)


def _minimal_environment() -> dict[str, str]:
    allowed = ("SYSTEMROOT", "WINDIR") if os.name == "nt" else ()
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _audit_loaded_local_modules(snapshot_root: Path, document: dict[str, Any]) -> None:
    from importlib.machinery import SourceFileLoader

    members = document.get("members")
    if not isinstance(members, list):
        raise _invalid()
    digests = {
        item.get("path"): item.get("sha256")
        for item in members
        if isinstance(item, dict)
    }
    root = snapshot_root.resolve(strict=True)
    for name, module in tuple(sys.modules.items()):
        if not (name == "scripts" or name.startswith("scripts.") or name == "platform" or name.startswith("platform.")):
            continue
        specification = getattr(module, "__spec__", None)
        origin = getattr(specification, "origin", None)
        loader = getattr(specification, "loader", None)
        if not isinstance(origin, str) or not isinstance(loader, SourceFileLoader):
            raise _invalid()
        try:
            origin_path = Path(origin).resolve(strict=True)
            relative = origin_path.relative_to(root).as_posix()
            raw = origin_path.read_bytes()
        except (OSError, ValueError):
            raise _invalid() from None
        expected = digests.get(relative)
        if not _is_sha256(expected) or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), expected
        ):
            raise _invalid()


def _child_main(argv: Sequence[str]) -> int:
    if len(argv) < 6 or argv[4] != "--":
        print("target-intake-validator-snapshot-child-invalid", file=sys.stderr)
        return 1
    snapshot_root = Path(argv[0])
    payload_sha256 = argv[1]
    file_sha256 = argv[2]
    interpreter_sha256 = argv[3]
    preflight_argv = list(argv[5:])
    if not preflight_argv or preflight_argv[0] not in _PREFLIGHT_COMMANDS:
        print("target-intake-validator-snapshot-child-invalid", file=sys.stderr)
        return 1
    try:
        executable_raw, executable_identity = _read_stable_binary(
            Path(sys.executable).absolute(),
            max_bytes=_MAX_INTERPRETER_BYTES,
        )
        if not hmac.compare_digest(
            hashlib.sha256(executable_raw).hexdigest(), interpreter_sha256
        ):
            raise _invalid()
        from scripts.target_intake_source_snapshot import (
            load_source_snapshot,
            recheck_source_snapshot,
        )

        snapshot = load_source_snapshot(
            snapshot_root,
            expected_payload_sha256=payload_sha256,
            expected_file_sha256=file_sha256,
        )
        document = snapshot.manifest
        from scripts.target_intake_validator_contract import (
            _current_runtime_environment,
            snapshot_execution_profile,
        )
        runtime_environment = _current_runtime_environment()
        from scripts import target_intake_preflight

        if (
            target_intake_preflight.main.__module__
            != "scripts.target_intake_preflight"
            or Path(target_intake_preflight.__file__).resolve(strict=True)
            != (snapshot_root / "scripts" / "target_intake_preflight.py").resolve(
                strict=True
            )
        ):
            raise _invalid()
        _audit_loaded_local_modules(snapshot_root, document)
        with snapshot_execution_profile(
            payload_sha256,
            file_sha256,
            interpreter_sha256,
        ):
            result = target_intake_preflight.main(preflight_argv)
        if _current_runtime_environment() != runtime_environment:
            raise _invalid()
        _audit_loaded_local_modules(snapshot_root, document)
        recheck_source_snapshot(snapshot)
        final_executable_raw, _ = _read_stable_binary(
            Path(sys.executable).absolute(),
            max_bytes=_MAX_INTERPRETER_BYTES,
            expected_identity=executable_identity,
        )
        if not hmac.compare_digest(executable_raw, final_executable_raw):
            raise _invalid()
    except (OSError, TypeError, ValueError):
        print("target-intake-validator-snapshot-child-invalid", file=sys.stderr)
        return 1
    if result == 0:
        print(
            "target-intake-validator-snapshot-child-ok "
            "production_acceptance=false "
            "execution-mode=clean-isolated-external-snapshot-subprocess-v1 "
            "current-loaded-local-source=snapshot-origin-sha256-rechecked "
            "snapshot-pre-post-recheck=matched "
            "runtime-pre-post-recheck=matched "
            "launcher-interpreter-pre-post-recheck=matched "
            "source-authority=unverified snapshot-atomicity=unverified "
            "interpreter-native-runtime-identity=unverified"
        )
    return result


def _prepare(destination: Path) -> int:
    while str(ROOT) in sys.path:
        sys.path.remove(str(ROOT))
    sys.path.insert(0, str(ROOT))
    try:
        from scripts.target_intake_source_snapshot import prepare_source_snapshot

        snapshot = prepare_source_snapshot(destination)
    except (OSError, TypeError, ValueError):
        print("target-intake-validator-source-snapshot-prepare-invalid", file=sys.stderr)
        return 1
    print(
        "target-intake-validator-source-snapshot-prepared "
        "production_acceptance=false "
        f"snapshot_manifest_payload_sha256={snapshot.payload_sha256} "
        f"snapshot_manifest_file_sha256={snapshot.file_sha256} "
        "source-authority=unverified snapshot-atomicity=unverified"
    )
    return 0


def _run(
    snapshot_root: Path,
    payload_sha256: str,
    file_sha256: str,
    preflight_argv: list[str],
) -> int:
    if not preflight_argv or preflight_argv[0] not in _PREFLIGHT_COMMANDS:
        print("target-intake-validator-snapshot-launch-invalid", file=sys.stderr)
        return 1
    try:
        resolved_snapshot = snapshot_root.resolve(strict=True)
        resolved_repository = ROOT.resolve(strict=True)
        try:
            resolved_snapshot.relative_to(resolved_repository)
        except ValueError:
            pass
        else:
            raise _invalid()
        snapshot_root = resolved_snapshot
        _, raw, identity = _read_stable_manifest(
            snapshot_root,
            expected_payload_sha256=payload_sha256,
            expected_file_sha256=file_sha256,
        )
        executable = Path(sys.executable).resolve(strict=True)
        if not executable.is_absolute():
            raise _invalid()
        executable_raw, executable_identity = _read_stable_binary(
            executable,
            max_bytes=_MAX_INTERPRETER_BYTES,
        )
        interpreter_sha256 = hashlib.sha256(executable_raw).hexdigest()
        command = [
            str(executable),
            "-I",
            "-B",
            "-S",
            "-P",
            "-c",
            _CHILD_BOOTSTRAP,
            str(snapshot_root),
            payload_sha256,
            file_sha256,
            interpreter_sha256,
            "--",
            *preflight_argv,
        ]
        completed = subprocess.run(
            command,
            cwd=snapshot_root,
            env=_minimal_environment(),
            stdin=subprocess.DEVNULL,
            shell=False,
            timeout=_CHILD_TIMEOUT_SECONDS,
            check=False,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            ),
        )
        _, final_raw, _ = _read_stable_manifest(
            snapshot_root,
            expected_payload_sha256=payload_sha256,
            expected_file_sha256=file_sha256,
            expected_identity=identity,
        )
        final_executable_raw, _ = _read_stable_binary(
            executable,
            max_bytes=_MAX_INTERPRETER_BYTES,
            expected_identity=executable_identity,
        )
        if (
            not hmac.compare_digest(raw, final_raw)
            or not hmac.compare_digest(executable_raw, final_executable_raw)
            or completed.returncode != 0
        ):
            raise _invalid()
    except (
        OSError,
        SnapshotLaunchError,
        subprocess.SubprocessError,
    ):
        print("target-intake-validator-snapshot-launch-invalid", file=sys.stderr)
        return 1
    print(
        "target-intake-validator-snapshot-launch-ok "
        "production_acceptance=false child-exit=0 "
        f"snapshot_manifest_payload_sha256={payload_sha256} "
        f"snapshot_manifest_file_sha256={file_sha256} "
        f"launcher_interpreter_sha256={interpreter_sha256} "
        "recovery-snapshot-mutation=not-performed "
        "source-authority=unverified snapshot-atomicity=unverified"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--snapshot-output", required=True, type=Path)
    run = commands.add_parser("run")
    run.add_argument("--snapshot", required=True, type=Path)
    run.add_argument("--expected-snapshot-manifest-payload-sha256", required=True)
    run.add_argument("--expected-snapshot-manifest-file-sha256", required=True)
    run.add_argument("preflight_argv", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "prepare":
        return _prepare(arguments.snapshot_output)
    preflight_argv = list(arguments.preflight_argv)
    if preflight_argv and preflight_argv[0] == "--":
        preflight_argv.pop(0)
    return _run(
        arguments.snapshot,
        arguments.expected_snapshot_manifest_payload_sha256,
        arguments.expected_snapshot_manifest_file_sha256,
        preflight_argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
