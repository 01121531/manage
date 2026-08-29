"""Prepare and verify a repository-external target-intake source snapshot."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, BinaryIO

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    StableFileError,
    StableFileIdentity,
    has_link_or_reparse_ancestor,
    is_link_or_reparse,
    load_unique_json_with_bytes_and_metadata,
    open_stable_binary,
    read_stable_bytes_with_metadata,
    recheck_stable_bytes,
    stable_file_identity,
)
from scripts.target_intake_validator_contract import SOURCE_FILES


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILENAME = "target-intake-validator-source-snapshot.json"
SNAPSHOT_KIND = "target_intake_validator_source_snapshot_v1"
MANIFEST_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "source_authority",
    "snapshot_atomicity",
    "members",
    "integrity",
}
MEMBER_KEYS = {"path", "size", "sha256"}
INTEGRITY_KEYS = {"payload_sha256"}
REPOSITORY_INPUT_FILES = (
    "deploy/phase-acceptance-matrix.json",
    "deploy/target-intake-requirements.json",
    "deploy/decision-envelopes/card-pci.synthetic.json",
    "deploy/decision-envelopes/oidc-deployment-identity.synthetic.json",
    "deploy/decision-envelopes/phase0-boundary-approval.synthetic.json",
    "deploy/provider-contracts/mail.synthetic.json",
    "deploy/provider-contracts/sub2.synthetic.json",
    "deploy/evidence-index-envelopes/phase1-platform.synthetic.json",
    "deploy/evidence-index-envelopes/phase2-mail.synthetic.json",
    "deploy/evidence-index-envelopes/phase3-card.synthetic.json",
    "deploy/evidence-index-envelopes/phase5-windows.synthetic.json",
    "deploy/evidence-index-envelopes/phase6-pilot.synthetic.json",
    "deploy/evidence-index-envelopes/phase6-operations.synthetic.json",
    "deploy/evidence-index-envelopes/sub2-execution.synthetic.json",
    "deploy/evidence-index-envelopes/vault-egress.synthetic.json",
    "deploy/inventory-envelopes/target-platform.synthetic.json",
    "deploy/inventory-envelopes/windows-pilot-inputs.synthetic.json",
    "deploy/inventory-envelopes/phase6-pilot-inputs.synthetic.json",
    "docker-compose.yml",
    ".env.example",
    "infra/keycloak/email-platform-realm.json",
    "infra/vault/policies/email-platform-api-cards.hcl",
    "infra/vault/policies/email-platform-mail.hcl",
    "infra/vault/policies/email-platform-sub2.hcl",
    "infra/vault/configure-approles.sh",
    "infra/vault/configure-audit.sh",
)
SOURCE_MEMBERS = tuple(SOURCE_FILES) + REPOSITORY_INPUT_FILES

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MEMBER_BYTES = 5 * 1024 * 1024
_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


class SourceSnapshotError(ValueError):
    """The source snapshot cannot be prepared or accepted safely."""


@dataclass(frozen=True)
class SnapshotMember:
    path: str
    raw: bytes
    identity: StableFileIdentity


@dataclass(frozen=True)
class LoadedSourceSnapshot:
    directory: Path
    manifest: dict[str, Any]
    manifest_raw: bytes
    manifest_identity: StableFileIdentity
    members: tuple[SnapshotMember, ...]
    payload_sha256: str
    file_sha256: str


def _canonical_bytes(document: Any) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _payload_sha256(document: dict[str, Any]) -> str:
    payload = {key: value for key, value in document.items() if key != "integrity"}
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _closed_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def source_snapshot_manifest_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        return ["source snapshot manifest schema is invalid"]
    if (
        document.get("schema_version") != 1
        or document.get("kind") != SNAPSHOT_KIND
        or document.get("production_acceptance") is not False
        or document.get("source_authority") != "unverified"
        or document.get("snapshot_atomicity") != "unverified"
    ):
        return ["source snapshot manifest identity is invalid"]
    members = document.get("members")
    if (
        not isinstance(members, list)
        or len(members) != len(SOURCE_MEMBERS)
        or [item.get("path") if isinstance(item, dict) else None for item in members]
        != list(SOURCE_MEMBERS)
    ):
        return ["source snapshot member inventory is invalid"]
    if any(
        not isinstance(item, dict)
        or set(item) != MEMBER_KEYS
        or not _closed_relative_path(item.get("path"))
        or not isinstance(item.get("size"), int)
        or isinstance(item.get("size"), bool)
        or not 0 < item["size"] <= _MAX_MEMBER_BYTES
        or _SHA256.fullmatch(item.get("sha256", "")) is None
        for item in members
    ):
        return ["source snapshot member inventory is invalid"]
    integrity = document.get("integrity")
    if (
        not isinstance(integrity, dict)
        or set(integrity) != INTEGRITY_KEYS
        or _SHA256.fullmatch(integrity.get("payload_sha256", "")) is None
        or not hmac.compare_digest(
            integrity["payload_sha256"],
            _payload_sha256(document),
        )
    ):
        return ["source snapshot manifest integrity is invalid"]
    return []


def _require_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SourceSnapshotError("source snapshot caller binding is invalid")
    return value


def _is_within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(str(path)), os.path.normcase(str(parent)))
        ) == os.path.normcase(str(parent))
    except ValueError:
        return False


def _resolved_external_directory(
    path: Path,
    *,
    require_exists: bool,
    allow_module_root: bool = False,
) -> Path:
    try:
        resolved = path.resolve(strict=require_exists)
        repository = ROOT.resolve(strict=True)
    except OSError as error:
        raise SourceSnapshotError("source snapshot directory is invalid") from error
    within_repository = _is_within(resolved, repository)
    if (
        (within_repository and not (allow_module_root and resolved == repository))
        or has_link_or_reparse_ancestor(path)
    ):
        raise SourceSnapshotError("source snapshot directory is invalid")
    if require_exists:
        try:
            metadata = resolved.lstat()
        except OSError as error:
            raise SourceSnapshotError("source snapshot directory is invalid") from error
        if not stat.S_ISDIR(metadata.st_mode) or is_link_or_reparse(resolved):
            raise SourceSnapshotError("source snapshot directory is invalid")
    return resolved


def _is_read_only(metadata: os.stat_result) -> bool:
    return metadata.st_mode & _WRITE_BITS == 0


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short snapshot write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _set_read_only(path: Path) -> None:
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directories(root: Path, members: tuple[str, ...]) -> None:
    if os.name == "nt":
        return
    directories = {root}
    directories.update(
        root.joinpath(*PurePosixPath(member).parts).parent for member in members
    )
    for directory in sorted(
        directories,
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _capture_sources() -> tuple[tuple[str, bytes], ...]:
    if len(SOURCE_MEMBERS) != len(set(SOURCE_MEMBERS)) or any(
        not _closed_relative_path(path) for path in SOURCE_MEMBERS
    ):
        raise SourceSnapshotError("source snapshot inventory is invalid")
    captured: list[tuple[str, bytes]] = []
    opened: list[tuple[str, BinaryIO, os.stat_result]] = []
    try:
        with ExitStack() as stack:
            for relative_path in SOURCE_MEMBERS:
                stream, metadata = stack.enter_context(
                    open_stable_binary(
                        ROOT.joinpath(*PurePosixPath(relative_path).parts)
                    )
                )
                if (
                    metadata.st_nlink != 1
                    or metadata.st_size <= 0
                    or metadata.st_size > _MAX_MEMBER_BYTES
                ):
                    raise SourceSnapshotError("source snapshot member is invalid")
                opened.append((relative_path, stream, metadata))
            for relative_path, stream, metadata in opened:
                raw = stream.read(_MAX_MEMBER_BYTES + 1)
                if len(raw) != metadata.st_size:
                    raise SourceSnapshotError("source snapshot member is unstable")
                captured.append((relative_path, raw))
            for (_, stream, _), (_, original) in zip(opened, captured, strict=True):
                stream.seek(0)
                current = stream.read(_MAX_MEMBER_BYTES + 1)
                if not hmac.compare_digest(
                    hashlib.sha256(current).digest(),
                    hashlib.sha256(original).digest(),
                ):
                    raise SourceSnapshotError("source snapshot member is unstable")
    except (OSError, StableFileError) as error:
        raise SourceSnapshotError(
            "source snapshot source set is unavailable"
        ) from error
    return tuple(captured)


def _expected_directories() -> set[str]:
    directories: set[str] = set()
    for relative_path in SOURCE_MEMBERS:
        parent = PurePosixPath(relative_path).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return directories


def _tree_entries(root: Path) -> tuple[set[str], set[str]]:
    directories: set[str] = set()
    files: set[str] = set()

    def fail(error: OSError) -> None:
        raise error

    try:
        for current, child_directories, child_files in os.walk(
            root, topdown=True, followlinks=False, onerror=fail
        ):
            current_path = Path(current)
            if current_path != root and is_link_or_reparse(current_path):
                raise SourceSnapshotError("source snapshot tree is invalid")
            for name in child_directories:
                path = current_path / name
                if is_link_or_reparse(path):
                    raise SourceSnapshotError("source snapshot tree is invalid")
                directories.add(path.relative_to(root).as_posix())
            for name in child_files:
                path = current_path / name
                if is_link_or_reparse(path):
                    raise SourceSnapshotError("source snapshot tree is invalid")
                files.add(path.relative_to(root).as_posix())
    except OSError as error:
        raise SourceSnapshotError("source snapshot tree is invalid") from error
    return directories, files


def _require_exact_tree(root: Path) -> None:
    directories, files = _tree_entries(root)
    if directories != _expected_directories() or files != {
        *SOURCE_MEMBERS,
        MANIFEST_FILENAME,
    }:
        raise SourceSnapshotError("source snapshot tree is invalid")


def _remove_manifest(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


def prepare_source_snapshot(destination: Path) -> LoadedSourceSnapshot:
    """Copy one stable source set into a new repository-external directory."""

    destination = Path(destination)
    resolved = _resolved_external_directory(destination, require_exists=False)
    try:
        resolved.mkdir(parents=False, exist_ok=False)
    except OSError as error:
        raise SourceSnapshotError(
            "source snapshot destination must be absent"
        ) from error
    manifest_path = resolved / MANIFEST_FILENAME
    try:
        captured = _capture_sources()
        member_records: list[dict[str, Any]] = []
        for relative_path, raw in captured:
            output = resolved.joinpath(*PurePosixPath(relative_path).parts)
            _write_exclusive(output, raw)
            _set_read_only(output)
            member_records.append(
                {
                    "path": relative_path,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "kind": SNAPSHOT_KIND,
            "production_acceptance": False,
            "source_authority": "unverified",
            "snapshot_atomicity": "unverified",
            "members": member_records,
        }
        document = {
            **payload,
            "integrity": {
                "payload_sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest()
            },
        }
        if source_snapshot_manifest_errors(document):
            raise SourceSnapshotError("source snapshot manifest is invalid")
        manifest_raw = _canonical_bytes(document) + b"\n"
        manifest_file_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        _write_exclusive(manifest_path, manifest_raw)
        _set_read_only(manifest_path)
        _fsync_directories(resolved, SOURCE_MEMBERS + (MANIFEST_FILENAME,))
        loaded = load_source_snapshot(
            resolved,
            expected_payload_sha256=document["integrity"]["payload_sha256"],
            expected_file_sha256=manifest_file_sha256,
        )
        recheck_source_snapshot(loaded)
        return loaded
    except Exception as error:
        _remove_manifest(manifest_path)
        if isinstance(error, SourceSnapshotError):
            raise
        raise SourceSnapshotError("source snapshot preparation failed") from error


def load_source_snapshot(
    directory: Path,
    *,
    expected_payload_sha256: str,
    expected_file_sha256: str,
) -> LoadedSourceSnapshot:
    """Accept an exact snapshot only when both caller-supplied pins match."""

    payload_pin = _require_sha256(expected_payload_sha256)
    file_pin = _require_sha256(expected_file_sha256)
    root = _resolved_external_directory(
        Path(directory),
        require_exists=True,
        allow_module_root=True,
    )
    manifest_path = root / MANIFEST_FILENAME
    try:
        document, manifest_raw, manifest_metadata = (
            load_unique_json_with_bytes_and_metadata(
                manifest_path,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
        )
    except (OSError, StableFileError, UnicodeError, json.JSONDecodeError) as error:
        raise SourceSnapshotError("source snapshot manifest is invalid") from error
    if (
        manifest_metadata.st_nlink != 1
        or not _is_read_only(manifest_metadata)
        or not hmac.compare_digest(hashlib.sha256(manifest_raw).hexdigest(), file_pin)
        or source_snapshot_manifest_errors(document)
        or not hmac.compare_digest(
            document["integrity"]["payload_sha256"], payload_pin
        )
    ):
        raise SourceSnapshotError("source snapshot manifest is invalid")
    _require_exact_tree(root)
    members: list[SnapshotMember] = []
    try:
        for record in document["members"]:
            path = root.joinpath(*PurePosixPath(record["path"]).parts)
            raw, metadata = _read_member(path, record["size"])
            if (
                metadata.st_nlink != 1
                or not _is_read_only(metadata)
                or not hmac.compare_digest(
                    hashlib.sha256(raw).hexdigest(), record["sha256"]
                )
            ):
                raise SourceSnapshotError("source snapshot member is invalid")
            members.append(
                SnapshotMember(
                    path=record["path"],
                    raw=raw,
                    identity=stable_file_identity(metadata),
                )
            )
        for member in members:
            _recheck_member(root, member)
        recheck_stable_bytes(
            manifest_path,
            manifest_raw,
            manifest_metadata,
            max_bytes=MAX_INTAKE_JSON_BYTES,
            require_single_link=True,
        )
        _require_exact_tree(root)
    except (OSError, StableFileError) as error:
        raise SourceSnapshotError("source snapshot member is invalid") from error
    return LoadedSourceSnapshot(
        directory=root,
        manifest=document,
        manifest_raw=manifest_raw,
        manifest_identity=stable_file_identity(manifest_metadata),
        members=tuple(members),
        payload_sha256=payload_pin,
        file_sha256=file_pin,
    )


def _read_member(path: Path, expected_size: int) -> tuple[bytes, os.stat_result]:
    raw, metadata = read_stable_bytes_with_metadata(
        path,
        max_bytes=_MAX_MEMBER_BYTES,
    )
    if len(raw) != expected_size:
        raise SourceSnapshotError("source snapshot member is invalid")
    return raw, metadata


def _recheck_member(root: Path, member: SnapshotMember) -> None:
    path = root.joinpath(*PurePosixPath(member.path).parts)
    metadata = _identity_metadata(path, member.identity)
    recheck_stable_bytes(
        path,
        member.raw,
        metadata,
        max_bytes=_MAX_MEMBER_BYTES,
        require_single_link=True,
    )
    if not _is_read_only(path.stat()):
        raise SourceSnapshotError("source snapshot member is invalid")


def recheck_source_snapshot(snapshot: LoadedSourceSnapshot) -> None:
    """Fail unless the loaded locators still name the same identities and bytes."""

    if not isinstance(snapshot, LoadedSourceSnapshot):
        raise SourceSnapshotError("source snapshot recheck input is invalid")
    root = _resolved_external_directory(
        snapshot.directory,
        require_exists=True,
        allow_module_root=True,
    )
    _require_exact_tree(root)
    try:
        manifest_path = root / MANIFEST_FILENAME
        recheck_stable_bytes(
            manifest_path,
            snapshot.manifest_raw,
            _identity_metadata(manifest_path, snapshot.manifest_identity),
            max_bytes=MAX_INTAKE_JSON_BYTES,
            require_single_link=True,
        )
        if not _is_read_only(manifest_path.stat()):
            raise SourceSnapshotError("source snapshot manifest is invalid")
        for member in snapshot.members:
            _recheck_member(root, member)
        _require_exact_tree(root)
    except (OSError, StableFileError) as error:
        raise SourceSnapshotError("source snapshot recheck failed") from error


def _identity_metadata(path: Path, identity: StableFileIdentity) -> os.stat_result:
    metadata = path.stat()
    if stable_file_identity(metadata) != identity:
        raise SourceSnapshotError("source snapshot identity changed")
    return metadata
