"""Read-only inventory and human-approved cleanup for private secret residues."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from scripts import private_secret_materialization as materialization
from scripts.backup_output_policy import (
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import read_stable_bytes
from scripts.release_control_lock import ReleaseControlLocked, release_control_lock


_ERROR = "private secret residue operation failed"
_CLAIM_ID = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_CLAIM_KEYS = {
    "claim_id",
    "directory_identity",
    "integrity_sha256",
    "kind",
    "lease",
    "platform",
    "root_identity",
    "schema_version",
    "secret",
}
_EXPECTED_ENTRY_NAMES = {
    materialization._FILENAME,
    materialization._CLAIM_FILENAME,
    materialization._LEASE_FILENAME,
}
_INVENTORY_KIND = "email-platform-private-secret-residue-inventory"
_INVENTORY_MAX_BYTES = 64 * 1024
_UNKNOWN_REASONS = frozenset({"unexpected_entry", "verification_failed"})


class PrivateSecretResidueError(OSError):
    """Residue state could not be authenticated or safely changed."""


def _fail(error: BaseException | None = None) -> PrivateSecretResidueError:
    return PrivateSecretResidueError(_ERROR) if error is None else PrivateSecretResidueError(_ERROR)


def _root_path(runtime_root: Path | str | None) -> Path:
    if runtime_root is not None:
        root = Path(runtime_root)
        if not root.is_absolute():
            raise _fail()
        materialization._require_outside_repository(root)
        return root
    if os.name == "nt":
        return materialization._windows_runtime_root(
            materialization._current_windows_sid(), create=False
        )
    return materialization._posix_runtime_root(create=False)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _load_claim(raw: bytes, claim_id: str) -> dict[str, Any]:
    if not raw or len(raw) > materialization._CLAIM_MAX_BYTES:
        raise _fail()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise _fail(error) from error
    if not isinstance(value, dict) or set(value) != _EXPECTED_CLAIM_KEYS:
        raise _fail()
    integrity = value.get("integrity_sha256")
    unsigned = dict(value)
    unsigned.pop("integrity_sha256", None)
    if (
        value.get("schema_version") != 1
        or value.get("kind") != materialization._CLAIM_KIND
        or value.get("claim_id") != claim_id
        or value.get("platform") != ("windows" if os.name == "nt" else "posix")
        or not isinstance(integrity, str)
        or _SHA256.fullmatch(integrity) is None
        or not hmac.compare_digest(
            integrity, hashlib.sha256(materialization._canonical_json(unsigned)).hexdigest()
        )
        or not hmac.compare_digest(raw, materialization._canonical_json(value))
    ):
        raise _fail()
    secret = value.get("secret")
    lease = value.get("lease")
    if (
        not isinstance(secret, dict)
        or set(secret) != {"identity", "name", "size", "source_sha256"}
        or secret.get("name") != materialization._FILENAME
        or not isinstance(secret.get("size"), int)
        or secret["size"] < 1
        or not isinstance(secret.get("source_sha256"), str)
        or _SHA256.fullmatch(secret["source_sha256"]) is None
        or not isinstance(lease, dict)
        or set(lease) != {"identity", "name"}
        or lease.get("name") != materialization._LEASE_FILENAME
    ):
        raise _fail()
    return value


def _approval(
    claim_id: str,
    root_identity: dict[str, int | str],
    directory_identity: dict[str, int | str],
    claim_identity: dict[str, int | str],
    secret_identity: dict[str, int | str],
    lease_identity: dict[str, int | str],
    claim_bytes: bytes,
) -> str:
    value = {
        "claim_id": claim_id,
        "claim_identity": claim_identity,
        "claim_sha256": hashlib.sha256(claim_bytes).hexdigest(),
        "directory_identity": directory_identity,
        "lease_identity": lease_identity,
        "root_identity": root_identity,
        "secret_identity": secret_identity,
    }
    return hashlib.sha256(materialization._canonical_json(value)).hexdigest()


def _matches_identity(value: Any, actual: object) -> bool:
    return value == materialization._identity_object(actual)  # type: ignore[arg-type]


def _posix_file(fd: int, mode: int, *, size: int | None = None) -> os.stat_result:
    metadata = os.fstat(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or (size is not None and metadata.st_size != size)
    ):
        raise _fail()
    return metadata


def _open_posix_root(root: Path) -> tuple[int, os.stat_result]:
    materialization._validate_posix_base(root.parent)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(root, flags)
    metadata = os.fstat(fd)
    named = os.lstat(root)
    if (
        materialization._identity(metadata) != materialization._identity(named)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(fd)
        raise _fail()
    return fd, metadata


def _inspect_posix(root_fd: int, root_metadata: os.stat_result, claim_id: str) -> dict[str, str]:
    import fcntl

    directory_fd = claim_fd = secret_fd = lease_fd = -1
    lease_acquired = False
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_fd = os.open(claim_id, flags, dir_fd=root_fd)
        directory = os.fstat(directory_fd)
        named_directory = os.stat(claim_id, dir_fd=root_fd, follow_symlinks=False)
        if (
            materialization._identity(directory) != materialization._identity(named_directory)
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise _fail()
        if set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        claim_fd = os.open(materialization._CLAIM_FILENAME, read_flags, dir_fd=directory_fd)
        secret_fd = os.open(materialization._FILENAME, read_flags, dir_fd=directory_fd)
        lease_fd = os.open(materialization._LEASE_FILENAME, read_flags, dir_fd=directory_fd)
        claim_meta = _posix_file(claim_fd, 0o400)
        secret_meta = _posix_file(secret_fd, 0o400)
        lease_meta = _posix_file(lease_fd, 0o600, size=0)
        claim_bytes = materialization._read_all_posix(
            claim_fd, materialization._CLAIM_MAX_BYTES
        )
        claim = _load_claim(claim_bytes, claim_id)
        if (
            not _matches_identity(claim["root_identity"], materialization._identity(root_metadata))
            or not _matches_identity(claim["directory_identity"], materialization._identity(directory))
            or not _matches_identity(claim["secret"]["identity"], materialization._identity(secret_meta))
            or not _matches_identity(claim["lease"]["identity"], materialization._identity(lease_meta))
            or secret_meta.st_size != claim["secret"]["size"]
            or not hmac.compare_digest(
                materialization._read_hash_posix(secret_fd), claim["secret"]["source_sha256"]
            )
        ):
            raise _fail()
        if set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lease_acquired = True
            state = "cleanup_candidate"
        except BlockingIOError:
            state = "active"
        result = {"claim_id": claim_id, "state": state}
        if lease_acquired:
            result["approval_sha256"] = _approval(
                claim_id,
                materialization._identity_object(materialization._identity(root_metadata)),
                materialization._identity_object(materialization._identity(directory)),
                materialization._identity_object(materialization._identity(claim_meta)),
                materialization._identity_object(materialization._identity(secret_meta)),
                materialization._identity_object(materialization._identity(lease_meta)),
                claim_bytes,
            )
        return result
    finally:
        if lease_acquired and lease_fd >= 0:
            try:
                fcntl.flock(lease_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        for fd in (lease_fd, secret_fd, claim_fd, directory_fd):
            if fd >= 0:
                os.close(fd)


def _inventory_posix(root: Path) -> list[dict[str, str | None]]:
    root_fd, root_metadata = _open_posix_root(root)
    try:
        records: list[dict[str, str | None]] = []
        for name in sorted(os.listdir(root_fd)):
            if _CLAIM_ID.fullmatch(name) is None:
                records.append({"claim_id": None, "state": "unknown", "reason": "unexpected_entry"})
                continue
            try:
                records.append(_inspect_posix(root_fd, root_metadata, name))
            except (OSError, ValueError):
                records.append({"claim_id": None, "state": "unknown", "reason": "verification_failed"})
        return records
    finally:
        os.close(root_fd)


def _cleanup_posix(root: Path, claim_id: str, confirmation: str) -> None:
    import fcntl

    root_fd, root_metadata = _open_posix_root(root)
    directory_fd = claim_fd = secret_fd = lease_fd = -1
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_fd = os.open(claim_id, flags, dir_fd=root_fd)
        directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
            or materialization._identity(
                os.stat(claim_id, dir_fd=root_fd, follow_symlinks=False)
            ) != materialization._identity(directory)
        ):
            raise _fail()
        if set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        lease_fd = os.open(materialization._LEASE_FILENAME, read_flags, dir_fd=directory_fd)
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise _fail(error) from error
        claim_fd = os.open(materialization._CLAIM_FILENAME, read_flags, dir_fd=directory_fd)
        secret_fd = os.open(materialization._FILENAME, read_flags, dir_fd=directory_fd)
        claim_meta = _posix_file(claim_fd, 0o400)
        secret_meta = _posix_file(secret_fd, 0o400)
        lease_meta = _posix_file(lease_fd, 0o600, size=0)
        claim_bytes = materialization._read_all_posix(claim_fd, materialization._CLAIM_MAX_BYTES)
        claim = _load_claim(claim_bytes, claim_id)
        identities_ok = (
            _matches_identity(claim["root_identity"], materialization._identity(root_metadata))
            and _matches_identity(claim["directory_identity"], materialization._identity(directory))
            and _matches_identity(claim["secret"]["identity"], materialization._identity(secret_meta))
            and _matches_identity(claim["lease"]["identity"], materialization._identity(lease_meta))
            and secret_meta.st_size == claim["secret"]["size"]
            and hmac.compare_digest(
                materialization._read_hash_posix(secret_fd), claim["secret"]["source_sha256"]
            )
        )
        approval = _approval(
            claim_id,
            materialization._identity_object(materialization._identity(root_metadata)),
            materialization._identity_object(materialization._identity(directory)),
            materialization._identity_object(materialization._identity(claim_meta)),
            materialization._identity_object(materialization._identity(secret_meta)),
            materialization._identity_object(materialization._identity(lease_meta)),
            claim_bytes,
        )
        if not identities_ok or not hmac.compare_digest(approval, confirmation):
            raise _fail()
        if set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        for name, metadata in (
            (materialization._FILENAME, secret_meta),
            (materialization._CLAIM_FILENAME, claim_meta),
            (materialization._LEASE_FILENAME, lease_meta),
        ):
            if materialization._identity(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            ) != materialization._identity(metadata):
                raise _fail()
        os.unlink(materialization._FILENAME, dir_fd=directory_fd)
        os.unlink(materialization._CLAIM_FILENAME, dir_fd=directory_fd)
        os.unlink(materialization._LEASE_FILENAME, dir_fd=directory_fd)
        os.fsync(directory_fd)
        for fd in (secret_fd, claim_fd, lease_fd, directory_fd):
            os.close(fd)
        secret_fd = claim_fd = lease_fd = directory_fd = -1
        if materialization._identity(
            os.stat(claim_id, dir_fd=root_fd, follow_symlinks=False)
        ) != materialization._identity(directory):
            raise _fail()
        os.rmdir(claim_id, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        for fd in (secret_fd, claim_fd, lease_fd, directory_fd, root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _open_windows_root(root: Path) -> tuple[int, object, str]:
    current_sid = materialization._current_windows_sid()
    materialization._validate_windows_base(root.parent)
    handle = materialization._win_open(
        root,
        materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES,
        materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
        materialization._OPEN_EXISTING,
        materialization._FILE_FLAG_BACKUP_SEMANTICS | materialization._FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        materialization._win_acl(handle, current_sid)
        identity = materialization._win_identity(handle, directory=True)
        return handle, identity, current_sid
    except BaseException:
        materialization._close_handle(handle)
        raise


def _windows_file(
    path: Path,
    current_sid: str,
    *,
    read_only: bool,
    share: int | None = None,
    mutable: bool = False,
) -> tuple[int, object, int]:
    access = materialization._GENERIC_READ | materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES
    if mutable:
        access |= materialization._FILE_WRITE_ATTRIBUTES | materialization._DELETE
    handle = materialization._win_open(
        path,
        access,
        materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE if share is None else share,
        materialization._OPEN_EXISTING,
        materialization._FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        identity, size = _validate_windows_file_handle(
            handle, current_sid, read_only=read_only
        )
        return handle, identity, size
    except BaseException:
        materialization._close_handle(handle)
        raise


def _validate_windows_file_handle(
    handle: int,
    current_sid: str,
    *,
    read_only: bool,
) -> tuple[object, int]:
    materialization._win_acl(handle, current_sid)
    identity = materialization._win_identity(
        handle, directory=False, read_only=read_only
    )
    size = materialization._win_info(
        handle,
        materialization._FILE_STANDARD_INFO_CLASS,
        materialization._FILE_STANDARD_INFO(),
    ).EndOfFile
    return identity, size


def _inspect_windows(root: Path, root_identity: object, current_sid: str, claim_id: str) -> dict[str, str]:
    directory_handle = claim_handle = secret_handle = lease_handle = None
    lease_acquired = False
    directory_path = root / claim_id
    try:
        directory_handle = materialization._win_open(
            directory_path,
            materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES,
            materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
            materialization._OPEN_EXISTING,
            materialization._FILE_FLAG_BACKUP_SEMANTICS | materialization._FILE_FLAG_OPEN_REPARSE_POINT,
        )
        materialization._win_acl(directory_handle, current_sid)
        directory_identity = materialization._win_identity(directory_handle, directory=True)
        if {entry.name for entry in directory_path.iterdir()} != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        claim_handle, claim_identity, claim_size = _windows_file(
            directory_path / materialization._CLAIM_FILENAME, current_sid, read_only=True
        )
        if claim_size > materialization._CLAIM_MAX_BYTES:
            raise _fail()
        secret_handle, secret_identity, secret_size = _windows_file(
            directory_path / materialization._FILENAME, current_sid, read_only=True
        )
        lease_path = directory_path / materialization._LEASE_FILENAME
        lease_access = (
            materialization._GENERIC_READ
            | materialization._READ_CONTROL
            | materialization._FILE_READ_ATTRIBUTES
        )
        try:
            # The active classification is sourced only from this exact
            # CreateFile call.  Later ACL/identity failures stay failures.
            lease_handle = materialization._win_open(
                lease_path,
                lease_access,
                0,
                materialization._OPEN_EXISTING,
                materialization._FILE_FLAG_OPEN_REPARSE_POINT,
            )
            lease_acquired = True
        except materialization.PrivateSecretMaterializationError as error:
            if error.winerror_code not in {32, 33}:
                raise
            lease_handle = materialization._win_open(
                lease_path,
                lease_access,
                materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
                materialization._OPEN_EXISTING,
                materialization._FILE_FLAG_OPEN_REPARSE_POINT,
            )
        try:
            lease_identity, lease_size = _validate_windows_file_handle(
                lease_handle, current_sid, read_only=False
            )
        except BaseException:
            materialization._close_handle(lease_handle)
            lease_handle = None
            raise
        if lease_size != 0:
            raise _fail()
        claim_bytes = materialization._read_all_windows(
            claim_handle, materialization._CLAIM_MAX_BYTES
        )
        claim = _load_claim(claim_bytes, claim_id)
        if (
            not _matches_identity(claim["root_identity"], root_identity)
            or not _matches_identity(claim["directory_identity"], directory_identity)
            or not _matches_identity(claim["secret"]["identity"], secret_identity)
            or not _matches_identity(claim["lease"]["identity"], lease_identity)
            or secret_size != claim["secret"]["size"]
            or not hmac.compare_digest(
                materialization._hash_windows(secret_handle), claim["secret"]["source_sha256"]
            )
        ):
            raise _fail()
        state = "cleanup_candidate" if lease_acquired else "active"
        result = {"claim_id": claim_id, "state": state}
        if lease_acquired:
            result["approval_sha256"] = _approval(
                claim_id,
                materialization._identity_object(root_identity),
                materialization._identity_object(directory_identity),
                materialization._identity_object(claim_identity),
                materialization._identity_object(secret_identity),
                materialization._identity_object(lease_identity),
                claim_bytes,
            )
        return result
    finally:
        for handle in (lease_handle, secret_handle, claim_handle, directory_handle):
            materialization._close_handle(handle)


def _inventory_windows(root: Path) -> list[dict[str, str | None]]:
    root_handle, root_identity, current_sid = _open_windows_root(root)
    try:
        records: list[dict[str, str | None]] = []
        for entry in sorted(root.iterdir(), key=lambda value: value.name):
            name = entry.name
            if _CLAIM_ID.fullmatch(name) is None:
                records.append({"claim_id": None, "state": "unknown", "reason": "unexpected_entry"})
                continue
            try:
                records.append(_inspect_windows(root, root_identity, current_sid, name))
            except (OSError, ValueError):
                records.append({"claim_id": None, "state": "unknown", "reason": "verification_failed"})
        return records
    finally:
        materialization._close_handle(root_handle)


def _cleanup_windows(root: Path, claim_id: str, confirmation: str) -> None:
    root_handle, root_identity, current_sid = _open_windows_root(root)
    directory_handle = claim_handle = secret_handle = lease_handle = None
    directory_path = root / claim_id
    failure: BaseException | None = None
    try:
        directory_handle = materialization._win_open(
            directory_path,
            materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES | materialization._DELETE,
            materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
            materialization._OPEN_EXISTING,
            materialization._FILE_FLAG_BACKUP_SEMANTICS | materialization._FILE_FLAG_OPEN_REPARSE_POINT,
        )
        materialization._win_acl(directory_handle, current_sid)
        directory_identity = materialization._win_identity(directory_handle, directory=True)
        if {entry.name for entry in directory_path.iterdir()} != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        lease_handle, lease_identity, lease_size = _windows_file(
            directory_path / materialization._LEASE_FILENAME,
            current_sid,
            read_only=False,
            share=0,
            mutable=True,
        )
        claim_handle, claim_identity, claim_size = _windows_file(
            directory_path / materialization._CLAIM_FILENAME,
            current_sid,
            read_only=True,
            mutable=True,
        )
        secret_handle, secret_identity, secret_size = _windows_file(
            directory_path / materialization._FILENAME,
            current_sid,
            read_only=True,
            mutable=True,
        )
        if lease_size != 0 or claim_size > materialization._CLAIM_MAX_BYTES:
            raise _fail()
        claim_bytes = materialization._read_all_windows(claim_handle, materialization._CLAIM_MAX_BYTES)
        claim = _load_claim(claim_bytes, claim_id)
        valid = (
            _matches_identity(claim["root_identity"], root_identity)
            and _matches_identity(claim["directory_identity"], directory_identity)
            and _matches_identity(claim["secret"]["identity"], secret_identity)
            and _matches_identity(claim["lease"]["identity"], lease_identity)
            and secret_size == claim["secret"]["size"]
            and hmac.compare_digest(
                materialization._hash_windows(secret_handle), claim["secret"]["source_sha256"]
            )
        )
        approval = _approval(
            claim_id,
            materialization._identity_object(root_identity),
            materialization._identity_object(directory_identity),
            materialization._identity_object(claim_identity),
            materialization._identity_object(secret_identity),
            materialization._identity_object(lease_identity),
            claim_bytes,
        )
        if not valid or not hmac.compare_digest(approval, confirmation):
            raise _fail()
        if {entry.name for entry in directory_path.iterdir()} != _EXPECTED_ENTRY_NAMES:
            raise _fail()
        materialization._set_windows_read_only(secret_handle, False)
        materialization._set_windows_read_only(claim_handle, False)
        for handle in (secret_handle, claim_handle, lease_handle):
            materialization._mark_windows_delete(handle)
        if not materialization._close_handle(secret_handle):
            raise _fail()
        secret_handle = None
        if not materialization._close_handle(claim_handle):
            raise _fail()
        claim_handle = None
        if not materialization._close_handle(lease_handle):
            raise _fail()
        lease_handle = None
        materialization._mark_windows_delete(directory_handle)
        if not materialization._close_handle(directory_handle):
            raise _fail()
        directory_handle = None
        if directory_path.exists():
            raise _fail()
    except BaseException as error:
        failure = error
    finally:
        for handle in (lease_handle, secret_handle, claim_handle, directory_handle, root_handle):
            if not materialization._close_handle(handle) and failure is None:
                failure = _fail()
    if failure is not None:
        raise failure


def _canonical_inventory_records(
    records: Any,
) -> list[dict[str, str | None]]:
    if not isinstance(records, list):
        raise _fail()
    normalized: list[dict[str, str | None]] = []
    seen_claim_ids: set[str] = set()
    seen_records: set[bytes] = set()
    for record in records:
        if not isinstance(record, dict):
            raise _fail()
        state = record.get("state")
        claim_id = record.get("claim_id")
        if state == "active":
            valid = (
                set(record) == {"claim_id", "state"}
                and isinstance(claim_id, str)
                and _CLAIM_ID.fullmatch(claim_id) is not None
            )
        elif state == "cleanup_candidate":
            approval = record.get("approval_sha256")
            valid = (
                set(record) == {"approval_sha256", "claim_id", "state"}
                and isinstance(claim_id, str)
                and _CLAIM_ID.fullmatch(claim_id) is not None
                and isinstance(approval, str)
                and _SHA256.fullmatch(approval) is not None
            )
        elif state == "unknown":
            valid = (
                set(record) == {"claim_id", "reason", "state"}
                and claim_id is None
                and isinstance(record.get("reason"), str)
                and record["reason"] in _UNKNOWN_REASONS
            )
        else:
            valid = False
        if not valid:
            raise _fail()
        if isinstance(claim_id, str):
            if claim_id in seen_claim_ids:
                raise _fail()
            seen_claim_ids.add(claim_id)
        encoded = materialization._canonical_json(record)
        if encoded in seen_records:
            raise _fail()
        seen_records.add(encoded)
        normalized.append(record)
    return sorted(normalized, key=materialization._canonical_json)


def _inventory_document(records: list[dict[str, str | None]]) -> tuple[bytes, str]:
    payload: dict[str, Any] = {
        "kind": _INVENTORY_KIND,
        "records": _canonical_inventory_records(records),
        "schema_version": 1,
    }
    payload_sha256 = hashlib.sha256(materialization._canonical_json(payload)).hexdigest()
    payload["payload_sha256"] = payload_sha256
    encoded = materialization._canonical_json(payload)
    if len(encoded) > _INVENTORY_MAX_BYTES:
        raise _fail()
    return encoded, payload_sha256


def _open_output_parent(path: Path) -> tuple[int, object]:
    if os.name == "nt":
        handle = materialization._win_open(
            path.parent,
            materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES,
            materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
            materialization._OPEN_EXISTING,
            materialization._FILE_FLAG_BACKUP_SEMANTICS
            | materialization._FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            return handle, materialization._win_identity(handle, directory=True)
        except BaseException:
            materialization._close_handle(handle)
            raise
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path.parent, flags)
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(path.parent)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or materialization._identity(opened) != materialization._identity(named)
        ):
            raise _fail()
        return descriptor, materialization._identity(opened)
    except BaseException:
        os.close(descriptor)
        raise


def _verify_output_parent(path: Path, handle: int, identity: object) -> None:
    if os.name == "nt":
        named = materialization._win_open(
            path.parent,
            materialization._READ_CONTROL | materialization._FILE_READ_ATTRIBUTES,
            materialization._FILE_SHARE_READ | materialization._FILE_SHARE_WRITE,
            materialization._OPEN_EXISTING,
            materialization._FILE_FLAG_BACKUP_SEMANTICS
            | materialization._FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            if (
                materialization._win_identity(handle, directory=True) != identity
                or materialization._win_identity(named, directory=True) != identity
            ):
                raise _fail()
        finally:
            if not materialization._close_handle(named):
                raise _fail()
        return
    opened = os.fstat(handle)
    # Flush the held directory even if the name is concurrently rebound; the
    # write-once commit, if reached, belongs to this exact object.
    os.fsync(handle)
    named = os.lstat(path.parent)
    if (
        materialization._identity(opened) != identity
        or materialization._identity(named) != identity
    ):
        raise _fail()


def _write_once(path_value: Path | str, raw: bytes) -> None:
    path = Path(path_value)
    if not path.is_absolute() or not path.parent.is_dir():
        raise _fail()
    materialization._require_outside_repository(path)
    # The shared publisher owns its os.O_EXCL claim and the temporary-file
    # os.fsync(descriptor); this wrapper binds and syncs the parent as well.
    parent_handle, parent_identity = _open_output_parent(path)
    temporary: Path | None = None
    failure: BaseException | None = None
    try:
        destination = prepare_write_once_file(path)
        temporary = write_fsynced_temporary_bytes(destination, raw)
        try:
            publish_write_once_file(temporary, destination)
        finally:
            discard_claimed_temporary_file(temporary)
            temporary = None
        _verify_output_parent(path, parent_handle, parent_identity)
        if not hmac.compare_digest(
            read_stable_bytes(path, max_bytes=_INVENTORY_MAX_BYTES), raw
        ):
            raise _fail()
        _verify_output_parent(path, parent_handle, parent_identity)
    except BaseException as error:
        failure = error
    finally:
        discard_claimed_temporary_file(temporary)
        try:
            _verify_output_parent(path, parent_handle, parent_identity)
        except BaseException as error:
            if failure is None:
                failure = error
        if os.name == "nt":
            if not materialization._close_handle(parent_handle) and failure is None:
                failure = _fail()
        else:
            try:
                os.close(parent_handle)
            except OSError as error:
                if failure is None:
                    failure = error
    if failure is not None:
        raise failure


def _require_output_outside_runtime_root(path_value: Path | str, root: Path) -> None:
    path = Path(path_value)
    if not path.is_absolute():
        raise _fail()
    try:
        path.parent.resolve(strict=True).relative_to(root.resolve(strict=True))
    except ValueError:
        return
    raise _fail()


def _read_inventory(path_value: Path | str, expected_payload_sha256: str) -> dict[str, Any]:
    path = Path(path_value)
    if (
        not path.is_absolute()
        or not isinstance(expected_payload_sha256, str)
        or _SHA256.fullmatch(expected_payload_sha256) is None
    ):
        raise _fail()
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > _INVENTORY_MAX_BYTES
    ):
        raise _fail()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, _INVENTORY_MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _INVENTORY_MAX_BYTES:
                raise _fail()
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size)
    if identity(before) != identity(opened) or identity(opened) != identity(final) or identity(final) != identity(after):
        raise _fail()
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise _fail(error) from error
    if not isinstance(value, dict) or set(value) != {"kind", "payload_sha256", "records", "schema_version"}:
        raise _fail()
    claimed_sha256 = value.get("payload_sha256")
    unsigned = dict(value)
    unsigned.pop("payload_sha256", None)
    calculated = hashlib.sha256(materialization._canonical_json(unsigned)).hexdigest()
    if (
        value.get("kind") != _INVENTORY_KIND
        or value.get("schema_version") != 1
        or not isinstance(claimed_sha256, str)
        or _SHA256.fullmatch(claimed_sha256) is None
        or not hmac.compare_digest(claimed_sha256, calculated)
        or not hmac.compare_digest(claimed_sha256, expected_payload_sha256)
        or not hmac.compare_digest(raw, materialization._canonical_json(value))
    ):
        raise _fail()
    canonical_records = _canonical_inventory_records(value.get("records"))
    if value["records"] != canonical_records:
        raise _fail()
    return value


def inventory_private_secret_residues(
    runtime_root: Path | str | None = None,
) -> list[dict[str, str | None]]:
    """Return redacted, read-only residue classifications."""

    try:
        root = _root_path(runtime_root)
        with release_control_lock():
            return _inventory_windows(root) if os.name == "nt" else _inventory_posix(root)
    except PrivateSecretResidueError:
        raise
    except (OSError, ReleaseControlLocked, ValueError, TypeError) as error:
        raise _fail(error) from error


def capture_private_secret_residue_inventory(
    output: Path | str,
    runtime_root: Path | str | None = None,
) -> str:
    """Capture one redacted live inventory in a newly claimed output file."""

    try:
        root = _root_path(runtime_root)
        with release_control_lock():
            records = _inventory_windows(root) if os.name == "nt" else _inventory_posix(root)
            raw, payload_sha256 = _inventory_document(records)
            _require_output_outside_runtime_root(output, root)
            _write_once(output, raw)
            verified = _read_inventory(output, payload_sha256)
            if not hmac.compare_digest(
                materialization._canonical_json(verified), raw
            ):
                raise _fail()
            return payload_sha256
    except PrivateSecretResidueError:
        raise
    except (OSError, ReleaseControlLocked, ValueError, TypeError) as error:
        raise _fail(error) from error


def _cleanup_private_secret_residue(
    claim_id: str,
    confirmation_sha256: str,
    runtime_root: Path | str | None = None,
) -> None:
    """Delete exactly one fully reauthenticated, operator-approved residue."""

    if (
        not isinstance(claim_id, str)
        or _CLAIM_ID.fullmatch(claim_id) is None
        or not isinstance(confirmation_sha256, str)
        or _SHA256.fullmatch(confirmation_sha256) is None
    ):
        raise _fail()
    try:
        root = _root_path(runtime_root)
        with release_control_lock():
            if os.name == "nt":
                _cleanup_windows(root, claim_id, confirmation_sha256)
            else:
                _cleanup_posix(root, claim_id, confirmation_sha256)
    except PrivateSecretResidueError:
        raise
    except (OSError, ReleaseControlLocked, ValueError, TypeError) as error:
        raise _fail(error) from error


def cleanup_private_secret_residue_from_inventory(
    inventory: Path | str,
    expected_payload_sha256: str,
    claim_id: str,
    runtime_root: Path | str | None = None,
) -> None:
    """Clean one claim only when a stable inventory artifact authorizes it."""

    if not isinstance(claim_id, str) or _CLAIM_ID.fullmatch(claim_id) is None:
        raise _fail()
    try:
        root = _root_path(runtime_root)
        with release_control_lock():
            inventory_path = Path(inventory)
            if not inventory_path.is_absolute():
                raise _fail()
            materialization._require_outside_repository(inventory_path)
            _require_output_outside_runtime_root(inventory_path, root)
            document = _read_inventory(inventory, expected_payload_sha256)
            matches = [
                record
                for record in document["records"]
                if record.get("claim_id") == claim_id
            ]
            if len(matches) != 1 or matches[0].get("state") != "cleanup_candidate":
                raise _fail()
            approval = matches[0].get("approval_sha256")
            if not isinstance(approval, str) or _SHA256.fullmatch(approval) is None:
                raise _fail()
            if os.name == "nt":
                _cleanup_windows(root, claim_id, approval)
            else:
                _cleanup_posix(root, claim_id, approval)
    except PrivateSecretResidueError:
        raise
    except (OSError, ReleaseControlLocked, ValueError, TypeError) as error:
        raise _fail(error) from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or clean one private secret residue.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("--runtime-root", type=Path)
    inventory.add_argument("--output", required=True, type=Path)
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--runtime-root", type=Path)
    cleanup.add_argument("--inventory", required=True, type=Path)
    cleanup.add_argument("--expected-payload-sha256", required=True)
    cleanup.add_argument("--claim-id", required=True)
    cleanup.add_argument("--confirm-residue-cleanup", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "inventory":
            payload_sha256 = capture_private_secret_residue_inventory(
                args.output, args.runtime_root
            )
            print(f"private-secret-residue-inventory-sha256={payload_sha256}")
        else:
            if not args.confirm_residue_cleanup:
                raise _fail()
            cleanup_private_secret_residue_from_inventory(
                args.inventory,
                args.expected_payload_sha256,
                args.claim_id,
                args.runtime_root,
            )
            print("private-secret-residue-cleanup-ok")
        return 0
    except PrivateSecretResidueError:
        print(_ERROR, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
