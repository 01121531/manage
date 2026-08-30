"""Private, identity-bound temporary materialization for secret bytes.

Normal cleanup is deterministic.  An uncatchable process or host failure can
leave a strictly permissioned residue; this module does not claim crash cleanup.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^[0-9a-f]{32}$")
_ERROR = "private secret materialization failed"
_FILENAME = "secret"
_CLAIM_FILENAME = "claim.json"
_LEASE_FILENAME = "lease"
_RUNTIME_ROOT_ENV = "EMAIL_PLATFORM_PRIVATE_SECRET_RUNTIME_ROOT"
_RUNTIME_ROOT_NAME = "email-platform-private-secret-runtime"
_CLAIM_KIND = "email-platform-private-secret-residue"
_CLAIM_MAX_BYTES = 4096
_RETRIES = 16
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PrivateSecretMaterializationError(OSError):
    """A private temporary object could not be created or authenticated."""

    def __init__(self, message: str = _ERROR, *, winerror_code: int | None = None) -> None:
        super().__init__(message)
        self.winerror_code = winerror_code


def _require_outside_repository(path: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(_REPOSITORY_ROOT.resolve(strict=True))
    except ValueError:
        return
    raise PrivateSecretMaterializationError(_ERROR)


@dataclass(frozen=True)
class _PosixIdentity:
    device: int
    inode: int


@dataclass
class _PosixState:
    root_fd: int
    directory_fd: int
    file_fd: int
    claim_fd: int
    lease_fd: int
    root_path: Path
    directory_name: str
    file_path: Path
    root_identity: _PosixIdentity
    directory_identity: _PosixIdentity
    file_identity: _PosixIdentity
    claim_identity: _PosixIdentity
    lease_identity: _PosixIdentity
    claim_bytes: bytes


@dataclass(frozen=True)
class _WindowsIdentity:
    volume: int
    file_id: bytes


@dataclass
class _WindowsState:
    root_handle: int
    directory_handle: int
    file_handle: int
    claim_handle: int
    lease_handle: int
    root_identity: _WindowsIdentity
    directory_identity: _WindowsIdentity
    file_identity: _WindowsIdentity
    claim_identity: _WindowsIdentity
    lease_identity: _WindowsIdentity
    claim_bytes: bytes
    current_sid: str
    directory_path: Path
    file_path: Path


class MaterializedPrivateSecret:
    """One active private materialization and its reviewed source digest."""

    def __init__(self, path: Path | str, source_sha256: str) -> None:
        self._path = Path(path)
        self._source_sha256 = source_sha256
        self._state: _PosixState | _WindowsState | None = None
        self._closed = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def source_sha256(self) -> str:
        return self._source_sha256

    def verify(self) -> None:
        if self._closed or self._state is None:
            raise PrivateSecretMaterializationError(_ERROR)
        try:
            if os.name == "nt":
                _verify_windows(self.path, self.source_sha256, self._state)
            else:
                _verify_posix(self.path, self.source_sha256, self._state)
        except PrivateSecretMaterializationError:
            raise
        except Exception as error:
            raise PrivateSecretMaterializationError(_ERROR) from error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        state, self._state = self._state, None
        if state is None:
            return
        try:
            if os.name == "nt":
                _close_windows(self.path, self.source_sha256, state)
            else:
                _close_posix(self.path, self.source_sha256, state)
        except PrivateSecretMaterializationError:
            raise
        except Exception as error:
            raise PrivateSecretMaterializationError(_ERROR) from error

    def __enter__(self) -> "MaterializedPrivateSecret":
        self.verify()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            self.close()
        except PrivateSecretMaterializationError:
            if exc_type is None:
                raise
            if exc_value is not None and hasattr(exc_value, "add_note"):
                exc_value.add_note("private secret cleanup was not confirmed")
        return False


def materialize_private_secret_bytes(
    raw: bytes,
    expected_sha256: str,
) -> MaterializedPrivateSecret:
    """Create one private read-only materialization of reviewed bytes."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or not isinstance(expected_sha256, str)
        or _SHA256.fullmatch(expected_sha256) is None
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise PrivateSecretMaterializationError(_ERROR)
    result: MaterializedPrivateSecret | None = None
    try:
        result = _materialize_windows(raw, expected_sha256) if os.name == "nt" else _materialize_posix(raw, expected_sha256)
        result.verify()
        return result
    except BaseException as error:
        if result is not None:
            try:
                result.close()
            except BaseException:
                if hasattr(error, "add_note"):
                    error.add_note("private secret cleanup was not confirmed")
        if isinstance(
            error,
            (PrivateSecretMaterializationError, KeyboardInterrupt, SystemExit),
        ):
            raise
        raise PrivateSecretMaterializationError(_ERROR) from error


def _identity(metadata: os.stat_result) -> _PosixIdentity:
    return _PosixIdentity(metadata.st_dev, metadata.st_ino)


def _identity_object(value: _PosixIdentity | _WindowsIdentity) -> dict[str, int | str]:
    if isinstance(value, _PosixIdentity):
        return {"device": value.device, "inode": value.inode}
    return {"volume": value.volume, "file_id": value.file_id.hex()}


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _claim_bytes(
    *,
    claim_id: str,
    source_sha256: str,
    size: int,
    root_identity: _PosixIdentity | _WindowsIdentity,
    directory_identity: _PosixIdentity | _WindowsIdentity,
    file_identity: _PosixIdentity | _WindowsIdentity,
    lease_identity: _PosixIdentity | _WindowsIdentity,
) -> bytes:
    payload: dict[str, Any] = {
        "claim_id": claim_id,
        "directory_identity": _identity_object(directory_identity),
        "kind": _CLAIM_KIND,
        "lease": {
            "identity": _identity_object(lease_identity),
            "name": _LEASE_FILENAME,
        },
        "platform": "windows" if os.name == "nt" else "posix",
        "root_identity": _identity_object(root_identity),
        "schema_version": 1,
        "secret": {
            "identity": _identity_object(file_identity),
            "name": _FILENAME,
            "size": size,
            "source_sha256": source_sha256,
        },
    }
    payload["integrity_sha256"] = hashlib.sha256(_canonical_json(payload)).hexdigest()
    encoded = _canonical_json(payload)
    if len(encoded) > _CLAIM_MAX_BYTES:
        raise PrivateSecretMaterializationError(_ERROR)
    return encoded


def _runtime_root_override() -> Path | None:
    value = os.environ.get(_RUNTIME_ROOT_ENV)
    if value is None:
        return None
    root = Path(value)
    if not root.is_absolute():
        raise PrivateSecretMaterializationError(_ERROR)
    _require_outside_repository(root)
    return root


def _validate_posix_base(root: Path) -> Path:
    if not root.is_absolute():
        raise PrivateSecretMaterializationError(_ERROR)
    _require_outside_repository(root)
    current = root
    while True:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise PrivateSecretMaterializationError(_ERROR)
        if current.parent == current:
            break
        current = current.parent
    metadata = os.lstat(root)
    mode = stat.S_IMODE(metadata.st_mode)
    owned_private = metadata.st_uid == os.geteuid() and mode & 0o022 == 0
    root_sticky = metadata.st_uid == 0 and mode & 0o1777 == 0o1777
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not (owned_private or root_sticky)
    ):
        raise PrivateSecretMaterializationError(_ERROR)
    return root


def _posix_temp_root() -> Path:
    return _validate_posix_base(Path(os.environ.get("TMPDIR", "/tmp")))


def _posix_runtime_root(*, create: bool = True) -> Path:
    override = _runtime_root_override()
    root = override or (_posix_temp_root() / f"{_RUNTIME_ROOT_NAME}-{os.geteuid()}")
    parent = _validate_posix_base(root.parent)
    parent_fd = -1
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent_fd = os.open(parent, flags)
        if _identity(os.fstat(parent_fd)) != _identity(os.lstat(parent)):
            raise PrivateSecretMaterializationError(_ERROR)
        if create:
            try:
                os.mkdir(root.name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
        root_fd = os.open(root.name, flags, dir_fd=parent_fd)
        try:
            metadata = os.fstat(root_fd)
            named = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _identity(metadata) != _identity(named)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PrivateSecretMaterializationError(_ERROR)
        finally:
            os.close(root_fd)
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
    return root


def _write_all_posix(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise PrivateSecretMaterializationError(_ERROR)
        offset += written


def _read_hash_posix(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _read_all_posix(descriptor: int, max_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise PrivateSecretMaterializationError(_ERROR)


def _materialize_posix(raw: bytes, expected_sha256: str) -> MaterializedPrivateSecret:
    required_flags = ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags):
        raise PrivateSecretMaterializationError(_ERROR)
    import fcntl

    root = _posix_runtime_root()
    directory_name: str | None = None
    root_fd = directory_fd = writer_fd = reader_fd = claim_writer_fd = claim_fd = lease_fd = -1
    created = False
    claimed_directory_identity: _PosixIdentity | None = None
    claimed_entries: dict[str, _PosixIdentity] = {}
    try:
        root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        root_flags |= getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(root, root_flags)
        if _identity(os.fstat(root_fd)) != _identity(os.lstat(root)):
            raise PrivateSecretMaterializationError(_ERROR)
        root_identity = _identity(os.fstat(root_fd))
        for _ in range(_RETRIES):
            candidate = secrets.token_hex(16)
            try:
                os.mkdir(candidate, 0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            directory_name = candidate
            created = True
            break
        if directory_name is None:
            raise PrivateSecretMaterializationError(_ERROR)

        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(directory_name, directory_flags, dir_fd=root_fd)
        os.fchmod(directory_fd, 0o700)
        directory_metadata = os.fstat(directory_fd)
        claimed_directory_identity = _identity(directory_metadata)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_uid != os.geteuid()
        ):
            raise PrivateSecretMaterializationError(_ERROR)

        file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        writer_fd = os.open(_FILENAME, file_flags, 0o600, dir_fd=directory_fd)
        initial_file = os.fstat(writer_fd)
        claimed_entries[_FILENAME] = _identity(initial_file)
        if (
            not stat.S_ISREG(initial_file.st_mode)
            or initial_file.st_nlink != 1
            or initial_file.st_uid != os.geteuid()
            or stat.S_IMODE(initial_file.st_mode) != 0o600
            or initial_file.st_size != 0
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        _write_all_posix(writer_fd, raw)
        os.fsync(writer_fd)
        os.fchmod(writer_fd, 0o400)
        os.fsync(writer_fd)
        writer_metadata = os.fstat(writer_fd)
        if (
            not stat.S_ISREG(writer_metadata.st_mode)
            or writer_metadata.st_nlink != 1
            or writer_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(writer_metadata.st_mode) != 0o400
            or writer_metadata.st_size != len(raw)
        ):
            raise PrivateSecretMaterializationError(_ERROR)

        reader_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        reader_fd = os.open(_FILENAME, reader_flags, dir_fd=directory_fd)
        reader_metadata = os.fstat(reader_fd)
        path_metadata = os.stat(_FILENAME, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _identity(reader_metadata) != _identity(writer_metadata)
            or _identity(path_metadata) != _identity(writer_metadata)
            or not hmac.compare_digest(_read_hash_posix(reader_fd), expected_sha256)
        ):
            raise PrivateSecretMaterializationError(_ERROR)

        lease_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        lease_fd = os.open(_LEASE_FILENAME, lease_flags, 0o600, dir_fd=directory_fd)
        lease_metadata = os.fstat(lease_fd)
        lease_identity = _identity(lease_metadata)
        claimed_entries[_LEASE_FILENAME] = lease_identity
        if (
            not stat.S_ISREG(lease_metadata.st_mode)
            or lease_metadata.st_nlink != 1
            or lease_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(lease_metadata.st_mode) != 0o600
            or lease_metadata.st_size != 0
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        encoded_claim = _claim_bytes(
            claim_id=directory_name,
            source_sha256=expected_sha256,
            size=len(raw),
            root_identity=root_identity,
            directory_identity=claimed_directory_identity,
            file_identity=_identity(reader_metadata),
            lease_identity=lease_identity,
        )
        claim_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        claim_writer_fd = os.open(_CLAIM_FILENAME, claim_flags, 0o600, dir_fd=directory_fd)
        initial_claim = os.fstat(claim_writer_fd)
        claimed_entries[_CLAIM_FILENAME] = _identity(initial_claim)
        if (
            not stat.S_ISREG(initial_claim.st_mode)
            or initial_claim.st_nlink != 1
            or initial_claim.st_uid != os.geteuid()
            or stat.S_IMODE(initial_claim.st_mode) != 0o600
            or initial_claim.st_size != 0
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        _write_all_posix(claim_writer_fd, encoded_claim)
        os.fsync(claim_writer_fd)
        os.fchmod(claim_writer_fd, 0o400)
        os.fsync(claim_writer_fd)
        claim_metadata = os.fstat(claim_writer_fd)
        if claim_metadata.st_size != len(encoded_claim):
            raise PrivateSecretMaterializationError(_ERROR)
        claim_fd = os.open(_CLAIM_FILENAME, reader_flags, dir_fd=directory_fd)
        if (
            _identity(os.fstat(claim_fd)) != _identity(claim_metadata)
            or not hmac.compare_digest(_read_hash_posix(claim_fd), hashlib.sha256(encoded_claim).hexdigest())
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        os.close(writer_fd)
        writer_fd = -1
        os.close(claim_writer_fd)
        claim_writer_fd = -1
        os.fsync(directory_fd)
        os.fsync(root_fd)

        path = root / directory_name / _FILENAME
        result = MaterializedPrivateSecret(path, expected_sha256)
        result._state = _PosixState(
            root_fd=root_fd,
            directory_fd=directory_fd,
            file_fd=reader_fd,
            claim_fd=claim_fd,
            lease_fd=lease_fd,
            root_path=root,
            directory_name=directory_name,
            file_path=path,
            root_identity=root_identity,
            directory_identity=_identity(directory_metadata),
            file_identity=_identity(reader_metadata),
            claim_identity=_identity(claim_metadata),
            lease_identity=lease_identity,
            claim_bytes=encoded_claim,
        )
        root_fd = directory_fd = reader_fd = claim_fd = lease_fd = -1
        return result
    except BaseException as error:
        for descriptor in (claim_fd, claim_writer_fd, reader_fd, writer_fd, lease_fd, directory_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if (
            created
            and directory_name is not None
            and root_fd >= 0
            and claimed_directory_identity is not None
        ):
            try:
                temporary_directory_fd = os.open(
                    directory_name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                try:
                    if _identity(os.fstat(temporary_directory_fd)) != claimed_directory_identity:
                        raise PrivateSecretMaterializationError(_ERROR)
                    if set(os.listdir(temporary_directory_fd)) != set(claimed_entries):
                        raise PrivateSecretMaterializationError(_ERROR)
                    for name, expected_identity in claimed_entries.items():
                        try:
                            named_file = os.stat(name, dir_fd=temporary_directory_fd, follow_symlinks=False)
                            if _identity(named_file) == expected_identity:
                                os.unlink(name, dir_fd=temporary_directory_fd)
                        except FileNotFoundError:
                            pass
                finally:
                    os.close(temporary_directory_fd)
                os.rmdir(directory_name, dir_fd=root_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, PrivateSecretMaterializationError):
            raise
        raise PrivateSecretMaterializationError(_ERROR) from error


def _verify_posix(path: Path, expected_sha256: str, state: _PosixState | _WindowsState) -> None:
    if not isinstance(state, _PosixState):
        raise PrivateSecretMaterializationError(_ERROR)
    directory_metadata = os.fstat(state.directory_fd)
    root_metadata = os.fstat(state.root_fd)
    file_metadata = os.fstat(state.file_fd)
    claim_metadata = os.fstat(state.claim_fd)
    lease_metadata = os.fstat(state.lease_fd)
    named_directory = os.stat(state.directory_name, dir_fd=state.root_fd, follow_symlinks=False)
    named_file = os.stat(_FILENAME, dir_fd=state.directory_fd, follow_symlinks=False)
    named_claim = os.stat(_CLAIM_FILENAME, dir_fd=state.directory_fd, follow_symlinks=False)
    named_lease = os.stat(_LEASE_FILENAME, dir_fd=state.directory_fd, follow_symlinks=False)
    if (
        path.name != _FILENAME
        or path != state.file_path
        or path.parent.name != state.directory_name
        or _CLAIM_ID.fullmatch(state.directory_name) is None
        or _identity(root_metadata) != state.root_identity
        or _identity(os.lstat(state.root_path)) != state.root_identity
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or _identity(directory_metadata) != state.directory_identity
        or _identity(named_directory) != state.directory_identity
        or _identity(file_metadata) != state.file_identity
        or _identity(named_file) != state.file_identity
        or _identity(claim_metadata) != state.claim_identity
        or _identity(named_claim) != state.claim_identity
        or _identity(lease_metadata) != state.lease_identity
        or _identity(named_lease) != state.lease_identity
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        or directory_metadata.st_uid != os.geteuid()
        or not stat.S_ISREG(file_metadata.st_mode)
        or file_metadata.st_nlink != 1
        or file_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(file_metadata.st_mode) != 0o400
        or not stat.S_ISREG(claim_metadata.st_mode)
        or claim_metadata.st_nlink != 1
        or claim_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(claim_metadata.st_mode) != 0o400
        or not stat.S_ISREG(lease_metadata.st_mode)
        or lease_metadata.st_nlink != 1
        or lease_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(lease_metadata.st_mode) != 0o600
        or lease_metadata.st_size != 0
        or not hmac.compare_digest(_read_hash_posix(state.file_fd), expected_sha256)
        or not hmac.compare_digest(
            _read_all_posix(state.claim_fd, _CLAIM_MAX_BYTES), state.claim_bytes
        )
        or set(os.listdir(state.directory_fd))
        != {_FILENAME, _CLAIM_FILENAME, _LEASE_FILENAME}
    ):
        raise PrivateSecretMaterializationError(_ERROR)


def _close_posix(
    path: Path,
    expected_sha256: str,
    state: _PosixState | _WindowsState,
) -> None:
    if not isinstance(state, _PosixState):
        raise PrivateSecretMaterializationError(_ERROR)
    failed = False
    try:
        _verify_posix(path, expected_sha256, state)
        if set(os.listdir(state.directory_fd)) != {
            _FILENAME,
            _CLAIM_FILENAME,
            _LEASE_FILENAME,
        }:
            raise PrivateSecretMaterializationError(_ERROR)
        for name, expected_identity in (
            (_FILENAME, state.file_identity),
            (_CLAIM_FILENAME, state.claim_identity),
            (_LEASE_FILENAME, state.lease_identity),
        ):
            named_file = os.stat(name, dir_fd=state.directory_fd, follow_symlinks=False)
            if _identity(named_file) != expected_identity:
                raise PrivateSecretMaterializationError(_ERROR)
        os.unlink(_FILENAME, dir_fd=state.directory_fd)
        os.unlink(_CLAIM_FILENAME, dir_fd=state.directory_fd)
        os.unlink(_LEASE_FILENAME, dir_fd=state.directory_fd)
        os.fsync(state.directory_fd)
    except FileNotFoundError:
        failed = True
    except BaseException:
        failed = True
    finally:
        for descriptor in (state.file_fd, state.claim_fd, state.lease_fd, state.directory_fd):
            try:
                os.close(descriptor)
            except OSError:
                failed = True
    try:
        named_directory = os.stat(state.directory_name, dir_fd=state.root_fd, follow_symlinks=False)
        if _identity(named_directory) != state.directory_identity:
            failed = True
        else:
            os.rmdir(state.directory_name, dir_fd=state.root_fd)
            os.fsync(state.root_fd)
    except FileNotFoundError:
        pass
    except OSError:
        failed = True
    finally:
        try:
            os.close(state.root_fd)
        except OSError:
            failed = True
    if failed:
        raise PrivateSecretMaterializationError(_ERROR)


# Windows implementation.  Definitions remain importable on non-Windows so
# the API can be inspected, while no Windows DLL is loaded there.
if os.name == "nt":
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]

    class _FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]

    class _FILE_STANDARD_INFO(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", wintypes.DWORD),
            ("DeletePending", wintypes.BYTE),
            ("Directory", wintypes.BYTE),
        ]

    class _FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    class _FILE_ID_128(ctypes.Structure):
        _fields_ = [("Identifier", wintypes.BYTE * 16)]

    class _FILE_ID_INFO(ctypes.Structure):
        _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong), ("FileId", _FILE_ID_128)]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", wintypes.BYTE), ("AceFlags", wintypes.BYTE), ("AceSize", wintypes.WORD)]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _READ_CONTROL = 0x00020000
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_WRITE_ATTRIBUTES = 0x0100
    _DELETE = 0x00010000
    _FILE_SHARE_READ = 0x1
    _FILE_SHARE_WRITE = 0x2
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_READONLY = 0x1
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _TOKEN_QUERY = 0x8
    _TOKEN_USER_CLASS = 1
    _SDDL_REVISION_1 = 1
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _GROUP_SECURITY_INFORMATION = 0x2
    _DACL_SECURITY_INFORMATION = 0x4
    _SE_DACL_PRESENT = 0x0004
    _SE_DACL_AUTO_INHERITED = 0x0400
    _SE_DACL_PROTECTED = 0x1000
    _ACL_SIZE_INFORMATION_CLASS = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _INHERITANCE_ACE_FLAGS = 0x1 | 0x2 | 0x8 | 0x10
    _FILE_ALL_ACCESS = 0x001F01FF
    _FILE_BASIC_INFO_CLASS = 0
    _FILE_STANDARD_INFO_CLASS = 1
    _FILE_DISPOSITION_INFO_CLASS = 4
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_INFO_CLASS = 18
    _FILE_PERSISTENT_ACLS = 0x00000008
    _DRIVE_REMOTE = 4

    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _ADVAPI32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    _ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
    _ADVAPI32.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    _ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD))
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = (wintypes.HLOCAL,)
    _KERNEL32.LocalFree.restype = wintypes.HLOCAL
    _KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.CreateDirectoryW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(_SECURITY_ATTRIBUTES))
    _KERNEL32.CreateDirectoryW.restype = wintypes.BOOL
    _KERNEL32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_SECURITY_ATTRIBUTES), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.WriteFile.argtypes = (wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    _KERNEL32.WriteFile.restype = wintypes.BOOL
    _KERNEL32.ReadFile.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    _KERNEL32.ReadFile.restype = wintypes.BOOL
    _KERNEL32.SetFilePointerEx.argtypes = (wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD)
    _KERNEL32.SetFilePointerEx.restype = wintypes.BOOL
    _KERNEL32.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
    _KERNEL32.FlushFileBuffers.restype = wintypes.BOOL
    _KERNEL32.GetFileInformationByHandleEx.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _KERNEL32.SetFileInformationByHandle.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
    _KERNEL32.DeleteFileW.argtypes = (wintypes.LPCWSTR,)
    _KERNEL32.DeleteFileW.restype = wintypes.BOOL
    _KERNEL32.RemoveDirectoryW.argtypes = (wintypes.LPCWSTR,)
    _KERNEL32.RemoveDirectoryW.restype = wintypes.BOOL
    _KERNEL32.GetFileAttributesW.argtypes = (wintypes.LPCWSTR,)
    _KERNEL32.GetFileAttributesW.restype = wintypes.DWORD
    _KERNEL32.GetVolumePathNameW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    _KERNEL32.GetVolumePathNameW.restype = wintypes.BOOL
    _KERNEL32.GetVolumeInformationW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    _KERNEL32.GetVolumeInformationW.restype = wintypes.BOOL
    _KERNEL32.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)
    _KERNEL32.GetDriveTypeW.restype = wintypes.UINT
    _ADVAPI32.GetSecurityInfo.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID))
    _ADVAPI32.GetSecurityInfo.restype = wintypes.DWORD
    _ADVAPI32.GetSecurityDescriptorControl.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD))
    _ADVAPI32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _ADVAPI32.GetAclInformation.argtypes = (wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int)
    _ADVAPI32.GetAclInformation.restype = wintypes.BOOL
    _ADVAPI32.GetAce.argtypes = (wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID))
    _ADVAPI32.GetAce.restype = wintypes.BOOL


def _win_error(code: int | None = None) -> PrivateSecretMaterializationError:
    if code is None:
        code = ctypes.get_last_error()
    return PrivateSecretMaterializationError(_ERROR, winerror_code=code)


def _close_handle(handle: int | None) -> bool:
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return True
    return bool(_KERNEL32.CloseHandle(wintypes.HANDLE(handle)))


def _sid_string(pointer: int | ctypes.c_void_p) -> str:
    output = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(wintypes.LPVOID(pointer), ctypes.byref(output)):
        raise _win_error()
    try:
        return output.value
    finally:
        _KERNEL32.LocalFree(wintypes.HLOCAL(ctypes.cast(output, ctypes.c_void_p).value))


def _current_windows_sid() -> str:
    token = wintypes.HANDLE()
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise _win_error()
    try:
        required = wintypes.DWORD()
        _ADVAPI32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(required))
        if required.value == 0:
            raise _win_error()
        buffer = ctypes.create_string_buffer(required.value)
        if not _ADVAPI32.GetTokenInformation(token, _TOKEN_USER_CLASS, buffer, required, ctypes.byref(required)):
            raise _win_error()
        user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
        return _sid_string(user.User.Sid)
    finally:
        _close_handle(int(token.value))


def _security_attributes(current_sid: str) -> tuple[_SECURITY_ATTRIBUTES, int]:
    sddl = (
        f"O:{current_sid}G:{current_sid}D:P"
        f"(A;;FA;;;{current_sid})(A;;FA;;;SY)(A;;FA;;;BA)"
    )
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise _win_error()
    attributes = _SECURITY_ATTRIBUTES(
        ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, False
    )
    return attributes, int(descriptor.value)


def _win_open(path: Path, access: int, share: int, disposition: int, flags: int, attributes=None) -> int:
    pointer = ctypes.byref(attributes) if attributes is not None else None
    handle = _KERNEL32.CreateFileW(str(path), access, share, pointer, disposition, flags, None)
    value = int(handle) if handle is not None else 0
    if value == _INVALID_HANDLE_VALUE:
        raise _win_error()
    return value


def _win_info(handle: int, info_class: int, value: Any) -> Any:
    if not _KERNEL32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle), info_class, ctypes.byref(value), ctypes.sizeof(value)
    ):
        raise _win_error()
    return value


def _win_identity(handle: int, *, directory: bool, read_only: bool = False) -> _WindowsIdentity:
    basic = _win_info(handle, _FILE_BASIC_INFO_CLASS, _FILE_BASIC_INFO())
    standard = _win_info(handle, _FILE_STANDARD_INFO_CLASS, _FILE_STANDARD_INFO())
    tag = _win_info(handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, _FILE_ATTRIBUTE_TAG_INFO())
    identity = _win_info(handle, _FILE_ID_INFO_CLASS, _FILE_ID_INFO())
    if (
        bool(standard.Directory) is not directory
        or tag.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or (directory and not tag.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY)
        or (not directory and (standard.NumberOfLinks != 1 or tag.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY))
        or (read_only and not basic.FileAttributes & _FILE_ATTRIBUTE_READONLY)
    ):
        raise PrivateSecretMaterializationError(_ERROR)
    return _WindowsIdentity(identity.VolumeSerialNumber, bytes(identity.FileId.Identifier))


def _win_acl(handle: int, current_sid: str) -> None:
    owner = wintypes.LPVOID()
    group = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    code = _ADVAPI32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _GROUP_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if code:
        raise _win_error(code)
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not _ADVAPI32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise _win_error()
        if (
            not control.value & _SE_DACL_PRESENT
            or not control.value & _SE_DACL_PROTECTED
            or control.value & _SE_DACL_AUTO_INHERITED
            or not dacl.value
            or _sid_string(owner.value) != current_sid
            or _sid_string(group.value) != current_sid
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        size = _ACL_SIZE_INFORMATION()
        if not _ADVAPI32.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION_CLASS):
            raise _win_error()
        rules: dict[str, int] = {}
        for index in range(size.AceCount):
            pointer = wintypes.LPVOID()
            if not _ADVAPI32.GetAce(dacl, index, ctypes.byref(pointer)):
                raise _win_error()
            ace = ctypes.cast(pointer, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
            if ace.Header.AceType != _ACCESS_ALLOWED_ACE_TYPE or ace.Header.AceFlags & _INHERITANCE_ACE_FLAGS:
                raise PrivateSecretMaterializationError(_ERROR)
            sid_pointer = int(pointer.value) + _ACCESS_ALLOWED_ACE.SidStart.offset
            sid = _sid_string(sid_pointer)
            if sid in rules:
                raise PrivateSecretMaterializationError(_ERROR)
            rules[sid] = int(ace.Mask)
        expected = {current_sid, "S-1-5-18", "S-1-5-32-544"}
        if set(rules) != expected or any(mask != _FILE_ALL_ACCESS for mask in rules.values()):
            raise PrivateSecretMaterializationError(_ERROR)
    finally:
        _KERNEL32.LocalFree(wintypes.HLOCAL(descriptor.value))


def _write_all_windows(handle: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        chunk = raw[offset:offset + 1024 * 1024]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not _KERNEL32.WriteFile(wintypes.HANDLE(handle), buffer, len(chunk), ctypes.byref(written), None):
            raise _win_error()
        if written.value == 0:
            raise PrivateSecretMaterializationError(_ERROR)
        offset += written.value


def _hash_windows(handle: int) -> str:
    if not _KERNEL32.SetFilePointerEx(wintypes.HANDLE(handle), 0, None, 0):
        raise _win_error()
    digest = hashlib.sha256()
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        read = wintypes.DWORD()
        if not _KERNEL32.ReadFile(wintypes.HANDLE(handle), buffer, len(buffer), ctypes.byref(read), None):
            raise _win_error()
        if read.value == 0:
            return digest.hexdigest()
        digest.update(buffer.raw[:read.value])


def _read_all_windows(handle: int, max_bytes: int) -> bytes:
    if not _KERNEL32.SetFilePointerEx(wintypes.HANDLE(handle), 0, None, 0):
        raise _win_error()
    chunks: list[bytes] = []
    total = 0
    while True:
        buffer = ctypes.create_string_buffer(min(64 * 1024, max_bytes + 1 - total))
        read = wintypes.DWORD()
        if not _KERNEL32.ReadFile(
            wintypes.HANDLE(handle), buffer, len(buffer), ctypes.byref(read), None
        ):
            raise _win_error()
        if read.value == 0:
            return b"".join(chunks)
        chunks.append(buffer.raw[:read.value])
        total += read.value
        if total > max_bytes:
            raise PrivateSecretMaterializationError(_ERROR)


def _set_windows_read_only(handle: int, enabled: bool) -> None:
    current = _win_info(handle, _FILE_BASIC_INFO_CLASS, _FILE_BASIC_INFO())
    attributes = current.FileAttributes & ~_FILE_ATTRIBUTE_NORMAL
    attributes = (attributes | _FILE_ATTRIBUTE_READONLY) if enabled else (attributes & ~_FILE_ATTRIBUTE_READONLY)
    if attributes == 0:
        attributes = _FILE_ATTRIBUTE_NORMAL
    update = _FILE_BASIC_INFO(0, 0, 0, 0, attributes)
    if not _KERNEL32.SetFileInformationByHandle(
        wintypes.HANDLE(handle), _FILE_BASIC_INFO_CLASS, ctypes.byref(update), ctypes.sizeof(update)
    ):
        raise _win_error()


def _mark_windows_delete(handle: int) -> None:
    disposition = _FILE_DISPOSITION_INFO(True)
    if not _KERNEL32.SetFileInformationByHandle(
        wintypes.HANDLE(handle),
        _FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise _win_error()


def _open_verified_windows_delete_handle(
    path: Path,
    current_sid: str,
    expected_identity: _WindowsIdentity,
    *,
    directory: bool,
    expected_sha256: str | None = None,
    expected_bytes: bytes | None = None,
) -> int:
    access = _DELETE | _READ_CONTROL | _FILE_READ_ATTRIBUTES
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    else:
        access |= _GENERIC_READ | _FILE_WRITE_ATTRIBUTES
    handle = _win_open(
        path,
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        _OPEN_EXISTING,
        flags,
    )
    try:
        _win_acl(handle, current_sid)
        if _win_identity(handle, directory=directory) != expected_identity:
            raise PrivateSecretMaterializationError(_ERROR)
        if expected_sha256 is not None and not hmac.compare_digest(
            _hash_windows(handle), expected_sha256
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        if expected_bytes is not None and not hmac.compare_digest(
            _read_all_windows(handle, _CLAIM_MAX_BYTES), expected_bytes
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        return handle
    except BaseException:
        _close_handle(handle)
        raise


def _delete_verified_windows_path(
    path: Path,
    current_sid: str,
    expected_identity: _WindowsIdentity,
    *,
    directory: bool,
    expected_sha256: str | None = None,
    expected_bytes: bytes | None = None,
) -> None:
    handle = _open_verified_windows_delete_handle(
        path,
        current_sid,
        expected_identity,
        directory=directory,
        expected_sha256=expected_sha256,
        expected_bytes=expected_bytes,
    )
    try:
        if not directory:
            _set_windows_read_only(handle, False)
        _mark_windows_delete(handle)
    finally:
        if not _close_handle(handle):
            raise PrivateSecretMaterializationError(_ERROR)


def _validate_windows_base(root: Path) -> Path:
    if not root.is_absolute():
        raise PrivateSecretMaterializationError(_ERROR)
    _require_outside_repository(root)
    current = root
    while True:
        attributes = _KERNEL32.GetFileAttributesW(str(current))
        if (
            attributes == 0xFFFFFFFF
            or not attributes & _FILE_ATTRIBUTE_DIRECTORY
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        if current.parent == current:
            break
        current = current.parent
    volume = ctypes.create_unicode_buffer(32768)
    if not _KERNEL32.GetVolumePathNameW(str(root), volume, len(volume)):
        raise _win_error()
    flags = wintypes.DWORD()
    if (
        _KERNEL32.GetDriveTypeW(volume.value) == _DRIVE_REMOTE
        or not _KERNEL32.GetVolumeInformationW(
            volume.value,
            None,
            0,
            None,
            None,
            ctypes.byref(flags),
            None,
            0,
        )
        or not flags.value & _FILE_PERSISTENT_ACLS
    ):
        raise PrivateSecretMaterializationError(_ERROR)
    return root


def _windows_temp_root() -> Path:
    function = getattr(_KERNEL32, "GetTempPath2W", _KERNEL32.GetTempPathW)
    function.argtypes = (wintypes.DWORD, wintypes.LPWSTR)
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = function(len(buffer), buffer)
    if not length or length >= len(buffer):
        raise _win_error()
    return _validate_windows_base(Path(buffer.value))


def _windows_runtime_root(current_sid: str, *, create: bool = True) -> Path:
    override = _runtime_root_override()
    suffix = hashlib.sha256(current_sid.encode("ascii")).hexdigest()[:16]
    root = override or (_windows_temp_root() / f"{_RUNTIME_ROOT_NAME}-{suffix}")
    _validate_windows_base(root.parent)
    attributes, descriptor = _security_attributes(current_sid)
    handle = None
    try:
        if create and not _KERNEL32.CreateDirectoryW(str(root), ctypes.byref(attributes)):
            if ctypes.get_last_error() not in {80, 183}:
                raise _win_error()
        handle = _win_open(
            root,
            _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        _win_acl(handle, current_sid)
        _win_identity(handle, directory=True)
    finally:
        _close_handle(handle)
        _KERNEL32.LocalFree(wintypes.HLOCAL(descriptor))
    return root


def _materialize_windows(raw: bytes, expected_sha256: str) -> MaterializedPrivateSecret:
    current_sid = _current_windows_sid()
    root = _windows_runtime_root(current_sid)
    attributes, descriptor = _security_attributes(current_sid)
    directory_path: Path | None = None
    file_path: Path | None = None
    claim_path: Path | None = None
    lease_path: Path | None = None
    root_handle = directory_handle = writer_handle = keeper_handle = None
    claim_writer_handle = claim_handle = lease_handle = None
    directory_identity = file_identity = claim_identity = lease_identity = None
    try:
        root_handle = _win_open(
            root,
            _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        _win_acl(root_handle, current_sid)
        root_identity = _win_identity(root_handle, directory=True)
        for _ in range(_RETRIES):
            candidate = root / secrets.token_hex(16)
            if _KERNEL32.CreateDirectoryW(str(candidate), ctypes.byref(attributes)):
                directory_path = candidate
                break
            if ctypes.get_last_error() not in {80, 183}:
                raise _win_error()
        if directory_path is None:
            raise PrivateSecretMaterializationError(_ERROR)
        directory_handle = _win_open(
            directory_path,
            _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        _win_acl(directory_handle, current_sid)
        directory_identity = _win_identity(directory_handle, directory=True)

        file_path = directory_path / _FILENAME
        writer_handle = _win_open(
            file_path,
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            attributes,
        )
        _win_acl(writer_handle, current_sid)
        file_identity = _win_identity(writer_handle, directory=False)
        _write_all_windows(writer_handle, raw)
        if not _KERNEL32.FlushFileBuffers(wintypes.HANDLE(writer_handle)):
            raise _win_error()
        _set_windows_read_only(writer_handle, True)
        _win_acl(writer_handle, current_sid)
        if _win_identity(writer_handle, directory=False, read_only=True) != file_identity:
            raise PrivateSecretMaterializationError(_ERROR)
        if not hmac.compare_digest(_hash_windows(writer_handle), expected_sha256):
            raise PrivateSecretMaterializationError(_ERROR)

        keeper_handle = _win_open(
            file_path,
            _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        _win_acl(keeper_handle, current_sid)
        if (
            _win_identity(keeper_handle, directory=False, read_only=True) != file_identity
            or not hmac.compare_digest(_hash_windows(keeper_handle), expected_sha256)
        ):
            raise PrivateSecretMaterializationError(_ERROR)

        lease_path = directory_path / _LEASE_FILENAME
        lease_handle = _win_open(
            lease_path,
            _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            attributes,
        )
        _win_acl(lease_handle, current_sid)
        lease_identity = _win_identity(lease_handle, directory=False)
        lease_info = _win_info(lease_handle, _FILE_STANDARD_INFO_CLASS, _FILE_STANDARD_INFO())
        if lease_info.EndOfFile != 0:
            raise PrivateSecretMaterializationError(_ERROR)

        encoded_claim = _claim_bytes(
            claim_id=directory_path.name,
            source_sha256=expected_sha256,
            size=len(raw),
            root_identity=root_identity,
            directory_identity=directory_identity,
            file_identity=file_identity,
            lease_identity=lease_identity,
        )
        claim_path = directory_path / _CLAIM_FILENAME
        claim_writer_handle = _win_open(
            claim_path,
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            attributes,
        )
        _win_acl(claim_writer_handle, current_sid)
        claim_identity = _win_identity(claim_writer_handle, directory=False)
        _write_all_windows(claim_writer_handle, encoded_claim)
        if not _KERNEL32.FlushFileBuffers(wintypes.HANDLE(claim_writer_handle)):
            raise _win_error()
        _set_windows_read_only(claim_writer_handle, True)
        if (
            _win_identity(claim_writer_handle, directory=False, read_only=True) != claim_identity
            or not hmac.compare_digest(
                _hash_windows(claim_writer_handle), hashlib.sha256(encoded_claim).hexdigest()
            )
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        claim_handle = _win_open(
            claim_path,
            _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        _win_acl(claim_handle, current_sid)
        if (
            _win_identity(claim_handle, directory=False, read_only=True) != claim_identity
            or not hmac.compare_digest(
                _read_all_windows(claim_handle, _CLAIM_MAX_BYTES), encoded_claim
            )
        ):
            raise PrivateSecretMaterializationError(_ERROR)
        _close_handle(writer_handle)
        writer_handle = None
        _close_handle(claim_writer_handle)
        claim_writer_handle = None

        result = MaterializedPrivateSecret(file_path, expected_sha256)
        result._state = _WindowsState(
            root_handle=root_handle,
            directory_handle=directory_handle,
            file_handle=keeper_handle,
            claim_handle=claim_handle,
            lease_handle=lease_handle,
            root_identity=root_identity,
            directory_identity=directory_identity,
            file_identity=file_identity,
            claim_identity=claim_identity,
            lease_identity=lease_identity,
            claim_bytes=encoded_claim,
            current_sid=current_sid,
            directory_path=directory_path,
            file_path=file_path,
        )
        root_handle = directory_handle = keeper_handle = claim_handle = lease_handle = None
        return result
    except BaseException as error:
        for mutable_handle in (writer_handle, keeper_handle, claim_writer_handle, claim_handle):
            if not mutable_handle:
                continue
            try:
                _set_windows_read_only(mutable_handle, False)
            except BaseException:
                pass
        for handle in (claim_handle, claim_writer_handle, keeper_handle, writer_handle, lease_handle):
            _close_handle(handle)
        claimed_windows_entries = tuple(
            (created_path, expected_identity)
            for created_path, expected_identity in (
            (claim_path, claim_identity),
            (file_path, file_identity),
            (lease_path, lease_identity),
            )
            if created_path is not None and expected_identity is not None
        )
        exact_entries = False
        if directory_path is not None:
            try:
                exact_entries = {entry.name for entry in directory_path.iterdir()} == {
                    created_path.name for created_path, _ in claimed_windows_entries
                }
            except OSError:
                pass
        if exact_entries:
            for created_path, expected_identity in claimed_windows_entries:
                try:
                    _delete_verified_windows_path(
                        created_path,
                        current_sid,
                        expected_identity,
                        directory=False,
                    )
                except BaseException:
                    pass
        _close_handle(directory_handle)
        if exact_entries and directory_path is not None and directory_identity is not None:
            try:
                _delete_verified_windows_path(
                    directory_path,
                    current_sid,
                    directory_identity,
                    directory=True,
                )
            except BaseException:
                pass
        _close_handle(root_handle)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, PrivateSecretMaterializationError):
            raise
        raise PrivateSecretMaterializationError(_ERROR) from error
    finally:
        _KERNEL32.LocalFree(wintypes.HLOCAL(descriptor))


def _verify_windows(path: Path, expected_sha256: str, state: _PosixState | _WindowsState) -> None:
    if not isinstance(state, _WindowsState):
        raise PrivateSecretMaterializationError(_ERROR)
    if path != state.file_path:
        raise PrivateSecretMaterializationError(_ERROR)
    _win_acl(state.root_handle, state.current_sid)
    _win_acl(state.directory_handle, state.current_sid)
    _win_acl(state.file_handle, state.current_sid)
    _win_acl(state.claim_handle, state.current_sid)
    _win_acl(state.lease_handle, state.current_sid)
    if (
        _win_identity(state.root_handle, directory=True) != state.root_identity
        or _win_identity(state.directory_handle, directory=True) != state.directory_identity
        or _win_identity(state.file_handle, directory=False, read_only=True) != state.file_identity
        or _win_identity(state.claim_handle, directory=False, read_only=True) != state.claim_identity
        or _win_identity(state.lease_handle, directory=False) != state.lease_identity
        or not hmac.compare_digest(_hash_windows(state.file_handle), expected_sha256)
        or not hmac.compare_digest(
            _read_all_windows(state.claim_handle, _CLAIM_MAX_BYTES), state.claim_bytes
        )
    ):
        raise PrivateSecretMaterializationError(_ERROR)
    if {entry.name for entry in state.directory_path.iterdir()} != {
        _FILENAME,
        _CLAIM_FILENAME,
        _LEASE_FILENAME,
    }:
        raise PrivateSecretMaterializationError(_ERROR)
    named_root = _win_open(
        state.directory_path.parent,
        _READ_CONTROL | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        _win_acl(named_root, state.current_sid)
        if _win_identity(named_root, directory=True) != state.root_identity:
            raise PrivateSecretMaterializationError(_ERROR)
    finally:
        _close_handle(named_root)
    for named_path, expected_identity, read_only, expected_bytes in (
        (path, state.file_identity, True, None),
        (state.directory_path / _CLAIM_FILENAME, state.claim_identity, True, state.claim_bytes),
        (state.directory_path / _LEASE_FILENAME, state.lease_identity, False, b""),
    ):
        named = _win_open(
            named_path,
            _GENERIC_READ | _READ_CONTROL | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            _win_acl(named, state.current_sid)
            if _win_identity(named, directory=False, read_only=read_only) != expected_identity:
                raise PrivateSecretMaterializationError(_ERROR)
            if expected_bytes is not None and not hmac.compare_digest(
                _read_all_windows(named, _CLAIM_MAX_BYTES), expected_bytes
            ):
                raise PrivateSecretMaterializationError(_ERROR)
        finally:
            _close_handle(named)


def _close_windows(
    path: Path,
    expected_sha256: str,
    state: _PosixState | _WindowsState,
) -> None:
    if not isinstance(state, _WindowsState):
        raise PrivateSecretMaterializationError(_ERROR)
    failed = False
    delete_handles: list[int] = []
    try:
        _verify_windows(path, expected_sha256, state)
        if {entry.name for entry in state.directory_path.iterdir()} != {
            _FILENAME,
            _CLAIM_FILENAME,
            _LEASE_FILENAME,
        }:
            raise PrivateSecretMaterializationError(_ERROR)
    except BaseException:
        failed = True
    for handle in (state.file_handle, state.claim_handle, state.lease_handle):
        if not _close_handle(handle):
            failed = True
    if not failed:
        try:
            # Acquire and completely authenticate every DELETE-capable child
            # handle before the first read-only bit or delete disposition is
            # changed.  This keeps a late replacement from causing a partial
            # cleanup.
            delete_handles.append(
                _open_verified_windows_delete_handle(
                    state.file_path,
                    state.current_sid,
                    state.file_identity,
                    directory=False,
                    expected_sha256=expected_sha256,
                )
            )
            delete_handles.append(
                _open_verified_windows_delete_handle(
                    state.directory_path / _CLAIM_FILENAME,
                    state.current_sid,
                    state.claim_identity,
                    directory=False,
                    expected_bytes=state.claim_bytes,
                )
            )
            delete_handles.append(
                _open_verified_windows_delete_handle(
                    state.directory_path / _LEASE_FILENAME,
                    state.current_sid,
                    state.lease_identity,
                    directory=False,
                    expected_bytes=b"",
                )
            )
            if {entry.name for entry in state.directory_path.iterdir()} != {
                _FILENAME,
                _CLAIM_FILENAME,
                _LEASE_FILENAME,
            }:
                raise PrivateSecretMaterializationError(_ERROR)
            _set_windows_read_only(delete_handles[0], False)
            _set_windows_read_only(delete_handles[1], False)
            for handle in delete_handles:
                _mark_windows_delete(handle)
        except BaseException:
            failed = True
        finally:
            for handle in delete_handles:
                if not _close_handle(handle):
                    failed = True
            delete_handles = []
    if not failed and any(
        candidate.exists()
        for candidate in (
            state.file_path,
            state.directory_path / _CLAIM_FILENAME,
            state.directory_path / _LEASE_FILENAME,
        )
    ):
        failed = True
    if not _close_handle(state.directory_handle):
        failed = True
    if not failed:
        try:
            _delete_verified_windows_path(
                state.directory_path,
                state.current_sid,
                state.directory_identity,
                directory=True,
            )
        except BaseException:
            failed = True
    if not failed and state.directory_path.exists():
        failed = True
    if not _close_handle(state.root_handle):
        failed = True
    if failed:
        raise PrivateSecretMaterializationError(_ERROR)
