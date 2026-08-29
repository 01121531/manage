"""Bounded, stable loading for repository-external JSON artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import stat
import tempfile
from typing import Any, BinaryIO, Iterator


MAX_EXTERNAL_JSON_BYTES = 5 * 1024 * 1024
MAX_INTAKE_JSON_BYTES = 64 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class StableFileError(OSError):
    def __init__(self, reason: str) -> None:
        super().__init__("file cannot be read safely")
        self.reason = reason


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True)
class StableFileIdentity:
    """Portable file identity and mutation evidence captured at one boundary."""

    device: int
    inode: int
    links: int
    size: int
    mode: int
    mtime_ns: int


def _file_shape(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
    )


def _regular_file_metadata(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and not bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _stable_mode(metadata: os.stat_result) -> int:
    mode = metadata.st_mode
    if os.name == "nt":
        mode &= ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return mode


def stable_file_identity(metadata: os.stat_result) -> StableFileIdentity:
    return StableFileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        links=metadata.st_nlink,
        size=metadata.st_size,
        mode=_stable_mode(metadata),
        mtime_ns=metadata.st_mtime_ns,
    )


def is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def has_link_or_reparse_ancestor(path: Path) -> bool:
    current = path.absolute()
    while True:
        if is_link_or_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


@contextmanager
def open_stable_binary(
    path: Path,
    *,
    expected_identity: StableFileIdentity | None = None,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one regular file and bind all reads to its checked identity."""

    if has_link_or_reparse_ancestor(path):
        raise StableFileError("read")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise StableFileError("missing") from error
    except OSError as error:
        raise StableFileError("read") from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        opened_identity = stable_file_identity(opened)
        if (
            not _regular_file_metadata(opened)
            or not _regular_file_metadata(named)
            or stat.S_ISLNK(named.st_mode)
            or opened_identity != stable_file_identity(named)
            or (
                expected_identity is not None
                and opened_identity != expected_identity
            )
        ):
            raise StableFileError("read")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream, opened
        final_opened = os.fstat(descriptor)
        final_named = path.lstat()
        final_identity = stable_file_identity(final_opened)
        if (
            not _regular_file_metadata(final_opened)
            or not _regular_file_metadata(final_named)
            or stat.S_ISLNK(final_named.st_mode)
            or final_identity != opened_identity
            or stable_file_identity(final_named) != opened_identity
        ):
            raise StableFileError("read")
    except StableFileError:
        raise
    except OSError as error:
        raise StableFileError("read") from error
    finally:
        os.close(descriptor)


def read_stable_bytes_with_metadata(
    path: Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
    expected_identity: StableFileIdentity | None = None,
) -> tuple[bytes, os.stat_result]:
    if has_link_or_reparse_ancestor(path):
        raise StableFileError("read")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise StableFileError("missing") from error
    except OSError as error:
        raise StableFileError("read") from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        opened_identity = stable_file_identity(opened)
        if (
            not _regular_file_metadata(opened)
            or not _regular_file_metadata(named)
            or stat.S_ISLNK(named.st_mode)
            or _file_shape(opened) != _file_shape(named)
            or _stable_mode(opened) != _stable_mode(named)
            or (
                expected_identity is not None
                and opened_identity != expected_identity
            )
        ):
            raise StableFileError("read")
        if (
            opened.st_size > max_bytes
            or opened.st_size < 0
            or (opened.st_size == 0 and not allow_empty)
        ):
            raise StableFileError("size")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        final_opened = os.fstat(descriptor)
        final_named = path.lstat()
        if (
            len(raw) != opened.st_size
            or _file_shape(opened) != _file_shape(final_opened)
            or _stable_mode(opened) != _stable_mode(final_opened)
            or opened.st_mtime_ns != final_opened.st_mtime_ns
            or not _regular_file_metadata(final_named)
            or stat.S_ISLNK(final_named.st_mode)
            or _file_shape(final_opened) != _file_shape(final_named)
            or _stable_mode(final_opened) != _stable_mode(final_named)
        ):
            raise StableFileError("read")
    except StableFileError:
        raise
    except OSError as error:
        raise StableFileError("read") from error
    finally:
        os.close(descriptor)
    return raw, final_opened


def read_stable_bytes(
    path: Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
    expected_identity: StableFileIdentity | None = None,
) -> bytes:
    return read_stable_bytes_with_metadata(
        path,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
        expected_identity=expected_identity,
    )[0]


def write_atomic_bytes(path: Path, raw: bytes) -> None:
    """Publish bytes through one unique same-directory temporary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError(key)
        value[key] = item
    return value


def parse_unique_json_bytes(raw: bytes) -> Any:
    text = raw.decode("utf-8")
    try:
        return json.loads(text, object_pairs_hook=_unique_json_object)
    except _DuplicateJsonKeyError as error:
        raise json.JSONDecodeError("duplicate JSON key", text, 0) from error


def load_unique_json_with_bytes(
    path: Path,
    *,
    max_bytes: int = MAX_EXTERNAL_JSON_BYTES,
    expected_identity: StableFileIdentity | None = None,
) -> tuple[Any, bytes]:
    raw = read_stable_bytes(
        path,
        max_bytes=max_bytes,
        expected_identity=expected_identity,
    )
    return parse_unique_json_bytes(raw), raw


def load_unique_json_with_bytes_and_metadata(
    path: Path,
    *,
    max_bytes: int = MAX_EXTERNAL_JSON_BYTES,
    expected_identity: StableFileIdentity | None = None,
) -> tuple[Any, bytes, os.stat_result]:
    """Parse one stable snapshot and return its authenticated final metadata."""

    raw, metadata = read_stable_bytes_with_metadata(
        path,
        max_bytes=max_bytes,
        expected_identity=expected_identity,
    )
    return parse_unique_json_bytes(raw), raw, metadata


def recheck_stable_bytes(
    path: Path,
    raw: bytes,
    metadata: os.stat_result,
    *,
    max_bytes: int = MAX_EXTERNAL_JSON_BYTES,
    require_single_link: bool = False,
) -> None:
    """Fail unless a locator still names the same stable bytes and identity."""

    if require_single_link and metadata.st_nlink != 1:
        raise StableFileError("read")
    current, current_metadata = read_stable_bytes_with_metadata(
        path,
        max_bytes=max_bytes,
        expected_identity=stable_file_identity(metadata),
    )
    if (
        (require_single_link and current_metadata.st_nlink != 1)
        or not hmac.compare_digest(
            hashlib.sha256(current).digest(),
            hashlib.sha256(raw).digest(),
        )
    ):
        raise StableFileError("read")


def load_unique_json(
    path: Path,
    *,
    max_bytes: int = MAX_EXTERNAL_JSON_BYTES,
    expected_identity: StableFileIdentity | None = None,
) -> Any:
    return load_unique_json_with_bytes(
        path,
        max_bytes=max_bytes,
        expected_identity=expected_identity,
    )[0]
