"""Bounded, stable reads for runtime-mounted platform files."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
from collections.abc import Iterator


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class RuntimeFileError(OSError):
    """A runtime-mounted file could not be read as one stable snapshot."""


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


@contextmanager
def open_stable_runtime_descriptor(
    path: str | Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> Iterator[tuple[int, os.stat_result]]:
    """Hold one stable projected-volume target open for a bounded consumer."""

    source = Path(path)
    try:
        resolved = source.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeFileError("runtime file is unavailable") from error

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise RuntimeFileError("runtime file is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        named = resolved.lstat()
        if (
            not _regular_file_metadata(opened)
            or not _regular_file_metadata(named)
            or _file_shape(opened) != _file_shape(named)
            or _stable_mode(opened) != _stable_mode(named)
        ):
            raise RuntimeFileError("runtime file is unstable")
        if (
            opened.st_size > max_bytes
            or opened.st_size < 0
            or (opened.st_size == 0 and not allow_empty)
        ):
            raise RuntimeFileError("runtime file size is invalid")

        yield descriptor, opened

        final_opened = os.fstat(descriptor)
        final_resolved = source.resolve(strict=True)
        final_named = final_resolved.lstat()
        if (
            final_resolved != resolved
            or _file_shape(opened) != _file_shape(final_opened)
            or _stable_mode(opened) != _stable_mode(final_opened)
            or opened.st_mtime_ns != final_opened.st_mtime_ns
            or not _regular_file_metadata(final_named)
            or _file_shape(final_opened) != _file_shape(final_named)
            or _stable_mode(final_opened) != _stable_mode(final_named)
        ):
            raise RuntimeFileError("runtime file changed during use")
    except RuntimeFileError:
        raise
    except (OSError, RuntimeError) as error:
        raise RuntimeFileError("runtime file is unavailable") from error
    finally:
        os.close(descriptor)


def read_stable_runtime_bytes_with_metadata(
    path: str | Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> tuple[bytes, os.stat_result]:
    """Read one stable regular-file snapshot, including projected-volume links."""

    with open_stable_runtime_descriptor(
        path,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    ) as (descriptor, opened):
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        final_opened = os.fstat(descriptor)
        if (
            len(raw) != opened.st_size
            or _file_shape(opened) != _file_shape(final_opened)
            or _stable_mode(opened) != _stable_mode(final_opened)
            or opened.st_mtime_ns != final_opened.st_mtime_ns
        ):
            raise RuntimeFileError("runtime file changed during read")
    return raw, final_opened


def read_stable_runtime_bytes(
    path: str | Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> bytes:
    return read_stable_runtime_bytes_with_metadata(
        path,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )[0]


def read_stable_runtime_text(
    path: str | Path,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> str:
    raw = read_stable_runtime_bytes(
        path,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeFileError("runtime file encoding is invalid") from None
