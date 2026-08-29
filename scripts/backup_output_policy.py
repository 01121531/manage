"""Write-once output policy shared by production backup tools."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import stat
import tempfile

from scripts.external_json import StableFileIdentity, stable_file_identity


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
CLEANUP_UNCONFIRMED_NOTE = "backup output cleanup could not be confirmed"


@dataclass(frozen=True)
class ClaimedDirectory:
    """Immutable identity for one directory created by this process."""

    path: Path
    device: int
    inode: int


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _assert_safe_absolute_path(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("backup output path must be absolute")

    current = path
    while True:
        if _is_link_or_reparse(current):
            raise ValueError("backup output path must not use symlink or reparse points")
        if current.parent == current:
            break
        current = current.parent

    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("backup output path must be outside the repository")


def create_write_once_directory(output_dir: Path | str) -> ClaimedDirectory:
    """Atomically claim a new, external backup bundle directory."""

    directory = Path(output_dir)
    _assert_safe_absolute_path(directory)
    if not directory.parent.is_dir():
        raise ValueError("backup output parent directory must already exist")
    try:
        directory.mkdir()
    except FileExistsError as error:
        raise ValueError("backup output directory must not already exist") from error
    if _is_link_or_reparse(directory):
        directory.rmdir()
        raise ValueError("backup output path must not use symlink or reparse points")
    metadata = os.lstat(directory)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("backup output path must be a directory")
    return ClaimedDirectory(
        path=directory,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def prepare_write_once_file(output_path: Path | str) -> Path:
    """Validate a single-file output before reading a key or starting a child."""

    path = Path(output_path)
    _assert_safe_absolute_path(path)
    if not path.parent.is_dir():
        raise ValueError("backup output parent directory must already exist")
    if os.path.lexists(path):
        raise ValueError("backup output file must not already exist")
    return path


def write_fsynced_temporary_bytes(output_path: Path, raw: bytes) -> Path:
    """Write one unique adjacent temporary file without publishing it."""

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary_path
    except BaseException:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise


def publish_write_once_file(temporary_path: Path, output_path: Path) -> None:
    """Publish without replace semantics; an unexpected target wins and fails closed."""

    os.link(temporary_path, output_path)
    try:
        temporary_path.unlink()
    except OSError:
        # The hard link is the commit point. Cleanup failure may leave only the
        # private temporary name and must not turn a committed artifact into a
        # reported publication failure.
        pass


def publish_bundle_write_once_file(
    temporary_path: Path,
    output_path: Path,
) -> None:
    """Publish inside a claimed bundle whose owner can roll back the directory."""

    os.link(temporary_path, output_path)
    temporary_path.unlink()


def cleanup_created_directory(claim: ClaimedDirectory) -> None:
    """Remove only a directory successfully claimed by this backup attempt."""

    try:
        metadata = os.lstat(claim.path)
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != claim.device
        or metadata.st_ino != claim.inode
    ):
        raise RuntimeError("refusing to clean a replaced backup output directory")
    shutil.rmtree(claim.path)


def cleanup_created_directory_after_failure(
    claim: ClaimedDirectory,
    primary_error: BaseException,
) -> bool:
    """Best-effort rollback which never replaces the operation's first error."""

    try:
        cleanup_created_directory(claim)
    except BaseException:
        notes = getattr(primary_error, "__notes__", ())
        if CLEANUP_UNCONFIRMED_NOTE not in notes:
            primary_error.add_note(CLEANUP_UNCONFIRMED_NOTE)
        return False
    return True


def cleanup_unconfirmed(error: BaseException) -> bool:
    """Return whether a fixed rollback diagnostic is attached to an error."""

    return CLEANUP_UNCONFIRMED_NOTE in getattr(error, "__notes__", ())


def discard_claimed_temporary_file(path: Path | None) -> None:
    """Best-effort local cleanup; the claimed directory remains authoritative."""

    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def require_exact_regular_files(
    directory: Path,
    expected_names: frozenset[str],
) -> dict[str, StableFileIdentity]:
    """Reject extra, missing, linked, reparse, or non-regular bundle leaves."""

    try:
        directory_metadata = os.lstat(directory)
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise ValueError("backup bundle directory cannot be read") from error
    if (
        stat.S_ISLNK(directory_metadata.st_mode)
        or bool(
            getattr(directory_metadata, "st_file_attributes", 0) & _REPARSE_POINT
        )
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or {entry.name for entry in entries} != expected_names
    ):
        raise ValueError("backup bundle leaf set is invalid")
    identities: dict[str, StableFileIdentity] = {}
    for entry in entries:
        try:
            metadata = os.lstat(entry)
        except OSError as error:
            raise ValueError("backup bundle leaf set is invalid") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ValueError("backup bundle leaf set is invalid")
        identities[entry.name] = stable_file_identity(metadata)
    return identities
