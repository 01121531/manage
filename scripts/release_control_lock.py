"""One advisory lock shared by deploy, rollback and rolling release controls."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import BinaryIO, Iterator


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK_FILE = ROOT.parent / ".email-platform-release-control.lock"


class ReleaseControlLocked(RuntimeError):
    """Another release-control process currently owns the host lock."""


def _lock(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            handle.seek(0)
            if handle.read(1) == b"":
                handle.seek(0)
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise ReleaseControlLocked("release control lock is already held") from error
        return
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise ReleaseControlLocked("release control lock is already held") from error


def _unlock(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def release_control_lock(
    path: Path = DEFAULT_LOCK_FILE,
) -> Iterator[None]:
    """Hold the process-scoped host release lock without stale lock semantics."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        _lock(handle)
        try:
            yield
        finally:
            _unlock(handle)
