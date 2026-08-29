"""Stable loading helpers for bounded repository text assets."""

from __future__ import annotations

from pathlib import Path

try:
    from scripts.external_json import StableFileError, read_stable_bytes
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import StableFileError, read_stable_bytes


MAX_REPOSITORY_TEXT_BYTES = 64 * 1024


def load_stable_text(
    path: Path, *, max_bytes: int = MAX_REPOSITORY_TEXT_BYTES
) -> str:
    raw = read_stable_bytes(path, max_bytes=max_bytes)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise StableFileError("decode") from None
