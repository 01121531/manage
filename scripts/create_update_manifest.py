"""Create the verified desktop update manifest attached to a GitHub Release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Sequence

try:
    from scripts.external_json import (
        has_link_or_reparse_ancestor,
        write_atomic_bytes,
    )
except ModuleNotFoundError:  # pragma: no cover - standalone script execution
    from external_json import has_link_or_reparse_ancestor, write_atomic_bytes


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ASSET_NAME = "email-platform-windows.exe"
MIN_EXE_BYTES = 1024 * 1024
MAX_EXE_BYTES = 200 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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


def _mode_signature(metadata: os.stat_result) -> int:
    mode = metadata.st_mode
    if os.name == "nt":
        mode &= ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return mode


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    same = (
        _file_shape(left) == _file_shape(right)
        and _mode_signature(left) == _mode_signature(right)
        and left.st_mtime_ns == right.st_mtime_ns
    )
    if os.name != "nt":
        same = same and left.st_ctime_ns == right.st_ctime_ns
    return same


def _hash_stable_exe(exe: Path) -> tuple[str, int]:
    if has_link_or_reparse_ancestor(exe):
        raise ValueError("EXE cannot be read safely")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(exe, flags)
    except FileNotFoundError:
        raise ValueError("EXE does not exist") from None
    except OSError:
        raise ValueError("EXE cannot be read safely") from None

    try:
        opened = os.fstat(descriptor)
        named = exe.lstat()
        if (
            not _regular_file_metadata(opened)
            or not _regular_file_metadata(named)
            or not _same_snapshot(opened, named)
        ):
            raise ValueError("EXE cannot be read safely")
        if not MIN_EXE_BYTES <= opened.st_size <= MAX_EXE_BYTES:
            raise ValueError("EXE size is outside the updater safety boundary")

        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(HASH_CHUNK_BYTES):
                size += len(chunk)
                if size > MAX_EXE_BYTES:
                    raise ValueError("EXE size is outside the updater safety boundary")
                digest.update(chunk)

        final_opened = os.fstat(descriptor)
        final_named = exe.lstat()
        if (
            size != opened.st_size
            or not _same_snapshot(opened, final_opened)
            or not _regular_file_metadata(final_named)
            or not _same_snapshot(final_opened, final_named)
        ):
            raise ValueError("EXE cannot be read safely")
    except ValueError:
        raise
    except OSError:
        raise ValueError("EXE cannot be read safely") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return digest.hexdigest(), size


def build_manifest(exe: Path, version: str, repository: str) -> dict[str, object]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("version must use MAJOR.MINOR.PATCH")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name")
    exe = exe.absolute()
    digest, size = _hash_stable_exe(exe)
    tag = f"v{version}"
    return {
        "version": version,
        "download_url": (
            f"https://github.com/{repository}/releases/download/{tag}/{ASSET_NAME}"
        ),
        "sha256": digest,
        "size": size,
        "release_notes_url": f"https://github.com/{repository}/releases/tag/{tag}",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default="01121531/manage")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = build_manifest(args.exe, args.version, args.repository)
    except ValueError:
        print("update-manifest-invalid", file=sys.stderr)
        return 1
    write_atomic_bytes(
        args.output,
        (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
