"""Create the verified desktop update manifest attached to a GitHub Release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ASSET_NAME = "email-platform-windows.exe"


def build_manifest(exe: Path, version: str, repository: str) -> dict[str, object]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("version must use MAJOR.MINOR.PATCH")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name")
    if not exe.is_file():
        raise ValueError("EXE does not exist")
    size = exe.stat().st_size
    if not 1024 * 1024 <= size <= 200 * 1024 * 1024:
        raise ValueError("EXE size is outside the updater safety boundary")
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default="01121531/manage")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.exe.resolve(), args.version, args.repository)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
