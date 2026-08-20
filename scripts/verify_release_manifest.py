"""Verify the committed release manifest matches the current repository state."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deploy" / "release-manifest.json"
MODULE_PATH = ROOT / "scripts" / "release_manifest.py"

SPEC = importlib.util.spec_from_file_location("release_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_manifest
SPEC.loader.exec_module(release_manifest)


def main() -> int:
    manifest = release_manifest.load_manifest(MANIFEST)
    errors = release_manifest.verify_manifest(manifest)
    if errors:
        print("Release manifest is stale: " + ", ".join(errors), file=sys.stderr)
        return 1
    print("release-manifest-ok committed-lock-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
