"""Verify PostgreSQL backup/restore tooling is documented and present."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "platform" / "README.md"
SCRIPT = ROOT / "scripts" / "postgres_maintenance.py"


def main() -> int:
    readme = README.read_text(encoding="utf-8")
    if not SCRIPT.exists():
        print("Missing postgres_maintenance.py", file=sys.stderr)
        return 1
    for needle in (
        "python -m scripts.postgres_maintenance backup",
        "python -m scripts.postgres_maintenance restore",
        "python -m scripts.postgres_maintenance drill",
        "PostgreSQL backup/restore drill",
    ):
        if needle not in readme:
            print(f"README is missing: {needle}", file=sys.stderr)
            return 1
    print("backup-tools-ok documented-and-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
