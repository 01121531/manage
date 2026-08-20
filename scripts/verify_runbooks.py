"""Verify operational runbooks are present and reference the core controls."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
RUNBOOKS = {
    "restore.md": ["python -m scripts.postgres_maintenance restore-bundle", "Do not use Alembic downgrade"],
    "vault-restore.md": ["python -m scripts.vault_maintenance restore", "--confirm-restore", "isolated"],
    "phase6-rehearsal.md": [
        "phase6_rehearsal.py run",
        "production_acceptance=false",
        "does **not** prove target",
    ],
    "rollback.md": ["python -m scripts.release_manifest verify", "restore-first"],
    "device-revocation.md": ["/api/v1/admin/devices/{device_id}/revoke", "device.revoked"],
    "key-rotation.md": ["docker compose config", "verify_compose_env.py", "PLATFORM_VAULT_API_TOKEN_DIR"],
    "incident-response.md": ["PlatformUnknownUploadsPresent", "reconcile"],
}


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    base = ROOT / "deploy" / "runbooks"
    if not base.exists():
        return _fail("Missing deploy/runbooks directory")
    for filename, needles in RUNBOOKS.items():
        path = base / filename
        if not path.exists():
            return _fail(f"Missing runbook: {filename}")
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                return _fail(f"Runbook {filename} is missing: {needle}")
    index = base / "README.md"
    if not index.exists():
        return _fail("Missing runbook index")
    print("runbooks-ok operational-guides-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
