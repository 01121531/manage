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
    "rollback.md": [
        "python -m scripts.rollback_release plan",
        "python -m scripts.rollback_release execute",
        "--confirm-release-tag",
        "platform + Keycloak",
        "Cosign",
        "--no-build --pull never",
        "edge` last",
        "production_acceptance=false",
    ],
    "device-revocation.md": ["/api/v1/admin/devices/{device_id}/revoke", "device.revoked"],
    "key-rotation.md": ["docker compose config", "verify_compose_env.py", "PLATFORM_VAULT_API_TOKEN_DIR"],
    "incident-response.md": ["PlatformUnknownUploadsPresent", "reconcile"],
}
ROLLBACK_FORBIDDEN = (
    "scripts.postgres_maintenance restore --input",
    "scripts.release_manifest verify",
    "127.0.0.1:8000",
    "127.0.0.1:9101",
    "127.0.0.1:9102",
    "Rebuild or pull",
)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def rollback_runbook_errors(text: str) -> list[str]:
    errors = [
        f"rollback runbook is missing: {needle}"
        for needle in RUNBOOKS["rollback.md"]
        if needle not in text
    ]
    errors.extend(
        f"rollback runbook contains obsolete control: {needle}"
        for needle in ROLLBACK_FORBIDDEN
        if needle in text
    )
    return errors


def main() -> int:
    base = ROOT / "deploy" / "runbooks"
    if not base.exists():
        return _fail("Missing deploy/runbooks directory")
    for filename, needles in RUNBOOKS.items():
        path = base / filename
        if not path.exists():
            return _fail(f"Missing runbook: {filename}")
        text = path.read_text(encoding="utf-8")
        if filename == "rollback.md":
            errors = rollback_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
            continue
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
