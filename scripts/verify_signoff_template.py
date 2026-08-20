"""Verify the production signoff template covers all required readiness gates."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "production-signoff-template.md"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    if not TEMPLATE.exists():
        return _fail("Missing production signoff template")
    text = TEMPLATE.read_text(encoding="utf-8")
    required = [
        "Compose/config and secret scan",
        "CodeQL SAST plus container build, HIGH/CRITICAL scan, SPDX SBOM, keyless signature and provenance",
        "PostgreSQL plus Vault isolated backup/restore drills and Alembic upgrade",
        "Keycloak realm, redirect URIs, client auth, MFA",
        "TLS headers, rate limits, log redaction, retention, alerting",
        "Mail connector and Sub2 boundary",
        "Worker retry / reconciliation / card lease safety",
        "Runbooks signed off by a separate operator",
        "Approved for production",
        "Signed by:",
        "Reviewer role:",
        "Review date:",
        "Container release manifest:",
        "API OCI digest:",
        "Web OCI digest:",
        "Edge OCI digest:",
        "SBOM SHA-256 values:",
        "Trivy report SHA-256 values:",
        "Cosign certificate identity:",
        "Cosign OIDC issuer:",
        "Provenance attestation evidence:",
        "CodeQL Python result:",
        "CodeQL JavaScript/TypeScript result:",
        "Vault snapshot artifact and SHA-256:",
        "Phase 6 CI rehearsal evidence, file SHA-256 and payload SHA-256 (preflight only):",
        "Target-environment pilot evidence:",
        "Target-environment pilot, alert delivery, training and rollback drill",
        "production_acceptance=false",
    ]
    missing = [item for item in required if item not in text]
    if missing:
        return _fail("Signoff template missing items: " + ", ".join(missing))
    print("signoff-template-ok readiness-gates-covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
