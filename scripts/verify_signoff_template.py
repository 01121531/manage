"""Verify the production signoff template covers all required readiness gates."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_text import load_stable_text


TEMPLATE = ROOT / "deploy" / "production-signoff-template.md"
MAX_SIGNOFF_TEMPLATE_BYTES = 64 * 1024


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    try:
        text = load_stable_text(
            TEMPLATE,
            max_bytes=MAX_SIGNOFF_TEMPLATE_BYTES,
        )
    except (OSError, UnicodeError):
        return _fail("Missing production signoff template")
    required = [
        "Compose/config and secret scan",
        "CodeQL SAST plus container build, HIGH/CRITICAL scan, SPDX SBOM, keyless signature and provenance",
        "PostgreSQL and Redis release recovery-set plus Vault isolated backup/restore drills and Alembic upgrade",
        "Keycloak realm, redirect URIs, client auth, MFA, user/admin audit and retention",
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
        "Stable container tag post-verification promotion and resolved-digest equality evidence:",
        "Forward deployment release tag, commit and migration head:",
        "Forward deployment container manifest SHA-256:",
        "Forward deployment expected and observed application OCI digests:",
        "Forward deployment five reviewed third-party OCI digest references:",
        "Forward deployment write-once terminal evidence file, whole-file SHA-256 and canonical payload SHA-256:",
        "Forward deployment Phase 0 target environment, canonical intake payload SHA-256 and requirements SHA-256:",
        "Forward deployment terminal state, fixed error code, ordered phase UTC values and final Edge state:",
        "Forward deployment Cosign, SPDX attestation and provenance verification:",
        "Forward deployment preflight-before-edge-stop and edge-closed failure evidence:",
        "Forward deployment current rollback release tag, commit and migration head:",
        "Forward deployment authenticated schema-v5 rollback manifest SHA-256, MAC and freshness evidence:",
        "Forward deployment current running application OCI digests:",
        "Forward deployment zero-mutation rollback-readiness failure evidence:",
        "Forward deployment Git HEAD/manifest commit equality and clean tracked checkout evidence:",
        "Forward deployment explicit production Compose path/project and override absence evidence:",
        "Single-instance outage window and no-rolling-release acknowledgement:",
        "Web/API blue-green plan fingerprint, source/target slot and release identity:",
        "Web/API rolling execution evidence file and canonical payload SHA-256:",
        "Web/API rolling Phase 0 target environment, canonical intake payload SHA-256 and requirements SHA-256:",
        "Web/API rolling terminal state and ordered phase UTC values:",
        "Web/API current/target exact API, Web and unchanged Edge OCI digests:",
        "Web/API Worker Mail/Sub2 before/after digest equality evidence:",
        "Web/API route before/after and canonical source/target SHA-256 evidence:",
        "Web/API atomic paired route, Nginx test/reload and three-observation evidence:",
        "Web/API three public releasez result identities and UTC values:",
        "Web/API mixed-version readiness, alert continuity and connection-drain evidence:",
        "Web/API failure-injection switch-back and `route_unconfirmed` handling evidence:",
        "Web/API source-retained cleanup approval and independent operator/reviewer:",
        "Web/API-only scope and unchanged single-instance Worker acknowledgement:",
        "Web/API rolling pilot `production_acceptance=false` preflight acknowledgement:",
        "Third-party runtime image digest-lock status and unresolved blocker:",
        "CodeQL Python result:",
        "CodeQL JavaScript/TypeScript result:",
        "Python runtime/test/desktop-build dependency audit evidence:",
        "Full frontend dependency-tree audit evidence (including devDependencies):",
        "CI/Security/Release checkout `persist-credentials=false` verifier evidence:",
        "Explicit-token publication step and authenticated Git-write review evidence:",
        "Vault snapshot artifact and SHA-256:",
        "Vault recovery-set, PostgreSQL manifest SHA-256 and schema-v2 HMAC evidence:",
        "Vault primary/secondary audit device and persistent-path evidence:",
        "Vault audit allowed/denied request correlation and raw-secret absence evidence:",
        "Vault audit 180-day retention, rotation, SIGHUP and capacity-alert evidence:",
        "Vault two-device audit, independent storage, allowed/denied events and alert result:",
        "Internal TLS CA fingerprint and nine unique leaf certificate/SAN/key evidence:",
        "Internal TLS API, JWKS, metrics and Alertmanager hostname-verification evidence:",
        "Internal TLS leaf/CA rotation drill and expiry-alert evidence:",
        "Internal cross-container HTTPS, CA, SAN/hostname and rotation evidence:",
        "Runtime secret-file verifier and protected Compose-render evidence:",
        "PostgreSQL/application/Redis/Keycloak secret file owner, mode and distinct-inode evidence:",
        "Runtime process argv/environment credential-absence evidence:",
        "Runtime credential rotation with old-secret rejection and redacted rollback evidence:",
        "Bounded container logging verifier and rendered production Compose evidence:",
        "Runtime LogConfig for all 11 base non-Vault containers and all 13 when both slots are retained:",
        "Container log rotation pilot UTC, retained-file counts and observed disk usage:",
        "Container logs versus database/Keycloak/Vault audit-retention acknowledgement:",
        "Bounded container LogConfig and target rotation evidence:",
        "Migration baseline/head, reviewed expansion SHA-256 and compatibility-verifier evidence:",
        "Target N/N+1 expand/backfill rolling-rehearsal evidence:",
        "Audit archive schema/tool source commit, ciphertext/manifest SHA-256 and key ID:",
        "Audit archive tenant, half-open UTC window, row count and first/last key:",
        "Consecutive audit-window no-gap/no-overlap review evidence:",
        "Audit archive SELECT-only role, source-table before/after and zero-prune evidence:",
        "Independent audit archive decrypt/verify evidence:",
        "Audit archive WORM/object-lock mode, retention, deny-delete and lifecycle evidence:",
        "Audit archive operator and independent reviewer:",
        "Audit archive UTC boundary/count continuity, SELECT-only and zero-prune evidence:",
        "Independent decrypt/verify plus target WORM/object-lock/retention evidence:",
        "Phase 6 CI rehearsal evidence, file SHA-256 and payload SHA-256 (preflight only):",
        "Phase 6 selected release-execution ledger type, WORM reference and whole-file SHA-256:",
        "Phase 6 selected release-execution Phase 0 environment, manifest payload SHA-256, requirements SHA-256 and checkpoint phase:",
        "Phase 6 selected schema-v2 ledger independent parse and successful-terminal result:",
        "Mail/Sub2 provider scope, external source version/SHA-256, capture/review/valid-until UTC and same-manifest review result:",
        "Phase 1–5/Sub2/Vault execution-index sealed review/valid-until and same-manifest review result:",
        "Windows pilot-input sealed review/valid-until and same-manifest review result:",
        "Phase 5 execution-window containment in Windows-input validity and single-clock preflight result:",
        "Phase 1–5 execution-index exact release-ledger selectors and target-release alignment result:",
        "Phase 4 Sub2 evidence exact release-ledger whole-file selector and target-release alignment result:",
        "Phase 4 Sub2 sealed review reference/time, execution window and same-manifest review-metadata result:",
        "Phase 6 pilot evidence same-manifest Sub2-evidence, pilot-input and target-inventory SHA-256 bindings:",
        "Phase 6 pilot operator/security-auditor subject, trace-set, sealed review reference and post-window review time:",
        "Phase 6 pilot-input sealed review/valid-until and maintenance-window validity result:",
        "Phase 6 pilot execution containment and pre-deadline reviewed result:",
        "Phase 6 operations/pilot exact release-execution selector equality:",
        "Phase 6 operations four-role subjects, pilot trace-set, sealed review reference and post-window review time:",
        "Phase 6 operations post-pilot/maintenance-window/rollback-deadline and review-validity result:",
        "Target-environment pilot evidence:",
        "Keycloak administrator group subject digest and membership evidence:",
        "Vault administrator group entity digest and membership evidence:",
        "Keycloak/Vault administrator non-overlap and no-shared-credential review:",
        "Cross-control-plane denied-access trace and audit-event evidence:",
        "Separate recovery custodians, two-person break-glass approval and post-use rotation evidence:",
        "Keycloak/Vault administration-separation independent reviewer:",
        "Non-production source/target environment and synthetic-fixture provenance:",
        "Non-production fixture SHA-256, masked last-four and `.invalid` validation evidence:",
        "Non-production denial of production backup/snapshot/clone/Vault-path access evidence:",
        "Non-production mailbox-secret and live-connector absence evidence:",
        "Non-production data-boundary independent privacy/security reviewer:",
        "Rollback release tag, commit and migration head:",
        "Rollback container manifest SHA-256:",
        "Release-bound dual-database backup manifest SHA-256:",
        "Redis release backup artifact and authenticated manifest SHA-256:",
        "Redis recovery-set, PostgreSQL manifest SHA-256 and release-binding evidence:",
        "Write-once external PostgreSQL/Redis/Vault output paths and pre-existing-target refusal evidence:",
        "Release-bound schema-v5 manifest HKDF/HMAC verification evidence:",
        "Rollback expected and observed OCI digests:",
        "Rollback Cosign, SBOM attestation and provenance verification:",
        "Rollback drill start/end UTC and achieved RTO/RPO:",
        "Rollback dual-database critical row counts:",
        "PostgreSQL/Redis shared recovery-set and restore-order evidence:",
        "Redis restored key count, representative TTL samples and expired-key non-revival evidence:",
        "Restore internal TLS readiness smoke and edge-closed failure evidence:",
        "Keycloak user/admin event configuration and 30-day retention evidence:",
        "Keycloak browser MFA flow alias and target realm export SHA-256:",
        "Keycloak password-required then OTP-required execution evidence:",
        "Keycloak password-only/invalid-OTP rejection and password-plus-OTP success evidence:",
        "Keycloak CONFIGURE_TOTP enrollment versus OTP challenge review evidence:",
        "Keycloak Desktop/Web direct-grant rejection evidence:",
        "Keycloak MFA cutover notBefore/logout-all and old session/token rejection evidence:",
        "Keycloak failed-login event and Alertmanager delivery evidence:",
        "Alertmanager external config path/SHA-256 and production verifier evidence:",
        "Alertmanager page firing/resolved receiver delivery IDs and UTC timestamps:",
        "Monitoring control-plane Prometheus/Alertmanager strict-TLS self-scrape evidence:",
        "Monitoring watchdog dedicated route/receiver and <=2m cadence evidence:",
        "Monitoring watchdog consecutive receiver delivery IDs and UTC timestamps:",
        "Monitoring watchdog suppression window, missed-heartbeat alarm and recovery evidence:",
        "Monitoring control-plane self-scrape and dead-man heartbeat evidence:",
        "Keycloak admin event with request representation disabled:",
        "Keycloak event_entity/admin_event_entity restore counts:",
        "Rollback failure-injection result (edge remained closed):",
        "Rollback Git HEAD/manifest commit equality and clean tracked checkout evidence:",
        "Rollback explicit production Compose path/project and override absence evidence:",
        "Rollback independent operator/reviewer:",
        "Phase 6 role-training evidence file and payload SHA-256:",
        "Training session/environment/release/window:",
        "Operator trainee/reviewer:",
        "Ops administrator trainee/reviewer:",
        "Security auditor trainee/reviewer:",
        "Platform administrator trainee/reviewer:",
        "Required tabletop scenarios and trace IDs:",
        "Target-environment pilot, alert delivery, training and rollback drill",
        "production_acceptance=false",
        "authenticated schema-v5 platform + Keycloak backup bundle",
        "kept edge closed",
    ]
    missing = [item for item in required if item not in text]
    if missing:
        return _fail("Signoff template missing items: " + ", ".join(missing))
    print("signoff-template-ok readiness-gates-covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
