"""Verify operational runbooks are present and reference the core controls."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_text import load_stable_text


MAX_RUNBOOK_BYTES = 64 * 1024
RELEASE_ENVIRONMENT_REQUIRED = (
    "clean shell owned by a dedicated production deployment account",
    "rejects the presence, including an empty value",
    "`VAULT_TOKEN`",
    "`PLATFORM_VAULT_*_SECRET_ID`",
    "`ALEMBIC_DATABASE_URL`",
    "`REDISCLI_AUTH`",
    "explicit environment rebuilt from only the reviewed OS locator variables",
    "`PYTHONPATH`",
    "`GIT_*`",
    "`TRIVY_*`",
    "`COSIGN_*`",
    "`SIGSTORE_*`",
    "`SSL_CERT_FILE`",
    "`GH_TOKEN` is copied only to the exact `gh attestation verify` process",
    "absent from Git, Cosign, Trivy, Docker, Compose, restore, and smoke-test processes",
)
RUNBOOKS = {
    "secure-pool-import.md": [
        "schema_version: 2",
        "submission_key",
        "signed receipt UUID",
        "Do not upload the raw",
        "结果尚未确认",
        "same bundle",
        "ordered_manifest_digest",
        "secure_receipt_fingerprint",
        "production_acceptance=false",
        "cleanup_required=true",
        "administrator manually uploads",
        "There is no automatic source collection",
        "--plan-output",
        "secure_import_vault_canary_cleanup.py render-policy",
        "preflight both canaries",
        "Never use a",
        "secure_pool_import_recovery.py",
        "automatic_resume_allowed=false",
        "partial_written",
        "commit_unknown",
    ],
    "admin-plane-separation.md": [
        "distinct human administrator groups",
        "must not administer both control planes",
        "denied Vault administration",
        "denied Keycloak administration",
        "two-person approval",
        "post-use credential rotation",
        "independent security reviewer",
        "blocks production",
        "mandatory production evidence",
    ],
    "nonproduction-data-boundary.md": [
        "source environment, target environment",
        "Do not import a production database snapshot",
        "Masking after a production copy",
        "reserved `.invalid` domain",
        "masked last four digits",
        "cannot read production backup buckets",
        "denied-access trace",
        "unknown provenance",
        "blocks the refresh",
        "does not claim that a local manifest proves target data provenance",
    ],
    "rolling-release.md": [
        "Web/API pair",
        "worker_release_strategy=unchanged-single-instance",
        "production_acceptance=false",
        "source_retained_after_switch=true",
        "PLATFORM_ROLLING_ROUTE_DIR",
        "api-green",
        "web-green",
        "atomic rename replaces its inode",
        "nginx -t",
        "three public `/releasez` identity observations",
        "route_unconfirmed",
        "Do not stop Edge or",
        "do not run Alembic downgrade",
        "COMPLETE_SOURCE_RETAINED",
        "independent operator/reviewer",
    ],
    "audit-archive.md": [
        "python -m scripts.audit_archive archive",
        "python -m scripts.audit_archive verify",
        "audit-events.v1.jsonl.enc",
        "[from, until)",
        "(created_at, id)",
        "repeatable-read and read-only",
        "plaintext is never written to disk",
        "zero source mutation and zero prune",
        "next window's `from` must exactly equal the previous window's `until`",
        "WORM/object-lock mode",
        "deny-delete permissions",
        "independent decrypt/verify",
        "production_acceptance=false",
    ],
    "restore.md": [
        "python -m scripts.postgres_maintenance restore-bundle",
        "python -m scripts.redis_maintenance verify-release",
        "python -m scripts.redis_maintenance restore-release",
        "--recovery-set",
        "--postgres-manifest-sha256",
        "DBSIZE",
        "PTTL",
        "expired key must not reappear",
        "python -m scripts.restore_readiness",
        "https://api:8443/readyz",
        "https://web:8443/",
        "https://keycloak:9000/health/ready",
        "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        "https://worker-mail:9101/metrics",
        "https://worker-sub2:9102/metrics",
        "https://prometheus:9090/-/ready",
        "/run/secrets/internal-tls/ca.crt",
        "TLS 1.2 minimum",
        "production_acceptance=false",
        "Do not use Alembic downgrade",
        "authenticated encrypted schema v5",
        "schema v4 is rejected with no override",
        "absolute, repository-external",
        "must not already exist",
    ],
    "vault-restore.md": [
        "python -m scripts.postgres_maintenance verify-bundle",
        "python -m scripts.vault_maintenance verify",
        "python -m scripts.vault_maintenance restore",
        "--manifest-key-file",
        "--recovery-set",
        "--postgres-manifest",
        "schema v2",
        "HKDF-SHA256",
        "HMAC-SHA256",
        "PostgreSQL manifest SHA-256",
        "--confirm-restore",
        "--ca-file",
        "X-Vault-Token",
        "token-free environment",
        "TLS 1.2",
        "POST /v1/sys/storage/raft/snapshot",
        "does not expose a force-restore mode",
        "consistency rejection is a stop condition",
        "isolated",
        "absolute, repository-external",
        "must not already exist",
    ],
    "vault-audit.md": [
        "configure-audit.sh",
        "email-platform-primary",
        "email-platform-secondary",
        "mode `0600`",
        "`log_raw=false`",
        "`elide_list_responses=true`",
        "not atomic",
        "never disables or replaces",
        "SIGHUP",
        "180 days",
        "70%",
        "85%",
        "permission denied",
        "must not contain",
        "independent persistent volumes",
    ],
    "phase6-rehearsal.md": [
        "phase6_rehearsal.py run",
        "outside the repository",
        "no-replace hard-link commit point",
        "never deletes or",
        "production_acceptance=false",
        "does **not** prove target",
    ],
    "keycloak-audit.md": [
        "eventsExpiration=2592000",
        "adminEventsDetailsEnabled=false",
        "keycloak_user_events_total",
        "event_entity",
        "admin_event_entity",
    ],
    "keycloak-mfa.md": [
        "browserFlow=email-platform-browser-mfa",
        "email-platform-browser-mfa-forms",
        "auth-username-password-form",
        "auth-otp-form",
        "`REQUIRED`",
        "Enrollment is not the OTP challenge",
        "directAccessGrantsEnabled=false",
        "password-only does not issue an authorization code",
        "password plus a valid OTP",
        "invalid OTP",
        "realm export SHA-256",
        "`notBefore`",
        "`logout-all`",
        "old session cookie, access token, and refresh token",
        "production_acceptance=false",
        "Never record the password, TOTP seed, or OTP code",
    ],
    "internal-tls.md": [
        "verify_internal_tls.py",
        "api, web, keycloak",
        "worker-mail",
        "worker-sub2",
        "prometheus",
        "alertmanager",
        "Subject Alternative Name",
        "distinct private key",
        "dual-CA trust bundle",
        "must not claim",
        "production_acceptance=false",
    ],
    "runtime-secrets.md": [
        "verify_runtime_secrets.py",
        "production_acceptance=false",
        "mode `0400` or `0440`",
        "credential-bearing URLs",
        "REDIS_HEALTHCHECK_PASSWORD_FILE",
        "bootstrap-admin-password",
        "process argv and container environment",
        "old credentials fail",
        "must never contain secret contents",
        "configure-broker-issuer-policies.sh",
        "three distinct external principals",
        "auth/token/revoke-accessor",
        "independent approved rotator",
        "Vault token-sink hash",
    ],
    "private-secret-provenance.md": [
        "python scripts/private_secret_github_attestation.py verify-repository",
        "python scripts/private_secret_target_provenance.py verify-repository",
        "python scripts/private_secret_github_rest_collection.py verify-repository",
        "python scripts/private_secret_worm_collection.py verify-repository",
        "python scripts/verify_private_secret_collection.py",
        "python scripts/private_secret_collection_review_decision.py verify-repository",
        "python scripts/verify_private_secret_collection_review.py",
        "python scripts/private_secret_collection_archive_receipt.py verify-repository",
        "python scripts/verify_private_secret_collection_archive.py",
        "python scripts/verify_private_secret_collector_deployment.py",
        "GitHub App installation token",
        "Actions: read and Attestations: read",
        "manual allowlisted HTTPS redirect origins",
        "CAS one-hop binding",
        "global CAS linearizability remains unverified",
        "intentionally `unconfigured`",
        "origin-authentication=unverified",
        "--expected-policy-sha256 <64-lowercase-hex>",
        "--expected-gh-sha256 <64-lowercase-hex>",
        "--expected-github-origin-sha256 <64-lowercase-hex>",
        "--expected-deployment-policy-sha256 <64-lowercase-hex>",
        "--expected-readiness-sha256 <64-lowercase-hex>",
        "--expected-archive-sha256 <64-lowercase-hex>",
        "--expected-bundle-sha256 <64-lowercase-hex>",
        "--expected-collection-ledger-id <opaque-ledger-id>",
        "no Authorization/cookie/proxy credential forwarding",
        "job-artifact-causality=unverified",
        "--expected-target-policy-sha256 <64-lowercase-hex>",
        "--expected-prior-head-sha256 <64-lowercase-hex>",
        "expected_runtime_policy_sha256",
        "duplicate file identities",
        "email-platform/private-secret-collection-review/v1",
        "--expected-decision-sha256 <64-lowercase-hex>",
        "--expected-verifier-source-sha256 <64-lowercase-hex>",
        "global decision-ID uniqueness",
        "never generates a signature",
        "write-once store",
        "email-platform/private-secret-collection-archive-provider/v1",
        "email-platform/private-secret-collection-archive-custody/v1",
        "--expected-prior-checkpoint-sha256 <64-lowercase-hex>",
        "pin the prior verified",
        "head_sha256",
        "at most one prior hop",
        "provider-native authentication, trusted time",
        "offline `gh attestation verify`",
        "sealed `memfd`",
        "never asks `gh` to reopen the original paths",
        "immutable owner/repository IDs",
        "job-binding=unverified",
        "rest-snapshot=unverified",
        "two distinct Ed25519 public-key anchors",
        "--expected-cluster-fingerprint-sha256 <64-lowercase-hex>",
        "authenticated-external-signer-assertion",
        "provider-receipt-authenticated=true",
        "do not independently prove",
        "no result opens `not_committed`",
        "production_acceptance=false",
    ],
    "migration-rollout.md": [
        "verify_migration_compatibility.py",
        "0017_mail_token_hash_unique",
        "reviewed_expansions",
        "version N",
        "N+1",
        "Do not use Alembic downgrade",
        "contract migrations",
        "production_acceptance=false",
        "static preflight only",
    ],
    "container-release.md": [
        "sha-${GITHUB_SHA}",
        "Push scanned staging digest",
        "aggregate promotion job",
        "performs a read-only preflight",
        "publish all three verified",
        "verified digest",
        "Runs for the same Git ref are serialized",
        "rejects a tag",
        "inspection errors fail",
        "cross-repository transaction",
        "must not exist",
        "signed digest",
        "verify_container_supply_chain.py",
        "production_acceptance=false",
    ],
    "container-logs.md": [
        "verify_container_logging.py",
        "json-file",
        "max-size: \"10m\"",
        "max-file: \"5\"",
        "11 non-Vault services",
        "exactly `vault-dev`",
        "HostConfig.LogConfig",
        "no more than five",
        "550 MiB",
        "not a whole-host capacity guarantee",
        "not replace platform database audit events",
        "production_acceptance=false",
    ],
    "deploy.md": [
        "python -m scripts.deploy_release plan",
        "python -m scripts.deploy_release execute",
        "POSTGRES_IMAGE_SHA256",
        "REDIS_IMAGE_SHA256",
        "KEYCLOAK_IMAGE_SHA256",
        "PROMETHEUS_IMAGE_SHA256",
        "ALERTMANAGER_IMAGE_SHA256",
        "docker compose --project-directory (Resolve-Path .).Path --env-file (Resolve-Path .\\.env).Path --project-name email-platform --file (Resolve-Path .\\docker-compose.yml).Path",
        "third-party image digest injection is incomplete",
        "profile must remain exactly `vault-dev`",
        "prove only fail-closed digest injection",
        "--container-manifest-sha256",
        "--confirm-release-tag",
        "--rollback-container-manifest",
        "--rollback-backup-dir",
        "--rollback-key-file",
        "exact `HEAD` equals the manifest",
        "tracked index and worktree must be clean",
        "source archive without `.git` is not supported",
        "Remove `COMPOSE_FILE`",
        "Remove `DOCKER_HOST`, `DOCKER_CONTEXT`, and `DOCKER_CONFIG`",
        "docker context show",
        "docker context inspect",
        "does not mean the executor has validated or pinned the real Docker daemon",
        "socket ACL",
        "remote TLS/mTLS",
        "absolute production Compose file",
        "Before Cosign, image pull, or any Docker Compose command",
        "without printing drifted paths or content",
        "authenticated schema-v5",
        "both encrypted database artifacts",
        "python -m scripts.redis_maintenance backup-release",
        "python -m scripts.redis_maintenance verify-release",
        "same recovery set",
        "--rollback-redis-backup-dir",
        "--rollback-recovery-set",
        "one-hour/five-minute freshness",
        "Before any target image pull",
        "PostgreSQL, Redis, Keycloak, API, both workers, Web, `edge`, Prometheus, and Alertmanager",
        "performs no Compose stop or up operation",
        "never includes the backup key or its path",
        "Cosign",
        "SPDX SBOM attestation",
        "GitHub build provenance",
        "--no-build --pull never",
        "internal TLS smoke",
        "https://api:8443/readyz",
        "https://web:8443/",
        "https://keycloak:9000/health/ready",
        "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        "https://worker-mail:9101/metrics",
        "https://worker-sub2:9102/metrics",
        "https://prometheus:9090/-/ready",
        "Alertmanager repository gate proves only",
        "HTTP 200",
        "redirect",
        "TLS 1.2 minimum",
        "Start `edge` last",
        "leaves `edge` stopped",
        "production_acceptance=false",
        "rolling_release=false",
        "not** a rolling or",
        "fallback for these five services",
    ],
    "dependency-audit.md": [
        "pip-audit -r platform/requirements.txt",
        "pip-audit -r platform/requirements-test.txt",
        "pip-audit -r requirements-desktop-build.txt",
        "npm audit --audit-level=high --include=prod --include=dev --include=optional --include=peer",
        "--omit=dev",
        "continue-on-error",
        "full frontend dependency audit results",
        "does not query live vulnerability databases",
        "production_acceptance=false",
    ],
    "ci-token-hygiene.md": [
        "GITHUB_TOKEN",
        "persist-credentials: false",
        "YAML boolean",
        "verify_ci_workflow.py",
        "verify_security_workflow.py",
        "verify_release_workflow.py",
        "minimum token explicitly in that single step",
        "does not prove GitHub organization rules",
        "production_acceptance=false",
    ],
    "alert-delivery.md": [
        "--production-alertmanager-config",
        "absolute path",
        "severity=\"page\"",
        "severity=\"watchdog\"",
        "Put it first",
        "dedicated receiver distinct from",
        "group_interval",
        "repeat_interval",
        "no longer than `2m`",
        "send_resolved: true",
        "create_host_path=false",
        "static-validation-only",
        "receiver-generated delivery IDs",
        "three consecutive watchdog deliveries",
        "missed-heartbeat alarm",
        "Alertmanager silence",
        "confirm watchdog deliveries resume",
        "does not prove external delivery",
        "production_acceptance=false",
    ],
    "rollback.md": [
        "python -m scripts.rollback_release plan",
        "python -m scripts.rollback_release execute",
        "--confirm-release-tag",
        "exact `HEAD` equals that manifest's commit",
        "Source archives without `.git` are not supported",
        "Clear `COMPOSE_FILE`",
        "Remove `DOCKER_HOST`, `DOCKER_CONTEXT`, and `DOCKER_CONFIG`",
        "docker context show",
        "docker context inspect",
        "does not mean the executor has validated or pinned the real Docker daemon",
        "socket ACL",
        "remote TLS/mTLS",
        "absolute, repository-external",
        "must not already exist",
        "pins the absolute production `docker-compose.yml`",
        "Before Cosign, image pull, or any Compose command",
        "never includes drifted file names or content",
        "platform + Keycloak",
        "python -m scripts.redis_maintenance backup-release",
        "python -m scripts.redis_maintenance verify-release",
        "python -m scripts.redis_maintenance restore-release",
        "same recovery set",
        "PostgreSQL manifest SHA-256",
        "DBSIZE",
        "PTTL",
        "expired key must not reappear",
        "Cosign",
        "--no-build --pull never",
        "edge` last",
        "https://api:8443/readyz",
        "https://web:8443/",
        "https://keycloak:9000/health/ready",
        "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        "https://worker-mail:9101/metrics",
        "https://worker-sub2:9102/metrics",
        "https://prometheus:9090/-/ready",
        "Alertmanager repository gate proves only",
        "/run/secrets/internal-tls/ca.crt",
        "TLS 1.2 minimum",
        "HTTP 200",
        "redirect",
        "authenticated encrypted schema-v5",
        "manifest MAC",
        "HKDF-SHA256",
        "production_acceptance=false",
    ],
    "role-training.md": [
        "operator_session_token_loss",
        "unknown_upload_no_blind_retry",
        "alert_triage_and_audit_replay",
        "device_revocation",
        "backup_rollback_go_no_go",
        "production_acceptance=false",
    ],
    "device-revocation.md": ["/api/v1/admin/devices/{device_id}/revoke", "device.revoked"],
    "key-rotation.md": ["verify_runtime_secrets.py"],
    "incident-response.md": ["PlatformUnknownUploadsPresent", "reconcile"],
}
INTERNAL_TLS_RESIDUE_REQUIRED = (
    "one dedicated, repository-external protected runtime root",
    "EMAIL_PLATFORM_PRIVATE_SECRET_RUNTIME_ROOT",
    "containing exactly `secret`, `claim.json` and `lease`",
    "integrity-sealed claim binds the claim ID",
    "It is an integrity record, not a signature",
    "POSIX `flock` or a Windows no-share handle",
    "Legacy `email-platform-secret-*` directories outside this root remain unowned `unknown` incidents",
    "independent inventory and cleanup tool implements exactly this two-step operator sequence",
    "python scripts/private_secret_residue.py inventory --output <new-write-once-inventory.json>",
    "python scripts/private_secret_residue.py cleanup --inventory <reviewed-inventory.json> --expected-payload-sha256 <64-lowercase-hex> --claim-id <opaque-claim-id> --confirm-residue-cleanup",
    "holding the same release-control lock used by rotation",
    "exactly one of `active`, `cleanup_candidate` or `unknown`",
    "external write-once artifact followed by stable readback",
    "contains no root or secret path, source digest or secret bytes",
    "Age, directory name and PID are never ownership or cleanup signals.",
    "human approval for exactly one reviewed `cleanup_candidate` claim",
    "revalidate the sealed claim, lease state, root/directory/leaf identity, owner, type, link count, POSIX mode or Windows ACL/FileId, and payload SHA-256 immediately before",
    "returns exit `1` with the fixed redacted stderr line",
    "The target-host scheduler or monitor must convert that nonzero result into an operator alert",
    "this repository does not prove that such an alert route is installed",
    "must not use glob, `rglob`, `shutil.rmtree`, `--all`, `--force`, age thresholds or PID-liveness heuristics",
    "It is not secure erasure",
    "configured to execute the POSIX materializer/residue and fake-runner Kubernetes boundary suites on GitHub `ubuntu-24.04`",
    "repository configuration and local Windows tests do not prove that a remote run has occurred",
    "A successful GitHub run proves only the exercised runner filesystem behavior and fake-runner exact-argv contract",
    "Real target-host kubectl and crash evidence remain pending and separately reviewed; `production_acceptance=false`.",
    "`github_actions_linux_ci` and `kubernetes_target_host`",
    "--expected-commit <40-lowercase-hex> --expected-workflow-sha256 <64-lowercase-hex>",
    "--target-inventory <external-reviewed-target-platform-inventory.json>",
    "every unrelated record remains unchanged",
    "The Linux scope cannot contain or satisfy target-host inventory or alert facts.",
    "distinct strings do not prove IAM separation",
    "origin-authentication=unverified",
    "it is not proof that a GitHub run, real kubectl",
)
INTERNAL_TLS_RESIDUE_FORBIDDEN = (
    "production_acceptance=true",
    "GitHub Ubuntu evidence proves target-host",
    "all crash residue is securely erased",
    "cleanup every residue automatically",
)
ROLLBACK_FORBIDDEN = (
    "scripts.postgres_maintenance restore --input",
    "scripts.release_manifest verify",
    "127.0.0.1:8000",
    "127.0.0.1:9101",
    "127.0.0.1:9102",
    "Rebuild or pull",
)
RESTORE_FORBIDDEN = (
    "http://",
    "127.0.0.1",
    ":8000",
    "CERT_NONE",
    "check_hostname=False",
    "_create_unverified_context",
)
RESTORE_PRODUCTION_COMPOSE_PREFIX = (
    "docker compose --project-directory $projectDirectory --env-file $envFile "
    "--project-name email-platform --file $composeFile"
)
RESTORE_PRODUCTION_COMPOSE_INITIALIZATION = (
    '$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"\n'
    "$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path\n"
    '$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path\n'
    '$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path'
)
RESTORE_COMPOSE_SUFFIXES = (
    "stop edge api worker-mail worker-sub2 web keycloak redis",
    "up -d --no-build --pull never redis",
    "ps redis",
    "up -d --no-build --pull never keycloak migrate api worker-mail worker-sub2 web",
    "up -d --no-build --pull never edge",
)
REDIS_COMMAND_FORBIDDEN = (
    "REDISCLI_AUTH=",
    "--password ",
    "--pass ",
    "redis-cli -a ",
    "redis://:",
    "redis-cli PING",
)
REDIS_PATH_ARGUMENTS = (
    "--output-dir",
    "--input-dir",
    "--key-file",
    "--redis-url-file",
    "--postgres-manifest",
)
REDIS_BINDING_ARGUMENTS = (
    "--release-tag",
    "--release-commit",
    "--migration-head",
    "--container-manifest-sha256",
    "--recovery-set",
    "--postgres-manifest-sha256",
)
INCIDENT_RESPONSE_REQUIRED = (
    "https://prometheus:9090/-/ready",
    "https://prometheus:9090/api/v1/alerts",
    "--cacert $internalCa",
    "--resolve prometheus:9090:127.0.0.1",
    "--tlsv1.2",
    "security_auditor",
    "ops_admin",
    "platform_admin",
    "exact upload ID, task ID, business name, trace ID",
    "row whose upload ID, task ID, business name",
    "status=succeeded",
    "external_ref",
    "status=failed",
    "error_code",
    "upload.reconciled",
    "response is missing or ambiguous",
    "refresh the same upload first",
    "Do not replay reconciliation",
    "Never create a new idempotency key",
)
INCIDENT_RESPONSE_FORBIDDEN = (
    "http://",
    "127.0.0.1:8000",
    ":8000",
)
KEY_ROTATION_REQUIRED = (
    "Rotate exactly one credential class per maintenance change",
    "Do not continue to another class",
    "| Platform database DML | Existing PostgreSQL role named by `POSTGRES_APP_USER` | `POSTGRES_APP_PASSWORD_FILE`, `PLATFORM_DATABASE_URL_FILE` | `api`, `worker-mail`, `worker-sub2` |",
    "| Migration/database owner | Existing PostgreSQL role named by `POSTGRES_USER` | `POSTGRES_PASSWORD_FILE`, `PLATFORM_MIGRATION_DATABASE_URL_FILE` | one-off `migrate` |",
    "| Keycloak database | Existing PostgreSQL role named by `KEYCLOAK_DB_USER` | `KEYCLOAK_DB_PASSWORD_FILE`, `KEYCLOAK_CONFIG_FILE` | `keycloak` |",
    "| Redis application ACL | Application user in `REDIS_ACL_FILE` | `REDIS_ACL_FILE`, `PLATFORM_REDIS_URL_FILE` | `redis`, `api`, `worker-sub2` |",
    "| Redis healthcheck ACL | `healthcheck` user in `REDIS_ACL_FILE` | `REDIS_ACL_FILE`, `REDIS_HEALTHCHECK_PASSWORD_FILE` | `redis` |",
    "| Keycloak active administrator | Active administrator credential in Keycloak | Remove or update bootstrap entries in `KEYCLOAK_CONFIG_FILE`; bootstrap values do not rotate an existing administrator | `keycloak` administration sessions |",
    "| API Vault token | Short-lived service token from `email-platform-api-cards` | `PLATFORM_VAULT_API_TOKEN_DIR/token` | `api` |",
    "| Mail Vault token | Short-lived service token from `email-platform-mail` | `PLATFORM_VAULT_MAIL_TOKEN_DIR/token` | `worker-mail` |",
    "| Sub2 Vault token | Short-lived service token from `email-platform-sub2` | `PLATFORM_VAULT_SUB2_TOKEN_DIR/token` | `worker-sub2` |",
    "POSTGRES_APP_PASSWORD_FILE",
    "PLATFORM_DATABASE_URL_FILE",
    "POSTGRES_PASSWORD_FILE",
    "PLATFORM_MIGRATION_DATABASE_URL_FILE",
    "KEYCLOAK_DB_PASSWORD_FILE",
    "KEYCLOAK_CONFIG_FILE",
    "REDIS_ACL_FILE",
    "PLATFORM_REDIS_URL_FILE",
    "REDIS_HEALTHCHECK_PASSWORD_FILE",
    "PLATFORM_VAULT_API_TOKEN_DIR/token",
    "PLATFORM_VAULT_MAIL_TOKEN_DIR/token",
    "PLATFORM_VAULT_SUB2_TOKEN_DIR/token",
    "Existing PostgreSQL volumes must use a controlled `ALTER ROLE`",
    "PostgreSQL initialization scripts are not a rotation mechanism",
    "Stopping edge is the first runtime mutation",
    "Stop only the exact consumers",
    "Change the backing credential",
    "atomically replace every coupled file",
    "one indivisible change",
    "Restart only the consumers named in the selected row",
    "--no-build --pull never",
    "python -m scripts.restore_readiness",
    "Prove the new credential succeeds",
    "Revoke the old credential",
    "RoleID is a role selector",
    "SecretID is a one-use login input",
    "Only an independent approved rotator",
    "auth/token/revoke-accessor",
    "never record a Vault token-sink SHA-256 value",
    "never restore a revoked token or a consumed SecretID",
    "Prove the old credential fails",
    "Create redacted evidence only after both authentication proofs pass",
    "Start edge last only after strict readiness",
    "Any partial rotation is a failed change",
    "Keep edge stopped",
    "production_acceptance=false",
)
KEY_ROTATION_FORBIDDEN = (
    "http://",
    "127.0.0.1:8000",
    ":8000",
    "docker-compose ",
    "docker-entrypoint-initdb.d",
    "docker compose up -d postgres redis keycloak api worker-mail worker-sub2 web",
)
KEY_ROTATION_INLINE_SECRET_PATTERNS = (
    r"(?<![A-Z0-9_])POSTGRES_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])POSTGRES_APP_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])KEYCLOAK_DB_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])REDIS_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])REDIS_HEALTHCHECK_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])KEYCLOAK_ADMIN_PASSWORD(?!_FILE)",
    r"(?<![A-Z0-9_])PLATFORM_DATABASE_URL(?!_FILE)",
    r"(?<![A-Z0-9_])PLATFORM_MIGRATION_DATABASE_URL(?!_FILE)",
    r"(?<![A-Z0-9_])PLATFORM_REDIS_URL(?!_FILE)",
    r"(?<![A-Z0-9_])PLATFORM_JWT_HMAC_SECRET(?!_FILE)",
)
KEY_ROTATION_DOCKER_ENVIRONMENT_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)
KEY_ROTATION_DOCKER_ENVIRONMENT_GATE = """$forbiddenDockerEnvironment = @(
  "DOCKER_HOST",
  "DOCKER_CONTEXT",
  "DOCKER_CONFIG",
  "DOCKER_TLS",
  "DOCKER_TLS_VERIFY",
  "DOCKER_CERT_PATH"
)
$presentDockerEnvironment = @(
  $forbiddenDockerEnvironment | Where-Object {
    Test-Path -LiteralPath "Env:$_"
  }
)
if ($presentDockerEnvironment.Count -ne 0) {
  throw "production credential rotation Docker environment preflight failed"
}"""
KEY_ROTATION_PRODUCTION_COMPOSE_INITIALIZATION = """$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"
$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path
$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path
$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path
$dockerContext = docker context show
docker context inspect $dockerContext"""
KEY_ROTATION_PRODUCTION_COMPOSE_PREFIX = (
    "docker compose --project-directory $projectDirectory --env-file $envFile "
    "--project-name email-platform --file $composeFile"
)
KEY_ROTATION_PRODUCTION_COMPOSE_SUFFIXES = (
    "config --quiet",
    "stop edge",
    "ps edge",
    "stop $consumers",
    "up -d --no-build --pull never $consumers",
    "up -d --no-build --pull never edge",
)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def internal_tls_runbook_errors(text: str) -> list[str]:
    """Require the bounded crash-residue policy without target-runtime overclaims."""

    normalized_text = " ".join(text.split())
    errors = [
        f"internal TLS runbook is missing residue control: {needle}"
        for needle in INTERNAL_TLS_RESIDUE_REQUIRED
        if needle not in normalized_text
    ]
    errors.extend(
        f"internal TLS runbook contains residue overclaim: {phrase}"
        for phrase in INTERNAL_TLS_RESIDUE_FORBIDDEN
        if phrase in normalized_text
    )
    return errors


def release_environment_runbook_errors(text: str, *, label: str) -> list[str]:
    """Require the operator guidance that matches the executor environment boundary."""

    normalized_text = " ".join(text.split())
    return [
        f"{label} runbook is missing release environment control: {needle}"
        for needle in RELEASE_ENVIRONMENT_REQUIRED
        if needle not in normalized_text
    ]


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
    errors.extend(release_environment_runbook_errors(text, label="rollback"))
    return errors


def restore_runbook_errors(text: str) -> list[str]:
    errors = [
        f"restore runbook is missing: {needle}"
        for needle in RUNBOOKS["restore.md"]
        if needle not in text
    ]
    errors.extend(
        f"restore runbook contains obsolete control: {needle}"
        for needle in RESTORE_FORBIDDEN
        if needle in text
    )
    if RESTORE_PRODUCTION_COMPOSE_INITIALIZATION not in text:
        errors.append(
            "restore runbook must resolve the reviewed production install root once"
        )
    if "Resolve-Path ." in text:
        errors.append(
            "restore runbook must not resolve Compose identity from the caller working directory"
        )
    readiness = text.find("python -m scripts.restore_readiness")
    edge_start = text.find(
        f"{RESTORE_PRODUCTION_COMPOSE_PREFIX} {RESTORE_COMPOSE_SUFFIXES[-1]}"
    )
    if readiness < 0 or edge_start < 0 or edge_start < readiness:
        errors.append("restore readiness must succeed before edge starts")
    errors.extend(redis_recovery_runbook_errors({"restore.md": text}))
    return errors


def _ordered_markers_error(text: str, markers: tuple[str, ...], label: str) -> str | None:
    positions = [text.find(marker) for marker in markers]
    if any(position < 0 for position in positions):
        return None
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        return f"{label} order is unsafe"
    return None


def key_rotation_runbook_errors(text: str) -> list[str]:
    """Reject stale or non-atomic production credential-rotation guidance."""

    normalized_text = " ".join(text.split())
    errors = [
        f"key rotation runbook is missing: {needle}"
        for needle in (*RUNBOOKS["key-rotation.md"], *KEY_ROTATION_REQUIRED)
        if needle not in normalized_text
    ]
    errors.extend(
        f"key rotation runbook contains unsafe control: {needle}"
        for needle in KEY_ROTATION_FORBIDDEN
        if needle.lower() in text.lower()
    )
    errors.extend(
        f"key rotation runbook contains inline secret setting: {pattern}"
        for pattern in KEY_ROTATION_INLINE_SECRET_PATTERNS
        if re.search(pattern, text)
    )

    gate_position = text.find(KEY_ROTATION_DOCKER_ENVIRONMENT_GATE)
    initialization_position = text.find(
        KEY_ROTATION_PRODUCTION_COMPOSE_INITIALIZATION
    )
    if gate_position < 0:
        errors.append(
            "key rotation must reject exactly the reviewed Docker environment variables by presence"
        )
    if initialization_position < 0:
        errors.append(
            "key rotation must resolve Compose identity from the reviewed production install root"
        )
    if any(text.count(f'"{name}"') != 1 for name in KEY_ROTATION_DOCKER_ENVIRONMENT_VARIABLES):
        errors.append("key rotation Docker environment inventory must contain exactly six keys")
    if "Resolve-Path ." in text:
        errors.append("key rotation Compose identity must not depend on caller cwd")

    docker_behavior_positions: list[int] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip().lower()
        if stripped.startswith("docker ") or "= docker context " in stripped:
            docker_behavior_positions.append(offset)
        offset += len(line)
    if (
        gate_position < 0
        or initialization_position < 0
        or gate_position > initialization_position
        or (
            docker_behavior_positions
            and gate_position > min(docker_behavior_positions)
        )
    ):
        errors.append("key rotation Docker environment gate must precede all Docker behavior")

    compose_commands = tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip().lower().startswith("docker compose")
    )
    expected_compose_commands = tuple(
        f"{KEY_ROTATION_PRODUCTION_COMPOSE_PREFIX} {suffix}"
        for suffix in KEY_ROTATION_PRODUCTION_COMPOSE_SUFFIXES
    )
    if not compose_commands:
        errors.append("key rotation runbook has no pinned Compose commands")
    elif compose_commands != expected_compose_commands:
        errors.append(
            "every key rotation Compose command must use the exact production identity"
        )
    mutating_commands: list[str] = []
    managed_services = {
        "postgres",
        "redis",
        "keycloak",
        "migrate",
        "api",
        "worker-mail",
        "worker-sub2",
        "web",
        "edge",
    }
    for command in compose_commands:
        if not command.startswith(f"{KEY_ROTATION_PRODUCTION_COMPOSE_PREFIX} "):
            errors.append("every key rotation Compose command must pin the production identity")
        lowered = f" {command.lower()} "
        is_mutating = any(
            marker in lowered
            for marker in (" stop ", " up ", " restart ", " run ", " kill ", " rm ", " down ")
        )
        if is_mutating:
            mutating_commands.append(command)
        if " up " in lowered and "--no-build --pull never" not in command:
            errors.append("every key rotation Compose up must forbid builds and pulls")
        services = managed_services.intersection(command.split())
        if is_mutating and len(services) >= 4:
            errors.append("key rotation must not batch-mutate unrelated services")
    if not mutating_commands or not mutating_commands[0].endswith("stop edge"):
        errors.append("stopping edge must be the first mutating Compose command")

    order_error = _ordered_markers_error(
        text,
        (
            expected_compose_commands[1],
            "Change the backing credential",
            "atomically replace every coupled file",
            expected_compose_commands[4],
            "python -m scripts.restore_readiness",
            "Prove the new credential succeeds",
            "Revoke the old credential",
            "Prove the old credential fails",
            "Create redacted evidence only after both authentication proofs pass",
            "Start edge last only after strict readiness",
            expected_compose_commands[5],
        ),
        "key rotation cutover",
    )
    if order_error:
        errors.append(order_error)
    return errors


def incident_response_runbook_errors(text: str) -> list[str]:
    """Reject incident guidance that bypasses TLS or permits blind reconciliation."""

    normalized_text = " ".join(text.split())
    errors = [
        f"incident response runbook is missing: {needle}"
        for needle in (*RUNBOOKS["incident-response.md"], *INCIDENT_RESPONSE_REQUIRED)
        if needle not in normalized_text
    ]
    errors.extend(
        f"incident response runbook contains unsafe control: {needle}"
        for needle in INCIDENT_RESPONSE_FORBIDDEN
        if needle in text
    )
    lines = text.splitlines()
    curl_blocks: list[str] = []
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index].strip()
        if not line.lower().startswith("curl.exe"):
            line_index += 1
            continue
        block_lines = [line]
        while block_lines[-1].rstrip().endswith("`") and line_index + 1 < len(lines):
            line_index += 1
            block_lines.append(lines[line_index].strip())
        curl_blocks.append(" ".join(block_lines))
        line_index += 1

    prometheus_blocks = [
        block for block in curl_blocks if "prometheus:9090" in block
    ]
    if len(prometheus_blocks) != 2:
        errors.append("incident response runbook must contain two Prometheus TLS probes")
    for block in prometheus_blocks:
        for control in (
            "--cacert $internalCa",
            "--resolve prometheus:9090:127.0.0.1",
            "--tlsv1.2",
            "https://prometheus:9090/",
        ):
            if control not in block:
                errors.append(
                    f"incident response Prometheus command is missing: {control}"
                )
        lowered_block = block.lower()
        if "--insecure" in lowered_block or " -k" in lowered_block:
            errors.append("incident response Prometheus command disables TLS verification")
    for line in text.splitlines():
        normalized = line.strip().lower()
        if "curl" in normalized and (
            "/admin/audit" in normalized or "/reconcile" in normalized
        ):
            errors.append(
                "incident response runbook must use the authenticated Web control "
                "plane for audit and reconciliation"
            )
    order_error = _ordered_markers_error(
        text,
        (
            "First confirm the external Sub2 result manually",
            "verify the same immutable identifiers",
            "status=succeeded",
            "After submission, refresh",
            "response is missing or ambiguous",
        ),
        "incident response reconciliation",
    )
    if order_error:
        errors.append(order_error)
    return errors


def redis_recovery_runbook_errors(documents: dict[str, str]) -> list[str]:
    """Reject Redis recovery guidance that can produce an unbound or unsafe restore."""

    errors: list[str] = []
    combined = "\n".join(documents.values())
    for command in ("backup-release", "verify-release", "restore-release"):
        if f"python -m scripts.redis_maintenance {command}" not in combined:
            errors.append(f"Redis recovery guidance is missing {command}")
    for argument in REDIS_BINDING_ARGUMENTS:
        if argument not in combined:
            errors.append(f"Redis recovery guidance is missing binding {argument}")
    for phrase in (
        "absolute, repository-external",
        "must not already exist",
        "same recovery set",
        "PostgreSQL manifest SHA-256",
        "DBSIZE",
        "PTTL",
        "expired key must not reappear",
    ):
        if phrase not in combined:
            errors.append(f"Redis recovery guidance is missing: {phrase}")
    for forbidden in REDIS_COMMAND_FORBIDDEN:
        if forbidden.lower() in combined.lower():
            errors.append(f"Redis recovery guidance contains unsafe command text: {forbidden}")
    lifecycle_phrases = (
        "automatically restarts only a Redis instance that was",
        "/usr/local/bin/redis-healthcheck",
        "Redis restart could not be confirmed` is fatal",
        "do not treat that attempt's",
        "manifest as successful",
    )
    for name, text in documents.items():
        for phrase in lifecycle_phrases:
            if phrase not in text:
                errors.append(
                    f"{name} is missing the Redis backup restart contract: {phrase}"
                )

    redis_command_lines = [
        line.strip()
        for text in documents.values()
        for line in text.splitlines()
        if "scripts.redis_maintenance" in line
    ]
    command_text = "\n".join(redis_command_lines)
    if not ("C:\\" in command_text or "D:\\" in command_text or "/" in command_text):
        errors.append("Redis recovery commands do not show absolute external inputs")
    for argument in REDIS_PATH_ARGUMENTS:
        for line in redis_command_lines:
            if argument not in line:
                continue
            suffix = line.split(argument, 1)[1].lstrip()
            if suffix.startswith((".\\", "./", "deploy/", "release/", "$PWD", "${PWD}")):
                errors.append(f"Redis recovery command uses a relative/repository path for {argument}")

    restore = documents.get("restore.md")
    if restore is not None:
        expected_compose_commands = tuple(
            f"{RESTORE_PRODUCTION_COMPOSE_PREFIX} {suffix}"
            for suffix in RESTORE_COMPOSE_SUFFIXES
        )
        compose_commands = tuple(
            line.strip()
            for line in restore.splitlines()
            if line.strip().startswith("docker compose ")
        )
        if compose_commands != expected_compose_commands:
            errors.append(
                "Redis/PostgreSQL restore must pin every Compose command to the reviewed production identity"
            )
        for command in compose_commands:
            if not command.startswith(f"{RESTORE_PRODUCTION_COMPOSE_PREFIX} "):
                errors.append(
                    "Redis/PostgreSQL restore contains a Compose command without the production identity"
                )
        order_error = _ordered_markers_error(
            restore,
            (
                "python -m scripts.postgres_maintenance verify-bundle",
                "python -m scripts.redis_maintenance verify-release",
                expected_compose_commands[0],
                "python -m scripts.postgres_maintenance restore-bundle",
                "python -m scripts.redis_maintenance restore-release",
                expected_compose_commands[1],
                expected_compose_commands[2],
                "DBSIZE",
                "PTTL",
                expected_compose_commands[3],
                "python -m scripts.restore_readiness",
                expected_compose_commands[4],
            ),
            "Redis/PostgreSQL restore",
        )
        if order_error:
            errors.append(order_error)
    return errors


def deploy_recovery_creation_errors(text: str) -> list[str]:
    """Require one executable, release-bound recovery-set creation sequence."""

    errors: list[str] = []
    section_marker = "## Create and authenticate the current rollback recovery set"
    if section_marker not in text:
        return ["deploy recovery-set creation section is missing"]
    section = text.split(section_marker, 1)[1].split("\n## ", 1)[0]
    postgres_prefix = "python -m scripts.postgres_maintenance backup-bundle"
    redis_backup = "python -m scripts.redis_maintenance backup-release"
    redis_verify = "python -m scripts.redis_maintenance verify-release"
    postgres_lines = [
        line.strip() for line in section.splitlines() if postgres_prefix in line
    ]
    if len(postgres_lines) != 1:
        errors.append("deploy recovery guidance must contain one PostgreSQL backup-bundle command")
        return errors

    required_arguments = (
        "--output-dir",
        "--key-file",
        "--platform-db",
        "--keycloak-db",
        "--release-tag",
        "--release-commit",
        "--migration-head",
        "--container-manifest-sha256",
    )
    if any(argument not in postgres_lines[0] for argument in required_arguments):
        errors.append("deploy PostgreSQL backup-bundle command is missing release binding")

    postgres_index = section.find(postgres_prefix)
    redis_backup_index = section.find(redis_backup)
    redis_verify_index = section.find(redis_verify)
    if not (
        postgres_index >= 0
        and redis_backup_index > postgres_index
        and redis_verify_index > redis_backup_index
    ):
        errors.append(
            "deploy recovery creation must order PostgreSQL backup before Redis backup and verification"
        )
    return errors


def main() -> int:
    base = ROOT / "deploy" / "runbooks"
    if not base.exists():
        return _fail("Missing deploy/runbooks directory")
    documents: dict[str, str] = {}
    for filename, needles in RUNBOOKS.items():
        path = base / filename
        if not path.exists():
            return _fail(f"Missing runbook: {filename}")
        try:
            text = load_stable_text(
                path,
                max_bytes=MAX_RUNBOOK_BYTES,
            )
        except (OSError, UnicodeError):
            return _fail("Unable to load operational runbooks")
        documents[filename] = text
        if filename == "restore.md":
            errors = restore_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
            continue
        if filename == "rollback.md":
            errors = rollback_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
            continue
        if filename == "incident-response.md":
            errors = incident_response_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
            continue
        if filename == "key-rotation.md":
            errors = key_rotation_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
            continue
        if filename == "internal-tls.md":
            errors = internal_tls_runbook_errors(text)
            if errors:
                return _fail("; ".join(errors))
        if filename == "deploy.md":
            errors = deploy_recovery_creation_errors(text)
            errors.extend(release_environment_runbook_errors(text, label="deploy"))
            if errors:
                return _fail("; ".join(errors))
        for needle in needles:
            if needle not in text:
                return _fail(f"Runbook {filename} is missing: {needle}")
    redis_errors = redis_recovery_runbook_errors(
        {
            filename: documents[filename]
            for filename in ("restore.md", "rollback.md", "deploy.md")
        }
    )
    if redis_errors:
        return _fail("; ".join(redis_errors))
    index = base / "README.md"
    if not index.exists():
        return _fail("Missing runbook index")
    print("runbooks-ok operational-guides-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
