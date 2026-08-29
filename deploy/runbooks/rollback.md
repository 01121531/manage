# Release-bound rollback runbook

Use this procedure to return to a previously released application version and
the platform + Keycloak PostgreSQL state and Redis persistence captured in the
same recovery set. This is not a cross-database transaction: safety comes from
authenticating both release-bound artifacts before any restore, matching the
exact PostgreSQL manifest SHA-256, stopping all writers, and keeping the public
edge closed until every restore and internal check succeeds.

## Required inputs

- The previous GitHub Release `container-release-manifest.json`.
- A Git checkout with `.git` metadata whose exact `HEAD` equals that manifest's commit
  and whose tracked index/worktree are clean. Source archives without `.git` are not supported
  by this procedure.
- An authenticated encrypted schema-v5 backup directory containing `platform.dump.enc`,
  `keycloak.dump.enc`, and `manifest.json`, created for that exact release.
- An authenticated Redis schema-1 directory containing `redis-data.tar.enc` and
  `redis-manifest.json`, bound to the same release fields, recovery-set ID, and
  PostgreSQL manifest SHA-256.
- The matching absolute-path 32-byte AES-256-GCM key file, stored separately
  with inherited ACLs disabled and access limited to the operator, SYSTEM, and
  local Administrators.
- `docker`, `cosign`, `gh`, and Python on the deployment host.
- Production `.env`, Compose secrets, and TLS files already provisioned outside
  Git. Independently verify that `.env` is a regular, non-symlink file with the
  intended owner, restrictive permissions, reviewed content, and readable
  secret-file targets on the deployment host; the repository gate cannot prove
  those target-host facts.
- The public Edge certificate and key settings in the fixed `.env` resolve to
  distinct, absolute, repository-external, non-symlink regular files. Validate
  the current non-CA leaf, exact platform-domain DNS SAN, and matching
  unencrypted PEM key before reviewing the rollback plan:

  ```powershell
  python scripts/validate_edge_tls.py --env-file (Resolve-Path .\.env).Path --domain platform.example.com
  ```

`deploy/release-manifest.json` is only a source-tree consistency snapshot. It
contains local development defaults and must never be used as the rollback
image lock.

Clear `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`, `COMPOSE_PROFILES`, and
`COMPOSE_ENV_FILES`, and remove all default Compose override files before the
plan: `compose.override.yaml`, `compose.override.yml`,
`docker-compose.override.yaml`, and `docker-compose.override.yml`. Apart from
the five reviewed dependency digest fragments, do not export any variable
interpolated by the production Compose file. The executor rejects such
process-level overrides, injects the three application images from the
authenticated manifest, and pins the absolute production `docker-compose.yml`,
absolute `.env`, repository project directory, and project name
`email-platform` for every Compose invocation.

Remove `DOCKER_HOST`, `DOCKER_CONTEXT`, and `DOCKER_CONFIG` too. Also remove
`DOCKER_TLS`, `DOCKER_TLS_VERIFY`, and `DOCKER_CERT_PATH`, including variables
exported with an empty value; the executor rejects their presence before
checkout or any command runner access:

```powershell
"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", `
    "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH" | ForEach-Object {
    Remove-Item "Env:$_" -ErrorAction SilentlyContinue
}
$dockerContext = docker context show
docker context inspect $dockerContext
```

Record the exact context name and reviewed endpoint in the target-environment
evidence. This operator evidence does not mean the executor has validated or pinned the real Docker daemon.
It also does not establish the real daemon's TLS identity. The real endpoint
and host identity, local socket ACL, and remote TLS/mTLS identity remain
target-environment production acceptance checks; repository and mocked tests
remain `production_acceptance=false`.

Run the executor only from a clean shell owned by a dedicated production
deployment account. The executor rejects the presence, including an empty
value, of known plaintext runtime credentials: `VAULT_TOKEN`, every
`PLATFORM_VAULT_*_TOKEN` and `PLATFORM_VAULT_*_SECRET_ID`,
`VAULT_DEV_ROOT_TOKEN_ID`, `ALEMBIC_DATABASE_URL`,
`PLATFORM_MIGRATION_DATABASE_URL`, `PLATFORM_DATABASE_URL`,
`PLATFORM_REDIS_URL`, the PostgreSQL and Keycloak password variables,
`REDIS_PASSWORD`, `REDIS_HEALTHCHECK_PASSWORD`, `REDISCLI_AUTH`, and
`PGPASSWORD`. Keep those values in the reviewed external secret-file and
broker paths; do not export them to run deployment or rollback.

Every Git, Cosign, GitHub CLI, Trivy, Docker, Compose, restore, and smoke-test
process receives an explicit environment rebuilt from only the reviewed OS
locator variables (`PATH`, `PATHEXT`, `SYSTEMROOT`, `WINDIR`, `COMSPEC`,
temporary/home/profile directories) and the five reviewed third-party digest
fragments. Caller overrides such as `PYTHONPATH`, `PYTHONHOME`, `GIT_*`,
`TRIVY_*`, `COSIGN_*`, `SIGSTORE_*`, proxy variables, and certificate-bundle
variables such as `SSL_CERT_FILE` are not forwarded. `GH_TOKEN` is copied only
to the exact `gh attestation verify` process; it is absent from Git, Cosign,
Trivy, Docker, Compose, restore, and smoke-test processes. Review the dedicated
account's installed binaries, per-user configuration, trust store, filesystem
ACLs, and executable search path on the target host; repository tests cannot
prove those host properties and remain `production_acceptance=false`.


## Create the release-bound backup

Before deploying a new version, bind the current release's dual-database backup
to its immutable container manifest:

```powershell
$containerManifest = "release/assets/container-release-manifest.json"
$release = Get-Content -LiteralPath $containerManifest -Raw | ConvertFrom-Json
$containerManifestSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $containerManifest).Hash.ToLowerInvariant()
$backupDir = "C:\ProgramData\EmailPlatform\backups\$($release.tag)-before-next-deploy"
$redisBackupDir = "C:\ProgramData\EmailPlatform\backups\redis-$($release.tag)-before-next-deploy"
$recoverySet = "$($release.tag)-before-next-deploy"

python -m scripts.postgres_maintenance backup-bundle `
  --output-dir $backupDir `
  --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key `
  --platform-db email_platform `
  --keycloak-db keycloak `
  --release-tag $release.tag `
  --release-commit $release.commit `
  --migration-head $release.migration_head `
  --container-manifest-sha256 $containerManifestSha
python -m scripts.postgres_maintenance verify-bundle --input-dir $backupDir --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key
python -m scripts.redis_maintenance backup-release --output-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy\manifest.json --recovery-set v1.2.3-before-next-deploy
python -m scripts.redis_maintenance verify-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --recovery-set v1.2.3-before-next-deploy
```

`backup-release` stops and automatically restarts only a Redis instance that was
running before the backup. It returns only after the fixed production Compose
project reports Redis running and `/usr/local/bin/redis-healthcheck` passes.
`Redis restart could not be confirmed` is fatal: do not treat that attempt's
manifest as successful or continue the release.

Provision only `C:\ProgramData\EmailPlatform\backups` ahead of time. Both the
PostgreSQL and Redis bundle leaves must be absolute, repository-external paths
and must not already exist, including empty directories. Never retry into or
refresh a prior release bundle; use a new unique leaf. Existing bundles are
preserved without reading a key, starting `pg_dump`, or requesting Redis
persistence, and a failed new attempt removes only its own leaf.

Archive the PostgreSQL files, Redis files, and exact container manifest as one
recovery-set record. Store both encryption keys separately; key values and Redis
passwords must never enter an argument, environment, log, or manifest. Do not
mix ciphertext or manifests from different release artifacts.
Schema v5 derives a dedicated HMAC-SHA256 key with the fixed versioned HKDF-SHA256
domain `email-platform/postgres-backup-manifest/v5/hmac-sha256`. The MAC covers
the exact canonical manifest except the MAC field itself, including schema,
creation time, all release-binding fields, and both complete database entries.

## Validate the rollback plan

Announce a change freeze. A second operator must review the selected tag,
commit, migration head, container-manifest SHA-256, all three OCI digest
references, and the backup directory before execution.

```powershell
python -m scripts.rollback_release plan `
  --container-manifest previous-release/container-release-manifest.json `
  --backup-dir C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy `
  --redis-backup-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy `
  --recovery-set v1.2.3-before-next-deploy `
  --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key
```

The plan is preflight evidence and always reports `production_acceptance=false`.
It rejects mutable tags, legacy plaintext schemas 1/2, generic encrypted schema
v3, unauthenticated release schema v4 with no override, missing Keycloak data,
a missing/wrong manifest MAC, a wrong key, swapped/tampered ciphertext, and any
release/commit/migration/manifest-hash mismatch.

## Execute

The confirmation value must exactly match the reviewed release tag:

```powershell
python -m scripts.rollback_release execute `
  --container-manifest previous-release/container-release-manifest.json `
  --backup-dir C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy `
  --redis-backup-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy `
  --recovery-set v1.2.3-before-next-deploy `
  --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key `
  --confirm-release-tag v1.2.3 `
  --platform-target-db email_platform `
  --keycloak-target-db keycloak `
  --domain platform.example.com `
  --evidence-output C:\ProgramData\EmailPlatform\evidence\rollback-v1.2.3-20260825T010000Z.json
```

The evidence parent directory must already exist outside the repository. The
leaf must be an absolute, new, non-symlink path; an existing target is preserved
and rejected before runner construction or service mutation. Use a new leaf for
every attempt, including a retry after a preflight failure.

The executor enforces this order:

1. Before creating a command runner or invoking Git, Docker, Cosign, or Compose,
   validate the public Edge certificate chain, exact DNS SAN, current validity,
   distinct external paths, and certificate/private-key match from the fixed
   production `.env`. Then validate the fixed three-way Vault sink inventory and
   reviewed Compose bind contract using path, file type, size, ownership/mode
   where POSIX metadata is available, and distinct path/inode metadata only.
   Never read, hash, compare, or log the token values. Any failure is redacted
   and performs no restore or service mutation.
2. Before Cosign, image pull, or any Compose command, require Git `HEAD` to
   equal the rollback manifest commit, require a clean tracked index/worktree,
   and reject Compose control variables, default overrides, caller-shell
   overrides of production Compose inputs other than the five reviewed digest
   fragments, Git absence, or a non-repository checkout. Failure output never includes drifted file names or content,
   and never includes environment values.
3. Revalidate the closed container manifest and release-bound dual-database
   bundle.
4. Run actual Cosign signature/SBOM-attestation and GitHub provenance checks.
5. Pull the three exact `ghcr.io/...@sha256:...` images.
   Before the pull or any restore mutation, require PostgreSQL, Redis, Keycloak,
   API, both workers, Web, `edge`, Prometheus, and Alertmanager to be running.
6. Stop `edge`, API, both workers, Web, Keycloak, and Redis so no writer or Redis
   process can cross the restore boundary. Prometheus and Alertmanager remain
   running.
7. Restore platform + Keycloak, then restore Redis from the same recovery set,
   rechecking both authenticated bindings immediately before mutation. The
   executor's Redis restore is equivalent to this fully bound command:

   ```powershell
   python -m scripts.redis_maintenance restore-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy\manifest.json --recovery-set v1.2.3-before-next-deploy --confirm-release-tag v1.2.3
   ```

8. Start Redis alone. Its container health is necessary but `PING` alone is not
   restore evidence. Before backend startup, record restored `DBSIZE`,
   representative `PTTL` samples, and proof that a pre-backup expired sentinel's
   expired key must not reappear. Counts and TTL semantics must match the
   authenticated backup/drill evidence.
9. Start Keycloak, migration, API, both workers, and Web with
   `--no-build --pull never`; then check running services, internal readiness,
   worker metrics, and each container's actual image digest. Internal smoke uses
   `https://api:8443/readyz`, `https://web:8443/`,
   `https://keycloak:9000/health/ready`,
   `https://keycloak:8443/realms/email-platform/.well-known/openid-configuration`,
   `https://worker-mail:9101/metrics`, `https://worker-sub2:9102/metrics`, and
   `https://prometheus:9090/-/ready` with
   `/run/secrets/internal-tls/ca.crt`, service-DNS hostname verification, and a
   TLS 1.2 minimum. Every probe requires exact HTTP 200 and rejects every
   redirect; it never falls back to HTTP or an unverified TLS context. After all
   probes pass, repeat the Vault sink metadata and Compose-bind check before any
   `edge` start; failure leaves the public edge closed.
10. Start and verify `edge` last, then check external HTTPS API and identity
    discovery with normal certificate validation. Repeat the exact ten-service
    running gate before reporting success.

The Alertmanager repository gate proves only that Compose reports its container
running; the API probe container is not attached to the alerting-only network.
It does not prove Alertmanager readiness, routing, receiver credentials, or live
alert delivery. Validate those in the target environment and keep
`production_acceptance=false` until recorded.

If signature verification or image pull fails, services are never stopped. If
either database restore or any internal check fails, the public edge remains
closed. If the final external smoke test fails, the executor stops edge again.
It never rebuilds an image and never uses Alembic downgrade as recovery.
The repository preflight does not prove public-CA trust, OCSP/revocation state,
container UID readability on Windows hosts, host ACL equivalence to container
identity, absence of a later TOCTOU replacement, token validity/policy, Nginx
reload behavior, or a real client handshake; those remain target-environment
acceptance checks.

Every execution attempt that acquires the release-control lock publishes one
closed-schema terminal ledger with `production_acceptance=false`. The terminal
state is exactly one of `succeeded`, `preflight_failed`,
`edge_closed_failure`, or `edge_unconfirmed`. It contains only release and
recovery-set identifiers, PostgreSQL/Redis manifest SHA-256 values, expected and
observed immutable image digests, fixed phase timestamps and bounded check
counts. It never contains the domain, database names, host paths, commands,
environment values, certificate material, credentials, or raw exception text.
Schema v2 additionally requires the seven internal and two external endpoint
TLS observations on success. The expected and live peer SHA-256 values and the
TLS version come from the same verified socket as the HTTP response; drift or
an unsupported version keeps or restores Edge to the closed state. The ledger
does not claim private-key inode identity and stores no URL, path or PEM bytes.

Independently verify the ledger against all reviewed release inputs and image
digests. Do not infer any value from the ledger itself:

```powershell
python -m scripts.rollback_release_evidence `
  --input C:\ProgramData\EmailPlatform\evidence\rollback-v1.2.3-20260825T010000Z.json `
  --expected-release-tag v1.2.3 `
  --expected-release-commit 0123456789abcdef0123456789abcdef01234567 `
  --expected-migration-head 0018_access_token_revocations `
  --expected-container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --expected-redis-manifest-sha256 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc `
  --expected-recovery-set v1.2.3-before-next-deploy `
  --expected-api-image ghcr.io/example/manage-api@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd `
  --expected-worker-mail-image ghcr.io/example/manage-api@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd `
  --expected-worker-sub2-image ghcr.io/example/manage-api@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd `
  --expected-web-image ghcr.io/example/manage-web@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee `
  --expected-edge-image ghcr.io/example/manage-edge@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

The rollback ledger verifier performs one bounded stable-file read with a
64 KiB limit before parsing. Link/reparse paths, duplicate JSON keys, and any
identity, link-count, size, or modification-state change fail closed without
printing the ledger content.

The canonical payload SHA-256 detects accidental or unreviewed changes but is
not a signature and does not provide non-repudiation. If evidence publication
fails after Edge start, the executor closes Edge and fails; if closure cannot be
confirmed, that `edge_unconfirmed` condition takes precedence over the evidence
publication error. A mocked or repository-local execution remains preflight
only and cannot satisfy production gate 9.

Record start/end UTC times, achieved RTO/RPO, both backup manifest SHA-256
values, recovery-set equality, expected and observed OCI digests,
Cosign/provenance results, dual-database critical row counts, Redis key count and
TTL/expired-key evidence, failure injection result, executor output, and the
independent reviewer in `deploy/production-signoff-template.md`.
