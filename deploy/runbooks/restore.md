# Restore runbook

Use this when PostgreSQL and Redis must be restored from the same latest
known-good recovery set. The PostgreSQL bundle contains the platform and
Keycloak databases; the Redis release artifact is separately encrypted and
authenticated but binds the exact PostgreSQL manifest SHA-256. A realm JSON
import does not replace the Keycloak database backup because it does not contain
the live user state.

Before any backup, restore, drill, verification, or Docker command, remove all
caller-controlled Docker target and TLS overrides, including variables exported
with an empty value. The maintenance CLIs reject their presence rather than
silently choosing a daemon or client certificate:

```powershell
"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", `
    "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH" | ForEach-Object {
    Remove-Item "Env:$_" -ErrorAction SilentlyContinue
}
$dockerContext = docker context show
docker context inspect $dockerContext
$productionInstallRoot = "C:\ProgramData\EmailPlatform\current"
$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path
$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path
$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path
```

Record the exact context name and reviewed endpoint. This environment cleanup,
the static verifier, and `docker context inspect` do not prove the real Docker
daemon or its TLS identity. Independently verify endpoint/host identity, local
socket ACLs, and remote TLS/mTLS before production acceptance; repository
evidence remains `production_acceptance=false`. The fixed install root above
must be the reviewed production installation; never replace it with `.` or
resolve these Compose inputs from the caller's working directory.

1. Select one reviewed release and authenticate every artifact before changing
   services or data. The tag, commit, migration head, container-manifest
   SHA-256, recovery-set ID, and PostgreSQL manifest SHA-256 must match exactly.

   ```powershell
   python -m scripts.postgres_maintenance verify-bundle --input-dir C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key
   python -m scripts.redis_maintenance verify-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --recovery-set v1.2.3-20260821T000000Z
   ```

   Required PostgreSQL artifacts are `platform.dump.enc`, `keycloak.dump.enc`,
   and `manifest.json`. Required Redis artifacts are `redis-data.tar.enc` and
   `redis-manifest.json` with authenticated schema 1. Stop if any ciphertext
   size, SHA-256, AES-256-GCM tag, key ID, manifest HMAC, logical identity, or
   release/recovery binding fails. Never mix artifacts from different recovery
   sets. This verification must finish before destructive restore work.

   Both JSON control manifests must be regular non-link/non-reparse files no
   larger than 64 KiB. Verification performs one bounded read through an open
   handle, checks the named path and handle before and after that read, and
   rejects duplicate JSON keys at every nesting level. A path replacement,
   size/identity/mtime drift, link ancestor, empty file, or oversized manifest
   fails with the existing manifest-specific error before any Docker access.

2. Freeze every writer and Redis. Keep edge closed through all later checks.

   ```powershell
   docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile stop edge api worker-mail worker-sub2 web keycloak redis
   ```

3. Restore both PostgreSQL databases from the already authenticated bundle.
   This is destructive for the named target databases.

   ```powershell
   python -m scripts.postgres_maintenance restore-bundle --input-dir C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-target-db email_platform --keycloak-target-db keycloak
   ```

4. Restore Redis from the same recovery set while all writers and Redis remain
   stopped. The confirmation value must equal the reviewed tag.

   ```powershell
   python -m scripts.redis_maintenance restore-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z\manifest.json --recovery-set v1.2.3-20260821T000000Z --confirm-release-tag v1.2.3
   ```

5. Start Redis alone and prove both service health and restored state before any
   backend writer starts.

   ```powershell
   docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile up -d --no-build --pull never redis
   docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile ps redis
   ```

   Do not accept `PING` as restore evidence. Preserve the authenticated
   `restore-release` report and independently record `DBSIZE`, representative
   key `PTTL` samples (persistent keys report `-1`; expiring keys must remain
   positive and plausible), and a pre-backup expired sentinel lookup proving the
   expired key must not reappear. Compare the restored key count with the backup
   manifest/drill evidence and stop if the count or TTL semantics are implausible.
   Supply any Redis credential only through the existing repository-external
   secret file/stdin control; never use `redis-cli -a`, `--password`,
   `REDISCLI_AUTH`, a credential-bearing URL, or any password argv.

6. Bring up internal services from the already selected images. Keep edge closed.

   ```powershell
   docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile up -d --no-build --pull never keycloak migrate api worker-mail worker-sub2 web
   ```

7. Validate every internal path while edge remains stopped.

   ```powershell
   python -m scripts.restore_readiness
   ```

   The fail-closed probe uses `/run/secrets/internal-tls/ca.crt`, DNS hostname
   verification and a TLS 1.2 minimum. It requires HTTP 200 without redirecting
   to a different scheme, host, port or path for all of these endpoints:

   - `https://api:8443/readyz`
   - `https://web:8443/`
   - `https://keycloak:9000/health/ready`
   - `https://keycloak:8443/realms/email-platform/.well-known/openid-configuration`
   - `https://worker-mail:9101/metrics`
   - `https://worker-sub2:9102/metrics`
   - `https://prometheus:9090/-/ready`

   Stop immediately if the command fails. It stops edge before probing, retries
   that stop on failure, never starts edge, and emits `production_acceptance=false`
   because repository tests do not prove a target restore.

8. Only after step 7 succeeds, open edge last and run the external smoke checks.

   ```powershell
   docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile up -d --no-build --pull never edge
   python -m unittest tests.test_postgres_maintenance -v
   ```

## Create release recovery evidence

Before every production release, create and exercise PostgreSQL and Redis
artifacts in the same recovery set. Create PostgreSQL first so Redis can bind its
authenticated manifest:

```powershell
python -m scripts.postgres_maintenance backup-bundle --output-dir C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-db email_platform --keycloak-db keycloak --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
python -m scripts.redis_maintenance backup-release --output-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z\manifest.json --recovery-set v1.2.3-20260821T000000Z
python -m scripts.redis_maintenance verify-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --recovery-set v1.2.3-20260821T000000Z
python -m scripts.postgres_maintenance drill-bundle --output-dir C:\ProgramData\EmailPlatform\backups\drill-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-db email_platform --keycloak-db keycloak --platform-scratch-db email_platform_restore_drill --keycloak-scratch-db keycloak_restore_drill
```

`backup-release` stops and automatically restarts only a Redis instance that was
running before the backup. It returns only after the fixed production Compose
project reports Redis running and `/usr/local/bin/redis-healthcheck` passes.
`Redis restart could not be confirmed` is fatal: do not treat that attempt's
manifest as successful or continue the release.

Provision only the parent backup root ahead of time. Every PostgreSQL and Redis
output leaf must be an absolute, repository-external path and must not already exist,
even if it is empty. Symlink/reparse ancestors and leaves are rejected.
A refused retry does not read a key, run `pg_dump`, request Redis persistence, or
alter the earlier artifact; choose a new unique UTC leaf. A failed attempt
removes only the leaf it atomically created. Key values and Redis passwords must
never appear in argv, environment, logs, or either manifest.

The two-database drill fails unless both source databases have public tables,
both restored table counts match their source counts, and every artifact matches
the manifest. It also prints source/restored row-count evidence and requires an
exact match for platform `users`, `devices`, `audit_events` and Keycloak `realm`,
`user_entity`, `credential`, `event_entity`, `admin_event_entity`. The two event
table counts prove that identity and administrator audit records survived the
restore. Zero is allowed so a newly provisioned environment can be tested, but
production signoff must review whether each count is operationally credible.

The Redis drill must additionally record PostgreSQL/Redis release binding and
recovery-set equality, authenticated manifest SHA-256 values, restored key
count, representative TTL samples, and proof that a deliberately expired key
did not revive. Static validation and connectivity-only checks remain
`production_acceptance=false`.

Do not use Alembic downgrade as a recovery mechanism.

For a release rollback, a generic encrypted schema-v3 bundle is insufficient.
Legacy plaintext schemas 1 and 2 are rejected with no rollback override. Follow
`rollback.md`; it requires authenticated encrypted schema v5 bound to the exact
release tag, commit, migration head, and immutable container-manifest SHA-256.
Unauthenticated release schema v4 is rejected with no override.
