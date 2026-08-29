# Production credential rotation runbook

Use this runbook for PostgreSQL, Redis, Keycloak, or Vault runtime credentials.
The production topology is a single-instance controlled switch, so rotation is
a maintenance change rather than a rolling or zero-downtime operation.
Rotate exactly one credential class per maintenance change. Do not continue to
another class until the current class is signed off or rolled back.

## Credential-class map

Select exactly one row. The backing credential and every coupled file in that
row form one indivisible change set. Files are delivered from the external
secret manager by atomic write/rename with the owner and mode required by
`runtime-secrets.md`; secret values never enter `.env`, process arguments,
process environment, logs, shell history, or evidence.

| Credential class | Backing credential | Coupled external files | Exact consumers |
| --- | --- | --- | --- |
| Platform database DML | Existing PostgreSQL role named by `POSTGRES_APP_USER` | `POSTGRES_APP_PASSWORD_FILE`, `PLATFORM_DATABASE_URL_FILE` | `api`, `worker-mail`, `worker-sub2` |
| Migration/database owner | Existing PostgreSQL role named by `POSTGRES_USER` | `POSTGRES_PASSWORD_FILE`, `PLATFORM_MIGRATION_DATABASE_URL_FILE` | one-off `migrate` |
| Keycloak database | Existing PostgreSQL role named by `KEYCLOAK_DB_USER` | `KEYCLOAK_DB_PASSWORD_FILE`, `KEYCLOAK_CONFIG_FILE` | `keycloak` |
| Redis application ACL | Application user in `REDIS_ACL_FILE` | `REDIS_ACL_FILE`, `PLATFORM_REDIS_URL_FILE` | `redis`, `api`, `worker-sub2` |
| Redis healthcheck ACL | `healthcheck` user in `REDIS_ACL_FILE` | `REDIS_ACL_FILE`, `REDIS_HEALTHCHECK_PASSWORD_FILE` | `redis` |
| Keycloak active administrator | Active administrator credential in Keycloak | Remove or update bootstrap entries in `KEYCLOAK_CONFIG_FILE`; bootstrap values do not rotate an existing administrator | `keycloak` administration sessions |
| API Vault token | Short-lived service token from `email-platform-api-cards` | `PLATFORM_VAULT_API_TOKEN_DIR/token` | `api` |
| Mail Vault token | Short-lived service token from `email-platform-mail` | `PLATFORM_VAULT_MAIL_TOKEN_DIR/token` | `worker-mail` |
| Sub2 Vault token | Short-lived service token from `email-platform-sub2` | `PLATFORM_VAULT_SUB2_TOKEN_DIR/token` | `worker-sub2` |

For a Vault row, keep object types separate: RoleID is a role selector, SecretID is a one-use login input, the resulting short-lived service token is the only
runtime sink credential, and its accessor is a non-authenticating management
identifier. The routine per-service issuer has no token-management capability.
Only an independent approved rotator may use the protected old accessor with
`auth/token/revoke-accessor`, after the new token's exact policy check, atomic
sink replacement, and consumer canary have all succeeded. Never pass an
accessor in argv or logs, and never record a Vault token-sink SHA-256 value.

Existing PostgreSQL volumes must use a controlled `ALTER ROLE` through an
approved administrative connection. PostgreSQL initialization scripts are not
a rotation mechanism and must not be rerun against an existing volume. Supply
the new value to the administrative client only through its protected file or
stdin facility, never through an argument or configured environment variable.

For Redis or Vault, use a bounded overlap when the backing service supports
multiple active credentials: create the new credential, move the selected
consumer to it, verify it, and only then revoke the old credential. For a
single-password PostgreSQL or Keycloak change, keep edge and the selected
consumers stopped while changing the backing credential and coupled files.

## 1. Freeze the reviewed release and preflight

Work only from the reviewed release checkout. Reject caller-controlled Docker
target or TLS overrides before inspecting a context or running Compose. Pin
every Compose command to the reviewed production installation, its external
`.env`, exact project name, and `docker-compose.yml`.

```powershell
$forbiddenDockerEnvironment = @(
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
}
$productionInstallRoot = "C:\ProgramData\EmailPlatform\current"
$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path
$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path
$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path
$dockerContext = docker context show
docker context inspect $dockerContext
python scripts/verify_runtime_secrets.py
python scripts/verify_compose_env.py
python scripts/verify_service_boundaries.py
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile config --quiet
```

The six-key check is based on key presence, so empty strings and `0` are also
rejected without printing a value. Record the context name and reviewed
endpoint. This static gate and `docker context inspect` do not prove the real
daemon, endpoint, socket ACL, or remote TLS/mTLS identity; those remain target-
host production acceptance checks.

Acquire the production change lock. Record the selected credential class,
secret-manager current/new version IDs, exact consumers, rollback owner, and
maintenance window. Retain the preceding version encrypted and access-controlled
for this rollback window without copying its value into the record.

## 2. Close ingress before the first credential change

Stopping edge is the first runtime mutation. Confirm it is stopped before
creating/activating a new backing credential, replacing a coupled file, stopping
a consumer, or changing a PostgreSQL/Redis/Keycloak account.

```powershell
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile stop edge
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile ps edge
```

Stop only the exact consumers from the selected table row. Do not combine rows
or restart PostgreSQL, Redis, Keycloak, API, Web, and both workers as one batch.
For example, the platform database DML class uses only this consumer set:

```powershell
$consumers = @("api", "worker-mail", "worker-sub2")
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile stop $consumers
```

## 3. Apply one indivisible credential change set

Change the backing credential using the approved target-specific administrative
path, then atomically replace every coupled file from the same selected row.
Treat the backing update plus all file replacements as one indivisible change:
do not start a consumer, revoke a rollback credential, or begin another class
between those operations.

Validate every replaced file as the matching container UID: absolute external
path, regular file, no symlink/reparse ancestor, exactly one non-empty line when
the file contract requires it, expected owner, mode `0400` or `0440`, and no
shared inode with another credential file. URL-encode reserved characters in
database and Redis URL files. Do not print a file, render it into Compose, or
record a secret-derived hash that was not approved for restricted evidence.

Keycloak administrator rotation must change the active administrator through
the approved Keycloak administration path and revoke its active sessions.
Editing bootstrap entries alone does not rotate an existing administrator;
remove bootstrap values from `KEYCLOAK_CONFIG_FILE` after initial bootstrap.

## 4. Restart only the listed consumers

Restart only the consumers named in the selected row, using the already selected
immutable images. Every Compose `up` must prohibit builds and pulls. The example
below remains the platform database DML class; choose the exact consumer set for
the selected row and do not add adjacent services.

```powershell
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile up -d --no-build --pull never $consumers
```

For the migration-owner class, run the reviewed one-off migration/current-state
probe with the immutable `migrate` image; do not restart PostgreSQL merely to
reload a password file. For Redis ACL changes, reload or restart Redis only as
required by the reviewed ACL procedure, then restart only the API consumer when
the application ACL changed.

## 5. Prove readiness and credential cutover

Keep edge stopped. First run the existing strict internal readiness gate; it
uses service DNS, the reviewed internal CA, hostname verification, TLS 1.2+, an
exact HTTP 200, and rejects redirects.

```powershell
python -m scripts.restore_readiness
```

Then perform a class-specific positive and negative authentication check through
an approved client that accepts credentials only from protected file/stdin:

1. Prove the new credential succeeds through the selected real consumer.
2. Revoke the old credential for Vault only through the independent approved rotator, using the old token's
   protected accessor. For another overlap-capable Redis change, revoke the old
   credential. For a single-password change, confirm the backing update already
   invalidated it.
3. Prove the old credential fails through the protected negative-auth path.
4. Confirm only the selected consumers restarted and inspect their argv,
   environment, and bounded logs for secret values or credential-bearing URLs.
5. Confirm the expected Vault/Keycloak/platform audit event and no authorization
   regression outside the selected class.

Create redacted evidence only after both authentication proofs pass. Record the
credential class, non-sensitive secret-manager version IDs, approved file
SHA-256 values, owner/mode results, exact consumers, restart timestamps,
readiness result, old-credential rejection, restricted accessor reference where
applicable, audit trace, and independent reviewer. Never record a secret value,
Vault token-sink hash, token, RoleID, or SecretID.

## 6. Start edge last

Start edge last only after strict readiness, new-credential success,
old-credential failure or revocation, and redacted evidence all succeed.

```powershell
docker compose --project-directory $projectDirectory --env-file $envFile --project-name email-platform --file $composeFile up -d --no-build --pull never edge
```

Run the external HTTPS smoke and retain its UTC result. This repository runbook
and its static verifier remain `production_acceptance=false` until target-host
evidence is independently reviewed.

## Failure and rollback

Any partial rotation is a failed change. Keep edge stopped, stop only the same
selected consumers, restore the preceding backing credential and all coupled
files as one change set, restart only those consumers with `--no-build --pull
never`, rerun strict readiness, and prove the restored credential succeeds.
Before Vault revocation, rollback may restore only a still-valid preceding
token. After revocation, issue a fresh one-use SecretID and service token; never restore a revoked token or a consumed SecretID.
Do not open edge or proceed to another credential class until rollback evidence
has been independently reviewed. Destroy the preceding credential version only
after successful production signoff and the approved rollback window.
