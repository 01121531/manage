# Platform API — Phase 4 service boundaries

This directory is the platform backend foundation. It provides OIDC/local-development login,
device-bound access tokens, owner-isolated tasks, mailbox sessions, card leases,
sanitized audit events, and a server-owned Sub2 upload outbox. Real mailbox,
secret-manager, and Sub2 adapters are injected server-side; the desktop API
never accepts their credentials or infrastructure policy.

## Run locally

Install the isolated runtime dependencies, then from the repository root run:

```powershell
python -m pip install -r platform/requirements.txt
```

Start the application with:

```powershell
python -m uvicorn platform.app:create_app --factory --reload
```

The default endpoints are:

- `GET /healthz` — infrastructure probe.
- `GET /readyz` — dependency readiness probe; currently verifies database access.
- `GET /metrics` — Prometheus text metrics for low-cardinality API request
  counters and upload job status counts.
- `GET /api/v1/health` — versioned service health.
- `GET /api/v1/version` — service and API version.
- `GET /api/v1/auth/config` — public OIDC client configuration (never secrets).
- `POST /api/v1/auth/login` — local-development platform login; disabled in OIDC mode.
- `GET /api/v1/me` — current platform user and bound device.
- `GET /api/v1/dashboard/summary` — safe aggregate counts for the current
  operator scope; no mailbox, card, business-name or secret details.
- `GET /api/v1/mailboxes` — masked mailbox connector status for the current
  tenant; no `secret_ref`, password, or raw mailbox configuration.
- `POST/GET /api/v1/tasks` — idempotently create and list the current user's tasks.
- `GET /api/v1/tasks/{id}` — fetch an owned task; foreign tasks return 404.
- `POST /api/v1/tasks/{id}/close` — close an owned active task and release task-bound resources.
- `POST /api/v1/tasks/{id}/mail-sessions` — bind an available masked mailbox
  to an owned task.
- `GET /api/v1/mail-sessions/{id}/code` — poll a one-time verification code.
- `GET /api/v1/mail-sessions/{id}/events` — stream verification-code status events.
- `POST /api/v1/mail-sessions/{id}/revoke` — revoke an active mail session.
- `POST /api/v1/tasks/{id}/card-allocations` — lease one server-managed card.
- `GET /api/v1/card-allocations/{id}` — return only masked card details.
- `POST /api/v1/card-allocations/{id}/reveal-challenges` — bind a short-lived
  step-up request to the current actor, device, and active lease.
- `POST /api/v1/card-allocations/{id}/reveal-grants` — exchange a fresh OIDC
  authentication with the required ACR for a hashed, one-use reveal grant.
- `POST /api/v1/card-allocations/{id}/reveal` — atomically consume that grant
  and reveal PAN/expiry once; CVV is not part of the default API contract.
- `POST /api/v1/card-allocations/{id}/release` — release a lease.
- `POST /api/v1/tasks/{id}/uploads` — enqueue an idempotent Sub2 upload job.
- `GET /api/v1/upload-jobs/{id}` — poll the upload state.
- `POST /api/v1/upload-jobs/{id}/cancel` — cancel a queued upload job.
- `POST /api/v1/upload-jobs/{id}/reconcile` — privileged reconciliation for unknown/failed jobs.
- `GET /api/v1/admin/policies/upload` — privileged, read-only upload policy
  status; returns booleans and version only, never `proxy_ref`, credentials,
  group, concurrency or upstream URLs.
- `/api/docs` — OpenAPI UI. Run `cd frontend && npm run generate:api` after
  contract changes; the quality gate rejects a stale generated TypeScript
  contract before building the Web console.

Configuration is environment-only and uses the `PLATFORM_` prefix, for
example `PLATFORM_ENVIRONMENT=staging` or `PLATFORM_DEBUG=true`. Do not put
tokens or passwords in source files or `.env` committed to the repository.
SQLite data defaults to `platform/platform.db` and can be changed with
`PLATFORM_DATABASE_URL`.

`PLATFORM_AUTH_MODE=local` is development/test only. When its HMAC secret is
omitted, a random process-local secret is generated, so tokens stop working
after a restart. Production startup fails unless `PLATFORM_AUTH_MODE=oidc` and
issuer, audience, public client ID and JWKS URL are configured. OIDC accepts
only RS256 and validates issuer, audience, expiry, subject, `tenant_id`, and
`device_id`; user, role and device are then revalidated from the platform DB.

There is no default account or password. Create a local development identity:

```powershell
python -m platform.bootstrap --tenant-id tenant-1 --email user@example.com --device-name workstation-1
```

The command prompts for the platform-account password without echoing it and
prints the generated user and device IDs. For production, first create the user
in Keycloak with reviewed `tenant_id` and `device_id` attributes, then provision
the matching subject without a local platform password:

```powershell
python -m platform.bootstrap --tenant-id tenant-1 --email user@example.com --device-name workstation-1 --oidc-subject KEYCLOAK_SUBJECT --role operator
```

Task creation accepts only this body; `device_id` is always derived from the
authenticated access token:

```json
{
  "type": "mail_code",
  "idempotency_key": "client-request-uuid",
  "client_reference": "optional-client-label"
}
```

The first request returns `201`. Replaying the same owner/key/payload returns
the original task with `200`; reusing the key with different task data returns
`409 conflict`. Alembic is the production schema source of truth; tests use
ephemeral `create_all` databases. An older `platform.db` must be migrated or replaced only
after its data has been reviewed and backed up; the application never deletes it.

Mail sessions store only an opaque `secret_ref`; the API never accepts or
returns mailbox passwords, credentials, or message bodies. The default mail
connector is intentionally unconfigured and returns `503 service_unavailable`.
Production connectors implement `MailConnector` and resolve the reference via a
secret manager. In production, set `PLATFORM_MAIL_POLL_MODE=worker` for the API
and run the dedicated `worker-mail` service with `PLATFORM_MAIL_API_URL`. The
API then only creates an `initializing` session and reads a worker-delivered
one-time code; it does not call the mailbox upstream. The built-in HTTP
connector is registered as `connector_type` `http` when `PLATFORM_MAIL_API_URL`
is configured on the mail worker. It calls `POST {PLATFORM_MAIL_API_URL}/watermark`
to initialize the session and `POST {PLATFORM_MAIL_API_URL}/code` while
polling; mailbox `secret_ref` values are resolved in-process through the
server-side secret resolver before the call. The desktop client never receives
mailbox credentials or raw message bodies. A session records a connector
watermark, ignores messages at or before that watermark, and marks the first
newer code consumed; later polls return `{"status":"consumed","code":null}`.
Mailbox allocation locks candidate rows with `FOR UPDATE SKIP LOCKED` on
PostgreSQL and is backed by a partial unique index, so one mailbox cannot serve
two active sessions. Worker-delivered codes have an independent
`PLATFORM_MAIL_CODE_TTL_SECONDS` (60 seconds by default); expiry, revocation,
task close, and device/user disable paths erase the plaintext columns.
The API-mode polling path remains available for local tests and injected
connectors.

Cards likewise store a provider reference, brand, last four digits, and an
opaque secret-manager reference—never PAN or CVV in the platform database.
Active leases are unique per card and task, tied to tenant/user/device,
time-limited, and audited. The ordinary allocation response returns only a
mask. A reveal first creates an actor-bound challenge; an isolated browser
PKCE flow must then produce a token whose signed `auth_time` is newer than the
challenge and whose `acr` equals `PLATFORM_CARD_STEP_UP_ACR`. The server stores
only a SHA-256 hash of the short-lived reveal grant and consumes it atomically.
The reveal response is `no-store`, returns PAN/expiry once, and deliberately
omits CVV. No PAN, grant, or CVV is written to audit events. The default
resolver is fail-closed and returns `503 service_unavailable` until a
production secret-manager adapter is injected. Configure a real Keycloak LoA
flow for the required ACR before production; a browser prompt by itself is not
accepted as step-up proof. Upload requests accept only `business_name` and an idempotency key.
Creating an upload job also inserts one payload-free `upload.requested` row in
`outbox_events` in the same database transaction. The upload worker claims only
those outbox rows; it does not scan `upload_jobs` as an implicit queue. A stale
event may be reclaimed only while its job is still `queued`. If the job had
already reached `running`, it becomes `unknown` for manual reconciliation so an
ambiguous external call is never submitted blindly a second time. Proxy
reference, group, concurrency, Sub2 credential reference, and card secret
reference are assembled inside the worker from `Sub2Policy`; none appear in
desktop requests, outbox rows, or API responses.

The upload worker can call a server-side HTTP upload interface by setting
`PLATFORM_SUB2_UPLOAD_URL`. Without it, the worker remains fail-closed and jobs
become `adapter_unavailable`.

Platform administrators can register the current server configuration as an
immutable upload policy snapshot through `/api/v1/admin/policies/upload/versions`.
The request contains only a version and change note; proxy, group, concurrency,
credential references, and endpoint details are copied inside the server and
are never returned by the management API. A different platform administrator
must approve the draft before it can be deployed. The first policy is deployed
at 100%; later versions can use a deterministic task-based rollout percentage.
The deployment retains the previous version for an audited rollback. Each
upload job records its selected version, and the worker resolves that exact
snapshot even if the tenant rolls back before the job runs.

Server-side secrets support two reference schemes. `env://NAME` reads a JSON
object or plain value from the process environment only in development/test;
production rejects all `env://` references. `vault://mount/path` uses Vault KV v2 and requires
`PLATFORM_VAULT_ADDR`; optional `PLATFORM_VAULT_NAMESPACE` is sent as
`X-Vault-Namespace`. Production must set `PLATFORM_VAULT_TOKEN_FILE` to an
absolute path below `/run/secrets` or `/var/run/secrets`. The resolver reopens
that regular file for every Vault request, so an atomic token rotation is used
by the next resolve without restarting the process. Oversized, empty,
non-regular, symlinked, or group/world-writable token files fail closed. The
legacy `PLATFORM_VAULT_TOKEN` environment value is accepted only in development
and test. For example, a production deployment can set
`PLATFORM_SUB2_CREDENTIAL_REF=vault://secret/sub2/credential`,
`PLATFORM_SUB2_PROXY_REF=vault://secret/sub2/proxy`, mailbox `secret_ref`
values such as `vault://secret/mailboxes/mail-001`, and card `secret_ref`
values such as `vault://secret/cards/card-001`. The mail and Sub2 workers
resolve these only in-process before calling the configured upstream
interfaces. Compose mounts three different host token directories read-only
and maps each process to `/run/secrets/email-platform-vault/token`; RoleIDs,
SecretIDs, and raw token values never enter the application environment. The
API token can read only `secret/data/cards/*`
for card reveal, the mail token only `secret/data/mailboxes/*`, and the Sub2
token only the reviewed Sub2 credential/proxy paths plus `secret/data/cards/*`,
which it must resolve when assembling the server-side upload payload. It has no
mailbox permission. A missing token fails startup when a Vault address is
configured; a missing resolver otherwise makes each Vault-backed operation
fail closed.

Reviewed least-privilege policies and an AppRole configuration helper live in
`infra/vault/`. The `*_ROLE_ID` and `*_SECRET_ID` variables are for Vault Agent
or an approved deployment secret broker; they are deliberately never injected
into application containers. The broker exchanges each one-use SecretID for a
short-lived service token and supplies only its matching `*_TOKEN`. Never write
SecretIDs or issued tokens to Git, container images, logs, or a shared `.env`
in a real production deployment. The broker writes each issued token to the
matching `PLATFORM_VAULT_*_TOKEN_DIR/token` sink using mode `0400` for container
UID 10001 and atomically replaces it on rotation.

Every response includes an `X-Trace-Id` header. A valid UUID supplied in the
request's `X-Trace-Id` header is propagated; otherwise one is generated. API
errors use the envelope `{ "error": { "code", "message", "trace_id" } }`.
`/metrics` exposes only operational labels such as method, route template,
status code, and upload status; it must not include emails, card details,
business names, tokens, secret references, or proxy settings. The mail and
upload workers also write one JSON log event per polling batch with aggregate
status counts only. Prometheus scrape targets and alert rules live under
`infra/prometheus/`; the mail and Sub2 workers expose worker-local metrics on
their internal ports for stalled-batch and availability alerts.
Audit events are append-only at both the application and database layer; update
and delete attempts are rejected so the audit trail remains tamper-evident.

## Verify

From the repository root:

```powershell
python -m unittest discover -s platform/tests -p "test_*.py"
python -m compileall -q platform
```

For the full local gate used by CI:

```powershell
.\scripts\quality_gate.ps1
```

It compiles Python modules, runs platform and desktop/client tests, validates
Compose variables against `.env.example`, performs a lightweight secret-pattern
scan, generates Alembic upgrade SQL, and builds the React console.

## Container deployment and migrations

The repository includes a PostgreSQL/Redis/Keycloak/API/mail-worker/Sub2-worker/Web
Compose topology. It is a deployment baseline, not a production secret store:

```powershell
Copy-Item .env.example .env
# Replace every CHANGE_ME value through the deployment secret manager.
# PLATFORM_MIGRATION_DATABASE_URL is the schema-owner/DDL role.
# PLATFORM_DATABASE_URL is the API/worker DML-only role.
# Provision the three Vault token directories using infra/vault/README.md;
# placeholder/missing directories intentionally prevent container startup.
docker compose config
docker compose up -d
```

Compose runs the one-shot `migrate` service first; the API, mail worker and
Sub2 worker wait for `alembic upgrade head` to finish successfully. The
migration URL must use a dedicated schema-owner role with DDL privileges.
`PLATFORM_DATABASE_URL` must use a separate runtime role limited to the DML
needed by the application, without `CREATE`, `ALTER`, `DROP`, or `TRIGGER`.
Production API and worker startup never calls `create_all` or rebuilds audit
triggers; Alembic is the only production schema source of truth. Development
and test environments keep local automatic schema creation for fast feedback.
The API image runs as UID 10001 and has no shell-level credentials baked into
the image. The API, mail worker, Sub2 worker and web containers run read-only,
drop all Linux capabilities, set `no-new-privileges:true`, and mount only the
small `/tmp`-style scratch space they need. Its container health check uses
`/readyz`, so a broken database connection or an unapplied migration makes the
API unhealthy instead of merely proving the process is listening. PostgreSQL and Redis data use named volumes. The Keycloak container
imports `infra/keycloak/email-platform-realm.json`, which requires Authorization
Code + PKCE (S256), disables direct password grants, forces TOTP enrollment as a
required action, and adds API audience plus tenant/device claims. Review the
exact redirect URIs, MFA policy, user attributes and bootstrap credentials
before deployment. Production must use a dedicated least-privilege database role.
The public desktop client enables Standard Flow with the native-app special
redirect `http://127.0.0.1` (random loopback ports), keeps Device Authorization
only as an explicit fallback, and enforces refresh-token rotation with zero
reuse. The EXE contains no OIDC client secret. `GET /api/v1/tasks?limit=1..100`
returns the current user's newest tasks with `trace_id`; desktop and Web UIs
show only task status/identifiers, never mailbox bodies, card secrets or Sub2
configuration.

Alembic is the source of truth for schema changes. Review and back up the
database before `upgrade`; never use `downgrade` as a data-recovery mechanism.
The migrations cover `users` (including OIDC subject and RBAC role), `devices`, `tasks`, `mailboxes`,
`mail_sessions`, `cards`, `card_allocations`, `card_reveal_challenges`, `upload_jobs`, and
`audit_events`. Generate offline SQL for review with:

```powershell
alembic -x db_url="postgresql+psycopg://USER:PASSWORD@HOST:5432/DB" upgrade head --sql > schema.sql
```

For production backup and restore, keep the platform and Keycloak databases in
one integrity-checked bundle. The Keycloak realm JSON is bootstrap configuration,
not a backup of live users or credentials. Use the helper from the repository root:

```powershell
python -m scripts.postgres_maintenance backup-bundle --output-dir backups/production-YYYYMMDDTHHMMSSZ --platform-db email_platform --keycloak-db keycloak
python -m scripts.postgres_maintenance verify-bundle --input-dir backups/production-YYYYMMDDTHHMMSSZ
python -m scripts.postgres_maintenance restore-bundle --input-dir backups/production-YYYYMMDDTHHMMSSZ --platform-target-db email_platform_restore --keycloak-target-db keycloak_restore
python -m scripts.postgres_maintenance drill-bundle --output-dir backups/production-YYYYMMDDTHHMMSSZ --platform-db email_platform --keycloak-db keycloak --platform-scratch-db email_platform_restore_drill --keycloak-scratch-db keycloak_restore_drill
```

The bundle manifest records the database name, artifact filename, byte size and
SHA-256 for `platform.dump` and `keycloak.dump` in `manifest.json`. Restore
verifies the complete bundle first. The drill
also requires non-empty source databases and matching source/restored public
table counts for both databases. It emits matching source/restored row counts
for platform `users`, `devices`, `audit_events` and Keycloak `realm`,
`user_entity`, `credential`; retain that output as signoff evidence and review
whether zero counts are credible for the environment. Archive the entire
directory as one unit.

The release lock is captured in `deploy/release-manifest.json`. Before a
production cut, verify it against the working tree with:

```powershell
python -m scripts.release_manifest verify --manifest deploy/release-manifest.json
```

To cut a fresh release record after a validated deployment, snapshot the
current state and archive the resulting manifest alongside the backup artifact.
For rollback, restore the latest backup first, then redeploy the previous
manifest and rerun `alembic upgrade head` only when moving forward again.
The operational runbooks live under `deploy/runbooks/` and cover restore,
rollback, device revocation, key rotation, and incident response.
The production signoff template lives at `deploy/production-signoff-template.md`
and captures the evidence for each readiness gate plus the separate operator
approval.

The mail worker must be the only service configured with `PLATFORM_MAIL_API_URL`
in production; the API runs in worker polling mode and stores only a temporary
delivered code until the desktop consumes it. The API-side upload policy view
now only exposes the safe readiness summary and policy version; the actual
Sub2 credential, proxy and concurrency refs belong to `worker-sub2`. The Sub2
worker currently stays fail-closed until `PLATFORM_SUB2_UPLOAD_URL` and
resolvable server-side secrets are configured. Before a production rollout,
configure the reviewed Sub2 upload URL and secret-manager resolver on
`worker-sub2`; the desktop client must never receive Sub2 credentials, proxy
addresses, group IDs or concurrency settings. Both workers write heartbeat
files at `PLATFORM_WORKER_HEARTBEAT_PATH`; the container health check fails
when that file is missing or older than `PLATFORM_WORKER_HEARTBEAT_MAX_AGE_SECONDS`.

Compose includes a non-root `edge` service as the only public HTTP/HTTPS entry.
It maps host ports 80/443 to unprivileged container ports 8080/8443; API, Web and
Keycloak stay reachable only on the backend network. Point both
`PLATFORM_DOMAIN` and `identity.PLATFORM_DOMAIN` DNS records at the host, then
set `PLATFORM_TLS_CERT_FILE` and `PLATFORM_TLS_KEY_FILE` to absolute host paths
for a certificate that covers both names (a matching wildcard or SAN
certificate). The files are mounted read-only and must be readable by container
UID 101; never put the private key in Git, the image, or the Compose environment.
Explicit HTTP and HTTPS default servers return Nginx status 444 for every
unrecognized Host/SNI name, so only the configured platform and identity names
can reach application upstreams.

At startup, `infra/nginx/render-edge-config.sh` validates the domain and TLS
files, replaces only the literal `${PLATFORM_DOMAIN}` token, runs `nginx -t`,
and then starts Nginx. Nginx runtime variables such as `$host`, `$request_uri`
and `$proxy_add_x_forwarded_for` remain intact. The container runs read-only,
drops all Linux capabilities and needs no `NET_BIND_SERVICE` capability because
it binds only high ports internally. Validate the static deployment contract
before rollout with `python scripts/verify_edge_assets.py`; then, on a Docker
host with real certificates, require `docker compose config`, a healthy `edge`
service, HTTP-to-HTTPS redirects, and successful external requests to both
hostnames as production signoff evidence.

An optional `vault-dev` Compose profile is provided solely for local contract
tests (`docker compose --profile vault-dev up vault`). It runs Vault in dev mode
with a caller-supplied token. It can exercise `vault://secret/...` references
locally when `PLATFORM_VAULT_ADDR=http://vault:8200` is set for containers.
Never enable this profile in staging/production; production uses a sealed,
least-privilege Vault deployment or another approved secret manager.

### Production readiness gates

Before exposing the service to users, an operator must record evidence for all
of the following:

1. `docker compose config` succeeds using a secret-manager-generated `.env`,
   and a scan confirms no real secrets in Git, images or logs.
2. A PostgreSQL backup/restore drill and Alembic `upgrade head` run complete;
   schema ownership and least-privilege roles are documented.
3. Keycloak realm, redirect URIs, client authentication and MFA policy are
   reviewed; bootstrap admin credentials are rotated and not reused.
4. TLS certificates, HSTS/CSP headers, rate limits, log redaction, audit-event
   retention and alerting are tested from outside the cluster.
5. Mail connector and Sub2 adapter integration tests use staging accounts and
   prove that mailbox passwords, PAN/CVV, Sub2 tokens, proxy configuration and
   raw message content never cross the desktop/API response boundary.
6. Worker retry/reconciliation behavior is tested: an external ambiguity is
   `unknown` and is never automatically retried; card leases expire and are
   released safely.
7. Restore, key rotation, device revocation and incident-response runbooks are
   signed off by an operator who is not the implementer.
