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
- `POST /api/v1/card-allocations/{id}/reveal` — one-time reveal for an active owned lease.
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
The API-mode polling path remains available for local tests and injected
connectors.

Cards likewise store a provider reference, brand, last four digits, and an
opaque secret-manager reference—never PAN or CVV in the platform database.
Active leases are unique per card and task, tied to tenant/user/device,
time-limited, and audited. The ordinary allocation response returns only a
mask; the reveal endpoint calls a server-side `CardSecretResolver`, returns
PAN/CVV once for an active owned lease, records `card.revealed`, and never
stores those details in audit events. The default resolver is fail-closed and
returns `503 service_unavailable` until a production secret-manager adapter is
injected. Upload requests accept only `business_name` and an idempotency key.
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
object or plain value from the process environment and is intended for local or
private validation. `vault://mount/path` uses Vault KV v2 and requires
`PLATFORM_VAULT_ADDR` plus `PLATFORM_VAULT_TOKEN`; optional
`PLATFORM_VAULT_NAMESPACE` is sent as `X-Vault-Namespace`. For example, a
production deployment can set
`PLATFORM_SUB2_CREDENTIAL_REF=vault://secret/sub2/credential`,
`PLATFORM_SUB2_PROXY_REF=vault://secret/sub2/proxy`, mailbox `secret_ref`
values such as `vault://secret/mailboxes/mail-001`, and card `secret_ref`
values such as `vault://secret/cards/card-001`. The mail and Sub2 workers
resolve these only in-process before calling the configured upstream
interfaces. Use distinct least-privilege Vault tokens for the API, mail worker,
and Sub2 worker in production.

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
# PLATFORM_DATABASE_URL must use a URL-encoded database password.
docker compose config
docker compose up -d postgres redis keycloak
docker compose run --rm api alembic upgrade head
docker compose up -d api worker-mail worker-sub2 web
```

The API image runs as UID 10001 and has no shell-level credentials baked into
the image. The API, mail worker, Sub2 worker and web containers run read-only,
drop all Linux capabilities, set `no-new-privileges:true`, and mount only the
small `/tmp`-style scratch space they need. Its container health check uses
`/readyz`, so a broken database connection makes the API unhealthy instead of
merely proving the process is listening. PostgreSQL and Redis data use named volumes. The Keycloak container
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
`mail_sessions`, `cards`, `card_allocations`, `upload_jobs`, and
`audit_events`. Generate offline SQL for review with:

```powershell
alembic -x db_url="postgresql+psycopg://USER:PASSWORD@HOST:5432/DB" upgrade head --sql > schema.sql
```

For an actual backup/restore drill, use the helper script from the repository
root:

```powershell
python -m scripts.postgres_maintenance backup --output backups/email-platform.dump
python -m scripts.postgres_maintenance restore --input backups/email-platform.dump --target-db email_platform_restore
python -m scripts.postgres_maintenance drill --output backups/email-platform.dump --scratch-db email_platform_restore_drill
```

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

For TLS termination, render
`infra/nginx/email-platform.conf.template` with the deployment domain and
mount certificates from a secret volume. The template includes HTTP→HTTPS
redirect, TLS 1.2/1.3, HSTS, CSP, clickjacking/content-type protections and an
API request limiter. Render only the intended variable so Nginx variables such
as `$host` survive, for example
`envsubst '${PLATFORM_DOMAIN}' < infra/nginx/email-platform.conf.template >
/etc/nginx/conf.d/email-platform.conf`. Do not commit certificate private keys.

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
