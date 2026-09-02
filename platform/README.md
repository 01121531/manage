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
- `GET /readyz` — dependency readiness probe; verifies database/migrations and,
  when distributed rate limiting is enabled, Redis connectivity.
- `GET /metrics` — Prometheus text metrics for low-cardinality API request
  counters and upload job status counts.
- `GET /api/v1/health` — versioned service health.
- `GET /api/v1/version` — service and API version.
- `GET /api/v1/auth/config` — public OIDC client configuration (never secrets).
- `POST /api/v1/auth/login` — local-development platform login; disabled in OIDC mode.
- `POST /api/v1/auth/logout` — idempotently revoke the exact bearer and, when
  present, its issuer-scoped OIDC `sid`, then reclaim device-owned resources once.
- `GET /api/v1/me` — current platform user and bound device.
- `POST /api/v1/devices/{device_id}/revoke` — let the authenticated owner revoke
  one of their own devices without gaining tenant-administrator device access.
- `POST /api/v1/admin/users/{user_id}/devices` — privileged, tenant-scoped
  pre-provisioning of a named device; this is not a login or token endpoint.
- `GET /api/v1/dashboard/summary` — safe workbench aggregates for the current
  scope. Tenant roles receive UTC-day task/upload metrics, allocator-accurate
  available-card capacity, active unavailable-mailbox count, and at most five
  recent tasks projected to ID/type/status/trace/time only. Operator scope is
  bound to the current user and device; tenant card capacity is not disclosed.
  No mailbox address, card metadata, business name, client reference, policy,
  provider error, or secret detail is returned.
- `GET /api/v1/mailboxes` — masked mailbox connector status for the current
  tenant; no `secret_ref`, password, or raw mailbox configuration.
- `POST /api/v1/admin/pool-import-contexts` — issue a short-lived, one-time,
  secret-free authorization for one exact card- or mailbox-pool manifest. The
  caller supplies pool type, ordered masked-manifest digest and count. Card
  requests additionally supply the normalized, secret-free `provider_ref` list;
  mailbox requests must not supply card identities. Before the importer can use
  Vault, the target rejects identities already present in the tenant card pool
  and atomically claims every new identity through a database unique constraint.
  An expired, unconsumed context can relinquish only the claims whose exact
  identities are requested by a later card context in the same tenant; another
  identity or tenant cannot mutate that renewal state. Matching expired context
  rows are locked once in ascending context-ID order before claim reads and
  transfer, so overlapping batches use the same lock order and renewal, final
  consumption and reclamation share one transaction boundary. New card identity
  claims are inserted in ascending provider-reference order while retaining their
  original manifest positions, so reversed batch input cannot reverse unique-index
  acquisition order. A claim's tenant must also match its authoritative owning
  context: a drifted row cannot be renewed, consumed, reclaimed, or deleted, and
  the owning context's tenant continues to block replacement until the row is
  repaired. Migration `0038_card_claim_context_binding` first rejects historical
  mismatches, then installs claim insert/update and owning-context update guards;
  PostgreSQL claim writes take a `FOR KEY SHARE` lock on the matching card context
  so direct SQL and concurrent context changes cannot break this binding. A
  later `0039_card_claim_delete_guard` migration rejects every direct claim
  deletion at the database boundary. Reclamation instead updates the existing
  claim row to the new context and manifest position, preserving the permanent
  identity history while remaining in the same audited transaction. Migration
  `0040_card_claim_identity_immutable` additionally makes the claim's tenant and
  provider reference immutable after insertion, so direct SQL cannot rename a
  consumed identity guard or move it across tenants; only its reclamation
  context and manifest position remain transferable. Migration
  `0041_card_claim_mutation_ledger` adds a database-generated append-only row
  for every such context or position change. The row carries only tenant,
  source/destination context and position, destination trace and time; it never
  stores the provider reference or card secret, and complements the existing
  administrator reclamation audit. Migration
  `0042_pool_context_identity_lock` freezes the server-issued context ID, token
  hash, tenant, audience, pool, manifest digest/count, creator, device, trace
  and creation time after insertion. Direct SQL therefore cannot rewrite the
  authorization identity or reinterpret mutation-ledger history after claims
  move away; only expiry renewal and the existing consumption/receipt lifecycle
  fields remain mutable. A
  following `0043_secure_consumption_lock` migration makes every signed-receipt
  consumption row append-only after insertion. Direct SQL cannot update or
  delete its receipt identity, local import receipt link, issue/expiry time,
  Transit key version or consumed time; fresh card and mailbox import
  transactions can still insert one new row. This shared replay guard does not
  merge the two pools or expose their source data. Migration
  `0044_pool_context_consumption_terminal` requires every context to start with
  both consumption fields empty, permits expiry renewal only before
  consumption, and accepts exactly one transition that simultaneously links a
  matching local receipt and its signed-receipt consumption. Afterward expiry,
  consumption time and receipt linkage are a database-enforced terminal state
  for both pools. Migration `0045_pool_import_receipt_append_only` also makes
  the linked local idempotency receipt append-only. Its identity, tenant, pool,
  idempotency key, manifest digest/count, actor, device, trace and creation time
  cannot be updated or deleted after insertion; a new card or mailbox import
  can still insert its own receipt. A
  reclamation writes a dedicated
  audit event containing only claim/context counts and SHA-256 fingerprints of
  the prior context IDs; provider references and context tokens are excluded.
  Consumed claims stay as a permanent identity guard. Final card import must
  match the context's ordered claims. Tenant, audience and receipt UUID are
  server-owned. The opaque
  context token is stored only as SHA-256 and is consumed in the final import
  transaction.
- `POST /api/v1/admin/mailboxes/imports` — atomically register a 1–100 item
  mailbox reference manifest containing masked records and pre-provisioned
  `vault://secret/mailboxes/` references. It is not a raw credential upload
  endpoint; the mailbox account and password must already have been handled by
  a separate Vault security-import flow.
  The endpoint is separate from the card pool and never accepts mailbox
  passwords or returns secret references. Required `Secure-Import-Context`,
  `Secure-Import-Receipt`, and `Idempotency-Key` headers
  binds the validated ordered payload to a secret-free durable receipt; an
  exact replay returns that receipt with 200 and does not duplicate resources
  or audit events.
- `POST /api/v1/admin/cards/imports` — atomically register a 1–100 item card
  reference manifest containing masked records and pre-provisioned
  `vault://secret/cards/` references. It is not a raw card-data upload endpoint;
  PAN/CVV must be handled by a separate Card Vault security-import flow. The
  endpoint is separate from the mailbox pool and rejects PAN/CVV or mixed-pool fields.
  Each batch must also have exact unique `provider_ref` values after the existing
  field normalization. The importer rejects duplicates before reading the
  platform token, issuing a context, using Vault, or creating local execution
  evidence. Context issuance then rejects an existing or already-claimed tenant
  identity before the first Vault write; a concurrent request is closed by the
  target database uniqueness contract. The final API independently verifies the
  ordered claim binding before database writes. It uses the same required
  idempotency receipt contract, namespaced to the card pool. Mailbox records are
  not deduplicated by masked address because distinct accounts can share the
  same display mask.

The server-side Transit receipt verifier validates its Vault address before it
reads the Vault token file or creates a request. The default constructor and
all managed environments require a pure HTTPS origin with a non-empty IDNA
hostname and valid optional port; user information, path, query, fragment,
control characters and malformed authorities fail with a fixed error. Local
HTTP requires an explicit opt-in; the settings factory supplies it only for
`development` or `test`. Proxy inheritance is disabled and redirects are
rejected.

Both the Transit verifier and KV v2 resolver validate the optional
`PLATFORM_VAULT_NAMESPACE` before reading a Vault token. An empty value omits
the header; a configured value is preserved exactly, limited to 8192 visible
ASCII bytes, and may use `/` for namespace hierarchy. Leading/trailing
whitespace, embedded whitespace/control characters, non-ASCII input or an
oversized value fails with the fixed `Vault namespace is invalid` error. The
settings factories likewise do not trim a non-blank Vault address before its
origin validation.

When Vault is configured, both settings factories also consume the existing
`PLATFORM_INTERNAL_CA_FILE` trust bundle. They validate the origin and Namespace
first, then read at most 256 KiB from one stable runtime-file snapshot and pass
the ASCII PEM bytes to an in-memory TLS context; the TLS library never reopens
the configured path. Group/world-writable POSIX targets, an unstable or
relative path, invalid/oversized/non-ASCII PEM, and read failures produce the
fixed `PLATFORM_INTERNAL_CA_FILE is unavailable or invalid for Vault` startup
error before Vault token preflight or request construction. The context requires
hostname verification, certificate validation, and TLS 1.2 or newer. If no CA
file is configured in direct development/test construction, system trust is
used with the same TLS policy. The explicit HTTPS handler remains behind the
no-proxy, no-redirect opener.

The OIDC access-token verifier uses the same stable internal-CA snapshot
boundary for Keycloak JWKS. A configured `PLATFORM_INTERNAL_CA_FILE` is read
once with the same 256 KiB ASCII PEM limit and used to create an in-memory,
hostname-verifying TLS 1.2+ context; the TLS library is never given the CA path.
An invalid bundle fails with the fixed `OIDC TLS trust is unavailable or
invalid` result before the database is initialized or the JWKS client is
published. Rotate the mounted bundle atomically and restart the affected API or
worker process so a new immutable context is built.
- `POST/GET /api/v1/tasks` — idempotently create and list the current user's tasks.
- `GET /api/v1/tasks/{id}` — fetch an owned task; foreign tasks return 404.
- `GET /api/v1/tasks/{id}/timeline` — return the current-device task workbench's
  canonical `workbench_step`, masked child-resource status, and entity-bound safe
  event projection. Failed, unknown, and cancellation-pending uploads remain in
  the `uploading` step while their distinct recovery status is preserved; no
  card secret, verification code, policy, provider configuration, or business
  reference is exposed.
- `POST /api/v1/tasks/{id}/close` — close an owned active task and release task-bound resources.
- `POST /api/v1/tasks/{id}/mail-sessions` — bind an available masked mailbox
  to an owned task.
- `GET /api/v1/mail-sessions/{id}/code` — consume a one-time verification code.
  A successful response returns the code together with timezone-aware
  `received_at` and a code-independent, domain-separated SHA-256
  `message_id_hash`; waiting, replayed, expired, revoked, and lost-CAS responses
  return `code: null` and omit `received_at` plus `message_id_hash`.
- `GET /api/v1/mail-sessions/{id}/events` — stream verification-code status events.
- `POST /api/v1/mail-sessions/{id}/revoke` — revoke an active mail session. Code,
  event, and revoke requests require the opaque capability in
  `X-Mail-Session-Token`; the capability must never be placed in a URL.
- `POST /api/v1/tasks/{id}/card-allocations` — lease one server-managed card.
- `GET /api/v1/card-allocations/{id}?task_id={task_id}` — return only masked
  card details after binding the allocation to the caller's task context.
- `POST /api/v1/card-allocations/{id}/reveal-challenges` — bind a short-lived
  step-up request to the current actor, device, and active lease.
- `POST /api/v1/card-allocations/{id}/reveal-grants` — exchange a fresh OIDC
  authentication with the required ACR for a hashed, one-use reveal grant.
- `POST /api/v1/card-allocations/{id}/reveal` — atomically consume that grant
  and reveal PAN/expiry once; CVV is not part of the default API contract.
- `POST /api/v1/card-allocations/{id}/release` — release a lease.
- `POST /api/v1/tasks/{id}/uploads` — enqueue an idempotent Sub2 upload job.
- The Sub2 HTTP adapter projects Card Vault data onto an explicit PAN/expiry
  egress contract; CVV and unknown secret fields are never forwarded by default.
- `GET /api/v1/upload-jobs/{id}` — poll the upload state.
- `POST /api/v1/upload-jobs/{id}/cancel` — cancel a queued upload job.
- `POST /api/v1/upload-jobs/{id}/reconcile` — privileged reconciliation for unknown/failed jobs.
- `GET /api/v1/admin/policies/upload` — privileged, read-only upload policy
  status; returns booleans and version only, never `proxy_ref`, credentials,
  group, concurrency or upstream URLs.
- `GET /api/v1/admin/audit` — tenant-scoped structured audit search by actor,
  user, resource, event/result, trace and time range.
- `GET /api/v1/admin/audit/export` — bounded, redacted CSV export that omits
  free-form details and is returned with `no-store`.
- `/api/docs` — OpenAPI UI. Run `cd frontend && npm run generate:api` after
  contract changes; the quality gate rejects either a stale tracked
  `frontend/openapi.json` or stale generated TypeScript contract before building
  the Web console.

Configuration is environment-only and uses the `PLATFORM_` prefix, for
example `PLATFORM_ENVIRONMENT=staging` or `PLATFORM_DEBUG=true`. Do not put
tokens or passwords in source files or `.env` committed to the repository.
SQLite data defaults to `platform/platform.db` and can be changed with
`PLATFORM_DATABASE_URL`.

`PLATFORM_MAX_ACTIVE_DEVICES_PER_USER=5` limits new administrator-provisioned
devices by counting only non-revoked devices for the target tenant and user.
A value of `0` is an admission freeze: it rejects every new device registration
but does not revoke, delete, rename, or invalidate any existing device. An
already-active device with the same normalized name is an idempotent replay and
returns that device without consuming another slot. A revoked device name is
reserved and cannot be silently revived; attempting to provision it again
returns a conflict. Provisioning is serialized against the target user so
concurrent different names cannot exceed the configured limit.

This admission policy does not change either login contract. Local login still
requires a pre-existing `device_id`, and OIDC requests still derive `device_id`
from the verified access-token claim and revalidate it in the platform database;
neither path creates or revives a device. The bundled Keycloak realm currently
maps `device_id` from one static, single-valued user attribute. That mapper does
not prove distinct per-installation claims for simultaneous devices belonging
to one user, so the repository must not claim a complete multi-device OIDC
session lifecycle until a reviewed enrollment and per-session claim design is
implemented and tested in Keycloak.

`PLATFORM_AUTH_MODE=local` is development/test only. When its HMAC secret is
omitted, a random process-local secret is generated, so tokens stop working
after a restart. Production startup fails unless `PLATFORM_AUTH_MODE=oidc` and
issuer, audience, public client ID and JWKS URL are configured. OIDC accepts
only RS256 and validates issuer, audience, expiry, subject, `tenant_id`,
`device_id`, and a required `azp` that exactly names the reviewed Web or Desktop
client; user, role and device are then revalidated from the platform DB. Tokens
from another realm client are rejected before device activity or business writes
even if that client obtained the API audience.
The configured JWKS URL must be the exact Keycloak
`<issuer>/protocol/openid-connect/certs` endpoint. Managed environments require
HTTPS for both values. JWKS retrieval uses a ten-second, proxy-free,
no-redirect opener and accepts at most 64 KiB of strict UTF-8 JSON with no
duplicate keys. The JWK set is cached for five minutes, but individual signing
keys are not cached without a TTL, so reviewed Keycloak rotation is observed at
that bounded refresh boundary.
Logout always persists the exact bearer SHA-256. For OIDC tokens with a valid
optional `sid`, it also persists a domain-separated SHA-256 over issuer and sid,
so sibling access tokens from the same identity-provider session are rejected.
The raw sid is never stored, returned, or audited. Missing sid retains the older
exact-token behavior. Session entries currently use a nullable expiry and are
kept indefinitely until the deployed Keycloak session lifetime is proven.

There is no default account or password. Create a local development identity:

```powershell
python -m platform.bootstrap --tenant-id tenant-1 --email user@example.invalid --device-name workstation-1
```

The command prompts for the platform-account password without echoing it and
prints the generated user and device IDs. For production, first create the user
in Keycloak with reviewed `tenant_id` and `device_id` attributes, then provision
the matching subject without a local platform password:

```powershell
python -m platform.bootstrap --tenant-id tenant-1 --email user@example.invalid --device-name workstation-1 --oidc-subject KEYCLOAK_SUBJECT --role operator
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
mailbox credentials or raw message bodies. The HTTP connector never follows a
redirect and rejects a response larger than 64 KiB before JSON decoding, so an
upstream cannot forward credentials to another address or grow worker memory
without bound. A session records a connector
watermark, ignores messages at or before that watermark, and marks the first
newer code consumed; later polls return `{"status":"consumed","code":null}`.
Mailbox allocation locks candidate rows with `FOR UPDATE SKIP LOCKED` on
PostgreSQL and is backed by a partial unique index, so one mailbox cannot serve
two active sessions. Worker-delivered codes have an independent
`PLATFORM_MAIL_CODE_TTL_SECONDS` (60 seconds by default); expiry, revocation,
task close, and device/user disable paths erase the plaintext columns.
Mailbox capacity (`available`/`busy`/`disabled`) is deliberately separate from
connector runtime health (`unknown`/`healthy`/`unavailable`). Both the mail
worker and direct API polling path persist only the last safe health enum,
timestamp and a fixed error code; upstream exception text is never stored or
returned. A successful call clears the error, enabling the admin console and
`PlatformMailConnectorUnavailable` alert to show failure and recovery without
exposing credentials or provider responses.
Every `current_watermark` and `find_code_after` invocation also crosses a fixed
exception boundary. Any regular Connector exception is converted without its
original exception chain to the existing safe unavailable path, so one broken
mailbox cannot terminate the remaining worker batch or expose provider text in
an API error. Process-control exceptions such as `KeyboardInterrupt` and
`SystemExit` are deliberately not swallowed.
Every terminal task transition also invalidates the opaque mailbox-session
capability, including a session whose code was already consumed, so a completed
or closed task cannot keep using an otherwise valid session token.
The API-mode polling path remains available for local tests and injected
connectors.

Cards likewise store a provider reference, brand, last four digits, and an
opaque secret-manager reference—never PAN or CVV in the platform database.
Active leases are unique per card and task, tied to tenant/user/device,
time-limited, and audited. The ordinary allocation response returns only a
mask. Administrative inventory derives `available`, `allocated`, `disabled`,
and `quarantined` from the quarantine marker, compatibility activity flag, and
active lease; `allocated` is never duplicated onto the card row. Ops and
platform administrators may quarantine with a bounded reason code, but only a
platform administrator may release quarantine. Release leaves the card
disabled, so a second explicit enable is required. Allocation, reveal, upload,
and worker dispatch all reject a quarantined card. Migration 0022 is additive,
but the quarantine action must not be enabled until every older API/worker node
has exited; see the migration rollout runbook. The separate append-only
`card_events` history records each masked before/after state, reason, actor,
allocation, trace, and timestamp. The administrative card timeline exposes
only those reviewed fields and retrieves older lease/event history with
separate `(created_at, id)` keyset cursors. Targeted recycle acts on the
selected lease without affecting a later allocation.

A reveal first creates an actor-bound challenge; an isolated browser
PKCE flow must then produce a token whose signed `auth_time` is newer than the
challenge and whose `acr` equals `PLATFORM_CARD_STEP_UP_ACR`. The server stores
only a SHA-256 hash of the short-lived reveal grant and consumes it atomically.
Challenge creation, grant exchange, and the final reveal lock and revalidate the
task and allocation in a fixed order before any card secret is resolved. A
closed, completed, expired, released, disabled, or ownership-mismatched context
therefore fails with one non-enumerating error and never reaches Card Vault.
The reveal response is `no-store` and enforces the requested field allowlist:
an expiry-only reveal never resolves or returns PAN, while a PAN-only reveal
omits expiry. CVV is deliberately absent from the contract. No PAN, grant, or
CVV is written to audit events. The default
resolver is fail-closed and returns `503 service_unavailable` until a
production secret-manager adapter is injected. Configure a real Keycloak LoA
flow for the required ACR before production; a browser prompt by itself is not
accepted as step-up proof. Upload requests accept only `business_name` and an idempotency key.
Before the first upload job is created, the server requires the same task's
mail session to have been atomically consumed by the same tenant, user and
device while both task and session are valid. Missing, waiting, merely
`code_ready`, expired or revoked verification returns the stable
`verification_required` conflict; an already-created idempotent job remains
replayable without repeating the verification side effect.
Creating an upload job also inserts one payload-free `upload.requested` row in
`outbox_events` in the same database transaction. The upload worker claims only
those outbox rows; it does not scan `upload_jobs` as an implicit queue. A stale
event may be reclaimed only while its job is still `queued`. If the job had
already reached `running`, it becomes `unknown` for manual reconciliation so an
ambiguous external call is never submitted blindly a second time. Proxy
reference, group, concurrency, Sub2 credential reference, and card secret
reference are assembled inside the worker from `Sub2Policy`; none appear in
desktop requests, outbox rows, or API responses.

A confirmed successful upload is the task completion boundary. In the same
database transaction, the worker records `upload.succeeded`, transitions the
task to `completed`, releases its card allocation, revokes its mailbox session,
and writes the corresponding resource audit events. Privileged reconciliation
from `unknown` to `succeeded` uses the same completion path; reconciliation to
`failed` deliberately leaves the task recoverable. Replaying or concurrently
observing the terminal state does not duplicate release events.

Upload cancellation is an owner-bound conditional state transition rather than
an unconditional overwrite. Only the request that atomically changes `queued`
to `cancelled` or `running` to `cancel_pending` writes the cancellation audit
event. A late cancellation can never replace `succeeded`; terminal jobs return
the stable `upload_not_cancellable` conflict, while cancellation replay remains
idempotent.

The Sub2 worker dispatches a claimed outbox batch concurrently, but every
outbound call first acquires a Redis lease budget keyed by a hash of the tenant
and immutable policy version. The snapshot `concurrency` value is therefore the
maximum across all worker replicas for that policy scope, while different
tenants or policy versions stay isolated. Exact owner tokens, server-time
expiry, periodic renewal, and owner-only release recover capacity after a
worker crash without exposing tenant or policy names in Redis keys. Redis
failure before the external boundary fails closed and safely defers the outbox
event; release failure cannot hide a known Sub2 result. Development without
Redis retains the process-local limiter.

Capacity waiting happens before the upload job claim and outside every database
session. After a slot is acquired, the worker atomically claims the still-queued
job and revalidates authorization, task state, verification, and card bindings;
cancellation or resource revocation committed during the wait therefore wins
without consuming a database connection or crossing the Sub2 boundary.

Both dedicated workers run the same bounded lifecycle sweep before each polling
batch, so cleanup does not depend on a user opening an API page. The sweep uses
conditional terminal transitions plus `FOR UPDATE SKIP LOCKED`: expired tasks
release card leases, erase active mailbox codes/sessions, cancel queued uploads,
and move abandoned running uploads to `unknown`; an expired card lease cancels
and compensates its task. Independent mailbox and verification-code TTLs are
also enforced and audited. Repeating or concurrently running the sweep is
idempotent and does not duplicate terminal audit events.

The upload worker can call a server-side HTTP upload interface by setting
`PLATFORM_SUB2_UPLOAD_URL`. Without it, the worker remains fail-closed and jobs
become `adapter_unavailable`. The HTTP adapter never follows redirects and caps
responses at 64 KiB. Either condition is treated as an ambiguous `unknown`
result, not a definitive failure and not an automatic retry.

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
`X-Vault-Namespace`. The default resolver fails production/staging startup when
the address is missing or blank, before database initialization or any API/worker
listener starts. It validates the Vault origin before reading a file-backed
token or constructing a request: the hostname must be non-empty and IDNA-valid,
the optional port must be valid, and user information, path, query, fragment,
control characters or malformed authorities produce one fixed secret-free
address error. Managed environments require HTTPS; direct local development and
test construction permits HTTP only for `localhost`, loopback addresses, or the
internal `vault` service name. Its default opener does not inherit system proxy
settings and rejects redirects, preventing an `X-Vault-Token` header from being
forwarded to another recipient. An explicitly injected `SecretResolver` remains
supported for an approved KMS or cloud Secret Manager implementation.
The managed settings factory loads `PLATFORM_INTERNAL_CA_FILE` once from a
bounded stable snapshot into the Vault HTTPS context after origin/Namespace
validation and before token preflight; it does not give the CA pathname to the
TLS stack for a second open.
Production must set `PLATFORM_VAULT_TOKEN_FILE` to an
absolute path below `/run/secrets` or `/var/run/secrets`. The resolver reopens
that regular file for every Vault request, so an atomic token rotation is used
by the next resolve without restarting the process. Oversized, empty,
non-regular, symlinked, or group/world-writable token files fail closed. The
default production/staging resolver validates the current token file locally
before database initialization; this preflight neither caches the token nor
contacts Vault. A token that is revoked, expired, or denied by policy therefore
remains a target-environment broker/canary and runtime-acceptance concern. The
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
mailbox permission. A missing or unsafe token file fails managed-environment
startup before database initialization; a missing resolver otherwise makes
each Vault-backed operation fail closed.

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
errors use the envelope
`{ "error": { "code", "message", "recovery_hint", "trace_id" } }`. Ordinary
framework HTTP exceptions are reduced to a fixed status-based contract and
never reflect their detail or arbitrary headers. Only explicitly reviewed
`BusinessHTTPException` messages are returned; the exception boundary retains
only exact `WWW-Authenticate: Bearer` for 401 and validated standard methods in
`Allow` for 405. `python scripts/verify_http_error_boundary.py` locks this
contract and rejects dynamic ordinary route details. OpenAPI describes this
same closed error schema for router defaults and validation failures, so clients
can decode `code`, `message`, `recovery_hint`, and `trace_id` without guessing.
`/metrics` exposes only operational labels such as method, route template,
status code, and upload status; it must not include emails, card details,
business names, tokens, secret references, or proxy settings. The mail and
upload workers also write one JSON log event per polling batch with aggregate
status counts only. Prometheus scrape targets and alert rules live under
`infra/prometheus/`; the mail and Sub2 workers expose worker-local metrics on
their internal ports. Each worker alert covers both `up == 0` target loss and
an old batch timestamp, so a dead metrics endpoint and a live-but-stalled loop
are both paged.
Prometheus also scrapes Keycloak's internal management endpoint at
`keycloak:9000/metrics`. `PlatformKeycloakDown` pages after two minutes so a
later identity-service outage is visible even while already-started API and
edge containers remain healthy.
Audit events are append-only at both the application and database layer; update
and delete attempts are rejected so the audit trail remains tamper-evident.
Each event records structured actor/action/result, tenant/user/device/resource,
trace, bounded request IP and user agent, timestamp and policy version fields.
Known sensitive keys and Luhn-valid card numbers embedded in arbitrary strings
are redacted before persistence. The Web console never renders the free-form
details object, and its CSV export includes only reviewed structured fields.

Production and staging require `PLATFORM_RATE_LIMIT_ENABLED=true` and a
secret-managed `PLATFORM_REDIS_URL`. One atomic Redis Lua operation increments
each fixed-window counter and assigns its TTL. Login uses a hashed client-IP
identity; upload writes and card-reveal operations use hashed Bearer/IP
fingerprints with a stricter tier; ordinary requests use a wider tier. Raw
tokens, email addresses, tenants and IP values never enter Redis keys. Limit
responses include `Retry-After`, `X-RateLimit-*` and the normal trace envelope.
If Redis cannot make a decision, managed environments fail closed with 503 and
`/readyz` becomes unhealthy; development/test may disable or inject the backend.

Managed environments also require `PLATFORM_ALLOWED_ORIGINS` to contain an
exact comma-separated HTTPS allowlist. Browser requests that carry `Origin`
must match it and receive explicit CORS headers; unapproved origins fail with a
traceable 403. Native EXE and server-to-server requests normally carry no
`Origin` and remain supported. Wildcards, credential-bearing URLs, paths and
non-loopback HTTP origins are rejected at startup.

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

For the scale/compliance expansion path, `deploy/kubernetes/` provides a
fail-closed Kustomize base for the platform-owned API, Web, workers, and a
release-bound migration Job. Do not apply that base directly: target overlays
must supply reviewed image digests, external Secrets, ingress, and the
cluster-managed PostgreSQL/Redis/Keycloak/Vault endpoints, then pass a
server-side dry-run and target-cluster acceptance. Repository validation remains
`production_acceptance=false`; see `deploy/kubernetes/README.md`.

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

Keycloak uses the dedicated `KEYCLOAK_DB_USER` role; the long-running identity
service never receives the PostgreSQL bootstrap/migration credentials. The
PostgreSQL image runs `infra/postgres/init/02-create-platform-runtime-role.sh`
automatically only for a new data volume. Before upgrading an existing volume
from a release that let Keycloak use `POSTGRES_USER`, freeze identity writes,
start PostgreSQL without Keycloak, and run the same idempotent role/ownership
provisioning script inside the database container before starting the rest of
the stack:

```powershell
docker compose stop edge keycloak
docker compose up -d postgres
docker compose exec -T postgres sh /docker-entrypoint-initdb.d/02-create-platform-runtime-role.sh
docker compose up -d keycloak migrate api worker-mail worker-sub2 web edge
```

Stop if the provisioning command fails. Verify the Keycloak database backup,
the dedicated role ownership and a real OIDC login before reopening traffic.
The script reads passwords from the container environment through `psql
\getenv`; passwords are not command-line arguments or backup-manifest fields.

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
before deployment. The repository verifier also rejects API-audience mappers
assigned directly or through a client scope to any client other than the reviewed
Web/Desktop pair. Production must use a dedicated least-privilege database role.
The public desktop client enables Standard Flow with the native-app special
redirect `http://127.0.0.1` (random loopback ports), keeps Device Authorization
only as an explicit fallback, and enforces refresh-token rotation with zero
reuse. The EXE contains no OIDC client secret. `GET /api/v1/tasks?limit=1..100`
returns the current user's newest tasks with `trace_id`; desktop and Web UIs
show only task status/identifiers, never mailbox bodies, card secrets or Sub2
configuration.
After login or saved-session refresh, the desktop checks the newest
device-scoped task before enabling task creation. A non-terminal task requires
an explicit takeover or close action: takeover revalidates the strict timeline
projection, rotates the existing opaque mail capability only after user intent,
reuses the active card lease, and resumes the exact queued/running upload when
present. `unknown` and `cancel_pending` uploads remain review-only and cannot be
closed or resubmitted by the desktop.

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
not a backup of live users or credentials. A release rollback must create
authenticated schema-v5 evidence bound to the release tag, commit, migration
head, and SHA-256 of the immutable container release manifest. Its HKDF-derived
HMAC authenticates the complete canonical manifest. Use the helper from the
repository root:

```powershell
python -m scripts.postgres_maintenance backup-bundle --output-dir C:\ProgramData\EmailPlatform\backups\production-YYYYMMDDTHHMMSSZ --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-db email_platform --keycloak-db keycloak
python -m scripts.postgres_maintenance verify-bundle --input-dir C:\ProgramData\EmailPlatform\backups\production-YYYYMMDDTHHMMSSZ --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key
python -m scripts.postgres_maintenance restore-bundle --input-dir C:\ProgramData\EmailPlatform\backups\production-YYYYMMDDTHHMMSSZ --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-target-db email_platform_restore --keycloak-target-db keycloak_restore
python -m scripts.postgres_maintenance drill-bundle --output-dir C:\ProgramData\EmailPlatform\backups\drill-YYYYMMDDTHHMMSSZ --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-db email_platform --keycloak-db keycloak --platform-scratch-db email_platform_restore_drill --keycloak-scratch-db keycloak_restore_drill
```

Backup output is write-once: provision the external parent root, then pass an
absolute, repository-external leaf that does not already exist. Empty leaves,
symlink/reparse paths, and reuse of a completed bundle are rejected before key
access or `pg_dump`; retries use a new unique leaf. Single-database backup output
also uses no-replace publication and cannot overwrite an existing artifact.

The generic commands above remain available for disaster-recovery exercises.
For a release rollback, use `backup-bundle` with all four release-binding flags
shown in `deploy/runbooks/rollback.md`; the rollback executor refuses legacy
plaintext schemas 1/2, generic encrypted schema v3, and unauthenticated release
schema v4.
bundles, partial bindings, or a manifest that does not match the selected OCI
release exactly.

Redis persistence belongs to that same release recovery set; a PostgreSQL-only
bundle is not complete rollback evidence. The Redis helper fixes the production
Compose file and `redis` service internally, so it accepts no Redis URL or
password argument. Create an authenticated schema-1 release artifact only after
the PostgreSQL schema-v5 manifest exists:

```powershell
python -m scripts.redis_maintenance backup-release --output-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z\manifest.json --recovery-set v1.2.3-20260821T000000Z
python -m scripts.redis_maintenance verify-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --recovery-set v1.2.3-20260821T000000Z
python -m scripts.redis_maintenance restore-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-20260821T000000Z --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\postgres-v1.2.3-20260821T000000Z\manifest.json --recovery-set v1.2.3-20260821T000000Z --confirm-release-tag v1.2.3
```

Each Redis output leaf is write-once and must be an absolute,
repository-external path that must not already exist. Archive
`redis-data.tar.enc` with `redis-manifest.json`; schema 1 authenticates the
complete manifest with `manifest_hmac_sha256` and binds the release tag, commit,
migration head, container-manifest SHA-256, recovery set, and exact PostgreSQL
manifest SHA-256. Authentication must finish before destructive restore work.
Stop all writers and Redis, restore PostgreSQL and Redis from the same recovery
set, prove Redis health and restored data before starting the backend, and start
edge last. Signoff must retain restored `DBSIZE` and representative `PTTL`
evidence and prove an expired key did not reappear. `PING` is connectivity only and is
not restore evidence. Never place a Redis password, credential-bearing URL, or
backup key value in argv.

The bundle streams `pg_dump` directly through a versioned AES-256-GCM envelope;
no plaintext dump is written to disk. `manifest.json` records only the source
database, `platform.dump.enc`/`keycloak.dump.enc`, ciphertext byte size and
SHA-256, algorithm, format version, and non-secret key ID. The 32-byte key is
read only from an absolute, regular, non-symlink, restricted-permission file and
never appears in argv, logs, or the manifest. Restore authenticates the full
ciphertext and its logical/source-database identity before starting
`pg_restore`, then decrypts it a second time as a stream. The drill
also requires non-empty source databases and matching source/restored public
table counts for both databases. It emits matching source/restored row counts
for platform `users`, `devices`, `audit_events` and Keycloak `realm`,
`user_entity`, `credential`, `event_entity`, `admin_event_entity`; retain that
output as signoff evidence and review whether zero counts are credible for the
environment. Archive the entire
directory as one unit.

Vault integrated storage is backed up separately from PostgreSQL. Use a
short-lived operator token file; the token is passed only to the Vault CLI
child process and is never written to the command line or manifest. Use a
separate restricted 32-byte Vault manifest key. Verify the PostgreSQL schema v5
bundle first; Vault schema v2 then authenticates its exact canonical manifest
and binds the recovery set to that PostgreSQL manifest SHA-256:

```powershell
$recoverySet = "release-v1.2.3-20260821T000000Z"
$postgresBundle = "C:\ProgramData\EmailPlatform\backups\v1.2.3-20260821T000000Z"
$postgresManifest = "$postgresBundle/manifest.json"
$vaultBundle = "C:\ProgramData\EmailPlatform\backups\vault-v1.2.3-20260821T000000Z"
python -m scripts.postgres_maintenance verify-bundle --input-dir $postgresBundle --key-file C:\secure\postgres-backup.key
python -m scripts.vault_maintenance backup --output-dir $vaultBundle --address https://vault.example.com --token-file C:\secure\vault-snapshot.token --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest
python -m scripts.vault_maintenance verify --input-dir $vaultBundle --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest
python -m scripts.vault_maintenance restore --input-dir $vaultBundle --address https://isolated-vault.example.com --token-file C:\secure\isolated-vault-restore.token --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest --confirm-restore
```

`vault.snap` and `vault-manifest.json` must be archived together. Restore first
checks the schema-v2 HMAC, recovery-set/PostgreSQL binding, size, SHA-256 and
`vault operator raft snapshot inspect`, and refuses to run without explicit
confirmation. Exercise restore only against an isolated
cluster with matching seal/KMS material before approving production recovery.
The complete procedure is in `deploy/runbooks/vault-restore.md`; the `vault-dev`
Compose profile is ephemeral and is not a valid snapshot or restore target.

`deploy/release-manifest.json` is a source/Compose consistency snapshot. Before
a production cut, verify it against the working tree with:

```powershell
python -m scripts.release_manifest verify --manifest deploy/release-manifest.json
```

It is not a runtime image lock and must never be used as the rollback input.
Runtime rollback uses the previous tag's strict `container-release-manifest.json`
with `api`, `web`, and `edge` GHCR digests, plus an authenticated schema-v5
dual-database bundle bound to that manifest. `scripts.rollback_release plan`
verifies the manifest MAC and all bindings;
`execute` verifies Cosign/SBOM/provenance, pulls exact digests, restores both
databases, verifies internal services, and exposes the edge only after all checks
pass. Follow `deploy/runbooks/rollback.md`; do not restore only one database and
do not rebuild images during rollback.
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
It maps host ports 80/443 to unprivileged container ports 8080/8443. The
`frontend` network contains only edge/Web plus the dual-homed API and Keycloak;
PostgreSQL, Redis, Vault, workers and monitoring remain on the separate
`backend` network. Exact-network verification rejects host networking, missing
links and any extra shared network, so a compromised edge cannot directly
reach the data plane. Point both
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

### Container supply-chain release gate

Every push and pull request runs CodeQL `security-extended` analysis for Python
and JavaScript/TypeScript, and builds the API, Web, and Edge images locally in
the Security Gate workflow. Syft produces an SPDX JSON SBOM for each exact candidate
and Trivy fails the job on any HIGH or CRITICAL OS or library vulnerability,
including vulnerabilities without a published fix. The workflow uploads the
SBOM and SARIF evidence but never pushes pull-request candidates.

For a semantic-version tag, `release.yml` first runs the complete quality gate,
then builds each image once, generates its Syft SBOM, and passes the same Trivy
gate before authenticating to GHCR. Only that scanned local image is tagged and
pushed. The workflow signs the OCI digest with keyless Cosign using GitHub OIDC,
attaches the SPDX SBOM as a signed Cosign attestation, attaches GitHub build
provenance, and verifies the expected workflow identity and issuer. The Windows
GitHub Release job depends on all three matrix publications and includes their
SBOMs, Trivy SARIF reports, and `container-release-manifest.json`; a container failure therefore
prevents the desktop release from being published.

Both ordinary CI and tag releases also start a real PostgreSQL 16 service and
run Alembic `upgrade head` online. The gate fails if the repository exposes
multiple migration heads or the resulting database `alembic_version` differs
from the unique source head. Windows artifacts, container publication, and the
final GitHub Release all depend on this gate, so PostgreSQL-specific DDL errors
are detected before deployment rather than by the production `migrate` job.

All newly added third-party Actions and self-built image base references are
pinned to immutable commit or registry digests. Run
`python scripts/verify_container_supply_chain.py` locally to validate the
workflow structure and release ordering. Production signoff must record each
OCI digest, SBOM SHA-256, Cosign identity/issuer, and provenance evidence.
The container release manifest also locks the Alembic migration head, each Trivy
report hash, and the exact HIGH/CRITICAL gate result. It is the immutable image
input for `scripts.rollback_release`; the repository source manifest is not.

The Python runtime requirements currently use bounded version ranges rather
than a resolver-generated `--require-hashes` lock. Do not hand-author hashes:
generate and review the lock in a controlled Linux build environment, then make
the image install from that lock in a subsequent supply-chain change.

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
8. The four platform roles complete the five scenarios in
   `deploy/runbooks/role-training.md`; `scripts.training_evidence` seals a
   release-bound, independently reviewed record with
   `production_acceptance=false` and a canonical payload SHA-256.
9. A separate target-environment pilot proves real identity, Mail, Sub2,
   alert delivery, restore and rollback behavior. CI and training-tool tests do
   not satisfy this production gate.
