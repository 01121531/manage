# Web/API blue-green rolling release

This runbook retains the Web/API pair topology but covers only a Web-only
change with an unchanged API image.
`worker-mail` and `worker-sub2`
remain on the current single-instance release path, so this procedure must not
be described as a whole-platform zero-downtime rollout. Repository tests and
local Compose rehearsals always record `production_acceptance=false`.

## One-time target-host enablement

The stable Edge image contains the canonical blue route. During a separately
approved maintenance window, create an absolute, repository-external route
directory owned by the dedicated production deployment account, copy
`infra/nginx/slots/blue.conf` to `active-slot.conf`, and remove group/world
write permission. Configure `PLATFORM_ROLLING_ROUTE_DIR` and four distinct,
read-only green leaf paths in `.env`:

- `PLATFORM_ROLLING_GREEN_API_CERT_FILE` / `_KEY_FILE`, exact SAN `api-green`
- `PLATFORM_ROLLING_GREEN_WEB_CERT_FILE` / `_KEY_FILE`, exact SAN `web-green`

The currently running blue API must have been started by the immutable deploy
or rollback executor so its non-secret `PLATFORM_RELEASE_TAG`,
`PLATFORM_RELEASE_COMMIT`, and `PLATFORM_RELEASE_MIGRATION_HEAD` identity matches
the current manifest. An older `unidentified` container is not eligible as a
rolling source; publish it once through the reviewed single-instance path.

Mount the whole route directory through `docker-compose.rolling.yml`; never
bind only `active-slot.conf`, because atomic rename replaces its inode. The
green keys must be distinct from each other and from the existing API/Web keys.
Record the Edge enablement outage separately; later Web/API switches do not
stop or recreate Edge.

## Plan with immutable current and target evidence

Start from a clean shell owned by a dedicated production deployment account.
The current container manifest and authenticated PostgreSQL/Keycloak/Redis
recovery set must identify the release actually serving the declared active
slot. The target and current Edge digest must be identical; publish an Edge
change through the single-instance path instead of this runbook.

```powershell
python -m scripts.rolling_release plan `
  --container-manifest D:\release-evidence\v1.3.0\container-release-manifest.json `
  --current-container-manifest D:\release-evidence\v1.2.9\container-release-manifest.json `
  --rollback-backup-dir D:\release-evidence\v1.2.9\postgres `
  --rollback-redis-backup-dir D:\release-evidence\v1.2.9\redis `
  --rollback-recovery-set release-v1.2.9-20260825T010000Z `
  --rollback-key-file D:\release-keys\v1.2.9.key `
  --active-slot blue `
  --route-dir D:\email-platform-state\edge-routing
```

Review that the JSON says `release_strategy=web-api-blue-green`,
`rolling_release=true`, `source_retained_after_switch=true`, and
`production_acceptance=false`. It must also say
`worker_release_strategy=unchanged-single-instance`.

The planner rejects any changed API image because the API image is also the
`worker-mail`/`worker-sub2` binary. A connector protocol change (including the
task-start watermark acknowledgement, non-empty cursor, strict found response,
or authoritative `received_at`) must use the reviewed single-instance release
path: stop and drain both `worker-mail` and `worker-sub2` before exposing the new
API, deploy the new API and workers from the same immutable image, then resume
intake. Never use this blue-green procedure to leave an old mail worker eligible
to initialize a new mail session or an old Sub2 worker eligible to write uploads
without the current phase protocol.

## Execute the switch

```powershell
python -m scripts.rolling_release execute `
  --container-manifest D:\release-evidence\v1.3.0\container-release-manifest.json `
  --current-container-manifest D:\release-evidence\v1.2.9\container-release-manifest.json `
  --rollback-backup-dir D:\release-evidence\v1.2.9\postgres `
  --rollback-redis-backup-dir D:\release-evidence\v1.2.9\redis `
  --rollback-recovery-set release-v1.2.9-20260825T010000Z `
  --rollback-key-file D:\release-keys\v1.2.9.key `
  --active-slot blue `
  --route-dir D:\email-platform-state\edge-routing `
  --confirm-release-tag v1.3.0 `
  --container-manifest-sha256 REVIEWED_64_HEX_SHA256 `
  --domain platform.example.com `
  --target-intake-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --target-environment staging `
  --evidence-output D:\release-evidence\v1.3.0\rolling-execution.json
```

The write-once Phase 0 target intake snapshot created by
`target_intake_preflight.py snapshot` and the exact target environment are
validated before evidence preparation, the shared release lock, runner
construction, Git, Docker, migration, service, route, or Edge access. The
entrypoint captures one host-UTC instant and uses it both for that Phase 0
validation and ledger `started_at`; this is replayable ordering, not trusted
time or authenticated approval. The
checkpoint is limited to 64 KiB; duplicate JSON keys or an opened-file identity,
link-count, size, or modification-state change are rejected before those steps. The
evidence parent directory must already exist outside the repository and
the output file must not exist. The executor refuses relative paths,
repository paths, symlink/reparse paths and pre-existing targets before any
release mutation. It publishes one canonical, SHA-256-sealed JSON file without
replace semantics. Verify it independently:

The intake-bound evidence contract is schema v3. Older ledgers that lack the
current TLS and intake contract must be rejected, not edited in place or
upgraded; execute a new attempt into a new write-once evidence leaf. The ledger
has no expiry of its own. Final strict intake reconstructs the frozen Phase 0
validity intersection and requires `started_at` inside it, while selection
review and every consuming execution window must follow `finished_at`. This does
not claim continuous authorization or an automatic mid-run expiry rollback.
The manifest's reviewer reference and UTC value are an opaque claim only;
digest/order checks do not authenticate the reviewer, establish trusted time or
provide global replay protection, and private-secret signing keys are not valid
for this release-review domain.

```powershell
python -m scripts.rolling_release_evidence `
  --input D:\release-evidence\v1.3.0\rolling-execution.json `
  --expected-source-tag v1.2.9 `
  --expected-source-commit REVIEWED_SOURCE_40_HEX_COMMIT `
  --expected-source-container-manifest-sha256 REVIEWED_SOURCE_64_HEX_SHA256 `
  --expected-target-tag v1.3.0 `
  --expected-target-commit REVIEWED_TARGET_40_HEX_COMMIT `
  --expected-target-container-manifest-sha256 REVIEWED_TARGET_64_HEX_SHA256 `
  --expected-target-environment staging `
  --expected-target-intake-manifest-sha256 REVIEWED_CANONICAL_INTAKE_PAYLOAD_SHA256 `
  --expected-target-intake-requirements-sha256 REVIEWED_REQUIREMENTS_SHA256
```

This standalone verifier proves the ledger's closed schema, integrity,
successful terminal, source/target/intake identity and internal chronology
only. It deliberately does not read the frozen Phase 0 checkpoint and therefore
does not prove start-time authorization. That replay is established only by
final strict intake with the exact repository-external
`--phase0-checkpoint-manifest`; do not promote
`rolling-release-evidence-ok` into a Phase 0 causality result.

The ledger verifier performs one bounded stable-file read with a 64 KiB limit
before parsing. Link/reparse paths, duplicate JSON keys, and any identity,
link-count, size, or modification-state change fail closed without printing the
ledger content.

The expected identities must come from the independently reviewed source and
target container manifests and canonical intake payload, not from the ledger
being checked. This prevents a structurally valid ledger from a different
release pair, target environment, intake payload, or requirements revision from
being reused for signoff.

The three release controls share one OS advisory release-control lock. After
acquiring it, the executor first revalidates that the protected route still
matches the declared source slot; a route already pointing at the target is not
treated as an unauthenticated resume. It pins both single-instance Worker
services to the authenticated source API digest and verifies those runtime
digests before migration and after the switch. The executor then verifies the
clean checkout, current strict TLS identity, supply chain, third-party scans,
and migration compatibility before mutation. It runs the reviewed expand
migration, starts only the
inactive API/Web services with `--no-deps --no-build --pull never`, checks exact
TLS hostnames, release identity and container image digests, atomically replaces
the canonical API/Web pair, runs `nginx -t`, sends an Nginx reload, and requires
three public `/releasez` identity observations without redirects.

`/readyz` is an exact Edge route to the active API; it no longer falls through
to the Web SPA. The compatibility marker allows release N to remain ready after
an approved N+1 expand migration, while a future contract floor rejects N.

## Failure and cleanup rules

- Before traffic switching, any failure leaves the active route and Edge
  untouched and stops only the inactive candidate.
- If target observation fails, restore the old canonical pair first, run
  `nginx -t`, reload Edge, prove the source `/releasez` identity three times,
  and only then stop the failed candidate.
- If old-route recovery cannot be confirmed, keep both slots running, page the
  operator, and treat `route_unconfirmed` as an incident. Do not stop Edge or
  either slot and do not run Alembic downgrade.
- A successful switch ends as `COMPLETE_SOURCE_RETAINED`. Do not stop the
  source slot until target-environment evidence shows old Nginx workers have
  drained, application in-flight work is zero, error/latency SLOs are stable,
  and an independent reviewer approves cleanup.

The external route directory contains `rolling-release-state.json`, which has
only immutable release identifiers, the plan fingerprint, phase and fixed
error code; it contains no credentials. Preserve it with the target pilot
evidence.

Every execute attempt also terminates in exactly one structured evidence
state: `complete_source_retained`, `switched_back`, `route_unconfirmed`, or
`pre_switch_failed`. The closed schema records source/target release identity;
the Phase 0 target environment, canonical intake payload SHA-256, requirements
SHA-256 and checkpoint phase;
source/target API, Web and unchanged Edge digests; Worker digest observations
before and after execution; route content SHA-256 before and after; phase UTC;
Nginx test/reload results; and each of the three validated public `/releasez`
observations. Schema v3 also records source/target API and Web expected/peer
leaf SHA-256 values and negotiated TLS versions, plus the same identity fields
for every passed public observation. The certificate fingerprint and HTTP
identity are read from the same verified connection; target drift triggers the
normal source-route restoration path. It never records command arguments, inherited environment,
domain or URL, host paths, certificate material, raw exception messages or
secrets, and `production_acceptance` is always `false`.

## Target evidence and signoff

Local FakeRunner ordering, Compose rendering, TLS assets and CI checks are only
preflight. Production approval additionally requires exact source/target
digests, API/Web release identities, atomic paired switch, mixed-version
traffic window, exact API release identity, exact Web image digest and health,
three consecutive public observations, alert continuity,
connection drain, failure-injection switch-back, lock contention, and an
independent operator/reviewer. Record all evidence in
`deploy/production-signoff-template.md`.
