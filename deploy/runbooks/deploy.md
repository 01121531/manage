# Immutable forward production deployment

Use this procedure to deploy the three verified application images from one
GitHub Release `container-release-manifest.json`. PostgreSQL, Redis, Keycloak,
Prometheus, and Alertmanager are a separate upstream trust set: resolve each
approved image to its authoritative multi-architecture manifest digest, review
that resolution independently, and place only the 64 lowercase hexadecimal
digest fragment in the matching `*_IMAGE_SHA256` setting. Production Compose
fixes each repository name and the `@sha256:` prefix; it has no mutable tag or
fallback for these five services.

The only mutable image exception is the local helper `hashicorp/vault:1.18`,
whose Compose profile must remain exactly `vault-dev`. It is not a production
service, must never be enabled in a production command, and is excluded from
the five production dependency digest injections.

This repository uses a single-instance Compose topology. This procedure keeps
the public edge fail closed during the change, but it is **not** a rolling or
zero-downtime release. Do not use it as rolling-release evidence.

## Required inputs

- The reviewed GitHub Release `container-release-manifest.json` containing
  exactly the API, Web, and Edge GHCR digest references.
- Its independently reviewed SHA-256 value and matching release tag.
- Release publication must assemble that manifest from exactly three image
  metadata files and their six named SPDX SBOM/Trivy SARIF artifacts. Each
  metadata file is a stable regular non-link file no larger than 64 KiB and has
  unique JSON keys; each SBOM/SARIF is a non-empty stable regular non-link file
  no larger than 32 MiB. Identity, link-count, size, or modification-state
  drift blocks publication, and each recorded artifact SHA-256 is computed from
  the same stable bytes that passed the size and file-shape checks.
- A Git checkout with `.git` metadata whose exact `HEAD` equals the manifest
  commit. The tracked index and worktree must be clean. Deployment from a
  source archive without `.git` is not supported by this procedure.
- The container manifest for the release that is currently running. Its tag,
  commit, migration head, and manifest SHA-256 must exactly bind the rollback
  backup below.
- A fresh authenticated schema-v5 backup directory containing both `platform`
  and `keycloak`, created no more than one hour before the preflight. A creation
  time more than five minutes in the future is rejected.
- A fresh authenticated Redis schema-1 backup containing `redis-data.tar.enc`
  and `redis-manifest.json`, bound to the current release and the same recovery set
  and exact PostgreSQL manifest SHA-256. A PostgreSQL-only rollback point is
  incomplete and must block deployment.
- The backup encryption key in a repository-external, absolute, read-only key
  file. Never place the key value in an argument, environment variable, log, or
  signoff record.
- `docker`, `cosign`, `gh`, Trivy, and Python on the deployment host. Trivy
  must be able to update its vulnerability database and read all five approved
  public-registry digest references without registry credentials.
- The already provisioned production `.env`, external runtime secret files,
  internal TLS files, and running PostgreSQL/Redis/Keycloak dependencies.
  Independently verify that `.env` is a regular, non-symlink file with the
  intended owner, restrictive permissions, reviewed content, and readable
  secret-file targets on the deployment host; the repository gate cannot prove
  those target-host facts.
- The public Edge certificate and private-key paths resolve before any Edge
  stop to existing, non-symlink regular files readable by container UID 101.
  The private key must also be a single-link owner-only file (`0600` or stricter
  on POSIX, protected operator/SYSTEM/Administrators DACL on Windows); its
  preflight permissions and PEM bytes are checked on the same descriptor.
  The production Compose mounts both with structured read-only binds and
  `create_host_path: false`; a missing or directory-valued source blocks the
  change and must never be repaired by allowing Docker to create the path.
  Both paths must be absolute, outside the repository, and distinct. The first
  certificate must be a currently valid non-CA leaf whose DNS SAN contains the
  requested platform domain, and its public key must match the unencrypted PEM
  key in `PLATFORM_TLS_KEY_FILE`.
- Independently reviewed `POSTGRES_IMAGE_SHA256`, `REDIS_IMAGE_SHA256`,
  `KEYCLOAK_IMAGE_SHA256`, `PROMETHEUS_IMAGE_SHA256`, and
  `ALERTMANAGER_IMAGE_SHA256` values. Each is exactly 64 lowercase hexadecimal
  characters obtained from the approved upstream registry; never infer a
  digest from a tag seen in a previous deployment.

The production [docker-compose.yml](../../docker-compose.yml) has no application
`build:` entries and no local-image fallback. The three `PLATFORM_*_IMAGE`
values are supplied by the executor from the reviewed release manifest. Local
builds require both `docker-compose.dev.yml` and `.env.development.example`:

```powershell
docker compose --env-file .env --env-file .env.development.example -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Before the first production start or any planned dependency update, run the
repository gate and inspect the fully rendered image references:

```powershell
python scripts/verify_deploy_release.py
python scripts/validate_edge_tls.py --env-file (Resolve-Path .\.env).Path --domain platform.example.com
$images = docker compose --project-directory (Resolve-Path .).Path --env-file (Resolve-Path .\.env).Path --project-name email-platform --file (Resolve-Path .\docker-compose.yml).Path config --images
if ($LASTEXITCODE -ne 0 -or $images.Count -ne 12) { throw "production image render failed" }
$thirdParty = $images | Where-Object { $_ -match '^(postgres|redis|quay\.io/keycloak/keycloak|prom/(prometheus|alertmanager))@sha256:[0-9a-f]{64}$' }
if ($thirdParty.Count -ne 5) { throw "third-party image digest injection is incomplete" }
```

Record the five rendered references, registry resolution evidence, review UTC,
and independent reviewer without copying registry credentials. A tag, uppercase
or non-64-hex digest, missing value, fallback, or unresolved registry response
blocks the dependency start/update. Change one dependency digest per approved
maintenance change; application deployment does not implicitly update them.
These Compose repository checks prove only fail-closed digest injection. The
deployment executor separately invokes Trivy for PostgreSQL, Redis, Keycloak,
Alertmanager, and Prometheus in that fixed order, binding every SARIF report to
the exact rendered `repository@sha256:digest`. It scans OS and library
vulnerabilities, includes unfixed findings, and fails on every HIGH or CRITICAL
finding, missing scanner, database/registry error, malformed report, wrong
target, non-Trivy report, or non-empty result set. Reports live only in an
automatically cleaned temporary directory. The local `vault-dev` helper is not
a production dependency and is not part of this five-image gate.

Every generated SARIF is consumed through one stable regular-file read capped
at 32 MiB. The reader rejects link/reparse paths and ancestors, empty or
oversized reports, duplicate JSON keys at any nesting level, and any
device/inode/link-count/size/mtime or named-path shape drift during the read.
These failures map to the same generic invalid-report gate and stop the fixed
image sequence before deployment mutation.

This gate proves only that the exact supplied digests passed the target host's
Trivy database at execution time. It does not prove that those digests are the
latest upstream release, independently approved, signed by their publishers,
or free of lower-severity/unknown vulnerabilities. Record the Trivy version,
database update UTC, five exact digest references, pass UTC, and independent
reviewer as target-environment evidence. Keep `production_acceptance=false`
until the real scan and upstream review succeed.

Remove `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`, `COMPOSE_PROFILES`, and
`COMPOSE_ENV_FILES` from the production execution context, and remove
`compose.override.yaml`, `compose.override.yml`, `docker-compose.override.yaml`,
and `docker-compose.override.yml`. Apart from the five reviewed dependency
digest fragments, do not export any variable interpolated by the production
Compose file: the executor rejects process-level overrides and supplies the
three application images from the authenticated manifest. Every Compose call
pins the absolute production Compose file, absolute `.env`, repository project
directory, and project name `email-platform`; auto-discovery and caller-shell
configuration are not part of this release path.

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


## Create and authenticate the current rollback recovery set

Create the PostgreSQL schema-v5 bundle first. Then create Redis into a distinct
write-once leaf and bind it to the PostgreSQL manifest:

```powershell
python -m scripts.postgres_maintenance backup-bundle --output-dir C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --platform-db email_platform --keycloak-db keycloak --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
python -m scripts.redis_maintenance backup-release --output-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest C:\ProgramData\EmailPlatform\backups\v1.2.3-before-next-deploy\manifest.json --recovery-set v1.2.3-before-next-deploy
python -m scripts.redis_maintenance verify-release --input-dir C:\ProgramData\EmailPlatform\backups\redis-v1.2.3-before-next-deploy --key-file C:\ProgramData\EmailPlatform\secrets\backup-aes.key --release-tag v1.2.3 --release-commit 0123456789abcdef0123456789abcdef01234567 --migration-head 0018_access_token_revocations --container-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --postgres-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --recovery-set v1.2.3-before-next-deploy
```

`backup-release` stops and automatically restarts only a Redis instance that was
running before the backup. It returns only after the fixed production Compose
project reports Redis running and `/usr/local/bin/redis-healthcheck` passes.
`Redis restart could not be confirmed` is fatal: do not treat that attempt's
manifest as successful or continue the release.

The PostgreSQL and Redis leaves must each be an absolute,
repository-external path and must not already exist. A retry uses a new unique
leaf; it never overwrites or refreshes the approved rollback point. Neither key
values nor Redis passwords may enter argv, environment, logs, or manifests.

## Review the deployment plan

```powershell
python -m scripts.deploy_release plan `
  --container-manifest release/assets/container-release-manifest.json `
  --rollback-container-manifest current/container-release-manifest.json `
  --rollback-backup-dir D:\protected\rollback\current `
  --rollback-redis-backup-dir D:\protected\rollback\redis-current `
  --rollback-recovery-set v1.2.3-before-next-deploy `
  --rollback-key-file D:\protected\keys\postgres-backup.key
```

The plan is static preflight evidence and reports
`production_acceptance=false` and `rolling_release=false`. A second operator
must compare its tag, commit, migration head, manifest SHA-256, and all three
OCI digest references with the approved GitHub Release.
It must also compare the authenticated rollback release binding and backup UTC
creation time with the currently running release, then authenticate the Redis
manifest's same release and recovery-set/PostgreSQL-SHA binding. The plan output
never includes the backup key or its path.

## Execute

```powershell
python -m scripts.deploy_release execute `
  --container-manifest release/assets/container-release-manifest.json `
  --rollback-container-manifest current/container-release-manifest.json `
  --rollback-backup-dir D:\protected\rollback\current `
  --rollback-redis-backup-dir D:\protected\rollback\redis-current `
  --rollback-recovery-set v1.2.3-before-next-deploy `
  --rollback-key-file D:\protected\keys\postgres-backup.key `
  --container-manifest-sha256 <reviewed-64-hex-value> `
  --confirm-release-tag v1.2.3 `
  --domain platform.example.com `
  --target-intake-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --target-environment staging `
  --evidence-output D:\protected\deployment-evidence\deploy-v1.2.3-<unique-utc>.json
```

The target intake manifest is the absolute repository-external write-once Phase
0 snapshot created by `target_intake_preflight.py snapshot`, not the original
manifest that later accumulates Phase 4/6 evidence. The checkpoint must be at
most 64 KiB, contain no duplicate JSON keys, and remain the same regular-file
identity and shape throughout its bounded read.
The executor requires the exact target environment and the strict Phase 0
checkpoint before it prepares evidence, acquires the release lock, constructs a
runner, or invokes Git, Trivy, Docker, Cosign, Compose, migrations, services, or
Edge changes. The entrypoint captures one host-UTC instant, passes it as the
Phase 0 checkpoint evaluation time, and records that exact value as ledger
`started_at`; this proves byte-bound ordering but does not make the host clock
trusted time or authenticate external approval. The executor then enforces this order:

1. Before acquiring the shared release-control lock, validate the evidence
   output as an absolute, repository-external new file whose parent already
   exists; relative, repository-local, existing, symlink, reparse-point, and
   racing targets fail before the lock or runner. Then, before creating a
   command runner or invoking Git, Trivy, Docker, Cosign, or Compose, read the
   fixed production `.env` and validate the public Edge
   certificate chain, exact DNS SAN, current validity, distinct external paths,
   and certificate/private-key match. Then validate the three fixed Vault token
   directory mappings and their Compose bind contract using metadata only:
   external absolute non-overlapping directories, non-aliased regular `token`
   leaves, bounded size, and the reviewed container identity/permissions where
   POSIX metadata is available. The executor never reads, hashes, compares, or
   logs token values. Any failure is redacted and leaves the current release
   untouched.
2. Before Cosign, image pull, or any Docker Compose command, require exact
   equality between Git `HEAD` and the target manifest commit, a clean tracked
   index/worktree, no Compose control variable or default Compose override, and
   no caller-shell override of a production Compose input other than the five
   reviewed dependency digest fragments. Git absence or a non-repository
   checkout fails closed without printing drifted paths or content, and without printing environment values.
3. Strictly parse the target container manifest. Load the current release with
   the reviewed rollback loader, authenticate the exact schema-v5 manifest and
   both encrypted database artifacts, then authenticate the Redis schema-1
   manifest and ciphertext. Require both artifacts' release fields, recovery
   set, and PostgreSQL manifest SHA-256 to match the current container manifest,
   and enforce the one-hour/five-minute freshness window.
4. Before any target image pull, `edge` stop, or migration, run the operational
   gate. Require PostgreSQL, Redis, Keycloak, API, both workers, Web, `edge`, Prometheus, and Alertmanager to be running.
   Verify the current release's exact digests with Cosign, its
   SPDX SBOM attestation, and GitHub build provenance,
   and compare every current container image reference with that release.
5. Scan all five exact third-party digest references with Trivy before any
   target pull or Compose mutation. A missing tool, unavailable vulnerability
   database/registry, invalid report binding, or HIGH/CRITICAL finding blocks
   the deployment while the current release remains untouched.
6. Verify the three target image digests with the same supply-chain controls,
   then pull all three exact target digests. Any failure through this point
   performs no Compose stop or up operation and leaves the current release
   untouched.
7. Stop `edge` and start migration, API, both workers, and Web with
   `--no-build --pull never`. Prometheus and Alertmanager remain running.
8. Require Keycloak and every backend service to be running; compare API, both
   workers, and Web container image references with the manifest digests.
9. Run the reviewed internal TLS smoke against all seven service endpoints:
   `https://api:8443/readyz`, `https://web:8443/`,
   `https://keycloak:9000/health/ready`,
   `https://keycloak:8443/realms/email-platform/.well-known/openid-configuration`,
   `https://worker-mail:9101/metrics`, `https://worker-sub2:9102/metrics`, and
   `https://prometheus:9090/-/ready`. Every probe uses service DNS, the
   internal CA, hostname verification, and a TLS 1.2 minimum; it requires exact
   HTTP 200 and rejects every redirect. After every probe succeeds, repeat the
   Vault sink metadata and Compose-bind check from the fixed files. A failed
   point-in-time recheck keeps `edge` closed.
10. Start `edge` last with `--no-build --pull never`, compare its running image
   reference with the manifest digest, run normal external HTTPS smoke, and
   repeat the exact ten-service running gate before reporting success.

The Alertmanager repository gate proves only that Compose reports its container
running; the API probe container is not attached to the alerting-only network.
It does not prove Alertmanager readiness, routing, receiver credentials, or live
alert delivery. Validate those in the target environment and keep
`production_acceptance=false` until recorded.

Any failure after the transition starts leaves `edge` stopped. Record the exact
manifest SHA-256, expected and observed application digests, verification
results, authenticated rollback binding/MAC/freshness, current running digests,
PostgreSQL/Redis recovery-set equality, Redis key-count/TTL/expired-key drill
evidence, timestamps, outage window, and independent reviewer in the production signoff.
Do not copy the backup key or secret-bearing error details into evidence. Static
verifier and mocked command-order tests remain
`production_acceptance=false`; target-environment execution is required.
Every execute attempt publishes one closed-schema terminal record with one of
`succeeded`, `preflight_failed`, `edge_closed_failure`, or `edge_unconfirmed`.
It binds the target release, the Phase 0 target environment, canonical intake
manifest payload SHA-256 and requirements SHA-256, authenticated rollback release and PostgreSQL/Redis
recovery set, five application expected/observed digests, five reviewed
third-party digest references, ordered phase UTC values, checks, final Edge
state, and a canonical payload SHA-256. Publication uses a same-directory
temporary file plus no-replace hard-link commit; retry with a new unique leaf.
The intake-bound evidence contract is schema v3. Older records that lack the
current TLS and intake contract must be rejected rather than rewritten or
promoted; run a new release attempt with a new write-once evidence leaf. The
ledger remains immutable history and has no expiry of its own. Final strict
intake reconstructs the frozen Phase 0 review-validity intersection and requires
`started_at` inside it; it does not invent continuous authorization, renewal or
mid-run expiry rollback. Ledger selection review and every consuming execution
window must follow ledger `finished_at`.
If publication fails after Edge was opened, the executor closes Edge again and
never reports success. An unconfirmed closure has priority over the original
execution or publication error.

Independently verify the file from approved target and rollback JSON projections
and the reviewed digest references; do not derive expected values from the
evidence being checked:

```powershell
python -m scripts.deploy_release_evidence `
  --input D:\protected\deployment-evidence\deploy-v1.2.3-<unique-utc>.json `
  --expected-target-release D:\protected\deployment-evidence\approved-target.json `
  --expected-target-environment staging `
  --expected-target-intake-manifest-sha256 <independently-computed-canonical-intake-payload-sha256> `
  --expected-target-intake-requirements-sha256 <reviewed-requirements-sha256> `
  --expected-rollback D:\protected\deployment-evidence\approved-rollback.json `
  --expected-api-image <api-digest-ref> `
  --expected-worker-mail-image <api-digest-ref> `
  --expected-worker-sub2-image <api-digest-ref> `
  --expected-web-image <web-digest-ref> `
  --expected-edge-image <edge-digest-ref> `
  --expected-postgres-image <postgres-digest-ref> `
  --expected-redis-image <redis-digest-ref> `
  --expected-keycloak-image <keycloak-digest-ref> `
  --expected-alertmanager-image <alertmanager-digest-ref> `
  --expected-prometheus-image <prometheus-digest-ref>
```

The execution ledger and both independently approved projection files each use
one bounded stable-file read with a 64 KiB limit before parsing. They reject
link/reparse paths, duplicate JSON keys, and any identity, link-count, size, or
modification-state change; exact projection fields, canonical payload
validation, and errors remain content-free.

Compute the intake payload SHA-256 independently from canonical JSON content,
not from a path copied out of the execution ledger. Archive the evidence file,
its whole-file SHA-256, the printed canonical payload
SHA-256, the two approved projections, and the independent reviewer's identity.
The record deliberately remains `production_acceptance=false`; it is an
execution ledger, not a substitute for live data correctness, RTO/RPO, public
TLS, alert delivery, outage-window, or human signoff evidence.
Its schema-v3 TLS observations bind all seven internal endpoints and both
external endpoints to reviewed leaf SHA-256 values. Each passed item contains
only the expected fingerprint, the peer DER SHA-256 and the TLS version from
the same verified socket used for the HTTP check. Missing, duplicate, drifted,
extra-field or TLS 1.1 observations invalidate the terminal ledger; no URL,
host path or PEM bytes are retained.
The preflight does not prove public-CA trust, OCSP/revocation state, container
UID readability on Windows hosts, host ACL equivalence to container identity,
absence of a later TOCTOU replacement, token validity/policy, Nginx reload
behavior, or a real client handshake; those remain mandatory target-environment
acceptance checks.
