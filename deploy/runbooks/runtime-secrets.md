# Production runtime secret files

This runbook covers PostgreSQL, platform/Alembic, Redis, Keycloak and the three
per-service Vault token sinks used at startup. `python
scripts/verify_runtime_secrets.py` is a repository
preflight only; it does **not** prove that target-host files exist or are
correct. Record target evidence with `production_acceptance=false` until an
independent operator completes the checks below.

## Prepare outside the repository

Create every host path named by the `*_FILE` entries in `.env`. Secret-manager
delivery must use an atomic write/rename, owner matching the container runtime
UID, mode `0400` or `0440`, and a parent directory that is not writable by
untrusted users. Never put file contents in `.env`, Compose, shell history,
support bundles or signoff evidence. The three PostgreSQL passwords must be
mutually distinct; each URL file must be distinct and role-specific. URL-encode
reserved password characters in URL files.

Each URL file contains exactly one non-empty line:

- the migration URL uses the schema owner and is mounted only into `migrate`;
- the platform database URL uses the DML-only role and is mounted into API and
  both workers;
- the Redis URL uses the application ACL user and is mounted only into API and
  `worker-sub2`.

Database, Redis, migration and Vault runtime values are projected-secret
inputs, not standalone operator-key files. Their readers deliberately allow a
stable Kubernetes projected symlink, open one target snapshot, and require the
projected name to resolve to that same regular object before and after reading.
DB/Redis/migration URL permission checks use the metadata returned with those
same bytes and reject group/world-writable targets; Vault token handling does
the same without caching across requests. The PostgreSQL/Redis health and
bootstrap shell readers likewise open one descriptor and compare the projected
path with `/proc/self/fd` before and after reading instead of validating and
then reopening a pathname. A rotation completed before the call is accepted;
a switch during a call fails closed.

`redis.conf` must include `appendonly yes` and
`aclfile /run/secrets/redis/users.acl`. The external ACL file must disable the
default user, give the application user only the required key patterns and
commands, and give `healthcheck` only `+ping`. Store the healthcheck user's
password in the separate `REDIS_HEALTHCHECK_PASSWORD_FILE`; the helper supplies
it to `redis-cli --askpass` over stdin, never in argv or configured environment.
The application ACL must cover both `rate-limit:*` and
`sub2-concurrency:*` keys. The latter requires the reviewed Lua entry point and
only the `TIME`, `GET`, `SET`, `DEL`, `PEXPIRE`, `ZADD`, `ZCARD`, `ZRANGE`,
`ZREM`, `ZREMRANGEBYSCORE`, and `ZSCORE` operations used by the atomic lease
scripts; do not grant broad administrative or unrelated data commands.

The external Keycloak configuration must contain `db=postgres`,
`db-url=jdbc:postgresql://postgres:5432/keycloak`, `db-username`, `db-password`,
`bootstrap-admin-username` and `bootstrap-admin-password`. Bootstrap values are
temporary and act only while the master realm is absent; rotate/remove them
from the delivered file after initial bootstrap according to change control.

Before issuing credentials, an approved administrator runs
`VAULT_ADDR=https://... sh infra/vault/configure-approles.sh`. The helper must
finish its structured read-after-write comparison for all three roles; any
HTTP address, missing `jq`, extra/default policy, periodic token, TTL drift, or
non-empty SecretID/token CIDR or alias metadata, or `local_secret_ids=true` is a
fixed fail-closed result. It reads only role
metadata and must never read RoleID, SecretID or token endpoints. This result
does not replace the later service-policy canaries.

The same administrator then runs `VAULT_ADDR=https://... sh
infra/vault/configure-broker-issuer-policies.sh`. Its write/readback comparison
must match all three reviewed issuer policy files. In the target Vault, bind
three distinct external principals, one to each of
`email-platform-broker-issuer-api`, `email-platform-broker-issuer-mail`, and
`email-platform-broker-issuer-sub2`. Each issuer may only read its own RoleID and
create its own one-use SecretID. It must be denied the other two AppRoles, all
runtime KV paths, policy administration, role configuration, and
`auth/token/revoke-accessor`. Keep `infra/vault/broker-contract.json` at
`production_acceptance=false` until the complete target evidence matrix is
independently reviewed.

The approved external credential broker runs outside this Compose project. It
must authenticate the three isolated issuer identities, exchange each fresh
RoleID and one-use SecretID for a service token with exactly the matching
service policy and no default or identity-added policy, and
successfully create `token` below each of `PLATFORM_VAULT_API_TOKEN_DIR`,
`PLATFORM_VAULT_MAIL_TOKEN_DIR` and `PLATFORM_VAULT_SUB2_TOKEN_DIR` before any
application container starts. Each leaf is a 1..4096-byte regular file with one
non-whitespace opaque token, no symlink/reparse path, the matching container UID
as reader and mode `0400` or `0440`. Keep the broker running so it can issue a
fresh one-use SecretID, re-authenticate, and rotate before token expiry. The
service policies do not grant token renewal or other token-management access.
Replace a sink atomically within its directory; never use a
delete-then-create rotation that exposes a missing or partial leaf. The three
directories and identities must remain distinct.

RoleID is only a role selector; SecretID is a single-use exchange input; the
short-lived service token is the only object written to a runtime sink; and the
token accessor is a non-authenticating management/audit identifier. Protect the
accessor record with mode `0600` handling and never pass it in argv or logs.
Routine issuer identities do not revoke tokens. After the replacement token's
exact policy check, atomic sink switch, and consumer canary succeed, an
independent approved rotator uses the old accessor to revoke the old token and
proves the old token is rejected. Before revocation, rollback may restore a
still-valid old token; after revocation it must issue a fresh token and must not
restore a revoked token or consumed SecretID.

## Preflight and start

The Vault token-sink preflight reads the production `.env` inventory once as
strict UTF-8 from a bounded stable regular-file snapshot with a 64 KiB limit.
An exact-limit valid inventory is accepted; an oversized file, link/reparse
ancestor, non-regular opened object, or path/shape replacement during the read
fails with the fixed `Vault token sink metadata is invalid` result. The checker
still reads only sink metadata and never token contents.

1. Run `python scripts/verify_runtime_secrets.py` and
   `python scripts/verify_compose_env.py`.
2. On the target host, wait for broker authentication and all three Vault sink
   success signals. Resolve every path, reject symlinks/unexpected owners,
   verify mode and readability as the matching container UID, confirm no two
   credential files or Vault directories resolve to the same inode, and verify
   each Vault `token` leaf against the bounded file contract above without
   printing its path-specific failure details or content.
3. Render `docker compose config` only into a protected temporary file. Search
   it for `://[^/]+:[^/]+@`, `PASSWORD:` and `--requirepass`; delete the render.
4. Only after the broker and sink checks pass, start PostgreSQL and Redis, then
   Keycloak, `migrate`, API and workers. Managed API/worker startup locally
   revalidates its own token leaf before database initialization and makes no
   Vault network request. Confirm the PostgreSQL Compose healthcheck
   authenticates the fixed superuser,
   platform DML and Keycloak role/database mappings and executes `SELECT 1` for
   each. Its command must remain the password-free exec-form helper; passwords
   exist only in a mode-`0600` temporary `PGPASSFILE` removed by the helper's
   trap. Also confirm Keycloak readiness and Redis authenticated API traffic.
5. Before opening Edge, recheck the three broker sink success signals and file
   metadata, then perform a non-sensitive service-policy read/canary for each
   identity. The local file preflight alone does not prove that a well-formed
   token is current, unrevoked or authorized. Keep Edge closed on any failure.
6. Inspect process argv and container environment. They may contain file paths,
   but no database/Redis/Keycloak passwords or credential-bearing URLs.

The reviewed forward-deploy and rollback executors automate the repository-owned
part of steps 2 and 5 twice: after public TLS validation but before constructing
their command runner, then after the complete internal TLS smoke and before any
Edge start. They re-read only the fixed `.env`/Compose inventory and token path
metadata; they do not open token leaves or cache a result. On POSIX, the gate
also enforces the reviewed UID/GID and exact `0400`/`0440` modes. On Windows,
host ACL-to-container-UID equivalence, reparse behavior unavailable to the host
API, and the remaining check-to-mount window still require target-host review;
the Vault policy canary remains mandatory on every host.

## Rotation and rollback

Rotate one credential class at a time. Deliver a new file by same-directory
atomic replacement, update
the backing PostgreSQL/Redis/Keycloak credential in the approved order, and
restart only its consumers. Prove old credentials fail and new credentials
succeed without printing either value. Keep the preceding version encrypted
and access-controlled only for the approved rollback window; destroy it after
signoff. A partial rotation is a failed change: stop dependent rollout, keep
edge closed if readiness fails, and follow the rollback runbook.

For Vault, additionally exercise re-authentication and replacement across the
configured maximum token TTL and prove the next consumer resolve observes the atomically
replaced sink. Never revoke the old token before the new complete leaf and its
policy canary are accepted.

Evidence records include only secret-manager version IDs, approved non-Vault
file SHA-256 values computed under restricted handling, owner/mode checks,
restart timestamps, restricted accessor references, and redacted success/failure
results. They must never contain secret contents, including a Vault token-sink hash,
token, RoleID, or SecretID.
