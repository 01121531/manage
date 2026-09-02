# Vault service isolation

These assets configure three independent AppRoles. Run the helper only from an
approved administrator workstation whose Vault CLI is already authenticated:

```sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-approles.sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-broker-issuer-policies.sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-secure-import.sh
```

The helper requires HTTPS plus `vault` and `jq`. It installs each policy and
role, immediately reads back non-secret role metadata, and fails unless all
three roles exactly match the reviewed policy, TTL, default-policy and token
lifecycle settings, with empty SecretID/token CIDR bindings and empty alias
metadata. It intentionally does not request or print RoleIDs,
SecretIDs, or tokens. An approved deployment secret broker must retrieve each
RoleID, create a one-use SecretID,
exchange it through `auth/approle/login`, and write only the resulting
short-lived token into the matching file sink:

| AppRole | Token sink | Allowed KV v2 path |
| --- | --- | --- |
| `email-platform-api-cards` | `PLATFORM_VAULT_API_TOKEN_DIR/token` | `secret/data/cards/*` |
| `email-platform-mail` | `PLATFORM_VAULT_MAIL_TOKEN_DIR/token` | `secret/data/mailboxes/*` |
| `email-platform-sub2` | `PLATFORM_VAULT_SUB2_TOKEN_DIR/token` | `secret/data/sub2/credential`, `secret/data/sub2/proxy`, `secret/data/cards/*` |

The second helper installs and reads back three issuer policies over HTTPS. It
does not bind identities or touch RoleIDs, SecretIDs, tokens, or accessors. Bind
three distinct external principals in the target Vault so that each principal
has exactly one issuer policy:

| External principal | Issuer policy | Only allowed AppRole operations |
| --- | --- | --- |
| API issuer | `email-platform-broker-issuer-api` | read the API RoleID; create an API SecretID |
| Mail issuer | `email-platform-broker-issuer-mail` | read the Mail RoleID; create a Mail SecretID |
| Sub2 issuer | `email-platform-broker-issuer-sub2` | read the Sub2 RoleID; create a Sub2 SecretID |

The machine-readable, non-secret [`broker-contract.json`](broker-contract.json)
fixes these bindings, token sinks, TTLs, positive capabilities, denied probes,
rotation order, and target evidence. Its `production_acceptance` remains
`false` until the target Vault proves three distinct principals, exact effective
capabilities, cross-service issuance denial, single-use SecretID consumption,
the service token policy, rotation, revocation, rejection of the old token, and
an independently reviewed audit trace. Do not bind a root/admin token or one
shared principal to these policies.

`*_ROLE_ID` and `*_SECRET_ID` are documented deployment inputs, not application
environment variables. Compose never passes them into a container. Do not use
the same RoleID, SecretID, or token for two services. The generated SecretID is
single-use with a 10-minute TTL; issued tokens have a 15-minute TTL and a
one-hour explicit maximum TTL, are non-periodic, and do not receive the default
policy. `token_num_uses=0` permits repeated KV reads only until TTL expiry; it
does not remove the TTL. The deployment broker must obtain a fresh one-use
SecretID and re-authenticate, then rotate each service token before expiry.
The service policies intentionally contain no token-management capability.
The broker writes a regular `token` file with mode `0400`, owned or
readable by UID 10001, then atomically replaces it inside the service-specific
host directory. Compose bind-mounts that directory read-only with
`create_host_path: false`; the resolver reopens the file on every request and
therefore observes the next token without restart. Prefer response wrapping
when transporting SecretIDs and deliver values directly to the sink, never to
Git or logs.

A RoleID is a role selector, and a one-use SecretID is an exchange input; neither
is a service runtime credential. Only the resulting short-lived service token
goes into the `token` sink. A token accessor cannot authenticate and is retained
only as a restricted management/audit identifier. Routine issuer principals
receive no token-management capability. After the new token contract, atomic
sink replacement, and consumer canary pass, a separate approved rotator revokes
the old token by accessor and proves that the old token is rejected.

The helper never deletes or recreates an existing role. In particular,
`local_secret_ids` is read back and must be `false`; an existing role with that
irreversible setting enabled fails closed and requires an approved change
window for explicit rebuild. Passing this repository preflight proves only the
reported target role metadata at that moment, not credential issuance,
cross-path denial, token rotation, revocation, or continuous broker operation.

Production rejects environment token authentication. The blank
`PLATFORM_VAULT_*_TOKEN` variables in `.env.example` exist only for explicit
development/test runs and are not referenced by Compose.

Before production, prove the negative boundaries: each token must receive a
Vault denial when reading either of the other services' paths. Rotate each role
independently and verify the other two services remain available.

The Sub2 worker also reads the allocated card secret while assembling the
server-side upload payload, so its role deliberately shares the card read path
with the API. It still has no mailbox access. This does not expose card material
to the desktop or Web clients.

## Secure card and mailbox pool import

Pool ingestion is a separate trust boundary from the three runtime identities
above. An administrator manually supplies card and mailbox source files from an
approved intake workstation; the application does not collect either source
automatically. Card records enter only the credit-card pool and mailbox records
enter only the mailbox pool. `scripts/secure_pool_import.py` reads the matching
restricted local input file,
writes no remote or local state when a card batch repeats an exact normalized
`provider_ref`: that deterministic error is rejected before the platform token,
context request, Vault login, execution directory, or secret write. The API
performs the same check again before receipt verification or database writes.
Mailbox records are not deduplicated by masked address because different
accounts can have the same safe display value. For card imports, the context
request carries only the normalized `provider_ref` list in addition to the
secret-free digest and count. The target rejects an identity already stored or
claimed for that tenant and persists all claims under a unique tenant/reference
constraint before the importer creates execution evidence or logs into Vault.
Expired unconsumed claims are reclaimable only when a later card context in the
same tenant requests the exact same provider reference; a request for another
identity or from another tenant cannot delete or invalidate them. The target
locks matching expired context rows once in ascending context-ID order before
reading or deleting claims, preventing reversed batch input from reversing the
database lock order. It records a
dedicated audit event with only claim/context counts and SHA-256 fingerprints
of prior context IDs, never provider references or context tokens. Consumed
claims remain an identity guard, and final submission must match the ordered
claims. Mailbox contexts do
not carry card identity fields. The importer then writes each secret to its
deterministic KV v2 path with `cas=0`, and asks the
pool-specific Vault Transit key to sign a five-minute, secret-free receipt. Its
output JSON contains `schema_version: 3`, an explicit `pool_type`, a stable
`submission_key` derived from the signed receipt UUID, the `receipt_token`, and
ordered masked `items`; upload that output through the matching card or mailbox
pool page. The API verifies that the submission key matches the signed receipt,
so selecting the exact same bundle after a lost response replays the original
platform receipt instead of creating another batch. The page rejects a wrong-pool bundle or
any item with an extra field before making an API request, then shows a
secret-free preview for confirmation. Never upload the raw input file through
the Web application.

Before reading its API Vault token file, the server-side Transit verifier
validates a non-empty IDNA hostname, valid optional port and origin-only address.
Malformed IPv6, empty host, named/out-of-range port, user information, path,
query, fragment or control character maps to one fixed secret-free address
error before any request. Its default and managed-environment transport is
HTTPS-only. Local HTTP requires explicit opt-in, which the settings factory
supplies only for `development`/`test`. Proxy inheritance remains disabled and
redirects remain rejected.

The API and worker KV v2 runtime resolver applies the same recipient boundary
before reading its service-token file: non-empty IDNA hostname, valid optional
port, and an origin-only address with no user information, control character,
query or fragment. Malformed inputs map to the same fixed secret-free address
error. Managed environments require HTTPS; direct development/test use permits
HTTP only for `localhost`, loopback addresses, or the internal `vault` service
name. Its default transport neither inherits system proxies nor follows
redirects. Custom openers remain an explicit dependency-injection boundary for
tests and approved integrations.

Both clients validate `PLATFORM_VAULT_NAMESPACE` before reading their Vault
token. Empty means no namespace header; a configured value is preserved without
trimming, may contain `/` hierarchy separators, and is limited to 8192 visible
ASCII bytes. Whitespace, control characters, non-ASCII or oversized values fail
with the fixed `Vault namespace is invalid` result. The two settings factories
also pass every non-blank Vault address to origin validation without trimming,
so malformed IPv6 and leading/trailing controls cannot be normalized away or
leak parser details before token preflight.

The runtime settings factories bind the KV v2 resolver and Transit verifier to
the already-mounted `PLATFORM_INTERNAL_CA_FILE`. After origin and Namespace
validation, they read a maximum 256 KiB ASCII PEM bundle from one stable runtime
snapshot, reject group/world-writable POSIX targets, and construct an in-memory
hostname-verifying TLS 1.2+ context. The TLS library does not receive or reopen
the CA path. Invalid, unstable, oversized or unreadable input fails with the
fixed `PLATFORM_INTERNAL_CA_FILE is unavailable or invalid for Vault` result
before token preflight or a Vault request. Direct local construction without a
CA file retains system trust; proxy inheritance and redirects remain disabled.

The same bounded stable snapshot helper now supplies the OIDC JWKS verifier's
internal-CA context. It passes only in-memory PEM to a hostname-verifying TLS
1.2+ context, maps failures to the fixed `OIDC TLS trust is unavailable or
invalid` result, and constructs the verifier before database initialization.
This shared runtime material boundary does not merge the OIDC and Vault
recipient identities, credentials, policies, or network destinations.
The OIDC recipient remains separately pinned to the exact Keycloak
`<issuer>/protocol/openid-connect/certs` URL. Its opener ignores inherited
proxies, rejects redirects, applies a ten-second timeout and caps strict JSON at
64 KiB. The JWK-set cache lasts five minutes while the non-expiring per-key
cache remains disabled, so a reviewed key rotation has a finite local refresh
boundary.

Example (the input, target-platform token, pool-specific AppRole RoleID and
single-use SecretID, optional CA, execution directory, and output use distinct
absolute paths; tenant and audience must match the target API environment).
The raw input, platform-token, RoleID and SecretID files must each be stable
regular files with exactly one hard link and a direct path containing no
symbolic-link or Windows reparse component. The importer checks the lexical
path before and after its descriptor-bound read, so a stable alias or observed
path drift fails before the affected platform request, Vault login,
execution-record creation, or receipt write. Raw import and receipt reissue
also map any OS or link-loop resolution failure to the fixed path-separation
error without exposing a path or operating-system detail, before remote use,
execution assessment, or local evidence writes. The target platform and Vault
addresses must each be a pure HTTPS origin with a non-empty hostname and valid
optional port; user information, path, query, fragment and control characters
are rejected. Both addresses are validated before the CA, private input or
execution record is read. Malformed IPv6 syntax, an empty host, an invalid port
or another origin violation maps to the corresponding fixed secret-free address
error before remote or local mutation. Platform and Vault must also use distinct
effective HTTPS origins after hostname case, IDNA and default-port
normalization. A shared origin produces one fixed secret-free separation error
before CA/private/evidence reads, preventing the administrator Bearer and
AppRole inputs from being sent to the same TLS recipient. Different effective
ports remain distinct origins; repository-external DNS aliases and CNAME
ownership remain a target review boundary. An explicit custom CA must be
an absolute, direct, single-link regular file. It is read once through a
bounded stable snapshot before private input or execution assessment, then one
in-memory TLS context is reused for all platform and Vault requests; the path
is not reopened by the TLS library. Alias/drift, size, encoding, identity or
TLS parsing failures produce only the fixed CA error before remote use or local
evidence writes. On Windows,
the raw input, platform token, RoleID and SecretID must also have a protected
DACL owned by the current operator, SYSTEM or local Administrators, with only
explicit non-inherited Allow entries for those three principals. The importer
checks the ACL through the same open handle before and after each bounded read;
on POSIX, those four files instead require mode `0600` or stricter, with no
group or other permission bits, and the same descriptor-bound mode comparison.
It does not claim secure erasure or replace the approved cleanup procedure:

```sh
python scripts/secure_pool_import.py card \
  --input-file /secure-intake/cards.json \
  --platform-address https://platform.example.invalid \
  --platform-token-file /run/secrets/email-platform-admin/token \
  --expected-tenant-id tenant-a \
  --expected-audience email-platform:pool-import:production \
  --vault-address https://vault.example.invalid \
  --ca-file /etc/email-platform/internal-ca.pem \
  --approle-role-id-file /run/secrets/email-platform-card-importer/role-id \
  --approle-secret-id-file /run/secrets/email-platform-card-importer/secret-id \
  --execution-directory /secure-evidence/card-import-execution-20260831 \
  --receipt-output /secure-intake/card-import-bundle.json
```

Use `mailbox` with its distinct mailbox AppRole files for the mailbox pool. The
CLI validates the target-issued context and publishes the execution plan before
reading those AppRole files. It then logs in through AppRole, verifies the exact
pool policy, role name, service-token type, no default or identity policies, and
an initial TTL no greater than 15 minutes. The returned Vault token remains only
in process memory; the retired `--token-file` option is rejected. The CLI builds
its authenticated HTTPS client and installs the conditional revocation guard
before AppRole login, so client setup cannot fail after Vault has issued a token
but before the guard exists. An authentication failure with no issued token
produces neither an empty-token revoke request nor revocation evidence. If Vault
has issued a syntactically safe token but any role, policy, type, orphan,
use-count or TTL validation fails, the exchange path attempts self-revocation
before returning the fixed validation error. An unsafe, control-bearing or
non-ASCII token is never copied into a revocation header. On every controlled
exit after successful validation, including KV, context-renewal and Transit
failures, the CLI attempts `POST /v1/auth/token/revoke-self`, requires an empty
HTTP 204 response, and clears its in-memory token. A raw import attempts to
publish a secret-free revocation intent first and confirmation afterward; an
intent-publication failure cannot suppress the actual revoke request. Receipt
reissue performs the same self-revocation without mutating the original
execution directory. Any primary import, reissue or process-control exception
remains authoritative if cleanup also fails; the same precedence applies to an
AppRole validation failure. The 15-minute TTL remains the backstop for a hard
process termination, an unusable token value or ambiguous revocation response.
Each SecretID has a 10-minute TTL and one use, so receipt reissue requires a
fresh SecretID.
Raw card
records may contain PAN and optional expiry but any CVV/CVC/CID/security-code
alias fails closed. Raw mailbox records place provider credentials under a
`secret` object; the approved real provider schema is still an R04.02 input.
The CLI disables proxy inheritance and redirects, requires HTTPS, reads bounded
stable files, requires restricted POSIX permissions, writes the receipt once
with mode `0600`, and never prints a secret or receipt token. It publishes a
secret-free execution plan before the first Vault mutation, then a write intent
before and a confirmation after each create-only operation. If the process is
interrupted, do not blindly rerun it: assess the new external execution
directory without Vault access or filesystem mutation:

```sh
python scripts/secure_pool_import_recovery.py \
  --execution-directory /secure-evidence/card-import-execution-20260831 \
  --receipt-output /secure-intake/card-import-bundle.json
```

The assessment reports `unwritten`, `partial_written`, `commit_unknown`, or
`completed`, separately reports `token_revocation=not_recorded`, `unconfirmed`,
or `confirmed`, and always reports `automatic_resume_allowed=false`. An
ambiguous revocation response never changes a completed import into an
incomplete one. In particular, an existing `cas=0` path never proves that its
value equals the source secret.

The API verifies the Transit signature and exact audience, tenant, pool,
ordered manifest digest, count, validity interval, UUID and key version. It
derives every `secret_ref` itself. A globally unique receipt ID is inserted in
the same PostgreSQL transaction as resources and audit events, so an exact
idempotent replay remains recoverable after an ambiguous response while the
same receipt cannot create a second batch. Vault response wrapping may be
added as transport hardening, but is not the authority: unwrap cannot be made
atomic with the database commit.

The non-secret [`secure-import-contract.json`](secure-import-contract.json)
and importer policies define the intended negative capabilities. They are
preflight assets only. Run `configure-secure-import.sh` from an approved,
already-authenticated administrator workstation after the AppRole and Transit
mounts exist. It installs and exactly reads back the two importer policies, the
existing API policy, and two pool-specific credential-issuer policies;
reconciles three AppRoles; and creates or verifies two
pool-specific Ed25519 signing keys. Both keys are non-exportable, disallow
plaintext backups and deletion, and are configured for 30-day automatic
rotation. The helper never enables mounts, logs in, generates or reads RoleIDs,
SecretIDs or tokens, or accesses private keys and pool data.

Assign `email-platform-secure-import-card-issuer` and
`email-platform-secure-import-mailbox-issuer` to separate external delivery
principals. Each may read only its matching importer RoleID and create only its
matching SecretID; neither can issue credentials for the other pool. Deliver
RoleID and SecretID through separate restricted files, and revoke the issuing
principal or importer token through the approved incident procedure when
custody is uncertain.

The contract's ordered `required_target_evidence` list is the exact 13-scenario
secure-import portion of the repository-external `vault_egress_evidence`
index. Repository verification fails if either side is missing, reordered or
renamed. This binds evidence coverage only; it does not authenticate the
referenced target objects or grant production acceptance.

The KV v2 policies grant only `create` on their own pool paths, so an existing
secret cannot be updated by either importer. The CLI additionally sends
`options.cas=0` for every write. Vault KV v2 does not support
`allowed_parameters`, `denied_parameters`, or `required_parameters` in ACL
policies, so the repository does not claim that the policy itself requires the
CAS field. If a deployment requires provider-side rejection when CAS is
omitted, use a separately governed KV v2 import mount with `cas_required=true`
and capture that target configuration as external evidence.

Bind and deliver credentials for `email-platform-card-importer`,
`email-platform-mailbox-importer`, and `email-platform-api-cards` as three
distinct external identities. After their short-lived tokens are delivered to
three separate protected files, run the target boundary smoke test. The output
must be a new absolute file outside the repository:

```sh
python scripts/secure_import_vault_smoke.py run \
  --vault-address https://vault.example.invalid \
  --ca-file /etc/email-platform/internal-ca.pem \
  --card-token-file /run/secrets/email-platform-card-importer/token \
  --mailbox-token-file /run/secrets/email-platform-mailbox-importer/token \
  --api-token-file /run/secrets/email-platform-vault-api/token \
  --environment staging \
  --plan-output /secure-evidence/secure-import-vault-smoke.plan.json \
  --evidence-output /secure-evidence/secure-import-vault-smoke.json

python scripts/secure_import_vault_smoke.py verify \
  --input /secure-evidence/secure-import-vault-smoke.json
```

The smoke test creates one synthetic canary under each import path and proves
24 positive and negative operations: create with `cas=0`, replay and wrong-CAS
rejection, cross-pool and cross-key denial, importer sign/verify separation,
API verify/sign separation, and denial of key reads and API pool writes. It
does not test omission of the CAS field and therefore does not prove
mount-level `cas_required` configuration. It
disables redirects and proxy inheritance and writes only status codes, path
identifiers and an origin digest; tokens, signatures and response bodies are
not retained. The plan is published before the first canary write and binds the
exact KV v2 data and metadata paths. After preserving the Vault audit trace,
render an exact, per-run cleanup policy with
`scripts/secure_import_vault_canary_cleanup.py render-policy`; an approved Vault
administrator must install that exact policy and issue a short-lived token with
only that policy and no `default` policy. The cleanup command reads and verifies
both canaries before deleting either, permanently deletes only the two exact KV
v2 metadata paths, verifies data and metadata both return 404, and emits a
write-once, secret-free receipt. Wildcard cleanup policy paths are forbidden.
Importer tokens intentionally cannot perform cleanup.

Before production, also prove an observed key rotation with old-receipt
verification, audit traces, and concurrent database consumption. Automatic-
rotation configuration alone is not evidence that a rotation occurred. A
passing smoke artifact remains `production_acceptance=false` and requires an
independent reviewer. Keep production acceptance false until those target
results and the separate PCI and mail-provider decisions are approved.

## Production audit devices

Vault auditing is a separate production bootstrap step. From an approved
administrator workstation with an already-authenticated Vault CLI, run:

```sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-audit.sh
```

The helper safely reconciles the named `email-platform-primary` and
`email-platform-secondary` JSON file devices with raw secret logging disabled.
It never logs in, obtains deployment credentials, or prints credentials. If one
device was enabled before a failure, a rerun retains a matching device and adds
the missing one; configuration drift fails closed and is never replaced. The
server paths `/var/log/vault-audit/email-platform-primary.json` and
`/var/lib/vault-audit/email-platform-secondary.json` must be backed by two
independent persistent volumes on every Vault node. Follow
[`deploy/runbooks/vault-audit.md`](../../deploy/runbooks/vault-audit.md) for
rotation, retention, capacity alerts and target-environment evidence. Committed
configuration and local tests are preflight only; they do not prove that a
production Vault cluster has enabled either device.
