# Vault service isolation

These assets configure three independent AppRoles. Run the helper only from an
approved administrator workstation whose Vault CLI is already authenticated:

```sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-approles.sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-broker-issuer-policies.sh
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
