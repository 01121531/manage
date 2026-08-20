# Vault service isolation

These assets configure three independent AppRoles. Run the helper only from an
approved administrator workstation whose Vault CLI is already authenticated:

```sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-approles.sh
```

The helper installs policy and role configuration but intentionally does not
request or print RoleIDs, SecretIDs, or tokens. An approved Vault Agent or
deployment secret broker must retrieve each RoleID, create a one-use SecretID,
exchange it through `auth/approle/login`, and write only the resulting
short-lived token into the matching file sink:

| AppRole | Token sink | Allowed KV v2 path |
| --- | --- | --- |
| `email-platform-api-cards` | `PLATFORM_VAULT_API_TOKEN_DIR/token` | `secret/data/cards/*` |
| `email-platform-mail` | `PLATFORM_VAULT_MAIL_TOKEN_DIR/token` | `secret/data/mailboxes/*` |
| `email-platform-sub2` | `PLATFORM_VAULT_SUB2_TOKEN_DIR/token` | `secret/data/sub2/credential`, `secret/data/sub2/proxy`, `secret/data/cards/*` |

`*_ROLE_ID` and `*_SECRET_ID` are documented deployment inputs, not application
environment variables. Compose never passes them into a container. Do not use
the same RoleID, SecretID, or token for two services. The generated SecretID is
single-use with a 10-minute TTL; issued tokens have a 15-minute TTL and a
one-hour maximum TTL. The deployment broker must renew or rotate each service
token before expiry. It writes a regular `token` file with mode `0400`, owned or
readable by UID 10001, then atomically replaces it inside the service-specific
host directory. Compose bind-mounts that directory read-only with
`create_host_path: false`; the resolver reopens the file on every request and
therefore observes the next token without restart. Prefer response wrapping
when transporting SecretIDs and deliver values directly to the sink, never to
Git or logs.

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
