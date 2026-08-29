# Vault audit device runbook

This runbook applies to the production Vault cluster. Repository checks are
preflight only and are not evidence that audit devices are enabled on a target.

## Configure without exposing credentials

Use an approved administrator workstation whose Vault CLI is already
authenticated. Do not put a token, RoleID or SecretID in the command, shell
history or evidence bundle.

```sh
VAULT_ADDR=https://vault.example.invalid sh ./infra/vault/configure-audit.sh
vault audit list -detailed
```

The result must contain exactly the reviewed `email-platform-primary` and
`email-platform-secondary` file devices. Both must use JSON, mode `0600`,
`log_raw=false`, `hmac_accessor=true` and `elide_list_responses=true`.
`stdout` and `discard` are not production evidence.

Configuration is safely re-runnable but is not atomic. If one device succeeds
and the next fails, correct the cause and rerun the helper. A reviewed existing
device is retained and a missing device is enabled; any existing-device drift
fails closed. The helper never disables or replaces a device.

Before enabling the devices, provision the parent directories for these file
paths on every Vault node as two independent persistent volumes. A directory on
the node root filesystem or two directories on the same underlying volume do
not satisfy the control.

- `/var/log/vault-audit/email-platform-primary.json`
- `/var/lib/vault-audit/email-platform-secondary.json`

## Rotation, retention and availability

Rotate each file independently with the approved host log rotation service.
After every rotation, send the Vault process `SIGHUP` so both file devices close
and reopen their paths. Retain audit records for at least 180 days, with expired
archives removed only through the approved retention workflow.

Alert at 70% volume utilization and page at 85%. Also page on audit write
failures, a missing device, rotation failure or a stale file. Vault writes each
request to all enabled devices and needs at least one successful audit write;
if all devices are unavailable, Vault rejects requests. Capacity alerts and two
independent volumes are therefore availability controls, not optional logging
preferences.

## Prove allowed and denied events

Use a synthetic secret whose value is unique to this test and is not production
data. Through the approved credential broker, open an API-service CLI session
without copying its token into the command line or evidence. Record UTC before
and after these requests:

```sh
vault read -format=json secret/data/cards/audit-probe >/dev/null
vault read -format=json secret/data/mailboxes/audit-probe >/dev/null
```

The first request must be allowed and the second must return `permission denied`.
Locate both request/response pairs in both audit files. Evidence must record only
the UTC window, request ID, HMAC accessor, request path, result, device name and
archive SHA-256. The files must not contain the synthetic secret value, service
token, RoleID or SecretID in raw form.

Finally, exercise the approved alert test without making both devices
unavailable at once. Confirm the capacity/write-failure notification reaches the
on-call route, then restore the device and verify fresh entries resume in both
files. Real target evidence and an independent reviewer are required for
production signoff.
