# Vault integrated-storage snapshot and restore runbook

This procedure applies only to a production Vault cluster that uses integrated
Raft storage. The repository's `vault-dev` profile uses ephemeral dev storage
and cannot produce a meaningful disaster-recovery snapshot.

## Create and verify a snapshot

Use a short-lived operator token whose policy permits reading the Raft snapshot
endpoint. Store it in an absolute, access-controlled file; do not use any of the
application service token files and do not place the token on the command line.
On POSIX the operator-token file must be `0600` or stricter; on Windows it must
use a protected DACL limited to the operator, SYSTEM and local Administrators.
The maintenance helper rejects link/reparse ancestors, hard links, ACL/mode
drift and file-identity drift while reading the token.
The helper sends it only as an in-process `X-Vault-Token` HTTPS header. The
token never enters a child-process environment; the Vault CLI is used only for
offline `snapshot inspect` with a rebuilt token-free environment.
Create a separate absolute-path 32-byte Vault manifest key with inherited ACLs
disabled and access restricted to the operator, SYSTEM and local Administrators.
It must be distinct from the PostgreSQL backup encryption key and must remain
outside Vault, the repository and both backup bundles. Set mode `0400` on Linux;
on Windows protect its ACL and set the file's read-only attribute before use.
Export the issuing CA as an absolute, access-controlled PEM file. Backup and
restore require `--ca-file`; caller proxy, CA, Vault and user-config environment
overrides are not trusted. TLS hostname verification is mandatory and TLS 1.2
is the minimum.

Before every backup or restore command, remove `VAULT_SKIP_VERIFY` from the
operator environment. The maintenance script rejects the key whenever it is
present, including an empty string or `0`, before reading the Vault token:

```powershell
if (Test-Path Env:VAULT_SKIP_VERIFY) { Remove-Item Env:VAULT_SKIP_VERIFY }
```

Choose one immutable recovery-set identifier. First verify the release-bound
PostgreSQL schema v5 bundle with its own key. Only then create and verify the
Vault snapshot against that exact PostgreSQL `manifest.json`:

```powershell
$recoverySet = "release-v1.2.3-20260821T000000Z"
$postgresBundle = "C:\ProgramData\EmailPlatform\backups\v1.2.3-20260821T000000Z"
$postgresManifest = "$postgresBundle/manifest.json"
$vaultBundle = "C:\ProgramData\EmailPlatform\backups\vault-v1.2.3-20260821T000000Z"

python -m scripts.postgres_maintenance verify-bundle --input-dir $postgresBundle --key-file C:\secure\postgres-backup.key
python -m scripts.vault_maintenance backup --output-dir $vaultBundle --address https://vault.example.com --ca-file C:\secure\vault-ca.pem --token-file C:\secure\vault-snapshot.token --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest
python -m scripts.vault_maintenance verify --input-dir $vaultBundle --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest
```

Provision only the external backup root before this command. `$vaultBundle`
must be an absolute, repository-external path whose leaf must not already exist,
even when empty. Symlink/reparse paths are rejected. Never refresh a prior
snapshot in place: a refused retry reads neither manifest key nor token and
does not invoke Vault. Use a new unique leaf; failure removes only the leaf
atomically created by that attempt.

Archive `vault.snap` and `vault-manifest.json` together. Schema v2 derives a
dedicated HMAC key with the fixed versioned HKDF-SHA256 domain
`email-platform/vault-snapshot-manifest/v2/hmac-sha256`. HMAC-SHA256 covers the
exact canonical manifest except its MAC field, including creation time,
recovery-set ID, snapshot size/SHA-256 and the verified PostgreSQL manifest
SHA-256. Record the exact PostgreSQL manifest SHA-256 as recovery evidence.
Both `vault-manifest.json` and the referenced PostgreSQL `manifest.json` must be
regular non-link/non-reparse files no larger than 64 KiB. Each is read once
through a bounded open handle, with named-path and handle identity/shape checks
before and after the read and unique JSON keys at every nesting level. The
PostgreSQL whole-file SHA-256 binding is calculated from those same stable bytes.
Unknown fields, schema v1, a wrong/missing MAC or key, and a mismatched
PostgreSQL manifest fail before `vault snapshot inspect` or restore. Store the
bundle encrypted and separately from the PostgreSQL bundle and both keys.

## Isolated restore drill

Never use the production cluster as the drill target. Provision an isolated
Vault cluster with the same Vault version, seal/KMS configuration and namespace
entitlements. Freeze access to that target. Re-run PostgreSQL schema v5
verification first, then the Vault binding verifier, and only then restore:

```powershell
python -m scripts.postgres_maintenance verify-bundle --input-dir $postgresBundle --key-file C:\secure\postgres-backup.key
python -m scripts.vault_maintenance verify --input-dir $vaultBundle --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest
python -m scripts.vault_maintenance restore --input-dir $vaultBundle --address https://isolated-vault.example.com --ca-file C:\secure\vault-ca.pem --token-file C:\secure\isolated-vault-restore.token --manifest-key-file C:\secure\vault-manifest.key --recovery-set $recoverySet --postgres-manifest $postgresManifest --confirm-restore
```

The restore command refuses to run without `--confirm-restore` and verifies the
snapshot before streaming it to the non-force
`POST /v1/sys/storage/raft/snapshot` endpoint. Redirects and non-success status
codes fail closed without reading or printing the response body. The target
must use the snapshot's original seal/KMS material; a consistency rejection is a stop condition,
not permission to bypass Vault's seal checks. This helper
does not expose a force-restore mode. A seal migration needs a separate,
reviewed isolated-cluster procedure and must never be substituted into the
production command. After the restore, unseal the isolated cluster and record
evidence for all of the following:

1. `vault status` reports an initialized, unsealed Raft cluster.
2. The reviewed KV paths for cards, mailboxes, Sub2 credentials and proxies are
   present; record counts and paths only, never secret values.
3. API, mail-worker and Sub2-worker AppRole policies still reject cross-service
   paths.
4. Newly issued short-lived service tokens can read only their permitted paths.

Destroy the isolated target and revoke the snapshot/restore operator tokens
after evidence has been approved by a second operator.

## Production recovery

Production restore is destructive. Freeze API and worker writes, verify the
PostgreSQL schema v5 bundle first, then verify the Vault schema v2 recovery-set
binding and authenticated creation time, and obtain separate change approval.
Restore Vault using the same command
against the production address only after the isolated drill has passed. Then
rotate all three application service tokens, atomically replace their token
files, restart affected services, and verify `/readyz`, worker heartbeats and a
complete non-sensitive smoke task before reopening traffic.
