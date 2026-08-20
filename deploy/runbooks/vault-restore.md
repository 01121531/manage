# Vault integrated-storage snapshot and restore runbook

This procedure applies only to a production Vault cluster that uses integrated
Raft storage. The repository's `vault-dev` profile uses ephemeral dev storage
and cannot produce a meaningful disaster-recovery snapshot.

## Create and verify a snapshot

Use a short-lived operator token whose policy permits reading the Raft snapshot
endpoint. Store it in an absolute, access-controlled file; do not use any of the
application service token files and do not place the token on the command line.

```powershell
python -m scripts.vault_maintenance backup --output-dir backups/vault-YYYYMMDDTHHMMSSZ --address https://vault.example.com --token-file C:\secure\vault-snapshot.token
python -m scripts.vault_maintenance verify --input-dir backups/vault-YYYYMMDDTHHMMSSZ
```

Archive `vault.snap` and `vault-manifest.json` together. The verifier checks the
recorded byte size and SHA-256 before asking the Vault CLI to inspect the Raft
snapshot. Store the bundle encrypted and separately from the PostgreSQL bundle.

## Isolated restore drill

Never use the production cluster as the drill target. Provision an isolated
Vault cluster with the same Vault version, seal/KMS configuration and namespace
entitlements. Freeze access to that target and then run:

```powershell
python -m scripts.vault_maintenance restore --input-dir backups/vault-YYYYMMDDTHHMMSSZ --address https://isolated-vault.example.com --token-file C:\secure\isolated-vault-restore.token --confirm-restore
```

The restore command refuses to run without `--confirm-restore` and verifies the
snapshot before invoking `vault operator raft snapshot restore -force`. After
the restore, unseal the isolated cluster with the snapshot's original seal/KMS
material and record evidence for all of the following:

1. `vault status` reports an initialized, unsealed Raft cluster.
2. The reviewed KV paths for cards, mailboxes, Sub2 credentials and proxies are
   present; record counts and paths only, never secret values.
3. API, mail-worker and Sub2-worker AppRole policies still reject cross-service
   paths.
4. Newly issued short-lived service tokens can read only their permitted paths.

Destroy the isolated target and revoke the snapshot/restore operator tokens
after evidence has been approved by a second operator.

## Production recovery

Production restore is destructive. Freeze API and worker writes, verify both
the Vault and PostgreSQL backup timestamps match the selected recovery point,
and obtain separate change approval. Restore Vault using the same command
against the production address only after the isolated drill has passed. Then
rotate all three application service tokens, atomically replace their token
files, restart affected services, and verify `/readyz`, worker heartbeats and a
complete non-sensitive smoke task before reopening traffic.
