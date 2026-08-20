# Release-bound rollback runbook

Use this procedure to return to a previously released application version and
the platform + Keycloak database state captured for that same release. This is
not a PostgreSQL cross-database transaction: safety comes from verifying one
release-bound bundle before either restore and keeping the public edge closed
until both restores and all internal checks succeed.

## Required inputs

- The previous GitHub Release `container-release-manifest.json`.
- A schema-v2 backup directory containing `platform.dump`, `keycloak.dump`, and
  `manifest.json`, created for that exact release.
- `docker`, `cosign`, `gh`, and Python on the deployment host.
- Production Compose secrets and TLS files already provisioned outside Git.

`deploy/release-manifest.json` is only a source-tree consistency snapshot. It
contains local development defaults and must never be used as the rollback
image lock.

## Create the release-bound backup

Before deploying a new version, bind the current release's dual-database backup
to its immutable container manifest:

```powershell
$containerManifest = "release/assets/container-release-manifest.json"
$release = Get-Content -LiteralPath $containerManifest -Raw | ConvertFrom-Json
$containerManifestSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $containerManifest).Hash.ToLowerInvariant()
$backupDir = "backups/$($release.tag)-before-next-deploy"

python -m scripts.postgres_maintenance backup-bundle `
  --output-dir $backupDir `
  --platform-db email_platform `
  --keycloak-db keycloak `
  --release-tag $release.tag `
  --release-commit $release.commit `
  --migration-head $release.migration_head `
  --container-manifest-sha256 $containerManifestSha
python -m scripts.postgres_maintenance verify-bundle --input-dir $backupDir
```

Archive the three backup files and the exact container manifest together. Do
not mix dumps or manifests from different release artifacts.

## Validate the rollback plan

Announce a change freeze. A second operator must review the selected tag,
commit, migration head, container-manifest SHA-256, all three OCI digest
references, and the backup directory before execution.

```powershell
python -m scripts.rollback_release plan `
  --container-manifest previous-release/container-release-manifest.json `
  --backup-dir backups/v1.2.3-before-next-deploy
```

The plan is preflight evidence and always reports `production_acceptance=false`.
It rejects mutable tags, legacy backup schema v1, missing Keycloak data,
tampered dumps, and any release/commit/migration/manifest-hash mismatch.

## Execute

The confirmation value must exactly match the reviewed release tag:

```powershell
python -m scripts.rollback_release execute `
  --container-manifest previous-release/container-release-manifest.json `
  --backup-dir backups/v1.2.3-before-next-deploy `
  --confirm-release-tag v1.2.3 `
  --platform-target-db email_platform `
  --keycloak-target-db keycloak `
  --domain platform.example.com
```

The executor enforces this order:

1. Revalidate the closed container manifest and release-bound dual-database
   bundle.
2. Run actual Cosign signature/SBOM-attestation and GitHub provenance checks.
3. Pull the three exact `ghcr.io/...@sha256:...` images.
4. Stop `edge`, API, both workers, Web, and Keycloak.
5. Restore platform + Keycloak from the same bundle, rechecking the binding
   immediately before each database restore.
6. Start Keycloak, migration, API, both workers, and Web with
   `--no-build --pull never`; then check running services, internal readiness,
   worker metrics, and each container's actual image digest.
7. Start and verify `edge` last, then check external HTTPS API and identity
   discovery with normal certificate validation.

If signature verification or image pull fails, services are never stopped. If
either database restore or any internal check fails, the public edge remains
closed. If the final external smoke test fails, the executor stops edge again.
It never rebuilds an image and never uses Alembic downgrade as recovery.

Record start/end UTC times, achieved RTO/RPO, backup manifest SHA-256, expected
and observed OCI digests, Cosign/provenance results, dual-database critical row
counts, failure injection result, executor output, and the independent reviewer
in `deploy/production-signoff-template.md`.
