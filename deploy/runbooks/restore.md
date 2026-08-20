# Restore runbook

Use this when the platform and Keycloak databases must be restored from the
same latest known-good backup bundle. A realm JSON import does not replace the
Keycloak database backup because it does not contain the live user state.

1. Freeze writes.

   ```powershell
   docker compose stop edge api worker-mail worker-sub2 web keycloak
   ```

2. Identify and verify the backup bundle before changing either database.

   - Bundle directory: `backups/production-YYYYMMDDTHHMMSSZ/`
   - Required artifacts: `platform.dump`, `keycloak.dump`, `manifest.json`

   ```powershell
   python -m scripts.postgres_maintenance verify-bundle --input-dir backups/production-YYYYMMDDTHHMMSSZ
   ```

   Stop if the size or SHA-256 check fails. Never mix database dumps from two
   different bundles.

3. Restore both databases. This is destructive for the named target databases.

   ```powershell
   python -m scripts.postgres_maintenance restore-bundle --input-dir backups/production-YYYYMMDDTHHMMSSZ --platform-target-db email_platform --keycloak-target-db keycloak
   ```

4. Bring up internal services from the already selected images. Keep edge closed.

   ```powershell
   docker compose up -d --no-build --pull never keycloak migrate api worker-mail worker-sub2 web
   ```

5. Validate internal services, then open edge last.

   ```powershell
   docker compose exec -T api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).read().decode())"
   docker compose ps keycloak api worker-mail worker-sub2 web
   docker compose up -d --no-build --pull never edge
   python -m unittest tests.test_postgres_maintenance -v
   ```

Before every production release, create and exercise a two-database bundle:

```powershell
python -m scripts.postgres_maintenance backup-bundle --output-dir backups/production-YYYYMMDDTHHMMSSZ --platform-db email_platform --keycloak-db keycloak
python -m scripts.postgres_maintenance drill-bundle --output-dir backups/production-YYYYMMDDTHHMMSSZ --platform-db email_platform --keycloak-db keycloak --platform-scratch-db email_platform_restore_drill --keycloak-scratch-db keycloak_restore_drill
```

The drill fails unless both source databases have public tables, both restored
table counts match their source counts, and every artifact matches the manifest.
It also prints source/restored row-count evidence and requires an exact match for
platform `users`, `devices`, `audit_events` and Keycloak `realm`, `user_entity`,
`credential`. Zero is allowed so a newly provisioned environment can be tested,
but production signoff must review whether each count is operationally credible.

Do not use Alembic downgrade as a recovery mechanism.

For a release rollback, a generic schema-v1 bundle is insufficient. Follow
`rollback.md`; it requires schema v2 bound to the exact release tag, commit,
migration head, and immutable container-manifest SHA-256.
