# Rollback runbook

Use this when a freshly deployed release must be backed out.

1. Announce a change freeze and stop writes.

   ```powershell
   docker compose stop api worker-mail worker-sub2 web
   ```

2. Restore the most recent backup before switching release state.

   ```powershell
   python -m scripts.postgres_maintenance restore --input backups/email-platform.dump --target-db email_platform
   ```

3. Re-deploy the previously archived release manifest and its image set.

   - Restore the archived `deploy/release-manifest.json` from the previous release artifact.
   - Rebuild or pull the images named in that manifest.
   - Bring the stack back up with the previous manifest selection.

4. Verify the active release lock.

   ```powershell
   python -m scripts.release_manifest verify --manifest deploy/release-manifest.json
   ```

5. Smoke-check API, worker metrics, and login.

   ```powershell
   curl.exe http://127.0.0.1:8000/readyz
   curl.exe http://127.0.0.1:9101/metrics
   curl.exe http://127.0.0.1:9102/metrics
   ```

Rollback is a restore-first action; do not use schema downgrade as the rollback path.

