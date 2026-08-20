# Restore runbook

Use this when the database must be restored from the latest known-good backup.

1. Freeze writes.

   ```powershell
   docker compose stop api worker-mail worker-sub2 web
   ```

2. Identify the backup artifact and the target database.

   - Backup artifact: `backups/email-platform.dump`
   - Target database: `email_platform`

3. Restore the backup.

   ```powershell
   python -m scripts.postgres_maintenance restore --input backups/email-platform.dump --target-db email_platform
   ```

4. Bring the application back in the current release manifest state.

   ```powershell
   docker compose up -d api worker-mail worker-sub2 web
   ```

5. Validate the service.

   ```powershell
   curl.exe http://127.0.0.1:8000/readyz
   python -m unittest tests.test_postgres_maintenance -v
   ```

Do not use Alembic downgrade as a recovery mechanism.

