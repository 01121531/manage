# Key rotation runbook

Use this when rotating platform secrets, bootstrap credentials, or identity-admin credentials.

1. Generate new values in the secret manager for:

   - `POSTGRES_PASSWORD`
   - `REDIS_PASSWORD`
   - `KEYCLOAK_ADMIN_PASSWORD`
   - `PLATFORM_JWT_HMAC_SECRET` if local auth is still used in non-production
   - `PLATFORM_VAULT_TOKEN`

2. Update the deployment `.env` from secret-manager output.
3. Re-run the config checks.

   ```powershell
   docker compose config
   python scripts/verify_compose_env.py
   python scripts/verify_service_boundaries.py
   ```

4. Restart the impacted services.

   ```powershell
   docker compose up -d postgres redis keycloak api worker-mail worker-sub2 web
   ```

5. Verify readiness and metrics.

   ```powershell
   curl.exe http://127.0.0.1:8000/readyz
   curl.exe http://127.0.0.1:9090/-/ready
   ```

