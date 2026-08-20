# Production readiness signoff template

Release manifest:

- Release ID:
- Backend version:
- Frontend version:
- Migration head:
- Backup artifact:
- Signed by:
- Reviewer role:
- Review date:

## Gate evidence

1. Compose/config and secret scan

   - Evidence:
   - Result:

2. PostgreSQL backup/restore drill and Alembic upgrade

   - Evidence:
   - Result:

3. Keycloak realm, redirect URIs, client auth, MFA

   - Evidence:
   - Result:

4. TLS headers, rate limits, log redaction, retention, alerting

   - Evidence:
   - Result:

5. Mail connector and Sub2 boundary

   - Evidence:
   - Result:

6. Worker retry / reconciliation / card lease safety

   - Evidence:
   - Result:

7. Runbooks signed off by a separate operator

   - Evidence:
   - Result:

## Final signoff

- Approved for production:
- Conditions:
- Follow-up actions:

