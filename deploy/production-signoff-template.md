# Production readiness signoff template

Release manifest:

- Release ID:
- Backend version:
- Frontend version:
- Migration head:
- Backup artifact:
- Vault snapshot artifact and SHA-256:
- Container release manifest:
- API OCI digest:
- Web OCI digest:
- Edge OCI digest:
- SBOM SHA-256 values:
- Trivy report SHA-256 values:
- Cosign certificate identity:
- Cosign OIDC issuer:
- Provenance attestation evidence:
- CodeQL Python result:
- CodeQL JavaScript/TypeScript result:
- Phase 6 CI rehearsal evidence and payload SHA-256 (preflight only):
- Target-environment pilot evidence:
- Signed by:
- Reviewer role:
- Review date:

## Gate evidence

1. Compose/config and secret scan

   - Evidence:
   - Result:

2. CodeQL SAST plus container build, HIGH/CRITICAL scan, SPDX SBOM, keyless signature and provenance

   - Evidence:
   - Result:

3. PostgreSQL plus Vault isolated backup/restore drills and Alembic upgrade

   - Evidence:
   - Result:

4. Keycloak realm, redirect URIs, client auth, MFA

   - Evidence:
   - Result:

5. TLS headers, rate limits, log redaction, retention, alerting

   - Evidence:
   - Result:

6. Mail connector and Sub2 boundary

   - Evidence:
   - Result:

7. Worker retry / reconciliation / card lease safety

   - Evidence:
   - Result:

8. Runbooks signed off by a separate operator

   - Evidence:
   - Result:

9. Target-environment pilot, alert delivery, training and rollback drill

   - Evidence:
   - Result:

The Phase 6 CI rehearsal is only a preflight artifact and must have
`production_acceptance=false`. It cannot be used as the evidence for gate 9.

## Final signoff

- Approved for production:
- Conditions:
- Follow-up actions:
