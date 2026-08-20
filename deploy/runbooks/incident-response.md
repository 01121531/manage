# Incident response runbook

Use this when alerts fire, traces look suspicious, or unknown uploads appear.

1. Triage the alert.

   - `PlatformApiDown`
   - `PlatformMailWorkerStalled`
   - `PlatformSub2WorkerStalled`
   - `PlatformUnknownUploadsPresent`
   - `PlatformApi5xxRateElevated`

2. Capture the trace ID, user ID, and affected object from the alert or audit event.
3. Inspect safe observability sources only.

   ```powershell
   curl.exe http://127.0.0.1:8000/metrics
   curl.exe http://127.0.0.1:8000/api/v1/admin/audit
   ```

4. If uploads are `unknown`, do not retry automatically.
   - Confirm the external result manually.
   - Reconcile only through the privileged reconciliation endpoint.

   ```powershell
   curl.exe -X POST http://127.0.0.1:8000/api/v1/upload-jobs/{job_id}/reconcile
   ```

5. If a credential or device is compromised, follow the key rotation and device revocation runbooks.
6. Preserve the current release manifest and backup before any rollback decision.

