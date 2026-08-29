# Incident response runbook

Use this when alerts fire, traces look suspicious, or unknown uploads appear.

1. Triage the alert.

   - `PlatformApiDown`
   - `PlatformMailWorkerStalled`
   - `PlatformSub2WorkerStalled`
   - `PlatformUnknownUploadsPresent`
   - `PlatformApi5xxRateElevated`

2. Capture the trace ID, user ID, and affected object from the alert or audit event.
3. Inspect the production Prometheus control plane over its loopback-only TLS
   listener. Resolve the certificate hostname explicitly and trust only the
   reviewed internal CA. `--tlsv1.2` sets TLS 1.2 as the minimum; never replace
   these controls with `--insecure`, `-k`, a plaintext URL, or an IP certificate
   hostname.

   ```powershell
   if ([string]::IsNullOrWhiteSpace($env:PLATFORM_INTERNAL_CA_FILE)) {
     throw "PLATFORM_INTERNAL_CA_FILE must name the reviewed internal CA"
   }
   $internalCa = (Resolve-Path -LiteralPath $env:PLATFORM_INTERNAL_CA_FILE).Path

   curl.exe --fail-with-body --silent --show-error `
     --cacert $internalCa `
     --resolve prometheus:9090:127.0.0.1 `
     --tlsv1.2 `
     https://prometheus:9090/-/ready
   curl.exe --fail-with-body --silent --show-error `
     --cacert $internalCa `
     --resolve prometheus:9090:127.0.0.1 `
     --tlsv1.2 `
     https://prometheus:9090/api/v1/alerts
   ```

4. Replay the tenant-scoped trace in the production HTTPS Web control plane.
   A `security_auditor` or `platform_admin` may use **Audit Center** to filter
   by the captured trace ID, user ID, entity type `upload_job`, and upload ID.
   Do not place a bearer token in a shell command, process argument, URL, or
   copied incident note.
5. If an upload is `unknown`, do not retry or create another upload.

   - First confirm the external Sub2 result manually. Preserve the upstream
     evidence and the exact upload ID, task ID, business name, trace ID, and
     current `unknown` state as one review set.
   - An `ops_admin` or `platform_admin` must open **Sub2 Uploads**, select the
     row whose upload ID, task ID, business name, and `unknown` state all match
     that review set, and verify the same immutable identifiers in the
     confirmation dialog before submitting.
   - For a confirmed success, select `status=succeeded` and enter the reviewed
     Sub2 identifier as `external_ref`. For a confirmed failure, select
     `status=failed` and enter a non-sensitive `error_code` when available.
     Never infer either terminal state from a timeout or disconnected response.
   - After submission, refresh **Sub2 Uploads** and **Audit Center**. Trust only
     the stored job state and its `upload.reconciled` audit event. If the submit
     response is missing or ambiguous, refresh the same upload first. Do not
     replay reconciliation unless it is still `unknown` and the external result
     has been rechecked. Never create a new idempotency key as a workaround.

6. If a credential or device is compromised, follow the key rotation and device revocation runbooks.
7. Preserve the current release manifest and backup before any rollback decision.
