# Alert delivery runbook

Use this before a production deployment and after every receiver or routing
change. Repository checks are preflight only; production acceptance still
requires observed firing and resolved deliveries at the approved receiver.

## External configuration boundary

`infra/prometheus/alertmanager.yml` is a development/static-test placeholder
that discards alerts on loopback port 9. It must never be selected by a
production `.env` or used as delivery evidence.

1. Create the production Alertmanager configuration outside the repository on
   the deployment host. Use an absolute path, owner restricted to deployment
   operators and the Alertmanager container UID, and mode `0400` or `0440`.
2. Configure an explicit `severity="page"` child route to a reviewed HTTPS
   webhook. The URL must not contain userinfo, query-string credentials or a
   placeholder/loopback host, and every page webhook must set
   `send_resolved: true`. Do not put receiver secrets in `.env` or inline
   `password`, `credentials`, `client_secret` or `bearer_token` fields.
3. Configure exactly one `severity="watchdog"` child route with no additional
   matcher and no `continue: true`. Put it first so a broader child route cannot
   intercept the heartbeat. Give it a dedicated receiver distinct from the page
   and root/default receivers. Set explicit `group_interval` and
   `repeat_interval` values no longer than `2m` (the reviewed baseline is `1m`).
   Its webhook must use a credential-free, non-placeholder external HTTPS URL,
   set `send_resolved: true`, and keep any authentication in `*_file` fields.
   The external service must alarm when the expected heartbeat stops; an
   ordinary webhook that only records firing alerts is not a dead-man receiver.
4. Set `ALERTMANAGER_CONFIG_FILE` to that absolute external path. Production
   Compose has no fallback, mounts the file read-only and uses
   `create_host_path=false`, so a missing path fails closed.

Run the repository and production-config preflight before Compose startup:

```powershell
python scripts/verify_monitoring_assets.py `
  --production-alertmanager-config $env:ALERTMANAGER_CONFIG_FILE
docker compose config --quiet
```

The verifier checks the reviewed routing and HTTPS contract without reading or
printing receiver secrets. If `amtool` is unavailable it reports
`static-validation-only`; that is not a successful delivery test.

## Firing and resolved delivery drill

After Alertmanager is healthy, post a synthetic page alert through the
localhost-bound HTTPS API while preserving CA and hostname verification:

```powershell
$alert = @(@{
  labels = @{ alertname = "PlatformSyntheticPage"; severity = "page" }
  annotations = @{ summary = "production receiver delivery drill" }
}) | ConvertTo-Json -Depth 5 -Compress
$alert | curl.exe --fail --silent --show-error `
  --cacert $env:PLATFORM_INTERNAL_CA_FILE `
  --resolve alertmanager:9093:127.0.0.1 `
  -H "Content-Type: application/json" `
  --data-binary "@-" `
  https://alertmanager:9093/api/v2/alerts
```

Confirm the approved receiver recorded one firing delivery. Then repeat the
request with the same labels and an `endsAt` timestamp in the past; confirm one
resolved delivery. Record UTC timestamps, receiver-generated delivery IDs,
Alertmanager configuration SHA-256, operator and independent reviewer in the
production signoff. Do not attach the external configuration or secret values.

Do not claim alert delivery from the static verifier, `amtool`, a successful
HTTP submission, or the repository placeholder alone. Until both receiver-side
events are observed, keep `production_acceptance=false`.

## Monitoring heartbeat and missed-heartbeat drill

Prometheus evaluates the low-cardinality, always-firing
`PlatformMonitoringWatchdog` rule. Before signoff, confirm the approved
dedicated heartbeat receiver records three consecutive watchdog deliveries at
the configured cadence. Record their receiver-generated delivery
IDs, UTC timestamps, the observed maximum gap, and the Alertmanager
configuration SHA-256. Do not record receiver credentials.

In an approved target-environment rehearsal window, create a time-bounded
Alertmanager silence that matches only `severity="watchdog"`; do not stop the
production Prometheus process to simulate this failure. Confirm the external
dead-man receiver raises its missed-heartbeat alarm within its reviewed timeout.
Let the silence expire or remove it, confirm watchdog deliveries resume, and
confirm the external alarm resolves. Record the silence start/end UTC, alarm
and recovery delivery IDs, configured timeout, operator, and independent
reviewer.

The repository verifier proves the strict-TLS self-scrapes, constant watchdog
rule, dedicated route, safe HTTPS receiver contract and maximum cadence. It
does not prove external delivery or receiver-side timeout behavior. Until the
continuous-heartbeat and stopped-heartbeat exercises both succeed, keep
`production_acceptance=false`.
