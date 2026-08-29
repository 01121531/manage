# Bounded container logging

Use this runbook before production approval and after changing the production
Compose topology. The repository policy uses the `json-file` driver with
`max-size: "10m"` and `max-file: "5"`. All 11 non-Vault services, including the
one-shot migration container, must reuse the same `x-platform-logging` anchor.
Only the local helper whose profile is exactly `vault-dev` may omit it.

## Repository preflight

Run from the reviewed, clean release checkout:

```powershell
python scripts/verify_container_logging.py
python scripts/verify_compose_env.py
```

The verifier parses YAML structure and fails if a current or future production
service omits or overrides the anchor, uses another driver, removes either
bound, changes a string option into a YAML number, or expands the Vault profile
exception. This preflight requires no Docker daemon, but it does not prove the
target daemon applied the policy. Keep `production_acceptance=false` until the
target checks below are complete.

## Target LogConfig and rotation check

1. Render the absolute production `docker-compose.yml` with `COMPOSE_FILE`
   unset. Review that every non-Vault service has driver `json-file`,
   `max-size=10m`, and `max-file=5`; do not use a Compose override.
2. After deployment, inspect `HostConfig.LogConfig` for PostgreSQL, Redis,
   Keycloak, migrate, API, both workers, Web, edge, Alertmanager, and Prometheus.
   Record the release, container ID, UTC time, driver and both options. Do not
   attach environment variables, mounts, command lines, or secret values.
3. On a disposable target-environment pilot stack, emit only synthetic,
   non-sensitive log lines until rotation occurs. Do not flood the production
   database or identity services. Confirm an active file and no more than five
   retained files per container, and record observed sizes plus host free space
   before and after the exercise.
4. Record the nominal retained payload bound of 550 MiB for 11 containers
   (`11 x 10 MiB x 5`). Treat filesystem metadata, Docker bookkeeping, image
   layers, stopped/orphaned containers and application data as additional disk
   usage; this is not a whole-host capacity guarantee.

Bounded stdout/stderr logs are short-lived operational diagnostics. They do
not replace platform database audit events, Keycloak event tables, the two
Vault audit devices, their independent retention controls, or backup evidence.
Do not extend container log retention by weakening the size/file bounds. Record
the pilot rotation evidence and an independent reviewer in the production
signoff.
