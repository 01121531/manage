# Phase 6 CI rehearsal

This rehearsal executes the complete in-process business chain before a release:

`login -> task -> card allocation -> mail session -> one-time code -> upload/outbox -> close -> audit replay`

It also tests cross-tenant and same-user cross-device resource isolation, verifies
that the code is consumed once, checks card/mail cleanup, and scans persistent
database, audit JSON/CSV, metrics, application-log, and non-ephemeral HTTP
surfaces for per-run secret sentinels.

Run and verify it from the repository root:

```powershell
$commit = (git rev-parse HEAD).Trim()
python scripts/phase6_rehearsal.py run --output release/evidence/phase6-ci-rehearsal.json --commit $commit
python scripts/phase6_rehearsal.py verify --input release/evidence/phase6-ci-rehearsal.json
```

The writer removes stale output before starting, publishes through a same-directory
temporary file plus `os.replace`, and then verifies the closed schema and canonical
payload SHA-256. Any failed or tampered check returns a non-zero exit code. The CI
workflow uploads the resulting JSON as `phase6-ci-rehearsal-<commit>`.

## Evidence boundary

The JSON always contains:

- `evidence_kind=phase6_ci_rehearsal`
- `identity_mode=local_test`
- `production_acceptance=false`

The rehearsal uses in-memory SQLite and fake Mail/Sub2 adapters. It proves that
the repository's API, ownership checks, workers, outbox, cleanup, audit replay,
and evidence scanner compose correctly. It does **not** prove target Keycloak,
PostgreSQL, Redis, Vault, certificates, Mail, Sub2, Alertmanager, backup restore,
operator training, or production rollback.

Do not copy `passed` from CI into the production approval field. A separate
operator must attach target-environment evidence for the real pilot, alert
delivery, dual-database and Vault restore drills, update/deployment rollback,
training, and the real Mail/Sub2 flow. Record both the CI rehearsal artifact and
the independent target evidence in `deploy/production-signoff-template.md`.
