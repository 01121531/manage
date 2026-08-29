# Platform audit-event archive

This runbook exports one tenant's `audit_events` rows from a half-open UTC
window into an authenticated encrypted archive. The first implementation is
deliberately read-only: it has no prune, delete, update, or restore command and
must not be used to change the source table.

## Preconditions

- Run from a clean, reviewed release checkout. Record the exact source commit.
- Use a PostgreSQL login whose only relevant privilege is `SELECT` on
  `audit_events`. Put its SQLAlchemy URL in an absolute, repository-external,
  owner-only file; use `0600` or stricter on POSIX, or a protected operator/
  SYSTEM/Administrators DACL on Windows. Hard links and link/reparse ancestors
  are rejected. Never pass the URL on the command line or print it.
- Put a random 32-byte AES key in a different absolute, repository-external,
  owner-only file. The key and its path are not evidence and must never be
  copied into the archive directory, logs, tickets, or screenshots.
- Select an absolute, repository-external output directory that does not exist.
  The tool claims it before reading the key or database and cleans up a failed
  attempt. Never retry into a partially created path.
- Approve exact tenant, `--from-created-at`, and `--until-created-at` values.
  Both boundaries must be timezone-aware UTC; the interval is `[from, until)`.

## Create a read-only encrypted archive

```powershell
$archiveDir = "D:\email-platform-evidence\audit\tenant-window-2026-08-24"
$databaseUrlFile = "D:\email-platform-secrets\audit-archive-database-url"
$archiveKeyFile = "D:\email-platform-secrets\audit-archive-aes-key"
$sourceCommit = git rev-parse HEAD

python -m scripts.audit_archive archive `
  --output-dir $archiveDir `
  --key-file $archiveKeyFile `
  --database-url-file $databaseUrlFile `
  --tenant-id "TENANT_UUID" `
  --from-created-at "2026-08-23T00:00:00Z" `
  --until-created-at "2026-08-24T00:00:00Z" `
  --tool-source-commit $sourceCommit
```

The database transaction is repeatable-read and read-only. Rows are ordered
and keyset-paged by `(created_at, id)` so equal timestamps and pages larger than
10,000 rows neither skip nor duplicate records. Historical values are passed
through the current audit redactor again. Only `audit-events.v1.jsonl.enc` and
the authenticated manifest are published; plaintext is never written to disk.
The manifest is closed-schema, records the tenant/window, row count,
first/last key, archive schema and redaction versions, source commit, key ID,
ciphertext/plaintext SHA-256, and always says `production_acceptance=false`.

After the command, independently prove the archive login had only `SELECT` and
record a before/after source row count (or database audit evidence) showing
zero source mutation and zero prune. The tool itself never deletes archived
rows.

## Verify before custody transfer

Use a separate process or reviewer. Verification authenticates the manifest,
checks the exact directory leaf set and ciphertext identity, authenticates
AES-256-GCM before parsing plaintext, then validates every JSONL record,
ordering, tenant, interval, count, hashes, and first/last coverage.

```powershell
python -m scripts.audit_archive verify `
  --input-dir $archiveDir `
  --key-file $archiveKeyFile `
  --expected-tenant-id "TENANT_UUID" `
  --expected-from-created-at "2026-08-23T00:00:00Z" `
  --expected-until-created-at "2026-08-24T00:00:00Z"
```

Any wrong key, manifest change, unknown field, ciphertext change/truncation,
record deletion/reordering/duplication, boundary mismatch, or parse failure is
a stop condition. Preserve only redacted summaries: archive schema, source
commit, ciphertext and manifest SHA-256, key ID, UTC window, row count,
first/last key, verifier result, operator, and independent reviewer.

For consecutive schedules, the next window's `from` must exactly equal the previous window's `until`.
Review both manifests together and reject gaps,
overlaps, tenant drift, or a source-commit change that was not approved.

## Production custody is separate evidence

Copy the completed two-file archive to approved immutable storage only after
verification. Target-environment acceptance requires independent proof of the
actual WORM/object-lock mode, retention period, deny-delete permissions,
lifecycle policy, custody transfer, and a fresh independent decrypt/verify
exercise. A normal filesystem read-only bit is not WORM. Local tests and this
tool always report `production_acceptance=false`; they cannot be used as the
production evidence.
