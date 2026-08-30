# Expand-only migration rollout

This control protects the N/N+1 overlap in a rolling release. Run:

```powershell
python scripts/verify_migration_compatibility.py
```

The immutable baseline is `0017_mail_token_hash_unique`. Each later revision must
extend that single chain, contain only expand/backfill work in `upgrade()`, and be
added to `reviewed_expansions` in
`deploy/migration-compatibility-baseline.json` with its exact SHA-256 after review.
Do not move or rewrite the reviewed history to make a new migration pass.

Allowed examples are a new table, a nullable column, a non-null column with a
server default, a non-unique index, internal constraints on a newly created
table, and an idempotent `UPDATE` backfill. Drops, renames, narrowing/type
changes, new uniqueness/foreign-key/check contracts on an existing table, and
dynamic SQL are contract work and are rejected.

Revision `0020_audit_event_subject_binding` has one hash-bound exception: its
exact `BEFORE INSERT` trigger closes a tenant/subject audit invariant already
required by every supported writer. The verifier accepts only the reviewed
trigger name, table, event and function tuple; changing any part or appending SQL
fails the gate. Before rollout, the preflight must report no historical invalid
row. If it fails, stop the release and investigate under an approved incident
procedure; never disable the append-only guards or silently rewrite audit rows.
The PostgreSQL preflight uses a bounded, data-dependent aggregate divisor: an
empty invalid-row set returns normally, while one actual invalid row makes the
divisor zero and aborts. Do not replace it with a literal `1 / 0` inside `CASE`;
PostgreSQL may fold that constant during planning even when the branch is false.

## Rollout sequence

1. Record the release, baseline/current heads, verifier output and database backup.
2. Deploy the expand migration while version N is still serving. Confirm N reads
   and writes through the migration and monitor locks, errors and replica lag.
3. Deploy N+1 with backward-compatible reads/writes. Run bounded, restartable
   backfill batches and record row counts and validation queries.
4. Keep rollback capable of running version N against the expanded schema. Do not use Alembic downgrade
   as application rollback.
   Revision `0022_card_quarantine` is schema-compatible with N, but its quarantine
   action must remain unavailable until every N API and worker instance has exited.
   Older nodes only understand `cards.is_active` and cannot enforce the new marker.
   After the fleet is fully N+1, verify allocation, reveal, upload and worker paths
   reject a marked card before operators receive access to the quarantine action.
   Revision `0023_card_events` is also schema-compatible with N: the release-reason
   column is nullable and the independent event table is additive. Older nodes do
   not emit `card_events`, so keep `audit_events` as the authoritative complete
   history during overlap. Expose the card allocation timeline and recycle action
   only after every N API and worker instance has exited, then verify all create,
   allocate, release, reveal, enable, disable and quarantine paths dual-write the
   masked event in the same transaction as their audit record. Do not backfill
   guessed events from current card state.
   Revision `0025_oidc_session_revocations` is expand-only: version 0024 must
   remain ready against the 0025 database and ignores the new deny-list table;
   version 0025 must reject an unmigrated 0024 database. Keep
   `platform_schema_compatibility.minimum_app_revision` at
   `0024_schema_compatibility`. During overlap, both versions still reject the
   exact bearer digest written by logout, but only 0025 understands the
   issuer-scoped `sid` digest. Do not claim cross-refresh OIDC session logout
   until every 0024 API instance and old in-flight request has drained and the
   sibling-token rejection probe passes through the active route. An application
   rollback to 0024 leaves the additive table in place and temporarily restores
   token-only logout semantics; do not use Alembic downgrade.
5. Only after every N instance is retired and the rollback window is formally
   closed may a separately reviewed later release propose contract cleanup. This
   verifier does not authorize contract migrations.

The AST/SQL gate and local tests are static preflight only. They do not prove lock
duration, live traffic compatibility, replica behavior or an actual rolling
deployment. Target-environment N/N+1 rehearsal evidence remains required and must
be recorded with `production_acceptance=false` until that rehearsal succeeds.
