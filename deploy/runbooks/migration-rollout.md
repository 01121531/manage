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
Revision `0028_operational_policy_governance` is the first immutable revision ID
longer than Alembic's default 32-character version column. Its hash-bound,
PostgreSQL-only first statement widens only `alembic_version.version_num` to
`VARCHAR(255)` before Alembic records 0028; do not rename historical revisions
or generalize this exception to application tables.

Revision `0037_pool_import_card_identity_claims` adds only a secret-free claim
table and index, so version N can continue serving ordinary task traffic against
the expanded database. The card secure-import context request itself is not an
N/N+1-compatible protocol: N does not accept `card_provider_refs`, while N+1
requires them and binds the final import to the stored claims. Pause card
secure-import operations for the API/CLI rollout window; mailbox imports retain
their existing request shape. Deploy the table first, retire every N API
instance, then distribute the N+1 importer CLI
and resume imports only after existing-card, competing-context and final-binding
negative probes pass. If the application rolls back to N, pause card imports
again; N ignores the additive claims and must not be used to create a new Vault
batch. Do not delete consumed claims during rollback or routine cleanup.

Revision `0038_card_claim_context_binding` converts the application-level claim
binding into a database invariant. Its first step checks every historical claim
against an owning context with the same tenant and `pool_type=card`; any mismatch
aborts the migration before triggers are installed. Pause card secure imports,
run and record that preflight, apply the hash-reviewed migration, then prove that
cross-tenant claim inserts/updates and owning-context tenant/pool changes fail
while a matching claim insert succeeds. PostgreSQL claim writes lock the matching
context `FOR KEY SHARE`, serializing them with protected context changes. Mailbox
imports do not use this table and may continue. An application rollback can keep
0038 in place because prior writers already use matching card contexts; do not
use Alembic downgrade as the rollback mechanism.

Revision `0039_card_claim_delete_guard` makes card identity claims non-deletable
at the database boundary. The matching application release reclaims an expired,
unconsumed identity by updating its existing claim row to the replacement
context; it never deletes and recreates that row. Pause card secure imports
before the application/migration overlap. The new application can run before
0039 because its transfer operation is compatible with 0038; after 0039 is
installed, do not restore or resume an older application that still attempts
claim deletion. Mailbox imports remain independent and may continue. Prove a
direct claim DELETE is rejected, a matching expired claim is transferred and
audited, and a consumed claim remains protected before resuming card imports.
If the application rolls back, keep 0039 installed and card imports paused until
the transfer-capable release is restored; do not use Alembic downgrade to make
the old deletion path work.

Revision `0040_card_claim_identity_immutable` freezes each card identity
claim's `tenant_id` and `provider_ref` after insertion. It is compatible with
the transfer-capable 0039 application because reclamation changes only
`context_id` and `position`. Keep card secure imports paused while installing
the migration, then prove direct updates to either identity column and a
combined cross-tenant context/tenant update are rejected, while a normal
same-tenant expired-claim reclamation still succeeds and emits its existing
audit event. Mailbox imports do not use card identity claims and may continue.
If the application rolls back, keep 0040 installed; do not downgrade the
database to permit identity mutation.

Revision `0041_card_claim_mutation_ledger` adds the append-only
`pool_import_card_claim_mutations` table and an `AFTER UPDATE` trigger that
records every card claim `context_id` or `position` change without storing the
provider reference or any card secret. Both the 0040 application and the new
application are compatible with the trigger because the database writes the
ledger automatically. Pause card secure imports during the DDL window, install
0041, then prove a direct claim transfer creates exactly one row, attempts to
update or delete that row fail, and a normal expired-claim reclamation produces
both its aggregate audit event and correlated ledger row. Mailbox imports do
not use either table and may continue. Keep 0041 installed on application
rollback; do not downgrade away the mutation evidence.

Revision `0042_pool_context_identity_lock` freezes every server-issued pool
import context identity field after insertion. It leaves only `expires_at`,
`consumed_at`, and `pool_import_receipt_id` mutable for the existing renewal and
final-consumption paths, so it is compatible with both the 0041 and 0042
applications. Pause secure imports during the DDL window, install 0042, then
prove direct updates to each identity field fail while one renewal and one
final card or mailbox import still succeed. Because the guard applies equally
to card and mailbox contexts, resume both pools only after this check. Keep
0042 installed on application rollback; do not restore a database state where
an issued context or its historical mutation evidence can be reinterpreted.

Revision `0043_secure_consumption_lock` makes
`secure_pool_import_consumptions` append-only after insertion. Pause both card
and mailbox secure imports during the DDL window, install 0043, then prove a
direct update of each stored field and a direct delete are rejected. Before
resuming, also prove one fresh card import and one fresh mailbox import can each
insert and atomically link a new consumption row. Keep 0043 installed on
application rollback; do not reopen deletion or rewriting of one-time receipt
consumption evidence.

Revision `0044_pool_context_consumption_terminal` preflights every existing
context for a complete consumed-at/local-receipt pair and an exact matching
signed consumption, tenant, pool, manifest, actor and device binding. Pause
both card and mailbox secure imports before this preflight; any invalid history
must stop the migration for authorized remediation. After installation, prove
a new context starts unconsumed, one pre-consumption renewal succeeds, partial
or mismatched consumption fails, a normal card and mailbox consumption each
succeed once, and all three lifecycle fields reject later change or clearing.
Keep 0044 installed on application rollback so a consumed context cannot be
reopened or reinterpreted.

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
