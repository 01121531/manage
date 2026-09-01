# Secure card and mailbox pool import

Use this runbook when an administrator manually uploads resources into the two
separate pools: card records enter only the credit-card pool, and mailbox
records enter only the mailbox pool. There is no automatic source collection.
Do not upload the raw card or mailbox source file to
the browser, ordinary API, issue tracker, chat, or repository. PAN and mailbox
credentials remain on the approved intake workstation and in Vault; CVV/CVC is
not accepted at all, including by runtime card-secret resolution. The mailbox
bundle display value uses the closed `m***@example.invalid` form: exactly one
visible ASCII local-part character, three asterisks, and a DNS-style domain.
Values that merely append an asterisk to an address are not masked and must be
rejected before the first Vault or API mutation.

1. Confirm Vault audit devices are healthy, then apply and read back
   `infra/vault/configure-secure-import.sh`. Use separate external principals
   carrying `email-platform-secure-import-card-issuer` and
   `email-platform-secure-import-mailbox-issuer` to deliver the matching RoleID
   and a fresh single-use, ten-minute SecretID into two distinct restricted
   files. Continue to issue a distinct short-lived API verifier token for the
   target smoke test. Repository assets and local tests remain
   `production_acceptance=false`.
2. Run `scripts/secure_import_vault_smoke.py run` with `--plan-output` and
   `--evidence-output` set to distinct new absolute files outside the repository,
   plus the three external token files. The write-once smoke plan is published
   before the first mutation and binds the exact two canary data and metadata
   paths. Preserve both files, their SHA-256 values and the matching Vault audit
   window. The smoke evidence deliberately records `cleanup_required=true`.
3. Pin the smoke plan SHA-256 and explicitly confirm its `run_id`. Run
   `scripts/secure_import_vault_canary_cleanup.py render-policy` to a new
   external file. Inspect that it contains no `*`: it may read only the exact
   two data paths, and may read/delete only the exact two metadata paths. An
   approved Vault administrator installs this uniquely named, per-run policy
   and issues a short-lived token containing only it, with no `default` policy.
   Run `secure_import_vault_canary_cleanup.py run` with the pinned plan hash,
   pinned policy hash, confirmed run ID and a new receipt path, then run its
   `verify` command. It must preflight both canaries before its first delete,
   use KV v2 metadata delete for permanent removal, and prove all four exact
   data/metadata reads return 404. Preserve the write-once secret-free cleanup
   receipt, revoke the token, and remove the per-run policy. Never use a
   `smoke/*` wildcard cleanup role.
4. Obtain a short-lived administrator access token for the target platform and
   place it in a restricted external file distinct from both Vault AppRole
   files. Run `scripts/secure_pool_import.py card` or `mailbox` with the exact
   HTTPS `--platform-address`, `--platform-token-file`,
   `--expected-tenant-id`, and `--expected-audience`, plus the matching
   `--approle-role-id-file`, `--approle-secret-id-file`, Vault address, and
   raw-input arguments. The retired `--token-file` option is rejected. The CLI
   sends only the pool type, ordered masked
   manifest digest and item count to `POST /api/v1/admin/pool-import-contexts`;
   it never sends PAN or mailbox credentials. The target platform supplies the
   authoritative tenant, audience and receipt UUID. Any mismatch stops before
   the AppRole files are read, the SecretID is consumed, the execution directory
   is created, or a Vault write occurs. After writing the execution plan, the
   CLI exchanges the AppRole values in memory and accepts only the exact
   pool-specific policy and role, a service token without default or identity
   policies, and an initial TTL no greater than 15 minutes. It never persists
   the returned Vault token.
5. The importer emits a browser-safe `schema_version: 3` bundle containing
   masked items, the target context token, a Transit receipt, and a
   `submission_key` of the form `spi:<signed receipt UUID>`. Keep the raw input,
   platform token, both AppRole files, and bundle outside the repository with
   restricted permissions. Supply a new external `--execution-directory`; the
   importer publishes `plan.json` before the first Vault write, a write intent
   before each mutation, and a confirmation only after Vault acknowledges version 1.
   After every write is confirmed, it renews the same target-issued context
   before Transit signing. Renewal never rotates the token or receipt UUID, is
   bound to the same authenticated user/device/tenant/audience, and is capped
   by the configured absolute renewal window (24 hours by default, no more than
   seven days).
6. If the importer is interrupted, run
   `scripts/secure_pool_import_recovery.py` against that execution directory and
   the intended receipt output. This is a read-only assessment with no network
   client, write/delete operation or importer dependency. It reports one of
   `unwritten`, `partial_written`, `commit_unknown`, or `completed`, always with
   `automatic_resume_allowed=false`. Do not retry a partial or unknown batch:
   create-only/CAS 0 rejection cannot prove an existing secret equals the
   original input. Preserve the source and records under incident procedure for
   operator reconciliation.
7. If the five-minute Transit receipt expires after recovery reports
   `completed`, rerun `secure_pool_import.py` with `--reissue-from` pointing to
   the original safe bundle, the same `--execution-directory`, and a new
   `--receipt-output`; omit `--input-file`. The command validates the closed
   execution record, renews its existing target context, and invokes Transit
   signing only. It does not read the raw source, write KV, or modify the
   original execution directory. A partial, unknown, consumed, caller-mismatched
   or out-of-window context is refused. Preserve the original bundle, fresh
   bundle and execution record; never overwrite any of them.
8. On the matching administration page, select the safe bundle, review the
   pool type, count and routing preview, then confirm once. If the page reports
   “结果尚未确认”, do not select a different bundle. Use the same-batch recovery
   action. After a refresh or navigation, selecting the exact same bundle is
   also safe: its stable key lets the API return the committed receipt without
   consuming the Transit receipt again.
9. A committed result must show the platform receipt ID, trace ID, pool/count,
   `ordered_manifest_digest`, `secure_receipt_fingerprint`, Transit key version
   and timestamps. These are secret-free correlation fields, not proof that the
   target Vault, audit custody, reviewer identity or source secret values are
   authentic.
10. Preserve the platform receipt and audit export according to the evidence
   policy. Destroy temporary raw input and bundle copies only under the approved
   intake retention procedure. Never print or paste a receipt token, RoleID,
   SecretID, or Vault token. A reissue consumes a new single-use SecretID. Keep
   `production_acceptance=false` until real AppRole provenance, Vault audit,
   canary cleanup/readback, key rotation with old-receipt verification, actual
   dual-pool import and independent review are complete.
11. Record those completed target checks as the 13 `secure_import_*` scenarios in
   the repository-external `vault_egress_evidence` index described by
   `deploy/runbooks/target-intake-preflight.md`. Use only opaque references,
   timestamps, fixed observations and digests. The index must reference the
   write-once smoke, cleanup, import, recovery, database-concurrency and audit
   objects; it must not embed their sensitive payloads.

The stable submission key prevents blind duplicate batches after an HTTP 5xx,
network loss, page navigation, or refresh. It does not recover a secure importer
process that failed after only some Vault writes. The write-ahead evidence makes
that failure classifiable, but deliberately does not turn it into an automatic
resume; partial and unknown executions remain stopped, operator-reviewed
recovery incidents.
