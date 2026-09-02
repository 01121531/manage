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
   files. The raw input, platform-token, RoleID and SecretID files must each be
   a stable regular file with exactly one hard link and a direct path containing
   no symbolic-link, Windows junction, volume mount-point or other reparse
   component. The importer checks that lexical path before and after the
   descriptor-bound read;
   any alias fails before the affected platform call, Vault login,
   execution-record creation, or receipt write. If any raw-import or receipt
   reissue path cannot be resolved because of an OS error or link loop, the CLI
   emits only its fixed path-separation error and does not include the path or
   operating-system detail; this also precedes platform/Vault use, execution
   assessment and local evidence writes. The platform and Vault addresses must
   each be an HTTPS origin with a non-empty hostname and valid optional port,
   and may not contain user information, a path, query, fragment or control
   character. Both origins are validated before the custom CA, private input or
   execution record is read. A malformed IPv6 authority, empty host, invalid
   port or other origin violation produces only the corresponding fixed
   secret-free address error before remote or local mutation. The two validated
   recipients must also remain separate effective HTTPS origins after hostname
   case, IDNA form and default port normalization. A shared origin is rejected
   with one fixed secret-free separation error before the CA, raw input,
   execution record or either credential is read, so the platform administrator
   Bearer and Vault AppRole inputs cannot be delivered to the same TLS origin.
   Different effective ports remain distinct origins; this check does not claim
   to detect repository-external DNS aliases or CNAME ownership. When `--ca-file`
   is supplied, it must
   also be an absolute, direct, single-link regular file. The CLI reads at most
   1 MiB once through the stable file boundary, rejects a link/reparse alias or
   observed path drift, and builds one in-memory TLS context reused for both
   platform and Vault traffic. The TLS library never reopens that custom CA
   path after validation. Any CA read, encoding, size, identity or TLS parsing
   failure becomes the fixed secret-free CA error before private input reads,
   remote use, execution assessment or local evidence writes. On Windows the
   importer also evaluates each raw-input, platform-token, RoleID and SecretID
   ACL through the same already-open file handle before and after its bounded
   read. The DACL must be protected, contain only explicit non-inherited Allow
   entries for the current operator, SYSTEM and local Administrators, and be
   owned by one of those principals; an inherited or broadened ACL fails closed.
   On POSIX, the same four files must have mode `0600` or stricter: no group or
   other read, write, or execute bit is allowed. The importer compares mode on
   the same open descriptor before and after the bounded read; `0640`, `0604`
   and `0644` therefore fail before any remote or local mutation.
   This does not replace the approved workstation cleanup procedure or prove
   secure erasure after the process exits. Run `scripts/secure_pool_import.py`
   `card` or `mailbox` with the exact
   HTTPS `--platform-address`, `--platform-token-file`,
   `--expected-tenant-id`, and `--expected-audience`, plus the matching
   `--approle-role-id-file`, `--approle-secret-id-file`, Vault address, and
   raw-input arguments. The retired `--token-file` option is rejected. The CLI
   requires every card batch to contain exact unique normalized `provider_ref`
   values and rejects a duplicate before reading the platform token, requesting
   a context, logging into Vault, creating the execution directory or writing a
   secret. The API repeats that deterministic check before Transit receipt or
   target-context verification and before its database transaction. Do not use
   masked mailbox addresses as a uniqueness key: distinct accounts can share the
   same safe display mask. The CLI sends the pool type, ordered masked manifest
   digest and item count to `POST /api/v1/admin/pool-import-contexts`; for cards
   it also sends the normalized, secret-free `provider_ref` list, while mailbox
   requests never send card identities. It never sends PAN or mailbox
   credentials. The target rejects a card identity already stored or claimed in
   the tenant, then atomically records every new claim before the CLI can create
   execution evidence or log into Vault. Expired unconsumed claims may be taken
   only by a later card context in the same tenant requesting the exact same
   provider reference. A request for another identity or from another tenant
   must not delete the claim or invalidate its bounded renewal window.
   The target locks every matching expired context once in ascending context-ID
   order before reading or transferring claims. Overlapping batches therefore use
   the same database lock order regardless of provider-reference input order,
   and renewal, final consumption and reclamation cannot silently pass one another.
   New card identity claims are inserted in ascending provider-reference order
   while preserving their original manifest positions. Reversed new batches
   therefore cannot reverse unique-index acquisition order or change manifest binding.
   A claim tenant must match the authoritative tenant on its owning context. If
   those values drift, renewal, final consumption, reclamation and deletion all
   fail closed; the owning context tenant still blocks a replacement until an
   authorized repair restores the binding. Migration
   `0038_card_claim_context_binding` rejects historical mismatches before it
   installs database triggers for claim insert/update and owning-context updates.
   PostgreSQL claim writes take `FOR KEY SHARE` on the matching card context, so
   direct SQL and concurrent context changes cannot create tenant or pool drift.
   Migration `0039_card_claim_delete_guard` rejects direct claim deletion in
   the database. Expired unconsumed reclamation updates the existing claim row
   to the replacement context and manifest position; it never removes and
   recreates the identity guard. Migration
   `0040_card_claim_identity_immutable` rejects any update to that row's
   `tenant_id` or `provider_ref`; only the context and manifest position used by
   the existing reclamation path remain transferable. Migration
   `0041_card_claim_mutation_ledger` automatically records every context or
   position change in `pool_import_card_claim_mutations`. The ledger is
   append-only, correlates the destination context and trace with the existing
   aggregate reclamation audit, and contains no `provider_ref`, PAN, CVV, Vault
   path or card secret. Migration `0042_pool_context_identity_lock` also makes
   the target-issued context identity immutable: ID, token hash, tenant,
   audience, pool, ordered manifest digest/count, creator, device, trace and
   creation time cannot be changed after insertion. Expiry renewal and the
   final consumed-at/receipt linkage remain the only mutable lifecycle fields.
   Migration `0043_secure_consumption_lock` separately freezes the resulting
   one-time signed-receipt consumption record after insertion. UPDATE and
   DELETE are rejected for every field, while a new card or mailbox import may
   still INSERT its own consumption row in the existing atomic transaction.
   The guard is shared infrastructure only: the card pool and mailbox pool
   remain independently uploaded and no raw source data is copied into it.
   Migration `0044_pool_context_consumption_terminal` requires a context to
   begin with no consumed-at value or local receipt. Expiry may be renewed only
   in that state. Final import must atomically set both fields against the
   matching signed consumption and tenant/pool/manifest/actor/device receipt;
   after that transition expiry, consumed-at and receipt linkage cannot change.
   Migration `0045_pool_import_receipt_append_only` freezes that linked local
   idempotency receipt after insertion. Direct UPDATE of any receipt field and
   direct DELETE must fail, while each new card or mailbox transaction may
   still INSERT one receipt. The row contains only secret-free binding and
   audit metadata; never add PAN, CVV, mailbox credentials or source content.
   Keep the card-import
   application and these migrations aligned during rollout because older code
   attempts deletion.
   Reclamation emits a dedicated audit event containing claim/context counts and
   SHA-256 fingerprints of prior context IDs only; it must not contain provider
   references, context tokens or source data.
   Consumed claims remain as an identity guard, and final
   import must match the context's ordered claims. The target platform supplies
   the authoritative tenant, audience and receipt UUID. Any mismatch stops before
   the AppRole files are read, the SecretID is consumed, the execution directory
   is created, or a Vault write occurs. After writing the execution plan, the
   CLI exchanges the AppRole values in memory and accepts only the exact
   pool-specific policy and role, a service token without default or identity
   policies, and an initial TTL no greater than 15 minutes. It never persists
   the returned Vault token. The HTTPS client is constructed and the conditional
   revocation guard is installed before AppRole login; a client setup failure
   therefore cannot strand an already issued token. Authentication failure with
   no issued token creates neither an empty-token revocation request nor false
   revocation evidence. If a visible-ASCII token was issued but any identity or
   lease validation fails, the exchange path attempts immediate self-revocation
   before returning the fixed validation error; an unsafe token value is never
   copied into a request header. The token does not need an operator-supplied
   accessor: on every controlled exit after successful validation, whether the
   bounded operation succeeds or fails, the CLI calls Vault's self-revocation
   endpoint and clears the token from memory. A cleanup failure never replaces
   the original validation, import, reissue or process-control exception. TTL
   expiry remains the fail-safe for a hard process termination, unusable token
   value or ambiguous network response.
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
   seven days). Before leaving this token lifetime on success or failure, the
   CLI writes `token-revoke.intent.json`, requests `POST
   /v1/auth/token/revoke-self`, accepts only an empty HTTP 204 acknowledgement,
   clears its in-memory token, then writes `token-revoke.confirmed.json`. If the
   intent cannot be published, the revoke request still runs; preserve the
   primary failure and reconcile the missing evidence through the Vault audit
   trail and TTL.
6. If the importer is interrupted, run
   `scripts/secure_pool_import_recovery.py` against that execution directory and
   the intended receipt output. This is a read-only assessment with no network
   client, write/delete operation or importer dependency. It reports one of
   `unwritten`, `partial_written`, `commit_unknown`, or `completed`, always with
   `automatic_resume_allowed=false`, plus an independent `token_revocation`
   value of `not_recorded`, `unconfirmed`, or `confirmed`. A completed import
   with unconfirmed revocation remains completed; preserve its evidence, do not
   rerun the raw import, and use the target Vault audit trail plus the 15-minute
   TTL backstop to close the revocation incident. Do not retry a partial or unknown batch:
   create-only/CAS 0 rejection cannot prove an existing secret equals the
   original input. Preserve the source and records under incident procedure for
   operator reconciliation.
7. If the five-minute Transit receipt expires after recovery reports
   `completed`, rerun `secure_pool_import.py` with `--reissue-from` pointing to
   the original safe bundle, the same `--execution-directory`, and a new
   `--receipt-output`; omit `--input-file`. The command validates the closed
   execution record, renews its existing target context, and invokes Transit
   signing only. It does not read the raw source, write KV, or modify the
   original execution directory. It self-revokes the new AppRole token on both
   successful publication and controlled signing/output failure, and treats
   anything other than an empty HTTP 204 as unconfirmed. If a post-publication
   acknowledgement fails, preserve any
   new write-once output, do not overwrite or blindly rerun it, and reconcile
   against the Vault audit trail and TTL. A partial, unknown, consumed,
   caller-mismatched or out-of-window context is refused. Preserve the original
   bundle, fresh bundle and execution record; never overwrite any of them.
8. On the matching administration page, select the safe bundle, review the
   pool type, count and routing preview, then confirm once. If the page reports
   “结果尚未确认”, do not select a different bundle. Use the same-batch recovery
   action. After a refresh or navigation, selecting the exact same bundle is
   also safe: its stable key lets the API return the committed receipt without
   consuming the Transit receipt again. The API-side Transit verifier validates
   its Vault origin before reading the Vault token file: managed environments
   and the default constructor require HTTPS. Local HTTP requires explicit
   opt-in, which the settings factory supplies only for `development`/`test`.
   Empty or malformed
   authorities, invalid ports, user information, path/query/fragment and
   control characters fail with a fixed secret-free error before token or
   network use; proxies and redirects remain disabled.
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
