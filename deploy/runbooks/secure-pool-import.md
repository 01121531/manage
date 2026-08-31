# Secure card and mailbox pool import

Use this runbook when an administrator manually adds resources to the separate
card pool or mailbox pool. Do not upload the raw card or mailbox source file to
the browser, ordinary API, issue tracker, chat, or repository. PAN and mailbox
credentials remain on the approved intake workstation and in Vault; CVV/CVC is
not accepted at all.

1. Confirm Vault audit devices are healthy, then apply and read back
   `infra/vault/configure-secure-import.sh`. Issue distinct short-lived card
   importer, mailbox importer, and API verifier tokens. Repository assets and
   local tests remain `production_acceptance=false`.
2. Run `scripts/secure_import_vault_smoke.py` with the three external token
   files. Preserve its write-once evidence and the matching Vault audit window.
   The current smoke result deliberately records `cleanup_required=true`; an
   approved operator must permanently remove only its two synthetic canary
   metadata paths and verify absence. Until a dedicated pinned cleanup receipt
   exists, this manual cleanup is a production-blocking external evidence gap.
3. Run `scripts/secure_pool_import.py card` or `mailbox` against the matching
   restricted raw input. It emits a browser-safe `schema_version: 2` bundle
   containing masked items, a Transit receipt, and a `submission_key` of the
   form `spi:<signed receipt UUID>`. Keep the raw input, Vault token, and bundle
   outside the repository with restricted permissions.
4. On the matching administration page, select the safe bundle, review the
   pool type, count and routing preview, then confirm once. If the page reports
   “结果尚未确认”, do not select a different bundle. Use the same-batch recovery
   action. After a refresh or navigation, selecting the exact same bundle is
   also safe: its stable key lets the API return the committed receipt without
   consuming the Transit receipt again.
5. A committed result must show the platform receipt ID, trace ID, pool/count,
   `ordered_manifest_digest`, `secure_receipt_fingerprint`, Transit key version
   and timestamps. These are secret-free correlation fields, not proof that the
   target Vault, audit custody, reviewer identity or source secret values are
   authentic.
6. Preserve the platform receipt and audit export according to the evidence
   policy. Destroy temporary raw input and bundle copies only under the approved
   intake retention procedure. Never print or paste a receipt token. Keep
   `production_acceptance=false` until real AppRole provenance, Vault audit,
   canary cleanup/readback, key rotation with old-receipt verification, actual
   dual-pool import and independent review are complete.

The stable submission key prevents blind duplicate batches after an HTTP 5xx,
network loss, page navigation, or refresh. It does not recover a secure importer
process that failed after only some Vault writes; that case remains a stopped,
operator-reviewed recovery incident until the write-ahead execution evidence
workflow is implemented.
