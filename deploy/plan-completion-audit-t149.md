# T149 authoritative completion audit

Audit date: 2026-08-28  
Production acceptance: **false**

## Authority and scope

This audit compares the exact source document
`docs/邮箱验证码助手_平台化建设方案.docx` (raw SHA-256
`ab3074a29140379723cf9d35da433edd9c9a4d30f33c7a12be759e70c6cb2918`)
against:

- `deploy/plan-requirement-inventory.json` for Chapters 1–11;
- `deploy/phase-acceptance-matrix.json` for Phase 0–6;
- `deploy/plan-completion-ledger.json` for repository gate entry points; and
- the T140–T148 implementation, direct tests, CI/release entries and runbook.

The source contains 121 paragraphs, 17 tables and 34 tracked insertions. The
tracked-insertion text was included through direct OOXML extraction. LibreOffice
is unavailable on the audit host, so visual rendering was not completed and is
not claimed by this record.

## Findings

1. The inventory omitted one explicit Chapter 9 requirement: the security
   operations visual direction, responsive layout, visible focus, and the rule
   that status must use text and icons in addition to color. The implementation
   is now implemented by the split `frontend/src/AuthenticatedShell.tsx`,
   `frontend/src/views/shared.tsx` and `frontend/src/authenticated.css`, with direct
   browser coverage in `frontend/e2e/platform.spec.ts`. It is recorded
   as `R09.05`. The sealed inventory therefore contains 51 requirements: 46
   repository-proven, one external-input-required and four target-evidence-required.
2. No inventory item is supported only by indirect verification. Every
   repository-proven item names both direct implementation/contract evidence and
   a test or verifier entry point.
3. The phase matrix and completion ledger agree that Phase 1 has passed only its
   repository gates. No phase claims production acceptance. Phase 0 still needs
   approved external boundaries; Phases 1–6 still need their listed target
   evidence, and Phases 2–6 also need the listed real provider, compliance,
   Windows, or pilot inputs.
4. T140–T148 have no orphaned repository gate or direct behavior-test module.
   External-input CLIs are intentionally documented in
   `deploy/runbooks/private-secret-provenance.md`; they are not local quality-gate
   commands because their required artifacts and signer/provider facts must stay
   outside the repository.

## T140–T148 entry-point audit

| Range | Repository entry points | Direct behavior tests | Static/mutation gate | Result |
| --- | --- | --- | --- | --- |
| T140 | `private_secret_crash_evidence.py` | `test_private_secret_crash_evidence.py` | `verify_private_secret_crash_evidence.py` | registered |
| T141 | `private_secret_github_attestation.py`, `private_secret_target_provenance.py` | matching two test modules | `verify_private_secret_provenance.py` | registered |
| T142 | `private_secret_github_rest_collection.py`, `private_secret_worm_collection.py` | matching two test modules | `verify_private_secret_collection.py` | registered |
| T143 | `private_secret_collector_deployment.py` | `test_private_secret_collector_deployment.py` | `verify_private_secret_collector_deployment.py` | registered |
| T144–T146 | `private_secret_collection_backed_acceptance.py` and its manifest CLI boundary | `test_private_secret_collection_backed_acceptance.py` | upstream T142/T143 gates | registered; no independent trust claim |
| T147 | `private_secret_collection_review_decision.py` | `test_private_secret_collection_review_decision.py` | `verify_private_secret_collection_review.py` | registered |
| T148 | `private_secret_collection_archive_receipt.py` | `test_private_secret_collection_archive_receipt.py` | `verify_private_secret_collection_archive.py` | registered |

The matching static-gate test modules are also present in the exact CI and
release test lists. T144 changes the T142/T143 contracts and has no separate
runtime entry point; this is intentional rather than an omission.

## Stop condition for offline trust layers

T147 authenticates a reviewer assertion and T148 authenticates an archive
provider/custody assertion. They bind different statements, but neither creates
provider-native evidence, trusted time, global replay/fork protection, immutable
storage, or real signer identity. The repository-side Phase 1 boundary is closed.
Do not add another signed wrapper, receipt, checkpoint or verifier unless a real
target system introduces a new independently enforceable boundary.

## First external pending requirement

`R01.07` remains the first external-input-required item. The repository already
provides redacted Mail/Sub2 envelope templates, conformance checks, target-intake
preflight and a runbook. Further repository-only protocol work would not reduce
the missing fact: an approved real Sub2 request/response/authentication,
idempotency and status-query contract. The next useful action is to collect that
redacted external contract and run the existing conformance command. Until then,
the current generic adapter's status-query/idempotency-lookup gap remains explicit
and production acceptance remains false.

## T168 evidence-strength correction

The T149 counts above are retained as a historical snapshot and are superseded
for current planning by the sealed requirement inventory. A direct semantic
audit found that file-existence evidence had overclaimed three requirements.
`R01.03` and `R01.05` are now `missing_implementation` until explicit card
replacement semantics and device-scoped audit replay are implemented.
`R11.05` is now `target_evidence_required`: repository fixtures and examples are
guarded, but only target IAM/storage-denial, provenance, fixture-digest,
live-connector absence and independent-review evidence can prove that a real
development or demo environment contains no production card or mailbox data.
The current classification is therefore 43 repository-proven, two
missing-implementation, one external-input-required and five
target-evidence-required; production acceptance remains false.
