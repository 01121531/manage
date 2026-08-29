# Target intake and preflight

This runbook collects the external inputs and evidence indexes required by
every Phase 0–6 acceptance-matrix entry. It is an intake completeness check,
not production acceptance. Every generated manifest and successful command remains
`production_acceptance=false`.

## Boundary

- Keep the manifest and every referenced artifact under a protected,
  repository-external directory. The CLI rejects relative paths, repository
  paths, missing files, and symlink or Windows reparse-point paths.
- Store only reviewed, redacted contracts, decisions, inventories, or evidence
  indexes; never copy live credentials, bearer tokens, PAN/CVV, raw mailbox
  data, private keys, or unredacted pilot identities into an intake artifact.
- `target_platform_inventory` records DNS/SAN/CA owners, control-plane owners,
  repository-external runtime-secret paths, and evidence roots. It records
  paths and owners only; it never contains the secret values.
- Each registered artifact is limited to 5 MiB; the selected release execution
  ledger has a stricter 64 KiB limit. Every artifact uses the same bounded
  regular-file reader, which rejects link/reparse paths and rechecks file
  identity, link count, size, and modification state after the read. Sixteen
  ordinary JSON artifact types use one parser that rejects duplicate JSON keys
  at every nesting level and parses the returned bytes once before their
  type-specific closed validator; the release ledger retains its stricter
  dedicated 64 KiB schema and successful-terminal validator.
  Standalone `check` commands reuse the same bounded reader and unique-key
  parser for these sixteen artifact types. The intake manifest
  arguments and Phase 0 checkpoint use the same
  stable reader and unique-key parser and are limited to 64 KiB.
  A replacement, expansion, shape change, or ambiguous JSON document fails
  closed. The preflight verifies each
  registered whole-file SHA-256 and never prints a path or file contents.
- Six generated evidence readers (CI rehearsal, training, forward deployment,
  rolling release, rollback, and selected release binding) also use the same
  stable reader and unique-key parser with a 64 KiB limit. Their existing
  schema, terminal-state, canonical digest, whole-file SHA-256, and redacted
  error contracts remain authoritative.
- `redaction_confirmed=true` is a human review assertion, not an automated
  secret scan. The reviewer remains responsible for the actual material.
- Authoring proceeds through immutable generations while Phase 0–6 evidence is
  collected. `init` publishes generation 000 and its closed schema-v2 genesis receipt;
  every later generation is a separate no-replace leaf accepted only when
  `register` has also published its write-once receipt. Never overwrite a prior
  generation or use the editable candidate, an unreceipted leaf, or a receipt
  selected for a different locator as an accepted manifest. Production
  sign-off uses a separately finalized leaf and caller-pinned canonical-payload
  and whole-file SHA-256 values.
- Every schema-v2 generation receipt self-binds its case-preserving lexical
  absolute `receipt_path`; copying identical receipt bytes to another locator
  does not transfer acceptance. Schema-v1 generation receipts and mixed v1/v2
  chains are incompatible and must be rebuilt under new external names rather
  than promoted or silently rewritten.
- Before each of the seven standalone manifest-consumer `check` commands, review
  the current authoring manifest and retain both digest values printed by a
  successful progress
  preflight. Pass those independently retained values as
  `--expected-intake-manifest-payload-sha256` and
  `--expected-intake-manifest-file-sha256`. Each consumer reads the manifest
  once before any other evidence, requires the exact schema-v2 top level and
  ordered seventeen-item closed inventory, and matches both semantic and byte
  identities. Each consumer requires the caller's absolute `--input` locator to
  equal its own `provided` manifest `artifact_path` after lexical absolute-path
  normalization without case folding, then reads the manifest locator itself.
  A different path with identical bytes, a case-only alias, a symlink/reparse
  path, or a hard-linked file is not the reviewed locator. The first stable
  read must have exactly one link and its raw whole-file SHA-256 must equal the
  own item; immediately before success the same manifest locator is stably
  reread against the captured file identity, single-link count and bytes.
  Semantic-equivalent reformatting, rename/replacement during the check, or a
  new hard link is therefore rejected. Do not calculate either expected value inside the
  consumer or
  read it back from the manifest during the check. These pins bind one reviewed
  authoring snapshot and the locator at the final recheck only: caller identity,
  review-time inode continuity, custody after that recheck, delete/recreate with
  identical bytes, parent-directory race closure, pin authority and
  global rollback/latest-head protection remain `unverified`, and coordinated
  replacement of both manifest and externally retained pins is outside this
  repository's proof. No digest is embedded in a consumer, so no self-hash
  cycle is created.

## Initialize an incomplete manifest

Create the protected parent directory and its target-platform ACL before this
step. The output leaf must not already exist; initialization uses exclusive
creation and never overwrites a previous manifest.

```powershell
python scripts/target_intake_preflight.py init `
  --output D:\email-platform-evidence\intake\staging-target-intake-000.json `
  --receipt-output D:\email-platform-evidence\intake\staging-target-intake-000.receipt.json `
  --environment staging
```

The generated manifest binds itself to the canonical requirements registry in
`deploy/target-intake-requirements.json`. It uses target-intake schema v2.
Every item starts with `status` set to `missing` and all artifact metadata set
to `null`; only `release_execution_evidence` also carries
`release_execution_review_subject=null`. Schema-v1 manifests are invalid under
the current verifier and must be rebuilt with a new Phase 0 checkpoint and
release execution. They are not silently reinterpreted as full-selector
reviews.

## Register one reviewed artifact

After an independent reviewer confirms that the material follows the boundary
above, copy the selected current generation to a separate candidate file and
change exactly one `missing` item to this shape. Do not edit the selected input
generation. Every other item and every top-level field must remain byte-for-byte
equivalent after JSON parsing:

```json
{
  "id": "sub2_contract",
  "status": "provided",
  "artifact_path": "D:\\email-platform-evidence\\intake\\sub2-contract-redacted.json",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "reviewed_by": "security-review-ticket-42",
  "reviewed_at": "2026-08-26T12:00:00Z",
  "redaction_confirmed": true
}
```

Retain the current generation's canonical-payload and whole-file SHA-256 values
from an independently reviewed progress preflight. Register the candidate to a
new, previously absent output leaf:

```powershell
python scripts/target_intake_preflight.py register `
  --input D:\email-platform-evidence\intake\staging-target-intake-000.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake-000.receipt.json `
  --candidate D:\email-platform-evidence\intake\staging-target-intake-candidate-001.json `
  --output D:\email-platform-evidence\intake\staging-target-intake-001.json `
  --receipt-output D:\email-platform-evidence\intake\staging-target-intake-001.receipt.json `
  --expected-input-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-input-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

`register` first validates the complete caller-pinned receipt chain and both
manifest pins, then validates the candidate and newly registered artifact. It
rechecks the full lineage, candidate and artifact before and after generation
publication. Only after those checks does it publish the new write-once receipt;
that receipt, not the manifest hard link alone, is the generation acceptance
point. Retain the printed manifest and receipt payload/file digests for the next
independently approved step. A generation published without a receipt is
`orphaned-unaccepted` and must never be consumed. A receipt published but not
successfully read back is `commit-state=unknown`; preserve both files and use an
independent exact-pin lineage verification before any recovery decision. The
failure line prints the exact manifest/receipt payload and whole-file SHA-256
values required by the command below. Never delete either automatically. A concurrent writer to the same output cannot
overwrite the winner. Writers can still choose different output names from the
same base and create forks, so fork protection, latest-head selection, pin
authority, cross-host linearization and post-publication custody remain
`unverified`. Change control must select and retain the intended current
generation; a successful command does not discover or certify a global latest
head.

Recover an `init` or `register` unknown state with the exact four pins printed
by that failed command and retained outside the mutable generation directory:

```powershell
python scripts/target_intake_preflight.py verify-generation-lineage `
  --manifest D:\email-platform-evidence\intake\staging-target-intake-001.json `
  --receipt D:\email-platform-evidence\intake\staging-target-intake-001.receipt.json `
  --expected-manifest-payload-sha256 1111111111111111111111111111111111111111111111111111111111111111 `
  --expected-manifest-file-sha256 2222222222222222222222222222222222222222222222222222222222222222 `
  --expected-receipt-payload-sha256 3333333333333333333333333333333333333333333333333333333333333333 `
  --expected-receipt-file-sha256 4444444444444444444444444444444444444444444444444444444444444444
```

`verify-generation-lineage` is read-only: it does not create, replace, delete,
repair, accept, or promote any file. It recursively replays the selected chain
to genesis and performs a final identity/bytes/single-link recheck, but always
reports `production_acceptance=false`. Pins printed by the same failed process
are recovery inputs, not independent pin authority; retain them in external
change control before relying on the result. An orphan manifest without a
published receipt cannot be promoted by this command.

The provided `release_execution_evidence` item has one additional closed
field. Copy the exact four-field selector from every consuming evidence index;
do not reduce it to a digest-only review:

```json
{
  "id": "release_execution_evidence",
  "status": "provided",
  "artifact_path": "D:\\email-platform-evidence\\release\\selected-v3-execution.json",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "release_execution_review_subject": {
    "kind": "release_execution_selector_v1",
    "selector": {
      "ledger_type": "forward",
      "evidence_object_reference": "worm-release-execution:record-42a",
      "evidence_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "target_intake": {
        "environment": "staging",
        "manifest_payload_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "requirements_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "checkpoint_phase": 0
      }
    }
  },
  "reviewed_by": "release-selection-review-record-42",
  "reviewed_at": "2026-08-26T12:00:00Z",
  "redaction_confirmed": true
}
```

Use an opaque ticket or approval reference for `reviewed_by`. For the sealed
Mail/Sub2 provider contracts, every Phase 1–5 execution index, the Windows and
Phase 6 pilot input inventories, the Sub2 and Vault/egress indexes, and the
Phase 6 pilot and operations indexes, this value must exactly equal the artifact's sealed
`review_reference`; `reviewed_at` must exactly equal its sealed UTC review
timestamp. Execution-index review cannot precede `finished_at`. Provider
contract review must fall between source capture and the exclusive
`valid_until`. Phase 1–6 execution evidence, Sub2, Vault/egress, Windows inputs
and Phase 6 pilot inputs are usable only in the half-open interval
`[reviewed_at, valid_until)`. One
preflight captures one UTC evaluation instant and passes it through the Phase 0
checkpoint, provider-contract runtime conformance and every evidence validator;
it never refreshes the clock between artifacts or dependency replays. For the
release execution ledger, `reviewed_by` and `reviewed_at` refer to the exact
closed `release_execution_selector_v1` subject: ledger type, opaque locator,
whole-file SHA-256, and frozen Phase 0 target-intake identity. The digest and
target-intake fields must match the independently parsed ledger, and the full
subject must exactly equal every release consumer in this manifest. Changing
only the locator—or rebinding all consumers together—requires a new matching
subject and a new review claim; it cannot inherit the old selector review. The
review time must be at or after ledger `finished_at` and not after the
evaluation instant. For the remaining artifact policies without a sealed
review time, the manifest timestamp must still be canonical UTC ending
in `Z`. An opaque reviewer reference and host-clock comparison are not an
authenticated signature or trusted time. The repository does not define a
release-review signer role, pinned public-key trust anchor, private-key custody/
rotation/revocation policy, signature domain and canonical signed payload,
trusted timestamp receipt, or nonce/sequence/ledger-head replay policy. The
existing private-secret Ed25519 policies have distinct, scope-limited signing
domains and are unconfigured; their keys and receipts must not be reused for a
release-selection review. Until a dedicated external trust policy defines all
of those controls, `reviewed_by` and `reviewed_at` remain an opaque attribution
claim. The full-selector projection and local ordering reject subject drift,
byte substitution and predating, but do not authenticate the reviewer, time,
storage provider, locator authority or global replay state.
Likewise, the legacy `worm-release-execution:` prefix is only a compatibility
namespace for an opaque storage locator. The selector does not read or
authenticate a provider configuration, immutable object/version identity,
retention mode or deadline, legal hold, denied-delete response, post-denial
readback, provider signer, trusted time, or replay head. The forward and rolling
writers' repository-external no-replace publication and whole-file SHA-256 prove
neither provider-native WORM enforcement nor continued retention. The existing
private-secret WORM policy is `unconfigured` and its signing usages are scoped
to the private-secret evidence domain, so its keys, receipts, policy, and
observations must not be reused for this release locator. Until a dedicated
release-storage trust policy and independently pinned provider receipts exist,
provider-native enforcement, retention, delete denial, and readback all remain
`unverified`.
Final strict intake additionally requires every reviewed Phase 1-5, Sub2,
Vault/egress, Phase 6 pilot, and Phase 6 operations consumer in that one
manifest to carry the exact same release-execution selector, including the
opaque locator, ledger type, whole-file digest, and target-intake identity.
This rejects a same-manifest alias or rebind such as one consumer changing only
the locator while retaining the reviewed digest. It proves only equality of
the claims presented in that intake. No provider/account namespace authority,
immutable object version/generation identity, or caller-pinned historical
registry/head is available to detect the same locator being rebound to another
digest or environment in a later manifest. Delete-then-recreate with identical
bytes also remains indistinguishable from continuous retention. Namespace
authority, version identity, and cross-manifest rebinding protection therefore
remain `unverified`; a local registry, path string, or same-manifest equality
must not upgrade those claims.
Recompute SHA-256 after every approved artifact change. Do not add inline
artifact content, self-authored signature fields, or extra manifest fields; the
schema is closed.

## Provider contract envelopes

The committed `deploy/provider-contracts/*.synthetic.json` files document the
closed Mail and Sub2 field-shape envelopes. Copy only the relevant shape to the
protected external intake directory, replace its capability mappings with the
reviewed provider facts, set `synthetic=false`, and record opaque
`provider_reference` and `review_reference` values. Mail schema v2 and Sub2
schema v3 also require a closed `source_provenance`: the target environment and
opaque provider-account scope; opaque source-document and source-version
references; the lowercase SHA-256 of the immutable, redacted external source
capture; and canonical UTC `captured_at` and exclusive `valid_until`. Seal the
contract's `reviewed_at` between those timestamps. Strict intake rejects an
expired contract, a scope environment different from the intake environment,
or manifest review metadata different from the contract. Synthetic contracts cannot
satisfy strict intake, and the envelope must never contain example values,
credentials, message content, verification codes, provider URLs, request or
response bodies, or cardholder data.

The Sub2 schema-v3 workflow is deliberately pending in the repository template.
Populate all four ordered operations (`balance_check`,
`authorization_exchange`, `create`, and `status_query`) with opaque operation
references, HTTP methods, and request/response field names only. Declare whether
the provider exposes one atomic create operation or an ordered multi-step flow.
Keep each operation mapped to the fixed platform phase in the template, with
`timeout_outcome=unknown` and `automatic_retry=false`.

The reviewed workflow must also state the provider-account idempotency scope,
minimum retention, same-key replay behavior, different-payload collision
behavior, query consistency model, maximum visibility delay, and query record
retention. `not_found_outcome` must remain `unknown`. The provider idempotency
value is the server-generated `upload_job_id`; the user-supplied API replay key
is never sent as the provider lookup key. Do not change this value source without
changing and revalidating both create and query implementations.

Check the reviewed Mail envelope against the current generic connector:

```powershell
python scripts/provider_contract_conformance.py check --input D:\email-platform-evidence\intake\mail-contract-redacted.json --expected-type mail
```

Check the reviewed Sub2 envelope independently:

```powershell
python scripts/provider_contract_conformance.py check --input D:\email-platform-evidence\intake\sub2-contract-redacted.json --expected-type sub2
```

Exit code 1 means the content envelope itself is invalid. Exit code 2 means the
reviewed envelope is structurally valid but the current runtime lacks one or
more declared capabilities. The repository currently locks a Sub2
workflow/status-query gap: the generic create request and provider idempotency
header exist, but the real balance/auth/create mapping, supplier status query,
and idempotency lookup are not implemented. A Phase 0 checkpoint may preserve
the reviewed contract while implementation is pending; a Phase 4-or-later
checkpoint additionally runs runtime conformance and rejects this gap. Do not
enable a production Sub2 Adapter until a real reviewed contract is present and
this command exits 0.

The worker has a provider-independent lookup protocol only. A supplier Adapter
may normalize a reviewed query result to exactly `succeeded`, `failed`,
`processing`, `not_found`, or `unknown`. Only the first two states may resolve an
unknown job. `processing`, `not_found`, malformed output, and transport failure
all remain `unknown`; in particular, `not_found` never proves that the original
submission was not created and never authorizes an automatic retry. This
protocol does not guess or enable an HTTP URL, method, reference field, result
field, or supplier outcome mapping.

## PCI and OIDC decision envelopes

The committed `deploy/decision-envelopes/*.synthetic.json` files are closed,
pending shapes for `card_pci_boundary` and `oidc_deployment_identity`. Synthetic
decision envelopes cannot satisfy strict intake. Copy the applicable shape to
the protected external directory, set `synthetic=false` and
`decision_status=approved`, then add distinct opaque decision, independent
review, assessment/mapping, issuer, and ownership references as required by the
shape. Seal canonical UTC `reviewed_at` and an exclusive `valid_until`; the
decision is usable only inside `[reviewed_at, valid_until)`. The same manifest
item must repeat the sealed `review_reference` and `reviewed_at` exactly. Do not
add reviewer names, email addresses, PAN/CVV values, token samples, client
secrets, or other credentials.

Check the reviewed PCI/CVV decision and its current runtime alignment:

```powershell
python scripts/decision_envelope_validation.py check --input D:\email-platform-evidence\intake\card-pci-boundary.json --expected-type card_pci_boundary
```

Check the reviewed OIDC deployment identity independently:

```powershell
python scripts/decision_envelope_validation.py check --input D:\email-platform-evidence\intake\oidc-deployment-identity.json --expected-type oidc_deployment_identity
```

Exit code 1 means the closed decision content or its cross-references are
invalid. Exit code 2 means the decision is valid but the current runtime is not
aligned; for example, a WebAuthn decision remains a runtime gap until the target
Keycloak realm implements and verifies that method. The card envelope does not
authorize CVV storage, API reveal, or Sub2 egress. Its runtime check proves those
three repository controls only; it does not claim that an upstream secret
provider can never return CVV to process memory. A stronger ingress-rejection
decision requires an explicit runtime change and new tests before acceptance.
The command captures one UTC comparison instant for content and runtime checks;
the host clock is not evidence of a trusted external time source.

## Phase 0 boundary approval

The committed `phase0-boundary-approval.synthetic.json` fixes the reviewed data
classification shape, but a synthetic Phase 0 approval cannot satisfy strict
intake. A reviewed copy must set `synthetic=false` and
`approval_status=approved`, use distinct opaque approval, independent-review,
security, privacy, and platform-owner references, and contain no sensitive
values. Seal canonical UTC `reviewed_at` and exclusive `valid_until`; the
approval is usable only inside `[reviewed_at, valid_until)`.

Populate its six `bindings` only after the two provider contracts, two decision
envelopes, and target platform inventory are registered. Their values must be
the exact SHA-256 values from the same intake manifest;
`target_intake_requirements_sha256` must equal that manifest's
`requirements_sha256`. The approval review time must not predate any of those
five reviewed inputs, and its own manifest item must repeat the approval's
`review_reference` and `reviewed_at` exactly. Then check the approval against
that manifest:

```powershell
python scripts/phase0_boundary_approval.py check `
  --input D:\email-platform-evidence\intake\phase0-boundary-approval.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

Exit code 1 means the closed approval, data classification, reviewer references,
or binding hashes are invalid. Exit code 2 means the approval names a different
artifact set or requirements digest, the authoring-manifest pins do not match,
the approval `--input` locator differs from its own manifest `artifact_path`,
or the approval's stable raw whole-file SHA-256/single-link identity differs
from its own supplied manifest item. Success proves
only that one approved record binds the same intake manifest content set; it
does not prove production acceptance, reviewer identity or authority, external
approval authenticity, or that any target control operated.

## Target platform inventory

The committed `deploy/inventory-envelopes/target-platform.synthetic.json` is a
closed pending shape. A synthetic target platform inventory cannot satisfy
strict intake. Copy it to the protected external intake directory, set
`synthetic=false`, `inventory_status=reviewed`, and set `environment` to the
exact environment in the same intake manifest.
Seal canonical UTC `reviewed_at` and exclusive `valid_until`; the inventory is
usable only inside `[reviewed_at, valid_until)`, and its manifest item must
repeat its `review_reference` and `reviewed_at` exactly.

Record paths and owner references only. The inventory accepts the public HTTPS
origin and Keycloak issuer, opaque DNS/TLS/Keycloak/Vault owner references, the
exact nine internal TLS leaf DNS names, repository-external target-host paths
for the ten runtime files, three isolated Vault token directories, three policy
files, and the TLS, rolling-route, and evidence roots. Never copy a password,
database URL, Vault token, role/secret ID, certificate, private key, PAN/CVV,
mail content, or personal contact into this file.

Check the reviewed inventory against the current Compose and `.env` input
contract:

```powershell
python scripts/target_platform_inventory.py check `
  --input D:\email-platform-evidence\intake\target-platform-inventory.json
```

Exit code 1 means the closed content, HTTPS relationship, responsibility
reference, path shape, environment, or prohibited-content declaration is
invalid. Exit code 2 means the inventory is valid but the repository no longer
declares or consumes the expected deployment inputs. This command checks path
syntax and the review assertion only; it does not prove that the target paths
exist, are outside the deployed source tree, have correct ACLs, or contain the
intended material. Verify those facts, DNS resolution, certificate chains and
TLS handshakes on the target host and retain external evidence.

Strict intake captures one UTC evaluation instant and passes it through both
decisions, the target inventory, the Phase 0 approval, provider contracts and
checkpoint replay. A future review time, an expiry equal to that instant, or a
non-canonical timestamp fails closed. This comparison does not make the local
clock trusted time and does not authenticate any opaque approval/reference.

The successful forward/rolling release execution ledger remains an immutable
historical account of one completed execution. Do not add an arbitrary
`valid_until` to that ledger. Reuse is instead constrained by its exact
whole-file digest and Phase 0 checkpoint identity, by revalidation of the
current Phase 0 contracts/decisions/inventory/approval at the same evaluation
instant, and by the consuming Phase 1–6 evidence index's own exclusive review
deadline. The release entrypoint captures one host-UTC instant and uses that
same value both to validate the frozen Phase 0 checkpoint and as ledger
`started_at`. Final strict intake reconstructs the frozen six-item validity
intersection as `[max(reviewed_at), min(valid_until))` and requires the recorded
start inside it, so a ledger cannot claim a start before its latest Phase 0
review or at the earliest expiry boundary. This is replayable ordering over
sealed bytes, not proof that the host clock or external approvals were authentic.

Phase 0 validity is an entry authorization, not an invented execution lease.
The repository has no approved renewal, mid-run cancellation or automatic
rollback policy, so it does not claim that a release completing after a Phase 0
expiry was continuously authorized. Instead, the ledger must finish before its
exact digest may be selected and reviewed, and every Phase 1–6 consuming
execution window must start at or after ledger `finished_at`. Equality at that
handoff is accepted. Historical ledgers do not expire merely because time passes.
The forward and rolling standalone ledger verifiers remain checkpoint-independent
historical-integrity checks: they do not read the frozen Phase 0 checkpoint and
must not claim start-time authorization. Final strict intake is the sole
repository verifier that combines the exact checkpoint, current six Phase 0
items, selected ledger and all consumers to prove the complete chain
`finished_at <= ledger reviewed_at <= consumer window.started_at` together with
the frozen-window start replay. Every success output explicitly reports
`release-review-selector-subject=manifest-exact`, while reviewer authentication,
trusted time and replay protection remain `unverified`; those markers cannot be
upgraded by supplying a SHA-256, host timestamp or opaque ticket reference. The
same outputs report provider-native storage,
retention, delete denial and post-denial readback as `unverified`; the legacy
locator prefix, local no-replace write, or ledger digest cannot upgrade them.

## Phase 1, 2, 3 and 5 typed target artifacts

The five committed files below are sealed `synthetic=true`, `pending`
contracts. Phase 1/2/3/5 execution indexes use schema v3; the Windows pilot
input inventory uses schema v2. They define the exact fields a future external
reviewer must fill; they are not target evidence and cannot satisfy a strict
checkpoint:

- `phase1-platform.synthetic.json` covers target Keycloak/Vault login,
  authorization, audit and administrator separation, plus PostgreSQL, Redis,
  internal TLS, secret-manager, backup/restore and CI release scenarios.
- `phase2-mail.synthetic.json` covers real mail concurrency, outage,
  rate-limit and stale-code behavior plus worker-only credential and network
  egress enforcement.
- `phase3-card.synthetic.json` covers PostgreSQL concurrent allocation,
  target migration, Keycloak step-up and PCI-boundary enforcement.
- `windows-pilot-inputs.synthetic.json` records the approved Windows pilot
  environment and an ordered list of symbolic business-field identifiers. It
  never records field values.
- `phase5-windows.synthetic.json` covers Windows EXE login, session-loss stop,
  offline recovery, signed-update rollback, clipboard continuous paste and
  preservation of the approved business-field order.

Phase 2 reuses the reviewed `mail_contract` because that closed provider
contract already validates the exact interface and policy facts named by the
Phase 2 missing-input entry. Phase 3 likewise reuses the typed
`card_pci_boundary` and `oidc_deployment_identity` decisions for its two
missing-input entries. The execution claims remain separate evidence indexes;
neither a contract nor a decision can stand in for a target run.

For each file, copy the corresponding pending shape to the protected external
directory, populate every fixed scenario with opaque execution, executor,
independent-reviewer, correlation and immutable evidence-object references,
canonical UTC time, its fixed observation, external-object SHA-256,
`result=passed`, and `redaction_confirmed=true`. Set `synthetic=false`, the
status to `reviewed`, and bind the artifact to the same manifest environment
and exact prerequisite item hashes. Seal the aggregate `review_reference`,
`reviewed_at` and exclusive `valid_until`; review every execution index only
after its window finishes. Strict intake requires its one evaluation instant to
remain inside `[reviewed_at, valid_until)`. Every execution evidence index also selects
the same successful schema-v3 release ledger by typed opaque storage reference, whole-file
SHA-256 and Phase 0 checkpoint identity. Its release tag, 40-hex commit and
immutable container-manifest SHA-256 must match an independent parse of that
ledger, and ledger `finished_at` must be no later than the index window's
`started_at`. `windows_pilot_inputs` is a pre-execution inventory and therefore does
not carry a release selector, but it carries the same sealed review and
exclusive validity fields. The complete Phase 5 execution window must start no
earlier than the Windows input review and finish strictly before those inputs
expire.

Check any reviewed artifact with its exact type, for example:

```powershell
python scripts/target_phase_artifacts.py check `
  --input D:\email-platform-evidence\intake\phase2-mail-evidence-index.json `
  --expected-type phase2_mail_evidence `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json
```

When checking Phase 5 directly, also supply the exact reviewed Windows input
file so the CLI verifies both its whole-file SHA-256 binding and temporal
containment:

```powershell
python scripts/target_phase_artifacts.py check `
  --input D:\email-platform-evidence\intake\phase5-windows-evidence-index.json `
  --expected-type phase5_windows_evidence `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json `
  --windows-pilot-inputs D:\email-platform-evidence\intake\windows-pilot-inputs.json
```

Allowed types are `phase1_platform_evidence`, `phase2_mail_evidence`,
`phase3_card_evidence`, `windows_pilot_inputs`, and
`phase5_windows_evidence`. Exit code 1 means the closed schema, seal, exact
scenario inventory, fixed result, window, review independence, or redaction
contract is invalid. Exit code 2 means the environment or a prerequisite
whole-file digest does not match the same intake manifest. A successful check
validates metadata only; independently inspect every referenced external
object before acceptance.

## Sub2 execution evidence index

The committed
`deploy/evidence-index-envelopes/sub2-execution.synthetic.json` contains index
metadata only and cannot satisfy strict intake. Create a reviewed external copy
after executing every fixed target scenario: balance check, authorization
exchange, successful create, definitive failure, submission timeout, each of
the five normalized status outcomes (`succeeded`, `failed`, `processing`,
`not_found`, and `unknown`), same-provider-key duplicate replay, and unknown
reconciliation without a blind retry. The fixed observations bind those real
provider actions to `provider_submit`, `provider_result`,
`reconciliation_check`, and `reconciliation_result` without storing provider
payloads.

For each scenario record only opaque execution, executor, independent reviewer,
trace, and immutable evidence-object references; canonical UTC execution time;
the fixed observation; external artifact SHA-256; `result=passed`; and
`redaction_confirmed=true`. Bind the index to the deployed release tag, 40-hex
commit, container-manifest SHA-256, and the exact Sub2 contract and target
platform inventory SHA-256 values from the same intake manifest. Seal one
aggregate `review_reference` and `reviewed_at` after the execution window and
an exclusive `valid_until` after that review. Strict intake rejects the index
before review, at expiration or afterward.
Select the exact successful schema-v3 release execution ledger by whole-file
SHA-256 and its Phase 0 checkpoint identity; the selector and release triple
must match an independent parse of that same ledger. Do not include
supplier URLs, request/response bodies, provider error text, credentials,
tokens, PAN/CVV, verification codes, or personal contact details.

Verify the sealed index and its same-manifest bindings:

```powershell
python scripts/sub2_execution_evidence.py check `
  --input D:\email-platform-evidence\intake\sub2-execution-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json
```

Exit code 1 means the closed index, canonical payload digest, scenario coverage,
time window, release binding, references, independence, or redaction assertion
is invalid. Exit code 2 means its environment, review metadata, Sub2 contract,
target platform inventory, release ledger bytes, release identity, or Phase 0
intake identity does not match the supplied intake manifest. Success proves the index
metadata at the reviewed locator matches the current single-link file identity
and bytes through the final recheck; it does not prove later immutability or
verify the external evidence
content, provider behavior, or production acceptance. Review the referenced
write-once objects independently on the target evidence system.

## Vault isolation and Sub2 egress evidence index

The committed `deploy/evidence-index-envelopes/vault-egress.synthetic.json`
contains index metadata only and cannot satisfy strict intake. Execute the
12-cell Vault identity/path matrix on the target Vault: API may read cards only,
Mail may read mailboxes only, and Sub2 may read cards plus its credential and
proxy objects; every other identity/path cell must return permission denied.

Separately execute the four application origin validation cases (approved
origin allowed; unapproved origin, port, and similar suffix denied before
secret or network access) and two network egress enforcement cases (approved
destination allowed and an unapproved destination denied by the target
firewall/proxy policy). Application validation is not network enforcement, and
neither substitutes for target DNS resolution, TLS-chain, or hostname checks.

For every scenario record only opaque execution, executor, independent
reviewer, trace and immutable evidence-object references, canonical UTC time,
the fixed observation, artifact SHA-256, `result=passed`, and explicit
redaction. Bind the sealed index to the release tag, 40-hex commit, container
manifest, and the exact Sub2 contract and target platform inventory hashes from
the same intake manifest. Seal aggregate `review_reference`, post-window
`reviewed_at` and exclusive `valid_until`; strict intake requires its single
evaluation instant inside that half-open interval and the same review metadata
in the manifest item. Select the same successful schema-v3 release ledger
by typed opaque storage reference, whole-file digest and Phase 0 checkpoint identity; the
release triple must match the independently parsed ledger. Do not record Vault addresses or responses, supplier
URLs or bodies, credentials, tokens, PAN/CVV, verification codes, or identities.

```powershell
python scripts/vault_egress_evidence.py check `
  --input D:\email-platform-evidence\intake\vault-egress-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json
```

Exit code 1 means the sealed content or scenario coverage is invalid; exit code
2 means its environment or same-manifest bindings differ; exit code 3 means the
current repository Vault/origin controls no longer align. Success proves only
the index metadata and repository control shape. It does not verify the
external evidence content or grant production acceptance; independently inspect
the referenced write-once objects and target policy configuration.

## Phase 6 pilot input inventory

The committed `deploy/inventory-envelopes/phase6-pilot-inputs.synthetic.json`
is a pending shape and cannot satisfy strict intake. A reviewed external copy
must list exactly the existing Phase 6 roles: `operator`, `ops_admin`,
`security_auditor`, and `platform_admin`. Use typed opaque roster references
only. Do not record names, email addresses, phone numbers, usernames, team chat
handles, credentials, tokens, or free-form participant notes.

Assign a distinct pilot subject and roster entry to every role. Record distinct
opaque owners for pilot coordination, target operators, the approved alert
receiver, and maintenance execution. The independent inventory reviewer must
not be one of the pilot subjects or owners. Seal `reviewed_at` and exclusive
`valid_until`; strict verification requires `reviewed_at <= starts_at <
rollback_decision_deadline < finishes_at < valid_until` and evaluates the
inventory inside `[reviewed_at, valid_until)`. The current check does not need
to occur during the maintenance window, so the same record remains verifiable
after execution while its review is current. Do not add an inferred duration,
capacity, or local-time conversion to the inventory.

Bind the inventory to the deployed release tag, 40-hex commit, container
manifest SHA-256, the same environment, and the exact target platform inventory
SHA-256 from the intake manifest. Its own manifest item must repeat the sealed
review reference and time. Then verify its closed schema, canonical payload
digest, review validity and binding:

```powershell
python scripts/phase6_pilot_inputs.py check `
  --input D:\email-platform-evidence\intake\phase6-pilot-inputs.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

Exit code 1 means the roster, ownership, release identity, window, review or
sealed content is invalid. Exit code 2 means the environment or target platform
inventory binding differs from the supplied manifest, either authoring-manifest
pin is wrong, the `--input` locator differs from its own manifest
`artifact_path`, or the inventory's stable raw whole-file SHA-256/single-link
identity differs from its own manifest item. Success proves only that the
reviewed locator, current bytes and inventory content match through the final
recheck; it does not prove that any pilot execution occurred, that an alert was
delivered, or that the release is
accepted for production.
It also does not prove custody or immutability after the final recheck.

## Phase 6 target pilot evidence index

The committed `deploy/evidence-index-envelopes/phase6-pilot.synthetic.json` is a
pending metadata shape and cannot satisfy strict intake. The real pilot must run
with target OIDC and reviewed real Mail and Sub2 connectors. CI rehearsal cannot
satisfy this requirement because it uses local test identity, SQLite, and fake
connectors.

Retain all nine fixed dimensions: authenticated session, full business flow,
one-time verification, server-side upload, cleanup, authorization isolation,
persistent-secret scan, audit-trace replay, and audit-resource replay. Record
only typed opaque execution, independent reviewer, trace-set and immutable WORM
object references, UTC timestamps, fixed observations, artifact SHA-256 values,
and redaction assertions. The pilot window must begin no earlier than the
approved maintenance start and finish strictly before the rollback decision
deadline. Seal the aggregate review reference and review time after the
execution window and no later than that decision deadline, plus an exclusive
`valid_until`; strict verification must occur inside that review-validity
interval. Bind the sealed index to the release identity and
the exact Sub2 execution evidence, Phase 6 pilot inputs and target platform
inventory hashes from the same intake manifest. The operator and
security-auditor subjects must match that reviewed pilot roster.

Select exactly one successful schema-v3 release execution ledger: either a
forward ledger with terminal `succeeded` or a Web/API rolling ledger with
terminal `complete_source_retained`. Record only `forward`/`rolling`, its typed
opaque storage reference in the legacy `worm-release-execution:` compatibility
namespace, whole-file SHA-256, and the ledger's four-field Phase 0
`target_intake` identity. Do not record its filesystem path in the index. The
release tag, commit, container-manifest SHA-256, environment and complete intake
identity must match the independently parsed ledger. Schema-v1 ledgers and
failure terminals cannot support target pilot evidence.

Register that exact repository-external ledger as the
`release_execution_evidence` item in the target intake manifest. Use the
forward deployment `--evidence-output` or rolling release `--evidence-output`
file itself; do not copy selector fields into a substitute JSON file. The
manifest SHA-256, pilot selector SHA-256, and operations selector SHA-256 must
all identify the same bytes. Only one successful release mode is required.

```powershell
python scripts/phase6_pilot_evidence.py check `
  --input D:\email-platform-evidence\intake\phase6-pilot-evidence-index.json `
  --pilot-inputs D:\email-platform-evidence\intake\phase6-pilot-inputs.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json
```

Exit code 1 means the sealed index, exact scenario contract, time window,
release identity, references, independence, or redaction assertion is invalid.
Exit code 2 means its roster, environment, or same-manifest bindings differ.
The `check` command independently parses the supplied v3 ledger and compares
its whole-file digest, successful terminal, target release and Phase 0 intake.
The final strict intake preflight also reads the registered ledger once from
the manifest, validates the same v3 success contract, and cross-checks its
identity against both sealed selectors.
Success still does not verify the remaining external evidence content, target
behavior, or production acceptance. Independently inspect the referenced
write-once objects on the target evidence system.

## Phase 6 target operations evidence index

The committed `deploy/evidence-index-envelopes/phase6-operations.synthetic.json`
is a pending metadata shape and cannot satisfy strict intake. Execute every
operation on the target environment and retain page firing and resolved
deliveries at the approved external receiver, three consecutive watchdog
deliveries, and the watchdog missed-heartbeat alarm plus recovery. The
repository Alertmanager placeholder, static configuration checks, and mocked
delivery tests cannot satisfy these scenarios.

Use one release-bound PostgreSQL/Redis recovery set and separately complete the
Vault restore with application-path verification. Execute the release-bound
rollback through a successful terminal ledger, keeping Edge closed until every
internal and external check passes. Complete the reviewed four-role training
session and all five existing tabletop cases, then replay one delivered alert
through its tenant-scoped redacted audit trace.

Operations may begin only after the pilot evidence has been independently
reviewed. The complete operations window must remain strictly inside the
approved maintenance window and finish before the pilot evidence expires. The
`release_bound_rollback` scenario must execute no later than the approved
rollback decision deadline.

Record only the six fixed source-artifact SHA-256 values, typed opaque execution,
independent reviewer and immutable WORM object references, UTC timestamps, fixed
observations, and redaction assertions. Bind the index to the exact T41 pilot
inputs, T42 pilot evidence, target platform inventory and release identity from
the same intake. Its four role subjects and pilot trace-set reference must match
those reviewed dependencies. Seal the aggregate review reference and review
time after the operations execution window, together with an exclusive
`valid_until`; strict verification must occur inside `[reviewed_at,
valid_until)`. The intake item must repeat the sealed review reference and time
exactly. A post-maintenance review is allowed, but it does not move or enlarge
the sealed execution window.
Copy the exact same release-execution selector from the reviewed pilot index;
do not choose another ledger for operations signoff or derive expected values
from the ledger under review.

```powershell
python scripts/phase6_operations_evidence.py check `
  --input D:\email-platform-evidence\intake\phase6-operations-evidence-index.json `
  --pilot-inputs D:\email-platform-evidence\intake\phase6-pilot-inputs.json `
  --pilot-evidence D:\email-platform-evidence\intake\phase6-pilot-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --expected-intake-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-intake-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v3-execution.json
```

Exit code 1 means the sealed index, scenario and artifact inventories, window,
references, results, independence, or redaction declaration is invalid. Exit
code 2 means the environment, roster, trace set, release identity, dependency,
or same-manifest binding differs. Success validates metadata only and does not
verify the external evidence content, delivery receiver, restored data, target
Vault, rollback execution, training attendance, or production acceptance.
It does independently parse the selected v3 release ledger and requires its
selector to equal the pilot selector. Independently inspect every referenced
write-once object and source artifact.

## Check progress without claiming readiness

This mode accepts still-missing items only for intake tracking:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --allow-incomplete
```

An incomplete result must not authorize a deployment, pilot, or acceptance
sign-off.

## Strict phase checkpoints

Do not require evidence from an execution phase before the target needed to
produce that evidence exists. The same manifest advances monotonically through
seven strict checkpoints; every provided item is still fully validated even
when a later-phase item is not yet required.

Before creating a target deployment or Kubernetes overlay, require the six
Phase 0 items: the Mail and Sub2 contracts, PCI and OIDC decisions, the target
platform inventory, and the Phase 0 approval that binds all five inputs.

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --through-phase 0
```

Preserve the successful command's `environment`, `manifest_payload_sha256`,
and `requirements_sha256` values with the release review. The payload digest is
computed from canonical JSON content and is required by forward and rolling
release evidence verifiers; do not derive it from the execution ledger being
checked.

Immediately freeze the validated Phase 0 manifest to a new repository-external
leaf. The command validates the same six items again, reads the source manifest
once, and creates the output exclusively; it never overwrites an existing
snapshot:

```powershell
python scripts/target_intake_preflight.py snapshot `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --output D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --receipt-output D:\email-platform-evidence\intake\staging-phase0-checkpoint.receipt.json `
  --environment staging
```

Use `staging-phase0-checkpoint.json`, not the subsequently evolving intake
manifest, as `--target-intake-manifest` for the forward or rolling release.
Retain the snapshot, its printed snapshot-receipt payload/file SHA-256 values,
and every Phase 0 artifact it references under write-once
  controls. Continue adding Phase 1–6 items only by registering a new generation
  from the selected terminal generation and receipt;
never edit, replace, or regenerate the checkpoint for an already executed
release. A newly approved Phase 0 contract requires a new checkpoint and a new
release execution ledger. The same replacement rule applies when any Phase 0
contract, decision, inventory or approval expires or is re-reviewed.

Advance through the intermediate phases only after each phase's typed external
material is reviewed and registered. The successful release execution ledger
and frozen Phase 0 checkpoint become cumulative requirements at Phase 1 because
every Phase 1–5 execution index selects that ledger. Phase 1 adds the platform evidence index;
Phase 2 adds the real Mail evidence index (the reviewed Mail contract is already
part of Phase 0); Phase 3 adds the card/identity evidence index (the reviewed
PCI and OIDC decisions are already part of Phase 0):

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 1

python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 2

python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 3
```

Before Phase 4 promotion, additionally require the real Sub2 execution and
Vault/egress evidence indexes. Both selectors must name the same ledger bytes
and Phase 0 checkpoint already required since Phase 1:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 4
```

Before Phase 5 promotion, additionally require the reviewed Windows pilot
input inventory and Windows/business-page evidence index. The Phase 0
checkpoint remains mandatory because the selected release ledger is already
part of the cumulative Phase 4 evidence. The preflight also proves
`windows.reviewed_at <= phase5.started_at < phase5.finished_at`,
`phase5.finished_at < windows.valid_until`, and that its single evaluation
instant is strictly before both artifacts' exclusive `valid_until` values:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 5
```

Before Phase 6 promotion, require all seventeen items, including the selected
release execution ledger, pilot roster, pilot execution evidence, and
operations evidence:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 6
```

The unqualified strict check is the production-signoff check. First finalize
the fully populated authoring manifest to a new repository-external leaf. The
command repeats the complete strict validation against the frozen Phase 0
checkpoint, writes deterministic JSON to an adjacent temporary whose file
contents are fsynced, publishes with no-replace semantics, performs a stable readback, and prints
both the canonical payload SHA-256 and the exact finalized-file SHA-256:

```powershell
python scripts/target_intake_preflight.py finalize `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --input-receipt D:\email-platform-evidence\intake\staging-target-intake.receipt.json `
  --expected-input-receipt-payload-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa `
  --expected-input-receipt-file-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb `
  --output D:\email-platform-evidence\intake\staging-target-intake-final.json `
  --receipt-output D:\email-platform-evidence\intake\staging-target-intake-final.receipt.json `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --phase0-checkpoint-receipt D:\email-platform-evidence\intake\staging-phase0-checkpoint.receipt.json `
  --expected-phase0-checkpoint-receipt-payload-sha256 1111111111111111111111111111111111111111111111111111111111111111 `
  --expected-phase0-checkpoint-receipt-file-sha256 2222222222222222222222222222222222222222222222222222222222222222
```

The output leaf must not already exist and is never overwritten. Preserve both
printed digests in the independent change-control or sign-off record before
running the final check. Do not read the expected values back from the manifest
inside the checking command and do not store them only beside the same writable
file. Run the final strict preflight on the finalized leaf with those exact
caller pins:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake-final.json `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --expected-manifest-payload-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  --expected-manifest-file-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 `
  --finalization-receipt D:\email-platform-evidence\intake\staging-target-intake-final.receipt.json `
  --expected-finalization-receipt-payload-sha256 3333333333333333333333333333333333333333333333333333333333333333 `
  --expected-finalization-receipt-file-sha256 4444444444444444444444444444444444444444444444444444444444444444
```

The final check requires both pins and validates the frozen snapshot as a
strict Phase 0 manifest, requires the current six Phase 0 item records to match
it exactly, and requires
the selected release ledger's canonical manifest digest, environment,
requirements digest and checkpoint phase to identify that snapshot. The
authoring manifest may add evidence before finalization; the finalized leaf is
not edited. Silently replacing a deployed contract, decision, approval,
inventory, reviewer reference, timestamp, path or digest is not allowed.

Snapshot and finalization acceptance are represented by separate closed,
canonical, write-once local schema-v2 receipts. Each receipt carries its own
case-preserving lexical absolute `receipt_path`; loading the same bytes from a
different locator fails. Schema-v1 acceptance receipts are incompatible and
must not be promoted or silently rewritten. The snapshot receipt records the Phase 0
evaluation instant and validity intersection and binds the exact source
generation receipt plus result checkpoint locator and bytes. Finalization records
its own evaluation instant so recovery can replay the original decision, then
requires caller pins for that snapshot receipt, verifies its source generation
is an exact ancestor of the terminal generation, and publishes its own receipt
only after the final leaf and all source rechecks succeed. A checkpoint/final
leaf left without its receipt is `orphaned-unaccepted`; a failure after receipt
publication is `commit-state=unknown`; the failure line prints the exact result
manifest and receipt payload/file SHA-256 values needed for explicit verification.
Never delete either artifact automatically in those states.

Recover a snapshot unknown state with a read-only replay. Supply the four pins
from the failed command's diagnostic; do not derive them from another mutable
file beside the receipt:

```powershell
python scripts/target_intake_preflight.py verify-receipt `
  --kind snapshot `
  --manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --receipt D:\email-platform-evidence\intake\staging-phase0-checkpoint.receipt.json `
  --expected-manifest-payload-sha256 1111111111111111111111111111111111111111111111111111111111111111 `
  --expected-manifest-file-sha256 2222222222222222222222222222222222222222222222222222222222222222 `
  --expected-receipt-payload-sha256 3333333333333333333333333333333333333333333333333333333333333333 `
  --expected-receipt-file-sha256 4444444444444444444444444444444444444444444444444444444444444444
```

Recover a finalization unknown state by additionally selecting the exact Phase
0 checkpoint bound by the finalization receipt:

```powershell
python scripts/target_intake_preflight.py verify-receipt `
  --kind finalization `
  --manifest D:\email-platform-evidence\intake\staging-target-intake-final.json `
  --receipt D:\email-platform-evidence\intake\staging-target-intake-final.receipt.json `
  --expected-manifest-payload-sha256 5555555555555555555555555555555555555555555555555555555555555555 `
  --expected-manifest-file-sha256 6666666666666666666666666666666666666666666666666666666666666666 `
  --expected-receipt-payload-sha256 7777777777777777777777777777777777777777777777777777777777777777 `
  --expected-receipt-file-sha256 8888888888888888888888888888888888888888888888888888888888888888 `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json
```

`verify-receipt` does not create, replace, delete, repair, or promote any file.
It reports `recovery=read-only-local-revalidation`, recursively reloads and
rechecks the selected local chain, replays Phase 0
at the snapshot time and complete final intake at the finalization time, and
always reports `production_acceptance=false`. A successful recovery is local
evidence for disposition; it is not a provider-backed commit decision.

These receipts still prove only that this process selected, published, and read
back one local chain without replacing an existing name. Self-binding rejects a
copied receipt at another locator, but cannot distinguish deleting and recreating
the same bytes at the same path. The final-manifest and
finalization-receipt caller pins detect a later
byte rewrite, semantic replacement, or rollback when the caller retains the
current values independently. They do not authenticate who supplied the pins,
prevent rollback of the receipt/result/four-pin set as one unit, prevent
same-path deletion and recreation, prove provider-native immutability, or identify
the globally latest manifest. Parent-directory replacement races remain open;
the staged file data fsync does not prove crash durability of the later hard-link
directory entry. Pin authority, locator continuity, parent-directory race
protection, publication crash durability, custody after publication, and global
rollback protection therefore remain `unverified`; a real guarantee
requires an external signed change-control record or provider-native CAS/WORM
head. Generation receipts are unsigned local JSON. Self-binding rejects receipt
copies at another locator, but does not distinguish deleting and recreating the
same bytes at the same path. Rolling an older manifest, generation receipt and
all four older pins back as one unit still passes local replay; sequence is not
a global head. The authoring writer fsyncs the staging file but does not prove
crash durability of the later hard-link directory entry, and a parent directory
can still be replaced between path preparation and publication. Generation
receipts therefore do not prove reviewer/pin/receipt authority, global
latest-head selection, cross-host fork prevention or CAS/WORM, trusted time,
locator continuity, parent-directory race protection, publication crash
durability, global rollback protection, or custody after the final recheck.
Snapshot and finalization receipts
have the same unsigned local authority boundary; the recorded host evaluation
instant is not trusted time. The
private-secret signing domains and their still-unconfigured trust
anchors are scope-limited and must not be reused for this purpose.

Checkpoint success proves only that the items required through that phase have
valid metadata, safely located paths, matching hashes, and explicit review and
redaction assertions. It never proves that a provider contract is correct,
that controls operated successfully, or that a production acceptance criterion
passed. Those claims require the real target execution, independent evidence
review, and the production sign-off workflow.
