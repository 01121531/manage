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

## Initialize an incomplete manifest

Create the protected parent directory and its target-platform ACL before this
step. The output leaf must not already exist; initialization uses exclusive
creation and never overwrites a previous manifest.

```powershell
python scripts/target_intake_preflight.py init `
  --output D:\email-platform-evidence\intake\staging-target-intake.json `
  --environment staging
```

The generated manifest binds itself to the canonical requirements registry in
`deploy/target-intake-requirements.json`. Every item starts with `status` set to
`missing` and all artifact metadata set to `null`.

## Register one reviewed artifact

After an independent reviewer confirms that the material follows the boundary
above, change the matching item to this shape:

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

Use an opaque ticket or approval reference for `reviewed_by`. The timestamp
must be canonical UTC ending in `Z`. Recompute SHA-256 after every approved
artifact change. Do not add inline artifact content or extra manifest fields;
the schema is closed.

## Provider contract envelopes

The committed `deploy/provider-contracts/*.synthetic.json` files document the
closed Mail and Sub2 field-shape envelopes. Copy only the relevant shape to the
protected external intake directory, replace its capability mappings with the
reviewed provider facts, set `synthetic=false`, and record opaque
`provider_reference` and `review_reference` values. Synthetic contracts cannot
satisfy strict intake, and the envelope must never contain example values,
credentials, message content, verification codes, or cardholder data.

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
more declared capabilities. The repository currently locks a Sub2 status-query
gap: submit and idempotency headers exist, but supplier status query and
idempotency lookup are not implemented. Do not enable a production Sub2
Adapter until a real reviewed contract is present and this command exits 0.

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
shape. Do not add reviewer names, email addresses, PAN/CVV values, token samples,
client secrets, or other credentials.

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

## Phase 0 boundary approval

The committed `phase0-boundary-approval.synthetic.json` fixes the reviewed data
classification shape, but a synthetic Phase 0 approval cannot satisfy strict
intake. A reviewed copy must set `synthetic=false` and
`approval_status=approved`, use distinct opaque approval, independent-review,
security, privacy, and platform-owner references, and contain no sensitive
values.

Populate its five `bindings` only after the two provider contracts and two
decision envelopes are registered. Their values must be the exact SHA-256
values from the same intake manifest; `target_intake_requirements_sha256` must
equal that manifest's `requirements_sha256`. Then check the approval against
that manifest:

```powershell
python scripts/phase0_boundary_approval.py check `
  --input D:\email-platform-evidence\intake\phase0-boundary-approval.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json
```

Exit code 1 means the closed approval, data classification, reviewer references,
or binding hashes are invalid. Exit code 2 means the approval names a different
artifact set or requirements digest than the supplied manifest. Success proves
only that one approved record binds the same intake manifest content set; it
does not prove production acceptance or that any target control operated.

## Target platform inventory

The committed `deploy/inventory-envelopes/target-platform.synthetic.json` is a
closed pending shape. A synthetic target platform inventory cannot satisfy
strict intake. Copy it to the protected external intake directory, set
`synthetic=false`, `inventory_status=reviewed`, and set `environment` to the
exact environment in the same intake manifest.

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

## Phase 1, 2, 3 and 5 typed target artifacts

The five committed files below are sealed `synthetic=true`, `pending`
contracts. They define the exact fields a future external reviewer must fill;
they are not target evidence and cannot satisfy a strict checkpoint:

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
and exact prerequisite item hashes. The evidence indexes also bind the release
tag, 40-hex commit and immutable container-manifest SHA-256.

Check any reviewed artifact with its exact type, for example:

```powershell
python scripts/target_phase_artifacts.py check `
  --input D:\email-platform-evidence\intake\phase2-mail-evidence-index.json `
  --expected-type phase2_mail_evidence `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json
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
after executing all five target scenarios: successful submission, definitive
failure, submission timeout, status/idempotency query, and unknown
reconciliation without a blind retry.

For each scenario record only opaque execution, executor, independent reviewer,
trace, and immutable evidence-object references; canonical UTC execution time;
the fixed observation; external artifact SHA-256; `result=passed`; and
`redaction_confirmed=true`. Bind the index to the deployed release tag, 40-hex
commit, container-manifest SHA-256, and the exact Sub2 contract and target
platform inventory SHA-256 values from the same intake manifest. Do not include
supplier URLs, request/response bodies, provider error text, credentials,
tokens, PAN/CVV, verification codes, or personal contact details.

Verify the sealed index and its same-manifest bindings:

```powershell
python scripts/sub2_execution_evidence.py check `
  --input D:\email-platform-evidence\intake\sub2-execution-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json
```

Exit code 1 means the closed index, canonical payload digest, scenario coverage,
time window, release binding, references, independence, or redaction assertion
is invalid. Exit code 2 means its environment, Sub2 contract, or target platform
inventory does not match the supplied intake manifest. Success proves the index
metadata is complete and immutable; it does not verify the external evidence
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
the same intake manifest. Do not record Vault addresses or responses, supplier
URLs or bodies, credentials, tokens, PAN/CVV, verification codes, or identities.

```powershell
python scripts/vault_egress_evidence.py check `
  --input D:\email-platform-evidence\intake\vault-egress-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json
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
not be one of the pilot subjects or owners. The approved maintenance window
must use canonical UTC and satisfy: start before rollback decision deadline,
and rollback decision deadline before finish. Do not add an inferred duration,
capacity, or local-time conversion to the inventory.

Bind the inventory to the deployed release tag, 40-hex commit, container
manifest SHA-256, the same environment, and the exact target platform inventory
SHA-256 from the intake manifest. Then verify its closed schema, canonical
payload digest and binding:

```powershell
python scripts/phase6_pilot_inputs.py check `
  --input D:\email-platform-evidence\intake\phase6-pilot-inputs.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json
```

Exit code 1 means the roster, ownership, release identity, window, review or
sealed content is invalid. Exit code 2 means the environment or target platform
inventory binding differs from the supplied manifest. Success proves only that
the approved inputs are complete and immutable. It does not prove that any
pilot execution occurred, that an alert was delivered, or that the release is
accepted for production.

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
and redaction assertions. Bind the sealed index to the release identity and the
exact Phase 6 pilot inputs and target platform inventory hashes from the same
intake manifest. The operator and security-auditor subjects must match that
reviewed pilot roster.

Select exactly one successful schema-v2 release execution ledger: either a
forward ledger with terminal `succeeded` or a Web/API rolling ledger with
terminal `complete_source_retained`. Record only `forward`/`rolling`, its typed
WORM object reference, whole-file SHA-256, and the ledger's four-field Phase 0
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
  --release-execution-evidence D:\email-platform-evidence\release\selected-v2-execution.json
```

Exit code 1 means the sealed index, exact scenario contract, time window,
release identity, references, independence, or redaction assertion is invalid.
Exit code 2 means its roster, environment, or same-manifest bindings differ.
The `check` command independently parses the supplied v2 ledger and compares
its whole-file digest, successful terminal, target release and Phase 0 intake.
The final strict intake preflight also reads the registered ledger once from
the manifest, validates the same v2 success contract, and cross-checks its
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

Record only the six fixed source-artifact SHA-256 values, typed opaque execution,
independent reviewer and immutable WORM object references, UTC timestamps, fixed
observations, and redaction assertions. Bind the index to the exact T41 pilot
inputs, T42 pilot evidence, target platform inventory and release identity from
the same intake. Its four role subjects and pilot trace-set reference must match
those reviewed dependencies.
Copy the exact same release-execution selector from the reviewed pilot index;
do not choose another ledger for operations signoff or derive expected values
from the ledger under review.

```powershell
python scripts/phase6_operations_evidence.py check `
  --input D:\email-platform-evidence\intake\phase6-operations-evidence-index.json `
  --pilot-inputs D:\email-platform-evidence\intake\phase6-pilot-inputs.json `
  --pilot-evidence D:\email-platform-evidence\intake\phase6-pilot-evidence-index.json `
  --intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --release-execution-evidence D:\email-platform-evidence\release\selected-v2-execution.json
```

Exit code 1 means the sealed index, scenario and artifact inventories, window,
references, results, independence, or redaction declaration is invalid. Exit
code 2 means the environment, roster, trace set, release identity, dependency,
or same-manifest binding differs. Success validates metadata only and does not
verify the external evidence content, delivery receiver, restored data, target
Vault, rollback execution, training attendance, or production acceptance.
It does independently parse the selected v2 release ledger and requires its
selector to equal the pilot selector. Independently inspect every referenced
write-once object and source artifact.

## Check progress without claiming readiness

This mode accepts still-missing items only for intake tracking:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
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
Phase 0 items: the Mail and Sub2 contracts, PCI and OIDC decisions, the bound
Phase 0 approval, and the target platform inventory.

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
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
  --output D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --environment staging
```

Use `staging-phase0-checkpoint.json`, not the subsequently evolving intake
manifest, as `--target-intake-manifest` for the forward or rolling release.
Retain the snapshot and every Phase 0 artifact it references under write-once
controls. Continue adding Phase 1–6 items only to the original intake manifest;
never edit, replace, or regenerate the checkpoint for an already executed
release. A newly approved Phase 0 contract requires a new checkpoint and a new
release execution ledger.

Advance through the intermediate phases only after each phase's typed external
material is reviewed and registered. Phase 1 adds the platform evidence index;
Phase 2 adds the real Mail evidence index (the reviewed Mail contract is already
part of Phase 0); Phase 3 adds the card/identity evidence index (the reviewed
PCI and OIDC decisions are already part of Phase 0):

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --through-phase 1

python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --through-phase 2

python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --through-phase 3
```

Before Phase 4 promotion, additionally require the real Sub2 execution and
Vault/egress evidence indexes:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --through-phase 4
```

Before Phase 5 promotion, additionally require the reviewed Windows pilot
input inventory and Windows/business-page evidence index:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --through-phase 5
```

Before Phase 6 promotion, require all seventeen items, including the selected
release execution ledger, pilot roster, pilot execution evidence, and
operations evidence:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json `
  --through-phase 6
```

The final unqualified strict check remains equivalent to the full Phase 6
checkpoint and is required before production sign-off:

```powershell
python scripts/target_intake_preflight.py preflight `
  --input D:\email-platform-evidence\intake\staging-target-intake.json `
  --phase0-checkpoint-manifest D:\email-platform-evidence\intake\staging-phase0-checkpoint.json
```

The final check validates the frozen snapshot as a strict Phase 0 manifest,
requires the current six Phase 0 item records to match it exactly, and requires
the selected release ledger's canonical manifest digest, environment,
requirements digest and checkpoint phase to identify that snapshot. Adding
later evidence is allowed; silently replacing a deployed contract, decision,
approval, inventory, reviewer reference, timestamp, path or digest is not.

Checkpoint success proves only that the items required through that phase have
valid metadata, safely located paths, matching hashes, and explicit review and
redaction assertions. It never proves that a provider contract is correct,
that controls operated successfully, or that a production acceptance criterion
passed. Those claims require the real target execution, independent evidence
review, and the production sign-off workflow.
