# Private-secret crash-evidence provenance

This runbook separates repository template validation from authentication of
real, repository-external evidence. Neither path collects runtime state,
executes a cleanup, invokes kubectl, publishes an artifact, or changes a
release. A successful authentication proves only that the pinned signer
authenticated the exact bytes and identity fields accepted by the verifier.

## Repository-only gate

Run these commands from the repository root:

```text
python scripts/private_secret_github_attestation.py verify-repository
python scripts/private_secret_target_provenance.py verify-repository
python scripts/private_secret_github_rest_collection.py verify-repository
python scripts/private_secret_worm_collection.py verify-repository
python scripts/verify_private_secret_collection.py
```

The checked-in GitHub policy and target policy are intentionally `unconfigured`;
the checked-in envelopes are synthetic and pending. Expected
output therefore retains `origin-authentication=unverified`,
`production_acceptance=false`, and `not_committed_eligible=false`. Repository
success is not evidence that GitHub, a target host, a storage provider, or an
independent reviewer was contacted.

## GitHub offline attestation intake

Obtain the exact T140 crash-evidence JSON, before/after inventories, downloaded
attestation bundle, reviewed Sigstore trusted root, configured trust policy, and
a reviewed absolute `gh` executable outside the repository. Do not preserve a
REST `bundle_url`, authorization header, token, proxy override, raw REST
response, or raw log in the intake envelope.

The caller must independently pin both the raw policy SHA-256 and the `gh`
executable SHA-256. Then run:

```text
python scripts/private_secret_github_attestation.py verify-authenticated --input <absolute-origin-envelope.json> --subject <absolute-t140-crash-evidence.json> --before-inventory <absolute-before.json> --after-inventory <absolute-after.json> --bundle <absolute-bundle.jsonl> --trusted-root <absolute-trusted-root.jsonl> --policy <absolute-configured-policy.json> --gh-executable <absolute-reviewed-gh> --expected-policy-sha256 <64-lowercase-hex> --expected-gh-sha256 <64-lowercase-hex>
```

The authenticated wrapper is Linux-only and fails closed when sealed `memfd`
support is unavailable. It copies the already checked `gh`, subject, bundle and
trusted-root bytes into sealed anonymous descriptors, passes only those held
descriptors to the child, and never asks `gh` to reopen the original paths. The
wrapper uses offline `gh attestation verify` with exact repository,
certificate identity, OIDC issuer, signer/source commit, protected ref,
predicate type, and self-hosted-runner denial. It also post-checks the single
JSON result against immutable owner/repository IDs and workflow run/attempt
bindings. The current attestation does not cryptographically bind the T140
`job_name`, a check-run ID, an artifact database ID, or a separately digested
REST snapshot, so `job-binding=unverified` and `rest-snapshot=unverified` remain
explicit. Freshness, replay protection, durability, and reviewer independence
also remain unverified. `github-origin=verified` authenticates the exact subject
bytes; T140 runtime facts remain a `reviewed-assertion`, and
`target-host=unverified`.

## Target signer and storage receipt intake

The configured policy must contain two distinct Ed25519 public-key anchors:
one for the target crash-origin assertion and one for the storage/WORM provider
receipt. Private keys must remain in independent external custody. The caller
must independently pin the raw policy SHA-256 and the target cluster
fingerprint. Run:

```text
python scripts/private_secret_target_provenance.py verify --input <absolute-target-origin.json> --crash-evidence <absolute-t140-crash-evidence.json> --before-inventory <absolute-before.json> --after-inventory <absolute-after.json> --target-inventory <absolute-target-inventory.json> --release-execution <absolute-release-execution.json> --alert-evidence <absolute-alert-evidence.json> --worm-receipt <absolute-worm-receipt.json> --delete-probe <absolute-delete-probe.json> --custody-evidence <absolute-custody-evidence.json> --expected-policy-sha256 <64-lowercase-hex> --expected-cluster-fingerprint-sha256 <64-lowercase-hex> --verification-time <UTC-timestamp>
```

The two domain-separated signatures bind the exact T140 artifacts, target
inventory, successful release identity, cluster fingerprint, alert artifact,
provider receipt, delete probe, custody artifact, object/version/storage
identity, and ordered time chain. `authenticated-external-signer-assertion`
means the pinned target key signed the closed assertion.
`provider-receipt-authenticated=true` means the distinct pinned storage key
signed the closed provider receipt. These results do not independently prove
that the target commands ran, that object lock or WORM semantics were enforced,
that deletion is impossible, or that custody/reviewer independence exists.
Freshness, replay protection, durability, and reviewer independence remain
explicitly unverified.

## GitHub REST collection handoff

The repository does not collect from GitHub and must not receive a GitHub token.
An independently operated external collector consumes a reviewed, canonical
request and captures only the fixed workflow-run attempt, attempt jobs,
workflow-run artifacts, artifact archive, and repository-attestation endpoint
set. Preserve the bounded raw response and archive bytes outside the repository;
the signed handoff contains only their SHA-256 values and a closed projection.

Configure two distinct Ed25519 trust anchors: one for the collector assertion
and one for the replay-ledger checkpoint. The caller independently pins every
raw input: collection receipt, policy, request, prior head, T141 GitHub-origin
envelope, T143 deployment profile/readiness, downloaded archive and downloaded
attestation bundle. The request binds the deployment/runner profile; the
readiness receipt binds the request and the collection ledger one-hop. Run:

```text
python scripts/private_secret_github_rest_collection.py verify --input <absolute-signed-collection.json> --request <absolute-reviewed-request.json> --previous-head <absolute-caller-accepted-head.json> --policy <absolute-configured-collection-policy.json> --github-origin <absolute-t141-github-origin.json> --deployment-policy <absolute-t143-profile.json> --readiness <absolute-t143-readiness.json> --archive <absolute-downloaded-archive> --bundle <absolute-downloaded-attestation-bundle> --expected-receipt-sha256 <64-lowercase-hex> --expected-policy-sha256 <64-lowercase-hex> --expected-request-sha256 <64-lowercase-hex> --expected-previous-head-sha256 <64-lowercase-hex> --expected-github-origin-sha256 <64-lowercase-hex> --expected-deployment-policy-sha256 <64-lowercase-hex> --expected-readiness-sha256 <64-lowercase-hex> --expected-archive-sha256 <64-lowercase-hex> --expected-bundle-sha256 <64-lowercase-hex> --expected-current-worm-collection-head-sha256 <64-lowercase-hex> --expected-ledger-id <opaque-ledger-id> --expected-sequence <positive-integer>
```

The verifier aligns repository/owner numeric IDs, workflow run/attempt,
commit/ref, unique job ID and check-run URL ID, artifact database ID, archive
digest, T140 subject artifact/payload/attempt, and the attestation bundle digest
already recorded in the caller-pinned T141 origin. The artifact API 302 is
recorded separately from the final archive GET; both final downloads use exact
profile-allowlisted HTTPS origins and hashed URLs, with no Authorization/cookie/proxy credential forwarding and byte-for-byte caller-pinned bodies. Full signed URLs
must not enter envelopes or logs. It validates only a signed
collector projection and one caller-pinned checkpoint link. GitHub's artifact
record identifies its workflow run but does not prove which job uploaded it;
therefore `job-artifact-causality=unverified`. The collector signature is not a
GitHub-native signature, and the stateless verifier cannot advance a global
latest head or authenticate an external clock. Provider-native authentication,
trusted time, freshness, replay protection, durability, and reviewer
independence remain `unverified`.

## Target WORM observation and replay handoff

An external provider observer captures the real storage configuration, object
metadata, denied-delete response, post-denial readback, and time artifact. The
repository verifier never calls a provider API, attempts a deletion, signs a
record, or writes a ledger. Configure distinct provider-observer and ledger
Ed25519 anchors. The caller independently pins both T142 and T141 policy raw
digests, the cluster fingerprint, ledger ID, next sequence, prior head, and
verification time. For sequence 1 use the all-zero SHA-256 prior and omit
`--prior-checkpoint`; later sequences require the exact previously accepted
collection:

```text
python scripts/private_secret_worm_collection.py verify --input <absolute-signed-worm-collection.json> --policy <absolute-configured-worm-policy.json> --target-policy <absolute-configured-t141-target-policy.json> --target-origin <absolute-t141-target-origin.json> --crash-evidence <absolute-t140-crash-evidence.json> --before-inventory <absolute-before.json> --after-inventory <absolute-after.json> --target-inventory <absolute-target-inventory.json> --release-execution <absolute-release-execution.json> --alert-evidence <absolute-alert-evidence.json> --worm-receipt <absolute-t141-worm-receipt.json> --target-delete-probe <absolute-t141-delete-probe.json> --custody-evidence <absolute-custody-evidence.json> --provider-config <absolute-provider-config-snapshot> --object-metadata <absolute-object-metadata-snapshot> --delete-observation <absolute-denied-delete-observation> --readback <absolute-post-denial-readback> --trusted-time <absolute-time-artifact> --expected-collection-sha256 <64-lowercase-hex> --expected-policy-sha256 <64-lowercase-hex> --expected-target-policy-sha256 <64-lowercase-hex> --expected-cluster-fingerprint-sha256 <64-lowercase-hex> --expected-ledger-id <opaque-ledger-id> --expected-sequence <positive-integer> --expected-prior-head-sha256 <64-lowercase-hex> --verification-time <UTC-timestamp> [--prior-checkpoint <absolute-previous-collection.json>]
```

The provider observation must match the storage identity, object reference,
immutable version, and T140 evidence readback digest already authenticated in
the T141 target-origin receipt. The checkpoint independently binds that
observation, the T141 receipt fingerprint, trusted-time artifact digest,
sequence, and prior head. A valid signature authenticates the observer's
assertion; it does not make a generic 403 response proof of object-lock, prove
the time source, prevent a separately signed fork, or establish future
retention. Consequently provider-native authentication, trusted time,
freshness, replay protection, durability, and reviewer independence remain
`unverified`.

## External collector deployment and acceptance transaction

The repository now defines a closed, disabled deployment profile and an
offline acceptance-transaction verifier. The checked-in policy is intentionally
`unconfigured`; it contains no GitHub App identity, provider, workload identity,
time authority, runner digest, sink, latest-head endpoint, or trust anchor. It
does not enable an executor or handoff. Validate that boundary with:

```text
python scripts/verify_private_secret_collector_deployment.py
```

A reviewed external profile must use a GitHub App installation token scoped to
one numeric repository ID, at most one hour, and exactly Actions: read and Attestations: read. The App JWT contract is RS256, issuer equal to the reviewed
client ID, no audience claim, at most ten minutes, and at most sixty seconds of
`iat` backdating. The HTTP contract is an exact method/path allowlist. Artifact
and attestation-bundle downloads use manual allowlisted HTTPS redirect origins;
never forward Authorization across an origin boundary, and do not use proxy or
netrc credential discovery.

The same profile must pin an immutable OCI manifest, collector binary and
entrypoint-contract digests; a selected compliance-mode object-lock/WORM
provider and short-lived workload identity; a create-only external raw-response
sink with immutable version/readback; a reviewed time authority; and a
provider-native compare-and-swap append-only latest-head service. Five distinct
Ed25519 anchors and signature domains authenticate readiness, GitHub execution,
WORM execution, external-time and latest-head assertions. Keys and all configured
profiles remain outside the repository.

After external approval and configuration, invoke the offline intake with three
pairwise-distinct absolute repository-external files and caller-supplied raw
SHA-256 pins:

```text
python scripts/private_secret_collector_deployment.py --policy <absolute-reviewed-profile.json> --readiness <absolute-readiness.json> --execution <absolute-execution.json> --expected-policy-sha256 <64-lowercase-hex> --expected-readiness-sha256 <64-lowercase-hex> --expected-execution-sha256 <64-lowercase-hex> --expected-request-sha256 <64-lowercase-hex> --expected-previous-github-collection-head-sha256 <64-lowercase-hex> --expected-current-worm-collection-head-sha256 <64-lowercase-hex> --expected-github-collection-head-sha256 <64-lowercase-hex> --expected-worm-collection-head-sha256 <64-lowercase-hex> --expected-collection-prior-head-sha256 <64-lowercase-hex> --expected-collection-ledger-id <opaque-ledger-id> --expected-collection-sequence <positive-integer> --expected-prior-head-sha256 <64-lowercase-hex> --expected-ledger-id <opaque-ledger-id> --expected-sequence <positive-integer> --expected-prior-generation <opaque-generation>
```

The verifier authenticates external signers against the caller-pinned profile,
binds both T142 heads and the exact prior head/sequence/generation, rejects role
key reuse, write permissions, mutable image tags, redirected credentials, sink
overwrite, CAS automatic retry and claim overstatement. A successful result
validates only the profile and CAS one-hop binding. Runtime byte execution,
token validity/revocation, permission and egress enforcement, provider-native
behavior, trusted time, sink immutability, durability, reviewer independence,
and fork/rollback protection remain unverified. In particular, global CAS linearizability remains unverified. An
ambiguous CAS response must be reconciled externally; it must not be retried
automatically or reported as success.

For collection-backed acceptance, author one closed external JSON manifest with
exactly `schema_version`, `manifest_kind`, the three T143 paths,
`acceptance_pins`, `github_inputs`, and `worm_inputs`. All paths are absolute and
repository-external; only `prior_checkpoint_path` may be null. Independently
review and pin the manifest's raw bytes, then invoke:

```text
python scripts/private_secret_collection_backed_acceptance.py verify --input-manifest <absolute-external-manifest.json> --expected-input-manifest-sha256 <64-lowercase-hex>
```

The manifest must not contain its own digest, defaults, inherited pins or
verifier results. The coordinator rejects duplicate keys, unknown fields,
wrong pin types, inconsistent repeated pins, path aliases, hardlinks, and duplicate file identities;
it also rejects a manifest path reused as an artifact. `worm_inputs` must
include `expected_runtime_policy_sha256`, independently pinning the raw bytes of
the fixed repository runtime policy. The coordinator stably acquires every
external artifact and that runtime policy once, passes only those exact bytes to
the GitHub and WORM cores, and rechecks file identity plus SHA-256 before return.
It invokes both T142 verifiers itself; do not derive expected heads from the
execution receipt. The execution receipt must bind each
collection receipt SHA, ledger ID, sequence and authenticated head, and its
GitHub raw-response-set digest must equal the fixed-order, domain-separated
digest returned by the GitHub verifier.

The T141 attestation producer is still a separate, externally approved future
step. This change does not add `id-token: write`, `attestations: write`, artifact
metadata write, or any other workflow permission, and it does not contact
GitHub, a cloud provider, the sink, a time service or the latest-head service.

The repository's collection-backed review policy and decision are deliberately
synthetic and pending. Verify that they have not been converted into production
configuration:

```text
python scripts/private_secret_collection_review_decision.py verify-repository
python scripts/verify_private_secret_collection_review.py
```

For an external review, keep both configured files outside the repository. The
policy must pin one Ed25519 reviewer key dedicated to
`email-platform/private-secret-collection-review/v1`; it must not reuse any of
the five T143 anchors, either GitHub collector/ledger key, or either WORM
provider/ledger key. It also pins the raw SHA-256 of the verifier source and the
reviewed release commit/manifest. The policy approval reference and the signed
decision's reviewer reference are distinct opaque references; neither proves a
person's real identity.

The signed decision binds its UUIDv4 decision ID, policy raw SHA-256, T146 input
manifest raw SHA-256, canonical frozen projections for the T143 acceptance and
readiness plus both T142 collection results, release identity, verifier source
raw SHA-256, review time and expiry. Supply every independent pin explicitly:

```text
python scripts/private_secret_collection_review_decision.py verify --decision <absolute-external-review-decision.json> --policy <absolute-external-review-policy.json> --input-manifest <absolute-external-T146-manifest.json> --expected-decision-sha256 <64-lowercase-hex> --expected-policy-sha256 <64-lowercase-hex> --expected-input-manifest-sha256 <64-lowercase-hex> --expected-verifier-source-sha256 <64-lowercase-hex> --expected-release-commit <40-lowercase-hex> --expected-release-manifest-sha256 <64-lowercase-hex> --expected-decision-id <uuidv4> --verification-time <UTC-Z-timestamp>
```

The verifier reads the decision, policy and its own source through stable,
single-link snapshots, asks T146 to acquire and verify the manifest exactly
once, verifies the domain-separated reviewer signature, then rechecks those
three snapshots before return. `--verification-time` is caller supplied and is
only a bounded comparison input; it is not trusted time. This stateless verifier
does not establish global decision-ID uniqueness, replay/CAS linearizability,
forklessness, rollback protection, provider-native behavior, sink immutability
or durability. After success, a separate governed process may create-only
archive the raw policy, decision, pins and referenced evidence in an external
write-once store. This verifier neither performs nor authenticates that archive
handoff, never generates a signature, and never writes a sink, WORM object or
CAS head.

The repository archive policy and receipt are also synthetic and pending. Keep
them fail closed with:

```text
python scripts/private_secret_collection_archive_receipt.py verify-repository
python scripts/verify_private_secret_collection_archive.py
```

A configured archive policy remains repository-external and pins two distinct
Ed25519 trust domains:
`email-platform/private-secret-collection-archive-provider/v1` for the provider
assertion and `email-platform/private-secret-collection-archive-custody/v1` for
the custody checkpoint. Neither key may reuse the T147 reviewer key or any of
the nine T141/T142/T143 keys frozen by T147. The policy fixes one provider kind,
ledger ID, `create_only` write mode, immutable-version requirement,
`compliance` retention mode, both verifier source raw SHA-256 values and the
reviewed release identity. Provider, custody, archive-policy reviewer and T147
reviewer references are distinct opaque references; real identities remain
unverified.

Obtain the raw archive readback, provider-configuration snapshot and retention
snapshot from the governed external process. The verifier treats these as
opaque evidence bytes: signatures bind their exact SHA-256 values, but the
repository does not independently prove their provider origin or semantics.
Independently pin every raw artifact and invoke the offline intake:

```text
python scripts/private_secret_collection_archive_receipt.py verify --receipt <absolute-external-current-receipt.json> --policy <absolute-external-archive-policy.json> --archive-readback <absolute-external-readback> --provider-config <absolute-external-provider-config-snapshot> --retention-snapshot <absolute-external-retention-snapshot> --review-decision <absolute-external-T147-decision.json> --review-policy <absolute-external-T147-policy.json> --input-manifest <absolute-external-T146-manifest.json> --expected-receipt-sha256 <64-lowercase-hex> --expected-policy-sha256 <64-lowercase-hex> --expected-archive-readback-sha256 <64-lowercase-hex> --expected-provider-config-sha256 <64-lowercase-hex> --expected-retention-snapshot-sha256 <64-lowercase-hex> --expected-verifier-source-sha256 <64-lowercase-hex> --expected-prior-receipt-sha256 <64-lowercase-hex> --expected-prior-checkpoint-sha256 <64-lowercase-hex> --expected-review-decision-sha256 <64-lowercase-hex> --expected-review-policy-sha256 <64-lowercase-hex> --expected-input-manifest-sha256 <64-lowercase-hex> --expected-review-verifier-source-sha256 <64-lowercase-hex> --expected-release-commit <40-lowercase-hex> --expected-release-manifest-sha256 <64-lowercase-hex> --expected-decision-id <uuidv4> --expected-receipt-id <uuidv4> --expected-ledger-id <opaque-ledger-id> --expected-sequence <positive-integer> --verification-time <UTC-Z-timestamp>
```

For genesis, omit `--prior-receipt`, set sequence to `1`, and set both prior
SHA-256 pins to 64 zeroes. For the next hop, add
`--prior-receipt <absolute-external-accepted-prior-receipt.json>`, increment the
sequence exactly once, pin that file's raw SHA-256, and pin the prior verified
`head_sha256` printed by the CLI. The current provider signature binds the
decision/policy/manifest/release/verifier identities, exact evidence-byte
digests, create-only object and immutable version references, ledger/sequence,
prior receipt and prior checkpoint. The independent custody signature binds a
checkpoint over that payload digest. A next hop rejects repeated receipt or
decision IDs, repeated readback/object/version, wrong prior policy/ledger,
sequence skips and fork/ABA substitution.

The path wrapper takes stable single-link snapshots of all T148 inputs, invokes
T147 exactly once, verifies both signatures and at most one prior hop, then
rechecks the original snapshots. It never creates or uploads an archive,
generates a signature, performs a denied-delete probe, or advances a replay/CAS
head. Caller-supplied time is not trusted time; provider-native enforcement,
global decision-ID uniqueness, global replay/forklessness, rollback protection,
sink immutability and durability remain unverified.

## Acceptance boundary

Reject any missing signature, trust anchor, caller policy pin, identity/time
binding, stable single-link input, or independent signer. Archive the raw
artifacts, configured policies, their caller pins, trusted root, verifier binary
digest, and reviewer decision in the governed external evidence store. Require
separate human review of provider retention/object-lock configuration and a
real denied-delete observation. No verifier result authorizes the executor or
handoff path, no result opens `not_committed`, and every result remains
`production_acceptance=false`.
