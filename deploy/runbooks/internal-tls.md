# Internal TLS certificate and rotation runbook

Repository verification is preflight only and always has
`production_acceptance=false`. Production acceptance requires target probes and
an independent reviewer.

## Required certificate inventory

The private CA is mounted read-only at
`/run/secrets/internal-tls/ca.crt`. Issue one leaf certificate and one distinct
private key for each of api, web, api-green, web-green, keycloak, worker-mail,
worker-sub2, prometheus and alertmanager. A private key or leaf certificate must not be reused between
services or copied from the public Edge certificate. Each leaf certificate's
Subject Alternative Name must contain exactly the Compose DNS name used by its
clients: `api`, `web`, `keycloak`, `worker-mail`, `worker-sub2`, `prometheus` or
`api-green`, `web-green`, `alertmanager` as applicable.

The stable base path still uses api, web, keycloak as its exact Edge upstream
hostnames; the rolling path adds the two explicit green hostnames.

Certificate and key host paths remain outside Git. They are bind-mounted
read-only with `create_host_path: false`; private keys are readable only by the
service UID. Evidence may contain CA/leaf SHA-256 fingerprints, issuer, serial,
SAN, validity window and verification result, but never a PEM private key.

## Preflight and target probes

Before a target change, run:

```text
python scripts/verify_internal_tls.py
docker compose config
```

From an approved diagnostics environment on the Compose networks, verify the
CA chain and hostname for every request-bearing path:

1. Edge to API, Web and Keycloak on HTTPS 8443.
2. API, mail worker and Sub2 worker to Keycloak JWKS on HTTPS 8443.
3. Prometheus to API 8443, Keycloak management 9000 and worker metrics
   9101/9102.
4. Prometheus to Alertmanager 9093.
5. Prometheus and Alertmanager operator endpoints on HTTPS 9090/9093.

Record the UTC window, source/target service, CA and leaf fingerprints, expected
SAN, negotiated TLS version, HTTP status and trace/request ID where available.
Also prove a wrong CA and a wrong server name are rejected. The API healthcheck
must perform a CA-verified HTTPS request; Keycloak may retain its TCP-only
management-port readiness probe because it sends no HTTP request. Web uses a
local process/config probe and does not create a plaintext HTTP exception.

For the Keycloak JWKS path, `PLATFORM_INTERNAL_CA_FILE` is consumed once from a
bounded stable 256 KiB ASCII PEM snapshot before database initialization. The
runtime creates a hostname-verifying TLS 1.2+ context from the in-memory bytes;
OpenSSL is not allowed to reopen the configured path. A CA rotation therefore
requires an atomic mount update followed by an API, mail-worker and Sub2-worker
restart before repeating the positive, wrong-CA and wrong-server-name probes.

The loopback-only `vault-dev` profile and the public port 80 redirect are local
development/redirect exceptions. If any cross-container path above remains
HTTP, skips verification, lacks its CA or omits hostname validation, the release
must not claim that all internal APIs use HTTPS.

## Leaf certificate rotation

1. Issue a replacement from the current CA with the same exact service SAN and
   a new distinct private key. Validate key/certificate match, validity and CA
   chain outside the container.
2. Atomically replace only that service's external certificate and key files.
   Recreate the affected Compose service or roll the affected Kubernetes Pod as
   required by the mount semantics; do not restart all services together.
3. Repeat the target probe from every client of that service. Confirm wrong-SAN
   and previous-certificate probes fail where applicable.
4. Record start/end UTC, old/new fingerprints, restart or reload result and
   service availability before proceeding to the next leaf.

## Automated leaf-expiry check

From a protected target checkout, run the fixed nine-leaf inventory at least once every 24 hours.
The env file must be an absolute, non-symlink production file containing the
existing `PLATFORM_INTERNAL_CA_FILE`, the seven base `PLATFORM_INTERNAL_*` leaf
pairs, and the two `PLATFORM_ROLLING_GREEN_*` leaf pairs; do not use the repository
`.env.example` placeholders.

The checker reads that inventory once as strict UTF-8 from a bounded stable
regular-file snapshot with a 64 KiB limit. An exact-limit valid inventory is
accepted; an oversized file, link/reparse ancestor, non-regular opened object,
or path/shape replacement during the read fails with the existing redacted
input classification before any certificate path is consumed.

```text
python scripts/check_internal_tls_expiry.py --env-file /absolute/protected/production.env
```

Route the machine-readable result and exit status through the independently
managed external scheduler and notification delivery path:

Before classifying expiry, the checker requires every CA, certificate and key
path to be distinct, parses a one-or-more-certificate CA trust bundle for staged
CA rotation, and verifies each leaf has exactly its service DNS SAN, matches its
private key and is directly signed by exactly one currently valid CA in that
bundle. Any malformed key, wrong SAN, mismatched key, non-CA certificate,
untrusted/self-signed leaf or ambiguous signer is an input failure; no path or
PEM material is emitted.

The checker reads the CA bundle with a 256 KiB limit and each leaf certificate
and private key with a 64 KiB limit. Each parse and reported fingerprint uses
the same bounded stable bytes after regular-file, link/reparse and read-drift
checks. The public Edge pre-deployment check applies the same boundary with a
256 KiB full-chain limit and a 64 KiB private-key limit. Exact-limit valid PEM
remains accepted; one additional byte fails closed.

The two Python preflight checkers additionally require every private-key
snapshot to come from one single-link, owner-only object: `0600` or stricter on
POSIX, or a protected operator/SYSTEM/Administrators DACL on Windows. Permission
identity is checked on the same descriptor before and after reading. This proves
the key used by the checker, not the later object opened by Docker, Nginx,
Keycloak, Uvicorn or OpenSSL. Those consumers reopen configured paths; the
target-host atomic replacement procedure and post-start TLS probes remain the
runtime evidence, and repository checks do not claim same-inode binding after
the preflight returns.

- Exit `0`: every leaf has more than 30 days remaining.
- Exit `1`: alert at the exact 30-, 14- and 7-day thresholds; seven days is an
  alert but not yet a page.
- Exit `2`: page when any leaf is expired or has less than seven days remaining.
- Exit `3`: page because the inventory, path or PEM input failed closed.

Page if no fresh successful invocation is recorded within 24 hours. Retain only
the UTC check time, service name, source env-name, state, validity window,
remaining seconds and SHA-256 certificate fingerprint. Do not retain host
paths, environment contents or PEM data. Also page if a target probe reports an
unexpected issuer, SAN or fingerprint.

The repository verifier and unit tests prove the fixed inventory, CA/SAN/key
binding, parsing, threshold and redaction contract only. Until an independent operator records a
target invocation, scheduler freshness and receiver delivery for the 30-, 14-
and 7-day cases, evidence remains `production_acceptance=false`.

## Runtime object and peer identity boundary

The worker metrics listener is the one in-process TLS consumer for which the
repository can narrow the final OpenSSL load to the already authenticated
objects. On Linux it opens the certificate and private key once, validates the
opened descriptor identity and private-key mode, and calls
`SSLContext.load_cert_chain` through `/proc/self/fd/<n>` while both descriptors
remain open. It rejects a missing procfs descriptor view, a shared cert/key
inode, a group/world-writable key, or identity drift; it has no path-reopen
fallback. The resulting `SSLContext` retains the loaded material until that
worker process is restarted and does not hot-reload a replacement file.

Nginx, Keycloak, Uvicorn, Docker and command-line OpenSSL remain external
consumers: a repository preflight cannot prove which private-key inode they
ultimately opened. Deployment, rollback and rolling-release execution therefore
record only the reviewed leaf SHA-256, the peer DER SHA-256 and negotiated TLS
version obtained from the same CA- and hostname-verified socket that carries the
HTTP smoke request. A mismatch fails closed. These fields prove the observed
leaf certificate identity, not possession or inode identity of its private key.

For Compose single-file bind mounts, atomically replacing a host certificate or
key is not sufficient: force-recreate only the affected service so the new host
inode is bound, then repeat every client probe and record the old/new container
identity and start UTC. Kubernetes TLS files are mounted with `subPath`; Secret
updates likewise require a Pod rollout rather than an in-place hot reload.
Record old/new Pod UID, container ID, process start UTC, reviewed fingerprint,
observed peer fingerprint and TLS version. Do not mark rotation complete until
the new fingerprint is observed and the old fingerprint is no longer served.

The target execution must start from an independently reviewed, closed
projection containing the environment, runtime kind, service, expected replica
count, complete logical observer inventory, and old/new leaf plus old/new SPKI
SHA-256 values. `scripts/tls_rotation_evidence.py` binds that projection with a
canonical rotation-plan digest and accepts only write-once evidence outside the
repository. The old and new leaf values and SPKI values must both differ; SPKI
comparison proves a new public key, not the inode or custody of the private key.

For Compose, capture the full container ID, normalized `StartedAt`, and exact
reviewed read-only TLS bind mounts before and after an explicit
`up -d --no-deps --no-build --pull never --force-recreate <service>`. For
Kubernetes, first require the Deployment generation to be observed with all
desired/updated/ready/available replicas and zero unavailable replicas, capture
every ready Pod UID, primary container ID and running start UTC, then use
`kubectl rollout restart deployment/<service>` and
`kubectl rollout status deployment/<service> --revision=<target-revision>
--timeout=10m`. The target revision must be obtained after restart from the
unchanged Deployment UID and advanced generation, and every Pod controller UID
must resolve through an exact ReplicaSet UID whose controller owner is that
Deployment UID. A ReplicaSet name prefix is never ownership evidence. The final
old and new Pod UID sets and container-ID sets must be disjoint. Pod name,
ReplicaSet name, and connect address remain runtime-only and are deliberately
not recorded.

Probe every before instance directly for the old leaf and every after instance
directly for the new leaf. A Kubernetes per-Pod probe may connect to the Pod IP
in memory while retaining the reviewed service DNS name for SNI, hostname
verification, and the HTTP Host header; the address must not enter evidence.
After instance checks, every required logical observer must make three ordered
same-connection probes through its normal final route and observe the new leaf.
Only then may the record state
`absent_from_final_inventory_and_sampled_routes`. This is a bounded retirement
claim, not proof that the old certificate was globally revoked. One handshake,
one Service-VIP sample, an unchanged container/Pod UID, a missing observer, or
an unobserved Deployment generation keeps the rotation unconfirmed.

Repository fake-runner and mutation tests validate the command, parsing,
redaction, and evidence contracts only. They do not execute Docker or a target
API server and cannot produce an accepted target rotation record;
`production_acceptance=false` remains mandatory here.

The executable entry point accepts exactly four values and no runtime-shaped
overrides:

```text
python scripts/tls_rotation_execute.py --projection /protected/rotation-plan.json --runtime-profile /protected/runtime-profile.json --evidence-output /protected/evidence/new-record.json --confirm-rotation-plan-sha256 <64-lowercase-hex>
```

All three paths must be absolute and outside the repository; the evidence leaf
must not exist. The confirmation value is the canonical plan digest printed by
the independent projection review. There are deliberately no CLI flags for a
service, URL, Pod, address, observer, CA/certificate/key path, kube context, or
command. Unknown, duplicate, positional, and missing inputs return only the
fixed failure message. The current execution evidence schema v5 additionally binds the canonical
SHA-256 of the complete runtime profile, so changing any reviewed image,
observer identity, runtime target, or blocked-observer declaration invalidates
the plan confirmation.

Create a closed locator-only capture request at a repository-external path,
capture current runtime metadata through the read-only collector, then review
the sealed capture offline before creating the projection. The capture command
allows only Compose config/ps plus fixed Docker inspect fields, or Kubernetes
GET metadata; it rejects mutation verbs, exec/probe commands and Secret reads.
The review command never starts a child process and requires an explicit match
for the sealed live-capture digest:

```powershell
python scripts/tls_rotation_profile_capture.py capture `
  --request D:\protected\runtime-profile-capture-request.json `
  --capture-output D:\protected\runtime-profile-live-capture.json
python scripts/tls_rotation_profile_capture.py verify `
  --request D:\protected\runtime-profile-capture-request.json `
  --capture D:\protected\runtime-profile-live-capture.json
python scripts/tls_rotation_profile.py review `
  --request D:\protected\runtime-profile-capture-request.json `
  --capture D:\protected\runtime-profile-live-capture.json `
  --confirm-live-capture-sha256 <capture-payload-sha256> `
  --profile-output D:\protected\runtime-profile.json
python scripts/tls_rotation_profile.py verify --runtime-kind compose `
  --profile D:\protected\runtime-profile.json
```

Every path above must be absolute and outside the repository, each output leaf
must not exist, and the request uses a closed schema. Compose requests contain
only environment and fixed service selection. Kubernetes requests additionally
contain the kubeconfig/context and direct/route observer namespace, Deployment
and container locators; live UIDs, revisions, Pod names and image identities are
collector output, not author input. The capture publishes only bounded identity
projections and SHA-256 values: it excludes raw runtime JSON, kubeconfig bytes,
Secret values, IP addresses and NetworkIDs. A stable double read is mandatory.

For Kubernetes capture and execution, provision a dedicated kubeconfig with
exactly one cluster, one user, one context, and the requested current context.
It must be an absolute repository-external regular file with one link, stable
identity and a stable permission fingerprint. On POSIX it must have no
group/world permissions and no owner write bit; use mode `0400` rather than a
typical writable `0600` `$HOME/.kube/config`. On Windows it must have a
protected DACL limited to the current identity, SYSTEM and Administrators and
must carry the read-only file attribute. Both capture snapshots and backend
preflight parse and validate the same bounded source bytes before any runtime
command.

The dedicated file must be self-contained. It requires an HTTPS server and an
inline CA certificate (`certificate-authority-data`). Authentication is either
a printable 32-byte-or-longer inline bearer token or matching inline client
certificate/key data. File references (`certificate-authority`,
`client-certificate`, `client-key`, `tokenFile`), `exec`, `auth-provider`, basic
authentication, impersonation, proxy URLs, insecure TLS, extensions, YAML
anchors/aliases/tags, duplicate keys and unknown fields are rejected. Common
EKS, GKE and AKS kubeconfigs that rely on an exec credential plugin therefore
cannot be used directly; an operator must provision a short-lived,
least-privilege, inline-only credential under the controls above. Never commit
that file or include its bytes in an artifact.

After validating the source bytes, capture and backend preflight copy that exact
snapshot into one fresh private materialization. Every kubectl argv is bound to
that materialized path; the operator source path never enters a child command.
Capture verifies the materialized identity before, between and after its two
snapshots, then re-reads the operator source to detect source drift. The backend
keeps the same materialization through preflight, action, reconciliation,
containment and the evidence publication attempt. Its idempotent close runs
inside the release lock after those operations on every catchable control-flow
path. A backend cannot be used after close.

On POSIX, the materializer creates a random `0700` directory below an
owner-private temp root or the root-owned sticky `/tmp` model. It uses
dirfd-relative `O_EXCL|O_NOFOLLOW|O_CLOEXEC` creation, writes and fsyncs a
`0600` file, changes it to `0400`, then verifies owner, link count, fd/path
identity and SHA-256. Cleanup only unlinks the claimed identity and never uses
recursive deletion. On Windows, both directory and file receive their final
protected DACL during `CreateDirectoryW`/`CreateFileW(CREATE_NEW)` via a
non-inheritable `SECURITY_ATTRIBUTES`; only the current identity, SYSTEM and
Administrators are allowed. The local volume must support persistent ACLs and
must not be remote. Data is flushed before READONLY is set through the same
handle; directory/file ACL, FileId, non-reparse shape, single link, read-only
attribute and SHA-256 are rechecked. Keeper handles omit delete sharing until
cleanup.

This binds all commands to one protected pathname and prevents replacement by
unapproved principals during its lifetime; kubectl still opens a pathname and
does not consume Python's open handle. Do not claim resistance to the current
identity, root, SYSTEM or Administrators, secure erasure, or automatic cleanup
after `SIGKILL`, `TerminateProcess` or host loss. Such a crash can leave a
random `0700`/protected-DACL directory containing a `0400`/READONLY file. Treat
that strict-ACL residue as an incident requiring identity-checked cleanup; do
not glob, recursively delete, or infer ownership from the name alone. Temporary
paths and bytes must never enter the profile, evidence or logs.

Crash-residue handling now uses one dedicated, repository-external protected
runtime root. Set `EMAIL_PLATFORM_PRIVATE_SECRET_RUNTIME_ROOT` to the reviewed
absolute root on the execution host, or use the platform-specific protected
default below the system temporary base. The materializer creates the root with
mode `0700` on POSIX or the final protected Windows DACL and refuses an existing
root whose canonical identity, owner, mode, ACL, local-volume or reparse
contract is invalid. A general-purpose temporary directory is not scanned as a
residue root. Each materialization creates one strict 32-lowercase-hex claim
directory containing exactly `secret`, `claim.json` and `lease`. The canonical,
integrity-sealed claim binds the claim ID, runtime-root/directory/secret/lease
identity, reviewed payload SHA-256 and size. It is an integrity record, not a
signature or protection from the current identity. The lease is held for the
whole live materialization by POSIX `flock` or a Windows no-share handle. The
claim contains no secret bytes, source path, materialized path, URL, IP address,
credential or PID. Legacy `email-platform-secret-*` directories outside this
root remain unowned `unknown` incidents and are never scanned or deleted.

The independent inventory and cleanup tool implements exactly this two-step
operator sequence:

```text
python scripts/private_secret_residue.py inventory --output <new-write-once-inventory.json>
python scripts/private_secret_residue.py cleanup --inventory <reviewed-inventory.json> --expected-payload-sha256 <64-lowercase-hex> --claim-id <opaque-claim-id> --confirm-residue-cleanup
```

Inventory runs while holding the same release-control lock used by rotation and
publishes a new external write-once artifact followed by stable readback. It
classifies every entry as exactly one of `active`, `cleanup_candidate` or
`unknown`. `active` requires a valid sealed claim whose lease is still held.
`cleanup_candidate` requires an exclusively acquirable lease plus a valid sealed
claim whose runtime root, directory, three-entry set, owner, type, link count,
POSIX mode or Windows ACL/FileId, size and payload SHA-256 all still match.
Missing or invalid claims, identity or hash drift, unexpected members and read
instability are `unknown`. The redacted inventory contains only opaque claim
IDs, fixed states/reasons and confirmation digests; it contains no root or
secret path, source digest or secret bytes. Age, directory name and PID are
never ownership or cleanup signals.

Cleanup requires a human approval for exactly one reviewed `cleanup_candidate` claim.
The approval, inventory canonical payload SHA-256 and claim ID must all name
that same claim. Under the release-control lock, cleanup must reopen the pinned
runtime root without following links or reparse points and revalidate the
sealed claim, lease state, root/directory/leaf identity, owner, type, link
count, POSIX mode or Windows ACL/FileId, and payload SHA-256 immediately before
unlinking the exact leaf and removing its exact empty directory. Any `active`,
`unknown`, mismatch, extra member or cleanup uncertainty fails closed and
returns exit `1` with the fixed redacted stderr line
`private secret residue operation failed`. The target-host scheduler or
monitor must convert that nonzero result into an operator alert and retain the
reviewed inventory artifact; this repository does not prove that such an alert
route is installed. The tool must not use glob,
`rglob`, `shutil.rmtree`, `--all`, `--force`, age thresholds or PID-liveness
heuristics, and it must never retry or broaden a one-claim approval.

Successful unlink only confirms removal of the reviewed directory entry. It is
not secure erasure and must not be reported as secure erasure, sanitization or
recovery from `SIGKILL`, `TerminateProcess` or host loss.

The CI and tag-release workflows are configured to execute the POSIX
materializer/residue and fake-runner Kubernetes boundary suites on GitHub
`ubuntu-24.04`; repository configuration and local Windows tests do not prove
that a remote run has occurred. A successful GitHub run proves only the
exercised runner filesystem behavior and fake-runner exact-argv contract for
that commit. It does not prove real kubectl execution, target-host runtime-root
ACL or mount behavior, uncatchable-crash residue discovery, cleanup on a target
host, or production acceptance. Real target-host kubectl and crash evidence
remain pending and separately reviewed; `production_acceptance=false`.

T140 adds a metadata-only, repository-external intake for the two evidence
scopes that must never substitute for one another: `github_actions_linux_ci`
and `kubernetes_target_host`. Start from
`deploy/evidence-index-envelopes/private-secret-crash.synthetic.json`, but keep
the completed reviewed envelope and both residue inventories outside the
repository. The verifier has no collection, kubectl, cleanup, materialization,
generate or create path. It only performs a stable, bounded, duplicate-key-free
read of caller-selected artifacts, checks the closed POSIX runtime-root policy,
and derives the exact state transition from one `cleanup_candidate` in the
before inventory to that claim being absent in the after inventory while every
unrelated record remains unchanged. Any `active`, `unknown`, duplicate,
non-canonical record, sibling drift, nonzero or uncertain cleanup result fails
closed. Absence after cleanup proves only that the reviewed directory entry was
not present in that snapshot; it does not prove why it disappeared, secure
erasure or durable recovery.

For a reviewed GitHub Linux assertion, pin the expected 40-hex commit and the
SHA-256 of the exact workflow blob supplied by the external reviewer:

```text
python scripts/private_secret_crash_evidence.py verify --input <external-reviewed-envelope.json> --before-inventory <external-before-inventory.json> --after-inventory <external-after-inventory.json> --expected-runtime-policy-sha256 <repository-policy-sha256> --expected-commit <40-lowercase-hex> --expected-workflow-sha256 <64-lowercase-hex>
```

For a target-host assertion, supply a reviewed, non-synthetic target platform
inventory whose environment, opaque inventory reference and exact artifact
SHA-256 match the envelope:

```text
python scripts/private_secret_crash_evidence.py verify --input <external-reviewed-envelope.json> --before-inventory <external-before-inventory.json> --after-inventory <external-after-inventory.json> --expected-runtime-policy-sha256 <repository-policy-sha256> --target-inventory <external-reviewed-target-platform-inventory.json>
```

The Linux scope cannot contain or satisfy target-host inventory or alert facts.
The target scope cannot use a CI or fake-runner record as kubectl, crash,
filesystem or alert-delivery evidence. Alert delivery remains a reviewed opaque
reference plus digest; the offline verifier does not inspect the receiver or
authenticate the receipt. Operator, cleanup approver and reviewer references
must be distinct, but distinct strings do not prove IAM separation. Likewise,
commit, run, workflow, runner and target-host fields remain external assertions
unless a future trusted GitHub attestation or target-platform signature and
WORM/no-delete receipt are independently verified. A successful command is
therefore only `status=reviewed-assertion origin-authentication=unverified
production_acceptance=false`; it is not proof that a GitHub run, real kubectl,
uncatchable crash, ACL/mount check, cleanup or alert delivery occurred.

The Compose profile is a closed repository-external JSON object. It selects one
of the nine fixed internal leaves, the fixed base or rolling Compose file set,
the production env-file digest, target/direct/route digest-pinned images, the complete real
observer inventory, and any observer whose image lacks the reviewed Python
same-connection probe runtime. The backend uses the exact project directory,
env file, project name, and Compose file order; resolves the target and direct
probe executor images; reads container ID, running state, start time, mount JSON,
configured image, and the endpoint on one fixed reviewed network from Docker;
and verifies the three reviewed read-only TLS mounts. Target address and
NetworkID stay in memory and never enter evidence. A direct probe resolves one
exact running executor container, verifies its reviewed digest image and the
same NetworkID, uses `docker exec -i <exact-id>`, and brackets the handshake with
exact target and executor identity reads. It never falls back to service DNS. A
blocked observer or either standalone green service fails before a child runner
is constructed. A future unblocked profile must also prove every real route can
observe the old leaf before mutation through its own exact reviewed container
ID, image and target NetworkID binding. The only action is a force recreate of
the selected service; containment stops only that service and confirms it is
absent.

The Kubernetes profile is likewise closed and repository-external. It pins the
kubeconfig path and digest, context, namespace UID, Deployment UID, desired
replica count, digest-pinned workload image, exact TLS Secret name implied by
the selected service, one separately identified direct-probe Pod, and every
named real-client observer Pod by namespace/Deployment/ReplicaSet/Pod UID,
revision, container, and runtime image identity. The direct probe is not counted
as a real route observer. Both direct and route probe runtimes must successfully
observe the old leaf during preflight; a diagnostics Pod can therefore support
per-instance verification but can never stand in for `edge` or `prometheus`.
Every kubectl call carries the fixed kubeconfig, context, request timeout, and
explicit namespace. The backend reads only the certificate member of the TLS
Secret, never its private key.

After `rollout restart`, Kubernetes reads the actual unchanged Deployment UID,
advanced generation, newly discovered revision, and changed restart annotation
before waiting on that exact revision. Each listed Pod is then read again by
exact name and must follow a unique Pod UID → ReplicaSet UID → Deployment UID
owner chain. The replacement generation must use one exact ReplicaSet UID, and
the old Pod UIDs must be absent from a namespace-wide final inventory. Every
direct and real-route probe is bracketed by exact observer/target Pod reads, and
the two final inventories compare runtime-only Pod name/IP, ReplicaSet UID, and
image identity as well as publishable UID/container/start fields. Containment
reads the exact Deployment UID, pauses only that Deployment, then rereads the
same UID with `spec.paused=true`.

The child-process runner freezes a small base-environment allowlist and rejects
Docker, Compose, kubeconfig, proxy, TLS override, credential, and Python-path
variables by presence, including empty values. It always uses argv execution
with `shell=False`, silent stderr, strict UTF-8, bounded stdout/stdin, and a
fixed timeout. Probe URL, CA path, expected response policy, and transient Pod
connect address travel only through bounded child stdin and never through child
argv, error text, or evidence.

`scripts/tls_rotation_executor.py` is the single ordering coordinator. It
requires an absolute repository-external reviewed projection and an unused
absolute repository-external evidence path before it constructs a backend. It
then holds the same host advisory release-control lock used by deploy, rollback,
and rolling release while it performs preflight, captures/probes the old
generation, records the action request, performs exactly one backend action,
captures/probes the replacement, samples each route three times, and captures
the final generation twice. Only an exact match with the probed generation can
publish `completed`; the published write-once record is read back and verified
before success is returned.

Catchable failures after safe projection/output preflight publish one of the
closed `preflight_failed`, `action_failed`, `generation_unconfirmed`,
`peer_verification_failed`, or `containment_unconfirmed` records. After a
mutation, Compose containment stops only the affected service; Kubernetes
containment runs only `rollout pause` for the affected Deployment. A Kubernetes
pause merely freezes further rollout reconciliation: it does not restore the
old certificate, isolate traffic, or prove the current Pods safe. Every
post-mutation failure therefore needs manual review; the executor never runs
rollout undo, restores a Secret, rotates a CA, or restarts unrelated services.
Invalid input, an unsafe/existing sink, publication races/failure, SIGKILL,
power loss, or host loss cannot be guaranteed an entry in a single final
write-once file. The shared lock is also a cooperating-process lock on the
designated execution host, not a distributed Kubernetes Lease.

The current repository coordinator consumes a reviewed runtime backend rather
than accepting arbitrary command, URL, address, certificate, key, or Secret
arguments. Public edge rotation and observer images without the reviewed probe
runtime remain outside this internal-leaf path; do not substitute a diagnostics
Pod observation for a named real client. Run
`python scripts/verify_tls_rotation_executor.py` before any target exercise.

### Indeterminate action return and independent handoff

The execution evidence schema is version 5. The action records one of
`not_requested`, `confirmed`, or `unknown`. If the one allowed Compose recreate
or Kubernetes restart call raises, the coordinator never retries it. Before
containment it asks the selected backend for one read-only reconciliation:

- `verified_old` requires a stable inventory identical to the captured old
  generation and an old-leaf direct observation for every instance;
- `verified_new` requires a stable, fully disjoint replacement generation and a
  new-leaf direct observation for every instance; Kubernetes additionally binds
  the unchanged Namespace/Deployment UIDs, advanced generation/revision,
  unique ReplicaSet ownership, and namespace-wide absence of old Pod UIDs;
- any partial rollout, drift, unreachable read/probe, ambiguous owner chain, or
  inconsistent second inventory is `unknown`. An unknown record carries one
  closed `reason_code`; mixed ReplicaSets, terminating/unready Pods, replica
  count mismatch, an unobserved Deployment, peer failure, and unstable inventory
  are distinguishable without publishing Pod names or addresses. Successful
  `verified_old`/`verified_new` records carry no reason code.

All three results remain terminal `action_failed` and still use the existing
service-stop or Deployment-pause containment. They are bounded observations,
not proof that the action did or did not cause the observed state, and never
authorize a second mutation. The reconciliation record contains only instance
identities/start times and the reviewed old/new leaf observation; it does not
claim old-fingerprint retirement or production acceptance.

Do not infer runtime state from the process exit code or author a state by hand.
When the sealed execution artifact is available, derive a separate, closed,
repository-external support artifact from it. The tool revalidates schema-v5,
integrity, plan/profile binding, instance inventory and peer observations; it
alone derives `verified_old`, `verified_new`, or a closed `unknown` reason:

```powershell
python scripts/tls_rotation_support.py generate `
  --projection D:\protected\rotation-projection.json `
  --execution-evidence D:\protected\rotation-execution.json `
  --support-output D:\protected\rotation-support.json `
  --assessor-reference incident-assessor-123 `
  --confirm-rotation-plan-sha256 <reviewed-plan-sha256>
python scripts/tls_rotation_assessment.py generate `
  --projection D:\protected\rotation-projection.json `
  --runtime-profile D:\protected\runtime-profile.json `
  --execution-evidence D:\protected\rotation-execution.json `
  --supporting-evidence D:\protected\rotation-support.json `
  --assessment-output D:\protected\rotation-assessment.json `
  --reviewer-reference incident-reviewer-456 `
  --confirm-rotation-plan-sha256 <reviewed-plan-sha256>
python scripts/tls_rotation_assessment.py verify `
  --projection D:\protected\rotation-projection.json `
  --runtime-profile D:\protected\runtime-profile.json `
  --execution-evidence D:\protected\rotation-execution.json `
  --supporting-evidence D:\protected\rotation-support.json `
  --assessment D:\protected\rotation-assessment.json `
  --confirm-rotation-plan-sha256 <reviewed-plan-sha256>
```

The assessor and reviewer references must be distinct opaque references. This
proves two different references were supplied, not two cryptographically
authenticated people; enforce real identity separation in the external access
and approval system. Review must occur within 15 minutes of the final runtime
observation. While all inputs remain read-only, publish a distinct handoff
record to a new write-once path within a further 15 minutes:

```powershell
python scripts/tls_rotation_handoff.py `
  --projection D:\protected\rotation-projection.json `
  --execution-evidence D:\protected\rotation-execution.json `
  --runtime-profile D:\protected\runtime-profile.json `
  --supporting-evidence D:\protected\rotation-support.json `
  --assessment-input D:\protected\rotation-assessment.json `
  --handoff-output D:\protected\rotation-handoff.json `
  --confirm-rotation-plan-sha256 <reviewed-plan-sha256>
```

The handoff re-opens the actual profile, execution, support and assessment and
repeats digest, derivation, distinct-reference and freshness checks before two
identity-bound stable reads can report the execution sink as `committed`.
Missing or invalid required review artifacts fail closed without publishing a
handoff. It cannot report `not_committed`: a normal pre-link JSON receipt plus
an absent sink cannot distinguish "never linked" from "linked then lost or
deleted". Enabling that state requires an authenticated, durable
`link_not_attempted` outcome or a verified WORM/no-delete journal, stable parent
directory identity and platform durability evidence. Sink observation and the
independently derived runtime assessment remain separate axes; every handoff has
`manual_review_required=true`, and all records retain
`production_acceptance=false`. Run
`python scripts/verify_tls_rotation_handoff.py` and
`python scripts/verify_tls_rotation_artifacts.py` before using this channel.

`scripts/tls_rotation_attempt_receipt.py` now provides only a pure verifier for
one pinned-key Ed25519 `ready_before_link` assertion. The trust anchor is passed
by reviewed caller configuration and its key ID is derived from the pinned
public key; the receipt cannot nominate its own trusted key. The signature binds
the canonical UUIDv4 attempt, plan/profile/evidence payload and artifact
digests, microsecond UTC readiness time, and external associated data containing
the normalized absolute evidence-sink path. The module does not load a private
key, sign, publish, read the sink, acquire the release lock, call a backend, or
integrate with the executor/handoff. The release-governed
`deploy/tls-rotation-attempt-publisher-policy.json` is only a prerequisite
declaration. Its current trust anchor is `unconfigured` with null key fields,
`publisher_integration_enabled=false`, and
`not_committed_eligible=false`. It requires a dedicated external signing key,
independent custody/review evidence, forbids repository/CLI/environment private
key transport, and fixes the future ready-before-link step order and one link
attempt. The pure validator can verify a future canonical raw-32 Ed25519 public
key pin and its derived key ID, but a pin alone does not enable integration.

Its crash matrix is deliberately one-sided: before a receipt, after readiness
but before link, during link, and after link but before stable readback are all
`unknown`; only verified stable sink readback is `committed`. A valid receipt
therefore proves only that the pinned-key holder asserted readiness before link.
Receipt absence never opens `not_committed`. The publisher policy deliberately
records ordering as `not_implemented` and durability as `unverified`; its WORM
or object-lock, deny-delete, retention, stable storage identity, committed
readback, crash-recovery and independent-evidence entries are requirements, not
proof that those controls exist. No ordering or durability claim is available
until a future publisher integration and protected storage contract are
independently implemented and verified.

## CA rotation

CA rotation is staged and is not a single-file replacement:

1. Publish a dual-CA trust bundle containing the old and new CA certificates.
   Roll it through every client and prove both chains validate.
2. Issue nine new leaf certificates with new distinct keys from the new CA.
   Rotate and probe one service at a time using the leaf procedure above.
3. After every client trusts the new leaves, remove the old CA from the trust
   bundle, roll clients again and prove old-CA leaves are rejected.

Record the trust-bundle fingerprints, all nine leaf fingerprints, failure
tests, availability result and independent reviewer in
`deploy/production-signoff-template.md`. Local mocks and static checks do not
prove that rotation or target hostname validation occurred.
