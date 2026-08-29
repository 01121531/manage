# Kubernetes portability baseline

This directory is the reviewed future split path described in Chapter 2. It
does not replace the current single-host Compose release and is not production
acceptance evidence.

The base deploys only platform-owned workloads:

- one release-bound Alembic migration Job;
- independently scalable API, Mail Worker, and Sub2 Worker Deployments;
- a separately scalable static Web Deployment;
- ClusterIP services for API and Web;
- HPAs, PodDisruptionBudgets, topology spreading, and default-deny network
  policy.

PostgreSQL, Redis, Keycloak, Vault, the ingress controller, monitoring, and the
external secret manager remain cluster-provided or managed dependencies. This
keeps database durability, identity administration, key custody, and public
TLS outside application manifests.

## Fail-closed template boundary

Do not apply `base/` directly. Its image digests are all-zero placeholders and
its public/provider hosts use `.example.invalid`. A release overlay must:

Before building that overlay, run the strict Phase 0 checkpoint described in
`deploy/runbooks/target-intake-preflight.md`:

```powershell
python scripts/verify_kubernetes_portability.py `
  --target-intake-manifest D:\email-platform-evidence\intake\staging-target-intake.json `
  --target-environment staging
```

This handoff command runs the repository portability checks and the same strict
`--through-phase 0` intake checkpoint before any overlay mutation.

The reviewed manifest must provide `mail_contract`, `sub2_contract`,
`card_pci_boundary`, `oidc_deployment_identity`,
`phase0_boundary_approval`, and `target_platform_inventory`. Later Phase 4/6
execution evidence is intentionally not required before the target exists;
those checkpoints remain mandatory before their respective promotions.
Synthetic repository envelopes and `--allow-incomplete` output cannot
authorize a target deployment.

1. replace API and Web images with reviewed OCI `@sha256:<64 hex>` identities;
2. replace release tag, 40-character commit, migration head, allowed origins,
   OIDC URLs, Vault address, and real Mail/Sub2 origins;
3. give the migration Job a release-unique name and wait for its successful
   completion before promoting traffic;
4. provision only the names and keys in `secret-contract.json` through an
   approved external-secret operator or CSI driver;
5. label the ingress and monitoring namespaces with
   `email-platform.io/ingress=true` and
   `email-platform.io/monitoring=true` respectively;
6. narrow each port-only egress rule to reviewed CIDRs, gateway identities, or
   CNI FQDN policies for the target environment;
7. configure the ingress controller to verify API/Web backend TLS against
   `platform-internal-ca`; TLS passthrough or disabled backend verification is
   not accepted.

No Kubernetes `Secret` object or secret value belongs in this repository.
File-backed database URLs and Vault tokens preserve the existing runtime
secret boundary. Each workload has a distinct ServiceAccount and distinct
runtime/TLS secret identity.

## Deployment order

1. Render the target overlay and run
   `python scripts/verify_kubernetes_portability.py` plus server-side dry-run
   validation against the target Kubernetes version.
2. Provision namespace labels, external dependencies, NetworkPolicy/CNI
   enforcement, and the external secrets from the reviewed release intake.
3. Create the release-unique migration Job and wait for `Complete=True`.
4. Apply API and Worker Deployments. Their `schema-current` init containers
   refuse to start against an older, newer-incompatible, or branched schema.
5. Apply Web and the independently reviewed ingress configuration.
6. Verify `/releasez`, `/readyz`, Worker heartbeats/metrics, cross-namespace
   denials, provider egress, alert delivery, and N/N+1 traffic before promotion.

Repository validation proves only manifest structure and drift resistance. A
real cluster dry run, admission policy, CNI behavior, scheduler spreading,
autoscaling, storage/provider connectivity, TLS, migration timing, rollback,
and alert evidence are still required. Therefore every repository result
remains `production_acceptance=false`.

## TLS Secret rotation boundary

The four Deployments pin their internal CA and leaf material as individual
read-only `subPath` mounts. The verifier locks the Secret volume name,
`secretName`, `defaultMode: 288`, exact key-to-path mapping, mount path,
`subPath`, `readOnly: true`, and the reviewed RollingUpdate availability values
(`0/1` unavailable/surge for API and Web, `1/1` for both Workers). Removing a
mount, making it writable, changing only an item path, making a Secret optional,
or weakening the rollout strategy fails repository validation.

A Secret update alone does not refresh these mounted files. Target operators
must follow `deploy/runbooks/internal-tls.md`: collect all old Pod UIDs,
container IDs and start UTCs, restart and wait for the Deployment rollout,
require an entirely disjoint final ready generation, directly probe every new
Pod with service-DNS SNI/Host verification, and sample every required client
route three times. Pod names and a single Service-VIP handshake are insufficient
and are not accepted as rotation evidence.
