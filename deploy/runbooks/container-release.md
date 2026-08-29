# Verified container tag publication

The release workflow treats `sha-${GITHUB_SHA}` as a staging reference, not a
deployable release tag. The three application images follow this order:

1. Build the candidate locally, generate the SPDX SBOM and pass the Trivy
   HIGH/CRITICAL gate.
2. `Push scanned staging digest`; do not push `${GITHUB_REF_NAME}` here.
3. Keyless-sign the exact digest, attach the SPDX attestation and GitHub build
   provenance, then verify the expected workflow identity and OIDC issuer.
4. `Publish verified release tag` only after verification. The registry push
   response digest must equal the already verified digest. Runs for the same
   Git ref are serialized without cancellation; promotion refuses to overwrite
   an existing version tag that resolves to a different or ambiguous digest,
   and registry inspection errors fail closed.
5. Record and upload the digest-bound metadata, SBOM and scan evidence before
   Windows/GitHub Release publication can proceed.

The workflow's non-authoritative GitHub annotation helper reads each Trivy
SARIF once through a stable regular-file handle with a 32 MiB limit and rejects
link/reparse paths, duplicate JSON keys and read-time file-shape drift. An
ambiguous report produces only the fixed redacted summary warning; it cannot
convert the authoritative Trivy step into success or disclose report content.

If signing, attestation, provenance or verification fails, the stable version
tag must not exist. A `sha-${GITHUB_SHA}` staging reference left by a failed job
is not approved for deployment; consumers must use the signed digest from the
release manifest, never infer trust from a tag.

Run the repository preflight with:

```powershell
python scripts/verify_container_supply_chain.py
python scripts/verify_release_workflow.py
```

Static workflow validation has `production_acceptance=false`. Production
signoff must record the GHCR version tag, resolved OCI digest, Cosign identity,
OIDC issuer, SPDX attestation and provenance, and prove all match the published
container release manifest.
