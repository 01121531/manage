"""Deterministic synthetic fixture for the T205 runtime-attestation protocol."""

from __future__ import annotations

import hashlib

from scripts.target_intake_runtime_attestation_intake import (
    GITHUB_PROFILE,
    INTOTO_STATEMENT_TYPE,
    RECORD_TYPE,
    SIGSTORE_MEDIA_TYPE,
    SIGSTORE_PROFILE,
    SLSA_PREDICATE_TYPE,
    _artifact_bytes,
    _canonical_digest,
    _evidence_imprint,
    _provider_entry_digest,
)


POLICY_SHA256 = "b56cd792f52b5b5984f69ea8b562e2e07068049e342e04b76eeb97d0333991b0"
PROFILE_PAYLOAD_SHA256 = "4756d65165e83297270f0eda3193aa136475bbfa20ad59ee4faa9412ed6ef216"


def _h(label: str) -> str:
    return hashlib.sha256(("runtime-attestation-fixture:" + label).encode()).hexdigest()


def build_fixture() -> dict[str, object]:
    artifact_digest = "sha256:" + _h("runtime-artifact")
    immutable_reference = "ghcr.io/01121531/email-api@" + artifact_digest
    runtime_subject = {
        "cas_request_id": "runtime-cas-fixture-00000001",
        "deploy_selected_digest": artifact_digest,
        "execution_profile_sha256": _h("execution-profile"),
        "expected_prior_provider_head": _h("prior-provider-head"),
        "generation_sequence": 8,
        "proposed_provider_sequence": 9,
        "provenance_subject_digest": artifact_digest,
        "replay_runtime_sha256": _h("replay-runtime"),
        "runtime_artifact_digest": artifact_digest,
        "runtime_artifact_immutable_reference": immutable_reference,
        "runtime_artifact_kind": "oci_container_image",
        "target_loaded_evidence_sha256": _h("target-loaded-evidence"),
        "target_observed_digest": artifact_digest,
        "target_process_identity_sha256": _h("target-process-identity"),
        "terminal_manifest_file_sha256": _h("terminal-manifest-file"),
        "terminal_manifest_payload_sha256": _h("terminal-manifest-payload"),
        "terminal_receipt_file_sha256": _h("terminal-receipt-file"),
        "terminal_receipt_payload_sha256": _h("terminal-receipt-payload"),
        "validation_context_sha256": _h("validation-context"),
        "validator_contract_sha256": _h("validator-contract"),
    }
    subject_sha256 = _canonical_digest(runtime_subject)

    sigstore = {
        "artifact_digest": artifact_digest,
        "certificate_der_sha256": _h("publisher-certificate"),
        "certificate_identity": "https://github.com/01121531/manage/.github/workflows/release.yml@refs/tags/v0.0.0-fixture",
        "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        "checkpoint_sha256": _h("rekor-checkpoint"),
        "content_kind": "messageSignature",
        "inclusion_promise_sha256": _h("rekor-set"),
        "inclusion_proof_sha256": _h("rekor-inclusion-proof"),
        "media_type": SIGSTORE_MEDIA_TYPE,
        "offline_verifier_sha256": _h("cosign-executable"),
        "profile": SIGSTORE_PROFILE,
        "raw_bundle_sha256": _h("cosign-raw-bundle"),
        "rfc3161_timestamp_sha256": _h("cosign-rfc3161"),
        "tlog_entry_sha256": _h("rekor-entry"),
        "tlog_log_id": "rekor-fixture-log",
        "trusted_root_sha256": _h("sigstore-trusted-root"),
        "verification_state": "synthetic_fixture_unverified",
    }
    sigstore_sha256 = _canonical_digest(sigstore)

    source_commit = hashlib.sha1(b"runtime-attestation-fixture-source").hexdigest()
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "ref": "refs/tags/v0.0.0-fixture",
                    "repository": "https://github.com/01121531/manage",
                    "workflow": ".github/workflows/release.yml",
                },
                "internalParameters": {
                    "github_event_name": "push",
                    "hermetic_build_claim": False,
                },
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": source_commit},
                        "uri": "git+https://github.com/01121531/manage@refs/tags/v0.0.0-fixture",
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/actions/runner/github-hosted"},
                "metadata": {
                    "finishedOn": "2026-01-02T03:05:00Z",
                    "invocationId": "https://github.com/01121531/manage/actions/runs/20500000001/attempts/1",
                    "startedOn": "2026-01-02T03:04:00Z",
                },
            },
        },
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [
            {
                "digest": {"sha256": artifact_digest.split(":", 1)[1]},
                "name": immutable_reference.split("@", 1)[0],
            }
        ],
    }
    github = {
        "offline_verifier_sha256": _h("gh-executable"),
        "profile": GITHUB_PROFILE,
        "raw_bundle_sha256": _h("github-attestation-raw-bundle"),
        "raw_statement_sha256": _canonical_digest(statement),
        "repository_id": "205000001",
        "repository_owner_id": "205000002",
        "repository_visibility": "public",
        "runner_environment": "github-hosted",
        "source_commit": source_commit,
        "statement": statement,
        "trusted_root_sha256": sigstore["trusted_root_sha256"],
        "verification_state": "synthetic_fixture_unverified",
        "workflow_ref": "01121531/manage/.github/workflows/release.yml@refs/tags/v0.0.0-fixture",
    }
    provenance_sha256 = _canonical_digest(github)

    trust = {
        "acquired_at": "2026-01-02T03:00:00Z",
        "ctlog_keys_sha256": _h("ctlog-keys"),
        "freshness_reference": "fixture-trust-review-205",
        "fulcio_roots_sha256": _h("fulcio-roots"),
        "rekor_keys_sha256": _h("rekor-keys"),
        "revocation_snapshot_sha256": _h("revocation-snapshot"),
        "transparency_checkpoint_sha256": sigstore["checkpoint_sha256"],
        "trusted_root_sha256": sigstore["trusted_root_sha256"],
        "valid_from": "2026-01-02T02:59:00Z",
        "valid_until": "2026-01-02T04:00:00Z",
        "verification_state": "synthetic_fixture_unverified",
    }
    trust_sha256 = _canonical_digest(trust)

    deployment = {
        "provenance_record_sha256": provenance_sha256,
        "publisher_record_sha256": sigstore_sha256,
        "release_commit": source_commit,
        "release_tag": "v0.0.0-fixture",
        "runtime_subject_sha256": subject_sha256,
        "selected_artifact_digest": artifact_digest,
        "selected_at": "2026-01-02T03:10:00Z",
        "selected_immutable_reference": immutable_reference,
        "target_account": "fixture-account-205",
        "target_cluster_or_host": "fixture-cluster-205",
        "target_environment": "fixture-staging-205",
        "verification_state": "synthetic_fixture_unverified",
    }
    deployment_sha256 = _canonical_digest(deployment)

    target = {
        "config_image": immutable_reference,
        "container_id_sha256": _h("container-id"),
        "deployment_selection_sha256": deployment_sha256,
        "executable_digest": "sha256:" + _h("target-executable"),
        "image_object_id": "sha256:" + _h("image-object-id"),
        "loaded_evidence_sha256": runtime_subject["target_loaded_evidence_sha256"],
        "observed_artifact_digest": artifact_digest,
        "observed_at": "2026-01-02T03:12:00Z",
        "observer_signature_artifact_sha256": _h("observer-signature"),
        "process_identity_sha256": runtime_subject["target_process_identity_sha256"],
        "readback_artifact_sha256": _h("target-readback"),
        "repo_digests": [immutable_reference],
        "runtime_subject_sha256": subject_sha256,
        "target_account": deployment["target_account"],
        "target_cluster_or_host": deployment["target_cluster_or_host"],
        "target_environment": deployment["target_environment"],
        "verification_state": "synthetic_fixture_unverified",
    }
    target_sha256 = _canonical_digest(target)

    imprint = _evidence_imprint(
        sigstore_sha256=sigstore_sha256,
        provenance_sha256=provenance_sha256,
        trust_sha256=trust_sha256,
        deployment_sha256=deployment_sha256,
        target_sha256=target_sha256,
    )
    timestamp = {
        "authority_identity_fingerprint_sha256": _h("timestamp-authority"),
        "evidence_imprint_sha256": imprint,
        "generated_at": "2026-01-02T03:13:00Z",
        "nonce": _h("timestamp-nonce"),
        "policy_oid": "1.3.6.1.4.1.57264.1.205",
        "runtime_subject_sha256": subject_sha256,
        "token_sha256": _h("timestamp-token"),
        "trust_root_sha256": _h("timestamp-root"),
        "verification_state": "synthetic_fixture_unverified",
    }
    timestamp_sha256 = _canonical_digest(timestamp)

    proposed_entry = _provider_entry_digest(
        subject_sha256,
        imprint,
        timestamp_sha256,
        runtime_subject["expected_prior_provider_head"],
        runtime_subject["proposed_provider_sequence"],
        runtime_subject["cas_request_id"],
    )
    head = {
        "append_only_claimed": True,
        "automatic_retry_performed": False,
        "cas_outcome_sha256": _h("cas-outcome"),
        "cas_request_id": runtime_subject["cas_request_id"],
        "delete_denial_claimed": True,
        "expected_prior_head": runtime_subject["expected_prior_provider_head"],
        "immutable_version": "fixture-version-00000009",
        "ledger_id": "fixture-runtime-ledger-205",
        "namespace": "fixture-runtime-attestation-205",
        "proposed_entry_sha256": proposed_entry,
        "proposed_sequence": runtime_subject["proposed_provider_sequence"],
        "provider_account_fingerprint_sha256": _h("provider-account"),
        "read_after_current_head": proposed_entry,
        "readback_sha256": _h("provider-readback"),
        "retention_claimed": True,
        "runtime_subject_sha256": subject_sha256,
        "stale_write_rejected_claimed": True,
        "timestamp_record_sha256": timestamp_sha256,
        "verification_state": "synthetic_fixture_unverified",
    }

    payload = {
        "deployment_selection": deployment,
        "evidence_status": "protocol_verified_fixture_only",
        "github_provenance": github,
        "not_committed_eligible": False,
        "policy_artifact_sha256": POLICY_SHA256,
        "production_acceptance": False,
        "profile_payload_sha256": PROFILE_PAYLOAD_SHA256,
        "provider_head": head,
        "record_type": RECORD_TYPE,
        "runtime_subject": runtime_subject,
        "schema_version": 1,
        "sigstore_cosign": sigstore,
        "synthetic": True,
        "target_observation": target,
        "trust_state": trust,
        "trusted_timestamp": timestamp,
    }
    return {**payload, "integrity": {"payload_sha256": _canonical_digest(payload)}}


def fixture_bytes() -> bytes:
    return _artifact_bytes(build_fixture())


if __name__ == "__main__":
    import sys

    sys.stdout.buffer.write(fixture_bytes())
