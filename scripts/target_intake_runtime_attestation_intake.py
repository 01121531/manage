"""Validate a closed runtime-attestation evidence protocol from exact bytes.

The bytes core proves schema, canonical encoding, caller pins, and cross-record
bindings only.  The repository fixture is deliberately synthetic: it does not
cryptographically authenticate Sigstore, GitHub, the target observer, trusted
time, or provider CAS, and it can never grant production acceptance.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

try:
    from scripts.external_json import (
        MAX_INTAKE_JSON_BYTES,
        StableFileError,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
    )
    from scripts.target_intake_runtime_attestation_trust import (
        REQUIRED_SUBJECT_BINDINGS,
        SUBJECT_DOMAIN,
        parse_policy,
    )
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import (
        MAX_INTAKE_JSON_BYTES,
        StableFileError,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
    )
    from target_intake_runtime_attestation_trust import (
        REQUIRED_SUBJECT_BINDINGS,
        SUBJECT_DOMAIN,
        parse_policy,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
PROFILE = ROOT / "deploy" / "target-intake-runtime-attestation-profile.synthetic.json"
EVIDENCE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-runtime-attestation-evidence.synthetic.json"
)
EXPECTED_FIXTURE_SUBJECT_SHA256 = "5f5d42ed25b9d4c5ad62f53aa4368273642dcdace47c5eb61d2e3997abd6d4bf"

PROFILE_KIND = "target_intake_runtime_attestation_verification_profile_v1"
RECORD_TYPE = "target_intake_runtime_attestation_evidence_v1"
SIGSTORE_PROFILE = "sigstore_cosign_bundle_v0_3_offline_v1"
GITHUB_PROFILE = "github_artifact_attestation_slsa_v1_offline_v1"
SIGSTORE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{2,255}$")
_CAS_ID = re.compile(r"^runtime-cas-[a-z0-9][a-z0-9-]{7,63}$")
_NONCE = re.compile(r"^[0-9a-f]{32,128}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

_PROFILE_FIELDS = {
    "schema_version",
    "profile_kind",
    "synthetic",
    "profile_status",
    "production_acceptance",
    "not_committed_eligible",
    "policy_artifact_sha256",
    "subject_domain",
    "provider_profiles",
    "bytes_core",
    "integrity",
}
_PROVIDER_PROFILE_FIELDS = {
    "sigstore_cosign",
    "github_provenance",
    "trust_state",
    "deployment_selection",
    "target_observation",
    "trusted_timestamp",
    "provider_head",
}
_BYTES_CORE_FIELDS = {
    "input_kind",
    "canonical_json_required",
    "duplicate_keys_rejected",
    "caller_policy_pin_required",
    "caller_profile_pin_required",
    "filesystem_access",
    "network_access",
    "host_time_access",
    "subprocess_access",
    "signing_or_key_generation",
    "production_authentication",
}
_EVIDENCE_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "evidence_status",
    "production_acceptance",
    "not_committed_eligible",
    "policy_artifact_sha256",
    "profile_payload_sha256",
    "runtime_subject",
    "sigstore_cosign",
    "github_provenance",
    "trust_state",
    "deployment_selection",
    "target_observation",
    "trusted_timestamp",
    "provider_head",
    "integrity",
}
_SIGSTORE_FIELDS = {
    "profile",
    "raw_bundle_sha256",
    "media_type",
    "content_kind",
    "artifact_digest",
    "certificate_der_sha256",
    "certificate_oidc_issuer",
    "certificate_identity",
    "trusted_root_sha256",
    "tlog_log_id",
    "tlog_entry_sha256",
    "inclusion_promise_sha256",
    "inclusion_proof_sha256",
    "checkpoint_sha256",
    "rfc3161_timestamp_sha256",
    "offline_verifier_sha256",
    "verification_state",
}
_GITHUB_FIELDS = {
    "profile",
    "raw_bundle_sha256",
    "raw_statement_sha256",
    "trusted_root_sha256",
    "offline_verifier_sha256",
    "repository_id",
    "repository_owner_id",
    "repository_visibility",
    "runner_environment",
    "source_commit",
    "statement",
    "workflow_ref",
    "verification_state",
}
_STATEMENT_FIELDS = {"_type", "subject", "predicateType", "predicate"}
_PREDICATE_FIELDS = {"buildDefinition", "runDetails"}
_BUILD_DEFINITION_FIELDS = {
    "buildType",
    "externalParameters",
    "internalParameters",
    "resolvedDependencies",
}
_RUN_DETAILS_FIELDS = {"builder", "metadata"}
_TRUST_FIELDS = {
    "trusted_root_sha256",
    "fulcio_roots_sha256",
    "rekor_keys_sha256",
    "ctlog_keys_sha256",
    "revocation_snapshot_sha256",
    "transparency_checkpoint_sha256",
    "acquired_at",
    "valid_from",
    "valid_until",
    "freshness_reference",
    "verification_state",
}
_DEPLOYMENT_FIELDS = {
    "runtime_subject_sha256",
    "publisher_record_sha256",
    "provenance_record_sha256",
    "selected_artifact_digest",
    "selected_immutable_reference",
    "release_commit",
    "release_tag",
    "target_environment",
    "target_account",
    "target_cluster_or_host",
    "selected_at",
    "verification_state",
}
_TARGET_FIELDS = {
    "runtime_subject_sha256",
    "deployment_selection_sha256",
    "target_environment",
    "target_account",
    "target_cluster_or_host",
    "container_id_sha256",
    "config_image",
    "image_object_id",
    "repo_digests",
    "observed_artifact_digest",
    "process_identity_sha256",
    "executable_digest",
    "loaded_evidence_sha256",
    "observed_at",
    "readback_artifact_sha256",
    "observer_signature_artifact_sha256",
    "verification_state",
}
_TIMESTAMP_FIELDS = {
    "runtime_subject_sha256",
    "evidence_imprint_sha256",
    "nonce",
    "authority_identity_fingerprint_sha256",
    "trust_root_sha256",
    "policy_oid",
    "token_sha256",
    "generated_at",
    "verification_state",
}
_HEAD_FIELDS = {
    "runtime_subject_sha256",
    "timestamp_record_sha256",
    "expected_prior_head",
    "proposed_sequence",
    "cas_request_id",
    "proposed_entry_sha256",
    "provider_account_fingerprint_sha256",
    "namespace",
    "ledger_id",
    "immutable_version",
    "cas_outcome_sha256",
    "read_after_current_head",
    "readback_sha256",
    "append_only_claimed",
    "stale_write_rejected_claimed",
    "automatic_retry_performed",
    "retention_claimed",
    "delete_denial_claimed",
    "verification_state",
}
class RuntimeAttestationIntakeError(ValueError):
    """The configured fixture protocol is malformed or overstates authority."""


def _invalid() -> RuntimeAttestationIntakeError:
    return RuntimeAttestationIntakeError(
        "target intake runtime attestation evidence is invalid"
    )


@dataclass(frozen=True)
class VerifiedRuntimeAttestationProtocol:
    runtime_subject_sha256: str
    runtime_artifact_digest: str
    profile_payload_sha256: str
    evidence_payload_sha256: str
    evidence_imprint_sha256: str
    provider_head_sha256: str


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _artifact_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _artifact_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _invalid()
    return value


def _reference(value: object) -> str:
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        raise _invalid()
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _invalid() from None
    if parsed.tzinfo != timezone.utc:
        raise _invalid()
    return parsed


def _parse_canonical(raw: bytes) -> object:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None
    if raw != _artifact_bytes(value):
        raise _invalid()
    return value


def _sealed(value: object, fields: set[str]) -> tuple[dict[str, Any], str]:
    document = _closed(value, fields)
    integrity = _closed(document["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in document.items() if key != "integrity"}
    expected = _canonical_digest(payload)
    if not hmac.compare_digest(_digest(integrity["payload_sha256"]), expected):
        raise _invalid()
    return document, expected


def validate_profile(value: object, *, policy_artifact_sha256: str) -> dict[str, Any]:
    profile, _ = _sealed(value, _PROFILE_FIELDS)
    providers = _closed(profile["provider_profiles"], _PROVIDER_PROFILE_FIELDS)
    expected_providers = {
        "sigstore_cosign": {
            "profile": SIGSTORE_PROFILE,
            "bundle_media_type": SIGSTORE_MEDIA_TYPE,
            "content_kind": "messageSignature",
            "subject_digest_algorithm": "sha256",
            "offline_verifier": "cosign",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "identity_binding": "exact-workflow-ref",
            "trusted_root_binding": "raw-artifact-sha256",
            "transparency_binding": "log-id-entry-set-proof-checkpoint",
            "cryptographic_verification_required": True,
        },
        "github_provenance": {
            "profile": GITHUB_PROFILE,
            "bundle_format": "github-attestation-jsonl-with-sigstore-bundle",
            "statement_type": INTOTO_STATEMENT_TYPE,
            "predicate_type": SLSA_PREDICATE_TYPE,
            "subject_digest_algorithm": "sha256",
            "offline_verifier": "gh-attestation-verify",
            "repository": "01121531/manage",
            "repository_identity_binding": "name-id-owner-id-visibility",
            "workflow": "01121531/manage/.github/workflows/release.yml",
            "workflow_ref_binding": "exact",
            "runner_environment": "github-hosted",
            "certificate_extensions_binding": "closed-profile",
            "source_commit_binding": "resolved-dependency-gitCommit",
            "external_parameters_binding": "closed-profile",
            "resolved_dependencies_binding": "closed-profile",
            "builder_binding": "exact-id",
            "trusted_root_binding": "raw-artifact-sha256",
            "cryptographic_verification_required": True,
        },
        "trust_state": {
            "trusted_root_artifact_required": True,
            "fulcio_roots_required": True,
            "rekor_keys_required": True,
            "ctlog_keys_required": True,
            "revocation_snapshot_required": True,
            "transparency_checkpoint_required": True,
            "freshness_must_be_externally_authenticated": True,
        },
        "deployment_selection": {
            "immutable_digest_reference_required": True,
            "publisher_record_pin_required": True,
            "provenance_record_pin_required": True,
            "target_identity_required": True,
        },
        "target_observation": {
            "independent_observer_required": True,
            "container_image_id_required": True,
            "repo_digests_required": True,
            "process_identity_required": True,
            "executable_digest_required": True,
            "loaded_evidence_required": True,
            "post_deployment_readback_required": True,
        },
        "trusted_timestamp": {
            "independent_authority_required": True,
            "nonce_required": True,
            "evidence_imprint_required": True,
            "currentness_must_be_externally_authenticated": True,
        },
        "provider_head": {
            "provider_native_cas_required": True,
            "caller_prior_head_required": True,
            "sequence_precondition_required": True,
            "artifact_precondition_required": True,
            "signed_outcome_required": True,
            "read_after_head_required": True,
            "append_only_required": True,
            "stale_rejection_required": True,
            "automatic_retry_forbidden": True,
            "retention_delete_denial_readback_required": True,
        },
    }
    bytes_core = _closed(profile["bytes_core"], _BYTES_CORE_FIELDS)
    if (
        profile["schema_version"] != 1
        or type(profile["schema_version"]) is not int
        or profile["profile_kind"] != PROFILE_KIND
        or profile["synthetic"] is not True
        or profile["profile_status"] != "configured_offline_fixture_only"
        or profile["production_acceptance"] is not False
        or profile["not_committed_eligible"] is not False
        or not hmac.compare_digest(
            _digest(profile["policy_artifact_sha256"]),
            _digest(policy_artifact_sha256),
        )
        or profile["subject_domain"] != SUBJECT_DOMAIN
        or providers != expected_providers
        or bytes_core
        != {
            "input_kind": "exact-caller-supplied-bytes",
            "canonical_json_required": True,
            "duplicate_keys_rejected": True,
            "caller_policy_pin_required": True,
            "caller_profile_pin_required": True,
            "filesystem_access": False,
            "network_access": False,
            "host_time_access": False,
            "subprocess_access": False,
            "signing_or_key_generation": False,
            "production_authentication": False,
        }
    ):
        raise _invalid()
    return dict(profile)


def parse_profile(raw: bytes, *, policy_artifact_sha256: str) -> dict[str, Any]:
    return validate_profile(
        _parse_canonical(raw), policy_artifact_sha256=policy_artifact_sha256
    )


def _validate_runtime_subject(value: object) -> dict[str, Any]:
    subject = _closed(value, set(REQUIRED_SUBJECT_BINDINGS))
    digest_fields = set(REQUIRED_SUBJECT_BINDINGS) - {
        "generation_sequence",
        "runtime_artifact_kind",
        "runtime_artifact_digest",
        "runtime_artifact_immutable_reference",
        "provenance_subject_digest",
        "deploy_selected_digest",
        "target_observed_digest",
        "expected_prior_provider_head",
        "proposed_provider_sequence",
        "cas_request_id",
    }
    for field in digest_fields:
        _digest(subject[field])
    artifact = _artifact_digest(subject["runtime_artifact_digest"])
    for field in (
        "provenance_subject_digest",
        "deploy_selected_digest",
        "target_observed_digest",
    ):
        if not hmac.compare_digest(_artifact_digest(subject[field]), artifact):
            raise _invalid()
    if (
        type(subject["generation_sequence"]) is not int
        or subject["generation_sequence"] < 0
        or subject["runtime_artifact_kind"] != "oci_container_image"
        or not isinstance(subject["runtime_artifact_immutable_reference"], str)
        or not subject["runtime_artifact_immutable_reference"].endswith("@" + artifact)
        or "://" in subject["runtime_artifact_immutable_reference"]
        or not subject["runtime_artifact_immutable_reference"].startswith("ghcr.io/")
        or _SHA256.fullmatch(subject["expected_prior_provider_head"] or "") is None
        or type(subject["proposed_provider_sequence"]) is not int
        or subject["proposed_provider_sequence"] < 1
        or not isinstance(subject["cas_request_id"], str)
        or _CAS_ID.fullmatch(subject["cas_request_id"]) is None
    ):
        raise _invalid()
    return subject


def _validate_sigstore(value: object, subject: Mapping[str, Any]) -> dict[str, Any]:
    record = _closed(value, _SIGSTORE_FIELDS)
    for field in _SIGSTORE_FIELDS - {
        "profile",
        "media_type",
        "content_kind",
        "artifact_digest",
        "certificate_oidc_issuer",
        "certificate_identity",
        "tlog_log_id",
        "verification_state",
    }:
        _digest(record[field])
    if (
        record["profile"] != SIGSTORE_PROFILE
        or record["media_type"] != SIGSTORE_MEDIA_TYPE
        or record["content_kind"] != "messageSignature"
        or not hmac.compare_digest(
            _artifact_digest(record["artifact_digest"]),
            subject["runtime_artifact_digest"],
        )
        or record["certificate_oidc_issuer"]
        != "https://token.actions.githubusercontent.com"
        or not isinstance(record["certificate_identity"], str)
        or not record["certificate_identity"].startswith(
            "https://github.com/01121531/manage/.github/workflows/release.yml@refs/tags/"
        )
        or not isinstance(record["tlog_log_id"], str)
        or not record["tlog_log_id"]
        or record["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return record


def _validate_statement(value: object, subject: Mapping[str, Any]) -> dict[str, Any]:
    statement = _closed(value, _STATEMENT_FIELDS)
    subjects = statement["subject"]
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise _invalid()
    provenance_subject = _closed(subjects[0], {"name", "digest"})
    provenance_digest = _closed(provenance_subject["digest"], {"sha256"})
    expected_digest = subject["runtime_artifact_digest"].split(":", 1)[1]
    if (
        statement["_type"] != INTOTO_STATEMENT_TYPE
        or statement["predicateType"] != SLSA_PREDICATE_TYPE
        or provenance_subject["name"]
        != subject["runtime_artifact_immutable_reference"].split("@", 1)[0]
        or not hmac.compare_digest(_digest(provenance_digest["sha256"]), expected_digest)
    ):
        raise _invalid()
    predicate = _closed(statement["predicate"], _PREDICATE_FIELDS)
    definition = _closed(predicate["buildDefinition"], _BUILD_DEFINITION_FIELDS)
    external = _closed(definition["externalParameters"], {"repository", "ref", "workflow"})
    internal = _closed(
        definition["internalParameters"],
        {"github_event_name", "hermetic_build_claim"},
    )
    dependencies = definition["resolvedDependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != 1:
        raise _invalid()
    dependency = _closed(dependencies[0], {"uri", "digest"})
    commit = _closed(dependency["digest"], {"gitCommit"})["gitCommit"]
    details = _closed(predicate["runDetails"], _RUN_DETAILS_FIELDS)
    builder = _closed(details["builder"], {"id"})
    metadata = _closed(
        details["metadata"], {"invocationId", "startedOn", "finishedOn"}
    )
    started = _timestamp(metadata["startedOn"])
    finished = _timestamp(metadata["finishedOn"])
    if (
        definition["buildType"]
        != "https://actions.github.io/buildtypes/workflow/v1"
        or external["repository"] != "https://github.com/01121531/manage"
        or not isinstance(external["ref"], str)
        or not external["ref"].startswith("refs/tags/")
        or external["workflow"] != ".github/workflows/release.yml"
        or internal["github_event_name"] != "push"
        or internal["hermetic_build_claim"] is not False
        or not isinstance(dependency["uri"], str)
        or not dependency["uri"].startswith("git+https://github.com/01121531/manage@")
        or not dependency["uri"].endswith("@" + external["ref"])
        or not isinstance(commit, str)
        or _COMMIT.fullmatch(commit) is None
        or builder["id"] != "https://github.com/actions/runner/github-hosted"
        or not isinstance(metadata["invocationId"], str)
        or not metadata["invocationId"].startswith(
            "https://github.com/01121531/manage/actions/runs/"
        )
        or started > finished
    ):
        raise _invalid()
    return statement


def _validate_github(value: object, subject: Mapping[str, Any]) -> dict[str, Any]:
    record = _closed(value, _GITHUB_FIELDS)
    for field in (
        "raw_bundle_sha256",
        "raw_statement_sha256",
        "trusted_root_sha256",
        "offline_verifier_sha256",
    ):
        _digest(record[field])
    statement = _validate_statement(record["statement"], subject)
    definition = statement["predicate"]["buildDefinition"]
    external = definition["externalParameters"]
    dependency_commit = definition["resolvedDependencies"][0]["digest"]["gitCommit"]
    if (
        record["profile"] != GITHUB_PROFILE
        or not isinstance(record["repository_id"], str)
        or not record["repository_id"].isdigit()
        or record["repository_id"].startswith("0")
        or not isinstance(record["repository_owner_id"], str)
        or not record["repository_owner_id"].isdigit()
        or record["repository_owner_id"].startswith("0")
        or record["repository_visibility"] != "public"
        or record["runner_environment"] != "github-hosted"
        or record["workflow_ref"]
        != "01121531/manage/.github/workflows/release.yml@" + external["ref"]
        or record["source_commit"] != dependency_commit
        or record["verification_state"] != "synthetic_fixture_unverified"
        or not hmac.compare_digest(
            record["raw_statement_sha256"], _canonical_digest(statement)
        )
    ):
        raise _invalid()
    return record


def _validate_trust(value: object, sigstore: Mapping[str, Any], github: Mapping[str, Any]) -> dict[str, Any]:
    trust = _closed(value, _TRUST_FIELDS)
    for field in _TRUST_FIELDS - {
        "acquired_at",
        "valid_from",
        "valid_until",
        "freshness_reference",
        "verification_state",
    }:
        _digest(trust[field])
    acquired = _timestamp(trust["acquired_at"])
    valid_from = _timestamp(trust["valid_from"])
    valid_until = _timestamp(trust["valid_until"])
    if (
        not (valid_from <= acquired <= valid_until)
        or not hmac.compare_digest(trust["trusted_root_sha256"], sigstore["trusted_root_sha256"])
        or not hmac.compare_digest(trust["trusted_root_sha256"], github["trusted_root_sha256"])
        or not hmac.compare_digest(
            trust["transparency_checkpoint_sha256"], sigstore["checkpoint_sha256"]
        )
        or _reference(trust["freshness_reference"]) != trust["freshness_reference"]
        or trust["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return trust


def _validate_deployment(
    value: object,
    subject: Mapping[str, Any],
    *,
    subject_sha256: str,
    sigstore_sha256: str,
    provenance_sha256: str,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    deployment = _closed(value, _DEPLOYMENT_FIELDS)
    for field in (
        "runtime_subject_sha256",
        "publisher_record_sha256",
        "provenance_record_sha256",
    ):
        _digest(deployment[field])
    _timestamp(deployment["selected_at"])
    if (
        not hmac.compare_digest(deployment["runtime_subject_sha256"], subject_sha256)
        or not hmac.compare_digest(deployment["publisher_record_sha256"], sigstore_sha256)
        or not hmac.compare_digest(deployment["provenance_record_sha256"], provenance_sha256)
        or not hmac.compare_digest(
            _artifact_digest(deployment["selected_artifact_digest"]),
            subject["runtime_artifact_digest"],
        )
        or deployment["selected_immutable_reference"]
        != subject["runtime_artifact_immutable_reference"]
        or not isinstance(deployment["release_commit"], str)
        or _COMMIT.fullmatch(deployment["release_commit"]) is None
        or deployment["release_commit"] != provenance["source_commit"]
        or not isinstance(deployment["release_tag"], str)
        or not deployment["release_tag"].startswith("v")
        or any(
            not isinstance(deployment[field], str) or not deployment[field]
            for field in ("target_environment", "target_account", "target_cluster_or_host")
        )
        or deployment["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return deployment


def _validate_target(
    value: object,
    subject: Mapping[str, Any],
    deployment: Mapping[str, Any],
    *,
    subject_sha256: str,
    deployment_sha256: str,
) -> dict[str, Any]:
    target = _closed(value, _TARGET_FIELDS)
    for field in (
        "runtime_subject_sha256",
        "deployment_selection_sha256",
        "container_id_sha256",
        "process_identity_sha256",
        "loaded_evidence_sha256",
        "readback_artifact_sha256",
        "observer_signature_artifact_sha256",
    ):
        _digest(target[field])
    repo_digests = target["repo_digests"]
    if (
        not isinstance(repo_digests, list)
        or len(repo_digests) != 1
        or not isinstance(repo_digests[0], str)
    ):
        raise _invalid()
    selected = subject["runtime_artifact_immutable_reference"]
    selected_at = _timestamp(deployment["selected_at"])
    observed_at = _timestamp(target["observed_at"])
    if (
        not hmac.compare_digest(target["runtime_subject_sha256"], subject_sha256)
        or not hmac.compare_digest(target["deployment_selection_sha256"], deployment_sha256)
        or any(target[field] != deployment[field] for field in ("target_environment", "target_account", "target_cluster_or_host"))
        or target["config_image"] != selected
        or repo_digests != [selected]
        or not hmac.compare_digest(
            _artifact_digest(target["observed_artifact_digest"]),
            subject["runtime_artifact_digest"],
        )
        or _DIGEST.fullmatch(target["image_object_id"] or "") is None
        or _DIGEST.fullmatch(target["executable_digest"] or "") is None
        or not hmac.compare_digest(target["process_identity_sha256"], subject["target_process_identity_sha256"])
        or not hmac.compare_digest(target["loaded_evidence_sha256"], subject["target_loaded_evidence_sha256"])
        or observed_at < selected_at
        or target["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return target


def _evidence_imprint(
    *,
    sigstore_sha256: str,
    provenance_sha256: str,
    trust_sha256: str,
    deployment_sha256: str,
    target_sha256: str,
) -> str:
    return _canonical_digest(
        {
            "deployment_selection_sha256": deployment_sha256,
            "github_provenance_sha256": provenance_sha256,
            "sigstore_cosign_sha256": sigstore_sha256,
            "target_observation_sha256": target_sha256,
            "trust_state_sha256": trust_sha256,
        }
    )


def _validate_timestamp(
    value: object,
    *,
    subject_sha256: str,
    evidence_imprint_sha256: str,
) -> dict[str, Any]:
    timestamp = _closed(value, _TIMESTAMP_FIELDS)
    for field in (
        "runtime_subject_sha256",
        "evidence_imprint_sha256",
        "authority_identity_fingerprint_sha256",
        "trust_root_sha256",
        "token_sha256",
    ):
        _digest(timestamp[field])
    _timestamp(timestamp["generated_at"])
    if (
        not hmac.compare_digest(timestamp["runtime_subject_sha256"], subject_sha256)
        or not hmac.compare_digest(timestamp["evidence_imprint_sha256"], evidence_imprint_sha256)
        or not isinstance(timestamp["nonce"], str)
        or _NONCE.fullmatch(timestamp["nonce"]) is None
        or timestamp["policy_oid"] != "1.3.6.1.4.1.57264.1.205"
        or timestamp["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return timestamp


def _provider_entry_digest(
    subject_sha256: str,
    evidence_imprint_sha256: str,
    timestamp_sha256: str,
    prior_head: str,
    sequence: int,
    cas_request_id: str,
) -> str:
    return _canonical_digest(
        {
            "cas_request_id": cas_request_id,
            "evidence_imprint_sha256": evidence_imprint_sha256,
            "expected_prior_head": prior_head,
            "proposed_sequence": sequence,
            "runtime_subject_sha256": subject_sha256,
            "timestamp_record_sha256": timestamp_sha256,
        }
    )


def _validate_head(
    value: object,
    subject: Mapping[str, Any],
    *,
    subject_sha256: str,
    evidence_imprint_sha256: str,
    timestamp_sha256: str,
) -> tuple[dict[str, Any], str]:
    head = _closed(value, _HEAD_FIELDS)
    for field in (
        "runtime_subject_sha256",
        "timestamp_record_sha256",
        "expected_prior_head",
        "proposed_entry_sha256",
        "provider_account_fingerprint_sha256",
        "cas_outcome_sha256",
        "read_after_current_head",
        "readback_sha256",
    ):
        _digest(head[field])
    expected = _provider_entry_digest(
        subject_sha256,
        evidence_imprint_sha256,
        timestamp_sha256,
        head["expected_prior_head"],
        head["proposed_sequence"],
        head["cas_request_id"],
    )
    if (
        not hmac.compare_digest(head["runtime_subject_sha256"], subject_sha256)
        or not hmac.compare_digest(head["timestamp_record_sha256"], timestamp_sha256)
        or not hmac.compare_digest(head["expected_prior_head"], subject["expected_prior_provider_head"])
        or head["proposed_sequence"] != subject["proposed_provider_sequence"]
        or head["cas_request_id"] != subject["cas_request_id"]
        or not hmac.compare_digest(head["proposed_entry_sha256"], expected)
        or not hmac.compare_digest(head["read_after_current_head"], expected)
        or type(head["proposed_sequence"]) is not int
        or head["proposed_sequence"] < 1
        or not isinstance(head["cas_request_id"], str)
        or _CAS_ID.fullmatch(head["cas_request_id"]) is None
        or any(not isinstance(head[field], str) or not head[field] for field in ("namespace", "ledger_id", "immutable_version"))
        or head["append_only_claimed"] is not True
        or head["stale_write_rejected_claimed"] is not True
        or head["automatic_retry_performed"] is not False
        or head["retention_claimed"] is not True
        or head["delete_denial_claimed"] is not True
        or head["verification_state"] != "synthetic_fixture_unverified"
    ):
        raise _invalid()
    return head, expected


def validate_evidence(
    value: object,
    *,
    policy_artifact_sha256: str,
    profile_payload_sha256: str,
    expected_runtime_subject_sha256: str,
) -> VerifiedRuntimeAttestationProtocol:
    evidence, evidence_payload_sha256 = _sealed(value, _EVIDENCE_FIELDS)
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != 1
        or evidence["record_type"] != RECORD_TYPE
        or evidence["synthetic"] is not True
        or evidence["evidence_status"] != "protocol_verified_fixture_only"
        or evidence["production_acceptance"] is not False
        or evidence["not_committed_eligible"] is not False
        or not hmac.compare_digest(_digest(evidence["policy_artifact_sha256"]), policy_artifact_sha256)
        or not hmac.compare_digest(_digest(evidence["profile_payload_sha256"]), profile_payload_sha256)
    ):
        raise _invalid()
    subject = _validate_runtime_subject(evidence["runtime_subject"])
    subject_sha256 = _canonical_digest(subject)
    if not hmac.compare_digest(
        subject_sha256, _digest(expected_runtime_subject_sha256)
    ):
        raise _invalid()
    sigstore = _validate_sigstore(evidence["sigstore_cosign"], subject)
    sigstore_sha256 = _canonical_digest(sigstore)
    github = _validate_github(evidence["github_provenance"], subject)
    provenance_sha256 = _canonical_digest(github)
    if sigstore["certificate_identity"] != "https://github.com/" + github["workflow_ref"]:
        raise _invalid()
    trust = _validate_trust(evidence["trust_state"], sigstore, github)
    trust_sha256 = _canonical_digest(trust)
    deployment = _validate_deployment(
        evidence["deployment_selection"],
        subject,
        subject_sha256=subject_sha256,
        sigstore_sha256=sigstore_sha256,
        provenance_sha256=provenance_sha256,
        provenance=github,
    )
    deployment_sha256 = _canonical_digest(deployment)
    target = _validate_target(
        evidence["target_observation"],
        subject,
        deployment,
        subject_sha256=subject_sha256,
        deployment_sha256=deployment_sha256,
    )
    target_sha256 = _canonical_digest(target)
    imprint = _evidence_imprint(
        sigstore_sha256=sigstore_sha256,
        provenance_sha256=provenance_sha256,
        trust_sha256=trust_sha256,
        deployment_sha256=deployment_sha256,
        target_sha256=target_sha256,
    )
    timestamp = _validate_timestamp(
        evidence["trusted_timestamp"],
        subject_sha256=subject_sha256,
        evidence_imprint_sha256=imprint,
    )
    timestamp_sha256 = _canonical_digest(timestamp)
    _, provider_head_sha256 = _validate_head(
        evidence["provider_head"],
        subject,
        subject_sha256=subject_sha256,
        evidence_imprint_sha256=imprint,
        timestamp_sha256=timestamp_sha256,
    )
    return VerifiedRuntimeAttestationProtocol(
        runtime_subject_sha256=subject_sha256,
        runtime_artifact_digest=subject["runtime_artifact_digest"],
        profile_payload_sha256=profile_payload_sha256,
        evidence_payload_sha256=evidence_payload_sha256,
        evidence_imprint_sha256=imprint,
        provider_head_sha256=provider_head_sha256,
    )


def parse_evidence(
    raw: bytes,
    *,
    policy_artifact_sha256: str,
    profile_payload_sha256: str,
    expected_runtime_subject_sha256: str,
) -> VerifiedRuntimeAttestationProtocol:
    return validate_evidence(
        _parse_canonical(raw),
        policy_artifact_sha256=policy_artifact_sha256,
        profile_payload_sha256=profile_payload_sha256,
        expected_runtime_subject_sha256=expected_runtime_subject_sha256,
    )


def verify_runtime_attestation_protocol_bytes(
    *,
    policy_raw: bytes,
    profile_raw: bytes,
    evidence_raw: bytes,
    expected_policy_sha256: str,
    expected_profile_sha256: str,
    expected_runtime_subject_sha256: str,
) -> VerifiedRuntimeAttestationProtocol:
    """Verify exact caller-supplied bytes without filesystem, clock, or subprocess use."""

    for raw in (policy_raw, profile_raw, evidence_raw):
        if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
            raise _invalid()
    expected_policy = _digest(expected_policy_sha256)
    expected_profile = _digest(expected_profile_sha256)
    actual_policy = hashlib.sha256(policy_raw).hexdigest()
    actual_profile = hashlib.sha256(profile_raw).hexdigest()
    if not hmac.compare_digest(actual_policy, expected_policy) or not hmac.compare_digest(actual_profile, expected_profile):
        raise _invalid()
    parse_policy(policy_raw)
    profile = parse_profile(profile_raw, policy_artifact_sha256=actual_policy)
    profile_payload = {key: item for key, item in profile.items() if key != "integrity"}
    return parse_evidence(
        evidence_raw,
        policy_artifact_sha256=actual_policy,
        profile_payload_sha256=_canonical_digest(profile_payload),
        expected_runtime_subject_sha256=expected_runtime_subject_sha256,
    )


def _read_single_link(path: Path) -> bytes:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            path, max_bytes=MAX_INTAKE_JSON_BYTES
        )
    except (OSError, StableFileError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return raw


def verify_repository_fixture() -> str:
    policy_raw = _read_single_link(POLICY)
    profile_raw = _read_single_link(PROFILE)
    evidence_raw = _read_single_link(EVIDENCE)
    verified = verify_runtime_attestation_protocol_bytes(
        policy_raw=policy_raw,
        profile_raw=profile_raw,
        evidence_raw=evidence_raw,
        expected_policy_sha256=hashlib.sha256(policy_raw).hexdigest(),
        expected_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        expected_runtime_subject_sha256=EXPECTED_FIXTURE_SUBJECT_SHA256,
    )
    return (
        "target-intake-runtime-attestation-intake-ok "
        "profile=configured-offline-fixture-only protocol-bindings=verified "
        "publisher-authentication=unverified provenance-authentication=unverified "
        "trust-root-currentness=unverified revocation-freshness=unverified "
        "target-observer-authentication=unverified trusted-time=unverified "
        "provider-cas=unverified global-fork-protection=unverified "
        "global-rollback-protection=unverified runtime-authority=unverified "
        "original-execution=unverified production_acceptance=false "
        "no-write-no-network-no-host-time-no-subprocess-no-signing=true "
        f"subject_sha256={verified.runtime_subject_sha256} "
        f"evidence_payload_sha256={verified.evidence_payload_sha256}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the synthetic offline runtime-attestation protocol fixture."
    )
    parser.add_argument("command", choices=("verify-repository-fixture",))
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify-repository-fixture":
            print(verify_repository_fixture())
            return 0
    except RuntimeAttestationIntakeError as error:
        print(f"target-intake-runtime-attestation-intake-error: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
