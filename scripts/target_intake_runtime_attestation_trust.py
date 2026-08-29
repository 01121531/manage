"""Validate the unconfigured external runtime-attestation handoff contract.

This repository-side validator is deliberately preparatory.  It validates one
closed synthetic policy and one pending readiness template.  It does not sign
or attest a runtime, inspect a target process, consult host time, contact an
artifact provider, or advance a provider head.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence

try:
    from scripts.external_json import (
        MAX_INTAKE_JSON_BYTES,
        StableFileError,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
    )
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import (
        MAX_INTAKE_JSON_BYTES,
        StableFileError,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
READINESS = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-runtime-attestation-readiness.synthetic.json"
)
POLICY_KIND = "target_intake_runtime_attestation_policy_v1"
READINESS_RECORD_TYPE = "target_intake_runtime_attestation_readiness"
SUBJECT_DOMAIN = "email-platform/target-intake-runtime-attestation-handoff/v1"
REQUIRED_SUBJECT_BINDINGS = (
    "terminal_manifest_payload_sha256",
    "terminal_manifest_file_sha256",
    "terminal_receipt_payload_sha256",
    "terminal_receipt_file_sha256",
    "generation_sequence",
    "validation_context_sha256",
    "validator_contract_sha256",
    "replay_runtime_sha256",
    "execution_profile_sha256",
    "runtime_artifact_kind",
    "runtime_artifact_digest",
    "runtime_artifact_immutable_reference",
    "provenance_subject_digest",
    "deploy_selected_digest",
    "target_observed_digest",
    "target_process_identity_sha256",
    "target_loaded_evidence_sha256",
    "expected_prior_provider_head",
    "proposed_provider_sequence",
    "cas_request_id",
)
PUBLISHER_CONTRACT = {
    "signer_role": "target_intake_runtime_publisher_authority",
    "usage_scope": "target_intake_runtime_publisher_v1_only",
    "signature_domain": (
        "email-platform/target-intake-runtime-attestation-handoff/publisher/v1"
    ),
}
PROVENANCE_CONTRACT = {
    "signer_role": "target_intake_runtime_provenance_authority",
    "usage_scope": "target_intake_runtime_provenance_v1_only",
    "signature_domain": (
        "email-platform/target-intake-runtime-attestation-handoff/provenance/v1"
    ),
}
TARGET_OBSERVER_CONTRACT = {
    "signer_role": "target_intake_runtime_target_observer_authority",
    "usage_scope": "target_intake_runtime_target_observer_v1_only",
    "signature_domain": (
        "email-platform/target-intake-runtime-attestation-handoff/target-observer/v1"
    ),
}
TRUSTED_TIME_CONTRACT = {
    "signer_role": "target_intake_runtime_trusted_time_authority",
    "usage_scope": "target_intake_runtime_trusted_time_v1_only",
    "signature_domain": (
        "email-platform/target-intake-runtime-attestation-handoff/trusted-time/v1"
    ),
}
PROVIDER_HEAD_CONTRACT = {
    "signer_role": "target_intake_runtime_head_authority",
    "usage_scope": "target_intake_runtime_head_authority_v1_only",
    "signature_domain": (
        "email-platform/target-intake-runtime-attestation-handoff/provider-head/v1"
    ),
}
GENERATION_CONTEXT_FORBIDDEN_IDENTITIES = (
    "target_intake_generation_context_authority",
    "target_intake_generation_context_authority_v1_only",
    "email-platform/target-intake-generation-context-handoff/context-authority/v1",
    "target_intake_generation_trusted_time_authority",
    "target_intake_generation_trusted_time_v1_only",
    "email-platform/target-intake-generation-context-handoff/trusted-time/v1",
    "target_intake_generation_head_authority",
    "target_intake_generation_head_authority_v1_only",
    "email-platform/target-intake-generation-context-handoff/provider-head/v1",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "authoring_integration_enabled",
    "recovery_integration_enabled",
    "deployment_integration_enabled",
    "runtime_acceptance_integration_enabled",
    "subject_domain",
    "required_subject_bindings",
    "artifact_requirements",
    "publisher_signature",
    "provenance_attestation",
    "target_runtime_observation",
    "trusted_timestamp",
    "provider_head",
    "custody_requirements",
}
_ARTIFACT_REQUIREMENT_FIELDS = {
    "digest_algorithm",
    "allowed_artifact_kinds",
    "immutable_digest_reference_required",
    "tag_only_reference_forbidden",
    "build_provenance_subject_digest_required",
    "deployment_digest_match_required",
    "target_observed_digest_match_required",
    "target_process_identity_required",
    "target_loaded_evidence_required",
}
_PUBLISHER_FIELDS = {
    "state",
    "signer_role",
    "usage_scope",
    "signature_domain",
    "algorithm",
    "issuer_identity",
    "key_id",
    "trust_anchor_sha256",
    "valid_from",
    "valid_until",
    "revocation_registry_reference",
    "revocation_registry_sha256",
    "transparency_log_reference",
    "subject_digest_required",
    "trust_anchor_chain_required",
    "revocation_freshness_required",
    "transparency_inclusion_required",
}
_PROVENANCE_FIELDS = {
    "state",
    "signer_role",
    "usage_scope",
    "signature_domain",
    "attestation_format",
    "issuer_identity",
    "builder_identity",
    "source_repository",
    "source_commit",
    "predicate_type",
    "trust_anchor_sha256",
    "revocation_registry_sha256",
    "subject_digest_required",
    "materials_digest_binding_required",
    "build_parameters_binding_required",
    "hermetic_build_claim_required",
    "signature_verification_required",
}
_TARGET_OBSERVER_FIELDS = {
    "state",
    "signer_role",
    "usage_scope",
    "signature_domain",
    "authority_identity",
    "target_environment",
    "target_account",
    "target_cluster_or_host",
    "observation_kind",
    "deployment_digest_selection_required",
    "observed_content_digest_required",
    "container_image_id_or_executable_digest_required",
    "process_identity_required",
    "loaded_module_native_evidence_required",
    "post_deployment_observation_required",
    "signed_observation_required",
    "read_after_observation_required",
}
_TRUSTED_TIMESTAMP_FIELDS = {
    "state",
    "signer_role",
    "usage_scope",
    "signature_domain",
    "authority_kind",
    "authority_identity_fingerprint_sha256",
    "trust_root_sha256",
    "policy_oid",
    "nonce_binding_required",
    "imprint_binding_required",
    "maximum_assertion_age_seconds",
}
_PROVIDER_HEAD_FIELDS = {
    "state",
    "signer_role",
    "usage_scope",
    "signature_domain",
    "provider_kind",
    "provider_account_fingerprint_sha256",
    "namespace",
    "ledger_id",
    "semantics",
    "caller_prior_head_required",
    "sequence_precondition_required",
    "artifact_digest_precondition_required",
    "immutable_version_required",
    "signed_cas_outcome_required",
    "read_after_cas_current_head_required",
    "append_only_history_required",
    "stale_write_rejection_required",
    "automatic_retry_forbidden",
    "retention_and_delete_denial_readback_required",
}
_CUSTODY_FIELDS = {
    "five_distinct_authorities_required",
    "generation_context_role_domain_scope_reuse",
    "private_secret_role_domain_scope_reuse",
    "cross_runtime_domain_key_reuse",
    "private_keys_in_repository",
    "private_key_cli_environment_transport",
    "external_key_custody_evidence_required",
    "independent_review_required",
    "caller_policy_pin_required",
    "externally_governed_policy_predecessor_required",
}
_READINESS_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "readiness_status",
    "production_acceptance",
    "not_committed_eligible",
    "policy_artifact_sha256",
    "runtime_subject",
    "publisher_signature",
    "provenance_attestation",
    "target_runtime_observation",
    "trusted_timestamp",
    "provider_head",
    "assertions",
    "integrity",
}
_ASSERTION_FIELDS = {
    "policy_configured",
    "publisher_signature_authenticated",
    "publisher_role_scope_authorized",
    "publisher_anchor_window_valid",
    "publisher_revocation_snapshot_current",
    "provenance_attestation_authenticated",
    "provenance_subject_digest_matched",
    "immutable_artifact_version_authenticated",
    "deployment_digest_selection_matched",
    "target_observation_authenticated",
    "target_digest_matched",
    "target_process_identity_bound",
    "target_loaded_evidence_bound",
    "timestamp_nonce_imprint_bound",
    "provider_current_head_authenticated",
    "provider_cas_precondition_ready",
    "global_fork_absence_proven",
    "global_rollback_protection_proven",
    "no_repository_signature_generated",
    "no_provider_mutation_performed",
    "no_target_observation_claimed",
}


class RuntimeAttestationTrustError(ValueError):
    """The external runtime-attestation handoff template is not safe."""


def _invalid() -> RuntimeAttestationTrustError:
    return RuntimeAttestationTrustError(
        "target intake runtime attestation handoff is invalid"
    )


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _all_true(value: dict[str, Any], fields: set[str]) -> bool:
    return all(value[key] is True for key in fields)


def _ensure_authority_separation() -> None:
    contracts = (
        PUBLISHER_CONTRACT,
        PROVENANCE_CONTRACT,
        TARGET_OBSERVER_CONTRACT,
        TRUSTED_TIME_CONTRACT,
        PROVIDER_HEAD_CONTRACT,
    )
    identities = {
        contract[key]
        for contract in contracts
        for key in ("signer_role", "usage_scope", "signature_domain")
    }
    if len(identities) != 15 or identities.intersection(
        GENERATION_CONTEXT_FORBIDDEN_IDENTITIES
    ):
        raise _invalid()


def _unconfigured_publisher(value: object) -> None:
    publisher = _closed(value, _PUBLISHER_FIELDS)
    if any(publisher[key] != expected for key, expected in PUBLISHER_CONTRACT.items()):
        raise _invalid()
    if (
        publisher["state"] != "unconfigured"
        or any(
            publisher[key] is not None
            for key in (
                "algorithm",
                "issuer_identity",
                "key_id",
                "trust_anchor_sha256",
                "valid_from",
                "valid_until",
                "revocation_registry_reference",
                "revocation_registry_sha256",
                "transparency_log_reference",
            )
        )
        or not _all_true(
            publisher,
            {
                "subject_digest_required",
                "trust_anchor_chain_required",
                "revocation_freshness_required",
                "transparency_inclusion_required",
            },
        )
    ):
        raise _invalid()


def _unconfigured_provenance(value: object) -> None:
    provenance = _closed(value, _PROVENANCE_FIELDS)
    if any(provenance[key] != expected for key, expected in PROVENANCE_CONTRACT.items()):
        raise _invalid()
    if (
        provenance["state"] != "unconfigured"
        or any(
            provenance[key] is not None
            for key in (
                "attestation_format",
                "issuer_identity",
                "builder_identity",
                "source_repository",
                "source_commit",
                "predicate_type",
                "trust_anchor_sha256",
                "revocation_registry_sha256",
            )
        )
        or not _all_true(
            provenance,
            {
                "subject_digest_required",
                "materials_digest_binding_required",
                "build_parameters_binding_required",
                "hermetic_build_claim_required",
                "signature_verification_required",
            },
        )
    ):
        raise _invalid()


def _unconfigured_target_observer(value: object) -> None:
    observer = _closed(value, _TARGET_OBSERVER_FIELDS)
    if any(
        observer[key] != expected
        for key, expected in TARGET_OBSERVER_CONTRACT.items()
    ):
        raise _invalid()
    if (
        observer["state"] != "unconfigured"
        or any(
            observer[key] is not None
            for key in (
                "authority_identity",
                "target_environment",
                "target_account",
                "target_cluster_or_host",
                "observation_kind",
            )
        )
        or not _all_true(
            observer,
            {
                "deployment_digest_selection_required",
                "observed_content_digest_required",
                "container_image_id_or_executable_digest_required",
                "process_identity_required",
                "loaded_module_native_evidence_required",
                "post_deployment_observation_required",
                "signed_observation_required",
                "read_after_observation_required",
            },
        )
    ):
        raise _invalid()


def _unconfigured_trusted_timestamp(value: object) -> None:
    timestamp = _closed(value, _TRUSTED_TIMESTAMP_FIELDS)
    if any(timestamp[key] != expected for key, expected in TRUSTED_TIME_CONTRACT.items()):
        raise _invalid()
    if (
        timestamp["state"] != "unconfigured"
        or timestamp["nonce_binding_required"] is not True
        or timestamp["imprint_binding_required"] is not True
        or any(
            timestamp[key] is not None
            for key in (
                "authority_kind",
                "authority_identity_fingerprint_sha256",
                "trust_root_sha256",
                "policy_oid",
                "maximum_assertion_age_seconds",
            )
        )
    ):
        raise _invalid()


def _unconfigured_provider_head(value: object) -> None:
    head = _closed(value, _PROVIDER_HEAD_FIELDS)
    if any(head[key] != expected for key, expected in PROVIDER_HEAD_CONTRACT.items()):
        raise _invalid()
    if (
        head["state"] != "unconfigured"
        or head["semantics"] != "provider_native_compare_and_swap_append_only_v1"
        or any(
            head[key] is not None
            for key in (
                "provider_kind",
                "provider_account_fingerprint_sha256",
                "namespace",
                "ledger_id",
            )
        )
        or not _all_true(
            head,
            {
                "caller_prior_head_required",
                "sequence_precondition_required",
                "artifact_digest_precondition_required",
                "immutable_version_required",
                "signed_cas_outcome_required",
                "read_after_cas_current_head_required",
                "append_only_history_required",
                "stale_write_rejection_required",
                "automatic_retry_forbidden",
                "retention_and_delete_denial_readback_required",
            },
        )
    ):
        raise _invalid()


def validate_policy(value: object) -> dict[str, Any]:
    policy = _closed(value, _POLICY_FIELDS)
    _ensure_authority_separation()
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or policy["policy_kind"] != POLICY_KIND
        or policy["synthetic"] is not True
        or policy["policy_status"] != "unconfigured"
        or policy["policy_effect"] != "external_handoff_readiness_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
        or policy["authoring_integration_enabled"] is not False
        or policy["recovery_integration_enabled"] is not False
        or policy["deployment_integration_enabled"] is not False
        or policy["runtime_acceptance_integration_enabled"] is not False
        or policy["subject_domain"] != SUBJECT_DOMAIN
        or policy["required_subject_bindings"] != list(REQUIRED_SUBJECT_BINDINGS)
    ):
        raise _invalid()
    requirements = _closed(
        policy["artifact_requirements"], _ARTIFACT_REQUIREMENT_FIELDS
    )
    if requirements != {
        "digest_algorithm": "sha256",
        "allowed_artifact_kinds": ["hermetic_runtime_bundle", "oci_container_image"],
        "immutable_digest_reference_required": True,
        "tag_only_reference_forbidden": True,
        "build_provenance_subject_digest_required": True,
        "deployment_digest_match_required": True,
        "target_observed_digest_match_required": True,
        "target_process_identity_required": True,
        "target_loaded_evidence_required": True,
    }:
        raise _invalid()
    _unconfigured_publisher(policy["publisher_signature"])
    _unconfigured_provenance(policy["provenance_attestation"])
    _unconfigured_target_observer(policy["target_runtime_observation"])
    _unconfigured_trusted_timestamp(policy["trusted_timestamp"])
    _unconfigured_provider_head(policy["provider_head"])
    custody = _closed(policy["custody_requirements"], _CUSTODY_FIELDS)
    if custody != {
        "five_distinct_authorities_required": True,
        "generation_context_role_domain_scope_reuse": "forbidden",
        "private_secret_role_domain_scope_reuse": "forbidden",
        "cross_runtime_domain_key_reuse": "forbidden",
        "private_keys_in_repository": "forbidden",
        "private_key_cli_environment_transport": "forbidden",
        "external_key_custody_evidence_required": True,
        "independent_review_required": True,
        "caller_policy_pin_required": True,
        "externally_governed_policy_predecessor_required": True,
    }:
        raise _invalid()
    return dict(policy)


def parse_policy(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        return validate_policy(parse_unique_json_bytes(raw))
    except RuntimeAttestationTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


def validate_readiness(value: object, *, policy_artifact_sha256: str) -> dict[str, Any]:
    readiness = _closed(value, _READINESS_FIELDS)
    integrity = _closed(readiness["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in readiness.items() if key != "integrity"}
    assertions = _closed(readiness["assertions"], _ASSERTION_FIELDS)
    expected_assertions = {key: False for key in _ASSERTION_FIELDS}
    for key in (
        "no_repository_signature_generated",
        "no_provider_mutation_performed",
        "no_target_observation_claimed",
    ):
        expected_assertions[key] = True
    if (
        type(readiness["schema_version"]) is not int
        or readiness["schema_version"] != 1
        or readiness["record_type"] != READINESS_RECORD_TYPE
        or readiness["synthetic"] is not True
        or readiness["readiness_status"] != "pending"
        or readiness["production_acceptance"] is not False
        or readiness["not_committed_eligible"] is not False
        or _SHA256.fullmatch(readiness["policy_artifact_sha256"] or "") is None
        or not hmac.compare_digest(
            readiness["policy_artifact_sha256"], policy_artifact_sha256
        )
        or any(
            readiness[key] is not None
            for key in (
                "runtime_subject",
                "publisher_signature",
                "provenance_attestation",
                "target_runtime_observation",
                "trusted_timestamp",
                "provider_head",
            )
        )
        or assertions != expected_assertions
        or _SHA256.fullmatch(integrity.get("payload_sha256", "")) is None
        or not hmac.compare_digest(
            integrity["payload_sha256"], _canonical_digest(payload)
        )
    ):
        raise _invalid()
    return dict(readiness)


def parse_readiness(raw: bytes, *, policy_artifact_sha256: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        return validate_readiness(
            parse_unique_json_bytes(raw),
            policy_artifact_sha256=policy_artifact_sha256,
        )
    except RuntimeAttestationTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


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


def verify_repository() -> str:
    policy_raw = _read_single_link(POLICY)
    parse_policy(policy_raw)
    policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
    readiness_raw = _read_single_link(READINESS)
    parse_readiness(readiness_raw, policy_artifact_sha256=policy_sha256)
    return (
        "target-intake-runtime-attestation-handoff-ok "
        "status=unconfigured readiness=pending production_acceptance=false "
        "not_committed_eligible=false authoring-integration=disabled "
        "recovery-integration=disabled deployment-integration=disabled "
        "runtime-acceptance-integration=disabled "
        "generation-context-role-domain-scope-reuse=forbidden "
        "no-repository-signature-generated=true no-provider-mutation-performed=true "
        "no-target-observation-claimed=true policy-pin-authority=unverified "
        "runtime-publisher-authentication=unverified "
        "runtime-publisher-role-scope=unverified trust-anchor-validity=unverified "
        "trust-anchor-revocation=unverified provenance-attestation=unverified "
        "immutable-artifact-version=unverified deploy-digest-selection=unverified "
        "target-observed-runtime-digest=unverified target-process-identity=unverified "
        "target-loaded-evidence=unverified trusted-timestamp=unverified "
        "timestamp-replay-protection=unverified provider-native-head=unverified "
        "provider-head-cas=unverified global-fork-protection=unverified "
        "global-rollback-protection=unverified runtime-authority=unverified "
        "original-execution=unverified "
        f"policy_sha256={policy_sha256}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the pending runtime-attestation handoff contract."
    )
    parser.add_argument("command", choices=("verify-repository",))
    parser.parse_args(argv)
    try:
        print(verify_repository())
    except RuntimeAttestationTrustError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
