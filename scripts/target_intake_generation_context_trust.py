"""Validate the unconfigured generation-context external handoff contract.

This module is deliberately preparatory.  It validates one closed synthetic
policy and pending readiness template, but it does not authenticate an
authority, inspect the host clock, sign anything, contact a provider, or move a
provider head.
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
POLICY = (
    ROOT / "deploy" / "target-intake-generation-context-handoff-policy.synthetic.json"
)
READINESS = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-generation-context-handoff-readiness.synthetic.json"
)
POLICY_KIND = "target_intake_generation_context_handoff_policy_v1"
READINESS_RECORD_TYPE = "target_intake_generation_context_handoff_readiness"
SUBJECT_DOMAIN = "email-platform/target-intake-generation-context-handoff/v1"
REQUIRED_SUBJECT_BINDINGS = (
    "terminal_manifest_payload_sha256",
    "terminal_manifest_file_sha256",
    "terminal_receipt_payload_sha256",
    "terminal_receipt_file_sha256",
    "generation_sequence",
    "validation_context_sha256",
    "validator_contract_sha256",
    "environment",
    "expected_prior_provider_head",
    "proposed_provider_sequence",
    "cas_request_id",
)
AUTHORITY_CONTRACT = {
    "signer_role": "target_intake_generation_context_authority",
    "usage_scope": "target_intake_generation_context_authority_v1_only",
    "signature_domain": (
        "email-platform/target-intake-generation-context-handoff/"
        "context-authority/v1"
    ),
}
TRUSTED_TIME_CONTRACT = {
    "signer_role": "target_intake_generation_trusted_time_authority",
    "usage_scope": "target_intake_generation_trusted_time_v1_only",
    "signature_domain": (
        "email-platform/target-intake-generation-context-handoff/trusted-time/v1"
    ),
}
PROVIDER_HEAD_CONTRACT = {
    "signer_role": "target_intake_generation_head_authority",
    "usage_scope": "target_intake_generation_head_authority_v1_only",
    "signature_domain": (
        "email-platform/target-intake-generation-context-handoff/provider-head/v1"
    ),
}

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
    "subject_domain",
    "required_subject_bindings",
    "context_authority",
    "trusted_timestamp",
    "provider_head",
    "custody_requirements",
}
_AUTHORITY_FIELDS = {
    "state",
    "signer_role",
    "algorithm",
    "usage_scope",
    "signature_domain",
    "key_id",
    "public_key_b64url",
    "valid_from",
    "valid_until",
    "revocation_registry_reference",
    "revocation_registry_sha256",
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
    "generation_precondition_required",
    "immutable_version_required",
    "signed_cas_outcome_required",
    "read_after_cas_current_head_required",
    "append_only_history_required",
    "stale_write_rejection_required",
    "automatic_retry_forbidden",
    "retention_and_delete_denial_readback_required",
}
_CUSTODY_FIELDS = {
    "three_distinct_authorities_required",
    "cross_domain_key_reuse",
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
    "generation_subject",
    "context_signature",
    "trusted_timestamp",
    "provider_head",
    "assertions",
    "integrity",
}
_ASSERTION_FIELDS = {
    "policy_configured",
    "context_signature_authenticated",
    "signer_role_scope_authorized",
    "anchor_window_valid",
    "revocation_snapshot_current",
    "timestamp_nonce_imprint_bound",
    "provider_current_head_authenticated",
    "provider_cas_precondition_ready",
    "global_fork_absence_proven",
    "global_rollback_protection_proven",
    "no_generation_publication_performed",
}


class GenerationContextTrustError(ValueError):
    """The external generation-context handoff template is not safe."""


def _invalid() -> GenerationContextTrustError:
    return GenerationContextTrustError(
        "target intake generation context handoff is invalid"
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


def _unconfigured_context_authority(value: object) -> None:
    authority = _closed(value, _AUTHORITY_FIELDS)
    if any(authority[key] != expected for key, expected in AUTHORITY_CONTRACT.items()):
        raise _invalid()
    if authority["state"] != "unconfigured" or any(
        authority[key] is not None
        for key in (
            "algorithm",
            "key_id",
            "public_key_b64url",
            "valid_from",
            "valid_until",
            "revocation_registry_reference",
            "revocation_registry_sha256",
        )
    ):
        raise _invalid()


def _unconfigured_trusted_timestamp(value: object) -> None:
    timestamp = _closed(value, _TRUSTED_TIMESTAMP_FIELDS)
    if any(
        timestamp[key] != expected
        for key, expected in TRUSTED_TIME_CONTRACT.items()
    ):
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
        or head["semantics"]
        != "provider_native_compare_and_swap_append_only_v1"
        or any(
            head[key] is not None
            for key in (
                "provider_kind",
                "provider_account_fingerprint_sha256",
                "namespace",
                "ledger_id",
            )
        )
        or any(
            head[key] is not True
            for key in (
                "caller_prior_head_required",
                "sequence_precondition_required",
                "generation_precondition_required",
                "immutable_version_required",
                "signed_cas_outcome_required",
                "read_after_cas_current_head_required",
                "append_only_history_required",
                "stale_write_rejection_required",
                "automatic_retry_forbidden",
                "retention_and_delete_denial_readback_required",
            )
        )
    ):
        raise _invalid()


def validate_policy(value: object) -> dict[str, Any]:
    policy = _closed(value, _POLICY_FIELDS)
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
        or policy["subject_domain"] != SUBJECT_DOMAIN
        or policy["required_subject_bindings"] != list(REQUIRED_SUBJECT_BINDINGS)
    ):
        raise _invalid()
    _unconfigured_context_authority(policy["context_authority"])
    _unconfigured_trusted_timestamp(policy["trusted_timestamp"])
    _unconfigured_provider_head(policy["provider_head"])
    custody = _closed(policy["custody_requirements"], _CUSTODY_FIELDS)
    if custody != {
        "three_distinct_authorities_required": True,
        "cross_domain_key_reuse": "forbidden",
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
    except GenerationContextTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


def validate_readiness(value: object, *, policy_artifact_sha256: str) -> dict[str, Any]:
    readiness = _closed(value, _READINESS_FIELDS)
    integrity = _closed(readiness["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in readiness.items() if key != "integrity"}
    assertions = _closed(readiness["assertions"], _ASSERTION_FIELDS)
    expected_assertions = {key: False for key in _ASSERTION_FIELDS}
    expected_assertions["no_generation_publication_performed"] = True
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
                "generation_subject",
                "context_signature",
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


def parse_readiness(
    raw: bytes, *, policy_artifact_sha256: str
) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        return validate_readiness(
            parse_unique_json_bytes(raw),
            policy_artifact_sha256=policy_artifact_sha256,
        )
    except GenerationContextTrustError:
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
        "target-intake-generation-context-handoff-ok "
        "status=unconfigured readiness=pending production_acceptance=false "
        "not_committed_eligible=false authoring-integration=disabled "
        "recovery-integration=disabled no-generation-publication-performed=true "
        f"policy_sha256={policy_sha256} "
        "policy-pin-authority=unverified "
        "context-signer-authentication=unverified "
        "context-signer-role-scope=unverified "
        "trust-anchor-validity=unverified "
        "trust-anchor-revocation=unverified "
        "trusted-timestamp=unverified "
        "timestamp-replay-protection=unverified "
        "provider-native-head=unverified provider-head-cas=unverified "
        "global-fork-protection=unverified global-rollback-protection=unverified"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the pending generation-context handoff contract."
    )
    parser.add_argument("command", choices=("verify-repository",))
    parser.parse_args(argv)
    try:
        print(verify_repository())
    except GenerationContextTrustError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
