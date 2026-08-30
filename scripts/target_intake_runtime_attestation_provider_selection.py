"""Validate one caller-pinned external evidence-custody provider selection.

The selection proves only that a closed profile chooses exactly one supported
provider and matches the repository policy.  It does not authenticate the
reviewer, call a cloud API, or establish provider-native custody.
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
from typing import Mapping

try:
    from scripts.external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )
except ModuleNotFoundError:
    from external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "runtime-attestation-provider-selection-policy.json"
SYNTHETIC_PROFILE = (
    ROOT / "deploy" / "runtime-attestation-provider-selection-profile.synthetic.json"
)
EXPECTED_POLICY_SHA256 = "1b678805c08f97331cd76aa1c1139fc095edd5271ba9f95d00546fa67e274581"
EXPECTED_SYNTHETIC_PROFILE_SHA256 = "8a507d52fb8367c3fc8563a4c8d32f6b9215ab4f78da14df3c41a1b22272b3c3"
PREDECESSOR_POLICY_SHA256 = "3c52cacdf836ba3c63288adf053871e8943cbe8c21676ce7c4fe1381a4820bbd"
MAX_PROFILE_BYTES = 131_072

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROVIDER_KINDS = [
    "aws_s3_object_lock",
    "azure_blob_immutable",
    "gcp_cloud_storage_generation",
]
_ADAPTER_CONTRACT = {
    "head_and_entry_must_be_distinct": True,
    "immutable_entry_write_once": True,
    "no_automatic_retry": True,
    "post_write_readback_required": True,
    "prior_head_must_be_caller_pinned": True,
    "stale_write_must_fail": True,
}
_PROFILE_REQUIREMENTS = [
    "external_approval_assertion",
    "caller_pinned_policy_and_profile",
    "authenticated_workload_identity_ref",
    "immutable_entry_namespace_ref",
    "mutable_head_locator_ref",
    "provider_native_cas",
    "no_automatic_retry",
    "post_write_readback",
    "retention_configuration_ref",
    "opaque_version_identity",
    "protected_version_delete_denial",
    "cross_host_latest_head",
    "fork_and_rollback_review",
]
_PROVIDER_SEMANTICS = {
    "aws_s3_object_lock": {
        "head_precondition": "if_match_etag",
        "immutability_control": "s3_object_lock_compliance",
        "stale_failure_outcomes": [
            "http_409_conflict",
            "http_412_precondition_failed",
        ],
        "version_identity_field": "version_id",
    },
    "azure_blob_immutable": {
        "head_precondition": "if_match_etag",
        "immutability_control": "azure_version_level_locked_time_retention",
        "stale_failure_outcomes": ["http_412_precondition_failed"],
        "version_identity_field": "version_id",
    },
    "gcp_cloud_storage_generation": {
        "head_precondition": "if_generation_match",
        "immutability_control": "gcs_locked_bucket_retention_policy",
        "stale_failure_outcomes": ["http_412_precondition_failed"],
        "version_identity_field": "generation",
    },
}

_POLICY_FIELDS = {
    "adapter_contract",
    "allowed_provider_kinds",
    "policy_kind",
    "policy_status",
    "predecessor",
    "production_acceptance",
    "profile_requirements",
    "provider_semantics",
    "schema_version",
    "selected_provider_kind",
    "synthetic",
}
_PREDECESSOR_FIELDS = {"policy_kind", "raw_sha256", "schema_version"}
_PROFILE_FIELDS = {
    "approval",
    "policy_sha256",
    "predecessor_policy_sha256",
    "production_acceptance",
    "profile_kind",
    "provider",
    "review_status",
    "schema_version",
    "selected_provider_kind",
    "synthetic",
}
_APPROVAL_FIELDS = {
    "decision_id",
    "provider_account_ref",
    "reviewed_at",
    "reviewer_ref",
    "target_environment",
    "valid_until",
}
_PROVIDER_FIELDS = {
    "head_precondition",
    "immutability_control",
    "immutable_entry_namespace_ref",
    "mutable_head_locator_ref",
    "namespace_ref",
    "no_automatic_retry",
    "post_write_readback_required",
    "protected_version_delete_denial_required",
    "stale_failure_outcomes",
    "version_identity_field",
    "workload_identity_ref",
}


class ProviderSelectionError(ValueError):
    """The provider selection is malformed, ambiguous, or overclaims authority."""


@dataclass(frozen=True)
class StableInput:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class VerifiedProviderSelection:
    policy_sha256: str
    profile_sha256: str
    selected_provider_kind: str
    target_environment: str
    decision_id: str
    predecessor_verified: bool
    selection_shape_verified: bool
    reviewer_authority_verified: bool = False
    provider_native_cas_verified: bool = False
    provider_custody_verified: bool = False
    production_acceptance: bool = False


def _invalid() -> ProviderSelectionError:
    return ProviderSelectionError("runtime-attestation provider selection is invalid")


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )


def _canonical_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_PROFILE_BYTES:
        raise _invalid()
    try:
        value = parse_unique_json_bytes(raw)
    except (TypeError, UnicodeError, ValueError) as error:
        raise _invalid() from error
    if not isinstance(value, Mapping) or raw != _canonical_bytes(value):
        raise _invalid()
    return dict(value)


def _closed(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _invalid()
    return dict(value)


def _sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _pin(raw: bytes, expected: str) -> str:
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, _sha256(expected)):
        raise _invalid()
    return actual


def _text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
    ):
        raise _invalid()
    return value


def _utc(value: object) -> datetime:
    text = _text(value)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise _invalid() from error
    return parsed


def _verify_policy(raw: bytes, expected_sha256: str) -> tuple[str, dict[str, object]]:
    actual = _pin(raw, expected_sha256)
    policy = _closed(_canonical_json(raw), _POLICY_FIELDS)
    predecessor = _closed(policy["predecessor"], _PREDECESSOR_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or policy["policy_kind"] != "runtime_attestation_provider_selection_policy"
        or policy["policy_status"] != "external_selection_required"
        or policy["synthetic"] is not False
        or policy["production_acceptance"] is not False
        or policy["selected_provider_kind"] is not None
        or policy["allowed_provider_kinds"] != _PROVIDER_KINDS
        or policy["adapter_contract"] != _ADAPTER_CONTRACT
        or policy["profile_requirements"] != _PROFILE_REQUIREMENTS
        or policy["provider_semantics"] != _PROVIDER_SEMANTICS
        or predecessor
        != {
            "policy_kind": "runtime_attestation_external_evidence_policy",
            "raw_sha256": PREDECESSOR_POLICY_SHA256,
            "schema_version": 1,
        }
    ):
        raise _invalid()
    return actual, policy


def _reject_placeholder(value: str) -> None:
    lowered = value.casefold()
    if any(
        marker in lowered
        for marker in ("synthetic", "example", "placeholder", ".invalid")
    ):
        raise _invalid()


def verify_provider_selection_bytes(
    *,
    policy_raw: bytes,
    profile_raw: bytes,
    expected_policy_sha256: str,
    expected_profile_sha256: str,
    allow_synthetic: bool = False,
) -> VerifiedProviderSelection:
    """Verify exact caller-pinned policy/profile bytes without external I/O."""

    policy_sha256, policy = _verify_policy(policy_raw, expected_policy_sha256)
    profile_sha256 = _pin(profile_raw, expected_profile_sha256)
    profile = _closed(_canonical_json(profile_raw), _PROFILE_FIELDS)
    synthetic = profile["synthetic"]
    if type(synthetic) is not bool or synthetic is not allow_synthetic:
        raise _invalid()
    if (
        type(profile["schema_version"]) is not int
        or profile["schema_version"] != 1
        or profile["profile_kind"]
        != "runtime_attestation_provider_selection_profile"
        or profile["production_acceptance"] is not False
        or profile["review_status"] != "approved_assertion"
        or profile["policy_sha256"] != policy_sha256
        or profile["predecessor_policy_sha256"] != PREDECESSOR_POLICY_SHA256
    ):
        raise _invalid()

    selected = profile["selected_provider_kind"]
    if not isinstance(selected, str) or selected not in policy["allowed_provider_kinds"]:
        raise _invalid()
    provider = _closed(profile["provider"], _PROVIDER_FIELDS)
    semantics = _PROVIDER_SEMANTICS[selected]
    for field in (
        "head_precondition",
        "immutability_control",
        "stale_failure_outcomes",
        "version_identity_field",
    ):
        if provider[field] != semantics[field]:
            raise _invalid()
    if (
        provider["no_automatic_retry"] is not True
        or provider["post_write_readback_required"] is not True
        or provider["protected_version_delete_denial_required"] is not True
    ):
        raise _invalid()

    references = [
        _text(provider[field])
        for field in (
            "immutable_entry_namespace_ref",
            "mutable_head_locator_ref",
            "namespace_ref",
            "workload_identity_ref",
        )
    ]
    if len(set(references)) != len(references):
        raise _invalid()

    approval = _closed(profile["approval"], _APPROVAL_FIELDS)
    decision_id = _text(approval["decision_id"])
    target_environment = _text(approval["target_environment"])
    approval_refs = [
        _text(approval[field])
        for field in ("provider_account_ref", "reviewer_ref")
    ]
    reviewed_at = _utc(approval["reviewed_at"])
    valid_until = _utc(approval["valid_until"])
    if reviewed_at >= valid_until:
        raise _invalid()
    if synthetic:
        if target_environment != "synthetic-fixture" or any(
            not value.startswith("synthetic://")
            for value in [*references, *approval_refs]
        ):
            raise _invalid()
    else:
        for value in [decision_id, target_environment, *references, *approval_refs]:
            _reject_placeholder(value)

    return VerifiedProviderSelection(
        policy_sha256=policy_sha256,
        profile_sha256=profile_sha256,
        selected_provider_kind=selected,
        target_environment=target_environment,
        decision_id=decision_id,
        predecessor_verified=True,
        selection_shape_verified=True,
    )


def _external_profile(path: Path) -> StableInput:
    if not path.is_absolute():
        raise _invalid()
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as error:
        raise _invalid() from error
    else:
        raise _invalid()
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            resolved, max_bytes=MAX_PROFILE_BYTES
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return StableInput(
        path=resolved,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _unchanged(value: StableInput) -> None:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            value.path,
            max_bytes=MAX_PROFILE_BYTES,
            expected_identity=value.identity,
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1 or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(), value.sha256
    ):
        raise _invalid()


def verify_external_profile(
    profile_path: Path | str,
    *,
    expected_policy_sha256: str,
    expected_profile_sha256: str,
) -> VerifiedProviderSelection:
    profile = _external_profile(Path(profile_path))
    result = verify_provider_selection_bytes(
        policy_raw=POLICY.read_bytes(),
        profile_raw=profile.raw,
        expected_policy_sha256=expected_policy_sha256,
        expected_profile_sha256=expected_profile_sha256,
    )
    _unchanged(profile)
    return result


def verify_repository_fixture() -> str:
    result = verify_provider_selection_bytes(
        policy_raw=POLICY.read_bytes(),
        profile_raw=SYNTHETIC_PROFILE.read_bytes(),
        expected_policy_sha256=EXPECTED_POLICY_SHA256,
        expected_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
        allow_synthetic=True,
    )
    return (
        "runtime-attestation-provider-selection-ok "
        f"selected={result.selected_provider_kind} synthetic=true "
        "reviewer-authority=unverified provider-native-cas=unverified "
        "provider-custody=unverified production_acceptance=false "
        f"policy_sha256={result.policy_sha256} "
        f"profile_sha256={result.profile_sha256}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify one caller-pinned external evidence provider selection."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-repository")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--profile", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-profile-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-repository":
            print(verify_repository_fixture())
        else:
            result = verify_external_profile(
                args.profile,
                expected_policy_sha256=args.expected_policy_sha256,
                expected_profile_sha256=args.expected_profile_sha256,
            )
            print(
                "runtime-attestation-provider-selection-ok "
                f"selected={result.selected_provider_kind} synthetic=false "
                "selection-shape=verified reviewer-authority=unverified "
                "provider-native-cas=unverified provider-custody=unverified "
                "production_acceptance=false "
                f"profile_sha256={result.profile_sha256}"
            )
    except (OSError, ProviderSelectionError) as error:
        print(f"runtime-attestation-provider-selection-error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
