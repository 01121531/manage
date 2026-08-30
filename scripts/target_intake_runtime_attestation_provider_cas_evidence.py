"""Validate a caller-pinned external provider CAS evidence package.

This verifier binds a reviewed T209 selection profile, one canonical evidence
manifest, and nine exact raw artifacts.  It performs no cloud operation and
does not authenticate provider responses, reviewer identity, or trusted time.
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
    from scripts.target_intake_runtime_attestation_provider_selection import (
        EXPECTED_POLICY_SHA256 as SELECTION_POLICY_SHA256,
        POLICY as SELECTION_POLICY,
        ProviderSelectionError,
        verify_provider_selection_bytes,
    )
except ModuleNotFoundError:
    from external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )
    from target_intake_runtime_attestation_provider_selection import (
        EXPECTED_POLICY_SHA256 as SELECTION_POLICY_SHA256,
        POLICY as SELECTION_POLICY,
        ProviderSelectionError,
        verify_provider_selection_bytes,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "runtime-attestation-provider-cas-evidence-policy.json"
SYNTHETIC_EVIDENCE = (
    ROOT / "deploy" / "runtime-attestation-provider-cas-evidence.synthetic.json"
)
SYNTHETIC_PROFILE = (
    ROOT / "deploy" / "runtime-attestation-provider-selection-profile.synthetic.json"
)
SYNTHETIC_ARTIFACT_ROOT = (
    ROOT / "deploy" / "runtime-attestation-provider-cas-fixture"
)
EXPECTED_POLICY_SHA256 = "ca4be029992e21d2f21fc9bc0462685d29807a2e9435d62d4312d79b943fd59d"
EXPECTED_SYNTHETIC_PROFILE_SHA256 = (
    "8a507d52fb8367c3fc8563a4c8d32f6b9215ab4f78da14df3c41a1b22272b3c3"
)
EXPECTED_SYNTHETIC_EVIDENCE_SHA256 = (
    "03adbba3dc1083314766a5fa1311859696a5b81c3793f01a1558576d3289fe88"
)
EXTERNAL_MANIFEST_NAME = "runtime-attestation-provider-cas-evidence.json"
MAX_JSON_BYTES = 262_144
MAX_ARTIFACT_BYTES = 4_194_304

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROVIDER_KINDS = [
    "aws_s3_object_lock",
    "azure_blob_immutable",
    "gcp_cloud_storage_generation",
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
_ARTIFACT_INVENTORY = [
    {
        "kind": "immutable_entry_write",
        "media_type": "application/json",
        "path": "immutable-entry-write.json",
    },
    {
        "kind": "successful_head_cas",
        "media_type": "application/json",
        "path": "successful-head-cas.json",
    },
    {
        "kind": "immutable_entry_readback",
        "media_type": "application/json",
        "path": "immutable-entry-readback.json",
    },
    {
        "kind": "stale_head_cas",
        "media_type": "application/json",
        "path": "stale-head-cas.json",
    },
    {
        "kind": "current_head_readback",
        "media_type": "application/json",
        "path": "current-head-readback.json",
    },
    {
        "kind": "retention_configuration",
        "media_type": "application/json",
        "path": "retention-configuration.json",
    },
    {
        "kind": "protected_version_delete_denial",
        "media_type": "application/json",
        "path": "protected-version-delete-denial.json",
    },
    {
        "kind": "post_denial_readback",
        "media_type": "application/json",
        "path": "post-denial-readback.json",
    },
    {
        "kind": "cross_host_review",
        "media_type": "application/json",
        "path": "cross-host-review.json",
    },
]
_EVIDENCE_CONTRACT = {
    "cross_host_writers_required": True,
    "current_head_readback_required": True,
    "evidence_caller_pinned": True,
    "immutable_entry_readback_required": True,
    "no_automatic_retry": True,
    "post_denial_readback_required": True,
    "prior_head_caller_pinned": True,
    "protected_version_delete_denial_required": True,
    "retention_configuration_required": True,
    "selection_profile_caller_pinned": True,
    "stale_write_attempt_exactly_once": True,
    "success_write_exactly_once": True,
}

_POLICY_FIELDS = {
    "artifact_inventory",
    "evidence_contract",
    "policy_kind",
    "policy_status",
    "predecessor",
    "production_acceptance",
    "provider_semantics",
    "schema_version",
    "synthetic",
}
_PREDECESSOR_FIELDS = {"policy_kind", "raw_sha256", "schema_version"}
_EVIDENCE_FIELDS = {
    "actors",
    "artifacts",
    "evidence_kind",
    "execution",
    "execution_window",
    "policy_sha256",
    "production_acceptance",
    "provider_account_ref",
    "review",
    "schema_version",
    "selected_provider_kind",
    "selection_policy_sha256",
    "selection_profile_sha256",
    "synthetic",
    "target_environment",
}
_ACTOR_FIELDS = {
    "stale_writer_host_ref",
    "successful_writer_host_ref",
    "workload_identity_ref",
}
_EXECUTION_FIELDS = {
    "cross_host_review",
    "delete_denial",
    "entry",
    "head",
    "retention",
}
_WINDOW_FIELDS = {"finished_at", "started_at"}
_ENTRY_FIELDS = {
    "immutable_entry_ref",
    "opaque_version_identity",
    "payload_sha256",
    "readback_observed_at",
    "readback_payload_sha256",
    "readback_version_identity",
    "version_identity_field",
    "write_observed_at",
    "write_request_id",
}
_HEAD_FIELDS = {
    "head_precondition_kind",
    "mutable_head_locator_ref",
    "prior_head_precondition",
    "prior_head_value",
    "proposed_head_payload_sha256",
    "proposed_head_value",
    "readback_head_value",
    "readback_observed_at",
    "readback_payload_sha256",
    "readback_version_identity",
    "stale_attempted_head_value",
    "stale_automatic_retry_count",
    "stale_observed_at",
    "stale_outcome",
    "stale_precondition",
    "stale_request_id",
    "success_observed_at",
    "success_outcome",
    "success_request_id",
    "successful_version_identity",
    "version_identity_field",
}
_RETENTION_FIELDS = {
    "immutability_control",
    "locked",
    "observed_at",
    "protected_until",
    "retention_configuration_ref",
}
_DELETE_FIELDS = {
    "observed_at",
    "opaque_version_identity",
    "outcome",
    "post_denial_observed_at",
    "post_denial_payload_sha256",
    "post_denial_version_identity",
    "request_id",
}
_CROSS_HOST_FIELDS = {
    "fork_detected",
    "latest_head_value",
    "observed_at",
    "rollback_detected",
}
_REVIEW_FIELDS = {"conclusion", "reviewed_at", "reviewer_ref", "valid_until"}
_ARTIFACT_FIELDS = {"kind", "media_type", "path", "raw_sha256", "size"}


class ProviderCasEvidenceError(ValueError):
    """The provider CAS evidence package is invalid or overclaims authority."""


@dataclass(frozen=True)
class StableInput:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class VerifiedProviderCasEvidence:
    policy_sha256: str
    selection_profile_sha256: str
    evidence_sha256: str
    selected_provider_kind: str
    artifact_count: int
    selection_shape_verified: bool
    evidence_shape_verified: bool
    artifact_bytes_bound: bool
    cross_host_writers_distinct: bool
    reviewer_authority_verified: bool = False
    provider_response_authentication_verified: bool = False
    provider_native_cas_verified: bool = False
    retention_delete_denial_verified: bool = False
    provider_custody_verified: bool = False
    trusted_time_verified: bool = False
    production_acceptance: bool = False


def _invalid() -> ProviderCasEvidenceError:
    return ProviderCasEvidenceError(
        "runtime-attestation provider CAS evidence is invalid"
    )


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )


def _canonical_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
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


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _pin(raw: bytes, expected: str) -> str:
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, _sha(expected)):
        raise _invalid()
    return actual


def _text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(ord(character) < 32 for character in value)
    ):
        raise _invalid()
    return value


def _utc(value: object) -> datetime:
    text = _text(value)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise _invalid() from error


def _reject_placeholder(value: str) -> None:
    lowered = value.casefold()
    if any(
        marker in lowered
        for marker in ("synthetic", "example", "placeholder", ".invalid")
    ):
        raise _invalid()


def _verify_policy(raw: bytes, expected_sha256: str) -> str:
    actual = _pin(raw, expected_sha256)
    policy = _closed(_canonical_json(raw), _POLICY_FIELDS)
    predecessor = _closed(policy["predecessor"], _PREDECESSOR_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or policy["policy_kind"]
        != "runtime_attestation_provider_cas_evidence_policy"
        or policy["policy_status"] != "external_execution_required"
        or policy["synthetic"] is not False
        or policy["production_acceptance"] is not False
        or policy["artifact_inventory"] != _ARTIFACT_INVENTORY
        or policy["evidence_contract"] != _EVIDENCE_CONTRACT
        or policy["provider_semantics"] != _PROVIDER_SEMANTICS
        or predecessor
        != {
            "policy_kind": "runtime_attestation_provider_selection_policy",
            "raw_sha256": SELECTION_POLICY_SHA256,
            "schema_version": 1,
        }
    ):
        raise _invalid()
    return actual


def _verify_artifacts(
    evidence_items: object,
    artifact_bytes: Mapping[str, bytes],
    *,
    allow_synthetic: bool,
) -> None:
    if not isinstance(evidence_items, list) or len(evidence_items) != len(
        _ARTIFACT_INVENTORY
    ):
        raise _invalid()
    expected_paths = {item["path"] for item in _ARTIFACT_INVENTORY}
    if set(artifact_bytes) != expected_paths:
        raise _invalid()
    for expected, value in zip(_ARTIFACT_INVENTORY, evidence_items, strict=True):
        item = _closed(value, _ARTIFACT_FIELDS)
        if any(item[field] != expected[field] for field in ("kind", "media_type", "path")):
            raise _invalid()
        raw = artifact_bytes[expected["path"]]
        if (
            type(raw) is not bytes
            or not raw
            or len(raw) > MAX_ARTIFACT_BYTES
            or type(item["size"]) is not int
            or item["size"] != len(raw)
            or not hmac.compare_digest(
                _sha(item["raw_sha256"]), hashlib.sha256(raw).hexdigest()
            )
        ):
            raise _invalid()
        if not allow_synthetic and any(
            marker in raw.lower()
            for marker in (b"synthetic", b"placeholder", b".invalid")
        ):
            raise _invalid()


def verify_provider_cas_evidence_bytes(
    *,
    selection_policy_raw: bytes,
    selection_profile_raw: bytes,
    policy_raw: bytes,
    evidence_raw: bytes,
    artifact_bytes: Mapping[str, bytes],
    expected_policy_sha256: str,
    expected_selection_profile_sha256: str,
    expected_evidence_sha256: str,
    allow_synthetic: bool = False,
) -> VerifiedProviderCasEvidence:
    """Verify exact package bytes without network, process, signing, or host time."""

    policy_sha256 = _verify_policy(policy_raw, expected_policy_sha256)
    try:
        selection = verify_provider_selection_bytes(
            policy_raw=selection_policy_raw,
            profile_raw=selection_profile_raw,
            expected_policy_sha256=SELECTION_POLICY_SHA256,
            expected_profile_sha256=expected_selection_profile_sha256,
            allow_synthetic=allow_synthetic,
        )
    except ProviderSelectionError as error:
        raise _invalid() from error
    profile = _canonical_json(selection_profile_raw)
    provider = dict(profile["provider"])
    approval = dict(profile["approval"])
    evidence_sha256 = _pin(evidence_raw, expected_evidence_sha256)
    evidence = _closed(_canonical_json(evidence_raw), _EVIDENCE_FIELDS)
    synthetic = evidence["synthetic"]
    if type(synthetic) is not bool or synthetic is not allow_synthetic:
        raise _invalid()
    selected = selection.selected_provider_kind
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != 1
        or evidence["evidence_kind"]
        != "runtime_attestation_provider_cas_evidence"
        or evidence["production_acceptance"] is not False
        or evidence["policy_sha256"] != policy_sha256
        or evidence["selection_policy_sha256"] != SELECTION_POLICY_SHA256
        or evidence["selection_profile_sha256"] != selection.profile_sha256
        or evidence["selected_provider_kind"] != selected
        or evidence["target_environment"] != selection.target_environment
        or evidence["provider_account_ref"] != approval["provider_account_ref"]
        or selected not in _PROVIDER_KINDS
    ):
        raise _invalid()
    _verify_artifacts(
        evidence["artifacts"], artifact_bytes, allow_synthetic=allow_synthetic
    )

    actors = _closed(evidence["actors"], _ACTOR_FIELDS)
    successful_host = _text(actors["successful_writer_host_ref"])
    stale_host = _text(actors["stale_writer_host_ref"])
    workload_identity = _text(actors["workload_identity_ref"])
    if (
        successful_host == stale_host
        or workload_identity != provider["workload_identity_ref"]
    ):
        raise _invalid()

    window = _closed(evidence["execution_window"], _WINDOW_FIELDS)
    started_at = _utc(window["started_at"])
    finished_at = _utc(window["finished_at"])
    review = _closed(evidence["review"], _REVIEW_FIELDS)
    reviewed_at = _utc(review["reviewed_at"])
    valid_until = _utc(review["valid_until"])
    profile_reviewed_at = _utc(approval["reviewed_at"])
    profile_valid_until = _utc(approval["valid_until"])
    reviewer_ref = _text(review["reviewer_ref"])
    if (
        review["conclusion"]
        != "structurally_complete_unverified_provider_evidence"
        or not (
            profile_reviewed_at <= started_at
            < finished_at
            < reviewed_at
            < valid_until
            <= profile_valid_until
        )
        or reviewer_ref in {successful_host, stale_host, workload_identity}
    ):
        raise _invalid()

    execution = _closed(evidence["execution"], _EXECUTION_FIELDS)
    entry = _closed(execution["entry"], _ENTRY_FIELDS)
    head = _closed(execution["head"], _HEAD_FIELDS)
    retention = _closed(execution["retention"], _RETENTION_FIELDS)
    delete_denial = _closed(execution["delete_denial"], _DELETE_FIELDS)
    cross_host = _closed(execution["cross_host_review"], _CROSS_HOST_FIELDS)
    semantics = _PROVIDER_SEMANTICS[selected]

    entry_ref = _text(entry["immutable_entry_ref"])
    entry_namespace = _text(provider["immutable_entry_namespace_ref"])
    entry_version = _text(entry["opaque_version_identity"])
    entry_payload = _sha(entry["payload_sha256"])
    if (
        not entry_ref.startswith(entry_namespace.rstrip("/") + "/")
        or entry_ref == provider["mutable_head_locator_ref"]
        or entry["version_identity_field"] != semantics["version_identity_field"]
        or entry["readback_version_identity"] != entry_version
        or entry["readback_payload_sha256"] != entry_payload
    ):
        raise _invalid()

    prior_value = _text(head["prior_head_value"])
    proposed_value = _text(head["proposed_head_value"])
    stale_value = _text(head["stale_attempted_head_value"])
    prior_precondition = _text(head["prior_head_precondition"])
    successful_head_version = _text(head["successful_version_identity"])
    proposed_payload = _sha(head["proposed_head_payload_sha256"])
    if (
        len({prior_value, proposed_value, stale_value}) != 3
        or head["mutable_head_locator_ref"] != provider["mutable_head_locator_ref"]
        or head["head_precondition_kind"] != semantics["head_precondition"]
        or head["version_identity_field"] != semantics["version_identity_field"]
        or head["stale_precondition"] != prior_precondition
        or head["success_outcome"] != "succeeded"
        or head["stale_outcome"] not in semantics["stale_failure_outcomes"]
        or type(head["stale_automatic_retry_count"]) is not int
        or head["stale_automatic_retry_count"] != 0
        or head["readback_head_value"] != proposed_value
        or head["readback_payload_sha256"] != proposed_payload
        or head["readback_version_identity"] != successful_head_version
    ):
        raise _invalid()

    request_ids = {
        _text(entry["write_request_id"]),
        _text(head["success_request_id"]),
        _text(head["stale_request_id"]),
        _text(delete_denial["request_id"]),
    }
    if len(request_ids) != 4:
        raise _invalid()

    protected_until = _utc(retention["protected_until"])
    retention_ref = _text(retention["retention_configuration_ref"])
    if (
        retention["immutability_control"] != semantics["immutability_control"]
        or retention["locked"] is not True
        or protected_until <= valid_until
        or retention_ref in {entry_ref, provider["mutable_head_locator_ref"]}
    ):
        raise _invalid()

    if (
        delete_denial["outcome"] != "denied"
        or delete_denial["opaque_version_identity"] != entry_version
        or delete_denial["post_denial_version_identity"] != entry_version
        or delete_denial["post_denial_payload_sha256"] != entry_payload
        or cross_host["fork_detected"] is not False
        or cross_host["rollback_detected"] is not False
        or cross_host["latest_head_value"] != proposed_value
    ):
        raise _invalid()

    observed = [
        _utc(entry["write_observed_at"]),
        _utc(head["success_observed_at"]),
        _utc(entry["readback_observed_at"]),
        _utc(head["stale_observed_at"]),
        _utc(head["readback_observed_at"]),
        _utc(retention["observed_at"]),
        _utc(delete_denial["observed_at"]),
        _utc(delete_denial["post_denial_observed_at"]),
        _utc(cross_host["observed_at"]),
    ]
    if not (
        started_at <= observed[0]
        and all(left < right for left, right in zip(observed, observed[1:]))
        and observed[-1] <= finished_at
    ):
        raise _invalid()

    references = [
        successful_host,
        stale_host,
        workload_identity,
        reviewer_ref,
        entry_ref,
        _text(head["mutable_head_locator_ref"]),
        retention_ref,
        _text(evidence["provider_account_ref"]),
        _text(evidence["target_environment"]),
    ]
    if synthetic:
        if any(not value.startswith("synthetic") for value in references[:-1]):
            raise _invalid()
    else:
        for value in references:
            _reject_placeholder(value)

    return VerifiedProviderCasEvidence(
        policy_sha256=policy_sha256,
        selection_profile_sha256=selection.profile_sha256,
        evidence_sha256=evidence_sha256,
        selected_provider_kind=selected,
        artifact_count=len(_ARTIFACT_INVENTORY),
        selection_shape_verified=True,
        evidence_shape_verified=True,
        artifact_bytes_bound=True,
        cross_host_writers_distinct=True,
    )


def _outside_repository(path: Path, *, directory: bool = False) -> Path:
    if not path.is_absolute():
        raise _invalid()
    try:
        direct_metadata = path.lstat()
        if path.is_symlink() or getattr(direct_metadata, "st_file_attributes", 0) & 0x400:
            raise _invalid()
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ProviderCasEvidenceError:
        raise
    except ValueError:
        pass
    except OSError as error:
        raise _invalid() from error
    else:
        raise _invalid()
    if resolved.is_symlink() or (directory and not resolved.is_dir()):
        raise _invalid()
    return resolved


def _read_external(path: Path, *, maximum: int) -> StableInput:
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=maximum)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1 or getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise _invalid()
    return StableInput(
        path=path,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _unchanged(value: StableInput, *, maximum: int) -> None:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            value.path, max_bytes=maximum, expected_identity=value.identity
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if (
        metadata.st_nlink != 1
        or getattr(metadata, "st_file_attributes", 0) & 0x400
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), value.sha256)
    ):
        raise _invalid()


def verify_external_evidence_package(
    *,
    selection_profile_path: Path | str,
    evidence_manifest_path: Path | str,
    evidence_root: Path | str,
    expected_policy_sha256: str,
    expected_selection_profile_sha256: str,
    expected_evidence_sha256: str,
) -> VerifiedProviderCasEvidence:
    profile_path = _outside_repository(Path(selection_profile_path))
    manifest_path = _outside_repository(Path(evidence_manifest_path))
    root = _outside_repository(Path(evidence_root), directory=True)
    if (
        manifest_path.parent != root
        or manifest_path.name != EXTERNAL_MANIFEST_NAME
    ):
        raise _invalid()
    expected_names = {EXTERNAL_MANIFEST_NAME, *[item["path"] for item in _ARTIFACT_INVENTORY]}
    try:
        children = list(root.iterdir())
    except OSError as error:
        raise _invalid() from error
    if {child.name for child in children} != expected_names or any(
        child.parent != root or child.is_symlink() or not child.is_file()
        for child in children
    ):
        raise _invalid()

    profile = _read_external(profile_path, maximum=MAX_JSON_BYTES)
    manifest = _read_external(manifest_path, maximum=MAX_JSON_BYTES)
    artifacts: dict[str, StableInput] = {}
    for item in _ARTIFACT_INVENTORY:
        path = root / item["path"]
        artifacts[item["path"]] = _read_external(path, maximum=MAX_ARTIFACT_BYTES)
    result = verify_provider_cas_evidence_bytes(
        selection_policy_raw=SELECTION_POLICY.read_bytes(),
        selection_profile_raw=profile.raw,
        policy_raw=POLICY.read_bytes(),
        evidence_raw=manifest.raw,
        artifact_bytes={name: value.raw for name, value in artifacts.items()},
        expected_policy_sha256=expected_policy_sha256,
        expected_selection_profile_sha256=expected_selection_profile_sha256,
        expected_evidence_sha256=expected_evidence_sha256,
    )
    _unchanged(profile, maximum=MAX_JSON_BYTES)
    _unchanged(manifest, maximum=MAX_JSON_BYTES)
    for value in artifacts.values():
        _unchanged(value, maximum=MAX_ARTIFACT_BYTES)
    return result


def verify_repository_fixture() -> str:
    artifacts = {
        item["path"]: (SYNTHETIC_ARTIFACT_ROOT / item["path"]).read_bytes()
        for item in _ARTIFACT_INVENTORY
    }
    result = verify_provider_cas_evidence_bytes(
        selection_policy_raw=SELECTION_POLICY.read_bytes(),
        selection_profile_raw=SYNTHETIC_PROFILE.read_bytes(),
        policy_raw=POLICY.read_bytes(),
        evidence_raw=SYNTHETIC_EVIDENCE.read_bytes(),
        artifact_bytes=artifacts,
        expected_policy_sha256=EXPECTED_POLICY_SHA256,
        expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
        expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
        allow_synthetic=True,
    )
    return (
        "runtime-attestation-provider-cas-evidence-ok "
        f"selected={result.selected_provider_kind} artifacts={result.artifact_count} "
        "selection-shape=verified evidence-shape=verified artifact-bytes=bound "
        "reviewer-authority=unverified provider-response-authentication=unverified "
        "provider-native-cas=unverified retention-delete-denial=unverified "
        "provider-custody=unverified trusted-time=unverified "
        "production_acceptance=false "
        f"policy_sha256={result.policy_sha256} evidence_sha256={result.evidence_sha256}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify one caller-pinned external provider CAS evidence package."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-repository")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--selection-profile", required=True)
    verify.add_argument("--evidence-manifest", required=True)
    verify.add_argument("--evidence-root", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-selection-profile-sha256", required=True)
    verify.add_argument("--expected-evidence-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-repository":
            print(verify_repository_fixture())
        else:
            result = verify_external_evidence_package(
                selection_profile_path=args.selection_profile,
                evidence_manifest_path=args.evidence_manifest,
                evidence_root=args.evidence_root,
                expected_policy_sha256=args.expected_policy_sha256,
                expected_selection_profile_sha256=args.expected_selection_profile_sha256,
                expected_evidence_sha256=args.expected_evidence_sha256,
            )
            print(
                "runtime-attestation-provider-cas-evidence-ok "
                f"selected={result.selected_provider_kind} synthetic=false "
                f"artifacts={result.artifact_count} evidence-shape=verified "
                "artifact-bytes=bound reviewer-authority=unverified "
                "provider-response-authentication=unverified "
                "provider-native-cas=unverified retention-delete-denial=unverified "
                "provider-custody=unverified trusted-time=unverified "
                "production_acceptance=false "
                f"evidence_sha256={result.evidence_sha256}"
            )
    except (OSError, ProviderCasEvidenceError) as error:
        print(f"runtime-attestation-provider-cas-evidence-error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
