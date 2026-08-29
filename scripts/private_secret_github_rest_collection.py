"""Verify an external GitHub REST projection and replay-ledger handoff offline.

This module never contacts GitHub, signs data, mutates a replay ledger, or
writes evidence.  It authenticates assertions made by two separately pinned
Ed25519 key holders.  GitHub REST fields remain collector assertions rather
than provider-signed facts, and same-run job/artifact presence does not prove
that the selected job uploaded the selected artifact.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)
from scripts import private_secret_github_attestation as github_attestation
from scripts import private_secret_collector_deployment as collector_deployment


POLICY = ROOT / "deploy" / "github-rest-collection-policy.synthetic.json"
SYNTHETIC = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-github-rest-collection.synthetic.json"
)

SCHEMA_VERSION = 1
POLICY_KIND = "github_rest_collection_trust_policy"
REQUEST_KIND = "private_secret_github_rest_collection_request"
EVIDENCE_KIND = "private_secret_github_rest_collection"
CHECKPOINT_KIND = "github_rest_collection_replay_checkpoint"
API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
COLLECTOR_DOMAIN = "email-platform/private-secret-github-rest-collector/v1"
LEDGER_DOMAIN = "email-platform/private-secret-github-rest-replay-ledger/v1"

MAX_JSON_BYTES = 512 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_PAGES = 16

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
_MEMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_NUMERIC_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_B64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64URL_64 = re.compile(r"^[A-Za-z0-9_-]{86}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")

_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "repository",
    "allowed_workflow_paths",
    "allowed_job_names",
    "source",
    "api",
    "collector",
    "replay_ledger",
    "time_constraints",
    "review",
}
_ANCHOR_FIELDS = {"algorithm", "key_id", "public_key_b64url", "signature_domain"}
_REPOSITORY_FIELDS = {
    "name",
    "repository_id",
    "repository_owner_id",
    "visibility",
}
_SOURCE_FIELDS = {"event", "source_ref"}
_API_FIELDS = {"origin", "version", "endpoint_kinds", "max_pages"}
_TIME_FIELDS = {
    "max_request_to_acquisition_seconds",
    "max_acquisition_seconds",
    "max_acquisition_to_signature_seconds",
    "max_signature_to_record_seconds",
}
_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}

_REQUEST_FIELDS = {
    "schema_version",
    "request_kind",
    "synthetic",
    "production_acceptance",
    "not_committed_eligible",
    "request_id",
    "nonce_b64url",
    "requested_at",
    "expires_at",
    "trust_policy_sha256",
    "collector_profile",
    "github_origin",
    "previous_head",
    "subject",
    "repository",
    "workflow",
    "job",
    "artifact",
}
_GITHUB_ORIGIN_FIELDS = {"artifact_sha256"}
_PREVIOUS_REQUEST_FIELDS = {"ledger_id", "expected_sequence", "artifact_sha256"}
_SUBJECT_FIELDS = {"artifact_sha256", "payload_sha256", "attempt_id"}
_REQUEST_WORKFLOW_FIELDS = {
    "run_id",
    "run_attempt",
    "workflow_path",
    "source_commit",
    "source_ref",
    "event",
}
_REQUEST_JOB_FIELDS = {"name"}
_COLLECTOR_PROFILE_FIELDS = {
    "policy_artifact_sha256",
    "deployment_id",
    "environment",
    "account_fingerprint_sha256",
    "cluster_fingerprint_sha256",
    "release_commit",
    "release_manifest_sha256",
    "target_intake_sha256",
    "runner_manifest_digest",
    "collector_binary_sha256",
    "entrypoint_contract_sha256",
    "workload_identity_fingerprint_sha256",
}
_REQUEST_ARTIFACT_FIELDS = {
    "artifact_id", "name", "subject_member_path", "archive_sha256",
}

_EVIDENCE_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "production_acceptance",
    "not_committed_eligible",
    "collection_payload",
    "collector_signature",
    "replay_head",
    "claim_boundary",
    "prohibited_content",
}
_CLAIM_BOUNDARY_FIELDS = {
    "job_artifact_causality",
    "provider_native",
    "trusted_time",
    "freshness",
    "replay_protection",
    "durability",
    "reviewer_independence",
}
_PROHIBITED_FIELDS = {
    "contains_token_values",
    "contains_authorization_headers",
    "contains_bundle_url",
    "contains_archive_download_url",
    "contains_raw_rest_response",
    "contains_raw_logs",
    "contains_personal_data",
}
_COLLECTION_FIELDS = {
    "request_binding",
    "trust_policy_sha256",
    "acquisition",
    "endpoint_snapshots",
    "projection",
}
_REQUEST_BINDING_FIELDS = {
    "artifact_sha256",
    "payload_sha256",
    "github_origin_artifact_sha256",
    "request_id",
    "nonce_b64url",
    "collector_readiness_artifact_sha256",
}
_ACQUISITION_FIELDS = {
    "api_origin",
    "api_version",
    "started_at",
    "completed_at",
    "signed_at",
}
_ENDPOINT_KINDS = (
    "get_workflow_run_attempt",
    "list_jobs_for_workflow_run_attempt",
    "list_workflow_run_artifacts",
    "get_workflow_artifact_redirect",
    "download_workflow_artifact",
    "list_repository_attestations",
    "download_attestation_bundle",
)
_ENDPOINT_FIELDS = {
    "endpoint_kind",
    "pagination_complete",
    "raw_response_sha256s",
}
_REDIRECT_ENDPOINT_FIELDS = {
    "endpoint_kind", "request_method", "request_origin", "response_status",
    "location_count", "location_url_sha256", "location_origin", "redirect_mode",
    "followed_automatically", "authorization_sent_to_source",
    "authorization_forwarded", "cookie_forwarded",
    "proxy_authorization_forwarded", "raw_response_sha256s",
}
_DOWNLOAD_ENDPOINT_FIELDS = {
    "endpoint_kind", "request_method", "request_url_sha256", "request_origin",
    "authorization_sent", "cookie_sent", "proxy_authorization_sent",
    "response_status", "further_redirect", "raw_body_sha256", "raw_body_size",
}
_PROJECTION_FIELDS = {"repository", "workflow", "job", "artifact", "attestation"}
_WORKFLOW_FIELDS = {
    "run_id",
    "run_attempt",
    "workflow_id",
    "workflow_path",
    "source_commit",
    "source_ref",
    "event",
    "status",
    "conclusion",
    "repository_id",
    "head_repository_id",
    "check_suite_id",
}
_JOB_FIELDS = {
    "job_id",
    "name",
    "run_id",
    "head_sha",
    "status",
    "conclusion",
    "check_run_id",
    "check_run_url",
    "matching_job_count",
}
_ARTIFACT_FIELDS = {
    "artifact_id",
    "name",
    "archive_digest_sha256",
    "subject_artifact_sha256",
    "subject_payload_sha256",
    "subject_member_path",
    "subject_binding_method",
    "workflow_run_id",
    "repository_id",
    "head_repository_id",
    "head_sha",
    "expired",
    "matching_artifact_count",
}
_ATTESTATION_FIELDS = {
    "subject_digest",
    "repository_id",
    "bundle_artifact_sha256",
    "bundle_url_sha256",
    "bundle_origin",
    "predicate_type",
    "matching_bundle_count",
}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}

_HEAD_FIELDS = {"checkpoint", "signature"}
_CHECKPOINT_FIELDS = {
    "schema_version",
    "checkpoint_kind",
    "ledger_id",
    "sequence",
    "genesis",
    "collection_payload_sha256",
    "collector_signature_sha256",
    "request_artifact_sha256",
    "previous_head_artifact_sha256",
    "previous_checkpoint_payload_sha256",
    "recorded_at",
}


class GitHubRestCollectionError(ValueError):
    """The external collector handoff is invalid or cannot be trusted."""


def _invalid() -> GitHubRestCollectionError:
    return GitHubRestCollectionError("private secret GitHub REST collection is invalid")


@dataclass(frozen=True)
class StableBlob:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class BytesBlob:
    raw: bytes
    sha256: str


@dataclass(frozen=True)
class Anchor:
    key_id: str
    public_key: bytes
    domain: str


@dataclass(frozen=True)
class VerifiedCollection:
    attempt_id: str
    deployment_id: str
    request_id: str
    collector_key_id: str
    ledger_key_id: str
    ledger_id: str
    sequence: int
    receipt_sha256: str
    request_sha256: str
    replay_head_sha256: str
    raw_response_set_sha256: str
    policy_sha256: str
    deployment_policy_sha256: str
    readiness_sha256: str
    previous_head_sha256: str
    current_worm_collection_head_sha256: str


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _positive_id(value: object) -> int:
    if type(value) is not int or value < 1 or value > 2**63 - 1:
        raise _invalid()
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _invalid() from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _invalid()
    return parsed


def _sealed(value: object, fields: set[str]) -> dict[str, Any]:
    document = _closed(value, {*fields, "integrity"})
    integrity = _closed(document["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in document.items() if key != "integrity"}
    if not hmac.compare_digest(
        _digest(integrity["payload_sha256"]), _canonical_digest(payload)
    ):
        raise _invalid()
    return document


def _external_path(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return path
    raise _invalid()


def _read_blob(
    path: Path | str, *, external: bool = True, max_bytes: int = MAX_JSON_BYTES
) -> StableBlob:
    target = _external_path(path) if external else Path(path)
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            target, max_bytes=max_bytes
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return StableBlob(
        target,
        raw,
        stable_file_identity(metadata),
        hashlib.sha256(raw).hexdigest(),
    )


def _unchanged(blob: StableBlob) -> None:
    current = _read_blob(blob.path, max_bytes=max(MAX_JSON_BYTES, len(blob.raw)))
    if current.identity != blob.identity or not hmac.compare_digest(
        current.sha256, blob.sha256
    ):
        raise _invalid()


def _document(blob: StableBlob | BytesBlob) -> object:
    try:
        return parse_unique_json_bytes(blob.raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error


def _bytes_blob(raw: bytes, *, max_bytes: int = MAX_JSON_BYTES) -> BytesBlob:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise _invalid()
    return BytesBlob(raw=raw, sha256=hashlib.sha256(raw).hexdigest())


def _decode_b64url(value: object, *, pattern: re.Pattern[str], size: int) -> bytes:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _invalid()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise _invalid() from error
    if len(raw) != size or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise _invalid()
    return raw


def _anchor(value: object, *, expected_domain: str) -> Anchor:
    anchor = _closed(value, _ANCHOR_FIELDS)
    if anchor["algorithm"] != "Ed25519" or anchor["signature_domain"] != expected_domain:
        raise _invalid()
    public_key = _decode_b64url(
        anchor["public_key_b64url"], pattern=_B64URL_32, size=32
    )
    key_id = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if not isinstance(anchor["key_id"], str) or not hmac.compare_digest(
        anchor["key_id"], key_id
    ):
        raise _invalid()
    try:
        Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as error:
        raise _invalid() from error
    return Anchor(key_id, public_key, expected_domain)


def _verify_signature(payload: Mapping[str, object], value: object, anchor: Anchor) -> None:
    signature = _closed(value, _SIGNATURE_FIELDS)
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
        or not hmac.compare_digest(signature["key_id"], anchor.key_id)
    ):
        raise _invalid()
    raw = _decode_b64url(signature["value_b64url"], pattern=_B64URL_64, size=64)
    message = anchor.domain.encode("ascii") + b"\0" + _canonical_bytes(payload)
    try:
        Ed25519PublicKey.from_public_bytes(anchor.public_key).verify(raw, message)
    except (InvalidSignature, ValueError) as error:
        raise _invalid() from error


def validate_policy(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    policy = _sealed(value, _POLICY_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "offline_external_collection_authentication_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
    ):
        raise _invalid()
    optional = (
        "repository",
        "allowed_workflow_paths",
        "allowed_job_names",
        "source",
        "api",
        "collector",
        "replay_ledger",
        "time_constraints",
        "review",
    )
    if policy["synthetic"] is True:
        if (
            not allow_synthetic
            or policy["policy_status"] != "pending"
            or any(policy[field] is not None for field in optional)
        ):
            raise _invalid()
        return dict(policy)
    if policy["synthetic"] is not False or policy["policy_status"] != "reviewed":
        raise _invalid()

    repository = _closed(policy["repository"], _REPOSITORY_FIELDS)
    if (
        not isinstance(repository["name"], str)
        or _REPOSITORY.fullmatch(repository["name"]) is None
        or not isinstance(repository["repository_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_id"]) is None
        or not isinstance(repository["repository_owner_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_owner_id"]) is None
        or repository["visibility"] not in {"public", "private", "internal"}
    ):
        raise _invalid()
    workflows = policy["allowed_workflow_paths"]
    jobs = policy["allowed_job_names"]
    if (
        not isinstance(workflows, list)
        or not 1 <= len(workflows) <= 8
        or len(set(workflows)) != len(workflows)
        or any(not isinstance(item, str) or _WORKFLOW_PATH.fullmatch(item) is None for item in workflows)
        or not isinstance(jobs, list)
        or not 1 <= len(jobs) <= 16
        or len(set(jobs)) != len(jobs)
        or any(not isinstance(item, str) or _NAME.fullmatch(item) is None for item in jobs)
    ):
        raise _invalid()
    source = _closed(policy["source"], _SOURCE_FIELDS)
    if (
        source["event"] != "push"
        or not isinstance(source["source_ref"], str)
        or _REF.fullmatch(source["source_ref"]) is None
    ):
        raise _invalid()
    api = _closed(policy["api"], _API_FIELDS)
    if (
        api["origin"] != API_ORIGIN
        or api["version"] != API_VERSION
        or api["endpoint_kinds"] != list(_ENDPOINT_KINDS)
        or type(api["max_pages"]) is not int
        or not 1 <= api["max_pages"] <= MAX_PAGES
    ):
        raise _invalid()
    collector = _anchor(policy["collector"], expected_domain=COLLECTOR_DOMAIN)
    ledger = _anchor(policy["replay_ledger"], expected_domain=LEDGER_DOMAIN)
    if hmac.compare_digest(collector.key_id, ledger.key_id):
        raise _invalid()
    constraints = _closed(policy["time_constraints"], _TIME_FIELDS)
    for field in _TIME_FIELDS:
        if type(constraints[field]) is not int or not 1 <= constraints[field] <= 86400:
            raise _invalid()
    review = _closed(policy["review"], _REVIEW_FIELDS)
    if (
        not isinstance(review["reviewer_reference"], str)
        or _REQUEST_ID.fullmatch(review["reviewer_reference"]) is None
        or review["decision"] != "approved_for_external_collection_authentication"
    ):
        raise _invalid()
    _timestamp(review["reviewed_at"])
    return dict(policy)


def validate_request(value: object) -> dict[str, Any]:
    request = _sealed(value, _REQUEST_FIELDS)
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != SCHEMA_VERSION
        or request["request_kind"] != REQUEST_KIND
        or request["synthetic"] is not False
        or request["production_acceptance"] is not False
        or request["not_committed_eligible"] is not False
        or not isinstance(request["request_id"], str)
        or _UUID4.fullmatch(request["request_id"]) is None
        or not isinstance(request["nonce_b64url"], str)
        or _NONCE.fullmatch(request["nonce_b64url"]) is None
    ):
        raise _invalid()
    _decode_b64url(request["nonce_b64url"], pattern=_B64URL_32, size=32)
    requested_at = _timestamp(request["requested_at"])
    expires_at = _timestamp(request["expires_at"])
    if expires_at <= requested_at:
        raise _invalid()
    _digest(request["trust_policy_sha256"])
    profile = _closed(request["collector_profile"], _COLLECTOR_PROFILE_FIELDS)
    for field in (
        "policy_artifact_sha256", "account_fingerprint_sha256",
        "cluster_fingerprint_sha256", "release_manifest_sha256",
        "target_intake_sha256", "collector_binary_sha256",
        "entrypoint_contract_sha256", "workload_identity_fingerprint_sha256",
    ):
        _digest(profile[field])
    for field in ("deployment_id", "environment", "runner_manifest_digest"):
        if not isinstance(profile[field], str) or not profile[field]:
            raise _invalid()
    if not isinstance(profile["release_commit"], str) or _COMMIT.fullmatch(profile["release_commit"]) is None:
        raise _invalid()
    github_origin = _closed(request["github_origin"], _GITHUB_ORIGIN_FIELDS)
    _digest(github_origin["artifact_sha256"])
    previous = _closed(request["previous_head"], _PREVIOUS_REQUEST_FIELDS)
    if (
        not isinstance(previous["ledger_id"], str)
        or _REQUEST_ID.fullmatch(previous["ledger_id"]) is None
        or type(previous["expected_sequence"]) is not int
        or previous["expected_sequence"] < 1
    ):
        raise _invalid()
    _digest(previous["artifact_sha256"])
    subject = _closed(request["subject"], _SUBJECT_FIELDS)
    _digest(subject["artifact_sha256"])
    _digest(subject["payload_sha256"])
    if not isinstance(subject["attempt_id"], str) or _UUID4.fullmatch(subject["attempt_id"]) is None:
        raise _invalid()
    repository = _closed(request["repository"], _REPOSITORY_FIELDS)
    if (
        not isinstance(repository["name"], str)
        or _REPOSITORY.fullmatch(repository["name"]) is None
        or not isinstance(repository["repository_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_id"]) is None
        or not isinstance(repository["repository_owner_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_owner_id"]) is None
        or repository["visibility"] not in {"public", "private", "internal"}
    ):
        raise _invalid()
    workflow = _closed(request["workflow"], _REQUEST_WORKFLOW_FIELDS)
    _positive_id(workflow["run_id"])
    _positive_id(workflow["run_attempt"])
    if (
        not isinstance(workflow["workflow_path"], str)
        or _WORKFLOW_PATH.fullmatch(workflow["workflow_path"]) is None
        or not isinstance(workflow["source_commit"], str)
        or _COMMIT.fullmatch(workflow["source_commit"]) is None
        or not isinstance(workflow["source_ref"], str)
        or _REF.fullmatch(workflow["source_ref"]) is None
        or workflow["event"] != "push"
    ):
        raise _invalid()
    job = _closed(request["job"], _REQUEST_JOB_FIELDS)
    artifact = _closed(request["artifact"], _REQUEST_ARTIFACT_FIELDS)
    _positive_id(artifact["artifact_id"])
    _digest(artifact["archive_sha256"])
    if (
        not isinstance(job["name"], str)
        or _NAME.fullmatch(job["name"]) is None
        or not isinstance(artifact["name"], str)
        or _NAME.fullmatch(artifact["name"]) is None
        or not isinstance(artifact["subject_member_path"], str)
        or _MEMBER.fullmatch(artifact["subject_member_path"]) is None
        or ".." in Path(artifact["subject_member_path"]).parts
    ):
        raise _invalid()
    return dict(request)


def _validate_signature_object(value: object) -> dict[str, Any]:
    signature = _closed(value, _SIGNATURE_FIELDS)
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
    ):
        raise _invalid()
    _decode_b64url(signature["value_b64url"], pattern=_B64URL_64, size=64)
    return signature


def _validate_checkpoint(value: object) -> dict[str, Any]:
    checkpoint = _closed(value, _CHECKPOINT_FIELDS)
    if (
        type(checkpoint["schema_version"]) is not int
        or checkpoint["schema_version"] != SCHEMA_VERSION
        or checkpoint["checkpoint_kind"] != CHECKPOINT_KIND
        or not isinstance(checkpoint["ledger_id"], str)
        or _REQUEST_ID.fullmatch(checkpoint["ledger_id"]) is None
        or type(checkpoint["sequence"]) is not int
        or checkpoint["sequence"] < 0
        or type(checkpoint["genesis"]) is not bool
    ):
        raise _invalid()
    _timestamp(checkpoint["recorded_at"])
    digest_fields = (
        "collection_payload_sha256",
        "collector_signature_sha256",
        "request_artifact_sha256",
        "previous_head_artifact_sha256",
        "previous_checkpoint_payload_sha256",
    )
    if checkpoint["genesis"] is True:
        if checkpoint["sequence"] != 0 or any(checkpoint[field] is not None for field in digest_fields):
            raise _invalid()
    else:
        if checkpoint["sequence"] < 1:
            raise _invalid()
        for field in digest_fields:
            _digest(checkpoint[field])
    return checkpoint


def validate_replay_head(value: object) -> dict[str, Any]:
    head = _closed(value, _HEAD_FIELDS)
    _validate_checkpoint(head["checkpoint"])
    _validate_signature_object(head["signature"])
    return head


def validate_evidence(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    evidence = _closed(value, _EVIDENCE_FIELDS)
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != SCHEMA_VERSION
        or evidence["evidence_kind"] != EVIDENCE_KIND
        or evidence["production_acceptance"] is not False
        or evidence["not_committed_eligible"] is not False
    ):
        raise _invalid()
    prohibited = _closed(evidence["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item is not False for item in prohibited.values()):
        raise _invalid()
    claim_boundary = _closed(evidence["claim_boundary"], _CLAIM_BOUNDARY_FIELDS)
    if any(item != "unverified" for item in claim_boundary.values()):
        raise _invalid()
    optional = ("collection_payload", "collector_signature", "replay_head")
    if evidence["synthetic"] is True:
        if (
            not allow_synthetic
            or evidence["evidence_status"] != "pending"
            or any(evidence[field] is not None for field in optional)
        ):
            raise _invalid()
        return dict(evidence)
    if evidence["synthetic"] is not False or evidence["evidence_status"] != "ready_for_verification":
        raise _invalid()
    _closed(evidence["collection_payload"], _COLLECTION_FIELDS)
    _validate_signature_object(evidence["collector_signature"])
    validate_replay_head(evidence["replay_head"])
    return dict(evidence)


def _endpoint_snapshots(value: object, *, max_pages: int) -> dict[str, Any]:
    snapshots = _closed(value, set(_ENDPOINT_KINDS))
    all_digests: list[str] = []
    for expected_kind in _ENDPOINT_KINDS:
        if expected_kind == "get_workflow_artifact_redirect":
            snapshot = _closed(snapshots[expected_kind], _REDIRECT_ENDPOINT_FIELDS)
            digests = snapshot["raw_response_sha256s"]
            if (
                snapshot["endpoint_kind"] != expected_kind
                or snapshot["request_method"] != "GET"
                or snapshot["request_origin"] != API_ORIGIN
                or snapshot["response_status"] != 302
                or snapshot["location_count"] != 1
                or snapshot["redirect_mode"] != "manual"
                or snapshot["followed_automatically"] is not False
                or snapshot["authorization_sent_to_source"] is not True
                or snapshot["authorization_forwarded"] is not False
                or snapshot["cookie_forwarded"] is not False
                or snapshot["proxy_authorization_forwarded"] is not False
                or not isinstance(digests, list)
                or len(digests) != 1
            ):
                raise _invalid()
            _digest(snapshot["location_url_sha256"])
            all_digests.extend(_digest(item) for item in digests)
            continue
        if expected_kind in {"download_workflow_artifact", "download_attestation_bundle"}:
            snapshot = _closed(snapshots[expected_kind], _DOWNLOAD_ENDPOINT_FIELDS)
            if (
                snapshot["endpoint_kind"] != expected_kind
                or snapshot["request_method"] != "GET"
                or snapshot["authorization_sent"] is not False
                or snapshot["cookie_sent"] is not False
                or snapshot["proxy_authorization_sent"] is not False
                or snapshot["response_status"] != 200
                or snapshot["further_redirect"] is not False
                or type(snapshot["raw_body_size"]) is not int
                or not 1 <= snapshot["raw_body_size"] <= MAX_DOWNLOAD_BYTES
            ):
                raise _invalid()
            _digest(snapshot["request_url_sha256"])
            all_digests.append(_digest(snapshot["raw_body_sha256"]))
            continue
        snapshot = _closed(snapshots[expected_kind], _ENDPOINT_FIELDS)
        digests = snapshot["raw_response_sha256s"]
        upper = 1 if expected_kind == "get_workflow_run_attempt" else max_pages
        if (
            snapshot["endpoint_kind"] != expected_kind
            or snapshot["pagination_complete"] is not True
            or not isinstance(digests, list)
            or not 1 <= len(digests) <= upper
        ):
            raise _invalid()
        all_digests.extend(_digest(item) for item in digests)
    if len(set(all_digests)) != len(all_digests):
        raise _invalid()
    return snapshots


def _raw_response_set_sha256(snapshots: Mapping[str, Any]) -> str:
    ordered: list[dict[str, object]] = []
    for endpoint_kind in _ENDPOINT_KINDS:
        snapshot = snapshots[endpoint_kind]
        digests = (
            [snapshot["raw_body_sha256"]]
            if endpoint_kind in {"download_workflow_artifact", "download_attestation_bundle"}
            else list(snapshot["raw_response_sha256s"])
        )
        ordered.append({"endpoint_kind": endpoint_kind, "digests": digests})
    message = (
        b"email-platform/private-secret-github-raw-response-set/v1\0"
        + _canonical_bytes(ordered)
    )
    return hashlib.sha256(message).hexdigest()


def _check_run_id(value: object, *, repository: str) -> int:
    if not isinstance(value, str):
        raise _invalid()
    prefix = f"{API_ORIGIN}/repos/{repository}/check-runs/"
    if not value.startswith(prefix):
        raise _invalid()
    raw_id = value[len(prefix) :]
    if not raw_id.isascii() or not raw_id.isdigit():
        raise _invalid()
    return _positive_id(int(raw_id))


def _projection(value: object, *, request: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    projection = _closed(value, _PROJECTION_FIELDS)
    repository = _closed(projection["repository"], _REPOSITORY_FIELDS)
    if repository != request["repository"] or repository != policy["repository"]:
        raise _invalid()

    requested_workflow = request["workflow"]
    if (
        requested_workflow["workflow_path"] not in policy["allowed_workflow_paths"]
        or request["job"]["name"] not in policy["allowed_job_names"]
        or requested_workflow["source_ref"] != policy["source"]["source_ref"]
        or requested_workflow["event"] != policy["source"]["event"]
    ):
        raise _invalid()
    workflow = _closed(projection["workflow"], _WORKFLOW_FIELDS)
    for field in ("run_id", "run_attempt", "workflow_id", "check_suite_id"):
        _positive_id(workflow[field])
    expected_workflow = {
        "run_id": requested_workflow["run_id"],
        "run_attempt": requested_workflow["run_attempt"],
        "workflow_path": requested_workflow["workflow_path"],
        "source_commit": requested_workflow["source_commit"],
        "source_ref": requested_workflow["source_ref"],
        "event": requested_workflow["event"],
        "status": "completed",
        "conclusion": "success",
        "repository_id": repository["repository_id"],
        "head_repository_id": repository["repository_id"],
    }
    if any(workflow[field] != expected for field, expected in expected_workflow.items()):
        raise _invalid()

    requested_job = request["job"]
    job = _closed(projection["job"], _JOB_FIELDS)
    for field in ("job_id", "run_id", "check_run_id"):
        _positive_id(job[field])
    parsed_check_id = _check_run_id(job["check_run_url"], repository=repository["name"])
    if (
        job["name"] != requested_job["name"]
        or job["run_id"] != workflow["run_id"]
        or job["head_sha"] != workflow["source_commit"]
        or job["status"] != "completed"
        or job["conclusion"] != "success"
        or parsed_check_id != job["check_run_id"]
        or job["matching_job_count"] != 1
    ):
        raise _invalid()

    requested_artifact = request["artifact"]
    subject = request["subject"]
    artifact = _closed(projection["artifact"], _ARTIFACT_FIELDS)
    _positive_id(artifact["artifact_id"])
    _digest(artifact["archive_digest_sha256"])
    _digest(artifact["subject_artifact_sha256"])
    _digest(artifact["subject_payload_sha256"])
    if (
        artifact["artifact_id"] != requested_artifact["artifact_id"]
        or artifact["name"] != requested_artifact["name"]
        or artifact["archive_digest_sha256"] != requested_artifact["archive_sha256"]
        or artifact["subject_member_path"] != requested_artifact["subject_member_path"]
        or artifact["subject_binding_method"] != "bounded_archive_member_sha256"
        or artifact["subject_artifact_sha256"] != subject["artifact_sha256"]
        or artifact["subject_payload_sha256"] != subject["payload_sha256"]
        or artifact["workflow_run_id"] != workflow["run_id"]
        or artifact["repository_id"] != repository["repository_id"]
        or artifact["head_repository_id"] != repository["repository_id"]
        or artifact["head_sha"] != workflow["source_commit"]
        or artifact["expired"] is not False
        or artifact["matching_artifact_count"] != 1
    ):
        raise _invalid()

    attestation = _closed(projection["attestation"], _ATTESTATION_FIELDS)
    if (
        attestation["subject_digest"] != "sha256:" + subject["artifact_sha256"]
        or attestation["repository_id"] != repository["repository_id"]
        or attestation["predicate_type"] != PREDICATE_TYPE
        or attestation["matching_bundle_count"] != 1
    ):
        raise _invalid()
    _digest(attestation["bundle_artifact_sha256"])
    _digest(attestation["bundle_url_sha256"])
    if not isinstance(attestation["bundle_origin"], str):
        raise _invalid()
    return projection


def verify_collection_bytes(
    *,
    input_raw: bytes,
    request_raw: bytes,
    previous_head_raw: bytes,
    policy_raw: bytes,
    github_origin_raw: bytes,
    deployment_policy_raw: bytes,
    readiness_raw: bytes,
    archive_raw: bytes,
    bundle_raw: bytes,
    expected_receipt_sha256: str,
    expected_policy_sha256: str,
    expected_request_sha256: str,
    expected_previous_head_sha256: str,
    expected_github_origin_sha256: str,
    expected_deployment_policy_sha256: str,
    expected_readiness_sha256: str,
    expected_archive_sha256: str,
    expected_bundle_sha256: str,
    expected_current_worm_collection_head_sha256: str,
    expected_ledger_id: str,
    expected_sequence: int,
) -> VerifiedCollection:
    """Authenticate exact caller-supplied collection bytes without filesystem I/O."""

    receipt_blob = _bytes_blob(input_raw)
    request_blob = _bytes_blob(request_raw)
    previous_blob = _bytes_blob(previous_head_raw)
    policy_blob = _bytes_blob(policy_raw)
    github_origin_blob = _bytes_blob(github_origin_raw)
    deployment_policy_blob = _bytes_blob(deployment_policy_raw)
    readiness_blob = _bytes_blob(readiness_raw)
    archive_blob = _bytes_blob(archive_raw, max_bytes=MAX_DOWNLOAD_BYTES)
    bundle_blob = _bytes_blob(bundle_raw, max_bytes=MAX_DOWNLOAD_BYTES)
    _digest(expected_receipt_sha256)
    _digest(expected_policy_sha256)
    _digest(expected_request_sha256)
    _digest(expected_previous_head_sha256)
    _digest(expected_github_origin_sha256)
    _digest(expected_deployment_policy_sha256)
    _digest(expected_readiness_sha256)
    _digest(expected_archive_sha256)
    _digest(expected_bundle_sha256)
    _digest(expected_current_worm_collection_head_sha256)
    if (
        not hmac.compare_digest(expected_receipt_sha256, receipt_blob.sha256)
        or not hmac.compare_digest(expected_policy_sha256, policy_blob.sha256)
        or not hmac.compare_digest(expected_request_sha256, request_blob.sha256)
        or not hmac.compare_digest(expected_previous_head_sha256, previous_blob.sha256)
        or not hmac.compare_digest(
            expected_github_origin_sha256, github_origin_blob.sha256
        )
        or not hmac.compare_digest(expected_archive_sha256, archive_blob.sha256)
        or not hmac.compare_digest(expected_bundle_sha256, bundle_blob.sha256)
        or not isinstance(expected_ledger_id, str)
        or _REQUEST_ID.fullmatch(expected_ledger_id) is None
        or type(expected_sequence) is not int
        or expected_sequence < 1
    ):
        raise _invalid()
    if (
        not hmac.compare_digest(
            expected_deployment_policy_sha256, deployment_policy_blob.sha256
        )
        or not hmac.compare_digest(expected_readiness_sha256, readiness_blob.sha256)
    ):
        raise _invalid()

    policy = validate_policy(_document(policy_blob))
    request = validate_request(_document(request_blob))
    evidence = validate_evidence(_document(receipt_blob))
    previous_head = validate_replay_head(_document(previous_blob))
    try:
        github_origin = github_attestation.validate_origin_envelope(
            _document(github_origin_blob)
        )
    except (github_attestation.GitHubAttestationError, TypeError, ValueError) as error:
        raise _invalid() from error
    collector_anchor = _anchor(policy["collector"], expected_domain=COLLECTOR_DOMAIN)
    ledger_anchor = _anchor(policy["replay_ledger"], expected_domain=LEDGER_DOMAIN)
    try:
        readiness = collector_deployment.verify_readiness_preflight(
            deployment_policy_blob.raw,
            readiness_blob.raw,
            expected_policy_sha256=expected_deployment_policy_sha256,
            expected_readiness_sha256=expected_readiness_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_previous_github_collection_head_sha256=expected_previous_head_sha256,
            expected_current_worm_collection_head_sha256=expected_current_worm_collection_head_sha256,
            expected_collection_prior_head_sha256=expected_previous_head_sha256,
            expected_collection_ledger_id=expected_ledger_id,
            expected_collection_sequence=expected_sequence,
        )
    except (collector_deployment.CollectorDeploymentError, TypeError, ValueError) as error:
        raise _invalid() from error
    profile = request["collector_profile"]
    expected_profile = {
        "policy_artifact_sha256": readiness.policy_sha256,
        "deployment_id": readiness.deployment_id,
        "environment": readiness.environment,
        "account_fingerprint_sha256": readiness.account_fingerprint_sha256,
        "cluster_fingerprint_sha256": readiness.cluster_fingerprint_sha256,
        "release_commit": readiness.release_commit,
        "release_manifest_sha256": readiness.release_manifest_sha256,
        "target_intake_sha256": readiness.target_intake_sha256,
        "runner_manifest_digest": readiness.runner_manifest_digest,
        "collector_binary_sha256": readiness.collector_binary_sha256,
        "entrypoint_contract_sha256": readiness.entrypoint_contract_sha256,
        "workload_identity_fingerprint_sha256": readiness.workload_identity_fingerprint_sha256,
    }
    if (
        request["trust_policy_sha256"] != policy_blob.sha256
        or request["github_origin"]["artifact_sha256"] != github_origin_blob.sha256
        or request["previous_head"]["ledger_id"] != expected_ledger_id
        or request["previous_head"]["expected_sequence"] != expected_sequence
        or request["previous_head"]["artifact_sha256"] != previous_blob.sha256
        or profile != expected_profile
        or readiness.attempt_id != request["subject"]["attempt_id"]
        or readiness.repository != request["repository"]["name"]
        or readiness.repository_id != request["repository"]["repository_id"]
        or readiness.repository_owner_id != request["repository"]["repository_owner_id"]
        or readiness.api_origin != policy["api"]["origin"]
        or readiness.api_version != policy["api"]["version"]
        or readiness.upstream_t142_github_policy_sha256 != policy_blob.sha256
        or readiness.upstream_t141_github_policy_sha256 != github_origin["trust_policy"]["artifact_sha256"]
        or readiness.upstream_github_collector_key_id != collector_anchor.key_id
        or readiness.upstream_github_ledger_key_id != ledger_anchor.key_id
    ):
        raise _invalid()

    origin_subject = github_origin["subject"]
    origin_verification = github_origin["verification"]
    request_subject = request["subject"]
    request_workflow = request["workflow"]
    if (
        origin_subject["artifact_sha256"] != request_subject["artifact_sha256"]
        or origin_subject["payload_sha256"] != request_subject["payload_sha256"]
        or origin_subject["attempt_id"] != request_subject["attempt_id"]
        or origin_verification["expected_commit"]
        != request_workflow["source_commit"]
    ):
        raise _invalid()

    previous_checkpoint = previous_head["checkpoint"]
    _verify_signature(previous_checkpoint, previous_head["signature"], ledger_anchor)
    if (
        previous_checkpoint["ledger_id"] != expected_ledger_id
        or previous_checkpoint["sequence"] != expected_sequence - 1
    ):
        raise _invalid()

    payload = _closed(evidence["collection_payload"], _COLLECTION_FIELDS)
    binding = _closed(payload["request_binding"], _REQUEST_BINDING_FIELDS)
    if binding != {
        "artifact_sha256": request_blob.sha256,
        "payload_sha256": request["integrity"]["payload_sha256"],
        "github_origin_artifact_sha256": github_origin_blob.sha256,
        "request_id": request["request_id"],
        "nonce_b64url": request["nonce_b64url"],
        "collector_readiness_artifact_sha256": readiness.readiness_sha256,
    } or payload["trust_policy_sha256"] != policy_blob.sha256:
        raise _invalid()

    acquisition = _closed(payload["acquisition"], _ACQUISITION_FIELDS)
    if (
        acquisition["api_origin"] != policy["api"]["origin"]
        or acquisition["api_version"] != policy["api"]["version"]
    ):
        raise _invalid()
    started_at = _timestamp(acquisition["started_at"])
    completed_at = _timestamp(acquisition["completed_at"])
    signed_at = _timestamp(acquisition["signed_at"])
    requested_at = _timestamp(request["requested_at"])
    readiness_observed_at = _timestamp(readiness.observed_at)
    expires_at = _timestamp(request["expires_at"])
    constraints = policy["time_constraints"]
    if (
        _timestamp(policy["review"]["reviewed_at"]) > requested_at
        or _timestamp(previous_checkpoint["recorded_at"]) > requested_at
        or not requested_at <= readiness_observed_at <= started_at <= completed_at <= signed_at <= expires_at
        or (started_at - requested_at).total_seconds() > constraints["max_request_to_acquisition_seconds"]
        or (completed_at - started_at).total_seconds() > constraints["max_acquisition_seconds"]
        or (signed_at - completed_at).total_seconds() > constraints["max_acquisition_to_signature_seconds"]
    ):
        raise _invalid()
    snapshots = _endpoint_snapshots(
        payload["endpoint_snapshots"], max_pages=policy["api"]["max_pages"]
    )
    projection = _projection(payload["projection"], request=request, policy=policy)
    if projection["attestation"]["bundle_artifact_sha256"] != github_origin["bundle"][
        "artifact_sha256"
    ]:
        raise _invalid()
    redirect = snapshots["get_workflow_artifact_redirect"]
    archive_download = snapshots["download_workflow_artifact"]
    bundle_download = snapshots["download_attestation_bundle"]
    attestation = projection["attestation"]
    if (
        redirect["location_origin"] not in readiness.artifact_redirect_origins
        or archive_download["request_origin"] != redirect["location_origin"]
        or archive_download["request_url_sha256"] != redirect["location_url_sha256"]
        or archive_download["raw_body_sha256"] != archive_blob.sha256
        or archive_download["raw_body_size"] != len(archive_blob.raw)
        or archive_blob.sha256 != projection["artifact"]["archive_digest_sha256"]
        or attestation["bundle_origin"] not in readiness.attestation_bundle_origins
        or bundle_download["request_origin"] != attestation["bundle_origin"]
        or bundle_download["request_url_sha256"] != attestation["bundle_url_sha256"]
        or bundle_download["raw_body_sha256"] != bundle_blob.sha256
        or bundle_download["raw_body_size"] != len(bundle_blob.raw)
        or bundle_blob.sha256 != attestation["bundle_artifact_sha256"]
        or bundle_blob.sha256 != github_origin["bundle"]["artifact_sha256"]
    ):
        raise _invalid()
    _verify_signature(payload, evidence["collector_signature"], collector_anchor)

    replay_head = evidence["replay_head"]
    checkpoint = replay_head["checkpoint"]
    if (
        checkpoint["genesis"] is not False
        or checkpoint["ledger_id"] != expected_ledger_id
        or checkpoint["sequence"] != expected_sequence
        or checkpoint["collection_payload_sha256"] != _canonical_digest(payload)
        or checkpoint["collector_signature_sha256"]
        != _canonical_digest(evidence["collector_signature"])
        or checkpoint["request_artifact_sha256"] != request_blob.sha256
        or checkpoint["previous_head_artifact_sha256"] != previous_blob.sha256
        or checkpoint["previous_checkpoint_payload_sha256"]
        != _canonical_digest(previous_checkpoint)
    ):
        raise _invalid()
    recorded_at = _timestamp(checkpoint["recorded_at"])
    if (
        recorded_at < signed_at
        or recorded_at > expires_at
        or recorded_at < _timestamp(previous_checkpoint["recorded_at"])
        or (recorded_at - signed_at).total_seconds()
        > constraints["max_signature_to_record_seconds"]
    ):
        raise _invalid()
    _verify_signature(checkpoint, replay_head["signature"], ledger_anchor)

    return VerifiedCollection(
        attempt_id=request["subject"]["attempt_id"],
        deployment_id=readiness.deployment_id,
        request_id=request["request_id"],
        collector_key_id=collector_anchor.key_id,
        ledger_key_id=ledger_anchor.key_id,
        ledger_id=expected_ledger_id,
        sequence=expected_sequence,
        receipt_sha256=receipt_blob.sha256,
        request_sha256=request_blob.sha256,
        replay_head_sha256=hashlib.sha256(_canonical_bytes(replay_head)).hexdigest(),
        raw_response_set_sha256=_raw_response_set_sha256(snapshots),
        policy_sha256=policy_blob.sha256,
        deployment_policy_sha256=readiness.policy_sha256,
        readiness_sha256=readiness.readiness_sha256,
        previous_head_sha256=previous_blob.sha256,
        current_worm_collection_head_sha256=expected_current_worm_collection_head_sha256,
    )


def verify_collection(
    input_path: Path | str,
    request_path: Path | str,
    previous_head_path: Path | str,
    policy_path: Path | str,
    github_origin_path: Path | str,
    deployment_policy_path: Path | str,
    readiness_path: Path | str,
    archive_path: Path | str,
    bundle_path: Path | str,
    *,
    expected_receipt_sha256: str,
    expected_policy_sha256: str,
    expected_request_sha256: str,
    expected_previous_head_sha256: str,
    expected_github_origin_sha256: str,
    expected_deployment_policy_sha256: str,
    expected_readiness_sha256: str,
    expected_archive_sha256: str,
    expected_bundle_sha256: str,
    expected_current_worm_collection_head_sha256: str,
    expected_ledger_id: str,
    expected_sequence: int,
) -> VerifiedCollection:
    """Acquire each external input once, authenticate exact bytes, then recheck."""

    paths = (
        input_path,
        request_path,
        previous_head_path,
        policy_path,
        github_origin_path,
        deployment_policy_path,
        readiness_path,
        archive_path,
        bundle_path,
    )
    normalized = {
        str(_external_path(path).resolve(strict=False)).casefold() for path in paths
    }
    if len(normalized) != len(paths):
        raise _invalid()

    blobs = (
        _read_blob(input_path),
        _read_blob(request_path),
        _read_blob(previous_head_path),
        _read_blob(policy_path),
        _read_blob(github_origin_path),
        _read_blob(deployment_policy_path),
        _read_blob(readiness_path),
        _read_blob(archive_path, max_bytes=MAX_DOWNLOAD_BYTES),
        _read_blob(bundle_path, max_bytes=MAX_DOWNLOAD_BYTES),
    )
    verified = verify_collection_bytes(
        input_raw=blobs[0].raw,
        request_raw=blobs[1].raw,
        previous_head_raw=blobs[2].raw,
        policy_raw=blobs[3].raw,
        github_origin_raw=blobs[4].raw,
        deployment_policy_raw=blobs[5].raw,
        readiness_raw=blobs[6].raw,
        archive_raw=blobs[7].raw,
        bundle_raw=blobs[8].raw,
        expected_receipt_sha256=expected_receipt_sha256,
        expected_policy_sha256=expected_policy_sha256,
        expected_request_sha256=expected_request_sha256,
        expected_previous_head_sha256=expected_previous_head_sha256,
        expected_github_origin_sha256=expected_github_origin_sha256,
        expected_deployment_policy_sha256=expected_deployment_policy_sha256,
        expected_readiness_sha256=expected_readiness_sha256,
        expected_archive_sha256=expected_archive_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_current_worm_collection_head_sha256=(
            expected_current_worm_collection_head_sha256
        ),
        expected_ledger_id=expected_ledger_id,
        expected_sequence=expected_sequence,
    )
    for blob in blobs:
        _unchanged(blob)
    return verified


def verify_repository_assets() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = validate_policy(
            parse_unique_json_bytes(read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
        evidence = validate_evidence(
            parse_unique_json_bytes(read_stable_bytes(SYNTHETIC, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
    except (
        OSError,
        StableFileError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error
    return policy, evidence


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GitHubRestCollectionError("private secret GitHub REST arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--request", type=Path, required=True)
    verify.add_argument("--previous-head", type=Path, required=True)
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--github-origin", type=Path, required=True)
    verify.add_argument("--deployment-policy", type=Path, required=True)
    verify.add_argument("--readiness", type=Path, required=True)
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-receipt-sha256", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-request-sha256", required=True)
    verify.add_argument("--expected-previous-head-sha256", required=True)
    verify.add_argument("--expected-github-origin-sha256", required=True)
    verify.add_argument("--expected-deployment-policy-sha256", required=True)
    verify.add_argument("--expected-readiness-sha256", required=True)
    verify.add_argument("--expected-archive-sha256", required=True)
    verify.add_argument("--expected-bundle-sha256", required=True)
    verify.add_argument("--expected-current-worm-collection-head-sha256", required=True)
    verify.add_argument("--expected-ledger-id", required=True)
    verify.add_argument("--expected-sequence", type=int, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            verify_repository_assets()
            print(
                "private-secret-github-rest-template-ok status=unconfigured "
                "t141-origin-envelope=unverified t141-consistency=unverified "
                "collector-receipt-authentication=unverified "
                "collector-readiness=unverified artifact-download=unverified "
                "attestation-bundle-download=unverified redirect-auth-stripping=unverified "
                "replay-ledger-checkpoint-authentication=unverified "
                "rest-snapshot=unverified job-binding=unverified "
                "job-artifact-causality=unverified provider-native=unverified "
                "trusted-time=unverified freshness=unverified "
                "replay-protection=unverified durability=unverified "
                "reviewer-independence=unverified production_acceptance=false"
                " not_committed_eligible=false"
            )
            return 0
        verified = verify_collection(
            options.input,
            options.request,
            options.previous_head,
            options.policy,
            options.github_origin,
            options.deployment_policy,
            options.readiness,
            options.archive,
            options.bundle,
            expected_receipt_sha256=options.expected_receipt_sha256,
            expected_policy_sha256=options.expected_policy_sha256,
            expected_request_sha256=options.expected_request_sha256,
            expected_previous_head_sha256=options.expected_previous_head_sha256,
            expected_github_origin_sha256=options.expected_github_origin_sha256,
            expected_deployment_policy_sha256=options.expected_deployment_policy_sha256,
            expected_readiness_sha256=options.expected_readiness_sha256,
            expected_archive_sha256=options.expected_archive_sha256,
            expected_bundle_sha256=options.expected_bundle_sha256,
            expected_current_worm_collection_head_sha256=options.expected_current_worm_collection_head_sha256,
            expected_ledger_id=options.expected_ledger_id,
            expected_sequence=options.expected_sequence,
        )
    except (GitHubRestCollectionError, OSError, TypeError, ValueError):
        print("private-secret-github-rest-collection-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-github-rest-collection-ok "
        "t141-origin-envelope=caller-pinned-schema-validated "
        "t141-consistency=verified "
        "collector-receipt-authenticated=true "
        "collector-readiness=authenticated-external-signer-assertion "
        "artifact-download=caller-pinned-byte-binding-validated "
        "attestation-bundle-download=caller-pinned-byte-binding-validated "
        "redirect-auth-stripping=authenticated-external-collector-assertion "
        "replay-ledger-checkpoint-authenticated=true "
        "rest-snapshot=authenticated-external-collector-assertion "
        "job-binding=authenticated-external-collector-assertion "
        "job-artifact-causality=unverified provider-native=unverified "
        "trusted-time=unverified freshness=unverified "
        "replay-protection=unverified durability=unverified "
        "reviewer-independence=unverified production_acceptance=false "
        "not_committed_eligible=false "
        f"ledger_id={verified.ledger_id} sequence={verified.sequence} "
        f"receipt_sha256={verified.receipt_sha256} "
        f"replay_head_sha256={verified.replay_head_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
