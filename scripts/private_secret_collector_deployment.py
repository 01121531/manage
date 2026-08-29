"""Offline validation for the disabled external collector deployment contract.

The module authenticates caller-pinned readiness and execution assertions.  It
does not mint credentials, make network requests, run a collector, write an
evidence sink, request time, or mutate a latest-head service.  Consequently an
authenticated assertion is not provider-native proof and is never production
acceptance.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)


POLICY = ROOT / "deploy" / "private-secret-collector-deployment-policy.synthetic.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-collector-acceptance-transaction.synthetic.json"
)

SCHEMA_VERSION = 1
POLICY_KIND = "private_secret_external_collector_deployment_policy"
READINESS_KIND = "private_secret_external_collector_readiness"
EXECUTION_KIND = "private_secret_external_collector_execution_receipt"
API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_JSON_BYTES = 256 * 1024

ROLE_DOMAINS = {
    "readiness": "email-platform/private-secret-collector-readiness/v1",
    "github_execution": "email-platform/private-secret-github-execution/v1",
    "worm_execution": "email-platform/private-secret-worm-execution/v1",
    "trusted_time": "email-platform/private-secret-trusted-time/v1",
    "latest_head": "email-platform/private-secret-latest-head-cas/v1",
}
GITHUB_PERMISSIONS = ["actions:read", "attestations:read"]
GITHUB_ENDPOINTS = [
    "POST /app/installations/{installation_id}/access_tokens",
    "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}",
    "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs",
    "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
    "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
    "GET /repos/{owner}/{repo}/attestations/{subject_digest}",
    "GET {approved_artifact_redirect_origin}{opaque_path}",
    "GET {approved_attestation_bundle_origin}{opaque_path}",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_NUMERIC_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_OCI = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_HTTPS = re.compile(r"^https://(?P<host>[A-Za-z0-9.-]+)(?::443)?$")
_DNS_NAME = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_B64_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64_64 = re.compile(r"^[A-Za-z0-9_-]{86}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")

_POLICY_FIELDS = {
    "schema_version", "policy_kind", "synthetic", "policy_status", "policy_effect",
    "production_acceptance", "not_committed_eligible", "executor_integration_enabled",
    "handoff_integration_enabled", "deployment", "github", "target", "runner",
    "raw_sink", "trusted_time", "latest_head", "upstream_bindings", "trust_anchors", "review", "integrity",
}
_DEPLOYMENT_FIELDS = {
    "deployment_id", "environment", "account_fingerprint_sha256",
    "cluster_fingerprint_sha256", "release_commit", "release_manifest_sha256",
    "target_intake_sha256",
}
_GITHUB_FIELDS = {
    "repository", "repository_id", "repository_owner_id", "app_id", "client_id", "installation_id",
    "repository_selection", "jwt_algorithm", "jwt_issuer", "jwt_audience",
    "jwt_max_ttl_seconds", "jwt_issued_at_backdate_seconds",
    "credential_type", "token_max_ttl_seconds", "token_repository_ids", "permissions",
    "api_origin", "api_version", "endpoint_allowlist", "redirect_mode",
    "artifact_redirect_origins", "attestation_bundle_origins", "authorization_on_redirect",
    "proxy_enabled", "netrc_enabled", "webhook_subscription_enabled",
}
_TARGET_FIELDS = {
    "provider_kind", "provider_account_fingerprint_sha256",
    "storage_identity_fingerprint_sha256", "workload_issuer",
    "workload_subject", "workload_audience", "workload_identity_fingerprint_sha256",
    "credential_type", "maximum_session_age_seconds", "static_credentials",
    "long_lived_tokens", "retention_mode", "minimum_retention_seconds",
}
_RUNNER_FIELDS = {
    "oci_manifest_digest", "collector_binary_sha256", "entrypoint_contract_sha256",
    "source_commit", "immutable_image_required", "read_only_filesystem_required",
    "private_keys_absent_required", "default_deny_network_required",
}
_SINK_FIELDS = {
    "service_origin", "storage_identity_fingerprint_sha256", "namespace_fingerprint_sha256",
    "key_prefix", "conditional_create_required", "immutable_version_required",
    "overwrite_forbidden", "readback_required", "repository_local_sink_forbidden",
}
_TIME_FIELDS = {
    "authority_kind", "authority_identity_fingerprint_sha256", "trust_root_sha256",
    "nonce_binding_required", "maximum_assertion_age_seconds",
}
_HEAD_FIELDS = {
    "service_origin", "service_identity_fingerprint_sha256", "ledger_id",
    "semantics", "caller_prior_head_required", "sequence_precondition_required",
    "generation_precondition_required", "append_only_history_required",
    "stale_write_rejection_required", "automatic_retry_forbidden",
}
_UPSTREAM_FIELDS = {
    "t141_github_policy_sha256", "t142_github_policy_sha256",
    "t141_target_policy_sha256", "t142_worm_policy_sha256",
    "producer_workflow_sha256", "github_collector_key_id", "github_ledger_key_id",
    "worm_provider_key_id", "worm_ledger_key_id",
}
_ANCHOR_FIELDS = {"algorithm", "key_id", "public_key_b64url", "signature_domain"}
_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}

_BASE_FIELDS = {
    "schema_version", "synthetic", "production_acceptance", "not_committed_eligible",
    "attempt_id", "deployment_id", "policy_artifact_sha256", "request_artifact_sha256",
    "environment", "account_fingerprint_sha256", "cluster_fingerprint_sha256",
    "release_commit", "release_manifest_sha256", "target_intake_sha256",
}
_READINESS_PAYLOAD_FIELDS = _BASE_FIELDS | {
    "receipt_kind", "readiness_status", "observed_at", "runner_manifest_digest",
    "collector_binary_sha256", "entrypoint_contract_sha256",
    "workload_identity_fingerprint_sha256", "previous_github_collection_head_sha256",
    "current_worm_collection_head_sha256", "collection_ledger_id",
    "collection_expected_sequence", "collection_prior_head_sha256", "assertions",
}
_READINESS_ASSERTION_FIELDS = {
    "profile_loaded", "release_bindings_loaded", "short_lived_identity_configured",
    "token_persistence_forbidden", "endpoint_allowlist_loaded", "redirect_auth_stripping_loaded",
    "raw_sink_create_only_loaded", "latest_head_cas_loaded", "no_execution_performed",
}
_READINESS_ENVELOPE_FIELDS = {"payload", "signature", "integrity"}

_EXECUTION_PAYLOAD_FIELDS = _BASE_FIELDS | {
    "receipt_kind", "execution_status", "readiness_receipt_sha256", "operation_id",
    "github_collection_head_sha256", "worm_collection_head_sha256",
    "ledger_id", "expected_sequence", "prior_head_sha256", "prior_generation",
    "github_execution", "worm_execution", "raw_sink_result", "trusted_time_result",
    "latest_head_result", "claim_boundary",
}
_GITHUB_EXECUTION_FIELDS = {
    "credential_type", "token_ttl_seconds", "repository_ids", "permissions",
    "endpoint_allowlist", "authorization_redirected", "proxy_used", "netrc_used",
    "raw_response_set_sha256", "collection_receipt_sha256", "collection_ledger_id",
    "collection_sequence",
}
_WORM_EXECUTION_FIELDS = {
    "provider_kind", "workload_identity_fingerprint_sha256",
    "storage_identity_fingerprint_sha256", "retention_mode", "configuration_snapshot_sha256",
    "collection_receipt_sha256", "collection_ledger_id", "collection_sequence",
}
_RAW_SINK_RESULT_FIELDS = {
    "storage_identity_fingerprint_sha256", "namespace_fingerprint_sha256",
    "object_reference", "immutable_version_reference", "content_sha256",
    "conditional_create", "overwrite_attempted", "commit_response_sha256", "readback_sha256",
}
_TRUSTED_TIME_RESULT_FIELDS = {
    "authority_identity_fingerprint_sha256", "nonce_sha256", "imprint_sha256",
    "assertion_artifact_sha256", "observed_at",
}
_LATEST_HEAD_RESULT_FIELDS = {
    "service_identity_fingerprint_sha256", "operation_id", "ledger_id",
    "expected_sequence", "prior_head_sha256", "prior_generation", "compare_token_sha256",
    "new_head_sha256", "new_sequence", "new_generation", "result", "automatic_retry",
    "request_sha256", "response_sha256",
}
_CLAIM_BOUNDARY_FIELDS = {
    "runtime_byte_execution", "token_current_validity", "token_revocation",
    "permission_enforcement", "egress_enforcement", "provider_native", "trusted_time",
    "global_cas_linearizability", "fork_protection", "rollback_protection",
    "sink_immutability", "durability", "reviewer_independence",
}
_EXECUTION_ENVELOPE_FIELDS = {"payload", "signatures", "integrity"}


class CollectorDeploymentError(ValueError):
    """A deployment profile or external assertion failed closed validation."""


@dataclass(frozen=True)
class Anchor:
    key_id: str
    public_key: bytes
    domain: str


@dataclass(frozen=True)
class StableBlob:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class VerifiedAcceptanceTransaction:
    deployment_id: str
    attempt_id: str
    operation_id: str
    readiness_receipt_sha256: str
    execution_receipt_sha256: str
    new_head_sha256: str
    new_sequence: int
    new_generation: str
    github_collection_head_sha256: str
    github_collection_receipt_sha256: str
    github_collection_ledger_id: str
    github_collection_sequence: int
    github_raw_response_set_sha256: str
    worm_collection_head_sha256: str
    worm_collection_receipt_sha256: str
    worm_collection_ledger_id: str
    worm_collection_sequence: int
    worm_provider_kind: str
    worm_storage_identity_fingerprint_sha256: str
    worm_configuration_snapshot_sha256: str
    worm_retention_mode: str


@dataclass(frozen=True)
class VerifiedReadinessPreflight:
    attempt_id: str
    deployment_id: str
    environment: str
    account_fingerprint_sha256: str
    cluster_fingerprint_sha256: str
    release_commit: str
    release_manifest_sha256: str
    target_intake_sha256: str
    repository: str
    repository_id: str
    repository_owner_id: str
    api_origin: str
    api_version: str
    artifact_redirect_origins: tuple[str, ...]
    attestation_bundle_origins: tuple[str, ...]
    runner_manifest_digest: str
    collector_binary_sha256: str
    entrypoint_contract_sha256: str
    workload_identity_fingerprint_sha256: str
    target_provider_kind: str
    target_provider_account_fingerprint_sha256: str
    target_storage_identity_fingerprint_sha256: str
    target_retention_mode: str
    readiness_key_id: str
    upstream_t141_github_policy_sha256: str
    upstream_t142_github_policy_sha256: str
    upstream_t141_target_policy_sha256: str
    upstream_t142_worm_policy_sha256: str
    upstream_github_collector_key_id: str
    upstream_github_ledger_key_id: str
    collection_ledger_id: str
    collection_expected_sequence: int
    collection_prior_head_sha256: str
    observed_at: str
    request_sha256: str
    policy_sha256: str
    readiness_sha256: str


def _invalid() -> CollectorDeploymentError:
    return CollectorDeploymentError("private secret collector deployment evidence is invalid")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


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
    document = _closed(value, fields)
    integrity = _closed(document["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in document.items() if key != "integrity"}
    if not hmac.compare_digest(_digest(integrity["payload_sha256"]), _canonical_digest(payload)):
        raise _invalid()
    return document


def _decode(value: object, pattern: re.Pattern[str], size: int) -> bytes:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _invalid()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise _invalid() from None
    if len(raw) != size or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise _invalid()
    return raw


def _anchor(value: object, role: str) -> Anchor:
    anchor = _closed(value, _ANCHOR_FIELDS)
    domain = ROLE_DOMAINS[role]
    if anchor["algorithm"] != "Ed25519" or anchor["signature_domain"] != domain:
        raise _invalid()
    public_key = _decode(anchor["public_key_b64url"], _B64_32, 32)
    key_id = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if not isinstance(anchor["key_id"], str) or not hmac.compare_digest(anchor["key_id"], key_id):
        raise _invalid()
    Ed25519PublicKey.from_public_bytes(public_key)
    return Anchor(key_id, public_key, domain)


def _verify_signature(payload: Mapping[str, object], value: object, anchor: Anchor) -> None:
    signature = _closed(value, _SIGNATURE_FIELDS)
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
        or not hmac.compare_digest(signature["key_id"], anchor.key_id)
    ):
        raise _invalid()
    raw = _decode(signature["value_b64url"], _B64_64, 64)
    try:
        Ed25519PublicKey.from_public_bytes(anchor.public_key).verify(
            raw, anchor.domain.encode("ascii") + b"\0" + _canonical_bytes(payload)
        )
    except (InvalidSignature, ValueError):
        raise _invalid() from None


def _safe_text(value: object) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise _invalid()
    return value


def _origin(value: object) -> str:
    if not isinstance(value, str):
        raise _invalid()
    match = _HTTPS.fullmatch(value)
    if match is None:
        raise _invalid()
    host = match.group("host").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise _invalid()
    if (
        _DNS_NAME.fullmatch(host) is None
        or host in {"localhost", "localhost.localdomain"}
        or host.endswith((".local", ".internal", ".localhost"))
    ):
        raise _invalid()
    return value


def validate_policy(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    policy = _sealed(value, _POLICY_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "offline_assertion_authentication_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
        or policy["executor_integration_enabled"] is not False
        or policy["handoff_integration_enabled"] is not False
    ):
        raise _invalid()
    configured_fields = (
        "deployment", "github", "target", "runner", "raw_sink", "trusted_time",
        "latest_head", "upstream_bindings", "trust_anchors", "review",
    )
    if policy["synthetic"] is True:
        if (
            not allow_synthetic
            or policy["policy_status"] != "unconfigured"
            or any(policy[field] is not None for field in configured_fields)
        ):
            raise _invalid()
        return dict(policy)
    if policy["synthetic"] is not False or policy["policy_status"] != "reviewed":
        raise _invalid()

    deployment = _closed(policy["deployment"], _DEPLOYMENT_FIELDS)
    _safe_text(deployment["deployment_id"])
    _safe_text(deployment["environment"])
    for field in ("account_fingerprint_sha256", "cluster_fingerprint_sha256", "release_manifest_sha256", "target_intake_sha256"):
        _digest(deployment[field])
    if not isinstance(deployment["release_commit"], str) or _COMMIT.fullmatch(deployment["release_commit"]) is None:
        raise _invalid()

    github = _closed(policy["github"], _GITHUB_FIELDS)
    if (
        not isinstance(github["repository"], str)
        or _REPOSITORY.fullmatch(github["repository"]) is None
        or any(not isinstance(github[field], str) or _NUMERIC_ID.fullmatch(github[field]) is None for field in ("repository_id", "repository_owner_id", "app_id", "installation_id"))
        or not isinstance(github["client_id"], str)
        or _ID.fullmatch(github["client_id"]) is None
        or github["repository_selection"] != "selected"
        or github["jwt_algorithm"] != "RS256"
        or github["jwt_issuer"] != github["client_id"]
        or github["jwt_audience"] is not None
        or type(github["jwt_max_ttl_seconds"]) is not int
        or not 1 <= github["jwt_max_ttl_seconds"] <= 600
        or type(github["jwt_issued_at_backdate_seconds"]) is not int
        or not 0 <= github["jwt_issued_at_backdate_seconds"] <= 60
        or github["credential_type"] != "github_app_installation_token"
        or type(github["token_max_ttl_seconds"]) is not int
        or not 1 <= github["token_max_ttl_seconds"] <= 3600
        or github["token_repository_ids"] != [github["repository_id"]]
        or github["permissions"] != GITHUB_PERMISSIONS
        or github["api_origin"] != API_ORIGIN
        or github["api_version"] != API_VERSION
        or github["endpoint_allowlist"] != GITHUB_ENDPOINTS
        or github["redirect_mode"] != "manual_allowlisted_https_origin_only"
        or not isinstance(github["artifact_redirect_origins"], list)
        or not github["artifact_redirect_origins"]
        or any(_origin(item) != item for item in github["artifact_redirect_origins"])
        or len(set(github["artifact_redirect_origins"])) != len(github["artifact_redirect_origins"])
        or not isinstance(github["attestation_bundle_origins"], list)
        or not github["attestation_bundle_origins"]
        or any(_origin(item) != item for item in github["attestation_bundle_origins"])
        or len(set(github["attestation_bundle_origins"])) != len(github["attestation_bundle_origins"])
        or github["authorization_on_redirect"] != "forbidden"
        or github["proxy_enabled"] is not False
        or github["netrc_enabled"] is not False
        or github["webhook_subscription_enabled"] is not False
    ):
        raise _invalid()

    target = _closed(policy["target"], _TARGET_FIELDS)
    if target["provider_kind"] not in {"aws_s3_object_lock", "azure_immutable_blob", "gcp_bucket_lock"}:
        raise _invalid()
    for field in ("provider_account_fingerprint_sha256", "storage_identity_fingerprint_sha256", "workload_identity_fingerprint_sha256"):
        _digest(target[field])
    for field in ("workload_issuer", "workload_subject", "workload_audience"):
        _origin(target[field]) if field == "workload_issuer" else _safe_text(target[field])
    if (
        target["credential_type"] != "federated_short_lived_workload_identity"
        or type(target["maximum_session_age_seconds"]) is not int
        or not 1 <= target["maximum_session_age_seconds"] <= 3600
        or target["static_credentials"] != "forbidden"
        or target["long_lived_tokens"] != "forbidden"
        or target["retention_mode"] != "compliance"
        or type(target["minimum_retention_seconds"]) is not int
        or target["minimum_retention_seconds"] < 86400
    ):
        raise _invalid()

    runner = _closed(policy["runner"], _RUNNER_FIELDS)
    if (
        not isinstance(runner["oci_manifest_digest"], str)
        or _OCI.fullmatch(runner["oci_manifest_digest"]) is None
        or not isinstance(runner["source_commit"], str)
        or _COMMIT.fullmatch(runner["source_commit"]) is None
    ):
        raise _invalid()
    for field in ("collector_binary_sha256", "entrypoint_contract_sha256"):
        _digest(runner[field])
    if any(runner[field] is not True for field in _RUNNER_FIELDS if field.endswith("_required")):
        raise _invalid()

    sink = _closed(policy["raw_sink"], _SINK_FIELDS)
    _origin(sink["service_origin"])
    _digest(sink["storage_identity_fingerprint_sha256"])
    _digest(sink["namespace_fingerprint_sha256"])
    if not isinstance(sink["key_prefix"], str) or not sink["key_prefix"].startswith("private-secret/") or ".." in sink["key_prefix"]:
        raise _invalid()
    if any(sink[field] is not True for field in _SINK_FIELDS if field.endswith(("_required", "_forbidden"))):
        raise _invalid()

    trusted_time = _closed(policy["trusted_time"], _TIME_FIELDS)
    if trusted_time["authority_kind"] not in {"rfc3161_tsa", "provider_signed_time"}:
        raise _invalid()
    _digest(trusted_time["authority_identity_fingerprint_sha256"])
    _digest(trusted_time["trust_root_sha256"])
    if trusted_time["nonce_binding_required"] is not True or type(trusted_time["maximum_assertion_age_seconds"]) is not int or not 1 <= trusted_time["maximum_assertion_age_seconds"] <= 86400:
        raise _invalid()

    head = _closed(policy["latest_head"], _HEAD_FIELDS)
    _origin(head["service_origin"])
    _digest(head["service_identity_fingerprint_sha256"])
    _safe_text(head["ledger_id"])
    if head["semantics"] != "provider_native_compare_and_swap_append_only_v1" or any(
        head[field] is not True for field in _HEAD_FIELDS if field.endswith(("_required", "_forbidden"))
    ):
        raise _invalid()
    if len({
        target["storage_identity_fingerprint_sha256"],
        sink["storage_identity_fingerprint_sha256"],
        head["service_identity_fingerprint_sha256"],
    }) != 3:
        raise _invalid()

    anchors_value = policy["trust_anchors"]
    if not isinstance(anchors_value, dict) or set(anchors_value) != set(ROLE_DOMAINS):
        raise _invalid()
    anchors = {role: _anchor(anchors_value[role], role) for role in ROLE_DOMAINS}
    if len({anchor.key_id for anchor in anchors.values()}) != len(anchors):
        raise _invalid()
    upstream = _closed(policy["upstream_bindings"], _UPSTREAM_FIELDS)
    for field in _UPSTREAM_FIELDS:
        if field.endswith("_sha256"):
            _digest(upstream[field])
    upstream_key_ids = []
    for field in _UPSTREAM_FIELDS:
        if field.endswith("_key_id"):
            value = upstream[field]
            if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
                raise _invalid()
            upstream_key_ids.append(value)
    if (
        len(set(upstream_key_ids)) != len(upstream_key_ids)
        or set(upstream_key_ids) & {anchor.key_id for anchor in anchors.values()}
    ):
        raise _invalid()
    review = _closed(policy["review"], _REVIEW_FIELDS)
    _safe_text(review["reviewer_reference"])
    _timestamp(review["reviewed_at"])
    if review["decision"] != "approved_for_offline_acceptance_transaction_authentication":
        raise _invalid()
    return dict(policy)


def parse_policy(raw: bytes, *, allow_synthetic: bool = False) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise _invalid()
    try:
        return validate_policy(parse_unique_json_bytes(raw), allow_synthetic=allow_synthetic)
    except CollectorDeploymentError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


def _common(payload: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["synthetic"] is not False
        or payload["production_acceptance"] is not False
        or payload["not_committed_eligible"] is not False
        or not isinstance(payload["attempt_id"], str)
        or _UUID4.fullmatch(payload["attempt_id"]) is None
    ):
        raise _invalid()
    for field in (
        "policy_artifact_sha256", "request_artifact_sha256", "account_fingerprint_sha256",
        "cluster_fingerprint_sha256", "release_manifest_sha256", "target_intake_sha256",
    ):
        _digest(payload[field])
    if not isinstance(payload["release_commit"], str) or _COMMIT.fullmatch(payload["release_commit"]) is None:
        raise _invalid()
    _safe_text(payload["deployment_id"])
    _safe_text(payload["environment"])
    deployment = policy["deployment"]
    expected = {
        "deployment_id": deployment["deployment_id"],
        "environment": deployment["environment"],
        "account_fingerprint_sha256": deployment["account_fingerprint_sha256"],
        "cluster_fingerprint_sha256": deployment["cluster_fingerprint_sha256"],
        "release_commit": deployment["release_commit"],
        "release_manifest_sha256": deployment["release_manifest_sha256"],
        "target_intake_sha256": deployment["target_intake_sha256"],
    }
    if any(not hmac.compare_digest(str(payload[field]), str(value)) for field, value in expected.items()):
        raise _invalid()


def _parse_sealed(raw: bytes, fields: set[str]) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise _invalid()
    try:
        return _sealed(parse_unique_json_bytes(raw), fields)
    except CollectorDeploymentError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


def _validate_readiness(raw: bytes, policy: Mapping[str, Any], anchor: Anchor) -> dict[str, Any]:
    envelope = _parse_sealed(raw, _READINESS_ENVELOPE_FIELDS)
    payload = _closed(envelope["payload"], _READINESS_PAYLOAD_FIELDS)
    _common(payload, policy)
    assertions = _closed(payload["assertions"], _READINESS_ASSERTION_FIELDS)
    _digest(payload["previous_github_collection_head_sha256"])
    _digest(payload["current_worm_collection_head_sha256"])
    _digest(payload["collection_prior_head_sha256"])
    _safe_text(payload["collection_ledger_id"])
    if type(payload["collection_expected_sequence"]) is not int or payload["collection_expected_sequence"] < 1:
        raise _invalid()
    if (
        payload["receipt_kind"] != READINESS_KIND
        or payload["readiness_status"] != "authenticated_external_signer_assertion"
        or any(assertions[field] is not True for field in assertions if field != "no_execution_performed")
        or assertions["no_execution_performed"] is not True
        or payload["runner_manifest_digest"] != policy["runner"]["oci_manifest_digest"]
        or payload["collector_binary_sha256"] != policy["runner"]["collector_binary_sha256"]
        or payload["entrypoint_contract_sha256"] != policy["runner"]["entrypoint_contract_sha256"]
        or payload["workload_identity_fingerprint_sha256"] != policy["target"]["workload_identity_fingerprint_sha256"]
    ):
        raise _invalid()
    _timestamp(payload["observed_at"])
    _verify_signature(payload, envelope["signature"], anchor)
    return payload


def _validate_execution(raw: bytes, policy: Mapping[str, Any], anchors: Mapping[str, Anchor]) -> dict[str, Any]:
    envelope = _parse_sealed(raw, _EXECUTION_ENVELOPE_FIELDS)
    payload = _closed(envelope["payload"], _EXECUTION_PAYLOAD_FIELDS)
    _common(payload, policy)
    _digest(payload["prior_head_sha256"])
    _safe_text(payload["ledger_id"])
    _safe_text(payload["prior_generation"])
    if (
        type(payload["expected_sequence"]) is not int
        or payload["expected_sequence"] < 1
        or payload["ledger_id"] != policy["latest_head"]["ledger_id"]
    ):
        raise _invalid()
    if payload["receipt_kind"] != EXECUTION_KIND or payload["execution_status"] != "externally_asserted_completed":
        raise _invalid()
    _digest(payload["github_collection_head_sha256"])
    _digest(payload["worm_collection_head_sha256"])
    _digest(payload["readiness_receipt_sha256"])
    if not isinstance(payload["operation_id"], str) or _UUID4.fullmatch(payload["operation_id"]) is None:
        raise _invalid()

    github = _closed(payload["github_execution"], _GITHUB_EXECUTION_FIELDS)
    if (
        github["credential_type"] != policy["github"]["credential_type"]
        or type(github["token_ttl_seconds"]) is not int
        or not 1 <= github["token_ttl_seconds"] <= policy["github"]["token_max_ttl_seconds"]
        or github["repository_ids"] != policy["github"]["token_repository_ids"]
        or github["permissions"] != GITHUB_PERMISSIONS
        or github["endpoint_allowlist"] != GITHUB_ENDPOINTS
        or github["authorization_redirected"] is not False
        or github["proxy_used"] is not False
        or github["netrc_used"] is not False
    ):
        raise _invalid()
    _digest(github["raw_response_set_sha256"])
    _digest(github["collection_receipt_sha256"])
    _safe_text(github["collection_ledger_id"])
    if type(github["collection_sequence"]) is not int or github["collection_sequence"] < 1:
        raise _invalid()

    worm = _closed(payload["worm_execution"], _WORM_EXECUTION_FIELDS)
    if (
        worm["provider_kind"] != policy["target"]["provider_kind"]
        or worm["workload_identity_fingerprint_sha256"] != policy["target"]["workload_identity_fingerprint_sha256"]
        or worm["storage_identity_fingerprint_sha256"] != policy["target"]["storage_identity_fingerprint_sha256"]
        or worm["retention_mode"] != "compliance"
    ):
        raise _invalid()
    _digest(worm["configuration_snapshot_sha256"])
    _digest(worm["collection_receipt_sha256"])
    _safe_text(worm["collection_ledger_id"])
    if type(worm["collection_sequence"]) is not int or worm["collection_sequence"] < 1:
        raise _invalid()

    sink = _closed(payload["raw_sink_result"], _RAW_SINK_RESULT_FIELDS)
    if (
        sink["storage_identity_fingerprint_sha256"] != policy["raw_sink"]["storage_identity_fingerprint_sha256"]
        or sink["namespace_fingerprint_sha256"] != policy["raw_sink"]["namespace_fingerprint_sha256"]
        or not isinstance(sink["object_reference"], str)
        or not sink["object_reference"].startswith(policy["raw_sink"]["key_prefix"])
        or ".." in Path(sink["object_reference"]).parts
        or not isinstance(sink["immutable_version_reference"], str)
        or _ID.fullmatch(sink["immutable_version_reference"]) is None
        or sink["conditional_create"] is not True
        or sink["overwrite_attempted"] is not False
    ):
        raise _invalid()
    for field in ("content_sha256", "commit_response_sha256", "readback_sha256"):
        _digest(sink[field])
    if not hmac.compare_digest(sink["content_sha256"], sink["readback_sha256"]):
        raise _invalid()

    trusted = _closed(payload["trusted_time_result"], _TRUSTED_TIME_RESULT_FIELDS)
    if trusted["authority_identity_fingerprint_sha256"] != policy["trusted_time"]["authority_identity_fingerprint_sha256"]:
        raise _invalid()
    for field in ("nonce_sha256", "imprint_sha256", "assertion_artifact_sha256"):
        _digest(trusted[field])
    _timestamp(trusted["observed_at"])

    head = _closed(payload["latest_head_result"], _LATEST_HEAD_RESULT_FIELDS)
    if (
        head["service_identity_fingerprint_sha256"] != policy["latest_head"]["service_identity_fingerprint_sha256"]
        or head["operation_id"] != payload["operation_id"]
        or head["ledger_id"] != payload["ledger_id"]
        or head["expected_sequence"] != payload["expected_sequence"]
        or head["prior_head_sha256"] != payload["prior_head_sha256"]
        or head["prior_generation"] != payload["prior_generation"]
        or head["new_sequence"] != payload["expected_sequence"]
        or head["new_head_sha256"] == payload["prior_head_sha256"]
        or head["new_generation"] == payload["prior_generation"]
        or head["result"] != "updated"
        or head["automatic_retry"] is not False
    ):
        raise _invalid()
    for field in ("compare_token_sha256", "new_head_sha256", "request_sha256", "response_sha256"):
        _digest(head[field])
    _safe_text(head["new_generation"])

    boundary = _closed(payload["claim_boundary"], _CLAIM_BOUNDARY_FIELDS)
    if any(value != "unverified" for value in boundary.values()):
        raise _invalid()
    signatures = payload_signatures = envelope["signatures"]
    execution_roles = {"github_execution", "worm_execution", "trusted_time", "latest_head"}
    if not isinstance(signatures, dict) or set(signatures) != execution_roles:
        raise _invalid()
    for role in execution_roles:
        _verify_signature(payload, payload_signatures[role], anchors[role])
    return payload


def verify_acceptance_transaction(
    policy_raw: bytes,
    readiness_raw: bytes,
    execution_raw: bytes,
    *,
    expected_policy_sha256: str,
    expected_readiness_sha256: str,
    expected_execution_sha256: str,
    expected_request_sha256: str,
    expected_previous_github_collection_head_sha256: str,
    expected_current_worm_collection_head_sha256: str,
    expected_github_collection_head_sha256: str,
    expected_worm_collection_head_sha256: str,
    expected_collection_prior_head_sha256: str,
    expected_collection_ledger_id: str,
    expected_collection_sequence: int,
    expected_prior_head_sha256: str,
    expected_ledger_id: str,
    expected_sequence: int,
    expected_prior_generation: str,
) -> VerifiedAcceptanceTransaction:
    """Authenticate one caller-pinned transaction without executing it."""

    pins = {
        "policy": (policy_raw, _digest(expected_policy_sha256)),
        "readiness": (readiness_raw, _digest(expected_readiness_sha256)),
        "execution": (execution_raw, _digest(expected_execution_sha256)),
    }
    for raw, expected in pins.values():
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
            raise _invalid()
    policy = parse_policy(policy_raw)
    anchors = {role: _anchor(policy["trust_anchors"][role], role) for role in ROLE_DOMAINS}
    readiness = _validate_readiness(readiness_raw, policy, anchors["readiness"])
    execution = _validate_execution(execution_raw, policy, anchors)
    common_pins = {
        "policy_artifact_sha256": expected_policy_sha256,
        "request_artifact_sha256": _digest(expected_request_sha256),
    }
    if type(expected_sequence) is not int or expected_sequence < 1:
        raise _invalid()
    for field, expected in common_pins.items():
        if readiness[field] != expected or execution[field] != expected:
            raise _invalid()
    execution_state_pins = {
        "prior_head_sha256": _digest(expected_prior_head_sha256),
        "ledger_id": _safe_text(expected_ledger_id),
        "expected_sequence": expected_sequence,
        "prior_generation": _safe_text(expected_prior_generation),
    }
    if any(execution[field] != expected for field, expected in execution_state_pins.items()):
        raise _invalid()
    readiness_pins = {
        "previous_github_collection_head_sha256": _digest(expected_previous_github_collection_head_sha256),
        "current_worm_collection_head_sha256": _digest(expected_current_worm_collection_head_sha256),
        "collection_prior_head_sha256": _digest(expected_collection_prior_head_sha256),
        "collection_ledger_id": _safe_text(expected_collection_ledger_id),
        "collection_expected_sequence": expected_collection_sequence,
    }
    if type(expected_collection_sequence) is not int or expected_collection_sequence < 1:
        raise _invalid()
    execution_pins = {
        "github_collection_head_sha256": _digest(expected_github_collection_head_sha256),
        "worm_collection_head_sha256": _digest(expected_worm_collection_head_sha256),
    }
    if any(readiness[field] != expected for field, expected in readiness_pins.items()):
        raise _invalid()
    if any(execution[field] != expected for field, expected in execution_pins.items()):
        raise _invalid()
    if (
        readiness["attempt_id"] != execution["attempt_id"]
        or readiness["deployment_id"] != execution["deployment_id"]
        or execution["readiness_receipt_sha256"] != expected_readiness_sha256
    ):
        raise _invalid()
    head = execution["latest_head_result"]
    return VerifiedAcceptanceTransaction(
        deployment_id=execution["deployment_id"],
        attempt_id=execution["attempt_id"],
        operation_id=execution["operation_id"],
        readiness_receipt_sha256=expected_readiness_sha256,
        execution_receipt_sha256=expected_execution_sha256,
        new_head_sha256=head["new_head_sha256"],
        new_sequence=head["new_sequence"],
        new_generation=head["new_generation"],
        github_collection_head_sha256=execution["github_collection_head_sha256"],
        github_collection_receipt_sha256=execution["github_execution"]["collection_receipt_sha256"],
        github_collection_ledger_id=execution["github_execution"]["collection_ledger_id"],
        github_collection_sequence=execution["github_execution"]["collection_sequence"],
        github_raw_response_set_sha256=execution["github_execution"]["raw_response_set_sha256"],
        worm_collection_head_sha256=execution["worm_collection_head_sha256"],
        worm_collection_receipt_sha256=execution["worm_execution"]["collection_receipt_sha256"],
        worm_collection_ledger_id=execution["worm_execution"]["collection_ledger_id"],
        worm_collection_sequence=execution["worm_execution"]["collection_sequence"],
        worm_provider_kind=execution["worm_execution"]["provider_kind"],
        worm_storage_identity_fingerprint_sha256=execution["worm_execution"]["storage_identity_fingerprint_sha256"],
        worm_configuration_snapshot_sha256=execution["worm_execution"]["configuration_snapshot_sha256"],
        worm_retention_mode=execution["worm_execution"]["retention_mode"],
    )


def verify_readiness_preflight(
    policy_raw: bytes,
    readiness_raw: bytes,
    *,
    expected_policy_sha256: str,
    expected_readiness_sha256: str,
    expected_request_sha256: str,
    expected_previous_github_collection_head_sha256: str,
    expected_current_worm_collection_head_sha256: str,
    expected_collection_prior_head_sha256: str,
    expected_collection_ledger_id: str,
    expected_collection_sequence: int,
) -> VerifiedReadinessPreflight:
    """Authenticate one caller-pinned, no-execution readiness assertion."""

    for raw, expected in (
        (policy_raw, _digest(expected_policy_sha256)),
        (readiness_raw, _digest(expected_readiness_sha256)),
    ):
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
            raise _invalid()
    policy = parse_policy(policy_raw)
    readiness_anchor = _anchor(policy["trust_anchors"]["readiness"], "readiness")
    readiness = _validate_readiness(readiness_raw, policy, readiness_anchor)
    pins: dict[str, object] = {
        "policy_artifact_sha256": expected_policy_sha256,
        "request_artifact_sha256": _digest(expected_request_sha256),
        "previous_github_collection_head_sha256": _digest(expected_previous_github_collection_head_sha256),
        "current_worm_collection_head_sha256": _digest(expected_current_worm_collection_head_sha256),
        "collection_prior_head_sha256": _digest(expected_collection_prior_head_sha256),
        "collection_ledger_id": _safe_text(expected_collection_ledger_id),
        "collection_expected_sequence": expected_collection_sequence,
    }
    if type(expected_collection_sequence) is not int or expected_collection_sequence < 1:
        raise _invalid()
    if any(readiness[field] != expected for field, expected in pins.items()):
        raise _invalid()
    github = policy["github"]
    runner = policy["runner"]
    deployment = policy["deployment"]
    target = policy["target"]
    upstream = policy["upstream_bindings"]
    return VerifiedReadinessPreflight(
        attempt_id=str(readiness["attempt_id"]),
        deployment_id=str(deployment["deployment_id"]),
        environment=str(deployment["environment"]),
        account_fingerprint_sha256=str(deployment["account_fingerprint_sha256"]),
        cluster_fingerprint_sha256=str(deployment["cluster_fingerprint_sha256"]),
        release_commit=str(deployment["release_commit"]),
        release_manifest_sha256=str(deployment["release_manifest_sha256"]),
        target_intake_sha256=str(deployment["target_intake_sha256"]),
        repository=str(github["repository"]),
        repository_id=str(github["repository_id"]),
        repository_owner_id=str(github["repository_owner_id"]),
        api_origin=str(github["api_origin"]),
        api_version=str(github["api_version"]),
        artifact_redirect_origins=tuple(github["artifact_redirect_origins"]),
        attestation_bundle_origins=tuple(github["attestation_bundle_origins"]),
        runner_manifest_digest=str(runner["oci_manifest_digest"]),
        collector_binary_sha256=str(runner["collector_binary_sha256"]),
        entrypoint_contract_sha256=str(runner["entrypoint_contract_sha256"]),
        workload_identity_fingerprint_sha256=str(target["workload_identity_fingerprint_sha256"]),
        target_provider_kind=str(target["provider_kind"]),
        target_provider_account_fingerprint_sha256=str(target["provider_account_fingerprint_sha256"]),
        target_storage_identity_fingerprint_sha256=str(target["storage_identity_fingerprint_sha256"]),
        target_retention_mode=str(target["retention_mode"]),
        readiness_key_id=readiness_anchor.key_id,
        upstream_t141_github_policy_sha256=str(upstream["t141_github_policy_sha256"]),
        upstream_t142_github_policy_sha256=str(upstream["t142_github_policy_sha256"]),
        upstream_t141_target_policy_sha256=str(upstream["t141_target_policy_sha256"]),
        upstream_t142_worm_policy_sha256=str(upstream["t142_worm_policy_sha256"]),
        upstream_github_collector_key_id=str(upstream["github_collector_key_id"]),
        upstream_github_ledger_key_id=str(upstream["github_ledger_key_id"]),
        collection_ledger_id=str(readiness["collection_ledger_id"]),
        collection_expected_sequence=int(readiness["collection_expected_sequence"]),
        collection_prior_head_sha256=str(readiness["collection_prior_head_sha256"]),
        observed_at=str(readiness["observed_at"]),
        request_sha256=expected_request_sha256,
        policy_sha256=expected_policy_sha256,
        readiness_sha256=expected_readiness_sha256,
    )


def _external_blob(path_value: Path) -> StableBlob:
    path = Path(path_value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise _invalid()
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=MAX_JSON_BYTES)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return StableBlob(path, raw, stable_file_identity(metadata), hashlib.sha256(raw).hexdigest())


def _unchanged(blob: StableBlob) -> None:
    current = _external_blob(blob.path)
    if current.identity != blob.identity or not hmac.compare_digest(current.sha256, blob.sha256):
        raise _invalid()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--readiness", required=True, type=Path)
    parser.add_argument("--execution", required=True, type=Path)
    for name in (
        "policy-sha256", "readiness-sha256", "execution-sha256", "request-sha256",
        "previous-github-collection-head-sha256", "current-worm-collection-head-sha256",
        "github-collection-head-sha256", "worm-collection-head-sha256", "prior-head-sha256",
        "collection-prior-head-sha256", "collection-ledger-id", "ledger-id", "prior-generation",
    ):
        parser.add_argument("--expected-" + name, required=True)
    parser.add_argument("--expected-sequence", required=True, type=int)
    parser.add_argument("--expected-collection-sequence", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        blobs = [_external_blob(arguments.policy), _external_blob(arguments.readiness), _external_blob(arguments.execution)]
        if len({blob.path.resolve(strict=True) for blob in blobs}) != 3:
            raise _invalid()
        result = verify_acceptance_transaction(
            blobs[0].raw, blobs[1].raw, blobs[2].raw,
            expected_policy_sha256=arguments.expected_policy_sha256,
            expected_readiness_sha256=arguments.expected_readiness_sha256,
            expected_execution_sha256=arguments.expected_execution_sha256,
            expected_request_sha256=arguments.expected_request_sha256,
            expected_previous_github_collection_head_sha256=arguments.expected_previous_github_collection_head_sha256,
            expected_current_worm_collection_head_sha256=arguments.expected_current_worm_collection_head_sha256,
            expected_github_collection_head_sha256=arguments.expected_github_collection_head_sha256,
            expected_worm_collection_head_sha256=arguments.expected_worm_collection_head_sha256,
            expected_collection_prior_head_sha256=arguments.expected_collection_prior_head_sha256,
            expected_collection_ledger_id=arguments.expected_collection_ledger_id,
            expected_collection_sequence=arguments.expected_collection_sequence,
            expected_prior_head_sha256=arguments.expected_prior_head_sha256,
            expected_ledger_id=arguments.expected_ledger_id,
            expected_sequence=arguments.expected_sequence,
            expected_prior_generation=arguments.expected_prior_generation,
        )
        for blob in blobs:
            _unchanged(blob)
    except (CollectorDeploymentError, OSError, ValueError):
        print("private-secret-collector-deployment-error: evidence is invalid", file=sys.stderr)
        return 1
    print(
        "private-secret-collector-deployment-ok "
        f"deployment={result.deployment_id} attempt={result.attempt_id} "
        "profile-binding=validated readiness=authenticated-external-signer-assertion "
        "execution=authenticated-external-signer-assertions cas-one-hop-binding=validated "
        "provider-native=unverified trusted-time=unverified global-cas-linearizability=unverified "
        "fork-protection=unverified rollback-protection=unverified sink-immutability=unverified "
        "durability=unverified reviewer-independence=unverified production_acceptance=false "
        "not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
