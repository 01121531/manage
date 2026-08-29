"""Verify an externally signed archive receipt for one T147 review decision.

This module is offline and read-only. It authenticates exact external bytes and
one custody-chain hop; it does not create an archive, sign data, or write a
WORM/CAS/replay head.
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
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import private_secret_collection_review_decision as review
from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)


SOURCE = Path(__file__).resolve()
POLICY = ROOT / "deploy" / "private-secret-collection-archive-policy.synthetic.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-collection-archive-receipt.synthetic.json"
)

SCHEMA_VERSION = 1
POLICY_KIND = "private_secret_collection_archive_policy"
RECEIPT_KIND = "private_secret_collection_review_archive_receipt"
CHECKPOINT_KIND = "private_secret_collection_archive_checkpoint"
PROVIDER_DOMAIN = "email-platform/private-secret-collection-archive-provider/v1"
CUSTODY_DOMAIN = "email-platform/private-secret-collection-archive-custody/v1"
ZERO_SHA256 = "0" * 64
MAX_JSON_BYTES = 256 * 1024
MAX_OPAQUE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 192 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_B64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64URL_64 = re.compile(r"^[A-Za-z0-9_-]{86}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,191}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

_POLICY_FIELDS = {
    "schema_version", "policy_kind", "synthetic", "policy_status",
    "policy_effect", "production_acceptance", "not_committed_eligible",
    "archive_contract", "provider_signer", "custody_signer",
    "verifier_identity", "time_constraints", "review",
}
_CONTRACT_FIELDS = {
    "provider_kind", "ledger_id", "write_mode",
    "immutable_version_required", "required_retention_mode",
}
_ANCHOR_FIELDS = {
    "algorithm", "key_id", "public_key_b64url", "signature_domain",
    "usage_scope",
}
_VERIFIER_FIELDS = {
    "archive_source_sha256", "review_source_sha256", "release_commit",
    "release_manifest_sha256",
}
_TIME_FIELDS = {
    "max_policy_to_archive_seconds", "max_archive_to_readback_seconds",
    "max_receipt_validity_seconds",
}
_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}
_RECEIPT_FIELDS = {
    "schema_version", "receipt_kind", "synthetic", "receipt_status",
    "production_acceptance", "not_committed_eligible", "payload",
    "provider_signature", "custody_checkpoint", "custody_signature",
    "claim_boundary", "prohibited_content",
}
_PAYLOAD_FIELDS = {
    "receipt_id", "decision_id", "provider_reference", "custody_reference",
    "archived_at", "readback_at", "expires_at", "archive_policy_sha256",
    "review_decision_sha256", "review_policy_sha256",
    "input_manifest_sha256", "review_verifier_source_sha256",
    "archive_verifier_source_sha256", "release_commit",
    "release_manifest_sha256", "archive_readback_sha256",
    "provider_config_sha256", "retention_snapshot_sha256", "provider_kind",
    "storage_identity_fingerprint_sha256", "object_reference",
    "immutable_version_reference", "write_mode", "retention_mode",
    "ledger_id", "sequence", "prior_receipt_sha256",
    "prior_checkpoint_sha256",
}
_CHECKPOINT_FIELDS = {
    "checkpoint_kind", "ledger_id", "sequence", "prior_receipt_sha256",
    "prior_checkpoint_sha256",
    "receipt_id", "decision_id", "receipt_payload_sha256",
    "archive_readback_sha256", "object_reference",
    "immutable_version_reference", "custody_reference",
}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_CLAIM_FIELDS = {
    "provider_native", "trusted_time", "global_replay_protection",
    "decision_id_uniqueness", "verifier_release_provenance",
    "provider_real_identity", "custody_real_identity", "sink_immutability",
    "durability", "fork_protection", "rollback_protection",
}
_PROHIBITED_FIELDS = {
    "contains_token_values", "contains_private_keys", "contains_secret_values",
    "contains_authorization_headers", "contains_raw_provider_responses",
    "contains_raw_evidence_bytes", "contains_repository_external_paths",
}
_PROVIDER_KINDS = {
    "aws_s3_object_lock", "gcp_bucket_lock", "azure_immutable_blob",
    "generic_write_once_archive",
}


class CollectionArchiveReceiptError(ValueError):
    pass


@dataclass(frozen=True)
class StableBlob:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str
    max_bytes: int


@dataclass(frozen=True)
class VerifiedArchiveReceipt:
    receipt_id: str
    decision_id: str
    provider_key_id: str
    custody_key_id: str
    policy_sha256: str
    receipt_sha256: str
    archive_readback_sha256: str
    ledger_id: str
    sequence: int
    prior_receipt_sha256: str
    prior_checkpoint_sha256: str
    head_sha256: str
    object_reference: str
    immutable_version_reference: str
    release_commit: str
    release_manifest_sha256: str
    production_acceptance: bool
    not_committed_eligible: bool


def _invalid() -> CollectionArchiveReceiptError:
    return CollectionArchiveReceiptError("collection archive receipt is invalid")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
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


def _reference(value: object) -> str:
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        raise _invalid()
    return value


def _uuid4(value: object) -> str:
    if not isinstance(value, str) or _UUID4.fullmatch(value) is None:
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


def _decode(value: object, *, pattern: re.Pattern[str], size: int) -> bytes:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _invalid()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (TypeError, ValueError) as error:
        raise _invalid() from error
    if len(raw) != size or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise _invalid()
    return raw


def _document(raw: bytes, *, max_bytes: int = MAX_JSON_BYTES) -> object:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise _invalid()
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error


def _anchor(value: object, *, domain: str, usage_scope: str) -> tuple[dict[str, Any], bytes]:
    anchor = _closed(value, _ANCHOR_FIELDS)
    public_key = _decode(anchor["public_key_b64url"], pattern=_B64URL_32, size=32)
    key_id = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if (
        anchor["algorithm"] != "Ed25519"
        or anchor["signature_domain"] != domain
        or anchor["usage_scope"] != usage_scope
        or not isinstance(anchor["key_id"], str)
        or _KEY_ID.fullmatch(anchor["key_id"]) is None
        or not hmac.compare_digest(anchor["key_id"], key_id)
    ):
        raise _invalid()
    return anchor, public_key


def validate_policy(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    policy = _sealed(value, _POLICY_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "offline_archive_receipt_authentication_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
    ):
        raise _invalid()
    optional = (
        "archive_contract", "provider_signer", "custody_signer",
        "verifier_identity", "time_constraints", "review",
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

    contract = _closed(policy["archive_contract"], _CONTRACT_FIELDS)
    if (
        contract["provider_kind"] not in _PROVIDER_KINDS
        or contract["write_mode"] != "create_only"
        or contract["immutable_version_required"] is not True
        or contract["required_retention_mode"] != "compliance"
    ):
        raise _invalid()
    _reference(contract["ledger_id"])
    provider, provider_key = _anchor(
        policy["provider_signer"],
        domain=PROVIDER_DOMAIN,
        usage_scope="private_secret_collection_archive_provider_v1_only",
    )
    custody, custody_key = _anchor(
        policy["custody_signer"],
        domain=CUSTODY_DOMAIN,
        usage_scope="private_secret_collection_archive_custody_v1_only",
    )
    if hmac.compare_digest(provider_key, custody_key):
        raise _invalid()
    identity = _closed(policy["verifier_identity"], _VERIFIER_FIELDS)
    for field in (
        "archive_source_sha256", "review_source_sha256",
        "release_manifest_sha256",
    ):
        _digest(identity[field])
    if not isinstance(identity["release_commit"], str) or _COMMIT.fullmatch(
        identity["release_commit"]
    ) is None:
        raise _invalid()
    constraints = _closed(policy["time_constraints"], _TIME_FIELDS)
    if any(
        type(constraints[field]) is not int or not 1 <= constraints[field] <= 86400
        for field in _TIME_FIELDS
    ):
        raise _invalid()
    policy_review = _closed(policy["review"], _REVIEW_FIELDS)
    _reference(policy_review["reviewer_reference"])
    _timestamp(policy_review["reviewed_at"])
    if policy_review["decision"] != "approved_for_archive_receipt_authentication":
        raise _invalid()
    return dict(policy)


def validate_receipt(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    receipt = _sealed(value, _RECEIPT_FIELDS)
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["receipt_kind"] != RECEIPT_KIND
        or receipt["production_acceptance"] is not False
        or receipt["not_committed_eligible"] is not False
    ):
        raise _invalid()
    claims = _closed(receipt["claim_boundary"], _CLAIM_FIELDS)
    prohibited = _closed(receipt["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item != "unverified" for item in claims.values()) or any(
        item is not False for item in prohibited.values()
    ):
        raise _invalid()
    optional = (
        "payload", "provider_signature", "custody_checkpoint", "custody_signature"
    )
    if receipt["synthetic"] is True:
        if (
            not allow_synthetic
            or receipt["receipt_status"] != "pending"
            or any(receipt[field] is not None for field in optional)
        ):
            raise _invalid()
        return dict(receipt)
    if receipt["synthetic"] is not False or receipt["receipt_status"] != "reviewed":
        raise _invalid()

    payload = _closed(receipt["payload"], _PAYLOAD_FIELDS)
    _uuid4(payload["receipt_id"])
    _uuid4(payload["decision_id"])
    for field in (
        "provider_reference", "custody_reference", "provider_kind", "object_reference",
        "immutable_version_reference", "ledger_id",
    ):
        _reference(payload[field])
    for field in (
        "archive_policy_sha256", "review_decision_sha256", "review_policy_sha256",
        "input_manifest_sha256", "review_verifier_source_sha256",
        "archive_verifier_source_sha256", "release_manifest_sha256",
        "archive_readback_sha256", "provider_config_sha256",
        "retention_snapshot_sha256", "storage_identity_fingerprint_sha256",
        "prior_receipt_sha256",
        "prior_checkpoint_sha256",
    ):
        _digest(payload[field])
    for field in ("archived_at", "readback_at", "expires_at"):
        _timestamp(payload[field])
    if (
        not isinstance(payload["release_commit"], str)
        or _COMMIT.fullmatch(payload["release_commit"]) is None
        or payload["provider_kind"] not in _PROVIDER_KINDS
        or payload["write_mode"] != "create_only"
        or payload["retention_mode"] != "compliance"
        or type(payload["sequence"]) is not int
        or not 1 <= payload["sequence"] <= 2**63 - 1
        or len(
            {
                payload["provider_reference"], payload["custody_reference"],
                payload["object_reference"], payload["immutable_version_reference"],
            }
        ) != 4
    ):
        raise _invalid()
    checkpoint = _closed(receipt["custody_checkpoint"], _CHECKPOINT_FIELDS)
    if checkpoint["checkpoint_kind"] != CHECKPOINT_KIND:
        raise _invalid()
    for field in (
        "ledger_id", "receipt_id", "decision_id", "object_reference",
        "immutable_version_reference", "custody_reference",
    ):
        _reference(checkpoint[field])
    for field in (
        "prior_receipt_sha256", "receipt_payload_sha256", "archive_readback_sha256"
    ):
        _digest(checkpoint[field])
    if type(checkpoint["sequence"]) is not int or not 1 <= checkpoint["sequence"] <= 2**63 - 1:
        raise _invalid()
    for field in ("provider_signature", "custody_signature"):
        signature = _closed(receipt[field], _SIGNATURE_FIELDS)
        if (
            signature["algorithm"] != "Ed25519"
            or not isinstance(signature["key_id"], str)
            or _KEY_ID.fullmatch(signature["key_id"]) is None
        ):
            raise _invalid()
        _decode(signature["value_b64url"], pattern=_B64URL_64, size=64)
    return dict(receipt)


def _checkpoint_for(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_kind": CHECKPOINT_KIND,
        "ledger_id": payload["ledger_id"],
        "sequence": payload["sequence"],
        "prior_receipt_sha256": payload["prior_receipt_sha256"],
        "prior_checkpoint_sha256": payload["prior_checkpoint_sha256"],
        "receipt_id": payload["receipt_id"],
        "decision_id": payload["decision_id"],
        "receipt_payload_sha256": _canonical_digest(payload),
        "archive_readback_sha256": payload["archive_readback_sha256"],
        "object_reference": payload["object_reference"],
        "immutable_version_reference": payload["immutable_version_reference"],
        "custody_reference": payload["custody_reference"],
    }


def _verify_signature(
    *, public_key: bytes, signature: dict[str, Any], domain: str, payload: dict[str, Any]
) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _decode(signature["value_b64url"], pattern=_B64URL_64, size=64),
            domain.encode("ascii") + b"\0" + _canonical_bytes(payload),
        )
    except (InvalidSignature, ValueError) as error:
        raise _invalid() from error


def _authenticate_receipt(
    receipt: dict[str, Any], policy: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = receipt["payload"]
    checkpoint = receipt["custody_checkpoint"]
    if checkpoint != _checkpoint_for(payload):
        raise _invalid()
    provider, provider_key = _anchor(
        policy["provider_signer"],
        domain=PROVIDER_DOMAIN,
        usage_scope="private_secret_collection_archive_provider_v1_only",
    )
    custody, custody_key = _anchor(
        policy["custody_signer"],
        domain=CUSTODY_DOMAIN,
        usage_scope="private_secret_collection_archive_custody_v1_only",
    )
    if (
        receipt["provider_signature"]["key_id"] != provider["key_id"]
        or receipt["custody_signature"]["key_id"] != custody["key_id"]
    ):
        raise _invalid()
    _verify_signature(
        public_key=provider_key,
        signature=receipt["provider_signature"],
        domain=PROVIDER_DOMAIN,
        payload=payload,
    )
    _verify_signature(
        public_key=custody_key,
        signature=receipt["custody_signature"],
        domain=CUSTODY_DOMAIN,
        payload=checkpoint,
    )
    return payload, checkpoint


def verify_archive_receipt_bytes(
    *,
    receipt_raw: bytes,
    policy_raw: bytes,
    archive_readback_raw: bytes,
    provider_config_raw: bytes,
    retention_snapshot_raw: bytes,
    verifier_source_raw: bytes,
    verified_review: review.VerifiedReviewDecision,
    prior_receipt_raw: bytes | None,
    expected_receipt_sha256: str,
    expected_policy_sha256: str,
    expected_archive_readback_sha256: str,
    expected_provider_config_sha256: str,
    expected_retention_snapshot_sha256: str,
    expected_verifier_source_sha256: str,
    expected_prior_receipt_sha256: str,
    expected_prior_checkpoint_sha256: str,
    expected_review_decision_sha256: str,
    expected_review_policy_sha256: str,
    expected_input_manifest_sha256: str,
    expected_review_verifier_source_sha256: str,
    expected_release_commit: str,
    expected_release_manifest_sha256: str,
    expected_decision_id: str,
    expected_receipt_id: str,
    expected_ledger_id: str,
    expected_sequence: int,
    verification_time: str,
) -> VerifiedArchiveReceipt:
    """Authenticate exact bytes, one T147 result, and one custody-chain hop."""

    raw_values = (
        receipt_raw, policy_raw, archive_readback_raw, provider_config_raw,
        retention_snapshot_raw, verifier_source_raw,
    )
    if (
        any(type(value) is not bytes or not value for value in raw_values)
        or type(verified_review) is not review.VerifiedReviewDecision
        or (prior_receipt_raw is not None and type(prior_receipt_raw) is not bytes)
        or len(archive_readback_raw) > MAX_OPAQUE_BYTES
        or len(provider_config_raw) > MAX_OPAQUE_BYTES
        or len(retention_snapshot_raw) > MAX_OPAQUE_BYTES
        or len(verifier_source_raw) > MAX_SOURCE_BYTES
    ):
        raise _invalid()
    digests = {
        "receipt": hashlib.sha256(receipt_raw).hexdigest(),
        "policy": hashlib.sha256(policy_raw).hexdigest(),
        "archive": hashlib.sha256(archive_readback_raw).hexdigest(),
        "config": hashlib.sha256(provider_config_raw).hexdigest(),
        "retention": hashlib.sha256(retention_snapshot_raw).hexdigest(),
        "source": hashlib.sha256(verifier_source_raw).hexdigest(),
        "prior": (
            hashlib.sha256(prior_receipt_raw).hexdigest()
            if prior_receipt_raw is not None
            else ZERO_SHA256
        ),
    }
    pin_pairs = (
        ("receipt", expected_receipt_sha256),
        ("policy", expected_policy_sha256),
        ("archive", expected_archive_readback_sha256),
        ("config", expected_provider_config_sha256),
        ("retention", expected_retention_snapshot_sha256),
        ("source", expected_verifier_source_sha256),
        ("prior", expected_prior_receipt_sha256),
    )
    for _, value in pin_pairs:
        _digest(value)
    for value in (
        expected_review_decision_sha256, expected_review_policy_sha256,
        expected_input_manifest_sha256, expected_review_verifier_source_sha256,
        expected_release_manifest_sha256, expected_prior_checkpoint_sha256,
    ):
        _digest(value)
    if (
        any(not hmac.compare_digest(digests[name], pin) for name, pin in pin_pairs)
        or not isinstance(expected_release_commit, str)
        or _COMMIT.fullmatch(expected_release_commit) is None
        or type(expected_sequence) is not int
        or not 1 <= expected_sequence <= 2**63 - 1
    ):
        raise _invalid()
    _uuid4(expected_decision_id)
    _uuid4(expected_receipt_id)
    _reference(expected_ledger_id)

    policy = validate_policy(_document(policy_raw))
    receipt = validate_receipt(_document(receipt_raw))
    payload, checkpoint = _authenticate_receipt(receipt, policy)
    identity = policy["verifier_identity"]
    contract = policy["archive_contract"]
    if (
        payload["receipt_id"] != expected_receipt_id
        or payload["decision_id"] != expected_decision_id
        or payload["archive_policy_sha256"] != digests["policy"]
        or payload["review_decision_sha256"] != verified_review.decision_sha256
        or payload["review_policy_sha256"] != verified_review.policy_sha256
        or payload["input_manifest_sha256"] != verified_review.input_manifest_sha256
        or payload["review_verifier_source_sha256"] != verified_review.verifier_source_sha256
        or payload["archive_verifier_source_sha256"] != digests["source"]
        or payload["release_commit"] != verified_review.release_commit
        or payload["release_manifest_sha256"] != verified_review.release_manifest_sha256
        or payload["archive_readback_sha256"] != digests["archive"]
        or payload["provider_config_sha256"] != digests["config"]
        or payload["retention_snapshot_sha256"] != digests["retention"]
        or payload["prior_receipt_sha256"] != digests["prior"]
        or payload["ledger_id"] != expected_ledger_id
        or payload["sequence"] != expected_sequence
        or payload["provider_kind"] != contract["provider_kind"]
        or payload["ledger_id"] != contract["ledger_id"]
        or payload["write_mode"] != contract["write_mode"]
        or payload["retention_mode"] != contract["required_retention_mode"]
        or identity
        != {
            "archive_source_sha256": digests["source"],
            "review_source_sha256": verified_review.verifier_source_sha256,
            "release_commit": verified_review.release_commit,
            "release_manifest_sha256": verified_review.release_manifest_sha256,
        }
        or verified_review.decision_sha256 != expected_review_decision_sha256
        or verified_review.policy_sha256 != expected_review_policy_sha256
        or verified_review.input_manifest_sha256 != expected_input_manifest_sha256
        or verified_review.verifier_source_sha256 != expected_review_verifier_source_sha256
        or verified_review.release_commit != expected_release_commit
        or verified_review.release_manifest_sha256 != expected_release_manifest_sha256
        or verified_review.decision_id != expected_decision_id
    ):
        raise _invalid()

    provider_key_id = policy["provider_signer"]["key_id"]
    custody_key_id = policy["custody_signer"]["key_id"]
    prohibited_keys = {
        verified_review.reviewer_key_id,
        *verified_review.upstream_key_ids,
    }
    if (
        provider_key_id in prohibited_keys
        or custody_key_id in prohibited_keys
        or provider_key_id == custody_key_id
        or policy["review"]["reviewer_reference"]
        in {payload["provider_reference"], payload["custody_reference"], verified_review.reviewer_reference}
    ):
        raise _invalid()

    policy_reviewed = _timestamp(policy["review"]["reviewed_at"])
    archived_at = _timestamp(payload["archived_at"])
    readback_at = _timestamp(payload["readback_at"])
    expires_at = _timestamp(payload["expires_at"])
    observed_at = _timestamp(verification_time)
    constraints = policy["time_constraints"]
    if (
        not policy_reviewed <= archived_at <= readback_at <= observed_at <= expires_at
        or (archived_at - policy_reviewed).total_seconds()
        > constraints["max_policy_to_archive_seconds"]
        or (readback_at - archived_at).total_seconds()
        > constraints["max_archive_to_readback_seconds"]
        or (expires_at - archived_at).total_seconds()
        > constraints["max_receipt_validity_seconds"]
    ):
        raise _invalid()

    if expected_sequence == 1:
        if (
            prior_receipt_raw is not None
            or expected_prior_receipt_sha256 != ZERO_SHA256
            or expected_prior_checkpoint_sha256 != ZERO_SHA256
            or payload["prior_checkpoint_sha256"] != ZERO_SHA256
        ):
            raise _invalid()
    else:
        if prior_receipt_raw is None or expected_prior_receipt_sha256 == ZERO_SHA256:
            raise _invalid()
        prior = validate_receipt(_document(prior_receipt_raw))
        prior_payload, prior_checkpoint = _authenticate_receipt(prior, policy)
        prior_checkpoint_sha256 = _canonical_digest(prior_checkpoint)
        if (
            not hmac.compare_digest(
                prior_checkpoint_sha256, expected_prior_checkpoint_sha256
            )
            or payload["prior_checkpoint_sha256"] != prior_checkpoint_sha256
            or prior_payload["archive_policy_sha256"] != digests["policy"]
            or prior_payload["ledger_id"] != expected_ledger_id
            or prior_payload["sequence"] != expected_sequence - 1
            or prior_payload["receipt_id"] == payload["receipt_id"]
            or prior_payload["decision_id"] == payload["decision_id"]
            or prior_payload["archive_readback_sha256"] == payload["archive_readback_sha256"]
            or prior_payload["object_reference"] == payload["object_reference"]
            or prior_payload["immutable_version_reference"]
            == payload["immutable_version_reference"]
        ):
            raise _invalid()

    return VerifiedArchiveReceipt(
        receipt_id=payload["receipt_id"],
        decision_id=payload["decision_id"],
        provider_key_id=provider_key_id,
        custody_key_id=custody_key_id,
        policy_sha256=digests["policy"],
        receipt_sha256=digests["receipt"],
        archive_readback_sha256=digests["archive"],
        ledger_id=payload["ledger_id"],
        sequence=payload["sequence"],
        prior_receipt_sha256=payload["prior_receipt_sha256"],
        prior_checkpoint_sha256=payload["prior_checkpoint_sha256"],
        head_sha256=_canonical_digest(checkpoint),
        object_reference=payload["object_reference"],
        immutable_version_reference=payload["immutable_version_reference"],
        release_commit=payload["release_commit"],
        release_manifest_sha256=payload["release_manifest_sha256"],
        production_acceptance=False,
        not_committed_eligible=False,
    )


def _external_path(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return path
    raise _invalid()


def _read_blob(path_value: Path | str, *, max_bytes: int, external: bool) -> StableBlob:
    path = _external_path(path_value) if external else Path(path_value)
    if not external and path.resolve(strict=False) != SOURCE.resolve(strict=False):
        raise _invalid()
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=max_bytes)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return StableBlob(
        path=path,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
        max_bytes=max_bytes,
    )


def _unchanged(blob: StableBlob) -> None:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            blob.path, max_bytes=blob.max_bytes, expected_identity=blob.identity
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1 or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(), blob.sha256
    ):
        raise _invalid()


def verify_archive_receipt(
    receipt_path: Path | str,
    policy_path: Path | str,
    archive_readback_path: Path | str,
    provider_config_path: Path | str,
    retention_snapshot_path: Path | str,
    review_decision_path: Path | str,
    review_policy_path: Path | str,
    input_manifest_path: Path | str,
    *,
    prior_receipt_path: Path | str | None,
    expected_receipt_sha256: str,
    expected_policy_sha256: str,
    expected_archive_readback_sha256: str,
    expected_provider_config_sha256: str,
    expected_retention_snapshot_sha256: str,
    expected_verifier_source_sha256: str,
    expected_prior_receipt_sha256: str,
    expected_prior_checkpoint_sha256: str,
    expected_review_decision_sha256: str,
    expected_review_policy_sha256: str,
    expected_input_manifest_sha256: str,
    expected_review_verifier_source_sha256: str,
    expected_release_commit: str,
    expected_release_manifest_sha256: str,
    expected_decision_id: str,
    expected_receipt_id: str,
    expected_ledger_id: str,
    expected_sequence: int,
    verification_time: str,
) -> VerifiedArchiveReceipt:
    direct_paths = [
        receipt_path, policy_path, archive_readback_path, provider_config_path,
        retention_snapshot_path, review_decision_path, review_policy_path,
        input_manifest_path,
    ]
    if prior_receipt_path is not None:
        direct_paths.append(prior_receipt_path)
    normalized = {
        str(_external_path(path).resolve(strict=False)).casefold() for path in direct_paths
    }
    if len(normalized) != len(direct_paths):
        raise _invalid()
    blobs = [
        _read_blob(receipt_path, max_bytes=MAX_JSON_BYTES, external=True),
        _read_blob(policy_path, max_bytes=MAX_JSON_BYTES, external=True),
        _read_blob(archive_readback_path, max_bytes=MAX_OPAQUE_BYTES, external=True),
        _read_blob(provider_config_path, max_bytes=MAX_OPAQUE_BYTES, external=True),
        _read_blob(retention_snapshot_path, max_bytes=MAX_OPAQUE_BYTES, external=True),
        _read_blob(SOURCE, max_bytes=MAX_SOURCE_BYTES, external=False),
    ]
    prior_blob = (
        _read_blob(prior_receipt_path, max_bytes=MAX_JSON_BYTES, external=True)
        if prior_receipt_path is not None
        else None
    )
    try:
        early_pins = (
            expected_receipt_sha256, expected_policy_sha256,
            expected_archive_readback_sha256, expected_provider_config_sha256,
            expected_retention_snapshot_sha256, expected_verifier_source_sha256,
            expected_prior_receipt_sha256,
            expected_prior_checkpoint_sha256,
        )
        for pin in early_pins:
            _digest(pin)
        actual = [blob.sha256 for blob in blobs]
        expected = list(early_pins[:6])
        if any(not hmac.compare_digest(item, pin) for item, pin in zip(actual, expected, strict=True)):
            raise _invalid()
        actual_prior = prior_blob.sha256 if prior_blob is not None else ZERO_SHA256
        if not hmac.compare_digest(actual_prior, expected_prior_receipt_sha256):
            raise _invalid()

        verified_review = review.verify_decision(
            review_decision_path,
            review_policy_path,
            input_manifest_path,
            expected_decision_sha256=expected_review_decision_sha256,
            expected_policy_sha256=expected_review_policy_sha256,
            expected_input_manifest_sha256=expected_input_manifest_sha256,
            expected_verifier_source_sha256=expected_review_verifier_source_sha256,
            expected_release_commit=expected_release_commit,
            expected_release_manifest_sha256=expected_release_manifest_sha256,
            expected_decision_id=expected_decision_id,
            verification_time=verification_time,
        )
        verified = verify_archive_receipt_bytes(
            receipt_raw=blobs[0].raw,
            policy_raw=blobs[1].raw,
            archive_readback_raw=blobs[2].raw,
            provider_config_raw=blobs[3].raw,
            retention_snapshot_raw=blobs[4].raw,
            verifier_source_raw=blobs[5].raw,
            verified_review=verified_review,
            prior_receipt_raw=prior_blob.raw if prior_blob is not None else None,
            expected_receipt_sha256=expected_receipt_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_archive_readback_sha256=expected_archive_readback_sha256,
            expected_provider_config_sha256=expected_provider_config_sha256,
            expected_retention_snapshot_sha256=expected_retention_snapshot_sha256,
            expected_verifier_source_sha256=expected_verifier_source_sha256,
            expected_prior_receipt_sha256=expected_prior_receipt_sha256,
            expected_prior_checkpoint_sha256=expected_prior_checkpoint_sha256,
            expected_review_decision_sha256=expected_review_decision_sha256,
            expected_review_policy_sha256=expected_review_policy_sha256,
            expected_input_manifest_sha256=expected_input_manifest_sha256,
            expected_review_verifier_source_sha256=expected_review_verifier_source_sha256,
            expected_release_commit=expected_release_commit,
            expected_release_manifest_sha256=expected_release_manifest_sha256,
            expected_decision_id=expected_decision_id,
            expected_receipt_id=expected_receipt_id,
            expected_ledger_id=expected_ledger_id,
            expected_sequence=expected_sequence,
            verification_time=verification_time,
        )
    except (review.CollectionReviewDecisionError, TypeError, ValueError) as error:
        raise _invalid() from error
    for blob in (*blobs, *((prior_blob,) if prior_blob is not None else ())):
        _unchanged(blob)
    return verified


def verify_repository_assets() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = validate_policy(
            _document(read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
        receipt = validate_receipt(
            _document(read_stable_bytes(TEMPLATE, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
    except (OSError, StableFileError, TypeError, ValueError) as error:
        raise _invalid() from error
    return policy, receipt


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CollectionArchiveReceiptError("collection archive arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    for option in (
        "receipt", "policy", "archive-readback", "provider-config",
        "retention-snapshot", "review-decision", "review-policy", "input-manifest",
    ):
        verify.add_argument(f"--{option}", required=True, type=Path)
    verify.add_argument("--prior-receipt", type=Path)
    for option in (
        "expected-receipt-sha256", "expected-policy-sha256",
        "expected-archive-readback-sha256", "expected-provider-config-sha256",
        "expected-retention-snapshot-sha256", "expected-verifier-source-sha256",
        "expected-prior-receipt-sha256", "expected-prior-checkpoint-sha256",
        "expected-review-decision-sha256",
        "expected-review-policy-sha256", "expected-input-manifest-sha256",
        "expected-review-verifier-source-sha256", "expected-release-commit",
        "expected-release-manifest-sha256", "expected-decision-id",
        "expected-receipt-id", "expected-ledger-id", "verification-time",
    ):
        verify.add_argument(f"--{option}", required=True)
    verify.add_argument("--expected-sequence", required=True, type=int)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            verify_repository_assets()
            print(
                "private-secret-collection-archive-template-ok status=pending "
                "provider-signature=unverified custody-signature=unverified "
                "provider-native=unverified trusted-time=unverified "
                "global-replay-protection=unverified durability=unverified "
                "production_acceptance=false not_committed_eligible=false"
            )
            return 0
        verified = verify_archive_receipt(
            options.receipt,
            options.policy,
            options.archive_readback,
            options.provider_config,
            options.retention_snapshot,
            options.review_decision,
            options.review_policy,
            options.input_manifest,
            prior_receipt_path=options.prior_receipt,
            expected_receipt_sha256=options.expected_receipt_sha256,
            expected_policy_sha256=options.expected_policy_sha256,
            expected_archive_readback_sha256=options.expected_archive_readback_sha256,
            expected_provider_config_sha256=options.expected_provider_config_sha256,
            expected_retention_snapshot_sha256=options.expected_retention_snapshot_sha256,
            expected_verifier_source_sha256=options.expected_verifier_source_sha256,
            expected_prior_receipt_sha256=options.expected_prior_receipt_sha256,
            expected_prior_checkpoint_sha256=options.expected_prior_checkpoint_sha256,
            expected_review_decision_sha256=options.expected_review_decision_sha256,
            expected_review_policy_sha256=options.expected_review_policy_sha256,
            expected_input_manifest_sha256=options.expected_input_manifest_sha256,
            expected_review_verifier_source_sha256=options.expected_review_verifier_source_sha256,
            expected_release_commit=options.expected_release_commit,
            expected_release_manifest_sha256=options.expected_release_manifest_sha256,
            expected_decision_id=options.expected_decision_id,
            expected_receipt_id=options.expected_receipt_id,
            expected_ledger_id=options.expected_ledger_id,
            expected_sequence=options.expected_sequence,
            verification_time=options.verification_time,
        )
    except (CollectionArchiveReceiptError, OSError, TypeError, ValueError):
        print("private-secret-collection-archive-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-archive-ok provider-signature=verified "
        "custody-signature=verified one-hop-chain=verified "
        "provider-native=unverified trusted-time=unverified "
        "global-replay-protection=unverified decision-id-uniqueness=unverified "
        "verifier-release-provenance=unverified sink-immutability=unverified "
        "durability=unverified fork-protection=unverified "
        "rollback-protection=unverified production_acceptance=false "
        "not_committed_eligible=false "
        f"receipt_id={verified.receipt_id} sequence={verified.sequence} "
        f"head_sha256={verified.head_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
