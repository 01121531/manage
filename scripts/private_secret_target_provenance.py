"""Authenticate target crash-evidence bindings without asserting target facts.

The two Ed25519 signatures authenticate only the pinned key holders' common
statement and the exact supplied bytes. They do not prove WORM semantics,
target execution, human identity, trusted time, or production acceptance.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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
    MAX_EXTERNAL_JSON_BYTES,
    MAX_INTAKE_JSON_BYTES,
    StableFileError,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
)
from scripts.private_secret_crash_evidence import (
    POLICY as RUNTIME_POLICY,
    PrivateSecretCrashEvidenceError,
    validate_runtime_policy,
    verify_evidence_snapshot_bytes,
)
from scripts.release_execution_binding import (
    ReleaseExecutionBindingError,
    release_execution_identity,
)


POLICY = ROOT / "deploy" / "private-secret-target-provenance-policy.json"
SYNTHETIC = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-target-origin.synthetic.json"
)
SCHEMA_VERSION = 1
POLICY_KIND = "private_secret_target_provenance_trust_policy"
RECORD_TYPE = "private_secret_target_origin_intake"
RECEIPT_KIND = "private_secret_target_origin_receipt"
STATEMENT = "external_signers_bound_target_crash_artifacts_and_provider_receipt"

_TARGET_DOMAIN = b"email-platform/private-secret-target-origin/target-signer/v1\0"
_STORAGE_DOMAIN = b"email-platform/private-secret-target-origin/storage-signer/v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = frozenset(
    {"development", "example", "local", "placeholder", "tbd", "test", "unknown"}
)
_SENSITIVE_REFERENCE_FRAGMENTS = frozenset(
    {"password", "path", "secret", "token", "url"}
)

_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "executor_integration_enabled",
    "handoff_integration_enabled",
    "state",
    "target_signer",
    "storage_signer",
    "custody_requirements",
    "time_constraints",
}
_ANCHOR_FIELDS = {
    "state",
    "algorithm",
    "usage_scope",
    "key_id",
    "public_key_b64url",
    "source",
}
_CUSTODY_REQUIREMENT_FIELDS = {
    "dedicated_distinct_keys_required",
    "private_keys_in_repository",
    "private_key_cli_environment_transport",
    "external_custody_evidence_required",
    "independent_review_required",
}
_TIME_CONSTRAINT_FIELDS = {
    "max_crash_review_to_commit_seconds",
    "max_commit_to_readback_seconds",
    "max_readback_to_review_seconds",
    "max_review_to_signature_seconds",
    "retention_must_cover_verification",
}
_TEMPLATE_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "provider_receipt_authentication",
    "production_acceptance",
    "not_committed_eligible",
    "payload",
    "signatures",
    "integrity",
}
_BUNDLE_FIELDS = _TEMPLATE_FIELDS - {"integrity"}
_PAYLOAD_FIELDS = {
    "schema_version",
    "receipt_kind",
    "statement",
    "production_acceptance",
    "not_committed_eligible",
    "attempt_id",
    "trust_policy_sha256",
    "target",
    "release",
    "crash_evidence",
    "publication",
    "custody",
    "review",
    "timeline",
}
_TARGET_FIELDS = {
    "environment",
    "target_inventory_artifact_sha256",
    "target_inventory_reference",
    "cluster_identity_fingerprint_sha256",
}
_RELEASE_FIELDS = {
    "ledger_type",
    "evidence_artifact_sha256",
    "tag",
    "commit",
    "container_manifest_sha256",
    "target_intake_manifest_payload_sha256",
    "target_intake_requirements_sha256",
}
_CRASH_FIELDS = {
    "evidence_artifact_sha256",
    "evidence_payload_sha256",
    "runtime_root_policy_sha256",
    "before_inventory_artifact_sha256",
    "after_inventory_artifact_sha256",
    "alert_delivery_reference",
    "alert_artifact_sha256",
}
_PUBLICATION_FIELDS = {
    "storage_identity_fingerprint_sha256",
    "object_reference",
    "immutable_version_reference",
    "provider_receipt_artifact_sha256",
    "delete_probe_artifact_sha256",
    "evidence_readback_sha256",
}
_CUSTODY_FIELDS = {"evidence_reference", "artifact_sha256"}
_REVIEW_FIELDS = {"reviewer_reference", "decision"}
_TIMELINE_FIELDS = {
    "crash_reviewed_at",
    "committed_at",
    "read_back_at",
    "reviewed_at",
    "signed_at",
    "retention_until",
}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_SIGNATURES_FIELDS = {"target_signer", "storage_signer"}


class PrivateSecretTargetProvenanceError(ValueError):
    """A target-origin assertion cannot be authenticated safely."""


def _invalid() -> PrivateSecretTargetProvenanceError:
    return PrivateSecretTargetProvenanceError(
        "private secret target provenance is invalid"
    )


@dataclass(frozen=True)
class PinnedAnchor:
    public_key_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.public_key_bytes) is not bytes or len(self.public_key_bytes) != 32:
            raise _invalid()
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError:
            raise _invalid() from None

    @property
    def key_id(self) -> str:
        return "ed25519-sha256:" + hashlib.sha256(self.public_key_bytes).hexdigest()


@dataclass(frozen=True)
class VerifiedTargetOrigin:
    attempt_id: str
    receipt_fingerprint_sha256: str
    alert_fingerprint_sha256: str
    storage_identity_fingerprint_sha256: str
    object_reference: str
    immutable_version_reference: str
    evidence_readback_sha256: str
    target_signer_key_id: str
    storage_signer_key_id: str


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


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _reference(value: object) -> str:
    folded = value.casefold() if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or _REFERENCE.fullmatch(value) is None
        or folded in _PLACEHOLDERS
        or any(fragment in folded for fragment in _SENSITIVE_REFERENCE_FRAGMENTS)
    ):
        raise _invalid()
    return value


def _object_reference(value: object) -> str:
    prefix = "worm-private-secret-crash:"
    suffix = value.removeprefix(prefix) if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or _REFERENCE.fullmatch(value) is None
        or not value.startswith(prefix)
        or suffix.casefold() in _PLACEHOLDERS
        or not any(character.isalpha() for character in suffix)
        or not any(character.isdigit() for character in suffix)
    ):
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


def _decode_public_key(value: object) -> bytes:
    if not isinstance(value, str) or _PUBLIC_KEY.fullmatch(value) is None:
        raise _invalid()
    try:
        raw = base64.urlsafe_b64decode(value + "=")
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    except (ValueError, binascii.Error, UnicodeError):
        raise _invalid() from None
    if len(raw) != 32 or not hmac.compare_digest(value, canonical):
        raise _invalid()
    return raw


def _validate_anchor(value: object, *, state: str, usage_scope: str) -> bytes | None:
    anchor = _closed(value, _ANCHOR_FIELDS)
    if (
        anchor["state"] != state
        or anchor["algorithm"] != "Ed25519"
        or anchor["usage_scope"] != usage_scope
        or anchor["source"] != "release_governed_repository_configuration"
    ):
        raise _invalid()
    if state == "unconfigured":
        if anchor["key_id"] is not None or anchor["public_key_b64url"] is not None:
            raise _invalid()
        return None
    if (
        not isinstance(anchor["key_id"], str)
        or _KEY_ID.fullmatch(anchor["key_id"]) is None
    ):
        raise _invalid()
    raw = _decode_public_key(anchor["public_key_b64url"])
    if not hmac.compare_digest(anchor["key_id"], PinnedAnchor(raw).key_id):
        raise _invalid()
    return raw


def validate_trust_policy(value: object) -> dict[str, Any]:
    policy = _closed(value, _POLICY_FIELDS)
    state = policy["state"]
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "authentication_prerequisite_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
        or policy["executor_integration_enabled"] is not False
        or policy["handoff_integration_enabled"] is not False
        or state not in {"unconfigured", "pinned"}
    ):
        raise _invalid()
    target_key = _validate_anchor(
        policy["target_signer"],
        state=state,
        usage_scope="private_secret_target_crash_origin_v1_only",
    )
    storage_key = _validate_anchor(
        policy["storage_signer"],
        state=state,
        usage_scope="private_secret_target_storage_receipt_v1_only",
    )
    if state == "pinned" and hmac.compare_digest(target_key or b"", storage_key or b""):
        raise _invalid()
    custody = _closed(policy["custody_requirements"], _CUSTODY_REQUIREMENT_FIELDS)
    if custody != {
        "dedicated_distinct_keys_required": True,
        "private_keys_in_repository": "forbidden",
        "private_key_cli_environment_transport": "forbidden",
        "external_custody_evidence_required": True,
        "independent_review_required": True,
    }:
        raise _invalid()
    constraints = _closed(policy["time_constraints"], _TIME_CONSTRAINT_FIELDS)
    if (
        any(
            type(constraints[field]) is not int
            or not 1 <= constraints[field] <= 86_400
            for field in _TIME_CONSTRAINT_FIELDS
            if field != "retention_must_cover_verification"
        )
        or constraints["retention_must_cover_verification"] is not True
    ):
        raise _invalid()
    return dict(policy)


def parse_trust_policy(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        return validate_trust_policy(parse_unique_json_bytes(raw))
    except PrivateSecretTargetProvenanceError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


def load_trust_policy(policy_path: Path | str | None = None) -> tuple[dict[str, Any], str]:
    try:
        raw = read_stable_bytes(POLICY if policy_path is None else policy_path, max_bytes=MAX_INTAKE_JSON_BYTES)
        policy = parse_trust_policy(raw)
    except (OSError, StableFileError) as error:
        raise _invalid() from error
    return policy, hashlib.sha256(raw).hexdigest()


def _external_path(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return path
    raise _invalid()


def _read_external_bytes(path: Path | str, *, max_bytes: int) -> bytes:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            _external_path(path), max_bytes=max_bytes
        )
        if metadata.st_nlink != 1:
            raise _invalid()
        return raw
    except (OSError, StableFileError, TypeError, ValueError) as error:
        raise _invalid() from error


def _validate_template(value: object) -> dict[str, Any]:
    template = _closed(value, _TEMPLATE_FIELDS)
    integrity = _closed(template["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in template.items() if key != "integrity"}
    if (
        type(template["schema_version"]) is not int
        or template["schema_version"] != SCHEMA_VERSION
        or template["record_type"] != RECORD_TYPE
        or template["synthetic"] is not True
        or template["evidence_status"] != "pending"
        or template["origin_authentication"] != "unverified"
        or template["provider_receipt_authentication"] != "unverified"
        or template["production_acceptance"] is not False
        or template["not_committed_eligible"] is not False
        or template["payload"] is not None
        or template["signatures"] is not None
        or not hmac.compare_digest(
            _digest(integrity["payload_sha256"]), _canonical_digest(payload)
        )
    ):
        raise _invalid()
    return dict(template)


def verify_repository_assets() -> tuple[dict[str, Any], str]:
    policy, policy_digest = load_trust_policy()
    if policy["state"] != "unconfigured":
        raise _invalid()
    try:
        template = _validate_template(
            parse_unique_json_bytes(
                read_stable_bytes(SYNTHETIC, max_bytes=MAX_INTAKE_JSON_BYTES)
            )
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
    return template, policy_digest


def _validate_payload(value: object) -> dict[str, Any]:
    payload = _closed(value, _PAYLOAD_FIELDS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["receipt_kind"] != RECEIPT_KIND
        or payload["statement"] != STATEMENT
        or payload["production_acceptance"] is not False
        or payload["not_committed_eligible"] is not False
    ):
        raise _invalid()
    try:
        from uuid import UUID

        attempt = UUID(payload["attempt_id"], version=4)
    except (AttributeError, TypeError, ValueError):
        raise _invalid() from None
    if str(attempt) != payload["attempt_id"]:
        raise _invalid()
    _digest(payload["trust_policy_sha256"])

    target = _closed(payload["target"], _TARGET_FIELDS)
    if (
        not isinstance(target["environment"], str)
        or _ENVIRONMENT.fullmatch(target["environment"]) is None
        or target["environment"].casefold() in _PLACEHOLDERS
    ):
        raise _invalid()
    _reference(target["target_inventory_reference"])
    for field in (
        "target_inventory_artifact_sha256",
        "cluster_identity_fingerprint_sha256",
    ):
        _digest(target[field])

    release = _closed(payload["release"], _RELEASE_FIELDS)
    if release["ledger_type"] not in {"forward", "rolling"}:
        raise _invalid()
    for field in (
        "evidence_artifact_sha256",
        "container_manifest_sha256",
        "target_intake_manifest_payload_sha256",
        "target_intake_requirements_sha256",
    ):
        _digest(release[field])
    if not isinstance(release["tag"], str) or not isinstance(release["commit"], str):
        raise _invalid()

    crash = _closed(payload["crash_evidence"], _CRASH_FIELDS)
    for field in _CRASH_FIELDS - {"alert_delivery_reference"}:
        _digest(crash[field])
    _reference(crash["alert_delivery_reference"])

    publication = _closed(payload["publication"], _PUBLICATION_FIELDS)
    for field in _PUBLICATION_FIELDS - {"object_reference", "immutable_version_reference"}:
        _digest(publication[field])
    _object_reference(publication["object_reference"])
    _reference(publication["immutable_version_reference"])

    custody = _closed(payload["custody"], _CUSTODY_FIELDS)
    _reference(custody["evidence_reference"])
    _digest(custody["artifact_sha256"])
    review = _closed(payload["review"], _REVIEW_FIELDS)
    _reference(review["reviewer_reference"])
    if review["decision"] != "accepted_for_provenance_only":
        raise _invalid()
    if custody["evidence_reference"].casefold() == review["reviewer_reference"].casefold():
        raise _invalid()
    timeline = _closed(payload["timeline"], _TIMELINE_FIELDS)
    for field in _TIMELINE_FIELDS:
        _timestamp(timeline[field])
    return payload


def _validate_signature(value: object) -> dict[str, Any]:
    signature = _closed(value, _SIGNATURE_FIELDS)
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
        or not isinstance(signature["value_b64url"], str)
        or _SIGNATURE.fullmatch(signature["value_b64url"]) is None
    ):
        raise _invalid()
    return signature


def _validate_bundle(value: object) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _closed(value, _BUNDLE_FIELDS)
    if (
        type(bundle["schema_version"]) is not int
        or bundle["schema_version"] != SCHEMA_VERSION
        or bundle["record_type"] != RECORD_TYPE
        or bundle["synthetic"] is not False
        or bundle["evidence_status"] != "signed_assertion"
        or bundle["origin_authentication"] != "unverified"
        or bundle["provider_receipt_authentication"] != "unverified"
        or bundle["production_acceptance"] is not False
        or bundle["not_committed_eligible"] is not False
    ):
        raise _invalid()
    payload = _validate_payload(bundle["payload"])
    signatures = _closed(bundle["signatures"], _SIGNATURES_FIELDS)
    target_signature = _validate_signature(signatures["target_signer"])
    storage_signature = _validate_signature(signatures["storage_signer"])
    if hmac.compare_digest(target_signature["key_id"], storage_signature["key_id"]):
        raise _invalid()
    return payload, signatures


def signature_message(payload: Mapping[str, object], *, role: str) -> bytes:
    """Return a role-separated canonical message; this function never signs."""

    validated = _validate_payload(dict(payload))
    if role == "target_signer":
        domain = _TARGET_DOMAIN
    elif role == "storage_signer":
        domain = _STORAGE_DOMAIN
    else:
        raise _invalid()
    canonical = _canonical_bytes(validated)
    return domain + len(canonical).to_bytes(8, "big") + canonical


def _verify_signature(
    payload: Mapping[str, object],
    signature: Mapping[str, object],
    *,
    role: str,
    anchor: PinnedAnchor,
) -> None:
    if not hmac.compare_digest(str(signature["key_id"]), anchor.key_id):
        raise _invalid()
    encoded = str(signature["value_b64url"])
    try:
        raw = base64.urlsafe_b64decode(encoded + "==")
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if len(raw) != 64 or not hmac.compare_digest(encoded, canonical):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(anchor.public_key_bytes).verify(
            raw, signature_message(payload, role=role)
        )
    except (InvalidSignature, ValueError, binascii.Error, UnicodeError):
        raise _invalid() from None


def _aligned_digest(actual: str, expected: object) -> None:
    if not hmac.compare_digest(actual, _digest(expected)):
        raise _invalid()


def _verify_times(
    payload: Mapping[str, Any],
    crash_envelope: Mapping[str, Any],
    constraints: Mapping[str, Any],
    verification_time: str,
) -> None:
    timeline = payload["timeline"]
    crash_reviewed = _timestamp(timeline["crash_reviewed_at"])
    if timeline["crash_reviewed_at"] != crash_envelope["review"]["reviewed_at"]:
        raise _invalid()
    committed = _timestamp(timeline["committed_at"])
    read_back = _timestamp(timeline["read_back_at"])
    reviewed = _timestamp(timeline["reviewed_at"])
    signed = _timestamp(timeline["signed_at"])
    retention = _timestamp(timeline["retention_until"])
    checked_at = _timestamp(verification_time)
    ordered = crash_reviewed <= committed <= read_back <= reviewed <= signed <= checked_at
    if not ordered or checked_at > retention or signed >= retention:
        raise _invalid()
    intervals = (
        (committed - crash_reviewed).total_seconds(),
        (read_back - committed).total_seconds(),
        (reviewed - read_back).total_seconds(),
        (signed - reviewed).total_seconds(),
    )
    limits = (
        constraints["max_crash_review_to_commit_seconds"],
        constraints["max_commit_to_readback_seconds"],
        constraints["max_readback_to_review_seconds"],
        constraints["max_review_to_signature_seconds"],
    )
    if any(interval > limit for interval, limit in zip(intervals, limits, strict=True)):
        raise _invalid()


def verify_target_origin(
    input_path: Path | str,
    crash_evidence_path: Path | str,
    before_inventory_path: Path | str,
    after_inventory_path: Path | str,
    target_inventory_path: Path | str,
    release_execution_path: Path | str,
    alert_evidence_path: Path | str,
    worm_receipt_path: Path | str,
    delete_probe_path: Path | str,
    custody_evidence_path: Path | str,
    *,
    policy_path: Path | str | None = None,
    expected_cluster_fingerprint_sha256: str,
    expected_policy_sha256: str,
    verification_time: str,
) -> VerifiedTargetOrigin:
    """Authenticate two assertions over exact, independently supplied snapshots."""

    paths = (
        input_path,
        crash_evidence_path,
        before_inventory_path,
        after_inventory_path,
        target_inventory_path,
        release_execution_path,
        alert_evidence_path,
        worm_receipt_path,
        delete_probe_path,
        custody_evidence_path,
    )
    normalized = {
        str(_external_path(path).resolve(strict=False)).casefold() for path in paths
    }
    if len(normalized) != len(paths):
        raise _invalid()
    try:
        policy_raw = (
            read_stable_bytes(POLICY, max_bytes=MAX_INTAKE_JSON_BYTES)
            if policy_path is None
            else _read_external_bytes(policy_path, max_bytes=MAX_INTAKE_JSON_BYTES)
        )
        runtime_policy_raw = read_stable_bytes(
            RUNTIME_POLICY, max_bytes=MAX_INTAKE_JSON_BYTES
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    bundle_raw = _read_external_bytes(input_path, max_bytes=MAX_INTAKE_JSON_BYTES)
    crash_raw = _read_external_bytes(crash_evidence_path, max_bytes=MAX_INTAKE_JSON_BYTES)
    before_raw = _read_external_bytes(before_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    after_raw = _read_external_bytes(after_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    target_inventory_raw = _read_external_bytes(target_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    release_raw = _read_external_bytes(release_execution_path, max_bytes=MAX_INTAKE_JSON_BYTES)
    alert_raw = _read_external_bytes(alert_evidence_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    worm_raw = _read_external_bytes(worm_receipt_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    delete_raw = _read_external_bytes(delete_probe_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    custody_raw = _read_external_bytes(custody_evidence_path, max_bytes=MAX_EXTERNAL_JSON_BYTES)
    return verify_target_origin_bytes(
        input_raw=bundle_raw,
        policy_raw=policy_raw,
        runtime_policy_raw=runtime_policy_raw,
        crash_evidence_raw=crash_raw,
        before_inventory_raw=before_raw,
        after_inventory_raw=after_raw,
        target_inventory_raw=target_inventory_raw,
        release_execution_raw=release_raw,
        alert_evidence_raw=alert_raw,
        worm_receipt_raw=worm_raw,
        delete_probe_raw=delete_raw,
        custody_evidence_raw=custody_raw,
        expected_cluster_fingerprint_sha256=expected_cluster_fingerprint_sha256,
        expected_policy_sha256=expected_policy_sha256,
        verification_time=verification_time,
    )


def verify_target_origin_bytes(
    *,
    input_raw: bytes,
    policy_raw: bytes,
    runtime_policy_raw: bytes,
    crash_evidence_raw: bytes,
    before_inventory_raw: bytes,
    after_inventory_raw: bytes,
    target_inventory_raw: bytes,
    release_execution_raw: bytes,
    alert_evidence_raw: bytes,
    worm_receipt_raw: bytes,
    delete_probe_raw: bytes,
    custody_evidence_raw: bytes,
    expected_cluster_fingerprint_sha256: str,
    expected_policy_sha256: str,
    verification_time: str,
) -> VerifiedTargetOrigin:
    """Authenticate exact caller-supplied bytes without filesystem access."""

    raw_limits = (
        (input_raw, MAX_INTAKE_JSON_BYTES),
        (policy_raw, MAX_INTAKE_JSON_BYTES),
        (runtime_policy_raw, MAX_INTAKE_JSON_BYTES),
        (crash_evidence_raw, MAX_INTAKE_JSON_BYTES),
        (before_inventory_raw, MAX_EXTERNAL_JSON_BYTES),
        (after_inventory_raw, MAX_EXTERNAL_JSON_BYTES),
        (target_inventory_raw, MAX_EXTERNAL_JSON_BYTES),
        (release_execution_raw, MAX_INTAKE_JSON_BYTES),
        (alert_evidence_raw, MAX_EXTERNAL_JSON_BYTES),
        (worm_receipt_raw, MAX_EXTERNAL_JSON_BYTES),
        (delete_probe_raw, MAX_EXTERNAL_JSON_BYTES),
        (custody_evidence_raw, MAX_EXTERNAL_JSON_BYTES),
    )
    if any(type(raw) is not bytes or not raw or len(raw) > limit for raw, limit in raw_limits):
        raise _invalid()
    _digest(expected_cluster_fingerprint_sha256)
    _digest(expected_policy_sha256)
    _timestamp(verification_time)
    try:
        policy = parse_trust_policy(policy_raw)
    except (PrivateSecretTargetProvenanceError, TypeError, ValueError) as error:
        raise _invalid() from error
    policy_digest = hashlib.sha256(policy_raw).hexdigest()
    if policy["state"] != "pinned" or not hmac.compare_digest(policy_digest, expected_policy_sha256):
        raise _invalid()
    target_key = _decode_public_key(policy["target_signer"]["public_key_b64url"])
    storage_key = _decode_public_key(policy["storage_signer"]["public_key_b64url"])

    try:
        bundle_value = parse_unique_json_bytes(input_raw)
        payload, signatures = _validate_bundle(bundle_value)
    except (
        UnicodeError,
        json.JSONDecodeError,
        PrivateSecretTargetProvenanceError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error
    if not hmac.compare_digest(input_raw, _canonical_bytes(bundle_value)):
        raise _invalid()
    try:
        runtime_policy = validate_runtime_policy(parse_unique_json_bytes(runtime_policy_raw))
        runtime_policy_digest = hashlib.sha256(_canonical_bytes(runtime_policy)).hexdigest()
        crash_snapshot = verify_evidence_snapshot_bytes(
            input_raw=crash_evidence_raw,
            before_inventory_raw=before_inventory_raw,
            after_inventory_raw=after_inventory_raw,
            runtime_policy_raw=runtime_policy_raw,
            expected_runtime_policy_sha256=runtime_policy_digest,
            target_inventory_raw=target_inventory_raw,
        )
    except (PrivateSecretCrashEvidenceError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error
    crash_envelope = crash_snapshot.envelope
    if crash_envelope["scope"]["kind"] != "kubernetes_target_host":
        raise _invalid()

    opaque_digests = {
        hashlib.sha256(raw).hexdigest()
        for raw in (alert_evidence_raw, worm_receipt_raw, delete_probe_raw, custody_evidence_raw)
    }
    if len(opaque_digests) != 4:
        raise _invalid()
    try:
        release_identity = release_execution_identity(release_execution_raw)
    except ReleaseExecutionBindingError as error:
        raise _invalid() from error
    if not release_identity["successful"]:
        raise _invalid()

    target = payload["target"]
    scope = crash_envelope["scope"]
    if (
        target["environment"] != scope["environment"]
        or target["target_inventory_reference"] != scope["target_inventory_reference"]
        or not hmac.compare_digest(
            target["cluster_identity_fingerprint_sha256"],
            expected_cluster_fingerprint_sha256,
        )
    ):
        raise _invalid()
    _aligned_digest(
        str(crash_snapshot.target_inventory_artifact_sha256),
        target["target_inventory_artifact_sha256"],
    )

    release = payload["release"]
    target_release = release_identity["target_release"]
    target_intake = release_identity["target_intake"]
    expected_release = {
        "ledger_type": release_identity["ledger_type"],
        "evidence_artifact_sha256": release_identity["evidence_sha256"],
        "tag": target_release["tag"],
        "commit": target_release["commit"],
        "container_manifest_sha256": target_release["container_manifest_sha256"],
        "target_intake_manifest_payload_sha256": target_intake["manifest_payload_sha256"],
        "target_intake_requirements_sha256": target_intake["requirements_sha256"],
    }
    if release != expected_release or target_intake["environment"] != target["environment"]:
        raise _invalid()

    crash = payload["crash_evidence"]
    expected_crash = {
        "evidence_artifact_sha256": crash_snapshot.evidence_artifact_sha256,
        "evidence_payload_sha256": crash_envelope["integrity"]["payload_sha256"],
        "runtime_root_policy_sha256": crash_envelope["runtime_root_policy_sha256"],
        "before_inventory_artifact_sha256": crash_snapshot.before_inventory_artifact_sha256,
        "after_inventory_artifact_sha256": crash_snapshot.after_inventory_artifact_sha256,
        "alert_delivery_reference": crash_envelope["alert"]["delivery_reference"],
        "alert_artifact_sha256": hashlib.sha256(alert_evidence_raw).hexdigest(),
    }
    if crash != expected_crash:
        raise _invalid()
    _aligned_digest(
        hashlib.sha256(alert_evidence_raw).hexdigest(),
        crash_envelope["alert"]["artifact_sha256"],
    )

    publication = payload["publication"]
    if hmac.compare_digest(
        publication["object_reference"].casefold(),
        publication["immutable_version_reference"].casefold(),
    ):
        raise _invalid()
    _aligned_digest(
        hashlib.sha256(worm_receipt_raw).hexdigest(),
        publication["provider_receipt_artifact_sha256"],
    )
    _aligned_digest(
        hashlib.sha256(delete_probe_raw).hexdigest(),
        publication["delete_probe_artifact_sha256"],
    )
    _aligned_digest(
        crash_snapshot.evidence_artifact_sha256,
        publication["evidence_readback_sha256"],
    )
    custody = payload["custody"]
    _aligned_digest(
        hashlib.sha256(custody_evidence_raw).hexdigest(), custody["artifact_sha256"]
    )
    refs = [
        custody["evidence_reference"],
        payload["review"]["reviewer_reference"],
        crash_envelope["review"]["operator_reference"],
        crash_envelope["review"]["cleanup_approver_reference"],
        crash_envelope["review"]["reviewer_reference"],
    ]
    if len({str(reference).casefold() for reference in refs}) != len(refs):
        raise _invalid()
    _aligned_digest(policy_digest, payload["trust_policy_sha256"])
    if payload["attempt_id"] != crash_envelope["attempt_id"]:
        raise _invalid()
    _verify_times(
        payload,
        crash_envelope,
        policy["time_constraints"],
        verification_time,
    )

    target_anchor = PinnedAnchor(target_key)
    storage_anchor = PinnedAnchor(storage_key)
    _verify_signature(
        payload,
        signatures["target_signer"],
        role="target_signer",
        anchor=target_anchor,
    )
    _verify_signature(
        payload,
        signatures["storage_signer"],
        role="storage_signer",
        anchor=storage_anchor,
    )
    return VerifiedTargetOrigin(
        attempt_id=payload["attempt_id"],
        receipt_fingerprint_sha256=hashlib.sha256(input_raw).hexdigest(),
        alert_fingerprint_sha256=hashlib.sha256(alert_evidence_raw).hexdigest(),
        storage_identity_fingerprint_sha256=publication[
            "storage_identity_fingerprint_sha256"
        ],
        object_reference=publication["object_reference"],
        immutable_version_reference=publication["immutable_version_reference"],
        evidence_readback_sha256=publication["evidence_readback_sha256"],
        target_signer_key_id=target_anchor.key_id,
        storage_signer_key_id=storage_anchor.key_id,
    )


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PrivateSecretTargetProvenanceError(
            "private secret target provenance arguments are invalid"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--crash-evidence", type=Path, required=True)
    verify.add_argument("--before-inventory", type=Path, required=True)
    verify.add_argument("--after-inventory", type=Path, required=True)
    verify.add_argument("--target-inventory", type=Path, required=True)
    verify.add_argument("--release-execution", type=Path, required=True)
    verify.add_argument("--alert-evidence", type=Path, required=True)
    verify.add_argument("--worm-receipt", type=Path, required=True)
    verify.add_argument("--delete-probe", type=Path, required=True)
    verify.add_argument("--custody-evidence", type=Path, required=True)
    verify.add_argument("--expected-cluster-fingerprint-sha256", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--verification-time", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            _, policy_digest = verify_repository_assets()
            print(
                "private-secret-target-origin-template-ok "
                "status=unconfigured origin-authentication=unverified "
                "provider-receipt-authentication=unverified "
                "freshness=unverified replay-protection=unverified "
                "durability=unverified reviewer-independence=unverified "
                "production_acceptance=false not_committed_eligible=false "
                f"policy_sha256={policy_digest}"
            )
            return 0
        verified = verify_target_origin(
            options.input,
            options.crash_evidence,
            options.before_inventory,
            options.after_inventory,
            options.target_inventory,
            options.release_execution,
            options.alert_evidence,
            options.worm_receipt,
            options.delete_probe,
            options.custody_evidence,
            expected_cluster_fingerprint_sha256=options.expected_cluster_fingerprint_sha256,
            expected_policy_sha256=options.expected_policy_sha256,
            verification_time=options.verification_time,
        )
    except (
        OSError,
        PrivateSecretTargetProvenanceError,
        TypeError,
        ValueError,
    ):
        print("private-secret-target-origin-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-target-origin-ok "
        "origin-authentication=authenticated-external-signer-assertion "
        "provider-receipt-authenticated=true "
        "freshness=unverified replay-protection=unverified "
        "durability=unverified reviewer-independence=unverified "
        "production_acceptance=false not_committed_eligible=false "
        f"receipt_fingerprint_sha256={verified.receipt_fingerprint_sha256} "
        f"alert_fingerprint_sha256={verified.alert_fingerprint_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
