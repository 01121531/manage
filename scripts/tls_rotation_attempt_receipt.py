"""Pure verification for a pinned Ed25519 ready-before-link assertion."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Mapping
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.external_json import parse_unique_json_bytes


SCHEMA_VERSION = 1
RECEIPT_KIND = "tls_rotation_publication_attempt"
STATEMENT = "ready_before_link"
MAX_RECEIPT_BYTES = 16 * 1024
_DOMAIN = b"email-platform/tls-rotation-publication-attempt/v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PAYLOAD_FIELDS = {
    "schema_version",
    "receipt_kind",
    "statement",
    "production_acceptance",
    "not_committed_eligible",
    "attempt_id",
    "rotation_plan_sha256",
    "runtime_profile_sha256",
    "evidence_payload_sha256",
    "evidence_artifact_sha256",
    "ready_at",
}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_ENVELOPE_FIELDS = {"payload", "signature"}


class TlsRotationAttemptReceiptError(ValueError):
    """A ready-before-link assertion failed closed validation."""


@dataclass(frozen=True)
class PinnedEd25519TrustAnchor:
    public_key_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.public_key_bytes) is not bytes or len(self.public_key_bytes) != 32:
            raise TlsRotationAttemptReceiptError("publisher trust anchor is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        except ValueError:
            raise TlsRotationAttemptReceiptError("publisher trust anchor is invalid") from None

    @property
    def key_id(self) -> str:
        return "ed25519-sha256:" + hashlib.sha256(self.public_key_bytes).hexdigest()


@dataclass(frozen=True)
class ValidatedReadyAssertion:
    attempt_id: str
    rotation_plan_sha256: str
    runtime_profile_sha256: str
    evidence_payload_sha256: str
    evidence_artifact_sha256: str
    ready_at: str
    signer_key_id: str


def _closed(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    return value


def _validate_attempt_id(value: object) -> str:
    if not isinstance(value, str):
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    return value


def _validate_utc(value: object) -> str:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid") from None
    if parsed.tzinfo != timezone.utc:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    return value


def _validate_payload(value: object) -> dict[str, object]:
    payload = _closed(value, _PAYLOAD_FIELDS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["receipt_kind"] != RECEIPT_KIND
        or payload["statement"] != STATEMENT
        or payload["production_acceptance"] is not False
        or payload["not_committed_eligible"] is not False
    ):
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    _validate_attempt_id(payload["attempt_id"])
    for field in (
        "rotation_plan_sha256",
        "runtime_profile_sha256",
        "evidence_payload_sha256",
        "evidence_artifact_sha256",
    ):
        _digest(payload[field])
    _validate_utc(payload["ready_at"])
    return payload


def _normalized_sink(path_flavor: str, value: str) -> str:
    if path_flavor == "windows":
        path = PureWindowsPath(value)
        if not path.is_absolute() or not path.drive or path.drive.startswith("\\"):
            raise TlsRotationAttemptReceiptError("evidence sink binding is invalid")
        normalized = str(path)
        if normalized != value or any(part in {".", ".."} for part in path.parts):
            raise TlsRotationAttemptReceiptError("evidence sink binding is invalid")
        return normalized
    if path_flavor == "posix":
        path = PurePosixPath(value)
        normalized = str(path)
        if not path.is_absolute() or normalized != value or any(
            part in {".", ".."} for part in path.parts
        ):
            raise TlsRotationAttemptReceiptError("evidence sink binding is invalid")
        return normalized
    raise TlsRotationAttemptReceiptError("evidence sink binding is invalid")


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attempt_signature_message(
    payload: Mapping[str, object],
    *,
    expected_evidence_output: str,
    path_flavor: str,
) -> bytes:
    """Return the domain-separated message; this function never signs it."""

    validated = _validate_payload(dict(payload))
    sink = _normalized_sink(path_flavor, expected_evidence_output)
    payload_bytes = _canonical(validated)
    aad_bytes = _canonical({
        "aad_kind": "tls_rotation_evidence_sink",
        "aad_version": 1,
        "normalized_absolute_path": sink,
        "path_flavor": path_flavor,
    })
    return (
        _DOMAIN
        + len(payload_bytes).to_bytes(8, "big")
        + payload_bytes
        + len(aad_bytes).to_bytes(8, "big")
        + aad_bytes
    )


def verify_authenticated_attempt(
    raw_receipt: bytes,
    *,
    expected_attempt_id: str,
    expected_rotation_plan_sha256: str,
    expected_runtime_profile_sha256: str,
    expected_evidence_payload_sha256: str,
    expected_evidence_artifact_sha256: str,
    expected_evidence_output: str,
    path_flavor: str,
    trusted_anchor: PinnedEd25519TrustAnchor,
) -> ValidatedReadyAssertion:
    """Authenticate one assertion without reading a sink or inferring publication."""

    if type(raw_receipt) is not bytes or not raw_receipt or len(raw_receipt) > MAX_RECEIPT_BYTES:
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid")
    try:
        envelope = _closed(parse_unique_json_bytes(raw_receipt), _ENVELOPE_FIELDS)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise TlsRotationAttemptReceiptError("publication attempt receipt is invalid") from None
    payload = _validate_payload(envelope["payload"])
    signature = _closed(envelope["signature"], _SIGNATURE_FIELDS)
    value_b64url = signature["value_b64url"]
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
        or not hmac.compare_digest(signature["key_id"], trusted_anchor.key_id)
        or not isinstance(value_b64url, str)
        or _SIGNATURE.fullmatch(value_b64url) is None
    ):
        raise TlsRotationAttemptReceiptError("publication attempt authentication failed")
    expected = {
        "attempt_id": _validate_attempt_id(expected_attempt_id),
        "rotation_plan_sha256": _digest(expected_rotation_plan_sha256),
        "runtime_profile_sha256": _digest(expected_runtime_profile_sha256),
        "evidence_payload_sha256": _digest(expected_evidence_payload_sha256),
        "evidence_artifact_sha256": _digest(expected_evidence_artifact_sha256),
    }
    if any(
        not hmac.compare_digest(str(payload[field]), expected_value)
        for field, expected_value in expected.items()
    ):
        raise TlsRotationAttemptReceiptError("publication attempt binding failed")
    try:
        signature_bytes = base64.urlsafe_b64decode(value_b64url + "==")
        if len(signature_bytes) != 64:
            raise ValueError
        canonical_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(value_b64url, canonical_signature):
            raise ValueError
        message = attempt_signature_message(
            payload,
            expected_evidence_output=expected_evidence_output,
            path_flavor=path_flavor,
        )
        Ed25519PublicKey.from_public_bytes(trusted_anchor.public_key_bytes).verify(
            signature_bytes, message
        )
    except (InvalidSignature, ValueError):
        raise TlsRotationAttemptReceiptError("publication attempt authentication failed") from None
    return ValidatedReadyAssertion(
        attempt_id=str(payload["attempt_id"]),
        rotation_plan_sha256=str(payload["rotation_plan_sha256"]),
        runtime_profile_sha256=str(payload["runtime_profile_sha256"]),
        evidence_payload_sha256=str(payload["evidence_payload_sha256"]),
        evidence_artifact_sha256=str(payload["evidence_artifact_sha256"]),
        ready_at=str(payload["ready_at"]),
        signer_key_id=str(signature["key_id"]),
    )


CRASH_MATRIX = {
    "before_ready_receipt": "unknown",
    "after_ready_before_link": "unknown",
    "during_link": "unknown",
    "after_link_before_readback": "unknown",
    "after_verified_stable_readback": "committed",
}
