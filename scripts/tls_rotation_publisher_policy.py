"""Pure validation for the disabled TLS rotation publisher prerequisite policy.

The policy is a declaration, not evidence that a publisher, signer, durable
store, or publication ordering exists.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from scripts.external_json import parse_unique_json_bytes
except ModuleNotFoundError:
    from external_json import parse_unique_json_bytes


SCHEMA_VERSION = 1
POLICY_KIND = "tls_rotation_attempt_publisher_prerequisites"
MAX_POLICY_BYTES = 16 * 1024
_ERROR = "TLS rotation publisher policy is invalid"
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "policy_effect",
    "production_acceptance",
    "publisher_integration_enabled",
    "not_committed_eligible",
    "receipt_schema_version",
    "trust_anchor",
    "signer_custody_requirements",
    "publisher_ordering",
    "durability_prerequisites",
}
_TRUST_FIELDS = {
    "state",
    "algorithm",
    "key_id",
    "public_key_b64url",
    "source",
}
_CUSTODY_FIELDS = {
    "usage_scope",
    "private_key_in_repository",
    "private_key_cli_environment_transport",
    "dedicated_signing_key_required",
    "independent_custody_evidence_required",
    "independent_reviewer_required",
}
_ORDERING_FIELDS = {"state", "required_steps", "evidence_link_attempt_limit"}
_DURABILITY_FIELDS = {
    "state",
    "worm_or_object_lock_required",
    "deny_delete_required",
    "retention_policy_required",
    "stable_storage_identity_required",
    "commit_ack_and_readback_required",
    "platform_crash_recovery_evidence_required",
    "independent_durability_evidence_required",
}
_REQUIRED_STEPS = [
    "canonical_evidence_bytes_fsynced",
    "ready_receipt_signed",
    "ready_receipt_durable_write_once_committed",
    "ready_receipt_stable_readback_confirmed",
    "evidence_link_attempted_once",
]


class TlsRotationPublisherPolicyError(ValueError):
    """A publisher prerequisite declaration failed closed validation."""


def _invalid() -> TlsRotationPublisherPolicyError:
    return TlsRotationPublisherPolicyError(_ERROR)


def _closed(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _public_key(value: str) -> bytes:
    if _PUBLIC_KEY.fullmatch(value) is None:
        raise _invalid()
    try:
        raw = base64.urlsafe_b64decode(value + "=")
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if len(raw) != 32 or not hmac.compare_digest(canonical, value):
            raise _invalid()
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error, UnicodeError):
        raise _invalid() from None
    return raw


def _validate_trust_anchor(value: object) -> None:
    anchor = _closed(value, _TRUST_FIELDS)
    if (
        anchor["algorithm"] != "Ed25519"
        or anchor["source"] != "release_governed_repository_configuration"
        or anchor["state"] not in {"unconfigured", "pinned"}
    ):
        raise _invalid()
    if anchor["state"] == "unconfigured":
        if anchor["key_id"] is not None or anchor["public_key_b64url"] is not None:
            raise _invalid()
        return
    if (
        not isinstance(anchor["key_id"], str)
        or _KEY_ID.fullmatch(anchor["key_id"]) is None
        or not isinstance(anchor["public_key_b64url"], str)
    ):
        raise _invalid()
    raw = _public_key(anchor["public_key_b64url"])
    expected_key_id = "ed25519-sha256:" + hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(anchor["key_id"], expected_key_id):
        raise _invalid()


def _validate_custody(value: object) -> None:
    custody = _closed(value, _CUSTODY_FIELDS)
    if (
        custody["usage_scope"] != "tls_rotation_publication_attempt_v1_only"
        or custody["private_key_in_repository"] != "forbidden"
        or custody["private_key_cli_environment_transport"] != "forbidden"
        or custody["dedicated_signing_key_required"] is not True
        or custody["independent_custody_evidence_required"] is not True
        or custody["independent_reviewer_required"] is not True
    ):
        raise _invalid()


def _validate_ordering(value: object) -> None:
    ordering = _closed(value, _ORDERING_FIELDS)
    if (
        ordering["state"] != "not_implemented"
        or type(ordering["required_steps"]) is not list
        or ordering["required_steps"] != _REQUIRED_STEPS
        or type(ordering["evidence_link_attempt_limit"]) is not int
        or ordering["evidence_link_attempt_limit"] != 1
    ):
        raise _invalid()


def _validate_durability(value: object) -> None:
    durability = _closed(value, _DURABILITY_FIELDS)
    if durability["state"] != "unverified" or any(
        durability[field] is not True
        for field in _DURABILITY_FIELDS
        if field != "state"
    ):
        raise _invalid()


def validate_publisher_policy(value: object) -> dict[str, object]:
    """Validate one declaration without treating it as readiness evidence."""

    policy = _closed(value, _POLICY_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "declaration_only"
        or policy["production_acceptance"] is not False
        or policy["publisher_integration_enabled"] is not False
        or policy["not_committed_eligible"] is not False
        or type(policy["receipt_schema_version"]) is not int
        or policy["receipt_schema_version"] != 1
    ):
        raise _invalid()
    _validate_trust_anchor(policy["trust_anchor"])
    _validate_custody(policy["signer_custody_requirements"])
    _validate_ordering(policy["publisher_ordering"])
    _validate_durability(policy["durability_prerequisites"])
    return policy


def parse_publisher_policy(raw: bytes) -> dict[str, object]:
    """Parse bounded unique-key JSON and apply the closed declaration schema."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_POLICY_BYTES:
        raise _invalid()
    try:
        value = parse_unique_json_bytes(raw)
        return validate_publisher_policy(value)
    except TlsRotationPublisherPolicyError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None
