"""Verify signed WORM collection assertions and one replay-ledger link offline.

Successful verification authenticates two pinned-key assertions and exact input
bytes. It does not validate provider-native semantics, trusted time, freshness,
global replay protection, durability, reviewer independence, or target facts.
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
from scripts.private_secret_target_provenance import (
    RUNTIME_POLICY,
    PrivateSecretTargetProvenanceError,
    verify_target_origin_bytes,
)


POLICY = ROOT / "deploy" / "private-secret-worm-collection-policy.synthetic.json"
SYNTHETIC = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-worm-collection.synthetic.json"
)
SCHEMA_VERSION = 1
POLICY_KIND = "private_secret_worm_collection_trust_policy"
RECORD_TYPE = "private_secret_worm_collection"
OBSERVATION_KIND = "private_secret_worm_provider_observation"
CHECKPOINT_KIND = "private_secret_worm_replay_checkpoint"
OBSERVATION_STATEMENT = "external_observer_bound_provider_collection_artifacts"
CHECKPOINT_STATEMENT = "external_ledger_signed_collection_checkpoint"
ZERO_SHA256 = "0" * 64

_PROVIDER_DOMAIN = b"email-platform/private-secret-worm-audit/provider-observation/v1\0"
_LEDGER_DOMAIN = b"email-platform/private-secret-worm-audit/replay-checkpoint/v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = frozenset(
    {"development", "example", "local", "placeholder", "tbd", "test", "unknown"}
)

_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "executor_integration_enabled",
    "handoff_integration_enabled",
    "provider_contract",
    "provider_observer",
    "ledger_signer",
    "requirements",
    "time_constraints",
    "integrity",
}
_PROVIDER_CONTRACT_FIELDS = {
    "state",
    "provider_kind",
    "ledger_id",
    "required_retention_mode",
    "denied_delete_reason_code",
}
_ANCHOR_FIELDS = {
    "state",
    "algorithm",
    "usage_scope",
    "key_id",
    "public_key_b64url",
    "source",
}
_REQUIREMENT_FIELDS = {
    "configuration_snapshot_required",
    "object_metadata_snapshot_required",
    "denied_delete_observation_required",
    "post_denial_readback_required",
    "trusted_time_artifact_required",
    "caller_head_pin_required",
}
_TIME_CONSTRAINT_FIELDS = {
    "max_config_to_trusted_time_seconds",
    "max_trusted_time_to_checkpoint_seconds",
    "max_checkpoint_to_verification_seconds",
    "retention_must_cover_verification",
}
_COLLECTION_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "collection_status",
    "provider_observation_authentication",
    "checkpoint_authentication",
    "production_acceptance",
    "not_committed_eligible",
    "observation",
    "checkpoint",
    "integrity",
}
_SIGNED_FIELDS = {"payload", "signature"}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_OBSERVATION_FIELDS = {
    "schema_version",
    "observation_kind",
    "statement",
    "production_acceptance",
    "not_committed_eligible",
    "observation_id",
    "trust_policy_sha256",
    "target_origin",
    "provider",
    "object",
    "delete_observation",
    "trusted_time",
    "timeline",
    "prohibited_content",
}
_TARGET_FIELDS = {"attempt_id", "receipt_fingerprint_sha256"}
_PROVIDER_FIELDS = {
    "provider_kind",
    "account_identity_fingerprint_sha256",
    "storage_identity_fingerprint_sha256",
    "configuration_snapshot_sha256",
    "configuration_version_fingerprint_sha256",
}
_OBJECT_FIELDS = {
    "object_reference",
    "immutable_version_reference",
    "content_sha256",
    "metadata_snapshot_sha256",
    "retention_mode",
    "retention_until",
}
_DELETE_FIELDS = {
    "artifact_sha256",
    "request_fingerprint_sha256",
    "result",
    "reason_code",
    "attempted_at",
    "post_denial_readback_sha256",
}
_TRUSTED_TIME_FIELDS = {
    "artifact_sha256",
    "authority_identity_fingerprint_sha256",
    "observed_at",
}
_TIMELINE_FIELDS = {
    "configuration_captured_at",
    "object_observed_at",
    "delete_observed_at",
}
_PROHIBITED_FIELDS = {
    "contains_credentials",
    "contains_secret_values",
    "contains_runtime_paths",
    "contains_provider_urls",
    "contains_raw_logs",
    "contains_personal_data",
}
_CHECKPOINT_FIELDS = {
    "schema_version",
    "checkpoint_kind",
    "statement",
    "production_acceptance",
    "not_committed_eligible",
    "checkpoint_id",
    "trust_policy_sha256",
    "ledger_id",
    "sequence",
    "previous",
    "observation_artifact_sha256",
    "observation_payload_sha256",
    "target_origin_receipt_sha256",
    "attempt_id",
    "trusted_time_artifact_sha256",
    "checkpointed_at",
}
_PREVIOUS_FIELDS = {"kind", "sequence", "artifact_sha256", "payload_sha256"}


class PrivateSecretWormCollectionError(ValueError):
    """A WORM collection or replay checkpoint is invalid."""


def _invalid() -> PrivateSecretWormCollectionError:
    return PrivateSecretWormCollectionError("private secret WORM collection is invalid")


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
class VerifiedCollection:
    attempt_id: str
    policy_sha256: str
    target_policy_sha256: str
    cluster_fingerprint_sha256: str
    ledger_id: str
    sequence: int
    prior_head_sha256: str
    receipt_sha256: str
    head_sha256: str
    observation_payload_sha256: str
    provider_kind: str
    provider_account_fingerprint_sha256: str
    storage_identity_fingerprint_sha256: str
    configuration_snapshot_sha256: str
    retention_mode: str
    provider_signer_key_id: str
    ledger_signer_key_id: str


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
    if (
        not isinstance(value, str)
        or _REFERENCE.fullmatch(value) is None
        or value.casefold() in _PLACEHOLDERS
    ):
        raise _invalid()
    return value


def _object_reference(value: object) -> str:
    prefix = "worm-private-secret-crash:"
    reference = _reference(value)
    suffix = reference.removeprefix(prefix)
    if (
        not reference.startswith(prefix)
        or not suffix
        or not any(character.isalpha() for character in suffix)
        or not any(character.isdigit() for character in suffix)
    ):
        raise _invalid()
    return reference


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


def _uuid4(value: object) -> str:
    try:
        from uuid import UUID

        parsed = UUID(value, version=4)
    except (AttributeError, TypeError, ValueError):
        raise _invalid() from None
    if str(parsed) != value:
        raise _invalid()
    return value


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
        or anchor["source"] != "release_governed_external_configuration"
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


def validate_policy(value: object, *, require_configured: bool = False) -> dict[str, Any]:
    policy = _closed(value, _POLICY_FIELDS)
    integrity = _closed(policy["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in policy.items() if key != "integrity"}
    if not hmac.compare_digest(
        _digest(integrity["payload_sha256"]), _canonical_digest(payload)
    ):
        raise _invalid()
    synthetic = policy["synthetic"]
    state = "unconfigured" if synthetic is True else "pinned"
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "authentication_prerequisite_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
        or policy["executor_integration_enabled"] is not False
        or policy["handoff_integration_enabled"] is not False
        or type(synthetic) is not bool
        or policy["policy_status"] != ("unconfigured" if synthetic else "reviewed")
        or (require_configured and synthetic)
    ):
        raise _invalid()
    provider_key = _validate_anchor(
        policy["provider_observer"],
        state=state,
        usage_scope="private_secret_worm_provider_observation_v1_only",
    )
    ledger_key = _validate_anchor(
        policy["ledger_signer"],
        state=state,
        usage_scope="private_secret_worm_replay_checkpoint_v1_only",
    )
    if not synthetic and hmac.compare_digest(provider_key or b"", ledger_key or b""):
        raise _invalid()

    contract = _closed(policy["provider_contract"], _PROVIDER_CONTRACT_FIELDS)
    if synthetic:
        if contract != {
            "state": "unconfigured",
            "provider_kind": None,
            "ledger_id": None,
            "required_retention_mode": None,
            "denied_delete_reason_code": None,
        }:
            raise _invalid()
    elif (
        contract["state"] != "configured"
        or contract["required_retention_mode"] != "compliance"
    ):
        raise _invalid()
    else:
        for field in ("provider_kind", "ledger_id", "denied_delete_reason_code"):
            _reference(contract[field])

    requirements = _closed(policy["requirements"], _REQUIREMENT_FIELDS)
    if any(item is not True for item in requirements.values()):
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


def parse_policy(raw: bytes, *, require_configured: bool = False) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        return validate_policy(
            parse_unique_json_bytes(raw), require_configured=require_configured
        )
    except PrivateSecretWormCollectionError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _invalid() from None


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


def _read_runtime_policy_bytes() -> bytes:
    try:
        return read_stable_bytes(RUNTIME_POLICY, max_bytes=MAX_INTAKE_JSON_BYTES)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error


def _validate_observation_payload(value: object) -> dict[str, Any]:
    payload = _closed(value, _OBSERVATION_FIELDS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["observation_kind"] != OBSERVATION_KIND
        or payload["statement"] != OBSERVATION_STATEMENT
        or payload["production_acceptance"] is not False
        or payload["not_committed_eligible"] is not False
    ):
        raise _invalid()
    _uuid4(payload["observation_id"])
    _digest(payload["trust_policy_sha256"])
    target = _closed(payload["target_origin"], _TARGET_FIELDS)
    _uuid4(target["attempt_id"])
    _digest(target["receipt_fingerprint_sha256"])
    provider = _closed(payload["provider"], _PROVIDER_FIELDS)
    _reference(provider["provider_kind"])
    for field in _PROVIDER_FIELDS - {"provider_kind"}:
        _digest(provider[field])
    observed_object = _closed(payload["object"], _OBJECT_FIELDS)
    _object_reference(observed_object["object_reference"])
    _reference(observed_object["immutable_version_reference"])
    if hmac.compare_digest(
        observed_object["object_reference"].casefold(),
        observed_object["immutable_version_reference"].casefold(),
    ):
        raise _invalid()
    for field in ("content_sha256", "metadata_snapshot_sha256"):
        _digest(observed_object[field])
    if observed_object["retention_mode"] != "compliance":
        raise _invalid()
    _timestamp(observed_object["retention_until"])
    deletion = _closed(payload["delete_observation"], _DELETE_FIELDS)
    for field in (
        "artifact_sha256",
        "request_fingerprint_sha256",
        "post_denial_readback_sha256",
    ):
        _digest(deletion[field])
    if deletion["result"] != "denied":
        raise _invalid()
    _reference(deletion["reason_code"])
    _timestamp(deletion["attempted_at"])
    trusted = _closed(payload["trusted_time"], _TRUSTED_TIME_FIELDS)
    _digest(trusted["artifact_sha256"])
    _digest(trusted["authority_identity_fingerprint_sha256"])
    _timestamp(trusted["observed_at"])
    timeline = _closed(payload["timeline"], _TIMELINE_FIELDS)
    for field in _TIMELINE_FIELDS:
        _timestamp(timeline[field])
    prohibited = _closed(payload["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item is not False for item in prohibited.values()):
        raise _invalid()
    return payload


def _validate_previous(value: object) -> dict[str, Any]:
    previous = _closed(value, _PREVIOUS_FIELDS)
    if previous["kind"] not in {"genesis", "checkpoint"}:
        raise _invalid()
    if type(previous["sequence"]) is not int or previous["sequence"] < 0:
        raise _invalid()
    _digest(previous["artifact_sha256"])
    _digest(previous["payload_sha256"])
    if previous["kind"] == "genesis" and previous != {
        "kind": "genesis",
        "sequence": 0,
        "artifact_sha256": ZERO_SHA256,
        "payload_sha256": ZERO_SHA256,
    }:
        raise _invalid()
    if previous["kind"] == "checkpoint" and previous["sequence"] < 1:
        raise _invalid()
    return previous


def _validate_checkpoint_payload(value: object) -> dict[str, Any]:
    payload = _closed(value, _CHECKPOINT_FIELDS)
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["checkpoint_kind"] != CHECKPOINT_KIND
        or payload["statement"] != CHECKPOINT_STATEMENT
        or payload["production_acceptance"] is not False
        or payload["not_committed_eligible"] is not False
        or type(payload["sequence"]) is not int
        or not 1 <= payload["sequence"] <= 2**63 - 1
    ):
        raise _invalid()
    _uuid4(payload["checkpoint_id"])
    _uuid4(payload["attempt_id"])
    _reference(payload["ledger_id"])
    for field in (
        "trust_policy_sha256",
        "observation_artifact_sha256",
        "observation_payload_sha256",
        "target_origin_receipt_sha256",
        "trusted_time_artifact_sha256",
    ):
        _digest(payload[field])
    _validate_previous(payload["previous"])
    _timestamp(payload["checkpointed_at"])
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


def _validate_signed(
    value: object, *, role: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    signed = _closed(value, _SIGNED_FIELDS)
    payload = (
        _validate_observation_payload(signed["payload"])
        if role == "provider_observer"
        else _validate_checkpoint_payload(signed["payload"])
    )
    return payload, _validate_signature(signed["signature"])


def _validate_collection(
    value: object, *, allow_synthetic: bool = False
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    collection = _closed(value, _COLLECTION_FIELDS)
    integrity = _closed(collection["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in collection.items() if key != "integrity"}
    if (
        type(collection["schema_version"]) is not int
        or collection["schema_version"] != SCHEMA_VERSION
        or collection["record_type"] != RECORD_TYPE
        or collection["production_acceptance"] is not False
        or collection["not_committed_eligible"] is not False
        or not hmac.compare_digest(
            _digest(integrity["payload_sha256"]), _canonical_digest(payload)
        )
    ):
        raise _invalid()
    if collection["synthetic"] is True:
        if not allow_synthetic or (
            collection["collection_status"] != "pending"
            or collection["provider_observation_authentication"] != "unverified"
            or collection["checkpoint_authentication"] != "unverified"
            or collection["observation"] is not None
            or collection["checkpoint"] is not None
        ):
            raise _invalid()
        return None, None
    if (
        collection["synthetic"] is not False
        or collection["collection_status"] != "signed_assertion"
        or collection["provider_observation_authentication"] != "unverified"
        or collection["checkpoint_authentication"] != "unverified"
    ):
        raise _invalid()
    observation_payload, _ = _validate_signed(
        collection["observation"], role="provider_observer"
    )
    checkpoint_payload, _ = _validate_signed(
        collection["checkpoint"], role="ledger_signer"
    )
    return observation_payload, checkpoint_payload


def signature_message(payload: Mapping[str, object], *, role: str) -> bytes:
    """Return one domain-separated canonical message; this function never signs."""

    if role == "provider_observer":
        validated = _validate_observation_payload(dict(payload))
        domain = _PROVIDER_DOMAIN
    elif role == "ledger_signer":
        validated = _validate_checkpoint_payload(dict(payload))
        domain = _LEDGER_DOMAIN
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


def _verify_collection_signatures(
    collection: Mapping[str, Any],
    *,
    provider_anchor: PinnedAnchor,
    ledger_anchor: PinnedAnchor,
) -> tuple[dict[str, Any], dict[str, Any]]:
    observation_payload, checkpoint_payload = _validate_collection(collection)
    if observation_payload is None or checkpoint_payload is None:
        raise _invalid()
    _verify_signature(
        observation_payload,
        collection["observation"]["signature"],
        role="provider_observer",
        anchor=provider_anchor,
    )
    _verify_signature(
        checkpoint_payload,
        collection["checkpoint"]["signature"],
        role="ledger_signer",
        anchor=ledger_anchor,
    )
    return observation_payload, checkpoint_payload


def _verify_times(
    observation: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    constraints: Mapping[str, Any],
    verification_time: str,
) -> None:
    timeline = observation["timeline"]
    configuration = _timestamp(timeline["configuration_captured_at"])
    observed_object = _timestamp(timeline["object_observed_at"])
    deletion_attempted = _timestamp(observation["delete_observation"]["attempted_at"])
    deletion_observed = _timestamp(timeline["delete_observed_at"])
    trusted = _timestamp(observation["trusted_time"]["observed_at"])
    checkpointed = _timestamp(checkpoint["checkpointed_at"])
    verified_at = _timestamp(verification_time)
    retained_until = _timestamp(observation["object"]["retention_until"])
    if not (
        configuration
        <= observed_object
        <= deletion_attempted
        <= deletion_observed
        <= trusted
        <= checkpointed
        <= verified_at
        <= retained_until
    ):
        raise _invalid()
    if (
        (trusted - configuration).total_seconds()
        > constraints["max_config_to_trusted_time_seconds"]
        or (checkpointed - trusted).total_seconds()
        > constraints["max_trusted_time_to_checkpoint_seconds"]
        or (verified_at - checkpointed).total_seconds()
        > constraints["max_checkpoint_to_verification_seconds"]
    ):
        raise _invalid()


def _load_json_bytes(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES:
        raise _invalid()
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error
    if not isinstance(value, dict) or not hmac.compare_digest(raw, _canonical_bytes(value)):
        raise _invalid()
    return value


def verify_repository_assets() -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        policy_raw = read_stable_bytes(POLICY, max_bytes=MAX_INTAKE_JSON_BYTES)
        policy = parse_policy(policy_raw)
        template_raw = read_stable_bytes(SYNTHETIC, max_bytes=MAX_INTAKE_JSON_BYTES)
        template_value = parse_unique_json_bytes(template_raw)
        _validate_collection(template_value, allow_synthetic=True)
    except (
        OSError,
        StableFileError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error
    if policy["synthetic"] is not True:
        raise _invalid()
    return policy, template_value, hashlib.sha256(policy_raw).hexdigest()


def verify_collection(
    input_path: Path | str,
    policy_path: Path | str,
    target_policy_path: Path | str,
    target_origin_path: Path | str,
    crash_evidence_path: Path | str,
    before_inventory_path: Path | str,
    after_inventory_path: Path | str,
    target_inventory_path: Path | str,
    release_execution_path: Path | str,
    alert_evidence_path: Path | str,
    worm_receipt_path: Path | str,
    target_delete_probe_path: Path | str,
    custody_evidence_path: Path | str,
    provider_config_path: Path | str,
    object_metadata_path: Path | str,
    delete_observation_path: Path | str,
    readback_path: Path | str,
    trusted_time_path: Path | str,
    *,
    expected_collection_sha256: str,
    expected_policy_sha256: str,
    expected_target_policy_sha256: str,
    expected_cluster_fingerprint_sha256: str,
    expected_ledger_id: str,
    expected_sequence: int,
    expected_prior_head_sha256: str,
    verification_time: str,
    prior_checkpoint_path: Path | str | None = None,
) -> VerifiedCollection:
    """Authenticate one collection and exactly one caller-pinned chain link."""

    paths: list[Path | str] = [
        input_path,
        policy_path,
        target_policy_path,
        target_origin_path,
        crash_evidence_path,
        before_inventory_path,
        after_inventory_path,
        target_inventory_path,
        release_execution_path,
        alert_evidence_path,
        worm_receipt_path,
        target_delete_probe_path,
        custody_evidence_path,
        provider_config_path,
        object_metadata_path,
        delete_observation_path,
        readback_path,
        trusted_time_path,
    ]
    if prior_checkpoint_path is not None:
        paths.append(prior_checkpoint_path)
    normalized = {
        str(_external_path(path).resolve(strict=False)).casefold() for path in paths
    }
    if len(normalized) != len(paths):
        raise _invalid()
    runtime_policy_raw = _read_runtime_policy_bytes()
    raw = {
        "input_raw": _read_external_bytes(input_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "policy_raw": _read_external_bytes(policy_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "target_policy_raw": _read_external_bytes(target_policy_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "runtime_policy_raw": runtime_policy_raw,
        "target_origin_raw": _read_external_bytes(target_origin_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "crash_evidence_raw": _read_external_bytes(crash_evidence_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "before_inventory_raw": _read_external_bytes(before_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "after_inventory_raw": _read_external_bytes(after_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "target_inventory_raw": _read_external_bytes(target_inventory_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "release_execution_raw": _read_external_bytes(release_execution_path, max_bytes=MAX_INTAKE_JSON_BYTES),
        "alert_evidence_raw": _read_external_bytes(alert_evidence_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "worm_receipt_raw": _read_external_bytes(worm_receipt_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "target_delete_probe_raw": _read_external_bytes(target_delete_probe_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "custody_evidence_raw": _read_external_bytes(custody_evidence_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "provider_config_raw": _read_external_bytes(provider_config_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "object_metadata_raw": _read_external_bytes(object_metadata_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "delete_observation_raw": _read_external_bytes(delete_observation_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "readback_raw": _read_external_bytes(readback_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "trusted_time_raw": _read_external_bytes(trusted_time_path, max_bytes=MAX_EXTERNAL_JSON_BYTES),
        "prior_checkpoint_raw": (_read_external_bytes(prior_checkpoint_path, max_bytes=MAX_INTAKE_JSON_BYTES) if prior_checkpoint_path is not None else None),
    }
    return verify_collection_bytes(
        **raw,
        expected_collection_sha256=expected_collection_sha256,
        expected_policy_sha256=expected_policy_sha256,
        expected_target_policy_sha256=expected_target_policy_sha256,
        expected_cluster_fingerprint_sha256=expected_cluster_fingerprint_sha256,
        expected_ledger_id=expected_ledger_id,
        expected_sequence=expected_sequence,
        expected_prior_head_sha256=expected_prior_head_sha256,
        verification_time=verification_time,
    )
def verify_collection_bytes(
    *,
    input_raw: bytes,
    policy_raw: bytes,
    target_policy_raw: bytes,
    runtime_policy_raw: bytes,
    target_origin_raw: bytes,
    crash_evidence_raw: bytes,
    before_inventory_raw: bytes,
    after_inventory_raw: bytes,
    target_inventory_raw: bytes,
    release_execution_raw: bytes,
    alert_evidence_raw: bytes,
    worm_receipt_raw: bytes,
    target_delete_probe_raw: bytes,
    custody_evidence_raw: bytes,
    provider_config_raw: bytes,
    object_metadata_raw: bytes,
    delete_observation_raw: bytes,
    readback_raw: bytes,
    trusted_time_raw: bytes,
    expected_collection_sha256: str,
    expected_policy_sha256: str,
    expected_target_policy_sha256: str,
    expected_cluster_fingerprint_sha256: str,
    expected_ledger_id: str,
    expected_sequence: int,
    expected_prior_head_sha256: str,
    verification_time: str,
    prior_checkpoint_raw: bytes | None = None,
) -> VerifiedCollection:
    """Authenticate one caller-pinned collection from exact supplied bytes."""

    intake = (
        input_raw, policy_raw, target_policy_raw, runtime_policy_raw,
        target_origin_raw, crash_evidence_raw, release_execution_raw,
    )
    external = (
        before_inventory_raw, after_inventory_raw, target_inventory_raw,
        alert_evidence_raw, worm_receipt_raw, target_delete_probe_raw,
        custody_evidence_raw, provider_config_raw, object_metadata_raw,
        delete_observation_raw, readback_raw, trusted_time_raw,
    )
    if (
        any(type(raw) is not bytes or not raw or len(raw) > MAX_INTAKE_JSON_BYTES for raw in intake)
        or any(type(raw) is not bytes or not raw or len(raw) > MAX_EXTERNAL_JSON_BYTES for raw in external)
        or (
            prior_checkpoint_raw is not None
            and (
                type(prior_checkpoint_raw) is not bytes
                or not prior_checkpoint_raw
                or len(prior_checkpoint_raw) > MAX_INTAKE_JSON_BYTES
            )
        )
    ):
        raise _invalid()
    _digest(expected_collection_sha256)
    _digest(expected_policy_sha256)
    _digest(expected_target_policy_sha256)
    _digest(expected_cluster_fingerprint_sha256)
    _digest(expected_prior_head_sha256)
    _reference(expected_ledger_id)
    if type(expected_sequence) is not int or not 1 <= expected_sequence <= 2**63 - 1:
        raise _invalid()
    _timestamp(verification_time)
    if not hmac.compare_digest(hashlib.sha256(input_raw).hexdigest(), expected_collection_sha256):
        raise _invalid()
    if not hmac.compare_digest(hashlib.sha256(policy_raw).hexdigest(), expected_policy_sha256):
        raise _invalid()
    policy = parse_policy(policy_raw, require_configured=True)
    policy_digest = hashlib.sha256(policy_raw).hexdigest()
    contract = policy["provider_contract"]
    if contract["ledger_id"] != expected_ledger_id:
        raise _invalid()
    provider_anchor = PinnedAnchor(
        _decode_public_key(policy["provider_observer"]["public_key_b64url"])
    )
    ledger_anchor = PinnedAnchor(
        _decode_public_key(policy["ledger_signer"]["public_key_b64url"])
    )
    try:
        target_origin = verify_target_origin_bytes(
            input_raw=target_origin_raw,
            policy_raw=target_policy_raw,
            runtime_policy_raw=runtime_policy_raw,
            crash_evidence_raw=crash_evidence_raw,
            before_inventory_raw=before_inventory_raw,
            after_inventory_raw=after_inventory_raw,
            target_inventory_raw=target_inventory_raw,
            release_execution_raw=release_execution_raw,
            alert_evidence_raw=alert_evidence_raw,
            worm_receipt_raw=worm_receipt_raw,
            delete_probe_raw=target_delete_probe_raw,
            custody_evidence_raw=custody_evidence_raw,
            expected_cluster_fingerprint_sha256=expected_cluster_fingerprint_sha256,
            expected_policy_sha256=expected_target_policy_sha256,
            verification_time=verification_time,
        )
    except PrivateSecretTargetProvenanceError as error:
        raise _invalid() from error

    collection = _load_json_bytes(input_raw)
    observation, checkpoint = _verify_collection_signatures(
        collection, provider_anchor=provider_anchor, ledger_anchor=ledger_anchor
    )
    opaque_digests = {
        hashlib.sha256(raw).hexdigest()
        for raw in (
            provider_config_raw, object_metadata_raw, delete_observation_raw,
            trusted_time_raw,
        )
    }
    if len(opaque_digests) != 4 or target_origin.receipt_fingerprint_sha256 in opaque_digests:
        raise _invalid()
    if (
        observation["trust_policy_sha256"] != policy_digest
        or observation["target_origin"]
        != {
            "attempt_id": target_origin.attempt_id,
            "receipt_fingerprint_sha256": target_origin.receipt_fingerprint_sha256,
        }
    ):
        raise _invalid()
    provider = observation["provider"]
    if (
        provider["provider_kind"] != contract["provider_kind"]
        or provider["storage_identity_fingerprint_sha256"]
        != target_origin.storage_identity_fingerprint_sha256
        or provider["configuration_snapshot_sha256"]
        != hashlib.sha256(provider_config_raw).hexdigest()
    ):
        raise _invalid()
    observed_object = observation["object"]
    if (
        observed_object["metadata_snapshot_sha256"]
        != hashlib.sha256(object_metadata_raw).hexdigest()
        or observed_object["object_reference"] != target_origin.object_reference
        or observed_object["immutable_version_reference"]
        != target_origin.immutable_version_reference
        or observed_object["retention_mode"] != contract["required_retention_mode"]
        or observed_object["content_sha256"] != target_origin.evidence_readback_sha256
    ):
        raise _invalid()
    deletion = observation["delete_observation"]
    if (
        deletion["artifact_sha256"] != hashlib.sha256(delete_observation_raw).hexdigest()
        or deletion["reason_code"] != contract["denied_delete_reason_code"]
        or deletion["post_denial_readback_sha256"] != target_origin.evidence_readback_sha256
        or hashlib.sha256(readback_raw).hexdigest() != target_origin.evidence_readback_sha256
    ):
        raise _invalid()
    trusted = observation["trusted_time"]
    if trusted["artifact_sha256"] != hashlib.sha256(trusted_time_raw).hexdigest():
        raise _invalid()

    observation_envelope_sha256 = _canonical_digest(collection["observation"])
    observation_payload_sha256 = _canonical_digest(observation)
    if (
        checkpoint["trust_policy_sha256"] != policy_digest
        or checkpoint["ledger_id"] != expected_ledger_id
        or checkpoint["sequence"] != expected_sequence
        or checkpoint["observation_artifact_sha256"] != observation_envelope_sha256
        or checkpoint["observation_payload_sha256"] != observation_payload_sha256
        or checkpoint["target_origin_receipt_sha256"] != target_origin.receipt_fingerprint_sha256
        or checkpoint["attempt_id"] != target_origin.attempt_id
        or checkpoint["trusted_time_artifact_sha256"] != trusted["artifact_sha256"]
    ):
        raise _invalid()
    previous = checkpoint["previous"]
    if expected_sequence == 1:
        if (
            prior_checkpoint_raw is not None
            or expected_prior_head_sha256 != ZERO_SHA256
            or previous
            != {
                "kind": "genesis", "sequence": 0,
                "artifact_sha256": ZERO_SHA256, "payload_sha256": ZERO_SHA256,
            }
        ):
            raise _invalid()
    else:
        if prior_checkpoint_raw is None or expected_prior_head_sha256 == ZERO_SHA256:
            raise _invalid()
        if not hmac.compare_digest(
            hashlib.sha256(prior_checkpoint_raw).hexdigest(), expected_prior_head_sha256
        ):
            raise _invalid()
        prior_collection = _load_json_bytes(prior_checkpoint_raw)
        prior_observation, prior_checkpoint = _verify_collection_signatures(
            prior_collection,
            provider_anchor=provider_anchor,
            ledger_anchor=ledger_anchor,
        )
        if (
            prior_observation["trust_policy_sha256"] != policy_digest
            or prior_checkpoint["trust_policy_sha256"] != policy_digest
            or prior_checkpoint["ledger_id"] != expected_ledger_id
            or prior_checkpoint["sequence"] != expected_sequence - 1
            or observation["observation_id"] == prior_observation["observation_id"]
            or checkpoint["checkpoint_id"] == prior_checkpoint["checkpoint_id"]
            or previous
            != {
                "kind": "checkpoint",
                "sequence": expected_sequence - 1,
                "artifact_sha256": expected_prior_head_sha256,
                "payload_sha256": _canonical_digest(prior_checkpoint),
            }
        ):
            raise _invalid()
    _verify_times(observation, checkpoint, policy["time_constraints"], verification_time)
    return VerifiedCollection(
        attempt_id=target_origin.attempt_id,
        policy_sha256=policy_digest,
        target_policy_sha256=expected_target_policy_sha256,
        cluster_fingerprint_sha256=expected_cluster_fingerprint_sha256,
        ledger_id=expected_ledger_id,
        sequence=expected_sequence,
        prior_head_sha256=expected_prior_head_sha256,
        receipt_sha256=expected_collection_sha256,
        head_sha256=expected_collection_sha256,
        observation_payload_sha256=observation_payload_sha256,
        provider_kind=provider["provider_kind"],
        provider_account_fingerprint_sha256=provider["account_identity_fingerprint_sha256"],
        storage_identity_fingerprint_sha256=provider["storage_identity_fingerprint_sha256"],
        configuration_snapshot_sha256=provider["configuration_snapshot_sha256"],
        retention_mode=observed_object["retention_mode"],
        provider_signer_key_id=provider_anchor.key_id,
        ledger_signer_key_id=ledger_anchor.key_id,
    )


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PrivateSecretWormCollectionError(
            "private secret WORM collection arguments are invalid"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    for option in (
        "input",
        "policy",
        "target-policy",
        "target-origin",
        "crash-evidence",
        "before-inventory",
        "after-inventory",
        "target-inventory",
        "release-execution",
        "alert-evidence",
        "worm-receipt",
        "target-delete-probe",
        "custody-evidence",
        "provider-config",
        "object-metadata",
        "delete-observation",
        "readback",
        "trusted-time",
    ):
        verify.add_argument(f"--{option}", type=Path, required=True)
    verify.add_argument("--prior-checkpoint", type=Path)
    verify.add_argument("--expected-collection-sha256", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-target-policy-sha256", required=True)
    verify.add_argument("--expected-cluster-fingerprint-sha256", required=True)
    verify.add_argument("--expected-ledger-id", required=True)
    verify.add_argument("--expected-sequence", type=int, required=True)
    verify.add_argument("--expected-prior-head-sha256", required=True)
    verify.add_argument("--verification-time", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            _, _, policy_sha256 = verify_repository_assets()
            print(
                "private-secret-worm-collection-template-ok status=unconfigured "
                "provider-observation=unverified checkpoint-signature=unverified "
                "provider-native=unverified trusted-time=unverified "
                "freshness=unverified replay-protection=unverified "
                "durability=unverified reviewer-independence=unverified "
                "production_acceptance=false not_committed_eligible=false "
                f"policy_sha256={policy_sha256}"
            )
            return 0
        verified = verify_collection(
            options.input,
            options.policy,
            options.target_policy,
            options.target_origin,
            options.crash_evidence,
            options.before_inventory,
            options.after_inventory,
            options.target_inventory,
            options.release_execution,
            options.alert_evidence,
            options.worm_receipt,
            options.target_delete_probe,
            options.custody_evidence,
            options.provider_config,
            options.object_metadata,
            options.delete_observation,
            options.readback,
            options.trusted_time,
            expected_collection_sha256=options.expected_collection_sha256,
            expected_policy_sha256=options.expected_policy_sha256,
            expected_target_policy_sha256=options.expected_target_policy_sha256,
            expected_cluster_fingerprint_sha256=options.expected_cluster_fingerprint_sha256,
            expected_ledger_id=options.expected_ledger_id,
            expected_sequence=options.expected_sequence,
            expected_prior_head_sha256=options.expected_prior_head_sha256,
            verification_time=options.verification_time,
            prior_checkpoint_path=options.prior_checkpoint,
        )
    except (OSError, PrivateSecretWormCollectionError, TypeError, ValueError):
        print("private-secret-worm-collection-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-worm-collection-ok "
        "provider-observation=authenticated-external-signer-assertion "
        "checkpoint-signature=authenticated checkpoint-chain-binding=validated "
        "provider-native=unverified trusted-time=unverified "
        "freshness=unverified replay-protection=unverified "
        "durability=unverified reviewer-independence=unverified "
        "production_acceptance=false not_committed_eligible=false "
        f"sequence={verified.sequence} head_sha256={verified.head_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
