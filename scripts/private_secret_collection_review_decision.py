"""Verify an externally signed review of one collection-backed acceptance.

This module is offline and read-only.  It does not create signatures, contact a
provider, write an evidence sink, or advance any replay/CAS head.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import private_secret_collection_backed_acceptance as backed
from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)


SOURCE = Path(__file__).resolve()
POLICY = ROOT / "deploy" / "private-secret-collection-review-policy.synthetic.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-collection-review-decision.synthetic.json"
)

SCHEMA_VERSION = 1
POLICY_KIND = "private_secret_collection_review_policy"
DECISION_KIND = "private_secret_collection_backed_review_decision"
SIGNATURE_DOMAIN = "email-platform/private-secret-collection-review/v1"
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 128 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_B64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64URL_64 = re.compile(r"^[A-Za-z0-9_-]{86}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

_POLICY_FIELDS = {
    "schema_version", "policy_kind", "synthetic", "policy_status",
    "policy_effect", "production_acceptance", "not_committed_eligible",
    "reviewer", "verifier_identity", "time_constraints", "review",
}
_ANCHOR_FIELDS = {
    "algorithm", "key_id", "public_key_b64url", "signature_domain",
    "usage_scope",
}
_VERIFIER_FIELDS = {
    "source_sha256", "release_commit", "release_manifest_sha256",
}
_TIME_FIELDS = {
    "max_policy_to_decision_seconds", "max_decision_validity_seconds",
}
_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}
_DECISION_FIELDS = {
    "schema_version", "decision_kind", "synthetic", "decision_status",
    "production_acceptance", "not_committed_eligible", "payload",
    "signature", "claim_boundary", "prohibited_content",
}
_PAYLOAD_FIELDS = {
    "decision_id", "reviewer_reference", "reviewed_at", "expires_at",
    "policy_sha256", "input_manifest_sha256",
    "t143_acceptance_projection_sha256", "readiness_projection_sha256",
    "github_collection_projection_sha256", "worm_collection_projection_sha256",
    "release_commit", "release_manifest_sha256", "verifier_source_sha256",
}
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_CLAIM_BOUNDARY_FIELDS = {
    "provider_native", "trusted_time", "global_replay_protection",
    "decision_id_uniqueness", "verifier_release_provenance",
    "reviewer_real_identity", "sink_immutability", "durability",
    "fork_protection", "rollback_protection",
}
_PROHIBITED_FIELDS = {
    "contains_token_values", "contains_private_keys", "contains_secret_values",
    "contains_authorization_headers", "contains_raw_provider_responses",
    "contains_raw_evidence_bytes", "contains_repository_external_paths",
}


class CollectionReviewDecisionError(ValueError):
    pass


@dataclass(frozen=True)
class StableBlob:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str
    max_bytes: int


@dataclass(frozen=True)
class VerifiedReviewDecision:
    decision_id: str
    reviewer_key_id: str
    reviewer_reference: str
    reviewed_at: str
    expires_at: str
    policy_sha256: str
    decision_sha256: str
    input_manifest_sha256: str
    verifier_source_sha256: str
    release_commit: str
    release_manifest_sha256: str
    upstream_key_ids: tuple[str, ...]
    production_acceptance: bool
    not_committed_eligible: bool


def _invalid() -> CollectionReviewDecisionError:
    return CollectionReviewDecisionError("collection review decision is invalid")


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


def validate_policy(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    policy = _sealed(value, _POLICY_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "offline_review_authentication_only"
        or policy["production_acceptance"] is not False
        or policy["not_committed_eligible"] is not False
    ):
        raise _invalid()
    optional = ("reviewer", "verifier_identity", "time_constraints", "review")
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

    anchor = _closed(policy["reviewer"], _ANCHOR_FIELDS)
    public_key = _decode(anchor["public_key_b64url"], pattern=_B64URL_32, size=32)
    key_id = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if (
        anchor["algorithm"] != "Ed25519"
        or anchor["signature_domain"] != SIGNATURE_DOMAIN
        or anchor["usage_scope"] != "private_secret_collection_review_v1_only"
        or not isinstance(anchor["key_id"], str)
        or _KEY_ID.fullmatch(anchor["key_id"]) is None
        or not hmac.compare_digest(anchor["key_id"], key_id)
    ):
        raise _invalid()
    identity = _closed(policy["verifier_identity"], _VERIFIER_FIELDS)
    _digest(identity["source_sha256"])
    _digest(identity["release_manifest_sha256"])
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
    review = _closed(policy["review"], _REVIEW_FIELDS)
    _reference(review["reviewer_reference"])
    _timestamp(review["reviewed_at"])
    if review["decision"] != "approved_for_external_review_authentication":
        raise _invalid()
    return dict(policy)


def validate_decision(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    decision = _sealed(value, _DECISION_FIELDS)
    if (
        type(decision["schema_version"]) is not int
        or decision["schema_version"] != SCHEMA_VERSION
        or decision["decision_kind"] != DECISION_KIND
        or decision["production_acceptance"] is not False
        or decision["not_committed_eligible"] is not False
    ):
        raise _invalid()
    claims = _closed(decision["claim_boundary"], _CLAIM_BOUNDARY_FIELDS)
    prohibited = _closed(decision["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item != "unverified" for item in claims.values()) or any(
        item is not False for item in prohibited.values()
    ):
        raise _invalid()
    if decision["synthetic"] is True:
        if (
            not allow_synthetic
            or decision["decision_status"] != "pending"
            or decision["payload"] is not None
            or decision["signature"] is not None
        ):
            raise _invalid()
        return dict(decision)
    if decision["synthetic"] is not False or decision["decision_status"] != "reviewed":
        raise _invalid()
    payload = _closed(decision["payload"], _PAYLOAD_FIELDS)
    if not isinstance(payload["decision_id"], str) or _UUID4.fullmatch(
        payload["decision_id"]
    ) is None:
        raise _invalid()
    _reference(payload["reviewer_reference"])
    _timestamp(payload["reviewed_at"])
    _timestamp(payload["expires_at"])
    for field in _PAYLOAD_FIELDS - {
        "decision_id", "reviewer_reference", "reviewed_at", "expires_at",
        "release_commit",
    }:
        _digest(payload[field])
    if not isinstance(payload["release_commit"], str) or _COMMIT.fullmatch(
        payload["release_commit"]
    ) is None:
        raise _invalid()
    signature = _closed(decision["signature"], _SIGNATURE_FIELDS)
    if (
        signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or _KEY_ID.fullmatch(signature["key_id"]) is None
    ):
        raise _invalid()
    _decode(signature["value_b64url"], pattern=_B64URL_64, size=64)
    return dict(decision)


def _projection_digests(
    verified: backed.VerifiedCollectionBackedAcceptance,
) -> dict[str, str]:
    return {
        "t143_acceptance_projection_sha256": _canonical_digest(
            asdict(verified.acceptance)
        ),
        "readiness_projection_sha256": _canonical_digest(asdict(verified.readiness)),
        "github_collection_projection_sha256": _canonical_digest(
            asdict(verified.github_collection)
        ),
        "worm_collection_projection_sha256": _canonical_digest(
            asdict(verified.worm_collection)
        ),
    }


def verify_decision_bytes(
    *,
    decision_raw: bytes,
    policy_raw: bytes,
    verifier_source_raw: bytes,
    verified_acceptance: backed.VerifiedCollectionBackedAcceptance,
    expected_decision_sha256: str,
    expected_policy_sha256: str,
    expected_input_manifest_sha256: str,
    expected_verifier_source_sha256: str,
    expected_release_commit: str,
    expected_release_manifest_sha256: str,
    expected_decision_id: str,
    verification_time: str,
) -> VerifiedReviewDecision:
    """Authenticate exact bytes and a previously verified T146 projection."""

    if (
        type(decision_raw) is not bytes
        or type(policy_raw) is not bytes
        or type(verifier_source_raw) is not bytes
        or type(verified_acceptance) is not backed.VerifiedCollectionBackedAcceptance
    ):
        raise _invalid()
    decision_sha256 = hashlib.sha256(decision_raw).hexdigest()
    policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
    verifier_sha256 = hashlib.sha256(verifier_source_raw).hexdigest()
    for value in (
        expected_decision_sha256, expected_policy_sha256,
        expected_input_manifest_sha256, expected_verifier_source_sha256,
        expected_release_manifest_sha256,
    ):
        _digest(value)
    if (
        not hmac.compare_digest(decision_sha256, expected_decision_sha256)
        or not hmac.compare_digest(policy_sha256, expected_policy_sha256)
        or not hmac.compare_digest(verifier_sha256, expected_verifier_source_sha256)
        or not hmac.compare_digest(
            verified_acceptance.manifest_sha256, expected_input_manifest_sha256
        )
        or not isinstance(expected_release_commit, str)
        or _COMMIT.fullmatch(expected_release_commit) is None
        or not isinstance(expected_decision_id, str)
        or _UUID4.fullmatch(expected_decision_id) is None
        or not verifier_source_raw
        or len(verifier_source_raw) > MAX_SOURCE_BYTES
    ):
        raise _invalid()

    policy = validate_policy(_document(policy_raw))
    decision = validate_decision(_document(decision_raw))
    payload = decision["payload"]
    signature = decision["signature"]
    identity = policy["verifier_identity"]
    readiness = verified_acceptance.readiness
    expected_projection = _projection_digests(verified_acceptance)
    if (
        payload["decision_id"] != expected_decision_id
        or payload["policy_sha256"] != policy_sha256
        or payload["input_manifest_sha256"] != verified_acceptance.manifest_sha256
        or any(payload[field] != digest for field, digest in expected_projection.items())
        or payload["release_commit"] != readiness.release_commit
        or payload["release_manifest_sha256"] != readiness.release_manifest_sha256
        or payload["verifier_source_sha256"] != verifier_sha256
        or identity
        != {
            "source_sha256": verifier_sha256,
            "release_commit": readiness.release_commit,
            "release_manifest_sha256": readiness.release_manifest_sha256,
        }
        or readiness.release_commit != expected_release_commit
        or readiness.release_manifest_sha256 != expected_release_manifest_sha256
    ):
        raise _invalid()

    anchor = policy["reviewer"]
    reviewer_key = _decode(
        anchor["public_key_b64url"], pattern=_B64URL_32, size=32
    )
    prohibited_key_ids = {
        *verified_acceptance.t143_trust_anchor_key_ids,
        verified_acceptance.github_collection.collector_key_id,
        verified_acceptance.github_collection.ledger_key_id,
        verified_acceptance.worm_collection.provider_signer_key_id,
        verified_acceptance.worm_collection.ledger_signer_key_id,
    }
    if (
        anchor["key_id"] in prohibited_key_ids
        or signature["key_id"] != anchor["key_id"]
        or payload["reviewer_reference"] == policy["review"]["reviewer_reference"]
    ):
        raise _invalid()
    try:
        Ed25519PublicKey.from_public_bytes(reviewer_key).verify(
            _decode(signature["value_b64url"], pattern=_B64URL_64, size=64),
            SIGNATURE_DOMAIN.encode("ascii") + b"\0" + _canonical_bytes(payload),
        )
    except (InvalidSignature, ValueError) as error:
        raise _invalid() from error

    policy_reviewed = _timestamp(policy["review"]["reviewed_at"])
    reviewed_at = _timestamp(payload["reviewed_at"])
    expires_at = _timestamp(payload["expires_at"])
    observed_at = _timestamp(verification_time)
    constraints = policy["time_constraints"]
    if (
        not policy_reviewed <= reviewed_at <= observed_at <= expires_at
        or (reviewed_at - policy_reviewed).total_seconds()
        > constraints["max_policy_to_decision_seconds"]
        or (expires_at - reviewed_at).total_seconds()
        > constraints["max_decision_validity_seconds"]
    ):
        raise _invalid()

    return VerifiedReviewDecision(
        decision_id=payload["decision_id"],
        reviewer_key_id=anchor["key_id"],
        reviewer_reference=payload["reviewer_reference"],
        reviewed_at=payload["reviewed_at"],
        expires_at=payload["expires_at"],
        policy_sha256=policy_sha256,
        decision_sha256=decision_sha256,
        input_manifest_sha256=verified_acceptance.manifest_sha256,
        verifier_source_sha256=verifier_sha256,
        release_commit=readiness.release_commit,
        release_manifest_sha256=readiness.release_manifest_sha256,
        upstream_key_ids=(
            *verified_acceptance.t143_trust_anchor_key_ids,
            verified_acceptance.github_collection.collector_key_id,
            verified_acceptance.github_collection.ledger_key_id,
            verified_acceptance.worm_collection.provider_signer_key_id,
            verified_acceptance.worm_collection.ledger_signer_key_id,
        ),
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


def _read_blob(
    path_value: Path | str,
    *,
    max_bytes: int,
    external: bool,
) -> StableBlob:
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
            blob.path,
            max_bytes=blob.max_bytes,
            expected_identity=blob.identity,
        )
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1 or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(), blob.sha256
    ):
        raise _invalid()


def verify_decision(
    decision_path: Path | str,
    policy_path: Path | str,
    input_manifest_path: Path | str,
    *,
    expected_decision_sha256: str,
    expected_policy_sha256: str,
    expected_input_manifest_sha256: str,
    expected_verifier_source_sha256: str,
    expected_release_commit: str,
    expected_release_manifest_sha256: str,
    expected_decision_id: str,
    verification_time: str,
) -> VerifiedReviewDecision:
    paths = (decision_path, policy_path, input_manifest_path)
    normalized = {
        str(_external_path(path).resolve(strict=False)).casefold() for path in paths
    }
    if len(normalized) != len(paths):
        raise _invalid()
    decision_blob = _read_blob(decision_path, max_bytes=MAX_JSON_BYTES, external=True)
    policy_blob = _read_blob(policy_path, max_bytes=MAX_JSON_BYTES, external=True)
    source_blob = _read_blob(SOURCE, max_bytes=MAX_SOURCE_BYTES, external=False)
    try:
        for value in (
            expected_decision_sha256,
            expected_policy_sha256,
            expected_input_manifest_sha256,
            expected_verifier_source_sha256,
            expected_release_manifest_sha256,
        ):
            _digest(value)
        if (
            not hmac.compare_digest(
                decision_blob.sha256, expected_decision_sha256
            )
            or not hmac.compare_digest(policy_blob.sha256, expected_policy_sha256)
            or not hmac.compare_digest(
                source_blob.sha256, expected_verifier_source_sha256
            )
        ):
            raise _invalid()
        verified_acceptance = backed.verify_input_manifest_projection(
            input_manifest_path,
            expected_manifest_sha256=expected_input_manifest_sha256,
        )
        verified = verify_decision_bytes(
            decision_raw=decision_blob.raw,
            policy_raw=policy_blob.raw,
            verifier_source_raw=source_blob.raw,
            verified_acceptance=verified_acceptance,
            expected_decision_sha256=expected_decision_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_input_manifest_sha256=expected_input_manifest_sha256,
            expected_verifier_source_sha256=expected_verifier_source_sha256,
            expected_release_commit=expected_release_commit,
            expected_release_manifest_sha256=expected_release_manifest_sha256,
            expected_decision_id=expected_decision_id,
            verification_time=verification_time,
        )
    except backed.CollectionBackedAcceptanceError as error:
        raise _invalid() from error
    for blob in (decision_blob, policy_blob, source_blob):
        _unchanged(blob)
    return verified


def verify_repository_assets() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = validate_policy(
            _document(read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
        decision = validate_decision(
            _document(read_stable_bytes(TEMPLATE, max_bytes=MAX_JSON_BYTES)),
            allow_synthetic=True,
        )
    except (OSError, StableFileError, TypeError, ValueError) as error:
        raise _invalid() from error
    return policy, decision


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CollectionReviewDecisionError("collection review arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--decision", required=True, type=Path)
    verify.add_argument("--policy", required=True, type=Path)
    verify.add_argument("--input-manifest", required=True, type=Path)
    verify.add_argument("--expected-decision-sha256", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-input-manifest-sha256", required=True)
    verify.add_argument("--expected-verifier-source-sha256", required=True)
    verify.add_argument("--expected-release-commit", required=True)
    verify.add_argument("--expected-release-manifest-sha256", required=True)
    verify.add_argument("--expected-decision-id", required=True)
    verify.add_argument("--verification-time", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            verify_repository_assets()
            print(
                "private-secret-collection-review-template-ok status=pending "
                "reviewer-authentication=unverified provider-native=unverified "
                "trusted-time=unverified global-replay-protection=unverified "
                "decision-id-uniqueness=unverified durability=unverified "
                "production_acceptance=false not_committed_eligible=false"
            )
            return 0
        verified = verify_decision(
            options.decision,
            options.policy,
            options.input_manifest,
            expected_decision_sha256=options.expected_decision_sha256,
            expected_policy_sha256=options.expected_policy_sha256,
            expected_input_manifest_sha256=options.expected_input_manifest_sha256,
            expected_verifier_source_sha256=options.expected_verifier_source_sha256,
            expected_release_commit=options.expected_release_commit,
            expected_release_manifest_sha256=options.expected_release_manifest_sha256,
            expected_decision_id=options.expected_decision_id,
            verification_time=options.verification_time,
        )
    except (CollectionReviewDecisionError, OSError, TypeError, ValueError):
        print("private-secret-collection-review-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-review-ok reviewer-authentication=verified "
        "projection-binding=verified manifest-binding=verified "
        "provider-native=unverified trusted-time=unverified "
        "global-replay-protection=unverified decision-id-uniqueness=unverified "
        "verifier-release-provenance=unverified sink-immutability=unverified "
        "durability=unverified fork-protection=unverified "
        "rollback-protection=unverified production_acceptance=false "
        "not_committed_eligible=false "
        f"decision_id={verified.decision_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
