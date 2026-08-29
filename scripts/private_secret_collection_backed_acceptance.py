"""Offline orchestration for a T143 acceptance backed by both T142 verifiers.

The caller supplies paths and independent pins, never preconstructed verifier
results.  This module performs no network, provider, sink, or CAS operation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import sys
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import private_secret_collector_deployment as deployment
from scripts import private_secret_github_rest_collection as github
from scripts import private_secret_worm_collection as worm
from scripts.external_json import (
    MAX_EXTERNAL_JSON_BYTES,
    MAX_INTAKE_JSON_BYTES,
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)


class CollectionBackedAcceptanceError(ValueError):
    pass


_GITHUB_PATH_ORDER = (
    "input_path", "request_path", "previous_head_path", "policy_path",
    "github_origin_path", "archive_path", "bundle_path",
)
_GITHUB_PATHS = set(_GITHUB_PATH_ORDER)
_GITHUB_PINS = {
    "expected_receipt_sha256", "expected_policy_sha256", "expected_request_sha256",
    "expected_previous_head_sha256", "expected_github_origin_sha256",
    "expected_archive_sha256", "expected_bundle_sha256", "expected_ledger_id",
    "expected_sequence",
}
_WORM_PATH_ORDER = (
    "input_path", "policy_path", "target_policy_path", "target_origin_path",
    "crash_evidence_path", "before_inventory_path", "after_inventory_path",
    "target_inventory_path", "release_execution_path", "alert_evidence_path",
    "worm_receipt_path", "target_delete_probe_path", "custody_evidence_path",
    "provider_config_path", "object_metadata_path", "delete_observation_path",
    "readback_path", "trusted_time_path", "prior_checkpoint_path",
)
_WORM_PATHS = set(_WORM_PATH_ORDER)
_WORM_PINS = {
    "expected_collection_sha256", "expected_policy_sha256", "expected_target_policy_sha256",
    "expected_cluster_fingerprint_sha256", "expected_ledger_id",
    "expected_sequence", "expected_prior_head_sha256", "verification_time",
    "expected_runtime_policy_sha256",
}
_ACCEPTANCE_PINS = {
    "expected_policy_sha256", "expected_readiness_sha256", "expected_execution_sha256",
    "expected_request_sha256", "expected_previous_github_collection_head_sha256",
    "expected_current_worm_collection_head_sha256", "expected_github_collection_head_sha256",
    "expected_worm_collection_head_sha256", "expected_collection_prior_head_sha256",
    "expected_collection_ledger_id", "expected_collection_sequence",
    "expected_prior_head_sha256", "expected_ledger_id", "expected_sequence",
    "expected_prior_generation",
}
_MANIFEST_FIELDS = {
    "schema_version", "manifest_kind", "policy_path", "readiness_path",
    "execution_path", "acceptance_pins", "github_inputs", "worm_inputs",
}
MANIFEST_KIND = "private_secret_collection_backed_acceptance_input_manifest"


@dataclass(frozen=True)
class StableInput:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str
    max_bytes: int


@dataclass(frozen=True)
class VerifiedCollectionBackedAcceptance:
    manifest_sha256: str
    acceptance: deployment.VerifiedAcceptanceTransaction
    readiness: deployment.VerifiedReadinessPreflight
    github_collection: github.VerifiedCollection
    worm_collection: worm.VerifiedCollection
    t143_trust_anchor_key_ids: tuple[str, ...]


def _closed(value: Mapping[str, object], fields: set[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    return dict(value)


def _all_paths(
    policy_path: Path | str,
    readiness_path: Path | str,
    execution_path: Path | str,
    github_values: Mapping[str, object],
    worm_values: Mapping[str, object],
) -> list[Path | str]:
    values: list[Path | str] = [policy_path, readiness_path, execution_path]
    values.extend(github_values[key] for key in _GITHUB_PATH_ORDER)  # type: ignore[arg-type]
    values.extend(
        worm_values[key]  # type: ignore[arg-type]
        for key in _WORM_PATH_ORDER
        if key != "prior_checkpoint_path" or worm_values[key] is not None
    )
    return values


def _external_absolute_path(value: object) -> None:
    if not isinstance(value, str):
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    try:
        path.resolve(strict=False).relative_to(deployment.ROOT.resolve(strict=True))
    except ValueError:
        return
    raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")


def _stable_input(
    path_value: Path | str,
    *,
    max_bytes: int,
    external: bool = True,
) -> StableInput:
    path = Path(path_value)
    if external:
        _external_absolute_path(str(path))
    elif path.resolve(strict=False) != worm.RUNTIME_POLICY.resolve(strict=False):
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=max_bytes)
    except (OSError, StableFileError, ValueError) as error:
        raise CollectionBackedAcceptanceError(
            "collection-backed acceptance is invalid"
        ) from error
    if metadata.st_nlink != 1:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    return StableInput(
        path=path,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
        max_bytes=max_bytes,
    )


def _unchanged(blob: StableInput) -> None:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            blob.path,
            max_bytes=blob.max_bytes,
            expected_identity=blob.identity,
        )
    except (OSError, StableFileError, ValueError) as error:
        raise CollectionBackedAcceptanceError(
            "collection-backed acceptance is invalid"
        ) from error
    if metadata.st_nlink != 1 or not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(), blob.sha256
    ):
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")


def _reject_duplicate_identities(blobs: list[StableInput]) -> None:
    identities = {(blob.identity.device, blob.identity.inode) for blob in blobs}
    if len(identities) != len(blobs):
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")


def parse_input_manifest(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > deployment.MAX_JSON_BYTES:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
    try:
        value = _closed(parse_unique_json_bytes(raw), _MANIFEST_FIELDS)
        if (
            value["schema_version"] != 1
            or type(value["schema_version"]) is not int
            or value["manifest_kind"] != MANIFEST_KIND
        ):
            raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
        for field in ("policy_path", "readiness_path", "execution_path"):
            _external_absolute_path(value[field])
        github_values = _closed(value["github_inputs"], _GITHUB_PATHS | _GITHUB_PINS)  # type: ignore[arg-type]
        worm_values = _closed(value["worm_inputs"], _WORM_PATHS | _WORM_PINS)  # type: ignore[arg-type]
        acceptance_pins = _closed(value["acceptance_pins"], _ACCEPTANCE_PINS)  # type: ignore[arg-type]
        for key in _GITHUB_PATHS:
            _external_absolute_path(github_values[key])
        for key in _WORM_PATHS:
            item = worm_values[key]
            if key == "prior_checkpoint_path" and item is None:
                continue
            _external_absolute_path(item)
        for mapping, digest_fields, integer_fields, text_fields in (
            (
                acceptance_pins,
                _ACCEPTANCE_PINS - {
                    "expected_collection_ledger_id", "expected_collection_sequence",
                    "expected_ledger_id", "expected_sequence", "expected_prior_generation",
                },
                {"expected_collection_sequence", "expected_sequence"},
                {"expected_collection_ledger_id", "expected_ledger_id", "expected_prior_generation"},
            ),
            (
                github_values,
                _GITHUB_PINS - {"expected_ledger_id", "expected_sequence"},
                {"expected_sequence"},
                {"expected_ledger_id"},
            ),
            (
                worm_values,
                _WORM_PINS - {"expected_ledger_id", "expected_sequence", "verification_time"},
                {"expected_sequence"},
                {"expected_ledger_id", "verification_time"},
            ),
        ):
            for field in digest_fields:
                deployment._digest(mapping[field])
            for field in integer_fields:
                if type(mapping[field]) is not int or mapping[field] < 1:
                    raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
            for field in text_fields:
                deployment._safe_text(mapping[field])
        if not (
            acceptance_pins["expected_request_sha256"] == github_values["expected_request_sha256"]
            and acceptance_pins["expected_previous_github_collection_head_sha256"]
            == acceptance_pins["expected_collection_prior_head_sha256"]
            == github_values["expected_previous_head_sha256"]
            and acceptance_pins["expected_collection_ledger_id"] == github_values["expected_ledger_id"]
            and acceptance_pins["expected_collection_sequence"] == github_values["expected_sequence"]
            and acceptance_pins["expected_current_worm_collection_head_sha256"]
            == acceptance_pins["expected_worm_collection_head_sha256"]
            == worm_values["expected_collection_sha256"]
        ):
            raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
        return value
    except CollectionBackedAcceptanceError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid") from error


def verify_input_manifest_projection(
    manifest_path: Path | str,
    *,
    expected_manifest_sha256: str,
) -> VerifiedCollectionBackedAcceptance:
    try:
        manifest_blob = _stable_input(
            manifest_path, max_bytes=deployment.MAX_JSON_BYTES
        )
        deployment._digest(expected_manifest_sha256)
        if not hmac.compare_digest(manifest_blob.sha256, expected_manifest_sha256):
            raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
        manifest = parse_input_manifest(manifest_blob.raw)
        github_values = dict(manifest["github_inputs"])  # type: ignore[arg-type]
        worm_values = dict(manifest["worm_inputs"])  # type: ignore[arg-type]
        paths = _all_paths(
            manifest["policy_path"], manifest["readiness_path"], manifest["execution_path"],
            github_values, worm_values,
        )
        normalized = {str(Path(value).resolve(strict=False)).casefold() for value in paths}
        normalized.add(str(manifest_blob.path.resolve(strict=False)).casefold())
        if len(normalized) != len(paths) + 1:
            raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
        accepted, readiness, github_result, worm_result, t143_key_ids = (
            _verify_collection_backed_acceptance(
            manifest["policy_path"], manifest["readiness_path"], manifest["execution_path"],
            acceptance_pins=manifest["acceptance_pins"],  # type: ignore[arg-type]
            github_inputs=github_values,
            worm_inputs=worm_values,
            )
        )
        _unchanged(manifest_blob)
        return VerifiedCollectionBackedAcceptance(
            manifest_sha256=manifest_blob.sha256,
            acceptance=accepted,
            readiness=readiness,
            github_collection=github_result,
            worm_collection=worm_result,
            t143_trust_anchor_key_ids=t143_key_ids,
        )
    except CollectionBackedAcceptanceError:
        raise
    except (deployment.CollectorDeploymentError, OSError, TypeError, ValueError) as error:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid") from error


def verify_input_manifest(
    manifest_path: Path | str,
    *,
    expected_manifest_sha256: str,
) -> deployment.VerifiedAcceptanceTransaction:
    return verify_input_manifest_projection(
        manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
    ).acceptance


def _verify_collection_backed_acceptance(
    policy_path: Path | str,
    readiness_path: Path | str,
    execution_path: Path | str,
    *,
    acceptance_pins: Mapping[str, object],
    github_inputs: Mapping[str, object],
    worm_inputs: Mapping[str, object],
) -> tuple[
    deployment.VerifiedAcceptanceTransaction,
    deployment.VerifiedReadinessPreflight,
    github.VerifiedCollection,
    worm.VerifiedCollection,
    tuple[str, ...],
]:
    """Invoke both T142 verifiers and reconcile their results with T143."""

    pins = _closed(acceptance_pins, _ACCEPTANCE_PINS)
    github_values = _closed(github_inputs, _GITHUB_PATHS | _GITHUB_PINS)
    worm_values = _closed(worm_inputs, _WORM_PATHS | _WORM_PINS)
    path_values = _all_paths(
        policy_path, readiness_path, execution_path, github_values, worm_values
    )
    try:
        normalized = {
            str(Path(value).resolve(strict=False)).casefold() for value in path_values
        }
    except (OSError, TypeError, ValueError) as error:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid") from error
    if len(normalized) != len(path_values):
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")

    try:
        acceptance_blobs = [
            _stable_input(value, max_bytes=deployment.MAX_JSON_BYTES)
            for value in (policy_path, readiness_path, execution_path)
        ]
        github_blobs = {
            key: _stable_input(
                github_values[key],  # type: ignore[arg-type]
                max_bytes=(
                    github.MAX_DOWNLOAD_BYTES
                    if key in {"archive_path", "bundle_path"}
                    else github.MAX_JSON_BYTES
                ),
            )
            for key in _GITHUB_PATH_ORDER
        }
        worm_intake_paths = {
            "input_path", "policy_path", "target_policy_path", "target_origin_path",
            "crash_evidence_path", "release_execution_path", "prior_checkpoint_path",
        }
        worm_blobs = {
            key: _stable_input(
                worm_values[key],  # type: ignore[arg-type]
                max_bytes=(
                    MAX_INTAKE_JSON_BYTES
                    if key in worm_intake_paths
                    else MAX_EXTERNAL_JSON_BYTES
                ),
            )
            for key in _WORM_PATH_ORDER
            if key != "prior_checkpoint_path" or worm_values[key] is not None
        }
        runtime_policy_blob = _stable_input(
            worm.RUNTIME_POLICY,
            max_bytes=MAX_INTAKE_JSON_BYTES,
            external=False,
        )
        all_blobs = [
            *acceptance_blobs,
            *github_blobs.values(),
            *worm_blobs.values(),
            runtime_policy_blob,
        ]
        _reject_duplicate_identities(all_blobs)
        if not hmac.compare_digest(
            runtime_policy_blob.sha256,
            worm_values["expected_runtime_policy_sha256"],  # type: ignore[arg-type]
        ):
            raise CollectionBackedAcceptanceError(
                "collection-backed acceptance is invalid"
            )

        readiness = deployment.verify_readiness_preflight(
            acceptance_blobs[0].raw,
            acceptance_blobs[1].raw,
            expected_policy_sha256=pins["expected_policy_sha256"],
            expected_readiness_sha256=pins["expected_readiness_sha256"],
            expected_request_sha256=pins["expected_request_sha256"],
            expected_previous_github_collection_head_sha256=pins["expected_previous_github_collection_head_sha256"],
            expected_current_worm_collection_head_sha256=pins["expected_current_worm_collection_head_sha256"],
            expected_collection_prior_head_sha256=pins["expected_collection_prior_head_sha256"],
            expected_collection_ledger_id=pins["expected_collection_ledger_id"],
            expected_collection_sequence=pins["expected_collection_sequence"],
        )
        github_result = github.verify_collection_bytes(
            input_raw=github_blobs["input_path"].raw,
            request_raw=github_blobs["request_path"].raw,
            previous_head_raw=github_blobs["previous_head_path"].raw,
            policy_raw=github_blobs["policy_path"].raw,
            github_origin_raw=github_blobs["github_origin_path"].raw,
            deployment_policy_raw=acceptance_blobs[0].raw,
            readiness_raw=acceptance_blobs[1].raw,
            archive_raw=github_blobs["archive_path"].raw,
            bundle_raw=github_blobs["bundle_path"].raw,
            expected_receipt_sha256=github_values["expected_receipt_sha256"],  # type: ignore[arg-type]
            expected_policy_sha256=github_values["expected_policy_sha256"],  # type: ignore[arg-type]
            expected_request_sha256=github_values["expected_request_sha256"],  # type: ignore[arg-type]
            expected_previous_head_sha256=github_values["expected_previous_head_sha256"],  # type: ignore[arg-type]
            expected_github_origin_sha256=github_values["expected_github_origin_sha256"],  # type: ignore[arg-type]
            expected_deployment_policy_sha256=pins["expected_policy_sha256"],
            expected_readiness_sha256=pins["expected_readiness_sha256"],
            expected_archive_sha256=github_values["expected_archive_sha256"],  # type: ignore[arg-type]
            expected_bundle_sha256=github_values["expected_bundle_sha256"],  # type: ignore[arg-type]
            expected_current_worm_collection_head_sha256=pins["expected_current_worm_collection_head_sha256"],
            expected_ledger_id=github_values["expected_ledger_id"],  # type: ignore[arg-type]
            expected_sequence=github_values["expected_sequence"],  # type: ignore[arg-type]
        )
        worm_result = worm.verify_collection_bytes(
            input_raw=worm_blobs["input_path"].raw,
            policy_raw=worm_blobs["policy_path"].raw,
            target_policy_raw=worm_blobs["target_policy_path"].raw,
            runtime_policy_raw=runtime_policy_blob.raw,
            target_origin_raw=worm_blobs["target_origin_path"].raw,
            crash_evidence_raw=worm_blobs["crash_evidence_path"].raw,
            before_inventory_raw=worm_blobs["before_inventory_path"].raw,
            after_inventory_raw=worm_blobs["after_inventory_path"].raw,
            target_inventory_raw=worm_blobs["target_inventory_path"].raw,
            release_execution_raw=worm_blobs["release_execution_path"].raw,
            alert_evidence_raw=worm_blobs["alert_evidence_path"].raw,
            worm_receipt_raw=worm_blobs["worm_receipt_path"].raw,
            target_delete_probe_raw=worm_blobs["target_delete_probe_path"].raw,
            custody_evidence_raw=worm_blobs["custody_evidence_path"].raw,
            provider_config_raw=worm_blobs["provider_config_path"].raw,
            object_metadata_raw=worm_blobs["object_metadata_path"].raw,
            delete_observation_raw=worm_blobs["delete_observation_path"].raw,
            readback_raw=worm_blobs["readback_path"].raw,
            trusted_time_raw=worm_blobs["trusted_time_path"].raw,
            prior_checkpoint_raw=(
                worm_blobs["prior_checkpoint_path"].raw
                if "prior_checkpoint_path" in worm_blobs
                else None
            ),
            expected_collection_sha256=worm_values["expected_collection_sha256"],  # type: ignore[arg-type]
            expected_policy_sha256=worm_values["expected_policy_sha256"],  # type: ignore[arg-type]
            expected_target_policy_sha256=worm_values["expected_target_policy_sha256"],  # type: ignore[arg-type]
            expected_cluster_fingerprint_sha256=worm_values["expected_cluster_fingerprint_sha256"],  # type: ignore[arg-type]
            expected_ledger_id=worm_values["expected_ledger_id"],  # type: ignore[arg-type]
            expected_sequence=worm_values["expected_sequence"],  # type: ignore[arg-type]
            expected_prior_head_sha256=worm_values["expected_prior_head_sha256"],  # type: ignore[arg-type]
            verification_time=worm_values["verification_time"],  # type: ignore[arg-type]
        )
        accepted = deployment.verify_acceptance_transaction(
            acceptance_blobs[0].raw,
            acceptance_blobs[1].raw,
            acceptance_blobs[2].raw,
            **pins,
        )
        deployment_policy = deployment.parse_policy(acceptance_blobs[0].raw)
        upstream = deployment_policy["upstream_bindings"]
        t143_key_ids = tuple(
            deployment_policy["trust_anchors"][role]["key_id"]
            for role in deployment.ROLE_DOMAINS
        )
        checks = (
            github_result.attempt_id == worm_result.attempt_id == accepted.attempt_id == readiness.attempt_id,
            github_result.deployment_id == accepted.deployment_id == readiness.deployment_id,
            github_result.request_sha256 == readiness.request_sha256,
            github_result.policy_sha256 == readiness.upstream_t142_github_policy_sha256,
            github_result.deployment_policy_sha256 == readiness.policy_sha256,
            github_result.readiness_sha256 == readiness.readiness_sha256,
            github_result.previous_head_sha256 == readiness.collection_prior_head_sha256,
            github_result.current_worm_collection_head_sha256 == worm_result.head_sha256,
            github_result.collector_key_id == upstream["github_collector_key_id"],
            github_result.ledger_key_id == upstream["github_ledger_key_id"],
            github_result.receipt_sha256 == accepted.github_collection_receipt_sha256,
            github_result.replay_head_sha256 == accepted.github_collection_head_sha256,
            github_result.ledger_id == accepted.github_collection_ledger_id == readiness.collection_ledger_id,
            github_result.sequence == accepted.github_collection_sequence == readiness.collection_expected_sequence,
            github_result.raw_response_set_sha256 == accepted.github_raw_response_set_sha256,
            worm_result.policy_sha256 == readiness.upstream_t142_worm_policy_sha256,
            worm_result.target_policy_sha256 == readiness.upstream_t141_target_policy_sha256,
            worm_result.cluster_fingerprint_sha256 == readiness.cluster_fingerprint_sha256,
            worm_result.provider_signer_key_id == upstream["worm_provider_key_id"],
            worm_result.ledger_signer_key_id == upstream["worm_ledger_key_id"],
            worm_result.provider_kind == accepted.worm_provider_kind == readiness.target_provider_kind,
            worm_result.provider_account_fingerprint_sha256 == readiness.target_provider_account_fingerprint_sha256,
            worm_result.storage_identity_fingerprint_sha256 == accepted.worm_storage_identity_fingerprint_sha256 == readiness.target_storage_identity_fingerprint_sha256,
            worm_result.configuration_snapshot_sha256 == accepted.worm_configuration_snapshot_sha256,
            worm_result.retention_mode == accepted.worm_retention_mode == readiness.target_retention_mode,
            worm_result.receipt_sha256 == accepted.worm_collection_receipt_sha256,
            worm_result.head_sha256 == accepted.worm_collection_head_sha256,
            worm_result.ledger_id == accepted.worm_collection_ledger_id,
            worm_result.sequence == accepted.worm_collection_sequence,
            github_result.replay_head_sha256 == pins["expected_github_collection_head_sha256"],
            worm_result.head_sha256 == pins["expected_worm_collection_head_sha256"],
        )
        if not all(checks):
            raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")
        for blob in all_blobs:
            _unchanged(blob)
        return accepted, readiness, github_result, worm_result, t143_key_ids
    except CollectionBackedAcceptanceError:
        raise
    except (deployment.CollectorDeploymentError, github.GitHubRestCollectionError, worm.PrivateSecretWormCollectionError, OSError, TypeError, ValueError) as error:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid") from error


def verify_collection_backed_acceptance(
    policy_path: Path | str,
    readiness_path: Path | str,
    execution_path: Path | str,
    *,
    acceptance_pins: Mapping[str, object],
    github_inputs: Mapping[str, object],
    worm_inputs: Mapping[str, object],
) -> deployment.VerifiedAcceptanceTransaction:
    return _verify_collection_backed_acceptance(
        policy_path,
        readiness_path,
        execution_path,
        acceptance_pins=acceptance_pins,
        github_inputs=github_inputs,
        worm_inputs=worm_inputs,
    )[0]


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CollectionBackedAcceptanceError("collection-backed acceptance is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--input-manifest", required=True, type=Path)
    verify.add_argument("--expected-input-manifest-sha256", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        result = verify_input_manifest(
            options.input_manifest,
            expected_manifest_sha256=options.expected_input_manifest_sha256,
        )
    except CollectionBackedAcceptanceError:
        print("private-secret-collection-backed-acceptance-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-backed-acceptance-ok "
        "manifest-authentication=caller-pinned-raw-sha256 "
        "github-collection=authenticated worm-collection=authenticated "
        "provider-native=unverified trusted-time=unverified "
        "global-cas-linearizability=unverified fork-protection=unverified "
        "rollback-protection=unverified sink-immutability=unverified "
        "durability=unverified reviewer-independence=unverified "
        "production_acceptance=false not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
