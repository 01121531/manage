"""Derive one closed TLS runtime support artifact from execution evidence.

The runtime state is recomputed from a sealed schema-v5 execution artifact.  A
caller cannot provide the state or peer observations on the command line.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence

from scripts.backup_output_policy import (
    REPOSITORY_ROOT,
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
from scripts.release_control_lock import release_control_lock
from scripts.tls_rotation_evidence import (
    assert_expected_rotation,
    load_projection,
    rotation_plan_digest,
    utc_now,
    validate_evidence,
    verify_evidence,
)


SCHEMA_VERSION = 1
EVIDENCE_KIND = "tls_leaf_rotation_runtime_support"
MAX_JSON_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SUPPORT_REASON_CODES = frozenset({
    "execution_not_completed",
    "preflight_unconfirmed",
    "action_result_unknown",
    "containment_unconfirmed",
    "runtime_observations_incomplete",
})
_PAYLOAD_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "rotation_plan_sha256",
    "runtime_profile_sha256",
    "execution_evidence_sha256",
    "assessor_reference",
    "observation_started_at",
    "observation_finished_at",
    "derived_runtime_state",
    "reason_code",
}


class TlsRotationSupportError(ValueError):
    """Runtime support could not be derived or verified safely."""


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationSupportError("TLS rotation support path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationSupportError("TLS rotation support path is invalid")


def _canonical_digest(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TlsRotationSupportError("TLS rotation support timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TlsRotationSupportError("TLS rotation support timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise TlsRotationSupportError("TLS rotation support timestamp is invalid")
    return parsed


def _execution_digest(evidence: Mapping[str, object]) -> str:
    return _canonical_digest(evidence)


def _observation_set(
    observations: object,
    *,
    phase: str,
    expected_sha256: str,
) -> list[dict[str, object]]:
    if not isinstance(observations, list):
        return []
    return [
        item for item in observations
        if isinstance(item, dict)
        and item.get("phase") == phase
        and item.get("expected_sha256") == expected_sha256
        and item.get("peer_sha256") == expected_sha256
    ]


def derive_runtime_state(
    evidence: Mapping[str, object], projection: Mapping[str, object]
) -> tuple[str, str | None]:
    """Recompute old/new/unknown without trusting a caller-authored state."""

    validated = validate_evidence(dict(evidence))
    assert_expected_rotation(validated, projection)
    count = int(projection["expected_instance_count"])
    action = validated["action"]
    instances = validated["instances"]
    observations = validated["peer_observations"]
    terminal = validated["terminal_state"]
    if not isinstance(action, dict) or not isinstance(instances, dict):
        return "unknown", "runtime_observations_incomplete"

    if terminal == "completed":
        after = instances.get("after")
        direct = _observation_set(
            observations,
            phase="after_instance",
            expected_sha256=str(projection["new_leaf_sha256"]),
        )
        route = _observation_set(
            observations,
            phase="retirement_route",
            expected_sha256=str(projection["new_leaf_sha256"]),
        )
        direct_ids = {
            item.get("instance_id") for item in direct if item.get("attempt") == 1
        }
        after_ids = {
            item.get("instance_id") for item in after if isinstance(item, dict)
        } if isinstance(after, list) else set()
        route_attempts = {
            (item.get("observer"), item.get("attempt")) for item in route
        }
        required_attempts = {
            (observer, attempt)
            for observer in projection["required_observers"]
            for attempt in (1, 2, 3)
        }
        if (
            isinstance(after, list)
            and len(after) == count
            and len(direct) == count
            and direct_ids == after_ids
            and route_attempts == required_attempts
            and validated["old_fingerprint_retirement"].get("status")
            == "absent_from_final_inventory_and_sampled_routes"
        ):
            return "verified_new", None
        return "unknown", "runtime_observations_incomplete"

    reconciliation = action.get("reconciliation")
    if terminal == "action_failed" and isinstance(reconciliation, dict):
        result = reconciliation.get("result")
        if result in {"verified_old", "verified_new"}:
            expected = str(
                projection["old_leaf_sha256"]
                if result == "verified_old"
                else projection["new_leaf_sha256"]
            )
            reconciled_instances = reconciliation.get("instances")
            reconciled_observations = reconciliation.get("peer_observations")
            matching = _observation_set(
                reconciled_observations,
                phase=(
                    "action_reconcile_old"
                    if result == "verified_old"
                    else "action_reconcile_new"
                ),
                expected_sha256=expected,
            )
            instance_ids = {
                item.get("instance_id")
                for item in reconciled_instances
                if isinstance(item, dict)
            } if isinstance(reconciled_instances, list) else set()
            observed_ids = {item.get("instance_id") for item in matching}
            if (
                isinstance(reconciled_instances, list)
                and len(reconciled_instances) == count
                and len(matching) == count
                and instance_ids == observed_ids
            ):
                return str(result), None
            return "unknown", "runtime_observations_incomplete"
        return "unknown", "action_result_unknown"
    if terminal == "preflight_failed":
        return "unknown", "preflight_unconfirmed"
    if terminal == "containment_unconfirmed":
        return "unknown", "containment_unconfirmed"
    return "unknown", "execution_not_completed"


def _seal(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != _PAYLOAD_FIELDS:
        raise TlsRotationSupportError("TLS rotation support is invalid")
    state = payload["derived_runtime_state"]
    reason = payload["reason_code"]
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
        or any(
            not isinstance(payload[field], str)
            or _SHA256.fullmatch(payload[field]) is None
            for field in (
                "rotation_plan_sha256",
                "runtime_profile_sha256",
                "execution_evidence_sha256",
            )
        )
        or not isinstance(payload["assessor_reference"], str)
        or _REFERENCE.fullmatch(payload["assessor_reference"]) is None
        or state not in {"verified_old", "verified_new", "unknown"}
        or (state == "unknown" and reason not in SUPPORT_REASON_CODES)
        or (state != "unknown" and reason is not None)
    ):
        raise TlsRotationSupportError("TLS rotation support is invalid")
    if parse_utc(payload["observation_finished_at"]) < parse_utc(
        payload["observation_started_at"]
    ):
        raise TlsRotationSupportError("TLS rotation support is invalid")
    sealed = dict(payload)
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def validate_support(
    value: object,
    projection: Mapping[str, object],
    execution_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {*_PAYLOAD_FIELDS, "integrity"}:
        raise TlsRotationSupportError("TLS rotation support is invalid")
    integrity = value["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        raise TlsRotationSupportError("TLS rotation support is invalid")
    payload = {key: item for key, item in value.items() if key != "integrity"}
    expected = _seal(payload)
    actual_digest = integrity.get("payload_sha256")
    if (
        not isinstance(actual_digest, str)
        or _SHA256.fullmatch(actual_digest) is None
        or not hmac.compare_digest(
            actual_digest, expected["integrity"]["payload_sha256"]
        )
        or payload["rotation_plan_sha256"] != rotation_plan_digest(projection)
        or payload["runtime_profile_sha256"] != projection["runtime_profile_sha256"]
    ):
        raise TlsRotationSupportError("TLS rotation support is invalid")
    if execution_evidence is not None:
        state, reason = derive_runtime_state(execution_evidence, projection)
        if (
            payload["execution_evidence_sha256"]
            != _execution_digest(execution_evidence)
            or payload["observation_started_at"] != execution_evidence["started_at"]
            or payload["observation_finished_at"] != execution_evidence["finished_at"]
            or payload["derived_runtime_state"] != state
            or payload["reason_code"] != reason
        ):
            raise TlsRotationSupportError("TLS rotation support derivation is invalid")
    return dict(value)


def load_support(
    path: Path,
    projection: Mapping[str, object],
    execution_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    raw = read_stable_bytes(_external_path(path), max_bytes=MAX_JSON_BYTES)
    return validate_support(parse_unique_json_bytes(raw), projection, execution_evidence)


def generate_support(
    projection_path: Path,
    execution_evidence_path: Path,
    support_output: Path,
    *,
    assessor_reference: str,
    confirm_rotation_plan_sha256: str,
) -> str:
    projection_source = _external_path(projection_path)
    evidence_source = _external_path(execution_evidence_path)
    output = prepare_write_once_file(_external_path(support_output))
    paths = {str(item.resolve(strict=False)).casefold() for item in (
        projection_source, evidence_source, output
    )}
    if len(paths) != 3:
        raise TlsRotationSupportError("TLS rotation support paths are invalid")
    with release_control_lock():
        projection = load_projection(projection_source)
        plan_digest = rotation_plan_digest(projection)
        if (
            _SHA256.fullmatch(confirm_rotation_plan_sha256 or "") is None
            or not hmac.compare_digest(confirm_rotation_plan_sha256, plan_digest)
        ):
            raise TlsRotationSupportError("TLS rotation plan confirmation failed")
        evidence = verify_evidence(evidence_source)
        assert_expected_rotation(evidence, projection)
        state, reason = derive_runtime_state(evidence, projection)
        sealed = _seal({
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "production_acceptance": False,
            "rotation_plan_sha256": plan_digest,
            "runtime_profile_sha256": projection["runtime_profile_sha256"],
            "execution_evidence_sha256": _execution_digest(evidence),
            "assessor_reference": assessor_reference,
            "observation_started_at": evidence["started_at"],
            "observation_finished_at": evidence["finished_at"],
            "derived_runtime_state": state,
            "reason_code": reason,
        })
        raw = (json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = write_fsynced_temporary_bytes(output, raw)
        try:
            publish_write_once_file(temporary, output)
        finally:
            discard_claimed_temporary_file(temporary)
        verified = load_support(output, projection, evidence)
        if verified != sealed:
            raise TlsRotationSupportError("TLS rotation support publication failed")
    return str(sealed["integrity"]["payload_sha256"])


def verify_support(
    projection_path: Path,
    execution_evidence_path: Path,
    support_path: Path,
    *,
    confirm_rotation_plan_sha256: str,
) -> str:
    projection = load_projection(_external_path(projection_path))
    plan_digest = rotation_plan_digest(projection)
    if not hmac.compare_digest(confirm_rotation_plan_sha256, plan_digest):
        raise TlsRotationSupportError("TLS rotation plan confirmation failed")
    evidence = verify_evidence(_external_path(execution_evidence_path))
    support = load_support(_external_path(support_path), projection, evidence)
    return str(support["integrity"]["payload_sha256"])


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationSupportError("TLS rotation support CLI input is invalid") from None


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    generate = sub.add_parser("generate", allow_abbrev=False)
    generate.add_argument("--projection", type=Path, required=True)
    generate.add_argument("--execution-evidence", type=Path, required=True)
    generate.add_argument("--support-output", type=Path, required=True)
    generate.add_argument("--assessor-reference", required=True)
    generate.add_argument("--confirm-rotation-plan-sha256", required=True)
    verify = sub.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--projection", type=Path, required=True)
    verify.add_argument("--execution-evidence", type=Path, required=True)
    verify.add_argument("--support", type=Path, required=True)
    verify.add_argument("--confirm-rotation-plan-sha256", required=True)
    return parser.parse_args(list(arguments))


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parse(list(sys.argv[1:] if arguments is None else arguments))
        if options.mode == "generate":
            digest = generate_support(
                options.projection,
                options.execution_evidence,
                options.support_output,
                assessor_reference=options.assessor_reference,
                confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
            )
        else:
            digest = verify_support(
                options.projection,
                options.execution_evidence,
                options.support,
                confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
            )
    except (KeyboardInterrupt, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("tls-rotation-support-failed", file=sys.stderr)
        return 1
    print(
        "tls-rotation-support-ok production_acceptance=false "
        f"schema_version={SCHEMA_VERSION} support_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
