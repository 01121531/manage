"""Publish one independent manual handoff after TLS rotation uncertainty.

This tool has no runtime mutation authority.  It can prove that an existing,
matching execution artifact is committed; every absent, invalid, mismatched, or
unstable sink is reported as unknown rather than as not committed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
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
from scripts.external_json import (
    StableFileError,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)
from scripts.release_control_lock import release_control_lock
from scripts.tls_rotation_evidence import (
    assert_expected_rotation,
    load_projection,
    rotation_plan_digest,
    utc_now,
    validate_evidence,
)
from scripts.tls_rotation_assessment import load_assessment
from scripts.tls_rotation_profile import verify_profile
from scripts.tls_rotation_support import SUPPORT_REASON_CODES, load_support, parse_utc


SCHEMA_VERSION = 2
EVIDENCE_KIND = "tls_leaf_rotation_manual_handoff"
MAX_JSON_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_HANDOFF_DELAY = timedelta(minutes=15)
_PAYLOAD_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "rotation_plan_sha256",
    "runtime_profile_sha256",
    "execution_sink_observation",
    "manual_runtime_assessment",
    "manual_review_required",
    "started_at",
    "finished_at",
}
_SINK_FIELDS = {"state", "payload_sha256", "terminal_state"}
_RUNTIME_FIELDS = {
    "state",
    "reason_code",
    "assessed_at",
    "assessor_reference",
    "reviewer_reference",
    "supporting_evidence_sha256",
    "execution_evidence_sha256",
    "assessment_sha256",
}


class TlsRotationHandoffError(ValueError):
    """The independent handoff could not be created safely."""


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationHandoffError("TLS rotation handoff input is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationHandoffError("TLS rotation handoff input is invalid")


def _utc(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TlsRotationHandoffError("TLS rotation assessment is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TlsRotationHandoffError("TLS rotation assessment is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise TlsRotationHandoffError("TLS rotation assessment is invalid")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _canonical_digest(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _observe_execution_sink(
    path: Path, projection: Mapping[str, object]
) -> dict[str, object]:
    unknown = {"state": "unknown", "payload_sha256": None, "terminal_state": None}
    try:
        first_raw, first_metadata = read_stable_bytes_with_metadata(
            _external_path(path), max_bytes=MAX_JSON_BYTES
        )
        first = validate_evidence(parse_unique_json_bytes(first_raw))
        assert_expected_rotation(first, projection)
        second_raw, _ = read_stable_bytes_with_metadata(
            path,
            max_bytes=MAX_JSON_BYTES,
            expected_identity=stable_file_identity(first_metadata),
        )
        second = validate_evidence(parse_unique_json_bytes(second_raw))
        assert_expected_rotation(second, projection)
        if first_raw != second_raw or first != second:
            return unknown
        return {
            "state": "committed",
            "payload_sha256": first["integrity"]["payload_sha256"],
            "terminal_state": first["terminal_state"],
        }
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        return unknown


def _seal(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != _PAYLOAD_FIELDS:
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    sink = payload["execution_sink_observation"]
    runtime = payload["manual_runtime_assessment"]
    if not isinstance(sink, dict) or set(sink) != _SINK_FIELDS:
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    if not isinstance(runtime, dict) or set(runtime) != _RUNTIME_FIELDS:
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    committed = sink["state"] == "committed"
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
        or payload["manual_review_required"] is not True
        or not isinstance(payload["rotation_plan_sha256"], str)
        or _SHA256.fullmatch(payload["rotation_plan_sha256"]) is None
        or not isinstance(payload["runtime_profile_sha256"], str)
        or _SHA256.fullmatch(payload["runtime_profile_sha256"]) is None
        or sink["state"] not in {"committed", "unknown"}
        or (committed and (
            not isinstance(sink["payload_sha256"], str)
            or _SHA256.fullmatch(sink["payload_sha256"]) is None
            or not isinstance(sink["terminal_state"], str)
        ))
        or (not committed and (
            sink["payload_sha256"] is not None or sink["terminal_state"] is not None
        ))
        or runtime["state"] not in {"verified_old", "verified_new", "unknown"}
        or (
            runtime["state"] == "unknown"
            and runtime["reason_code"] not in SUPPORT_REASON_CODES
        )
        or (runtime["state"] != "unknown" and runtime["reason_code"] is not None)
        or not isinstance(runtime["assessor_reference"], str)
        or _REFERENCE.fullmatch(runtime["assessor_reference"]) is None
        or not isinstance(runtime["reviewer_reference"], str)
        or _REFERENCE.fullmatch(runtime["reviewer_reference"]) is None
        or hmac.compare_digest(
            str(runtime["assessor_reference"]), str(runtime["reviewer_reference"])
        )
        or not isinstance(runtime["supporting_evidence_sha256"], str)
        or _SHA256.fullmatch(runtime["supporting_evidence_sha256"]) is None
        or not isinstance(runtime["execution_evidence_sha256"], str)
        or _SHA256.fullmatch(runtime["execution_evidence_sha256"]) is None
        or not isinstance(runtime["assessment_sha256"], str)
        or _SHA256.fullmatch(runtime["assessment_sha256"]) is None
    ):
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    started = _utc(payload["started_at"])
    finished = _utc(payload["finished_at"])
    assessed = _utc(runtime["assessed_at"])
    if finished < started or assessed > finished:
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def validate_handoff(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {*_PAYLOAD_FIELDS, "integrity"}:
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    integrity = value["integrity"]
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or not isinstance(integrity["payload_sha256"], str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
    ):
        raise TlsRotationHandoffError("TLS rotation handoff is invalid")
    payload = {key: item for key, item in value.items() if key != "integrity"}
    expected = _seal(payload)
    if not hmac.compare_digest(
        integrity["payload_sha256"], expected["integrity"]["payload_sha256"]
    ):
        raise TlsRotationHandoffError("TLS rotation handoff integrity is invalid")
    return value


def create_tls_rotation_handoff(
    projection_path: Path,
    *,
    execution_evidence: Path,
    runtime_profile: Path,
    supporting_evidence: Path,
    assessment_input: Path,
    handoff_output: Path,
    confirm_rotation_plan_sha256: str,
    clock=utc_now,
) -> dict[str, object]:
    output = prepare_write_once_file(_external_path(handoff_output))
    projection = load_projection(_external_path(projection_path))
    plan_sha256 = rotation_plan_digest(projection)
    if (
        not isinstance(confirm_rotation_plan_sha256, str)
        or _SHA256.fullmatch(confirm_rotation_plan_sha256) is None
        or not hmac.compare_digest(confirm_rotation_plan_sha256, plan_sha256)
    ):
        raise TlsRotationHandoffError("TLS rotation plan confirmation failed")
    inputs = [
        _external_path(projection_path),
        _external_path(execution_evidence),
        _external_path(runtime_profile),
        _external_path(supporting_evidence),
        _external_path(assessment_input),
        output,
    ]
    if len({str(path.resolve(strict=False)).casefold() for path in inputs}) != len(inputs):
        raise TlsRotationHandoffError("TLS rotation handoff paths are invalid")
    with release_control_lock():
        started_at = clock()
        _, actual_profile_sha256 = verify_profile(
            str(projection["runtime_kind"]), _external_path(runtime_profile)
        )
        if not hmac.compare_digest(
            actual_profile_sha256, str(projection["runtime_profile_sha256"])
        ):
            raise TlsRotationHandoffError("TLS rotation runtime profile is invalid")
        try:
            execution = validate_evidence(
                parse_unique_json_bytes(
                    read_stable_bytes(
                        _external_path(execution_evidence), max_bytes=MAX_JSON_BYTES
                    )
                )
            )
            assert_expected_rotation(execution, projection)
            support = load_support(
                _external_path(supporting_evidence), projection, execution
            )
            assessment = load_assessment(
                _external_path(assessment_input), projection, support
            )
        except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
            raise TlsRotationHandoffError(
                "TLS rotation review artifacts are invalid"
            ) from None
        sink = _observe_execution_sink(execution_evidence, projection)
        started_time = parse_utc(started_at)
        assessed_time = parse_utc(assessment["assessed_at"])
        if started_time < assessed_time or started_time - assessed_time > MAX_HANDOFF_DELAY:
            raise TlsRotationHandoffError("TLS rotation handoff assessment is stale")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "production_acceptance": False,
            "rotation_plan_sha256": plan_sha256,
            "runtime_profile_sha256": projection["runtime_profile_sha256"],
            "execution_sink_observation": sink,
            "manual_runtime_assessment": {
                "state": assessment["runtime_state"],
                "reason_code": assessment["reason_code"],
                "assessed_at": assessment["assessed_at"],
                "assessor_reference": assessment["assessor_reference"],
                "reviewer_reference": assessment["reviewer_reference"],
                "supporting_evidence_sha256": assessment["supporting_evidence_sha256"],
                "execution_evidence_sha256": assessment["execution_evidence_sha256"],
                "assessment_sha256": assessment["integrity"]["payload_sha256"],
            },
            "manual_review_required": True,
            "started_at": started_at,
            "finished_at": clock(),
        }
        sealed = _seal(payload)
        raw = (
            json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(raw) > MAX_JSON_BYTES:
            raise TlsRotationHandoffError("TLS rotation handoff is invalid")
        temporary = write_fsynced_temporary_bytes(output, raw)
        try:
            publish_write_once_file(temporary, output)
        finally:
            discard_claimed_temporary_file(temporary)
        readback = read_stable_bytes(output, max_bytes=MAX_JSON_BYTES)
        if not hmac.compare_digest(readback, raw):
            raise TlsRotationHandoffError("TLS rotation handoff publication failed")
        return sealed


_FLAGS = (
    "--projection",
    "--execution-evidence",
    "--runtime-profile",
    "--supporting-evidence",
    "--assessment-input",
    "--handoff-output",
    "--confirm-rotation-plan-sha256",
)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationHandoffError("TLS rotation handoff CLI input is invalid") from None


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    if "--help" not in arguments and (
        len(arguments) != len(_FLAGS) * 2
        or any(arguments.count(flag) != 1 for flag in _FLAGS)
    ):
        raise TlsRotationHandoffError("TLS rotation handoff CLI input is invalid")
    parser = _SafeParser(description=__doc__)
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--execution-evidence", type=Path, required=True)
    parser.add_argument("--runtime-profile", type=Path, required=True)
    parser.add_argument("--supporting-evidence", type=Path, required=True)
    parser.add_argument("--assessment-input", type=Path, required=True)
    parser.add_argument("--handoff-output", type=Path, required=True)
    parser.add_argument("--confirm-rotation-plan-sha256", required=True)
    return parser.parse_args(list(arguments))


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parse(list(sys.argv[1:] if arguments is None else arguments))
        create_tls_rotation_handoff(
            options.projection,
            execution_evidence=options.execution_evidence,
            runtime_profile=options.runtime_profile,
            supporting_evidence=options.supporting_evidence,
            assessment_input=options.assessment_input,
            handoff_output=options.handoff_output,
            confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
        )
    except KeyboardInterrupt:
        print("tls-rotation-handoff-failed", file=sys.stderr)
        return 130
    except (OSError, TypeError, ValueError):
        print("tls-rotation-handoff-failed", file=sys.stderr)
        return 1
    print("tls-rotation-handoff-ok production_acceptance=false manual_review_required=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
