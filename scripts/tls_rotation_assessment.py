"""Independently review a TLS runtime support artifact and actual profile."""

from __future__ import annotations

import argparse
from datetime import timedelta
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
from scripts.tls_rotation_evidence import load_projection, rotation_plan_digest, utc_now, verify_evidence
from scripts.tls_rotation_profile import verify_profile
from scripts.tls_rotation_support import (
    MAX_JSON_BYTES,
    SUPPORT_REASON_CODES,
    load_support,
    parse_utc,
)


SCHEMA_VERSION = 2
ASSESSMENT_KIND = "tls_leaf_rotation_independent_assessment"
MAX_REVIEW_DELAY = timedelta(minutes=15)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PAYLOAD_FIELDS = {
    "schema_version", "evidence_kind", "production_acceptance",
    "rotation_plan_sha256", "runtime_profile_sha256",
    "supporting_evidence_sha256", "execution_evidence_sha256",
    "runtime_state", "reason_code", "observation_finished_at",
    "assessed_at", "assessor_reference", "reviewer_reference",
}


class TlsRotationAssessmentError(ValueError):
    """A TLS runtime assessment could not be reviewed safely."""


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationAssessmentError("TLS rotation assessment path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationAssessmentError("TLS rotation assessment path is invalid")


def _canonical_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _confirm(projection: Mapping[str, object], confirmation: str) -> None:
    digest = rotation_plan_digest(projection)
    if _SHA256.fullmatch(confirmation or "") is None or not hmac.compare_digest(
        confirmation, digest
    ):
        raise TlsRotationAssessmentError("TLS rotation plan confirmation failed")


def _seal(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != _PAYLOAD_FIELDS:
        raise TlsRotationAssessmentError("TLS rotation assessment is invalid")
    state = payload["runtime_state"]
    reason = payload["reason_code"]
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != ASSESSMENT_KIND
        or payload["production_acceptance"] is not False
        or any(
            not isinstance(payload[field], str)
            or _SHA256.fullmatch(payload[field]) is None
            for field in (
                "rotation_plan_sha256", "runtime_profile_sha256",
                "supporting_evidence_sha256", "execution_evidence_sha256",
            )
        )
        or state not in {"verified_old", "verified_new", "unknown"}
        or (state == "unknown" and reason not in SUPPORT_REASON_CODES)
        or (state != "unknown" and reason is not None)
        or not isinstance(payload["assessor_reference"], str)
        or _REFERENCE.fullmatch(payload["assessor_reference"]) is None
        or not isinstance(payload["reviewer_reference"], str)
        or _REFERENCE.fullmatch(payload["reviewer_reference"]) is None
        or hmac.compare_digest(
            str(payload["assessor_reference"]), str(payload["reviewer_reference"])
        )
    ):
        raise TlsRotationAssessmentError("TLS rotation assessment is invalid")
    observed = parse_utc(payload["observation_finished_at"])
    assessed = parse_utc(payload["assessed_at"])
    if assessed < observed or assessed - observed > MAX_REVIEW_DELAY:
        raise TlsRotationAssessmentError("TLS rotation assessment is stale")
    sealed = dict(payload)
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def validate_assessment(
    value: object,
    projection: Mapping[str, object],
    support: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {*_PAYLOAD_FIELDS, "integrity"}:
        raise TlsRotationAssessmentError("TLS rotation assessment is invalid")
    integrity = value["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        raise TlsRotationAssessmentError("TLS rotation assessment is invalid")
    payload = {key: item for key, item in value.items() if key != "integrity"}
    expected = _seal(payload)
    actual = integrity.get("payload_sha256")
    if (
        not isinstance(actual, str)
        or _SHA256.fullmatch(actual) is None
        or not hmac.compare_digest(actual, expected["integrity"]["payload_sha256"])
        or payload["rotation_plan_sha256"] != rotation_plan_digest(projection)
        or payload["runtime_profile_sha256"] != projection["runtime_profile_sha256"]
        or payload["supporting_evidence_sha256"] != support["integrity"]["payload_sha256"]
        or payload["execution_evidence_sha256"] != support["execution_evidence_sha256"]
        or payload["runtime_state"] != support["derived_runtime_state"]
        or payload["reason_code"] != support["reason_code"]
        or payload["observation_finished_at"] != support["observation_finished_at"]
        or payload["assessor_reference"] != support["assessor_reference"]
    ):
        raise TlsRotationAssessmentError("TLS rotation assessment derivation is invalid")
    return dict(value)


def load_assessment(
    path: Path, projection: Mapping[str, object], support: Mapping[str, object]
) -> dict[str, object]:
    raw = read_stable_bytes(_external_path(path), max_bytes=MAX_JSON_BYTES)
    return validate_assessment(parse_unique_json_bytes(raw), projection, support)


def _load_bound_inputs(
    projection_path: Path,
    runtime_profile_path: Path,
    execution_evidence_path: Path,
    support_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    projection = load_projection(_external_path(projection_path))
    _, profile_digest = verify_profile(
        str(projection["runtime_kind"]), _external_path(runtime_profile_path)
    )
    if not hmac.compare_digest(profile_digest, str(projection["runtime_profile_sha256"])):
        raise TlsRotationAssessmentError("TLS rotation runtime profile is invalid")
    evidence = verify_evidence(_external_path(execution_evidence_path))
    support = load_support(_external_path(support_path), projection, evidence)
    return projection, support


def generate_assessment(
    projection_path: Path,
    runtime_profile_path: Path,
    execution_evidence_path: Path,
    support_path: Path,
    assessment_output: Path,
    *,
    reviewer_reference: str,
    confirm_rotation_plan_sha256: str,
    clock=utc_now,
) -> str:
    output = prepare_write_once_file(_external_path(assessment_output))
    inputs = [
        _external_path(projection_path), _external_path(runtime_profile_path),
        _external_path(execution_evidence_path), _external_path(support_path), output,
    ]
    if len({str(path.resolve(strict=False)).casefold() for path in inputs}) != len(inputs):
        raise TlsRotationAssessmentError("TLS rotation assessment paths are invalid")
    with release_control_lock():
        projection, support = _load_bound_inputs(*inputs[:4])
        _confirm(projection, confirm_rotation_plan_sha256)
        sealed = _seal({
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": ASSESSMENT_KIND,
            "production_acceptance": False,
            "rotation_plan_sha256": rotation_plan_digest(projection),
            "runtime_profile_sha256": projection["runtime_profile_sha256"],
            "supporting_evidence_sha256": support["integrity"]["payload_sha256"],
            "execution_evidence_sha256": support["execution_evidence_sha256"],
            "runtime_state": support["derived_runtime_state"],
            "reason_code": support["reason_code"],
            "observation_finished_at": support["observation_finished_at"],
            "assessed_at": clock(),
            "assessor_reference": support["assessor_reference"],
            "reviewer_reference": reviewer_reference,
        })
        raw = (json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = write_fsynced_temporary_bytes(output, raw)
        try:
            publish_write_once_file(temporary, output)
        finally:
            discard_claimed_temporary_file(temporary)
        verified = load_assessment(output, projection, support)
        if verified != sealed:
            raise TlsRotationAssessmentError("TLS rotation assessment publication failed")
    return str(sealed["integrity"]["payload_sha256"])


def verify_assessment(
    projection_path: Path,
    runtime_profile_path: Path,
    execution_evidence_path: Path,
    support_path: Path,
    assessment_path: Path,
    *,
    confirm_rotation_plan_sha256: str,
) -> str:
    projection, support = _load_bound_inputs(
        projection_path, runtime_profile_path, execution_evidence_path, support_path
    )
    _confirm(projection, confirm_rotation_plan_sha256)
    assessment = load_assessment(_external_path(assessment_path), projection, support)
    return str(assessment["integrity"]["payload_sha256"])


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationAssessmentError("TLS rotation assessment CLI input is invalid") from None


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    generate = sub.add_parser("generate", allow_abbrev=False)
    generate.add_argument("--projection", type=Path, required=True)
    generate.add_argument("--runtime-profile", type=Path, required=True)
    generate.add_argument("--execution-evidence", type=Path, required=True)
    generate.add_argument("--supporting-evidence", type=Path, required=True)
    generate.add_argument("--assessment-output", type=Path, required=True)
    generate.add_argument("--reviewer-reference", required=True)
    generate.add_argument("--confirm-rotation-plan-sha256", required=True)
    verify = sub.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--projection", type=Path, required=True)
    verify.add_argument("--runtime-profile", type=Path, required=True)
    verify.add_argument("--execution-evidence", type=Path, required=True)
    verify.add_argument("--supporting-evidence", type=Path, required=True)
    verify.add_argument("--assessment", type=Path, required=True)
    verify.add_argument("--confirm-rotation-plan-sha256", required=True)
    return parser.parse_args(list(arguments))


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parse(list(sys.argv[1:] if arguments is None else arguments))
        common = (
            options.projection, options.runtime_profile,
            options.execution_evidence, options.supporting_evidence,
        )
        if options.mode == "generate":
            digest = generate_assessment(
                *common, options.assessment_output,
                reviewer_reference=options.reviewer_reference,
                confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
            )
        else:
            digest = verify_assessment(
                *common, options.assessment,
                confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
            )
    except (KeyboardInterrupt, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("tls-rotation-assessment-failed", file=sys.stderr)
        return 1
    print(
        "tls-rotation-assessment-ok production_acceptance=false "
        f"schema_version={SCHEMA_VERSION} assessment_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
