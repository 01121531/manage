"""Seal and verify closed-schema Phase 6 role-training evidence.

This evidence proves only that the required training/tabletop records were
reviewed. It never represents production acceptance or a live-system test.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
EVIDENCE_KIND = "phase6_role_training"
REQUIRED_ROLES = (
    "operator",
    "ops_admin",
    "security_auditor",
    "platform_admin",
)
REQUIRED_SCENARIOS = {
    "operator_session_token_loss": "operator",
    "unknown_upload_no_blind_retry": "ops_admin",
    "alert_triage_and_audit_replay": "security_auditor",
    "device_revocation": "platform_admin",
    "backup_rollback_go_no_go": "platform_admin",
}
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "session_id",
    "environment_id",
    "release_tag",
    "release_commit",
    "window",
    "roles",
    "scenarios",
}
_SEALED_FIELDS = _TOP_LEVEL_FIELDS | {"integrity"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_FORBIDDEN_VALUE_FRAGMENT = re.compile(
    r"password|passwd|bearer|authorization|api[_-]?key|secret|credential|cvv|pan|token",
    re.IGNORECASE,
)
_MAX_EVIDENCE_BYTES = 64 * 1024


class TrainingEvidenceError(ValueError):
    """The training record cannot be accepted as evidence."""


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise TrainingEvidenceError("training timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TrainingEvidenceError("training timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise TrainingEvidenceError("training timestamp must be UTC")
    return parsed


def _require_identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise TrainingEvidenceError(f"invalid {context}")
    if _FORBIDDEN_VALUE_FRAGMENT.search(value):
        raise TrainingEvidenceError(f"unsafe {context}")
    return value


def _require_exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TrainingEvidenceError(f"invalid {context} schema")
    return value


def _canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _require_exact_mapping(value, _TOP_LEVEL_FIELDS, "training evidence")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
    ):
        raise TrainingEvidenceError("training evidence identity is invalid")
    _require_identifier(payload["session_id"], "session id")
    _require_identifier(payload["environment_id"], "environment id")
    if not isinstance(payload["release_tag"], str) or _TAG.fullmatch(payload["release_tag"]) is None:
        raise TrainingEvidenceError("invalid release tag")
    if (
        not isinstance(payload["release_commit"], str)
        or _COMMIT.fullmatch(payload["release_commit"]) is None
    ):
        raise TrainingEvidenceError("invalid release commit")

    window = _require_exact_mapping(
        payload["window"], {"started_at", "finished_at"}, "training window"
    )
    started_at = _parse_utc(window["started_at"])
    finished_at = _parse_utc(window["finished_at"])
    if finished_at <= started_at:
        raise TrainingEvidenceError("training window is invalid")

    roles = payload["roles"]
    if not isinstance(roles, dict) or set(roles) != set(REQUIRED_ROLES):
        raise TrainingEvidenceError("required training roles are incomplete")
    trainees: set[str] = set()
    reviewers: set[str] = set()
    for role in REQUIRED_ROLES:
        result = _require_exact_mapping(
            roles[role],
            {"trainee_id", "reviewer_id", "status", "completed_at"},
            f"role result: {role}",
        )
        trainee_id = _require_identifier(result["trainee_id"], "trainee id")
        reviewer_id = _require_identifier(result["reviewer_id"], "reviewer id")
        if result["status"] != "passed":
            raise TrainingEvidenceError("all role training must pass")
        completed_at = _parse_utc(result["completed_at"])
        if not started_at <= completed_at <= finished_at:
            raise TrainingEvidenceError("role completion is outside the training window")
        trainees.add(trainee_id)
        reviewers.add(reviewer_id)
    if len(trainees) != len(REQUIRED_ROLES):
        raise TrainingEvidenceError("each role requires a distinct trainee")
    if trainees & reviewers:
        raise TrainingEvidenceError("training reviewers must be independent")

    scenarios = payload["scenarios"]
    if not isinstance(scenarios, dict) or set(scenarios) != set(REQUIRED_SCENARIOS):
        raise TrainingEvidenceError("required tabletop scenarios are incomplete")
    for scenario, expected_role in REQUIRED_SCENARIOS.items():
        result = _require_exact_mapping(
            scenarios[scenario],
            {"actor_role", "reviewer_id", "result", "trace_id", "completed_at"},
            f"scenario result: {scenario}",
        )
        if result["actor_role"] != expected_role or result["result"] != "passed":
            raise TrainingEvidenceError("tabletop scenario result is invalid")
        reviewer_id = _require_identifier(result["reviewer_id"], "scenario reviewer id")
        if reviewer_id not in reviewers:
            raise TrainingEvidenceError("scenario reviewer is not an approved reviewer")
        trace_id = result["trace_id"]
        if (
            not isinstance(trace_id, str)
            or _TRACE_ID.fullmatch(trace_id) is None
            or _FORBIDDEN_VALUE_FRAGMENT.search(trace_id)
        ):
            raise TrainingEvidenceError("scenario trace id is invalid")
        completed_at = _parse_utc(result["completed_at"])
        if not started_at <= completed_at <= finished_at:
            raise TrainingEvidenceError("scenario completion is outside the training window")
    return payload


def seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_payload(payload)
    sealed = json.loads(json.dumps(validated))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(validated)}
    return sealed


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _require_exact_mapping(value, _SEALED_FIELDS, "sealed training evidence")
    integrity = _require_exact_mapping(
        evidence["integrity"], {"payload_sha256"}, "training evidence integrity"
    )
    digest = integrity["payload_sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise TrainingEvidenceError("training evidence digest is invalid")
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    _validate_payload(payload)
    if digest != _canonical_digest(payload):
        raise TrainingEvidenceError("training evidence integrity check failed")
    return evidence


def _read_json(path: Path, *, max_bytes: int = _MAX_EVIDENCE_BYTES) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise TrainingEvidenceError("training evidence file cannot be read") from error
    if not raw or len(raw) > max_bytes:
        raise TrainingEvidenceError("training evidence file size is invalid")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrainingEvidenceError("training evidence JSON is invalid") from error


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.unlink(missing_ok=True)
    validate_evidence(evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(evidence, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        verify_evidence(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def create_evidence(input_path: Path, output_path: Path) -> dict[str, Any]:
    if input_path.resolve() == output_path.resolve():
        raise TrainingEvidenceError("training input and output must be different files")
    output_path.unlink(missing_ok=True)
    evidence = seal_evidence(_read_json(input_path))
    write_evidence(output_path, evidence)
    return evidence


def verify_evidence(
    path: Path,
    *,
    expected_release_tag: str | None = None,
    expected_release_commit: str | None = None,
) -> dict[str, Any]:
    evidence = validate_evidence(_read_json(path))
    if expected_release_tag is not None and evidence["release_tag"] != expected_release_tag:
        raise TrainingEvidenceError("training evidence release tag mismatch")
    if (
        expected_release_commit is not None
        and evidence["release_commit"] != expected_release_commit
    ):
        raise TrainingEvidenceError("training evidence release commit mismatch")
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--input", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--expected-release-tag")
    verify.add_argument("--expected-release-commit")
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    output = options.output if options.command == "create" else None
    if (
        options.command == "create"
        and options.input.resolve() == options.output.resolve()
    ):
        print("phase6-role-training-evidence-failed", file=sys.stderr)
        return 1
    try:
        if options.command == "create":
            evidence = create_evidence(options.input, options.output)
        else:
            evidence = verify_evidence(
                options.input,
                expected_release_tag=options.expected_release_tag,
                expected_release_commit=options.expected_release_commit,
            )
    except (TrainingEvidenceError, OSError):
        if output is not None:
            output.unlink(missing_ok=True)
        print("phase6-role-training-evidence-failed", file=sys.stderr)
        return 1
    print(
        "phase6-role-training-evidence-ok "
        "production_acceptance=false "
        f"payload_sha256={evidence['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
