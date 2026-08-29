"""Offline verification for reviewed private-secret crash-drill assertions.

This module never collects runtime state and never authenticates artifact origin.
Its successful result means only that repository-external, independently reviewed
metadata is closed, internally consistent, and bound to the supplied artifacts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    StableFileError,
    parse_unique_json_bytes,
    read_stable_bytes,
    read_stable_bytes_with_metadata,
)
from scripts.target_platform_inventory import inventory_errors


POLICY = ROOT / "deploy" / "private-secret-runtime-policy.json"
SYNTHETIC = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-crash.synthetic.json"
)
SCHEMA_VERSION = 1
EVIDENCE_KIND = "private_secret_materialization_crash_drill_intake"
POLICY_KIND = "private_secret_runtime_root_policy"
RESIDUE_KIND = "email-platform-private-secret-residue-inventory"
MAX_JSON_BYTES = MAX_INTAKE_JSON_BYTES

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CLAIM_ID = re.compile(r"^[0-9a-f]{32}$")
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

_PAYLOAD_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "production_acceptance",
    "attempt_id",
    "scope",
    "runtime_root_policy_sha256",
    "claim_id",
    "before_inventory",
    "cleanup",
    "after_inventory",
    "alert",
    "review",
    "prohibited_content",
}
_INVENTORY_BINDING_FIELDS = {"artifact_sha256", "payload_sha256", "captured_at"}
_CLEANUP_FIELDS = {"result", "exit_code", "finished_at", "execution_reference"}
_ALERT_FIELDS = {
    "result",
    "observed_at",
    "delivery_reference",
    "artifact_sha256",
}
_REVIEW_FIELDS = {
    "operator_reference",
    "cleanup_approver_reference",
    "reviewer_reference",
    "reviewed_at",
    "decision",
}
_LINUX_SCOPE_FIELDS = {
    "kind",
    "repository_reference",
    "workflow_path",
    "workflow_sha256",
    "commit_sha",
    "run_id",
    "run_attempt",
    "job_name",
    "runner_os",
}
_TARGET_SCOPE_FIELDS = {
    "kind",
    "environment",
    "target_inventory_artifact_sha256",
    "target_inventory_reference",
    "execution_host_reference",
    "kubernetes_context_reference",
}
_PROHIBITED_FIELDS = {
    "contains_secret_values",
    "contains_source_sha256",
    "contains_runtime_paths",
    "contains_kubeconfig",
    "contains_pem_values",
    "contains_token_values",
    "contains_raw_logs",
    "contains_pid_or_age_heuristics",
    "contains_personal_data",
}
_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "policy_effect",
    "production_acceptance",
    "platform",
    "runtime_root",
    "claim",
    "cleanup",
}
_POLICY_ROOT_FIELDS = {
    "environment_variable",
    "path_policy",
    "owner",
    "mode",
    "link_policy",
}
_POLICY_CLAIM_FIELDS = {
    "id_policy",
    "directory_mode",
    "exact_entries",
    "claim_mode",
    "lease_mode",
    "secret_mode",
    "lease_mechanism",
}
_POLICY_CLEANUP_FIELDS = {
    "scope",
    "bulk_cleanup",
    "age_or_pid_heuristics",
    "secure_erasure_claimed",
}
_RESIDUE_FIELDS = {"kind", "payload_sha256", "records", "schema_version"}
_WORKFLOWS = frozenset({".github/workflows/ci.yml", ".github/workflows/release.yml"})
_JOBS = frozenset({"postgres-migration-gate", "release-postgres-migration-gate"})


class PrivateSecretCrashEvidenceError(ValueError):
    """One assertion or bound artifact is not safely reviewable."""


@dataclass(frozen=True)
class VerifiedEvidenceSnapshot:
    """Validated target inputs and whole-file digests from one stable read each."""

    envelope: dict[str, Any]
    evidence_artifact_sha256: str
    before_inventory_artifact_sha256: str
    after_inventory_artifact_sha256: str
    target_inventory_artifact_sha256: str | None


def _invalid() -> PrivateSecretCrashEvidenceError:
    return PrivateSecretCrashEvidenceError("private secret crash evidence is invalid")


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
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


def _external_path(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise _invalid()


def _read_external(path: Path | str) -> tuple[object, bytes]:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            _external_path(path), max_bytes=MAX_JSON_BYTES
        )
        if metadata.st_nlink != 1:
            raise _invalid()
        return parse_unique_json_bytes(raw), raw
    except (
        OSError,
        StableFileError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error


def validate_runtime_policy(value: object) -> dict[str, Any]:
    policy = _closed(value, _POLICY_FIELDS)
    runtime_root = _closed(policy["runtime_root"], _POLICY_ROOT_FIELDS)
    claim = _closed(policy["claim"], _POLICY_CLAIM_FIELDS)
    cleanup = _closed(policy["cleanup"], _POLICY_CLEANUP_FIELDS)
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != SCHEMA_VERSION
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "repository_contract_only"
        or policy["production_acceptance"] is not False
        or policy["platform"] != "posix"
        or runtime_root
        != {
            "environment_variable": "EMAIL_PLATFORM_PRIVATE_SECRET_RUNTIME_ROOT",
            "path_policy": "absolute_repository_external",
            "owner": "effective_uid",
            "mode": "0700",
            "link_policy": "no_follow",
        }
        or claim
        != {
            "id_policy": "32_lowercase_hex",
            "directory_mode": "0700",
            "exact_entries": ["claim.json", "lease", "secret"],
            "claim_mode": "0400",
            "lease_mode": "0600",
            "secret_mode": "0400",
            "lease_mechanism": "posix_flock_exclusive_nonblocking",
        }
        or cleanup
        != {
            "scope": "one_authenticated_claim",
            "bulk_cleanup": False,
            "age_or_pid_heuristics": False,
            "secure_erasure_claimed": False,
        }
    ):
        raise _invalid()
    return dict(policy)


def load_runtime_policy() -> tuple[dict[str, Any], str]:
    try:
        raw = read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES)
        policy = validate_runtime_policy(parse_unique_json_bytes(raw))
    except (
        OSError,
        StableFileError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error
    return policy, _canonical_digest(policy)


def _validate_inventory_binding(value: object) -> dict[str, Any]:
    binding = _closed(value, _INVENTORY_BINDING_FIELDS)
    _digest(binding["artifact_sha256"])
    _digest(binding["payload_sha256"])
    _timestamp(binding["captured_at"])
    return binding


def _validate_linux_scope(value: object) -> dict[str, Any]:
    scope = _closed(value, _LINUX_SCOPE_FIELDS)
    if (
        scope["kind"] != "github_actions_linux_ci"
        or scope["workflow_path"] not in _WORKFLOWS
        or scope["job_name"] not in _JOBS
        or scope["runner_os"] != "Linux"
        or not isinstance(scope["commit_sha"], str)
        or _COMMIT.fullmatch(scope["commit_sha"]) is None
        or type(scope["run_id"]) is not int
        or scope["run_id"] < 1
        or type(scope["run_attempt"]) is not int
        or scope["run_attempt"] < 1
    ):
        raise _invalid()
    _reference(scope["repository_reference"])
    _digest(scope["workflow_sha256"])
    return scope


def _validate_target_scope(value: object) -> dict[str, Any]:
    scope = _closed(value, _TARGET_SCOPE_FIELDS)
    environment = scope["environment"]
    if (
        scope["kind"] != "kubernetes_target_host"
        or not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        raise _invalid()
    _digest(scope["target_inventory_artifact_sha256"])
    for field in (
        "target_inventory_reference",
        "execution_host_reference",
        "kubernetes_context_reference",
    ):
        _reference(scope[field])
    return scope


def validate_envelope(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    envelope = _closed(value, {*_PAYLOAD_FIELDS, "integrity"})
    integrity = _closed(envelope["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in envelope.items() if key != "integrity"}
    expected = _canonical_digest(payload)
    actual = _digest(integrity["payload_sha256"])
    if not hmac.compare_digest(actual, expected):
        raise _invalid()
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["origin_authentication"] != "unverified"
        or payload["production_acceptance"] is not False
    ):
        raise _invalid()
    prohibited = _closed(payload["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item is not False for item in prohibited.values()):
        raise _invalid()

    if payload["synthetic"] is True:
        if not allow_synthetic or (
            payload["evidence_status"] != "pending"
            or payload["attempt_id"] is not None
            or payload["scope"] != {"kind": "pending"}
            or any(
                payload[field] is not None
                for field in (
                    "runtime_root_policy_sha256",
                    "claim_id",
                    "before_inventory",
                    "cleanup",
                    "after_inventory",
                    "alert",
                    "review",
                )
            )
        ):
            raise _invalid()
        return dict(envelope)

    if payload["synthetic"] is not False or payload["evidence_status"] != "reviewed":
        raise _invalid()
    attempt_id = payload["attempt_id"]
    try:
        import uuid

        parsed_attempt = uuid.UUID(attempt_id, version=4)
    except (AttributeError, TypeError, ValueError):
        raise _invalid() from None
    if str(parsed_attempt) != attempt_id:
        raise _invalid()
    _digest(payload["runtime_root_policy_sha256"])
    if not isinstance(payload["claim_id"], str) or _CLAIM_ID.fullmatch(payload["claim_id"]) is None:
        raise _invalid()

    scope = payload["scope"]
    if not isinstance(scope, dict):
        raise _invalid()
    if scope.get("kind") == "github_actions_linux_ci":
        _validate_linux_scope(scope)
        scope_kind = "linux"
    elif scope.get("kind") == "kubernetes_target_host":
        _validate_target_scope(scope)
        scope_kind = "target"
    else:
        raise _invalid()

    before = _validate_inventory_binding(payload["before_inventory"])
    after = _validate_inventory_binding(payload["after_inventory"])
    if hmac.compare_digest(before["payload_sha256"], after["payload_sha256"]):
        raise _invalid()
    cleanup = _closed(payload["cleanup"], _CLEANUP_FIELDS)
    if (
        cleanup["result"] != "succeeded"
        or type(cleanup["exit_code"]) is not int
        or cleanup["exit_code"] != 0
    ):
        raise _invalid()
    _reference(cleanup["execution_reference"])
    cleanup_at = _timestamp(cleanup["finished_at"])

    alert = _closed(payload["alert"], _ALERT_FIELDS)
    if scope_kind == "linux":
        if alert != {
            "result": "not_applicable",
            "observed_at": None,
            "delivery_reference": None,
            "artifact_sha256": None,
        }:
            raise _invalid()
        alert_at = None
    else:
        if alert["result"] != "delivered":
            raise _invalid()
        alert_at = _timestamp(alert["observed_at"])
        _reference(alert["delivery_reference"])
        _digest(alert["artifact_sha256"])

    review = _closed(payload["review"], _REVIEW_FIELDS)
    references = [
        _reference(review[field])
        for field in (
            "operator_reference",
            "cleanup_approver_reference",
            "reviewer_reference",
        )
    ]
    if len(set(references)) != 3 or review["decision"] != "accepted_for_manual_review":
        raise _invalid()
    reviewed_at = _timestamp(review["reviewed_at"])
    before_at = _timestamp(before["captured_at"])
    after_at = _timestamp(after["captured_at"])
    if scope_kind == "linux":
        ordered = before_at <= cleanup_at <= after_at <= reviewed_at
    else:
        ordered = before_at <= alert_at <= cleanup_at <= after_at <= reviewed_at
    if not ordered:
        raise _invalid()
    return dict(envelope)


def _load_residue_inventory(
    path: Path | str,
    binding: Mapping[str, object],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value, raw = _read_external(path)
    return _validate_residue_inventory(value, raw, binding)


def _validate_residue_inventory(
    value: object,
    raw: bytes,
    binding: Mapping[str, object],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = _closed(value, _RESIDUE_FIELDS)
    payload = {key: item for key, item in document.items() if key != "payload_sha256"}
    payload_digest = _canonical_digest(payload)
    if (
        document["schema_version"] != 1
        or document["kind"] != RESIDUE_KIND
        or not hmac.compare_digest(_digest(document["payload_sha256"]), payload_digest)
        or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), str(binding["artifact_sha256"])
        )
        or not hmac.compare_digest(
            str(document["payload_sha256"]), str(binding["payload_sha256"])
        )
        or not isinstance(document["records"], list)
        or not hmac.compare_digest(raw, _canonical_bytes(document))
    ):
        raise _invalid()
    records: list[dict[str, Any]] = []
    claim_ids: list[str] = []
    record_bytes: list[bytes] = []
    for item in document["records"]:
        if not isinstance(item, dict):
            raise _invalid()
        state = item.get("state")
        fields = {"claim_id", "state"}
        if state == "cleanup_candidate":
            fields.add("approval_sha256")
        elif state == "unknown":
            fields.add("reason")
        elif state != "active":
            raise _invalid()
        if set(item) != fields:
            raise _invalid()
        claim_id = item.get("claim_id")
        if state == "unknown":
            if claim_id is not None or item.get("reason") not in {
                "unexpected_entry",
                "verification_failed",
            }:
                raise _invalid()
        else:
            if not isinstance(claim_id, str) or _CLAIM_ID.fullmatch(claim_id) is None:
                raise _invalid()
            claim_ids.append(claim_id)
            if state == "cleanup_candidate":
                _digest(item.get("approval_sha256"))
        normalized = dict(item)
        records.append(normalized)
        record_bytes.append(_canonical_bytes(normalized))
    if (
        len(claim_ids) != len(set(claim_ids))
        or len(record_bytes) != len(set(record_bytes))
        or record_bytes != sorted(record_bytes)
    ):
        raise _invalid()
    return dict(document), records


def _verify_transition(
    claim_id: str,
    before_records: list[dict[str, Any]],
    after_records: list[dict[str, Any]],
) -> None:
    if any(item.get("state") == "unknown" for item in [*before_records, *after_records]):
        raise _invalid()
    before_matches = [item for item in before_records if item.get("claim_id") == claim_id]
    after_matches = [item for item in after_records if item.get("claim_id") == claim_id]
    if len(before_matches) != 1 or before_matches[0].get("state") != "cleanup_candidate" or after_matches:
        raise _invalid()
    before_siblings = [item for item in before_records if item.get("claim_id") != claim_id]
    if before_siblings != after_records:
        raise _invalid()


def verify_evidence(
    input_path: Path | str,
    before_inventory_path: Path | str,
    after_inventory_path: Path | str,
    *,
    expected_runtime_policy_sha256: str,
    expected_commit: str | None = None,
    expected_workflow_sha256: str | None = None,
    target_inventory_path: Path | str | None = None,
) -> dict[str, Any]:
    return verify_evidence_snapshot(
        input_path,
        before_inventory_path,
        after_inventory_path,
        expected_runtime_policy_sha256=expected_runtime_policy_sha256,
        expected_commit=expected_commit,
        expected_workflow_sha256=expected_workflow_sha256,
        target_inventory_path=target_inventory_path,
    ).envelope


def verify_evidence_snapshot(
    input_path: Path | str,
    before_inventory_path: Path | str,
    after_inventory_path: Path | str,
    *,
    expected_runtime_policy_sha256: str,
    expected_commit: str | None = None,
    expected_workflow_sha256: str | None = None,
    target_inventory_path: Path | str | None = None,
) -> VerifiedEvidenceSnapshot:
    """Validate one scope and retain digests from the exact checked snapshots."""

    paths = [input_path, before_inventory_path, after_inventory_path]
    if target_inventory_path is not None:
        paths.append(target_inventory_path)
    normalized = {str(_external_path(path).resolve(strict=False)).casefold() for path in paths}
    if len(normalized) != len(paths):
        raise _invalid()
    envelope_raw = _read_external(input_path)[1]
    before_raw = _read_external(before_inventory_path)[1]
    after_raw = _read_external(after_inventory_path)[1]
    target_inventory_raw = (
        _read_external(target_inventory_path)[1]
        if target_inventory_path is not None
        else None
    )
    try:
        runtime_policy_raw = read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    return verify_evidence_snapshot_bytes(
        input_raw=envelope_raw,
        before_inventory_raw=before_raw,
        after_inventory_raw=after_raw,
        runtime_policy_raw=runtime_policy_raw,
        expected_runtime_policy_sha256=expected_runtime_policy_sha256,
        expected_commit=expected_commit,
        expected_workflow_sha256=expected_workflow_sha256,
        target_inventory_raw=target_inventory_raw,
    )


def verify_evidence_snapshot_bytes(
    *,
    input_raw: bytes,
    before_inventory_raw: bytes,
    after_inventory_raw: bytes,
    runtime_policy_raw: bytes,
    expected_runtime_policy_sha256: str,
    expected_commit: str | None = None,
    expected_workflow_sha256: str | None = None,
    target_inventory_raw: bytes | None = None,
) -> VerifiedEvidenceSnapshot:
    """Validate caller-supplied bytes without reading filesystem state."""

    required = (input_raw, before_inventory_raw, after_inventory_raw, runtime_policy_raw)
    if any(type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES for raw in required):
        raise _invalid()
    if target_inventory_raw is not None and (
        type(target_inventory_raw) is not bytes
        or not target_inventory_raw
        or len(target_inventory_raw) > MAX_JSON_BYTES
    ):
        raise _invalid()
    try:
        envelope = validate_envelope(parse_unique_json_bytes(input_raw))
        policy = validate_runtime_policy(parse_unique_json_bytes(runtime_policy_raw))
        before_value = parse_unique_json_bytes(before_inventory_raw)
        after_value = parse_unique_json_bytes(after_inventory_raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error
    policy_digest = _canonical_digest(policy)
    if (
        _SHA256.fullmatch(expected_runtime_policy_sha256 or "") is None
        or not hmac.compare_digest(expected_runtime_policy_sha256, policy_digest)
        or not hmac.compare_digest(
            str(envelope["runtime_root_policy_sha256"]), policy_digest
        )
    ):
        raise _invalid()

    scope = envelope["scope"]
    linux = scope["kind"] == "github_actions_linux_ci"
    target_inventory_digest: str | None = None
    if linux:
        if (
            target_inventory_raw is not None
            or not isinstance(expected_commit, str)
            or _COMMIT.fullmatch(expected_commit) is None
            or _SHA256.fullmatch(expected_workflow_sha256 or "") is None
            or not hmac.compare_digest(scope["commit_sha"], expected_commit)
            or not hmac.compare_digest(scope["workflow_sha256"], expected_workflow_sha256)
        ):
            raise _invalid()
    else:
        if expected_commit is not None or expected_workflow_sha256 is not None or target_inventory_raw is None:
            raise _invalid()
        try:
            inventory_value = parse_unique_json_bytes(target_inventory_raw)
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise _invalid() from error
        target_inventory_digest = hashlib.sha256(target_inventory_raw).hexdigest()
        if (
            inventory_errors(inventory_value)
            or inventory_value.get("synthetic") is not False
            or inventory_value.get("inventory_status") != "reviewed"
            or inventory_value.get("environment") != scope["environment"]
            or inventory_value.get("inventory_reference")
            != scope["target_inventory_reference"]
            or not hmac.compare_digest(
                target_inventory_digest,
                scope["target_inventory_artifact_sha256"],
            )
        ):
            raise _invalid()

    _, before_records = _validate_residue_inventory(
        before_value, before_inventory_raw, envelope["before_inventory"]
    )
    _, after_records = _validate_residue_inventory(
        after_value, after_inventory_raw, envelope["after_inventory"]
    )
    _verify_transition(envelope["claim_id"], before_records, after_records)
    return VerifiedEvidenceSnapshot(
        envelope=envelope,
        evidence_artifact_sha256=hashlib.sha256(input_raw).hexdigest(),
        before_inventory_artifact_sha256=hashlib.sha256(before_inventory_raw).hexdigest(),
        after_inventory_artifact_sha256=hashlib.sha256(after_inventory_raw).hexdigest(),
        target_inventory_artifact_sha256=target_inventory_digest,
    )


def verify_repository_assets() -> tuple[dict[str, Any], str]:
    _, policy_digest = load_runtime_policy()
    try:
        raw = read_stable_bytes(SYNTHETIC, max_bytes=MAX_JSON_BYTES)
        envelope = validate_envelope(parse_unique_json_bytes(raw), allow_synthetic=True)
    except (
        OSError,
        StableFileError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _invalid() from error
    return envelope, policy_digest


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PrivateSecretCrashEvidenceError("private secret crash evidence arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--before-inventory", type=Path, required=True)
    verify.add_argument("--after-inventory", type=Path, required=True)
    verify.add_argument("--expected-runtime-policy-sha256", required=True)
    scope = verify.add_mutually_exclusive_group(required=True)
    scope.add_argument("--expected-commit")
    scope.add_argument("--target-inventory", type=Path)
    verify.add_argument("--expected-workflow-sha256")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            _, policy_digest = verify_repository_assets()
            print(
                "private-secret-crash-evidence-template-ok "
                "status=pending origin-authentication=unverified "
                "production_acceptance=false "
                f"policy_sha256={policy_digest}"
            )
            return 0
        evidence = verify_evidence(
            options.input,
            options.before_inventory,
            options.after_inventory,
            expected_runtime_policy_sha256=options.expected_runtime_policy_sha256,
            expected_commit=options.expected_commit,
            expected_workflow_sha256=options.expected_workflow_sha256,
            target_inventory_path=options.target_inventory,
        )
    except (PrivateSecretCrashEvidenceError, OSError, TypeError, ValueError):
        print("private-secret-crash-evidence-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-crash-evidence-ok "
        "status=reviewed-assertion origin-authentication=unverified "
        "production_acceptance=false "
        f"payload_sha256={evidence['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
