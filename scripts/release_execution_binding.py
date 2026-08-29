"""Bind one successful v3 forward or rolling release ledger to target evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import stat
from typing import Any

from scripts.deploy_release_evidence import (
    DeploymentReleaseEvidenceError,
    TERMINAL_SUCCEEDED,
    validate_evidence as validate_forward_evidence,
)
from scripts.external_json import (
    StableFileError,
    parse_unique_json_bytes,
    read_stable_bytes,
)
from scripts.rolling_release_evidence import (
    RollingReleaseEvidenceError,
    TERMINAL_COMPLETE,
    validate_evidence as validate_rolling_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
LEDGER_TYPES = frozenset({"forward", "rolling"})
SELECTOR_KEYS = {
    "ledger_type",
    "evidence_object_reference",
    "evidence_sha256",
    "target_intake",
}
TARGET_INTAKE_KEYS = {
    "environment",
    "manifest_payload_sha256",
    "requirements_sha256",
    "checkpoint_phase",
}
IDENTITY_KEYS = {
    "ledger_type",
    "evidence_sha256",
    "terminal_state",
    "successful",
    "target_release",
    "target_intake",
    "started_at",
    "finished_at",
}
TARGET_RELEASE_KEYS = {"tag", "commit", "container_manifest_sha256"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
_MAX_EVIDENCE_BYTES = 64 * 1024


class ReleaseExecutionBindingError(ValueError):
    """A release execution ledger cannot satisfy a target evidence binding."""


def release_execution_identity(raw: bytes) -> dict[str, Any]:
    """Validate one v3 ledger and return its normalized non-secret identity."""

    if not raw or len(raw) > _MAX_EVIDENCE_BYTES:
        raise ReleaseExecutionBindingError("release execution evidence size is invalid")
    value = _parse_json(raw)
    if not isinstance(value, dict):
        raise ReleaseExecutionBindingError("release execution evidence is invalid")
    kind = value.get("evidence_kind")
    try:
        if kind == "release_bound_forward_deployment_execution":
            evidence = validate_forward_evidence(value)
            ledger_type = "forward"
            release = evidence["target_release"]
            successful = evidence["terminal_state"] == TERMINAL_SUCCEEDED
        elif kind == "web_api_rolling_execution":
            evidence = validate_rolling_evidence(value)
            ledger_type = "rolling"
            release = evidence["target"]
            successful = evidence["terminal_state"] == TERMINAL_COMPLETE
        else:
            raise ReleaseExecutionBindingError("release execution kind is invalid")
    except (DeploymentReleaseEvidenceError, RollingReleaseEvidenceError) as error:
        raise ReleaseExecutionBindingError("release execution evidence is invalid") from error
    return {
        "ledger_type": ledger_type,
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_state": evidence["terminal_state"],
        "successful": successful,
        "target_release": {
            "tag": release["tag"],
            "commit": release["commit"],
            "container_manifest_sha256": release["container_manifest_sha256"],
        },
        "target_intake": dict(evidence["target_intake"]),
        "started_at": evidence["started_at"],
        "finished_at": evidence["finished_at"],
    }


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _environment(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _ENVIRONMENT.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
    )


def _opaque_execution_reference(value: Any) -> bool:
    """Validate only the compatibility locator syntax, never WORM semantics."""

    prefix = "worm-release-execution:"
    if (
        not isinstance(value, str)
        or _REFERENCE.fullmatch(value) is None
        or not value.startswith(prefix)
    ):
        return False
    suffix = value.removeprefix(prefix)
    return any(character.isalpha() for character in suffix) and any(
        character.isdigit() for character in suffix
    )


def _reviewer_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 128
        and value.strip() == value
        and value.casefold() not in _PLACEHOLDERS
        and all(character.isprintable() for character in value)
    )


def release_execution_reviewed_at(manifest: Any, selector: Any) -> Any:
    """Return an opaque review claim's time for one exact selected ledger."""

    if (
        not isinstance(manifest, dict)
        or not isinstance(manifest.get("items"), list)
        or not isinstance(selector, dict)
        or not _digest(selector.get("evidence_sha256"))
    ):
        return None
    matches = [
        item
        for item in manifest["items"]
        if isinstance(item, dict)
        and item.get("id") == "release_execution_evidence"
        and item.get("status") == "provided"
        and item.get("sha256") == selector["evidence_sha256"]
        and _reviewer_reference(item.get("reviewed_by"))
    ]
    return matches[0].get("reviewed_at") if len(matches) == 1 else None


def selector_errors(
    selector: Any,
    *,
    synthetic: bool,
    environment: str | None = None,
) -> list[str]:
    if not _exact_mapping(selector, SELECTOR_KEYS):
        return ["release execution selector schema is invalid"]
    target_intake = selector.get("target_intake")
    if not _exact_mapping(target_intake, TARGET_INTAKE_KEYS):
        return ["release execution target intake schema is invalid"]
    if synthetic:
        if (
            selector != {
                "ledger_type": None,
                "evidence_object_reference": None,
                "evidence_sha256": None,
                "target_intake": {
                    "environment": None,
                    "manifest_payload_sha256": None,
                    "requirements_sha256": None,
                    "checkpoint_phase": None,
                },
            }
        ):
            return ["synthetic release execution selector is invalid"]
        return []

    errors: list[str] = []
    if selector.get("ledger_type") not in LEDGER_TYPES:
        errors.append("release execution ledger type is invalid")
    if not _opaque_execution_reference(
        selector.get("evidence_object_reference")
    ):
        errors.append("release execution object reference is invalid")
    if not _digest(selector.get("evidence_sha256")):
        errors.append("release execution whole-file digest is invalid")
    intake_environment = target_intake.get("environment")
    if not _environment(intake_environment):
        errors.append("release execution target environment is invalid")
    elif environment is not None and intake_environment != environment:
        errors.append("release execution target environment does not match its index")
    if not _digest(target_intake.get("manifest_payload_sha256")):
        errors.append("release execution intake manifest digest is invalid")
    if not _digest(target_intake.get("requirements_sha256")):
        errors.append("release execution intake requirements digest is invalid")
    if target_intake.get("checkpoint_phase") != 0:
        errors.append("release execution intake checkpoint phase is invalid")
    return errors


def _parse_json(raw: bytes) -> Any:
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if isinstance(error, json.JSONDecodeError) and error.msg == "duplicate JSON key":
            raise ReleaseExecutionBindingError(
                "release execution JSON has duplicate keys"
            ) from error
        raise ReleaseExecutionBindingError("release execution JSON is invalid") from error


def _external_regular_file(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        resolved = path.resolve(strict=True)
        root = ROOT.resolve(strict=True)
        details = path.lstat()
    except OSError:
        return False
    if resolved == root or root in resolved.parents or not path.is_file() or path.is_symlink():
        return False
    attributes = getattr(details, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return not bool(attributes & reparse)


def release_execution_alignment_errors(
    selector: Any,
    evidence_path: Path,
    *,
    environment: str,
    release_tag: str,
    release_commit: str,
    container_manifest_sha256: str,
    release_reviewed_at: str,
    consumer_started_at: str,
) -> list[str]:
    validation_errors = selector_errors(
        selector,
        synthetic=False,
        environment=environment,
    )
    if validation_errors:
        return validation_errors
    if not _external_regular_file(evidence_path):
        return ["release execution evidence path is invalid"]
    try:
        raw = read_stable_bytes(evidence_path, max_bytes=_MAX_EVIDENCE_BYTES)
    except StableFileError as error:
        if error.reason == "size":
            return ["release execution evidence size is invalid"]
        return ["release execution evidence cannot be read"]
    if hashlib.sha256(raw).hexdigest() != selector["evidence_sha256"]:
        return ["release execution whole-file digest does not match"]
    try:
        identity = release_execution_identity(raw)
    except ReleaseExecutionBindingError:
        return ["release execution evidence is invalid"]
    return release_execution_identity_alignment_errors(
        selector,
        identity,
        environment=environment,
        release_tag=release_tag,
        release_commit=release_commit,
        container_manifest_sha256=container_manifest_sha256,
        release_reviewed_at=release_reviewed_at,
        consumer_started_at=consumer_started_at,
    )


def release_execution_identity_alignment_errors(
    selector: Any,
    identity: Any,
    *,
    environment: str,
    release_tag: str,
    release_commit: str,
    container_manifest_sha256: str,
    release_reviewed_at: str,
    consumer_started_at: str,
) -> list[str]:
    errors = selector_errors(
        selector,
        synthetic=False,
        environment=environment,
    )
    if errors:
        return errors
    if (
        not _environment(environment)
        or not isinstance(release_tag, str)
        or _TAG.fullmatch(release_tag) is None
        or not isinstance(release_commit, str)
        or _COMMIT.fullmatch(release_commit) is None
        or not _digest(container_manifest_sha256)
    ):
        return ["expected release execution identity is invalid"]
    if (
        not _exact_mapping(identity, IDENTITY_KEYS)
        or not _exact_mapping(identity.get("target_release"), TARGET_RELEASE_KEYS)
        or not _exact_mapping(identity.get("target_intake"), TARGET_INTAKE_KEYS)
    ):
        return ["release execution identity is invalid"]
    if identity["ledger_type"] != selector["ledger_type"]:
        errors.append("release execution ledger type does not match its selector")
    if identity["evidence_sha256"] != selector["evidence_sha256"]:
        errors.append("release execution whole-file digest does not match its selector")
    if not identity["successful"]:
        errors.append("release execution terminal state is not successful")
    expected_release = {
        "tag": release_tag,
        "commit": release_commit,
        "container_manifest_sha256": container_manifest_sha256,
    }
    if identity["target_release"] != expected_release:
        errors.append("release execution target release does not match its index")
    if identity["target_intake"] != selector["target_intake"]:
        errors.append("release execution target intake does not match its selector")
    finished_at = _timestamp(identity.get("finished_at"))
    reviewed_at = _timestamp(release_reviewed_at)
    consumer_started = _timestamp(consumer_started_at)
    if (
        finished_at is None
        or consumer_started is None
        or consumer_started < finished_at
    ):
        errors.append(
            "release execution must finish before its consuming evidence starts"
        )
    if (
        finished_at is None
        or reviewed_at is None
        or reviewed_at < finished_at
    ):
        errors.append(
            "release execution review must not predate ledger completion"
        )
    if (
        reviewed_at is None
        or consumer_started is None
        or consumer_started < reviewed_at
    ):
        errors.append(
            "release execution must be reviewed before its consuming evidence starts"
        )
    return errors
