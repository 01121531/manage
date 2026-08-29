"""Shared closed-schema and caller-pin validation for intake manifest consumers."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    load_unique_json_with_bytes,
)


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_IDS = (
    "sub2_contract",
    "mail_contract",
    "card_pci_boundary",
    "oidc_deployment_identity",
    "phase0_boundary_approval",
    "target_platform_inventory",
    "phase1_platform_evidence",
    "phase2_mail_evidence",
    "phase3_card_evidence",
    "sub2_execution_evidence",
    "vault_egress_evidence",
    "windows_pilot_inputs",
    "phase5_windows_evidence",
    "release_execution_evidence",
    "phase6_pilot_inputs",
    "phase6_pilot_evidence",
    "phase6_operations_evidence",
)
MANIFEST_KEYS = {
    "schema_version",
    "environment",
    "production_acceptance",
    "requirements_sha256",
    "items",
}
ITEM_KEYS = {
    "id",
    "status",
    "artifact_path",
    "sha256",
    "reviewed_by",
    "reviewed_at",
    "redaction_confirmed",
}
RELEASE_ITEM_KEYS = ITEM_KEYS | {"release_execution_review_subject"}

_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
_REVIEW_SUBJECT_KEYS = {"kind", "selector"}
_SELECTOR_KEYS = {
    "ledger_type",
    "evidence_object_reference",
    "evidence_sha256",
    "target_intake",
}
_TARGET_INTAKE_KEYS = {
    "environment",
    "manifest_payload_sha256",
    "requirements_sha256",
    "checkpoint_phase",
}


class PinnedIntakeManifestError(ValueError):
    """A manifest did not satisfy the closed caller-pinned boundary."""

    def __init__(self) -> None:
        super().__init__("intake manifest caller binding is invalid")


def canonical_bytes(document: Any) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_payload_sha256(document: Any) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def manifest_artifact_sha256_matches(
    manifest: Any,
    identifier: str,
    raw: bytes,
) -> bool:
    """Bind one consumer's stable input bytes to its unique provided item."""

    if not isinstance(manifest, dict) or not isinstance(raw, bytes):
        return False
    items = manifest.get("items")
    if not isinstance(items, list):
        return False
    matches = [
        item
        for item in items
        if isinstance(item, dict) and item.get("id") == identifier
    ]
    if len(matches) != 1 or matches[0].get("status") != "provided":
        return False
    expected = matches[0].get("sha256")
    return (
        isinstance(expected, str)
        and _SHA256.fullmatch(expected) is not None
        and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected)
    )


def _reviewer_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 128
        and value.strip() == value
        and value.casefold() not in _PLACEHOLDERS
        and all(character.isprintable() for character in value)
    )


def _canonical_utc(value: Any) -> bool:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def _closed_release_subject(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != _REVIEW_SUBJECT_KEYS:
        return False
    selector = value.get("selector")
    if not isinstance(selector, dict) or set(selector) != _SELECTOR_KEYS:
        return False
    target_intake = selector.get("target_intake")
    return isinstance(target_intake, dict) and set(target_intake) == _TARGET_INTAKE_KEYS


def _external_absolute_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    if not path.is_absolute():
        return False
    try:
        return not path.resolve().is_relative_to(ROOT.resolve())
    except OSError:
        return False


def manifest_shape_errors(document: Any) -> list[str]:
    """Validate the complete v2 envelope without reading referenced artifacts."""

    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        return ["intake manifest top-level schema is invalid"]
    errors: list[str] = []
    environment = document.get("environment")
    if document.get("schema_version") != 2:
        errors.append("intake manifest identity is invalid")
    if (
        not isinstance(environment, str)
        or not _ENVIRONMENT.fullmatch(environment)
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("intake environment is invalid or a placeholder")
    if document.get("production_acceptance") is not False:
        errors.append("intake manifest must not claim production acceptance")
    requirements_digest = document.get("requirements_sha256")
    if not isinstance(requirements_digest, str) or not _SHA256.fullmatch(
        requirements_digest
    ):
        errors.append("intake requirements digest is invalid")

    items = document.get("items")
    if not isinstance(items, list):
        errors.append("intake manifest items must be a list")
        return errors
    identifiers = [item.get("id") if isinstance(item, dict) else None for item in items]
    if identifiers != list(REQUIRED_IDS):
        errors.append("intake manifest item inventory is invalid")
    for item in items:
        if not isinstance(item, dict):
            errors.append("intake manifest item schema is invalid")
            continue
        identifier = item.get("id")
        expected_keys = (
            RELEASE_ITEM_KEYS if identifier == "release_execution_evidence" else ITEM_KEYS
        )
        if set(item) != expected_keys:
            errors.append("intake manifest item schema is invalid")
            continue
        metadata = (
            "artifact_path",
            "sha256",
            "reviewed_by",
            "reviewed_at",
            "redaction_confirmed",
        )
        if identifier == "release_execution_evidence":
            metadata += ("release_execution_review_subject",)
        status = item.get("status")
        if status == "missing":
            if any(item.get(key) is not None for key in metadata):
                errors.append(f"{identifier} missing item metadata must be null")
            continue
        if status != "provided":
            errors.append(f"{identifier} intake status is invalid")
            continue
        artifact_path = item.get("artifact_path")
        if not _external_absolute_path(artifact_path):
            errors.append(f"{identifier} artifact path must be absolute and external")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            errors.append(f"{identifier} artifact sha256 is invalid")
        if not _reviewer_reference(item.get("reviewed_by")):
            errors.append(f"{identifier} reviewer reference is invalid")
        reviewed_at = item.get("reviewed_at")
        if not _canonical_utc(reviewed_at):
            errors.append(f"{identifier} reviewed_at must be canonical UTC")
        if item.get("redaction_confirmed") is not True:
            errors.append(f"{identifier} redaction confirmation is required")
        if (
            identifier == "release_execution_evidence"
            and not _closed_release_subject(
                item.get("release_execution_review_subject")
            )
        ):
            errors.append("release execution review subject is invalid")
    return errors


def load_pinned_intake_manifest(
    path: Path,
    *,
    expected_payload_sha256: str,
    expected_file_sha256: str,
) -> dict[str, Any]:
    """Perform one stable read and bind both semantic and byte identities."""

    if (
        not isinstance(expected_payload_sha256, str)
        or not _SHA256.fullmatch(expected_payload_sha256)
        or not isinstance(expected_file_sha256, str)
        or not _SHA256.fullmatch(expected_file_sha256)
        or not path.is_absolute()
    ):
        raise PinnedIntakeManifestError()
    try:
        resolved = path.resolve(strict=True)
        if resolved.is_relative_to(ROOT.resolve()):
            raise PinnedIntakeManifestError()
        document, raw = load_unique_json_with_bytes(
            path,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except PinnedIntakeManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise PinnedIntakeManifestError() from error
    if not isinstance(document, dict):
        raise PinnedIntakeManifestError()
    actual_file_sha256 = hashlib.sha256(raw).hexdigest()
    actual_payload_sha256 = canonical_payload_sha256(document)
    if (
        not hmac.compare_digest(actual_file_sha256, expected_file_sha256)
        or not hmac.compare_digest(actual_payload_sha256, expected_payload_sha256)
        or manifest_shape_errors(document)
    ):
        raise PinnedIntakeManifestError()
    return document
