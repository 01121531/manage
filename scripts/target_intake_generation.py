"""Validate write-once target-intake generation receipts and their local lineage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    StableFileError,
    load_unique_json_with_bytes_and_metadata,
    parse_unique_json_bytes,
    recheck_stable_bytes,
)
from scripts.target_intake_manifest import (
    ITEM_KEYS,
    MANIFEST_KEYS,
    RELEASE_ITEM_KEYS,
    REQUIRED_IDS,
    canonical_bytes,
    canonical_payload_sha256,
    manifest_shape_errors,
)
from scripts.target_intake_validator_contract import validator_contract_shape_errors


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_KIND = "target_intake_generation_receipt_v6"
RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "receipt_path",
    "sequence",
    "manifest",
    "predecessor",
    "registered_item",
    "validation_context",
}
VALIDATION_CONTEXT_KEYS = {
    "evaluated_at",
    "requirements",
    "phase_acceptance_matrix",
    "validator_contract",
}
MANIFEST_SELECTOR_KEYS = {
    "path",
    "environment",
    "requirements_sha256",
    "payload_sha256",
    "file_sha256",
}
RECEIPT_SELECTOR_KEYS = {"path", "payload_sha256", "file_sha256"}
PREDECESSOR_KEYS = {"manifest", "receipt"}
REGISTERED_ITEM_KEYS = {"id", "artifact_sha256", "candidate_file_sha256"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)


class GenerationLineageError(ValueError):
    """A selected manifest was not backed by one complete local receipt chain."""

    def __init__(self) -> None:
        super().__init__("target intake generation lineage is invalid")


@dataclass(frozen=True)
class _Snapshot:
    path: Path
    raw: bytes
    metadata: os.stat_result


@dataclass(frozen=True)
class GenerationLineage:
    manifest: dict[str, Any]
    manifest_raw: bytes
    manifest_metadata: os.stat_result
    receipt: dict[str, Any]
    receipt_raw: bytes
    receipt_metadata: os.stat_result
    snapshots: tuple[_Snapshot, ...]


def receipt_bytes(document: Any) -> bytes:
    return canonical_bytes(document) + b"\n"


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _parse_recorded_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _validation_context(
    evaluated_at: str,
    requirements: Any,
    phase_acceptance_matrix: Any,
    validator_contract: Any,
) -> dict[str, Any]:
    context = {
        "evaluated_at": evaluated_at,
        "requirements": requirements,
        "phase_acceptance_matrix": phase_acceptance_matrix,
        "validator_contract": validator_contract,
    }
    if (
        _parse_recorded_utc(evaluated_at) is None
        or not isinstance(requirements, dict)
        or not isinstance(phase_acceptance_matrix, dict)
        or validator_contract_shape_errors(validator_contract)
    ):
        raise GenerationLineageError()
    return context


def _external_locator(value: Any) -> bool:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        return False
    try:
        return not Path(value).resolve(strict=True).is_relative_to(ROOT.resolve())
    except OSError:
        return False


def _external_output_locator(value: Any) -> bool:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        return False
    try:
        return not Path(value).resolve(strict=False).is_relative_to(ROOT.resolve())
    except OSError:
        return False


def _manifest_selector(path: Path, manifest: Any, raw: bytes) -> dict[str, Any]:
    if (
        not path.is_absolute()
        or not isinstance(manifest, dict)
        or not isinstance(raw, bytes)
        or manifest_shape_errors(manifest)
    ):
        raise GenerationLineageError()
    return {
        "path": os.path.abspath(path),
        "environment": manifest["environment"],
        "requirements_sha256": manifest["requirements_sha256"],
        "payload_sha256": canonical_payload_sha256(manifest),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _receipt_selector(path: Path, receipt: Any, raw: bytes) -> dict[str, str]:
    if (
        not path.is_absolute()
        or receipt_errors(receipt)
        or os.path.abspath(path) != receipt.get("receipt_path")
        or not isinstance(raw, bytes)
    ):
        raise GenerationLineageError()
    return {
        "path": os.path.abspath(path),
        "payload_sha256": canonical_payload_sha256(receipt),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def manifest_registration_item_id(base: Any, candidate: Any) -> str | None:
    """Return the one missing-to-provided item in one generation transition."""

    if not isinstance(base, dict) or not isinstance(candidate, dict):
        return None
    if set(base) != MANIFEST_KEYS or set(candidate) != MANIFEST_KEYS:
        return None
    if any(base[key] != candidate[key] for key in MANIFEST_KEYS - {"items"}):
        return None
    base_items = base.get("items")
    candidate_items = candidate.get("items")
    if not isinstance(base_items, list) or not isinstance(candidate_items, list):
        return None
    if len(base_items) != len(REQUIRED_IDS) or len(candidate_items) != len(base_items):
        return None
    base_ids = [item.get("id") if isinstance(item, dict) else None for item in base_items]
    candidate_ids = [
        item.get("id") if isinstance(item, dict) else None
        for item in candidate_items
    ]
    if base_ids != list(REQUIRED_IDS) or candidate_ids != list(REQUIRED_IDS):
        return None
    changed = [
        (before, after)
        for before, after in zip(base_items, candidate_items, strict=True)
        if before != after
    ]
    if len(changed) != 1:
        return None
    before, after = changed[0]
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    identifier = before.get("id")
    expected_keys = (
        RELEASE_ITEM_KEYS
        if identifier == "release_execution_evidence"
        else ITEM_KEYS
    )
    metadata_keys = expected_keys - {"id", "status"}
    if (
        set(before) != expected_keys
        or set(after) != expected_keys
        or after.get("id") != identifier
        or before.get("status") != "missing"
        or after.get("status") != "provided"
        or any(before.get(key) is not None for key in metadata_keys)
    ):
        return None
    return identifier if isinstance(identifier, str) else None


def receipt_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != RECEIPT_KEYS:
        return ["generation receipt top-level schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 6
        or document.get("kind") != RECEIPT_KIND
        or document.get("production_acceptance") is not False
        or not _external_output_locator(document.get("receipt_path"))
    ):
        errors.append("generation receipt identity is invalid")
    context = document.get("validation_context")
    if (
        not isinstance(context, dict)
        or set(context) != VALIDATION_CONTEXT_KEYS
        or _parse_recorded_utc(context.get("evaluated_at")) is None
        or not isinstance(context.get("requirements"), dict)
        or not isinstance(context.get("phase_acceptance_matrix"), dict)
        or validator_contract_shape_errors(context.get("validator_contract"))
    ):
        errors.append("generation receipt validation context is invalid")
    sequence = document.get("sequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 0 <= sequence <= len(REQUIRED_IDS)
    ):
        errors.append("generation receipt sequence is invalid")
    manifest = document.get("manifest")
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_SELECTOR_KEYS:
        errors.append("generation receipt manifest selector is invalid")
    elif not (
        _external_locator(manifest.get("path"))
        and isinstance(manifest.get("environment"), str)
        and _digest(manifest.get("requirements_sha256"))
        and _digest(manifest.get("payload_sha256"))
        and _digest(manifest.get("file_sha256"))
    ):
        errors.append("generation receipt manifest selector is invalid")
    elif isinstance(context, dict) and isinstance(context.get("requirements"), dict):
        if not hmac.compare_digest(
            canonical_payload_sha256(context["requirements"]),
            manifest["requirements_sha256"],
        ):
            errors.append("generation receipt validation context does not match manifest")
    predecessor = document.get("predecessor")
    registered = document.get("registered_item")
    if sequence == 0:
        if predecessor is not None or registered is not None:
            errors.append("genesis receipt must not claim a predecessor or item")
        return errors
    if not isinstance(predecessor, dict) or set(predecessor) != PREDECESSOR_KEYS:
        errors.append("generation receipt predecessor is invalid")
    else:
        predecessor_manifest = predecessor.get("manifest")
        predecessor_receipt = predecessor.get("receipt")
        if not (
            isinstance(predecessor_manifest, dict)
            and set(predecessor_manifest) == MANIFEST_SELECTOR_KEYS
            and _external_locator(predecessor_manifest.get("path"))
            and isinstance(predecessor_manifest.get("environment"), str)
            and _digest(predecessor_manifest.get("requirements_sha256"))
            and _digest(predecessor_manifest.get("payload_sha256"))
            and _digest(predecessor_manifest.get("file_sha256"))
        ):
            errors.append("generation receipt predecessor manifest is invalid")
        if not (
            isinstance(predecessor_receipt, dict)
            and set(predecessor_receipt) == RECEIPT_SELECTOR_KEYS
            and _external_locator(predecessor_receipt.get("path"))
            and _digest(predecessor_receipt.get("payload_sha256"))
            and _digest(predecessor_receipt.get("file_sha256"))
        ):
            errors.append("generation receipt predecessor receipt is invalid")
    if not isinstance(registered, dict) or set(registered) != REGISTERED_ITEM_KEYS:
        errors.append("generation receipt registered item is invalid")
    elif not (
        registered.get("id") in REQUIRED_IDS
        and _digest(registered.get("artifact_sha256"))
        and _digest(registered.get("candidate_file_sha256"))
    ):
        errors.append("generation receipt registered item is invalid")
    return errors


def create_genesis_receipt(
    manifest_path: Path,
    receipt_path: Path,
    manifest: dict[str, Any],
    manifest_raw: bytes,
    *,
    evaluated_at: str,
    requirements: dict[str, Any],
    phase_acceptance_matrix: dict[str, Any],
    validator_contract: dict[str, Any],
) -> dict[str, Any]:
    if any(item.get("status") != "missing" for item in manifest.get("items", [])):
        raise GenerationLineageError()
    receipt = {
        "schema_version": 6,
        "kind": RECEIPT_KIND,
        "production_acceptance": False,
        "receipt_path": os.path.abspath(receipt_path),
        "sequence": 0,
        "manifest": _manifest_selector(manifest_path, manifest, manifest_raw),
        "predecessor": None,
        "registered_item": None,
        "validation_context": _validation_context(
            evaluated_at, requirements, phase_acceptance_matrix, validator_contract
        ),
    }
    if receipt_errors(receipt):
        raise GenerationLineageError()
    return receipt


def create_registration_receipt(
    *,
    manifest_path: Path,
    manifest: dict[str, Any],
    manifest_raw: bytes,
    receipt_path: Path,
    predecessor: GenerationLineage,
    predecessor_manifest_path: Path,
    predecessor_receipt_path: Path,
    registered_item_id: str,
    artifact_sha256: str,
    candidate_raw: bytes,
    evaluated_at: str,
    requirements: dict[str, Any],
    phase_acceptance_matrix: dict[str, Any],
    validator_contract: dict[str, Any],
) -> dict[str, Any]:
    if (
        manifest_registration_item_id(predecessor.manifest, manifest)
        != registered_item_id
        or not _digest(artifact_sha256)
    ):
        raise GenerationLineageError()
    receipt = {
        "schema_version": 6,
        "kind": RECEIPT_KIND,
        "production_acceptance": False,
        "receipt_path": os.path.abspath(receipt_path),
        "sequence": predecessor.receipt["sequence"] + 1,
        "manifest": _manifest_selector(manifest_path, manifest, manifest_raw),
        "predecessor": {
            "manifest": _manifest_selector(
                predecessor_manifest_path,
                predecessor.manifest,
                predecessor.manifest_raw,
            ),
            "receipt": _receipt_selector(
                predecessor_receipt_path,
                predecessor.receipt,
                predecessor.receipt_raw,
            ),
        },
        "registered_item": {
            "id": registered_item_id,
            "artifact_sha256": artifact_sha256,
            "candidate_file_sha256": hashlib.sha256(candidate_raw).hexdigest(),
        },
        "validation_context": _validation_context(
            evaluated_at, requirements, phase_acceptance_matrix, validator_contract
        ),
    }
    if receipt_errors(receipt):
        raise GenerationLineageError()
    return receipt


def _matches_manifest_selector(
    selector: Any,
    path: Path,
    manifest: Any,
    raw: bytes,
) -> bool:
    try:
        return selector == _manifest_selector(path, manifest, raw)
    except GenerationLineageError:
        return False


def _matches_receipt_selector(
    selector: Any,
    path: Path,
    receipt: Any,
    raw: bytes,
) -> bool:
    try:
        return selector == _receipt_selector(path, receipt, raw)
    except GenerationLineageError:
        return False


def recheck_generation_lineage(lineage: GenerationLineage) -> None:
    try:
        for snapshot in lineage.snapshots:
            recheck_stable_bytes(
                snapshot.path,
                snapshot.raw,
                snapshot.metadata,
                max_bytes=MAX_INTAKE_JSON_BYTES,
                require_single_link=True,
            )
    except StableFileError as error:
        raise GenerationLineageError() from error


def generation_lineage_contains(
    lineage: GenerationLineage,
    manifest_selector: Any,
    receipt_selector: Any,
) -> bool:
    """Return whether one exact manifest/receipt selection is in the chain."""

    try:
        for index in range(0, len(lineage.snapshots), 2):
            receipt_snapshot = lineage.snapshots[index]
            manifest_snapshot = lineage.snapshots[index + 1]
            receipt = parse_unique_json_bytes(receipt_snapshot.raw)
            manifest = parse_unique_json_bytes(manifest_snapshot.raw)
            if _matches_manifest_selector(
                manifest_selector,
                manifest_snapshot.path,
                manifest,
                manifest_snapshot.raw,
            ) and _matches_receipt_selector(
                receipt_selector,
                receipt_snapshot.path,
                receipt,
                receipt_snapshot.raw,
            ):
                return True
    except (IndexError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return False


def load_generation_lineage(
    manifest_path: Path,
    receipt_path: Path,
    *,
    expected_receipt_payload_sha256: str,
    expected_receipt_file_sha256: str,
    expected_manifest_payload_sha256: str | None = None,
    expected_manifest_file_sha256: str | None = None,
) -> GenerationLineage:
    if not (
        manifest_path.is_absolute()
        and receipt_path.is_absolute()
        and _digest(expected_receipt_payload_sha256)
        and _digest(expected_receipt_file_sha256)
        and (
            expected_manifest_payload_sha256 is None
            or _digest(expected_manifest_payload_sha256)
        )
        and (
            expected_manifest_file_sha256 is None
            or _digest(expected_manifest_file_sha256)
        )
        and (expected_manifest_payload_sha256 is None)
        == (expected_manifest_file_sha256 is None)
    ):
        raise GenerationLineageError()
    selected: GenerationLineage | None = None
    snapshots: list[_Snapshot] = []
    seen_manifests: set[tuple[str, str]] = set()
    seen_receipts: set[tuple[str, str]] = set()
    child_manifest: dict[str, Any] | None = None
    child_receipt: dict[str, Any] | None = None
    current_manifest_path = manifest_path
    current_receipt_path = receipt_path
    receipt_payload_pin = expected_receipt_payload_sha256
    receipt_file_pin = expected_receipt_file_sha256
    try:
        for _ in range(len(REQUIRED_IDS) + 1):
            receipt, receipt_raw, receipt_metadata = (
                load_unique_json_with_bytes_and_metadata(
                    current_receipt_path,
                    max_bytes=MAX_INTAKE_JSON_BYTES,
                )
            )
            if (
                receipt_errors(receipt)
                or os.path.abspath(current_receipt_path)
                != receipt.get("receipt_path")
                or not hmac.compare_digest(
                    canonical_payload_sha256(receipt),
                    receipt_payload_pin,
                )
                or not hmac.compare_digest(
                    hashlib.sha256(receipt_raw).hexdigest(),
                    receipt_file_pin,
                )
            ):
                raise GenerationLineageError()
            manifest, manifest_raw, manifest_metadata = (
                load_unique_json_with_bytes_and_metadata(
                    current_manifest_path,
                    max_bytes=MAX_INTAKE_JSON_BYTES,
                )
            )
            if not _matches_manifest_selector(
                receipt["manifest"],
                current_manifest_path,
                manifest,
                manifest_raw,
            ):
                raise GenerationLineageError()
            provided = sum(
                item.get("status") == "provided" for item in manifest["items"]
            )
            if provided != receipt["sequence"]:
                raise GenerationLineageError()
            manifest_identity = (
                receipt["manifest"]["file_sha256"],
                receipt["manifest"]["path"],
            )
            receipt_identity = (
                hashlib.sha256(receipt_raw).hexdigest(),
                os.path.abspath(current_receipt_path),
            )
            if (
                manifest_identity in seen_manifests
                or receipt_identity in seen_receipts
            ):
                raise GenerationLineageError()
            seen_manifests.add(manifest_identity)
            seen_receipts.add(receipt_identity)
            snapshots.extend(
                (
                    _Snapshot(current_receipt_path, receipt_raw, receipt_metadata),
                    _Snapshot(current_manifest_path, manifest_raw, manifest_metadata),
                )
            )
            if selected is None:
                if (
                    expected_manifest_payload_sha256 is not None
                    and not hmac.compare_digest(
                        receipt["manifest"]["payload_sha256"],
                        expected_manifest_payload_sha256,
                    )
                ) or (
                    expected_manifest_file_sha256 is not None
                    and not hmac.compare_digest(
                        receipt["manifest"]["file_sha256"],
                        expected_manifest_file_sha256,
                    )
                ):
                    raise GenerationLineageError()
                selected = GenerationLineage(
                    manifest,
                    manifest_raw,
                    manifest_metadata,
                    receipt,
                    receipt_raw,
                    receipt_metadata,
                    (),
                )
            if child_manifest is not None and child_receipt is not None:
                predecessor = child_receipt["predecessor"]
                registered = child_receipt["registered_item"]
                item_id = manifest_registration_item_id(manifest, child_manifest)
                child_item = next(
                    item for item in child_manifest["items"] if item["id"] == item_id
                ) if item_id is not None else None
                child_time = _parse_recorded_utc(
                    child_receipt["validation_context"]["evaluated_at"]
                )
                predecessor_time = _parse_recorded_utc(
                    receipt["validation_context"]["evaluated_at"]
                )
                if not (
                    child_receipt["sequence"] == receipt["sequence"] + 1
                    and item_id == registered["id"]
                    and child_item is not None
                    and hmac.compare_digest(
                        child_item["sha256"],
                        registered["artifact_sha256"],
                    )
                    and _matches_manifest_selector(
                        predecessor["manifest"],
                        current_manifest_path,
                        manifest,
                        manifest_raw,
                    )
                    and _matches_receipt_selector(
                        predecessor["receipt"],
                        current_receipt_path,
                        receipt,
                        receipt_raw,
                    )
                    and child_time is not None
                    and predecessor_time is not None
                    and child_time >= predecessor_time
                ):
                    raise GenerationLineageError()
            if receipt["sequence"] == 0:
                break
            predecessor = receipt["predecessor"]
            child_manifest = manifest
            child_receipt = receipt
            current_manifest_path = Path(predecessor["manifest"]["path"])
            current_receipt_path = Path(predecessor["receipt"]["path"])
            receipt_payload_pin = predecessor["receipt"]["payload_sha256"]
            receipt_file_pin = predecessor["receipt"]["file_sha256"]
        else:
            raise GenerationLineageError()
    except GenerationLineageError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, StableFileError) as error:
        raise GenerationLineageError() from error
    if selected is None:
        raise GenerationLineageError()
    lineage = GenerationLineage(
        selected.manifest,
        selected.manifest_raw,
        selected.manifest_metadata,
        selected.receipt,
        selected.receipt_raw,
        selected.receipt_metadata,
        tuple(snapshots),
    )
    recheck_generation_lineage(lineage)
    return lineage
