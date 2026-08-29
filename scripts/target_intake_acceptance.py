"""Validate local write-once acceptance receipts for target-intake leaves."""

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
    recheck_stable_bytes,
)
from scripts.target_intake_generation import (
    GenerationLineage,
    GenerationLineageError,
    generation_lineage_contains,
    load_generation_lineage,
    recheck_generation_lineage,
)
from scripts.target_intake_manifest import (
    canonical_bytes,
    canonical_payload_sha256,
    manifest_shape_errors,
)


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_RECEIPT_KIND = "target_intake_phase0_snapshot_receipt_v2"
FINALIZATION_RECEIPT_KIND = "target_intake_finalization_receipt_v2"
SNAPSHOT_RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "receipt_path",
    "checkpoint_phase",
    "evaluated_at",
    "valid_from",
    "valid_until",
    "source_generation",
    "result_checkpoint",
}
FINALIZATION_RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "receipt_path",
    "evaluated_at",
    "source_generation",
    "phase0_snapshot",
    "result_final_manifest",
}
SELECTION_KEYS = {"manifest", "receipt"}
SNAPSHOT_SELECTION_KEYS = {"checkpoint", "receipt"}
MANIFEST_SELECTOR_KEYS = {
    "path",
    "environment",
    "requirements_sha256",
    "payload_sha256",
    "file_sha256",
}
RECEIPT_SELECTOR_KEYS = {"path", "payload_sha256", "file_sha256"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


class AcceptanceReceiptError(ValueError):
    """A selected snapshot or finalization receipt is invalid."""

    def __init__(self) -> None:
        super().__init__("target intake acceptance receipt is invalid")


@dataclass(frozen=True)
class _Snapshot:
    path: Path
    raw: bytes
    metadata: os.stat_result


@dataclass(frozen=True)
class SnapshotAcceptance:
    receipt: dict[str, Any]
    receipt_raw: bytes
    receipt_metadata: os.stat_result
    checkpoint: dict[str, Any]
    checkpoint_raw: bytes
    checkpoint_metadata: os.stat_result
    source_lineage: GenerationLineage
    snapshots: tuple[_Snapshot, ...]


@dataclass(frozen=True)
class FinalizationAcceptance:
    receipt: dict[str, Any]
    receipt_raw: bytes
    receipt_metadata: os.stat_result
    finalized_manifest: dict[str, Any]
    finalized_raw: bytes
    finalized_metadata: os.stat_result
    source_lineage: GenerationLineage
    phase0_snapshot: SnapshotAcceptance
    snapshots: tuple[_Snapshot, ...]


def acceptance_receipt_bytes(document: Any) -> bytes:
    return canonical_bytes(document) + b"\n"


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


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
        raise AcceptanceReceiptError()
    return {
        "path": os.path.abspath(path),
        "environment": manifest["environment"],
        "requirements_sha256": manifest["requirements_sha256"],
        "payload_sha256": canonical_payload_sha256(manifest),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _receipt_selector(path: Path, receipt: Any, raw: bytes) -> dict[str, str]:
    if not path.is_absolute() or not isinstance(receipt, dict) or not isinstance(raw, bytes):
        raise AcceptanceReceiptError()
    return {
        "path": os.path.abspath(path),
        "payload_sha256": canonical_payload_sha256(receipt),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _manifest_selector_valid(selector: Any) -> bool:
    return bool(
        isinstance(selector, dict)
        and set(selector) == MANIFEST_SELECTOR_KEYS
        and _external_locator(selector.get("path"))
        and isinstance(selector.get("environment"), str)
        and _digest(selector.get("requirements_sha256"))
        and _digest(selector.get("payload_sha256"))
        and _digest(selector.get("file_sha256"))
    )


def _receipt_selector_valid(selector: Any) -> bool:
    return bool(
        isinstance(selector, dict)
        and set(selector) == RECEIPT_SELECTOR_KEYS
        and _external_locator(selector.get("path"))
        and _digest(selector.get("payload_sha256"))
        and _digest(selector.get("file_sha256"))
    )


def _selection_valid(selection: Any) -> bool:
    return bool(
        isinstance(selection, dict)
        and set(selection) == SELECTION_KEYS
        and _manifest_selector_valid(selection.get("manifest"))
        and _receipt_selector_valid(selection.get("receipt"))
    )


def snapshot_receipt_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != SNAPSHOT_RECEIPT_KEYS:
        return ["snapshot receipt top-level schema is invalid"]
    errors: list[str] = []
    evaluated_at = _utc(document.get("evaluated_at"))
    valid_from = _utc(document.get("valid_from"))
    valid_until = _utc(document.get("valid_until"))
    if (
        document.get("schema_version") != 2
        or document.get("kind") != SNAPSHOT_RECEIPT_KIND
        or document.get("production_acceptance") is not False
        or not _external_output_locator(document.get("receipt_path"))
        or document.get("checkpoint_phase") != 0
        or evaluated_at is None
        or valid_from is None
        or valid_until is None
        or not valid_from <= evaluated_at < valid_until
    ):
        errors.append("snapshot receipt identity is invalid")
    if not _selection_valid(document.get("source_generation")):
        errors.append("snapshot receipt source generation is invalid")
    if not _manifest_selector_valid(document.get("result_checkpoint")):
        errors.append("snapshot receipt checkpoint is invalid")
    return errors


def finalization_receipt_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != FINALIZATION_RECEIPT_KEYS:
        return ["finalization receipt top-level schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 2
        or document.get("kind") != FINALIZATION_RECEIPT_KIND
        or document.get("production_acceptance") is not False
        or not _external_output_locator(document.get("receipt_path"))
        or _utc(document.get("evaluated_at")) is None
    ):
        errors.append("finalization receipt identity is invalid")
    if not _selection_valid(document.get("source_generation")):
        errors.append("finalization receipt source generation is invalid")
    phase0_snapshot = document.get("phase0_snapshot")
    if not (
        isinstance(phase0_snapshot, dict)
        and set(phase0_snapshot) == SNAPSHOT_SELECTION_KEYS
        and _manifest_selector_valid(phase0_snapshot.get("checkpoint"))
        and _receipt_selector_valid(phase0_snapshot.get("receipt"))
    ):
        errors.append("finalization receipt Phase 0 snapshot is invalid")
    if not _manifest_selector_valid(document.get("result_final_manifest")):
        errors.append("finalization receipt manifest is invalid")
    return errors


def _generation_selection(
    lineage: GenerationLineage,
    manifest_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    return {
        "manifest": _manifest_selector(
            manifest_path,
            lineage.manifest,
            lineage.manifest_raw,
        ),
        "receipt": _receipt_selector(
            receipt_path,
            lineage.receipt,
            lineage.receipt_raw,
        ),
    }


def create_snapshot_receipt(
    *,
    source_lineage: GenerationLineage,
    source_manifest_path: Path,
    source_receipt_path: Path,
    checkpoint_path: Path,
    receipt_path: Path,
    checkpoint: dict[str, Any],
    checkpoint_raw: bytes,
    evaluated_at: str,
    valid_from: str,
    valid_until: str,
) -> dict[str, Any]:
    if (
        checkpoint != source_lineage.manifest
        or not hmac.compare_digest(checkpoint_raw, source_lineage.manifest_raw)
    ):
        raise AcceptanceReceiptError()
    receipt = {
        "schema_version": 2,
        "kind": SNAPSHOT_RECEIPT_KIND,
        "production_acceptance": False,
        "receipt_path": os.path.abspath(receipt_path),
        "checkpoint_phase": 0,
        "evaluated_at": evaluated_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "source_generation": _generation_selection(
            source_lineage,
            source_manifest_path,
            source_receipt_path,
        ),
        "result_checkpoint": _manifest_selector(
            checkpoint_path,
            checkpoint,
            checkpoint_raw,
        ),
    }
    if snapshot_receipt_errors(receipt):
        raise AcceptanceReceiptError()
    return receipt


def create_finalization_receipt(
    *,
    source_lineage: GenerationLineage,
    source_manifest_path: Path,
    source_receipt_path: Path,
    phase0_snapshot: SnapshotAcceptance,
    phase0_checkpoint_path: Path,
    phase0_receipt_path: Path,
    finalized_path: Path,
    receipt_path: Path,
    finalized_manifest: dict[str, Any],
    finalized_raw: bytes,
    evaluated_at: str,
) -> dict[str, Any]:
    source_selection = _generation_selection(
        source_lineage,
        source_manifest_path,
        source_receipt_path,
    )
    snapshot_source = phase0_snapshot.receipt["source_generation"]
    if not (
        finalized_manifest == source_lineage.manifest
        and hmac.compare_digest(finalized_raw, source_lineage.manifest_raw)
        and generation_lineage_contains(
            source_lineage,
            snapshot_source["manifest"],
            snapshot_source["receipt"],
        )
    ):
        raise AcceptanceReceiptError()
    receipt = {
        "schema_version": 2,
        "kind": FINALIZATION_RECEIPT_KIND,
        "production_acceptance": False,
        "receipt_path": os.path.abspath(receipt_path),
        "evaluated_at": evaluated_at,
        "source_generation": source_selection,
        "phase0_snapshot": {
            "checkpoint": _manifest_selector(
                phase0_checkpoint_path,
                phase0_snapshot.checkpoint,
                phase0_snapshot.checkpoint_raw,
            ),
            "receipt": _receipt_selector(
                phase0_receipt_path,
                phase0_snapshot.receipt,
                phase0_snapshot.receipt_raw,
            ),
        },
        "result_final_manifest": _manifest_selector(
            finalized_path,
            finalized_manifest,
            finalized_raw,
        ),
    }
    if finalization_receipt_errors(receipt):
        raise AcceptanceReceiptError()
    return receipt


def _matching_digest(actual: str, expected: str) -> bool:
    return _digest(expected) and hmac.compare_digest(actual, expected)


def recheck_snapshot_acceptance(acceptance: SnapshotAcceptance) -> None:
    try:
        recheck_generation_lineage(acceptance.source_lineage)
        for snapshot in acceptance.snapshots:
            recheck_stable_bytes(
                snapshot.path,
                snapshot.raw,
                snapshot.metadata,
                max_bytes=MAX_INTAKE_JSON_BYTES,
                require_single_link=True,
            )
    except (GenerationLineageError, StableFileError) as error:
        raise AcceptanceReceiptError() from error


def load_snapshot_acceptance(
    checkpoint_path: Path,
    receipt_path: Path,
    *,
    expected_receipt_payload_sha256: str,
    expected_receipt_file_sha256: str,
) -> SnapshotAcceptance:
    try:
        receipt, receipt_raw, receipt_metadata = load_unique_json_with_bytes_and_metadata(
            receipt_path,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        if (
            snapshot_receipt_errors(receipt)
            or os.path.abspath(receipt_path) != receipt.get("receipt_path")
            or not _matching_digest(
                canonical_payload_sha256(receipt),
                expected_receipt_payload_sha256,
            )
            or not _matching_digest(
                hashlib.sha256(receipt_raw).hexdigest(),
                expected_receipt_file_sha256,
            )
        ):
            raise AcceptanceReceiptError()
        checkpoint, checkpoint_raw, checkpoint_metadata = (
            load_unique_json_with_bytes_and_metadata(
                checkpoint_path,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
        )
        if receipt["result_checkpoint"] != _manifest_selector(
            checkpoint_path,
            checkpoint,
            checkpoint_raw,
        ):
            raise AcceptanceReceiptError()
        source = receipt["source_generation"]
        source_manifest = source["manifest"]
        source_receipt = source["receipt"]
        lineage = load_generation_lineage(
            Path(source_manifest["path"]),
            Path(source_receipt["path"]),
            expected_receipt_payload_sha256=source_receipt["payload_sha256"],
            expected_receipt_file_sha256=source_receipt["file_sha256"],
            expected_manifest_payload_sha256=source_manifest["payload_sha256"],
            expected_manifest_file_sha256=source_manifest["file_sha256"],
        )
        if (
            source != _generation_selection(
                lineage,
                Path(source_manifest["path"]),
                Path(source_receipt["path"]),
            )
            or checkpoint != lineage.manifest
            or not hmac.compare_digest(checkpoint_raw, lineage.manifest_raw)
        ):
            raise AcceptanceReceiptError()
    except AcceptanceReceiptError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        StableFileError,
        GenerationLineageError,
    ) as error:
        raise AcceptanceReceiptError() from error
    acceptance = SnapshotAcceptance(
        receipt,
        receipt_raw,
        receipt_metadata,
        checkpoint,
        checkpoint_raw,
        checkpoint_metadata,
        lineage,
        (
            _Snapshot(receipt_path, receipt_raw, receipt_metadata),
            _Snapshot(checkpoint_path, checkpoint_raw, checkpoint_metadata),
        ),
    )
    recheck_snapshot_acceptance(acceptance)
    return acceptance


def recheck_finalization_acceptance(acceptance: FinalizationAcceptance) -> None:
    try:
        recheck_generation_lineage(acceptance.source_lineage)
        recheck_snapshot_acceptance(acceptance.phase0_snapshot)
        for snapshot in acceptance.snapshots:
            recheck_stable_bytes(
                snapshot.path,
                snapshot.raw,
                snapshot.metadata,
                max_bytes=MAX_INTAKE_JSON_BYTES,
                require_single_link=True,
            )
    except (GenerationLineageError, AcceptanceReceiptError, StableFileError) as error:
        raise AcceptanceReceiptError() from error


def load_finalization_acceptance(
    finalized_path: Path,
    receipt_path: Path,
    phase0_checkpoint_path: Path,
    *,
    expected_receipt_payload_sha256: str,
    expected_receipt_file_sha256: str,
    expected_manifest_payload_sha256: str,
    expected_manifest_file_sha256: str,
) -> FinalizationAcceptance:
    try:
        receipt, receipt_raw, receipt_metadata = load_unique_json_with_bytes_and_metadata(
            receipt_path,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        if (
            finalization_receipt_errors(receipt)
            or os.path.abspath(receipt_path) != receipt.get("receipt_path")
            or not _matching_digest(
                canonical_payload_sha256(receipt),
                expected_receipt_payload_sha256,
            )
            or not _matching_digest(
                hashlib.sha256(receipt_raw).hexdigest(),
                expected_receipt_file_sha256,
            )
        ):
            raise AcceptanceReceiptError()
        finalized, finalized_raw, finalized_metadata = (
            load_unique_json_with_bytes_and_metadata(
                finalized_path,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
        )
        if (
            receipt["result_final_manifest"]
            != _manifest_selector(finalized_path, finalized, finalized_raw)
            or not _matching_digest(
                canonical_payload_sha256(finalized),
                expected_manifest_payload_sha256,
            )
            or not _matching_digest(
                hashlib.sha256(finalized_raw).hexdigest(),
                expected_manifest_file_sha256,
            )
        ):
            raise AcceptanceReceiptError()
        phase0 = receipt["phase0_snapshot"]
        if os.path.abspath(phase0_checkpoint_path) != phase0["checkpoint"]["path"]:
            raise AcceptanceReceiptError()
        snapshot_acceptance = load_snapshot_acceptance(
            phase0_checkpoint_path,
            Path(phase0["receipt"]["path"]),
            expected_receipt_payload_sha256=phase0["receipt"]["payload_sha256"],
            expected_receipt_file_sha256=phase0["receipt"]["file_sha256"],
        )
        if (
            phase0["checkpoint"]
            != snapshot_acceptance.receipt["result_checkpoint"]
            or phase0["receipt"]
            != _receipt_selector(
                Path(phase0["receipt"]["path"]),
                snapshot_acceptance.receipt,
                snapshot_acceptance.receipt_raw,
            )
        ):
            raise AcceptanceReceiptError()
        source = receipt["source_generation"]
        lineage = load_generation_lineage(
            Path(source["manifest"]["path"]),
            Path(source["receipt"]["path"]),
            expected_receipt_payload_sha256=source["receipt"]["payload_sha256"],
            expected_receipt_file_sha256=source["receipt"]["file_sha256"],
            expected_manifest_payload_sha256=source["manifest"]["payload_sha256"],
            expected_manifest_file_sha256=source["manifest"]["file_sha256"],
        )
        snapshot_source = snapshot_acceptance.receipt["source_generation"]
        if not (
            source
            == _generation_selection(
                lineage,
                Path(source["manifest"]["path"]),
                Path(source["receipt"]["path"]),
            )
            and finalized == lineage.manifest
            and hmac.compare_digest(finalized_raw, lineage.manifest_raw)
            and generation_lineage_contains(
                lineage,
                snapshot_source["manifest"],
                snapshot_source["receipt"],
            )
        ):
            raise AcceptanceReceiptError()
    except AcceptanceReceiptError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        StableFileError,
        GenerationLineageError,
    ) as error:
        raise AcceptanceReceiptError() from error
    acceptance = FinalizationAcceptance(
        receipt,
        receipt_raw,
        receipt_metadata,
        finalized,
        finalized_raw,
        finalized_metadata,
        lineage,
        snapshot_acceptance,
        (
            _Snapshot(receipt_path, receipt_raw, receipt_metadata),
            _Snapshot(finalized_path, finalized_raw, finalized_metadata),
        ),
    )
    recheck_finalization_acceptance(acceptance)
    return acceptance
