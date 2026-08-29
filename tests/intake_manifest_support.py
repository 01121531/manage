"""Test builders for the closed, repository-external intake manifest boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any

from scripts.target_intake_manifest import REQUIRED_IDS, canonical_payload_sha256


def closed_manifest(partial: dict[str, Any]) -> dict[str, Any]:
    """Expand a focused binding fixture into the exact v2 authoring shape."""

    supplied = {
        item.get("id"): item
        for item in partial.get("items", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    external = Path(tempfile.gettempdir()).resolve() / "email-1-intake-tests"
    items: list[dict[str, Any]] = []
    for identifier in REQUIRED_IDS:
        source = supplied.get(identifier)
        if source is None:
            item: dict[str, Any] = {
                "id": identifier,
                "status": "missing",
                "artifact_path": None,
                "sha256": None,
                "reviewed_by": None,
                "reviewed_at": None,
                "redaction_confirmed": None,
            }
            if identifier == "release_execution_evidence":
                item["release_execution_review_subject"] = None
        else:
            item = {
                "id": identifier,
                "status": "provided",
                "artifact_path": str(external / f"{identifier}.json"),
                "sha256": "0" * 64,
                "reviewed_by": "review-record-default",
                "reviewed_at": "2026-08-26T08:00:00Z",
                "redaction_confirmed": True,
                **source,
            }
            if identifier == "release_execution_evidence":
                item.setdefault(
                    "release_execution_review_subject",
                    {
                        "kind": "release_execution_selector_v1",
                        "selector": {
                            "ledger_type": "forward",
                            "evidence_object_reference": "worm-release-execution:fixture",
                            "evidence_sha256": item["sha256"],
                            "target_intake": {
                                "environment": partial.get("environment", "staging"),
                                "manifest_payload_sha256": "9" * 64,
                                "requirements_sha256": partial.get(
                                    "requirements_sha256", "a" * 64
                                ),
                                "checkpoint_phase": 0,
                            },
                        },
                    },
                )
        items.append(item)
    return {
        "schema_version": 2,
        "environment": partial.get("environment", "staging"),
        "production_acceptance": False,
        "requirements_sha256": partial.get("requirements_sha256", "a" * 64),
        "items": items,
    }


def bind_manifest_item_bytes(
    manifest: dict[str, Any],
    identifier: str,
    raw: bytes,
    *,
    path: Path | None = None,
) -> None:
    """Bind one provided test item to the exact bytes and optional locator."""

    matches = [item for item in manifest["items"] if item.get("id") == identifier]
    if len(matches) != 1 or matches[0].get("status") != "provided":
        raise ValueError("manifest test item must be uniquely provided")
    matches[0]["sha256"] = hashlib.sha256(raw).hexdigest()
    if path is not None:
        if not path.is_absolute():
            raise ValueError("manifest test artifact path must be absolute")
        matches[0]["artifact_path"] = str(path)


def manifest_pin_arguments(path: Path) -> list[str]:
    raw = path.read_bytes()
    document = json.loads(raw)
    return [
        "--expected-intake-manifest-payload-sha256",
        canonical_payload_sha256(document),
        "--expected-intake-manifest-file-sha256",
        hashlib.sha256(raw).hexdigest(),
    ]
