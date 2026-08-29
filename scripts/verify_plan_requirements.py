"""Verify the Chapters 1-11 requirement inventory and its evidence boundary."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    load_unique_json,
    read_stable_bytes,
)
from scripts.external_text import load_stable_text

INVENTORY = ROOT / "deploy" / "plan-requirement-inventory.json"
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"
MAX_PLAN_SOURCE_BYTES = 5 * 1024 * 1024
MAX_QUALITY_GATE_BYTES = 64 * 1024

CLASSIFICATIONS = (
    "repository_proven",
    "indirect_only",
    "missing_implementation",
    "external_input_required",
    "target_evidence_required",
)
CHAPTER_COUNTS = {1: 9, 2: 3, 3: 5, 4: 4, 5: 5, 6: 4, 7: 5, 8: 4, 9: 5, 10: 2, 11: 5}
EXPECTED_IDS = tuple(
    f"R{chapter:02d}.{index:02d}"
    for chapter, count in CHAPTER_COUNTS.items()
    for index in range(1, count + 1)
)
NON_REPOSITORY_CLASSIFICATIONS = {
    "R01.07": "external_input_required",
    "R04.02": "external_input_required",
    "R05.01": "external_input_required",
    "R06.02": "repository_proven",
    "R07.03": "target_evidence_required",
    "R11.01": "target_evidence_required",
    "R11.02": "target_evidence_required",
    "R11.03": "target_evidence_required",
    "R11.05": "target_evidence_required",
}

_TOP_LEVEL_KEYS = {
    "schema_version", "record_type", "source", "inventory_status",
    "production_acceptance", "classifications", "requirements", "summary",
    "integrity",
}
_SOURCE_KEYS = {"path", "sha256", "chapters"}
_REQUIREMENT_KEYS = {
    "id", "chapter", "source_ref", "requirement", "classification",
    "evidence", "gap_or_boundary",
}
_SUMMARY_KEYS = {"total", *CLASSIFICATIONS}
_INTEGRITY_KEYS = {"payload_sha256"}
_MAX_PROVEN_EVIDENCE = 6


def _is_verification_evidence(path: str) -> bool:
    return (
        path.startswith("tests/")
        or path.startswith("platform/tests/")
        or path.startswith("frontend/e2e/")
        or path.startswith("scripts/verify_")
        or path in {"scripts/quality_gate.ps1", "scripts/secret_scan.py"}
    )


def evidence_contract_errors(entry: dict[str, Any]) -> list[str]:
    evidence = entry.get("evidence")
    if not isinstance(evidence, list) or any(
        not isinstance(path, str) for path in evidence
    ):
        return ["evidence inventory is invalid"]
    errors: list[str] = []
    if len(evidence) > _MAX_PROVEN_EVIDENCE:
        errors.append("evidence is not minimal")
    if not any(not _is_verification_evidence(path) for path in evidence):
        errors.append("direct implementation or contract evidence is missing")
    if not any(_is_verification_evidence(path) for path in evidence):
        errors.append("verification evidence is missing")
    return errors


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def _is_exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def inventory_errors(document: Any, *, check_files: bool = False) -> list[str]:
    if not _is_exact_mapping(document, _TOP_LEVEL_KEYS):
        return ["plan requirement inventory top-level schema is invalid"]
    payload = {key: value for key, value in document.items() if key != "integrity"}
    integrity = document.get("integrity")
    if (
        not _is_exact_mapping(integrity, _INTEGRITY_KEYS)
        or integrity.get("payload_sha256") != _canonical_digest(payload)
    ):
        return ["plan requirement inventory integrity is invalid"]

    errors: list[str] = []
    source = payload.get("source")
    if (
        payload.get("schema_version") != 1
        or payload.get("record_type") != "plan_requirement_inventory"
        or payload.get("inventory_status") != "repository_evidence_classification"
        or payload.get("production_acceptance") is not False
        or payload.get("classifications") != list(CLASSIFICATIONS)
        or not _is_exact_mapping(source, _SOURCE_KEYS)
        or source.get("path") != "docs/邮箱验证码助手_平台化建设方案.docx"
        or source.get("chapters") != list(CHAPTER_COUNTS)
    ):
        errors.append("plan requirement inventory identity is invalid")

    requirements = payload.get("requirements")
    if not isinstance(requirements, list):
        return errors + ["plan requirement entries are invalid"]
    ids = [entry.get("id") for entry in requirements if isinstance(entry, dict)]
    if ids != list(EXPECTED_IDS):
        errors.append("plan requirement ids are incomplete or out of order")

    counts: Counter[str] = Counter()
    for position, entry in enumerate(requirements):
        if not _is_exact_mapping(entry, _REQUIREMENT_KEYS):
            errors.append(f"plan requirement entry {position} schema is invalid")
            continue
        requirement_id = entry["id"]
        expected_classification = NON_REPOSITORY_CLASSIFICATIONS.get(
            requirement_id, "repository_proven"
        )
        classification = entry["classification"]
        if classification != expected_classification:
            errors.append(f"{requirement_id} classification is invalid")
        counts[classification] += 1
        if entry["chapter"] != int(requirement_id[1:3]):
            errors.append(f"{requirement_id} chapter binding is invalid")
        for key in ("source_ref", "requirement"):
            if not isinstance(entry[key], str) or not entry[key].strip():
                errors.append(f"{requirement_id} {key} is invalid")
        evidence = entry["evidence"]
        if (
            not isinstance(evidence, list)
            or len(evidence) < 2
            or any(not isinstance(path, str) or not path.strip() for path in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            errors.append(f"{requirement_id} evidence inventory is invalid")
        elif check_files:
            for relative in evidence:
                candidate = Path(relative)
                if candidate.is_absolute() or ".." in candidate.parts:
                    errors.append(f"{requirement_id} evidence path escapes repository")
                elif not (ROOT / candidate).exists():
                    errors.append(f"{requirement_id} evidence path is unavailable")
        if classification == "repository_proven":
            errors.extend(
                f"{requirement_id} {error}"
                for error in evidence_contract_errors(entry)
            )
        boundary = entry["gap_or_boundary"]
        if classification == "repository_proven":
            if boundary is not None:
                errors.append(f"{requirement_id} proven entry carries a gap")
        elif not isinstance(boundary, str) or not boundary.strip():
            errors.append(f"{requirement_id} boundary is missing")

    expected_summary = {"total": len(EXPECTED_IDS)}
    expected_summary.update({key: counts.get(key, 0) for key in CLASSIFICATIONS})
    if payload.get("summary") != expected_summary or not _is_exact_mapping(
        payload.get("summary"), _SUMMARY_KEYS
    ):
        errors.append("plan requirement summary is invalid")

    if check_files and isinstance(source, dict):
        source_path = ROOT / source.get("path", "")
        try:
            source_bytes = read_stable_bytes(
                source_path,
                max_bytes=MAX_PLAN_SOURCE_BYTES,
            )
            source_digest = hashlib.sha256(source_bytes).hexdigest()
        except OSError:
            errors.append("plan source document is unavailable")
        else:
            if source_digest != source.get("sha256"):
                errors.append("plan source document digest has drifted")
        try:
            gate = load_stable_text(
                QUALITY_GATE,
                max_bytes=MAX_QUALITY_GATE_BYTES,
            )
        except (OSError, UnicodeError):
            errors.append("plan requirement quality gate is unavailable")
        else:
            if "python scripts/verify_plan_requirements.py" not in gate:
                errors.append("plan requirement verifier is not active in quality gate")
    return errors


def main() -> int:
    try:
        document = load_unique_json(
            INVENTORY,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("plan-requirement-inventory-invalid", file=sys.stderr)
        return 1
    errors = inventory_errors(document, check_files=True)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    summary = document["summary"]
    print(
        "plan-requirement-inventory-ok "
        f"total={summary['total']} repository_proven={summary['repository_proven']} "
        f"missing_implementation={summary['missing_implementation']} "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
