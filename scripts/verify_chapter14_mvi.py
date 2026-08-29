"""Verify the Chapter 14 minimum viable flow remains a local preflight contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.external_text import load_stable_text
from scripts.phase6_pilot_evidence import EXECUTION_SCOPE, REQUIRED_SCENARIOS
from scripts.phase6_rehearsal import (
    SCENARIO,
    _CHECK_KEYS,
    _PERSISTENT_SURFACES,
    _RESOURCE_STATES,
)


CONTRACT = ROOT / "deploy" / "chapter14-mvi-contract.json"
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"

EXTERNAL_REQUIREMENTS = (
    "target_oidc_identity",
    "reviewed_real_mail_connector",
    "reviewed_real_sub2_connector",
    "target_postgresql_and_redis_runtime",
    "target_vault_and_network_controls",
    "target_tls_and_public_edge",
    "independent_external_evidence_review",
)
VERIFIER_COMMANDS = (
    "python scripts/phase6_rehearsal.py run",
    "python scripts/phase6_rehearsal.py verify",
    "python scripts/phase6_pilot_evidence.py verify-repository",
)

_PAYLOAD_KEYS = {
    "schema_version", "record_type", "plan_chapter", "repository_status",
    "production_acceptance", "identity_mode", "scenario", "checks",
    "resource_states", "persistent_surfaces", "target_execution_required",
    "external_requirements", "verifier_commands",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_INTEGRITY_KEYS = {"payload_sha256"}


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_contract(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def contract_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Chapter 14 MVI contract top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not isinstance(integrity, dict)
        or set(integrity) != _INTEGRITY_KEYS
        or integrity.get("payload_sha256") != _canonical_digest(payload)
    ):
        return ["Chapter 14 MVI contract integrity is invalid"]
    errors: list[str] = []
    if (
        payload.get("schema_version") != 1
        or payload.get("record_type") != "minimum_viable_flow_contract"
        or payload.get("plan_chapter") != "14"
        or payload.get("repository_status") != "local_ci_rehearsal_only"
        or payload.get("identity_mode") != "local_test"
        or payload.get("scenario") != SCENARIO
        or payload.get("target_execution_required") is not True
    ):
        errors.append("Chapter 14 MVI identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Chapter 14 MVI must not claim production acceptance")
    if payload.get("checks") != sorted(_CHECK_KEYS):
        errors.append("Chapter 14 MVI check inventory is invalid")
    if payload.get("resource_states") != _RESOURCE_STATES:
        errors.append("Chapter 14 MVI resource states are invalid")
    if payload.get("persistent_surfaces") != _PERSISTENT_SURFACES:
        errors.append("Chapter 14 MVI persistent-surface inventory is invalid")
    if payload.get("external_requirements") != list(EXTERNAL_REQUIREMENTS):
        errors.append("Chapter 14 MVI external requirements are invalid")
    if payload.get("verifier_commands") != list(VERIFIER_COMMANDS):
        errors.append("Chapter 14 MVI verifier inventory is invalid")
    return errors


def repository_contract_errors(*, gate_text: str | None = None) -> list[str]:
    errors: list[str] = []
    if set(_CHECK_KEYS) != set(REQUIRED_SCENARIOS):
        errors.append("Chapter 14 CI and target-pilot dimensions have drifted")
    if EXECUTION_SCOPE != {
        "origin": "target_environment",
        "identity_mode": "oidc",
        "connector_mode": "reviewed_real_mail_and_sub2",
        "evidence_policy": "repository_external_worm_metadata_only",
    }:
        errors.append("Chapter 14 target execution boundary has drifted")
    try:
        gate = load_stable_text(QUALITY_GATE) if gate_text is None else gate_text
    except (OSError, UnicodeError):
        return errors + ["Chapter 14 quality gate is unavailable"]
    for command in VERIFIER_COMMANDS:
        if command not in gate:
            errors.append("Chapter 14 verifier is not active in the quality gate")
    return errors


def main() -> int:
    try:
        document = load_unique_json(
            CONTRACT,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("chapter14-mvi-contract-invalid", file=sys.stderr)
        return 1
    errors = contract_errors(document) + repository_contract_errors()
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "chapter14-mvi-contract-ok repository_status=local_ci_rehearsal_only "
        "production_acceptance=false target_execution=pending"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
