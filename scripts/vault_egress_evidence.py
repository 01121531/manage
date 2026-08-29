"""Validate a sealed metadata-only Vault isolation and Sub2 egress evidence index."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    selector_errors as release_execution_selector_errors,
)
from platform.uploads import _origin_key
from scripts.verify_vault_isolation import load_assets, validate_vault_isolation


EVIDENCE_INDEX = (
    ROOT / "deploy" / "evidence-index-envelopes" / "vault-egress.synthetic.json"
)

REQUIRED_SCENARIO_OBSERVATIONS = {
    "vault_api_cards_allowed": "read_succeeded",
    "vault_api_mailboxes_denied": "permission_denied",
    "vault_api_sub2_credential_denied": "permission_denied",
    "vault_api_sub2_proxy_denied": "permission_denied",
    "vault_mail_cards_denied": "permission_denied",
    "vault_mail_mailboxes_allowed": "read_succeeded",
    "vault_mail_sub2_credential_denied": "permission_denied",
    "vault_mail_sub2_proxy_denied": "permission_denied",
    "vault_sub2_cards_allowed": "read_succeeded",
    "vault_sub2_mailboxes_denied": "permission_denied",
    "vault_sub2_credential_allowed": "read_succeeded",
    "vault_sub2_proxy_allowed": "read_succeeded",
    "sub2_application_approved_origin_allowed": "request_reached_reviewed_origin",
    "sub2_application_unapproved_origin_denied": "rejected_before_secret_or_network_access",
    "sub2_application_unapproved_port_denied": "rejected_before_secret_or_network_access",
    "sub2_application_similar_suffix_denied": "rejected_before_secret_or_network_access",
    "sub2_network_approved_destination_allowed": "destination_connection_allowed",
    "sub2_network_unapproved_destination_denied": "destination_connection_denied",
}

_PAYLOAD_KEYS = {
    "schema_version",
    "record_type",
    "index_reference",
    "synthetic",
    "index_status",
    "review_reference",
    "production_acceptance",
    "environment",
    "bindings",
    "window",
    "release_execution",
    "scenarios",
    "prohibited_content",
}
_SEALED_KEYS = _PAYLOAD_KEYS | {"integrity"}
_BINDING_KEYS = {
    "release_tag",
    "release_commit",
    "container_manifest_sha256",
    "sub2_contract_sha256",
    "target_platform_inventory_sha256",
}
_WINDOW_KEYS = {"started_at", "finished_at"}
_SCENARIO_KEYS = {
    "execution_reference",
    "executor_reference",
    "reviewer_reference",
    "trace_reference",
    "executed_at",
    "observation",
    "result",
    "evidence_object_reference",
    "evidence_sha256",
    "redaction_confirmed",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_vault_responses",
    "contains_provider_payloads",
    "contains_request_or_response_bodies",
    "contains_provider_urls",
    "contains_pan_values",
    "contains_cvv_values",
    "contains_verification_code_values",
    "contains_token_values",
}
_INTEGRITY_KEYS = {"payload_sha256"}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PLACEHOLDERS = {"example", "local", "placeholder", "tbd", "test", "todo", "unknown"}
_FORBIDDEN_REFERENCE_FRAGMENT = re.compile(
    r"(?:^|[._:-])(?:password|passwd|bearer|authorization|api[-_]?key|secret|"
    r"credential|cvv|pan|token)(?:$|[._:-])",
    re.IGNORECASE,
)


def _canonical_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def seal_index(payload: dict[str, Any]) -> dict[str, Any]:
    sealed = json.loads(json.dumps(payload))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
        and _FORBIDDEN_REFERENCE_FRAGMENT.search(value) is None
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _payload_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 2
        or payload.get("record_type") != "vault_egress_evidence_index"
    ):
        errors.append("Vault/egress evidence index identity is invalid")
    if payload.get("production_acceptance") is not False:
        errors.append("Vault/egress evidence index must not claim production acceptance")

    prohibited = payload.get("prohibited_content")
    if (
        not _exact_mapping(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("Vault/egress evidence prohibited-content declaration is invalid")
    bindings = payload.get("bindings")
    window = payload.get("window")
    scenarios = payload.get("scenarios")
    if not _exact_mapping(bindings, _BINDING_KEYS):
        errors.append("Vault/egress evidence binding schema is invalid")
    if not _exact_mapping(window, _WINDOW_KEYS):
        errors.append("Vault/egress evidence window schema is invalid")
    if not _exact_mapping(scenarios, set(REQUIRED_SCENARIO_OBSERVATIONS)):
        errors.append("Vault/egress evidence scenario inventory is invalid")

    synthetic = payload.get("synthetic")
    reference = payload.get("index_reference")
    review_reference = payload.get("review_reference")
    environment = payload.get("environment")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append("Vault/egress evidence index reference is invalid")
        return errors

    if synthetic:
        if (
            not reference.startswith("synthetic-")
            or payload.get("index_status") != "pending"
            or review_reference is not None
            or environment != "production"
            or not isinstance(bindings, dict)
            or any(value is not None for value in bindings.values())
            or window != {"started_at": None, "finished_at": None}
            or release_execution_selector_errors(
                payload.get("release_execution"), synthetic=True
            )
            or not isinstance(scenarios, dict)
            or any(value is not None for value in scenarios.values())
        ):
            errors.append("synthetic Vault/egress evidence index metadata is invalid")
        return errors

    if (
        reference.startswith("synthetic-")
        or payload.get("index_status") != "reviewed"
        or not _safe_reference(review_reference)
        or reference == review_reference
    ):
        errors.append("reviewed Vault/egress evidence index metadata is invalid")
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed Vault/egress evidence environment is invalid")

    if isinstance(bindings, dict):
        if (
            not isinstance(bindings.get("release_tag"), str)
            or _TAG.fullmatch(bindings["release_tag"]) is None
            or not isinstance(bindings.get("release_commit"), str)
            or _COMMIT.fullmatch(bindings["release_commit"]) is None
            or any(
                not isinstance(bindings.get(key), str)
                or _SHA256.fullmatch(bindings[key]) is None
                for key in (
                    "container_manifest_sha256",
                    "sub2_contract_sha256",
                    "target_platform_inventory_sha256",
                )
            )
        ):
            errors.append("reviewed Vault/egress evidence release or intake binding is invalid")
    errors.extend(
        f"Vault/egress evidence {error}"
        for error in release_execution_selector_errors(
            payload.get("release_execution"),
            synthetic=False,
            environment=(environment if isinstance(environment, str) else None),
        )
    )

    started_at = _parse_utc(window.get("started_at")) if isinstance(window, dict) else None
    finished_at = _parse_utc(window.get("finished_at")) if isinstance(window, dict) else None
    if started_at is None or finished_at is None or finished_at <= started_at:
        errors.append("reviewed Vault/egress evidence window is invalid")

    unique_fields: dict[str, list[str]] = {
        "execution_reference": [],
        "trace_reference": [],
        "evidence_object_reference": [],
        "evidence_sha256": [],
    }
    if isinstance(scenarios, dict):
        for scenario, expected_observation in REQUIRED_SCENARIO_OBSERVATIONS.items():
            result = scenarios.get(scenario)
            if not _exact_mapping(result, _SCENARIO_KEYS):
                errors.append(f"Vault/egress evidence {scenario} scenario schema is invalid")
                continue
            reference_fields = (
                "execution_reference",
                "executor_reference",
                "reviewer_reference",
                "trace_reference",
                "evidence_object_reference",
            )
            if not all(_safe_reference(result.get(key)) for key in reference_fields):
                errors.append(f"Vault/egress evidence {scenario} references are invalid")
            elif result["executor_reference"] == result["reviewer_reference"]:
                errors.append(f"Vault/egress evidence {scenario} reviewer is not independent")
            if (
                result.get("observation") != expected_observation
                or result.get("result") != "passed"
                or result.get("redaction_confirmed") is not True
            ):
                errors.append(f"Vault/egress evidence {scenario} result is invalid")
            executed_at = _parse_utc(result.get("executed_at"))
            if (
                executed_at is None
                or started_at is None
                or finished_at is None
                or not started_at <= executed_at <= finished_at
            ):
                errors.append(f"Vault/egress evidence {scenario} timestamp is outside the window")
            digest = result.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append(f"Vault/egress evidence {scenario} artifact digest is invalid")
            for key in unique_fields:
                value = result.get(key)
                if isinstance(value, str):
                    unique_fields[key].append(value)
    for field, values in unique_fields.items():
        if len(values) != len(set(values)):
            errors.append(f"Vault/egress evidence {field} values must be unique")
    return errors


def index_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or set(document) != _SEALED_KEYS:
        return ["Vault/egress evidence index top-level schema is invalid"]
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    if (
        not _exact_mapping(integrity, _INTEGRITY_KEYS)
        or not isinstance(integrity.get("payload_sha256"), str)
        or _SHA256.fullmatch(integrity["payload_sha256"]) is None
        or integrity["payload_sha256"] != _canonical_digest(payload)
    ):
        return ["Vault/egress evidence index integrity is invalid"]
    return _payload_errors(payload)


def intake_binding_errors(document: Any, manifest: Any) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), dict):
        return ["Vault/egress evidence bindings are invalid"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("items"), list):
        return ["Vault/egress evidence intake manifest is invalid"]
    errors: list[str] = []
    if document.get("environment") != manifest.get("environment"):
        errors.append("Vault/egress evidence environment does not match this intake manifest")
    release_execution = document.get("release_execution")
    target_intake = (
        release_execution.get("target_intake")
        if isinstance(release_execution, dict)
        else None
    )
    if (
        not isinstance(target_intake, dict)
        or target_intake.get("environment") != manifest.get("environment")
        or target_intake.get("requirements_sha256")
        != manifest.get("requirements_sha256")
        or target_intake.get("checkpoint_phase") != 0
    ):
        errors.append(
            "Vault/egress evidence release execution intake does not match this intake manifest"
        )
    for identifier, binding_key in (
        ("sub2_contract", "sub2_contract_sha256"),
        ("target_platform_inventory", "target_platform_inventory_sha256"),
    ):
        matches = [
            item
            for item in manifest["items"]
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        if (
            len(matches) != 1
            or matches[0].get("status") != "provided"
            or not isinstance(matches[0].get("sha256"), str)
            or _SHA256.fullmatch(matches[0]["sha256"]) is None
        ):
            errors.append(f"Vault/egress evidence {identifier} binding target is not provided")
        elif document["bindings"].get(binding_key) != matches[0]["sha256"]:
            errors.append(
                f"Vault/egress evidence {identifier} binding does not match this intake manifest"
            )
    return errors


def repository_control_errors() -> list[str]:
    """Check repository policy/origin controls without claiming target execution."""

    try:
        errors = validate_vault_isolation(*load_assets())
    except (OSError, ValueError) as error:
        return [f"repository Vault control assets are unavailable: {error}"]
    try:
        approved = _origin_key("https://sub2-upload.invalid", allow_path=False)
        if approved != _origin_key(
            "https://sub2-upload.invalid/api/upload", allow_path=True
        ):
            errors.append("Sub2 reviewed origin is not accepted exactly")
        for candidate in (
            "https://other.invalid/api/upload",
            "https://sub2-upload.invalid:8443/api/upload",
            "https://sub2-upload.invalid.evil/api/upload",
        ):
            if _origin_key(candidate, allow_path=True) == approved:
                errors.append("Sub2 unapproved origin boundary is not exact")
    except ValueError:
        errors.append("Sub2 exact HTTPS origin control is unavailable")
    return errors


def _load(path: Path, *, max_bytes: int | None = None) -> Any:
    if max_bytes is None:
        return load_unique_json(path)
    return load_unique_json(path, max_bytes=max_bytes)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    check.add_argument("--intake-manifest", required=True, type=Path)
    check.add_argument("--release-execution-evidence", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        try:
            document = _load(EVIDENCE_INDEX)
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("vault-egress-evidence-index-invalid", file=sys.stderr)
            return 1
        errors = index_errors(document) + repository_control_errors()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print("vault-egress-evidence-index-ok status=pending production_acceptance=false")
        return 0
    try:
        document = _load(arguments.input)
        manifest = _load(
            arguments.intake_manifest,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("vault-egress-evidence-index-invalid", file=sys.stderr)
        return 1
    errors = index_errors(document)
    if not errors and document.get("synthetic") is not False:
        errors.append("Vault/egress evidence index must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    control_errors = repository_control_errors()
    if control_errors:
        print("; ".join(control_errors), file=sys.stderr)
        return 3
    binding_errors = intake_binding_errors(document, manifest)
    if arguments.release_execution_evidence is None:
        binding_errors.append("Vault/egress evidence requires release execution evidence")
    else:
        bindings = document.get("bindings", {})
        binding_errors += release_execution_alignment_errors(
            document.get("release_execution"),
            arguments.release_execution_evidence,
            environment=document.get("environment"),
            release_tag=bindings.get("release_tag"),
            release_commit=bindings.get("release_commit"),
            container_manifest_sha256=bindings.get("container_manifest_sha256"),
        )
    if binding_errors:
        print("; ".join(binding_errors), file=sys.stderr)
        return 2
    print("vault-egress-evidence-index-bound production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
