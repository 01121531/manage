"""Render and execute exact, evidence-bound Vault smoke-canary cleanup."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable
from uuid import UUID

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from scripts.backup_output_policy import (
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.secure_import_vault_smoke import (
    MAX_RESPONSE_BYTES,
    SmokeFailure,
    VaultClient,
    VaultResponse,
    _canonical_bytes,
    _external_regular_file,
    _json_data,
    _read_token,
    _vault_origin,
    load_smoke_plan,
    smoke_plan_errors,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "environment",
    "vault_origin_sha256",
    "run_id",
    "smoke_plan_payload_sha256",
    "smoke_plan_file_sha256",
    "cleanup_policy_sha256",
    "started_at",
    "finished_at",
    "result",
    "error_code",
    "cleanup_required",
    "canary_data_paths",
    "canary_metadata_paths",
    "checks",
    "prohibited_content",
}
_CHECK_KEYS = {
    "pre_data_status",
    "pre_metadata_status",
    "pre_state",
    "delete_status",
    "post_data_status",
    "post_metadata_status",
    "result",
}
_PROHIBITED_KEYS = {
    "contains_token_values",
    "contains_response_bodies",
    "contains_signatures",
    "contains_pool_secrets",
    "contains_vault_origin",
}


class CleanupFailure(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def cleanup_policy_name(run_id: str) -> str:
    return "email-platform-secure-import-cleanup-" + str(UUID(run_id)).replace("-", "")


def render_cleanup_policy(plan: dict[str, object]) -> str:
    if smoke_plan_errors(plan):
        raise CleanupFailure("smoke_plan_invalid")
    data_paths = plan["canary_data_paths"]
    metadata_paths = plan["canary_metadata_paths"]
    assert isinstance(data_paths, list) and isinstance(metadata_paths, list)
    lines = [
        "# Exact per-run policy; never replace these paths with a wildcard.",
        'path "sys/capabilities-self" {',
        '  capabilities = ["update"]',
        "}",
    ]
    for path in data_paths:
        lines.extend([
            "",
            f'path "{path}" {{',
            '  capabilities = ["read"]',
            "}",
        ])
    for path in metadata_paths:
        lines.extend([
            "",
            f'path "{path}" {{',
            '  capabilities = ["read", "delete"]',
            "}",
        ])
    return "\n".join(lines) + "\n"


def _write_once_bytes(path: Path | str, raw: bytes) -> None:
    try:
        output = prepare_write_once_file(path)
        temporary = write_fsynced_temporary_bytes(output, raw)
        publish_write_once_file(temporary, output)
    except (OSError, ValueError):
        raise CleanupFailure("cleanup_output_invalid") from None


def _load_policy(
    path_value: str,
    *,
    expected_sha256: str,
    expected_text: str,
) -> str:
    if _SHA256.fullmatch(expected_sha256) is None:
        raise CleanupFailure("cleanup_policy_pin_invalid")
    path = _external_regular_file(path_value, label="cleanup_policy")
    try:
        raw, _ = read_stable_runtime_bytes_with_metadata(path, max_bytes=MAX_RESPONSE_BYTES)
        text = raw.decode("ascii")
    except (OSError, UnicodeError):
        raise CleanupFailure("cleanup_policy_invalid") from None
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CleanupFailure("cleanup_policy_pin_invalid")
    if text != expected_text:
        raise CleanupFailure("cleanup_policy_invalid")
    return expected_sha256


def _empty_check() -> dict[str, object]:
    return {
        "pre_data_status": None,
        "pre_metadata_status": None,
        "pre_state": "not_run",
        "delete_status": None,
        "post_data_status": None,
        "post_metadata_status": None,
        "result": "not_run",
    }


def _preflight_canary(
    client: VaultClient,
    *,
    run_id: str,
    data_path: str,
    metadata_path: str,
    check: dict[str, object],
) -> None:
    data_response = client.request("GET", data_path)
    metadata_response = client.request("GET", metadata_path)
    check["pre_data_status"] = data_response.status
    check["pre_metadata_status"] = metadata_response.status
    if data_response.status == 404 and metadata_response.status == 404:
        check["pre_state"] = "already_absent"
        return
    if data_response.status != 200 or metadata_response.status != 200:
        raise CleanupFailure("canary_state_invalid")
    data = _json_data(data_response)
    if data.get("data") != {"smoke_canary": run_id}:
        raise CleanupFailure("canary_content_invalid")
    _json_data(metadata_response)
    check["pre_state"] = "present"


def _verify_capabilities(
    client: VaultClient,
    data_paths: list[str],
    metadata_paths: list[str],
) -> None:
    expected = {
        **{path: {"read"} for path in data_paths},
        **{path: {"read", "delete"} for path in metadata_paths},
    }
    response = client.request(
        "POST",
        "sys/capabilities-self",
        {"paths": [*data_paths, *metadata_paths]},
    )
    if response.status != 200:
        raise CleanupFailure("cleanup_capabilities_invalid")
    data = _json_data(response)
    if set(data) != set(expected) or any(
        not isinstance(data.get(path), list)
        or set(data[path]) != capabilities
        for path, capabilities in expected.items()
    ):
        raise CleanupFailure("cleanup_capabilities_invalid")


def _seal_receipt(payload: dict[str, object]) -> dict[str, object]:
    document = dict(payload)
    document["integrity"] = {
        "payload_sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    }
    return document


def _write_receipt(path: Path | str, payload: dict[str, object]) -> None:
    document = _seal_receipt(payload)
    _write_once_bytes(Path(path), _canonical_bytes(document) + b"\n")


def cleanup_receipt_errors(document: object) -> list[str]:
    if not isinstance(document, dict) or set(document) != _RECEIPT_KEYS | {"integrity"}:
        return ["secure import cleanup receipt schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "secure_import_vault_canary_cleanup"
        or document.get("production_acceptance") is not False
    ):
        errors.append("secure import cleanup receipt identity is invalid")
    try:
        source_run_id = document.get("run_id")
        run_id = str(UUID(str(source_run_id)))
        if run_id != source_run_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        run_id = ""
        errors.append("secure import cleanup run identity is invalid")
    for name in (
        "vault_origin_sha256",
        "smoke_plan_payload_sha256",
        "smoke_plan_file_sha256",
        "cleanup_policy_sha256",
    ):
        value = document.get(name)
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            errors.append(f"secure import cleanup {name} is invalid")
    environment = document.get("environment")
    if not isinstance(environment, str) or _ENVIRONMENT.fullmatch(environment) is None:
        errors.append("secure import cleanup environment is invalid")
    if not _utc_timestamp(document.get("started_at")) or not _utc_timestamp(
        document.get("finished_at")
    ):
        errors.append("secure import cleanup timestamp is invalid")
    if run_id:
        data_paths = [
            f"secret/data/cards/imports/smoke/{run_id}",
            f"secret/data/mailboxes/imports/smoke/{run_id}",
        ]
        if document.get("canary_data_paths") != data_paths:
            errors.append("secure import cleanup data paths are invalid")
        if document.get("canary_metadata_paths") != [
            path.replace("/data/", "/metadata/", 1) for path in data_paths
        ]:
            errors.append("secure import cleanup metadata paths are invalid")
    checks = document.get("checks")
    if not isinstance(checks, dict) or set(checks) != {"card", "mailbox"}:
        errors.append("secure import cleanup checks are invalid")
        checks = {}
    for name in ("card", "mailbox"):
        check = checks.get(name)
        if not isinstance(check, dict) or set(check) != _CHECK_KEYS:
            errors.append(f"secure import cleanup {name} check is invalid")
            continue
        for status_name in (
            "pre_data_status",
            "pre_metadata_status",
            "delete_status",
            "post_data_status",
            "post_metadata_status",
        ):
            status = check[status_name]
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                errors.append(f"secure import cleanup {name} status is invalid")
        if check["pre_state"] not in {"not_run", "already_absent", "present"}:
            errors.append(f"secure import cleanup {name} pre-state is invalid")
        if check["result"] not in {"not_run", "failed", "confirmed_absent"}:
            errors.append(f"secure import cleanup {name} result is invalid")
    result = document.get("result")
    cleanup_required = document.get("cleanup_required")
    error_code = document.get("error_code")
    if result == "confirmed_absent":
        if cleanup_required is not False or error_code is not None:
            errors.append("secure import cleanup success is invalid")
        for check in checks.values():
            if (
                check.get("result") != "confirmed_absent"
                or check.get("post_data_status") != 404
                or check.get("post_metadata_status") != 404
            ):
                errors.append("secure import cleanup absence proof is invalid")
                break
    elif result == "failed":
        if cleanup_required is not True or not isinstance(error_code, str):
            errors.append("secure import cleanup failure is invalid")
    else:
        errors.append("secure import cleanup result is invalid")
    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("secure import cleanup redaction claim is invalid")
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    expected_digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or integrity.get("payload_sha256") != expected_digest
    ):
        errors.append("secure import cleanup receipt integrity is invalid")
    return errors


def verify_cleanup_receipt(path_value: str) -> dict[str, object]:
    path = _external_regular_file(path_value, label="cleanup_receipt")
    try:
        raw, _ = read_stable_runtime_bytes_with_metadata(path, max_bytes=MAX_RESPONSE_BYTES)
        document = parse_unique_json_bytes(raw)
    except (OSError, JsonBoundaryError):
        raise CleanupFailure("cleanup_receipt_invalid") from None
    if cleanup_receipt_errors(document) or not isinstance(document, dict):
        raise CleanupFailure("cleanup_receipt_invalid")
    return dict(document)


def execute(
    args: argparse.Namespace,
    *,
    client_factory: Callable[..., VaultClient] = VaultClient,
) -> tuple[dict[str, object], bool]:
    output = prepare_write_once_file(args.receipt_output)
    try:
        plan, plan_file_sha256 = load_smoke_plan(
            args.smoke_plan,
            expected_sha256=args.expected_smoke_plan_sha256,
        )
    except SmokeFailure as exc:
        raise CleanupFailure(str(exc)) from exc
    run_id = str(UUID(str(args.confirm_run_id)))
    if run_id != args.confirm_run_id or run_id != plan["run_id"]:
        raise CleanupFailure("cleanup_run_confirmation_invalid")
    policy_sha256 = _load_policy(
        args.policy_file,
        expected_sha256=args.expected_policy_sha256,
        expected_text=render_cleanup_policy(plan),
    )
    origin = _vault_origin(args.vault_address)
    origin_digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()
    if origin_digest != plan["vault_origin_sha256"]:
        raise CleanupFailure("cleanup_vault_binding_invalid")
    token_path = _external_regular_file(args.cleanup_token_file, label="cleanup_token_file")
    source_paths = {
        token_path.resolve(),
        Path(args.smoke_plan).resolve(),
        Path(args.policy_file).resolve(),
        Path(output).resolve(),
    }
    if len(source_paths) != 4:
        raise CleanupFailure("cleanup_input_paths_not_distinct")
    ca_file = _external_regular_file(args.ca_file, label="ca_file") if args.ca_file else None
    if ca_file is not None and ca_file.resolve() in source_paths:
        raise CleanupFailure("ca_file_invalid")
    client = client_factory(origin, _read_token(token_path), ca_file=ca_file)
    data_paths = list(plan["canary_data_paths"])
    metadata_paths = list(plan["canary_metadata_paths"])
    _verify_capabilities(client, data_paths, metadata_paths)

    checks = {"card": _empty_check(), "mailbox": _empty_check()}
    started_at = _utc_now()
    error_code: str | None = None
    try:
        for name, data_path, metadata_path in zip(
            ("card", "mailbox"), data_paths, metadata_paths, strict=True
        ):
            _preflight_canary(
                client,
                run_id=run_id,
                data_path=data_path,
                metadata_path=metadata_path,
                check=checks[name],
            )
        for name, metadata_path in zip(("card", "mailbox"), metadata_paths, strict=True):
            if checks[name]["pre_state"] == "present":
                response = client.request("DELETE", metadata_path)
                checks[name]["delete_status"] = response.status
                if response.status != 204:
                    checks[name]["result"] = "failed"
                    raise CleanupFailure("cleanup_delete_failed")
        for name, data_path, metadata_path in zip(
            ("card", "mailbox"), data_paths, metadata_paths, strict=True
        ):
            data_status = client.request("GET", data_path).status
            metadata_status = client.request("GET", metadata_path).status
            checks[name]["post_data_status"] = data_status
            checks[name]["post_metadata_status"] = metadata_status
            if data_status != 404 or metadata_status != 404:
                checks[name]["result"] = "failed"
                raise CleanupFailure("cleanup_absence_unconfirmed")
            checks[name]["result"] = "confirmed_absent"
    except (CleanupFailure, SmokeFailure) as error:
        error_code = str(error)

    passed = error_code is None
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "secure_import_vault_canary_cleanup",
        "production_acceptance": False,
        "environment": plan["environment"],
        "vault_origin_sha256": origin_digest,
        "run_id": run_id,
        "smoke_plan_payload_sha256": plan["integrity"]["payload_sha256"],
        "smoke_plan_file_sha256": plan_file_sha256,
        "cleanup_policy_sha256": policy_sha256,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "result": "confirmed_absent" if passed else "failed",
        "error_code": error_code,
        "cleanup_required": not passed,
        "canary_data_paths": data_paths,
        "canary_metadata_paths": metadata_paths,
        "checks": checks,
        "prohibited_content": {key: False for key in sorted(_PROHIBITED_KEYS)},
    }
    _write_receipt(output, payload)
    return payload, passed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-policy")
    run = commands.add_parser("run")
    verify = commands.add_parser("verify")
    for command in (render, run):
        command.add_argument("--smoke-plan", required=True)
        command.add_argument("--expected-smoke-plan-sha256", required=True)
        command.add_argument("--confirm-run-id", required=True)
    render.add_argument("--output", required=True)
    run.add_argument("--vault-address", required=True)
    run.add_argument("--cleanup-token-file", required=True)
    run.add_argument("--policy-file", required=True)
    run.add_argument("--expected-policy-sha256", required=True)
    run.add_argument("--receipt-output", required=True)
    run.add_argument("--ca-file")
    verify.add_argument("--input", required=True)
    return parser


def main() -> int:
    try:
        arguments = build_parser().parse_args()
        if arguments.command == "verify":
            payload = verify_cleanup_receipt(arguments.input)
            print(
                "secure-import-vault-cleanup-receipt-ok "
                f"result={payload['result']} cleanup_required={str(payload['cleanup_required']).lower()} "
                "production_acceptance=false"
            )
            return 0
        if arguments.command == "render-policy":
            plan, _ = load_smoke_plan(
                arguments.smoke_plan,
                expected_sha256=arguments.expected_smoke_plan_sha256,
            )
            if str(UUID(arguments.confirm_run_id)) != plan["run_id"]:
                raise CleanupFailure("cleanup_run_confirmation_invalid")
            _write_once_bytes(
                Path(arguments.output), render_cleanup_policy(plan).encode("ascii")
            )
            print(
                "secure-import-vault-cleanup-policy-ok "
                f"policy={cleanup_policy_name(plan['run_id'])} production_acceptance=false"
            )
            return 0
        payload, passed = execute(arguments)
    except (OSError, ValueError, SmokeFailure, CleanupFailure) as error:
        code = str(error) if isinstance(error, (SmokeFailure, CleanupFailure)) else "cleanup_preflight_failed"
        print(f"secure-import-vault-cleanup-failed: {code}", file=sys.stderr)
        return 1
    print(
        "secure-import-vault-cleanup-"
        + ("ok" if passed else "failed")
        + f" run_id={payload['run_id']} cleanup_required={str(payload['cleanup_required']).lower()} "
        "production_acceptance=false"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
