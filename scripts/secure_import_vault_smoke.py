"""Exercise the secure pool-import Vault boundary with three external tokens.

The smoke run uses synthetic canary values and emits only a redacted,
write-once result. It never creates credentials and never records Vault tokens,
signatures, response bodies, PANs, mailbox credentials, or provider data.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from typing import Callable
import urllib.error
import urllib.parse
import urllib.request
from uuid import uuid4
from uuid import UUID

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from scripts.backup_output_policy import (
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import has_link_or_reparse_ancestor


ROOT = Path(__file__).resolve().parents[1]
MAX_TOKEN_BYTES = 4096
MAX_RESPONSE_BYTES = 64 * 1024
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_SIGNATURE = re.compile(r"^vault:v[1-9][0-9]*:[A-Za-z0-9+/=_-]+$")
_CHECK_NAMES = (
    "card_create_cas_zero",
    "card_replay_cas_zero_rejected",
    "card_wrong_cas_rejected",
    "card_cross_pool_denied",
    "card_cross_key_sign_denied",
    "card_verify_denied",
    "card_key_read_denied",
    "card_sign_allowed",
    "mailbox_create_cas_zero",
    "mailbox_replay_cas_zero_rejected",
    "mailbox_wrong_cas_rejected",
    "mailbox_cross_pool_denied",
    "mailbox_cross_key_sign_denied",
    "mailbox_verify_denied",
    "mailbox_key_read_denied",
    "mailbox_sign_allowed",
    "api_card_verify_allowed",
    "api_mailbox_verify_allowed",
    "api_card_sign_denied",
    "api_mailbox_sign_denied",
    "api_card_pool_write_denied",
    "api_mailbox_pool_write_denied",
    "api_card_key_read_denied",
    "api_mailbox_key_read_denied",
)
_EXPECTED_STATUSES = {
    **{
        name: {200}
        for name in (
            "card_sign_allowed",
            "mailbox_sign_allowed",
            "api_card_verify_allowed",
            "api_mailbox_verify_allowed",
        )
    },
    "card_create_cas_zero": {200, 204},
    "mailbox_create_cas_zero": {200, 204},
    **{
        name: {400}
        for name in (
            "card_replay_cas_zero_rejected",
            "card_wrong_cas_rejected",
            "mailbox_replay_cas_zero_rejected",
            "mailbox_wrong_cas_rejected",
        )
    },
    **{
        name: {403}
        for name in _CHECK_NAMES
        if "denied" in name
    },
}
_PAYLOAD_KEYS = {
    "schema_version",
    "kind",
    "production_acceptance",
    "environment",
    "vault_origin_sha256",
    "run_id",
    "started_at",
    "finished_at",
    "result",
    "error_code",
    "cleanup_required",
    "canary_paths",
    "checks",
    "prohibited_content",
}
_PROHIBITED_KEYS = {
    "contains_token_values",
    "contains_signatures",
    "contains_response_bodies",
    "contains_pan_values",
    "contains_mailbox_credentials",
}


class SmokeFailure(RuntimeError):
    """The target boundary could not be proven exactly."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class VaultResponse:
    status: int
    body: bytes


class VaultClient:
    def __init__(self, origin: str, token: str, *, ca_file: Path | None) -> None:
        parsed = urllib.parse.urlsplit(origin.strip().rstrip("/"))
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise SmokeFailure("vault_origin_invalid")
        self.origin = urllib.parse.urlunsplit(parsed)
        self._token = token
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> VaultResponse:
        raw_body = (
            json.dumps(body, separators=(",", ":")).encode("ascii")
            if body is not None
            else None
        )
        request = urllib.request.Request(
            self.origin + "/v1/" + path.lstrip("/"),
            data=raw_body,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Vault-Request": "true",
                "X-Vault-Token": self._token,
            },
        )
        try:
            with self._opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise SmokeFailure("vault_response_invalid")
                return VaultResponse(response.status, raw)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            return VaultResponse(status, b"")
        except (urllib.error.URLError, TimeoutError, OSError):
            raise SmokeFailure("vault_request_failed") from None


def _external_regular_file(value: str, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise SmokeFailure(f"{label}_invalid")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except FileNotFoundError:
        raise SmokeFailure(f"{label}_invalid") from None
    except ValueError:
        pass
    else:
        raise SmokeFailure(f"{label}_invalid")
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & 0x400
        or metadata.st_nlink != 1
        or has_link_or_reparse_ancestor(path)
    ):
        raise SmokeFailure(f"{label}_invalid")
    return path


def _read_token(path: Path) -> str:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(
            path, max_bytes=MAX_TOKEN_BYTES
        )
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OSError
        token = raw.decode("utf-8").strip()
        if not token or any(character.isspace() for character in token):
            raise ValueError
        return token
    except (OSError, UnicodeError, ValueError):
        raise SmokeFailure("vault_token_file_invalid") from None


def _json_data(response: VaultResponse) -> dict[str, object]:
    try:
        value = parse_unique_json_bytes(response.body)
    except JsonBoundaryError:
        raise SmokeFailure("vault_response_invalid") from None
    data = value.get("data") if isinstance(value, dict) else None
    if not isinstance(data, dict):
        raise SmokeFailure("vault_response_invalid")
    return dict(data)


def _record(
    checks: dict[str, dict[str, object]],
    name: str,
    response: VaultResponse,
    expected: set[int],
) -> None:
    passed = response.status in expected
    checks[name] = {"result": "passed" if passed else "failed", "status": response.status}
    if not passed:
        raise SmokeFailure("boundary_check_failed")


def _sign(
    client: VaultClient,
    key: str,
    message: bytes,
) -> tuple[VaultResponse, str]:
    response = client.request(
        "POST",
        f"transit/sign/{key}",
        {"input": base64.b64encode(message).decode("ascii")},
    )
    if response.status != 200:
        return response, ""
    signature = _json_data(response).get("signature")
    if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
        raise SmokeFailure("vault_response_invalid")
    return response, signature


def _verify(
    client: VaultClient,
    key: str,
    message: bytes,
    signature: str,
) -> VaultResponse:
    response = client.request(
        "POST",
        f"transit/verify/{key}",
        {
            "input": base64.b64encode(message).decode("ascii"),
            "signature": signature,
        },
    )
    if response.status == 200 and _json_data(response).get("valid") is not True:
        raise SmokeFailure("vault_response_invalid")
    return response


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _write_evidence(output: Path, payload: dict[str, object]) -> None:
    document = dict(payload)
    document["integrity"] = {
        "payload_sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    }
    temporary = write_fsynced_temporary_bytes(output, _canonical_bytes(document) + b"\n")
    publish_write_once_file(temporary, output)


def evidence_errors(document: object) -> list[str]:
    if not isinstance(document, dict) or set(document) != _PAYLOAD_KEYS | {"integrity"}:
        return ["secure import smoke evidence schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "secure_import_vault_boundary_smoke"
        or document.get("production_acceptance") is not False
        or document.get("cleanup_required") is not True
    ):
        errors.append("secure import smoke evidence identity is invalid")
    environment = document.get("environment")
    if not isinstance(environment, str) or _ENVIRONMENT.fullmatch(environment) is None:
        errors.append("secure import smoke environment is invalid")
    origin_digest = document.get("vault_origin_sha256")
    if not isinstance(origin_digest, str) or re.fullmatch(r"[0-9a-f]{64}", origin_digest) is None:
        errors.append("secure import smoke Vault binding is invalid")
    try:
        run_id = str(UUID(str(document.get("run_id"))))
    except (ValueError, TypeError, AttributeError):
        run_id = ""
        errors.append("secure import smoke run identity is invalid")
    timestamps: list[datetime] = []
    for name in ("started_at", "finished_at"):
        value = document.get(name)
        try:
            parsed = datetime.fromisoformat(str(value).removesuffix("Z") + "+00:00")
        except ValueError:
            parsed = None
        if (
            not isinstance(value, str)
            or not value.endswith("Z")
            or parsed is None
            or parsed.tzinfo != timezone.utc
        ):
            errors.append(f"secure import smoke {name} is invalid")
        else:
            timestamps.append(parsed)
    if len(timestamps) == 2 and timestamps[1] < timestamps[0]:
        errors.append("secure import smoke time window is invalid")
    canary_paths = document.get("canary_paths")
    if run_id and canary_paths != [
        f"secret/data/cards/imports/smoke/{run_id}",
        f"secret/data/mailboxes/imports/smoke/{run_id}",
    ]:
        errors.append("secure import smoke canary paths are invalid")

    checks = document.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(_CHECK_NAMES):
        errors.append("secure import smoke check inventory is invalid")
        checks = {}
    check_results: list[str] = []
    for name in _CHECK_NAMES:
        check = checks.get(name)
        if (
            not isinstance(check, dict)
            or set(check) != {"result", "status"}
            or check.get("result") not in {"passed", "failed", "not_run"}
            or (
                check.get("status") is not None
                and (type(check.get("status")) is not int or not 100 <= check["status"] <= 599)
            )
        ):
            errors.append(f"secure import smoke check {name} is invalid")
            continue
        result = str(check["result"])
        status = check["status"]
        check_results.append(result)
        if result == "passed" and status not in _EXPECTED_STATUSES[name]:
            errors.append(f"secure import smoke check {name} status is invalid")
        if result == "failed" and status in _EXPECTED_STATUSES[name]:
            errors.append(f"secure import smoke check {name} failure is invalid")
        if result == "not_run" and status is not None:
            errors.append(f"secure import smoke check {name} not-run state is invalid")

    result = document.get("result")
    error_code = document.get("error_code")
    if result == "passed":
        if error_code is not None or check_results != ["passed"] * len(_CHECK_NAMES):
            errors.append("secure import smoke passed result is invalid")
    elif result == "failed":
        if not isinstance(error_code, str) or error_code not in {
            "boundary_check_failed",
            "vault_request_failed",
            "vault_response_invalid",
        }:
            errors.append("secure import smoke failed result is invalid")
        first_non_pass = next(
            (index for index, value in enumerate(check_results) if value != "passed"),
            len(check_results),
        )
        if any(value != "not_run" for value in check_results[first_non_pass + 1 :]):
            errors.append("secure import smoke failed check sequence is invalid")
    else:
        errors.append("secure import smoke result is invalid")

    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("secure import smoke redaction claim is invalid")
    integrity = document.get("integrity")
    payload = {key: value for key, value in document.items() if key != "integrity"}
    expected_digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or integrity.get("payload_sha256") != expected_digest
    ):
        errors.append("secure import smoke evidence integrity is invalid")
    return errors


def verify_evidence(path_value: str) -> dict[str, object]:
    path = _external_regular_file(path_value, label="evidence_file")
    try:
        raw, _ = read_stable_runtime_bytes_with_metadata(
            path, max_bytes=MAX_RESPONSE_BYTES
        )
        document = parse_unique_json_bytes(raw)
    except (OSError, JsonBoundaryError):
        raise SmokeFailure("evidence_file_invalid") from None
    errors = evidence_errors(document)
    if errors:
        raise SmokeFailure("evidence_file_invalid")
    assert isinstance(document, dict)
    return dict(document)


def execute(
    args: argparse.Namespace,
    *,
    client_factory: Callable[..., VaultClient] = VaultClient,
) -> tuple[dict[str, object], bool]:
    output = prepare_write_once_file(args.evidence_output)
    environment = args.environment.strip()
    if environment != args.environment or _ENVIRONMENT.fullmatch(environment) is None:
        raise SmokeFailure("environment_invalid")
    token_paths = {
        "card": _external_regular_file(args.card_token_file, label="card_token_file"),
        "mailbox": _external_regular_file(
            args.mailbox_token_file, label="mailbox_token_file"
        ),
        "api": _external_regular_file(args.api_token_file, label="api_token_file"),
    }
    if len({path.resolve() for path in token_paths.values()}) != 3:
        raise SmokeFailure("vault_token_files_not_distinct")
    token_identities = {
        (metadata.st_dev, metadata.st_ino)
        for metadata in (os.stat(path) for path in token_paths.values())
    }
    if len(token_identities) != 3:
        raise SmokeFailure("vault_token_files_not_distinct")
    ca_file = (
        _external_regular_file(args.ca_file, label="ca_file") if args.ca_file else None
    )
    if ca_file is not None and ca_file.resolve() in {
        path.resolve() for path in token_paths.values()
    }:
        raise SmokeFailure("ca_file_invalid")

    clients = {
        name: client_factory(
            args.vault_address,
            _read_token(path),
            ca_file=ca_file,
        )
        for name, path in token_paths.items()
    }
    origin_digest = hashlib.sha256(
        clients["api"].origin.encode("utf-8")
    ).hexdigest()
    run_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    card_path = f"secret/data/cards/imports/smoke/{run_id}"
    mailbox_path = f"secret/data/mailboxes/imports/smoke/{run_id}"
    card_wrong_cas_path = card_path + "-wrong-cas"
    mailbox_wrong_cas_path = mailbox_path + "-wrong-cas"
    synthetic = {"smoke_canary": run_id}
    create = {"options": {"cas": 0}, "data": synthetic}
    wrong_cas = {"options": {"cas": 1}, "data": synthetic}
    message = ("email-platform-secure-import-smoke:" + run_id).encode("ascii")
    checks: dict[str, dict[str, object]] = {
        name: {"result": "not_run", "status": None} for name in _CHECK_NAMES
    }
    error_code: str | None = None

    try:
        card = clients["card"]
        mailbox = clients["mailbox"]
        api = clients["api"]
        _record(checks, "card_create_cas_zero", card.request("POST", card_path, create), {200, 204})
        _record(checks, "card_replay_cas_zero_rejected", card.request("POST", card_path, create), {400})
        _record(checks, "card_wrong_cas_rejected", card.request("POST", card_wrong_cas_path, wrong_cas), {400})
        _record(checks, "card_cross_pool_denied", card.request("POST", mailbox_path + "-cross", create), {403})
        _record(checks, "card_cross_key_sign_denied", card.request("POST", "transit/sign/email-platform-mailbox-import-receipt", {"input": base64.b64encode(message).decode("ascii")}), {403})
        _record(checks, "card_verify_denied", card.request("POST", "transit/verify/email-platform-card-import-receipt", {"input": base64.b64encode(message).decode("ascii"), "signature": "vault:v1:invalid"}), {403})
        _record(checks, "card_key_read_denied", card.request("GET", "transit/keys/email-platform-card-import-receipt"), {403})
        card_sign_response, card_signature = _sign(card, "email-platform-card-import-receipt", message)
        _record(checks, "card_sign_allowed", card_sign_response, {200})

        _record(checks, "mailbox_create_cas_zero", mailbox.request("POST", mailbox_path, create), {200, 204})
        _record(checks, "mailbox_replay_cas_zero_rejected", mailbox.request("POST", mailbox_path, create), {400})
        _record(checks, "mailbox_wrong_cas_rejected", mailbox.request("POST", mailbox_wrong_cas_path, wrong_cas), {400})
        _record(checks, "mailbox_cross_pool_denied", mailbox.request("POST", card_path + "-cross", create), {403})
        _record(checks, "mailbox_cross_key_sign_denied", mailbox.request("POST", "transit/sign/email-platform-card-import-receipt", {"input": base64.b64encode(message).decode("ascii")}), {403})
        _record(checks, "mailbox_verify_denied", mailbox.request("POST", "transit/verify/email-platform-mailbox-import-receipt", {"input": base64.b64encode(message).decode("ascii"), "signature": "vault:v1:invalid"}), {403})
        _record(checks, "mailbox_key_read_denied", mailbox.request("GET", "transit/keys/email-platform-mailbox-import-receipt"), {403})
        mailbox_sign_response, mailbox_signature = _sign(
            mailbox, "email-platform-mailbox-import-receipt", message
        )
        _record(checks, "mailbox_sign_allowed", mailbox_sign_response, {200})

        _record(checks, "api_card_verify_allowed", _verify(api, "email-platform-card-import-receipt", message, card_signature), {200})
        _record(checks, "api_mailbox_verify_allowed", _verify(api, "email-platform-mailbox-import-receipt", message, mailbox_signature), {200})
        encoded = {"input": base64.b64encode(message).decode("ascii")}
        _record(checks, "api_card_sign_denied", api.request("POST", "transit/sign/email-platform-card-import-receipt", encoded), {403})
        _record(checks, "api_mailbox_sign_denied", api.request("POST", "transit/sign/email-platform-mailbox-import-receipt", encoded), {403})
        _record(checks, "api_card_pool_write_denied", api.request("POST", card_path + "-api", create), {403})
        _record(checks, "api_mailbox_pool_write_denied", api.request("POST", mailbox_path + "-api", create), {403})
        _record(checks, "api_card_key_read_denied", api.request("GET", "transit/keys/email-platform-card-import-receipt"), {403})
        _record(checks, "api_mailbox_key_read_denied", api.request("GET", "transit/keys/email-platform-mailbox-import-receipt"), {403})
    except SmokeFailure as error:
        error_code = str(error)

    passed = error_code is None and all(
        check["result"] == "passed" for check in checks.values()
    )
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "secure_import_vault_boundary_smoke",
        "production_acceptance": False,
        "environment": environment,
        "vault_origin_sha256": origin_digest,
        "run_id": run_id,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "result": "passed" if passed else "failed",
        "error_code": error_code,
        "cleanup_required": True,
        "canary_paths": [card_path, mailbox_path],
        "checks": checks,
        "prohibited_content": {
            "contains_token_values": False,
            "contains_signatures": False,
            "contains_response_bodies": False,
            "contains_pan_values": False,
            "contains_mailbox_credentials": False,
        },
    }
    _write_evidence(output, payload)
    return payload, passed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run or verify a redacted secure-import Vault boundary smoke test"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--vault-address", required=True)
    run.add_argument("--card-token-file", required=True)
    run.add_argument("--mailbox-token-file", required=True)
    run.add_argument("--api-token-file", required=True)
    run.add_argument("--environment", required=True)
    run.add_argument("--evidence-output", required=True)
    run.add_argument("--ca-file")
    verify = commands.add_parser("verify")
    verify.add_argument("--input", required=True)
    return parser


def main() -> int:
    try:
        arguments = build_parser().parse_args()
        if arguments.command == "verify":
            payload = verify_evidence(arguments.input)
            print(
                "secure-import-vault-smoke-evidence-ok "
                f"result={payload['result']} production_acceptance=false"
            )
            return 0
        payload, passed = execute(arguments)
    except (OSError, ValueError, SmokeFailure) as error:
        code = str(error) if isinstance(error, SmokeFailure) else "smoke_preflight_failed"
        print(f"secure-import-vault-smoke-failed: {code}", file=sys.stderr)
        return 1
    print(
        "secure-import-vault-smoke-"
        + ("ok" if passed else "failed")
        + f" run_id={payload['run_id']} production_acceptance=false"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
