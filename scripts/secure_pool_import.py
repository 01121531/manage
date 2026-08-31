"""Write raw pool secrets to Vault and emit a secret-free signed import bundle.

Raw input, the Vault token, and the output path must be absolute files.  Secrets
are never accepted on argv/stdin/environment and are never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.pool_imports import (
    canonical_receipt_claims,
    encode_receipt_token,
    pool_import_digest,
    pool_secret_ref,
)


MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_TOKEN_BYTES = 4096
MAX_RESPONSE_BYTES = 64 * 1024
RECEIPT_TTL_SECONDS = 300
SIGNING_DOMAIN = b"email-platform/pool-import-receipt/v1\0"
_CARD_KEYS = {
    "provider_ref", "pool_key", "region", "brand", "pan",
    "expiry_month", "expiry_year",
}
_MAILBOX_KEYS = {"email_masked", "connector_type", "task_type", "secret"}
_CVV_ALIASES = {"cvv", "cvc", "cid", "security_code", "card_verification_value"}


class ImportFailure(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _absolute_file(value: str, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ImportFailure(f"{label} must be an absolute path")
    return path


def _read_json(path: Path) -> object:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(path, max_bytes=MAX_INPUT_BYTES)
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise OSError
        return parse_unique_json_bytes(raw)
    except (OSError, JsonBoundaryError):
        raise ImportFailure("Input file is unavailable or invalid") from None


def _read_token(path: Path) -> str:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(path, max_bytes=MAX_TOKEN_BYTES)
        if os.name != "nt" and metadata.st_mode & 0o022:
            raise OSError
        token = raw.decode("utf-8").strip()
        if not token or any(character.isspace() for character in token):
            raise ValueError
        return token
    except (OSError, UnicodeError, ValueError):
        raise ImportFailure("Vault token file is unavailable") from None


def _contains_forbidden_card_secret(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).strip().lower() in _CVV_ALIASES
            or _contains_forbidden_card_secret(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_card_secret(item) for item in value)
    return False


def _luhn_valid(pan: str) -> bool:
    checksum = 0
    parity = len(pan) % 2
    for index, character in enumerate(pan):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _card_record(value: object) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(value, dict) or set(value) - _CARD_KEYS:
        raise ImportFailure("Card input schema is invalid")
    if _contains_forbidden_card_secret(value):
        raise ImportFailure("Card security codes are forbidden")
    try:
        raw_provider_ref = value["provider_ref"]
        raw_pool_key = value.get("pool_key", "legacy-unclassified")
        raw_region = value.get("region", "legacy-unclassified")
        raw_brand = value["brand"]
        raw_pan = value["pan"]
    except KeyError:
        raise ImportFailure("Card input schema is invalid") from None
    if not all(isinstance(item, str) for item in (
        raw_provider_ref, raw_pool_key, raw_region, raw_brand, raw_pan,
    )):
        raise ImportFailure("Card input schema is invalid")
    provider_ref = raw_provider_ref.strip()
    pool_key = raw_pool_key.strip().lower()
    region = raw_region.strip().lower()
    brand = raw_brand.strip()
    pan = raw_pan.replace(" ", "").replace("-", "")
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", provider_ref) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", pool_key) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", region) is None
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}", brand) is None
        or re.fullmatch(r"\d{12,19}", pan) is None
        or not _luhn_valid(pan)
    ):
        raise ImportFailure("Card input schema is invalid")
    month = value.get("expiry_month")
    year = value.get("expiry_year")
    if (month is None) != (year is None):
        raise ImportFailure("Card input schema is invalid")
    if month is not None and (
        type(month) is not int or not 1 <= month <= 12
        or type(year) is not int or not 2000 <= year <= 9999
    ):
        raise ImportFailure("Card input schema is invalid")
    manifest: dict[str, object] = {
        "provider_ref": provider_ref,
        "pool_key": pool_key,
        "region": region,
        "brand": brand,
        "last4": pan[-4:],
        "expiry_month": month,
        "expiry_year": year,
    }
    secret = {"pan": pan}
    if month is not None:
        secret.update({"expiry_month": month, "expiry_year": year})
    return manifest, secret


def _mailbox_record(value: object) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(value, dict) or set(value) - _MAILBOX_KEYS:
        raise ImportFailure("Mailbox input schema is invalid")
    try:
        raw_masked = value["email_masked"]
        raw_connector = value["connector_type"]
        raw_task_type = value.get("task_type", "mail_code")
        secret = value["secret"]
    except KeyError:
        raise ImportFailure("Mailbox input schema is invalid") from None
    if not all(isinstance(item, str) for item in (
        raw_masked, raw_connector, raw_task_type,
    )):
        raise ImportFailure("Mailbox input schema is invalid")
    masked = raw_masked.strip().lower()
    connector = raw_connector.strip().lower()
    task_type = raw_task_type.strip().lower()
    if (
        "@" not in masked
        or "*" not in masked
        or len(masked) > 320
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", connector) is None
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", task_type) is None
        or not isinstance(secret, dict)
        or not secret
    ):
        raise ImportFailure("Mailbox input schema is invalid")
    return {
        "email_masked": masked,
        "connector_type": connector,
        "task_type": task_type,
    }, dict(secret)


class VaultClient:
    def __init__(self, addr: str, token: str, *, ca_file: Path | None) -> None:
        parsed = urllib.parse.urlsplit(addr.strip().rstrip("/"))
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ImportFailure("Vault address must be an HTTPS origin")
        if parsed.path or parsed.query or parsed.fragment:
            raise ImportFailure("Vault address must be an HTTPS origin")
        self.addr = urllib.parse.urlunsplit(parsed)
        self.token = token
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            self.addr + path,
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Vault-Token": self.token,
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ImportFailure("Vault returned an invalid response")
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ImportFailure("Vault request failed") from None
        try:
            value = parse_unique_json_bytes(raw)
        except JsonBoundaryError:
            raise ImportFailure("Vault returned an invalid response") from None
        if not isinstance(value, dict):
            raise ImportFailure("Vault returned an invalid response")
        return dict(value)

    def write_secret(self, secret_ref: str, secret: dict[str, object]) -> None:
        parsed = urllib.parse.urlsplit(secret_ref)
        path = f"/v1/{parsed.netloc}/data/{parsed.path.lstrip('/')}"
        self.post(path, {"options": {"cas": 0}, "data": secret})

    def sign(self, pool_type: Literal["card", "mailbox"], claims: bytes) -> str:
        key = f"email-platform-{pool_type}-import-receipt"
        value = self.post(
            f"/v1/transit/sign/{key}",
            {"input": base64.b64encode(SIGNING_DOMAIN + claims).decode("ascii")},
        )
        data = value.get("data")
        signature = data.get("signature") if isinstance(data, dict) else None
        if not isinstance(signature, str) or re.fullmatch(
            r"vault:v[1-9][0-9]*:[A-Za-z0-9+/=_-]+", signature
        ) is None:
            raise ImportFailure("Vault returned an invalid signature")
        return signature


def _write_bundle(path: Path, bundle: dict[str, object]) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            if os.name != "nt":
                os.chmod(path, 0o600)
            json.dump(bundle, handle, ensure_ascii=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise ImportFailure("Receipt output must be a new writable file") from None


def run(args: argparse.Namespace) -> tuple[str, int]:
    input_path = _absolute_file(args.input_file, label="Input file")
    token_path = _absolute_file(args.token_file, label="Vault token file")
    output_path = _absolute_file(args.receipt_output, label="Receipt output")
    ca_file = _absolute_file(args.ca_file, label="CA file") if args.ca_file else None
    tenant_id = args.tenant_id.strip()
    audience = args.audience.strip()
    if tenant_id != args.tenant_id or not 1 <= len(tenant_id) <= 64:
        raise ImportFailure("Tenant ID is invalid")
    if audience != args.audience or not 1 <= len(audience) <= 160:
        raise ImportFailure("Receipt audience is invalid")
    if output_path.exists():
        raise ImportFailure("Receipt output must not already exist")
    if not output_path.parent.is_dir():
        raise ImportFailure("Receipt output directory must already exist")
    distinct_paths = [input_path, token_path, output_path]
    if ca_file is not None:
        distinct_paths.append(ca_file)
    if len({path.resolve() for path in distinct_paths}) != len(distinct_paths):
        raise ImportFailure("Input, token, CA, and receipt output must be separate files")
    value = _read_json(input_path)
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise ImportFailure("Input must contain 1 to 100 records")
    pool_type: Literal["card", "mailbox"] = args.pool_type
    parser = _card_record if pool_type == "card" else _mailbox_record
    parsed_records = [parser(item) for item in value]
    manifest = [item[0] for item in parsed_records]
    secrets = [item[1] for item in parsed_records]
    receipt_id = str(uuid4())
    client = VaultClient(args.vault_address, _read_token(token_path), ca_file=ca_file)
    for index, secret in enumerate(secrets):
        client.write_secret(pool_secret_ref(
            pool_type,
            tenant_id=tenant_id,
            receipt_id=receipt_id,
            index=index,
        ), secret)
    now = int(datetime.now(timezone.utc).timestamp())
    digest = pool_import_digest(pool_type, manifest)
    claims = {
        "schema_version": 1,
        "audience": audience,
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "pool_type": pool_type,
        "ordered_manifest_digest": digest,
        "item_count": len(manifest),
        "issued_at": now,
        "expires_at": now + RECEIPT_TTL_SECONDS,
        "key_version": 1,
    }
    unsigned = canonical_receipt_claims(claims)
    signature = client.sign(pool_type, unsigned)
    key_version = int(signature.split(":", 2)[1].removeprefix("v"))
    if key_version != claims["key_version"]:
        claims["key_version"] = key_version
        unsigned = canonical_receipt_claims(claims)
        signature = client.sign(pool_type, unsigned)
        if int(signature.split(":", 2)[1].removeprefix("v")) != key_version:
            raise ImportFailure("Transit key rotated during receipt signing; retry safely")
    _write_bundle(output_path, {
        "schema_version": 1,
        "pool_type": pool_type,
        "receipt_token": encode_receipt_token(unsigned, signature),
        "items": manifest,
    })
    return receipt_id, len(manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Securely import one card or mailbox pool")
    parser.add_argument("pool_type", choices=("card", "mailbox"))
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--vault-address", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--receipt-output", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--ca-file")
    return parser


def main() -> int:
    try:
        receipt_id, count = run(build_parser().parse_args())
    except ImportFailure as error:
        print(f"secure-pool-import-failed: {error}", file=sys.stderr)
        return 1
    print(f"secure-pool-import-ok receipt_id={receipt_id} count={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
