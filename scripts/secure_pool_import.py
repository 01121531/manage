"""Write raw pool secrets to Vault and emit a secret-free signed import bundle.

Raw input, AppRole credentials, and output paths must be absolute files. Secret
values are never accepted on argv/stdin/environment or printed; the exchanged
Vault token is retained only in process memory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Literal
from uuid import UUID

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.pool_imports import (
    canonical_receipt_claims,
    encode_receipt_token,
    pool_import_digest,
    pool_import_submission_key,
    pool_secret_ref,
    normalize_masked_email,
)
from platform.pool_import_execution import (
    build_execution_event,
    build_execution_plan,
    canonical_bytes as execution_canonical_bytes,
    execution_plan_errors,
)
from scripts.backup_output_policy import (
    create_write_once_directory,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.secure_pool_import_recovery import (
    RecoveryFailure,
    assess_execution_directory,
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
_APPROLE_IDENTITIES = {
    "card": ("email-platform-card-importer", "email-platform-card-importer"),
    "mailbox": (
        "email-platform-mailbox-importer",
        "email-platform-mailbox-importer",
    ),
}


class ImportFailure(RuntimeError):
    pass


_REVOCATION_FAILURE_NOTE = (
    "Vault token revocation is unconfirmed; inspect the execution record and audit trail"
)


@contextmanager
def _revoke_token_on_exit(revoke: Callable[[], None]) -> Iterator[None]:
    try:
        yield
    except BaseException as primary_error:
        try:
            revoke()
        except (ImportFailure, OSError, ValueError):
            primary_error.add_note(_REVOCATION_FAILURE_NOTE)
        raise
    else:
        revoke()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _vault_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip().rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ImportFailure("Vault address must be an HTTPS origin")
    return urllib.parse.urlunsplit(parsed)


def _platform_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip().rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ImportFailure("Platform address must be an HTTPS origin")
    return urllib.parse.urlunsplit(parsed)


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


def _read_approle_value(path: Path) -> str:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(path, max_bytes=MAX_TOKEN_BYTES)
        if metadata.st_nlink != 1 or (os.name != "nt" and metadata.st_mode & 0o077):
            raise OSError
        value = raw.decode("utf-8").strip()
        if not value or any(character.isspace() for character in value):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError):
        raise ImportFailure("Vault AppRole credential file is unavailable") from None


def _safe_vault_token(value: object) -> str | None:
    if (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_TOKEN_BYTES
        and re.fullmatch(r"[\x21-\x7e]+", value) is not None
    ):
        return value
    return None


def _revoke_vault_token(vault_origin: str, token: str, opener: Any) -> None:
    request = urllib.request.Request(
        vault_origin + "/v1/auth/token/revoke-self",
        method="POST",
        headers={"Accept": "application/json", "X-Vault-Token": token},
    )
    try:
        with opener.open(request, timeout=20) as response:
            status = response.getcode()
            raw = response.read(1)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ImportFailure("Vault token revocation is unconfirmed") from None
    if status != 204 or raw:
        raise ImportFailure("Vault token revocation acknowledgement is invalid")


def _exchange_approle_token(
    vault_origin: str,
    *,
    role_id: str,
    secret_id: str,
    expected_role: str,
    expected_policy: str,
    ca_file: Path | None,
) -> str:
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )
    request = urllib.request.Request(
        vault_origin + "/v1/auth/approle/login",
        data=json.dumps(
            {"role_id": role_id, "secret_id": secret_id},
            separators=(",", ":"),
        ).encode("utf-8"),
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ImportFailure("Vault AppRole response is invalid")
    except urllib.error.HTTPError as error:
        if error.code in {400, 401, 403}:
            raise ImportFailure("Vault rejected AppRole authentication") from None
        raise ImportFailure("Vault AppRole authentication failed") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ImportFailure("Vault AppRole authentication failed") from None
    try:
        value = parse_unique_json_bytes(raw)
    except JsonBoundaryError:
        raise ImportFailure("Vault AppRole response is invalid") from None
    auth = value.get("auth") if isinstance(value, dict) else None
    metadata = auth.get("metadata") if isinstance(auth, dict) else None
    token = auth.get("client_token") if isinstance(auth, dict) else None
    safe_token = _safe_vault_token(token)
    if (
        not isinstance(auth, dict)
        or safe_token is None
        or auth.get("policies") != [expected_policy]
        or auth.get("token_policies") != [expected_policy]
        or auth.get("identity_policies") != []
        or type(auth.get("lease_duration")) is not int
        or not 1 <= auth["lease_duration"] <= 900
        or auth.get("token_type") != "service"
        or auth.get("orphan") is not True
        or auth.get("num_uses") != 0
        or not isinstance(metadata, dict)
        or metadata.get("role_name") != expected_role
    ):
        primary_error = ImportFailure("Vault AppRole response is invalid")
        if safe_token is not None:
            try:
                _revoke_vault_token(vault_origin, safe_token, opener)
            except ImportFailure:
                primary_error.add_note(_REVOCATION_FAILURE_NOTE)
            finally:
                safe_token = ""
        raise primary_error
    return safe_token


def _read_vault_approle_token(
    vault_origin: str,
    *,
    pool_type: Literal["card", "mailbox"],
    role_id_path: Path,
    secret_id_path: Path,
    ca_file: Path | None,
) -> str:
    expected_role, expected_policy = _APPROLE_IDENTITIES[pool_type]
    return _exchange_approle_token(
        vault_origin,
        role_id=_read_approle_value(role_id_path),
        secret_id=_read_approle_value(secret_id_path),
        expected_role=expected_role,
        expected_policy=expected_policy,
        ca_file=ca_file,
    )


def _read_platform_access_token(path: Path) -> str:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(
            path, max_bytes=MAX_TOKEN_BYTES
        )
        if os.name != "nt" and metadata.st_mode & 0o022:
            raise OSError
        token = raw.decode("utf-8").strip()
        if not token or any(character.isspace() for character in token):
            raise ValueError
        return token
    except (OSError, UnicodeError, ValueError):
        raise ImportFailure("Platform access token file is unavailable") from None


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
    try:
        masked = normalize_masked_email(raw_masked)
    except ValueError:
        raise ImportFailure("Mailbox input schema is invalid") from None
    connector = raw_connector.strip().lower()
    task_type = raw_task_type.strip().lower()
    if (
        re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", connector) is None
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
        self.addr = _vault_origin(addr)
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
        value = self.post(path, {"options": {"cas": 0}, "data": secret})
        data = value.get("data")
        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or type(data.get("version")) is not int
        ):
            raise ImportFailure("Vault write acknowledgement is invalid")

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

    def revoke_self(self) -> None:
        token = self.token
        self.token = ""
        if not token:
            return
        _revoke_vault_token(self.addr, token, self.opener)


def _revoke_import_token(
    client: VaultClient,
    *,
    execution_directory: Path,
    plan: dict[str, object],
) -> None:
    evidence_failure: ImportFailure | None = None
    try:
        _write_execution_record(
            execution_directory / "token-revoke.intent.json",
            build_execution_event(
                plan,
                event_type="vault_token_revoke_intent",
                index=None,
                artifact_sha256=None,
                occurred_at=_utc_now(),
            ),
        )
    except ImportFailure as error:
        evidence_failure = error
    client.revoke_self()
    if evidence_failure is not None:
        raise ImportFailure("Vault token revocation evidence is unconfirmed") from None
    _write_execution_record(
        execution_directory / "token-revoke.confirmed.json",
        build_execution_event(
            plan,
            event_type="vault_token_revoke_confirmed",
            index=None,
            artifact_sha256=None,
            occurred_at=_utc_now(),
        ),
    )


@dataclass(frozen=True)
class PoolImportContext:
    schema_version: int
    context_token: str
    receipt_id: str
    tenant_id: str
    audience: str
    pool_type: Literal["card", "mailbox"]
    ordered_manifest_digest: str
    item_count: int
    expires_at: datetime


def _parse_platform_context(raw: bytes) -> PoolImportContext:
    try:
        value = parse_unique_json_bytes(raw)
    except JsonBoundaryError:
        raise ImportFailure("Platform returned an invalid import context") from None
    expected_keys = {
        "schema_version",
        "context_token",
        "receipt_id",
        "tenant_id",
        "audience",
        "pool_type",
        "ordered_manifest_digest",
        "item_count",
        "expires_at",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ImportFailure("Platform returned an invalid import context")
    try:
        receipt_id = str(UUID(value["receipt_id"]))
        expires_at = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
    except (ValueError, TypeError, AttributeError):
        raise ImportFailure("Platform returned an invalid import context") from None
    now = datetime.now(timezone.utc)
    if (
        value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or not isinstance(value["context_token"], str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", value["context_token"]) is None
        or value["receipt_id"] != receipt_id
        or not isinstance(value["tenant_id"], str)
        or not 1 <= len(value["tenant_id"]) <= 64
        or not isinstance(value["audience"], str)
        or not 1 <= len(value["audience"]) <= 160
        or value["pool_type"] not in {"card", "mailbox"}
        or not isinstance(value["ordered_manifest_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["ordered_manifest_digest"]) is None
        or type(value["item_count"]) is not int
        or not 1 <= value["item_count"] <= 100
        or not isinstance(value["expires_at"], str)
        or expires_at.utcoffset() is None
        or expires_at <= now
        or expires_at > now + timedelta(seconds=3_660)
    ):
        raise ImportFailure("Platform returned an invalid import context")
    return PoolImportContext(
        schema_version=1,
        context_token=value["context_token"],
        receipt_id=receipt_id,
        tenant_id=value["tenant_id"],
        audience=value["audience"],
        pool_type=value["pool_type"],
        ordered_manifest_digest=value["ordered_manifest_digest"],
        item_count=value["item_count"],
        expires_at=expires_at,
    )


class PlatformClient:
    def __init__(self, addr: str, access_token: str, *, ca_file: Path | None) -> None:
        self.addr = _platform_origin(addr)
        self.access_token = access_token
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def issue_context(
        self,
        pool_type: Literal["card", "mailbox"],
        ordered_manifest_digest: str,
        item_count: int,
    ) -> PoolImportContext:
        request = urllib.request.Request(
            self.addr + "/api/v1/admin/pool-import-contexts",
            data=json.dumps(
                {
                    "pool_type": pool_type,
                    "ordered_manifest_digest": ordered_manifest_digest,
                    "item_count": item_count,
                },
                separators=(",", ":"),
            ).encode("ascii"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ImportFailure("Platform returned an invalid import context")
        except urllib.error.HTTPError as error:
            if error.code in {401, 403}:
                raise ImportFailure("Platform rejected import context authorization") from None
            raise ImportFailure("Platform import context request failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ImportFailure("Platform import context request failed") from None
        return _parse_platform_context(raw)

    def renew_context(self, context_token: str) -> PoolImportContext:
        request = urllib.request.Request(
            self.addr + "/api/v1/admin/pool-import-contexts/renew",
            data=b"",
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "Secure-Import-Context": context_token,
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ImportFailure("Platform returned an invalid import context")
        except urllib.error.HTTPError as error:
            if error.code in {401, 403, 409, 410}:
                raise ImportFailure("Platform rejected import context renewal") from None
            raise ImportFailure("Platform import context renewal failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ImportFailure("Platform import context renewal failed") from None
        context = _parse_platform_context(raw)
        if context.context_token != context_token:
            raise ImportFailure("Platform rotated an idempotent import context")
        return context


def _write_execution_record(path: Path, document: dict[str, object]) -> None:
    raw = execution_canonical_bytes(document) + b"\n"
    try:
        output = prepare_write_once_file(path)
        temporary = write_fsynced_temporary_bytes(output, raw)
        publish_write_once_file(temporary, output)
    except (OSError, ValueError):
        raise ImportFailure("Execution record publication failed") from None


def _write_bundle(path: Path, bundle: dict[str, object]) -> str:
    raw = json.dumps(
        bundle, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii") + b"\n"
    try:
        output = prepare_write_once_file(path)
        temporary = write_fsynced_temporary_bytes(output, raw)
        publish_write_once_file(temporary, output)
    except (OSError, ValueError):
        raise ImportFailure("Receipt output must be a new writable file") from None
    return hashlib.sha256(raw).hexdigest()


def _context_matches(
    context: PoolImportContext,
    *,
    context_token: str,
    receipt_id: str,
    tenant_id: str,
    audience: str,
    pool_type: Literal["card", "mailbox"],
    digest: str,
    item_count: int,
) -> bool:
    return (
        context.schema_version == 1
        and context.context_token == context_token
        and context.receipt_id == receipt_id
        and context.tenant_id == tenant_id
        and context.audience == audience
        and context.pool_type == pool_type
        and context.ordered_manifest_digest == digest
        and context.item_count == item_count
        and context.expires_at > datetime.now(timezone.utc)
    )


def _signed_bundle(
    client: VaultClient,
    *,
    context: PoolImportContext,
    manifest: list[dict[str, object]],
) -> dict[str, object]:
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "schema_version": 1,
        "audience": context.audience,
        "receipt_id": context.receipt_id,
        "tenant_id": context.tenant_id,
        "pool_type": context.pool_type,
        "ordered_manifest_digest": context.ordered_manifest_digest,
        "item_count": len(manifest),
        "issued_at": now,
        "expires_at": now + RECEIPT_TTL_SECONDS,
        "key_version": 1,
    }
    unsigned = canonical_receipt_claims(claims)
    signature = client.sign(context.pool_type, unsigned)
    key_version = int(signature.split(":", 2)[1].removeprefix("v"))
    if key_version != claims["key_version"]:
        claims["key_version"] = key_version
        unsigned = canonical_receipt_claims(claims)
        signature = client.sign(context.pool_type, unsigned)
        if int(signature.split(":", 2)[1].removeprefix("v")) != key_version:
            raise ImportFailure(
                "Transit key changed during signing; inspect the execution record"
            )
    return {
        "schema_version": 3,
        "pool_type": context.pool_type,
        "submission_key": pool_import_submission_key(context.receipt_id),
        "context_token": context.context_token,
        "receipt_token": encode_receipt_token(unsigned, signature),
        "items": manifest,
    }


def run(args: argparse.Namespace) -> tuple[str, int]:
    if not getattr(args, "input_file", None) or getattr(args, "reissue_from", None):
        raise ImportFailure("Raw import requires one input file and no reissue bundle")
    input_path = _absolute_file(args.input_file, label="Input file")
    platform_token_path = _absolute_file(
        args.platform_token_file, label="Platform access token file"
    )
    role_id_path = _absolute_file(
        args.approle_role_id_file, label="Vault AppRole RoleID file"
    )
    secret_id_path = _absolute_file(
        args.approle_secret_id_file, label="Vault AppRole SecretID file"
    )
    output_path = _absolute_file(args.receipt_output, label="Receipt output")
    execution_path = Path(args.execution_directory)
    if not execution_path.is_absolute():
        raise ImportFailure("Execution record directory must be an absolute path")
    ca_file = _absolute_file(args.ca_file, label="CA file") if args.ca_file else None
    expected_tenant_id = args.expected_tenant_id.strip()
    expected_audience = args.expected_audience.strip()
    if (
        expected_tenant_id != args.expected_tenant_id
        or not 1 <= len(expected_tenant_id) <= 64
    ):
        raise ImportFailure("Expected tenant ID is invalid")
    if (
        expected_audience != args.expected_audience
        or not 1 <= len(expected_audience) <= 160
    ):
        raise ImportFailure("Expected receipt audience is invalid")
    if output_path.exists():
        raise ImportFailure("Receipt output must not already exist")
    if not output_path.parent.is_dir():
        raise ImportFailure("Receipt output directory must already exist")
    distinct_paths = [
        input_path,
        platform_token_path,
        role_id_path,
        secret_id_path,
        output_path,
        execution_path,
    ]
    if ca_file is not None:
        distinct_paths.append(ca_file)
    if len({path.resolve() for path in distinct_paths}) != len(distinct_paths):
        raise ImportFailure(
            "Input, AppRole, platform token, CA, and receipt output paths must be separate"
        )
    value = _read_json(input_path)
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise ImportFailure("Input must contain 1 to 100 records")
    pool_type: Literal["card", "mailbox"] = args.pool_type
    parser = _card_record if pool_type == "card" else _mailbox_record
    parsed_records = [parser(item) for item in value]
    manifest = [item[0] for item in parsed_records]
    secrets = [item[1] for item in parsed_records]
    vault_origin = _vault_origin(args.vault_address)
    platform_origin = _platform_origin(args.platform_address)
    digest = pool_import_digest(pool_type, manifest)
    platform_client = PlatformClient(
        platform_origin,
        _read_platform_access_token(platform_token_path),
        ca_file=ca_file,
    )
    context = platform_client.issue_context(pool_type, digest, len(manifest))
    if (
        context.schema_version != 1
        or context.tenant_id != expected_tenant_id
        or context.audience != expected_audience
        or context.pool_type != pool_type
        or context.ordered_manifest_digest != digest
        or context.item_count != len(manifest)
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", context.context_token) is None
    ):
        raise ImportFailure("Platform import context does not match this execution")
    try:
        receipt_id = str(UUID(context.receipt_id))
    except (ValueError, TypeError, AttributeError):
        raise ImportFailure("Platform import context is invalid") from None
    tenant_id = context.tenant_id
    audience = context.audience
    secret_refs = [
        pool_secret_ref(
            pool_type,
            tenant_id=tenant_id,
            receipt_id=receipt_id,
            index=index,
        )
        for index in range(len(secrets))
    ]
    try:
        execution_claim = create_write_once_directory(execution_path)
    except (OSError, ValueError):
        raise ImportFailure("Execution record directory must be a new external directory") from None
    execution_directory = execution_claim.path
    plan = build_execution_plan(
        execution_id=receipt_id,
        pool_type=pool_type,
        vault_origin=vault_origin,
        tenant_id=tenant_id,
        audience=audience,
        ordered_manifest_digest=digest,
        secret_refs=secret_refs,
        created_at=_utc_now(),
    )
    _write_execution_record(execution_directory / "plan.json", plan)

    client = VaultClient(vault_origin, "", ca_file=ca_file)
    with _revoke_token_on_exit(
        lambda: _revoke_import_token(
            client,
            execution_directory=execution_directory,
            plan=plan,
        ) if client.token else None
    ):
        client.token = _read_vault_approle_token(
            vault_origin,
            pool_type=pool_type,
            role_id_path=role_id_path,
            secret_id_path=secret_id_path,
            ca_file=ca_file,
        )
        for index, (secret_ref, secret) in enumerate(
            zip(secret_refs, secrets, strict=True)
        ):
            _write_execution_record(
                execution_directory / f"write-{index:03d}.intent.json",
                build_execution_event(
                    plan,
                    event_type="vault_write_intent",
                    index=index,
                    artifact_sha256=None,
                    occurred_at=_utc_now(),
                ),
            )
            client.write_secret(secret_ref, secret)
            _write_execution_record(
                execution_directory / f"write-{index:03d}.confirmed.json",
                build_execution_event(
                    plan,
                    event_type="vault_write_confirmed",
                    index=index,
                    artifact_sha256=None,
                    occurred_at=_utc_now(),
                ),
            )
        renewed_context = platform_client.renew_context(context.context_token)
        if not _context_matches(
            renewed_context,
            context_token=context.context_token,
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            audience=audience,
            pool_type=pool_type,
            digest=digest,
            item_count=len(manifest),
        ):
            raise ImportFailure("Renewed platform context does not match this execution")
        bundle = _signed_bundle(client, context=renewed_context, manifest=manifest)
        _write_execution_record(
            execution_directory / "bundle.intent.json",
            build_execution_event(
                plan,
                event_type="bundle_publish_intent",
                index=None,
                artifact_sha256=None,
                occurred_at=_utc_now(),
            ),
        )
        bundle_sha256 = _write_bundle(output_path, bundle)
        _write_execution_record(
            execution_directory / "complete.json",
            build_execution_event(
                plan,
                event_type="execution_complete",
                index=None,
                artifact_sha256=bundle_sha256,
                occurred_at=_utc_now(),
            ),
        )
    return receipt_id, len(manifest)


def reissue_completed(args: argparse.Namespace) -> tuple[str, int]:
    if getattr(args, "input_file", None) or not getattr(args, "reissue_from", None):
        raise ImportFailure("Receipt reissue requires one completed bundle and no raw input")
    source_bundle_path = _absolute_file(args.reissue_from, label="Reissue bundle")
    platform_token_path = _absolute_file(
        args.platform_token_file, label="Platform access token file"
    )
    role_id_path = _absolute_file(
        args.approle_role_id_file, label="Vault AppRole RoleID file"
    )
    secret_id_path = _absolute_file(
        args.approle_secret_id_file, label="Vault AppRole SecretID file"
    )
    output_path = _absolute_file(args.receipt_output, label="Receipt output")
    execution_path = Path(args.execution_directory)
    if not execution_path.is_absolute():
        raise ImportFailure("Execution record directory must be an absolute path")
    ca_file = _absolute_file(args.ca_file, label="CA file") if args.ca_file else None
    expected_tenant_id = args.expected_tenant_id.strip()
    expected_audience = args.expected_audience.strip()
    if (
        expected_tenant_id != args.expected_tenant_id
        or not 1 <= len(expected_tenant_id) <= 64
    ):
        raise ImportFailure("Expected tenant ID is invalid")
    if (
        expected_audience != args.expected_audience
        or not 1 <= len(expected_audience) <= 160
    ):
        raise ImportFailure("Expected receipt audience is invalid")
    if output_path.exists() or not output_path.parent.is_dir():
        raise ImportFailure("Receipt output must be a new file in an existing directory")
    resolved_execution = execution_path.resolve()
    resolved_output = output_path.resolve()
    if resolved_output == resolved_execution or resolved_execution in resolved_output.parents:
        raise ImportFailure("Reissued receipt output must be outside the execution record")
    distinct_paths = [
        source_bundle_path,
        platform_token_path,
        role_id_path,
        secret_id_path,
        output_path,
        execution_path,
    ]
    if ca_file is not None:
        distinct_paths.append(ca_file)
    if len({path.resolve() for path in distinct_paths}) != len(distinct_paths):
        raise ImportFailure(
            "Bundle, AppRole, platform token, CA, execution, and output paths must be separate"
        )
    try:
        assessment = assess_execution_directory(execution_path, source_bundle_path)
    except (OSError, ValueError, RecoveryFailure):
        raise ImportFailure("Completed execution record is invalid") from None
    if assessment["status"] != "completed":
        raise ImportFailure("Only a completed execution can be reissued")
    plan_value = _read_json(execution_path / "plan.json")
    bundle_value = _read_json(source_bundle_path)
    if (
        not isinstance(plan_value, dict)
        or execution_plan_errors(plan_value)
        or not isinstance(bundle_value, dict)
        or set(bundle_value) != {
            "schema_version",
            "pool_type",
            "submission_key",
            "context_token",
            "receipt_token",
            "items",
        }
    ):
        raise ImportFailure("Completed execution evidence is invalid")
    plan = dict(plan_value)
    bundle = dict(bundle_value)
    pool_type: Literal["card", "mailbox"] = args.pool_type
    items = bundle.get("items")
    try:
        receipt_id = str(UUID(str(plan["execution_id"])))
        digest = pool_import_digest(pool_type, items)
    except (KeyError, TypeError, ValueError):
        raise ImportFailure("Completed execution evidence is invalid") from None
    context_token = bundle.get("context_token")
    vault_origin = _vault_origin(args.vault_address)
    platform_origin = _platform_origin(args.platform_address)
    if (
        plan.get("pool_type") != pool_type
        or bundle.get("schema_version") != 3
        or bundle.get("pool_type") != pool_type
        or bundle.get("submission_key") != pool_import_submission_key(receipt_id)
        or not isinstance(context_token, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", context_token) is None
        or not isinstance(items, list)
        or len(items) != plan.get("item_count")
        or digest != plan.get("ordered_manifest_digest")
        or plan.get("vault_origin_sha256")
        != hashlib.sha256(vault_origin.encode("utf-8")).hexdigest()
        or plan.get("tenant_scope_sha256")
        != hashlib.sha256(expected_tenant_id.encode("utf-8")).hexdigest()
        or plan.get("audience_sha256")
        != hashlib.sha256(expected_audience.encode("utf-8")).hexdigest()
    ):
        raise ImportFailure("Completed execution does not match this reissue request")
    platform_client = PlatformClient(
        platform_origin,
        _read_platform_access_token(platform_token_path),
        ca_file=ca_file,
    )
    renewed_context = platform_client.renew_context(context_token)
    if not _context_matches(
        renewed_context,
        context_token=context_token,
        receipt_id=receipt_id,
        tenant_id=expected_tenant_id,
        audience=expected_audience,
        pool_type=pool_type,
        digest=digest,
        item_count=len(items),
    ):
        raise ImportFailure("Renewed platform context does not match this execution")
    client = VaultClient(vault_origin, "", ca_file=ca_file)
    with _revoke_token_on_exit(
        lambda: client.revoke_self() if client.token else None
    ):
        client.token = _read_vault_approle_token(
            vault_origin,
            pool_type=pool_type,
            role_id_path=role_id_path,
            secret_id_path=secret_id_path,
            ca_file=ca_file,
        )
        fresh_bundle = _signed_bundle(client, context=renewed_context, manifest=items)
        _write_bundle(output_path, fresh_bundle)
    return receipt_id, len(items)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Securely import one card or mailbox pool")
    parser.add_argument("pool_type", choices=("card", "mailbox"))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-file")
    source.add_argument("--reissue-from")
    parser.add_argument("--platform-address", required=True)
    parser.add_argument("--platform-token-file", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-audience", required=True)
    parser.add_argument("--vault-address", required=True)
    parser.add_argument("--approle-role-id-file", required=True)
    parser.add_argument("--approle-secret-id-file", required=True)
    parser.add_argument("--receipt-output", required=True)
    parser.add_argument("--execution-directory", required=True)
    parser.add_argument("--ca-file")
    return parser


def main() -> int:
    try:
        arguments = build_parser().parse_args()
        action = reissue_completed if arguments.reissue_from else run
        receipt_id, count = action(arguments)
    except ImportFailure as error:
        print(
            f"secure-pool-import-failed: {error}; run the read-only execution assessment",
            file=sys.stderr,
        )
        return 1
    print(f"secure-pool-import-ok receipt_id={receipt_id} count={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
