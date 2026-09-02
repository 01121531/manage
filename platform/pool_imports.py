"""Verification and deterministic references for secure pool imports.

The browser-facing API only receives masked metadata and a short-lived,
Vault Transit-signed receipt.  Secret paths are derived here and therefore
cannot be selected by the caller.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes


PoolType = Literal["card", "mailbox"]
SECURE_IMPORT_RECEIPT_HEADER = "Secure-Import-Receipt"
_TOKEN_PREFIX = "epir1"
_DOMAIN = b"email-platform/pool-import-receipt/v1\0"
_MAX_TOKEN_BYTES = 12 * 1024
_MAX_VAULT_RESPONSE_BYTES = 32 * 1024
_MAX_VAULT_TOKEN_BYTES = 4096
_MAX_RECEIPT_TTL_SECONDS = 600
_MAX_FUTURE_SKEW_SECONDS = 60
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TRANSIT_SIGNATURE_RE = re.compile(r"^vault:v([1-9][0-9]*):[A-Za-z0-9+/=_-]+$")
MASKED_EMAIL_PATTERN = (
    r"^[a-z0-9]\*{3}@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_MASKED_EMAIL_RE = re.compile(MASKED_EMAIL_PATTERN)
_CLAIM_KEYS = {
    "schema_version",
    "audience",
    "receipt_id",
    "tenant_id",
    "pool_type",
    "ordered_manifest_digest",
    "item_count",
    "issued_at",
    "expires_at",
    "key_version",
}


class PoolImportReceiptInvalid(ValueError):
    """The receipt is malformed, forged, or outside its trust domain."""


class PoolImportReceiptExpired(ValueError):
    """The receipt is authentic but no longer within its validity window."""


class PoolImportReceiptBindingMismatch(ValueError):
    """The receipt does not authorize this exact normalized manifest."""


class PoolImportReceiptVerifierUnavailable(RuntimeError):
    """The external receipt verifier cannot currently be reached."""


def normalize_masked_email(value: str) -> str:
    """Return the one-visible-character mailbox display form or fail closed."""

    normalized = value.strip().lower()
    if len(normalized) > 320 or _MASKED_EMAIL_RE.fullmatch(normalized) is None:
        raise ValueError("email_masked must be a strictly masked email address")
    return normalized


@dataclass(frozen=True)
class VerifiedPoolImportReceipt:
    receipt_id: str
    tenant_id: str
    pool_type: PoolType
    ordered_manifest_digest: str
    item_count: int
    issued_at: datetime
    expires_at: datetime
    key_version: int


class PoolImportReceiptVerifier(Protocol):
    def verify(
        self,
        token: str,
        *,
        tenant_id: str,
        pool_type: PoolType,
        ordered_manifest_digest: str,
        item_count: int,
    ) -> VerifiedPoolImportReceipt:
        """Verify and bind one secret-free receipt to an exact import."""


class UnconfiguredPoolImportReceiptVerifier:
    def verify(
        self,
        token: str,
        *,
        tenant_id: str,
        pool_type: PoolType,
        ordered_manifest_digest: str,
        item_count: int,
    ) -> VerifiedPoolImportReceipt:
        del token, tenant_id, pool_type, ordered_manifest_digest, item_count
        raise PoolImportReceiptVerifierUnavailable("Secure import verifier unavailable")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _vault_verifier_origin(addr: str, *, allow_http: bool) -> str:
    try:
        if not isinstance(addr, str) or not addr or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in addr
        ):
            raise ValueError
        parsed = urllib.parse.urlsplit(addr.rstrip("/"))
        hostname = parsed.hostname
        hostname_key = hostname.rstrip(".") if hostname is not None else ""
        if not hostname_key:
            raise ValueError
        hostname_key.encode("idna")
        port = parsed.port
    except (AttributeError, UnicodeError, ValueError):
        raise ValueError("Vault address is invalid") from None
    if parsed.scheme != "https" and not (
        allow_http is True and parsed.scheme == "http"
    ):
        raise ValueError("Vault address must use HTTPS")
    if (
        not parsed.netloc
        or port == 0
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Vault address is invalid")
    return urllib.parse.urlunsplit(parsed)


def pool_import_digest(pool_type: PoolType, payload: Sequence[Any]) -> str:
    """Return the ordered, canonical digest shared by importer and API."""

    normalized = [
        item.model_dump(mode="json") if hasattr(item, "model_dump") else item
        for item in payload
    ]
    canonical_payload = json.dumps(
        normalized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest_input = (
        f"email-platform:pool-import-manifest:v2\0{pool_type}\0{canonical_payload}"
    ).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


def pool_secret_ref(
    pool_type: PoolType,
    *,
    tenant_id: str,
    receipt_id: str,
    index: int,
) -> str:
    """Derive the only Vault path accepted for a verified receipt item."""

    if index < 0 or index >= 100:
        raise ValueError("Pool import index is out of range")
    canonical_receipt_id = str(UUID(receipt_id))
    tenant_scope = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:24]
    namespace = "cards" if pool_type == "card" else "mailboxes"
    return (
        f"vault://secret/{namespace}/imports/{tenant_scope}/"
        f"{canonical_receipt_id}/{index:03d}"
    )


def pool_import_submission_key(receipt_id: str) -> str:
    """Derive the stable API idempotency key from a signed receipt identity."""

    return f"spi:{UUID(receipt_id)}"


def canonical_receipt_claims(claims: dict[str, object]) -> bytes:
    """Encode exact receipt claims for Vault Transit signing."""

    if set(claims) != _CLAIM_KEYS:
        raise PoolImportReceiptInvalid("Secure import receipt is invalid")
    return json.dumps(
        claims,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def encode_receipt_token(claims_bytes: bytes, transit_signature: str) -> str:
    """Build the transport token emitted by the independent secure importer."""

    def encoded(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    return f"{_TOKEN_PREFIX}.{encoded(claims_bytes)}.{encoded(transit_signature.encode('ascii'))}"


def _decode_segment(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise PoolImportReceiptInvalid("Secure import receipt is invalid")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeError):
        raise PoolImportReceiptInvalid("Secure import receipt is invalid") from None


class VaultTransitPoolImportReceiptVerifier:
    """Verify compact receipt tokens using pool-specific Vault Transit keys."""

    def __init__(
        self,
        addr: str,
        *,
        audience: str,
        token: str | None = None,
        token_file: str | None = None,
        namespace: str | None = None,
        timeout: int = 10,
        opener: Callable[..., Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        allow_http: bool = False,
    ) -> None:
        cleaned_token = token.strip() if isinstance(token, str) else ""
        cleaned_file = token_file.strip() if isinstance(token_file, str) else ""
        if bool(cleaned_token) == bool(cleaned_file):
            raise ValueError("Configure exactly one Vault token source")
        if cleaned_file and not Path(cleaned_file).is_absolute():
            raise ValueError("Vault token file path must be absolute")
        if not audience.strip() or len(audience.strip()) > 160:
            raise ValueError("Receipt audience is invalid")
        self.addr = _vault_verifier_origin(addr, allow_http=allow_http)
        self.audience = audience.strip()
        self._static_token = cleaned_token or None
        self._token_file = cleaned_file or None
        self.namespace = namespace.strip() if namespace and namespace.strip() else None
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        ).open
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        source = "file" if self._token_file else "environment"
        return (
            "VaultTransitPoolImportReceiptVerifier("
            f"addr={self.addr!r}, audience={self.audience!r}, token_source={source!r})"
        )

    def _token(self) -> str:
        if self._static_token is not None:
            return self._static_token
        assert self._token_file is not None
        try:
            raw, metadata = read_stable_runtime_bytes_with_metadata(
                Path(self._token_file), max_bytes=_MAX_VAULT_TOKEN_BYTES
            )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                raise OSError
            token = raw.decode("utf-8").strip()
            if not token or any(character.isspace() for character in token):
                raise ValueError
            return token
        except (OSError, UnicodeError, ValueError):
            raise PoolImportReceiptVerifierUnavailable(
                "Secure import verifier unavailable"
            ) from None

    def _verify_transit(
        self, pool_type: PoolType, claims_bytes: bytes, signature: str
    ) -> None:
        key = f"email-platform-{pool_type}-import-receipt"
        url = f"{self.addr}/v1/transit/verify/{key}"
        body = json.dumps(
            {
                "input": base64.b64encode(_DOMAIN + claims_bytes).decode("ascii"),
                "signature": signature,
            },
            separators=(",", ":"),
        ).encode("ascii")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Vault-Token": self._token(),
        }
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_VAULT_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_VAULT_RESPONSE_BYTES:
                    raise PoolImportReceiptVerifierUnavailable(
                        "Secure import verifier unavailable"
                    )
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500:
                raise PoolImportReceiptInvalid("Secure import receipt is invalid") from None
            raise PoolImportReceiptVerifierUnavailable(
                "Secure import verifier unavailable"
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise PoolImportReceiptVerifierUnavailable(
                "Secure import verifier unavailable"
            ) from None
        try:
            value = parse_unique_json_bytes(raw)
        except JsonBoundaryError:
            raise PoolImportReceiptVerifierUnavailable(
                "Secure import verifier unavailable"
            ) from None
        if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
            raise PoolImportReceiptVerifierUnavailable(
                "Secure import verifier unavailable"
            )
        valid = value["data"].get("valid")
        if valid is not True:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")

    def verify(
        self,
        token: str,
        *,
        tenant_id: str,
        pool_type: PoolType,
        ordered_manifest_digest: str,
        item_count: int,
    ) -> VerifiedPoolImportReceipt:
        if not isinstance(token, str) or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        claims_bytes = _decode_segment(parts[1])
        try:
            signature = _decode_segment(parts[2]).decode("ascii")
        except UnicodeError:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid") from None
        signature_match = _TRANSIT_SIGNATURE_RE.fullmatch(signature)
        if signature_match is None:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        try:
            raw_claims = parse_unique_json_bytes(claims_bytes)
        except JsonBoundaryError:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid") from None
        if not isinstance(raw_claims, dict):
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        claims = dict(raw_claims)
        if canonical_receipt_claims(claims) != claims_bytes:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        try:
            receipt_id = str(UUID(str(claims["receipt_id"])))
            claim_pool = str(claims["pool_type"])
            claim_digest = str(claims["ordered_manifest_digest"])
            claim_count = int(claims["item_count"])
            issued_at_seconds = int(claims["issued_at"])
            expires_at_seconds = int(claims["expires_at"])
            key_version = int(claims["key_version"])
        except (KeyError, TypeError, ValueError, OverflowError):
            raise PoolImportReceiptInvalid("Secure import receipt is invalid") from None
        if (
            claims["schema_version"] != 1
            or isinstance(claims["schema_version"], bool)
            or claims["audience"] != self.audience
            or not isinstance(claims["audience"], str)
            or claims["receipt_id"] != receipt_id
            or claim_pool not in {"card", "mailbox"}
            or not _DIGEST_RE.fullmatch(claim_digest)
            or not 1 <= claim_count <= 100
            or key_version != int(signature_match.group(1))
            or isinstance(claims["item_count"], bool)
            or isinstance(claims["issued_at"], bool)
            or isinstance(claims["expires_at"], bool)
            or isinstance(claims["key_version"], bool)
            or claims["issued_at"] != issued_at_seconds
            or claims["expires_at"] != expires_at_seconds
            or claims["item_count"] != claim_count
            or claims["key_version"] != key_version
            or not isinstance(claims["tenant_id"], str)
            or not 1 <= len(claims["tenant_id"]) <= 64
        ):
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        if expires_at_seconds <= issued_at_seconds or (
            expires_at_seconds - issued_at_seconds > _MAX_RECEIPT_TTL_SECONDS
        ):
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        now_seconds = int(self._clock().timestamp())
        if issued_at_seconds > now_seconds + _MAX_FUTURE_SKEW_SECONDS:
            raise PoolImportReceiptInvalid("Secure import receipt is invalid")
        if expires_at_seconds <= now_seconds:
            raise PoolImportReceiptExpired("Secure import receipt has expired")
        self._verify_transit(pool_type, claims_bytes, signature)
        if (
            claims["tenant_id"] != tenant_id
            or claim_pool != pool_type
            or claim_digest != ordered_manifest_digest
            or claim_count != item_count
        ):
            raise PoolImportReceiptBindingMismatch(
                "Secure import receipt does not match this import"
            )
        return VerifiedPoolImportReceipt(
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            pool_type=pool_type,
            ordered_manifest_digest=claim_digest,
            item_count=claim_count,
            issued_at=datetime.fromtimestamp(issued_at_seconds, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(expires_at_seconds, tz=timezone.utc),
            key_version=key_version,
        )


def pool_import_receipt_verifier_from_settings(
    settings: Any,
) -> PoolImportReceiptVerifier:
    addr = str(getattr(settings, "vault_addr", "") or "").strip()
    if not addr:
        return UnconfiguredPoolImportReceiptVerifier()
    token_value = getattr(settings, "vault_token", None)
    token = (
        token_value.get_secret_value()
        if token_value is not None and hasattr(token_value, "get_secret_value")
        else token_value
    )
    environment = str(
        getattr(settings, "environment", "development")
    ).strip().lower()
    configured_audience = getattr(settings, "pool_import_receipt_audience", None)
    audience = (
        str(configured_audience).strip()
        if configured_audience
        else "email-platform:pool-import:" + environment
    )
    return VaultTransitPoolImportReceiptVerifier(
        addr,
        audience=audience,
        token=token,
        token_file=getattr(settings, "vault_token_file", None),
        namespace=getattr(settings, "vault_namespace", None),
        timeout=getattr(settings, "vault_timeout_seconds", 10),
        allow_http=environment in {"development", "test"},
    )
