"""Server-side mailbox connector contract.

Connectors receive only an opaque secret reference. A production implementation
must resolve it through a secret manager; passwords never belong in Settings or
API request/response models.
"""

import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request

from platform.secrets import SecretResolver, SecretResolverUnavailable


class MailConnectorUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class MailboxAccess:
    mailbox_id: str
    secret_ref: str


@dataclass(frozen=True)
class MailCodeMessage:
    message_id: str
    watermark: str
    code: str


class MailConnector(Protocol):
    def current_watermark(self, mailbox: MailboxAccess) -> str | None:
        """Return the newest message watermark visible before polling starts."""

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        """Return only a message strictly newer than ``watermark``."""


class UnconfiguredMailConnector:
    def _raise(self) -> None:
        raise MailConnectorUnavailable("Mail connector is not configured")

    def current_watermark(self, mailbox: MailboxAccess) -> str | None:
        self._raise()

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        self._raise()


ResponseOpener = Callable[..., Any]
_MAX_RESPONSE_BYTES = 64 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _normalize_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip().rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Mail API URL must be HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Mail API URL must not contain credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Mail API URL must use HTTPS outside localhost")
    if parsed.query or parsed.fragment:
        raise ValueError("Mail API URL must not contain query or fragment")
    return urllib.parse.urlunsplit(parsed)


def _unwrap_response(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise MailConnectorUnavailable("Mail API returned invalid data")
    if "data" in data and "code" in data and data.get("code") not in {0, "0"}:
        raise MailConnectorUnavailable("Mail API returned failure")
    nested = data.get("data")
    if isinstance(nested, dict):
        return nested
    return data


def _optional_text(data: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = data.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, (dict, list, tuple)):
            return str(value).strip() or None
    return None


class HttpMailConnector:
    """Call a server-owned HTTP mailbox-code interface."""

    def __init__(
        self,
        base_url: str,
        secret_resolver: SecretResolver,
        *,
        timeout: int = 20,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = _normalize_https_url(base_url)
        self.secret_resolver = secret_resolver
        self.timeout = timeout
        self._opener = opener
        self._default_opener = urllib.request.build_opener(_NoRedirectHandler())

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return self._default_opener.open(request, timeout=timeout)

    def _post(
        self,
        action: str,
        mailbox: MailboxAccess,
        *,
        watermark: str | None = None,
    ) -> dict[str, Any]:
        try:
            mailbox_secret = dict(self.secret_resolver.resolve(mailbox.secret_ref))
        except SecretResolverUnavailable as error:
            raise MailConnectorUnavailable(str(error)) from error
        payload: dict[str, object] = {
            "mailbox_id": mailbox.mailbox_id,
            "mailbox": mailbox_secret,
        }
        if watermark is not None:
            payload["after_watermark"] = watermark
        request = urllib.request.Request(
            f"{self.base_url}/{action.lstrip('/')}",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "EmailPlatformMailConnector/1.0",
            },
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                get_url = getattr(response, "geturl", None)
                if callable(get_url) and get_url() != request.full_url:
                    raise MailConnectorUnavailable("Mail API redirect is forbidden")
                charset = response.headers.get_content_charset() or "utf-8"
                response_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(response_bytes) > _MAX_RESPONSE_BYTES:
                    raise MailConnectorUnavailable("Mail API response is too large")
                raw = response_bytes.decode(charset, errors="replace")
        except urllib.error.HTTPError as error:
            raise MailConnectorUnavailable(f"Mail API rejected request with HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise MailConnectorUnavailable("Mail API is unavailable") from error
        try:
            return _unwrap_response(json.loads(raw))
        except json.JSONDecodeError as error:
            raise MailConnectorUnavailable("Mail API returned invalid JSON") from error

    def current_watermark(self, mailbox: MailboxAccess) -> str | None:
        data = self._post("watermark", mailbox)
        return _optional_text(data, "watermark", "latest_watermark", "message_id")

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        data = self._post("code", mailbox, watermark=watermark)
        status = _optional_text(data, "status")
        if status is not None and status.lower() in {"waiting", "empty", "not_found"}:
            return None
        code = _optional_text(data, "code", "verification_code")
        message_id = _optional_text(data, "message_id", "id")
        next_watermark = _optional_text(data, "watermark", "latest_watermark", "message_id")
        if code is None and message_id is None and next_watermark is None:
            return None
        if code is None or not code.isdigit() or not 4 <= len(code) <= 8:
            raise MailConnectorUnavailable("Mail API returned invalid verification code")
        if message_id is None:
            message_id = next_watermark or code
        if next_watermark is None:
            next_watermark = message_id
        return MailCodeMessage(
            message_id=message_id,
            watermark=next_watermark,
            code=code,
        )
