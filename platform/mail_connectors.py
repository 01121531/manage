"""Server-side mailbox connector contract.

Connectors receive only an opaque secret reference. A production implementation
must resolve it through a secret manager; passwords never belong in Settings or
API request/response models.
"""

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence, TypeVar
import urllib.error
import urllib.parse
import urllib.request

from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.secrets import SecretResolver, SecretResolverUnavailable


class MailConnectorUnavailable(RuntimeError):
    pass


_ConnectorResult = TypeVar("_ConnectorResult")


def call_mail_connector(operation: Callable[[], _ConnectorResult]) -> _ConnectorResult:
    """Run one connector call behind a fixed, non-sensitive error boundary."""

    try:
        return operation()
    except Exception:
        pass
    raise MailConnectorUnavailable("Mail connector is unavailable") from None


@dataclass(frozen=True)
class MailboxAccess:
    mailbox_id: str
    secret_ref: str


@dataclass(frozen=True)
class MailCodeMessage:
    message_id: str
    watermark: str
    code: str
    received_at: datetime | None = None


class MailConnector(Protocol):
    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str:
        """Return the stable mailbox cursor at the persisted task start."""

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str
    ) -> MailCodeMessage | None:
        """Return only a message strictly newer than ``watermark``."""


class UnconfiguredMailConnector:
    def _raise(self) -> None:
        raise MailConnectorUnavailable("Mail connector is not configured")

    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str:
        self._raise()

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str
    ) -> MailCodeMessage | None:
        self._raise()


ResponseOpener = Callable[..., Any]
_MAX_RESPONSE_BYTES = 64 * 1024
_MAIL_AUTH_LOCATION = "request_json.mailbox"
_MAIL_CURSOR_FIELD = "after_watermark"
_MAIL_WATERMARK_BOUNDARY_FIELD = "received_at_or_before"
_MAIL_WATERMARK_BASIS_FIELD = "watermark_basis"
_MAIL_WATERMARK_BASIS = "task_created_at"
_MAIL_EMPTY_WATERMARK_STATUSES = ("empty", "not_found")
_MAIL_WAITING_STATUSES = ("waiting", "empty", "not_found")
_MAIL_FOUND_STATUSES = ("found", "success")
_MAIL_CODE_FIELDS = ("code", "verification_code")
_MAIL_MESSAGE_ID_FIELDS = ("message_id",)
_MAIL_WATERMARK_FIELDS = ("watermark",)
_MAIL_SENDER_FILTER_FIELD = "sender_filter"
_MAIL_SUBJECT_FILTER_FIELD = "subject_filter"
_MAIL_SENDER_FIELDS = ("sender",)
_MAIL_SUBJECT_FIELDS = ("subject",)
_MAIL_RECEIVED_AT_FIELD = "received_at"
_MAIL_CODE_DIGITS_MIN = 4
_MAIL_CODE_DIGITS_MAX = 8
_MAIL_CURSOR_MAX_LENGTH = 512


def mail_connector_contract_capabilities() -> dict[str, object]:
    """Return the generic HTTP connector behavior used by contract preflight."""

    return {
        "auth_location": _MAIL_AUTH_LOCATION,
        "watermark_at_task_start": True,
        "cursor_field": _MAIL_CURSOR_FIELD,
        "watermark_boundary_field": _MAIL_WATERMARK_BOUNDARY_FIELD,
        "watermark_basis_field": _MAIL_WATERMARK_BASIS_FIELD,
        "watermark_basis": _MAIL_WATERMARK_BASIS,
        "empty_watermark_statuses": _MAIL_EMPTY_WATERMARK_STATUSES,
        "pagination": "single_response",
        "rate_limit_strategy": "fixed_poll_interval",
        "waiting_statuses": _MAIL_WAITING_STATUSES,
        "code_fields": _MAIL_CODE_FIELDS,
        "message_id_fields": _MAIL_MESSAGE_ID_FIELDS,
        "watermark_fields": _MAIL_WATERMARK_FIELDS,
        "sender_filter_field": _MAIL_SENDER_FILTER_FIELD,
        "subject_filter_field": _MAIL_SUBJECT_FILTER_FIELD,
        "sender_fields": _MAIL_SENDER_FIELDS,
        "subject_fields": _MAIL_SUBJECT_FIELDS,
        "received_at_field": _MAIL_RECEIVED_AT_FIELD,
        "code_digits_min": _MAIL_CODE_DIGITS_MIN,
        "code_digits_max": _MAIL_CODE_DIGITS_MAX,
        "max_response_bytes": _MAX_RESPONSE_BYTES,
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _normalize_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Mail API URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Mail API URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Mail API URL must not contain query or fragment")
    return urllib.parse.urlunsplit(parsed).rstrip("/")


def _origin_key(value: str, *, allow_path: bool) -> tuple[str, str, int]:
    candidate = value.strip()
    if not candidate or "*" in candidate:
        raise ValueError("Mail allowed origin is invalid")
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise ValueError("Mail allowed origin is invalid")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Mail allowed origin is invalid")
    if (not allow_path and parsed.path) or parsed.query or parsed.fragment:
        raise ValueError("Mail allowed origin is invalid")
    hostname = parsed.hostname.lower()
    if (
        not hostname
        or hostname.endswith(".")
        or hostname == "localhost"
        or hostname.endswith(".localhost")
    ):
        raise ValueError("Mail allowed origin is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Mail allowed origin is invalid")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Mail allowed origin is invalid") from exc
    port = 443 if parsed_port is None else parsed_port
    if not 1 <= port <= 65_535:
        raise ValueError("Mail allowed origin is invalid")
    return ("https", hostname, port)


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


def _canonical_cursor(data: dict[str, Any], field: str) -> str | None:
    value = data.get(field)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > _MAIL_CURSOR_MAX_LENGTH:
        return None
    return value


def _utc_boundary(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_utc_datetime(data: dict[str, Any], field: str) -> datetime:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise MailConnectorUnavailable("Mail API returned invalid received_at")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise MailConnectorUnavailable("Mail API returned invalid received_at") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MailConnectorUnavailable("Mail API returned invalid received_at")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class _MailMessageFilter:
    expected_sender: str
    subject_contains: str


def _message_filter_from_secret(
    mailbox_secret: dict[str, object],
) -> _MailMessageFilter:
    expected_sender = mailbox_secret.pop("expected_sender", None)
    subject_contains = mailbox_secret.pop("subject_contains", None)
    if (
        not isinstance(expected_sender, str)
        or not isinstance(subject_contains, str)
        or expected_sender != expected_sender.strip()
        or subject_contains != subject_contains.strip()
        or not expected_sender
        or not subject_contains
        or len(expected_sender) > 320
        or len(subject_contains) > 256
        or any(character in expected_sender for character in "\r\n\0")
        or any(character in subject_contains for character in "\r\n\0")
    ):
        raise MailConnectorUnavailable("Mail filter configuration is unavailable")
    return _MailMessageFilter(
        expected_sender=expected_sender,
        subject_contains=subject_contains,
    )


class HttpMailConnector:
    """Call a server-owned HTTP mailbox-code interface."""

    def __init__(
        self,
        base_url: str,
        secret_resolver: SecretResolver,
        *,
        allowed_origins: Sequence[str],
        timeout: int = 20,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = _normalize_https_url(base_url)
        origin_keys = tuple(
            _origin_key(origin, allow_path=False) for origin in allowed_origins
        )
        if not origin_keys or len(set(origin_keys)) != len(origin_keys):
            raise ValueError("Mail allowed origins policy is invalid")
        if _origin_key(self.base_url, allow_path=True) not in origin_keys:
            raise ValueError("Mail API origin is not allowed")
        self.allowed_origins = frozenset(origin_keys)
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
        watermark_boundary: datetime | None = None,
    ) -> tuple[dict[str, Any], _MailMessageFilter]:
        try:
            mailbox_secret = dict(self.secret_resolver.resolve(mailbox.secret_ref))
        except SecretResolverUnavailable as error:
            raise MailConnectorUnavailable(str(error)) from error
        message_filter = _message_filter_from_secret(mailbox_secret)
        payload: dict[str, object] = {
            "mailbox_id": mailbox.mailbox_id,
            "mailbox": mailbox_secret,
            _MAIL_SENDER_FILTER_FIELD: message_filter.expected_sender,
            _MAIL_SUBJECT_FILTER_FIELD: message_filter.subject_contains,
        }
        if watermark is not None:
            payload[_MAIL_CURSOR_FIELD] = watermark
        if watermark_boundary is not None:
            payload[_MAIL_WATERMARK_BOUNDARY_FIELD] = _utc_boundary(
                watermark_boundary
            )
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
                response_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(response_bytes) > _MAX_RESPONSE_BYTES:
                    raise MailConnectorUnavailable("Mail API response is too large")
        except urllib.error.HTTPError as error:
            raise MailConnectorUnavailable(f"Mail API rejected request with HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise MailConnectorUnavailable("Mail API is unavailable") from error
        try:
            data = _unwrap_response(parse_unique_json_bytes(response_bytes))
        except JsonBoundaryError:
            raise MailConnectorUnavailable("Mail API returned invalid JSON") from None
        return data, message_filter

    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str:
        expected_boundary = _utc_boundary(task_started_at)
        data, _ = self._post(
            "watermark", mailbox, watermark_boundary=task_started_at
        )
        if (
            _optional_text(data, _MAIL_WATERMARK_BOUNDARY_FIELD)
            != expected_boundary
            or _optional_text(data, _MAIL_WATERMARK_BASIS_FIELD)
            != _MAIL_WATERMARK_BASIS
        ):
            raise MailConnectorUnavailable(
                "Mail API did not confirm task-start watermark"
            )
        watermark = _canonical_cursor(data, "watermark")
        if watermark is None:
            raise MailConnectorUnavailable(
                "Mail API did not confirm task-start watermark"
            )
        return watermark

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str
    ) -> MailCodeMessage | None:
        if (
            not isinstance(watermark, str)
            or not watermark.strip()
            or len(watermark.strip()) > _MAIL_CURSOR_MAX_LENGTH
        ):
            raise MailConnectorUnavailable("Mail API cursor is unavailable")
        watermark = watermark.strip()
        data, message_filter = self._post("code", mailbox, watermark=watermark)
        raw_status = data.get("status")
        if raw_status is not None and not isinstance(raw_status, str):
            raise MailConnectorUnavailable("Mail API returned invalid message status")
        status = raw_status.strip().lower() if isinstance(raw_status, str) else None
        found_field_names = {
            *_MAIL_CODE_FIELDS,
            *_MAIL_MESSAGE_ID_FIELDS,
            *_MAIL_WATERMARK_FIELDS,
            *_MAIL_SENDER_FIELDS,
            *_MAIL_SUBJECT_FIELDS,
        }
        if status in _MAIL_WAITING_STATUSES:
            if any(field in data for field in found_field_names):
                raise MailConnectorUnavailable("Mail API returned ambiguous message data")
            return None
        if status is not None and status not in _MAIL_FOUND_STATUSES:
            raise MailConnectorUnavailable("Mail API returned invalid message status")
        sender = _optional_text(data, *_MAIL_SENDER_FIELDS)
        subject = _optional_text(data, *_MAIL_SUBJECT_FIELDS)
        if (
            sender is None
            or subject is None
            or sender.casefold() != message_filter.expected_sender.casefold()
            or message_filter.subject_contains.casefold() not in subject.casefold()
        ):
            raise MailConnectorUnavailable("Mail API returned invalid message metadata")
        code = _optional_text(data, *_MAIL_CODE_FIELDS)
        message_id = _canonical_cursor(data, "message_id")
        next_watermark = _canonical_cursor(data, "watermark")
        if (
            code is None
            or not code.isdigit()
            or not _MAIL_CODE_DIGITS_MIN <= len(code) <= _MAIL_CODE_DIGITS_MAX
        ):
            raise MailConnectorUnavailable("Mail API returned invalid verification code")
        if message_id is None or next_watermark is None or next_watermark == watermark:
            raise MailConnectorUnavailable("Mail API returned invalid message cursor")
        received_at = _required_utc_datetime(data, _MAIL_RECEIVED_AT_FIELD)
        return MailCodeMessage(
            message_id=message_id,
            watermark=next_watermark,
            code=code,
            received_at=received_at,
        )
