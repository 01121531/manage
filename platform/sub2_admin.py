"""Server-side client for the official Sub2API admin account contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.file_boundary import RuntimeFileError, read_stable_runtime_bytes
from platform.secrets import SecretResolver, SecretResolverUnavailable


class Sub2AdminError(RuntimeError):
    pass


class Sub2AdminUnavailable(Sub2AdminError):
    pass


class Sub2AdminRejected(Sub2AdminError):
    pass


class Sub2AdminUnknown(Sub2AdminError):
    """A state-changing request may have completed remotely."""


@dataclass(frozen=True)
class Sub2AdminPolicy:
    version: str
    proxy_id: int | None
    group_ids: tuple[int, ...]
    concurrency: int
    priority: int = 1
    rate_multiplier: float = 1.0
    model_mapping: Mapping[str, str] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Sub2OAuthSession:
    auth_url: str = field(repr=False)
    session_id: str = field(repr=False)
    state: str = field(repr=False)
    proxy_id: int | None
    redirect_uri: str | None = None


@dataclass(frozen=True)
class Sub2OAuthCredentials:
    values: Mapping[str, object] = field(repr=False)


@dataclass(frozen=True)
class Sub2Account:
    account_id: int
    platform: str
    account_type: str
    status: str


@dataclass(frozen=True)
class Sub2AdminProbeResult:
    reachable: bool
    authenticated: bool


ResponseOpener = Callable[..., Any]
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_API_KEY_BYTES = 4096
_MAX_MODEL_MAPPING_BYTES = 64 * 1024
_IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,128}$")
_AMBIGUOUS_HTTP_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_CREDENTIAL_FIELDS = (
    "access_token",
    "expires_at",
    "refresh_token",
    "id_token",
    "email",
    "chatgpt_account_id",
    "chatgpt_user_id",
    "chatgpt_account_is_fedramp",
    "organization_id",
    "plan_type",
    "subscription_expires_at",
    "client_id",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


def _origin(value: str, *, allow_path: bool) -> tuple[str, str, int]:
    candidate = value.strip()
    if not candidate or "*" in candidate:
        raise ValueError("Sub2 admin URL is invalid")
    parsed = urllib.parse.urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path)
    ):
        raise ValueError("Sub2 admin URL is invalid")
    hostname = parsed.hostname.lower()
    if (
        not hostname
        or hostname.endswith(".")
        or hostname == "localhost"
        or hostname.endswith(".localhost")
    ):
        raise ValueError("Sub2 admin URL is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Sub2 admin URL is invalid")
    try:
        port = 443 if parsed.port is None else parsed.port
    except ValueError as error:
        raise ValueError("Sub2 admin URL is invalid") from error
    if not 1 <= port <= 65_535:
        raise ValueError("Sub2 admin URL is invalid")
    return ("https", hostname, port)


def _normalize_base_url(value: str, allowed_origins: Sequence[str]) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    origin = _origin(value, allow_path=True)
    allowed = tuple(_origin(item, allow_path=False) for item in allowed_origins)
    if not allowed or len(set(allowed)) != len(allowed) or origin not in allowed:
        raise ValueError("Sub2 admin origin is not allowed")
    path = parsed.path.rstrip("/")
    if path != "/api/v1/admin":
        raise ValueError("Sub2 admin base path is invalid")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _text(value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(character in value for character in "\r\n\0")
    ):
        raise Sub2AdminUnavailable("Sub2 admin configuration is unavailable")
    return value


def _auth_url(value: object) -> str:
    url = _text(value, maximum=16 * 1024)
    parsed = urllib.parse.urlsplit(url)
    try:
        port = 443 if parsed.port is None else parsed.port
    except ValueError:
        raise Sub2AdminUnknown("Sub2 OAuth result is unknown") from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "auth.openai.com"
        or port != 443
        or parsed.path != "/oauth/authorize"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise Sub2AdminUnknown("Sub2 OAuth result is unknown")
    return url


def _account(value: Mapping[str, object]) -> Sub2Account:
    account_id = value.get("id")
    platform = value.get("platform")
    account_type = value.get("type")
    status = value.get("status")
    if (
        not isinstance(account_id, int)
        or isinstance(account_id, bool)
        or account_id <= 0
        or platform != "openai"
        or account_type != "oauth"
        or not isinstance(status, str)
        or not status
    ):
        raise Sub2AdminUnknown("Sub2 account result is unknown")
    return Sub2Account(
        account_id=account_id,
        platform=platform,
        account_type=account_type,
        status=status,
    )


def _model_mapping(path: str) -> dict[str, str]:
    try:
        raw = read_stable_runtime_bytes(
            Path(path),
            max_bytes=_MAX_MODEL_MAPPING_BYTES,
        )
        value = parse_unique_json_bytes(raw)
    except (RuntimeFileError, JsonBoundaryError):
        raise RuntimeError("Sub2 model mapping policy is unavailable") from None
    if not isinstance(value, dict) or not value:
        raise RuntimeError("Sub2 model mapping policy is invalid")
    mapping: dict[str, str] = {}
    for source, target in value.items():
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or source != source.strip()
            or target != target.strip()
            or not source
            or not target
            or len(source.encode("utf-8")) > 256
            or len(target.encode("utf-8")) > 256
            or any(character in source for character in "\r\n\0")
            or any(character in target for character in "\r\n\0")
        ):
            raise RuntimeError("Sub2 model mapping policy is invalid")
        mapping[source] = target
    return mapping


class Sub2AdminAccountAdapter:
    """Provision OpenAI OAuth accounts without exposing admin or card secrets."""

    def __init__(
        self,
        base_url: str,
        admin_api_key_ref: str,
        secret_resolver: SecretResolver,
        *,
        allowed_origins: Sequence[str],
        timeout: int = 30,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = _normalize_base_url(base_url, allowed_origins)
        self.admin_api_key_ref = _text(admin_api_key_ref)
        self.secret_resolver = secret_resolver
        self.timeout = timeout
        self._opener = opener
        self._default_opener = urllib.request.build_opener(_NoRedirectHandler())

    def _open(self, request: urllib.request.Request) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=self.timeout)
        return self._default_opener.open(request, timeout=self.timeout)

    def _api_key(self) -> str:
        try:
            secret = self.secret_resolver.resolve(self.admin_api_key_ref)
        except SecretResolverUnavailable as error:
            raise Sub2AdminUnavailable("Sub2 admin credential is unavailable") from error
        for field_name in ("x_api_key", "admin_api_key", "value"):
            value = secret.get(field_name)
            if value is not None:
                return _text(value, maximum=_MAX_API_KEY_BYTES)
        raise Sub2AdminUnavailable("Sub2 admin credential is unavailable")

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, object] | None = None,
        idempotency_key: str | None = None,
        ambiguous: bool = False,
    ) -> dict[str, object]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "EmailPlatformSub2Admin/1.0",
            "x-api-key": self._api_key(),
        }
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if idempotency_key is not None:
            if _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
                raise ValueError("Sub2 idempotency key is invalid")
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(
            f"{self.base_url}/{path.lstrip('/')}",
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with self._open(request) as response:
                status = int(getattr(response, "status", 200))
                get_url = getattr(response, "geturl", None)
                if callable(get_url) and get_url() != request.full_url:
                    raise Sub2AdminUnknown("Sub2 admin result is unknown")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise Sub2AdminUnknown("Sub2 admin result is unknown")
        except urllib.error.HTTPError as error:
            if error.code in _AMBIGUOUS_HTTP_STATUSES:
                raise Sub2AdminUnknown("Sub2 admin result is unknown") from error
            raise Sub2AdminRejected(
                f"Sub2 admin request was rejected with HTTP {error.code}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            if ambiguous:
                raise Sub2AdminUnknown("Sub2 admin result is unknown") from error
            raise Sub2AdminUnavailable("Sub2 admin API is unavailable") from error
        if status not in range(200, 300):
            if status in _AMBIGUOUS_HTTP_STATUSES:
                raise Sub2AdminUnknown("Sub2 admin result is unknown")
            raise Sub2AdminRejected(
                f"Sub2 admin request was rejected with HTTP {status}"
            )
        try:
            envelope = parse_unique_json_bytes(raw)
        except JsonBoundaryError:
            raise Sub2AdminUnknown("Sub2 admin returned invalid JSON") from None
        code = envelope.get("code") if isinstance(envelope, dict) else None
        if not (
            isinstance(envelope, dict)
            and ((type(code) is int and code == 0) or code == "0")
        ):
            raise Sub2AdminRejected("Sub2 admin request was rejected")
        data = envelope.get("data")
        if not isinstance(data, dict):
            raise Sub2AdminUnknown("Sub2 admin result is unknown")
        return data

    def generate_auth_url(
        self,
        policy: Sub2AdminPolicy,
        *,
        redirect_uri: str | None = None,
    ) -> Sub2OAuthSession:
        payload: dict[str, object] = {"proxy_id": policy.proxy_id}
        if redirect_uri is not None:
            payload["redirect_uri"] = _text(redirect_uri, maximum=8192)
        data = self._request(
            "POST", "openai/generate-auth-url", payload=payload
        )
        auth_url = _auth_url(data.get("auth_url"))
        session_id = _text(data.get("session_id"))
        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(auth_url).query,
            keep_blank_values=True,
        )
        states = query.get("state")
        if not isinstance(states, list) or len(states) != 1:
            raise Sub2AdminUnknown("Sub2 OAuth result is unknown")
        state = _text(states[0])
        return Sub2OAuthSession(
            auth_url=auth_url,
            session_id=session_id,
            state=state,
            proxy_id=policy.proxy_id,
            redirect_uri=redirect_uri,
        )

    def exchange_code(
        self,
        session: Sub2OAuthSession,
        code: str,
    ) -> Sub2OAuthCredentials:
        payload: dict[str, object] = {
            "session_id": session.session_id,
            "code": _text(code),
            "state": session.state,
            "proxy_id": session.proxy_id,
        }
        if session.redirect_uri is not None:
            payload["redirect_uri"] = session.redirect_uri
        data = self._request(
            "POST", "openai/exchange-code", payload=payload, ambiguous=True
        )
        if not isinstance(data.get("access_token"), str) or not data["access_token"]:
            raise Sub2AdminUnknown("Sub2 OAuth result is unknown")
        return Sub2OAuthCredentials(values=data)

    def create_account(
        self,
        name: str,
        credentials: Sub2OAuthCredentials,
        policy: Sub2AdminPolicy,
        *,
        idempotency_key: str,
    ) -> Sub2Account:
        if policy.concurrency <= 0 or policy.priority < 0 or policy.rate_multiplier < 0:
            raise ValueError("Sub2 admin policy is invalid")
        account_name = _text(name, maximum=800)
        credential_payload = {
            key: credentials.values[key]
            for key in _CREDENTIAL_FIELDS
            if credentials.values.get(key) not in {None, ""}
        }
        if "access_token" not in credential_payload:
            raise ValueError("Sub2 OAuth credentials are invalid")
        credential_payload["model_mapping"] = dict(policy.model_mapping)
        payload: dict[str, object] = {
            "name": account_name,
            "notes": "",
            "platform": "openai",
            "type": "oauth",
            "credentials": credential_payload,
            "extra": {},
            "proxy_id": policy.proxy_id,
            "concurrency": policy.concurrency,
            "priority": policy.priority,
            "rate_multiplier": policy.rate_multiplier,
            "group_ids": list(policy.group_ids),
            "auto_pause_on_expired": True,
        }
        data = self._request(
            "POST",
            "accounts",
            payload=payload,
            idempotency_key=idempotency_key,
            ambiguous=True,
        )
        return _account(data)

    def get_account(self, account_id: int) -> Sub2Account:
        if not isinstance(account_id, int) or isinstance(account_id, bool) or account_id <= 0:
            raise ValueError("Sub2 account ID is invalid")
        return _account(self._request("GET", f"accounts/{account_id}"))

    def probe_credentials(self) -> Sub2AdminProbeResult:
        """Verify reachability and admin authentication without returning account data."""

        self._request("GET", "accounts?page=1&page_size=1")
        return Sub2AdminProbeResult(reachable=True, authenticated=True)


def sub2_admin_from_settings(
    settings: Any,
    secret_resolver: SecretResolver,
) -> tuple[Sub2AdminAccountAdapter, Sub2AdminPolicy] | None:
    """Build the optional Sub2 admin client without resolving its API key."""

    base_value = getattr(settings, "sub2_admin_base_url", None)
    base_url = base_value.strip() if isinstance(base_value, str) else ""
    ref_setting = getattr(settings, "sub2_admin_api_key_ref", None)
    ref_value = (
        ref_setting.get_secret_value()
        if ref_setting is not None and hasattr(ref_setting, "get_secret_value")
        else ref_setting
    )
    api_key_ref = ref_value.strip() if isinstance(ref_value, str) else ""
    proxy_id = getattr(settings, "sub2_admin_proxy_id", None)
    mapping_value = getattr(settings, "sub2_admin_model_mapping_file", None)
    mapping_file = mapping_value.strip() if isinstance(mapping_value, str) else ""

    if not base_url and not api_key_ref and proxy_id is None and not mapping_file:
        return None
    if not base_url or not api_key_ref or not mapping_file:
        raise RuntimeError("Sub2 admin configuration is incomplete")

    environment = str(getattr(settings, "environment", "development")).strip().lower()
    managed_environment = environment not in {"development", "test"}
    if managed_environment and not api_key_ref.startswith("vault://"):
        raise RuntimeError(
            "PLATFORM_SUB2_ADMIN_API_KEY_REF must use vault:// outside "
            "development/test"
        )
    if not api_key_ref.startswith(("vault://", "env://")):
        raise RuntimeError("PLATFORM_SUB2_ADMIN_API_KEY_REF is invalid")

    adapter = Sub2AdminAccountAdapter(
        base_url,
        api_key_ref,
        secret_resolver,
        allowed_origins=settings.resolved_sub2_allowed_origins(),
        timeout=settings.sub2_timeout_seconds,
    )
    policy = Sub2AdminPolicy(
        version=settings.sub2_policy_version,
        proxy_id=proxy_id,
        group_ids=(settings.sub2_group_id,),
        concurrency=settings.sub2_concurrency,
        model_mapping=_model_mapping(mapping_file),
    )
    return adapter, policy
