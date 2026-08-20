"""HTTP client used by the desktop application to call the platform API.

The client deliberately exposes only platform-owned operations.  Mailbox
passwords and Sub2 infrastructure settings have no place in its request API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from typing import Any
from uuid import uuid4

from session_store import (
    MemorySessionStore,
    SessionStore,
    SessionStoreError,
    WindowsDpapiSessionStore,
)


PLATFORM_BASE_URL_ENV = "PLATFORM_BASE_URL"
API_PREFIX = "/api/v1"
DEFAULT_TIMEOUT_SECONDS = 15.0


class PlatformClientError(Exception):
    """Base class for all platform client failures."""


class PlatformConfigurationError(PlatformClientError):
    """The client configuration is missing or invalid."""


class PlatformAuthenticationRequiredError(PlatformClientError):
    """An authenticated operation was attempted without an access token."""


class PlatformTransportError(PlatformClientError):
    """The platform could not be reached."""


class PlatformTimeoutError(PlatformTransportError):
    """The platform request exceeded the configured timeout."""


class PlatformProtocolError(PlatformClientError):
    """The platform returned a response that did not match its JSON contract."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        trace_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.trace_id = trace_id


class PlatformApiError(PlatformClientError):
    """A structured error returned by the platform API."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status: int,
        trace_id: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.trace_id = trace_id
        self.details = details


class PlatformAuthenticationError(PlatformApiError):
    """The platform rejected the current access token or its permissions."""


class PlatformDeviceAuthorizationError(PlatformClientError):
    """The OIDC device flow was denied, expired or returned an invalid state."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class PlatformSessionError(PlatformClientError):
    """A securely persisted OIDC refresh session could not be used."""


@dataclass(frozen=True)
class MailSessionSnapshot:
    id: str
    email_masked: str
    status: str
    expires_at: str
    trace_id: str | None = None


@dataclass(frozen=True)
class MailCodeSnapshot:
    status: str
    code: str | None = None


@dataclass(frozen=True)
class CardAllocationSnapshot:
    id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    status: str
    expires_at: str
    trace_id: str | None = None


@dataclass(frozen=True)
class CardRevealSnapshot:
    id: str
    allocation_id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    pan: str = dataclass_field(repr=False)
    cvv: str = dataclass_field(repr=False)
    reveal_expires_at: str
    trace_id: str | None = None


@dataclass(frozen=True)
class UploadJobSnapshot:
    id: str
    task_id: str
    status: str
    business_name: str
    policy_version: str
    external_ref: str | None
    error_code: str | None
    created_at: str
    updated_at: str
    trace_id: str | None = None


@dataclass(frozen=True)
class DeviceAuthorizationChallenge:
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int
    device_code: str = dataclass_field(repr=False)
    token_endpoint: str = dataclass_field(repr=False)
    client_id: str = dataclass_field(repr=False)


@dataclass(frozen=True)
class TaskSnapshot:
    id: str
    task_type: str
    status: str
    trace_id: str
    created_at: str
    expires_at: str | None
    closed_at: str | None


class LoopbackAuthorizationReceiver:
    """Receive one OAuth callback on an ephemeral IPv4 loopback port."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(4)
        except OSError:
            self._listener.close()
            raise
        port = int(self._listener.getsockname()[1])
        self.redirect_uri = f"http://127.0.0.1:{port}/callback"

    def __enter__(self) -> LoopbackAuthorizationReceiver:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._listener.close()

    @staticmethod
    def _reply(connection: socket.socket, status: str, text: str) -> None:
        body = (
            "<!doctype html><meta charset=utf-8><title>平台登录</title>"
            f"<p>{text}</p><p>现在可以关闭此页面。</p>"
        ).encode("utf-8")
        headers = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        connection.sendall(headers + body)

    def wait_for_code(
        self,
        *,
        expected_state: str,
        timeout: float,
        cancelled: Callable[[], bool],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> str:
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            if cancelled():
                raise PlatformDeviceAuthorizationError(
                    "统一身份登录已取消", code="cancelled"
                )
            self._listener.settimeout(min(0.25, max(0.01, deadline - monotonic())))
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2.0)
                raw = b""
                try:
                    while b"\r\n\r\n" not in raw and len(raw) <= 8192:
                        chunk = connection.recv(2048)
                        if not chunk:
                            break
                        raw += chunk
                    request_line = raw.split(b"\r\n", 1)[0].decode("ascii")
                    method, target, _version = request_line.split(" ", 2)
                except (OSError, UnicodeDecodeError, ValueError):
                    self._reply(connection, "400 Bad Request", "登录回调格式无效")
                    continue
                parsed = urllib.parse.urlsplit(target)
                if method != "GET" or parsed.path != "/callback":
                    self._reply(connection, "404 Not Found", "登录回调地址无效")
                    continue
                try:
                    query = urllib.parse.parse_qs(
                        parsed.query,
                        keep_blank_values=True,
                        strict_parsing=True,
                        max_num_fields=10,
                    )
                except ValueError:
                    self._reply(connection, "400 Bad Request", "登录回调参数无效")
                    continue
                states = query.get("state", [])
                if len(states) != 1 or not secrets.compare_digest(
                    states[0], expected_state
                ):
                    self._reply(connection, "400 Bad Request", "登录状态校验失败")
                    continue
                errors = query.get("error", [])
                if len(errors) == 1 and errors[0]:
                    self._reply(connection, "400 Bad Request", "统一身份登录未完成")
                    raise PlatformDeviceAuthorizationError(
                        "统一身份登录未完成", code=_safe_oauth_error({"error": errors[0]})
                    )
                codes = query.get("code", [])
                if len(codes) != 1 or not codes[0].strip():
                    self._reply(connection, "400 Bad Request", "登录授权码缺失")
                    continue
                self._reply(connection, "200 OK", "平台登录已完成")
                return codes[0].strip()
        raise PlatformDeviceAuthorizationError(
            "统一身份登录已过期", code="expired_token"
        )


ResponseOpener = Callable[..., Any]


def _default_session_store() -> SessionStore:
    if os.name == "nt":
        return WindowsDpapiSessionStore()
    return MemorySessionStore()


def _normalize_base_url(value: str | None) -> str:
    base_url = (value or "").strip().rstrip("/")
    if not base_url:
        raise PlatformConfigurationError(
            f"请设置 {PLATFORM_BASE_URL_ENV} 后再连接平台"
        )
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PlatformConfigurationError(
            f"{PLATFORM_BASE_URL_ENV} 必须是有效的 HTTP(S) 地址"
        )
    if parsed.username is not None or parsed.password is not None:
        raise PlatformConfigurationError(
            f"{PLATFORM_BASE_URL_ENV} 不得包含账号密码"
        )
    if parsed.scheme == "http" and parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise PlatformConfigurationError(
            f"{PLATFORM_BASE_URL_ENV} 仅允许 HTTPS；本机开发地址可使用 HTTP"
        )
    if parsed.query or parsed.fragment:
        raise PlatformConfigurationError(
            f"{PLATFORM_BASE_URL_ENV} 不得包含查询参数或片段"
        )
    return base_url


def _response_trace_id(headers: Any) -> str | None:
    if headers is None:
        return None
    return headers.get("X-Trace-Id") or headers.get("X-Trace-ID")


class PlatformClient:
    """Small synchronous client for the EXE's platform-owned workflow."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        opener: ResponseOpener | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")
        self.base_url = _normalize_base_url(
            base_url if base_url is not None else os.environ.get(PLATFORM_BASE_URL_ENV)
        )
        self.timeout = float(timeout)
        self._opener = opener or urllib.request.urlopen
        self._access_token: str | None = None
        self._session_store = session_store or _default_session_store()
        self._state_lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._auth_generation = 0
        self._oidc_session_active = False
        self.last_trace_id: str | None = None

    @property
    def is_authenticated(self) -> bool:
        with self._state_lock:
            return self._access_token is not None

    def set_access_token(self, access_token: str) -> None:
        normalized = access_token.strip()
        if not normalized or "\r" in normalized or "\n" in normalized:
            raise ValueError("access token 格式无效")
        with self._state_lock:
            self._access_token = normalized

    def clear_access_token(self) -> None:
        with self._state_lock:
            self._access_token = None

    def _begin_auth_attempt(self) -> int:
        with self._state_lock:
            self._auth_generation += 1
            self._access_token = None
            self._oidc_session_active = False
            return self._auth_generation

    def cancel_authentication(self) -> None:
        with self._state_lock:
            self._auth_generation += 1
            self._access_token = None
            self._oidc_session_active = False
            try:
                self._session_store.clear()
            except SessionStoreError as error:
                raise PlatformSessionError("无法清除已保存的平台会话") from error

    def _clear_access_for_attempt(self, generation: int) -> None:
        with self._state_lock:
            if generation == self._auth_generation:
                self._access_token = None

    def clear_refresh_session(self) -> None:
        with self._state_lock:
            self._oidc_session_active = False
            try:
                self._session_store.clear()
            except SessionStoreError as error:
                raise PlatformSessionError("无法清除已保存的平台会话") from error

    def _activate_oidc_tokens(
        self,
        payload: Mapping[str, Any],
        *,
        require_refresh: bool,
        require_token_type: bool,
        expected_generation: int | None = None,
    ) -> int:
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        token_type = payload.get("token_type")
        if (
            not isinstance(access_token, str)
            or not access_token.strip()
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
            or (
                require_token_type
                and (
                    not isinstance(token_type, str)
                    or token_type.lower() != "bearer"
                )
            )
            or (
                token_type is not None
                and (not isinstance(token_type, str) or token_type.lower() != "bearer")
            )
        ):
            raise PlatformProtocolError("统一身份令牌响应无效")
        if require_refresh and (
            not isinstance(refresh_token, str) or not refresh_token.strip()
        ):
            raise PlatformProtocolError("统一身份响应缺少可轮换会话")
        with self._state_lock:
            if (
                expected_generation is not None
                and expected_generation != self._auth_generation
            ):
                raise PlatformDeviceAuthorizationError(
                    "统一身份登录已取消", code="cancelled"
                )
            if refresh_token is not None:
                if not isinstance(refresh_token, str):
                    raise PlatformProtocolError("统一身份刷新令牌格式无效")
                try:
                    self._session_store.save(refresh_token)
                except (SessionStoreError, ValueError) as error:
                    self._access_token = None
                    self._oidc_session_active = False
                    try:
                        self._session_store.clear()
                    except SessionStoreError:
                        pass
                    raise PlatformSessionError("无法安全保存平台会话") from error
            try:
                self.set_access_token(access_token)
            except ValueError as error:
                raise PlatformProtocolError("统一身份访问令牌格式无效") from error
            self._oidc_session_active = True
        return expires_in

    @property
    def can_refresh_oidc_session(self) -> bool:
        with self._state_lock:
            return self._oidc_session_active

    def has_saved_refresh_session(self) -> bool:
        with self._state_lock:
            try:
                return self._session_store.load() is not None
            except (SessionStoreError, ValueError) as error:
                raise PlatformSessionError("无法读取已保存的平台会话") from error

    def get_auth_config(self) -> dict[str, str | None]:
        response = self._request_json("GET", "/auth/config", authenticated=False)
        expected = {"mode", "issuer", "client_id", "desktop_client_id", "audience"}
        if set(response) != expected or response.get("mode") not in {"local", "oidc"}:
            raise PlatformProtocolError("平台身份配置响应无效", trace_id=self.last_trace_id)
        if any(
            value is not None and not isinstance(value, str)
            for key, value in response.items()
            if key != "mode"
        ):
            raise PlatformProtocolError("平台身份配置字段类型无效", trace_id=self.last_trace_id)
        if response["mode"] == "oidc" and any(
            not isinstance(response.get(key), str) or not response[key].strip()
            for key in ("issuer", "client_id", "desktop_client_id", "audience")
        ):
            raise PlatformProtocolError("平台 OIDC 公共配置不完整", trace_id=self.last_trace_id)
        return response

    def login_with_authorization_code(
        self,
        on_authorization_url: Callable[[str], None],
        *,
        authorization_timeout: float = 300.0,
        cancelled: Callable[[], bool] | None = None,
        loopback_factory: Callable[[], LoopbackAuthorizationReceiver] = LoopbackAuthorizationReceiver,
    ) -> int:
        """Run browser Authorization Code + PKCE with a loopback callback."""

        if authorization_timeout <= 0:
            raise ValueError("authorization_timeout 必须大于 0")
        generation = self._begin_auth_attempt()
        is_cancelled = cancelled or (lambda: False)
        if is_cancelled():
            raise PlatformDeviceAuthorizationError(
                "统一身份登录已取消", code="cancelled"
            )
        config = self.get_auth_config()
        if config["mode"] != "oidc":
            raise PlatformDeviceAuthorizationError(
                "平台当前未启用统一身份登录", code="oidc_not_enabled"
            )
        issuer = _normalize_oidc_base(str(config["issuer"]))
        discovery = self._request_external_json(
            "GET", f"{issuer}/.well-known/openid-configuration"
        )
        authorization_endpoint = _same_origin_oidc_endpoint(
            discovery.get("authorization_endpoint"), issuer
        )
        token_endpoint = _same_origin_oidc_endpoint(
            discovery.get("token_endpoint"), issuer
        )
        client_id = _required_value(
            str(config["desktop_client_id"]), "desktop_client_id"
        )
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")

        with loopback_factory() as receiver:
            redirect = urllib.parse.urlsplit(receiver.redirect_uri)
            if (
                redirect.scheme != "http"
                or redirect.hostname != "127.0.0.1"
                or redirect.port is None
                or redirect.path != "/callback"
                or redirect.query
                or redirect.fragment
            ):
                raise PlatformProtocolError("统一身份回调地址无效")
            authorization_url = authorization_endpoint + "?" + urllib.parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": receiver.redirect_uri,
                    "scope": "openid profile email",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
            on_authorization_url(authorization_url)
            code = receiver.wait_for_code(
                expected_state=state,
                timeout=authorization_timeout,
                cancelled=is_cancelled,
            )
            if is_cancelled():
                raise PlatformDeviceAuthorizationError(
                    "统一身份登录已取消", code="cancelled"
                )
            status, token_payload = self._request_external_json_with_status(
                "POST",
                token_endpoint,
                form={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": receiver.redirect_uri,
                    "code_verifier": verifier,
                },
            )
        if status < 200 or status >= 300:
            raise PlatformDeviceAuthorizationError(
                "统一身份授权码兑换失败", code=_safe_oauth_error(token_payload)
            )
        if is_cancelled():
            raise PlatformDeviceAuthorizationError(
                "统一身份登录已取消", code="cancelled"
            )
        return self._activate_oidc_tokens(
            token_payload,
            require_refresh=True,
            require_token_type=True,
            expected_generation=generation,
        )

    def refresh_oidc_session(self) -> int:
        """Rotate the saved refresh token and replace the in-memory access token."""

        with self._refresh_lock:
            with self._state_lock:
                generation = self._auth_generation
                try:
                    refresh_token = self._session_store.load()
                except (SessionStoreError, ValueError) as error:
                    self._access_token = None
                    raise PlatformSessionError("无法读取已保存的平台会话") from error
            if not refresh_token:
                raise PlatformAuthenticationRequiredError("没有可恢复的平台会话")
            config = self.get_auth_config()
            if config["mode"] != "oidc":
                raise PlatformDeviceAuthorizationError(
                    "平台当前未启用统一身份登录", code="oidc_not_enabled"
                )
            issuer = _normalize_oidc_base(str(config["issuer"]))
            discovery = self._request_external_json(
                "GET", f"{issuer}/.well-known/openid-configuration"
            )
            token_endpoint = _same_origin_oidc_endpoint(
                discovery.get("token_endpoint"), issuer
            )
            client_id = _required_value(
                str(config["desktop_client_id"]), "desktop_client_id"
            )
            status, token_payload = self._request_external_json_with_status(
                "POST",
                token_endpoint,
                form={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                },
            )
            if status < 200 or status >= 300:
                code = _safe_oauth_error(token_payload)
                if code in {"invalid_grant", "invalid_token"}:
                    with self._state_lock:
                        if generation == self._auth_generation:
                            self._access_token = None
                            try:
                                self._session_store.clear()
                            except SessionStoreError as error:
                                raise PlatformSessionError(
                                    "无法清除失效的平台会话"
                                ) from error
                raise PlatformDeviceAuthorizationError(
                    "统一身份会话刷新失败", code=code
                )
            try:
                return self._activate_oidc_tokens(
                    token_payload,
                    require_refresh=True,
                    require_token_type=True,
                    expected_generation=generation,
                )
            except (PlatformProtocolError, PlatformSessionError):
                with self._state_lock:
                    if generation == self._auth_generation:
                        self._access_token = None
                        self._oidc_session_active = False
                        try:
                            self._session_store.clear()
                        except SessionStoreError:
                            pass
                raise

    def login_with_device_authorization(
        self,
        on_challenge: Callable[[DeviceAuthorizationChallenge], None],
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] | None = None,
    ) -> int:
        """Run OIDC Device Authorization Grant and keep the token in memory.

        The browser receives the organization login page. The EXE handles only
        the opaque device code and the resulting short-lived access token.
        """

        generation = self._begin_auth_attempt()
        is_cancelled = cancelled or (lambda: False)
        if is_cancelled():
            raise PlatformDeviceAuthorizationError(
                "统一身份登录已取消", code="cancelled"
            )
        config = self.get_auth_config()
        if config["mode"] != "oidc":
            raise PlatformDeviceAuthorizationError(
                "平台当前未启用统一身份登录", code="oidc_not_enabled"
            )
        issuer = _normalize_oidc_base(str(config["issuer"]))
        discovery = self._request_external_json(
            "GET", f"{issuer}/.well-known/openid-configuration"
        )
        device_endpoint = _same_origin_oidc_endpoint(
            discovery.get("device_authorization_endpoint"), issuer
        )
        token_endpoint = _same_origin_oidc_endpoint(
            discovery.get("token_endpoint"), issuer
        )
        client_id = _required_value(str(config["desktop_client_id"]), "desktop_client_id")
        status, authorization = self._request_external_json_with_status(
            "POST",
            device_endpoint,
            form={"client_id": client_id, "scope": "openid profile email"},
        )
        if status < 200 or status >= 300:
            raise PlatformDeviceAuthorizationError(
                "统一身份服务拒绝创建设备登录", code=_safe_oauth_error(authorization)
            )
        challenge = _decode_device_challenge(
            authorization, token_endpoint=token_endpoint, client_id=client_id
        )
        on_challenge(challenge)
        deadline = monotonic() + challenge.expires_in
        interval = challenge.interval
        while monotonic() < deadline:
            if is_cancelled():
                self._clear_access_for_attempt(generation)
                raise PlatformDeviceAuthorizationError(
                    "统一身份登录已取消", code="cancelled"
                )
            sleep(interval)
            if is_cancelled():
                self._clear_access_for_attempt(generation)
                raise PlatformDeviceAuthorizationError(
                    "统一身份登录已取消", code="cancelled"
                )
            status, token_payload = self._request_external_json_with_status(
                "POST",
                challenge.token_endpoint,
                form={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": challenge.device_code,
                    "client_id": challenge.client_id,
                },
            )
            if 200 <= status < 300:
                if is_cancelled():
                    self._clear_access_for_attempt(generation)
                    raise PlatformDeviceAuthorizationError(
                        "统一身份登录已取消", code="cancelled"
                    )
                return self._activate_oidc_tokens(
                    token_payload,
                    require_refresh=True,
                    require_token_type=True,
                    expected_generation=generation,
                )
            error_code = _safe_oauth_error(token_payload)
            if error_code == "authorization_pending":
                continue
            if error_code == "slow_down":
                interval += 5
                continue
            raise PlatformDeviceAuthorizationError(
                "统一身份登录未完成", code=error_code
            )
        raise PlatformDeviceAuthorizationError(
            "统一身份登录已过期", code="expired_token"
        )

    def login(
        self,
        tenant_id: str,
        email: str,
        password: str,
        device_id: str,
    ) -> int:
        """Log in with platform credentials, never a source-mailbox password.

        The returned access token stays only in this instance's memory.  The
        caller receives its lifetime in seconds so it can schedule re-login.
        """

        if not password or "\r" in password or "\n" in password:
            raise ValueError("平台账号密码格式无效")
        generation = self._begin_auth_attempt()
        self.clear_refresh_session()
        response = self._request_json(
            "POST",
            "/auth/login",
            {
                "tenant_id": _required_value(tenant_id, "tenant_id"),
                "email": _required_value(email, "email"),
                "password": password,
                "device_id": _required_value(device_id, "device_id"),
            },
            authenticated=False,
        )
        access_token = response.get("access_token")
        expires_in = response.get("expires_in")
        if not isinstance(access_token, str):
            raise PlatformProtocolError(
                "平台登录响应缺少 access_token",
                trace_id=self.last_trace_id,
            )
        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
        ):
            raise PlatformProtocolError(
                "平台登录响应缺少有效的 expires_in",
                trace_id=self.last_trace_id,
            )
        with self._state_lock:
            if generation != self._auth_generation:
                raise PlatformDeviceAuthorizationError(
                    "平台登录已取消", code="cancelled"
                )
            try:
                self.set_access_token(access_token)
            except ValueError as error:
                raise PlatformProtocolError(
                    "平台登录响应中的 access_token 无效",
                    trace_id=self.last_trace_id,
                ) from error
        return expires_in

    def me(self) -> dict[str, Any]:
        return self._request_json("GET", "/me")

    def create_task(
        self,
        task_type: str,
        idempotency_key: str,
        *,
        client_reference: str | None = None,
    ) -> dict[str, Any]:
        """Create a task using only identifiers safe for the desktop to send."""

        normalized_type = task_type.strip()
        if not normalized_type:
            raise ValueError("task_type 不能为空")
        payload: dict[str, str] = {
            "type": normalized_type,
            "idempotency_key": _required_value(
                idempotency_key, "idempotency_key"
            ),
        }
        if client_reference is not None:
            payload["client_reference"] = _required_value(
                client_reference, "client_reference"
            )
        return self._request_json("POST", "/tasks", payload)

    def get_task(self, task_id: str) -> dict[str, Any]:
        task_path = urllib.parse.quote(_required_value(task_id, "task_id"), safe="")
        return self._request_json("GET", f"/tasks/{task_path}")

    def list_tasks(self, *, limit: int = 50) -> list[TaskSnapshot]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit 必须是 1 到 100 的整数")
        response = self._request_json_list("GET", f"/tasks?limit={limit}")
        return [_decode_task(item, self.last_trace_id) for item in response]

    def close_task(self, task_id: str) -> dict[str, Any]:
        task_path = urllib.parse.quote(_required_value(task_id, "task_id"), safe="")
        return self._request_json("POST", f"/tasks/{task_path}/close")

    def prepare_logout_cleanup(self, task_id: str | None) -> Callable[[], None]:
        """Detach the current token and return a best-effort cleanup action.

        Detaching is synchronous, so a newly logged-in session cannot be
        cleared by a late cleanup thread.  The returned closure keeps the old
        tokens private and can only close the task and revoke the refresh token
        that belonged to the session active at logout.
        """

        session_error: PlatformSessionError | None = None
        refresh_token: str | None = None
        with self._state_lock:
            self._auth_generation += 1
            access_token = self._access_token
            self._access_token = None
            self._oidc_session_active = False
            try:
                refresh_token = self._session_store.load()
                self._session_store.clear()
            except (SessionStoreError, ValueError) as error:
                session_error = PlatformSessionError(
                    "无法清除已保存的平台会话"
                )
                session_error.__cause__ = error
        normalized_task_id = task_id.strip() if isinstance(task_id, str) else ""

        def cleanup() -> None:
            first_error: PlatformClientError | None = None
            if access_token is not None and normalized_task_id:
                task_path = urllib.parse.quote(normalized_task_id, safe="")
                try:
                    self._request_json(
                        "POST",
                        f"/tasks/{task_path}/close",
                        _access_token_override=access_token,
                    )
                except PlatformClientError as error:
                    first_error = error
            if refresh_token is not None:
                try:
                    self._revoke_oidc_refresh_token(refresh_token)
                except PlatformClientError as error:
                    if first_error is None:
                        first_error = error
            if session_error is not None:
                raise session_error
            if first_error is not None:
                raise first_error

        return cleanup

    def _revoke_oidc_refresh_token(self, refresh_token: str) -> None:
        """Best-effort remote revocation for a refresh token captured at logout."""

        config = self.get_auth_config()
        if config["mode"] != "oidc":
            return
        issuer = _normalize_oidc_base(str(config["issuer"]))
        discovery = self._request_external_json(
            "GET", f"{issuer}/.well-known/openid-configuration"
        )
        raw_endpoint = discovery.get("revocation_endpoint")
        if raw_endpoint is None:
            return
        revocation_endpoint = _same_origin_oidc_endpoint(raw_endpoint, issuer)
        client_id = _required_value(
            str(config["desktop_client_id"]), "desktop_client_id"
        )
        status, payload = self._request_external_json_with_status(
            "POST",
            revocation_endpoint,
            form={
                "client_id": client_id,
                "token": refresh_token,
                "token_type_hint": "refresh_token",
            },
            allow_empty=True,
        )
        if status < 200 or status >= 300:
            raise PlatformDeviceAuthorizationError(
                "统一身份会话撤销失败", code=_safe_oauth_error(payload)
            )

    def create_mail_session(self, task_id: str) -> MailSessionSnapshot:
        task_path = urllib.parse.quote(_required_value(task_id, "task_id"), safe="")
        response = self._request_json("POST", f"/tasks/{task_path}/mail-sessions")
        return _decode_mail_session(response, self.last_trace_id)

    def get_mail_code(self, session_id: str) -> MailCodeSnapshot:
        session_path = urllib.parse.quote(
            _required_value(session_id, "session_id"), safe=""
        )
        response = self._request_json(
            "GET", f"/mail-sessions/{session_path}/code"
        )
        return _decode_mail_code(response, self.last_trace_id)

    def revoke_mail_session(self, session_id: str) -> MailSessionSnapshot:
        session_path = urllib.parse.quote(
            _required_value(session_id, "session_id"), safe=""
        )
        response = self._request_json(
            "POST", f"/mail-sessions/{session_path}/revoke"
        )
        return _decode_mail_session(response, self.last_trace_id)

    def create_upload_job(
        self,
        task_id: str,
        business_name: str,
        idempotency_key: str,
    ) -> UploadJobSnapshot:
        task_path = urllib.parse.quote(_required_value(task_id, "task_id"), safe="")
        normalized_business = _required_value(business_name, "business_name")
        normalized_key = _required_value(idempotency_key, "idempotency_key")
        response = self._request_json(
            "POST",
            f"/tasks/{task_path}/uploads",
            {"business_name": normalized_business, "idempotency_key": normalized_key},
        )
        return _decode_upload_job(response, self.last_trace_id)

    def allocate_card(self, task_id: str) -> CardAllocationSnapshot:
        task_path = urllib.parse.quote(_required_value(task_id, "task_id"), safe="")
        response = self._request_json("POST", f"/tasks/{task_path}/card-allocations")
        return _decode_card_allocation(response, self.last_trace_id)

    def get_card_allocation(self, allocation_id: str) -> CardAllocationSnapshot:
        allocation_path = urllib.parse.quote(
            _required_value(allocation_id, "allocation_id"), safe=""
        )
        response = self._request_json("GET", f"/card-allocations/{allocation_path}")
        return _decode_card_allocation(response, self.last_trace_id)

    def release_card_allocation(self, allocation_id: str) -> CardAllocationSnapshot:
        allocation_path = urllib.parse.quote(
            _required_value(allocation_id, "allocation_id"), safe=""
        )
        response = self._request_json(
            "POST", f"/card-allocations/{allocation_path}/release"
        )
        return _decode_card_allocation(response, self.last_trace_id)

    def reveal_card_allocation(self, allocation_id: str) -> CardRevealSnapshot:
        allocation_path = urllib.parse.quote(
            _required_value(allocation_id, "allocation_id"), safe=""
        )
        response = self._request_json(
            "POST", f"/card-allocations/{allocation_path}/reveal"
        )
        return _decode_card_reveal(response, self.last_trace_id)

    def get_upload_job(self, job_id: str) -> UploadJobSnapshot:
        job_path = urllib.parse.quote(_required_value(job_id, "job_id"), safe="")
        response = self._request_json("GET", f"/upload-jobs/{job_path}")
        return _decode_upload_job(response, self.last_trace_id)

    def cancel_upload_job(self, job_id: str) -> UploadJobSnapshot:
        job_path = urllib.parse.quote(_required_value(job_id, "job_id"), safe="")
        response = self._request_json("POST", f"/upload-jobs/{job_path}/cancel")
        return _decode_upload_job(response, self.last_trace_id)

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        authenticated: bool = True,
        _access_token_override: str | None = None,
    ) -> dict[str, Any]:
        response = self._request_json_value(
            method,
            path,
            payload,
            authenticated=authenticated,
            _access_token_override=_access_token_override,
        )
        if not isinstance(response, dict):
            raise PlatformProtocolError(
                "平台 JSON 响应必须是对象",
                trace_id=self.last_trace_id,
            )
        return response

    def _request_json_list(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = True,
    ) -> list[dict[str, Any]]:
        response = self._request_json_value(
            method, path, authenticated=authenticated
        )
        if not isinstance(response, list) or any(
            not isinstance(item, dict) for item in response
        ):
            raise PlatformProtocolError(
                "平台 JSON 响应必须是对象列表",
                trace_id=self.last_trace_id,
            )
        return response

    def _request_json_value(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        authenticated: bool = True,
        _access_token_override: str | None = None,
    ) -> Any:
        if _access_token_override is not None:
            access_token = _access_token_override
        else:
            with self._state_lock:
                access_token = self._access_token
        if authenticated and access_token is None:
            raise PlatformAuthenticationRequiredError("请先登录平台")

        trace_id = str(uuid4())
        headers: dict[str, str] = {
            "Accept": "application/json",
            "X-Trace-Id": trace_id,
        }
        if authenticated:
            headers["Authorization"] = f"Bearer {access_token}"
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        request = urllib.request.Request(
            f"{self.base_url}{API_PREFIX}{path}",
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with self._opener(request, timeout=self.timeout) as response:
                response_body = response.read()
                self.last_trace_id = (
                    _response_trace_id(getattr(response, "headers", None)) or trace_id
                )
                status = getattr(response, "status", 200)
        except urllib.error.HTTPError as error:
            self.last_trace_id = _response_trace_id(error.headers) or trace_id
            self._raise_api_error(error.code, error.read(), self.last_trace_id)
        except (TimeoutError, socket.timeout) as error:
            self.last_trace_id = trace_id
            raise PlatformTimeoutError(
                f"平台请求超时（{self.timeout:g} 秒），trace_id={trace_id}"
            ) from error
        except urllib.error.URLError as error:
            self.last_trace_id = trace_id
            if isinstance(error.reason, (TimeoutError, socket.timeout)):
                raise PlatformTimeoutError(
                    f"平台请求超时（{self.timeout:g} 秒），trace_id={trace_id}"
                ) from error
            raise PlatformTransportError(
                f"无法连接平台，trace_id={trace_id}"
            ) from error
        except OSError as error:
            self.last_trace_id = trace_id
            raise PlatformTransportError(
                f"平台连接失败，trace_id={trace_id}"
            ) from error

        return self._decode_success(response_body, status, self.last_trace_id)

    def _request_external_json(
        self, method: str, url: str, *, form: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        status, payload = self._request_external_json_with_status(method, url, form=form)
        if status < 200 or status >= 300:
            raise PlatformDeviceAuthorizationError(
                "统一身份服务请求失败", code=_safe_oauth_error(payload)
            )
        return payload

    def _request_external_json_with_status(
        self,
        method: str,
        url: str,
        *,
        form: Mapping[str, str] | None = None,
        allow_empty: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        headers = {"Accept": "application/json"}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                response_body = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            response_body = error.read()
        except (TimeoutError, socket.timeout) as error:
            raise PlatformTimeoutError("统一身份服务请求超时") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, (TimeoutError, socket.timeout)):
                raise PlatformTimeoutError("统一身份服务请求超时") from error
            raise PlatformTransportError("无法连接统一身份服务") from error
        except OSError as error:
            raise PlatformTransportError("统一身份服务连接失败") from error
        if allow_empty and not response_body.strip():
            return status, {}
        try:
            payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PlatformProtocolError("统一身份服务返回无效 JSON") from error
        if not isinstance(payload, dict):
            raise PlatformProtocolError("统一身份服务响应必须是对象")
        return status, payload

    def _decode_success(
        self, body: bytes, status: int, trace_id: str | None
    ) -> Any:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PlatformProtocolError(
                "平台返回了无效的 JSON 响应",
                status=status,
                trace_id=trace_id,
            ) from error
        if not isinstance(payload, (dict, list)):
            raise PlatformProtocolError(
                "平台 JSON 响应必须是对象或列表",
                status=status,
                trace_id=trace_id,
            )
        return payload

    def _raise_api_error(
        self, status: int, body: bytes, header_trace_id: str | None
    ) -> None:
        try:
            payload = json.loads(body.decode("utf-8"))
            envelope = payload["error"]
            code = envelope["code"]
            message = envelope["message"]
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
        ) as error:
            raise PlatformProtocolError(
                f"平台返回 HTTP {status}，但错误响应格式无效",
                status=status,
                trace_id=header_trace_id,
            ) from error
        if not isinstance(code, str) or not isinstance(message, str):
            raise PlatformProtocolError(
                f"平台返回 HTTP {status}，但错误响应格式无效",
                status=status,
                trace_id=header_trace_id,
            )
        trace_id = envelope.get("trace_id") or header_trace_id
        self.last_trace_id = trace_id
        error_type = (
            PlatformAuthenticationError if status in {401, 403} else PlatformApiError
        )
        raise error_type(
            message,
            code=code,
            status=status,
            trace_id=trace_id,
            details=envelope.get("details"),
        )


def _required_value(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized or "\r" in normalized or "\n" in normalized:
        raise ValueError(f"{field_name} 格式无效")
    return normalized


def _normalize_oidc_base(value: str) -> str:
    normalized = _normalize_base_url(value)
    parsed = urllib.parse.urlsplit(normalized)
    if parsed.query or parsed.fragment:
        raise PlatformProtocolError("OIDC issuer 地址无效")
    return normalized


def _same_origin_oidc_endpoint(value: Any, issuer: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlatformProtocolError("OIDC discovery 缺少端点")
    endpoint = value.strip()
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    parsed_issuer = urllib.parse.urlsplit(issuer)
    if (
        parsed_endpoint.scheme != parsed_issuer.scheme
        or parsed_endpoint.hostname != parsed_issuer.hostname
        or parsed_endpoint.port != parsed_issuer.port
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or parsed_endpoint.fragment
    ):
        raise PlatformProtocolError("OIDC discovery 返回了非同源端点")
    return endpoint


def _safe_oauth_error(payload: Mapping[str, Any]) -> str:
    value = payload.get("error")
    if isinstance(value, str) and re.fullmatch(r"[a-z_]{1,64}", value):
        return value
    return "oidc_error"


def _decode_device_challenge(
    payload: Mapping[str, Any], *, token_endpoint: str, client_id: str
) -> DeviceAuthorizationChallenge:
    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    verification_uri = payload.get("verification_uri")
    complete = payload.get("verification_uri_complete")
    expires_in = payload.get("expires_in")
    interval = payload.get("interval", 5)
    if (
        not isinstance(device_code, str)
        or not device_code
        or not isinstance(user_code, str)
        or not user_code
        or not isinstance(verification_uri, str)
        or not verification_uri
        or (complete is not None and not isinstance(complete, str))
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in <= 0
        or not isinstance(interval, int)
        or isinstance(interval, bool)
        or interval <= 0
    ):
        raise PlatformProtocolError("设备登录响应格式无效")
    _same_origin_oidc_endpoint(verification_uri, token_endpoint)
    if complete is not None:
        _same_origin_oidc_endpoint(complete, token_endpoint)
    return DeviceAuthorizationChallenge(
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=complete,
        expires_in=expires_in,
        interval=interval,
        device_code=device_code,
        token_endpoint=token_endpoint,
        client_id=client_id,
    )


def _decode_task(payload: Mapping[str, Any], trace_id: str | None) -> TaskSnapshot:
    expected = {
        "id",
        "tenant_id",
        "user_id",
        "device_id",
        "type",
        "idempotency_key",
        "client_reference",
        "trace_id",
        "status",
        "expires_at",
        "closed_at",
        "created_at",
    }
    if set(payload) != expected:
        raise PlatformProtocolError("任务历史响应字段无效", trace_id=trace_id)
    required_strings = (
        "id",
        "tenant_id",
        "user_id",
        "device_id",
        "type",
        "idempotency_key",
        "trace_id",
        "status",
        "created_at",
    )
    if any(
        not isinstance(payload[key], str) or not payload[key].strip()
        for key in required_strings
    ):
        raise PlatformProtocolError("任务历史响应字段类型无效", trace_id=trace_id)
    if payload["status"] not in {"created", "closed", "expired", "cancelled", "completed"}:
        raise PlatformProtocolError("任务历史响应状态无效", trace_id=trace_id)
    if payload["client_reference"] is not None and not isinstance(
        payload["client_reference"], str
    ):
        raise PlatformProtocolError("任务历史响应字段类型无效", trace_id=trace_id)
    for key in ("created_at", "expires_at", "closed_at"):
        value = payload[key]
        if value is None and key != "created_at":
            continue
        if not isinstance(value, str):
            raise PlatformProtocolError("任务历史时间字段无效", trace_id=trace_id)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise PlatformProtocolError("任务历史时间字段无效", trace_id=trace_id) from error
        if parsed.tzinfo is None:
            raise PlatformProtocolError("任务历史时间必须包含时区", trace_id=trace_id)
    return TaskSnapshot(
        id=payload["id"],
        task_type=payload["type"],
        status=payload["status"],
        trace_id=payload["trace_id"],
        created_at=payload["created_at"],
        expires_at=payload["expires_at"],
        closed_at=payload["closed_at"],
    )


def _decode_mail_session(
    payload: Mapping[str, Any], trace_id: str | None
) -> MailSessionSnapshot:
    expected = {"id", "email_masked", "status", "expires_at", "trace_id"}
    required = expected - {"trace_id"}
    if set(payload) - expected or not required.issubset(payload):
        raise PlatformProtocolError(
            "邮箱会话响应字段无效",
            trace_id=trace_id,
        )
    if not all(isinstance(payload[field], str) for field in required):
        raise PlatformProtocolError(
            "邮箱会话响应字段类型无效",
            trace_id=trace_id,
        )
    if (
        not payload["id"].strip()
        or not payload["email_masked"].strip()
        or payload["status"]
        not in {"initializing", "waiting", "code_ready", "consumed", "expired", "revoked"}
        or (payload.get("trace_id") is not None and not isinstance(payload["trace_id"], str))
    ):
        raise PlatformProtocolError(
            "邮箱会话响应状态无效",
            trace_id=trace_id,
        )
    try:
        expires_at = payload["expires_at"].replace("Z", "+00:00")
        parsed_expiry = datetime.fromisoformat(expires_at)
    except ValueError as error:
        raise PlatformProtocolError(
            "邮箱会话响应过期时间无效",
            trace_id=trace_id,
        ) from error
    if parsed_expiry.tzinfo is None:
        raise PlatformProtocolError(
            "邮箱会话响应过期时间必须包含时区",
            trace_id=trace_id,
        )
    return MailSessionSnapshot(
        id=payload["id"],
        email_masked=payload["email_masked"],
        status=payload["status"],
        expires_at=payload["expires_at"],
        trace_id=payload.get("trace_id"),
    )


def _decode_mail_code(
    payload: Mapping[str, Any], trace_id: str | None
) -> MailCodeSnapshot:
    if set(payload) - {"status", "code"} or "status" not in payload:
        raise PlatformProtocolError(
            "邮箱验证码响应字段无效",
            trace_id=trace_id,
        )
    status = payload["status"]
    code = payload.get("code")
    if not isinstance(status, str) or status not in {
        "initializing",
        "waiting",
        "code_ready",
        "consumed",
        "expired",
        "revoked",
    }:
        raise PlatformProtocolError(
            "邮箱验证码响应状态无效",
            trace_id=trace_id,
        )
    if code is not None and (
        not isinstance(code, str) or re.fullmatch(r"\d{4,8}", code) is None
    ):
        raise PlatformProtocolError(
            "邮箱验证码响应代码无效",
            trace_id=trace_id,
        )
    if code is not None and status != "consumed":
        raise PlatformProtocolError(
            "邮箱验证码响应状态与代码不一致",
            trace_id=trace_id,
        )
    return MailCodeSnapshot(status=status, code=code)


def _decode_upload_job(
    payload: Mapping[str, Any], trace_id: str | None
) -> UploadJobSnapshot:
    expected = {
        "id",
        "task_id",
        "status",
        "business_name",
        "policy_version",
        "external_ref",
        "error_code",
        "created_at",
        "updated_at",
        "trace_id",
    }
    if set(payload) - expected:
        raise PlatformProtocolError("上传作业响应字段无效", trace_id=trace_id)
    required_strings = (
        "id",
        "task_id",
        "status",
        "business_name",
        "policy_version",
        "created_at",
        "updated_at",
    )
    if any(not isinstance(payload[key], str) or not payload[key].strip() for key in required_strings):
        raise PlatformProtocolError("上传作业响应字段类型无效", trace_id=trace_id)
    for key in ("external_ref", "error_code"):
        if payload[key] is not None and not isinstance(payload[key], str):
            raise PlatformProtocolError("上传作业响应字段类型无效", trace_id=trace_id)
    if payload.get("trace_id") is not None and not isinstance(payload["trace_id"], str):
        raise PlatformProtocolError("上传作业响应字段类型无效", trace_id=trace_id)
    if payload["status"] not in {
        "queued",
        "running",
        "succeeded",
        "failed",
        "unknown",
        "cancelled",
        "cancel_pending",
    }:
        raise PlatformProtocolError("上传作业响应状态无效", trace_id=trace_id)
    return UploadJobSnapshot(
        id=payload["id"],
        task_id=payload["task_id"],
        status=payload["status"],
        business_name=payload["business_name"],
        policy_version=payload["policy_version"],
        external_ref=payload["external_ref"],
        error_code=payload["error_code"],
        created_at=payload["created_at"],
        updated_at=payload["updated_at"],
        trace_id=payload.get("trace_id"),
    )


def _decode_card_allocation(
    payload: Mapping[str, Any], trace_id: str | None
) -> CardAllocationSnapshot:
    expected = {
        "id",
        "card_masked",
        "brand",
        "expiry_month",
        "expiry_year",
        "status",
        "expires_at",
        "trace_id",
    }
    if set(payload) - expected:
        raise PlatformProtocolError("卡租约响应字段无效", trace_id=trace_id)
    for key in ("id", "card_masked", "brand", "status", "expires_at"):
        if not isinstance(payload[key], str) or not payload[key].strip():
            raise PlatformProtocolError("卡租约响应字段类型无效", trace_id=trace_id)
    if payload["status"] not in {"active", "released", "expired"}:
        raise PlatformProtocolError("卡租约响应状态无效", trace_id=trace_id)
    if payload.get("trace_id") is not None and not isinstance(payload["trace_id"], str):
        raise PlatformProtocolError("卡租约响应字段类型无效", trace_id=trace_id)
    for key in ("expiry_month", "expiry_year"):
        if payload[key] is not None and (
            not isinstance(payload[key], int) or isinstance(payload[key], bool)
        ):
            raise PlatformProtocolError("卡租约响应有效期无效", trace_id=trace_id)
    return CardAllocationSnapshot(
        id=payload["id"],
        card_masked=payload["card_masked"],
        brand=payload["brand"],
        expiry_month=payload["expiry_month"],
        expiry_year=payload["expiry_year"],
        status=payload["status"],
        expires_at=payload["expires_at"],
        trace_id=payload.get("trace_id"),
    )


def _decode_card_reveal(
    payload: Mapping[str, Any], trace_id: str | None
) -> CardRevealSnapshot:
    expected = {
        "id",
        "allocation_id",
        "card_masked",
        "brand",
        "expiry_month",
        "expiry_year",
        "pan",
        "cvv",
        "reveal_expires_at",
        "trace_id",
    }
    if set(payload) - expected:
        raise PlatformProtocolError("卡详情响应字段无效", trace_id=trace_id)
    for key in (
        "id",
        "allocation_id",
        "card_masked",
        "brand",
        "pan",
        "cvv",
        "reveal_expires_at",
    ):
        if not isinstance(payload[key], str) or not payload[key].strip():
            raise PlatformProtocolError("卡详情响应字段类型无效", trace_id=trace_id)
    if payload.get("trace_id") is not None and not isinstance(payload["trace_id"], str):
        raise PlatformProtocolError("卡详情响应字段类型无效", trace_id=trace_id)
    for key in ("expiry_month", "expiry_year"):
        if payload[key] is not None and (
            not isinstance(payload[key], int) or isinstance(payload[key], bool)
        ):
            raise PlatformProtocolError("卡详情响应有效期无效", trace_id=trace_id)
    return CardRevealSnapshot(
        id=payload["id"],
        allocation_id=payload["allocation_id"],
        card_masked=payload["card_masked"],
        brand=payload["brand"],
        expiry_month=payload["expiry_month"],
        expiry_year=payload["expiry_year"],
        pan=payload["pan"],
        cvv=payload["cvv"],
        reveal_expires_at=payload["reveal_expires_at"],
        trace_id=payload.get("trace_id"),
    )
