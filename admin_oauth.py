from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from scripts.external_json import (
    StableFileError,
    read_stable_bytes,
    write_atomic_bytes,
)


ADMIN_API_BASE = "http://subscriber-api.qnxie.com/api/v1/admin"
ADMIN_ORIGIN = "http://subscriber-api.qnxie.com"
PROXY_ID = 2940
CONCURRENCY = 40
GROUP_IDS = [49]
REQUEST_TIMEOUT_SECONDS = 30
MAX_ACCOUNT_NAME_BYTES = 4 * 200
MAX_PROXY_ID_BYTES = 4300
MAX_ADMIN_TOKEN_BYTES = 64 * 1024
MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES = 128 * 1024

DEFAULT_MODEL_MAPPING = {
    model: model
    for model in (
        "gpt-5.2",
        "gpt-5.2-2025-12-11",
        "gpt-5.2-chat-latest",
        "gpt-5.2-pro",
        "gpt-5.2-pro-2025-12-11",
        "gpt-5.6",
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
        "gpt-5.5",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.4-2026-03-05",
        "gpt-5.3-codex-spark",
        "codex-auto-review",
        "gpt-4o-audio-preview",
        "gpt-4o-realtime-preview",
        "gpt-image-1",
        "gpt-image-1.5",
        "gpt-image-2",
    )
}

_CREDENTIAL_FIELDS = (
    "access_token",
    "expires_at",
    "refresh_token",
    "id_token",
    "email",
    "chatgpt_account_id",
    "chatgpt_user_id",
    "organization_id",
    "plan_type",
    "subscription_expires_at",
    "client_id",
)


class TokenStoreError(Exception):
    pass


class TokenValidationError(Exception):
    pass


class AccountNameStoreError(Exception):
    pass


class ProxyIdStoreError(Exception):
    pass


class AdminApiError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.ambiguous = ambiguous


class ConcurrencyLimitError(AdminApiError):
    def __init__(self, maximum: Any = None) -> None:
        message = "并发额度不足"
        if maximum is not None:
            message += f"，当前最大值为 {maximum}"
        super().__init__(message)
        self.maximum = maximum


def _concurrency_allowed(data: dict[str, Any]) -> tuple[bool, Any]:
    """Interpret compatibility variants without bypassing an explicit denial."""
    candidate = data
    nested = data.get("data")
    if "allowed" not in candidate and isinstance(nested, dict):
        candidate = nested

    maximum = candidate.get("max_concurrency")
    if maximum is None:
        maximum = candidate.get("max_allowed_concurrency")

    allowed = candidate.get("allowed")
    if allowed is True or allowed == 1:
        return True, maximum
    if isinstance(allowed, str):
        normalized = allowed.strip().lower()
        if normalized in {"true", "1", "yes", "allowed", "ok"}:
            return True, maximum
        if normalized in {"false", "0", "no", "denied"}:
            return False, maximum
    if allowed is False or allowed == 0:
        return False, maximum

    try:
        if maximum is not None:
            return float(maximum) >= CONCURRENCY, maximum
    except (TypeError, ValueError):
        pass

    # Some compatible deployments return only a successful status object.
    # The create endpoint remains authoritative and will reject excess quota.
    if candidate.get("success") is True or candidate.get("ok") is True:
        return True, maximum
    raise AdminApiError("管理端未返回可识别的并发额度检查结果")


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_ulong),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _protect_data(data: bytes) -> bytes:
    if os.name != "nt":
        raise TokenStoreError("DPAPI 仅支持 Windows")
    source_buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(
        len(data),
        ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    output = _DataBlob()
    try:
        success = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source),
            "MailCodeHelper admin token",
            None,
            None,
            None,
            0x01,
            ctypes.byref(output),
        )
        if not success:
            raise ctypes.WinError()
        return ctypes.string_at(output.pbData, output.cbData)
    except OSError as error:
        raise TokenStoreError("无法使用 Windows DPAPI 加密管理令牌") from error
    finally:
        if output.pbData:
            ctypes.windll.kernel32.LocalFree(output.pbData)


def _unprotect_data(data: bytes) -> bytes:
    if os.name != "nt":
        raise TokenStoreError("DPAPI 仅支持 Windows")
    source_buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(
        len(data),
        ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    output = _DataBlob()
    try:
        success = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source),
            None,
            None,
            None,
            None,
            0x01,
            ctypes.byref(output),
        )
        if not success:
            raise ctypes.WinError()
        return ctypes.string_at(output.pbData, output.cbData)
    except OSError as error:
        raise TokenStoreError("无法解密已保存的管理令牌") from error
    finally:
        if output.pbData:
            ctypes.windll.kernel32.LocalFree(output.pbData)


def default_token_path() -> Path:
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    return base / "MailCodeHelper" / "admin_token.bin"


def default_account_name_path() -> Path:
    return application_directory() / "account_name.txt"


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


class AccountNameStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_account_name_path()

    def save(self, name: str) -> None:
        normalized = name.strip()
        if not normalized:
            raise AccountNameStoreError("账号名称不能为空")
        if len(normalized) > 200 or "\n" in normalized or "\r" in normalized:
            raise AccountNameStoreError("账号名称格式无效")
        try:
            write_atomic_bytes(self.path, normalized.encode("utf-8"))
        except OSError as error:
            raise AccountNameStoreError("无法保存账号名称") from error

    def load(self) -> str | None:
        try:
            raw = read_stable_bytes(
                self.path,
                max_bytes=MAX_ACCOUNT_NAME_BYTES,
                allow_empty=True,
            )
        except StableFileError as error:
            if error.reason == "missing":
                return None
            raise AccountNameStoreError("无法读取已保存的账号名称") from error
        try:
            name = raw.decode("utf-8").strip()
        except UnicodeError as error:
            raise AccountNameStoreError("无法读取已保存的账号名称") from error
        if not name:
            return None
        if len(name) > 200 or "\n" in name or "\r" in name:
            raise AccountNameStoreError("已保存的账号名称格式无效")
        return name


def normalize_proxy_id(value: Any) -> int:
    try:
        proxy_id = int(str(value).strip())
    except (TypeError, ValueError) as error:
        raise ProxyIdStoreError("代理 ID 必须是正整数") from error
    if proxy_id <= 0:
        raise ProxyIdStoreError("代理 ID 必须是正整数")
    return proxy_id


def default_proxy_id_path() -> Path:
    return application_directory() / "proxy_id.txt"


class ProxyIdStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_proxy_id_path()

    def save(self, proxy_id: Any) -> int:
        normalized = normalize_proxy_id(proxy_id)
        try:
            write_atomic_bytes(self.path, str(normalized).encode("ascii"))
        except OSError as error:
            raise ProxyIdStoreError("无法保存代理 ID") from error
        return normalized

    def load(self) -> int:
        try:
            raw = read_stable_bytes(
                self.path,
                max_bytes=MAX_PROXY_ID_BYTES,
                allow_empty=True,
            )
        except StableFileError as error:
            if error.reason == "missing":
                return PROXY_ID
            raise ProxyIdStoreError("无法读取已保存的代理 ID") from error
        try:
            value = raw.decode("ascii")
        except UnicodeError as error:
            raise ProxyIdStoreError("无法读取已保存的代理 ID") from error
        return normalize_proxy_id(value)


class AdminTokenStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_token_path()

    def save(self, token: str) -> None:
        normalized = normalize_bearer_token(token)
        if not normalized:
            raise TokenValidationError("管理令牌不能为空")
        encoded = normalized.encode("utf-8")
        if len(encoded) > MAX_ADMIN_TOKEN_BYTES:
            raise TokenValidationError("管理令牌格式无效")
        encrypted = _protect_data(encoded)
        if not encrypted or len(encrypted) > MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES:
            raise TokenStoreError("无法保存已加密的管理令牌")
        try:
            write_atomic_bytes(self.path, encrypted)
        except OSError as error:
            raise TokenStoreError("无法保存已加密的管理令牌") from error

    def load(self) -> str | None:
        try:
            encrypted = read_stable_bytes(
                self.path,
                max_bytes=MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES,
                allow_empty=True,
            )
        except StableFileError as error:
            if error.reason == "missing":
                return None
            raise TokenStoreError("无法读取已保存的管理令牌") from error
        if not encrypted:
            raise TokenStoreError("已保存的管理令牌数据为空")
        try:
            return _unprotect_data(encrypted).decode("utf-8")
        except TokenStoreError:
            raise
        except Exception as error:
            raise TokenStoreError("无法读取已保存的管理令牌") from error

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            raise TokenStoreError("无法删除已保存的管理令牌") from error


def normalize_bearer_token(token: str) -> str:
    normalized = token.strip()
    if normalized.lower().startswith("bearer "):
        normalized = normalized[7:].strip()
    return normalized


def jwt_expiry(token: str) -> int | None:
    parts = normalize_bearer_token(token).split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        expiry = decoded.get("exp")
        return int(expiry) if expiry is not None else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def validate_admin_token(token: str, now: float | None = None) -> str:
    normalized = normalize_bearer_token(token)
    if not normalized:
        raise TokenValidationError("请输入管理端 Bearer Token")
    if len(normalized.encode("utf-8")) > MAX_ADMIN_TOKEN_BYTES:
        raise TokenValidationError("管理令牌格式无效")
    expiry = jwt_expiry(normalized)
    if expiry is not None and expiry <= int(time.time() if now is None else now):
        raise TokenValidationError("管理令牌已过期，请更新后重试")
    return normalized


def redact_secrets(message: str) -> str:
    text = str(message)
    patterns = (
        r"Bearer\s+[A-Za-z0-9._-]+",
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        r"\bac_[A-Za-z0-9._-]+",
        r"\brt\.[A-Za-z0-9._-]+",
    )
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
    return text[:300]


def parse_authorization_input(value: str, expected_state: str) -> str:
    entered = value.strip()
    if not entered:
        raise ValueError("请输入授权码")

    if "://" not in entered:
        return entered

    parsed = urllib.parse.urlparse(entered)
    query = urllib.parse.parse_qs(parsed.query)
    code = (query.get("code") or [""])[0].strip()
    callback_state = (query.get("state") or [""])[0].strip()
    if not code:
        raise ValueError("回调链接中没有授权码")
    if callback_state and callback_state != expected_state:
        raise ValueError("回调链接的 state 与当前授权会话不一致")
    return code


@dataclass(frozen=True)
class AuthSession:
    auth_url: str
    session_id: str
    state: str
    proxy_id: int = PROXY_ID


def build_account_payload(
    name: str,
    exchanged: dict[str, Any],
    proxy_id: Any = PROXY_ID,
) -> dict[str, Any]:
    account_name = name.strip()
    if not account_name:
        raise ValueError("账号名称不能为空")
    if not isinstance(exchanged, dict):
        raise ValueError("兑换响应格式无效")

    credentials: dict[str, Any] = {}
    for field in _CREDENTIAL_FIELDS:
        value = exchanged.get(field)
        if value is not None and value != "":
            credentials[field] = value
    if not credentials.get("access_token"):
        raise ValueError("兑换响应缺少 access_token")

    credentials["model_mapping"] = dict(DEFAULT_MODEL_MAPPING)

    extra: dict[str, Any] = {}
    email = exchanged.get("email")
    if email is not None and email != "":
        extra["email"] = email
    extra.update(
        {
            "privacy_mode": "training_off",
            "openai_oauth_responses_websockets_v2_mode": "off",
            "openai_oauth_responses_websockets_v2_enabled": False,
            "openai_long_context_billing_enabled": False,
        }
    )

    return {
        "name": account_name,
        "notes": "",
        "platform": "openai",
        "type": "oauth",
        "credentials": credentials,
        "extra": extra,
        "proxy_id": normalize_proxy_id(proxy_id),
        "concurrency": CONCURRENCY,
        "priority": 1,
        "rate_multiplier": 1,
        "group_ids": list(GROUP_IDS),
        "expires_at": None,
        "auto_pause_on_expired": True,
    }


def _response_error_message(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        message = data.get("detail") or data.get("message") or data.get("error")
        if message:
            return redact_secrets(str(message))
    return fallback


class AdminApiClient:
    def __init__(
        self,
        token: str,
        base_url: str = ADMIN_API_BASE,
        open_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.token = validate_admin_token(token)
        self.base_url = base_url.rstrip("/")
        self._open_fn = open_fn

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._open_fn is not None:
            return self._open_fn(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        ambiguous_on_network: bool = False,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}/{path.lstrip('/')}",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Origin": ADMIN_ORIGIN,
                "Referer": f"{ADMIN_ORIGIN}/admin/accounts",
                "User-Agent": "MailCodeHelper/2.0 (Windows)",
                "X-Admin-UI-Request": "1",
            },
        )
        try:
            with self._open(request, REQUEST_TIMEOUT_SECONDS) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as error:
            try:
                data = json.loads(error.read().decode("utf-8", errors="replace"))
            except Exception:
                data = None
            if error.code in {401, 403}:
                message = "管理令牌无效、已过期或无权限"
            elif error.code == 429:
                message = "管理端请求过于频繁，请稍后重试"
            elif error.code == 409:
                message = _response_error_message(data, "账号名称或账号记录冲突")
            else:
                message = _response_error_message(data, f"管理端请求失败（HTTP {error.code}）")
            raise AdminApiError(message, status=error.code) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise AdminApiError(
                "无法连接管理端或请求超时",
                ambiguous=ambiguous_on_network,
            ) from error

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise AdminApiError("管理端返回了无效 JSON") from error
        if not isinstance(data, dict):
            raise AdminApiError("管理端返回了无效数据")
        if "code" in data:
            if data.get("code") not in {0, "0"}:
                raise AdminApiError(
                    _response_error_message(data, "管理端业务请求失败")
                )
            unwrapped = data.get("data")
            if not isinstance(unwrapped, dict):
                raise AdminApiError("管理端成功响应缺少 data")
            data = unwrapped
        if data.get("success") is False:
            raise AdminApiError(_response_error_message(data, "管理端业务请求失败"))
        return data

    def check_concurrency(self) -> dict[str, Any]:
        data = self._post(
            "accounts/check-concurrency-limit",
            {
                "platform": "openai",
                "concurrency": CONCURRENCY,
                "group_ids": list(GROUP_IDS),
            },
        )
        allowed, maximum = _concurrency_allowed(data)
        if not allowed:
            raise ConcurrencyLimitError(maximum)
        return data

    def generate_auth_url(self, proxy_id: Any = PROXY_ID) -> AuthSession:
        selected_proxy_id = normalize_proxy_id(proxy_id)
        data = self._post(
            "openai/generate-auth-url",
            {"proxy_id": selected_proxy_id},
        )
        auth_url = data.get("auth_url")
        session_id = data.get("session_id")
        if not isinstance(auth_url, str) or not auth_url:
            raise AdminApiError("生成链接响应缺少 auth_url")
        if not isinstance(session_id, str) or not session_id:
            raise AdminApiError("生成链接响应缺少 session_id")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query)
        state = (query.get("state") or [""])[0]
        if not state:
            raise AdminApiError("授权链接中缺少 state")
        return AuthSession(
            auth_url=auth_url,
            session_id=session_id,
            state=state,
            proxy_id=selected_proxy_id,
        )

    def exchange_code(self, session: AuthSession, code: str) -> dict[str, Any]:
        return self._post(
            "openai/exchange-code",
            {
                "session_id": session.session_id,
                "code": code,
                "state": session.state,
                "proxy_id": session.proxy_id,
            },
        )

    def create_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("accounts", payload, ambiguous_on_network=True)


class AuthorizationService:
    def __init__(self, client: AdminApiClient) -> None:
        self.client = client

    def begin(self, proxy_id: Any = PROXY_ID) -> AuthSession:
        self.client.check_concurrency()
        return self.client.generate_auth_url(proxy_id)

    def complete(
        self,
        session: AuthSession,
        authorization_input: str,
        account_name: str,
    ) -> dict[str, Any]:
        code = parse_authorization_input(authorization_input, session.state)
        exchanged = self.client.exchange_code(session, code)
        payload = build_account_payload(account_name, exchanged, session.proxy_id)
        return self.client.create_account(payload)
