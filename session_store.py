"""Secure refresh-token storage for the desktop platform session."""

from __future__ import annotations

import ctypes
import hashlib
import os
from abc import ABC, abstractmethod
from ctypes import wintypes
from pathlib import Path


CRYPTPROTECT_UI_FORBIDDEN = 0x01


class SessionStoreError(Exception):
    """A refresh token could not be stored, read, or cleared safely."""


class SessionStore(ABC):
    """Storage boundary for the long-lived refresh token."""

    @abstractmethod
    def save(self, refresh_token: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def load(self) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> None:
        raise NotImplementedError


class MemorySessionStore(SessionStore):
    """Non-persistent store for tests and explicitly ephemeral sessions."""

    def __init__(self) -> None:
        self._refresh_token: str | None = None

    def save(self, refresh_token: str) -> None:
        self._refresh_token = _validate_refresh_token(refresh_token)

    def load(self) -> str | None:
        return self._refresh_token

    def clear(self) -> None:
        self._refresh_token = None


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _protect_data(data: bytes, entropy: bytes) -> bytes:
    if os.name != "nt":
        raise SessionStoreError("Windows DPAPI 仅支持 Windows")
    source_buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(
        len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    entropy_buffer = ctypes.create_string_buffer(entropy)
    optional_entropy = _DataBlob(
        len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    output = _DataBlob()
    try:
        success = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source),
            "MailCodeHelper platform refresh token",
            ctypes.byref(optional_entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        if not success:
            raise ctypes.WinError()
        return ctypes.string_at(output.pbData, output.cbData)
    except OSError as error:
        raise SessionStoreError("无法使用 Windows DPAPI 加密平台会话") from error
    finally:
        if output.pbData:
            ctypes.windll.kernel32.LocalFree(output.pbData)


def _unprotect_data(data: bytes, entropy: bytes) -> bytes:
    if os.name != "nt":
        raise SessionStoreError("Windows DPAPI 仅支持 Windows")
    source_buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(
        len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    entropy_buffer = ctypes.create_string_buffer(entropy)
    optional_entropy = _DataBlob(
        len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    output = _DataBlob()
    try:
        success = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source),
            None,
            ctypes.byref(optional_entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        if not success:
            raise ctypes.WinError()
        return ctypes.string_at(output.pbData, output.cbData)
    except OSError as error:
        raise SessionStoreError("无法解密已保存的平台会话") from error
    finally:
        if output.pbData:
            ctypes.windll.kernel32.LocalFree(output.pbData)


def default_session_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise SessionStoreError("未找到 Windows APPDATA，无法安全保存平台会话")
    return Path(appdata) / "MailCodeHelper" / "platform_refresh_token.bin"


def default_device_binding_id() -> str:
    """Return a stable local binding without sending the identifier to the API."""

    configured = os.environ.get("PLATFORM_DEVICE_BINDING_ID", "").strip()
    if configured:
        return configured
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
    except (ImportError, OSError, TypeError) as error:
        raise SessionStoreError("未找到 Windows 设备绑定标识，无法安全保存平台会话") from error
    if not isinstance(value, str) or not value.strip():
        raise SessionStoreError("Windows 设备绑定标识无效")
    return value.strip()


def _session_entropy(device_binding_id: str) -> bytes:
    normalized = device_binding_id.strip()
    if not normalized:
        raise ValueError("device_binding_id 不能为空")
    return hashlib.sha256(
        f"MailCodeHelper|platform-refresh-v1|{normalized}".encode("utf-8")
    ).digest()


class WindowsDpapiSessionStore(SessionStore):
    """Persist a refresh token as user-bound Windows DPAPI ciphertext."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        device_binding_id: str | None = None,
    ) -> None:
        if os.name != "nt":
            raise SessionStoreError("平台会话持久化需要 Windows DPAPI")
        self.path = path or default_session_path()
        self._entropy = _session_entropy(
            device_binding_id or default_device_binding_id()
        )

    def save(self, refresh_token: str) -> None:
        token = _validate_refresh_token(refresh_token)
        ciphertext = _protect_data(token.encode("utf-8"), self._entropy)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_bytes(ciphertext)
            os.replace(temporary, self.path)
        except OSError as error:
            raise SessionStoreError("无法保存已加密的平台会话") from error
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def load(self) -> str | None:
        if not self.path.exists():
            return None
        try:
            ciphertext = self.path.read_bytes()
        except OSError as error:
            raise SessionStoreError("无法读取已加密的平台会话") from error
        if not ciphertext:
            raise SessionStoreError("已保存的平台会话无效")
        try:
            token = _unprotect_data(ciphertext, self._entropy).decode("utf-8")
        except UnicodeDecodeError as error:
            raise SessionStoreError("已保存的平台会话内容无效") from error
        return _validate_refresh_token(token)

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            raise SessionStoreError("无法清除平台会话") from error


def _validate_refresh_token(refresh_token: str) -> str:
    normalized = refresh_token.strip()
    if not normalized or "\r" in normalized or "\n" in normalized:
        raise ValueError("refresh token 格式无效")
    return normalized
