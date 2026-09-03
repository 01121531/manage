"""Verified GitHub Releases updater for the packaged Windows desktop app."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app_version import APP_VERSION
from scripts.external_json import (
    load_unique_json,
    parse_unique_json_bytes,
    read_stable_bytes,
    write_atomic_bytes,
)


DEFAULT_MANIFEST_URL = (
    "https://github.com/01121531/manage/releases/latest/download/update-manifest.json"
)
_REPOSITORY_RELEASE_PREFIX = "https://github.com/01121531/manage/releases/"
_DOWNLOAD_HOSTS = frozenset(
    {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_READY_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_PACKAGE_BYTES = 200 * 1024 * 1024
_MIN_PACKAGE_BYTES = 1024 * 1024
_UPDATE_NOTICE_FILE = "update-notice.json"
_MAX_UPDATE_NOTICE_BYTES = 256
_ROLLED_BACK_NOTICE = "startup_failed_rolled_back"
_NOTICE_MESSAGES = {
    _ROLLED_BACK_NOTICE: (
        "在线更新未能安全启动，已恢复原版本；当前版本可继续使用。"
        "请稍后重试，持续失败请联系管理员。"
    )
}


class UpdateError(RuntimeError):
    """A safe, user-facing update failure category."""


@dataclass(frozen=True)
class UpdateManifest:
    version: str
    download_url: str
    sha256: str
    size: int
    release_notes_url: str | None = None


UrlOpen = Callable[..., object]


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = _VERSION_PATTERN.fullmatch(value.strip())
    if match is None:
        raise UpdateError("更新版本格式无效")
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


def is_newer_version(candidate: str, current: str = APP_VERSION) -> bool:
    return _version_tuple(candidate) > _version_tuple(current)


def _is_loopback_http(parsed: urllib.parse.SplitResult) -> bool:
    return parsed.scheme == "http" and parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


def _validate_manifest_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.username or parsed.password or parsed.fragment:
        raise UpdateError("更新地址无效")
    normalized = urllib.parse.urlunsplit(parsed)
    if _is_loopback_http(parsed):
        return normalized
    if parsed.scheme != "https" or not normalized.startswith(_REPOSITORY_RELEASE_PREFIX):
        raise UpdateError("更新清单必须来自官方 GitHub Releases")
    return normalized


def _validate_download_url(value: str, *, allow_loopback: bool = False) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.username or parsed.password or parsed.fragment:
        raise UpdateError("更新包地址无效")
    normalized = urllib.parse.urlunsplit(parsed)
    if allow_loopback and _is_loopback_http(parsed):
        return normalized
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or not normalized.startswith(
            "https://github.com/01121531/manage/releases/download/"
        )
    ):
        raise UpdateError("更新包必须来自官方 GitHub Release")
    return normalized


def parse_update_manifest(
    value: object, *, allow_loopback_download: bool = False
) -> UpdateManifest:
    if not isinstance(value, dict):
        raise UpdateError("更新清单格式无效")
    required = {"version", "download_url", "sha256", "size"}
    if not required.issubset(value):
        raise UpdateError("更新清单缺少必要字段")
    version = value["version"]
    sha256 = value["sha256"]
    size = value["size"]
    if not isinstance(version, str):
        raise UpdateError("更新版本格式无效")
    _version_tuple(version)
    if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256.lower()):
        raise UpdateError("更新包摘要无效")
    if not isinstance(size, int) or isinstance(size, bool):
        raise UpdateError("更新包大小无效")
    if not _MIN_PACKAGE_BYTES <= size <= _MAX_PACKAGE_BYTES:
        raise UpdateError("更新包大小超出允许范围")
    download_url = value["download_url"]
    if not isinstance(download_url, str):
        raise UpdateError("更新包地址无效")
    notes = value.get("release_notes_url")
    if notes is not None:
        if not isinstance(notes, str):
            raise UpdateError("发行说明地址无效")
        notes = _validate_manifest_url(notes)
    return UpdateManifest(
        version=version.removeprefix("v"),
        download_url=_validate_download_url(
            download_url, allow_loopback=allow_loopback_download
        ),
        sha256=sha256.lower(),
        size=size,
        release_notes_url=notes,
    )


def update_cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path(tempfile.gettempdir())
    return root / "MailCodeHelper" / "updates"


def discard_downloaded_update(package: Path) -> bool:
    """Delete only a completed package owned by the update cache."""

    cache = update_cache_dir().resolve()
    candidate = package.resolve()
    if (
        candidate.parent != cache
        or candidate.suffix.lower() != ".exe"
        or not candidate.name.startswith("package-")
    ):
        return False
    try:
        candidate.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _startup_ready_path(token: str) -> Path | None:
    if not _READY_TOKEN_PATTERN.fullmatch(token):
        return None
    cache = update_cache_dir().resolve()
    path = cache / f"startup-ready-{token}.txt"
    return path if path.parent == cache else None


def _ready_marker_matches(path: Path, token: str) -> bool:
    try:
        return read_stable_bytes(path, max_bytes=len(token)) == token.encode("ascii")
    except (OSError, UnicodeError):
        return False


def confirm_update_startup(token: str) -> bool:
    """Confirm a verified update only after the replacement UI reaches first idle."""

    path = _startup_ready_path(token)
    if path is None:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="ascii") as marker:
            marker.write(token)
            marker.flush()
            os.fsync(marker.fileno())
    except FileExistsError:
        return _ready_marker_matches(path, token)
    except OSError:
        return False
    return True


def _write_update_notice(code: str) -> None:
    if code not in _NOTICE_MESSAGES:
        return
    cache = update_cache_dir().resolve()
    payload = json.dumps({"code": code}, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_UPDATE_NOTICE_BYTES:
        return
    try:
        write_atomic_bytes(cache / _UPDATE_NOTICE_FILE, payload)
    except OSError:
        pass


def consume_update_notice() -> str | None:
    """Consume one safe updater result without surfacing raw process errors."""

    path = update_cache_dir().resolve() / _UPDATE_NOTICE_FILE
    try:
        payload = load_unique_json(path, max_bytes=_MAX_UPDATE_NOTICE_BYTES)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    if not isinstance(payload, dict) or set(payload) != {"code"}:
        return None
    code = payload["code"]
    return _NOTICE_MESSAGES.get(code) if isinstance(code, str) else None


def _response_url(response: object) -> str | None:
    getter = getattr(response, "geturl", None)
    return getter() if callable(getter) else None


def _validate_final_github_url(value: str | None, *, allow_loopback: bool) -> None:
    if value is None:
        return
    parsed = urllib.parse.urlsplit(value)
    if allow_loopback and _is_loopback_http(parsed):
        return
    if parsed.scheme != "https" or parsed.hostname not in _DOWNLOAD_HOSTS:
        raise UpdateError("更新下载发生了不受信任的重定向")


class UpdateClient:
    def __init__(
        self,
        manifest_url: str | None = None,
        *,
        open_fn: UrlOpen = urllib.request.urlopen,
        timeout: float = 15.0,
    ) -> None:
        configured = manifest_url or os.environ.get(
            "PLATFORM_UPDATE_MANIFEST_URL", DEFAULT_MANIFEST_URL
        )
        self.manifest_url = _validate_manifest_url(configured)
        self._allow_loopback = urllib.parse.urlsplit(self.manifest_url).scheme == "http"
        self._open = open_fn
        self.timeout = timeout

    def fetch_manifest(self) -> UpdateManifest:
        request = urllib.request.Request(
            self.manifest_url,
            headers={"Accept": "application/json", "User-Agent": f"Manage/{APP_VERSION}"},
        )
        try:
            with self._open(request, timeout=self.timeout) as response:  # type: ignore[attr-defined]
                _validate_final_github_url(
                    _response_url(response), allow_loopback=self._allow_loopback
                )
                raw = response.read(_MAX_MANIFEST_BYTES + 1)
        except UpdateError:
            raise
        except Exception as error:
            raise UpdateError("无法获取更新清单") from error
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise UpdateError("更新清单过大")
        try:
            payload = parse_unique_json_bytes(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise UpdateError("更新清单格式无效") from error
        return parse_update_manifest(
            payload, allow_loopback_download=self._allow_loopback
        )

    def check(self) -> UpdateManifest | None:
        manifest = self.fetch_manifest()
        return manifest if is_newer_version(manifest.version) else None

    def download(self, manifest: UpdateManifest) -> Path:
        cache = update_cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        part = cache / f"package-{manifest.version}-{uuid4().hex}.exe.part"
        completed = part.with_suffix("")
        request = urllib.request.Request(
            manifest.download_url,
            headers={"Accept": "application/octet-stream", "User-Agent": f"Manage/{APP_VERSION}"},
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with self._open(request, timeout=max(self.timeout, 30.0)) as response:  # type: ignore[attr-defined]
                _validate_final_github_url(
                    _response_url(response), allow_loopback=self._allow_loopback
                )
                with part.open("xb") as output:
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > manifest.size or total > _MAX_PACKAGE_BYTES:
                            raise UpdateError("更新包大小与清单不一致")
                        digest.update(chunk)
                        output.write(chunk)
            if total != manifest.size or digest.hexdigest() != manifest.sha256:
                raise UpdateError("更新包完整性校验失败")
            os.replace(part, completed)
            return completed
        except UpdateError:
            part.unlink(missing_ok=True)
            raise
        except Exception as error:
            part.unlink(missing_ok=True)
            raise UpdateError("更新包下载失败") from error


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def launch_update_helper(package: Path, expected_sha256: str) -> None:
    if os.name != "nt" or not getattr(sys, "frozen", False):
        raise UpdateError("在线替换仅支持正式 Windows EXE")
    if not _SHA256_PATTERN.fullmatch(expected_sha256):
        raise UpdateError("更新包摘要无效")
    target = Path(sys.executable).resolve()
    cache = update_cache_dir().resolve()
    package = package.resolve()
    if package.parent != cache or not package.is_file():
        raise UpdateError("更新包位置无效")
    helper = cache / f"updater-{uuid4().hex}.exe"
    shutil.copy2(target, helper)
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        subprocess.Popen(
            [
                str(helper),
                "--apply-update",
                "--package",
                str(package),
                "--target",
                str(target),
                "--sha256",
                expected_sha256,
                "--parent-pid",
                str(os.getpid()),
            ],
            close_fds=True,
            creationflags=flags,
        )
    except Exception as error:
        helper.unlink(missing_ok=True)
        raise UpdateError("无法启动更新替换程序") from error


def _wait_for_process_exit(pid: int, timeout_seconds: int = 60) -> bool:
    if os.name != "nt":
        return False
    synchronize = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        return True
    try:
        return ctypes.windll.kernel32.WaitForSingleObject(
            handle, timeout_seconds * 1000
        ) == 0
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _launch_process(
    arguments: list[str], launch_fn: Callable[[list[str]], object] | None
) -> object:
    if launch_fn is not None:
        return launch_fn(arguments)
    return subprocess.Popen(arguments, close_fds=True)


def _process_exited(process: object) -> bool:
    poll = getattr(process, "poll", None)
    return callable(poll) and poll() is not None


def _stop_process(process: object) -> None:
    if _process_exited(process):
        return
    terminate = getattr(process, "terminate", None)
    wait = getattr(process, "wait", None)
    if callable(terminate):
        try:
            terminate()
        except OSError:
            pass
    if callable(wait):
        try:
            wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            kill = getattr(process, "kill", None)
            if callable(kill):
                try:
                    kill()
                    wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def _wait_for_startup_ready(
    process: object,
    ready_path: Path,
    token: str,
    *,
    timeout_seconds: float,
    stability_seconds: float,
    monotonic_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
) -> bool:
    deadline = monotonic_fn() + timeout_seconds
    ready_at: float | None = None
    while True:
        if _process_exited(process):
            return False
        now = monotonic_fn()
        if _ready_marker_matches(ready_path, token):
            if ready_at is None:
                ready_at = now
            if now - ready_at >= stability_seconds:
                return True
        if now >= deadline:
            return False
        sleep_fn(min(0.1, max(0.0, deadline - now)))


def apply_downloaded_update(
    *,
    package: Path,
    target: Path,
    expected_sha256: str,
    parent_pid: int,
    wait_fn: Callable[[int], bool] = _wait_for_process_exit,
    launch_fn: Callable[[list[str]], object] | None = None,
    startup_timeout_seconds: float = 30.0,
    startup_stability_seconds: float = 1.0,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    package = package.resolve()
    target = target.resolve()
    if package.parent != update_cache_dir().resolve() or package.suffix.lower() != ".exe":
        raise UpdateError("更新包位置无效")
    if target.suffix.lower() != ".exe" or not target.is_file():
        raise UpdateError("目标程序位置无效")
    if not _SHA256_PATTERN.fullmatch(expected_sha256):
        raise UpdateError("更新包摘要无效")
    if startup_timeout_seconds <= 0 or startup_stability_seconds < 0:
        raise UpdateError("更新启动确认参数无效")
    if not wait_fn(parent_pid):
        raise UpdateError("等待当前程序退出超时")
    if file_sha256(package) != expected_sha256:
        raise UpdateError("更新包完整性校验失败")
    staged = target.with_name(f".{target.name}.update-{uuid4().hex}")
    backup = target.with_name(f".{target.name}.rollback-{uuid4().hex}")
    ready_token = uuid4().hex
    ready_path = _startup_ready_path(ready_token)
    if ready_path is None:
        raise UpdateError("更新启动确认路径无效")
    ready_path.unlink(missing_ok=True)
    try:
        shutil.copy2(package, staged)
        if file_sha256(staged) != expected_sha256:
            raise UpdateError("更新文件复制校验失败")
        try:
            os.replace(target, backup)
        except OSError as error:
            raise UpdateError("无法备份当前程序") from error
        try:
            os.replace(staged, target)
        except OSError as error:
            try:
                os.replace(backup, target)
            except OSError as restore_error:
                raise UpdateError("更新替换失败且原版本恢复失败") from restore_error
            raise UpdateError("更新替换失败，已恢复原版本") from error

        process: object | None = None
        try:
            process = _launch_process(
                [str(target), "--update-ready-token", ready_token], launch_fn
            )
            startup_ready = _wait_for_startup_ready(
                process,
                ready_path,
                ready_token,
                timeout_seconds=startup_timeout_seconds,
                stability_seconds=startup_stability_seconds,
                monotonic_fn=monotonic_fn,
                sleep_fn=sleep_fn,
            )
        except Exception:
            startup_ready = False
        if not startup_ready:
            if process is not None:
                _stop_process(process)
            try:
                os.replace(backup, target)
            except OSError as restore_error:
                raise UpdateError("新版本启动失败且原版本恢复失败") from restore_error
            _write_update_notice(_ROLLED_BACK_NOTICE)
            try:
                _launch_process([str(target)], launch_fn)
            except Exception:
                raise UpdateError(
                    "新版本启动失败，已恢复原版本；请手动重新打开程序"
                ) from None
            raise UpdateError("新版本启动失败，已恢复原版本") from None

        backup.unlink(missing_ok=True)
        package.unlink(missing_ok=True)
    finally:
        staged.unlink(missing_ok=True)
        ready_path.unlink(missing_ok=True)


def cleanup_update_cache(*, max_age_seconds: int = 24 * 60 * 60) -> None:
    cache = update_cache_dir()
    if not cache.is_dir():
        return
    cutoff = time.time() - max_age_seconds
    for path in cache.iterdir():
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue


def apply_update_cli(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--apply-update", action="store_true", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    options = parser.parse_args(arguments)
    try:
        apply_downloaded_update(
            package=options.package,
            target=options.target,
            expected_sha256=options.sha256,
            parent_pid=options.parent_pid,
        )
    except UpdateError:
        return 1
    return 0


__all__ = [
    "DEFAULT_MANIFEST_URL",
    "UpdateClient",
    "UpdateError",
    "UpdateManifest",
    "apply_downloaded_update",
    "apply_update_cli",
    "cleanup_update_cache",
    "confirm_update_startup",
    "consume_update_notice",
    "discard_downloaded_update",
    "file_sha256",
    "is_newer_version",
    "launch_update_helper",
    "parse_update_manifest",
    "update_cache_dir",
]
