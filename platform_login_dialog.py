"""Platform account login dialog for the desktop application.

The dialog deliberately owns only platform credentials.  Source mailbox
credentials, Sub2 credentials, proxies, groups and concurrency settings do
not belong in this module.  The small controller and validation helpers are
kept independent from Tk so they can be tested on a headless build machine.
"""

from __future__ import annotations

import re
import threading
import tkinter as tk
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Any

from platform_client import (
    PlatformApiError,
    PlatformAuthenticationError,
    PlatformClient,
    PlatformClientError,
    PlatformConfigurationError,
    PlatformDeviceAuthorizationError,
    PlatformProtocolError,
    PlatformSessionError,
    PlatformTimeoutError,
    PlatformTransportError,
    DeviceAuthorizationChallenge,
)


# These values intentionally match the dark palette already used by app.py
# and oauth_dialog.py.  Keeping them local avoids importing the legacy UI.
BG = "#0b1220"
PANEL = "#111c32"
FIELD = "#172238"
TEXT = "#e5e7eb"
MUTED = "#94a3b8"
ACCENT = "#38bdf8"
ERROR = "#fca5a5"
SUCCESS = "#86efac"


@dataclass(frozen=True)
class LoginCredentials:
    """Validated platform credentials.

    ``repr=False`` is intentional: accidental debug logging must not expose
    the password.  The password exists only for the duration of a login call.
    """

    tenant_id: str
    email: str
    password: str = field(repr=False)
    device_id: str


def _clean_identifier(value: str | None, label: str) -> str:
    value = "" if value is None else str(value).strip()
    if not value:
        raise ValueError(f"请输入{label}")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{label}格式无效")
    return value


def make_login_credentials(
    tenant_id: str | None,
    email: str | None,
    password: str | None,
    device_id: str | None,
) -> LoginCredentials:
    """Validate and normalize form values without touching Tk.

    Password whitespace is preserved (some organizations permit it), while
    empty and newline-containing passwords are rejected.  No value is echoed
    in a validation error.
    """

    tenant = _clean_identifier(tenant_id, "租户 ID")
    address = _clean_identifier(email, "平台邮箱")
    device = _clean_identifier(device_id, "设备 ID")
    secret = "" if password is None else str(password)
    if not secret:
        raise ValueError("请输入平台密码")
    if "\r" in secret or "\n" in secret:
        raise ValueError("平台密码格式无效")
    if "@" not in address or address.startswith("@") or address.endswith("@"):
        raise ValueError("平台邮箱格式无效")
    return LoginCredentials(tenant, address, secret, device)


def validate_login_fields(
    tenant_id: str | None,
    email: str | None,
    password: str | None,
    device_id: str | None,
) -> list[str]:
    """Return user-facing validation errors; an empty list means valid."""

    try:
        make_login_credentials(tenant_id, email, password, device_id)
    except ValueError as error:
        return [str(error)]
    return []


_SAFE_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_SAFE_TRACE_ID = re.compile(r"^[A-Fa-f0-9-]{8,80}$")


def _safe_error_metadata(error: BaseException) -> str:
    """Return non-secret trace metadata suitable for a status label."""

    code = getattr(error, "code", None)
    trace_id = getattr(error, "trace_id", None)
    parts: list[str] = []
    if isinstance(code, str) and _SAFE_CODE.fullmatch(code):
        parts.append(f"错误码：{code}")
    if isinstance(trace_id, str) and _SAFE_TRACE_ID.fullmatch(trace_id):
        parts.append(f"trace_id：{trace_id}")
    return "，".join(parts)


class _PartialLoginCleanupError(PlatformClientError):
    """Preserve the login failure while marking remote cleanup uncertain."""

    def __init__(self, identity_error: BaseException) -> None:
        super().__init__("partial login cleanup was not confirmed")
        self.identity_error = identity_error


def format_login_error(error: BaseException) -> str:
    """Convert platform failures into reason + recovery advice.

    We intentionally do not include ``str(error)``.  A misconfigured server
    could echo a password or token, and a desktop status label is not a safe
    place for either value.
    """

    cleanup_unconfirmed = isinstance(error, _PartialLoginCleanupError)
    effective_error = error.identity_error if cleanup_unconfirmed else error

    if isinstance(effective_error, PlatformAuthenticationError):
        reason = "平台账号或密码不正确，或账号无权访问该租户"
        advice = "请核对租户 ID、平台邮箱和密码；仍失败时联系管理员确认账号状态"
    elif isinstance(effective_error, PlatformConfigurationError):
        reason = "平台地址配置无效"
        advice = "请检查 PLATFORM_BASE_URL 是否为正确的 HTTPS 地址"
    elif isinstance(effective_error, PlatformTimeoutError):
        reason = "平台请求超时"
        advice = "请检查网络后重试；持续超时请联系管理员"
    elif isinstance(effective_error, PlatformTransportError):
        reason = "无法连接平台"
        advice = "请确认网络和平台服务状态后重试"
    elif isinstance(effective_error, PlatformSessionError):
        reason = "无法安全保存或恢复平台会话"
        advice = "请检查当前 Windows 用户的 DPAPI 与应用数据目录后重新登录"
    elif isinstance(effective_error, PlatformProtocolError):
        reason = "平台返回的数据格式异常"
        advice = "请升级客户端或联系管理员检查平台版本"
    elif isinstance(effective_error, PlatformDeviceAuthorizationError):
        reason = "统一身份登录未完成"
        advice = "请重新打开浏览器登录；持续失败时联系管理员检查账号和设备绑定"
    elif isinstance(effective_error, PlatformApiError):
        reason = "平台拒绝了登录请求"
        advice = "请核对输入并稍后重试；持续失败请联系管理员"
    elif isinstance(effective_error, ValueError):
        reason = "登录信息格式无效"
        advice = "请检查所有字段后重试"
    else:
        reason = "登录失败"
        advice = "请稍后重试；持续失败请联系管理员"
    metadata = _safe_error_metadata(effective_error)
    suffix = f"（{metadata}）" if metadata else ""
    if cleanup_unconfirmed:
        return (
            f"原因：{reason}{suffix}。"
            "影响：本地会话已清除，但服务端设备会话清理未确认。"
            "下一步：检查网络后重新登录；持续失败请联系管理员核对当前设备会话。"
        )
    return f"{reason}{suffix}。建议：{advice}。"


_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "密码",
    "密钥",
)


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).replace("-", "_").lower()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def safe_user_info(value: Any) -> dict[str, Any]:
    """Keep safe scalar/list user fields while dropping secret-like keys."""

    def clean(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                str(key): clean(item_value)
                for key, item_value in item.items()
                if not _is_sensitive_key(key)
            }
        if isinstance(item, (list, tuple)):
            return [clean(part) for part in item]
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)

    cleaned = clean(value)
    return cleaned if isinstance(cleaned, dict) else {}


SuccessCallback = Callable[[dict[str, Any], int], None]
ErrorCallback = Callable[[BaseException], None]
ScheduleCallback = Callable[[Callable[[], None]], Any]
ThreadFactory = Callable[..., threading.Thread]


class PlatformLoginController:
    """Run login + ``me`` off the Tk event loop.

    ``schedule`` is normally ``window.after(0, callback)``.  Tests can pass a
    synchronous scheduler, so this class has no display dependency.
    """

    def __init__(
        self,
        client: PlatformClient,
        *,
        schedule: ScheduleCallback | None = None,
        thread_factory: ThreadFactory = threading.Thread,
    ) -> None:
        self.client = client
        self._schedule = schedule or (lambda callback: callback())
        self._thread_factory = thread_factory
        self.busy = False
        self._generation = 0
        self._device_cancel = threading.Event()
        self._cancel_cleanup_action: Callable[[], None] | None = None
        self._worker_lock = threading.Lock()
        self._worker_threads: list[threading.Thread] = []

    def _compensate_partial_login(self, error: BaseException) -> BaseException:
        """Detach a token issued before identity lookup failed, then clean it once."""

        if not self.client.is_authenticated:
            return error
        cleanup = self.client.prepare_logout_cleanup(None)
        try:
            cleanup()
        except PlatformClientError:
            return _PartialLoginCleanupError(error)
        return error

    def _schedule_current(
        self,
        generation: int,
        callback: Callable[[], None],
        *,
        cancel_event: threading.Event | None = None,
    ) -> None:
        """Schedule a callback only while its login attempt is still current."""

        def deliver() -> None:
            if generation != self._generation:
                return
            if cancel_event is not None and cancel_event.is_set():
                return
            callback()

        self._schedule(deliver)

    def _start_worker(
        self,
        worker: Callable[[], None],
        *,
        generation: int,
        on_error: ErrorCallback,
        cancel_event: threading.Event | None = None,
    ) -> bool:
        thread: threading.Thread

        def owned_worker() -> None:
            try:
                worker()
            finally:
                with self._worker_lock:
                    if thread in self._worker_threads:
                        self._worker_threads.remove(thread)

        thread = self._thread_factory(target=owned_worker, daemon=False)
        with self._worker_lock:
            self._worker_threads.append(thread)
        try:
            thread.start()
        except RuntimeError:
            with self._worker_lock:
                if thread in self._worker_threads:
                    self._worker_threads.remove(thread)
            if cancel_event is not None:
                cancel_event.set()
            if generation == self._generation:
                self.busy = False
                error = PlatformTransportError("login worker unavailable")
                self._schedule_current(
                    generation,
                    lambda: on_error(error),
                )
            return False
        return True

    def detach_worker_threads(self) -> tuple[threading.Thread, ...]:
        """Transfer ownership of any still-running login workers."""

        with self._worker_lock:
            threads = tuple(self._worker_threads)
            self._worker_threads.clear()
        return threads

    def stop_workers(self) -> None:
        self._generation += 1
        self._device_cancel.set()
        self.busy = False

    def submit(
        self,
        tenant_id: str | None,
        email: str | None,
        password: str | None,
        device_id: str | None,
        *,
        on_success: SuccessCallback,
        on_error: ErrorCallback,
        on_complete: Callable[[], None] | None = None,
    ) -> bool:
        """Validate and start one background login; return whether it started."""

        if self.busy or self._cancel_cleanup_action is not None:
            return False
        try:
            credentials = make_login_credentials(
                tenant_id, email, password, device_id
            )
        except ValueError as error:
            on_error(error)
            return False

        self.busy = True
        self._generation += 1
        generation = self._generation

        def worker() -> None:
            try:
                expires_in = self.client.login(
                    credentials.tenant_id,
                    credentials.email,
                    credentials.password,
                    credentials.device_id,
                )
                profile = safe_user_info(self.client.me())
                if generation != self._generation:
                    return
            except BaseException as error:  # marshal all worker failures safely
                if generation == self._generation:
                    error = self._compensate_partial_login(error)
                    self._schedule(lambda error=error: on_error(error))
            else:
                self._schedule(lambda: on_success(profile, expires_in))
            finally:
                def finish() -> None:
                    if generation != self._generation:
                        return
                    self.busy = False
                    if on_complete is not None:
                        on_complete()

                self._schedule(finish)

        return self._start_worker(
            worker,
            generation=generation,
            on_error=on_error,
        )

    def submit_device(
        self,
        *,
        on_challenge: Callable[[DeviceAuthorizationChallenge], None],
        on_success: SuccessCallback,
        on_error: ErrorCallback,
        on_complete: Callable[[], None] | None = None,
    ) -> bool:
        if self.busy or self._cancel_cleanup_action is not None:
            return False
        self.busy = True
        self._generation += 1
        generation = self._generation
        self._device_cancel = threading.Event()
        cancel_event = self._device_cancel

        def worker() -> None:
            try:
                def publish_challenge(
                    challenge: DeviceAuthorizationChallenge,
                ) -> None:
                    self._schedule_current(
                        generation,
                        lambda challenge=challenge: on_challenge(challenge),
                        cancel_event=cancel_event,
                    )

                expires_in = self.client.login_with_device_authorization(
                    publish_challenge,
                    cancelled=cancel_event.is_set,
                )
                profile = safe_user_info(self.client.me())
                if generation != self._generation:
                    return
            except BaseException as error:
                if generation == self._generation:
                    error = self._compensate_partial_login(error)
                    self._schedule_current(
                        generation,
                        lambda error=error: on_error(error),
                        cancel_event=cancel_event,
                    )
            else:
                self._schedule_current(
                    generation,
                    lambda: on_success(profile, expires_in),
                    cancel_event=cancel_event,
                )
            finally:
                def finish() -> None:
                    if generation != self._generation:
                        return
                    self.busy = False
                    if on_complete is not None:
                        on_complete()

                self._schedule(finish)

        return self._start_worker(
            worker,
            generation=generation,
            on_error=on_error,
            cancel_event=cancel_event,
        )

    def submit_authorization_code(
        self,
        *,
        on_authorization_url: Callable[[str], None],
        on_success: SuccessCallback,
        on_error: ErrorCallback,
        on_complete: Callable[[], None] | None = None,
    ) -> bool:
        """Start the preferred browser Authorization Code + PKCE flow."""

        if self.busy or self._cancel_cleanup_action is not None:
            return False
        self.busy = True
        self._generation += 1
        generation = self._generation
        self._device_cancel = threading.Event()
        cancel_event = self._device_cancel

        def worker() -> None:
            try:
                expires_in = self.client.login_with_authorization_code(
                    lambda url: self._schedule_current(
                        generation,
                        lambda url=url: on_authorization_url(url),
                        cancel_event=cancel_event,
                    ),
                    cancelled=cancel_event.is_set,
                )
                profile = safe_user_info(self.client.me())
                if generation != self._generation:
                    return
            except BaseException as error:
                if generation == self._generation:
                    error = self._compensate_partial_login(error)
                    self._schedule_current(
                        generation,
                        lambda error=error: on_error(error),
                        cancel_event=cancel_event,
                    )
            else:
                self._schedule_current(
                    generation,
                    lambda: on_success(profile, expires_in),
                    cancel_event=cancel_event,
                )
            finally:
                def finish() -> None:
                    if generation != self._generation:
                        return
                    self.busy = False
                    if on_complete is not None:
                        on_complete()

                self._schedule(finish)

        return self._start_worker(
            worker,
            generation=generation,
            on_error=on_error,
            cancel_event=cancel_event,
        )

    def cancel(self) -> bool:
        self.stop_workers()
        cleanup = self._cancel_cleanup_action
        if cleanup is None:
            prepare_cleanup = getattr(self.client, "prepare_logout_cleanup", None)
            if prepare_cleanup is None:
                self.client.cancel_authentication()
                return True
            try:
                cleanup = prepare_cleanup(None)
            except PlatformClientError:
                return False
            self._cancel_cleanup_action = cleanup
        try:
            cleanup()
        except PlatformClientError:
            return False
        if self._cancel_cleanup_action is cleanup:
            self._cancel_cleanup_action = None
        return True


class PlatformLoginDialog:
    """Dark, modal-capable Tk dialog for platform account login."""

    def __init__(
        self,
        parent: tk.Misc | None,
        client: PlatformClient,
        on_success: SuccessCallback,
        on_close: Callable[[], None] | None = None,
        *,
        tenant_id: str = "",
        email: str = "",
        device_id: str = "",
        title: str = "平台登录",
        window: tk.Misc | None = None,
    ) -> None:
        self._closed = False
        self._busy = False
        self._on_success = on_success
        self._on_close = on_close
        self._owns_root = window is None and parent is None
        if window is not None:
            self.window = window
        elif parent is None:
            self.window = tk.Tk()
        else:
            self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.configure(bg=BG)
        self.window.resizable(False, False)
        if parent is not None:
            self.window.transient(parent)
        self.window.protocol("WM_DELETE_WINDOW", self.close)

        self.tenant_var = tk.StringVar(self.window, value=tenant_id)
        self.email_var = tk.StringVar(self.window, value=email)
        self.password_var = tk.StringVar(self.window)
        self.device_var = tk.StringVar(self.window, value=device_id)
        self.device_verification_uri_var = tk.StringVar(self.window)
        self.device_user_code_var = tk.StringVar(self.window)
        self._password_visible = False
        self._auth_mode = "loading"
        self._device_challenge_generation = 0
        self._device_verification_uri: str | None = None
        self._device_user_code: str | None = None
        self._device_clipboard_value: str | None = None

        self._configure_styles()
        self._build_widgets()
        self._controller = PlatformLoginController(
            client,
            schedule=lambda callback: self._schedule(callback),
        )
        self.window.bind("<Return>", self._submit_event)
        self.window.bind("<Escape>", self._close_event)
        self.login_button.configure(state="disabled")
        self._load_auth_config(client)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.window)
        style.theme_use("clam")
        style.configure(
            "PlatformLogin.Action.TButton",
            font=("Microsoft YaHei UI", 9),
            padding=(11, 7),
            background="#1e293b",
            foreground=TEXT,
            borderwidth=0,
        )
        style.map(
            "PlatformLogin.Action.TButton",
            background=[("active", "#334155"), ("disabled", "#172033")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "PlatformLogin.Primary.TButton",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=(13, 7),
            background="#0284c7",
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "PlatformLogin.Primary.TButton",
            background=[("active", "#0369a1"), ("disabled", "#1e3a5f")],
            foreground=[("disabled", "#7790aa")],
        )

    def _build_widgets(self) -> None:
        panel = tk.Frame(self.window, bg=PANEL, padx=20, pady=16)
        panel.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Label(
            panel,
            text="平台登录",
            bg=PANEL,
            fg=TEXT,
            font=("Microsoft YaHei UI", 14, "bold"),
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            panel,
            text="使用平台账号登录；邮箱验证码和 Sub2 配置由平台托管",
            bg=PANEL,
            fg=MUTED,
            font=("Microsoft YaHei UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(4, 14))

        self.auth_area = tk.Frame(panel, bg=PANEL)
        self.auth_area.pack(fill="x")
        form = tk.Frame(self.auth_area, bg=PANEL)
        form.pack(fill="x")
        self.local_form = form
        form.grid_columnconfigure(1, weight=1)
        self.tenant_entry = self._add_field(form, 0, "租户 ID", self.tenant_var)
        self.email_entry = self._add_field(form, 1, "平台邮箱", self.email_var)
        self.password_entry = self._add_field(
            form, 2, "平台密码", self.password_var, show="*", columnspan=1
        )
        self.password_toggle = tk.Button(
            form,
            text="显示",
            command=self.toggle_password,
            bg="#263650",
            activebackground="#334155",
            activeforeground=TEXT,
            fg=TEXT,
            relief="flat",
            borderwidth=0,
            font=("Microsoft YaHei UI", 8),
            padx=9,
            pady=3,
            takefocus=True,
        )
        self.password_toggle.grid(row=2, column=2, padx=(7, 0), pady=4, ipady=3)
        self.device_entry = self._add_field(form, 3, "设备 ID", self.device_var)

        self.oidc_panel = tk.Frame(self.auth_area, bg=PANEL)
        tk.Label(
            self.oidc_panel,
            text="点击下方按钮后，将在系统浏览器中完成统一身份认证。\nEXE 不会读取或保存您的生产平台密码。",
            bg=PANEL,
            fg=TEXT,
            justify="left",
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        ).pack(fill="x", pady=(4, 8))
        self.device_fallback_button = ttk.Button(
            self.oidc_panel,
            text="浏览器回调不可用？使用设备代码",
            command=self.submit_device_fallback,
            style="PlatformLogin.Action.TButton",
        )
        self.device_fallback_button.pack(anchor="w", pady=(0, 4))

        self.device_challenge_panel = tk.Frame(
            self.oidc_panel, bg=FIELD, padx=10, pady=8
        )
        self.device_challenge_panel.grid_columnconfigure(1, weight=1)
        tk.Label(
            self.device_challenge_panel,
            text="登录网址",
            bg=FIELD,
            fg=MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        ).grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        self.device_verification_uri_entry = tk.Entry(
            self.device_challenge_panel,
            textvariable=self.device_verification_uri_var,
            state="readonly",
            readonlybackground=FIELD,
            fg=TEXT,
            relief="flat",
            font=("Consolas", 9),
            takefocus=True,
        )
        self.device_verification_uri_entry.grid(
            row=0, column=1, sticky="ew", pady=3, ipady=3
        )
        self.copy_device_uri_button = ttk.Button(
            self.device_challenge_panel,
            text="复制登录网址",
            command=self.copy_device_verification_uri,
            style="PlatformLogin.Action.TButton",
            takefocus=True,
        )
        self.copy_device_uri_button.grid(row=0, column=2, padx=(8, 0), pady=3)
        tk.Label(
            self.device_challenge_panel,
            text="设备代码",
            bg=FIELD,
            fg=MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        ).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        self.device_user_code_entry = tk.Entry(
            self.device_challenge_panel,
            textvariable=self.device_user_code_var,
            state="readonly",
            readonlybackground=FIELD,
            fg=TEXT,
            relief="flat",
            font=("Consolas", 10, "bold"),
            takefocus=True,
        )
        self.device_user_code_entry.grid(
            row=1, column=1, sticky="ew", pady=3, ipady=3
        )
        self.copy_device_code_button = ttk.Button(
            self.device_challenge_panel,
            text="复制设备代码",
            command=self.copy_device_user_code,
            style="PlatformLogin.Action.TButton",
            takefocus=True,
        )
        self.copy_device_code_button.grid(row=1, column=2, padx=(8, 0), pady=3)
        self.device_expiry_label = tk.Label(
            self.device_challenge_panel,
            text="",
            bg=FIELD,
            fg=MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 8),
        )
        self.device_expiry_label.grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(5, 0)
        )
        self.cancel_device_button = ttk.Button(
            self.device_challenge_panel,
            text="取消设备登录",
            command=self.cancel_device_fallback,
            style="PlatformLogin.Action.TButton",
            takefocus=True,
        )
        self.cancel_device_button.grid(row=2, column=2, padx=(8, 0), pady=(5, 0))

        self.status_label = tk.Label(
            panel,
            text="请输入平台账号信息",
            bg=PANEL,
            fg=MUTED,
            font=("Microsoft YaHei UI", 9),
            anchor="w",
            justify="left",
            wraplength=460,
        )
        self.status_label.pack(fill="x", pady=(12, 14))
        actions = tk.Frame(panel, bg=PANEL)
        actions.pack(fill="x")
        self.login_button = ttk.Button(
            actions,
            text="登录平台",
            command=self.submit,
            style="PlatformLogin.Primary.TButton",
        )
        self.login_button.pack(side="left")
        self.close_button = ttk.Button(
            actions,
            text="关闭",
            command=self.close,
            style="PlatformLogin.Action.TButton",
        )
        self.close_button.pack(side="right")

        # Creation order plus explicit takefocus keeps keyboard traversal
        # predictable in local and OIDC/device-code modes.
        for widget in (
            self.tenant_entry,
            self.email_entry,
            self.password_entry,
            self.password_toggle,
            self.device_entry,
            self.device_fallback_button,
            self.device_verification_uri_entry,
            self.copy_device_uri_button,
            self.device_user_code_entry,
            self.copy_device_code_button,
            self.cancel_device_button,
            self.login_button,
            self.close_button,
        ):
            widget.configure(takefocus=True)

    def _add_field(
        self,
        parent: tk.Misc,
        row: int,
        label: str,
        variable: tk.StringVar,
        *,
        show: str = "",
        columnspan: int = 2,
    ) -> tk.Entry:
        tk.Label(
            parent,
            text=label,
            bg=PANEL,
            fg=MUTED,
            font=("Microsoft YaHei UI", 9),
            anchor="w",
        ).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=4)
        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground="#075985",
            relief="flat",
            font=("Microsoft YaHei UI", 9),
            takefocus=True,
        )
        entry.grid(
            row=row,
            column=1,
            columnspan=columnspan,
            sticky="ew",
            pady=4,
            ipady=7,
        )
        return entry

    def _schedule(self, callback: Callable[[], None]) -> None:
        if self._closed:
            return

        def deliver() -> None:
            if not self._closed:
                callback()

        try:
            self.window.after(0, deliver)
        except tk.TclError:
            # The user may close the window while the worker is completing.
            return

    def _submit_event(self, _event: tk.Event[Any]) -> str:
        self.submit()
        return "break"

    def _close_event(self, _event: tk.Event[Any]) -> str:
        self.close()
        return "break"

    def toggle_password(self) -> None:
        self._password_visible = not self._password_visible
        self.password_entry.configure(show="" if self._password_visible else "*")
        self.password_toggle.configure(text="隐藏" if self._password_visible else "显示")

    def submit(self) -> bool:
        if self._busy or self._closed:
            return False
        if self._auth_mode == "oidc":
            self._set_busy(True)
            started = self._controller.submit_authorization_code(
                on_authorization_url=self._handle_authorization_url,
                on_success=self._handle_success,
                on_error=self._handle_error,
                on_complete=lambda: self._set_busy(False),
            )
            if not started:
                self._set_busy(False)
            return started
        if self._auth_mode != "local":
            return False
        # Clear the Tk variable before any network work and before returning.
        # This prevents the password from lingering in the form after submit.
        password = self.password_var.get()
        self.password_var.set("")
        self._set_busy(True)
        started = self._controller.submit(
            self.tenant_var.get(),
            self.email_var.get(),
            password,
            self.device_var.get(),
            on_success=self._handle_success,
            on_error=self._handle_error,
            on_complete=lambda: self._set_busy(False),
        )
        if not started:
            self._set_busy(False)
        return started

    def submit_device_fallback(self) -> bool:
        if self._busy or self._closed or self._auth_mode != "oidc":
            return False
        self._set_busy(True)
        started = self._controller.submit_device(
            on_challenge=self._handle_device_challenge,
            on_success=self._handle_success,
            on_error=self._handle_error,
            on_complete=lambda: self._set_busy(False),
        )
        if not started:
            self._set_busy(False)
        return started

    def cancel_device_fallback(self) -> None:
        if self._closed or self._device_verification_uri is None:
            return
        self._controller.cancel()
        self._set_busy(False)
        self._clear_device_challenge()
        self._set_status("已取消设备代码登录；可重新选择登录方式。", MUTED)

    def _load_auth_config(self, client: PlatformClient) -> None:
        def worker() -> None:
            try:
                config = client.get_auth_config()
            except BaseException as error:
                self._schedule(lambda error=error: self._handle_auth_config_error(error))
            else:
                self._schedule(lambda: self._apply_auth_mode(str(config["mode"])))

        thread = threading.Thread(target=worker, daemon=True)
        try:
            thread.start()
        except RuntimeError:
            self._handle_auth_config_error(
                PlatformTransportError("authentication config worker unavailable")
            )

    def _apply_auth_mode(self, mode: str) -> None:
        if self._closed:
            return
        self._auth_mode = mode
        if mode == "oidc":
            self.local_form.pack_forget()
            self.oidc_panel.pack(fill="x")
            self.login_button.configure(text="打开浏览器登录", state="normal")
            self._set_status("统一身份服务已就绪", MUTED)
            self.login_button.focus_set()
        else:
            self.oidc_panel.pack_forget()
            self.local_form.pack(fill="x")
            self.login_button.configure(text="登录平台", state="normal")
            self._set_status("请输入开发平台账号信息", MUTED)
            self.tenant_entry.focus_set()

    def _handle_auth_config_error(self, error: BaseException) -> None:
        self._auth_mode = "error"
        self.login_button.configure(state="disabled")
        self._handle_error(error)

    def _handle_device_challenge(self, challenge: DeviceAuthorizationChallenge) -> None:
        if self._closed:
            return
        self._clear_device_challenge()
        generation = self._device_challenge_generation
        self._device_verification_uri = challenge.verification_uri
        self._device_user_code = challenge.user_code
        self.device_verification_uri_var.set(challenge.verification_uri)
        self.device_user_code_var.set(challenge.user_code)
        self.device_expiry_label.configure(
            text=f"设备代码将在 {challenge.expires_in} 秒后过期"
        )
        for button in (
            self.copy_device_uri_button,
            self.copy_device_code_button,
            self.cancel_device_button,
        ):
            button.configure(state="normal")
        self.device_challenge_panel.pack(fill="x", pady=(5, 4))
        self.window.after(
            max(1, int(challenge.expires_in)) * 1000,
            self._expire_device_challenge,
            generation,
        )
        browser_url = challenge.verification_uri_complete or challenge.verification_uri
        try:
            opened = webbrowser.open(browser_url, new=2)
        except (OSError, webbrowser.Error):
            opened = False
        prefix = "浏览器已打开" if opened else "请使用下方登录网址"
        self._set_status(
            f"{prefix}，在任一设备完成统一身份认证。",
            ACCENT,
        )

    def copy_device_verification_uri(self) -> None:
        self._copy_device_challenge_value(
            self._device_verification_uri,
            "登录网址已复制；设备代码到期后将自动清理。",
        )

    def copy_device_user_code(self) -> None:
        self._copy_device_challenge_value(
            self._device_user_code,
            "设备代码已复制；到期后将自动清理。",
        )

    def _copy_device_challenge_value(self, value: str | None, message: str) -> None:
        if self._closed or not value:
            return
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(value)
            self.window.update_idletasks()
        except tk.TclError:
            self._set_status("无法安全写入剪贴板，请手动选择并复制。", ERROR)
            return
        self._device_clipboard_value = value
        self._set_status(message, ACCENT)

    def _clear_owned_device_clipboard(self) -> None:
        owned_value = self._device_clipboard_value
        self._device_clipboard_value = None
        if not owned_value:
            return
        try:
            if self.window.clipboard_get() != owned_value:
                return
            self.window.clipboard_clear()
            self.window.update_idletasks()
        except tk.TclError:
            return

    def _clear_device_challenge(self) -> None:
        self._device_challenge_generation += 1
        self._clear_owned_device_clipboard()
        self._device_verification_uri = None
        self._device_user_code = None
        self.device_verification_uri_var.set("")
        self.device_user_code_var.set("")
        self.device_expiry_label.configure(text="")
        for button in (
            self.copy_device_uri_button,
            self.copy_device_code_button,
            self.cancel_device_button,
        ):
            button.configure(state="disabled")
        self.device_challenge_panel.pack_forget()

    def _expire_device_challenge(self, generation: int) -> None:
        if self._closed or generation != self._device_challenge_generation:
            return
        self._controller.cancel()
        self._set_busy(False)
        self._clear_device_challenge()
        self._set_status("设备代码已过期并清理，请重新发起设备登录。", ERROR)

    def _handle_authorization_url(self, url: str) -> None:
        if self._closed:
            return
        try:
            opened = webbrowser.open(url, new=2)
        except (OSError, webbrowser.Error):
            opened = False
        if not opened:
            self._controller.cancel()
            self._set_busy(False)
            self._set_status("无法打开系统浏览器，请使用设备代码登录。", ERROR)
            return
        self._set_status("浏览器已打开，完成平台登录后返回此窗口。", ACCENT)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for widget in (
            self.tenant_entry,
            self.email_entry,
            self.password_entry,
            self.password_toggle,
            self.device_entry,
            self.login_button,
            self.device_fallback_button,
        ):
            widget.configure(state=state)
        self.close_button.configure(state="normal")
        if busy:
            self._set_status(
                "正在等待浏览器认证，请稍候…" if self._auth_mode == "oidc" else "正在登录平台，请稍候…",
                MUTED,
            )

    def _handle_success(self, profile: dict[str, Any], expires_in: int) -> None:
        if self._closed:
            return
        self._clear_device_challenge()
        self._set_status("登录成功", SUCCESS)
        self._on_success(profile, expires_in)

    def _handle_error(self, error: BaseException) -> None:
        if self._closed:
            return
        self._clear_device_challenge()
        self._set_status(format_login_error(error), ERROR)

    def _set_status(self, text: str, color: str = MUTED) -> None:
        if not self._closed:
            self.status_label.configure(text=text, fg=color)

    def show(self, *, modal: bool = True) -> None:
        """Show the dialog; callers decide whether to run their own mainloop."""

        if self._closed:
            return
        self.window.deiconify()
        if modal:
            try:
                self.window.grab_set()
            except tk.TclError:
                return

    def exists(self) -> bool:
        """Return whether the underlying Tk window still exists."""

        if self._closed:
            return False
        try:
            return bool(self.window.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        """Bring the dialog to the foreground and focus its first field."""

        if not self.exists():
            return
        try:
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
            self.tenant_entry.focus_set()
        except tk.TclError:
            return

    def detach_worker_threads(self) -> tuple[threading.Thread, ...]:
        return self._controller.detach_worker_threads()

    def stop_and_detach_worker_threads(self) -> tuple[threading.Thread, ...]:
        self._controller.stop_workers()
        return self._controller.detach_worker_threads()

    def close(self, *, cancel_authentication: bool = True) -> None:
        if self._closed:
            return
        self._clear_device_challenge()
        if cancel_authentication and not self._controller.cancel():
            self._set_busy(True)
            self._set_status(
                "登录会话清理尚未确认；窗口保持打开，请恢复网络后再次关闭。",
                ERROR,
            )
            return
        self._closed = True
        self.password_var.set("")
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
        try:
            self.window.destroy()
        except tk.TclError:
            pass
        if self._on_close is not None:
            self._on_close()


# A short alias is convenient for callers that do not need the full class
# name, while the explicit name remains the documented API.
LoginDialog = PlatformLoginDialog


__all__ = [
    "LoginCredentials",
    "LoginDialog",
    "PlatformLoginController",
    "PlatformLoginDialog",
    "format_login_error",
    "make_login_credentials",
    "safe_user_info",
    "validate_login_fields",
]
