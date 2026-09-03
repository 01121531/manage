"""Platform-owned desktop workflow for the default EXE entry point.

The legacy Tk window is isolated in ``legacy_app.py`` and is not reachable from
the packaged entry point.  This window never reads account credentials from the
clipboard and never calls the source-mail service.
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable
from uuid import uuid4

from app_version import APP_VERSION
from platform_clipboard import (
    SecurePasteSequence,
    WindowsPasteObserver,
    get_clipboard_sequence_number,
)
from platform_client import (
    CardAllocationSnapshot,
    CardRevealSnapshot,
    MailCodeSnapshot,
    MailSessionSnapshot,
    PlatformApiError,
    PlatformAuthenticationError,
    PlatformAuthenticationRequiredError,
    PlatformClient,
    PlatformClientError,
    PlatformConfigurationError,
    PlatformDeviceAuthorizationError,
    PlatformProtocolError,
    PlatformSessionError,
    PlatformTimeoutError,
    PlatformTransportError,
    TaskRecoverySnapshot,
    TaskTransitionCleanup,
    TaskSnapshot,
    UploadJobSnapshot,
)
from platform_login_dialog import PlatformLoginDialog, format_login_error, safe_user_info
from update_client import (
    UpdateClient,
    UpdateError,
    UpdateManifest,
    discard_downloaded_update,
    launch_update_helper,
)


BG = "#0f172a"
PANEL = "#111c32"
FIELD = "#172238"
TEXT = "#e5e7eb"
MUTED = "#94a3b8"
ACCENT = "#38bdf8"
SUCCESS = "#4ade80"
ERROR = "#fca5a5"
WARNING = "#fbbf24"
POLL_SECONDS = 5.0
CODE_VISIBLE_SECONDS = 60
CARD_DETAILS_VISIBLE_SECONDS = 60
CARD_DETAILS_PLACEHOLDER = "•••• •••• •••• •••• · --/--"
TRACE_ID_CLIPBOARD_SECONDS = 60
CLIPBOARD_CLEAR_RETRY_MS = 50
CLIPBOARD_CLEAR_RETRY_LIMIT = 3
CLIPBOARD_WRITE_ERROR_MESSAGE = (
    "原因：系统剪贴板当前不可写；"
    "影响：目标内容未确认写入，请勿粘贴当前剪贴板内容；"
    "下一步：关闭占用剪贴板的程序后重新执行复制。"
)
CARD_REVEAL_SHUTDOWN_WAIT_SECONDS = 10
PASTE_ADVANCE_DELAY_MS = 250
_RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_WORKFLOW_STEPS = ("登录", "分配卡", "等待验证码", "已获取", "上传", "完成")
_WORKFLOW_STAGE_INDEX = {
    "logged_out": 0,
    "authenticated": 1,
    "allocating": 1,
    "waiting": 2,
    "code_ready": 3,
    "uploading": 4,
    "completed": len(_WORKFLOW_STEPS),
    "review": 4,
    "upload_failed": 4,
    "stopped": 2,
}


class _CardRevealAction:
    def __init__(self, allocation_id: str, generation: int) -> None:
        self.allocation_id = allocation_id
        self.generation = generation
        self.cancel = threading.Event()


class _UnlockAction:
    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.cancel = threading.Event()


class _UploadSubmissionAction:
    def __init__(self, task_id: str, business_name: str, idempotency_key: str) -> None:
        self.task_id = task_id
        self.business_name = business_name
        self.idempotency_key = idempotency_key
        self.pending = False
        self.ambiguous = False


class _TaskProvisioningCompensation:
    def __init__(
        self,
        *,
        generation: int,
        transition: TaskTransitionCleanup,
        cleanup: Callable[[], None],
    ) -> None:
        self.generation = generation
        self.transition = transition
        self.cleanup = cleanup
        self.in_progress = False
        self.thread: threading.Thread | None = None


class _SessionRestoreCompensation:
    def __init__(
        self,
        *,
        generation: int,
        action: object,
        cleanup: Callable[[], None],
    ) -> None:
        self.generation = generation
        self.action = action
        self.cleanup = cleanup
        self.in_progress = False
        self.thread: threading.Thread | None = None


class _ActiveTaskDiscoveryAction:
    def __init__(self, session_generation: int, task_generation: int) -> None:
        self.session_generation = session_generation
        self.task_generation = task_generation


class _ActiveTaskRecoveryAction:
    def __init__(
        self,
        *,
        task_id: str,
        trace_id: str,
        session_generation: int,
        task_generation: int,
    ) -> None:
        self.task_id = task_id
        self.trace_id = trace_id
        self.session_generation = session_generation
        self.task_generation = task_generation


def format_workflow_progress(stage: str) -> tuple[str, str]:
    """Return icon-backed workflow text and its accessible status color."""

    current = _WORKFLOW_STAGE_INDEX.get(stage, 0)
    items: list[str] = []
    for index, label in enumerate(_WORKFLOW_STEPS):
        if stage == "completed" or index < current:
            icon = "✓"
        elif index == current:
            icon = "●"
            if stage in {"review", "stopped"}:
                icon = "!"
            elif stage == "upload_failed":
                icon = "×"
        else:
            icon = "○"
        items.append(f"{icon} {label}")
    color = {
        "completed": SUCCESS,
        "review": WARNING,
        "stopped": WARNING,
        "upload_failed": ERROR,
    }.get(stage, ACCENT if stage != "logged_out" else MUTED)
    return "  →  ".join(items), color


def format_operation_error(error: BaseException) -> str:
    """Return actionable text without reflecting server-controlled messages."""

    if isinstance(error, PlatformApiError):
        code = error.code if isinstance(error.code, str) else "api_error"
        if re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", code) is None:
            code = "api_error"
        recovery_hint = getattr(error, "recovery_hint", None)
        if (
            not isinstance(recovery_hint, str)
            or not 1 <= len(recovery_hint) <= 500
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in recovery_hint
            )
        ):
            recovery_hint = "刷新当前状态后按页面提示继续"
        trace_id = error.trace_id if isinstance(error.trace_id, str) else ""
        trace_suffix = (
            f"；trace_id：{trace_id}"
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", trace_id)
            else ""
        )
        reason = (
            "登录已失效或设备已撤销"
            if isinstance(error, PlatformAuthenticationError)
            else f"平台拒绝了当前操作（错误码：{code}）"
        )
        impact = (
            "受保护功能已停止"
            if isinstance(error, PlatformAuthenticationError)
            else "本次操作未确认完成"
        )
        return (
            f"原因：{reason}{trace_suffix}；"
            f"影响：{impact}；"
            f"下一步：{recovery_hint}。"
        )
    if isinstance(error, PlatformSessionError):
        return "安全会话已失效或无法刷新。请重新登录平台。"
    if isinstance(error, PlatformDeviceAuthorizationError):
        return "统一身份二次认证未完成或已取消，请重试。"
    if isinstance(error, PlatformConfigurationError):
        return "平台地址配置无效。请检查 PLATFORM_BASE_URL。"
    if isinstance(error, PlatformTimeoutError):
        return "平台请求超时。请检查网络后重试。"
    if isinstance(error, PlatformTransportError):
        return "无法连接平台。请确认网络和服务状态后重试。"
    if isinstance(error, PlatformProtocolError):
        return "平台响应格式异常。请升级客户端或联系管理员。"
    return "平台操作失败。请稍后重试；持续失败请联系管理员。"


class PlatformDesktopApp:
    """Small, login-first Tk workflow backed entirely by platform APIs."""

    def __init__(self, root: tk.Tk, *, client: PlatformClient | None = None) -> None:
        self.root = root
        self.root.title(f"邮箱验证码助手 v{APP_VERSION} · 平台")
        self.root.geometry("640x600")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.root.attributes("-topmost", True)
        try:
            self.root.attributes("-toolwindow", True)
        except tk.TclError:
            pass

        self._closed = False
        self._locked = False
        self._client: PlatformClient | None = client
        self._login_dialog: PlatformLoginDialog | None = None
        self._login_worker_threads: list[threading.Thread] = []
        self._task_id: str | None = None
        self._task_transition: TaskTransitionCleanup | None = None
        self._task_transition_thread: threading.Thread | None = None
        self._task_transition_threads: list[threading.Thread] = []
        self._terminal_task_cleanup_action: Callable[[], None] | None = None
        self._terminal_task_cleanup_thread: threading.Thread | None = None
        self._terminal_task_cleanup_in_progress = False
        self._terminal_task_cleanup_task_id: str | None = None
        self._terminal_task_cleanup_outcome: str | None = None
        self._terminal_task_cleanup_generation = 0
        self._task_compensation_lock = threading.Lock()
        self._task_compensation: _TaskProvisioningCompensation | None = None
        self._detached_task_cleanup_threads: list[threading.Thread] = []
        self._mail_session_id: str | None = None
        self._mail_session_token: str | None = None
        self._mail_poll_interval_seconds = POLL_SECONDS
        self._mail_poll_thread: threading.Thread | None = None
        self._mail_poll_threads: list[threading.Thread] = []
        self._current_code: str | None = None
        self._current_card_clipboard: str | None = None
        self._current_trace_clipboard: str | None = None
        self._card_reveal_action: _CardRevealAction | None = None
        self._card_reveal_thread: threading.Thread | None = None
        self._paste_sequence = SecurePasteSequence()
        self._paste_observer = WindowsPasteObserver()
        self._card_allocation_id: str | None = None
        self._verified_task_id: str | None = None
        self._upload_job_id: str | None = None
        self._upload_idempotency_key: str | None = None
        self._upload_business_name: str | None = None
        self._upload_submission_action: _UploadSubmissionAction | None = None
        self._upload_submission_thread: threading.Thread | None = None
        self._upload_poll_thread: threading.Thread | None = None
        self._upload_poll_threads: list[threading.Thread] = []
        self._poll_generation = 0
        self._poll_retry_attempt = 0
        self._task_generation = 0
        self._upload_generation = 0
        self._poll_cancel: threading.Event | None = None
        self._sensitive_focus = threading.Event()
        self._sensitive_focus.set()
        self._code_clear_generation = 0
        self._card_clear_generation = 0
        self._trace_clear_generation = 0
        self._clipboard_clear_generation = 0
        self._clipboard_cleanup_pending = 0
        self._clipboard_owner: tuple[str, int | None] | None = None
        self._clipboard_cleanup_failed: list[tuple[str, int | None]] | None = None
        self._destroy_pending = False
        self._history_generation = 0
        self._history_threads: list[threading.Thread] = []
        self._session_generation = 0
        self._session_restore_action: object | None = None
        self._session_restore_lock = threading.Lock()
        self._session_restore_thread: threading.Thread | None = None
        self._session_restore_compensation: _SessionRestoreCompensation | None = None
        self._active_task_discovery_action: _ActiveTaskDiscoveryAction | None = None
        self._active_task_discovery_thread: threading.Thread | None = None
        self._active_task_discovery_threads: list[threading.Thread] = []
        self._active_task_discovery_required = False
        self._active_task_recovery_action: _ActiveTaskRecoveryAction | None = None
        self._active_task_recovery: TaskRecoverySnapshot | None = None
        self._session_deadline = 0.0
        self._session_refreshing = False
        self._session_refresh_thread: threading.Thread | None = None
        self._session_refresh_threads: list[threading.Thread] = []
        self._unlock_action: _UnlockAction | None = None
        self._unlock_thread: threading.Thread | None = None
        self._update_generation = 0
        self._update_client: UpdateClient | None = None
        self._update_check_lock = threading.Lock()
        self._update_check_threads: list[threading.Thread] = []
        self._update_download_thread: threading.Thread | None = None
        self._update_download_threads: list[threading.Thread] = []
        self._update_cleanup_in_progress = False
        self._update_cleanup_completed = False
        self._update_cleanup_action: Callable[[], None] | None = None
        self._update_cleanup_thread: threading.Thread | None = None
        self._pending_update_install: tuple[UpdateManifest, Path] | None = None
        self._cleanup_thread: threading.Thread | None = None
        self._shutdown_cleanup_in_progress = False
        self._shutdown_cleanup_action: Callable[[], None] | None = None
        self._shutdown_cleanup_thread: threading.Thread | None = None
        self._shutdown_generation = 0
        self._shutdown_intent: str | None = None
        self._shutdown_message = ""
        self._profile_summary = ""
        self._profile_identity: tuple[str, str, str] | None = None
        self._history_window: tk.Toplevel | None = None
        self._history_tree: ttk.Treeview | None = None
        self._history_status: tk.Label | None = None
        self._history_refresh_button: ttk.Button | None = None
        self._events: queue.Queue[tuple[int, str, Any]] = queue.Queue()

        self._build_ui()
        self._set_authenticated(False)
        if self._client is None:
            try:
                self._client = PlatformClient()
            except PlatformClientError as error:
                self._set_status(format_login_error(error), ERROR)
        try:
            self._update_client = UpdateClient()
        except UpdateError:
            self.check_update_button.configure(state="disabled")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.bind("<FocusOut>", self._on_focus_out, add="+")
        self.root.bind("<FocusIn>", self._on_focus_in, add="+")
        self.root.after(100, self._drain_events)
        self.root.after(50, self._check_paste_shortcut)
        self.root.after(0, self._attempt_session_restore)
        if getattr(sys, "frozen", False) and os.environ.get(
            "PLATFORM_AUTO_UPDATE", "1"
        ) != "0":
            self.root.after(2500, lambda: self.check_for_updates(silent=True))

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Platform.Action.TButton",
            font=("Microsoft YaHei UI", 9),
            padding=(11, 7),
            background="#1e293b",
            foreground=TEXT,
            borderwidth=0,
        )
        style.map(
            "Platform.Action.TButton",
            background=[("active", "#334155"), ("disabled", "#172033")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "Platform.Primary.TButton",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=(12, 7),
            background="#0284c7",
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Platform.Primary.TButton",
            background=[("active", "#0369a1"), ("disabled", "#1e3a5f")],
            foreground=[("disabled", "#7790aa")],
        )

        panel = tk.Frame(self.root, bg=PANEL, padx=18, pady=15)
        panel.pack(fill="both", expand=True, padx=1, pady=1)
        header = tk.Frame(panel, bg=PANEL)
        header.pack(fill="x")
        tk.Label(
            header,
            text=f"邮箱验证码助手  v{APP_VERSION}",
            bg=PANEL,
            fg=TEXT,
            font=("Microsoft YaHei UI", 14, "bold"),
        ).pack(side="left")
        self.auth_label = tk.Label(
            header,
            text="未登录",
            bg=PANEL,
            fg=WARNING,
            font=("Microsoft YaHei UI", 9),
        )
        self.auth_label.pack(side="right")

        self.profile_label = tk.Label(
            panel,
            text="平台账号尚未登录",
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        )
        self.profile_label.pack(fill="x", pady=(8, 12))

        workflow_text, workflow_color = format_workflow_progress("logged_out")
        self.workflow_label = tk.Label(
            panel,
            text=workflow_text,
            bg=PANEL,
            fg=workflow_color,
            anchor="w",
            justify="left",
            wraplength=570,
            font=("Microsoft YaHei UI", 9),
        )
        self.workflow_label.pack(fill="x", pady=(0, 12))

        info = tk.Frame(panel, bg=FIELD, padx=12, pady=9)
        info.pack(fill="x")
        info.grid_columnconfigure(1, weight=1)
        self.task_label = self._add_value(info, 0, "任务", "未创建")
        self.mail_label = self._add_value(info, 1, "分配邮箱", "登录后创建任务")
        self.code_label = self._add_value(info, 2, "验证码", "------")
        self.card_label = self._add_value(info, 3, "分配卡", "未分配")
        self.card_reveal_label = self._add_value(
            info, 4, "临时卡详情", CARD_DETAILS_PLACEHOLDER
        )
        self.session_label = self._add_value(info, 5, "邮箱会话", "未开始")
        self.upload_label = self._add_value(info, 6, "上传作业", "未创建")

        business = tk.Frame(panel, bg=PANEL)
        business.pack(fill="x", pady=(11, 0))
        tk.Label(
            business,
            text="业务名称",
            width=9,
            anchor="w",
            bg=PANEL,
            fg=MUTED,
            font=("Microsoft YaHei UI", 9),
        ).pack(side="left")
        self.business_entry = tk.Entry(
            business,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground="#075985",
            relief="flat",
            font=("Microsoft YaHei UI", 9),
        )
        self.business_entry.pack(side="left", fill="x", expand=True, ipady=6)

        self.status_label = tk.Label(
            panel,
            text="请先登录平台",
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=480,
            font=("Microsoft YaHei UI", 9),
        )
        self.status_label.pack(fill="x", pady=(11, 10))

        actions = tk.Frame(panel, bg=PANEL)
        actions.pack(fill="x")
        self.login_button = ttk.Button(
            actions,
            text="登录平台",
            style="Platform.Primary.TButton",
            command=self.open_login_dialog,
        )
        self.login_button.pack(side="left")
        self.new_task_button = ttk.Button(
            actions,
            text="新建邮箱任务",
            style="Platform.Action.TButton",
            command=self.create_mail_task,
        )
        self.new_task_button.pack(side="left", padx=8)
        self.copy_button = ttk.Button(
            actions,
            text="复制验证码",
            style="Platform.Action.TButton",
            command=self.copy_code,
        )
        self.copy_button.pack(side="left")
        self.copy_card_button = ttk.Button(
            actions,
            text="揭示卡号 60 秒",
            style="Platform.Action.TButton",
            command=self.reveal_card_details,
        )
        self.copy_card_button.pack(side="left", padx=(8, 0))
        self.upload_button = ttk.Button(
            actions,
            text="提交上传",
            style="Platform.Action.TButton",
            command=self.submit_upload,
        )
        self.upload_button.pack(side="left", padx=(8, 0))

        utilities = tk.Frame(panel, bg=PANEL)
        utilities.pack(fill="x", pady=(8, 0))
        self.history_button = ttk.Button(
            utilities,
            text="任务记录 / trace_id",
            style="Platform.Action.TButton",
            command=self.show_task_history,
        )
        self.history_button.pack(side="left")
        self.close_active_task_button = ttk.Button(
            utilities,
            text="关闭活动任务",
            style="Platform.Action.TButton",
            command=self.close_active_task,
        )
        self.close_active_task_button.pack(side="left", padx=(8, 0))
        self.check_update_button = ttk.Button(
            utilities,
            text="检查更新",
            style="Platform.Action.TButton",
            command=self.check_for_updates,
        )
        self.check_update_button.pack(side="left", padx=(8, 0))
        self.logout_button = ttk.Button(
            utilities,
            text="退出登录",
            style="Platform.Action.TButton",
            command=self.logout,
        )
        self.logout_button.pack(side="right")
        self.lock_button = ttk.Button(
            utilities,
            text="锁定",
            style="Platform.Action.TButton",
            command=self.lock,
        )
        self.lock_button.pack(side="right", padx=(0, 8))

    @staticmethod
    def _add_value(parent: tk.Frame, row: int, label: str, value: str) -> ttk.Label:
        tk.Label(
            parent,
            text=label,
            width=9,
            anchor="w",
            bg=FIELD,
            fg=MUTED,
            font=("Microsoft YaHei UI", 9),
        ).grid(row=row, column=0, sticky="w", pady=3)
        value_label = ttk.Label(parent, text=value, background=FIELD, foreground=TEXT)
        value_label.grid(row=row, column=1, sticky="w", pady=3)
        return value_label

    def _set_authenticated(self, authenticated: bool) -> None:
        available = authenticated and not self._locked
        self.auth_label.configure(
            text="已登录" if authenticated else "未登录",
            fg=SUCCESS if authenticated else WARNING,
        )
        self.new_task_button.configure(state="normal" if available else "disabled")
        self.close_active_task_button.configure(state="disabled")
        self.history_button.configure(state="normal" if available else "disabled")
        self.logout_button.configure(state="normal" if authenticated else "disabled")
        self.login_button.configure(state="disabled" if authenticated else "normal")
        self.lock_button.configure(
            text="锁定",
            command=self.lock,
            state=(
                "normal"
                if available and self._profile_identity is not None
                else "disabled"
            ),
        )
        upload_input_available = (
            available
            and self._upload_job_id is None
            and self._upload_submission_action is None
        )
        self.business_entry.configure(
            state="normal" if upload_input_available else "disabled"
        )
        if not authenticated:
            self.stop_polling()
            self._cancel_card_reveal()
            self._poll_retry_attempt = 0
            self._paste_sequence.stop()
            self._clear_sensitive_code()
            self._clear_card_details()
            self._clear_trace_id()
            self._reset_task_verification()
            self.copy_card_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
            self.upload_button.configure(state="disabled")
            self._set_workflow_stage("logged_out")

    def _set_workflow_stage(self, stage: str) -> None:
        text, color = format_workflow_progress(stage)
        self.workflow_label.configure(text=text, fg=color)

    def _upload_attempt_key(self, business_name: str) -> str:
        if (
            self._upload_idempotency_key is None
            or self._upload_business_name != business_name
        ):
            self._upload_idempotency_key = str(uuid4())
            self._upload_business_name = business_name
        return self._upload_idempotency_key

    def _reset_upload_attempt(self) -> None:
        self._upload_idempotency_key = None
        self._upload_business_name = None
        self._upload_submission_action = None
        self._upload_submission_thread = None

    def _present_ambiguous_upload(self, action: _UploadSubmissionAction) -> None:
        if self._upload_submission_action is not action:
            return
        action.pending = False
        action.ambiguous = True
        self._upload_submission_thread = None
        if self._locked:
            return
        self.business_entry.configure(state="disabled")
        self.upload_label.configure(text="状态未确认")
        self.upload_button.configure(
            text="确认同一上传状态",
            state=(
                "normal"
                if self._current_task_is_verified()
                and action.task_id == self._task_id
                and self._client is not None
                and self._client.is_authenticated
                else "disabled"
            ),
        )
        self._set_status(
            "原因：上传创建响应超时、中断或无法确认；"
            "影响：请求可能已提交，不得按失败推断，也不能创建新的上传尝试；"
            "下一步：检查网络后点击“确认同一上传状态”，客户端只会使用原任务、业务名称和幂等键核对。",
            ERROR,
        )

    def _current_task_is_verified(self) -> bool:
        return (
            self._task_id is not None
            and self._verified_task_id == self._task_id
        )

    def _mark_current_task_verified(self) -> None:
        if self._task_id is None:
            return
        self._verified_task_id = self._task_id
        self.upload_button.configure(state="normal")

    def _reset_task_verification(self) -> None:
        self._verified_task_id = None
        self.upload_button.configure(state="disabled")

    def _set_status(self, text: str, color: str = MUTED) -> None:
        if not self._closed:
            self.status_label.configure(text=text, fg=color)

    def show_startup_notice(self, message: str) -> None:
        """Show a safe one-time startup result after the first UI idle cycle."""

        self._set_status(message, WARNING)

    @staticmethod
    def _format_task_time(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone().strftime("%m-%d %H:%M:%S")
        except ValueError:
            return "时间无效"

    def show_task_history(self) -> None:
        if self._locked:
            self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        if self._client is None or not self._client.is_authenticated:
            self._set_status("请先登录平台后查看任务记录。", ERROR)
            return
        if self._history_window is not None and self._history_window.winfo_exists():
            self._history_window.lift()
            self._history_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        window.title("我的任务记录 · trace_id")
        window.geometry("820x380")
        window.minsize(700, 320)
        window.configure(bg=BG)
        window.transient(self.root)
        window.protocol("WM_DELETE_WINDOW", self._close_task_history)
        self._history_window = window

        panel = tk.Frame(window, bg=PANEL, padx=14, pady=14)
        panel.pack(fill="both", expand=True)
        heading = tk.Frame(panel, bg=PANEL)
        heading.pack(fill="x", pady=(0, 9))
        tk.Label(
            heading,
            text="最近 50 条任务",
            bg=PANEL,
            fg=TEXT,
            font=("Microsoft YaHei UI", 11, "bold"),
        ).pack(side="left")
        self._history_refresh_button = ttk.Button(
            heading,
            text="刷新",
            style="Platform.Action.TButton",
            command=self._load_task_history,
        )
        self._history_refresh_button.pack(side="right")
        copy_trace_button = ttk.Button(
            heading,
            text="复制所选 trace_id",
            style="Platform.Action.TButton",
            command=self._copy_selected_trace,
        )
        copy_trace_button.pack(side="right", padx=(0, 8))

        columns = ("created_at", "status", "task_id", "trace_id")
        tree = ttk.Treeview(panel, columns=columns, show="headings", height=11)
        tree.heading("created_at", text="创建时间")
        tree.heading("status", text="状态")
        tree.heading("task_id", text="任务 ID")
        tree.heading("trace_id", text="trace_id（审计追踪）")
        tree.column("created_at", width=125, anchor="w", stretch=False)
        tree.column("status", width=90, anchor="center", stretch=False)
        tree.column("task_id", width=180, anchor="w", stretch=False)
        tree.column("trace_id", width=320, anchor="w")
        tree.tag_configure("created", foreground=ACCENT)
        tree.tag_configure("closed", foreground=SUCCESS)
        tree.tag_configure("expired", foreground=WARNING)
        tree.tag_configure("cancelled", foreground=WARNING)
        tree.tag_configure("completed", foreground=SUCCESS)
        tree.pack(fill="both", expand=True)
        tree.bind("<Double-1>", lambda _event: self._copy_selected_trace())
        self._history_tree = tree

        self._history_status = tk.Label(
            panel,
            text="正在加载…",
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        )
        self._history_status.pack(fill="x", pady=(9, 0))
        self._load_task_history()

    def _load_task_history(self) -> None:
        if (
            self._locked
            or self._client is None
            or not self._client.is_authenticated
            or self._history_window is None
            or not self._history_window.winfo_exists()
        ):
            return
        self._history_generation += 1
        generation = self._history_generation
        if self._history_refresh_button is not None:
            self._history_refresh_button.configure(state="disabled")
        if self._history_status is not None:
            self._history_status.configure(text="正在加载…", fg=MUTED)

        def worker() -> None:
            try:
                tasks = self._client.list_tasks(limit=50)
            except BaseException as error:
                self._events.put((generation, "task_history_error", error))
                return
            self._events.put((generation, "task_history", tasks))

        thread = threading.Thread(
            target=worker, daemon=False, name="platform-task-history"
        )
        self._history_threads = [
            existing for existing in self._history_threads if existing.is_alive()
        ]
        self._history_threads.append(thread)
        try:
            thread.start()
        except RuntimeError:
            self._history_threads.remove(thread)
            self._events.put(
                (
                    generation,
                    "task_history_error",
                    PlatformTransportError("task history worker unavailable"),
                )
            )

    def _render_task_history(self, tasks: list[TaskSnapshot]) -> None:
        if self._history_tree is None or self._history_window is None:
            return
        if not self._history_window.winfo_exists():
            return
        for item in self._history_tree.get_children():
            self._history_tree.delete(item)
        status_labels = {
            "created": "● 进行中",
            "closed": "✓ 已关闭",
            "expired": "! 已过期",
            "cancelled": "! 已取消",
            "completed": "✓ 已完成",
        }
        for task in tasks:
            self._history_tree.insert(
                "",
                "end",
                values=(
                    self._format_task_time(task.created_at),
                    status_labels[task.status],
                    task.id,
                    task.trace_id,
                ),
                tags=(task.status,),
            )
        if self._history_refresh_button is not None:
            self._history_refresh_button.configure(state="normal")
        if self._history_status is not None:
            text = f"已加载 {len(tasks)} 条。双击记录或点击按钮复制 trace_id。"
            self._history_status.configure(text=text, fg=MUTED)

    def _copy_selected_trace(self) -> None:
        if self._history_tree is None:
            return
        selected = self._history_tree.selection()
        if not selected:
            if self._history_status is not None:
                self._history_status.configure(text="请先选择一条任务记录。", fg=WARNING)
            return
        values = self._history_tree.item(selected[0], "values")
        if len(values) != 4:
            return
        trace_id = str(values[3])
        self._current_trace_clipboard = trace_id
        if not self._write_clipboard(trace_id):
            self._current_trace_clipboard = None
            self._trace_clear_generation += 1
            if self._history_status is not None:
                self._history_status.configure(
                    text=CLIPBOARD_WRITE_ERROR_MESSAGE, fg=ERROR
                )
            return
        self._schedule_trace_cleanup()
        if self._history_status is not None:
            self._history_status.configure(
                text="trace_id 已复制，60 秒后自动清理。", fg=SUCCESS
            )

    def _close_task_history(self) -> None:
        self._history_generation += 1
        self._clear_trace_id()
        window = self._history_window
        self._history_window = None
        self._history_tree = None
        self._history_status = None
        self._history_refresh_button = None
        if window is not None and window.winfo_exists():
            window.destroy()

    @staticmethod
    def _identity_from_profile(
        profile: dict[str, Any],
    ) -> tuple[str, str, str] | None:
        values = tuple(profile.get(field) for field in ("tenant_id", "id", "device_id"))
        if any(not isinstance(value, str) or not value.strip() for value in values):
            return None
        return tuple(value.strip() for value in values)

    def lock(self) -> None:
        """Freeze local work without revoking or replacing the primary session."""

        if (
            self._locked
            or self._client is None
            or not self._client.is_authenticated
        ):
            return
        self._locked = True
        self._cancel_card_reveal()
        self._cancel_task_transition(retain_failure=True)
        self.stop_polling()
        self._paste_sequence.stop()
        self._close_task_history()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._clear_trace_id()
        self._poll_retry_attempt = 0
        if self._active_task_discovery_action is not None:
            self._active_task_discovery_action = None
            self._active_task_discovery_thread = None
            self._active_task_discovery_required = True
        if self._upload_submission_action is not None:
            self._upload_submission_action.ambiguous = True
        self._task_generation += 1
        self._upload_generation += 1
        self._update_generation += 1
        self._session_generation += 1
        self._session_refreshing = False
        for widget in (
            self.new_task_button,
            self.close_active_task_button,
            self.copy_button,
            self.copy_card_button,
            self.upload_button,
            self.history_button,
            self.check_update_button,
            self.business_entry,
        ):
            widget.configure(state="disabled")
        self.login_button.configure(state="disabled")
        self.lock_button.configure(text="解锁", command=self.unlock, state="normal")
        self.logout_button.configure(state="normal")
        self.auth_label.configure(text="已锁定", fg=WARNING)
        self.profile_label.configure(text=f"{self._profile_summary} · 已锁定")
        self._set_status("客户端已锁定；重新验证当前账号后才能继续。", WARNING)
        self._update_session_countdown(self._session_generation)

    def unlock(self) -> None:
        """Start forced, isolated PKCE reauthentication for the locked principal."""

        if (
            not self._locked
            or self._client is None
            or self._unlock_action is not None
        ):
            return
        if not self._client.is_authenticated or self._profile_identity is None:
            self._set_status("主会话或身份信息已失效，请退出后重新登录。", ERROR)
            return
        generation = self._session_generation
        action = _UnlockAction(generation)
        self._unlock_action = action
        expected_tenant_id, expected_user_id, expected_device_id = self._profile_identity
        self.lock_button.configure(state="disabled")
        self._set_status("正在启动强制身份验证…", ACCENT)

        def worker() -> None:
            try:
                def cancelled() -> bool:
                    return (
                        self._closed
                        or not self._locked
                        or action.cancel.is_set()
                        or self._unlock_action is not action
                        or generation != self._session_generation
                    )

                def open_authorization_url(url: str) -> None:
                    if cancelled():
                        raise PlatformDeviceAuthorizationError(
                            "unlock was cancelled"
                        )
                    if not webbrowser.open(url, new=2):
                        raise PlatformTransportError("无法打开统一身份登录页面")
                    self._events.put((generation, "unlock_authorizing", action))

                profile = self._client.reauthenticate_for_unlock(
                    open_authorization_url,
                    expected_tenant_id=expected_tenant_id,
                    expected_user_id=expected_user_id,
                    expected_device_id=expected_device_id,
                    cancelled=cancelled,
                )
            except BaseException as error:
                self._events.put((generation, "unlock_error", (action, error)))
            else:
                self._events.put(
                    (generation, "unlock_success", (action, safe_user_info(profile)))
                )
            finally:
                self._events.put((generation, "unlock_finished", action))

        thread = threading.Thread(target=worker, daemon=False, name="platform-unlock")
        self._unlock_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._events.put(
                (
                    generation,
                    "unlock_error",
                    (
                        action,
                        PlatformTransportError("unlock worker unavailable"),
                    ),
                )
            )
            self._events.put((generation, "unlock_finished", action))

    def _finish_unlock(self, profile: dict[str, Any]) -> None:
        identity = self._identity_from_profile(profile)
        if identity is None or identity != self._profile_identity:
            self.lock_button.configure(state="normal")
            self._set_status("解锁身份与当前会话不一致，客户端仍保持锁定。", ERROR)
            return
        if self._session_deadline <= time.monotonic():
            self.logout(message="会话已过期，已停止任务并清除临时数据。")
            return
        self._locked = False
        self._session_generation += 1
        self._set_authenticated(True)
        compensation = self._task_compensation
        if compensation is not None:
            if compensation.in_progress:
                self.new_task_button.configure(text="资源关闭中…", state="disabled")
            else:
                self._present_task_compensation_failure(compensation)
            self.close_active_task_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
            self.copy_card_button.configure(state="disabled")
            self.business_entry.configure(state="disabled")
            self.upload_button.configure(state="disabled")
            self.check_update_button.configure(
                state="normal" if self._update_client is not None else "disabled"
            )
            self._update_session_countdown(self._session_generation)
            return
        if self._terminal_task_cleanup_action is not None:
            self.new_task_button.configure(
                text=(
                    "任务收尾中…"
                    if self._terminal_task_cleanup_in_progress
                    else "重试资源关闭"
                ),
                command=self._retry_terminal_task_cleanup,
                state=(
                    "disabled" if self._terminal_task_cleanup_in_progress else "normal"
                ),
            )
            self.close_active_task_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
            self.copy_card_button.configure(state="disabled")
            self.business_entry.configure(state="disabled")
            self.upload_button.configure(state="disabled")
            self.check_update_button.configure(
                state="normal" if self._update_client is not None else "disabled"
            )
            self._update_session_countdown(self._session_generation)
            if not self._terminal_task_cleanup_in_progress:
                self._set_workflow_stage("stopped")
                self._set_status(
                    "原因：平台暂未确认任务资源关闭；"
                    "影响：任务、卡和邮箱资源不会标记为已安全释放；"
                    "下一步：检查网络后点击“重试资源关闭”。",
                    ERROR,
                )
            return
        if self._active_task_discovery_action is not None:
            self.new_task_button.configure(state="disabled")
        elif self._active_task_discovery_required:
            self.new_task_button.configure(
                text="重试检查活动任务",
                command=self._discover_active_task,
                state="normal",
            )
        elif self._active_task_recovery is not None:
            active_upload = self._recovery_active_upload(self._active_task_recovery)
            review_only = active_upload is not None and active_upload.status in {
                "cancel_pending",
                "unknown",
            }
            self.new_task_button.configure(
                text=(
                    "活动任务已接管"
                    if self._mail_session_id is not None or self._upload_job_id is not None
                    else "接管活动任务"
                ),
                command=self.take_over_active_task,
                state=(
                    "normal"
                    if self._mail_session_id is None
                    and self._upload_job_id is None
                    and not review_only
                    else "disabled"
                ),
            )
            self.close_active_task_button.configure(
                state="disabled" if review_only else "normal"
            )
        self.copy_card_button.configure(
            state="normal" if self._card_allocation_id is not None else "disabled"
        )
        upload_action = self._upload_submission_action
        if upload_action is not None and upload_action.ambiguous:
            self.business_entry.configure(state="disabled")
            self.upload_button.configure(
                text="确认中…" if upload_action.pending else "确认同一上传状态",
                state=(
                    "normal"
                    if self._current_task_is_verified()
                    and upload_action.task_id == self._task_id
                    and not upload_action.pending
                    else "disabled"
                ),
            )
        else:
            self.upload_button.configure(
                text="提交上传",
                state=(
                    "normal"
                    if self._current_task_is_verified()
                    and self._upload_job_id is None
                    else "disabled"
                ),
            )
        self.check_update_button.configure(
            state="normal" if self._update_client is not None else "disabled"
        )
        self._update_session_countdown(self._session_generation)
        if not self._current_task_is_verified() and self._mail_session_id is not None:
            self._start_polling()
        if self._upload_job_id is not None:
            self._poll_upload()
        self._set_status("身份验证通过，客户端已解锁。", SUCCESS)

    def open_login_dialog(self) -> None:
        barrier = self._session_restore_compensation
        if barrier is not None:
            if barrier.in_progress:
                self._set_status(
                    "恢复失败后的安全清理仍在进行；确认完成前不会开始新登录。",
                    WARNING,
                )
            else:
                self._present_session_restore_compensation_failure(barrier)
            return
        if self._locked:
            self.unlock()
            return
        if self._client is None:
            self._set_status("平台地址未配置，无法登录。请设置 PLATFORM_BASE_URL 后重启。", ERROR)
            return
        if self._login_dialog is not None and self._login_dialog.exists():
            self._login_dialog.focus()
            return

        dialog: PlatformLoginDialog

        def closed() -> None:
            self._login_worker_threads = [
                thread for thread in self._login_worker_threads if thread.is_alive()
            ]
            self._login_worker_threads.extend(dialog.detach_worker_threads())
            self._login_dialog = None

        dialog = PlatformLoginDialog(
            self.root,
            self._client,
            on_success=self._on_login_success,
            on_close=closed,
        )
        self._login_dialog = dialog
        dialog.show(modal=True)

    def _on_login_success(self, profile: dict[str, Any], expires_in: int) -> None:
        self._session_restore_action = None
        self.stop_polling()
        self._cancel_card_reveal()
        self._task_generation += 1
        self._upload_generation += 1
        self._active_task_discovery_action = None
        self._active_task_discovery_thread = None
        self._active_task_recovery_action = None
        self._active_task_recovery = None
        email = profile.get("email")
        tenant_id = profile.get("tenant_id")
        device_id = profile.get("device_id")
        summary = str(email) if isinstance(email, str) else "平台账号"
        if isinstance(tenant_id, str) and tenant_id:
            summary += f" · 组织 {tenant_id}"
        if isinstance(device_id, str) and device_id:
            summary += f" · 设备 {device_id[:8]}"
        self._profile_summary = summary
        self._profile_identity = self._identity_from_profile(profile)
        self._update_cleanup_completed = False
        self._session_generation += 1
        self._session_refreshing = False
        self._session_deadline = time.monotonic() + max(1, expires_in)
        self._update_session_countdown(self._session_generation)
        self._set_authenticated(True)
        self._active_task_discovery_required = True
        self._set_workflow_stage("authenticated")
        self.new_task_button.configure(state="disabled")
        self.close_active_task_button.configure(state="disabled")
        self._set_status("登录成功，正在检查本设备是否有未完成任务…", MUTED)
        if self._login_dialog is not None and self._login_dialog.exists():
            self._login_dialog.close(cancel_authentication=False)
        self._login_dialog = None
        self._discover_active_task()

    def _discover_active_task(self) -> None:
        if (
            self._closed
            or self._locked
            or self._client is None
            or not self._client.is_authenticated
            or self._active_task_discovery_action is not None
            or self._active_task_recovery_action is not None
        ):
            return
        self._active_task_discovery_threads = [
            thread
            for thread in self._active_task_discovery_threads
            if thread.is_alive()
        ]
        if self._active_task_discovery_threads:
            session_generation = self._session_generation
            task_generation = self._task_generation
            self.new_task_button.configure(state="disabled")

            def retry_if_current() -> None:
                if (
                    session_generation == self._session_generation
                    and task_generation == self._task_generation
                ):
                    self._discover_active_task()

            self.root.after(250, retry_if_current)
            return
        action = _ActiveTaskDiscoveryAction(
            self._session_generation, self._task_generation
        )
        self._active_task_discovery_required = True
        self._active_task_discovery_action = action
        self.new_task_button.configure(state="disabled")
        self.close_active_task_button.configure(state="disabled")

        def worker() -> None:
            try:
                tasks = self._client.list_tasks(limit=1)
                recovery = None
                if tasks and tasks[0].status not in {
                    "closed",
                    "expired",
                    "cancelled",
                    "completed",
                }:
                    recovery = self._client.get_task_timeline(tasks[0].id)
                    if (
                        recovery.task.id != tasks[0].id
                        or recovery.task.trace_id != tasks[0].trace_id
                    ):
                        raise PlatformProtocolError(
                            "活动任务摘要与任务列表不一致"
                        )
                    self._recovery_active_upload(recovery)
            except BaseException as error:
                self._events.put(
                    (action.session_generation, "active_task_discovery_error", (action, error))
                )
                return
            self._events.put(
                (action.session_generation, "active_task_discovered", (action, recovery))
            )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        action.session_generation,
                        "active_task_discovery_finished",
                        (action, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker,
            daemon=False,
            name="platform-active-task-discovery",
        )
        self._active_task_discovery_threads.append(thread)
        self._active_task_discovery_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._active_task_discovery_threads.remove(thread)
            self._events.put(
                (
                    action.session_generation,
                    "active_task_discovery_error",
                    (
                        action,
                        PlatformTransportError(
                            "active task discovery worker unavailable"
                        ),
                    ),
                )
            )
            self._events.put(
                (
                    action.session_generation,
                    "active_task_discovery_finished",
                    (action, thread),
                )
            )

    @staticmethod
    def _recovery_active_upload(
        recovery: TaskRecoverySnapshot,
    ) -> UploadJobSnapshot | None:
        active = [
            upload
            for upload in recovery.uploads
            if upload.status in {"queued", "running", "cancel_pending", "unknown"}
        ]
        if len(active) > 1:
            raise PlatformProtocolError("活动任务包含多个未终结上传作业")
        return active[0] if active else None

    @staticmethod
    def _task_is_terminal(recovery: TaskRecoverySnapshot) -> bool:
        return recovery.task.status in {
            "closed",
            "expired",
            "cancelled",
            "completed",
        }

    def _show_discovered_task(self, recovery: TaskRecoverySnapshot) -> None:
        self._active_task_recovery = recovery
        self._task_id = recovery.task.id
        self.task_label.configure(
            text=f"{recovery.task.id[:8]} · trace {recovery.task.trace_id[:8]}"
        )
        if recovery.mail_session is None:
            self.mail_label.configure(text="尚未分配")
            self.session_label.configure(text="尚未开始")
        else:
            self.mail_label.configure(text=recovery.mail_session.email_masked)
            self.session_label.configure(text=recovery.mail_session.status)
        active_allocations = [
            allocation
            for allocation in recovery.card_allocations
            if allocation.status == "active"
        ]
        self.card_label.configure(
            text=(active_allocations[0].card_masked if active_allocations else "尚未分配")
        )
        active_upload = self._recovery_active_upload(recovery)
        self.upload_label.configure(
            text=active_upload.status if active_upload is not None else "未创建"
        )
        review_only = active_upload is not None and active_upload.status in {
            "cancel_pending",
            "unknown",
        }
        self.new_task_button.configure(
            text="接管活动任务",
            command=self.take_over_active_task,
            state="disabled" if review_only else "normal",
        )
        self.close_active_task_button.configure(
            state="disabled" if review_only else "normal"
        )
        self._set_workflow_stage("review" if review_only else "waiting")
        self._set_status(
            (
                "检测到结果待核对的活动任务；为避免重复提交，客户端不会接管、关闭或重试。"
                if review_only
                else "检测到未完成任务。请选择“接管活动任务”继续，或“关闭活动任务”安全释放资源。"
            ),
            WARNING,
        )

    @classmethod
    def _validate_recovered_resources(
        cls,
        recovery: TaskRecoverySnapshot,
        session: MailSessionSnapshot,
        allocation: CardAllocationSnapshot,
    ) -> None:
        if recovery.mail_session is None or recovery.mail_session.id != session.id:
            raise PlatformProtocolError("恢复的邮箱会话不属于活动任务")
        active_allocations = [
            candidate
            for candidate in recovery.card_allocations
            if candidate.status == "active"
        ]
        if (
            len(active_allocations) != 1
            or active_allocations[0].id != allocation.id
        ):
            raise PlatformProtocolError("恢复的卡租约不属于活动任务")
        if session.trace_id != recovery.task.trace_id:
            raise PlatformProtocolError("恢复的邮箱会话追踪标识不一致")
        if allocation.trace_id != recovery.task.trace_id:
            raise PlatformProtocolError("恢复的卡租约追踪标识不一致")
        if session.status not in {"initializing", "waiting", "code_ready", "consumed"}:
            raise PlatformProtocolError("恢复的邮箱会话状态不可用")
        if allocation.status != "active":
            raise PlatformProtocolError("恢复的卡租约状态不可用")
        now = datetime.now().astimezone()
        if not cls._resource_expiry_is_live(session.expires_at, now=now):
            raise PlatformProtocolError("恢复的邮箱会话已失效")
        if not cls._resource_expiry_is_live(allocation.expires_at, now=now):
            raise PlatformProtocolError("恢复的卡租约已失效")

    def take_over_active_task(self) -> None:
        recovery = self._active_task_recovery
        if (
            self._closed
            or self._locked
            or recovery is None
            or self._client is None
            or not self._client.is_authenticated
            or self._active_task_recovery_action is not None
            or self._task_transition is not None
            or self._task_compensation is not None
            or self._terminal_task_cleanup_action is not None
        ):
            return
        active_upload = self._recovery_active_upload(recovery)
        if active_upload is not None and active_upload.status in {
            "cancel_pending",
            "unknown",
        }:
            self._set_status(
                "上传结果尚未确认，当前任务只能由管理员核对，客户端不会重复提交或关闭。",
                WARNING,
            )
            return
        try:
            transition = self._client.begin_task_transition(recovery.task.id)
        except PlatformClientError as error:
            self._set_status(format_operation_error(error), ERROR)
            return
        self._task_generation += 1
        action = _ActiveTaskRecoveryAction(
            task_id=recovery.task.id,
            trace_id=recovery.task.trace_id,
            session_generation=self._session_generation,
            task_generation=self._task_generation,
        )
        self._active_task_recovery_action = action
        self._task_transition = transition
        self.new_task_button.configure(state="disabled")
        self.close_active_task_button.configure(state="disabled")
        self._set_status("正在重新核对并接管活动任务…", ACCENT)

        def worker() -> None:
            mutation_started = False
            try:
                current = self._client.get_task_timeline(action.task_id)
                if (
                    current.task.id != action.task_id
                    or current.task.trace_id != action.trace_id
                ):
                    raise PlatformProtocolError("活动任务在接管前发生身份漂移")
                if self._task_is_terminal(current):
                    transition.worker_finished()
                    if not transition.cancelled and transition.commit():
                        self._events.put(
                            (
                                action.task_generation,
                                "active_task_recovery_closed",
                                (action, PlatformProtocolError("活动任务已终结")),
                            )
                        )
                    return
                upload = self._recovery_active_upload(current)
                session = None
                allocation = None
                redisplay = False
                if upload is not None:
                    if upload.status in {"cancel_pending", "unknown"}:
                        pass
                    else:
                        upload = self._client.get_upload_job(upload.id)
                        if (
                            upload.task_id != action.task_id
                            or upload.trace_id != action.trace_id
                        ):
                            raise PlatformProtocolError("恢复的上传作业与活动任务不一致")
                        if upload.status not in {"queued", "running"}:
                            current = self._client.get_task_timeline(action.task_id)
                            if (
                                current.task.id != action.task_id
                                or current.task.trace_id != action.trace_id
                            ):
                                raise PlatformProtocolError(
                                    "活动任务在上传终结后发生身份漂移"
                                )
                            if self._task_is_terminal(current):
                                transition.worker_finished()
                                if not transition.cancelled and transition.commit():
                                    self._events.put(
                                        (
                                            action.task_generation,
                                            "active_task_recovery_closed",
                                            (action, PlatformProtocolError("活动任务已终结")),
                                        )
                                    )
                                return
                            upload = self._recovery_active_upload(current)
                            redisplay = True
                else:
                    mutation_started = True
                    session = self._client.create_mail_session(action.task_id)
                    if transition.cancelled:
                        return
                    allocation = self._client.allocate_card(action.task_id)
                    current = self._client.get_task_timeline(action.task_id)
                    if (
                        current.task.id != action.task_id
                        or current.task.trace_id != action.trace_id
                    ):
                        raise PlatformProtocolError("活动任务在资源恢复后发生身份漂移")
                    if self._task_is_terminal(current):
                        raise PlatformProtocolError("活动任务在资源恢复后已终结")
                    self._validate_recovered_resources(current, session, allocation)
                    reconciled_upload = self._recovery_active_upload(current)
                    if reconciled_upload is not None:
                        upload = self._client.get_upload_job(reconciled_upload.id)
                        if (
                            upload.task_id != action.task_id
                            or upload.trace_id != action.trace_id
                        ):
                            raise PlatformProtocolError("恢复的上传作业与活动任务不一致")
            except BaseException as error:
                if mutation_started:
                    cleanup = transition.cancel()
                    worker_cleanup = transition.worker_finished()
                    cleanup = cleanup or worker_cleanup
                    if cleanup is not None:
                        try:
                            cleanup()
                        except PlatformClientError:
                            barrier = _TaskProvisioningCompensation(
                                generation=action.task_generation,
                                transition=transition,
                                cleanup=cleanup,
                            )
                            self._publish_task_compensation(barrier)
                            self._events.put(
                                (action.task_generation, "task_compensation_error", barrier)
                            )
                            return
                    self._events.put(
                        (action.task_generation, "active_task_recovery_closed", (action, error))
                    )
                    return
                transition.worker_finished()
                if not transition.cancelled:
                    self._events.put(
                        (action.task_generation, "active_task_recovery_error", (action, error))
                    )
                return
            cleanup = transition.worker_finished()
            if cleanup is not None:
                try:
                    cleanup()
                except PlatformClientError:
                    return
            if not transition.cancelled:
                self._events.put(
                    (
                        action.task_generation,
                        (
                            "active_task_recovery_review"
                            if redisplay
                            or (
                                upload is not None
                                and upload.status in {"cancel_pending", "unknown"}
                            )
                            else "active_task_recovered"
                        ),
                        (action, current, session, allocation, upload, transition),
                    )
                )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        action.task_generation,
                        "active_task_recovery_finished",
                        (action, transition, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker,
            daemon=False,
            name="platform-active-task-recovery",
        )
        self._task_transition_threads = [
            existing
            for existing in self._task_transition_threads
            if existing.is_alive()
        ]
        self._task_transition_threads.append(thread)
        self._task_transition_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._task_transition_threads.remove(thread)
            transition.worker_finished()
            self._events.put(
                (
                    action.task_generation,
                    "active_task_recovery_error",
                    (
                        action,
                        PlatformTransportError(
                            "active task recovery worker unavailable"
                        ),
                    ),
                )
            )
            self._events.put(
                (
                    action.task_generation,
                    "active_task_recovery_finished",
                    (action, transition, thread),
                )
            )

    def close_active_task(self) -> None:
        recovery = self._active_task_recovery
        if recovery is None or self._task_id != recovery.task.id:
            return
        active_upload = self._recovery_active_upload(recovery)
        if active_upload is not None and active_upload.status in {
            "cancel_pending",
            "unknown",
        }:
            self._set_status(
                "上传结果尚未确认，客户端不会关闭该任务；请由管理员核对。",
                WARNING,
            )
            return
        self._begin_terminal_task_cleanup("stopped")

    def _update_session_countdown(self, generation: int) -> None:
        if self._closed or generation != self._session_generation:
            return
        if not self._locked and (
            self._client is None or not self._client.is_authenticated
        ):
            return
        remaining = max(0, int(self._session_deadline - time.monotonic()))
        minutes, seconds = divmod(remaining, 60)
        if self._locked:
            self.profile_label.configure(
                text=f"{self._profile_summary} · 已锁定 · 会话 {minutes:02d}:{seconds:02d}"
            )
            if remaining <= 0:
                self.logout(message="会话已过期，已停止任务并清除临时数据。")
                return
            self.root.after(1000, self._update_session_countdown, generation)
            return
        self.profile_label.configure(
            text=f"{self._profile_summary} · 会话 {minutes:02d}:{seconds:02d}"
        )
        if (
            0 < remaining <= 60
            and not self._session_refreshing
            and self._client is not None
            and self._client.can_refresh_oidc_session
        ):
            self._refresh_session_async(generation)
        if remaining <= 0:
            self.logout(message="会话已过期，已停止任务并清除临时数据。")
            return
        self.root.after(1000, self._update_session_countdown, generation)

    def _attempt_session_restore(self) -> None:
        if (
            self._closed
            or self._client is None
            or self._session_restore_action is not None
            or self._session_restore_compensation is not None
        ):
            return
        client = self._client
        try:
            has_saved_session = client.has_saved_refresh_session()
        except PlatformClientError as error:
            self._set_status(format_operation_error(error), ERROR)
            return
        if not has_saved_session:
            return
        self._session_generation += 1
        generation = self._session_generation
        action = object()
        self._session_restore_action = action
        self.login_button.configure(state="disabled")
        self._set_status("正在安全恢复平台会话…", MUTED)

        def worker() -> None:
            refresh_succeeded = False
            try:
                expires_in = client.refresh_oidc_session()
                refresh_succeeded = True
                profile = safe_user_info(client.me())
            except BaseException as error:
                explicit_identity_failure = isinstance(
                    error,
                    (
                        PlatformAuthenticationError,
                        PlatformAuthenticationRequiredError,
                        PlatformDeviceAuthorizationError,
                        PlatformProtocolError,
                    ),
                )
                if (
                    refresh_succeeded
                    and explicit_identity_failure
                    and generation == self._session_generation
                    and self._session_restore_action is action
                ):
                    try:
                        cleanup = client.prepare_logout_cleanup(None)
                    except Exception:
                        captured_cleanup: Callable[[], None] | None = None

                        def cleanup() -> None:
                            nonlocal captured_cleanup
                            if captured_cleanup is None:
                                captured_cleanup = client.prepare_logout_cleanup(None)
                            captured_cleanup()

                    barrier = _SessionRestoreCompensation(
                        generation=generation,
                        action=action,
                        cleanup=cleanup,
                    )
                    with self._session_restore_lock:
                        self._session_restore_compensation = barrier
                    self._events.put(
                        (generation, "session_restore_compensation_ready", barrier)
                    )
                else:
                    self._events.put(
                        (generation, "session_restore_error", (action, error))
                    )
                return
            self._events.put(
                (generation, "session_restored", (action, profile, expires_in))
            )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (generation, "session_restore_finished", (action, thread))
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-session-restore"
        )
        self._session_restore_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._session_restore_thread = None
            self._events.put(
                (
                    generation,
                    "session_restore_error",
                    (
                        action,
                        PlatformTransportError("session restore worker unavailable"),
                    ),
                )
            )
            self._events.put(
                (generation, "session_restore_finished", (action, thread))
            )

    def _start_session_restore_compensation_attempt(
        self, barrier: _SessionRestoreCompensation
    ) -> None:
        if (
            self._session_restore_compensation is not barrier
            or barrier.in_progress
            or barrier.generation != self._session_generation
        ):
            return
        barrier.in_progress = True
        self.login_button.configure(state="disabled", text="正在安全清理…")
        self._set_status(
            "正在清理恢复失败后轮换的凭据与设备会话；确认完成前不会开始新登录。",
            ACCENT,
        )

        def worker() -> None:
            try:
                barrier.cleanup()
            except Exception:
                kind = "session_restore_compensation_error"
            else:
                kind = "session_restore_compensation_succeeded"
            self._events.put((barrier.generation, kind, barrier))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        barrier.generation,
                        "session_restore_compensation_finished",
                        (barrier, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker,
            daemon=False,
            name="platform-session-restore-compensation",
        )
        barrier.thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._present_session_restore_compensation_failure(barrier)

    def _present_session_restore_compensation_failure(
        self, barrier: _SessionRestoreCompensation
    ) -> None:
        if self._session_restore_compensation is not barrier:
            return
        barrier.in_progress = False
        barrier.thread = None
        self.login_button.configure(
            text="重试安全清理",
            command=self._retry_session_restore_compensation,
            state="normal",
        )
        self._set_status(
            "原因：恢复后的身份校验未通过，且安全清理尚未确认；"
            "影响：本地 access 与 refresh 已清除，但服务端设备会话或长期凭据撤销尚未确认；"
            "下一步：检查网络后点击“重试安全清理”。",
            ERROR,
        )

    def _retry_session_restore_compensation(self) -> None:
        barrier = self._session_restore_compensation
        if barrier is None or barrier.in_progress:
            return
        self._start_session_restore_compensation_attempt(barrier)

    def _refresh_session_async(self, generation: int) -> None:
        if self._client is None or self._session_refreshing:
            return
        self._session_refresh_threads = [
            thread for thread in self._session_refresh_threads if thread.is_alive()
        ]
        if self._session_refresh_threads:
            return
        self._session_refreshing = True
        self._set_status("正在刷新安全会话…", MUTED)

        def worker() -> None:
            try:
                expires_in = self._client.refresh_oidc_session()
            except BaseException as error:
                self._events.put((generation, "session_refresh_error", error))
                return
            self._events.put((generation, "session_refreshed", expires_in))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (generation, "session_refresh_finished", thread)
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-session-refresh"
        )
        self._session_refresh_threads.append(thread)
        self._session_refresh_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._session_refresh_threads.remove(thread)
            self._events.put(
                (
                    generation,
                    "session_refresh_error",
                    PlatformTransportError("session refresh worker unavailable"),
                )
            )
            self._events.put((generation, "session_refresh_finished", thread))

    def _on_focus_out(self, _event: tk.Event[Any]) -> None:
        self._sensitive_focus.clear()
        self.root.after(100, self._clear_code_if_unfocused)

    def _on_focus_in(self, _event: tk.Event[Any]) -> None:
        self._sensitive_focus.set()

    def _clear_code_if_unfocused(self) -> None:
        if self._closed:
            return
        if self.root.focus_displayof() is not None:
            self._sensitive_focus.set()
            return
        self.stop_polling()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._clear_trace_id()

    def _remember_clipboard_cleanup_failure(
        self, owner: tuple[str, int | None]
    ) -> None:
        if self._clipboard_cleanup_failed is None:
            self._clipboard_cleanup_failed = []
        if owner not in self._clipboard_cleanup_failed:
            self._clipboard_cleanup_failed.append(owner)

    def _forget_clipboard_cleanup_failure(
        self, owner: tuple[str, int | None]
    ) -> None:
        failures = self._clipboard_cleanup_failed
        if failures is None:
            return
        self._clipboard_cleanup_failed = [item for item in failures if item != owner]
        if not self._clipboard_cleanup_failed:
            self._clipboard_cleanup_failed = None

    def _clear_owned_clipboard(self, text: str | None) -> None:
        if not text:
            return
        owner = self._clipboard_owner
        if owner is None or owner[0] != text:
            owner = (text, None)
        generation = self._clipboard_clear_generation
        self._clipboard_cleanup_pending += 1
        finished = False

        def finish() -> None:
            nonlocal finished
            if finished:
                return
            finished = True
            self._clipboard_cleanup_pending -= 1
            self._finish_update_cleanup_if_ready()
            self._finish_session_shutdown_if_ready()
            if (
                self._clipboard_cleanup_pending == 0
                and self._destroy_pending
                and self._clipboard_cleanup_failed is None
            ):
                self._destroy_window()

        def record_failure() -> None:
            self._remember_clipboard_cleanup_failure(owner)
            try:
                self._set_status(
                    "原因：系统剪贴板持续被占用；"
                    "影响：客户端无法确认已清除自己写入的临时内容，窗口不会退出；"
                    "下一步：关闭占用剪贴板的程序后再次点击关闭。",
                    ERROR,
                )
            except Exception:
                pass
            finally:
                finish()

        def clear_if_owned(retries_remaining: int) -> None:
            if self._closed or generation != self._clipboard_clear_generation:
                finish()
                return
            if owner[1] is not None and get_clipboard_sequence_number() != owner[1]:
                if self._clipboard_owner == owner:
                    self._clipboard_owner = None
                self._forget_clipboard_cleanup_failure(owner)
                finish()
                return
            try:
                if self.root.clipboard_get() != text:
                    if self._clipboard_owner == owner:
                        self._clipboard_owner = None
                    self._forget_clipboard_cleanup_failure(owner)
                    finish()
                    return
                self.root.clipboard_clear()
                self.root.update_idletasks()
            except Exception:
                if retries_remaining <= 0:
                    record_failure()
                    return
                try:
                    self.root.after(
                        CLIPBOARD_CLEAR_RETRY_MS,
                        lambda: clear_if_owned(retries_remaining - 1),
                    )
                except Exception:
                    record_failure()
                    return
            else:
                if self._clipboard_owner == owner:
                    self._clipboard_owner = None
                self._forget_clipboard_cleanup_failure(owner)
                finish()

        clear_if_owned(CLIPBOARD_CLEAR_RETRY_LIMIT)

    def _clear_sensitive_code(self) -> None:
        code = self._current_code
        self._current_code = None
        self._paste_sequence.stop_if_pending(code)
        self._code_clear_generation += 1
        if not self._closed:
            try:
                self.code_label.configure(text="------", foreground=TEXT)
            except Exception:
                pass
            try:
                self.copy_button.configure(state="disabled")
            except Exception:
                pass
        self._clear_owned_clipboard(code)

    def _schedule_code_cleanup(self) -> bool:
        self._code_clear_generation += 1
        generation = self._code_clear_generation

        def clear_if_current() -> None:
            if generation == self._code_clear_generation:
                self._clear_sensitive_code()

        try:
            self.root.after(CODE_VISIBLE_SECONDS * 1000, clear_if_current)
        except Exception:
            self._clear_sensitive_code()
            return False
        return True

    def _clear_card_details(self) -> None:
        text = self._current_card_clipboard
        self._current_card_clipboard = None
        self._paste_sequence.stop_if_pending(text)
        self._card_clear_generation += 1
        if not self._closed:
            self.card_reveal_label.configure(
                text=CARD_DETAILS_PLACEHOLDER, foreground=TEXT
            )
        self._clear_owned_clipboard(text)

    def _schedule_card_cleanup(self, delay_ms: int) -> None:
        self._card_clear_generation += 1
        generation = self._card_clear_generation

        def clear_if_current() -> None:
            if generation == self._card_clear_generation:
                self._clear_card_details()

        self.root.after(delay_ms, clear_if_current)

    @staticmethod
    def _card_reveal_cleanup_delay_ms(
        reveal_expires_at: str, *, now: datetime | None = None
    ) -> int | None:
        if not isinstance(reveal_expires_at, str):
            return None
        value = reveal_expires_at.strip()
        if value != reveal_expires_at:
            return None
        if not _RFC3339_TIMESTAMP.fullmatch(value):
            return None
        try:
            expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            return None
        reference = now or datetime.now().astimezone()
        if reference.tzinfo is None or reference.utcoffset() is None:
            return None
        remaining_ms = int((expires_at - reference).total_seconds() * 1000)
        if remaining_ms <= 0:
            return None
        return min(CARD_DETAILS_VISIBLE_SECONDS * 1000, remaining_ms)

    @staticmethod
    def _resource_expiry_is_live(
        expires_at: str, *, now: datetime | None = None
    ) -> bool:
        if not isinstance(expires_at, str) or not _RFC3339_TIMESTAMP.fullmatch(
            expires_at
        ):
            return False
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return False
        reference = now or datetime.now().astimezone()
        return (
            reference.tzinfo is not None
            and reference.utcoffset() is not None
            and parsed > reference
        )

    @classmethod
    def _validate_provisioned_resources(
        cls,
        task_trace_id: str,
        session: MailSessionSnapshot,
        allocation: CardAllocationSnapshot,
    ) -> None:
        now = datetime.now().astimezone()
        if session.trace_id != task_trace_id:
            raise PlatformProtocolError("新建邮箱会话归属不匹配")
        if allocation.trace_id != task_trace_id:
            raise PlatformProtocolError("新建卡租约归属不匹配")
        if session.status not in {"initializing", "waiting", "code_ready"}:
            raise PlatformProtocolError("新建邮箱会话状态不可用")
        if allocation.status != "active":
            raise PlatformProtocolError("新建卡租约状态不可用")
        if not cls._resource_expiry_is_live(session.expires_at, now=now):
            raise PlatformProtocolError("新建邮箱会话有效期不可用")
        if not cls._resource_expiry_is_live(allocation.expires_at, now=now):
            raise PlatformProtocolError("新建卡租约有效期不可用")

    def _clear_trace_id(self) -> None:
        trace_id = self._current_trace_clipboard
        self._current_trace_clipboard = None
        self._trace_clear_generation += 1
        self._clear_owned_clipboard(trace_id)

    def _schedule_trace_cleanup(self) -> None:
        self._trace_clear_generation += 1
        generation = self._trace_clear_generation

        def clear_if_current() -> None:
            if generation == self._trace_clear_generation:
                self._clear_trace_id()

        self.root.after(TRACE_ID_CLIPBOARD_SECONDS * 1000, clear_if_current)

    def _check_paste_shortcut(self) -> None:
        if self._closed:
            return
        if self._paste_observer.consume() and self._paste_sequence.active:
            self.root.after(
                PASTE_ADVANCE_DELAY_MS,
                self._advance_after_paste,
                self._task_generation,
                self._paste_sequence.generation,
            )
        self.root.after(50, self._check_paste_shortcut)

    def _advance_after_paste(
        self, task_generation: int, sequence_generation: int
    ) -> None:
        if (
            self._closed
            or task_generation != self._task_generation
            or sequence_generation != self._paste_sequence.generation
        ):
            return
        try:
            clipboard_value = self.root.clipboard_get()
        except tk.TclError:
            return
        action = self._paste_sequence.on_paste(clipboard_value)
        if action is None:
            return
        if action.consumed == "code":
            self._clear_sensitive_code()
        elif action.consumed == "card":
            self._clear_card_details()
        if action.value is not None:
            if not self._write_clipboard(action.value):
                if action.value == self._current_card_clipboard:
                    self._discard_card_after_clipboard_failure()
                else:
                    self._paste_sequence.stop()
                return
        self._set_status(action.status, SUCCESS)

    def create_mail_task(self) -> None:
        if self._locked:
            self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        self._task_transition_threads = [
            thread for thread in self._task_transition_threads if thread.is_alive()
        ]
        if self._task_transition_threads:
            session_generation = self._session_generation
            task_generation = self._task_generation
            self.new_task_button.configure(state="disabled")
            self._set_status("上一任务操作仍在安全收尾，请稍后再试。", WARNING)

            def retry_if_current() -> None:
                if (
                    session_generation == self._session_generation
                    and task_generation == self._task_generation
                ):
                    self.create_mail_task()

            self.root.after(250, retry_if_current)
            return
        if (
            self._active_task_discovery_action is not None
            or self._active_task_discovery_required
            or self._active_task_recovery is not None
            or self._active_task_recovery_action is not None
        ):
            self._set_status(
                "本设备仍有未完成任务；请先接管或安全关闭，不能创建第二个任务。",
                WARNING,
            )
            return
        if self._task_compensation is not None:
            if self._task_compensation.in_progress:
                self._set_status(
                    "任务资源仍在安全关闭；确认成功前不会创建新任务。",
                    WARNING,
                )
            else:
                self._present_task_compensation_failure(self._task_compensation)
            return
        if self._terminal_task_cleanup_action is not None:
            if self._terminal_task_cleanup_in_progress:
                self._set_status(
                    "任务资源仍在安全关闭；确认成功前不会创建新任务。", WARNING
                )
            else:
                self._set_status(
                    "原因：上一个任务的资源关闭尚未确认；"
                    "影响：不会创建新任务或重新分配资源；"
                    "下一步：点击“重试资源关闭”。",
                    ERROR,
                )
            return
        if self._client is None or not self._client.is_authenticated:
            self._set_authenticated(False)
            self._set_status("登录已失效，请重新登录平台。", ERROR)
            return
        self.stop_polling()
        self._cancel_card_reveal()
        self._poll_retry_attempt = 0
        self._paste_sequence.stop()
        self._clear_sensitive_code()
        self._clear_card_details()
        previous_task_id = self._task_id
        self._cancel_task_transition()
        try:
            transition = self._client.begin_task_transition(previous_task_id)
        except PlatformClientError as error:
            self._set_status(format_operation_error(error), ERROR)
            return
        self._task_transition = transition
        self._task_id = None
        self._mail_session_id = None
        self._mail_session_token = None
        self._card_allocation_id = None
        self._reset_task_verification()
        self._upload_job_id = None
        self._reset_upload_attempt()
        self.business_entry.configure(state="normal")
        self.upload_button.configure(text="提交上传")
        self._task_generation += 1
        self._upload_generation += 1
        self.task_label.configure(text="创建中…")
        self.mail_label.configure(text="分配中…")
        self.session_label.configure(text="连接中…")
        self.card_label.configure(text="分配中…")
        self.upload_label.configure(text="未创建")
        self.copy_card_button.configure(state="disabled")
        self.new_task_button.configure(state="disabled")
        self._set_workflow_stage("allocating")
        generation = self._task_generation

        def worker() -> None:
            task_id: str | None = None
            cleanup: Callable[[], Any] | None = None
            try:
                if previous_task_id:
                    cleanup = transition.close(previous_task_id)
                    if cleanup is not None:
                        cleanup()
                        cleanup = None
                if transition.cancelled:
                    return
                task = self._client.create_task("mail_code", str(uuid4()))
                task_id = task.id
                task_trace_id = task.trace_id
                cleanup = transition.attach(task_id)
                if cleanup is not None:
                    cleanup()
                    cleanup = None
                if transition.cancelled:
                    return
                session = self._client.create_mail_session(task_id)
                if transition.cancelled:
                    return
                allocation = self._client.allocate_card(task_id)
                self._validate_provisioned_resources(
                    task_trace_id,
                    session,
                    allocation,
                )
            except BaseException as error:
                cleanup = transition.cancel() or cleanup
                if cleanup is not None:
                    try:
                        cleanup()
                    except PlatformClientError:
                        barrier = _TaskProvisioningCompensation(
                            generation=generation,
                            transition=transition,
                            cleanup=cleanup,
                        )
                        self._publish_task_compensation(barrier)
                        self._events.put(
                            (generation, "task_compensation_error", barrier)
                        )
                        return
                self._events.put((generation, "error", error))
                return
            finally:
                cleanup = transition.worker_finished()
                if cleanup is not None:
                    try:
                        cleanup()
                    except PlatformClientError:
                        pass
            if not transition.cancelled:
                self._events.put(
                    (
                        generation,
                        "session",
                        (task_id, task_trace_id, session, allocation, transition),
                    )
                )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        generation,
                        "task_create_finished",
                        (transition, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-task-create"
        )
        self._task_transition_threads.append(thread)
        self._task_transition_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._task_transition_threads.remove(thread)
            self._task_transition_thread = None
            cleanup = transition.cancel()
            worker_cleanup = transition.worker_finished()
            cleanup = cleanup or worker_cleanup
            if cleanup is not None:
                barrier = _TaskProvisioningCompensation(
                    generation=generation,
                    transition=transition,
                    cleanup=cleanup,
                )
                self._publish_task_compensation(barrier)
                self._events.put(
                    (
                        generation,
                        "task_compensation_error",
                        barrier,
                    )
                )
            else:
                self._events.put(
                    (
                        generation,
                        "error",
                        PlatformTransportError(
                            "task creation worker unavailable"
                        ),
                    )
                )
            self._events.put(
                (generation, "task_create_finished", (transition, thread))
            )

    def _start_polling(self) -> None:
        if (
            self._locked
            or self._mail_session_id is None
            or self._mail_session_token is None
            or self._client is None
        ):
            return
        self.stop_polling()
        self._poll_generation += 1
        generation = self._poll_generation
        cancel = threading.Event()
        self._poll_cancel = cancel
        client = self._client
        session_id = self._mail_session_id
        session_token = self._mail_session_token
        task_generation = self._task_generation

        def is_current() -> bool:
            return (
                not cancel.is_set()
                and not self._closed
                and not self._locked
                and self._sensitive_focus.is_set()
                and self._poll_generation == generation
                and self._task_generation == task_generation
                and self._mail_session_id == session_id
                and self._mail_session_token == session_token
            )

        def worker() -> None:
            if not is_current():
                return
            try:
                snapshot: MailCodeSnapshot = client.get_mail_code(
                    session_id, session_token
                )
            except BaseException as error:
                if is_current():
                    self._events.put((generation, "poll_error", error))
                return
            if is_current():
                self._events.put((generation, "code", snapshot))

        def start_next_if_current() -> None:
            if is_current():
                self._start_polling()

        def schedule_next() -> None:
            if is_current():
                self.root.after(
                    int(self._mail_poll_interval_seconds * 1000),
                    start_next_if_current,
                )

        self._schedule_next_poll = schedule_next
        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put((generation, "mail_poll_finished", thread))

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-code-poll"
        )
        self._mail_poll_threads = [
            poll_thread
            for poll_thread in self._mail_poll_threads
            if poll_thread.is_alive()
        ]
        self._mail_poll_threads.append(thread)
        self._mail_poll_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._mail_poll_threads.remove(thread)
            if self._mail_poll_thread is thread:
                self._mail_poll_thread = None
            self._poll_retry_attempt += 1
            self._set_status(
                "验证码查询线程暂不可用；请求尚未发送，将按当前间隔自动重试。",
                WARNING,
            )
            schedule_next()

    def stop_polling(self) -> None:
        self._poll_generation += 1
        if self._poll_cancel is not None:
            self._poll_cancel.set()
        self._poll_cancel = None

    @staticmethod
    def _run_task_cleanup(cleanup: Callable[[], None] | None) -> None:
        if cleanup is None:
            return
        try:
            cleanup()
        except PlatformClientError:
            pass

    def _start_task_cleanup(self, cleanup: Callable[[], None] | None) -> None:
        if cleanup is None:
            return
        thread = threading.Thread(
            target=self._run_task_cleanup,
            args=(cleanup,),
            daemon=False,
            name="platform-task-compensation",
        )
        self._detached_task_cleanup_threads = [
            existing
            for existing in self._detached_task_cleanup_threads
            if existing.is_alive()
        ]
        self._detached_task_cleanup_threads.append(thread)
        try:
            thread.start()
        except RuntimeError:
            self._detached_task_cleanup_threads.remove(thread)
            self._run_task_cleanup(cleanup)

    def _present_task_compensation_failure(
        self, barrier: _TaskProvisioningCompensation
    ) -> None:
        if self._task_compensation is not barrier:
            return
        barrier.in_progress = False
        barrier.thread = None
        self.new_task_button.configure(
            text="重试资源关闭",
            command=self._retry_task_compensation,
            state="disabled" if self._locked else "normal",
        )
        self._set_workflow_stage("stopped")
        self._set_status(
            "原因：任务配置失败，且平台暂未确认已创建资源关闭；"
            "影响：不会创建新任务或重新分配邮箱与卡资源；"
            "下一步：检查网络后点击“重试资源关闭”。",
            ERROR,
        )

    def _publish_task_compensation(
        self,
        barrier: _TaskProvisioningCompensation,
    ) -> bool:
        with self._task_compensation_lock:
            if self._task_compensation is None:
                self._task_compensation = barrier
                return True
            return self._task_compensation is barrier

    def _take_task_compensation(
        self,
        *,
        transition: TaskTransitionCleanup | None = None,
    ) -> _TaskProvisioningCompensation | None:
        with self._task_compensation_lock:
            barrier = self._task_compensation
            if barrier is None or (
                transition is not None and barrier.transition is not transition
            ):
                return None
            self._task_compensation = None
            return barrier

    def _retry_task_compensation(self) -> None:
        barrier = self._task_compensation
        if barrier is None or barrier.in_progress:
            return
        barrier.in_progress = True
        self.new_task_button.configure(state="disabled")
        self._set_status(
            "正在重试已创建资源关闭；确认成功前不会创建新任务。",
            ACCENT,
        )

        def worker() -> None:
            try:
                barrier.cleanup()
            except PlatformClientError:
                kind = "task_compensation_error"
            else:
                kind = "task_compensation_succeeded"
            self._events.put((barrier.generation, kind, barrier))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        barrier.generation,
                        "task_compensation_finished",
                        (barrier, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker,
            daemon=False,
            name="platform-task-compensation-retry",
        )
        barrier.thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._present_task_compensation_failure(barrier)

    def _cancel_task_transition(self, *, retain_failure: bool = False) -> None:
        transition = getattr(self, "_task_transition", None)
        if transition is None:
            return
        cleanup = transition.cancel()
        if cleanup is None or not retain_failure:
            self._start_task_cleanup(cleanup)
            return
        barrier = _TaskProvisioningCompensation(
            generation=self._task_generation,
            transition=transition,
            cleanup=cleanup,
        )
        barrier.in_progress = True
        self._publish_task_compensation(barrier)
        self._task_transition = None

        def worker() -> None:
            try:
                cleanup()
            except PlatformClientError:
                kind = "task_compensation_error"
            else:
                kind = "task_compensation_succeeded"
            self._events.put((barrier.generation, kind, barrier))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        barrier.generation,
                        "task_compensation_finished",
                        (barrier, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker,
            daemon=False,
            name="platform-task-cancel-compensation",
        )
        barrier.thread = thread
        try:
            thread.start()
        except RuntimeError:
            barrier.thread = None
            try:
                cleanup()
            except PlatformClientError:
                self._present_task_compensation_failure(barrier)
            else:
                self._events.put(
                    (barrier.generation, "task_compensation_succeeded", barrier)
                )

    def _drain_events(self) -> None:
        if self._closed:
            return
        while True:
            try:
                generation, kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "unlock_finished":
                if self._unlock_action is value:
                    self._unlock_action = None
                    self._unlock_thread = None
                continue
            if kind == "card_reveal_finished":
                action, succeeded = value
                if self._card_reveal_action is action:
                    self._card_reveal_action = None
                    self._card_reveal_thread = None
                    if (
                        not succeeded
                        and not self._locked
                        and action.generation == self._task_generation
                        and action.allocation_id == self._card_allocation_id
                        and self._client is not None
                        and self._client.is_authenticated
                    ):
                        self.copy_card_button.configure(state="normal")
                continue
            if kind == "active_task_recovery_finished":
                action, transition, worker_thread = value
                if self._task_transition_thread is worker_thread:
                    self._task_transition_thread = None
                if self._active_task_recovery_action is action:
                    self._active_task_recovery_action = None
                    if self._task_transition is transition:
                        self._task_transition = None
                elif self._task_transition is transition and transition.cancelled:
                    self._task_transition = None
                continue
            if kind == "task_create_finished":
                transition, worker_thread = value
                if self._task_transition_thread is worker_thread:
                    self._task_transition_thread = None
                if self._task_transition is transition and transition.cancelled:
                    self._task_transition = None
                continue
            if kind == "session_refresh_finished":
                if self._session_refresh_thread is value:
                    self._session_refresh_thread = None
                    self._session_refreshing = False
                continue
            if kind == "update_download_finished":
                if self._update_download_thread is value:
                    self._update_download_thread = None
                continue
            if kind == "upload_poll_finished":
                if self._upload_poll_thread is value:
                    self._upload_poll_thread = None
                continue
            if kind == "session_restore_finished":
                action, worker_thread = value
                if self._session_restore_thread is worker_thread:
                    self._session_restore_thread = None
                if self._session_restore_action is action:
                    self._session_restore_action = None
                continue
            if kind == "mail_poll_finished":
                if self._mail_poll_thread is value:
                    self._mail_poll_thread = None
                continue
            if kind == "captured_cleanup_finished":
                if self._cleanup_thread is value:
                    self._cleanup_thread = None
                if (
                    self._update_cleanup_thread is value
                    and self._update_cleanup_in_progress
                ):
                    self._update_cleanup_thread = None
                    self._update_cleanup_in_progress = False
                    self.check_update_button.configure(
                        text="重试安全清理",
                        command=self._retry_update_cleanup,
                        state="normal",
                    )
                    self._set_status(
                        "原因：在线更新的安全清理结果已失效；"
                        "影响：当前版本保持运行且不会安装更新；"
                        "下一步：点击“重试安全清理”重新确认。",
                        ERROR,
                    )
                if (
                    self._shutdown_cleanup_thread is value
                    and self._shutdown_cleanup_in_progress
                ):
                    self._shutdown_cleanup_thread = None
                    self._shutdown_cleanup_in_progress = False
                    self.login_button.configure(
                        text="重试安全清理",
                        command=self._retry_session_shutdown,
                        state="normal",
                    )
                    self._set_status(
                        "原因：安全退出的清理结果已失效；"
                        "影响：本地敏感值已清除，但退出尚未完成；"
                        "下一步：点击“重试安全清理”重新确认。",
                        ERROR,
                    )
                continue
            if kind == "session_restore_compensation_finished":
                barrier, worker_thread = value
                if (
                    self._session_restore_compensation is barrier
                    and barrier.thread is worker_thread
                    and barrier.in_progress
                ):
                    barrier.generation = self._session_generation
                    self._present_session_restore_compensation_failure(barrier)
                continue
            if kind == "task_compensation_finished":
                barrier, worker_thread = value
                if (
                    self._task_compensation is barrier
                    and barrier.thread is worker_thread
                    and barrier.in_progress
                ):
                    self._present_task_compensation_failure(barrier)
                continue
            if kind == "active_task_discovery_finished":
                action, worker_thread = value
                if self._active_task_discovery_thread is worker_thread:
                    self._active_task_discovery_thread = None
                if self._active_task_discovery_action is action:
                    self._active_task_discovery_action = None
                continue
            if kind == "terminal_task_cleanup_finished":
                cleanup, worker_thread = value
                if (
                    self._terminal_task_cleanup_action is cleanup
                    and self._terminal_task_cleanup_thread is worker_thread
                ):
                    self._terminal_task_cleanup_thread = None
                    self._terminal_task_cleanup_in_progress = False
                    self.new_task_button.configure(
                        text="重试资源关闭",
                        command=self._retry_terminal_task_cleanup,
                        state="normal",
                    )
                    self._set_status(
                        "原因：任务资源关闭结果已失效；"
                        "影响：任务、卡和邮箱资源不会标记为已安全释放；"
                        "下一步：点击“重试资源关闭”重新确认。",
                        ERROR,
                    )
                continue
            if (
                kind in {"upload_submitted", "upload_submit_error"}
                and generation != self._upload_generation
            ):
                action = value[0]
                if self._upload_submission_action is action:
                    self._present_ambiguous_upload(action)
                continue
            if kind in {
                "session",
                "active_task_recovered",
                "active_task_recovery_review",
            } and (
                self._locked or generation != self._task_generation
            ):
                transition = value[-1]
                self._start_task_cleanup(transition.cancel())
                continue
            if kind.startswith("update_") and generation != self._update_generation:
                if kind == "update_downloaded":
                    _manifest, package = value
                    discard_downloaded_update(package)
                continue
            if self._locked and kind not in {
                "unlock_authorizing",
                "unlock_success",
                "unlock_error",
                "session_restore_compensation_ready",
                "session_restore_compensation_error",
                "session_restore_compensation_succeeded",
                "task_compensation_error",
                "task_compensation_succeeded",
                "terminal_task_cleanup_succeeded",
                "terminal_task_cleanup_error",
            }:
                continue
            if kind in {
                "error",
                "session",
                "active_task_recovered",
                "active_task_recovery_review",
                "active_task_recovery_error",
                "active_task_recovery_closed",
            } and generation != self._task_generation:
                continue
            if kind in {"poll_error", "code"} and generation != self._poll_generation:
                continue
            if kind in {
                "upload",
                "upload_submitted",
                "upload_submit_error",
                "upload_poll_error",
            } and generation != self._upload_generation:
                continue
            if kind in {
                "card_reveal",
                "card_reveal_authorizing",
                "card_reveal_error",
            } and generation != self._task_generation:
                continue
            if kind in {"code", "card_reveal"} and (
                not self._sensitive_focus.is_set()
                or self._client is None
                or not self._client.is_authenticated
            ):
                continue
            if kind in {
                "terminal_task_cleanup_succeeded",
                "terminal_task_cleanup_error",
            } and generation != self._terminal_task_cleanup_generation:
                continue
            if kind in {"task_history", "task_history_error"} and (
                generation != self._history_generation
            ):
                continue
            if kind in {
                "session_restored",
                "session_restore_error",
                "session_restore_compensation_ready",
                "session_restore_compensation_error",
                "session_restore_compensation_succeeded",
                "session_refreshed",
                "session_refresh_error",
                "active_task_discovered",
                "active_task_discovery_error",
                "unlock_authorizing",
                "unlock_success",
                "unlock_error",
            } and generation != self._session_generation:
                continue
            if kind == "active_task_discovered":
                action, recovery = value
                if (
                    self._active_task_discovery_action is not action
                    or action.task_generation != self._task_generation
                    or self._client is None
                    or not self._client.is_authenticated
                ):
                    continue
                self._active_task_discovery_action = None
                self._active_task_discovery_thread = None
                if recovery is None:
                    self._active_task_discovery_required = False
                    self._active_task_recovery = None
                    self._task_id = None
                    self.new_task_button.configure(
                        text="创建邮箱任务",
                        command=self.create_mail_task,
                        state="normal",
                    )
                    self.close_active_task_button.configure(state="disabled")
                    self._set_status("登录成功，本设备没有未完成任务。", SUCCESS)
                else:
                    self._active_task_discovery_required = False
                    self._show_discovered_task(recovery)
            elif kind == "active_task_discovery_error":
                action, error = value
                if self._active_task_discovery_action is not action:
                    continue
                self._active_task_discovery_action = None
                self._active_task_discovery_thread = None
                self.new_task_button.configure(
                    text="重试检查活动任务",
                    command=self._discover_active_task,
                    state="normal",
                )
                self.close_active_task_button.configure(state="disabled")
                if isinstance(error, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                self._set_status(
                    "原因：未能确认本设备是否存在未完成任务；"
                    "影响：为避免重复分配，当前不会创建新任务；"
                    "下一步：检查网络后点击“重试检查活动任务”。",
                    ERROR,
                )
            elif kind == "active_task_recovery_error":
                action, error = value
                if self._active_task_recovery_action is not action:
                    continue
                self._active_task_recovery_action = None
                self._task_transition = None
                self._task_transition_thread = None
                self.new_task_button.configure(
                    text="重试接管活动任务",
                    command=self.take_over_active_task,
                    state="normal",
                )
                self.close_active_task_button.configure(state="normal")
                if isinstance(error, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                self._set_status(
                    "原因：活动任务状态暂未能安全核对；"
                    "影响：未轮换邮箱 capability，也不会创建新任务；"
                    "下一步：检查网络后重试接管，或安全关闭该任务。",
                    ERROR,
                )
            elif kind == "active_task_recovery_closed":
                action, _error = value
                if self._active_task_recovery_action is not action:
                    continue
                self._active_task_recovery_action = None
                self._active_task_recovery = None
                self._task_transition = None
                self._task_transition_thread = None
                self._task_id = None
                self.new_task_button.configure(
                    text="创建邮箱任务",
                    command=self.create_mail_task,
                    state="normal",
                )
                self.close_active_task_button.configure(state="disabled")
                self.task_label.configure(text="已安全关闭")
                self.mail_label.configure(text="登录后创建任务")
                self.session_label.configure(text="未开始")
                self.card_label.configure(text="未分配")
                self.upload_label.configure(text="未创建")
                self._set_workflow_stage("authenticated")
                self._set_status(
                    "活动任务资源恢复后未通过安全校验，平台已确认关闭，可重新创建任务。",
                    WARNING,
                )
            elif kind == "active_task_recovery_review":
                action, recovery, _session, _allocation, _upload, transition = value
                if (
                    self._active_task_recovery_action is not action
                    or transition is not self._task_transition
                    or not transition.commit()
                ):
                    self._start_task_cleanup(transition.cancel())
                    continue
                self._active_task_recovery_action = None
                self._task_transition = None
                self._task_transition_thread = None
                self._mail_session_id = None
                self._mail_session_token = None
                self._card_allocation_id = None
                self._upload_job_id = None
                self._reset_task_verification()
                self.copy_card_button.configure(state="disabled")
                self.upload_button.configure(state="disabled")
                self._show_discovered_task(recovery)
            elif kind == "active_task_recovered":
                action, recovery, session, allocation, upload, transition = value
                if (
                    self._active_task_recovery_action is not action
                    or transition is not self._task_transition
                    or not transition.commit()
                ):
                    self._start_task_cleanup(transition.cancel())
                    continue
                self._active_task_recovery_action = None
                self._active_task_recovery = recovery
                self._task_transition = None
                self._task_transition_thread = None
                self._task_id = recovery.task.id
                self.task_label.configure(
                    text=f"{recovery.task.id[:8]} · trace {recovery.task.trace_id[:8]}"
                )
                self.new_task_button.configure(
                    text="活动任务已接管", state="disabled"
                )
                self.close_active_task_button.configure(state="normal")
                if allocation is not None:
                    self._card_allocation_id = allocation.id
                    self.card_label.configure(text=allocation.card_masked)
                    self.copy_card_button.configure(state="normal")
                if session is not None:
                    self._mail_session_id = session.id
                    self._mail_session_token = session.session_token
                    self._mail_poll_interval_seconds = (
                        session.polling_interval or POLL_SECONDS
                    )
                    self.mail_label.configure(text=session.email_masked)
                    self.session_label.configure(text=session.status)
                if upload is not None:
                    self._upload_job_id = upload.id
                    self._upload_business_name = upload.business_name
                    self.upload_label.configure(text=upload.status)
                    self.business_entry.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("uploading")
                    self._set_status("已接管活动任务，继续核对原上传作业状态。", SUCCESS)
                    self._schedule_upload_poll(0)
                elif session is not None and session.status == "consumed":
                    self._mark_current_task_verified()
                    self._set_workflow_stage("code_ready")
                    self._set_status(
                        "已接管活动任务；服务端确认验证码已消费，可继续提交上传。",
                        SUCCESS,
                    )
                else:
                    self._reset_task_verification()
                    self._poll_retry_attempt = 0
                    self._set_workflow_stage("waiting")
                    self._set_status("已接管活动任务，继续等待新验证码…", SUCCESS)
                    self._start_polling()
            elif kind == "update_current":
                self.check_update_button.configure(state="normal")
                if not value:
                    self._set_status(f"当前已是最新版本 v{APP_VERSION}。", SUCCESS)
            elif kind == "update_error":
                self.check_update_button.configure(state="normal")
                if not value:
                    self._set_status("检查更新失败，请稍后重试。", WARNING)
            elif kind == "update_available":
                manifest, silent = value
                self.check_update_button.configure(state="normal")
                accepted = messagebox.askyesno(
                    "发现新版本",
                    f"发现 v{manifest.version}，是否下载并安装？\n\n"
                    "安装前会校验官方 Release 地址、文件大小和 SHA-256。",
                    parent=self.root,
                )
                if accepted:
                    self._download_update(manifest)
                elif not silent:
                    self._set_status("已暂缓本次更新。", MUTED)
            elif kind == "update_downloaded":
                manifest, package = value
                self._begin_update_cleanup(manifest, package)
            elif kind == "update_cleanup_succeeded":
                if (
                    not self._update_cleanup_in_progress
                    or value != self._pending_update_install
                ):
                    continue
                self._update_cleanup_in_progress = False
                self._update_cleanup_action = None
                self._task_id = None
                self._finish_update_cleanup_if_ready()
            elif kind == "update_cleanup_error":
                if (
                    not self._update_cleanup_in_progress
                    or value != self._pending_update_install
                ):
                    continue
                self._update_cleanup_in_progress = False
                self.check_update_button.configure(
                    text="重试安全清理",
                    command=self._retry_update_cleanup,
                    state="normal",
                )
                self._set_status(
                    "原因：平台资源或登录会话未能确认清理；"
                    "影响：当前版本保持运行且不会安装更新；"
                    "下一步：检查网络后点击“重试安全清理”。",
                    ERROR,
                )
            elif kind == "shutdown_cleanup_succeeded":
                if (
                    generation != self._shutdown_generation
                    or not self._shutdown_cleanup_in_progress
                    or value != self._shutdown_intent
                ):
                    continue
                self._shutdown_cleanup_in_progress = False
                self._shutdown_cleanup_action = None
                self._task_id = None
                self._finish_session_shutdown_if_ready()
            elif kind == "shutdown_cleanup_error":
                if (
                    generation != self._shutdown_generation
                    or not self._shutdown_cleanup_in_progress
                    or value != self._shutdown_intent
                ):
                    continue
                self._shutdown_cleanup_in_progress = False
                self.login_button.configure(
                    text="重试安全清理",
                    command=self._retry_session_shutdown,
                    state="normal",
                )
                self._set_status(
                    "原因：平台任务或登录会话未能确认清理；"
                    "影响：本地敏感值已清除，但退出尚未完成；"
                    "下一步：检查网络后点击“重试安全清理”。",
                    ERROR,
                )
            elif kind == "task_compensation_error":
                barrier = value
                if generation != barrier.generation:
                    continue
                if self._task_compensation is not barrier:
                    continue
                self._task_transition = None
                if (
                    self._shutdown_cleanup_action is not None
                    or self._pending_update_install is not None
                ):
                    continue
                self._present_task_compensation_failure(barrier)
            elif kind == "task_compensation_succeeded":
                barrier = value
                if (
                    generation != barrier.generation
                    or self._task_compensation is not barrier
                ):
                    continue
                barrier.in_progress = False
                barrier.thread = None
                self._task_compensation = None
                self._active_task_recovery_action = None
                self._active_task_recovery = None
                self._task_id = None
                self.close_active_task_button.configure(state="disabled")
                self.task_label.configure(text="已关闭")
                self.mail_label.configure(text="登录后创建任务")
                self.session_label.configure(text="未开始")
                self.card_label.configure(text="未分配")
                self.new_task_button.configure(
                    text="创建邮箱任务",
                    command=self.create_mail_task,
                    state=(
                        "normal"
                        if not self._locked
                        and self._client is not None
                        and self._client.is_authenticated
                        else "disabled"
                    ),
                )
                if not self._locked:
                    self._set_workflow_stage("authenticated")
                    self._set_status(
                        "任务配置失败后的资源已关闭，可重新创建任务。",
                        SUCCESS,
                    )
            elif kind == "update_download_error":
                self.check_update_button.configure(state="normal")
                self._set_status("更新下载或完整性校验失败，未修改当前程序。", ERROR)
            elif kind == "error":
                self._task_transition = None
                self.new_task_button.configure(state="normal")
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                else:
                    self._set_workflow_stage("authenticated")
                if isinstance(value, PlatformProtocolError):
                    self._set_status(
                        "原因：平台返回的任务资源不可安全使用；"
                        "影响：客户端未绑定邮箱或卡资源，也未启动轮询；"
                        "下一步：请重新创建任务；若持续出现请联系管理员。",
                        ERROR,
                    )
                else:
                    self._set_status(format_operation_error(value), ERROR)
            elif kind == "session":
                task_id, task_trace_id, session, allocation, transition = value
                if transition is not self._task_transition or not transition.commit():
                    self._start_task_cleanup(transition.cancel())
                    continue
                self._task_transition = None
                self._task_id = task_id
                self._mail_session_id = session.id
                self._mail_session_token = session.session_token
                self._mail_poll_interval_seconds = (
                    session.polling_interval or POLL_SECONDS
                )
                self._card_allocation_id = allocation.id
                self.task_label.configure(
                    text=f"{task_id[:8]} · trace {task_trace_id[:8]}"
                )
                self.mail_label.configure(text=session.email_masked)
                self.card_label.configure(text=allocation.card_masked)
                self.session_label.configure(text=session.status)
                self.copy_card_button.configure(state="normal")
                self._reset_task_verification()
                self._poll_retry_attempt = 0
                self.new_task_button.configure(state="normal")
                self._set_workflow_stage("waiting")
                self._set_status("邮箱已分配，正在等待新验证码…", ACCENT)
                self._start_polling()
            elif kind == "poll_error":
                if isinstance(value, (PlatformTransportError, PlatformTimeoutError)):
                    self.stop_polling()
                    self._poll_retry_attempt = 0
                    self._reset_task_verification()
                    self.copy_button.configure(state="disabled")
                    self.copy_card_button.configure(state="disabled")
                    self.business_entry.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self.session_label.configure(text="读取结果待核对")
                    self._set_workflow_stage("stopped")
                    self._set_status(
                        "原因：一次性验证码读取响应超时或传输中断；"
                        "影响：验证码可能已被服务端消费，客户端不会按失败推断，也不会自动重试；"
                        "下一步：请先在任务记录中核对邮箱会话状态，再决定是否关闭并新建任务。",
                        WARNING,
                    )
                elif isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                    self._set_status(format_operation_error(value), ERROR)
                else:
                    self.stop_polling()
                    self._set_status(format_operation_error(value), ERROR)
            elif kind == "code":
                snapshot: MailCodeSnapshot = value
                recovered = self._poll_retry_attempt > 0
                self._poll_retry_attempt = 0
                self.session_label.configure(text=snapshot.status)
                if snapshot.code:
                    self._mark_current_task_verified()
                    self._current_code = snapshot.code
                    try:
                        self.code_label.configure(
                            text=snapshot.code, foreground=ACCENT
                        )
                    except Exception:
                        pass
                    try:
                        self.copy_button.configure(state="normal")
                    except Exception:
                        pass
                    paste_action = self._paste_sequence.start(
                        snapshot.code, self._current_card_clipboard
                    )
                    copied = paste_action.value is None or self._write_clipboard(
                        paste_action.value
                    )
                    cleanup_scheduled = self._schedule_code_cleanup()
                    if not cleanup_scheduled:
                        self._set_status(
                            "无法安排验证码自动清理；为避免敏感信息残留，"
                            "验证码与客户端写入的剪贴板内容已立即清除。",
                            ERROR,
                        )
                    elif copied:
                        self._set_status(paste_action.status, SUCCESS)
                    else:
                        self._paste_sequence.stop()
                    self._set_workflow_stage("code_ready")
                    self.stop_polling()
                elif snapshot.status == "code_ready":
                    self._reset_task_verification()
                    self._set_status("验证码已到达，正在安全获取…", ACCENT)
                    self._set_workflow_stage("code_ready")
                    if hasattr(self, "_schedule_next_poll"):
                        self._schedule_next_poll()
                elif snapshot.status in {"expired", "revoked"}:
                    self._reset_task_verification()
                    self.stop_polling()
                    self.copy_card_button.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("stopped")
                    self._begin_terminal_task_cleanup("stopped")
                elif snapshot.status == "consumed":
                    self._mark_current_task_verified()
                    self._set_status("验证码已消费，可继续提交上传。", SUCCESS)
                    self._set_workflow_stage("code_ready")
                    self.stop_polling()
                else:
                    self._set_status(
                        "网络连接已恢复，继续等待新验证码…"
                        if recovered
                        else "等待新验证码…",
                        SUCCESS if recovered else MUTED,
                    )
                    if hasattr(self, "_schedule_next_poll"):
                        self._schedule_next_poll()
            elif kind in {"upload", "upload_submitted"}:
                if kind == "upload_submitted":
                    action, snapshot = value
                    if (
                        self._upload_submission_action is not action
                        or snapshot.task_id != action.task_id
                    ):
                        continue
                    action.pending = False
                    self._upload_submission_action = None
                    self._upload_submission_thread = None
                    self.upload_button.configure(text="提交上传")
                else:
                    self._upload_poll_thread = None
                    snapshot = value
                self._upload_job_id = snapshot.id
                self.upload_label.configure(text=snapshot.status)
                if snapshot.status in {"queued", "running"}:
                    self.business_entry.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self._set_status("上传作业已进入服务端队列。", ACCENT)
                    self._set_workflow_stage("uploading")
                    self._schedule_upload_poll(2000)
                elif snapshot.status == "succeeded":
                    self._reset_task_verification()
                    self.copy_card_button.configure(state="disabled")
                    self._set_workflow_stage("uploading")
                    self._begin_terminal_task_cleanup("completed")
                elif snapshot.status == "unknown":
                    self._set_status(
                        "原因：服务端未能确认外部平台最终结果；"
                        "影响：作业可能已提交，不得按失败推断或重复提交；"
                        "下一步：请管理员核对外部结果后再处理，系统不会自动重试。",
                        WARNING,
                    )
                    self._reset_task_verification()
                    self._set_workflow_stage("review")
                else:
                    self._set_status(
                        f"原因：服务端已确认上传失败（错误码：{snapshot.error_code or 'unknown_error'}）；"
                        "影响：本次上传未成功，当前任务仍保留；"
                        "下一步：按错误码修正后可从当前任务重新提交。",
                        ERROR,
                    )
                    self._reset_upload_attempt()
                    self.business_entry.configure(state="normal")
                    self.upload_button.configure(
                        text="提交上传",
                        state="normal" if self._current_task_is_verified() else "disabled"
                    )
                    self._set_workflow_stage("upload_failed")
            elif kind == "card_reveal_authorizing":
                self._set_status(
                    "请在浏览器中重新登录并完成 MFA；完成后将自动返回。", ACCENT
                )
            elif kind == "card_reveal":
                cleanup_delay_ms = self._card_reveal_cleanup_delay_ms(
                    value.reveal_expires_at
                )
                if cleanup_delay_ms is None:
                    self._clear_card_details()
                    if (
                        self._card_allocation_id is not None
                        and self._client is not None
                        and self._client.is_authenticated
                    ):
                        self.copy_card_button.configure(state="normal")
                    self._set_status(
                        "原因：卡号揭示已过期或有效期无效；"
                        "影响：卡详情未写入本地状态或剪贴板；"
                        "下一步：请重新点击揭示并完成身份验证。",
                        WARNING,
                    )
                    continue
                details = self._format_card_details(value)
                self._current_card_clipboard = details
                self.card_reveal_label.configure(
                    text=self._format_card_display(value), foreground=ACCENT
                )
                paste_action = self._paste_sequence.offer_card(details)
                visible_seconds = max(1, (cleanup_delay_ms + 999) // 1000)
                if paste_action is None:
                    copied = self._write_clipboard(details)
                    status = (
                        f"卡详情已复制到剪贴板；请尽快粘贴，"
                        f"最多 {visible_seconds} 秒后自动清理。"
                    )
                else:
                    copied = paste_action.value is None or self._write_clipboard(
                        paste_action.value
                    )
                    status = paste_action.status
                if not copied:
                    self._discard_card_after_clipboard_failure()
                    continue
                self._schedule_card_cleanup(cleanup_delay_ms)
                self.copy_card_button.configure(state="disabled")
                self._set_status(status, SUCCESS)
            elif kind == "card_reveal_error":
                if self._card_allocation_id is not None and self._client is not None and self._client.is_authenticated:
                    self.copy_card_button.configure(state="normal")
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                if isinstance(value, PlatformProtocolError):
                    self._set_status(
                        "原因：平台返回的卡揭示结果与当前卡租约不一致或无法安全验证；"
                        "影响：卡详情未写入本地状态或剪贴板；"
                        "下一步：请重新点击揭示；若持续出现请联系管理员。",
                        ERROR,
                    )
                else:
                    self._set_status(format_operation_error(value), ERROR)
            elif kind == "upload_submit_error":
                action, error = value
                if self._upload_submission_action is not action:
                    continue
                action.pending = False
                self._upload_submission_thread = None
                if isinstance(
                    error,
                    (PlatformTimeoutError, PlatformTransportError, PlatformProtocolError),
                ):
                    self._present_ambiguous_upload(action)
                elif isinstance(error, PlatformAuthenticationError):
                    self._reset_upload_attempt()
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                    self._set_status(
                        "原因：登录已失效或设备已撤销；"
                        "影响：平台已拒绝本次上传创建请求；"
                        "下一步：重新登录并核对当前任务状态后再操作。",
                        ERROR,
                    )
                else:
                    reason = format_operation_error(error)
                    self._reset_upload_attempt()
                    self.business_entry.configure(state="normal")
                    self.upload_button.configure(
                        text="提交上传",
                        state="normal" if self._current_task_is_verified() else "disabled"
                    )
                    self._set_status(
                        f"原因：{reason}"
                        "影响：平台未建立可跟踪的上传作业；"
                        "下一步：按错误码或配置提示修正后，从当前任务重新提交。",
                        ERROR,
                    )
            elif kind == "upload_poll_error":
                self._upload_poll_thread = None
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                    self._set_status(format_operation_error(value), ERROR)
                elif isinstance(value, PlatformProtocolError):
                    self.business_entry.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self.upload_label.configure(text="状态校验失败")
                    self._set_workflow_stage("review")
                    self._set_status(
                        "原因：平台返回的上传状态与当前作业不一致；"
                        "影响：无法安全确认当前上传结果，当前任务和原作业已保留；"
                        "下一步：请联系管理员检查外部平台服务配置，确认前请勿重复提交。",
                        ERROR,
                    )
                else:
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("uploading")
                    self._set_status(
                        "暂时无法获取上传状态；将继续查询，请勿重复提交。", WARNING
                    )
                    self._schedule_upload_poll(3000)
            elif kind == "terminal_task_cleanup_succeeded":
                task_id, outcome = value
                if (
                    self._terminal_task_cleanup_action is None
                    or task_id != self._terminal_task_cleanup_task_id
                    or outcome != self._terminal_task_cleanup_outcome
                ):
                    continue
                self._terminal_task_cleanup_in_progress = False
                self._terminal_task_cleanup_action = None
                self._terminal_task_cleanup_thread = None
                self._terminal_task_cleanup_task_id = None
                self._terminal_task_cleanup_outcome = None
                if self._task_id == task_id:
                    self._task_id = None
                    self._mail_session_id = None
                    self._mail_session_token = None
                    self._card_allocation_id = None
                    self._upload_job_id = None
                    self._reset_task_verification()
                    self._reset_upload_attempt()
                self._active_task_recovery = None
                self._active_task_recovery_action = None
                self.close_active_task_button.configure(state="disabled")
                self.task_label.configure(text="已关闭")
                self.mail_label.configure(text="已撤销")
                self.session_label.configure(text="已撤销")
                self.card_label.configure(text="已释放")
                self.new_task_button.configure(
                    text="创建邮箱任务",
                    command=self.create_mail_task,
                    state=(
                        "normal"
                        if not self._locked
                        and self._client is not None
                        and self._client.is_authenticated
                        else "disabled"
                    ),
                )
                if outcome == "completed":
                    self._set_workflow_stage("completed")
                    self._set_status("上传完成，任务已关闭并释放资源。", SUCCESS)
                else:
                    self._set_workflow_stage("stopped")
                    self._set_status("邮箱会话已结束，任务已关闭并释放资源。", SUCCESS)
            elif kind == "terminal_task_cleanup_error":
                task_id, outcome = value
                if (
                    self._terminal_task_cleanup_action is None
                    or task_id != self._terminal_task_cleanup_task_id
                    or outcome != self._terminal_task_cleanup_outcome
                ):
                    continue
                self._terminal_task_cleanup_in_progress = False
                self._terminal_task_cleanup_thread = None
                self.new_task_button.configure(
                    text="重试资源关闭",
                    command=self._retry_terminal_task_cleanup,
                    state="disabled" if self._locked else "normal",
                )
                self.close_active_task_button.configure(state="disabled")
                self._set_workflow_stage("stopped")
                self._set_status(
                    "原因：平台暂未确认任务资源关闭；"
                    "影响：上传结果保留，但任务、卡和邮箱资源不会标记为已安全释放；"
                    "下一步：检查网络后点击“重试资源关闭”。",
                    ERROR,
                )
            elif kind == "session_restored":
                action, profile, expires_in = value
                if self._session_restore_action is not action:
                    continue
                self._session_restore_action = None
                self._on_login_success(profile, expires_in)
            elif kind == "session_restore_error":
                action, error = value
                if self._session_restore_action is not action:
                    continue
                self._session_restore_action = None
                if self._client is not None:
                    self._client.clear_access_token()
                self._set_authenticated(False)
                if isinstance(error, (PlatformTransportError, PlatformTimeoutError)):
                    self._set_status(
                        "原因：网络中断，平台身份暂无法确认；"
                        "影响：本地 access 已清除，长期恢复凭据尚未撤销，以便网络恢复后重试；"
                        "下一步：恢复网络后重新启动客户端或重新登录；若设备不再受信任，请完成安全退出。",
                        ERROR,
                    )
                elif not isinstance(error, PlatformAuthenticationRequiredError):
                    self._set_status(format_operation_error(error), ERROR)
            elif kind == "session_restore_compensation_ready":
                barrier = value
                if (
                    generation != barrier.generation
                    or self._session_restore_action is not barrier.action
                    or self._session_restore_compensation is not barrier
                ):
                    continue
                self._session_restore_action = None
                if self._client is not None:
                    self._client.clear_access_token()
                self._set_authenticated(False)
                self._start_session_restore_compensation_attempt(barrier)
            elif kind == "session_restore_compensation_error":
                barrier = value
                if (
                    generation != barrier.generation
                    or self._session_restore_compensation is not barrier
                ):
                    continue
                self._present_session_restore_compensation_failure(barrier)
            elif kind == "session_restore_compensation_succeeded":
                barrier = value
                if (
                    generation != barrier.generation
                    or self._session_restore_compensation is not barrier
                ):
                    continue
                barrier.in_progress = False
                barrier.thread = None
                self._session_restore_compensation = None
                self._set_authenticated(False)
                self.login_button.configure(
                    text="登录",
                    command=self.open_login_dialog,
                    state="normal",
                )
                self._set_status(
                    "原因：恢复后的身份校验未通过；"
                    "影响：本地凭据、服务端设备会话与长期凭据撤销已确认，客户端未进入登录状态；"
                    "下一步：请重新登录；持续失败请联系管理员。",
                    ERROR,
                )
            elif kind == "session_refreshed":
                self._session_refreshing = False
                self._session_refresh_thread = None
                self._session_deadline = time.monotonic() + max(1, int(value))
                self._set_status("安全会话已刷新。", SUCCESS)
            elif kind == "session_refresh_error":
                self._session_refreshing = False
                self._session_refresh_thread = None
                self.logout(message="安全会话刷新失败，已停止任务并清除临时数据。")
            elif kind == "task_history":
                self._render_task_history(value)
            elif kind == "task_history_error":
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                elif self._history_refresh_button is not None:
                    self._history_refresh_button.configure(state="normal")
                if self._history_status is not None:
                    self._history_status.configure(
                        text=format_operation_error(value), fg=ERROR
                    )
            elif kind == "unlock_authorizing":
                if self._unlock_action is not value:
                    continue
                self._set_status(
                    "请在浏览器中重新登录当前账号；完成后将自动返回。", ACCENT
                )
            elif kind == "unlock_success":
                action, profile = value
                if self._unlock_action is not action:
                    continue
                self._finish_unlock(profile)
            elif kind == "unlock_error":
                action, error = value
                if self._unlock_action is not action:
                    continue
                self.lock_button.configure(state="normal")
                self._set_status(
                    f"{format_operation_error(error)} 客户端仍保持锁定。", ERROR
                )
        if not self._closed:
            self.root.after(100, self._drain_events)

    def check_for_updates(self, *, silent: bool = False) -> None:
        """Check the pinned official GitHub Release manifest in the background."""

        if (
            self._closed
            or self._shutdown_cleanup_action is not None
            or self._update_cleanup_action is not None
            or self._pending_update_install is not None
        ):
            return
        if self._locked:
            if not silent:
                self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        if self._update_client is None:
            if not silent:
                self._set_status("在线更新配置无效，请联系管理员。", ERROR)
            return
        with self._update_check_lock:
            self._update_check_threads = [
                thread for thread in self._update_check_threads if thread.is_alive()
            ]
            check_in_progress = bool(self._update_check_threads)
        if check_in_progress:
            retry_generation = self._update_generation
            self.check_update_button.configure(state="disabled")

            def retry_if_current() -> None:
                if retry_generation == self._update_generation:
                    self.check_for_updates(silent=silent)

            self.root.after(250, retry_if_current)
            return
        self._update_generation += 1
        generation = self._update_generation
        self.check_update_button.configure(state="disabled")
        if not silent:
            self._set_status("正在检查新版本…", ACCENT)

        thread: threading.Thread

        def worker() -> None:
            try:
                try:
                    manifest = self._update_client.check()
                except Exception:
                    self._events.put((generation, "update_error", silent))
                else:
                    if manifest is None:
                        self._events.put((generation, "update_current", silent))
                    else:
                        self._events.put(
                            (generation, "update_available", (manifest, silent))
                        )
            finally:
                with self._update_check_lock:
                    if thread in self._update_check_threads:
                        self._update_check_threads.remove(thread)

        thread = threading.Thread(
            target=worker, daemon=False, name="platform-update-check"
        )
        with self._update_check_lock:
            self._update_check_threads.append(thread)
        try:
            thread.start()
        except RuntimeError:
            with self._update_check_lock:
                if thread in self._update_check_threads:
                    self._update_check_threads.remove(thread)
            self._events.put((generation, "update_error", silent))

    def _download_update(self, manifest: UpdateManifest) -> None:
        if self._update_client is None:
            return
        generation = self._update_generation
        self.check_update_button.configure(state="disabled")
        self._set_status(f"正在下载并校验 v{manifest.version}…", ACCENT)

        def worker() -> None:
            try:
                package = self._update_client.download(manifest)
            except Exception:
                self._events.put((generation, "update_download_error", None))
            else:
                self._events.put(
                    (generation, "update_downloaded", (manifest, package))
                )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (generation, "update_download_finished", thread)
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-update-download"
        )
        self._update_download_threads = [
            download_thread
            for download_thread in self._update_download_threads
            if download_thread.is_alive()
        ]
        self._update_download_threads.append(thread)
        self._update_download_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._update_download_threads.remove(thread)
            if self._update_download_thread is thread:
                self._update_download_thread = None
            self._events.put((generation, "update_download_error", None))

    def _begin_update_cleanup(self, manifest: UpdateManifest, package: Path) -> None:
        """Detach the session and prove remote cleanup before replacing the EXE."""

        if (
            self._pending_update_install is not None
            or self._shutdown_cleanup_action is not None
        ):
            return
        pending = (manifest, package)
        self.stop_polling()
        self._paste_sequence.stop()
        self._close_task_history()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._clear_trace_id()
        self._cancel_card_reveal()
        self._session_generation += 1
        self._session_refreshing = False
        self._task_generation += 1
        self._upload_generation += 1

        self._update_cleanup_action = self._capture_session_cleanup(self._task_id)
        self._update_cleanup_completed = False
        self._pending_update_install = pending

        self._mail_session_id = None
        self._mail_session_token = None
        self._card_allocation_id = None
        self._reset_task_verification()
        self._upload_job_id = None
        self._reset_upload_attempt()
        self._profile_identity = None
        self.task_label.configure(text="安全清理中…")
        self.mail_label.configure(text="本地会话已清除")
        self.session_label.configure(text="正在撤销")
        self.card_label.configure(text="本地详情已清除")
        self.upload_label.configure(text="等待安全清理")
        self.profile_label.configure(text="本地登录会话已清除")
        self._set_authenticated(False)
        self.login_button.configure(state="disabled")
        self.check_update_button.configure(state="disabled")
        self._set_workflow_stage("stopped")
        self._set_status(
            "正在关闭平台任务并撤销登录会话；完成前不会退出或替换程序。",
            ACCENT,
        )
        self._start_update_cleanup_attempt()

    def _capture_session_cleanup(self, task_id: str | None) -> Callable[[], None]:
        """Capture one detachable session cleanup that remains safe to retry."""

        transition_cleanup: Callable[[], None] | None = None
        transition = getattr(self, "_task_transition", None)
        if transition is not None:
            transition_cleanup = transition.cancel()
            self._task_transition = None
        transition_threads = tuple(getattr(self, "_task_transition_threads", ()))
        transition_thread = getattr(self, "_task_transition_thread", None)
        if transition_thread is not None and transition_thread not in transition_threads:
            transition_threads += (transition_thread,)
        self._task_transition_threads = []
        compensation = self._take_task_compensation()
        compensation_cleanup = (
            compensation.cleanup if compensation is not None else None
        )
        compensation_thread = (
            compensation.thread if compensation is not None else None
        )
        restore_thread = getattr(self, "_session_restore_thread", None)
        self._session_restore_thread = None
        session_refresh_threads = tuple(
            getattr(self, "_session_refresh_threads", ())
        )
        session_refresh_thread = getattr(self, "_session_refresh_thread", None)
        if (
            session_refresh_thread is not None
            and session_refresh_thread not in session_refresh_threads
        ):
            session_refresh_threads += (session_refresh_thread,)
        self._session_refresh_threads = []
        self._session_refresh_thread = None
        restore_lock = getattr(self, "_session_restore_lock", None)
        if restore_lock is None:
            restore_lock = threading.Lock()
        with restore_lock:
            restore_compensation = self._session_restore_compensation
            self._session_restore_compensation = None
        restore_compensation_cleanup = (
            restore_compensation.cleanup
            if restore_compensation is not None
            else None
        )
        restore_compensation_thread = (
            restore_compensation.thread
            if restore_compensation is not None
            else None
        )
        terminal_cleanup_thread = getattr(
            self, "_terminal_task_cleanup_thread", None
        )
        active_task_discovery_threads = tuple(
            getattr(self, "_active_task_discovery_threads", ())
        )
        active_task_discovery_thread = getattr(
            self, "_active_task_discovery_thread", None
        )
        if (
            active_task_discovery_thread is not None
            and active_task_discovery_thread not in active_task_discovery_threads
        ):
            active_task_discovery_threads += (active_task_discovery_thread,)
        self._active_task_discovery_threads = []
        self._active_task_discovery_thread = None
        history_threads = tuple(getattr(self, "_history_threads", ()))
        self._history_threads = []
        login_worker_threads = tuple(getattr(self, "_login_worker_threads", ()))
        self._login_worker_threads = []
        login_dialog = getattr(self, "_login_dialog", None)
        if login_dialog is not None:
            login_worker_threads += login_dialog.stop_and_detach_worker_threads()
        detached_task_cleanup_threads = tuple(
            getattr(self, "_detached_task_cleanup_threads", ())
        )
        unlock_action = getattr(self, "_unlock_action", None)
        unlock_thread = getattr(self, "_unlock_thread", None)
        if unlock_action is not None:
            unlock_action.cancel.set()
        card_reveal_thread = getattr(self, "_card_reveal_thread", None)
        mail_poll_threads = tuple(getattr(self, "_mail_poll_threads", ()))
        mail_poll_thread = getattr(self, "_mail_poll_thread", None)
        if mail_poll_thread is not None and mail_poll_thread not in mail_poll_threads:
            mail_poll_threads += (mail_poll_thread,)
        self._mail_poll_threads = []
        self._mail_poll_thread = None
        upload_submission_thread = getattr(
            self, "_upload_submission_thread", None
        )
        self._upload_submission_thread = None
        upload_poll_threads = tuple(getattr(self, "_upload_poll_threads", ()))
        upload_poll_thread = getattr(self, "_upload_poll_thread", None)
        if (
            upload_poll_thread is not None
            and upload_poll_thread not in upload_poll_threads
        ):
            upload_poll_threads += (upload_poll_thread,)
        self._upload_poll_threads = []
        self._upload_poll_thread = None
        update_check_lock = getattr(self, "_update_check_lock", None)
        if update_check_lock is None:
            update_check_threads = tuple(getattr(self, "_update_check_threads", ()))
        else:
            with update_check_lock:
                update_check_threads = tuple(self._update_check_threads)
                self._update_check_threads = []
        update_download_threads = tuple(
            getattr(self, "_update_download_threads", ())
        )
        update_download_thread = getattr(self, "_update_download_thread", None)
        if (
            update_download_thread is not None
            and update_download_thread not in update_download_threads
        ):
            update_download_threads += (update_download_thread,)
        self._update_download_threads = []
        self._update_download_thread = None
        cleanup_client = self._client
        try:
            logout_cleanup = (
                cleanup_client.prepare_logout_cleanup(task_id)
                if cleanup_client is not None
                else lambda: None
            )
        except Exception:
            captured_logout_cleanup: Callable[[], None] | None = None

            def logout_cleanup() -> None:
                nonlocal captured_logout_cleanup
                if cleanup_client is None:
                    return
                if captured_logout_cleanup is None:
                    captured_logout_cleanup = cleanup_client.prepare_logout_cleanup(
                        task_id
                    )
                captured_logout_cleanup()

        late_compensation: _TaskProvisioningCompensation | None = None
        late_restore_compensation: _SessionRestoreCompensation | None = None

        def cleanup_action() -> None:
            nonlocal late_compensation, late_restore_compensation
            first_error: Exception | None = None
            if transition_cleanup is not None:
                try:
                    transition_cleanup()
                except Exception as error:
                    first_error = error
            for transition_thread in transition_threads:
                if transition_thread.is_alive():
                    transition_thread.join()
            if transition is not None and late_compensation is None:
                late_compensation = self._take_task_compensation(
                    transition=transition
                )
            if late_compensation is not None:
                try:
                    late_compensation.cleanup()
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if compensation_thread is not None and compensation_thread.is_alive():
                compensation_thread.join()
            if compensation_cleanup is not None:
                try:
                    compensation_cleanup()
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if restore_thread is not None and restore_thread.is_alive():
                restore_thread.join()
            for session_refresh_thread in session_refresh_threads:
                if session_refresh_thread.is_alive():
                    session_refresh_thread.join()
            if restore_compensation is None and late_restore_compensation is None:
                with restore_lock:
                    late_restore_compensation = self._session_restore_compensation
                    self._session_restore_compensation = None
            late_restore_cleanup = (
                late_restore_compensation.cleanup
                if late_restore_compensation is not None
                else None
            )
            if (
                restore_compensation_thread is not None
                and restore_compensation_thread.is_alive()
            ):
                restore_compensation_thread.join()
            if restore_compensation_cleanup is not None:
                try:
                    restore_compensation_cleanup()
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if late_restore_cleanup is not None:
                try:
                    late_restore_cleanup()
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if (
                terminal_cleanup_thread is not None
                and terminal_cleanup_thread.is_alive()
            ):
                terminal_cleanup_thread.join()
            for active_task_discovery_thread in active_task_discovery_threads:
                if active_task_discovery_thread.is_alive():
                    active_task_discovery_thread.join()
            for history_thread in history_threads:
                if history_thread.is_alive():
                    history_thread.join()
            for login_worker_thread in login_worker_threads:
                if login_worker_thread.is_alive():
                    login_worker_thread.join()
            for cleanup_thread in detached_task_cleanup_threads:
                if cleanup_thread.is_alive():
                    cleanup_thread.join()
            if unlock_thread is not None and unlock_thread.is_alive():
                unlock_thread.join(CARD_REVEAL_SHUTDOWN_WAIT_SECONDS)
                if unlock_thread.is_alive():
                    raise PlatformTimeoutError(
                        "unlock did not stop before session cleanup"
                    )
            if card_reveal_thread is not None and card_reveal_thread.is_alive():
                card_reveal_thread.join(CARD_REVEAL_SHUTDOWN_WAIT_SECONDS)
                if card_reveal_thread.is_alive():
                    raise PlatformTimeoutError(
                        "card reveal did not stop before session cleanup"
                    )
            for mail_poll_thread in mail_poll_threads:
                if mail_poll_thread.is_alive():
                    mail_poll_thread.join()
            if (
                upload_submission_thread is not None
                and upload_submission_thread.is_alive()
            ):
                upload_submission_thread.join()
            for upload_poll_thread in upload_poll_threads:
                if upload_poll_thread.is_alive():
                    upload_poll_thread.join()
            for update_check_thread in update_check_threads:
                if update_check_thread.is_alive():
                    update_check_thread.join()
            for update_download_thread in update_download_threads:
                if update_download_thread.is_alive():
                    update_download_thread.join()
            try:
                logout_cleanup()
            except Exception as error:
                if first_error is None:
                    first_error = error
            if first_error is not None:
                raise first_error

        return cleanup_action

    def _start_captured_cleanup_attempt(
        self,
        cleanup: Callable[[], None],
        *,
        generation: int,
        success_kind: str,
        error_kind: str,
        value: Any,
        name: str,
    ) -> threading.Thread | None:
        previous = self._cleanup_thread
        if previous is not None and previous.is_alive():
            return None

        def worker() -> None:
            try:
                cleanup()
            except Exception:
                self._events.put((generation, error_kind, value))
            else:
                self._events.put((generation, success_kind, value))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (generation, "captured_cleanup_finished", thread)
                )

        thread = threading.Thread(target=run_worker, daemon=False, name=name)
        self._cleanup_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._cleanup_thread = None
            raise
        return thread

    def _start_update_cleanup_attempt(self) -> None:
        pending = self._pending_update_install
        cleanup = self._update_cleanup_action
        if pending is None or cleanup is None or self._update_cleanup_in_progress:
            return
        generation = self._update_generation
        try:
            thread = self._start_captured_cleanup_attempt(
                cleanup,
                generation=generation,
                success_kind="update_cleanup_succeeded",
                error_kind="update_cleanup_error",
                value=pending,
                name="platform-update-cleanup",
            )
        except RuntimeError:
            self.check_update_button.configure(
                text="重试安全清理",
                command=self._retry_update_cleanup,
                state="normal",
            )
            self._set_status(
                "原因：平台资源或登录会话清理线程未能启动；"
                "影响：当前版本保持运行且不会安装更新；"
                "下一步：点击“重试安全清理”。",
                ERROR,
            )
            return
        if thread is None:
            return
        self._update_cleanup_in_progress = True
        self.check_update_button.configure(state="disabled")
        self._update_cleanup_thread = thread

    def _retry_update_cleanup(self) -> None:
        if self._pending_update_install is None or self._update_cleanup_in_progress:
            return
        self._set_status(
            "正在重试平台资源与登录会话清理；确认成功前不会安装更新。",
            ACCENT,
        )
        self._start_update_cleanup_attempt()

    def _retry_update_clipboard_cleanup(self) -> None:
        failed = tuple(self._clipboard_cleanup_failed or ())
        if not failed or self._clipboard_cleanup_pending:
            return
        self.check_update_button.configure(state="disabled")
        self._set_status("正在重试清除客户端写入的临时剪贴板内容…", ACCENT)
        for owner in failed:
            self._clipboard_owner = owner
            self._clear_owned_clipboard(owner[0])

    def _retry_update_helper(self) -> None:
        self.check_update_button.configure(state="disabled")
        self._finish_update_cleanup_if_ready()

    def _finish_update_cleanup_if_ready(self) -> None:
        pending = self._pending_update_install
        if (
            pending is None
            or self._update_cleanup_completed
            or self._update_cleanup_action is not None
            or self._update_cleanup_in_progress
        ):
            return
        if self._clipboard_cleanup_pending:
            self.check_update_button.configure(state="disabled")
            self._set_status(
                "平台会话已撤销，正在确认清除客户端写入的临时剪贴板内容…",
                ACCENT,
            )
            return
        if self._clipboard_cleanup_failed is not None:
            self.check_update_button.configure(
                text="重试清除剪贴板",
                command=self._retry_update_clipboard_cleanup,
                state="normal",
            )
            self._set_status(
                "原因：系统剪贴板持续被占用；"
                "影响：不会启动更新替换程序；"
                "下一步：关闭占用剪贴板的程序后点击“重试清除剪贴板”。",
                ERROR,
            )
            return
        manifest, package = pending
        try:
            launch_update_helper(package, manifest.sha256)
        except Exception:
            self.check_update_button.configure(
                text="重试启动更新",
                command=self._retry_update_helper,
                state="normal",
            )
            self._set_status(
                "更新包已校验且安全清理已完成，但无法启动替换程序；"
                "请点击“重试启动更新”。",
                ERROR,
            )
            return
        self._update_cleanup_completed = True
        self._pending_update_install = None
        self._update_generation += 1
        self._set_status("更新已校验，正在退出并替换程序…", SUCCESS)
        try:
            self.root.after(200, self.close)
        except Exception:
            self.close()

    @staticmethod
    def _format_card_details(snapshot: CardRevealSnapshot) -> str:
        expiry = ""
        if snapshot.expiry_month is not None and snapshot.expiry_year is not None:
            expiry = f"{snapshot.expiry_month:02d}/{snapshot.expiry_year % 100:02d}"
        return "\t".join((snapshot.pan, expiry)) if expiry else snapshot.pan

    @staticmethod
    def _format_card_display(snapshot: CardRevealSnapshot) -> str:
        pan = " ".join(
            snapshot.pan[index : index + 4]
            for index in range(0, len(snapshot.pan), 4)
        )
        expiry = "--/--"
        if snapshot.expiry_month is not None and snapshot.expiry_year is not None:
            expiry = f"{snapshot.expiry_month:02d}/{snapshot.expiry_year % 100:02d}"
        return f"{pan} · {expiry}"

    def _cancel_card_reveal(self) -> None:
        action = self._card_reveal_action
        if action is not None:
            action.cancel.set()

    def _card_reveal_is_current(self, action: _CardRevealAction) -> bool:
        return (
            self._card_reveal_action is action
            and not action.cancel.is_set()
            and not self._closed
            and not self._locked
            and action.generation == self._task_generation
            and action.allocation_id == self._card_allocation_id
            and self._client is not None
            and self._client.is_authenticated
        )

    def _wait_for_sensitive_focus(
        self, action: _CardRevealAction, expires_at: str
    ) -> bool:
        if self._sensitive_focus.is_set():
            return self._card_reveal_is_current(action)
        delay_ms = self._card_reveal_cleanup_delay_ms(expires_at)
        if delay_ms is None:
            raise PlatformProtocolError("卡号揭示授权已过期或有效期无效")
        deadline = time.monotonic() + delay_ms / 1000
        while self._card_reveal_is_current(action):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PlatformProtocolError("卡号揭示授权已过期")
            if self._sensitive_focus.wait(min(0.1, remaining)):
                return self._card_reveal_is_current(action)
        return False

    def reveal_card_details(self) -> None:
        if self._locked:
            self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._card_allocation_id is None
        ):
            self._set_status("请先登录并创建已分配卡的任务。", ERROR)
            return
        active_action = self._card_reveal_action
        if active_action is not None:
            if not self._card_reveal_is_current(active_action):
                generation = self._task_generation
                allocation_id = self._card_allocation_id
                self.copy_card_button.configure(state="disabled")
                self._set_status("上一卡号揭示仍在安全收尾，请稍后再试。", WARNING)

                def retry_if_current() -> None:
                    if (
                        generation == self._task_generation
                        and allocation_id == self._card_allocation_id
                    ):
                        self.reveal_card_details()

                self.root.after(250, retry_if_current)
                return
            self._set_status("卡号揭示仍在进行，请完成当前验证后再试。", WARNING)
            return
        allocation_id = self._card_allocation_id
        generation = self._task_generation
        action = _CardRevealAction(allocation_id, generation)
        self._card_reveal_action = action
        confirmed = messagebox.askyesno(
            "重新验证后揭示卡号",
            "即将通过浏览器重新登录并完成 MFA。\n\n"
            "验证通过后只复制卡号和有效期，不包含 CVV；"
            "操作会写入审计，剪贴板将在服务端授权到期、最长 60 秒或窗口失焦时清除。\n\n"
            "是否继续？",
            parent=self.root,
        )
        if not confirmed:
            if self._card_reveal_action is action:
                self._card_reveal_action = None
            self._set_status("已取消卡号揭示。", MUTED)
            return
        if not self._card_reveal_is_current(action):
            if self._card_reveal_action is action:
                self._card_reveal_action = None
            self._set_status("卡号揭示已因任务或会话状态变化而停止。", WARNING)
            return
        self.copy_card_button.configure(state="disabled")
        self._set_status("正在创建卡揭示安全挑战…", ACCENT)

        def worker() -> None:
            succeeded = False
            try:
                if not self._card_reveal_is_current(action):
                    return
                challenge = self._client.create_card_reveal_challenge(allocation_id)
                if not self._card_reveal_is_current(action):
                    return

                def open_authorization_url(url: str) -> None:
                    if not self._card_reveal_is_current(action):
                        raise PlatformDeviceAuthorizationError(
                            "card reveal was cancelled"
                        )
                    if not webbrowser.open(url, new=2):
                        raise PlatformTransportError("无法打开统一身份登录页面")
                    self._events.put(
                        (generation, "card_reveal_authorizing", None)
                    )

                step_up = self._client.reauthenticate_for_card_reveal(
                    open_authorization_url,
                    acr_values=challenge.acr_values,
                    cancelled=lambda: not self._card_reveal_is_current(action),
                )
                if not self._card_reveal_is_current(action):
                    return
                grant = self._client.create_card_reveal_grant(
                    allocation_id,
                    challenge.challenge_id,
                    step_up.access_token,
                )
                if not self._card_reveal_is_current(action):
                    return
                if not self._wait_for_sensitive_focus(action, grant.expires_at):
                    return
                snapshot = self._client.reveal_card_allocation(
                    allocation_id, grant.reveal_grant
                )
                if (
                    not self._card_reveal_is_current(action)
                    or not self._sensitive_focus.is_set()
                ):
                    return
                if snapshot.allocation_id != allocation_id:
                    raise PlatformProtocolError("卡号揭示响应归属不一致")
            except BaseException as error:
                if self._card_reveal_is_current(action):
                    self._events.put((generation, "card_reveal_error", error))
            else:
                succeeded = True
                self._events.put((generation, "card_reveal", snapshot))
            finally:
                self._events.put(
                    (generation, "card_reveal_finished", (action, succeeded))
                )

        thread = threading.Thread(
            target=worker, daemon=False, name="platform-card-reveal"
        )
        self._card_reveal_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._events.put(
                (
                    generation,
                    "card_reveal_error",
                    PlatformTransportError("card reveal worker unavailable"),
                )
            )
            self._events.put(
                (generation, "card_reveal_finished", (action, False))
            )

    def submit_upload(self) -> None:
        if self._locked:
            self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._task_id is None
            or self._card_allocation_id is None
        ):
            self._set_status("请先登录并创建已分配卡的任务。", ERROR)
            return
        if not self._current_task_is_verified():
            self.upload_button.configure(state="disabled")
            self._set_status("请等待当前任务取得验证码后再提交上传。", ERROR)
            return
        action = self._upload_submission_action
        if action is not None:
            if action.pending:
                return
            if not action.ambiguous or action.task_id != self._task_id:
                return
        else:
            business_name = self.business_entry.get().strip()
            if not business_name:
                self._set_status("请输入业务名称后再提交上传。", ERROR)
                self.business_entry.focus_set()
                return
            action = _UploadSubmissionAction(
                self._task_id,
                business_name,
                self._upload_attempt_key(business_name),
            )
            self._upload_submission_action = action
        self._start_upload_submission(action)

    def _start_upload_submission(self, action: _UploadSubmissionAction) -> None:
        if action.pending or self._client is None:
            return
        recovering = action.ambiguous
        action.pending = True
        self.business_entry.configure(state="disabled")
        self.upload_button.configure(
            text="确认中…" if recovering else "提交上传",
            state="disabled",
        )
        self.upload_label.configure(text="状态确认中…" if recovering else "提交中…")
        self._upload_generation += 1
        generation = self._upload_generation
        client = self._client

        def worker() -> None:
            try:
                job = client.create_upload_job(
                    action.task_id,
                    action.business_name,
                    action.idempotency_key,
                )
                if (
                    job.task_id != action.task_id
                    or job.business_name != action.business_name
                ):
                    raise PlatformProtocolError(
                        "上传作业响应与捕获的任务或业务名称不一致"
                    )
            except BaseException as error:
                self._events.put(
                    (generation, "upload_submit_error", (action, error))
                )
                return
            self._events.put((generation, "upload_submitted", (action, job)))

        thread = threading.Thread(
            target=worker, daemon=False, name="platform-upload-create"
        )
        self._upload_submission_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._events.put(
                (
                    generation,
                    "upload_submit_error",
                    (
                        action,
                        PlatformClientError(
                            "upload submission worker unavailable"
                        ),
                    ),
                )
            )

    def _schedule_upload_poll(self, delay_ms: int) -> None:
        generation = self._upload_generation
        job_id = self._upload_job_id
        task_id = self._task_id
        business_name = self._upload_business_name

        def poll_if_current() -> None:
            if (
                self._upload_generation != generation
                or self._upload_job_id != job_id
                or self._task_id != task_id
                or self._upload_business_name != business_name
                or self._locked
                or self._closed
                or self._terminal_task_cleanup_action is not None
            ):
                return
            self._poll_upload()

        self.root.after(delay_ms, poll_if_current)

    def _poll_upload(self) -> None:
        if (
            self._locked
            or self._client is None
            or self._upload_job_id is None
            or self._closed
            or self._terminal_task_cleanup_action is not None
        ):
            return
        self._upload_poll_threads = [
            thread for thread in self._upload_poll_threads if thread.is_alive()
        ]
        if self._upload_poll_threads:
            self._schedule_upload_poll(250)
            return
        job_id = self._upload_job_id
        task_id = self._task_id
        business_name = self._upload_business_name
        generation = self._upload_generation

        def worker() -> None:
            try:
                job = self._client.get_upload_job(job_id)
                if (
                    job.id != job_id
                    or job.task_id != task_id
                    or job.business_name != business_name
                ):
                    raise PlatformProtocolError(
                        "上传作业状态响应与当前任务不一致"
                    )
            except BaseException as error:
                self._events.put((generation, "upload_poll_error", error))
                return
            self._events.put((generation, "upload", job))

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (generation, "upload_poll_finished", thread)
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-upload-poll"
        )
        self._upload_poll_threads.append(thread)
        self._upload_poll_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._upload_poll_threads.remove(thread)
            if self._upload_poll_thread is thread:
                self._upload_poll_thread = None
            self._events.put(
                (
                    generation,
                    "upload_poll_error",
                    PlatformTransportError("upload status worker unavailable"),
                )
            )

    def _begin_terminal_task_cleanup(self, outcome: str) -> None:
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._task_id is None
        ):
            return
        if self._terminal_task_cleanup_action is not None:
            if self._terminal_task_cleanup_in_progress:
                self._set_status(
                    "任务结果已保留，正在关闭任务并释放卡与邮箱资源…",
                    ACCENT,
                )
            else:
                self._set_status(
                    "原因：平台暂未确认任务资源关闭；"
                    "影响：任务、卡和邮箱资源不会标记为已安全释放；"
                    "下一步：检查网络后点击“重试资源关闭”。",
                    ERROR,
                )
            return
        self.stop_polling()
        self._paste_sequence.stop()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._clear_trace_id()
        self._cancel_card_reveal()
        self.copy_button.configure(state="disabled")
        self.copy_card_button.configure(state="disabled")
        self.business_entry.configure(state="disabled")
        self.upload_button.configure(state="disabled")
        task_id = self._task_id
        card_reveal_thread = self._card_reveal_thread
        upload_poll_threads = tuple(getattr(self, "_upload_poll_threads", ()))
        upload_poll_thread = self._upload_poll_thread
        if (
            upload_poll_thread is not None
            and upload_poll_thread not in upload_poll_threads
        ):
            upload_poll_threads += (upload_poll_thread,)
        try:
            transition = self._client.begin_task_transition(task_id)
            cleanup = transition.close(task_id)
            transition.worker_finished()
        except PlatformClientError as error:
            self._set_status(format_operation_error(error), ERROR)
            return
        if cleanup is None:
            self._set_status("平台未能准备任务资源关闭，请重新登录后处理。", ERROR)
            return
        mail_poll_threads = tuple(getattr(self, "_mail_poll_threads", ()))
        mail_poll_thread = getattr(self, "_mail_poll_thread", None)
        if mail_poll_thread is not None and mail_poll_thread not in mail_poll_threads:
            mail_poll_threads += (mail_poll_thread,)
        self._mail_poll_threads = []
        self._mail_poll_thread = None
        self._upload_poll_threads = []
        self._upload_poll_thread = None

        if (
            card_reveal_thread is not None
            or mail_poll_threads
            or upload_poll_threads
        ):
            task_cleanup = cleanup

            def cleanup() -> None:
                if card_reveal_thread is not None and card_reveal_thread.is_alive():
                    card_reveal_thread.join(CARD_REVEAL_SHUTDOWN_WAIT_SECONDS)
                    if card_reveal_thread.is_alive():
                        raise PlatformTimeoutError(
                            "card reveal did not stop before task cleanup"
                        )
                for mail_poll_thread in mail_poll_threads:
                    if mail_poll_thread.is_alive():
                        mail_poll_thread.join()
                for upload_poll_thread in upload_poll_threads:
                    if upload_poll_thread.is_alive():
                        upload_poll_thread.join()
                task_cleanup()

        self._upload_generation += 1
        self._terminal_task_cleanup_generation += 1
        self._terminal_task_cleanup_action = cleanup
        self._terminal_task_cleanup_task_id = task_id
        self._terminal_task_cleanup_outcome = outcome
        self.new_task_button.configure(
            text="任务收尾中…",
            command=self._retry_terminal_task_cleanup,
            state="disabled",
        )
        self._set_status(
            "上传成功，正在关闭任务并释放卡与邮箱资源…"
            if outcome == "completed"
            else "邮箱会话已结束，正在关闭任务并释放卡与邮箱资源…",
            ACCENT,
        )
        self._start_terminal_task_cleanup_attempt()

    def _start_terminal_task_cleanup_attempt(self) -> None:
        cleanup = self._terminal_task_cleanup_action
        task_id = self._terminal_task_cleanup_task_id
        outcome = self._terminal_task_cleanup_outcome
        if (
            cleanup is None
            or task_id is None
            or outcome is None
            or self._terminal_task_cleanup_in_progress
        ):
            return
        generation = self._terminal_task_cleanup_generation

        def worker() -> None:
            try:
                cleanup()
            except PlatformClientError:
                self._events.put(
                    (
                        generation,
                        "terminal_task_cleanup_error",
                        (task_id, outcome),
                    )
                )
            else:
                self._events.put(
                    (
                        generation,
                        "terminal_task_cleanup_succeeded",
                        (task_id, outcome),
                    )
                )

        thread: threading.Thread

        def run_worker() -> None:
            try:
                worker()
            finally:
                self._events.put(
                    (
                        generation,
                        "terminal_task_cleanup_finished",
                        (cleanup, thread),
                    )
                )

        thread = threading.Thread(
            target=run_worker, daemon=False, name="platform-terminal-task-cleanup"
        )
        self._terminal_task_cleanup_in_progress = True
        self._terminal_task_cleanup_thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._events.put(
                (
                    generation,
                    "terminal_task_cleanup_error",
                    (task_id, outcome),
                )
            )
            self._events.put(
                (
                    generation,
                    "terminal_task_cleanup_finished",
                    (cleanup, thread),
                )
            )

    def _retry_terminal_task_cleanup(self) -> None:
        if (
            self._terminal_task_cleanup_action is None
            or self._terminal_task_cleanup_in_progress
        ):
            return
        self.new_task_button.configure(state="disabled")
        self._set_status(
            "正在重试任务、卡和邮箱资源关闭；确认成功前不会创建新任务。",
            ACCENT,
        )
        self._start_terminal_task_cleanup_attempt()

    def _discard_card_after_clipboard_failure(self) -> None:
        self._current_card_clipboard = None
        self._card_clear_generation += 1
        self._paste_sequence.stop()
        if not self._closed:
            self.card_reveal_label.configure(
                text=CARD_DETAILS_PLACEHOLDER, foreground=TEXT
            )
        if (
            not self._locked
            and self._card_allocation_id is not None
            and self._client is not None
            and self._client.is_authenticated
        ):
            self.copy_card_button.configure(state="normal")

    def _write_clipboard(self, text: str) -> bool:
        clipboard_cleared = False
        try:
            self.root.clipboard_clear()
            clipboard_cleared = True
            self.root.clipboard_append(text)
            self.root.update_idletasks()
        except Exception:
            if clipboard_cleared:
                self._clipboard_clear_generation += 1
                self._clipboard_owner = (text, get_clipboard_sequence_number())
                self._clipboard_cleanup_failed = None
                self._clear_owned_clipboard(text)
            self._set_status(CLIPBOARD_WRITE_ERROR_MESSAGE, ERROR)
            return False
        else:
            self._clipboard_clear_generation += 1
            self._clipboard_owner = (text, get_clipboard_sequence_number())
            self._clipboard_cleanup_failed = None
            return True

    def copy_code(self) -> None:
        if self._locked:
            self._set_status("客户端已锁定，请先解锁。", WARNING)
            return
        if self._current_code:
            paste_action = self._paste_sequence.start(
                self._current_code, self._current_card_clipboard
            )
            if paste_action.value is not None and not self._write_clipboard(
                paste_action.value
            ):
                self._paste_sequence.stop()
                return
            self._set_status(paste_action.status, SUCCESS)

    def _begin_session_shutdown(self, intent: str, message: str) -> None:
        if self._pending_update_install is not None:
            self._set_status(
                "在线更新的安全清理尚未完成；当前操作不会绕过该屏障。",
                WARNING,
            )
            return
        if self._shutdown_cleanup_action is not None:
            if self._shutdown_cleanup_in_progress:
                self._set_status(
                    "安全清理仍在进行；确认成功前不会完成退出。",
                    WARNING,
                )
            else:
                self._set_status(
                    "原因：平台任务或登录会话未能确认清理；"
                    "影响：本地敏感值已清除，但退出尚未完成；"
                    "下一步：检查网络后点击“重试安全清理”。",
                    ERROR,
                )
            return

        self._locked = False
        self.stop_polling()
        self._paste_sequence.stop()
        self._close_task_history()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._clear_trace_id()
        self._cancel_card_reveal()
        self._session_generation += 1
        self._session_refreshing = False
        self._update_generation += 1
        self._shutdown_generation += 1
        self._shutdown_intent = intent
        self._shutdown_message = message
        self._shutdown_cleanup_action = self._capture_session_cleanup(self._task_id)
        self._active_task_discovery_action = None
        self._active_task_discovery_thread = None
        self._active_task_discovery_required = False
        self._active_task_recovery_action = None
        self._active_task_recovery = None
        self._mail_session_id = None
        self._mail_session_token = None
        self._card_allocation_id = None
        self._reset_task_verification()
        self._upload_job_id = None
        self._profile_identity = None
        self._session_refresh_thread = None
        self._reset_upload_attempt()
        self._task_generation += 1
        self._upload_generation += 1
        self.task_label.configure(text="安全清理中…")
        self.mail_label.configure(text="本地会话已清除")
        self.session_label.configure(text="正在撤销")
        self.card_label.configure(text="本地详情已清除")
        self.copy_card_button.configure(state="disabled")
        self.close_active_task_button.configure(state="disabled")
        self.upload_label.configure(text="等待安全清理")
        self.profile_label.configure(text="本地登录会话已清除")
        self._set_authenticated(False)
        self.login_button.configure(state="disabled")
        self.check_update_button.configure(state="disabled")
        self._set_workflow_stage("stopped")
        if intent == "close":
            try:
                self._paste_observer.close()
            except Exception:
                pass
        self._set_status(
            "正在关闭平台任务并撤销登录会话；确认成功前不会完成退出。",
            ACCENT,
        )
        self._start_session_shutdown_attempt()

    def _start_session_shutdown_attempt(self) -> None:
        cleanup = self._shutdown_cleanup_action
        intent = self._shutdown_intent
        if cleanup is None or intent is None or self._shutdown_cleanup_in_progress:
            return
        try:
            thread = self._start_captured_cleanup_attempt(
                cleanup,
                generation=self._shutdown_generation,
                success_kind="shutdown_cleanup_succeeded",
                error_kind="shutdown_cleanup_error",
                value=intent,
                name="platform-session-cleanup",
            )
        except RuntimeError:
            self.login_button.configure(
                text="重试安全清理",
                command=self._retry_session_shutdown,
                state="normal",
            )
            self._set_status(
                "原因：平台任务或登录会话清理线程未能启动；"
                "影响：本地敏感值已清除，但退出尚未完成；"
                "下一步：点击“重试安全清理”。",
                ERROR,
            )
            return
        if thread is None:
            return
        self._shutdown_cleanup_in_progress = True
        self._shutdown_cleanup_thread = thread
        self.login_button.configure(state="disabled")

    def _retry_session_shutdown(self) -> None:
        if self._shutdown_cleanup_action is None or self._shutdown_cleanup_in_progress:
            return
        self.login_button.configure(state="disabled")
        self._set_status(
            "正在重试平台任务与登录会话清理；成功前不会完成退出。",
            ACCENT,
        )
        self._start_session_shutdown_attempt()

    def _retry_shutdown_clipboard_cleanup(self) -> None:
        failed = tuple(self._clipboard_cleanup_failed or ())
        if not failed or self._clipboard_cleanup_pending:
            return
        self.login_button.configure(state="disabled")
        self._set_status("正在重试清除客户端写入的临时剪贴板内容…", ACCENT)
        for owner in failed:
            self._clipboard_owner = owner
            self._clear_owned_clipboard(owner[0])

    def _finish_session_shutdown_if_ready(self) -> None:
        intent = self._shutdown_intent
        if (
            intent is None
            or self._shutdown_cleanup_action is not None
            or self._shutdown_cleanup_in_progress
        ):
            return
        if self._clipboard_cleanup_pending:
            self.login_button.configure(state="disabled")
            self._set_status(
                "平台会话已撤销，正在确认清除客户端写入的临时剪贴板内容…",
                ACCENT,
            )
            return
        if self._clipboard_cleanup_failed is not None:
            self.login_button.configure(
                text="重试清除剪贴板",
                command=self._retry_shutdown_clipboard_cleanup,
                state="normal",
            )
            self._set_status(
                "原因：系统剪贴板持续被占用；"
                "影响：客户端不会重新开放登录或退出；"
                "下一步：关闭占用剪贴板的程序后点击“重试清除剪贴板”。",
                ERROR,
            )
            return
        message = self._shutdown_message
        self._shutdown_intent = None
        self._finish_local_logout(message)
        if intent == "close":
            self._destroy_window()

    def _finish_local_logout(self, message: str) -> None:
        self._terminal_task_cleanup_generation += 1
        self._terminal_task_cleanup_action = None
        self._terminal_task_cleanup_thread = None
        self._terminal_task_cleanup_in_progress = False
        self._terminal_task_cleanup_task_id = None
        self._terminal_task_cleanup_outcome = None
        self._active_task_discovery_action = None
        self._active_task_discovery_thread = None
        self._active_task_discovery_required = False
        self._active_task_recovery_action = None
        self._active_task_recovery = None
        self._mail_session_id = None
        self._mail_session_token = None
        self._card_allocation_id = None
        self._reset_task_verification()
        self._upload_job_id = None
        self._profile_identity = None
        self._reset_upload_attempt()
        self.task_label.configure(text="未创建")
        self.mail_label.configure(text="登录后创建任务")
        self.session_label.configure(text="未开始")
        self.card_label.configure(text="未分配")
        self.copy_card_button.configure(state="disabled")
        self.close_active_task_button.configure(state="disabled")
        self.upload_label.configure(text="未创建")
        self.profile_label.configure(text="平台账号尚未登录")
        self._set_authenticated(False)
        self.login_button.configure(
            text="登录平台",
            command=self.open_login_dialog,
            state="normal",
        )
        self.check_update_button.configure(
            text="检查更新",
            command=self.check_for_updates,
            state="normal" if self._update_client is not None else "disabled",
        )
        self._shutdown_message = ""
        self._set_status(message, MUTED)

    def logout(self, *, message: str = "已退出登录。") -> None:
        self._begin_session_shutdown("logout", message)

    def _destroy_window(self) -> None:
        if self._closed:
            return
        if self._clipboard_cleanup_pending:
            self._destroy_pending = True
            return
        if self._clipboard_cleanup_failed is not None:
            self._destroy_pending = True
            self._set_status(
                "原因：临时剪贴板内容尚未确认清除；"
                "影响：窗口保持打开，不会绕过本地清理屏障；"
                "下一步：关闭占用剪贴板的程序后再次点击关闭。",
                ERROR,
            )
            return
        self._destroy_pending = False
        self._clipboard_clear_generation += 1
        self._closed = True
        try:
            self._paste_observer.close()
            if self._login_dialog is not None and self._login_dialog.exists():
                self._login_dialog.close()
            self.root.destroy()
        except Exception:
            self._closed = False
            self._set_status(
                "窗口关闭尚未完成；请再次点击关闭。",
                ERROR,
            )

    def close(self) -> None:
        if self._closed:
            return
        if self._clipboard_cleanup_failed is not None:
            self._set_status("正在重试清除客户端写入的临时剪贴板内容…", ACCENT)
            for owner in tuple(self._clipboard_cleanup_failed):
                self._clipboard_owner = owner
                self._clear_owned_clipboard(owner[0])
            return
        if self._pending_update_install is not None and not self._update_cleanup_completed:
            self._set_status(
                "安全清理尚未成功；请按提示重试，完成前不会退出或安装更新。",
                WARNING,
            )
            return
        if self._update_cleanup_completed:
            self._destroy_window()
            return
        self._begin_session_shutdown("close", "已安全退出平台。")


__all__ = ["PlatformDesktopApp", "format_operation_error"]
