"""Platform-owned desktop workflow for the default EXE entry point.

The legacy Tk window is isolated in ``legacy_app.py`` and is not reachable from
the packaged entry point.  This window never reads account credentials from the
clipboard and never calls the source-mail service.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Any
from uuid import uuid4

from app_version import APP_VERSION
from platform_client import (
    CardAllocationSnapshot,
    CardRevealSnapshot,
    MailCodeSnapshot,
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
    TaskSnapshot,
    UploadJobSnapshot,
)
from platform_login_dialog import PlatformLoginDialog, format_login_error, safe_user_info
from update_client import (
    UpdateClient,
    UpdateError,
    UpdateManifest,
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

    if isinstance(error, PlatformAuthenticationError):
        return "登录已失效或设备已撤销。请重新登录平台。"
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
    if isinstance(error, PlatformApiError):
        code = error.code if isinstance(error.code, str) else "api_error"
        return f"平台操作失败（错误码：{code}）。请按当前状态修正后重试。"
    return "平台操作失败。请稍后重试；持续失败请联系管理员。"


class PlatformDesktopApp:
    """Small, login-first Tk workflow backed entirely by platform APIs."""

    def __init__(self, root: tk.Tk, *, client: PlatformClient | None = None) -> None:
        self.root = root
        self.root.title(f"邮箱验证码助手 v{APP_VERSION} · 平台")
        self.root.geometry("640x570")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.root.attributes("-topmost", True)
        try:
            self.root.attributes("-toolwindow", True)
        except tk.TclError:
            pass

        self._closed = False
        self._client: PlatformClient | None = client
        self._login_dialog: PlatformLoginDialog | None = None
        self._task_id: str | None = None
        self._mail_session_id: str | None = None
        self._current_code: str | None = None
        self._current_card_clipboard: str | None = None
        self._card_allocation_id: str | None = None
        self._upload_job_id: str | None = None
        self._upload_idempotency_key: str | None = None
        self._upload_business_name: str | None = None
        self._poll_generation = 0
        self._task_generation = 0
        self._upload_generation = 0
        self._poll_cancel: threading.Event | None = None
        self._code_clear_generation = 0
        self._card_clear_generation = 0
        self._session_generation = 0
        self._session_deadline = 0.0
        self._session_refreshing = False
        self._update_generation = 0
        self._update_client: UpdateClient | None = None
        self._profile_summary = ""
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
        self.root.after(100, self._drain_events)
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
        self.session_label = self._add_value(info, 4, "邮箱会话", "未开始")
        self.upload_label = self._add_value(info, 5, "上传作业", "未创建")

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
        self.auth_label.configure(
            text="已登录" if authenticated else "未登录",
            fg=SUCCESS if authenticated else WARNING,
        )
        self.new_task_button.configure(state="normal" if authenticated else "disabled")
        self.history_button.configure(state="normal" if authenticated else "disabled")
        self.logout_button.configure(state="normal" if authenticated else "disabled")
        self.login_button.configure(state="disabled" if authenticated else "normal")
        if not authenticated:
            self.upload_button.configure(state="disabled")
            self.copy_card_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
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

    def _set_status(self, text: str, color: str = MUTED) -> None:
        if not self._closed:
            self.status_label.configure(text=text, fg=color)

    @staticmethod
    def _format_task_time(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone().strftime("%m-%d %H:%M:%S")
        except ValueError:
            return "时间无效"

    def show_task_history(self) -> None:
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
            self._client is None
            or not self._client.is_authenticated
            or self._history_window is None
            or not self._history_window.winfo_exists()
        ):
            return
        generation = self._session_generation
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

        threading.Thread(
            target=worker, daemon=True, name="platform-task-history"
        ).start()

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
        self._write_clipboard(trace_id)
        if self._history_status is not None:
            self._history_status.configure(text="trace_id 已复制。", fg=SUCCESS)

    def _close_task_history(self) -> None:
        window = self._history_window
        self._history_window = None
        self._history_tree = None
        self._history_status = None
        self._history_refresh_button = None
        if window is not None and window.winfo_exists():
            window.destroy()

    def open_login_dialog(self) -> None:
        if self._client is None:
            self._set_status("平台地址未配置，无法登录。请设置 PLATFORM_BASE_URL 后重启。", ERROR)
            return
        if self._login_dialog is not None and self._login_dialog.exists():
            self._login_dialog.focus()
            return

        def closed() -> None:
            self._login_dialog = None

        self._login_dialog = PlatformLoginDialog(
            self.root,
            self._client,
            on_success=self._on_login_success,
            on_close=closed,
        )
        self._login_dialog.show(modal=True)

    def _on_login_success(self, profile: dict[str, Any], expires_in: int) -> None:
        email = profile.get("email")
        device_id = profile.get("device_id")
        summary = str(email) if isinstance(email, str) else "平台账号"
        if isinstance(device_id, str) and device_id:
            summary += f" · 设备 {device_id[:8]}"
        self._profile_summary = summary
        self._session_generation += 1
        self._session_refreshing = False
        self._session_deadline = time.monotonic() + max(1, expires_in)
        self._update_session_countdown(self._session_generation)
        self._set_authenticated(True)
        self._set_workflow_stage("authenticated")
        self._set_status(f"登录成功，会话剩余约 {expires_in // 60} 分钟；可创建邮箱任务。", SUCCESS)
        if self._login_dialog is not None and self._login_dialog.exists():
            self._login_dialog.close()
        self._login_dialog = None

    def _update_session_countdown(self, generation: int) -> None:
        if self._closed or generation != self._session_generation:
            return
        remaining = max(0, int(self._session_deadline - time.monotonic()))
        minutes, seconds = divmod(remaining, 60)
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
        if self._closed or self._client is None:
            return
        try:
            has_saved_session = self._client.has_saved_refresh_session()
        except PlatformClientError as error:
            self._set_status(format_operation_error(error), ERROR)
            return
        if not has_saved_session:
            return
        self._session_generation += 1
        generation = self._session_generation
        self.login_button.configure(state="disabled")
        self._set_status("正在安全恢复平台会话…", MUTED)

        def worker() -> None:
            try:
                expires_in = self._client.refresh_oidc_session()
                profile = safe_user_info(self._client.me())
            except BaseException as error:
                self._events.put((generation, "session_restore_error", error))
                return
            self._events.put(
                (generation, "session_restored", (profile, expires_in))
            )

        threading.Thread(
            target=worker, daemon=True, name="platform-session-restore"
        ).start()

    def _refresh_session_async(self, generation: int) -> None:
        if self._client is None or self._session_refreshing:
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

        threading.Thread(
            target=worker, daemon=True, name="platform-session-refresh"
        ).start()

    def _on_focus_out(self, _event: tk.Event[Any]) -> None:
        self.root.after(100, self._clear_code_if_unfocused)

    def _clear_code_if_unfocused(self) -> None:
        if self._closed or self.root.focus_displayof() is not None:
            return
        self._clear_sensitive_code()
        self._clear_card_details()

    def _clear_sensitive_code(self) -> None:
        code = self._current_code
        self._current_code = None
        self._code_clear_generation += 1
        if not self._closed:
            self.code_label.configure(text="------", foreground=TEXT)
            self.copy_button.configure(state="disabled")
        if not code:
            return
        try:
            if self.root.clipboard_get() == code:
                self.root.clipboard_clear()
                self.root.update_idletasks()
        except tk.TclError:
            pass

    def _schedule_code_cleanup(self) -> None:
        self._code_clear_generation += 1
        generation = self._code_clear_generation

        def clear_if_current() -> None:
            if generation == self._code_clear_generation:
                self._clear_sensitive_code()

        self.root.after(CODE_VISIBLE_SECONDS * 1000, clear_if_current)

    def _clear_card_details(self) -> None:
        text = self._current_card_clipboard
        self._current_card_clipboard = None
        self._card_clear_generation += 1
        if not text:
            return
        try:
            if self.root.clipboard_get() == text:
                self.root.clipboard_clear()
                self.root.update_idletasks()
        except tk.TclError:
            pass

    def _schedule_card_cleanup(self) -> None:
        self._card_clear_generation += 1
        generation = self._card_clear_generation

        def clear_if_current() -> None:
            if generation == self._card_clear_generation:
                self._clear_card_details()

        self.root.after(CARD_DETAILS_VISIBLE_SECONDS * 1000, clear_if_current)

    def create_mail_task(self) -> None:
        if self._client is None or not self._client.is_authenticated:
            self._set_authenticated(False)
            self._set_status("登录已失效，请重新登录平台。", ERROR)
            return
        self.stop_polling()
        previous_task_id = self._task_id
        self._task_id = None
        self._mail_session_id = None
        self._clear_sensitive_code()
        self._clear_card_details()
        self._card_allocation_id = None
        self._upload_job_id = None
        self._reset_upload_attempt()
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
            try:
                if previous_task_id:
                    self._client.close_task(previous_task_id)
                task = self._client.create_task("mail_code", str(uuid4()))
                task_id = task.get("id")
                task_trace_id = task.get("trace_id")
                if (
                    not isinstance(task_id, str)
                    or not task_id
                    or not isinstance(task_trace_id, str)
                    or not task_trace_id
                ):
                    raise PlatformProtocolError("平台任务响应缺少任务或追踪 ID")
                session = self._client.create_mail_session(task_id)
                allocation = self._client.allocate_card(task_id)
            except BaseException as error:
                if task_id:
                    try:
                        self._client.close_task(task_id)
                    except PlatformClientError:
                        pass
                self._events.put((generation, "error", error))
                return
            self._events.put(
                (generation, "session", (task_id, task_trace_id, session, allocation))
            )

        threading.Thread(target=worker, daemon=True, name="platform-task-create").start()

    def _start_polling(self) -> None:
        if self._mail_session_id is None or self._client is None:
            return
        self.stop_polling()
        self._poll_generation += 1
        generation = self._poll_generation
        cancel = threading.Event()
        self._poll_cancel = cancel

        def worker() -> None:
            try:
                snapshot: MailCodeSnapshot = self._client.get_mail_code(self._mail_session_id)
            except BaseException as error:
                self._events.put((generation, "poll_error", error))
                return
            self._events.put((generation, "code", snapshot))

        threading.Thread(target=worker, daemon=True, name="platform-code-poll").start()

        def schedule_next() -> None:
            if not self._closed and self._poll_generation == generation and not cancel.is_set():
                self.root.after(int(POLL_SECONDS * 1000), self._start_polling)

        self._schedule_next_poll = schedule_next

    def stop_polling(self) -> None:
        self._poll_generation += 1
        if self._poll_cancel is not None:
            self._poll_cancel.set()
        self._poll_cancel = None

    def _drain_events(self) -> None:
        if self._closed:
            return
        while True:
            try:
                generation, kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if kind.startswith("update_") and generation != self._update_generation:
                continue
            if kind in {"error", "session"} and generation != self._task_generation:
                continue
            if kind in {"poll_error", "code"} and generation != self._poll_generation:
                continue
            if kind in {"upload", "upload_submit_error", "upload_poll_error"} and generation != self._upload_generation:
                continue
            if kind in {
                "card_reveal",
                "card_reveal_authorizing",
                "card_reveal_error",
            } and generation != self._task_generation:
                continue
            if kind in {
                "session_restored",
                "session_restore_error",
                "session_refreshed",
                "session_refresh_error",
                "task_history",
                "task_history_error",
            } and generation != self._session_generation:
                continue
            if kind == "update_current":
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
                try:
                    launch_update_helper(package, manifest.sha256)
                except UpdateError:
                    self.check_update_button.configure(state="normal")
                    self._set_status("更新包已校验，但无法启动安全替换程序。", ERROR)
                else:
                    self._set_status("更新已校验，正在退出并替换程序…", SUCCESS)
                    self.root.after(200, self.close)
            elif kind == "update_download_error":
                self.check_update_button.configure(state="normal")
                self._set_status("更新下载或完整性校验失败，未修改当前程序。", ERROR)
            elif kind == "error":
                self.new_task_button.configure(state="normal")
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                else:
                    self._set_workflow_stage("authenticated")
                self._set_status(format_operation_error(value), ERROR)
            elif kind == "session":
                task_id, task_trace_id, session, allocation = value
                self._task_id = task_id
                self._mail_session_id = session.id
                self._card_allocation_id = allocation.id
                self.task_label.configure(
                    text=f"{task_id[:8]} · trace {task_trace_id[:8]}"
                )
                self.mail_label.configure(text=session.email_masked)
                self.card_label.configure(text=allocation.card_masked)
                self.session_label.configure(text=session.status)
                self.copy_card_button.configure(state="normal")
                self.upload_button.configure(state="normal")
                self.new_task_button.configure(state="normal")
                self._set_workflow_stage("waiting")
                self._set_status("邮箱已分配，正在等待新验证码…", ACCENT)
                self._start_polling()
            elif kind == "poll_error":
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                self._set_status(format_operation_error(value), ERROR)
                self._schedule_next_poll = lambda: None
            elif kind == "code":
                snapshot: MailCodeSnapshot = value
                self.session_label.configure(text=snapshot.status)
                if snapshot.code:
                    self._current_code = snapshot.code
                    self.code_label.configure(text=snapshot.code, foreground=ACCENT)
                    self.copy_button.configure(state="normal")
                    self._write_clipboard(snapshot.code)
                    self._schedule_code_cleanup()
                    self._set_status("已收到验证码并复制到剪贴板。", SUCCESS)
                    self._set_workflow_stage("code_ready")
                    self.stop_polling()
                elif snapshot.status in {"expired", "revoked"}:
                    self._set_status("邮箱会话已结束，请新建任务。", WARNING)
                    self.stop_polling()
                    self.copy_card_button.configure(state="disabled")
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("stopped")
                    self._close_active_task_async()
                elif snapshot.status == "consumed":
                    self._set_status("验证码已消费。", MUTED)
                    self.stop_polling()
                else:
                    self._set_status("等待新验证码…", MUTED)
                    if hasattr(self, "_schedule_next_poll"):
                        self._schedule_next_poll()
            elif kind == "upload":
                snapshot: UploadJobSnapshot = value
                self._upload_job_id = snapshot.id
                self.upload_label.configure(text=snapshot.status)
                if snapshot.status in {"queued", "running"}:
                    self._set_status("上传作业已进入服务端队列。", ACCENT)
                    self._set_workflow_stage("uploading")
                    self.root.after(2000, self._poll_upload)
                elif snapshot.status == "succeeded":
                    self._set_status("上传完成。", SUCCESS)
                    self.upload_button.configure(state="disabled")
                    self.copy_card_button.configure(state="disabled")
                    self._set_workflow_stage("completed")
                    self._close_active_task_async()
                elif snapshot.status == "unknown":
                    self._set_status("上传结果未知，请管理员核对后再处理，系统不会自动重试。", WARNING)
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("review")
                else:
                    self._set_status(f"上传失败：{snapshot.error_code or 'unknown_error'}。", ERROR)
                    self._reset_upload_attempt()
                    self.upload_button.configure(state="normal")
                    self._set_workflow_stage("upload_failed")
            elif kind == "card_reveal_authorizing":
                self._set_status(
                    "请在浏览器中重新登录并完成 MFA；完成后将自动返回。", ACCENT
                )
            elif kind == "card_reveal":
                details = self._format_card_details(value)
                self._current_card_clipboard = details
                self._write_clipboard(details)
                self._schedule_card_cleanup()
                self.copy_card_button.configure(state="disabled")
                self._set_status("卡详情已复制到剪贴板；请尽快粘贴，60 秒后自动清理。", SUCCESS)
            elif kind == "card_reveal_error":
                if self._card_allocation_id is not None and self._client is not None and self._client.is_authenticated:
                    self.copy_card_button.configure(state="normal")
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                self._set_status(format_operation_error(value), ERROR)
            elif kind == "upload_submit_error":
                self.upload_button.configure(state="normal")
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                self._set_status(format_operation_error(value), ERROR)
            elif kind == "upload_poll_error":
                if isinstance(value, PlatformAuthenticationError):
                    if self._client is not None:
                        self._client.clear_access_token()
                    self._set_authenticated(False)
                    self._set_status(format_operation_error(value), ERROR)
                else:
                    self.upload_button.configure(state="disabled")
                    self._set_workflow_stage("uploading")
                    self._set_status(
                        "暂时无法获取上传状态；将继续查询，请勿重复提交。", WARNING
                    )
                    self.root.after(3000, self._poll_upload)
            elif kind == "session_restored":
                profile, expires_in = value
                self._on_login_success(profile, expires_in)
                self._set_status("已安全恢复平台会话。", SUCCESS)
            elif kind == "session_restore_error":
                self.login_button.configure(state="normal")
                if self._client is not None:
                    self._client.clear_access_token()
                self._set_authenticated(False)
                if not isinstance(value, PlatformAuthenticationRequiredError):
                    self._set_status(format_operation_error(value), ERROR)
            elif kind == "session_refreshed":
                self._session_refreshing = False
                self._session_deadline = time.monotonic() + max(1, int(value))
                self._set_status("安全会话已刷新。", SUCCESS)
            elif kind == "session_refresh_error":
                self._session_refreshing = False
                self.logout(message="安全会话刷新失败，已停止任务并清除临时数据。")
            elif kind == "task_history":
                self._render_task_history(value)
            elif kind == "task_history_error":
                if self._history_refresh_button is not None:
                    self._history_refresh_button.configure(state="normal")
                if self._history_status is not None:
                    self._history_status.configure(
                        text=format_operation_error(value), fg=ERROR
                    )
        self.root.after(100, self._drain_events)

    def check_for_updates(self, *, silent: bool = False) -> None:
        """Check the pinned official GitHub Release manifest in the background."""

        if self._update_client is None:
            if not silent:
                self._set_status("在线更新配置无效，请联系管理员。", ERROR)
            return
        self._update_generation += 1
        generation = self._update_generation
        self.check_update_button.configure(state="disabled")
        if not silent:
            self._set_status("正在检查新版本…", ACCENT)

        def worker() -> None:
            try:
                manifest = self._update_client.check()
            except UpdateError:
                self._events.put((generation, "update_error", silent))
            else:
                if manifest is None:
                    self._events.put((generation, "update_current", silent))
                else:
                    self._events.put(
                        (generation, "update_available", (manifest, silent))
                    )

        threading.Thread(
            target=worker, daemon=True, name="platform-update-check"
        ).start()

    def _download_update(self, manifest: UpdateManifest) -> None:
        if self._update_client is None:
            return
        generation = self._update_generation
        self.check_update_button.configure(state="disabled")
        self._set_status(f"正在下载并校验 v{manifest.version}…", ACCENT)

        def worker() -> None:
            try:
                package = self._update_client.download(manifest)
            except UpdateError:
                self._events.put((generation, "update_download_error", None))
            else:
                self._events.put(
                    (generation, "update_downloaded", (manifest, package))
                )

        threading.Thread(
            target=worker, daemon=True, name="platform-update-download"
        ).start()

    @staticmethod
    def _format_card_details(snapshot: CardRevealSnapshot) -> str:
        expiry = ""
        if snapshot.expiry_month is not None and snapshot.expiry_year is not None:
            expiry = f"{snapshot.expiry_month:02d}/{snapshot.expiry_year % 100:02d}"
        return "\t".join((snapshot.pan, expiry)) if expiry else snapshot.pan

    def reveal_card_details(self) -> None:
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._card_allocation_id is None
        ):
            self._set_status("请先登录并创建已分配卡的任务。", ERROR)
            return
        confirmed = messagebox.askyesno(
            "重新验证后揭示卡号",
            "即将通过浏览器重新登录并完成 MFA。\n\n"
            "验证通过后只复制卡号和有效期，不包含 CVV；"
            "操作会写入审计，剪贴板将在 60 秒或窗口失焦时清除。\n\n"
            "是否继续？",
            parent=self.root,
        )
        if not confirmed:
            self._set_status("已取消卡号揭示。", MUTED)
            return
        self.copy_card_button.configure(state="disabled")
        self._set_status("正在创建卡揭示安全挑战…", ACCENT)
        allocation_id = self._card_allocation_id
        generation = self._task_generation

        def worker() -> None:
            try:
                challenge = self._client.create_card_reveal_challenge(allocation_id)

                def open_authorization_url(url: str) -> None:
                    if not webbrowser.open(url, new=2):
                        raise PlatformTransportError("无法打开统一身份登录页面")
                    self._events.put(
                        (generation, "card_reveal_authorizing", None)
                    )

                step_up = self._client.reauthenticate_for_card_reveal(
                    open_authorization_url,
                    acr_values=challenge.acr_values,
                    cancelled=lambda: (
                        self._closed or generation != self._task_generation
                    ),
                )
                grant = self._client.create_card_reveal_grant(
                    allocation_id,
                    challenge.challenge_id,
                    step_up.access_token,
                )
                snapshot = self._client.reveal_card_allocation(
                    allocation_id, grant.reveal_grant
                )
            except BaseException as error:
                self._events.put((generation, "card_reveal_error", error))
                return
            self._events.put((generation, "card_reveal", snapshot))

        threading.Thread(target=worker, daemon=True, name="platform-card-reveal").start()

    def submit_upload(self) -> None:
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._task_id is None
            or self._card_allocation_id is None
        ):
            self._set_status("请先登录并创建已分配卡的任务。", ERROR)
            return
        business_name = self.business_entry.get().strip()
        if not business_name:
            self._set_status("请输入业务名称后再提交上传。", ERROR)
            self.business_entry.focus_set()
            return
        self.upload_button.configure(state="disabled")
        self.upload_label.configure(text="提交中…")
        task_id = self._task_id
        idempotency_key = self._upload_attempt_key(business_name)
        self._upload_generation += 1
        generation = self._upload_generation

        def worker() -> None:
            try:
                job = self._client.create_upload_job(
                    task_id, business_name, idempotency_key
                )
            except BaseException as error:
                self._events.put((generation, "upload_submit_error", error))
                return
            self._events.put((generation, "upload", job))

        threading.Thread(target=worker, daemon=True, name="platform-upload-create").start()

    def _poll_upload(self) -> None:
        if self._client is None or self._upload_job_id is None or self._closed:
            return
        job_id = self._upload_job_id
        generation = self._upload_generation

        def worker() -> None:
            try:
                job = self._client.get_upload_job(job_id)
            except BaseException as error:
                self._events.put((generation, "upload_poll_error", error))
                return
            self._events.put((generation, "upload", job))

        threading.Thread(target=worker, daemon=True, name="platform-upload-poll").start()

    def _close_active_task_async(self) -> None:
        if (
            self._client is None
            or not self._client.is_authenticated
            or self._task_id is None
        ):
            return
        client = self._client
        task_id = self._task_id

        def worker() -> None:
            try:
                client.close_task(task_id)
            except PlatformClientError:
                return

        threading.Thread(target=worker, daemon=True, name="platform-task-close").start()

    def _write_clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
        except tk.TclError:
            self._set_status("写入剪贴板失败，请重新操作。", ERROR)

    def copy_code(self) -> None:
        if self._current_code:
            self._write_clipboard(self._current_code)
            self._set_status("验证码已复制。", SUCCESS)

    def logout(self, *, message: str = "已退出登录。") -> None:
        self.stop_polling()
        self._close_task_history()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._session_generation += 1
        self._session_refreshing = False
        if self._client is not None:
            cleanup = self._client.prepare_logout_cleanup(self._task_id)

            def worker() -> None:
                try:
                    cleanup()
                except PlatformClientError:
                    return

            threading.Thread(
                target=worker, daemon=True, name="platform-logout-cleanup"
            ).start()
        self._task_id = None
        self._mail_session_id = None
        self._card_allocation_id = None
        self._upload_job_id = None
        self._reset_upload_attempt()
        self._task_generation += 1
        self._upload_generation += 1
        self.task_label.configure(text="未创建")
        self.mail_label.configure(text="登录后创建任务")
        self.session_label.configure(text="未开始")
        self.card_label.configure(text="未分配")
        self.copy_card_button.configure(state="disabled")
        self.upload_label.configure(text="未创建")
        self.profile_label.configure(text="平台账号尚未登录")
        self._set_authenticated(False)
        self._set_status(message, MUTED)

    def close(self) -> None:
        if self._closed:
            return
        self.stop_polling()
        self._close_task_history()
        self._clear_sensitive_code()
        self._clear_card_details()
        self._session_generation += 1
        if self._client is not None:
            cleanup = self._client.prepare_logout_cleanup(self._task_id)

            def worker() -> None:
                try:
                    cleanup()
                except PlatformClientError:
                    return

            threading.Thread(
                target=worker, daemon=True, name="platform-close-cleanup"
            ).start()
        self._closed = True
        if self._login_dialog is not None and self._login_dialog.exists():
            self._login_dialog.close()
        self.root.destroy()


__all__ = ["PlatformDesktopApp", "format_operation_error"]
