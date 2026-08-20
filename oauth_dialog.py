from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from admin_oauth import (
    AccountNameStore,
    AccountNameStoreError,
    AdminApiClient,
    AdminApiError,
    AdminTokenStore,
    AuthSession,
    AuthorizationService,
    PROXY_ID,
    ProxyIdStore,
    ProxyIdStoreError,
    TokenStoreError,
    TokenValidationError,
    validate_admin_token,
)


class OAuthAuthorizationDialog:
    """A self-contained, non-blocking UI for the third-party OAuth import flow."""

    BG = "#0b1220"
    PANEL = "#111c32"
    FIELD = "#172238"
    TEXT = "#e5e7eb"
    MUTED = "#94a3b8"
    ACCENT = "#38bdf8"
    SUCCESS = "#4ade80"
    WARNING = "#fbbf24"
    ERROR = "#fb7185"

    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_close: Callable[[], None] | None = None,
        token_store: AdminTokenStore | None = None,
        name_store: AccountNameStore | None = None,
        proxy_store: ProxyIdStore | None = None,
    ) -> None:
        self.parent = parent
        self.on_close = on_close
        self.token_store = token_store or AdminTokenStore()
        self.name_store = name_store or AccountNameStore()
        self.proxy_store = proxy_store or ProxyIdStore()
        self.session: AuthSession | None = None
        self.auth_url = ""
        self._busy = False
        self._closed = False
        self._operation = 0
        self._events: queue.Queue[tuple[int, str, Any]] = queue.Queue()

        self.window = tk.Toplevel(parent)
        self.window.title("OpenAI OAuth 授权")
        self.window.geometry("650x610")
        self.window.minsize(650, 610)
        self.window.resizable(False, False)
        self.window.configure(bg=self.BG)
        self.window.transient(parent)
        self.window.attributes("-topmost", True)
        self.window.protocol("WM_DELETE_WINDOW", self.close)

        self._build_ui()
        self._center()
        self._load_saved_name()
        self._load_saved_proxy_id()
        self._load_saved_token()
        self.window.after(100, self._drain_events)

    def exists(self) -> bool:
        return not self._closed and bool(self.window.winfo_exists())

    def focus(self) -> None:
        if self.exists():
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()

    def _build_ui(self) -> None:
        style = ttk.Style(self.window)
        style.configure(
            "OAuth.Action.TButton",
            font=("Microsoft YaHei UI", 9),
            padding=(9, 6),
            background="#1e293b",
            foreground=self.TEXT,
            borderwidth=0,
        )
        style.map(
            "OAuth.Action.TButton",
            background=[("active", "#334155"), ("disabled", "#172033")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "OAuth.Primary.TButton",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=(10, 7),
            background="#0284c7",
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "OAuth.Primary.TButton",
            background=[("active", "#0369a1"), ("disabled", "#1e3a5f")],
            foreground=[("disabled", "#7790aa")],
        )

        panel = tk.Frame(self.window, bg=self.PANEL, padx=18, pady=14)
        panel.pack(fill="both", expand=True, padx=1, pady=1)

        heading = tk.Frame(panel, bg=self.PANEL)
        heading.pack(fill="x")
        tk.Label(
            heading,
            text="OpenAI OAuth 授权与账号创建",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Microsoft YaHei UI", 13, "bold"),
        ).pack(side="left")
        tk.Label(
            heading,
            text="第三方管理端",
            bg=self.PANEL,
            fg=self.WARNING,
            font=("Microsoft YaHei UI", 9),
        ).pack(side="right")

        warning_text = (
            "注意：管理端使用明文 HTTP，Token、授权码和 OAuth 凭据在传输中可能被窃取。"
            "点击生成链接后将直接向第三方管理端发送请求。"
        )
        tk.Label(
            panel,
            text=warning_text,
            bg="#382b16",
            fg="#fde68a",
            anchor="w",
            justify="left",
            wraplength=590,
            padx=10,
            pady=7,
            font=("Microsoft YaHei UI", 8),
        ).pack(fill="x", pady=(10, 10))

        form = tk.Frame(panel, bg=self.PANEL)
        form.pack(fill="x")
        form.grid_columnconfigure(1, weight=1)
        self.name_entry = self._add_entry_row(form, 0, "账号名称", show="")
        self.token_entry = self._add_entry_row(form, 1, "管理 Token", show="●")
        self.proxy_entry = self._add_entry_row(form, 2, "代理 ID", show="")
        self.proxy_entry.bind("<KeyRelease>", self._on_proxy_id_edited)

        token_actions = tk.Frame(form, bg=self.PANEL)
        token_actions.grid(row=3, column=1, sticky="w", pady=(5, 9))
        self.save_token_button = ttk.Button(
            token_actions,
            text="保存 / 更新令牌",
            style="OAuth.Action.TButton",
            command=self.save_token,
        )
        self.save_token_button.pack(side="left")
        self.clear_token_button = ttk.Button(
            token_actions,
            text="清除令牌",
            style="OAuth.Action.TButton",
            command=self.clear_token,
        )
        self.clear_token_button.pack(side="left", padx=(8, 0))

        separator = tk.Frame(panel, bg="#263650", height=1)
        separator.pack(fill="x", pady=(0, 10))

        link_heading = tk.Frame(panel, bg=self.PANEL)
        link_heading.pack(fill="x")
        self.generate_button = ttk.Button(
            link_heading,
            text="生成授权链接",
            style="OAuth.Primary.TButton",
            command=self.generate_link,
        )
        self.generate_button.pack(side="left")
        self.copy_link_button = ttk.Button(
            link_heading,
            text="复制链接",
            style="OAuth.Action.TButton",
            command=self.copy_link,
            state="disabled",
        )
        self.copy_link_button.pack(side="left", padx=(8, 0))

        self.link_var = tk.StringVar(value="尚未生成授权链接")
        link_entry = tk.Entry(
            panel,
            textvariable=self.link_var,
            state="readonly",
            readonlybackground=self.FIELD,
            fg=self.MUTED,
            relief="flat",
            font=("Microsoft YaHei UI", 8),
        )
        link_entry.pack(fill="x", pady=(7, 10), ipady=6)

        tk.Label(
            panel,
            text="授权码或完整回调 URL",
            bg=self.PANEL,
            fg=self.MUTED,
            anchor="w",
            font=("Microsoft YaHei UI", 9),
        ).pack(fill="x")
        self.code_text = tk.Text(
            panel,
            height=4,
            bg=self.FIELD,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            selectbackground="#075985",
            relief="flat",
            wrap="word",
            font=("Consolas", 9),
            padx=8,
            pady=7,
        )
        self.code_text.pack(fill="x", pady=(5, 10))

        final_actions = tk.Frame(panel, bg=self.PANEL)
        final_actions.pack(fill="x")
        self.complete_button = ttk.Button(
            final_actions,
            text="授权并创建账号",
            style="OAuth.Primary.TButton",
            command=self.complete_authorization,
            state="disabled",
        )
        self.complete_button.pack(side="left")
        ttk.Button(
            final_actions,
            text="关闭",
            style="OAuth.Action.TButton",
            command=self.close,
        ).pack(side="right")

        self.status_label = tk.Label(
            panel,
            text="请填写名称并保存管理 Token",
            bg=self.PANEL,
            fg=self.MUTED,
            anchor="w",
            justify="left",
            wraplength=600,
            font=("Microsoft YaHei UI", 9),
        )
        self.status_label.pack(fill="x", pady=(12, 0))

    def _add_entry_row(
        self,
        parent: tk.Frame,
        row: int,
        label: str,
        *,
        show: str,
    ) -> tk.Entry:
        tk.Label(
            parent,
            text=label,
            width=11,
            anchor="w",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Microsoft YaHei UI", 9),
        ).grid(row=row, column=0, sticky="w", pady=4)
        entry = tk.Entry(
            parent,
            show=show,
            bg=self.FIELD,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            selectbackground="#075985",
            relief="flat",
            font=("Microsoft YaHei UI", 9),
        )
        entry.grid(row=row, column=1, sticky="ew", pady=4, ipady=7)
        return entry

    def _center(self) -> None:
        self.window.update_idletasks()
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_w = self.parent.winfo_width()
        screen_w = self.window.winfo_screenwidth()
        screen_h = self.window.winfo_screenheight()
        x = min(max(0, parent_x + parent_w - 650), max(0, screen_w - 650))
        y = min(max(0, parent_y + 20), max(0, screen_h - 650))
        self.window.geometry(f"650x610+{x}+{y}")

    def _load_saved_token(self) -> None:
        try:
            token = self.token_store.load()
        except TokenStoreError as error:
            self._set_status(str(error) + "；请清除后重新保存", self.ERROR)
            return
        if token:
            self.token_entry.insert(0, token)
            try:
                validate_admin_token(token)
            except TokenValidationError as error:
                self._set_status(str(error), self.WARNING)
            else:
                self._set_status("已加载由当前 Windows 用户加密保存的管理令牌", self.SUCCESS)

    def _load_saved_name(self) -> None:
        try:
            name = self.name_store.load()
        except AccountNameStoreError as error:
            self._set_status(str(error), self.WARNING)
            return
        if name:
            self.name_entry.insert(0, name)

    def _load_saved_proxy_id(self) -> None:
        try:
            proxy_id = self.proxy_store.load()
        except ProxyIdStoreError as error:
            proxy_id = PROXY_ID
            self._set_status(str(error) + f"；已恢复默认值 {PROXY_ID}", self.WARNING)
        self.proxy_entry.insert(0, str(proxy_id))

    def _set_status(self, text: str, color: str | None = None) -> None:
        if not self._closed:
            self.status_label.configure(text=text, fg=color or self.MUTED)

    def _current_token(self) -> str:
        return validate_admin_token(self.token_entry.get())

    def save_token(self) -> None:
        try:
            token = self._current_token()
            self.token_store.save(token)
        except (TokenValidationError, TokenStoreError) as error:
            self._set_status(str(error), self.ERROR)
            return
        self._set_status("管理令牌已使用 Windows DPAPI 加密保存", self.SUCCESS)

    def clear_token(self) -> None:
        if self._busy:
            self._set_status("当前操作进行中，完成后再清除令牌", self.WARNING)
            return
        try:
            self.token_store.clear()
        except TokenStoreError as error:
            self._set_status(str(error), self.ERROR)
            return
        self.token_entry.delete(0, "end")
        self._invalidate_session()
        self._set_status("管理令牌及本地 DPAPI 密文已清除", self.SUCCESS)

    def _account_name(self) -> str:
        name = self.name_entry.get().strip()
        if not name:
            raise ValueError("请先填写自定义账号名称")
        return name

    def _proxy_id(self) -> int:
        return self.proxy_store.save(self.proxy_entry.get())

    def _on_proxy_id_edited(self, event: tk.Event | None = None) -> None:
        del event
        session = self.session
        if session is None or self._busy:
            return
        try:
            current_proxy_id = int(self.proxy_entry.get().strip())
        except ValueError:
            current_proxy_id = None
        if current_proxy_id != session.proxy_id:
            self._invalidate_session()
            self._set_status(
                "代理 ID 已更改，旧授权链接已作废；请重新生成链接",
                self.WARNING,
            )

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        normal = "disabled" if busy else "normal"
        self.generate_button.configure(state=normal)
        self.save_token_button.configure(state=normal)
        self.clear_token_button.configure(state=normal)
        self.name_entry.configure(state=normal)
        self.token_entry.configure(state=normal)
        self.proxy_entry.configure(state=normal)
        self.code_text.configure(state=normal)
        if busy or self.session is None:
            self.complete_button.configure(state="disabled")
            self.copy_link_button.configure(state="disabled")
        else:
            self.complete_button.configure(state="normal")
            self.copy_link_button.configure(state="normal")

    def _invalidate_session(self) -> None:
        self.session = None
        self.auth_url = ""
        self.link_var.set("尚未生成授权链接")
        self.code_text.delete("1.0", "end")
        self.complete_button.configure(state="disabled")
        self.copy_link_button.configure(state="disabled")
        self.proxy_entry.configure(state="normal")

    def generate_link(self) -> None:
        if self._busy:
            return
        try:
            name = self._account_name()
            token = self._current_token()
            self.name_store.save(name)
            proxy_id = self._proxy_id()
        except (
            ValueError,
            TokenValidationError,
            AccountNameStoreError,
            ProxyIdStoreError,
        ) as error:
            self._set_status(str(error), self.ERROR)
            return

        self._invalidate_session()
        self._operation += 1
        operation = self._operation
        self._set_busy(True)
        self._set_status("正在检查并发额度并生成授权链接…", self.ACCENT)

        def work() -> None:
            try:
                session = AuthorizationService(AdminApiClient(token)).begin(proxy_id)
            except (AdminApiError, TokenValidationError) as error:
                self._events.put((operation, "begin_error", str(error)))
            except Exception:
                self._events.put((operation, "begin_error", "生成授权链接时发生未知错误"))
            else:
                self._events.put((operation, "begin_success", session))

        threading.Thread(
            target=work,
            daemon=True,
            name=f"oauth-begin-{operation}",
        ).start()

    def complete_authorization(self) -> None:
        if self._busy:
            return
        session = self.session
        if session is None:
            self._set_status("授权会话缺失，请重新生成链接", self.ERROR)
            return
        try:
            name = self._account_name()
            token = self._current_token()
            self.name_store.save(name)
        except (ValueError, TokenValidationError, AccountNameStoreError) as error:
            self._set_status(str(error), self.ERROR)
            return
        code_input = self.code_text.get("1.0", "end-1c").strip()
        if not code_input:
            self._set_status("请输入授权码或完整回调 URL", self.ERROR)
            return

        self._operation += 1
        operation = self._operation
        self._set_busy(True)
        self._set_status("正在兑换授权码并创建账号，请勿重复提交…", self.ACCENT)

        def work() -> None:
            try:
                result = AuthorizationService(AdminApiClient(token)).complete(
                    session,
                    code_input,
                    name,
                )
            except AdminApiError as error:
                self._events.put(
                    (
                        operation,
                        "complete_error",
                        (str(error), error.ambiguous),
                    )
                )
            except (TokenValidationError, ValueError) as error:
                self._events.put((operation, "complete_error", (str(error), False)))
            except Exception:
                self._events.put(
                    (operation, "complete_error", ("授权创建时发生未知错误", False))
                )
            else:
                self._events.put((operation, "complete_success", (name, result)))

        threading.Thread(
            target=work,
            daemon=True,
            name=f"oauth-complete-{operation}",
        ).start()

    def _drain_events(self) -> None:
        if self._closed:
            return
        try:
            while True:
                operation, kind, value = self._events.get_nowait()
                if operation == self._operation:
                    self._handle_event(kind, value)
        except queue.Empty:
            pass
        self.window.after(100, self._drain_events)

    def _handle_event(self, kind: str, value: Any) -> None:
        self._set_busy(False)
        if kind == "begin_success":
            session = value
            self.session = session
            self.auth_url = session.auth_url
            self.link_var.set(session.auth_url)
            self._set_busy(False)
            self._set_status("授权链接已生成，请复制后手动打开", self.SUCCESS)
        elif kind == "begin_error":
            self._set_status(str(value), self.ERROR)
        elif kind == "complete_error":
            message, ambiguous = value
            if ambiguous:
                self._set_status(
                    "创建请求超时或连接中断，结果未知。请先到管理端确认是否已创建，"
                    "不要立即重复提交。",
                    self.WARNING,
                )
            else:
                self._set_status(str(message), self.ERROR)
        elif kind == "complete_success":
            requested_name, result = value
            account = result.get("data") if isinstance(result.get("data"), dict) else result
            account_id = account.get("id", "未知") if isinstance(account, dict) else "未知"
            email = account.get("email", "") if isinstance(account, dict) else ""
            if not email and isinstance(account, dict):
                extra = account.get("extra")
                if isinstance(extra, dict):
                    email = extra.get("email", "")
            self._invalidate_session()
            details = f"账号创建成功：{requested_name}；邮箱：{email or '未返回'}；ID：{account_id}"
            self._set_status(details, self.SUCCESS)

    def _copy(self, value: str, success_text: str) -> None:
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(value)
            self.window.update_idletasks()
        except tk.TclError:
            self._set_status("写入剪贴板失败", self.ERROR)
        else:
            self._set_status(success_text, self.SUCCESS)

    def copy_link(self) -> None:
        if self.auth_url:
            self._copy(self.auth_url, "授权链接已复制")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._operation += 1
        self.session = None
        self.auth_url = ""
        try:
            self.code_text.delete("1.0", "end")
            self.token_entry.delete(0, "end")
        except tk.TclError:
            pass
        self.window.destroy()
        if self.on_close is not None:
            self.on_close()
