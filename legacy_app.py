from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import queue
import re
import secrets
import ssl
import threading
import tkinter as tk
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum, auto
from html.parser import HTMLParser
from tkinter import ttk
from typing import Any, Callable

from oauth_dialog import OAuthAuthorizationDialog


API_ORIGIN = "https://email111.6ltd.ltd"
API_URL = f"{API_ORIGIN}/api/v1/stream"
REQUEST_TIMEOUT_SECONDS = 15
NORMAL_RETRY_SECONDS = 5
NETWORK_RETRY_SECONDS = (5, 10, 20, 30)
PASTE_ADVANCE_DELAY_MS = 250

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
CARD_PATTERN = re.compile(r"^\d{12,19}$")
CODE_PATTERN = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")
KEYWORD_PATTERN = re.compile(
    r"验证码|校验码|动态码|一次性(?:密码|代码)|"
    r"\botp\b|\bverification\s+code\b|\bsecurity\s+code\b|"
    r"\bpasscode\b|\bcode\b",
    re.IGNORECASE,
)

FIRST_NAMES = (
    "Mary",
    "Jennifer",
    "Linda",
    "Patricia",
    "Elizabeth",
    "Susan",
    "Jessica",
    "Sarah",
    "Karen",
    "Nancy",
    "Michael",
    "James",
    "Robert",
    "John",
    "David",
    "Daniel",
    "Joseph",
    "Thomas",
    "Christopher",
    "Matthew",
)
LAST_NAMES = (
    "Martinez",
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Wilson",
    "Anderson",
    "Taylor",
    "Thomas",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Thompson",
    "White",
)
STREET_NAMES = (
    "Elm",
    "Maple",
    "Oak",
    "Pine",
    "Cedar",
    "Willow",
    "Lake",
    "Hill",
    "Park",
    "Sunset",
    "Ridge",
    "River",
    "Highland",
    "Meadow",
    "Forest",
    "Cherry",
)
STREET_TYPES = ("Street", "Avenue", "Road", "Lane", "Drive", "Court", "Way")
SALES_TAX_FREE_LOCATIONS = (
    ("Salem", "Oregon", "97301"),
    ("Portland", "Oregon", "97205"),
    ("Eugene", "Oregon", "97401"),
    ("Bend", "Oregon", "97701"),
    ("Wilmington", "Delaware", "19801"),
    ("Dover", "Delaware", "19901"),
    ("Newark", "Delaware", "19711"),
    ("Billings", "Montana", "59101"),
    ("Missoula", "Montana", "59801"),
    ("Bozeman", "Montana", "59715"),
    ("Helena", "Montana", "59601"),
    ("Concord", "New Hampshire", "03301"),
    ("Manchester", "New Hampshire", "03101"),
    ("Nashua", "New Hampshire", "03060"),
    ("Portsmouth", "New Hampshire", "03801"),
)


def parse_credentials(text: str) -> tuple[str, str] | None:
    """Parse a complete `email----password` or `email:password` value."""
    if not isinstance(text, str):
        return None

    if "----" in text:
        email, password = (part.strip() for part in text.split("----", 1))
    elif ":" in text:
        email, password = (part.strip() for part in text.split(":", 1))
    else:
        return None
    if not email or not password:
        return None
    if "\n" in email or "\r" in email or "\n" in password or "\r" in password:
        return None
    if not EMAIL_PATTERN.fullmatch(email):
        return None
    return email, password


@dataclass(frozen=True)
class ClipboardRecord:
    email: str
    password: str
    card_number: str = ""
    second_value: str = ""


@dataclass(frozen=True)
class GeneratedIdentity:
    name: str
    address: str


class WorkflowStage(Enum):
    DISABLED = auto()
    EMAIL_READY = auto()
    WAITING_CODE = auto()
    CODE_READY = auto()
    FIRST_NAME_READY = auto()
    CARD_READY = auto()
    SECOND_VALUE_READY = auto()
    SECOND_NAME_READY = auto()
    ADDRESS_READY = auto()
    COMPLETE = auto()


@dataclass(frozen=True)
class WorkflowAction:
    status: str
    value: str | None = None


class ClipboardWorkflow:
    """Pure state machine for the global paste-driven clipboard sequence."""

    def __init__(self) -> None:
        self.stop()

    @property
    def active(self) -> bool:
        return self.stage not in {WorkflowStage.DISABLED, WorkflowStage.COMPLETE}

    @property
    def expected_value(self) -> str | None:
        return self._expected_value

    def stop(self) -> None:
        self.stage = WorkflowStage.DISABLED
        self._expected_value: str | None = None
        self._pending_code: str | None = None
        self._record: ClipboardRecord | None = None
        self._identity: GeneratedIdentity | None = None

    def start(
        self,
        record: ClipboardRecord,
        identity: GeneratedIdentity,
    ) -> WorkflowAction | None:
        self.stop()
        if not record.card_number or not record.second_value:
            return None
        self._record = record
        self._identity = identity
        return self._ready(
            WorkflowStage.EMAIL_READY,
            record.email,
            "邮箱已复制，请粘贴；正在等待验证码",
        )

    def on_code_found(self, code: str) -> WorkflowAction | None:
        if not self.active:
            return None
        self._pending_code = code
        if self.stage is WorkflowStage.WAITING_CODE:
            return self._ready(
                WorkflowStage.CODE_READY,
                code,
                "验证码已复制，请粘贴",
            )
        return None

    def on_paste(self, clipboard_value: str | None) -> WorkflowAction | None:
        if not self.active or self._expected_value is None:
            return None
        if clipboard_value != self._expected_value:
            return None

        if self.stage is WorkflowStage.EMAIL_READY:
            if self._pending_code:
                return self._ready(
                    WorkflowStage.CODE_READY,
                    self._pending_code,
                    "邮箱已粘贴，验证码已复制，请粘贴",
                )
            self.stage = WorkflowStage.WAITING_CODE
            self._expected_value = None
            return WorkflowAction("邮箱已粘贴，正在等待验证码…")

        record = self._record
        identity = self._identity
        if record is None or identity is None:
            self.stop()
            return None
        if self.stage is WorkflowStage.CODE_READY:
            return self._ready(
                WorkflowStage.FIRST_NAME_READY,
                identity.name,
                "验证码已粘贴，姓名已复制，请粘贴",
            )
        if self.stage is WorkflowStage.FIRST_NAME_READY:
            return self._ready(
                WorkflowStage.CARD_READY,
                record.card_number,
                "姓名已粘贴，卡号已复制，请粘贴",
            )
        if self.stage is WorkflowStage.CARD_READY:
            return self._ready(
                WorkflowStage.SECOND_VALUE_READY,
                record.second_value,
                "卡号已粘贴，第二列已复制，请粘贴",
            )
        if self.stage is WorkflowStage.SECOND_VALUE_READY:
            return self._ready(
                WorkflowStage.SECOND_NAME_READY,
                identity.name,
                "第二列已粘贴，姓名已再次复制，请粘贴",
            )
        if self.stage is WorkflowStage.SECOND_NAME_READY:
            return self._ready(
                WorkflowStage.ADDRESS_READY,
                identity.address,
                "姓名已粘贴，地址已复制，请粘贴",
            )
        if self.stage is WorkflowStage.ADDRESS_READY:
            self.stage = WorkflowStage.COMPLETE
            self._expected_value = None
            self._pending_code = None
            return WorkflowAction("自动填充流程已完成")
        return None

    def _ready(
        self,
        stage: WorkflowStage,
        value: str,
        status: str,
    ) -> WorkflowAction:
        self.stage = stage
        self._expected_value = value
        return WorkflowAction(status=status, value=value)


class PasteShortcutDetector:
    """Debounce Ctrl+V and Shift+Insert into one event per key press."""

    def __init__(self) -> None:
        self._latched = False

    def update(
        self,
        *,
        control: bool,
        v_key: bool,
        shift: bool,
        insert: bool,
    ) -> bool:
        pressed = (control and v_key) or (shift and insert)
        triggered = pressed and not self._latched
        self._latched = pressed
        return triggered


class _LowLevelKeyboardData(ctypes.Structure):
    _fields_ = (
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    )


_LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    ctypes.c_int,
    ctypes.c_size_t,
    ctypes.c_ssize_t,
)


class WindowsPasteHook:
    """Observe global paste shortcuts without consuming keyboard events."""

    WH_KEYBOARD_LL = 13
    HC_ACTION = 0
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_SYSKEYDOWN = 0x0104
    WM_SYSKEYUP = 0x0105
    VK_CONTROL_KEYS = {0x11, 0xA2, 0xA3}
    VK_SHIFT_KEYS = {0x10, 0xA0, 0xA1}
    VK_V = 0x56
    VK_INSERT = 0x2D

    def __init__(self) -> None:
        self._events: queue.SimpleQueue[None] = queue.SimpleQueue()
        self._pressed: set[int] = set()
        self._callback = _LowLevelKeyboardProc(self._hook_proc)
        self._handle: int | None = None
        try:
            user32 = ctypes.windll.user32
            user32.SetWindowsHookExW.argtypes = (
                ctypes.c_int,
                _LowLevelKeyboardProc,
                ctypes.c_void_p,
                wintypes.DWORD,
            )
            user32.SetWindowsHookExW.restype = ctypes.c_void_p
            user32.CallNextHookEx.argtypes = (
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_size_t,
                ctypes.c_ssize_t,
            )
            user32.CallNextHookEx.restype = ctypes.c_ssize_t
            user32.UnhookWindowsHookEx.argtypes = (ctypes.c_void_p,)
            user32.UnhookWindowsHookEx.restype = wintypes.BOOL
            handle = user32.SetWindowsHookExW(
                self.WH_KEYBOARD_LL,
                self._callback,
                None,
                0,
            )
            if handle:
                self._handle = int(handle)
        except (AttributeError, OSError, TypeError):
            self._handle = None

    @property
    def installed(self) -> bool:
        return self._handle is not None

    def consume(self) -> bool:
        triggered = False
        while True:
            try:
                self._events.get_nowait()
            except queue.Empty:
                return triggered
            triggered = True

    def close(self) -> None:
        handle = self._handle
        self._handle = None
        self._pressed.clear()
        if handle is not None:
            try:
                ctypes.windll.user32.UnhookWindowsHookEx(ctypes.c_void_p(handle))
            except (AttributeError, OSError):
                pass

    def _hook_proc(self, code: int, message: int, pointer: int) -> int:
        try:
            if code == self.HC_ACTION and pointer:
                data = ctypes.cast(
                    pointer,
                    ctypes.POINTER(_LowLevelKeyboardData),
                ).contents
                key = int(data.vkCode)
                if message in {self.WM_KEYDOWN, self.WM_SYSKEYDOWN}:
                    was_down = key in self._pressed
                    self._pressed.add(key)
                    if not was_down and self._is_paste_key(key):
                        self._events.put(None)
                elif message in {self.WM_KEYUP, self.WM_SYSKEYUP}:
                    self._pressed.discard(key)
        finally:
            try:
                return int(
                    ctypes.windll.user32.CallNextHookEx(
                        ctypes.c_void_p(self._handle or 0),
                        code,
                        message,
                        pointer,
                    )
                )
            except (AttributeError, OSError):
                return 0

    def _is_paste_key(self, key: int) -> bool:
        if key == self.VK_V:
            return bool(self._pressed & self.VK_CONTROL_KEYS)
        if key == self.VK_INSERT:
            return bool(self._pressed & self.VK_SHIFT_KEYS)
        return False


def generate_test_identity(rng: Any | None = None) -> GeneratedIdentity:
    """Generate a fictional profile in a state without a general sales tax."""
    rng = rng or secrets.SystemRandom()
    name = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"
    city, state, zip_code = rng.choice(SALES_TAX_FREE_LOCATIONS)
    address = (
        f"{rng.randint(10, 9999)} {rng.choice(STREET_NAMES)} "
        f"{rng.choice(STREET_TYPES)}, {city}, {state} {zip_code}, United States"
    )
    return GeneratedIdentity(name=name, address=address)


def parse_clipboard_record(text: str) -> ClipboardRecord | None:
    """Parse either credentials alone or a tab-separated account record."""
    if not isinstance(text, str):
        return None

    stripped = text.strip()
    columns = [column.strip() for column in stripped.split("\t")]
    if len(columns) >= 4:
        credentials = parse_credentials(columns[-1])
        card_number = re.sub(r"[ -]", "", columns[0])
        if credentials and CARD_PATTERN.fullmatch(card_number) and columns[1]:
            return ClipboardRecord(
                email=credentials[0],
                password=credentials[1],
                card_number=card_number,
                second_value=columns[1],
            )

    credentials = parse_credentials(stripped)
    if credentials:
        return ClipboardRecord(email=credentials[0], password=credentials[1])
    return None


class _VisibleTextParser(HTMLParser):
    _IGNORED_TAGS = {"head", "script", "style", "noscript"}
    _BLOCK_TAGS = {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "p",
        "section",
        "table",
        "td",
        "th",
        "tr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.lower()
        if tag in self._IGNORED_TAGS:
            self._ignored_depth += 1
        elif self._ignored_depth == 0 and tag in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._IGNORED_TAGS:
            self._ignored_depth = max(0, self._ignored_depth - 1)
        elif self._ignored_depth == 0 and tag in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def html_to_visible_text(html: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Broken email HTML is common. Keep any text parsed before the error.
        pass

    text = parser.text()
    text = text.replace("\xa0", " ")
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    # Codes are often rendered as one digit per inline element.
    text = re.sub(r"(?<=\d)\s+(?=\d)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_verification_code(html: str) -> str | None:
    if not isinstance(html, str) or not html:
        return None

    text = html_to_visible_text(html)
    if not text:
        return None

    for keyword in KEYWORD_PATTERN.finditer(text):
        after = CODE_PATTERN.search(text[keyword.end() : keyword.end() + 80])
        if after:
            return after.group(1)

        before_matches = list(
            CODE_PATTERN.finditer(text[max(0, keyword.start() - 80) : keyword.start()])
        )
        if before_matches:
            return before_matches[-1].group(1)

    fallback = CODE_PATTERN.search(text)
    return fallback.group(1) if fallback else None


class ApiError(Exception):
    def __init__(self, message: str, *, fatal: bool) -> None:
        super().__init__(message)
        self.fatal = fatal


def _message_from_response(data: dict[str, Any]) -> str:
    message = data.get("error") or data.get("message") or "邮件服务返回失败"
    return str(message)[:300]


def _is_fatal_service_error(message: str) -> bool:
    lowered = message.lower()
    transient_markers = (
        "timeout",
        "rate limit",
        "too many",
        "network",
        "connection",
        "server",
        "temporarily",
        "unavailable",
        "econn",
        "tls",
        "certificate",
        "超时",
        "频繁",
        "网络",
        "连接",
        "服务器",
        "稍后",
    )
    if any(marker in lowered for marker in transient_markers):
        return False

    fatal_markers = (
        "password",
        "credential",
        "unauthorized",
        "forbidden",
        "mailbox not found",
        "invalid account",
        "bad request",
        "密码",
        "账号",
        "邮箱不存在",
        "无权限",
        "参数",
    )
    return any(marker in lowered for marker in fatal_markers)


class MailApiClient:
    def __init__(
        self,
        endpoint: str = API_URL,
        open_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self._ssl_context = ssl.create_default_context()
        self._open_fn = open_fn

    def _open(self, request: urllib.request.Request) -> Any:
        if self._open_fn is not None:
            return self._open_fn(request, timeout=REQUEST_TIMEOUT_SECONDS)
        return urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=self._ssl_context,
        )

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": API_ORIGIN,
                "Referer": f"{API_ORIGIN}/",
                "User-Agent": "MailCodeHelper/1.0 (Windows)",
            },
        )

        try:
            with self._open(request) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as error:
            try:
                error_data = json.loads(error.read().decode("utf-8", errors="replace"))
                message = _message_from_response(error_data)
            except Exception:
                message = f"HTTP {error.code}"
            fatal = error.code not in {408, 429} and error.code < 500
            raise ApiError(message, fatal=fatal) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ApiError(str(error), fatal=False) from error

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ApiError("邮件服务返回了无效数据", fatal=False) from error
        if not isinstance(data, dict):
            raise ApiError("邮件服务返回了无效数据", fatal=False)
        return data

    @staticmethod
    def _require_success(data: dict[str, Any]) -> None:
        if data.get("success") is True:
            return
        message = _message_from_response(data)
        raise ApiError(message, fatal=_is_fatal_service_error(message))

    def fetch_latest_body(self, email: str, password: str) -> str | None:
        common = {
            "email": email,
            "password": password,
            "clientId": "",
            "refreshToken": "",
        }
        first = self._post_json({**common, "search": "", "days": 30})
        self._require_success(first)

        body = first.get("latestBody")
        if isinstance(body, str) and body:
            return body

        mail_list = first.get("mailList")
        if not isinstance(mail_list, list) or not mail_list:
            return None
        first_mail = mail_list[0]
        if not isinstance(first_mail, dict) or not first_mail.get("mailId"):
            return None

        detail = self._post_json({**common, "mailId": first_mail["mailId"]})
        self._require_success(detail)
        detail_body = detail.get("latestBody")
        return detail_body if isinstance(detail_body, str) and detail_body else None


EventCallback = Callable[[str, Any], None]
WaitCallback = Callable[[float], bool]


def run_polling(
    email: str,
    password: str,
    api: MailApiClient,
    cancel_event: threading.Event,
    on_event: EventCallback,
    wait: WaitCallback | None = None,
) -> None:
    wait = wait or cancel_event.wait
    network_failure_count = 0
    last_code: str | None = None

    while not cancel_event.is_set():
        on_event("fetching", None)
        try:
            body = api.fetch_latest_body(email, password)
        except ApiError as error:
            if error.fatal:
                on_event("fatal", "账号、密码或请求参数无效")
                return
            delay = NETWORK_RETRY_SECONDS[
                min(network_failure_count, len(NETWORK_RETRY_SECONDS) - 1)
            ]
            network_failure_count += 1
            on_event("retry", delay)
            if wait(delay):
                return
            continue

        network_failure_count = 0
        code = extract_verification_code(body) if body else None
        if code:
            if code != last_code:
                last_code = code
                on_event("found", code)
            else:
                on_event("unchanged", NORMAL_RETRY_SECONDS)
        else:
            on_event("waiting", NORMAL_RETRY_SECONDS)

        if wait(NORMAL_RETRY_SECONDS):
            return


class VerificationCodeApp:
    BG = "#0f172a"
    PANEL = "#111c32"
    TEXT = "#e5e7eb"
    MUTED = "#94a3b8"
    ACCENT = "#38bdf8"
    SUCCESS = "#4ade80"
    WARNING = "#fbbf24"
    ERROR = "#fb7185"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("邮箱验证码助手")
        self.root.geometry("470x330")
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG)
        self.root.attributes("-topmost", True)
        try:
            self.root.attributes("-toolwindow", True)
        except tk.TclError:
            pass

        self._closed = False
        self._generation = 0
        self._cancel_event: threading.Event | None = None
        self._last_seen_clipboard: str | None = None
        self._last_clipboard_sequence: int | None = None
        self._self_clipboard: str | None = None
        self._current_code: str | None = None
        self._oauth_dialog: OAuthAuthorizationDialog | None = None
        self._workflow = ClipboardWorkflow()
        self._paste_detector = PasteShortcutDetector()
        self._paste_hook = WindowsPasteHook()
        self._events: queue.Queue[tuple[int, str, Any]] = queue.Queue()

        self._build_ui()
        self._place_top_right()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self._drain_events)
        self.root.after(150, self._check_clipboard)
        self.root.after(50, self._check_paste_shortcut)

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Action.TButton",
            font=("Microsoft YaHei UI", 9),
            padding=(8, 4),
            background="#1e293b",
            foreground=self.TEXT,
            borderwidth=0,
        )
        style.map(
            "Action.TButton",
            background=[("active", "#334155"), ("disabled", "#172033")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "Value.TButton",
            font=("Consolas", 9),
            padding=(7, 3),
            anchor="w",
            background="#172238",
            foreground=self.TEXT,
            borderwidth=0,
        )
        style.map(
            "Value.TButton",
            background=[("active", "#263650"), ("disabled", "#121b2c")],
            foreground=[("disabled", "#64748b")],
        )

        panel = tk.Frame(self.root, bg=self.PANEL, padx=12, pady=9)
        panel.pack(fill="both", expand=True, padx=1, pady=1)

        header = tk.Frame(panel, bg=self.PANEL)
        header.pack(fill="x")
        tk.Label(
            header,
            text="邮箱验证码助手",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Microsoft YaHei UI", 10, "bold"),
        ).pack(side="left")
        tk.Label(
            header,
            text="● 始终置顶",
            bg=self.PANEL,
            fg=self.ACCENT,
            font=("Microsoft YaHei UI", 8),
        ).pack(side="right")

        values = tk.Frame(panel, bg=self.PANEL)
        values.pack(fill="x", pady=(6, 1))
        self.email_button = self._add_value_row(values, 0, "邮箱", "等待复制")
        self.card_button = self._add_value_row(values, 1, "卡号", "未提供")
        self.second_button = self._add_value_row(values, 2, "第二列", "未提供")
        self.name_button = self._add_value_row(values, 3, "姓名", "等待生成")
        self.address_button = self._add_value_row(values, 4, "地址", "等待生成")

        self.status_label = tk.Label(
            panel,
            text="复制完整账号信息后将自动查询",
            anchor="w",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Microsoft YaHei UI", 9),
            wraplength=440,
        )
        self.status_label.pack(fill="x", pady=(2, 0))

        self.code_label = tk.Label(
            panel,
            text="------",
            bg=self.PANEL,
            fg=self.ACCENT,
            font=("Consolas", 26, "bold"),
        )
        self.code_label.pack(pady=(0, 1))

        actions = tk.Frame(panel, bg=self.PANEL)
        actions.pack(fill="x")
        self.copy_button = ttk.Button(
            actions,
            text="复制验证码",
            style="Action.TButton",
            command=self.copy_code,
            state="disabled",
        )
        self.copy_button.pack(side="left")
        self.stop_button = ttk.Button(
            actions,
            text="停止",
            style="Action.TButton",
            command=self.stop_fetch,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=6)
        ttk.Button(
            actions,
            text="OpenAI 授权",
            style="Action.TButton",
            command=self.open_oauth_dialog,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="关闭",
            style="Action.TButton",
            command=self.close,
        ).pack(side="right")

    def _add_value_row(
        self,
        parent: tk.Frame,
        row: int,
        label: str,
        initial: str,
    ) -> ttk.Button:
        tk.Label(
            parent,
            text=label,
            width=6,
            anchor="w",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Microsoft YaHei UI", 8),
        ).grid(row=row, column=0, sticky="w", pady=1)
        button = ttk.Button(
            parent,
            text=initial,
            style="Value.TButton",
            state="disabled",
        )
        button.grid(row=row, column=1, sticky="ew", pady=1)
        parent.grid_columnconfigure(1, weight=1)
        return button

    def _place_top_right(self) -> None:
        self.root.update_idletasks()
        x = max(0, self.root.winfo_screenwidth() - 490)
        self.root.geometry(f"470x330+{x}+40")

    def _set_status(self, text: str, color: str | None = None) -> None:
        self.status_label.configure(text=text, fg=color or self.MUTED)

    def _read_clipboard(self) -> str | None:
        try:
            value = self.root.clipboard_get()
        except tk.TclError:
            return None
        return value if isinstance(value, str) else None

    @staticmethod
    def _clipboard_sequence_number() -> int | None:
        try:
            return int(ctypes.windll.user32.GetClipboardSequenceNumber())
        except (AttributeError, OSError):
            return None

    @staticmethod
    def _key_is_down(virtual_key: int) -> bool:
        try:
            return bool(ctypes.windll.user32.GetAsyncKeyState(virtual_key) & 0x8000)
        except (AttributeError, OSError):
            return False

    def _oauth_has_focus(self) -> bool:
        dialog = self._oauth_dialog
        if dialog is None or not dialog.exists():
            return False
        try:
            focused = self.root.focus_displayof()
            return focused is not None and focused.winfo_toplevel() == dialog.window
        except tk.TclError:
            return False

    def _check_paste_shortcut(self) -> None:
        if self._closed:
            return
        if self._paste_hook.installed:
            triggered = self._paste_hook.consume()
        else:
            triggered = self._paste_detector.update(
                control=self._key_is_down(0x11),
                v_key=self._key_is_down(0x56),
                shift=self._key_is_down(0x10),
                insert=self._key_is_down(0x2D),
            )
        if (
            triggered
            and not self._oauth_has_focus()
            and self._workflow.expected_value is not None
        ):
            generation = self._generation
            expected = self._workflow.expected_value
            self.root.after(
                PASTE_ADVANCE_DELAY_MS,
                lambda: self._advance_after_paste(generation, expected),
            )
        self.root.after(50, self._check_paste_shortcut)

    def _advance_after_paste(self, generation: int, expected: str) -> None:
        if self._closed or generation != self._generation:
            return
        if expected != self._workflow.expected_value:
            return
        action = self._workflow.on_paste(self._read_clipboard())
        if action is not None:
            self._apply_workflow_action(action)

    def _check_clipboard(self) -> None:
        if self._closed:
            return

        text = self._read_clipboard()
        sequence = self._clipboard_sequence_number()
        if sequence is None:
            changed = text is not None and text != self._last_seen_clipboard
        else:
            changed = text is not None and sequence != self._last_clipboard_sequence

        if changed:
            self._last_seen_clipboard = text
            self._last_clipboard_sequence = sequence
            if self._self_clipboard == text:
                self._self_clipboard = None
            else:
                record = parse_clipboard_record(text)
                if record is not None:
                    self.start_fetch(record)
        self.root.after(500, self._check_clipboard)

    def start_fetch(self, record: ClipboardRecord) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()

        self._generation += 1
        generation = self._generation
        cancel_event = threading.Event()
        self._cancel_event = cancel_event
        self._current_code = None
        identity = generate_test_identity()
        workflow_action = self._workflow.start(record, identity)

        self._configure_value_button(self.email_button, record.email, "邮箱")
        self._configure_value_button(self.card_button, record.card_number, "卡号")
        self._configure_value_button(self.second_button, record.second_value, "第二列")
        self._configure_value_button(self.name_button, identity.name, "姓名")
        address_display = identity.address.replace(", ", ",\n", 1)
        self._configure_value_button(
            self.address_button,
            identity.address,
            "地址",
            display_value=address_display,
        )
        self.code_label.configure(text="------", fg=self.ACCENT)
        self.copy_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        if workflow_action is not None:
            self._apply_workflow_action(workflow_action)
        else:
            self._set_status("已识别账号，正在查询最新邮件…", self.ACCENT)

        def publish(kind: str, value: Any) -> None:
            self._events.put((generation, kind, value))

        worker = threading.Thread(
            target=run_polling,
            args=(
                record.email,
                record.password,
                MailApiClient(),
                cancel_event,
                publish,
            ),
            daemon=True,
            name=f"mail-fetch-{generation}",
        )
        worker.start()

    def _configure_value_button(
        self,
        button: ttk.Button,
        value: str,
        label: str,
        display_value: str | None = None,
    ) -> None:
        if value:
            button.configure(
                text=display_value or value,
                state="normal",
                command=lambda: self.copy_value(label, value),
            )
        else:
            button.configure(text="未提供", state="disabled", command=None)

    def _drain_events(self) -> None:
        if self._closed:
            return
        try:
            while True:
                generation, kind, value = self._events.get_nowait()
                if generation == self._generation:
                    self._handle_event(kind, value)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    def _handle_event(self, kind: str, value: Any) -> None:
        if kind == "fetching":
            if self._workflow.stage is WorkflowStage.WAITING_CODE:
                self._set_status("邮箱已粘贴，正在查询验证码…", self.ACCENT)
            elif not self._workflow.active:
                self._set_status("正在查询最新邮件…", self.ACCENT)
        elif kind == "waiting":
            if self._workflow.stage is WorkflowStage.EMAIL_READY:
                self._set_status(
                    f"邮箱已复制，请粘贴；暂未找到验证码，{value} 秒后重试",
                    self.WARNING,
                )
            elif self._workflow.stage is WorkflowStage.WAITING_CODE:
                self._set_status(f"正在等待验证码，{value} 秒后重试", self.WARNING)
            elif not self._workflow.active:
                self._set_status(f"暂未找到验证码，{value} 秒后重试", self.WARNING)
        elif kind == "retry":
            if self._workflow.active:
                self._set_status(
                    f"等待验证码时网络或服务异常，{value} 秒后重试",
                    self.WARNING,
                )
            else:
                self._set_status(f"网络或服务暂时异常，{value} 秒后重试", self.WARNING)
        elif kind == "unchanged":
            if self._workflow.stage is WorkflowStage.COMPLETE:
                self._set_status(
                    f"自动流程已完成；{value} 秒后检查最新邮件",
                    self.SUCCESS,
                )
            elif not self._workflow.active:
                self._set_status(
                    f"验证码未变化，{value} 秒后检查最新邮件",
                    self.SUCCESS,
                )
        elif kind == "fatal":
            self._workflow.stop()
            self.stop_button.configure(state="disabled")
            self._set_status(str(value), self.ERROR)
        elif kind == "found":
            code = str(value)
            self._current_code = code
            self.code_label.configure(text=code, fg=self.SUCCESS)
            self.copy_button.configure(state="normal")
            if self._workflow.active:
                action = self._workflow.on_code_found(code)
                if action is not None:
                    self._apply_workflow_action(action)
                elif self._workflow.stage is WorkflowStage.EMAIL_READY:
                    self._set_status("验证码已就绪；请先粘贴当前邮箱", self.SUCCESS)
            elif self._workflow.stage is WorkflowStage.COMPLETE:
                self._set_status(
                    "发现新验证码，已更新显示；5 秒后继续检查最新邮件",
                    self.SUCCESS,
                )
            else:
                self._write_clipboard(code)
                self._set_status(
                    "已找到验证码并自动复制；5 秒后检查最新邮件",
                    self.SUCCESS,
                )

    def _apply_workflow_action(self, action: WorkflowAction) -> None:
        if action.value is not None:
            self._write_clipboard(action.value)
        self._set_status(action.status, self.SUCCESS)

    def _write_clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self._self_clipboard = text
            self._last_seen_clipboard = text
            self._last_clipboard_sequence = self._clipboard_sequence_number()
        except tk.TclError:
            self._set_status("内容已显示，但写入剪贴板失败", self.ERROR)

    def copy_value(self, label: str, value: str) -> None:
        self._write_clipboard(value)
        self._set_status(f"{label}已复制", self.SUCCESS)

    def copy_code(self) -> None:
        if self._current_code:
            self._write_clipboard(self._current_code)
            self._set_status("验证码已复制", self.SUCCESS)

    def stop_fetch(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        self._generation += 1
        self._workflow.stop()
        self.stop_button.configure(state="disabled")
        self._set_status("已停止，等待复制新的账号", self.MUTED)

    def open_oauth_dialog(self) -> None:
        if self._oauth_dialog is not None and self._oauth_dialog.exists():
            self._oauth_dialog.focus()
            return

        def dialog_closed() -> None:
            self._oauth_dialog = None

        self._oauth_dialog = OAuthAuthorizationDialog(
            self.root,
            on_close=dialog_closed,
        )

    def close(self) -> None:
        self._closed = True
        self._paste_hook.close()
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._oauth_dialog is not None and self._oauth_dialog.exists():
            self._oauth_dialog.close()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    # The platform workflow is the default EXE entry point.  The old
    # VerificationCodeApp remains in this module only as a migration reference
    # until the platform card/upload phases are complete; it is not launched
    # and therefore cannot send source-mail credentials in the normal build.
    from platform_desktop import PlatformDesktopApp

    PlatformDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
