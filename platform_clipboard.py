"""Platform-only paste sequencing without legacy credentials or page automation."""

from __future__ import annotations

import ctypes
import queue
from ctypes import wintypes
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class PasteStage(str, Enum):
    STOPPED = "stopped"
    CODE_READY = "code_ready"
    WAITING_CARD = "waiting_card"
    CARD_READY = "card_ready"
    COMPLETE = "complete"


@dataclass(frozen=True)
class PasteAction:
    status: str
    value: str | None = field(default=None, repr=False)
    consumed: str | None = None
    completed: bool = False


class SecurePasteSequence:
    """Advance from a task code to an already-authorized card value on paste."""

    def __init__(self) -> None:
        self._generation = 0
        self._stage = PasteStage.STOPPED
        self._expected: str | None = None
        self._card_details: str | None = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(stage={self._stage.value!r})"

    @property
    def active(self) -> bool:
        return self._stage not in {PasteStage.STOPPED, PasteStage.COMPLETE}

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def stage(self) -> PasteStage:
        return self._stage

    def start(self, code: str, card_details: str | None = None) -> PasteAction:
        code = self._required_value(code, "code")
        if card_details is not None:
            card_details = self._required_value(card_details, "card_details")
        self._generation += 1
        self._stage = PasteStage.CODE_READY
        self._expected = code
        self._card_details = card_details
        return PasteAction(
            "验证码已复制；粘贴后将继续当前任务的安全填充。",
            value=code,
        )

    def offer_card(self, card_details: str) -> PasteAction | None:
        card_details = self._required_value(card_details, "card_details")
        if self._stage in {PasteStage.STOPPED, PasteStage.COMPLETE}:
            return None
        self._card_details = card_details
        if self._stage is PasteStage.WAITING_CARD:
            self._generation += 1
            self._stage = PasteStage.CARD_READY
            self._expected = card_details
            return PasteAction(
                "验证码已粘贴，已复制经二次认证授权的卡详情；请粘贴。",
                value=card_details,
            )
        if self._stage is PasteStage.CODE_READY:
            return PasteAction("卡详情已授权；请先粘贴当前验证码。")
        return None

    def on_paste(self, clipboard_value: str | None) -> PasteAction | None:
        if not self.active or self._expected is None:
            return None
        if clipboard_value != self._expected:
            return None
        if self._stage is PasteStage.CODE_READY:
            self._generation += 1
            self._expected = None
            if self._card_details is None:
                self._stage = PasteStage.WAITING_CARD
                return PasteAction(
                    "验证码已粘贴；完成卡号二次认证后将继续填充。",
                    consumed="code",
                )
            self._stage = PasteStage.CARD_READY
            self._expected = self._card_details
            return PasteAction(
                "验证码已粘贴，已复制经二次认证授权的卡详情；请粘贴。",
                value=self._card_details,
                consumed="code",
            )
        if self._stage is PasteStage.CARD_READY:
            self._generation += 1
            self._stage = PasteStage.COMPLETE
            self._expected = None
            self._card_details = None
            return PasteAction(
                "当前任务的连续粘贴流程已完成。",
                consumed="card",
                completed=True,
            )
        return None

    def stop(self) -> None:
        self._generation += 1
        self._stage = PasteStage.STOPPED
        self._expected = None
        self._card_details = None

    def stop_if_pending(self, value: str | None) -> bool:
        if value is None or value not in {self._expected, self._card_details}:
            return False
        self.stop()
        return True

    @staticmethod
    def _required_value(value: str, name: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} is required")
        return value


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


_callback_factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
_LowLevelKeyboardProc = _callback_factory(
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


def _key_is_down(key: int) -> bool:
    try:
        return bool(ctypes.windll.user32.GetAsyncKeyState(key) & 0x8000)
    except (AttributeError, OSError):
        return False


def get_clipboard_sequence_number() -> int | None:
    """Return the Windows clipboard revision without reading its contents."""

    try:
        value = int(ctypes.windll.user32.GetClipboardSequenceNumber())
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return value if value >= 0 else None


class WindowsPasteObserver:
    """Use the global hook when available and a narrow key-state fallback otherwise."""

    def __init__(
        self,
        *,
        hook: WindowsPasteHook | None = None,
        key_reader: Callable[[int], bool] = _key_is_down,
    ) -> None:
        self._hook = hook or WindowsPasteHook()
        self._key_reader = key_reader
        self._detector = PasteShortcutDetector()

    def consume(self) -> bool:
        if self._hook.installed:
            return self._hook.consume()
        return self._detector.update(
            control=self._key_reader(0x11),
            v_key=self._key_reader(0x56),
            shift=self._key_reader(0x10),
            insert=self._key_reader(0x2D),
        )

    def close(self) -> None:
        self._hook.close()


__all__ = [
    "PasteAction",
    "PasteShortcutDetector",
    "PasteStage",
    "SecurePasteSequence",
    "WindowsPasteHook",
    "WindowsPasteObserver",
    "get_clipboard_sequence_number",
]
