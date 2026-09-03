import inspect
import queue
import threading
import time
import tkinter as tk
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import app
from platform_clipboard import PasteStage, SecurePasteSequence
from platform_client import (
    CardAllocationSnapshot,
    CardRevealChallenge,
    CardRevealGrant,
    CardRevealSnapshot,
    MailSessionSnapshot,
    MailCodeSnapshot,
    PlatformApiError,
    PlatformAuthenticationError,
    PlatformAuthenticationRequiredError,
    PlatformDeviceAuthorizationError,
    PlatformProtocolError,
    PlatformTimeoutError,
    PlatformTransportError,
    StepUpAuthorization,
    TaskRecoverySnapshot,
    TaskSnapshot,
    TaskTimelineAllocationSnapshot,
    TaskTimelineMailSnapshot,
    TaskTransitionCleanup,
    UploadJobSnapshot,
)
from platform_desktop import (
    PlatformDesktopApp,
    _SessionRestoreCompensation,
    format_operation_error,
    format_workflow_progress,
)
from update_client import UpdateError


class RecordingWidget:
    def __init__(self):
        self.values = {}
        self.states = []

    def configure(self, **values):
        self.values.update(values)
        if "state" in values:
            self.states.append(values["state"])


class RootStub:
    def __init__(self):
        self.scheduled = []
        self.clipboard = ""
        self.destroy_calls = 0

    def after(self, delay, callback, *args):
        self.scheduled.append((delay, callback, args))

    def clipboard_get(self):
        return self.clipboard

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, text):
        self.clipboard += text

    @staticmethod
    def focus_displayof():
        return None

    @staticmethod
    def update_idletasks():
        return None

    def destroy(self):
        self.destroy_calls += 1


def task_snapshot(task_id: str, trace_id: str) -> TaskSnapshot:
    return TaskSnapshot(
        id=task_id,
        task_type="mail_code",
        status="created",
        trace_id=trace_id,
        created_at="2026-08-20T00:00:00Z",
        expires_at="2026-08-20T00:30:00Z",
        closed_at=None,
    )


class PlatformDesktopBoundaryTests(unittest.TestCase):
    @staticmethod
    def _event_app() -> PlatformDesktopApp:
        instance = object.__new__(PlatformDesktopApp)
        instance._closed = False
        instance._locked = False
        instance._events = queue.Queue()
        instance._task_generation = 1
        instance._poll_generation = 1
        instance._poll_retry_attempt = 0
        instance._poll_cancel = None
        instance._sensitive_focus = threading.Event()
        instance._sensitive_focus.set()
        instance._upload_generation = 1
        instance._update_generation = 1
        instance._update_cleanup_in_progress = False
        instance._update_cleanup_completed = False
        instance._update_cleanup_action = None
        instance._update_cleanup_thread = None
        instance._pending_update_install = None
        instance._cleanup_thread = None
        instance._shutdown_cleanup_in_progress = False
        instance._shutdown_cleanup_action = None
        instance._shutdown_cleanup_thread = None
        instance._shutdown_generation = 0
        instance._shutdown_intent = None
        instance._shutdown_message = ""
        instance._session_generation = 1
        instance._session_restore_action = None
        instance._session_restore_compensation = None
        instance._active_task_discovery_action = None
        instance._active_task_discovery_thread = None
        instance._active_task_discovery_required = False
        instance._active_task_recovery_action = None
        instance._active_task_recovery = None
        instance._task_id = "task-1"
        instance._task_transition = None
        instance._task_transition_thread = None
        instance._terminal_task_cleanup_action = None
        instance._terminal_task_cleanup_thread = None
        instance._terminal_task_cleanup_in_progress = False
        instance._terminal_task_cleanup_task_id = None
        instance._terminal_task_cleanup_outcome = None
        instance._terminal_task_cleanup_generation = 0
        instance._task_compensation = None
        instance._mail_session_id = "mail-1"
        instance._mail_session_token = "opaque-session-token"
        instance._card_allocation_id = "allocation-1"
        instance._upload_job_id = None
        instance._verified_task_id = None
        instance._current_code = None
        instance._current_card_clipboard = None
        instance._current_trace_clipboard = None
        instance._card_reveal_action = None
        instance._card_reveal_thread = None
        instance._code_clear_generation = 0
        instance._card_clear_generation = 0
        instance._trace_clear_generation = 0
        instance._clipboard_clear_generation = 0
        instance._clipboard_cleanup_pending = 0
        instance._clipboard_owner = None
        instance._clipboard_cleanup_failed = None
        instance._destroy_pending = False
        instance._history_generation = 0
        instance._paste_sequence = SecurePasteSequence()
        instance._paste_observer = mock.Mock()
        instance._upload_idempotency_key = "attempt-1"
        instance._upload_business_name = "Example Store"
        instance._upload_submission_action = None
        instance._upload_submission_thread = None
        instance._session_refreshing = False
        instance._unlock_action = None
        instance._unlock_thread = None
        instance._profile_summary = "operator@example.test"
        instance._profile_identity = ("tenant-1", "user-1", "device-1")
        instance._session_deadline = time.monotonic() + 300
        instance._client = None
        instance._update_client = mock.Mock()
        instance._login_dialog = None
        instance.root = RootStub()
        instance.auth_label = RecordingWidget()
        instance.profile_label = RecordingWidget()
        instance.task_label = RecordingWidget()
        instance.mail_label = RecordingWidget()
        instance.card_label = RecordingWidget()
        instance.card_reveal_label = RecordingWidget()
        instance.session_label = RecordingWidget()
        instance.code_label = RecordingWidget()
        instance.copy_button = RecordingWidget()
        instance.upload_button = RecordingWidget()
        instance.copy_card_button = RecordingWidget()
        instance.upload_label = RecordingWidget()
        instance.workflow_label = RecordingWidget()
        instance.status_label = RecordingWidget()
        instance.new_task_button = RecordingWidget()
        instance.close_active_task_button = RecordingWidget()
        instance.history_button = RecordingWidget()
        instance.logout_button = RecordingWidget()
        instance.lock_button = RecordingWidget()
        instance.login_button = RecordingWidget()
        instance.check_update_button = RecordingWidget()
        instance.business_entry = RecordingWidget()
        instance._write_clipboard = mock.Mock(return_value=True)
        instance._schedule_code_cleanup = mock.Mock()
        instance._schedule_card_cleanup = mock.Mock()
        instance.stop_polling = mock.Mock()
        instance._close_task_history = mock.Mock()
        return instance

    def test_default_entry_point_uses_platform_window(self) -> None:
        source = inspect.getsource(app.main)
        self.assertIn("PlatformDesktopApp", source)
        self.assertNotIn("VerificationCodeApp(root)", source)

    def test_task_workflow_has_no_source_mail_or_sub2_inputs(self) -> None:
        source = inspect.getsource(PlatformDesktopApp)
        for forbidden in (
            "API_URL",
            "MailApiClient",
            "parse_credentials",
            "password",
            "secret_ref",
            "proxy_id",
            "group_ids",
            "concurrency",
        ):
            self.assertNotIn(forbidden, source)

    def test_mail_polling_uses_opaque_session_token(self) -> None:
        init_source = inspect.getsource(PlatformDesktopApp.__init__)
        polling_source = inspect.getsource(PlatformDesktopApp._start_polling)
        event_source = inspect.getsource(PlatformDesktopApp._drain_events)
        logout_source = inspect.getsource(PlatformDesktopApp._begin_session_shutdown)
        self.assertIn("self._mail_session_token: str | None = None", init_source)
        self.assertIn("session.session_token", event_source)
        self.assertIn("self._mail_session_token", polling_source)
        self.assertIn("self._mail_session_token = None", logout_source)

    def test_workflow_progress_uses_text_icons_and_distinct_terminal_states(self) -> None:
        waiting_text, waiting_color = format_workflow_progress("waiting")
        self.assertIn("✓ 登录", waiting_text)
        self.assertIn("✓ 分配卡", waiting_text)
        self.assertIn("● 等待验证码", waiting_text)

        completed_text, completed_color = format_workflow_progress("completed")
        self.assertTrue(all(item.startswith("✓ ") for item in completed_text.split("  →  ")))
        self.assertNotEqual(waiting_color, completed_color)

        review_text, review_color = format_workflow_progress("review")
        failed_text, failed_color = format_workflow_progress("upload_failed")
        self.assertIn("! 上传", review_text)
        self.assertIn("× 上传", failed_text)
        self.assertNotEqual(review_color, failed_color)

    def test_operation_error_uses_safe_contract_without_reflecting_server_message(self) -> None:
        secret_message = "server echoed password=do-not-display"
        error = PlatformApiError(
            secret_message,
            code="active_task_exists",
            status=409,
            trace_id="00000000-0000-0000-0000-000000000016",
            recovery_hint="请先完成或关闭当前任务，再创建新任务",
        )

        text = format_operation_error(error)

        self.assertIn("原因：", text)
        self.assertIn("影响：", text)
        self.assertIn("下一步：", text)
        self.assertIn("active_task_exists", text)
        self.assertIn("00000000-0000-0000-0000-000000000016", text)
        self.assertIn("请先完成或关闭当前任务，再创建新任务", text)
        self.assertNotIn(secret_message, text)

    def test_secure_paste_advances_only_for_current_task_generation(self) -> None:
        instance = self._event_app()
        code = "246810"
        card = "4111111111111111\t12/30"
        instance._current_code = code
        instance._current_card_clipboard = card
        instance._paste_sequence.start(code, card)
        first_generation = instance._paste_sequence.generation

        instance.root.clipboard = code
        instance._advance_after_paste(
            instance._task_generation, first_generation
        )

        instance._write_clipboard.assert_called_once_with(card)
        self.assertIsNone(instance._current_code)
        self.assertEqual(instance._paste_sequence.stage, PasteStage.CARD_READY)

        instance.root.clipboard = card
        instance._advance_after_paste(
            instance._task_generation, first_generation
        )
        self.assertEqual(instance._paste_sequence.stage, PasteStage.CARD_READY)
        instance._advance_after_paste(
            instance._task_generation, instance._paste_sequence.generation
        )

        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(instance._paste_sequence.stage, PasteStage.COMPLETE)

    def test_stale_paste_callback_cannot_copy_after_task_switch(self) -> None:
        instance = self._event_app()
        instance._paste_sequence.start(
            "246810", "4111111111111111\t12/30"
        )
        old_task_generation = instance._task_generation
        old_sequence_generation = instance._paste_sequence.generation
        instance.root.clipboard = "246810"

        instance._task_generation += 1
        instance._paste_sequence.stop()
        instance._advance_after_paste(
            old_task_generation, old_sequence_generation
        )

        instance._write_clipboard.assert_not_called()
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)

    def test_code_event_clipboard_write_failure_is_final_and_stops_sequence(self) -> None:
        instance = self._event_app()
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        instance.root.clipboard = "foreign clipboard value"
        instance.root.clipboard_clear = mock.Mock(
            side_effect=tk.TclError("raw clipboard failure")
        )

        instance._events.put(
            (
                instance._poll_generation,
                "code",
                MailCodeSnapshot(status="code_ready", code="246810"),
            )
        )
        instance._drain_events()

        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("raw clipboard failure", status)
        self.assertNotIn("已复制", status)
        self.assertEqual(instance.root.clipboard, "foreign clipboard value")
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)
        self.assertEqual(instance._current_code, "246810")

    def test_manual_code_copy_failure_does_not_publish_success(self) -> None:
        instance = self._event_app()
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        instance._current_code = "246810"
        instance.root.clipboard = "foreign clipboard value"
        instance.root.clipboard_clear = mock.Mock(
            side_effect=tk.TclError("manual copy raw failure")
        )

        instance.copy_code()

        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("manual copy raw failure", status)
        self.assertNotIn("已复制", status)
        self.assertEqual(instance.root.clipboard, "foreign clipboard value")
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)

    def test_failed_initial_clear_never_claims_same_value_foreign_clipboard(self) -> None:
        instance = self._event_app()
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        target = "246810"
        instance.root.clipboard = target
        available_clear = instance.root.clipboard_clear
        instance.root.clipboard_clear = mock.Mock(
            side_effect=tk.TclError("clipboard initially busy")
        )

        self.assertFalse(instance._write_clipboard(target))
        instance.root.clipboard_clear = available_clear
        while instance.root.scheduled:
            _, retry, args = instance.root.scheduled.pop(0)
            retry(*args)

        self.assertEqual(instance.root.clipboard, target)
        self.assertEqual(instance.root.scheduled, [])

    def test_partial_card_write_failure_is_cleaned_and_stops_auto_advance(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        code = "246810"
        card = "4111111111111111\t12/30"
        instance._current_code = code
        instance._current_card_clipboard = card
        instance._paste_sequence.start(code, card)
        sequence_generation = instance._paste_sequence.generation
        instance.root.clipboard = code
        instance.root.update_idletasks = mock.Mock(
            side_effect=(None, tk.TclError("partial card write raw failure"), None)
        )

        instance._advance_after_paste(
            instance._task_generation, sequence_generation
        )

        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("partial card write raw failure", status)
        self.assertNotIn("已复制", status)
        self.assertEqual(instance.root.clipboard, "")
        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)
        self.assertEqual(instance.copy_card_button.values["state"], "normal")

    def test_trace_copy_failure_uses_non_sensitive_error_and_does_not_claim_success(self) -> None:
        instance = self._event_app()
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        instance._history_tree = mock.Mock()
        instance._history_tree.selection.return_value = ("row-1",)
        instance._history_tree.item.return_value = (
            "2026-08-24 12:00",
            "closed",
            "task-1",
            "trace-1",
        )
        instance._history_status = RecordingWidget()
        instance.root.clipboard = "foreign clipboard value"
        instance.root.clipboard_clear = mock.Mock(
            side_effect=tk.TclError("trace copy raw failure")
        )

        instance._copy_selected_trace()

        status = instance._history_status.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("敏感", status)
        self.assertNotIn("trace copy raw failure", status)
        self.assertNotIn("已复制", status)
        self.assertIsNone(instance._current_trace_clipboard)
        self.assertEqual(instance.root.clipboard, "foreign clipboard value")

    def test_logout_stops_sequence_and_clears_only_owned_clipboard(self) -> None:
        instance = self._event_app()
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance._current_trace_clipboard = "trace-owned"
        instance._paste_sequence.start(
            instance._current_code, instance._current_card_clipboard
        )
        instance.root.clipboard = instance._current_trace_clipboard

        instance.logout()

        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        self.assertIsNone(instance._current_trace_clipboard)
        self.assertEqual(instance.root.clipboard, "")

        instance._current_code = "135790"
        instance.root.clipboard = "user copied this later"
        instance._clear_sensitive_code()
        self.assertEqual(instance.root.clipboard, "user copied this later")

    def test_clipboard_busy_cleanup_retries_then_clears_owned_value(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        clipboard_get = instance.root.clipboard_get
        attempts = 0

        def busy_once():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise tk.TclError("clipboard busy")
            return clipboard_get()

        instance.root.clipboard_get = busy_once
        instance._clear_sensitive_code()

        self.assertEqual(instance.root.clipboard, secret)
        self.assertEqual(len(instance.root.scheduled), 1)
        _, retry, args = instance.root.scheduled.pop()
        retry(*args)
        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(attempts, 2)

    def test_clipboard_busy_retry_preserves_later_foreign_value(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard busy")
        )

        instance._clear_sensitive_code()
        _, retry, args = instance.root.scheduled.pop()
        instance.root.clipboard_get = lambda: instance.root.clipboard
        instance.root.clipboard = "user copied this later"
        retry(*args)

        self.assertEqual(instance.root.clipboard, "user copied this later")
        self.assertEqual(instance.root.scheduled, [])

    def test_stale_clipboard_retry_cannot_clear_new_application_write(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard busy")
        )

        instance._clear_sensitive_code()
        _, retry, args = instance.root.scheduled.pop()
        instance.root.clipboard_get = lambda: instance.root.clipboard
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        instance._write_clipboard(secret)
        retry(*args)

        self.assertEqual(instance.root.clipboard, secret)
        self.assertEqual(instance.root.scheduled, [])

    def test_clipboard_busy_cleanup_retry_is_bounded(self) -> None:
        instance = self._event_app()
        instance._current_code = "246810"
        instance.root.clipboard = instance._current_code
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard remains busy")
        )

        instance._clear_sensitive_code()
        for _ in range(10):
            if not instance.root.scheduled:
                break
            _, retry, args = instance.root.scheduled.pop(0)
            retry(*args)
        else:
            self.fail("clipboard cleanup retry must be bounded")

        self.assertEqual(instance.root.clipboard_get.call_count, 4)
        self.assertEqual(instance.root.scheduled, [])

    def test_destroy_waits_for_pending_clipboard_retry_then_clears(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        clipboard_get = instance.root.clipboard_get
        attempts = 0

        def busy_once():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise tk.TclError("clipboard busy")
            return clipboard_get()

        instance.root.clipboard_get = busy_once

        instance._clear_sensitive_code()
        _, retry, args = instance.root.scheduled.pop()
        instance._destroy_window()

        self.assertEqual(instance.root.destroy_calls, 0)
        self.assertFalse(instance._closed)
        retry(*args)

        self.assertEqual(attempts, 2)
        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(instance.root.destroy_calls, 1)
        self.assertTrue(instance._closed)

    def test_destroy_remains_blocked_after_bounded_clipboard_retry_budget(self) -> None:
        instance = self._event_app()
        instance._current_code = "246810"
        instance.root.clipboard = instance._current_code
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard remains busy")
        )

        instance._clear_sensitive_code()
        instance._destroy_window()

        self.assertEqual(instance.root.destroy_calls, 0)
        for attempt in range(2):
            _, retry, args = instance.root.scheduled.pop(0)
            retry(*args)
            self.assertEqual(instance.root.destroy_calls, 0)
            self.assertEqual(instance.root.clipboard_get.call_count, attempt + 2)
        _, final_retry, args = instance.root.scheduled.pop(0)
        final_retry(*args)

        self.assertEqual(instance.root.clipboard_get.call_count, 4)
        self.assertEqual(instance.root.scheduled, [])
        self.assertEqual(instance.root.destroy_calls, 0)
        self.assertFalse(instance._closed)
        self.assertIsNotNone(instance._clipboard_cleanup_failed)
        self.assertIn("再次点击关闭", instance.status_label.values["text"])

    def test_clipboard_sequence_preserves_foreign_same_text(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance._clipboard_owner = (secret, 10)
        instance.root.clipboard = secret

        with mock.patch(
            "platform_desktop.get_clipboard_sequence_number", return_value=11
        ):
            instance._clear_sensitive_code()

        self.assertEqual(instance.root.clipboard, secret)
        self.assertIsNone(instance._clipboard_owner)

    def test_logout_waits_for_referenced_cleanup_and_repeated_expiry_cannot_bypass(self) -> None:
        instance = self._event_app()
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()

        def cleanup() -> None:
            cleanup_started.set()
            self.assertTrue(release_cleanup.wait(timeout=1))

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance.root.clipboard = instance._current_card_clipboard

        instance.logout(message="已完成安全退出。")

        self.assertTrue(cleanup_started.wait(timeout=1))
        self.assertIsNotNone(instance._shutdown_cleanup_thread)
        self.assertFalse(instance._shutdown_cleanup_thread.daemon)
        self.assertEqual(instance._task_id, "task-1")
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(instance.root.clipboard, "")
        self.assertNotEqual(instance.status_label.values["text"], "已完成安全退出。")
        self.assertEqual(instance.login_button.values["state"], "disabled")

        instance.logout(message="不得覆盖原退出意图")
        instance._session_deadline = time.monotonic() - 1
        instance._update_session_countdown(instance._session_generation)
        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")

        release_cleanup.set()
        instance._shutdown_cleanup_thread.join(timeout=1)
        self.assertFalse(instance._shutdown_cleanup_thread.is_alive())
        instance._drain_events()

        self.assertIsNone(instance._task_id)
        self.assertEqual(instance.status_label.values["text"], "已完成安全退出。")
        self.assertEqual(instance.login_button.values["text"], "登录平台")
        self.assertEqual(instance.login_button.values["state"], "normal")

    def test_logout_waits_for_owned_clipboard_cleanup_before_enabling_login(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        clipboard_get = instance.root.clipboard_get
        attempts = 0

        def busy_once():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise tk.TclError("clipboard busy")
            return clipboard_get()

        instance.root.clipboard_get = busy_once
        instance.logout(message="已完成安全退出。")
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(instance.root.clipboard, secret)
        self.assertEqual(instance.login_button.values["state"], "disabled")
        self.assertNotEqual(instance.status_label.values["text"], "已完成安全退出。")

        _, retry, args = instance.root.scheduled.pop(0)
        retry(*args)

        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(instance.login_button.values["text"], "登录平台")
        self.assertEqual(instance.login_button.values["state"], "normal")
        self.assertEqual(instance.status_label.values["text"], "已完成安全退出。")

    def test_logout_clipboard_retry_exhaustion_keeps_login_blocked(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard remains busy")
        )

        instance.logout(message="已完成安全退出。")
        instance._shutdown_cleanup_thread.join(timeout=1)
        for _ in range(3):
            _, retry, args = instance.root.scheduled.pop(0)
            retry(*args)
        instance._drain_events()

        self.assertEqual(instance.root.clipboard, secret)
        self.assertEqual(instance.login_button.values["text"], "重试清除剪贴板")
        self.assertNotEqual(
            instance.login_button.values["command"], instance.open_login_dialog
        )
        self.assertIsNotNone(instance._clipboard_cleanup_failed)

        instance.root.clipboard_get = lambda: instance.root.clipboard
        instance.login_button.values["command"]()

        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(instance.login_button.values["text"], "登录平台")
        self.assertEqual(instance.login_button.values["state"], "normal")
        self.assertEqual(instance.status_label.values["text"], "已完成安全退出。")

    def test_logout_retries_every_failed_sensitive_clipboard_owner(self) -> None:
        instance = self._event_app()
        code = "246810"
        card = "4111111111111111\t12/30"
        trace = "trace-owned"
        instance._current_code = code
        instance._current_card_clipboard = card
        instance._current_trace_clipboard = trace
        instance._clipboard_owner = (code, 10)
        instance.root.clipboard = code
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard remains busy")
        )

        with mock.patch(
            "platform_desktop.get_clipboard_sequence_number", return_value=10
        ):
            instance.logout(message="已完成安全退出。")
            instance._shutdown_cleanup_thread.join(timeout=1)
            for _ in range(9):
                _, retry, args = instance.root.scheduled.pop(0)
                retry(*args)
            instance._drain_events()

            self.assertEqual(instance.root.clipboard, code)
            self.assertEqual(instance.login_button.values["text"], "重试清除剪贴板")

            instance.root.clipboard_get = lambda: instance.root.clipboard
            instance.login_button.values["command"]()

        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(instance.login_button.values["text"], "登录平台")
        self.assertEqual(instance.login_button.values["state"], "normal")
        self.assertEqual(instance.status_label.values["text"], "已完成安全退出。")

    def test_failed_logout_retries_same_captured_cleanup_without_close_bypass(self) -> None:
        instance = self._event_app()
        attempts = []

        def cleanup() -> None:
            attempts.append(f"cleanup-{len(attempts) + 1}")
            if len(attempts) == 1:
                raise PlatformTransportError("raw logout failure")

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup

        instance.logout()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(instance._task_id, "task-1")
        self.assertFalse(instance._closed)
        self.assertEqual(instance.root.destroy_calls, 0)
        self.assertIn("原因：", instance.status_label.values["text"])
        self.assertIn("影响：", instance.status_label.values["text"])
        self.assertIn("下一步：", instance.status_label.values["text"])
        self.assertNotIn("raw logout failure", instance.status_label.values["text"])

        instance.logout()
        instance.close()
        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
        self.assertEqual(attempts, ["cleanup-1"])
        self.assertEqual(instance.root.destroy_calls, 0)

        instance.login_button.values["command"]()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(attempts, ["cleanup-1", "cleanup-2"])
        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
        self.assertIsNone(instance._task_id)
        self.assertFalse(instance._closed)

    def test_close_failure_never_destroys_and_retry_success_destroys_once(self) -> None:
        instance = self._event_app()
        attempts = 0

        def cleanup() -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise PlatformTransportError("raw close failure")

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup

        instance.close()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertFalse(instance._closed)
        self.assertEqual(instance.root.destroy_calls, 0)
        self.assertEqual(instance._task_id, "task-1")
        instance.close()
        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")

        instance.login_button.values["command"]()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(attempts, 2)
        self.assertTrue(instance._closed)
        self.assertEqual(instance.root.destroy_calls, 1)
        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")

    def test_logout_without_active_task_still_completes_session_revocation(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        revoked = mock.Mock()
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = revoked

        instance.logout()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        instance._client.prepare_logout_cleanup.assert_called_once_with(None)
        revoked.assert_called_once_with()
        self.assertEqual(instance.login_button.values["state"], "normal")

    def test_lock_stops_work_and_invalidates_every_async_generation(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance.stop_polling = mock.Mock(
            side_effect=lambda: PlatformDesktopApp.stop_polling(instance)
        )
        poll_cancel = mock.Mock()
        instance._poll_cancel = poll_cancel
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance._current_trace_clipboard = "trace-owned"
        instance._paste_sequence.start(
            instance._current_code, instance._current_card_clipboard
        )
        instance.root.clipboard = instance._current_trace_clipboard
        generations = (
            instance._task_generation,
            instance._poll_generation,
            instance._upload_generation,
            instance._update_generation,
            instance._session_generation,
        )

        instance.lock()

        self.assertTrue(instance._locked)
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        self.assertIsNone(instance._current_trace_clipboard)
        self.assertEqual(instance.root.clipboard, "")
        self.assertEqual(
            (
                instance._task_generation,
                instance._poll_generation,
                instance._upload_generation,
                instance._update_generation,
                instance._session_generation,
            ),
            tuple(value + 1 for value in generations),
        )
        poll_cancel.set.assert_called_once_with()
        instance._close_task_history.assert_called_once_with()
        instance._client.prepare_logout_cleanup.assert_not_called()
        for widget in (
            instance.new_task_button,
            instance.copy_button,
            instance.copy_card_button,
            instance.upload_button,
            instance.history_button,
            instance.check_update_button,
            instance.business_entry,
        ):
            self.assertEqual(widget.values["state"], "disabled")
        self.assertEqual(instance.lock_button.values["text"], "解锁")
        self.assertEqual(instance.auth_label.values["text"], "已锁定")

    def test_lock_preserves_user_owned_clipboard_and_blocks_stale_events(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance.root.clipboard = "user copied this later"
        old_poll_generation = instance._poll_generation
        old_upload_generation = instance._upload_generation

        instance.lock()
        instance._events.put(
            (old_poll_generation, "code", MailCodeSnapshot(status="code_ready", code="135790"))
        )
        instance._events.put(
            (
                old_upload_generation,
                "upload",
                UploadJobSnapshot(
                    id="job-1",
                    task_id="task-1",
                    status="succeeded",
                    business_name="Example Store",
                    policy_version="v1",
                    external_ref=None,
                    error_code=None,
                    created_at="2026-08-20T00:00:00Z",
                    updated_at="2026-08-20T00:00:01Z",
                ),
            )
        )
        instance._drain_events()

        self.assertEqual(instance.root.clipboard, "user copied this later")
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._upload_job_id)
        instance._write_clipboard.assert_not_called()

    @staticmethod
    def _provisioning_race_app(previous_task_id=None):
        created = threading.Event()
        release = threading.Event()

        class Client:
            is_authenticated = True

            def __init__(self):
                self.closed = []

            def begin_task_transition(self, previous_task_id=None):
                transition = TaskTransitionCleanup(self, "captured-access")
                if previous_task_id:
                    transition.attach(previous_task_id)
                self.transition = transition
                return transition

            def create_task(self, *_):
                created.set()
                release.wait(timeout=2)
                return task_snapshot(
                    "task-created-in-flight", "trace-created"
                )

            @staticmethod
            def create_mail_session(_task_id):
                raise AssertionError("cancelled transition must not create a mail session")

            @staticmethod
            def allocate_card(_task_id):
                raise AssertionError("cancelled transition must not allocate a card")

            def _close_task_with_access_token(self, task_id, access_token):
                self.closed.append((task_id, access_token))
                return {"status": "closed"}

            def prepare_logout_cleanup(self, _task_id):
                self.is_authenticated = False
                return lambda: None

        instance = PlatformDesktopBoundaryTests._event_app()
        instance._task_id = previous_task_id
        instance._client = Client()
        instance.create_mail_task()
        if not created.wait(timeout=1):
            raise AssertionError("task provisioning did not reach the barrier")
        return instance, release

    def test_lock_and_logout_compensate_task_created_in_flight(self) -> None:
        for boundary in ("lock", "logout"):
            with self.subTest(boundary=boundary):
                instance, release = self._provisioning_race_app()

                getattr(instance, boundary)()
                release.set()
                instance._task_transition_thread.join(timeout=1)
                if boundary == "logout":
                    instance._shutdown_cleanup_thread.join(timeout=1)
                    instance._drain_events()

                self.assertFalse(instance._task_transition_thread.is_alive())
                self.assertEqual(
                    instance._client.closed,
                    [("task-created-in-flight", "captured-access")],
                )
                self.assertTrue(instance._events.empty())

    def test_logout_during_task_switch_closes_previous_and_new_task_once(self) -> None:
        instance, release = self._provisioning_race_app("task-previous")

        instance.logout()
        release.set()
        instance._task_transition_thread.join(timeout=1)
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(
            instance._client.closed,
            [
                ("task-previous", "captured-access"),
                ("task-created-in-flight", "captured-access"),
            ],
        )

    def test_close_waits_for_non_daemon_provisioning_compensation(self) -> None:
        instance, release = self._provisioning_race_app()
        self.assertFalse(instance._task_transition_thread.daemon)
        cancelled = threading.Event()
        original_cancel = instance._task_transition.cancel

        def cancel():
            result = original_cancel()
            cancelled.set()
            return result

        instance._task_transition.cancel = cancel
        closing = threading.Thread(target=instance.close)
        closing.start()
        self.assertTrue(cancelled.wait(timeout=1))
        release.set()
        closing.join(timeout=1)
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertFalse(closing.is_alive())
        self.assertFalse(instance._task_transition_thread.is_alive())
        self.assertEqual(
            instance._client.closed,
            [("task-created-in-flight", "captured-access")],
        )
        self.assertTrue(instance._closed)

    def test_stale_session_cleanup_is_dispatched_off_the_ui_stack(self) -> None:
        instance = self._event_app()
        instance._task_generation = 2
        transition = mock.Mock()
        cleanup = mock.Mock()
        transition.cancel.return_value = cleanup
        transition.commit.return_value = False
        instance._start_task_cleanup = mock.Mock()
        instance._events.put(
            (
                1,
                "session",
                ("task-1", "trace-1", object(), object(), transition),
            )
        )

        instance._drain_events()

        transition.cancel.assert_called_once_with()
        instance._start_task_cleanup.assert_called_once_with(cleanup)
        cleanup.assert_not_called()

    def test_task_provisioning_rejects_unusable_resource_snapshots(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        valid_session = MailSessionSnapshot(
            id="mail-safe",
            email_masked="m***@example.test",
            status="waiting",
            expires_at=future,
            trace_id="trace-created",
            session_token="s" * 32,
        )
        valid_allocation = CardAllocationSnapshot(
            id="allocation-safe",
            card_masked="411111******1111",
            brand="visa",
            expiry_month=12,
            expiry_year=2030,
            status="active",
            expires_at=future,
            trace_id="trace-created",
        )
        cases = {
            "terminal mail session": (
                MailSessionSnapshot(
                    **{**valid_session.__dict__, "status": "expired"}
                ),
                valid_allocation,
            ),
            "terminal card allocation": (
                valid_session,
                CardAllocationSnapshot(
                    **{**valid_allocation.__dict__, "status": "released"}
                ),
            ),
            "mail expiry without timezone": (
                MailSessionSnapshot(
                    **{
                        **valid_session.__dict__,
                        "expires_at": "2099-01-01T00:00:00",
                    }
                ),
                valid_allocation,
            ),
            "malformed mail expiry": (
                MailSessionSnapshot(
                    **{**valid_session.__dict__, "expires_at": "not-a-time"}
                ),
                valid_allocation,
            ),
            "expired mail lease": (
                MailSessionSnapshot(
                    **{
                        **valid_session.__dict__,
                        "expires_at": "2000-01-01T00:00:00Z",
                    }
                ),
                valid_allocation,
            ),
            "card expiry without timezone": (
                valid_session,
                CardAllocationSnapshot(
                    **{
                        **valid_allocation.__dict__,
                        "expires_at": "2099-01-01T00:00:00",
                    }
                ),
            ),
            "malformed card expiry": (
                valid_session,
                CardAllocationSnapshot(
                    **{**valid_allocation.__dict__, "expires_at": "not-a-time"}
                ),
            ),
            "expired card lease": (
                valid_session,
                CardAllocationSnapshot(
                    **{
                        **valid_allocation.__dict__,
                        "expires_at": "2000-01-01T00:00:00Z",
                    }
                ),
            ),
        }

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        for label, (session, allocation) in cases.items():
            with self.subTest(label=label):
                cleanup = mock.Mock()
                transition = mock.Mock(cancelled=False)
                transition.attach.return_value = None
                transition.cancel.return_value = cleanup
                transition.worker_finished.return_value = None
                client = mock.Mock(is_authenticated=True)
                client.begin_task_transition.return_value = transition
                client.create_task.return_value = task_snapshot(
                    "task-created", "trace-created"
                )
                client.create_mail_session.return_value = session
                client.allocate_card.return_value = allocation
                instance = self._event_app()
                instance._task_id = None
                instance._mail_session_id = None
                instance._mail_session_token = None
                instance._card_allocation_id = None
                instance._client = client
                instance._start_polling = mock.Mock()

                with mock.patch("platform_desktop.threading.Thread", InlineThread):
                    instance.create_mail_task()
                instance._drain_events()

                cleanup.assert_called_once_with()
                transition.commit.assert_not_called()
                self.assertIsNone(instance._task_id)
                self.assertIsNone(instance._mail_session_id)
                self.assertIsNone(instance._mail_session_token)
                self.assertIsNone(instance._card_allocation_id)
                instance._start_polling.assert_not_called()
                self.assertNotEqual(
                    instance.copy_card_button.values.get("state"), "normal"
                )
                status = instance.status_label.values["text"]
                self.assertIn("原因：", status)
                self.assertIn("影响：", status)
                self.assertIn("下一步：", status)
                self.assertNotIn(session.id, status)
                self.assertNotIn(allocation.id, status)

    def test_task_provisioning_rejects_resources_from_another_trace(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        for mismatched_resource in ("mail", "card"):
            with self.subTest(mismatched_resource=mismatched_resource):
                cleanup = mock.Mock()
                transition = mock.Mock(cancelled=False)
                transition.attach.return_value = None
                transition.cancel.return_value = cleanup
                transition.worker_finished.return_value = None
                client = mock.Mock(is_authenticated=True)
                client.begin_task_transition.return_value = transition
                client.create_task.return_value = task_snapshot(
                    "task-created", "trace-created"
                )
                client.create_mail_session.return_value = MailSessionSnapshot(
                    id="mail-safe",
                    email_masked="m***@example.test",
                    status="waiting",
                    expires_at=future,
                    trace_id=(
                        "trace-other"
                        if mismatched_resource == "mail"
                        else "trace-created"
                    ),
                    session_token="s" * 32,
                )
                client.allocate_card.return_value = CardAllocationSnapshot(
                    id="allocation-safe",
                    card_masked="411111******1111",
                    brand="visa",
                    expiry_month=12,
                    expiry_year=2030,
                    status="active",
                    expires_at=future,
                    trace_id=(
                        "trace-other"
                        if mismatched_resource == "card"
                        else "trace-created"
                    ),
                )
                instance = self._event_app()
                instance._task_id = None
                instance._mail_session_id = None
                instance._mail_session_token = None
                instance._card_allocation_id = None
                instance._client = client
                instance._start_polling = mock.Mock()

                with mock.patch("platform_desktop.threading.Thread", InlineThread):
                    instance.create_mail_task()
                instance._drain_events()

                cleanup.assert_called_once_with()
                transition.commit.assert_not_called()
                self.assertIsNone(instance._task_id)
                self.assertIsNone(instance._mail_session_id)
                self.assertIsNone(instance._mail_session_token)
                self.assertIsNone(instance._card_allocation_id)
                instance._start_polling.assert_not_called()

    def test_task_provisioning_accepts_live_resources(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        session = MailSessionSnapshot(
            id="mail-safe",
            email_masked="m***@example.test",
            status="waiting",
            expires_at=future,
            trace_id="trace-created",
            session_token="s" * 32,
        )
        allocation = CardAllocationSnapshot(
            id="allocation-safe",
            card_masked="411111******1111",
            brand="visa",
            expiry_month=12,
            expiry_year=2030,
            status="active",
            expires_at=future,
            trace_id="trace-created",
        )
        transition = mock.Mock(cancelled=False)
        transition.attach.return_value = None
        transition.worker_finished.return_value = None
        transition.commit.return_value = True
        client = mock.Mock(is_authenticated=True)
        client.begin_task_transition.return_value = transition
        client.create_task.return_value = task_snapshot(
            "task-created", "trace-created"
        )
        client.create_mail_session.return_value = session
        client.allocate_card.return_value = allocation
        instance = self._event_app()
        instance._task_id = None
        instance._client = client
        instance._start_polling = mock.Mock()

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance.create_mail_task()
        instance._drain_events()

        transition.commit.assert_called_once_with()
        transition.cancel.assert_not_called()
        self.assertEqual(instance._task_id, "task-created")
        self.assertEqual(instance._mail_session_id, "mail-safe")
        self.assertEqual(instance._card_allocation_id, "allocation-safe")
        instance._start_polling.assert_called_once_with()

    def test_task_creation_thread_start_failure_exposes_safe_recovery(self) -> None:
        cleanup = mock.Mock()
        transition = mock.Mock(cancelled=False)
        transition.cancel.return_value = cleanup
        transition.worker_finished.return_value = None
        client = mock.Mock(is_authenticated=True)
        client.begin_task_transition.return_value = transition
        instance = self._event_app()
        instance._client = client

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.create_mail_task()
            instance._drain_events()

        client.create_task.assert_not_called()
        cleanup.assert_not_called()
        transition.cancel.assert_called_once_with()
        transition.worker_finished.assert_called_once_with()
        self.assertIsNone(instance._task_transition)
        self.assertIsNone(instance._task_transition_thread)
        self.assertIsNotNone(instance._task_compensation)
        self.assertIs(instance._task_compensation.transition, transition)
        self.assertIs(instance._task_compensation.cleanup, cleanup)
        self.assertEqual(instance.new_task_button.values["text"], "重试资源关闭")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    @staticmethod
    def _provisioning_compensation_failure_app(cleanup):
        transition = mock.Mock(cancelled=False)
        transition.attach.return_value = None
        transition.cancel.return_value = cleanup
        transition.worker_finished.return_value = None
        client = mock.Mock(is_authenticated=True)
        client.begin_task_transition.return_value = transition
        client.create_task.return_value = task_snapshot(
            "task-needs-compensation", "trace-needs-compensation"
        )
        client.create_mail_session.side_effect = PlatformProtocolError(
            "raw provisioning failure"
        )
        instance = PlatformDesktopBoundaryTests._event_app()
        instance._task_id = None
        instance._client = client

        instance.create_mail_task()
        instance._task_transition_thread.join(timeout=1)
        instance._drain_events()
        return instance, transition, client

    def test_provisioning_cleanup_failure_retains_barrier_and_blocks_new_task(self) -> None:
        cleanup = mock.Mock(
            side_effect=PlatformTransportError("raw cleanup failure")
        )
        instance, transition, client = self._provisioning_compensation_failure_app(
            cleanup
        )

        self.assertIsNotNone(instance._task_compensation)
        self.assertIs(instance._task_compensation.cleanup, cleanup)
        self.assertIs(instance._task_compensation.transition, transition)
        self.assertEqual(instance.new_task_button.values["text"], "重试资源关闭")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("raw provisioning failure", status)
        self.assertNotIn("raw cleanup failure", status)

        instance.create_mail_task()
        client.begin_task_transition.assert_called_once_with(None)
        self.assertIs(instance._task_compensation.cleanup, cleanup)

        barrier = instance._task_compensation
        instance._retry_task_compensation()
        barrier.thread.join(timeout=1)
        instance._drain_events()
        self.assertIs(instance._task_compensation, barrier)
        self.assertEqual(instance.status_label.values["text"], status)
        self.assertNotIn("raw cleanup failure", instance.status_label.values["text"])

    def test_provisioning_cleanup_retry_reuses_closure_then_restores_new_task(self) -> None:
        attempts = []

        def cleanup():
            attempts.append("same-closure")
            if len(attempts) == 1:
                raise PlatformTransportError("raw first cleanup failure")

        instance, _transition, _client = self._provisioning_compensation_failure_app(
            cleanup
        )
        barrier = instance._task_compensation

        instance._retry_task_compensation()
        barrier.thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(attempts, ["same-closure", "same-closure"])
        self.assertIsNone(instance._task_compensation)
        self.assertEqual(instance.new_task_button.values["text"], "创建邮箱任务")
        self.assertEqual(instance.new_task_button.values["state"], "normal")

    def test_provisioning_cleanup_retry_thread_start_failure_keeps_retry(self) -> None:
        cleanup = mock.Mock(
            side_effect=PlatformTransportError("raw cleanup failure")
        )
        instance, _transition, _client = self._provisioning_compensation_failure_app(
            cleanup
        )
        barrier = instance._task_compensation

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("thread unavailable")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._retry_task_compensation()

        self.assertIs(instance._task_compensation, barrier)
        self.assertFalse(barrier.in_progress)
        self.assertIsNone(barrier.thread)
        self.assertEqual(instance.new_task_button.values["text"], "重试资源关闭")
        self.assertEqual(instance.new_task_button.values["state"], "normal")

    def test_provisioning_cleanup_retry_is_single_flight(self) -> None:
        retry_started = threading.Event()
        release_retry = threading.Event()
        attempts = 0

        def cleanup():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise PlatformTransportError("raw first cleanup failure")
            retry_started.set()
            release_retry.wait(timeout=1)

        instance, _transition, _client = self._provisioning_compensation_failure_app(
            cleanup
        )
        barrier = instance._task_compensation

        instance._retry_task_compensation()
        self.assertTrue(retry_started.wait(timeout=1))
        retry_thread = barrier.thread
        instance._retry_task_compensation()

        self.assertIs(barrier.thread, retry_thread)
        self.assertEqual(attempts, 2)
        release_retry.set()
        retry_thread.join(timeout=1)
        instance._drain_events()
        self.assertIsNone(instance._task_compensation)

    def test_stale_provisioning_compensation_events_do_not_clear_new_barrier(self) -> None:
        cleanup = mock.Mock(
            side_effect=PlatformTransportError("raw cleanup failure")
        )
        instance, _transition, _client = self._provisioning_compensation_failure_app(
            cleanup
        )
        old_barrier = instance._task_compensation
        barrier_type = type(old_barrier)
        new_barrier = barrier_type(
            generation=old_barrier.generation + 1,
            transition=object(),
            cleanup=mock.Mock(),
        )
        instance._task_compensation = new_barrier

        instance._events.put(
            (old_barrier.generation, "task_compensation_succeeded", old_barrier)
        )
        instance._events.put(
            (old_barrier.generation, "task_compensation_error", old_barrier)
        )
        instance._drain_events()

        self.assertIs(instance._task_compensation, new_barrier)
        new_barrier.cleanup.assert_not_called()

    def test_logout_absorbs_pending_provisioning_compensation_barrier(self) -> None:
        attempts = []

        def cleanup():
            attempts.append("same-closure")
            if len(attempts) == 1:
                raise PlatformTransportError("raw first cleanup failure")

        instance, _transition, client = self._provisioning_compensation_failure_app(
            cleanup
        )
        logout_cleanup = mock.Mock()
        client.prepare_logout_cleanup.return_value = logout_cleanup

        instance.logout()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(attempts, ["same-closure", "same-closure"])
        logout_cleanup.assert_called_once_with()
        self.assertIsNone(instance._task_compensation)

    def test_locked_business_commands_never_call_clients(self) -> None:
        instance = self._event_app()
        instance._locked = True
        instance._client = mock.Mock(is_authenticated=True)
        instance._current_code = "246810"
        instance.business_entry.get = mock.Mock(return_value="Example Store")

        instance.create_mail_task()
        instance.show_task_history()
        instance.reveal_card_details()
        instance.submit_upload()
        instance.copy_code()
        instance.check_for_updates()

        instance._client.assert_not_called()
        self.assertEqual(instance._client.method_calls, [])
        instance._update_client.check.assert_not_called()
        instance._write_clipboard.assert_not_called()
        instance.business_entry.get.assert_not_called()

    def test_lock_completes_when_task_compensation_thread_cannot_start(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        cleanup = mock.Mock()
        transition = mock.Mock()
        transition.cancel.return_value = cleanup
        instance._task_transition = transition
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance._current_trace_clipboard = "trace-sensitive"

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.lock()

        transition.cancel.assert_called_once_with()
        cleanup.assert_called_once_with()
        instance.stop_polling.assert_called_once_with()
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        self.assertIsNone(instance._current_trace_clipboard)
        self.assertTrue(instance._locked)
        self.assertEqual(instance.lock_button.values["text"], "解锁")
        self.assertEqual(instance.lock_button.values["state"], "normal")
        for widget in (
            instance.new_task_button,
            instance.close_active_task_button,
            instance.copy_button,
            instance.copy_card_button,
            instance.upload_button,
            instance.history_button,
            instance.check_update_button,
            instance.business_entry,
        ):
            self.assertEqual(widget.values["state"], "disabled")

    def test_task_switch_preparation_failure_clears_sensitive_values_but_keeps_owner(self) -> None:
        code = "246810"
        card = "4111111111111111\t12/30"
        for owned_clipboard in (code, card):
            with self.subTest(owned_clipboard=owned_clipboard):
                instance = self._event_app()
                instance._client = mock.Mock(is_authenticated=True)
                instance._client.begin_task_transition.side_effect = (
                    PlatformAuthenticationRequiredError("raw auth race")
                )
                instance._current_code = code
                instance._current_card_clipboard = card
                instance.root.clipboard = owned_clipboard
                instance.code_label.configure(text=code)
                instance.copy_button.configure(state="normal")

                instance.create_mail_task()

                self.assertIsNone(instance._current_code)
                self.assertIsNone(instance._current_card_clipboard)
                self.assertEqual(instance.root.clipboard, "")
                self.assertEqual(instance.code_label.values["text"], "------")
                self.assertEqual(instance.copy_button.values["state"], "disabled")
                self.assertEqual(instance._task_id, "task-1")
                self.assertEqual(instance._mail_session_id, "mail-1")
                self.assertEqual(
                    instance._mail_session_token, "opaque-session-token"
                )
                self.assertEqual(instance._card_allocation_id, "allocation-1")
                instance._client.begin_task_transition.assert_called_once_with(
                    "task-1"
                )
                self.assertNotIn(
                    "raw auth race", instance.status_label.values["text"]
                )

    def test_unlock_requires_same_identity_and_restores_safe_controls(self) -> None:
        instance = self._event_app()
        profile = {
            "id": "user-1",
            "tenant_id": "tenant-1",
            "email": "operator@example.test",
            "device_id": "device-1",
            "role": "operator",
        }
        instance._client = mock.Mock(is_authenticated=True)
        instance._client.reauthenticate_for_unlock.return_value = profile
        instance._start_polling = mock.Mock()
        instance._poll_upload = mock.Mock()
        instance.lock()

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        with (
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
            mock.patch("platform_desktop.threading.Thread", InlineThread),
        ):
            instance.unlock()
        instance._drain_events()

        self.assertFalse(instance._locked)
        call = instance._client.reauthenticate_for_unlock.call_args
        self.assertEqual(call.kwargs["expected_tenant_id"], "tenant-1")
        self.assertEqual(call.kwargs["expected_user_id"], "user-1")
        self.assertEqual(call.kwargs["expected_device_id"], "device-1")
        self.assertEqual(instance.lock_button.values["text"], "锁定")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        self.assertEqual(instance.copy_button.values["state"], "disabled")
        self.assertEqual(instance.copy_card_button.values["state"], "normal")
        self.assertEqual(instance.business_entry.values["state"], "normal")
        instance._start_polling.assert_called_once_with()

        instance._locked = True
        instance._finish_unlock({**profile, "id": "other-user"})
        self.assertTrue(instance._locked)
        self.assertIn("仍保持锁定", instance.status_label.values["text"])

    def test_unlock_thread_start_failure_restores_retry(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance.lock()

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.unlock()
            instance._drain_events()

        instance._client.reauthenticate_for_unlock.assert_not_called()
        self.assertIsNone(instance._unlock_action)
        self.assertIsNone(instance._unlock_thread)
        self.assertTrue(instance._locked)
        self.assertEqual(instance.lock_button.values["text"], "解锁")
        self.assertEqual(instance.lock_button.values["state"], "normal")
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_close_waits_for_current_unlock_before_logout_cleanup(self) -> None:
        instance = self._event_app()
        unlock_entered = threading.Event()
        release_unlock = threading.Event()
        cleanup_calls = []
        profile = {
            "id": "user-1",
            "tenant_id": "tenant-1",
            "email": "operator@example.test",
            "device_id": "device-1",
            "role": "operator",
        }

        class Client:
            is_authenticated = True

            @staticmethod
            def reauthenticate_for_unlock(*_args, **_kwargs):
                unlock_entered.set()
                release_unlock.wait(timeout=2)
                return profile

            @staticmethod
            def prepare_logout_cleanup(_task_id):
                return lambda: cleanup_calls.append("logout")

        instance._client = Client()
        instance.lock()
        with mock.patch("platform_desktop.webbrowser.open", return_value=True):
            instance.unlock()
        self.assertTrue(unlock_entered.wait(timeout=1))
        unlock_thread = instance._unlock_thread
        try:
            self.assertIsNotNone(unlock_thread)
            self.assertFalse(unlock_thread.daemon)

            instance.close()
            instance._shutdown_cleanup_thread.join(timeout=0.05)

            self.assertTrue(instance._shutdown_cleanup_thread.is_alive())
            self.assertEqual(cleanup_calls, [])
            self.assertEqual(instance.root.destroy_calls, 0)

            release_unlock.set()
            unlock_thread.join(timeout=1)
            instance._shutdown_cleanup_thread.join(timeout=1)
            instance._drain_events()

            self.assertEqual(cleanup_calls, ["logout"])
            self.assertEqual(instance.root.destroy_calls, 1)
        finally:
            release_unlock.set()
            if unlock_thread is not None:
                unlock_thread.join(timeout=1)

    def test_unlock_cleanup_wait_is_bounded_and_stale_finish_is_identity_safe(self) -> None:
        instance = self._event_app()
        logout_cleanup = mock.Mock()
        instance._client = mock.Mock(is_authenticated=True)
        instance._client.prepare_logout_cleanup.return_value = logout_cleanup
        old_action = mock.Mock()
        old_action.cancel = threading.Event()
        blocked_thread = mock.Mock()
        blocked_thread.is_alive.return_value = True
        instance._unlock_action = old_action
        instance._unlock_thread = blocked_thread

        instance.close()
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertTrue(old_action.cancel.is_set())
        blocked_thread.join.assert_called_once_with(10)
        logout_cleanup.assert_not_called()
        self.assertEqual(instance.root.destroy_calls, 0)
        self.assertIsNotNone(instance._shutdown_cleanup_action)
        self.assertEqual(instance.login_button.values["text"], "重试安全清理")
        self.assertNotIn("已安全退出", instance.status_label.values["text"])

        new_action = mock.Mock()
        new_thread = object()
        instance._unlock_action = new_action
        instance._unlock_thread = new_thread
        instance._events.put((0, "unlock_finished", old_action))
        instance._drain_events()

        self.assertIs(instance._unlock_action, new_action)
        self.assertIs(instance._unlock_thread, new_thread)

    def test_locked_session_expiry_still_uses_logout_cleanup_boundary(self) -> None:
        instance = self._event_app()
        instance._locked = True
        instance._session_deadline = time.monotonic() - 1
        instance.logout = mock.Mock()

        instance._update_session_countdown(instance._session_generation)

        instance.logout.assert_called_once_with(
            message="会话已过期，已停止任务并清除临时数据。"
        )

    def test_refresh_thread_start_failure_enters_session_failure_path(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(can_refresh_oidc_session=True)
        instance._session_deadline = time.monotonic() + 30
        instance.logout = mock.Mock()

        class FailingThread:
            def __init__(self, **_kwargs):
                pass

            @staticmethod
            def start():
                raise RuntimeError("cannot start refresh thread")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._update_session_countdown(instance._session_generation)

        self.assertTrue(instance._session_refreshing)
        self.assertTrue(
            any(delay == 1000 for delay, _callback, _args in instance.root.scheduled)
        )
        instance._drain_events()
        self.assertFalse(instance._session_refreshing)
        instance.logout.assert_called_once_with(
            message="安全会话刷新失败，已停止任务并清除临时数据。"
        )

    def test_session_expiry_completes_captured_cleanup_before_success_message(self) -> None:
        instance = self._event_app()
        cleanup = mock.Mock()
        instance._client = mock.Mock(can_refresh_oidc_session=False)
        instance._client.prepare_logout_cleanup.return_value = cleanup
        instance._session_deadline = time.monotonic() - 1

        instance._update_session_countdown(instance._session_generation)

        self.assertIsNotNone(instance._shutdown_cleanup_thread)
        self.assertFalse(instance._shutdown_cleanup_thread.daemon)
        instance._shutdown_cleanup_thread.join(timeout=1)
        instance._drain_events()

        instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
        cleanup.assert_called_once_with()
        self.assertIsNone(instance._task_id)
        self.assertEqual(
            instance.status_label.values["text"],
            "会话已过期，已停止任务并清除临时数据。",
        )

    def test_sensitive_sequence_stops_on_all_desktop_boundaries(self) -> None:
        self.assertIn(
            "self._paste_sequence.stop()",
            inspect.getsource(PlatformDesktopApp.create_mail_task),
        )
        self.assertIn(
            "self._paste_sequence.stop()",
            inspect.getsource(PlatformDesktopApp._begin_session_shutdown),
        )
        shutdown_source = inspect.getsource(PlatformDesktopApp._begin_session_shutdown)
        destroy_source = inspect.getsource(PlatformDesktopApp._destroy_window)
        self.assertIn("self._paste_sequence.stop()", shutdown_source)
        self.assertIn("self._paste_observer.close()", shutdown_source + destroy_source)
        unauthenticated_source = inspect.getsource(
            PlatformDesktopApp._set_authenticated
        )
        self.assertIn("self._clear_sensitive_code()", unauthenticated_source)
        self.assertIn("self._clear_card_details()", unauthenticated_source)

    def test_upload_attempt_reuses_key_after_ambiguous_submission(self) -> None:
        app_instance = object.__new__(PlatformDesktopApp)
        app_instance._upload_idempotency_key = None
        app_instance._upload_business_name = None

        first = app_instance._upload_attempt_key("Example Store")
        retry = app_instance._upload_attempt_key("Example Store")
        changed_payload = app_instance._upload_attempt_key("Another Store")

        self.assertEqual(retry, first)
        self.assertNotEqual(changed_payload, first)
        app_instance._reset_upload_attempt()
        confirmed_retry = app_instance._upload_attempt_key("Another Store")
        self.assertNotEqual(confirmed_retry, changed_payload)

    def test_upload_submission_thread_start_failure_restores_safe_retry(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._verified_task_id = "task-1"
        instance.business_entry = mock.Mock()
        instance.business_entry.get.return_value = "Example Store"

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.submit_upload()
            instance._drain_events()

        instance._client.create_upload_job.assert_not_called()
        self.assertIsNone(instance._upload_submission_action)
        self.assertIsNone(instance._upload_submission_thread)
        self.assertEqual(
            instance.business_entry.configure.call_args.kwargs["state"], "normal"
        )
        self.assertEqual(instance.upload_button.values["text"], "提交上传")
        self.assertEqual(instance.upload_button.values["state"], "normal")
        status = instance.status_label.values["text"]
        for marker in ("原因：", "影响：", "下一步："):
            self.assertIn(marker, status)
        self.assertNotIn("raw thread failure", status)

    def test_ambiguous_upload_submission_freezes_and_recovers_same_request(self) -> None:
        first_started = threading.Event()
        release_first = threading.Event()
        calls = []
        queued = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="queued",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        class Client:
            is_authenticated = True

            @staticmethod
            def create_upload_job(task_id, business_name, idempotency_key):
                calls.append((task_id, business_name, idempotency_key))
                if len(calls) == 1:
                    first_started.set()
                    release_first.wait(timeout=1)
                    raise PlatformTimeoutError("raw timeout detail")
                return queued

        instance = self._event_app()
        instance._client = Client()
        instance._verified_task_id = "task-1"
        instance._upload_idempotency_key = None
        instance._upload_business_name = None
        instance.business_entry = mock.Mock()
        instance.business_entry.get.return_value = "Example Store"

        instance.submit_upload()
        self.assertTrue(first_started.wait(timeout=1))
        first_thread = instance._upload_submission_thread
        instance.submit_upload()
        self.assertIs(instance._upload_submission_thread, first_thread)
        self.assertEqual(len(calls), 1)

        release_first.set()
        first_thread.join(timeout=1)
        instance._drain_events()

        action = instance._upload_submission_action
        self.assertIsNotNone(action)
        self.assertTrue(action.ambiguous)
        self.assertFalse(action.pending)
        self.assertEqual(instance.business_entry.configure.call_args.kwargs["state"], "disabled")
        self.assertEqual(instance.upload_button.values["text"], "确认同一上传状态")
        status = instance.status_label.values["text"]
        for marker in ("原因：", "影响：", "下一步：", "可能已提交", "不得按失败推断"):
            self.assertIn(marker, status)
        self.assertNotIn("raw timeout detail", status)

        instance.business_entry.get.return_value = "Changed Store"
        instance.submit_upload()
        recovery_thread = instance._upload_submission_thread
        recovery_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], calls[0])
        self.assertEqual(calls[1][1], "Example Store")
        self.assertEqual(instance._upload_job_id, "upload-1")
        self.assertIsNone(instance._upload_submission_action)
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        self.assertIn(2000, [delay for delay, _, _ in instance.root.scheduled])

    def test_late_recovered_upload_cannot_bind_after_generation_changes(self) -> None:
        recovery_started = threading.Event()
        release_recovery = threading.Event()
        queued = UploadJobSnapshot(
            id="upload-old",
            task_id="task-1",
            status="queued",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        class Client:
            is_authenticated = True

            @staticmethod
            def create_upload_job(*_):
                recovery_started.set()
                release_recovery.wait(timeout=1)
                return queued

        instance = self._event_app()
        instance._client = Client()
        instance._verified_task_id = "task-1"
        instance.business_entry = mock.Mock()
        instance.business_entry.get.return_value = "Example Store"

        instance.submit_upload()
        self.assertTrue(recovery_started.wait(timeout=1))
        thread = instance._upload_submission_thread
        instance._upload_generation += 1
        instance._task_id = "task-2"
        instance._reset_upload_attempt()
        release_recovery.set()
        thread.join(timeout=1)
        instance._drain_events()

        self.assertIsNone(instance._upload_job_id)
        self.assertNotIn(2000, [delay for delay, _, _ in instance.root.scheduled])

    def test_mismatched_upload_response_stays_ambiguous_and_unbound(self) -> None:
        mismatched = UploadJobSnapshot(
            id="upload-wrong",
            task_id="task-1",
            status="queued",
            business_name="Different Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._client.create_upload_job.return_value = mismatched
        instance._verified_task_id = "task-1"
        instance._upload_idempotency_key = None
        instance._upload_business_name = None
        instance.business_entry = mock.Mock()
        instance.business_entry.get.return_value = "Example Store"

        instance.submit_upload()
        instance._upload_submission_thread.join(timeout=1)
        instance._drain_events()

        self.assertIsNone(instance._upload_job_id)
        self.assertTrue(instance._upload_submission_action.ambiguous)
        self.assertEqual(instance.upload_button.values["text"], "确认同一上传状态")
        self.assertIn("不得按失败推断", instance.status_label.values["text"])
        self.assertNotIn("Different Store", instance.status_label.values["text"])

    def test_upload_poll_thread_start_failure_retries_same_job(self) -> None:
        instance = self._event_app()
        instance._upload_job_id = "upload-1"
        instance._client = mock.Mock()

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._poll_upload()
            instance._drain_events()

        instance._client.get_upload_job.assert_not_called()
        self.assertEqual(instance._upload_job_id, "upload-1")
        self.assertEqual(instance._task_id, "task-1")
        self.assertEqual(instance._upload_business_name, "Example Store")
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        retries = [
            entry
            for entry in instance.root.scheduled
            if entry[0] == 3_000 and entry[1] == instance._poll_upload
        ]
        self.assertEqual(len(retries), 1)
        self.assertIn("继续查询", instance.status_label.values["text"])
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_upload_poll_rejects_each_mismatched_binding_before_enqueue(self) -> None:
        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        mismatches = (
            ("job", "upload-wrong", "task-1", "Example Store"),
            ("task", "upload-1", "task-wrong", "Example Store"),
            ("business", "upload-1", "task-1", "Different Store"),
        )
        for binding, job_id, task_id, business_name in mismatches:
            with self.subTest(binding=binding):
                snapshot = UploadJobSnapshot(
                    id=job_id,
                    task_id=task_id,
                    status="succeeded",
                    business_name=business_name,
                    policy_version="v1",
                    external_ref=None,
                    error_code=None,
                    created_at="2026-08-20T00:00:00Z",
                    updated_at="2026-08-20T00:00:01Z",
                )
                instance = self._event_app()
                instance._upload_job_id = "upload-1"
                instance._client = mock.Mock()
                instance._client.get_upload_job.return_value = snapshot

                with mock.patch("platform_desktop.threading.Thread", InlineThread):
                    instance._poll_upload()

                generation, kind, error = instance._events.get_nowait()
                self.assertEqual(generation, instance._upload_generation)
                self.assertEqual(kind, "upload_poll_error")
                self.assertIsInstance(error, PlatformProtocolError)
                self.assertTrue(instance._events.empty())
                self.assertEqual(instance._upload_job_id, "upload-1")
                self.assertEqual(instance._task_id, "task-1")
                self.assertEqual(instance._upload_business_name, "Example Store")

    def test_upload_poll_protocol_error_fails_closed_without_retry_or_leak(self) -> None:
        instance = self._event_app()
        instance._upload_job_id = "upload-1"
        instance._begin_terminal_task_cleanup = mock.Mock()
        instance._events.put(
            (
                instance._upload_generation,
                "upload_poll_error",
                PlatformProtocolError(
                    "wrong upload-secret task-secret Different Store"
                ),
            )
        )

        instance._drain_events()

        self.assertEqual(instance._upload_job_id, "upload-1")
        self.assertEqual(instance._task_id, "task-1")
        self.assertEqual(instance._upload_business_name, "Example Store")
        instance._begin_terminal_task_cleanup.assert_not_called()
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        self.assertNotIn(3000, [delay for delay, _, _ in instance.root.scheduled])
        status = instance.status_label.values["text"]
        for marker in ("原因：", "影响：", "下一步："):
            self.assertIn(marker, status)
        for secret in ("upload-secret", "task-secret", "Different Store"):
            self.assertNotIn(secret, status)

    def test_matching_upload_poll_response_keeps_normal_status_flow(self) -> None:
        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        snapshot = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="queued",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )
        instance = self._event_app()
        instance._upload_job_id = "upload-1"
        instance._client = mock.Mock()
        instance._client.get_upload_job.return_value = snapshot

        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance._poll_upload()
        instance._drain_events()

        self.assertEqual(instance._upload_job_id, "upload-1")
        self.assertEqual(instance.upload_label.values["text"], "queued")
        self.assertIn(2000, [delay for delay, _, _ in instance.root.scheduled])
        self.assertNotIn(3000, [delay for delay, _, _ in instance.root.scheduled])

    def test_upload_poll_transport_failures_keep_retrying_original_job(self) -> None:
        for error in (
            PlatformTransportError("offline"),
            PlatformTimeoutError("slow"),
        ):
            with self.subTest(error=type(error).__name__):
                instance = self._event_app()
                instance._upload_job_id = "upload-1"
                instance._events.put(
                    (instance._upload_generation, "upload_poll_error", error)
                )

                instance._drain_events()

                self.assertEqual(instance._upload_job_id, "upload-1")
                self.assertEqual(instance.upload_button.values["state"], "disabled")
                self.assertIn(
                    3000, [delay for delay, _, _ in instance.root.scheduled]
                )

    def test_lock_keeps_inflight_upload_single_flight_then_recovers_same_key(self) -> None:
        first_started = threading.Event()
        release_first = threading.Event()
        calls = []
        queued = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="queued",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        class Client:
            is_authenticated = True

            @staticmethod
            def create_upload_job(task_id, business_name, idempotency_key):
                calls.append((task_id, business_name, idempotency_key))
                if len(calls) == 1:
                    first_started.set()
                    release_first.wait(timeout=1)
                return queued

        instance = self._event_app()
        instance._client = Client()
        instance._verified_task_id = "task-1"
        instance._upload_idempotency_key = None
        instance._upload_business_name = None
        instance.business_entry = mock.Mock()
        instance.business_entry.get.return_value = "Example Store"

        instance.submit_upload()
        self.assertTrue(first_started.wait(timeout=1))
        first_thread = instance._upload_submission_thread
        instance.lock()
        instance._locked = False
        instance.submit_upload()
        self.assertEqual(len(calls), 1)

        release_first.set()
        first_thread.join(timeout=1)
        instance._drain_events()

        self.assertIsNone(instance._upload_job_id)
        self.assertTrue(instance._upload_submission_action.ambiguous)
        self.assertFalse(instance._upload_submission_action.pending)
        instance.submit_upload()
        instance._upload_submission_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], calls[0])
        self.assertEqual(instance._upload_job_id, "upload-1")

    def test_upload_poll_failure_cannot_enable_duplicate_submission(self) -> None:
        source = inspect.getsource(PlatformDesktopApp._drain_events)
        self.assertIn('kind == "upload_submit_error"', source)
        self.assertIn('kind == "upload_poll_error"', source)
        poll_branch = source.split('kind == "upload_poll_error"', 1)[1]
        self.assertIn('upload_button.configure(state="disabled")', poll_branch)
        self.assertIn('root.after(3000, self._poll_upload)', poll_branch)
        self.assertIn("请勿重复提交", poll_branch)

    def test_code_ready_stays_disabled_until_code_is_consumed(self) -> None:
        instance = self._event_app()
        instance._schedule_next_poll = mock.Mock()

        instance._events.put(
            (1, "code", MailCodeSnapshot(status="code_ready", code=None))
        )
        instance._drain_events()

        self.assertIsNone(instance._verified_task_id)
        self.assertFalse(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        instance._schedule_next_poll.assert_called_once_with()

        instance._events.put(
            (1, "code", MailCodeSnapshot(status="consumed", code="123456"))
        )
        instance._drain_events()

        self.assertEqual(instance._verified_task_id, "task-1")
        self.assertEqual(instance.upload_button.values["state"], "normal")
        self.assertTrue(instance._current_task_is_verified())

        instance._clear_sensitive_code()

        self.assertIsNone(instance._current_code)
        self.assertTrue(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "normal")

    def test_consumed_code_enables_upload_but_expired_session_resets_it(self) -> None:
        instance = self._event_app()

        instance._events.put(
            (1, "code", MailCodeSnapshot(status="consumed", code=None))
        )
        instance._drain_events()

        self.assertTrue(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "normal")

        instance._events.put(
            (1, "code", MailCodeSnapshot(status="expired", code=None))
        )
        instance._drain_events()

        self.assertFalse(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "disabled")

    def test_mail_polling_captures_capability_and_discards_switched_task_result(self) -> None:
        instance = self._event_app()
        client = mock.Mock()
        client.get_mail_code.return_value = MailCodeSnapshot(
            status="code_ready", code="246810"
        )
        instance._client = client
        workers = []

        class DeferredThread:
            def __init__(self, *, target, **_kwargs):
                workers.append(target)

            @staticmethod
            def start():
                return None

        with mock.patch("platform_desktop.threading.Thread", DeferredThread):
            instance._start_polling()

        instance._mail_session_id = "mail-2"
        instance._mail_session_token = "new-token"
        instance._task_generation += 1
        workers[0]()

        client.get_mail_code.assert_not_called()
        self.assertTrue(instance._events.empty())

    def test_mail_polling_uses_server_selected_interval(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock()
        instance._mail_poll_interval_seconds = 7

        with mock.patch("platform_desktop.threading.Thread"):
            instance._start_polling()
        instance._schedule_next_poll()

        self.assertEqual(instance.root.scheduled[-1][0], 7_000)

    def test_mail_poll_thread_start_failure_schedules_safe_retry_without_request(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock()
        instance._mail_poll_interval_seconds = 7

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._start_polling()

        instance._client.get_mail_code.assert_not_called()
        self.assertEqual(instance._task_id, "task-1")
        self.assertEqual(instance._mail_session_id, "mail-1")
        self.assertEqual(instance._mail_session_token, "opaque-session-token")
        self.assertEqual(instance._poll_retry_attempt, 1)
        retries = [
            entry
            for entry in instance.root.scheduled
            if entry[0] == 7_000 and entry[1] == instance._start_polling
        ]
        self.assertEqual(len(retries), 1)
        self.assertIn("自动重试", instance.status_label.values["text"])
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_transient_poll_error_is_ambiguous_and_never_auto_retries(self) -> None:
        instance = self._event_app()
        instance._events.put(
            (1, "poll_error", PlatformTransportError("offline"))
        )
        instance._drain_events()

        self.assertEqual(instance._poll_retry_attempt, 0)
        self.assertIn("不会自动重试", instance.status_label.values["text"])
        self.assertIn("下一步：", instance.status_label.values["text"])
        self.assertEqual(instance.session_label.values["text"], "读取结果待核对")
        self.assertNotIn(1000, [delay for delay, _, _ in instance.root.scheduled])
        instance.stop_polling.assert_called_once_with()

    def test_focus_loss_blocks_late_code_and_card_events(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._on_focus_out(mock.Mock())
        card = CardRevealSnapshot(
            id="reveal-1",
            allocation_id="allocation-1",
            card_masked="VISA •••• 1111",
            brand="VISA",
            expiry_month=12,
            expiry_year=2030,
            pan="4111111111111111",
            reveal_expires_at="2099-08-21T12:00:05Z",
        )
        instance._events.put(
            (instance._poll_generation, "code", MailCodeSnapshot("code_ready", "246810"))
        )
        instance._events.put((instance._task_generation, "card_reveal", card))

        instance._drain_events()

        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        instance._write_clipboard.assert_not_called()
        self.assertNotIn("246810", str(instance.code_label.values))
        self.assertNotIn("4111111111111111", str(instance.card_reveal_label.values))

    def test_authentication_loss_blocks_queued_code_and_card_events(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        card = CardRevealSnapshot(
            id="reveal-1",
            allocation_id="allocation-1",
            card_masked="VISA •••• 1111",
            brand="VISA",
            expiry_month=12,
            expiry_year=2030,
            pan="4111111111111111",
            reveal_expires_at="2099-08-21T12:00:05Z",
        )
        instance._events.put(
            (
                instance._poll_generation,
                "code",
                MailCodeSnapshot("code_ready", "246810"),
            )
        )
        instance._events.put(
            (instance._task_generation, "card_reveal", card)
        )

        instance._client.is_authenticated = False
        instance._set_authenticated(False)
        instance._drain_events()

        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        instance._write_clipboard.assert_not_called()
        self.assertNotIn("246810", str(instance.code_label.values))
        self.assertNotIn("4111111111111111", str(instance.card_reveal_label.values))

    def test_relogin_drops_queued_code_from_previous_identity(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        old_poll_generation = instance._poll_generation
        instance._events.put(
            (
                old_poll_generation,
                "code",
                MailCodeSnapshot("code_ready", "246810"),
            )
        )
        instance.stop_polling.side_effect = lambda: setattr(
            instance, "_poll_generation", instance._poll_generation + 1
        )
        instance._discover_active_task = mock.Mock()

        instance._on_login_success(
            {
                "id": "user-B",
                "tenant_id": "tenant-B",
                "device_id": "device-B",
                "email": "operator-b@example.test",
            },
            300,
        )
        instance._drain_events()

        self.assertEqual(
            instance._profile_identity,
            ("tenant-B", "user-B", "device-B"),
        )
        self.assertIsNone(instance._current_code)
        instance._write_clipboard.assert_not_called()
        self.assertNotIn("246810", str(instance.code_label.values))

    def test_non_transient_poll_errors_stop_without_retry(self) -> None:
        for error in (
            PlatformProtocolError("bad response"),
            PlatformAuthenticationError(
                "expired",
                code="unauthorized",
                status=401,
                recovery_hint="重新登录后再试",
            ),
        ):
            with self.subTest(error=type(error).__name__):
                instance = self._event_app()
                instance._client = mock.Mock()
                instance._events.put((1, "poll_error", error))
                instance._drain_events()
                self.assertEqual(instance._poll_retry_attempt, 0)
                self.assertNotIn(
                    1000, [delay for delay, _, _ in instance.root.scheduled]
                )
                if isinstance(error, PlatformProtocolError):
                    instance.stop_polling.assert_called_once_with()

    def test_upload_guard_rejects_unverified_current_task(self) -> None:
        class ClientStub:
            is_authenticated = True

            def create_upload_job(self, *_):
                raise AssertionError("unverified upload must not reach the client")

        instance = self._event_app()
        instance._client = ClientStub()
        instance._card_allocation_id = "allocation-1"
        instance.business_entry = mock.Mock()

        instance.submit_upload()

        instance.business_entry.get.assert_not_called()
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        self.assertIn("取得验证码", instance.status_label.values["text"])

    def test_failed_upload_can_retry_only_for_same_verified_task(self) -> None:
        instance = self._event_app()
        instance._verified_task_id = "task-1"
        failed = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="failed",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code="upstream_rejected",
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        instance._events.put((1, "upload", failed))
        instance._drain_events()

        self.assertTrue(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "normal")

        instance._task_id = "task-2"
        instance._events.put((1, "upload", failed))
        instance._drain_events()

        self.assertFalse(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "disabled")

    def test_terminal_cleanup_thread_start_failure_exposes_retry(self) -> None:
        instance = self._event_app()
        cleanup = mock.Mock()
        instance._terminal_task_cleanup_action = cleanup
        instance._terminal_task_cleanup_task_id = "task-1"
        instance._terminal_task_cleanup_outcome = "completed"

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("thread unavailable")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._start_terminal_task_cleanup_attempt()
            instance._drain_events()

        cleanup.assert_not_called()
        self.assertIs(instance._terminal_task_cleanup_action, cleanup)
        self.assertFalse(instance._terminal_task_cleanup_in_progress)
        self.assertIsNone(instance._terminal_task_cleanup_thread)
        self.assertEqual(instance.new_task_button.values["text"], "重试资源关闭")
        self.assertEqual(instance.new_task_button.values["state"], "normal")

    def test_succeeded_upload_blocks_until_same_captured_cleanup_retries(self) -> None:
        instance = self._event_app()
        release_first_attempt = threading.Event()
        attempts = []

        def cleanup() -> None:
            attempts.append("captured-cleanup")
            if len(attempts) == 1:
                release_first_attempt.wait(1)
                raise PlatformTransportError("temporary close failure")

        transition = mock.Mock()
        transition.close.return_value = cleanup
        client = mock.Mock()
        client.is_authenticated = True
        client.begin_task_transition.return_value = transition
        instance._client = client
        succeeded = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="succeeded",
            business_name="Example Store",
            policy_version="v1",
            external_ref="external-1",
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        instance._events.put((1, "upload", succeeded))
        instance._drain_events()

        first_thread = instance._terminal_task_cleanup_thread
        self.assertIsNotNone(first_thread)
        self.assertFalse(first_thread.daemon)
        self.assertTrue(instance._terminal_task_cleanup_in_progress)
        self.assertEqual(instance._task_id, "task-1")
        self.assertIn("正在关闭任务", instance.status_label.values["text"])

        instance._events.put((1, "upload", succeeded))
        instance._drain_events()
        instance.create_mail_task()

        client.begin_task_transition.assert_called_once_with("task-1")
        self.assertIs(instance._terminal_task_cleanup_thread, first_thread)
        self.assertIn("不会创建新任务", instance.status_label.values["text"])

        release_first_attempt.set()
        first_thread.join(1)
        instance._drain_events()

        captured_cleanup = instance._terminal_task_cleanup_action
        self.assertIs(captured_cleanup, cleanup)
        self.assertEqual(instance._task_id, "task-1")
        self.assertIn("原因：", instance.status_label.values["text"])
        self.assertIn("影响：", instance.status_label.values["text"])
        self.assertIn("下一步：", instance.status_label.values["text"])
        self.assertEqual(instance.new_task_button.values["text"], "重试资源关闭")

        instance._retry_terminal_task_cleanup()
        retry_thread = instance._terminal_task_cleanup_thread
        self.assertIsNotNone(retry_thread)
        self.assertFalse(retry_thread.daemon)
        retry_thread.join(1)
        instance._drain_events()

        self.assertEqual(attempts, ["captured-cleanup", "captured-cleanup"])
        transition.close.assert_called_once_with("task-1")
        client.begin_task_transition.assert_called_once_with("task-1")
        self.assertIsNone(instance._task_id)
        self.assertIsNone(instance._terminal_task_cleanup_action)
        self.assertEqual(
            instance.status_label.values["text"],
            "上传完成，任务已关闭并释放资源。",
        )
        self.assertEqual(instance.new_task_button.values["text"], "创建邮箱任务")

    def test_expired_mail_waits_for_terminal_cleanup_before_safe_end(self) -> None:
        instance = self._event_app()
        release_cleanup = threading.Event()

        def cleanup() -> None:
            release_cleanup.wait(1)

        transition = mock.Mock()
        transition.close.return_value = cleanup
        client = mock.Mock()
        client.is_authenticated = True
        client.begin_task_transition.return_value = transition
        instance._client = client
        instance._current_code = "246810"
        instance._current_card_clipboard = "4111111111111111\t12/30"
        instance.card_reveal_label.configure(text="4111 1111 1111 1111 · 12/30")

        instance._events.put(
            (1, "code", MailCodeSnapshot(status="expired", code=None))
        )
        instance._drain_events()

        cleanup_thread = instance._terminal_task_cleanup_thread
        self.assertIsNotNone(cleanup_thread)
        self.assertEqual(instance._task_id, "task-1")
        self.assertNotIn("已关闭并释放", instance.status_label.values["text"])
        self.assertIsNone(instance._current_code)
        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(
            instance.card_reveal_label.values["text"],
            "•••• •••• •••• •••• · --/--",
        )

        release_cleanup.set()
        cleanup_thread.join(1)
        instance._drain_events()

        self.assertIsNone(instance._task_id)
        self.assertEqual(
            instance.status_label.values["text"],
            "邮箱会话已结束，任务已关闭并释放资源。",
        )

    def test_unknown_upload_blocks_resubmission_and_task_boundaries_reset(self) -> None:
        instance = self._event_app()
        instance._verified_task_id = "task-1"
        unknown = UploadJobSnapshot(
            id="upload-1",
            task_id="task-1",
            status="unknown",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:00Z",
            updated_at="2026-08-20T00:00:01Z",
        )

        instance._events.put((1, "upload", unknown))
        instance._drain_events()

        self.assertFalse(instance._current_task_is_verified())
        self.assertEqual(instance.upload_button.values["state"], "disabled")
        self.assertIn("不会自动重试", instance.status_label.values["text"])

        self.assertIn(
            "self._reset_task_verification()",
            inspect.getsource(PlatformDesktopApp.create_mail_task),
        )
        self.assertIn(
            "self._reset_task_verification()",
            inspect.getsource(PlatformDesktopApp._begin_session_shutdown),
        )

    @staticmethod
    def _recovery_snapshot(
        *,
        mail_status="waiting",
        uploads=(),
    ) -> TaskRecoverySnapshot:
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        return TaskRecoverySnapshot(
            task=TaskSnapshot(
                id="task-recovery",
                task_type="mail_code",
                status="created",
                trace_id="trace-recovery",
                created_at="2026-08-20T00:00:00Z",
                expires_at=future,
                closed_at=None,
            ),
            mail_session=TaskTimelineMailSnapshot(
                id="mail-recovery",
                email_masked="m***@example.test",
                status=mail_status,
                expires_at=future,
                consumed_at=(
                    "2026-08-20T00:01:00Z" if mail_status == "consumed" else None
                ),
                created_at="2026-08-20T00:00:01Z",
            ),
            card_allocations=(
                TaskTimelineAllocationSnapshot(
                    id="allocation-recovery",
                    card_masked="**** **** **** 1111",
                    brand="visa",
                    status="active",
                    expires_at=future,
                    released_at=None,
                    created_at="2026-08-20T00:00:02Z",
                ),
            ),
            uploads=tuple(uploads),
        )

    def test_login_discovers_no_active_task_before_enabling_creation(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        client = mock.Mock(is_authenticated=True)
        client.list_tasks.return_value = []
        instance._client = client

        instance._on_login_success(
            {
                "id": "user-1",
                "tenant_id": "tenant-1",
                "device_id": "device-1",
                "email": "operator@example.test",
            },
            300,
        )
        instance._active_task_discovery_thread.join(timeout=1)
        instance._drain_events()

        client.list_tasks.assert_called_once_with(limit=1)
        self.assertIsNone(instance._task_id)
        self.assertEqual(instance.new_task_button.values["text"], "创建邮箱任务")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        self.assertEqual(instance.close_active_task_button.values["state"], "disabled")

    def test_active_task_discovery_thread_start_failure_exposes_retry(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        client = mock.Mock(is_authenticated=True)
        instance._client = client

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._discover_active_task()
            instance._drain_events()

        client.list_tasks.assert_not_called()
        self.assertIsNone(instance._active_task_discovery_action)
        self.assertIsNone(instance._active_task_discovery_thread)
        self.assertTrue(instance._active_task_discovery_required)
        self.assertEqual(instance.new_task_button.values["text"], "重试检查活动任务")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        self.assertEqual(instance.close_active_task_button.values["state"], "disabled")
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_active_task_discovery_requires_explicit_takeover(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        recovery = self._recovery_snapshot()
        client = mock.Mock(is_authenticated=True)
        client.list_tasks.return_value = [recovery.task]
        client.get_task_timeline.return_value = recovery
        instance._client = client

        instance._discover_active_task()
        instance._active_task_discovery_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(instance._task_id, recovery.task.id)
        self.assertIs(instance._active_task_recovery, recovery)
        self.assertEqual(instance.new_task_button.values["text"], "接管活动任务")
        self.assertEqual(instance.close_active_task_button.values["state"], "normal")
        client.create_mail_session.assert_not_called()
        client.allocate_card.assert_not_called()
        client.create_task.assert_not_called()

    def test_explicit_takeover_rotates_capability_once_and_resumes_polling(self) -> None:
        instance = self._event_app()
        instance._task_id = "task-recovery"
        recovery = self._recovery_snapshot()
        instance._active_task_recovery = recovery
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        class Client:
            is_authenticated = True

            def __init__(self):
                self.mail_calls = 0
                self.card_calls = 0

            def begin_task_transition(self, task_id):
                return TaskTransitionCleanup(self, "captured-access")

            @staticmethod
            def get_task_timeline(_task_id):
                return recovery

            def create_mail_session(self, _task_id):
                self.mail_calls += 1
                return MailSessionSnapshot(
                    id="mail-recovery",
                    email_masked="m***@example.test",
                    status="waiting",
                    expires_at=future,
                    trace_id="trace-recovery",
                    session_token="s" * 32,
                )

            def allocate_card(self, _task_id):
                self.card_calls += 1
                return CardAllocationSnapshot(
                    id="allocation-recovery",
                    card_masked="**** **** **** 1111",
                    brand="visa",
                    expiry_month=12,
                    expiry_year=2030,
                    status="active",
                    expires_at=future,
                    trace_id="trace-recovery",
                )

            @staticmethod
            def _close_task_with_access_token(*_):
                raise AssertionError("successful takeover must not close the task")

        client = Client()
        instance._client = client
        instance._start_polling = mock.Mock()

        instance.take_over_active_task()
        instance._task_transition_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(client.mail_calls, 1)
        self.assertEqual(client.card_calls, 1)
        self.assertEqual(instance._task_id, "task-recovery")
        self.assertEqual(instance._mail_session_id, "mail-recovery")
        self.assertEqual(instance._mail_session_token, "s" * 32)
        self.assertEqual(instance._card_allocation_id, "allocation-recovery")
        instance._start_polling.assert_called_once_with()

    def test_unknown_upload_is_review_only_and_never_rotates_or_closes(self) -> None:
        unknown = UploadJobSnapshot(
            id="upload-unknown",
            task_id="task-recovery",
            status="unknown",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code="external_unknown",
            created_at="2026-08-20T00:00:03Z",
            updated_at="2026-08-20T00:00:04Z",
            trace_id="trace-recovery",
        )
        recovery = self._recovery_snapshot(uploads=(unknown,))
        instance = self._event_app()
        instance._task_id = recovery.task.id
        instance._mail_session_id = None
        instance._mail_session_token = None
        instance._card_allocation_id = None
        instance._active_task_recovery = recovery
        client = mock.Mock(is_authenticated=True)
        instance._client = client

        instance._show_discovered_task(recovery)
        instance.take_over_active_task()
        instance.close_active_task()

        self.assertEqual(instance.new_task_button.values["state"], "disabled")
        self.assertEqual(instance.close_active_task_button.values["state"], "disabled")
        client.begin_task_transition.assert_not_called()
        client.create_mail_session.assert_not_called()
        client.close_task.assert_not_called()
        self.assertIn("管理员核对", instance.status_label.values["text"])

    def test_running_upload_takeover_polls_exact_job_without_rotating_mail_token(self) -> None:
        running = UploadJobSnapshot(
            id="upload-running",
            task_id="task-recovery",
            status="running",
            business_name="Example Store",
            policy_version="v1",
            external_ref=None,
            error_code=None,
            created_at="2026-08-20T00:00:03Z",
            updated_at="2026-08-20T00:00:04Z",
            trace_id="trace-recovery",
        )
        recovery = self._recovery_snapshot(uploads=(running,))
        instance = self._event_app()
        instance._task_id = recovery.task.id
        instance._active_task_recovery = recovery

        class Client:
            is_authenticated = True

            def begin_task_transition(self, task_id):
                transition = TaskTransitionCleanup(self, "captured-access")
                transition.attach(task_id)
                return transition

            @staticmethod
            def get_task_timeline(_task_id):
                return recovery

            @staticmethod
            def get_upload_job(job_id):
                if job_id != running.id:
                    raise AssertionError("wrong upload job")
                return running

            @staticmethod
            def create_mail_session(_task_id):
                raise AssertionError("running upload must not rotate mail token")

            @staticmethod
            def allocate_card(_task_id):
                raise AssertionError("running upload must not allocate a card")

            @staticmethod
            def _close_task_with_access_token(*_):
                raise AssertionError("successful takeover must not close the task")

        instance._client = Client()
        instance._poll_upload = mock.Mock()

        instance.take_over_active_task()
        instance._task_transition_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(instance._upload_job_id, running.id)
        self.assertEqual(instance._upload_business_name, running.business_name)
        scheduled = [entry for entry in instance.root.scheduled if entry[1] is instance._poll_upload]
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(instance.upload_button.values["state"], "disabled")

    def test_explicit_close_uses_existing_single_flight_cleanup(self) -> None:
        recovery = self._recovery_snapshot()
        instance = self._event_app()
        instance._task_id = recovery.task.id
        instance._active_task_recovery = recovery
        closed = []

        class Client:
            is_authenticated = True

            def begin_task_transition(self, task_id):
                transition = TaskTransitionCleanup(self, "captured-access")
                transition.attach(task_id)
                return transition

            @staticmethod
            def _close_task_with_access_token(task_id, _token):
                closed.append(task_id)
                return {"status": "closed"}

        instance._client = Client()

        instance.close_active_task()
        instance._terminal_task_cleanup_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(closed, [recovery.task.id])
        self.assertIsNone(instance._task_id)
        self.assertIsNone(instance._active_task_recovery)
        self.assertEqual(instance.close_active_task_button.values["state"], "disabled")

    def test_takeover_read_failure_retains_exact_task_without_mutation(self) -> None:
        instance = self._event_app()
        recovery = self._recovery_snapshot()
        instance._task_id = recovery.task.id
        instance._active_task_recovery = recovery

        class Client:
            is_authenticated = True

            def __init__(self):
                self.closed = []

            def begin_task_transition(self, _task_id):
                return TaskTransitionCleanup(self, "captured-access")

            @staticmethod
            def get_task_timeline(_task_id):
                raise PlatformTransportError("raw offline failure")

            def _close_task_with_access_token(self, task_id, _token):
                self.closed.append(task_id)

        client = Client()
        instance._client = client

        instance.take_over_active_task()
        instance._task_transition_thread.join(timeout=1)
        instance._drain_events()

        self.assertEqual(client.closed, [])
        self.assertEqual(instance._task_id, recovery.task.id)
        self.assertIs(instance._active_task_recovery, recovery)
        self.assertEqual(instance.new_task_button.values["text"], "重试接管活动任务")
        self.assertNotIn("raw offline failure", instance.status_label.values["text"])

    def test_takeover_thread_start_failure_exposes_retry(self) -> None:
        instance = self._event_app()
        recovery = self._recovery_snapshot()
        instance._task_id = recovery.task.id
        instance._active_task_recovery = recovery
        transition = mock.Mock(cancelled=False)
        client = mock.Mock(is_authenticated=True)
        client.begin_task_transition.return_value = transition
        instance._client = client

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.take_over_active_task()
            instance._drain_events()

        client.get_task_timeline.assert_not_called()
        transition.worker_finished.assert_called_once_with()
        transition.cancel.assert_not_called()
        self.assertIsNone(instance._active_task_recovery_action)
        self.assertIsNone(instance._task_transition)
        self.assertIsNone(instance._task_transition_thread)
        self.assertEqual(instance._task_id, recovery.task.id)
        self.assertIs(instance._active_task_recovery, recovery)
        self.assertEqual(instance.new_task_button.values["text"], "重试接管活动任务")
        self.assertEqual(instance.new_task_button.values["state"], "normal")
        self.assertEqual(instance.close_active_task_button.values["state"], "normal")
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_discovery_failure_blocks_direct_task_creation_until_retry(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        client = mock.Mock(is_authenticated=True)
        client.list_tasks.side_effect = PlatformTransportError("raw discovery failure")
        instance._client = client

        instance._discover_active_task()
        instance._active_task_discovery_thread.join(timeout=1)
        instance._drain_events()
        instance.create_mail_task()

        self.assertTrue(instance._active_task_discovery_required)
        client.create_task.assert_not_called()
        self.assertIn("不能创建第二个任务", instance.status_label.values["text"])

    def test_lock_during_takeover_closes_exact_task_and_rejects_stale_result(self) -> None:
        recovery = self._recovery_snapshot()
        entered = threading.Event()
        release = threading.Event()
        closed = threading.Event()

        class Client:
            is_authenticated = True

            def begin_task_transition(self, task_id):
                transition = TaskTransitionCleanup(self, "captured-access")
                transition.attach(task_id)
                return transition

            @staticmethod
            def get_task_timeline(_task_id):
                entered.set()
                release.wait(timeout=2)
                return recovery

            @staticmethod
            def get_upload_job(_job_id):
                raise AssertionError("recovery has no upload")

            @staticmethod
            def create_mail_session(_task_id):
                raise AssertionError("cancelled takeover must not rotate mail token")

            @staticmethod
            def _close_task_with_access_token(task_id, _token):
                if task_id != recovery.task.id:
                    raise AssertionError("wrong cleanup task")
                closed.set()
                return {"status": "closed"}

        instance = self._event_app()
        instance._task_id = recovery.task.id
        instance._mail_session_id = None
        instance._mail_session_token = None
        instance._card_allocation_id = None
        instance._active_task_recovery = recovery
        instance._client = Client()

        instance.take_over_active_task()
        self.assertTrue(entered.wait(timeout=1))
        instance.lock()
        release.set()
        instance._task_transition_thread.join(timeout=1)
        self.assertTrue(closed.wait(timeout=1))
        instance._drain_events()

        self.assertIsNone(instance._mail_session_id)
        self.assertNotEqual(instance.new_task_button.values.get("state"), "normal")

    def test_saved_oidc_session_is_restored_and_refreshed_before_expiry(self) -> None:
        restore_source = inspect.getsource(PlatformDesktopApp._attempt_session_restore)
        countdown_source = inspect.getsource(PlatformDesktopApp._update_session_countdown)
        drain_source = inspect.getsource(PlatformDesktopApp._drain_events)
        self.assertIn("has_saved_refresh_session", restore_source)
        self.assertIn("refresh_oidc_session", restore_source)
        self.assertIn("0 < remaining <= 60", countdown_source)
        self.assertIn("can_refresh_oidc_session", countdown_source)
        self.assertIn('kind == "session_refresh_error"', drain_source)
        self.assertIn("self.logout", drain_source)

    def test_session_restore_thread_start_failure_reenables_login(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock()
        instance._client.has_saved_refresh_session.return_value = True

        class FailingThread:
            def __init__(self, **_kwargs):
                pass

            @staticmethod
            def start():
                raise RuntimeError("cannot start restore thread")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._attempt_session_restore()

        self.assertIsNotNone(instance._session_restore_action)
        instance._drain_events()
        self.assertIsNone(instance._session_restore_action)
        self.assertEqual(instance.login_button.values["state"], "normal")
        self.assertEqual(instance.auth_label.values["text"], "未登录")
        instance._client.clear_access_token.assert_called_once_with()
        self.assertIn("网络中断", instance.status_label.values["text"])

    def test_restore_me_auth_failure_compensates_rotated_session_once(self) -> None:
        instance = self._event_app()

        class RotatingClient:
            def __init__(self):
                self.access_token = None
                self.refresh_token = "R1"
                self.prepare_calls = 0
                self.cleanup_calls = 0

            @property
            def is_authenticated(self):
                return self.access_token is not None

            @staticmethod
            def has_saved_refresh_session():
                return True

            def refresh_oidc_session(self):
                self.access_token = "A2"
                self.refresh_token = "R2"
                return 600

            @staticmethod
            def me():
                raise PlatformAuthenticationError(
                    "raw rotated-token rejection",
                    code="invalid_token",
                    status=401,
                    recovery_hint="重新登录后再试",
                )

            def clear_access_token(self):
                self.access_token = None

            def prepare_logout_cleanup(self, task_id):
                self.prepare_calls += 1
                self.assert_task_id = task_id
                captured = (self.access_token, self.refresh_token)
                self.access_token = None
                self.refresh_token = None

                def cleanup():
                    self.cleanup_calls += 1
                    self.cleaned = captured

                return cleanup

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        client = RotatingClient()
        instance._client = client
        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance._attempt_session_restore()
            instance._drain_events()

        self.assertEqual(client.prepare_calls, 1)
        self.assertIsNone(client.assert_task_id)
        self.assertEqual(client.cleanup_calls, 1)
        self.assertEqual(client.cleaned, ("A2", "R2"))
        self.assertIsNone(client.access_token)
        self.assertIsNone(client.refresh_token)
        self.assertIsNone(instance._session_restore_compensation)
        status = instance.status_label.values["text"]
        for field in ("原因：", "影响：", "下一步："):
            self.assertIn(field, status)
        self.assertNotIn("raw rotated-token rejection", status)

    def test_restore_me_device_failure_uses_same_compensation_path(self) -> None:
        instance = self._event_app()
        state = {"access": None, "refresh": "R1"}
        cleanup = mock.Mock()
        client = mock.Mock()
        client.has_saved_refresh_session.return_value = True

        def refresh():
            state.update(access="A2", refresh="R2")
            return 600

        def prepare(task_id):
            self.assertIsNone(task_id)
            state.update(access=None, refresh=None)
            return cleanup

        client.refresh_oidc_session.side_effect = refresh
        client.me.side_effect = PlatformDeviceAuthorizationError(
            "raw device rejection",
            code="access_denied",
        )
        client.prepare_logout_cleanup.side_effect = prepare
        client.clear_access_token.side_effect = lambda: state.update(access=None)
        instance._client = client

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance._attempt_session_restore()
            instance._drain_events()

        client.prepare_logout_cleanup.assert_called_once_with(None)
        cleanup.assert_called_once_with()
        self.assertEqual(state, {"access": None, "refresh": None})
        self.assertNotIn(
            "raw device rejection",
            instance.status_label.values["text"],
        )

    def test_restore_compensation_failure_retries_same_closure_single_flight(self) -> None:
        instance = self._event_app()
        workers = []

        class DeferredThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                workers.append(self.target)

        class RotatingClient:
            access_token = None
            refresh_token = "R1"
            prepare_calls = 0
            cleanup_calls = 0

            @property
            def is_authenticated(self):
                return self.access_token is not None

            @staticmethod
            def has_saved_refresh_session():
                return True

            def refresh_oidc_session(self):
                self.access_token = "A2"
                self.refresh_token = "R2"
                return 600

            @staticmethod
            def me():
                raise PlatformProtocolError("raw malformed profile", status=200)

            def clear_access_token(self):
                self.access_token = None

            def prepare_logout_cleanup(self, task_id):
                self.prepare_calls += 1
                self.access_token = None
                self.refresh_token = None

                def cleanup():
                    self.cleanup_calls += 1
                    if self.cleanup_calls == 1:
                        raise PlatformTransportError("raw cleanup outage")

                return cleanup

        client = RotatingClient()
        instance._client = client
        with mock.patch("platform_desktop.threading.Thread", DeferredThread):
            instance._attempt_session_restore()
            workers.pop(0)()
            instance._drain_events()
            workers.pop(0)()
            instance._drain_events()

            barrier = instance._session_restore_compensation
            self.assertIsNotNone(barrier)
            status = instance.status_label.values["text"]
            self.assertIn("尚未确认", status)
            self.assertNotIn("raw malformed profile", status)
            self.assertNotIn("raw cleanup outage", status)

            instance._retry_session_restore_compensation()
            instance._retry_session_restore_compensation()
            self.assertEqual(len(workers), 1)
            workers.pop(0)()
            instance._drain_events()

        self.assertEqual(client.prepare_calls, 1)
        self.assertEqual(client.cleanup_calls, 2)
        self.assertIsNone(instance._session_restore_compensation)

    def test_restore_cleanup_preparation_failure_enters_retryable_barrier(self) -> None:
        instance = self._event_app()
        workers = []

        class DeferredThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                workers.append(self.target)

        class RotatingClient:
            access_token = None
            refresh_token = "R1"
            prepare_calls = 0
            cleanup_calls = 0

            @property
            def is_authenticated(self):
                return self.access_token is not None

            @staticmethod
            def has_saved_refresh_session():
                return True

            def refresh_oidc_session(self):
                self.access_token = "A2"
                self.refresh_token = "R2"
                return 600

            @staticmethod
            def me():
                raise PlatformAuthenticationError(
                    "raw identity failure",
                    code="invalid_token",
                    status=401,
                    recovery_hint="重新登录后再试",
                )

            def clear_access_token(self):
                self.access_token = None

            def prepare_logout_cleanup(self, task_id):
                self.prepare_calls += 1
                if self.prepare_calls <= 2:
                    raise PlatformTransportError("raw preparation outage")
                self.access_token = None
                self.refresh_token = None

                def cleanup():
                    self.cleanup_calls += 1

                return cleanup

        client = RotatingClient()
        instance._client = client
        with mock.patch("platform_desktop.threading.Thread", DeferredThread):
            instance._attempt_session_restore()
            workers.pop(0)()
            instance._drain_events()
            workers.pop(0)()
            instance._drain_events()

            barrier = instance._session_restore_compensation
            self.assertIsNotNone(barrier)
            self.assertIsNone(instance._session_restore_action)
            status = instance.status_label.values["text"]
            self.assertIn("尚未确认", status)
            self.assertNotIn("raw identity failure", status)
            self.assertNotIn("raw preparation outage", status)

            instance._retry_session_restore_compensation()
            workers.pop(0)()
            instance._drain_events()

        self.assertEqual(client.prepare_calls, 3)
        self.assertEqual(client.cleanup_calls, 1)
        self.assertIsNone(client.access_token)
        self.assertIsNone(client.refresh_token)
        self.assertIsNone(instance._session_restore_compensation)

    def test_old_restore_compensation_event_cannot_clear_new_session_barrier(self) -> None:
        instance = self._event_app()
        old_barrier = mock.Mock(generation=1)
        new_barrier = mock.Mock(generation=2)
        instance._session_generation = 2
        instance._session_restore_compensation = new_barrier
        instance.auth_label.configure(text="已登录")
        instance._events.put((1, "session_restore_compensation_succeeded", old_barrier))

        instance._drain_events()

        self.assertIs(instance._session_restore_compensation, new_barrier)
        self.assertEqual(instance.auth_label.values["text"], "已登录")

    def test_stale_restore_me_failure_cannot_detach_new_session(self) -> None:
        instance = self._event_app()

        class RotatingClient:
            access_token = None
            refresh_token = "R1"
            prepare_calls = 0

            @property
            def is_authenticated(self):
                return self.access_token is not None

            @staticmethod
            def has_saved_refresh_session():
                return True

            def refresh_oidc_session(self):
                self.access_token = "A2"
                self.refresh_token = "R2"
                return 600

            def me(self):
                self.access_token = "access-B"
                self.refresh_token = "refresh-B"
                instance._on_login_success(
                    {
                        "email": "new@example.test",
                        "tenant_id": "tenant-B",
                        "user_id": "user-B",
                        "device_id": "device-B",
                    },
                    600,
                )
                raise PlatformAuthenticationError(
                    "raw stale rejection",
                    code="invalid_token",
                    status=401,
                    recovery_hint="重新登录后再试",
                )

            def clear_access_token(self):
                self.access_token = None

            def prepare_logout_cleanup(self, task_id):
                self.prepare_calls += 1
                self.access_token = None
                self.refresh_token = None
                return lambda: None

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        client = RotatingClient()
        instance._client = client
        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance._attempt_session_restore()
            instance._drain_events()

        self.assertEqual(client.prepare_calls, 0)
        self.assertEqual(client.access_token, "access-B")
        self.assertEqual(client.refresh_token, "refresh-B")
        self.assertIsNone(instance._session_restore_action)
        self.assertEqual(instance.auth_label.values["text"], "已登录")

    def test_restore_compensation_thread_start_failure_exposes_retry(self) -> None:
        instance = self._event_app()
        cleanup = mock.Mock()
        barrier = _SessionRestoreCompensation(
            generation=instance._session_generation,
            action=object(),
            cleanup=cleanup,
        )
        instance._session_restore_compensation = barrier

        class FailingThread:
            def __init__(self, **_kwargs):
                pass

            @staticmethod
            def start():
                raise RuntimeError("cannot start compensation thread")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._start_session_restore_compensation_attempt(barrier)

        cleanup.assert_not_called()
        self.assertFalse(barrier.in_progress)
        self.assertIsNone(barrier.thread)
        self.assertEqual(instance.login_button.values["text"], "重试安全清理")
        self.assertEqual(instance.login_button.values["state"], "normal")
        self.assertEqual(
            instance.login_button.values["command"],
            instance._retry_session_restore_compensation,
        )

    def test_restore_me_timeout_keeps_rotated_refresh_for_offline_recovery(self) -> None:
        instance = self._event_app()

        class RotatingClient:
            access_token = None
            refresh_token = "R1"
            prepare_calls = 0

            @property
            def is_authenticated(self):
                return self.access_token is not None

            @staticmethod
            def has_saved_refresh_session():
                return True

            def refresh_oidc_session(self):
                self.access_token = "A2"
                self.refresh_token = "R2"
                return 600

            @staticmethod
            def me():
                raise PlatformTimeoutError("raw offline timeout")

            def clear_access_token(self):
                self.access_token = None

            def prepare_logout_cleanup(self, task_id):
                self.prepare_calls += 1
                raise AssertionError("transport failure must preserve refresh")

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        client = RotatingClient()
        instance._client = client
        with mock.patch("platform_desktop.threading.Thread", InlineThread):
            instance._attempt_session_restore()
            instance._drain_events()

        self.assertIsNone(client.access_token)
        self.assertEqual(client.refresh_token, "R2")
        self.assertEqual(client.prepare_calls, 0)
        status = instance.status_label.values["text"]
        for field in ("原因：", "影响：", "下一步："):
            self.assertIn(field, status)
        self.assertIn("长期", status)
        self.assertIn("未撤销", status)
        self.assertNotIn("raw offline timeout", status)

    def test_session_cleanup_takes_over_inflight_restore_compensation_once(self) -> None:
        instance = self._event_app()
        order = []
        restore_cleanup = mock.Mock(
            side_effect=lambda: order.append("restore-cleanup")
        )
        restore_thread = mock.Mock()
        restore_thread.is_alive.return_value = True
        restore_thread.join.side_effect = lambda: order.append("restore-waited")
        barrier = mock.Mock(
            cleanup=restore_cleanup,
            thread=restore_thread,
            in_progress=True,
        )
        instance._session_restore_compensation = barrier
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = (
            lambda: order.append("current-session-cleanup")
        )

        cleanup = instance._capture_session_cleanup(None)

        self.assertIsNone(instance._session_restore_compensation)
        cleanup()
        restore_thread.join.assert_called_once_with()
        restore_cleanup.assert_called_once_with()
        self.assertEqual(
            order,
            ["restore-waited", "restore-cleanup", "current-session-cleanup"],
        )

    def test_failed_restore_compensation_does_not_skip_remaining_cleanup(self) -> None:
        instance = self._event_app()
        order = []

        def restore_cleanup():
            order.append("restore-cleanup")
            raise PlatformTransportError("raw restore cleanup failure")

        instance._session_restore_compensation = mock.Mock(
            cleanup=restore_cleanup,
            thread=None,
            in_progress=False,
        )
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = (
            lambda: order.append("current-session-cleanup")
        )

        cleanup = instance._capture_session_cleanup(None)

        with self.assertRaises(PlatformTransportError):
            cleanup()
        self.assertEqual(
            order,
            ["restore-cleanup", "current-session-cleanup"],
        )
        self.assertIsNone(instance._session_restore_compensation)

    def test_task_history_exposes_trace_and_closes_with_session(self) -> None:
        history_source = inspect.getsource(PlatformDesktopApp.show_task_history)
        render_source = inspect.getsource(PlatformDesktopApp._render_task_history)
        self.assertIn("trace_id（审计追踪）", history_source)
        self.assertIn("list_tasks(limit=50)", history_source + inspect.getsource(PlatformDesktopApp._load_task_history))
        self.assertIn("双击记录或点击按钮复制 trace_id", render_source)
        shutdown_source = inspect.getsource(PlatformDesktopApp._begin_session_shutdown)
        self.assertIn("self._close_task_history()", shutdown_source)

    def test_task_history_thread_start_failure_restores_retry(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._history_window = mock.Mock()
        instance._history_window.winfo_exists.return_value = True
        instance._history_status = RecordingWidget()
        instance._history_refresh_button = RecordingWidget()

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._load_task_history()
            instance._drain_events()

        instance._client.list_tasks.assert_not_called()
        self.assertEqual(
            instance._history_refresh_button.states,
            ["disabled", "normal"],
        )
        self.assertNotIn(
            "raw thread failure", instance._history_status.values["text"]
        )

    def test_task_history_late_closed_window_events_do_not_touch_reopened_window(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        first_window = mock.Mock()
        first_window.winfo_exists.return_value = True
        instance._history_window = first_window
        instance._history_tree = mock.Mock()
        instance._history_status = RecordingWidget()
        instance._history_refresh_button = RecordingWidget()
        workers = []

        class DeferredThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                workers.append(self.target)

        with mock.patch("platform_desktop.threading.Thread", DeferredThread):
            instance._load_task_history()
            PlatformDesktopApp._close_task_history(instance)

            second_window = mock.Mock()
            second_window.winfo_exists.return_value = True
            second_button = RecordingWidget()
            second_status = RecordingWidget()
            instance._history_window = second_window
            instance._history_tree = mock.Mock()
            instance._history_status = second_status
            instance._history_refresh_button = second_button
            instance._load_task_history()

        self.assertEqual(len(workers), 2)
        current_tasks = ["current-window-task"]
        stale_tasks = ["closed-window-task"]
        instance._client.list_tasks.return_value = current_tasks
        workers[1]()
        current_event = instance._events.get_nowait()
        instance._client.list_tasks.return_value = stale_tasks
        workers[0]()
        stale_event = instance._events.get_nowait()

        instance._events.put(current_event)
        instance._events.put(stale_event)
        instance._events.put(
            (
                stale_event[0],
                "task_history_error",
                PlatformTransportError("closed window request failed"),
            )
        )
        instance._render_task_history = mock.Mock()

        instance._drain_events()

        instance._render_task_history.assert_called_once_with(current_tasks)
        self.assertEqual(second_button.states, ["disabled"])
        self.assertEqual(second_status.values["text"], "正在加载…")

    def test_trace_clipboard_ttl_ignores_stale_cleanup_and_clears_latest(self) -> None:
        instance = self._event_app()
        instance._history_tree = mock.Mock()
        instance._history_tree.selection.return_value = ["selected"]
        instance._history_status = RecordingWidget()
        first_trace = "trace-first"
        second_trace = "trace-second"
        instance._history_tree.item.side_effect = [
            ("time", "status", "task-1", first_trace),
            ("time", "status", "task-2", second_trace),
        ]

        instance._copy_selected_trace()
        first_cleanup = instance.root.scheduled[-1]
        self.assertEqual(first_cleanup[0], 60_000)
        instance.root.clipboard = first_trace

        instance._copy_selected_trace()
        second_cleanup = instance.root.scheduled[-1]
        instance.root.clipboard = second_trace

        first_cleanup[1](*first_cleanup[2])
        self.assertEqual(instance.root.clipboard, second_trace)
        self.assertEqual(instance._current_trace_clipboard, second_trace)

        second_cleanup[1](*second_cleanup[2])
        self.assertEqual(instance.root.clipboard, "")
        self.assertIsNone(instance._current_trace_clipboard)
        self.assertEqual(
            instance._history_status.values["text"],
            "trace_id 已复制，60 秒后自动清理。",
        )

    def test_trace_clipboard_lifecycle_clears_only_owned_value(self) -> None:
        instance = self._event_app()
        instance._current_trace_clipboard = "trace-owned"
        instance.root.clipboard = "user copied this later"
        instance._clear_trace_id()
        self.assertEqual(instance.root.clipboard, "user copied this later")

        for cleanup in (
            lambda: PlatformDesktopApp._close_task_history(instance),
            instance._clear_code_if_unfocused,
            lambda: instance._set_authenticated(False),
        ):
            instance._current_trace_clipboard = "trace-owned"
            instance.root.clipboard = "trace-owned"
            instance._history_window = None
            instance._history_tree = None
            instance._history_status = None
            instance._history_refresh_button = None
            cleanup()
            self.assertEqual(instance.root.clipboard, "")
            self.assertIsNone(instance._current_trace_clipboard)

    def test_online_update_uses_background_check_and_verified_helper(self) -> None:
        check_source = inspect.getsource(PlatformDesktopApp.check_for_updates)
        drain_source = inspect.getsource(PlatformDesktopApp._drain_events)
        finish_source = inspect.getsource(
            PlatformDesktopApp._finish_update_cleanup_if_ready
        )
        self.assertIn("self._update_client.check()", check_source)
        self.assertIn('name="platform-update-check"', check_source)
        self.assertIn("launch_update_helper", finish_source)
        self.assertIn("SHA-256", drain_source)

    def test_update_check_thread_start_failure_restores_retry(self) -> None:
        instance = self._event_app()

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance.check_for_updates()
            instance._drain_events()

        instance._update_client.check.assert_not_called()
        self.assertEqual(instance.check_update_button.states, ["disabled", "normal"])
        self.assertEqual(
            instance.status_label.values["text"],
            "检查更新失败，请稍后重试。",
        )
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_update_download_thread_start_failure_restores_retry(self) -> None:
        instance = self._event_app()
        manifest = mock.Mock(version="9.9.9")

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with mock.patch("platform_desktop.threading.Thread", FailingThread):
            instance._download_update(manifest)
            instance._drain_events()

        instance._update_client.download.assert_not_called()
        self.assertEqual(instance.check_update_button.states, ["disabled", "normal"])
        self.assertEqual(
            instance.status_label.values["text"],
            "更新下载或完整性校验失败，未修改当前程序。",
        )
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_update_waits_for_referenced_non_daemon_cleanup_before_helper(self) -> None:
        instance = self._event_app()
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()

        def cleanup() -> None:
            cleanup_started.set()
            self.assertTrue(release_cleanup.wait(timeout=1))

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup
        manifest = mock.Mock(sha256="a" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()

            self.assertTrue(cleanup_started.wait(timeout=1))
            self.assertIsNotNone(instance._update_cleanup_thread)
            self.assertFalse(instance._update_cleanup_thread.daemon)
            self.assertIsNotNone(instance._update_cleanup_action)
            launch_helper.assert_not_called()
            self.assertEqual(instance._task_id, "task-1")
            self.assertIsNone(instance._current_code)
            self.assertIsNone(instance._current_card_clipboard)

            instance.close()
            self.assertFalse(instance._closed)
            self.assertEqual(instance.root.destroy_calls, 0)

            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
            launch_helper.assert_not_called()

            release_cleanup.set()
            instance._update_cleanup_thread.join(timeout=1)
            self.assertFalse(instance._update_cleanup_thread.is_alive())
            instance._drain_events()

            launch_helper.assert_called_once_with(package, manifest.sha256)
            self.assertIsNone(instance._task_id)
            self.assertTrue(instance._update_cleanup_completed)
            self.assertIsNone(instance._pending_update_install)
            install_exit = next(
                callback
                for delay, callback, _args in instance.root.scheduled
                if delay == 200 and callback == instance.close
            )
            install_exit()
            self.assertTrue(instance._closed)
            self.assertEqual(instance.root.destroy_calls, 1)
            instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")

    def test_update_synchronous_clipboard_cleanup_cannot_bypass_remote_cleanup(
        self,
    ) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()

        def cleanup() -> None:
            cleanup_started.set()
            self.assertTrue(release_cleanup.wait(timeout=1))

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup
        manifest = mock.Mock(sha256="f" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()

            self.assertTrue(cleanup_started.wait(timeout=1))
            self.assertIsNotNone(instance._update_cleanup_thread)
            self.assertEqual(instance.root.clipboard, "")
            self.assertEqual(instance._pending_update_install, pending)
            self.assertFalse(instance._update_cleanup_completed)
            launch_helper.assert_not_called()

            release_cleanup.set()
            instance._update_cleanup_thread.join(timeout=1)
            self.assertFalse(instance._update_cleanup_thread.is_alive())
            instance._drain_events()

            launch_helper.assert_called_once_with(package, manifest.sha256)
            self.assertIsNone(instance._pending_update_install)
            self.assertTrue(instance._update_cleanup_completed)

    def test_update_retry_schedule_failure_blocks_helper(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard busy")
        )
        original_after = instance.root.after

        def fail_clipboard_retry(delay, callback, *args):
            if delay == 50:
                raise tk.TclError("window cannot schedule retry")
            return original_after(delay, callback, *args)

        instance.root.after = fail_clipboard_retry
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = lambda: None
        manifest = mock.Mock(sha256="9" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

            launch_helper.assert_not_called()
            self.assertEqual(instance.root.clipboard, secret)
            self.assertIsNotNone(instance._clipboard_cleanup_failed)
            self.assertEqual(instance._pending_update_install, pending)
            self.assertFalse(instance._update_cleanup_completed)

    def test_update_close_schedule_failure_closes_synchronously(self) -> None:
        instance = self._event_app()
        manifest = mock.Mock(sha256="8" * 64)
        package = Path("verified-update.exe")
        instance._pending_update_install = (manifest, package)
        original_after = instance.root.after

        def fail_update_close(delay, callback, *args):
            if delay == 200:
                raise tk.TclError("window cannot schedule update close")
            return original_after(delay, callback, *args)

        instance.root.after = fail_update_close

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._finish_update_cleanup_if_ready()

        launch_helper.assert_called_once_with(package, manifest.sha256)
        self.assertTrue(instance._update_cleanup_completed)
        self.assertIsNone(instance._pending_update_install)
        self.assertTrue(instance._closed)
        self.assertEqual(instance.root.destroy_calls, 1)

    def test_update_cleanup_thread_start_failure_exposes_retry(self) -> None:
        instance = self._event_app()
        manifest = mock.Mock(sha256="7" * 64)
        package = Path("verified-update.exe")
        instance._pending_update_install = (manifest, package)
        instance._update_cleanup_action = mock.Mock()
        instance.check_update_button.configure(state="disabled")

        class FailingThread:
            def __init__(self, **_kwargs):
                pass

            @staticmethod
            def is_alive():
                return False

            @staticmethod
            def start():
                raise RuntimeError("cannot start thread")

        with (
            mock.patch("platform_desktop.threading.Thread", FailingThread),
            mock.patch("platform_desktop.launch_update_helper") as launch_helper,
        ):
            instance._start_update_cleanup_attempt()

        launch_helper.assert_not_called()
        self.assertEqual(instance._pending_update_install, (manifest, package))
        self.assertIsNotNone(instance._update_cleanup_action)
        self.assertFalse(instance._update_cleanup_in_progress)
        self.assertEqual(instance.check_update_button.values["text"], "重试安全清理")
        self.assertEqual(instance.check_update_button.values["state"], "normal")
        self.assertEqual(
            instance.check_update_button.values["command"],
            instance._retry_update_cleanup,
        )

    def test_update_waits_for_owned_clipboard_cleanup_before_helper(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        clipboard_get = instance.root.clipboard_get
        attempts = 0

        def busy_once():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise tk.TclError("clipboard busy")
            return clipboard_get()

        instance.root.clipboard_get = busy_once
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = lambda: None
        manifest = mock.Mock(sha256="d" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

            launch_helper.assert_not_called()
            self.assertEqual(instance._pending_update_install, pending)
            self.assertFalse(instance._update_cleanup_completed)
            self.assertEqual(instance.check_update_button.values["state"], "disabled")

            retry_index = next(
                index
                for index, scheduled in enumerate(instance.root.scheduled)
                if scheduled[0] == 50
            )
            _, retry, args = instance.root.scheduled.pop(retry_index)
            retry(*args)

            launch_helper.assert_called_once_with(package, manifest.sha256)
            self.assertEqual(instance.root.clipboard, "")
            self.assertIsNone(instance._pending_update_install)
            self.assertTrue(instance._update_cleanup_completed)

    def test_update_clipboard_failure_retries_before_helper_and_close(self) -> None:
        instance = self._event_app()
        secret = "246810"
        instance._current_code = secret
        instance.root.clipboard = secret
        instance.root.clipboard_get = mock.Mock(
            side_effect=tk.TclError("clipboard remains busy")
        )
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = lambda: None
        manifest = mock.Mock(sha256="e" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch("platform_desktop.launch_update_helper") as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()
            for _ in range(3):
                retry_index = next(
                    index
                    for index, scheduled in enumerate(instance.root.scheduled)
                    if scheduled[0] == 50
                )
                _, retry, args = instance.root.scheduled.pop(retry_index)
                retry(*args)

            launch_helper.assert_not_called()
            self.assertEqual(instance._pending_update_install, pending)
            self.assertFalse(instance._update_cleanup_completed)
            self.assertEqual(
                instance.check_update_button.values["text"],
                "重试清除剪贴板",
            )
            self.assertEqual(instance.root.destroy_calls, 0)

            instance.root.clipboard_get = lambda: instance.root.clipboard
            instance.check_update_button.values["command"]()

            launch_helper.assert_called_once_with(package, manifest.sha256)
            self.assertEqual(instance.root.clipboard, "")
            close_callback = next(
                callback
                for delay, callback, _args in instance.root.scheduled
                if delay == 200 and callback == instance.close
            )
            close_callback()
            self.assertTrue(instance._closed)
            self.assertEqual(instance.root.destroy_calls, 1)

    def test_update_helper_failure_retries_exact_verified_package(self) -> None:
        instance = self._event_app()
        cleanup = mock.Mock()
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup
        manifest = mock.Mock(sha256="f" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch(
            "platform_desktop.launch_update_helper",
            side_effect=(UpdateError("helper failed"), None),
        ) as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

            self.assertEqual(instance._pending_update_install, pending)
            self.assertFalse(instance._update_cleanup_completed)
            self.assertEqual(
                instance.check_update_button.values["text"],
                "重试启动更新",
            )
            instance.check_update_button.values["command"]()

            self.assertEqual(
                launch_helper.call_args_list,
                [
                    mock.call(package, manifest.sha256),
                    mock.call(package, manifest.sha256),
                ],
            )
            cleanup.assert_called_once_with()
            self.assertIsNone(instance._pending_update_install)
            self.assertTrue(instance._update_cleanup_completed)

    def test_failed_update_cleanup_retries_same_captured_action_before_install(self) -> None:
        instance = self._event_app()
        attempts = []

        def cleanup() -> None:
            attempts.append(f"cleanup-{len(attempts) + 1}")
            if len(attempts) == 1:
                raise PlatformTransportError("raw upstream failure")

        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = cleanup
        manifest = mock.Mock(sha256="b" * 64)
        package = Path("verified-update.exe")
        pending = (manifest, package)

        with mock.patch(
            "platform_desktop.launch_update_helper",
            side_effect=lambda *_: attempts.append("helper"),
        ) as launch_helper:
            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

            launch_helper.assert_not_called()
            self.assertEqual(instance._task_id, "task-1")
            self.assertEqual(instance.root.destroy_calls, 0)
            self.assertIn("原因：", instance.status_label.values["text"])
            self.assertIn("影响：", instance.status_label.values["text"])
            self.assertIn("下一步：", instance.status_label.values["text"])
            self.assertNotIn("raw upstream failure", instance.status_label.values["text"])
            self.assertEqual(
                instance.check_update_button.values["text"], "重试安全清理"
            )

            instance._events.put(
                (instance._update_generation, "update_downloaded", pending)
            )
            instance._drain_events()
            instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
            self.assertEqual(attempts, ["cleanup-1"])
            launch_helper.assert_not_called()

            instance.close()
            self.assertFalse(instance._closed)
            self.assertEqual(instance.root.destroy_calls, 0)

            instance.check_update_button.values["command"]()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

            self.assertEqual(attempts, ["cleanup-1", "cleanup-2", "helper"])
            instance._client.prepare_logout_cleanup.assert_called_once_with("task-1")
            launch_helper.assert_called_once_with(package, manifest.sha256)
            self.assertIsNone(instance._task_id)

    def test_update_without_active_task_still_runs_session_cleanup_before_helper(self) -> None:
        instance = self._event_app()
        instance._task_id = None
        order = []
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = lambda: order.append(
            "session-cleanup"
        )
        manifest = mock.Mock(sha256="c" * 64)
        package = Path("verified-update.exe")

        with mock.patch(
            "platform_desktop.launch_update_helper",
            side_effect=lambda *_: order.append("helper"),
        ):
            instance._events.put(
                (
                    instance._update_generation,
                    "update_downloaded",
                    (manifest, package),
                )
            )
            instance._drain_events()
            instance._update_cleanup_thread.join(timeout=1)
            instance._drain_events()

        instance._client.prepare_logout_cleanup.assert_called_once_with(None)
        self.assertEqual(order, ["session-cleanup", "helper"])

    def test_card_clipboard_format_never_includes_cvv(self) -> None:
        snapshot = CardRevealSnapshot(
            id="reveal-1",
            allocation_id="allocation-1",
            card_masked="VISA •••• 1111",
            brand="VISA",
            expiry_month=12,
            expiry_year=2030,
            pan="4111111111111111",
            reveal_expires_at="2026-08-20T00:01:00Z",
        )

        formatted = PlatformDesktopApp._format_card_details(snapshot)

        self.assertEqual(formatted, "4111111111111111\t12/30")

    def test_card_reveal_cleanup_delay_obeys_authoritative_expiry(self) -> None:
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)

        self.assertEqual(
            PlatformDesktopApp._card_reveal_cleanup_delay_ms(
                (now + timedelta(seconds=5)).isoformat(), now=now
            ),
            5_000,
        )
        self.assertEqual(
            PlatformDesktopApp._card_reveal_cleanup_delay_ms(
                (now + timedelta(seconds=300)).isoformat(), now=now
            ),
            60_000,
        )
        for invalid in (
            (now - timedelta(milliseconds=1)).isoformat(),
            "2026-08-21T12:00:05",
            " 2026-08-21T12:00:05Z",
            "not-a-timestamp",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(
                    PlatformDesktopApp._card_reveal_cleanup_delay_ms(
                        invalid, now=now
                    )
                )

    def test_expired_or_invalid_card_reveal_never_reaches_local_pan_state(self) -> None:
        for invalid in (
            "2000-01-01T00:00:00Z",
            "2026-08-21T12:00:05",
            "not-a-timestamp",
        ):
            with self.subTest(invalid=invalid):
                instance = self._event_app()
                instance._client = mock.Mock(is_authenticated=True)
                instance._paste_sequence = mock.Mock()
                snapshot = CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id="allocation-1",
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at=invalid,
                )

                instance._events.put(
                    (instance._task_generation, "card_reveal", snapshot)
                )
                instance._drain_events()

                instance._write_clipboard.assert_not_called()
                instance._paste_sequence.offer_card.assert_not_called()
                instance._schedule_card_cleanup.assert_not_called()
                self.assertIsNone(instance._current_card_clipboard)
                self.assertEqual(instance.copy_card_button.values["state"], "normal")
                status = instance.status_label.values["text"]
                self.assertIn("原因：", status)
                self.assertIn("影响：", status)
                self.assertIn("下一步：", status)

    def test_valid_card_reveal_uses_server_bounded_cleanup_delay(self) -> None:
        instance = self._event_app()
        snapshot = CardRevealSnapshot(
            id="reveal-1",
            allocation_id="allocation-1",
            card_masked="VISA •••• 1111",
            brand="VISA",
            expiry_month=12,
            expiry_year=2030,
            pan="4111111111111111",
            reveal_expires_at="2026-08-21T12:00:05Z",
        )

        with mock.patch.object(
            PlatformDesktopApp,
            "_card_reveal_cleanup_delay_ms",
            return_value=5_000,
        ):
            instance._events.put(
                (instance._task_generation, "card_reveal", snapshot)
            )
            instance._drain_events()

        instance._write_clipboard.assert_called_once_with(
            "4111111111111111\t12/30"
        )
        instance._schedule_card_cleanup.assert_called_once_with(5_000)
        self.assertEqual(
            instance.card_reveal_label.values["text"],
            "4111 1111 1111 1111 · 12/30",
        )

        instance._clear_card_details()
        self.assertEqual(
            instance.card_reveal_label.values["text"],
            "•••• •••• •••• •••• · --/--",
        )

    def test_card_reveal_clipboard_failure_clears_details_and_restores_reveal(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)
        instance._write_clipboard = PlatformDesktopApp._write_clipboard.__get__(
            instance
        )
        instance.root.clipboard = "foreign clipboard value"
        instance.root.clipboard_clear = mock.Mock(
            side_effect=tk.TclError("card reveal raw failure")
        )
        snapshot = CardRevealSnapshot(
            id="reveal-1",
            allocation_id="allocation-1",
            card_masked="VISA •••• 1111",
            brand="VISA",
            expiry_month=12,
            expiry_year=2030,
            pan="4111111111111111",
            reveal_expires_at="2026-08-21T12:00:05Z",
        )

        with mock.patch.object(
            PlatformDesktopApp,
            "_card_reveal_cleanup_delay_ms",
            return_value=5_000,
        ):
            instance._events.put(
                (instance._task_generation, "card_reveal", snapshot)
            )
            instance._drain_events()

        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("card reveal raw failure", status)
        self.assertNotIn("已复制", status)
        self.assertEqual(instance.root.clipboard, "foreign clipboard value")
        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(instance._paste_sequence.stage, PasteStage.STOPPED)
        self.assertEqual(instance.copy_card_button.values["state"], "normal")
        instance._schedule_card_cleanup.assert_not_called()

    def test_stale_card_cleanup_timer_cannot_clear_newer_reveal(self) -> None:
        instance = self._event_app()
        instance._schedule_card_cleanup = (
            PlatformDesktopApp._schedule_card_cleanup.__get__(instance)
        )
        first = "4111111111111111\t12/30"
        second = "5555555555554444\t01/31"

        instance._current_card_clipboard = first
        instance.root.clipboard = first
        instance._schedule_card_cleanup(5_000)
        first_cleanup = instance.root.scheduled[-1][1]

        instance._current_card_clipboard = second
        instance.root.clipboard = second
        instance._schedule_card_cleanup(5_000)
        second_cleanup = instance.root.scheduled[-1][1]

        first_cleanup()
        self.assertEqual(instance._current_card_clipboard, second)
        self.assertEqual(instance.root.clipboard, second)

        second_cleanup()
        self.assertIsNone(instance._current_card_clipboard)
        self.assertEqual(instance.root.clipboard, "")

    def test_card_reveal_is_single_flight_and_cancelled_confirmation_releases_it(self) -> None:
        challenge_entered = threading.Event()
        release_challenge = threading.Event()
        calls = []

        class Client:
            is_authenticated = True

            def create_card_reveal_challenge(self, allocation_id):
                calls.append(("challenge", allocation_id))
                challenge_entered.set()
                release_challenge.wait(timeout=2)
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(*_, **__):
                return StepUpAuthorization(access_token="step-up", expires_in=120)

            @staticmethod
            def create_card_reveal_grant(*_):
                return CardRevealGrant(
                    reveal_grant="grant-1", expires_at="2026-08-20T00:01:00Z"
                )

            @staticmethod
            def reveal_card_allocation(allocation_id, _grant):
                return CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id=allocation_id,
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at="2026-08-20T00:01:00Z",
                )

        instance = self._event_app()
        instance._client = Client()
        with (
            mock.patch("platform_desktop.messagebox.askyesno", return_value=True) as confirm,
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
        ):
            instance.reveal_card_details()
            self.assertTrue(challenge_entered.wait(timeout=1))
            action = instance._card_reveal_action
            thread = instance._card_reveal_thread
            instance.reveal_card_details()
            self.assertIs(instance._card_reveal_action, action)
            self.assertIs(instance._card_reveal_thread, thread)
            confirm.assert_called_once_with(
                mock.ANY, mock.ANY, parent=instance.root
            )
            self.assertFalse(thread.daemon)
            release_challenge.set()
            thread.join(timeout=1)

        self.assertEqual(calls, [("challenge", "allocation-1")])

        cancelled = self._event_app()
        cancelled._client = Client()
        with mock.patch(
            "platform_desktop.messagebox.askyesno", return_value=False
        ) as confirm:
            cancelled.reveal_card_details()
            cancelled.reveal_card_details()
        self.assertEqual(confirm.call_count, 2)
        self.assertIsNone(cancelled._card_reveal_action)
        self.assertIsNone(cancelled._card_reveal_thread)

    def test_card_reveal_thread_start_failure_restores_retry(self) -> None:
        instance = self._event_app()
        instance._client = mock.Mock(is_authenticated=True)

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start() -> None:
                raise RuntimeError("raw thread failure")

        with (
            mock.patch("platform_desktop.messagebox.askyesno", return_value=True),
            mock.patch("platform_desktop.threading.Thread", FailingThread),
        ):
            instance.reveal_card_details()
            instance._drain_events()

        instance._client.create_card_reveal_challenge.assert_not_called()
        self.assertIsNone(instance._card_reveal_action)
        self.assertIsNone(instance._card_reveal_thread)
        self.assertEqual(instance.copy_card_button.values["state"], "normal")
        self.assertNotIn("raw thread failure", instance.status_label.values["text"])

    def test_card_reveal_lock_after_step_up_prevents_grant_and_reveal(self) -> None:
        step_up_entered = threading.Event()
        release_step_up = threading.Event()
        grant_calls = []
        reveal_calls = []

        class Client:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(on_authorization_url, **_):
                on_authorization_url("https://identity.example.test/step-up")
                step_up_entered.set()
                release_step_up.wait(timeout=2)
                return StepUpAuthorization(access_token="step-up", expires_in=120)

            @staticmethod
            def create_card_reveal_grant(*args):
                grant_calls.append(args)
                raise AssertionError("locked reveal must not create a grant")

            @staticmethod
            def reveal_card_allocation(*args):
                reveal_calls.append(args)
                raise AssertionError("locked reveal must not request card details")

        instance = self._event_app()
        instance._client = Client()
        with (
            mock.patch("platform_desktop.messagebox.askyesno", return_value=True),
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
        ):
            instance.reveal_card_details()
            thread = instance._card_reveal_thread
            self.assertTrue(step_up_entered.wait(timeout=1))
            instance.lock()
            release_step_up.set()
            thread.join(timeout=1)
            instance._drain_events()

        self.assertEqual(grant_calls, [])
        self.assertEqual(reveal_calls, [])
        self.assertIsNone(instance._card_reveal_action)

    def test_card_reveal_logout_after_grant_prevents_reveal(self) -> None:
        grant_entered = threading.Event()
        release_grant = threading.Event()
        reveal_calls = []
        cleanup_calls = []

        class Client:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(*_, **__):
                return StepUpAuthorization(access_token="step-up", expires_in=120)

            @staticmethod
            def create_card_reveal_grant(*_):
                grant_entered.set()
                release_grant.wait(timeout=2)
                return CardRevealGrant(
                    reveal_grant="grant-1", expires_at="2026-08-20T00:01:00Z"
                )

            @staticmethod
            def reveal_card_allocation(*args):
                reveal_calls.append(args)
                raise AssertionError("logout reveal must not request card details")

            @staticmethod
            def prepare_logout_cleanup(_task_id):
                return lambda: cleanup_calls.append("logout")

        instance = self._event_app()
        instance._client = Client()
        with mock.patch("platform_desktop.messagebox.askyesno", return_value=True):
            instance.reveal_card_details()
            reveal_thread = instance._card_reveal_thread
            self.assertTrue(grant_entered.wait(timeout=1))
            instance.logout()
            self.assertTrue(instance._shutdown_cleanup_thread.is_alive())
            self.assertEqual(cleanup_calls, [])
            release_grant.set()
            reveal_thread.join(timeout=1)
            instance._shutdown_cleanup_thread.join(timeout=1)
            instance._drain_events()

        self.assertEqual(reveal_calls, [])
        self.assertEqual(cleanup_calls, ["logout"])
        self.assertIsNone(instance._card_reveal_action)

    def test_card_reveal_close_waits_for_inflight_reveal_before_cleanup(self) -> None:
        reveal_entered = threading.Event()
        release_reveal = threading.Event()
        cleanup_calls = []

        class Client:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(*_, **__):
                return StepUpAuthorization(access_token="step-up", expires_in=120)

            @staticmethod
            def create_card_reveal_grant(*_):
                return CardRevealGrant(
                    reveal_grant="grant-1", expires_at="2026-08-20T00:01:00Z"
                )

            @staticmethod
            def reveal_card_allocation(allocation_id, _grant):
                reveal_entered.set()
                release_reveal.wait(timeout=2)
                return CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id=allocation_id,
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def prepare_logout_cleanup(_task_id):
                return lambda: cleanup_calls.append("logout")

        instance = self._event_app()
        instance._client = Client()
        with mock.patch("platform_desktop.messagebox.askyesno", return_value=True):
            instance.reveal_card_details()
            reveal_thread = instance._card_reveal_thread
            self.assertTrue(reveal_entered.wait(timeout=1))
            instance.close()
            self.assertTrue(instance._shutdown_cleanup_thread.is_alive())
            self.assertEqual(cleanup_calls, [])
            self.assertEqual(instance.root.destroy_calls, 0)
            release_reveal.set()
            reveal_thread.join(timeout=1)
            instance._shutdown_cleanup_thread.join(timeout=1)
            instance._drain_events()

        self.assertEqual(cleanup_calls, ["logout"])
        self.assertEqual(instance.root.destroy_calls, 1)
        instance._write_clipboard.assert_not_called()

    def test_card_reveal_cleanup_wait_is_bounded_and_stale_finish_cannot_clear_new_action(self) -> None:
        instance = self._event_app()
        logout_cleanup = mock.Mock()
        instance._client = mock.Mock()
        instance._client.prepare_logout_cleanup.return_value = logout_cleanup
        reveal_thread = mock.Mock()
        reveal_thread.is_alive.return_value = True
        instance._card_reveal_thread = reveal_thread

        cleanup = instance._capture_session_cleanup("task-1")
        with self.assertRaises(PlatformTimeoutError):
            cleanup()
        reveal_thread.join.assert_called_once_with(10)
        logout_cleanup.assert_not_called()

        old_action = object()
        new_action = object()
        new_thread = object()
        instance._card_reveal_action = new_action
        instance._card_reveal_thread = new_thread
        instance._events.put((1, "card_reveal_finished", (old_action, False)))
        instance._drain_events()
        self.assertIs(instance._card_reveal_action, new_action)
        self.assertIs(instance._card_reveal_thread, new_thread)

    def test_card_reveal_rejects_snapshot_for_another_allocation(self) -> None:
        wrong_pan = "5555555555554444"
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        class Client:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at=future,
                )

            @staticmethod
            def reauthenticate_for_card_reveal(on_authorization_url, **_):
                on_authorization_url("https://identity.example.test/step-up")
                return StepUpAuthorization(access_token="step-up", expires_in=120)

            @staticmethod
            def create_card_reveal_grant(*_):
                return CardRevealGrant(reveal_grant="grant-1", expires_at=future)

            @staticmethod
            def reveal_card_allocation(_allocation_id, _grant):
                return CardRevealSnapshot(
                    id="reveal-wrong",
                    allocation_id="allocation-other",
                    card_masked="MASTERCARD •••• 4444",
                    brand="MASTERCARD",
                    expiry_month=11,
                    expiry_year=2031,
                    pan=wrong_pan,
                    reveal_expires_at=future,
                )

        instance = self._event_app()
        instance._client = Client()
        with (
            mock.patch("platform_desktop.messagebox.askyesno", return_value=True),
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
        ):
            instance.reveal_card_details()
            instance._card_reveal_thread.join(timeout=1)
        instance._drain_events()

        self.assertIsNone(instance._current_card_clipboard)
        instance._write_clipboard.assert_not_called()
        instance._schedule_card_cleanup.assert_not_called()
        self.assertEqual(instance.copy_card_button.values["state"], "normal")
        status = instance.status_label.values["text"]
        self.assertIn("原因：", status)
        self.assertIn("影响：", status)
        self.assertIn("下一步：", status)
        self.assertNotIn("allocation-1", status)
        self.assertNotIn("allocation-other", status)
        self.assertNotIn(wrong_pan, status)

    def test_card_reveal_confirms_then_runs_step_up_grant_chain(self) -> None:
        calls = []

        class FakeWidget:
            def __init__(self):
                self.states = []

            def configure(self, **values):
                self.states.append(values)

        class FakeClient:
            is_authenticated = True

            def create_card_reveal_challenge(self, allocation_id):
                calls.append(("challenge", allocation_id))
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2026-08-20T00:01:00Z",
                )

            def reauthenticate_for_card_reveal(
                self, on_authorization_url, *, acr_values, cancelled
            ):
                calls.append(("step_up", acr_values))
                self.assertFalse(cancelled())
                on_authorization_url("https://identity.example.test/step-up")
                return StepUpAuthorization(
                    access_token="step-up-access", expires_in=120
                )

            def create_card_reveal_grant(
                self, allocation_id, challenge_id, step_up_access_token
            ):
                calls.append(
                    (
                        "grant",
                        allocation_id,
                        challenge_id,
                        step_up_access_token,
                    )
                )
                return CardRevealGrant(
                    reveal_grant="opaque-grant",
                    expires_at="2026-08-20T00:01:00Z",
                )

            def reveal_card_allocation(self, allocation_id, reveal_grant):
                calls.append(("reveal", allocation_id, reveal_grant))
                return CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id=allocation_id,
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at="2026-08-20T00:01:00Z",
                )

            @staticmethod
            def assertFalse(value):
                if value:
                    raise AssertionError(f"expected false, got {value!r}")

        instance = object.__new__(PlatformDesktopApp)
        instance._locked = False
        instance._client = FakeClient()
        instance._card_allocation_id = "allocation-1"
        instance._task_generation = 7
        instance._closed = False
        instance._card_reveal_action = None
        instance._card_reveal_thread = None
        instance._sensitive_focus = threading.Event()
        instance._sensitive_focus.set()
        instance._events = queue.Queue()
        instance.root = object()
        instance.copy_card_button = FakeWidget()
        instance.status_label = FakeWidget()

        with (
            mock.patch(
                "platform_desktop.messagebox.askyesno", return_value=True
            ) as confirm,
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
        ):
            instance.reveal_card_details()
            instance._card_reveal_thread.join(timeout=1)

        confirm.assert_called_once()
        self.assertFalse(instance._card_reveal_thread.daemon)
        self.assertFalse(instance._card_reveal_thread.is_alive())
        confirmation_text = confirm.call_args.args[1]
        self.assertIn("MFA", confirmation_text)
        self.assertIn("不包含 CVV", confirmation_text)
        self.assertEqual(
            calls,
            [
                ("challenge", "allocation-1"),
                ("step_up", "urn:email-platform:acr:mfa"),
                (
                    "grant",
                    "allocation-1",
                    "challenge-1",
                    "step-up-access",
                ),
                ("reveal", "allocation-1", "opaque-grant"),
            ],
        )
        event_kinds = [instance._events.get_nowait()[1] for _ in range(3)]
        self.assertEqual(
            event_kinds,
            ["card_reveal_authorizing", "card_reveal", "card_reveal_finished"],
        )
        self.assertIn({"state": "disabled"}, instance.copy_card_button.states)

    def test_card_reveal_waits_for_focus_before_consuming_one_shot_grant(self) -> None:
        grant_created = threading.Event()
        reveal_called = threading.Event()
        instance = self._event_app()

        class ClientStub:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    challenge_id="challenge-1",
                    acr_values="urn:email-platform:acr:mfa",
                    expires_at="2099-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(
                on_authorization_url, *, acr_values, cancelled
            ):
                on_authorization_url("https://identity.example.test/step-up")
                instance._sensitive_focus.clear()
                return StepUpAuthorization("step-up-access", 120)

            @staticmethod
            def create_card_reveal_grant(*_args):
                grant_created.set()
                return CardRevealGrant("one-shot-grant", "2099-08-20T00:01:00Z")

            @staticmethod
            def reveal_card_allocation(_allocation_id, _grant):
                reveal_called.set()
                return CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id="allocation-1",
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at="2099-08-20T00:01:00Z",
                )

        instance._client = ClientStub()
        with (
            mock.patch("platform_desktop.messagebox.askyesno", return_value=True),
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
        ):
            instance.reveal_card_details()
            self.assertTrue(grant_created.wait(1))
            self.assertFalse(reveal_called.wait(0.05))
            instance._on_focus_in(mock.Mock())
            instance._card_reveal_thread.join(1)

        self.assertTrue(reveal_called.is_set())
        self.assertFalse(instance._card_reveal_thread.is_alive())

    def test_focus_loss_during_reveal_response_discards_pan(self) -> None:
        reveal_started = threading.Event()
        release_reveal = threading.Event()
        instance = self._event_app()

        class ClientStub:
            is_authenticated = True

            @staticmethod
            def create_card_reveal_challenge(_allocation_id):
                return CardRevealChallenge(
                    "challenge-1",
                    "urn:email-platform:acr:mfa",
                    "2099-08-20T00:01:00Z",
                )

            @staticmethod
            def reauthenticate_for_card_reveal(*_args, **_kwargs):
                return StepUpAuthorization("step-up-access", 120)

            @staticmethod
            def create_card_reveal_grant(*_args):
                return CardRevealGrant("one-shot-grant", "2099-08-20T00:01:00Z")

            @staticmethod
            def reveal_card_allocation(_allocation_id, _grant):
                reveal_started.set()
                release_reveal.wait(1)
                return CardRevealSnapshot(
                    id="reveal-1",
                    allocation_id="allocation-1",
                    card_masked="VISA •••• 1111",
                    brand="VISA",
                    expiry_month=12,
                    expiry_year=2030,
                    pan="4111111111111111",
                    reveal_expires_at="2099-08-20T00:01:00Z",
                )

        instance._client = ClientStub()
        with mock.patch("platform_desktop.messagebox.askyesno", return_value=True):
            instance.reveal_card_details()
            self.assertTrue(reveal_started.wait(1))
            instance._on_focus_out(mock.Mock())
            release_reveal.set()
            instance._card_reveal_thread.join(1)

        event_kinds = []
        while not instance._events.empty():
            event_kinds.append(instance._events.get_nowait()[1])
        self.assertNotIn("card_reveal", event_kinds)
        self.assertIsNone(instance._current_card_clipboard)


if __name__ == "__main__":
    unittest.main()
