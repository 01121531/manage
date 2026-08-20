import inspect
import queue
import unittest
from unittest import mock

import app
from platform_client import (
    CardRevealChallenge,
    CardRevealGrant,
    CardRevealSnapshot,
    MailCodeSnapshot,
    StepUpAuthorization,
    UploadJobSnapshot,
)
from platform_desktop import PlatformDesktopApp, format_workflow_progress


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

    def after(self, delay, callback, *args):
        self.scheduled.append((delay, callback, args))

    @staticmethod
    def clipboard_get():
        return ""


class PlatformDesktopBoundaryTests(unittest.TestCase):
    @staticmethod
    def _event_app() -> PlatformDesktopApp:
        instance = object.__new__(PlatformDesktopApp)
        instance._closed = False
        instance._events = queue.Queue()
        instance._task_generation = 1
        instance._poll_generation = 1
        instance._upload_generation = 1
        instance._update_generation = 1
        instance._session_generation = 1
        instance._task_id = "task-1"
        instance._verified_task_id = None
        instance._current_code = None
        instance._code_clear_generation = 0
        instance._upload_idempotency_key = "attempt-1"
        instance._upload_business_name = "Example Store"
        instance.root = RootStub()
        instance.session_label = RecordingWidget()
        instance.code_label = RecordingWidget()
        instance.copy_button = RecordingWidget()
        instance.upload_button = RecordingWidget()
        instance.copy_card_button = RecordingWidget()
        instance.upload_label = RecordingWidget()
        instance.workflow_label = RecordingWidget()
        instance.status_label = RecordingWidget()
        instance._write_clipboard = mock.Mock()
        instance._schedule_code_cleanup = mock.Mock()
        instance.stop_polling = mock.Mock()
        instance._close_active_task_async = mock.Mock()
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
        logout_source = inspect.getsource(PlatformDesktopApp.logout)
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
            inspect.getsource(PlatformDesktopApp.logout),
        )

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

    def test_task_history_exposes_trace_and_closes_with_session(self) -> None:
        history_source = inspect.getsource(PlatformDesktopApp.show_task_history)
        render_source = inspect.getsource(PlatformDesktopApp._render_task_history)
        self.assertIn("trace_id（审计追踪）", history_source)
        self.assertIn("list_tasks(limit=50)", history_source + inspect.getsource(PlatformDesktopApp._load_task_history))
        self.assertIn("双击记录或点击按钮复制 trace_id", render_source)
        self.assertIn("self._close_task_history()", inspect.getsource(PlatformDesktopApp.logout))
        self.assertIn("self._close_task_history()", inspect.getsource(PlatformDesktopApp.close))

    def test_online_update_uses_background_check_and_verified_helper(self) -> None:
        check_source = inspect.getsource(PlatformDesktopApp.check_for_updates)
        drain_source = inspect.getsource(PlatformDesktopApp._drain_events)
        self.assertIn("self._update_client.check()", check_source)
        self.assertIn('name="platform-update-check"', check_source)
        self.assertIn("launch_update_helper", drain_source)
        self.assertIn("SHA-256", drain_source)

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

        class InlineThread:
            def __init__(self, *, target, **_):
                self.target = target

            def start(self):
                self.target()

        instance = object.__new__(PlatformDesktopApp)
        instance._client = FakeClient()
        instance._card_allocation_id = "allocation-1"
        instance._task_generation = 7
        instance._closed = False
        instance._events = queue.Queue()
        instance.root = object()
        instance.copy_card_button = FakeWidget()
        instance.status_label = FakeWidget()

        with (
            mock.patch(
                "platform_desktop.messagebox.askyesno", return_value=True
            ) as confirm,
            mock.patch("platform_desktop.webbrowser.open", return_value=True),
            mock.patch("platform_desktop.threading.Thread", InlineThread),
        ):
            instance.reveal_card_details()

        confirm.assert_called_once()
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
        event_kinds = [instance._events.get_nowait()[1] for _ in range(2)]
        self.assertEqual(event_kinds, ["card_reveal_authorizing", "card_reveal"])
        self.assertIn({"state": "disabled"}, instance.copy_card_button.states)


if __name__ == "__main__":
    unittest.main()
