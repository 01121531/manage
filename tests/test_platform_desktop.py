import inspect
import queue
import unittest
from unittest import mock

import app
from platform_client import (
    CardRevealChallenge,
    CardRevealGrant,
    CardRevealSnapshot,
    StepUpAuthorization,
)
from platform_desktop import PlatformDesktopApp, format_workflow_progress


class PlatformDesktopBoundaryTests(unittest.TestCase):
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
