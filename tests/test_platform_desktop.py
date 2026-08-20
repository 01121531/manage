import inspect
import unittest

import app
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


if __name__ == "__main__":
    unittest.main()
