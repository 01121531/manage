import inspect
import unittest
from unittest import mock

from platform_login_dialog import (
    PlatformLoginController,
    PlatformLoginDialog,
    format_login_error,
    make_login_credentials,
    safe_user_info,
    validate_login_fields,
)
from platform_client import DeviceAuthorizationChallenge, PlatformTransportError


class _ImmediateThread:
    def __init__(self, *, target, daemon):
        self.target = target

    def start(self):
        self.target()


class _DeferredThread:
    instances = []

    def __init__(self, *, target, daemon):
        self.target = target
        self.daemon = daemon
        self.started = False
        self.instances.append(self)

    def start(self):
        self.started = True


class _FakeVariable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _FakeWidget:
    def __init__(self):
        self.options = {}
        self.visible = False

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def pack(self, **_kwargs):
        self.visible = True

    def pack_forget(self):
        self.visible = False


class _FakeWindow:
    def __init__(self):
        self.clipboard = None
        self.after_calls = []
        self.destroyed = False

    def after(self, delay, callback, *args):
        self.after_calls.append((delay, callback, args))

    def clipboard_clear(self):
        self.clipboard = None

    def clipboard_append(self, value):
        self.clipboard = value

    def clipboard_get(self):
        return self.clipboard

    def update_idletasks(self):
        pass

    def grab_release(self):
        pass

    def destroy(self):
        self.destroyed = True


class _FakeController:
    def __init__(self):
        self.cancel_calls = 0

    def cancel(self):
        self.cancel_calls += 1
        return True


class _FakeClient:
    def __init__(self):
        self.login_args = None
        self.is_authenticated = False

    def login(self, tenant, email, password, device):
        self.login_args = (tenant, email, password, device)
        return 900

    def me(self):
        return {
            "email": "operator@example.test",
            "device_id": "device-123",
            "access_token": "must-not-be-forwarded",
            "password_hash": "must-not-be-forwarded",
        }

    def login_with_device_authorization(self, on_challenge, *, cancelled=None):
        if cancelled is not None and cancelled():
            raise RuntimeError("cancelled")
        on_challenge(
            DeviceAuthorizationChallenge(
                user_code="ABCD-EFGH",
                verification_uri="https://identity.example/device",
                verification_uri_complete=None,
                expires_in=600,
                interval=5,
                device_code="opaque",
                token_endpoint="https://identity.example/token",
                client_id="desktop",
            )
        )
        return 600

    def login_with_authorization_code(self, on_authorization_url, *, cancelled=None):
        if cancelled is not None and cancelled():
            raise RuntimeError("cancelled")
        on_authorization_url("https://identity.example/authorize?state=opaque")
        return 300

    def cancel_authentication(self):
        self.is_authenticated = False


class _DeviceErrorClient(_FakeClient):
    def login_with_device_authorization(self, on_challenge, *, cancelled=None):
        super().login_with_device_authorization(
            on_challenge,
            cancelled=cancelled,
        )
        raise PlatformTransportError("device polling failed")


class _IdentityFailureClient:
    def __init__(self, *, cleanup_fails=False):
        self.is_authenticated = False
        self.cleanup_fails = cleanup_fails
        self.me_hook = None
        self.cleanup_preparations = 0
        self.cleanup_calls = 0
        self.identity_error = PlatformTransportError(
            "identity lookup reflected bearer-value"
        )

    def login(self, *_):
        self.is_authenticated = True
        return 900

    def login_with_device_authorization(self, on_challenge, *, cancelled=None):
        self.is_authenticated = True
        return 900

    def login_with_authorization_code(self, on_authorization_url, *, cancelled=None):
        self.is_authenticated = True
        return 900

    def me(self):
        if self.me_hook is not None:
            self.me_hook()
        raise self.identity_error

    def cancel_authentication(self):
        self.is_authenticated = False

    def prepare_logout_cleanup(self, task_id):
        self.cleanup_preparations += 1
        self.is_authenticated = False
        if task_id is not None:
            raise AssertionError("partial login cleanup must be device scoped")

        def cleanup():
            self.cleanup_calls += 1
            if self.cleanup_fails:
                raise PlatformTransportError(
                    "cleanup endpoint reflected refresh-value"
                )

        return cleanup


class PlatformLoginDialogTests(unittest.TestCase):
    @staticmethod
    def device_challenge(*, suffix=""):
        return DeviceAuthorizationChallenge(
            user_code=f"ABCD-EFGH{suffix}",
            verification_uri=f"https://identity.example/device{suffix}",
            verification_uri_complete=(
                f"https://identity.example/device?user_code=ABCD-EFGH{suffix}"
            ),
            expires_in=600,
            interval=5,
            device_code=f"opaque-device-code{suffix}",
            token_endpoint=f"https://identity.example/token{suffix}",
            client_id=f"desktop-client{suffix}",
        )

    @staticmethod
    def headless_dialog():
        dialog = object.__new__(PlatformLoginDialog)
        dialog._closed = False
        dialog._busy = True
        dialog._auth_mode = "oidc"
        dialog._device_challenge_generation = 0
        dialog._device_verification_uri = None
        dialog._device_user_code = None
        dialog._device_clipboard_value = None
        dialog.device_verification_uri_var = _FakeVariable()
        dialog.device_user_code_var = _FakeVariable()
        dialog.password_var = _FakeVariable("password-that-must-clear")
        dialog.device_expiry_label = _FakeWidget()
        dialog.copy_device_uri_button = _FakeWidget()
        dialog.copy_device_code_button = _FakeWidget()
        dialog.cancel_device_button = _FakeWidget()
        dialog.device_challenge_panel = _FakeWidget()
        dialog.status_label = _FakeWidget()
        dialog.login_button = _FakeWidget()
        dialog.window = _FakeWindow()
        dialog._controller = _FakeController()
        dialog._set_busy = mock.Mock()
        dialog._on_success = mock.Mock()
        dialog._on_close = mock.Mock()
        return dialog

    def test_auth_config_thread_start_failure_restores_safe_error(self):
        dialog = self.headless_dialog()
        client = mock.Mock()
        raw_error = "raw auth config thread failure"

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start():
                raise RuntimeError(raw_error)

        with mock.patch("platform_login_dialog.threading.Thread", FailingThread):
            dialog._load_auth_config(client)

        client.get_auth_config.assert_not_called()
        self.assertEqual(dialog._auth_mode, "error")
        self.assertEqual(dialog.login_button.options["state"], "disabled")
        self.assertIn("无法连接平台", dialog.status_label.options["text"])
        self.assertNotIn(raw_error, dialog.status_label.options["text"])

    def test_successful_dismiss_does_not_cancel_authenticated_session(self):
        dialog = self.headless_dialog()

        dialog.close(cancel_authentication=False)

        self.assertTrue(dialog._closed)
        self.assertTrue(dialog.window.destroyed)
        self.assertEqual(dialog._controller.cancel_calls, 0)
        dialog._on_close.assert_called_once_with()

    def test_device_challenge_keeps_base_uri_and_code_visible_and_copyable(self):
        dialog = self.headless_dialog()
        challenge = self.device_challenge()

        with mock.patch(
            "platform_login_dialog.webbrowser.open", return_value=False
        ) as open_browser:
            dialog._handle_device_challenge(challenge)

        open_browser.assert_called_once_with(challenge.verification_uri_complete, new=2)
        self.assertEqual(
            dialog.device_verification_uri_var.get(), challenge.verification_uri
        )
        self.assertEqual(dialog.device_user_code_var.get(), challenge.user_code)
        self.assertTrue(dialog.device_challenge_panel.visible)
        self.assertEqual(dialog.copy_device_uri_button.options["state"], "normal")
        self.assertEqual(dialog.copy_device_code_button.options["state"], "normal")
        self.assertIn("请使用下方登录网址", dialog.status_label.options["text"])
        self.assertEqual(dialog.window.after_calls[0][0], 600_000)

        dialog.copy_device_verification_uri()
        self.assertEqual(dialog.window.clipboard, challenge.verification_uri)
        dialog.copy_device_user_code()
        self.assertEqual(dialog.window.clipboard, challenge.user_code)

        visible_text = " ".join(
            (
                dialog.device_verification_uri_var.get(),
                dialog.device_user_code_var.get(),
                dialog.device_expiry_label.options["text"],
                dialog.status_label.options["text"],
            )
        )
        for hidden in (
            challenge.device_code,
            challenge.token_endpoint,
            challenge.client_id,
            challenge.verification_uri_complete,
        ):
            self.assertNotIn(hidden, visible_text)

        widget_source = inspect.getsource(PlatformLoginDialog._build_widgets)
        self.assertIn('state="readonly"', widget_source)
        self.assertIn('text="复制登录网址"', widget_source)
        self.assertIn('text="复制设备代码"', widget_source)
        self.assertIn("takefocus=True", widget_source)

    def test_device_challenge_terminal_paths_clear_fields_and_owned_clipboard(self):
        for path in ("success", "error", "cancel", "close", "expiry"):
            with self.subTest(path=path):
                dialog = self.headless_dialog()
                challenge = self.device_challenge(suffix=f"-{path}")
                with mock.patch(
                    "platform_login_dialog.webbrowser.open", return_value=True
                ):
                    dialog._handle_device_challenge(challenge)
                dialog.copy_device_user_code()
                self.assertEqual(dialog.window.clipboard, challenge.user_code)

                if path == "success":
                    dialog._handle_success({"email": "user@example.test"}, 300)
                elif path == "error":
                    dialog._handle_error(RuntimeError("safe test failure"))
                elif path == "cancel":
                    dialog.cancel_device_fallback()
                elif path == "close":
                    dialog.close()
                else:
                    _, expire, args = dialog.window.after_calls[-1]
                    expire(*args)

                self.assertEqual(dialog.device_verification_uri_var.get(), "")
                self.assertEqual(dialog.device_user_code_var.get(), "")
                self.assertFalse(dialog.device_challenge_panel.visible)
                self.assertIsNone(dialog.window.clipboard)
                self.assertEqual(dialog.copy_device_uri_button.options["state"], "disabled")
                self.assertEqual(dialog.copy_device_code_button.options["state"], "disabled")
                if path in {"cancel", "close", "expiry"}:
                    self.assertEqual(dialog._controller.cancel_calls, 1)

    def test_device_challenge_cleanup_preserves_replaced_clipboard_and_new_generation(self):
        dialog = self.headless_dialog()
        first = self.device_challenge(suffix="-first")
        second = self.device_challenge(suffix="-second")
        with mock.patch("platform_login_dialog.webbrowser.open", return_value=False):
            dialog._handle_device_challenge(first)
        _, stale_expire, stale_args = dialog.window.after_calls[-1]
        dialog.copy_device_user_code()
        dialog.window.clipboard = "operator-owned-note"

        with mock.patch("platform_login_dialog.webbrowser.open", return_value=False):
            dialog._handle_device_challenge(second)

        self.assertEqual(dialog.window.clipboard, "operator-owned-note")
        stale_expire(*stale_args)
        self.assertEqual(
            dialog.device_verification_uri_var.get(), second.verification_uri
        )
        self.assertEqual(dialog.device_user_code_var.get(), second.user_code)
        self.assertTrue(dialog.device_challenge_panel.visible)
        self.assertEqual(dialog._controller.cancel_calls, 0)

    def test_validation_has_labels_and_never_echoes_secret(self):
        self.assertEqual(validate_login_fields("", "", "secret-value", ""), ["请输入租户 ID"])
        self.assertEqual(validate_login_fields("tenant", "bad", "secret-value", "device"), ["平台邮箱格式无效"])
        credentials = make_login_credentials(
            " tenant ", "user@example.test", " secret-value ", " device "
        )
        self.assertEqual(credentials.tenant_id, "tenant")
        self.assertEqual(credentials.email, "user@example.test")
        self.assertEqual(credentials.password, " secret-value ")
        self.assertNotIn("secret-value", repr(credentials))

    def test_safe_profile_drops_secret_like_fields(self):
        profile = safe_user_info(
            {
                "email": "operator@example.test",
                "nested": {"token": "secret", "device_id": "device-1"},
                "password": "secret",
            }
        )
        self.assertEqual(profile["email"], "operator@example.test")
        self.assertEqual(profile["nested"], {"device_id": "device-1"})
        self.assertNotIn("password", profile)
        self.assertNotIn("token", repr(profile))

    def test_controller_runs_off_ui_and_returns_safe_profile(self):
        client = _FakeClient()
        results = []
        errors = []
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )
        started = controller.submit(
            "tenant",
            "user@example.test",
            "platform-secret",
            "device-1",
            on_success=lambda profile, expires: results.append((profile, expires)),
            on_error=errors.append,
        )
        self.assertTrue(started)
        self.assertEqual(errors, [])
        self.assertEqual(results, [({"email": "operator@example.test", "device_id": "device-123"}, 900)])
        self.assertEqual(client.login_args[-1], "device-1")
        self.assertFalse(controller.busy)

    def test_controller_thread_start_failure_restores_all_login_flows(self):
        raw_error = "raw thread creation failure"

        class FailingThread:
            def __init__(self, **_):
                pass

            @staticmethod
            def start():
                raise RuntimeError(raw_error)

        for flow in ("local", "device", "authorization_code"):
            with self.subTest(flow=flow):
                errors = []
                published = []
                controller = PlatformLoginController(
                    _FakeClient(),
                    schedule=lambda callback: callback(),
                    thread_factory=FailingThread,
                )
                if flow == "local":
                    started = controller.submit(
                        "tenant",
                        "user@example.test",
                        "platform-secret",
                        "device-1",
                        on_success=self.fail,
                        on_error=errors.append,
                    )
                elif flow == "device":
                    started = controller.submit_device(
                        on_challenge=published.append,
                        on_success=self.fail,
                        on_error=errors.append,
                    )
                else:
                    started = controller.submit_authorization_code(
                        on_authorization_url=published.append,
                        on_success=self.fail,
                        on_error=errors.append,
                    )

                self.assertFalse(started)
                self.assertFalse(controller.busy)
                self.assertEqual(published, [])
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], PlatformTransportError)
                self.assertNotIn(raw_error, str(errors[0]))
                if flow != "local":
                    self.assertTrue(controller._device_cancel.is_set())

    def test_controller_retains_non_daemon_login_worker_until_detached(self):
        _DeferredThread.instances = []
        controller = PlatformLoginController(
            _FakeClient(),
            schedule=lambda callback: callback(),
            thread_factory=_DeferredThread,
        )

        self.assertTrue(controller.submit(
            "tenant",
            "user@example.test",
            "platform-secret",
            "device-1",
            on_success=self.fail,
            on_error=self.fail,
        ))

        worker = _DeferredThread.instances[-1]
        self.assertTrue(worker.started)
        self.assertFalse(worker.daemon)
        self.assertEqual(controller.detach_worker_threads(), (worker,))
        self.assertEqual(controller.detach_worker_threads(), ())

    def test_controller_device_login_returns_challenge_and_safe_profile(self):
        client = _FakeClient()
        challenges = []
        results = []
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )
        started = controller.submit_device(
            on_challenge=challenges.append,
            on_success=lambda profile, expires: results.append((profile, expires)),
            on_error=self.fail,
        )
        self.assertTrue(started)
        self.assertEqual(challenges[0].user_code, "ABCD-EFGH")
        self.assertNotIn("opaque", repr(challenges[0]))
        self.assertEqual(results[0][1], 600)
        self.assertNotIn("access_token", results[0][0])

    def test_cancelled_device_login_drops_queued_challenge_and_error(self):
        scheduled = []
        challenges = []
        errors = []
        controller = PlatformLoginController(
            _DeviceErrorClient(),
            schedule=scheduled.append,
            thread_factory=_ImmediateThread,
        )

        self.assertTrue(
            controller.submit_device(
                on_challenge=challenges.append,
                on_success=self.fail,
                on_error=errors.append,
            )
        )
        self.assertEqual(challenges, [])
        self.assertEqual(errors, [])

        controller.cancel()
        for callback in list(scheduled):
            callback()

        self.assertEqual(challenges, [])
        self.assertEqual(errors, [])
        self.assertFalse(controller.busy)

    def test_new_device_generation_drops_queued_old_success(self):
        scheduled = []
        old_challenges = []
        old_results = []
        new_challenges = []
        new_results = []
        errors = []
        controller = PlatformLoginController(
            _FakeClient(),
            schedule=scheduled.append,
            thread_factory=_ImmediateThread,
        )

        self.assertTrue(
            controller.submit_device(
                on_challenge=old_challenges.append,
                on_success=lambda profile, expires: old_results.append(
                    (profile, expires)
                ),
                on_error=errors.append,
            )
        )
        controller.cancel()
        self.assertTrue(
            controller.submit_device(
                on_challenge=new_challenges.append,
                on_success=lambda profile, expires: new_results.append(
                    (profile, expires)
                ),
                on_error=errors.append,
            )
        )

        for callback in list(scheduled):
            callback()

        self.assertEqual(old_challenges, [])
        self.assertEqual(old_results, [])
        self.assertEqual(errors, [])
        self.assertEqual(len(new_challenges), 1)
        self.assertEqual(new_results[0][1], 600)
        self.assertFalse(controller.busy)

    def test_controller_prefers_authorization_code_and_keeps_device_as_fallback(self):
        client = _FakeClient()
        urls = []
        results = []
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )
        started = controller.submit_authorization_code(
            on_authorization_url=urls.append,
            on_success=lambda profile, expires: results.append((profile, expires)),
            on_error=self.fail,
        )
        self.assertTrue(started)
        self.assertEqual(urls, ["https://identity.example/authorize?state=opaque"])
        self.assertEqual(results[0][1], 300)
        self.assertIn("submit_authorization_code", inspect.getsource(PlatformLoginDialog.submit))
        self.assertIn("submit_device_fallback", inspect.getsource(PlatformLoginDialog))

    def test_cancelled_authorization_code_drops_queued_url_and_success(self):
        scheduled = []
        urls = []
        results = []
        controller = PlatformLoginController(
            _FakeClient(),
            schedule=scheduled.append,
            thread_factory=_ImmediateThread,
        )

        self.assertTrue(
            controller.submit_authorization_code(
                on_authorization_url=urls.append,
                on_success=lambda profile, expires: results.append(
                    (profile, expires)
                ),
                on_error=self.fail,
            )
        )
        self.assertEqual(urls, [])
        controller.cancel()

        for callback in list(scheduled):
            callback()

        self.assertEqual(urls, [])
        self.assertEqual(results, [])
        self.assertFalse(controller.busy)

    def test_primary_browser_failure_cancels_pkce_and_enables_device_fallback(self):
        authorization_url = "https://identity.example/authorize?state=opaque"
        for browser_result in (False, OSError("browser unavailable")):
            with self.subTest(browser_result=repr(browser_result)):
                dialog = self.headless_dialog()
                browser_call = (
                    mock.patch(
                        "platform_login_dialog.webbrowser.open",
                        side_effect=browser_result,
                    )
                    if isinstance(browser_result, BaseException)
                    else mock.patch(
                        "platform_login_dialog.webbrowser.open",
                        return_value=browser_result,
                    )
                )
                with browser_call:
                    dialog._handle_authorization_url(authorization_url)

                self.assertEqual(dialog._controller.cancel_calls, 1)
                dialog._set_busy.assert_called_once_with(False)
                self.assertIn("设备代码登录", dialog.status_label.options["text"])
                self.assertNotIn(authorization_url, dialog.status_label.options["text"])

    def test_identity_failure_compensates_each_partially_issued_login_once(self):
        for flow in ("local", "device", "authorization_code"):
            with self.subTest(flow=flow):
                client = _IdentityFailureClient()
                errors = []
                controller = PlatformLoginController(
                    client,
                    schedule=lambda callback: callback(),
                    thread_factory=_ImmediateThread,
                )

                if flow == "local":
                    started = controller.submit(
                        "tenant",
                        "user@example.test",
                        "platform-secret",
                        "device-1",
                        on_success=self.fail,
                        on_error=errors.append,
                    )
                elif flow == "device":
                    started = controller.submit_device(
                        on_challenge=lambda _challenge: None,
                        on_success=self.fail,
                        on_error=errors.append,
                    )
                else:
                    started = controller.submit_authorization_code(
                        on_authorization_url=lambda _url: None,
                        on_success=self.fail,
                        on_error=errors.append,
                    )

                self.assertTrue(started)
                self.assertFalse(client.is_authenticated)
                self.assertEqual(client.cleanup_preparations, 1)
                self.assertEqual(client.cleanup_calls, 1)
                self.assertEqual(errors, [client.identity_error])
                self.assertFalse(controller.busy)

    def test_partial_login_cleanup_failure_preserves_identity_reason_safely(self):
        client = _IdentityFailureClient(cleanup_fails=True)
        errors = []
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )

        controller.submit(
            "tenant",
            "user@example.test",
            "platform-secret",
            "device-1",
            on_success=self.fail,
            on_error=errors.append,
        )

        self.assertFalse(client.is_authenticated)
        self.assertEqual(client.cleanup_preparations, 1)
        self.assertEqual(client.cleanup_calls, 1)
        message = format_login_error(errors[0])
        self.assertIn("原因：无法连接平台", message)
        self.assertIn("影响：本地会话已清除，但服务端设备会话清理未确认", message)
        self.assertIn("下一步：", message)
        self.assertNotIn("bearer-value", message)
        self.assertNotIn("refresh-value", message)

    def test_cancel_during_oidc_identity_lookup_cleans_original_session_once(self):
        client = _IdentityFailureClient()
        errors = []
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )

        def replace_cancelled_session():
            controller.cancel()
            client.is_authenticated = True

        client.me_hook = replace_cancelled_session
        controller.submit_authorization_code(
            on_authorization_url=lambda _url: None,
            on_success=self.fail,
            on_error=errors.append,
        )

        self.assertTrue(client.is_authenticated)
        self.assertEqual(client.cleanup_preparations, 1)
        self.assertEqual(client.cleanup_calls, 1)
        self.assertEqual(errors, [])
        self.assertFalse(controller.busy)

    def test_cancel_cleanup_failure_blocks_login_and_retries_same_closure(self):
        client = _IdentityFailureClient(cleanup_fails=True)
        client.is_authenticated = True
        controller = PlatformLoginController(
            client,
            schedule=lambda callback: callback(),
            thread_factory=_ImmediateThread,
        )

        self.assertFalse(controller.cancel())
        self.assertFalse(controller.submit_authorization_code(
            on_authorization_url=lambda _url: None,
            on_success=self.fail,
            on_error=self.fail,
        ))
        client.cleanup_fails = False
        self.assertTrue(controller.cancel())
        self.assertEqual(client.cleanup_preparations, 1)
        self.assertEqual(client.cleanup_calls, 2)

    def test_login_error_is_recovery_guidance_without_exception_text(self):
        error = RuntimeError("server reflected platform-secret and bearer token")
        message = format_login_error(error)
        self.assertNotIn("platform-secret", message)
        self.assertNotIn("bearer token", message.lower())
        self.assertIn("建议", message)


if __name__ == "__main__":
    unittest.main()
