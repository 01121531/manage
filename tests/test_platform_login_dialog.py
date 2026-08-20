import inspect
import unittest

from platform_login_dialog import (
    PlatformLoginController,
    PlatformLoginDialog,
    format_login_error,
    make_login_credentials,
    safe_user_info,
    validate_login_fields,
)
from platform_client import DeviceAuthorizationChallenge


class _ImmediateThread:
    def __init__(self, *, target, daemon):
        self.target = target

    def start(self):
        self.target()


class _FakeClient:
    def __init__(self):
        self.login_args = None

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


class PlatformLoginDialogTests(unittest.TestCase):
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

    def test_login_error_is_recovery_guidance_without_exception_text(self):
        error = RuntimeError("server reflected platform-secret and bearer token")
        message = format_login_error(error)
        self.assertNotIn("platform-secret", message)
        self.assertNotIn("bearer token", message.lower())
        self.assertIn("建议", message)


if __name__ == "__main__":
    unittest.main()
