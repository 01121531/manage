import base64
import io
import json
import random
import tempfile
import time
import unittest
import urllib.error
from unittest import mock
from email.message import Message
from pathlib import Path

from admin_oauth import (
    AccountNameStore,
    AccountNameStoreError,
    DEFAULT_MODEL_MAPPING,
    AdminApiClient,
    AdminApiError,
    AdminTokenStore,
    AuthSession,
    AuthorizationService,
    ConcurrencyLimitError,
    ProxyIdStore,
    ProxyIdStoreError,
    TokenStoreError,
    TokenValidationError,
    build_account_payload,
    default_account_name_path,
    default_proxy_id_path,
    jwt_expiry,
    parse_authorization_input,
    redact_secrets,
    normalize_proxy_id,
    validate_admin_token,
)


def fake_jwt(expiry):
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": expiry}).encode("utf-8")
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


class FakeResponse:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")
        self.headers = Message()
        self.headers["Content-Type"] = "application/json; charset=utf-8"

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class TokenTests(unittest.TestCase):
    def test_reads_expiry_and_rejects_expired_token(self):
        token = fake_jwt(1_900_000_000)
        self.assertEqual(jwt_expiry(token), 1_900_000_000)
        self.assertEqual(validate_admin_token(f"Bearer {token}", now=1_800_000_000), token)
        with self.assertRaises(TokenValidationError):
            validate_admin_token(token, now=2_000_000_000)

    def test_accepts_opaque_nonempty_token(self):
        self.assertEqual(validate_admin_token("opaque-token", now=0), "opaque-token")

    def test_dpapi_store_round_trip_and_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AdminTokenStore(Path(directory) / "token.bin")
            token = fake_jwt(int(time.time()) + 3600)
            store.save(token)
            self.assertNotEqual(store.path.read_bytes(), token.encode("utf-8"))
            self.assertEqual(store.load(), token)
            store.clear()
            self.assertIsNone(store.load())

    def test_corrupt_dpapi_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token.bin"
            path.write_bytes(bytes(random.Random(3).randrange(256) for _ in range(32)))
            with self.assertRaises(TokenStoreError):
                AdminTokenStore(path).load()

    def test_account_name_store_round_trip_and_update(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AccountNameStore(Path(directory) / "account_name.txt")
            self.assertIsNone(store.load())
            store.save("0818-0011")
            self.assertEqual(store.load(), "0818-0011")
            store.save("0818-0012")
            self.assertEqual(store.load(), "0818-0012")

    def test_account_name_store_rejects_invalid_name(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AccountNameStore(Path(directory) / "account_name.txt")
            with self.assertRaises(AccountNameStoreError):
                store.save("   ")
            with self.assertRaises(AccountNameStoreError):
                store.save("line1\nline2")

    def test_proxy_id_store_round_trip_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProxyIdStore(Path(directory) / "proxy_id.txt")
            self.assertEqual(store.load(), 2940)
            self.assertEqual(store.save(" 3100 "), 3100)
            self.assertEqual(store.load(), 3100)
            self.assertEqual(normalize_proxy_id(88), 88)
            for invalid in ("", "abc", 0, -1):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ProxyIdStoreError):
                        normalize_proxy_id(invalid)

    def test_visible_settings_default_to_application_directory(self):
        fake_executable = Path("C:/Tools/MailHelper/邮箱验证码助手.exe")
        with mock.patch("admin_oauth.sys.frozen", True, create=True), mock.patch(
            "admin_oauth.sys.executable",
            str(fake_executable),
        ):
            self.assertEqual(
                default_account_name_path(),
                fake_executable.parent / "account_name.txt",
            )
            self.assertEqual(
                default_proxy_id_path(),
                fake_executable.parent / "proxy_id.txt",
            )


class InputTests(unittest.TestCase):
    def test_accepts_raw_code(self):
        self.assertEqual(parse_authorization_input(" ac_example ", "state1"), "ac_example")

    def test_extracts_code_from_callback_url(self):
        callback = "http://localhost/callback?code=ac_example&state=state1"
        self.assertEqual(parse_authorization_input(callback, "state1"), "ac_example")

    def test_rejects_mismatched_state(self):
        callback = "http://localhost/callback?code=ac_example&state=other"
        with self.assertRaisesRegex(ValueError, "state"):
            parse_authorization_input(callback, "state1")

    def test_redacts_sensitive_token_shapes(self):
        value = "Bearer aaa.bbb.ccc code ac_123456.secret refresh rt.1.secret"
        redacted = redact_secrets(value)
        self.assertNotIn("aaa.bbb.ccc", redacted)
        self.assertNotIn("ac_123456", redacted)
        self.assertNotIn("rt.1.secret", redacted)


class PayloadTests(unittest.TestCase):
    def test_static_fields_match_sample_request(self):
        payload = build_account_payload(
            "custom-name",
            {
                "access_token": "access-value",
                "refresh_token": "refresh-value",
                "email": "person@example.com",
                "extra": {"privacy_mode": "training_off", "unknown": "discard-me"},
                "model_mapping": {"custom-model": "upstream-model"},
                "name": "upstream-name-must-not-be-copied",
            },
        )
        self.assertEqual(payload["credentials"]["model_mapping"], DEFAULT_MODEL_MAPPING)
        self.assertEqual(payload["proxy_id"], 2940)
        self.assertEqual(payload["concurrency"], 40)
        self.assertEqual(payload["group_ids"], [49])
        self.assertEqual(payload["name"], "custom-name")
        self.assertEqual(payload["extra"]["privacy_mode"], "training_off")
        self.assertNotIn("unknown", payload["extra"])
        self.assertNotIn("name", payload["extra"])
        self.assertEqual(
            set(payload),
            {
                "name",
                "notes",
                "platform",
                "type",
                "credentials",
                "extra",
                "proxy_id",
                "concurrency",
                "priority",
                "rate_multiplier",
                "group_ids",
                "expires_at",
                "auto_pause_on_expired",
            },
        )

    def test_sample_mapping_is_used_as_fallback(self):
        payload = build_account_payload("name", {"access_token": "access-value"})
        self.assertEqual(payload["credentials"]["model_mapping"], DEFAULT_MODEL_MAPPING)

    def test_access_token_and_name_are_required(self):
        with self.assertRaises(ValueError):
            build_account_payload("", {"access_token": "access-value"})
        with self.assertRaises(ValueError):
            build_account_payload("name", {})


class ClientFlowTests(unittest.TestCase):
    def test_full_request_sequence_and_shapes(self):
        responses = iter(
            (
                {
                    "code": 0,
                    "data": {"allowed": True, "max_concurrency": 50},
                },
                {
                    "code": 0,
                    "data": {
                        "auth_url": "https://auth.example/authorize?state=state-123",
                        "session_id": "session-123",
                    },
                },
                {
                    "code": 0,
                    "data": {
                        "access_token": "access-value",
                        "refresh_token": "refresh-value",
                        "email": "person@example.com",
                    },
                },
                {
                    "code": 0,
                    "data": {
                        "id": 88,
                        "name": "custom-name",
                        "email": "person@example.com",
                    },
                },
            )
        )
        requests = []

        def open_fn(request, timeout):
            requests.append((request, timeout, json.loads(request.data)))
            return FakeResponse(next(responses))

        client = AdminApiClient("test-admin-token", open_fn=open_fn)
        service = AuthorizationService(client)
        session = service.begin(3100)
        result = service.complete(session, "ac_example", "custom-name")

        self.assertEqual(result["id"], 88)
        self.assertEqual(len(requests), 4)
        self.assertTrue(requests[0][0].full_url.endswith("/accounts/check-concurrency-limit"))
        self.assertEqual(requests[0][2]["concurrency"], 40)
        self.assertTrue(requests[1][0].full_url.endswith("/openai/generate-auth-url"))
        self.assertEqual(requests[1][2]["proxy_id"], 3100)
        self.assertEqual(requests[2][2]["state"], "state-123")
        self.assertEqual(requests[2][2]["code"], "ac_example")
        self.assertEqual(requests[2][2]["proxy_id"], 3100)
        self.assertTrue(requests[3][0].full_url.endswith("/accounts"))
        self.assertEqual(requests[3][2]["name"], "custom-name")
        self.assertEqual(requests[3][2]["proxy_id"], 3100)
        self.assertEqual(requests[0][0].get_header("Authorization"), "Bearer test-admin-token")
        self.assertTrue(all(timeout == 30 for _, timeout, _ in requests))

    def test_concurrency_rejection_stops_before_link_generation(self):
        requests = []

        def open_fn(request, timeout):
            del timeout
            requests.append(request)
            return FakeResponse({"allowed": False, "max_concurrency": 20})

        service = AuthorizationService(AdminApiClient("token", open_fn=open_fn))
        with self.assertRaises(ConcurrencyLimitError):
            service.begin()
        self.assertEqual(len(requests), 1)

    def test_concurrency_accepts_compatible_success_shapes(self):
        responses = (
            {"allowed": 1},
            {"allowed": "true"},
            {"data": {"allowed": True, "max_concurrency": 40}},
            {"max_concurrency": 40},
            {"success": True},
        )
        for response in responses:
            with self.subTest(response=response):
                client = AdminApiClient(
                    "token",
                    open_fn=lambda request, timeout, value=response: FakeResponse(value),
                )
                self.assertEqual(client.check_concurrency(), response)

    def test_concurrency_does_not_bypass_explicit_denial(self):
        responses = (
            {"allowed": False, "max_concurrency": 40},
            {"allowed": "false", "max_concurrency": 100},
            {"max_concurrency": 39},
        )
        for response in responses:
            with self.subTest(response=response):
                client = AdminApiClient(
                    "token",
                    open_fn=lambda request, timeout, value=response: FakeResponse(value),
                )
                with self.assertRaises(ConcurrencyLimitError):
                    client.check_concurrency()

    def test_http_auth_error_does_not_echo_token(self):
        token = "secret-admin-token"

        def open_fn(request, timeout):
            del request, timeout
            raise urllib.error.HTTPError(
                "http://example.invalid",
                401,
                "Unauthorized",
                {},
                io.BytesIO(b'{"detail":"bad token"}'),
            )

        with self.assertRaises(AdminApiError) as caught:
            AdminApiClient(token, open_fn=open_fn).check_concurrency()
        self.assertNotIn(token, str(caught.exception))
        self.assertEqual(caught.exception.status, 401)

    def test_create_network_failure_is_ambiguous(self):
        def open_fn(request, timeout):
            del timeout
            if request.full_url.endswith("/accounts"):
                raise TimeoutError("timed out")
            return FakeResponse({})

        client = AdminApiClient("token", open_fn=open_fn)
        with self.assertRaises(AdminApiError) as caught:
            client.create_account({"name": "test"})
        self.assertTrue(caught.exception.ambiguous)

    def test_application_error_is_not_treated_as_success(self):
        def open_fn(request, timeout):
            del request, timeout
            return FakeResponse({"success": False, "message": "duplicate name"})

        client = AdminApiClient("token", open_fn=open_fn)
        with self.assertRaisesRegex(AdminApiError, "duplicate name"):
            client.create_account({"name": "duplicate"})

    def test_nonzero_envelope_code_is_an_error(self):
        def open_fn(request, timeout):
            del request, timeout
            return FakeResponse({"code": 4001, "message": "authorization failed"})

        client = AdminApiClient("token", open_fn=open_fn)
        with self.assertRaisesRegex(AdminApiError, "authorization failed"):
            client.generate_auth_url()


if __name__ == "__main__":
    unittest.main()
