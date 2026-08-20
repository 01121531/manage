import io
import base64
import hashlib
import json
import os
import socket
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from unittest import mock

from platform_client import (
    CardAllocationSnapshot,
    CardRevealChallenge,
    CardRevealGrant,
    CardRevealSnapshot,
    DEFAULT_CARD_REVEAL_ACR_VALUES,
    DEFAULT_TIMEOUT_SECONDS,
    PlatformApiError,
    PlatformAuthenticationError,
    PlatformAuthenticationRequiredError,
    PlatformClient,
    PlatformConfigurationError,
    MailCodeSnapshot,
    MailSessionSnapshot,
    PlatformProtocolError,
    PlatformDeviceAuthorizationError,
    LoopbackAuthorizationReceiver,
    PlatformTimeoutError,
    UploadJobSnapshot,
    DeviceAuthorizationChallenge,
    TaskSnapshot,
)
from session_store import MemorySessionStore


class FakeResponse:
    def __init__(self, payload, *, trace_id="server-trace", status=200):
        self.body = json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = Message()
        self.headers["X-Trace-Id"] = trace_id

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class EmptyResponse(FakeResponse):
    def __init__(self, *, status=204):
        super().__init__({}, status=status)
        self.body = b""


class RecordingOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class SequenceOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append((request, timeout))
        return self.responses.pop(0)


class PlatformClientTests(unittest.TestCase):
    def test_reads_base_url_from_environment(self):
        with mock.patch.dict(
            os.environ, {"PLATFORM_BASE_URL": "https://platform.example/"}
        ):
            client = PlatformClient(opener=RecordingOpener(FakeResponse({})))
        self.assertEqual(client.base_url, "https://platform.example")
        self.assertEqual(client.timeout, DEFAULT_TIMEOUT_SECONDS)

    def test_rejects_missing_or_invalid_base_url(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PlatformConfigurationError):
                PlatformClient()
        with self.assertRaises(PlatformConfigurationError):
            PlatformClient("file:///tmp/platform")

    def test_requires_https_except_for_loopback_development(self):
        for url in (
            "http://platform.example",
            "http://10.0.0.2:8000",
            "http://localhost.evil.example",
        ):
            with self.subTest(url=url):
                with self.assertRaises(PlatformConfigurationError):
                    PlatformClient(url)
        for url in (
            "https://platform.example",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ):
            with self.subTest(url=url):
                self.assertEqual(PlatformClient(url).base_url, url)

    def test_login_uses_only_platform_credentials_and_keeps_token_in_memory(self):
        opener = RecordingOpener(
            FakeResponse({"access_token": "platform-access", "expires_in": 900})
        )
        client = PlatformClient("https://platform.example", opener=opener)

        expires_in = client.login(
            "tenant-1",
            "operator@example.com",
            "platform-password",
            "device-1",
        )

        request, _ = opener.requests[0]
        self.assertEqual(expires_in, 900)
        self.assertTrue(client.is_authenticated)
        self.assertEqual(
            request.full_url,
            "https://platform.example/api/v1/auth/login",
        )
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {
                "tenant_id": "tenant-1",
                "email": "operator@example.com",
                "password": "platform-password",
                "device_id": "device-1",
            },
        )

    def test_oidc_device_flow_opens_safe_challenge_and_keeps_token_in_memory(self):
        issuer = "https://identity.example.test/realms/email-platform"
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "device_authorization_endpoint": f"{issuer}/protocol/openid-connect/auth/device",
                        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    }
                ),
                FakeResponse(
                    {
                        "device_code": "opaque-device-code",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": f"{issuer}/device",
                        "verification_uri_complete": f"{issuer}/device?user_code=ABCD-EFGH",
                        "expires_in": 600,
                        "interval": 1,
                    }
                ),
                FakeResponse({"error": "authorization_pending"}, status=400),
                FakeResponse(
                    {
                        "access_token": "short-lived-access",
                        "refresh_token": "device-refresh",
                        "token_type": "Bearer",
                        "expires_in": 300,
                    }
                ),
            ]
        )
        store = MemorySessionStore()
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        challenges: list[DeviceAuthorizationChallenge] = []
        waits: list[float] = []

        expires = client.login_with_device_authorization(
            challenges.append,
            sleep=waits.append,
            monotonic=lambda: 0,
        )

        self.assertEqual(expires, 300)
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "device-refresh")
        self.assertEqual(challenges[0].user_code, "ABCD-EFGH")
        self.assertNotIn("opaque-device-code", repr(challenges[0]))
        self.assertEqual(waits, [1, 1])
        authorization_request = opener.requests[2][0]
        self.assertEqual(
            urllib.parse.parse_qs(authorization_request.data.decode("ascii")),
            {"client_id": ["email-platform-desktop"], "scope": ["openid profile email"]},
        )
        all_request_data = "\n".join(
            request.data.decode("ascii") if request.data else ""
            for request, _ in opener.requests
        ).lower()
        self.assertNotIn("password", all_request_data)
        self.assertNotIn("short-lived-access", all_request_data)

    def test_oidc_authorization_code_uses_loopback_pkce_and_rotatable_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        store = MemorySessionStore()
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    }
                ),
                FakeResponse(
                    {
                        "access_token": "short-lived-access",
                        "refresh_token": "rotatable-refresh",
                        "token_type": "Bearer",
                        "expires_in": 300,
                    }
                ),
            ]
        )

        class FakeReceiver:
            redirect_uri = "http://127.0.0.1:54321/callback"
            expected_state = None

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def wait_for_code(self, *, expected_state, timeout, cancelled):
                self.expected_state = expected_state
                self.assert_timeout = timeout
                self.assert_cancelled = cancelled()
                return "one-time-code"

        receiver = FakeReceiver()
        urls = []
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        expires = client.login_with_authorization_code(
            urls.append, loopback_factory=lambda: receiver
        )

        self.assertEqual(expires, 300)
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "rotatable-refresh")
        authorization = urllib.parse.urlsplit(urls[0])
        query = urllib.parse.parse_qs(authorization.query)
        self.assertEqual(query["state"], [receiver.expected_state])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["redirect_uri"], [receiver.redirect_uri])
        self.assertEqual(query["response_type"], ["code"])

        token_request = opener.requests[2][0]
        form = urllib.parse.parse_qs(token_request.data.decode("ascii"))
        verifier = form["code_verifier"][0]
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(query["code_challenge"], [expected_challenge])
        self.assertEqual(form["code"], ["one-time-code"])
        self.assertEqual(form["redirect_uri"], [receiver.redirect_uri])
        self.assertNotIn("password", form)

    def test_card_reveal_step_up_isolated_from_primary_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        store = MemorySessionStore()
        store.save("primary-refresh")
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                        "revocation_endpoint": f"{issuer}/protocol/openid-connect/revoke",
                    }
                ),
                FakeResponse(
                    {
                        "access_token": "step-up-access",
                        "refresh_token": "step-up-refresh",
                        "token_type": "Bearer",
                        "expires_in": 120,
                    }
                ),
                EmptyResponse(),
                FakeResponse(
                    {
                        "challenge_id": "challenge-1",
                        "acr_values": DEFAULT_CARD_REVEAL_ACR_VALUES,
                        "expires_at": "2026-08-20T00:01:00Z",
                    }
                ),
            ]
        )

        class FakeReceiver:
            redirect_uri = "http://127.0.0.1:54321/callback"
            expected_state = None

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def wait_for_code(self, *, expected_state, timeout, cancelled):
                self.expected_state = expected_state
                self.assertEqual(timeout, 300.0)
                self.assertFalse(cancelled())
                return "step-up-code"

            def assertEqual(self, first, second):
                if first != second:
                    raise AssertionError(f"{first!r} != {second!r}")

            def assertFalse(self, value):
                if value:
                    raise AssertionError(f"expected false, got {value!r}")

        receiver = FakeReceiver()
        urls = []
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("primary-access")

        step_up = client.reauthenticate_for_card_reveal(
            urls.append,
            acr_values=DEFAULT_CARD_REVEAL_ACR_VALUES,
            loopback_factory=lambda: receiver,
        )
        challenge = client.create_card_reveal_challenge("allocation-1")

        self.assertEqual(step_up.expires_in, 120)
        self.assertNotIn("step-up-access", repr(step_up))
        self.assertEqual(store.load(), "primary-refresh")
        self.assertTrue(client.is_authenticated)
        self.assertEqual(
            challenge,
            CardRevealChallenge(
                challenge_id="challenge-1",
                acr_values=DEFAULT_CARD_REVEAL_ACR_VALUES,
                expires_at="2026-08-20T00:01:00Z",
            ),
        )

        authorization = urllib.parse.urlsplit(urls[0])
        query = urllib.parse.parse_qs(authorization.query)
        self.assertEqual(query["state"], [receiver.expected_state])
        self.assertEqual(query["prompt"], ["login"])
        self.assertEqual(query["max_age"], ["0"])
        self.assertEqual(
            query["acr_values"], [DEFAULT_CARD_REVEAL_ACR_VALUES]
        )
        self.assertEqual(query["code_challenge_method"], ["S256"])

        token_form = urllib.parse.parse_qs(
            opener.requests[2][0].data.decode("ascii")
        )
        verifier = token_form["code_verifier"][0]
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(query["code_challenge"], [expected_challenge])
        revoke_form = urllib.parse.parse_qs(
            opener.requests[3][0].data.decode("ascii")
        )
        self.assertEqual(revoke_form["token"], ["step-up-refresh"])
        self.assertEqual(revoke_form["token_type_hint"], ["refresh_token"])
        self.assertEqual(
            opener.requests[4][0].get_header("Authorization"),
            "Bearer primary-access",
        )

    def test_refresh_rotates_dpapi_boundary_and_invalid_grant_clears_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        config = {
            "mode": "oidc",
            "issuer": issuer,
            "client_id": "email-platform-web",
            "desktop_client_id": "email-platform-desktop",
            "audience": "email-platform-api",
        }
        discovery = {
            "token_endpoint": f"{issuer}/protocol/openid-connect/token"
        }
        store = MemorySessionStore()
        store.save("old-refresh")
        opener = SequenceOpener(
            [
                FakeResponse(config),
                FakeResponse(discovery),
                FakeResponse(
                    {
                        "access_token": "new-access",
                        "refresh_token": "new-refresh",
                        "token_type": "Bearer",
                        "expires_in": 600,
                    }
                ),
            ]
        )
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        self.assertEqual(client.refresh_oidc_session(), 600)
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "new-refresh")
        refresh_form = urllib.parse.parse_qs(
            opener.requests[2][0].data.decode("ascii")
        )
        self.assertEqual(refresh_form["refresh_token"], ["old-refresh"])

        rejected = SequenceOpener(
            [
                FakeResponse(config),
                FakeResponse(discovery),
                FakeResponse({"error": "invalid_grant"}, status=400),
            ]
        )
        client = PlatformClient(
            "https://platform.example", opener=rejected, session_store=store
        )
        client.set_access_token("stale-access")
        with self.assertRaises(PlatformDeviceAuthorizationError):
            client.refresh_oidc_session()
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(store.load())

    def test_loopback_callback_ignores_forged_state_and_accepts_valid_code(self):
        with LoopbackAuthorizationReceiver() as receiver:
            parsed = urllib.parse.urlsplit(receiver.redirect_uri)
            forged = socket.create_connection(("127.0.0.1", parsed.port))
            valid = socket.create_connection(("127.0.0.1", parsed.port))
            with forged, valid:
                forged.sendall(
                    b"GET /callback?code=stolen&state=forged HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n\r\n"
                )
                valid.sendall(
                    b"GET /callback?code=valid-code&state=expected-state HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n\r\n"
                )
                code = receiver.wait_for_code(
                    expected_state="expected-state",
                    timeout=1,
                    cancelled=lambda: False,
                )
                self.assertEqual(code, "valid-code")

    def test_cancelled_pkce_attempt_cannot_overwrite_newer_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        store = MemorySessionStore()
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    }
                ),
                FakeResponse(
                    {
                        "access_token": "stale-access",
                        "refresh_token": "stale-refresh",
                        "token_type": "Bearer",
                        "expires_in": 300,
                    }
                ),
            ]
        )
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )

        class CancellingReceiver:
            redirect_uri = "http://127.0.0.1:54322/callback"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def wait_for_code(self, **_):
                client.cancel_authentication()
                client.set_access_token("new-access")
                store.save("new-refresh")
                return "stale-code"

        with self.assertRaises(PlatformDeviceAuthorizationError) as raised:
            client.login_with_authorization_code(
                lambda _: None,
                loopback_factory=CancellingReceiver,
            )
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "new-refresh")

    def test_oidc_device_flow_rejects_cross_origin_discovery(self):
        issuer = "https://identity.example.test/realms/email-platform"
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "device_authorization_endpoint": "https://evil.example/device",
                        "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    }
                ),
            ]
        )
        client = PlatformClient("https://platform.example", opener=opener)
        with self.assertRaises(PlatformProtocolError):
            client.login_with_device_authorization(lambda _: None, sleep=lambda _: None)

    def test_login_rejects_malformed_token_response(self):
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse({"expires_in": 900})),
        )
        with self.assertRaises(PlatformProtocolError):
            client.login("tenant-1", "user@example.com", "password", "device-1")
        self.assertFalse(client.is_authenticated)

    def test_requires_an_in_memory_access_token(self):
        client = PlatformClient("https://platform.example")
        with self.assertRaises(PlatformAuthenticationRequiredError):
            client.me()
        client.set_access_token("access-secret")
        self.assertTrue(client.is_authenticated)
        client.clear_access_token()
        self.assertFalse(client.is_authenticated)

    def test_me_sends_bearer_and_saves_server_trace_id(self):
        opener = RecordingOpener(FakeResponse({"user_id": "user-1"}))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.me()

        request, timeout = opener.requests[0]
        self.assertEqual(result, {"user_id": "user-1"})
        self.assertEqual(request.full_url, "https://platform.example/api/v1/me")
        self.assertEqual(request.get_header("Authorization"), "Bearer access-secret")
        self.assertEqual(timeout, DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(client.last_trace_id, "server-trace")

    def test_create_task_has_a_strict_non_secret_payload(self):
        opener = RecordingOpener(FakeResponse({"task_id": "task-1"}))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        client.create_task(
            "mail_code", "request-1", client_reference="desktop-job-1"
        )

        request, _ = opener.requests[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(
            body,
            {
                "type": "mail_code",
                "idempotency_key": "request-1",
                "client_reference": "desktop-job-1",
            },
        )
        serialized = request.data.decode("utf-8").lower()
        for forbidden in (
            "password",
            "sub2",
            "proxy",
            "group",
            "concurrency",
            "refresh_token",
            "token",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_password_can_only_be_sent_to_login_not_tasks(self):
        login_opener = RecordingOpener(
            FakeResponse({"access_token": "platform-access", "expires_in": 900})
        )
        login_client = PlatformClient(
            "https://platform.example", opener=login_opener
        )
        login_client.login(
            "tenant-1", "user@example.com", "platform-password", "device-1"
        )
        login_request, _ = login_opener.requests[0]
        self.assertIn(b'"password"', login_request.data)
        self.assertTrue(login_request.full_url.endswith("/auth/login"))

        task_opener = RecordingOpener(FakeResponse({"task_id": "task-1"}))
        task_client = PlatformClient(
            "https://platform.example", opener=task_opener
        )
        task_client.set_access_token("platform-access")
        task_client.create_task("mail_code", "request-1")
        task_request, _ = task_opener.requests[0]
        task_body = task_request.data.decode("utf-8").lower()
        for forbidden in (
            "password",
            "sub2",
            "proxy",
            "group",
            "concurrency",
            "token",
        ):
            self.assertNotIn(forbidden, task_body)

    def test_get_task_url_quotes_the_identifier(self):
        opener = RecordingOpener(FakeResponse({"task_id": "task/1"}))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")
        client.get_task("task/1")
        request, _ = opener.requests[0]
        self.assertEqual(
            request.full_url, "https://platform.example/api/v1/tasks/task%2F1"
        )

    def test_list_tasks_is_bounded_and_returns_safe_trace_snapshots(self):
        response = {
            "id": "task-1",
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "device_id": "device-1",
            "type": "mail_code",
            "idempotency_key": "request-1",
            "client_reference": None,
            "trace_id": "00000000-0000-0000-0000-000000000001",
            "status": "created",
            "expires_at": "2026-08-19T12:30:00+00:00",
            "closed_at": None,
            "created_at": "2026-08-19T12:00:00+00:00",
        }
        opener = RecordingOpener(FakeResponse([response]))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("platform-access")

        tasks = client.list_tasks(limit=25)

        self.assertEqual(len(tasks), 1)
        self.assertIsInstance(tasks[0], TaskSnapshot)
        self.assertEqual(tasks[0].trace_id, response["trace_id"])
        self.assertTrue(opener.requests[0][0].full_url.endswith("/tasks?limit=25"))
        self.assertNotIn("idempotency_key", repr(tasks[0]))
        with self.assertRaises(ValueError):
            client.list_tasks(limit=101)

    def test_close_task_and_logout_cleanup_use_only_captured_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        opener = SequenceOpener(
            [
                FakeResponse({}),
                FakeResponse({}),
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "revocation_endpoint": (
                            f"{issuer}/protocol/openid-connect/revoke"
                        )
                    }
                ),
                EmptyResponse(),
            ]
        )
        store = MemorySessionStore()
        store.save("old-refresh-token")
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("old-session-token")
        client.close_task("task/unsafe")
        first_request = opener.requests[0][0]
        self.assertTrue(first_request.full_url.endswith("/tasks/task%2Funsafe/close"))

        cleanup = client.prepare_logout_cleanup("task/unsafe")
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(store.load())
        client.set_access_token("new-session-token")
        store.save("new-refresh-token")
        cleanup()
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "new-refresh-token")
        second_request = opener.requests[1][0]
        self.assertEqual(
            second_request.headers["Authorization"], "Bearer old-session-token"
        )
        revocation_request = opener.requests[4][0]
        self.assertEqual(
            revocation_request.full_url,
            f"{issuer}/protocol/openid-connect/revoke",
        )
        self.assertEqual(
            urllib.parse.parse_qs(revocation_request.data.decode("ascii")),
            {
                "client_id": ["email-platform-desktop"],
                "token": ["old-refresh-token"],
                "token_type_hint": ["refresh_token"],
            },
        )
        self.assertEqual(store.load(), "new-refresh-token")

    def test_logout_revocation_failure_never_restores_local_refresh_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        store = MemorySessionStore()
        store.save("old-refresh-token")
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "mode": "oidc",
                        "issuer": issuer,
                        "client_id": "email-platform-web",
                        "desktop_client_id": "email-platform-desktop",
                        "audience": "email-platform-api",
                    }
                ),
                FakeResponse(
                    {
                        "revocation_endpoint": (
                            f"{issuer}/protocol/openid-connect/revoke"
                        )
                    }
                ),
                FakeResponse({"error": "temporarily_unavailable"}, status=503),
            ]
        )
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("old-access-token")

        cleanup = client.prepare_logout_cleanup(None)
        self.assertIsNone(store.load())
        store.save("new-refresh-token")

        with self.assertRaises(PlatformDeviceAuthorizationError):
            cleanup()

        self.assertEqual(store.load(), "new-refresh-token")
        self.assertTrue(client.is_authenticated is False)

    def test_create_mail_session_quotes_id_and_sends_empty_body(self):
        opener = RecordingOpener(
            FakeResponse(
                {
                    "id": "session-1",
                    "email_masked": "m***@example.com",
                    "status": "waiting",
                    "expires_at": "2026-08-19T12:00:00Z",
                    "session_token": "s" * 43,
                }
            )
        )
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.create_mail_session("task/1")

        request, _ = opener.requests[0]
        self.assertEqual(
            result,
            MailSessionSnapshot(
                "session-1",
                "m***@example.com",
                "waiting",
                "2026-08-19T12:00:00Z",
                session_token="s" * 43,
            ),
        )
        self.assertEqual(
            request.full_url,
            "https://platform.example/api/v1/tasks/task%2F1/mail-sessions",
        )
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Authorization"), "Bearer access-secret")
        self.assertNotIn("s" * 43, repr(result))

    def test_get_mail_code_quotes_id_and_parses_optional_code(self):
        opener = RecordingOpener(FakeResponse({"status": "consumed", "code": "123456"}))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.get_mail_code("session/1", "opaque-session-token")

        request, _ = opener.requests[0]
        self.assertEqual(result, MailCodeSnapshot("consumed", "123456"))
        self.assertEqual(
            request.full_url,
            "https://platform.example/api/v1/mail-sessions/session%2F1/code",
        )
        self.assertEqual(
            request.get_header("X-mail-session-token"),
            "opaque-session-token",
        )
        waiting_opener = RecordingOpener(FakeResponse({"status": "waiting"}))
        waiting_client = PlatformClient("https://platform.example", opener=waiting_opener)
        waiting_client.set_access_token("access-secret")
        self.assertEqual(
            waiting_client.get_mail_code("session-1", "opaque-session-token"),
            MailCodeSnapshot("waiting"),
        )

    def test_revoke_mail_session_sends_opaque_session_token(self):
        opener = RecordingOpener(
            FakeResponse(
                {
                    "id": "session-1",
                    "email_masked": "m***@example.com",
                    "status": "revoked",
                    "expires_at": "2026-08-19T12:00:00Z",
                }
            )
        )
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.revoke_mail_session("session/1", "opaque-session-token")

        request, _ = opener.requests[0]
        self.assertEqual(result.status, "revoked")
        self.assertEqual(
            request.get_header("X-mail-session-token"),
            "opaque-session-token",
        )

    def test_mail_responses_reject_unknown_sensitive_fields_and_wrong_types(self):
        for payload in (
            {
                "id": "session-1",
                "email_masked": "m***@example.com",
                "status": "waiting",
                "expires_at": "2026-08-19T12:00:00Z",
                "password": "secret",
            },
                {"status": "consumed", "code": "123456", "body": "message"},
            {"status": "consumed", "token": "secret"},
            {"status": "consumed", "secret_ref": "opaque"},
            {"status": "consumed", "code": 123456},
        ):
            with self.subTest(payload=payload):
                opener = RecordingOpener(FakeResponse(payload))
                client = PlatformClient("https://platform.example", opener=opener)
                client.set_access_token("access-secret")
                with self.assertRaises(PlatformProtocolError):
                    (
                        client.create_mail_session("task-1")
                        if "id" in payload
                        else client.get_mail_code(
                            "session-1", "opaque-session-token"
                        )
                    )

    def test_upload_requests_keep_sub2_policy_server_side(self):
        payload = {
            "id": "upload-1",
            "task_id": "task-1",
            "status": "queued",
            "business_name": "Example Store",
            "policy_version": "sub2-v1",
            "external_ref": None,
            "error_code": None,
            "created_at": "2026-08-19T12:00:00Z",
            "updated_at": "2026-08-19T12:00:00Z",
        }
        opener = RecordingOpener(FakeResponse(payload))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")
        result = client.create_upload_job("task/1", "Example Store", "upload-1")
        self.assertEqual(result, UploadJobSnapshot(**payload))
        request, _ = opener.requests[0]
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {"business_name": "Example Store", "idempotency_key": "upload-1"},
        )
        for forbidden in ("password", "token", "proxy", "group", "concurrency", "secret_ref"):
            self.assertNotIn(forbidden, request.data.decode("utf-8").lower())

    def test_upload_response_rejects_policy_secrets(self):
        payload = {
            "id": "upload-1",
            "task_id": "task-1",
            "status": "queued",
            "business_name": "Example Store",
            "policy_version": "sub2-v1",
            "external_ref": None,
            "error_code": None,
            "created_at": "2026-08-19T12:00:00Z",
            "updated_at": "2026-08-19T12:00:00Z",
            "proxy_id": "2940",
        }
        client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(FakeResponse(payload))
        )
        client.set_access_token("access-secret")
        with self.assertRaises(PlatformProtocolError):
            client.get_upload_job("upload-1")

    def test_card_allocation_request_has_no_raw_card_fields(self):
        payload = {
            "id": "allocation-1",
            "card_masked": "VISA •••• 1111",
            "brand": "VISA",
            "expiry_month": 12,
            "expiry_year": 2030,
            "status": "active",
            "expires_at": "2026-08-19T12:00:00Z",
        }
        opener = RecordingOpener(FakeResponse(payload))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")
        snapshot = client.allocate_card("task/1")
        self.assertEqual(snapshot, CardAllocationSnapshot(**payload))
        request, _ = opener.requests[0]
        self.assertIsNone(request.data)
        self.assertTrue(request.full_url.endswith("/tasks/task%2F1/card-allocations"))
        for forbidden in ("pan", "cvv", "password", "secret_ref", "provider_ref"):
            self.assertNotIn(forbidden, repr(snapshot).lower())

    def test_card_reveal_requires_one_time_grant_and_never_requests_cvv(self):
        opener = SequenceOpener(
            [
                FakeResponse(
                    {
                        "challenge_id": "challenge-1",
                        "acr_values": DEFAULT_CARD_REVEAL_ACR_VALUES,
                        "expires_at": "2026-08-19T12:00:30Z",
                    }
                ),
                FakeResponse(
                    {
                        "reveal_grant": "opaque-reveal-grant",
                        "expires_at": "2026-08-19T12:00:45Z",
                    }
                ),
                FakeResponse(
                    {
                        "id": "reveal-1",
                        "allocation_id": "allocation/1",
                        "trace_id": "task-trace",
                        "card_masked": "VISA •••• 1111",
                        "brand": "VISA",
                        "expiry_month": 12,
                        "expiry_year": 2030,
                        "pan": "4111111111111111",
                        "reveal_expires_at": "2026-08-19T12:00:45Z",
                    }
                ),
            ]
        )
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("primary-access")

        challenge = client.create_card_reveal_challenge("allocation/1")
        grant = client.create_card_reveal_grant(
            "allocation/1", challenge.challenge_id, "step-up-access"
        )
        snapshot = client.reveal_card_allocation(
            "allocation/1", grant.reveal_grant
        )

        self.assertEqual(
            grant,
            CardRevealGrant(
                reveal_grant="opaque-reveal-grant",
                expires_at="2026-08-19T12:00:45Z",
            ),
        )
        self.assertFalse(hasattr(snapshot, "cvv"))
        challenge_request, _ = opener.requests[0]
        self.assertEqual(challenge_request.get_method(), "POST")
        self.assertIsNone(challenge_request.data)
        self.assertTrue(
            challenge_request.full_url.endswith(
                "/card-allocations/allocation%2F1/reveal-challenges"
            )
        )
        grant_request, _ = opener.requests[1]
        self.assertEqual(
            grant_request.get_header("Authorization"), "Bearer step-up-access"
        )
        self.assertEqual(
            json.loads(grant_request.data), {"challenge_id": "challenge-1"}
        )
        reveal_request, _ = opener.requests[2]
        self.assertEqual(
            reveal_request.get_header("Authorization"), "Bearer primary-access"
        )
        self.assertEqual(
            json.loads(reveal_request.data),
            {
                "reveal_grant": "opaque-reveal-grant",
                "fields": ["pan", "expiry"],
            },
        )
        self.assertNotIn("cvv", reveal_request.data.decode("utf-8").lower())
        self.assertNotIn("4111111111111111", repr(snapshot))
        self.assertNotIn("opaque-reveal-grant", repr(grant))
        self.assertNotIn("secret_ref", repr(snapshot).lower())

    def test_rejected_step_up_grant_does_not_clear_primary_session(self):
        headers = Message()
        body = json.dumps(
            {
                "error": {
                    "code": "forbidden",
                    "message": "Required authentication level missing",
                }
            }
        ).encode("utf-8")
        rejected = urllib.error.HTTPError(
            "https://platform.example/api/v1/card-allocations/a/reveal-grants",
            403,
            "Forbidden",
            headers,
            io.BytesIO(body),
        )
        client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(rejected)
        )
        client.set_access_token("primary-access")

        with self.assertRaises(PlatformDeviceAuthorizationError):
            client.create_card_reveal_grant(
                "allocation-1", "challenge-1", "step-up-access"
            )

        self.assertTrue(client.is_authenticated)

    def test_parses_unified_error_envelope(self):
        headers = Message()
        headers["X-Trace-Id"] = "header-trace"
        body = json.dumps(
            {
                "error": {
                    "code": "task_not_found",
                    "message": "任务不存在",
                    "trace_id": "body-trace",
                    "details": {"task_id": "missing"},
                }
            }
        ).encode("utf-8")
        http_error = urllib.error.HTTPError(
            "https://platform.example/api/v1/tasks/missing",
            404,
            "Not Found",
            headers,
            io.BytesIO(body),
        )
        client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(http_error)
        )
        client.set_access_token("access-secret")

        with self.assertRaises(PlatformApiError) as caught:
            client.get_task("missing")

        self.assertEqual(caught.exception.code, "task_not_found")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.trace_id, "body-trace")
        self.assertEqual(caught.exception.details, {"task_id": "missing"})
        self.assertEqual(client.last_trace_id, "body-trace")

    def test_classifies_authentication_and_protocol_errors(self):
        auth_body = json.dumps(
            {"error": {"code": "unauthorized", "message": "登录已失效"}}
        ).encode("utf-8")
        auth_error = urllib.error.HTTPError(
            "https://platform.example/api/v1/me",
            401,
            "Unauthorized",
            Message(),
            io.BytesIO(auth_body),
        )
        client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(auth_error)
        )
        client.set_access_token("access-secret")
        with self.assertRaises(PlatformAuthenticationError):
            client.me()

        invalid_error = urllib.error.HTTPError(
            "https://platform.example/api/v1/me",
            500,
            "Server Error",
            Message(),
            io.BytesIO(b"not-json"),
        )
        client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(invalid_error)
        )
        client.set_access_token("access-secret")
        with self.assertRaises(PlatformProtocolError):
            client.me()

    def test_classifies_socket_timeout(self):
        client = PlatformClient(
            "https://platform.example",
            timeout=3,
            opener=RecordingOpener(urllib.error.URLError(socket.timeout())),
        )
        client.set_access_token("access-secret")
        with self.assertRaises(PlatformTimeoutError) as caught:
            client.me()
        self.assertIn("3 秒", str(caught.exception))
        self.assertIsNotNone(client.last_trace_id)


if __name__ == "__main__":
    unittest.main()
