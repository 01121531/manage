import io
import base64
import hashlib
import json
import os
import socket
import threading
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from unittest import mock

from platform_client import (
    AUTH_CONFIG_FIELDS,
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
    PlatformSessionError,
    LoopbackAuthorizationReceiver,
    PlatformTimeoutError,
    StepUpAuthorization,
    UploadJobSnapshot,
    DeviceAuthorizationChallenge,
    TaskRecoverySnapshot,
    TaskSnapshot,
    TaskTimelineAllocationSnapshot,
    TaskTimelineMailSnapshot,
    TaskTransitionCleanup,
)
from platform.schemas import AuthConfigResponse
from session_store import MemorySessionStore


_MAX_TEST_JSON_RESPONSE_BYTES = 64 * 1024


class RecordingBytesIO(io.BytesIO):
    def __init__(self, value: bytes):
        super().__init__(value)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


class FakeResponse:
    def __init__(self, payload, *, trace_id="server-trace", status=200):
        self.body = json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = Message()
        self.headers["X-Trace-Id"] = trace_id
        self.read_sizes: list[int] = []

    def read(self, size: int = -1):
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class EmptyResponse(FakeResponse):
    def __init__(self, *, status=204):
        super().__init__({}, status=status)
        self.body = b""


class RawResponse(FakeResponse):
    def __init__(self, body: bytes, *, trace_id="server-trace", status=200):
        super().__init__({}, trace_id=trace_id, status=status)
        self.body = body


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


def task_timeline_payload() -> dict[str, object]:
    task_trace_id = "00000000-0000-0000-0000-000000000016"
    return {
        "workbench_step": "uploading",
        "task": {
            "id": "task-1",
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "device_id": "device-1",
            "type": "mail_code",
            "idempotency_key": "request-1",
            "client_reference": None,
            "trace_id": task_trace_id,
            "status": "created",
            "expires_at": "2026-08-19T12:30:00+00:00",
            "closed_at": None,
            "created_at": "2026-08-19T12:00:00+00:00",
        },
        "mail_session": {
            "id": "session-1",
            "email_masked": "m***@example.test",
            "status": "consumed",
            "expires_at": "2026-08-19T12:20:00+00:00",
            "consumed_at": "2026-08-19T12:05:00+00:00",
            "created_at": "2026-08-19T12:01:00+00:00",
        },
        "card_allocations": [
            {
                "id": "allocation-1",
                "card_masked": "**** **** **** 4242",
                "brand": "visa",
                "status": "active",
                "expires_at": "2026-08-19T12:25:00+00:00",
                "released_at": None,
                "created_at": "2026-08-19T12:02:00+00:00",
            }
        ],
        "uploads": [
            {
                "id": "upload-1",
                "business_name": "Example Business",
                "status": "running",
                "policy_version": "sub2-v1",
                "external_ref": None,
                "error_code": None,
                "created_at": "2026-08-19T12:06:00+00:00",
                "updated_at": "2026-08-19T12:07:00+00:00",
            }
        ],
        "events": [
            {
                "id": "event-1",
                "event_type": "upload.started",
                "action": "upload.submit",
                "result": "success",
                "entity_type": "upload_job",
                "entity_id": "upload-1",
                "policy_version": "sub2-v1",
                "created_at": "2026-08-19T12:06:00+00:00",
            }
        ],
    }


def task_response_payload(
    *,
    task_id: str = "task-1",
    status: str = "created",
    client_reference: str | None = None,
) -> dict[str, object]:
    return {
        "id": task_id,
        "tenant_id": "tenant-1",
        "user_id": "user-1",
        "device_id": "device-1",
        "type": "mail_code",
        "idempotency_key": "request-1",
        "client_reference": client_reference,
        "trace_id": "00000000-0000-0000-0000-000000000016",
        "status": status,
        "expires_at": "2026-08-19T12:30:00+00:00",
        "closed_at": None,
        "created_at": "2026-08-19T12:00:00+00:00",
    }


def padded_json_bytes(payload: object, size: int) -> bytes:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(raw) > size:
        raise AssertionError("test JSON exceeds requested size")
    return raw + (b" " * (size - len(raw)))


class PlatformClientTests(unittest.TestCase):
    def test_auth_config_contract_matches_api_and_accepts_current_response(self):
        payload = {
            "mode": "oidc",
            "issuer": "https://identity.example.test/realms/email-platform",
            "client_id": "email-platform-web",
            "desktop_client_id": "email-platform-desktop",
            "audience": "email-platform-api",
            "admin_role_change_acr": "urn:email-platform:acr:mfa",
        }
        self.assertEqual(AUTH_CONFIG_FIELDS, frozenset(AuthConfigResponse.model_fields))
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse(payload)),
            session_store=MemorySessionStore(),
        )

        self.assertEqual(client.get_auth_config(), payload)

    def test_task_transition_cleanup_uses_captured_access_after_logout(self):
        opener = RecordingOpener(
            FakeResponse(
                task_response_payload(
                    task_id="task-created-after-logout", status="closed"
                )
            )
        )
        client = PlatformClient(
            "https://platform.example",
            opener=opener,
            session_store=MemorySessionStore(),
        )
        client.set_access_token("captured-access")
        transition = client.begin_task_transition()

        client.prepare_logout_cleanup(None)
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(transition.cancel())
        cleanup = transition.attach("task-created-after-logout")
        self.assertIsNotNone(cleanup)
        cleanup()
        transition.worker_finished()

        self.assertEqual(len(opener.requests), 1)
        request, _ = opener.requests[0]
        self.assertTrue(request.full_url.endswith("/tasks/task-created-after-logout/close"))
        self.assertEqual(request.get_header("Authorization"), "Bearer captured-access")
        self.assertNotIn("captured-access", repr(transition))

    def test_task_transition_cleanup_is_exactly_once_and_commit_preserves_task(self):
        client = mock.Mock()
        transition = TaskTransitionCleanup(client, "captured-access")
        transition.attach("task-1")
        first = transition.cancel()
        self.assertIsNotNone(first)
        self.assertIsNone(transition.cancel())
        self.assertIsNone(transition.attach("task-1"))
        first()
        self.assertIsNone(transition.worker_finished())
        self.assertFalse(transition.commit())
        client._close_task_with_access_token.assert_called_once_with(
            "task-1", "captured-access"
        )

        committed_client = mock.Mock()
        committed = TaskTransitionCleanup(committed_client, "another-access")
        committed.attach("task-2")
        self.assertIsNone(committed.worker_finished())
        self.assertTrue(committed.commit())
        self.assertIsNone(committed.cancel())
        committed_client._close_task_with_access_token.assert_not_called()

        late_client = mock.Mock()
        late = TaskTransitionCleanup(late_client, "late-access")
        late.attach("task-3")
        late.worker_finished()
        late_cleanup = late.cancel()
        self.assertIsNotNone(late_cleanup)
        self.assertIsNone(late._access_token)
        late_cleanup()
        late_client._close_task_with_access_token.assert_called_once_with(
            "task-3", "late-access"
        )

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

    def test_oidc_device_flow_applies_slow_down_and_surfaces_denial(self):
        issuer = "https://identity.example.test/realms/email-platform"

        def responses(*token_responses):
            return [
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
                        "device_authorization_endpoint": f"{issuer}/device-auth",
                        "token_endpoint": f"{issuer}/token",
                    }
                ),
                FakeResponse(
                    {
                        "device_code": "opaque-device-code",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": f"{issuer}/device",
                        "expires_in": 600,
                        "interval": 1,
                    }
                ),
                *token_responses,
            ]

        opener = SequenceOpener(
            responses(
                FakeResponse({"error": "slow_down"}, status=400),
                FakeResponse({"error": "authorization_pending"}, status=400),
                FakeResponse(
                    {
                        "access_token": "short-lived-access",
                        "refresh_token": "device-refresh",
                        "token_type": "Bearer",
                        "expires_in": 300,
                    }
                ),
            )
        )
        waits: list[float] = []
        clock = [0.0]

        def sleep(seconds: float) -> None:
            waits.append(seconds)
            clock[0] += seconds

        client = PlatformClient("https://platform.example", opener=opener)
        self.assertEqual(
            client.login_with_device_authorization(
                lambda _: None,
                sleep=sleep,
                monotonic=lambda: clock[0],
            ),
            300,
        )
        self.assertEqual(waits, [1, 6, 6])

        denied_client = PlatformClient(
            "https://platform.example",
            opener=SequenceOpener(
                responses(FakeResponse({"error": "access_denied"}, status=400))
            ),
        )
        with self.assertRaises(PlatformDeviceAuthorizationError) as denied:
            denied_client.login_with_device_authorization(
                lambda _: None,
                sleep=lambda _: None,
                monotonic=lambda: 0,
            )
        self.assertEqual(denied.exception.code, "access_denied")
        self.assertFalse(denied_client.is_authenticated)

    def test_oidc_device_flow_never_polls_after_its_deadline(self):
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
                        "device_authorization_endpoint": f"{issuer}/device-auth",
                        "token_endpoint": f"{issuer}/token",
                    }
                ),
                FakeResponse(
                    {
                        "device_code": "opaque-device-code",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": f"{issuer}/device",
                        "expires_in": 3,
                        "interval": 5,
                    }
                ),
            ]
        )
        clock = [0.0]
        waits: list[float] = []

        def sleep(seconds: float) -> None:
            waits.append(seconds)
            clock[0] += seconds

        client = PlatformClient("https://platform.example", opener=opener)
        with self.assertRaises(PlatformDeviceAuthorizationError) as expired:
            client.login_with_device_authorization(
                lambda _: None,
                sleep=sleep,
                monotonic=lambda: clock[0],
            )
        self.assertEqual(expired.exception.code, "expired_token")
        self.assertEqual(waits, [3])
        self.assertEqual(len(opener.requests), 3)

    def test_oidc_device_flow_rejects_non_short_lifetime(self):
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
                        "device_authorization_endpoint": f"{issuer}/device-auth",
                        "token_endpoint": f"{issuer}/token",
                    }
                ),
                FakeResponse(
                    {
                        "device_code": "opaque-device-code",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": f"{issuer}/device",
                        "expires_in": 601,
                        "interval": 5,
                    }
                ),
            ]
        )
        client = PlatformClient("https://platform.example", opener=opener)
        with self.assertRaises(PlatformProtocolError):
            client.login_with_device_authorization(
                lambda _: None,
                sleep=lambda _: None,
                monotonic=lambda: 0,
            )
        self.assertEqual(len(opener.requests), 3)

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

    def test_failed_temporary_refresh_revocation_transfers_to_logout_cleanup(self):
        issuer = "https://identity.example.test/realms/email-platform"
        token_endpoint = f"{issuer}/protocol/openid-connect/token"
        revocation_endpoint = f"{issuer}/protocol/openid-connect/revoke"
        temporary_refresh = "temporary-refresh-secret"
        config = {
            "mode": "oidc",
            "issuer": issuer,
            "client_id": "email-platform-web",
            "desktop_client_id": "email-platform-desktop",
            "audience": "email-platform-api",
        }

        class TemporaryRevocationOpener:
            def __init__(self):
                self.revoked_tokens = []

            def __call__(self, request, *, timeout):
                del timeout
                if request.full_url.endswith("/auth/config"):
                    return FakeResponse(config)
                if request.full_url.endswith("/.well-known/openid-configuration"):
                    return FakeResponse(
                        {
                            "authorization_endpoint": f"{issuer}/authorize",
                            "token_endpoint": token_endpoint,
                            "revocation_endpoint": revocation_endpoint,
                        }
                    )
                if request.full_url == token_endpoint:
                    return FakeResponse(
                        {
                            "access_token": "temporary-access-secret",
                            "refresh_token": temporary_refresh,
                            "token_type": "Bearer",
                            "expires_in": 120,
                        }
                    )
                if request.full_url == revocation_endpoint:
                    form = urllib.parse.parse_qs(request.data.decode("ascii"))
                    self.revoked_tokens.append(form["token"][0])
                    if len(self.revoked_tokens) == 1:
                        return FakeResponse(
                            {"error": "raw-upstream-revocation-failure"}, status=503
                        )
                    return EmptyResponse()
                if request.full_url.endswith("/auth/logout"):
                    return FakeResponse({"status": "logged_out"})
                raise AssertionError(f"unexpected request: {request.full_url}")

        class FakeReceiver:
            redirect_uri = "http://127.0.0.1:54321/callback"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            @staticmethod
            def wait_for_code(**_):
                return "unlock-code"

        opener = TemporaryRevocationOpener()
        store = MemorySessionStore()
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("primary-access-secret")

        with self.assertRaises(PlatformSessionError) as raised:
            client.reauthenticate_for_unlock(
                lambda _url: None,
                expected_tenant_id="tenant-1",
                expected_user_id="user-1",
                expected_device_id="device-1",
                loopback_factory=FakeReceiver,
            )

        self.assertEqual(str(raised.exception), "无法撤销二次认证临时会话")
        failure = repr(raised.exception)
        self.assertNotIn(temporary_refresh, failure)
        self.assertNotIn(issuer, failure)
        self.assertNotIn("raw-upstream-revocation-failure", failure)
        self.assertEqual(opener.revoked_tokens, [temporary_refresh])

        cleanup = client.prepare_logout_cleanup(None)
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(store.load())
        cleanup()
        cleanup()

        self.assertEqual(
            opener.revoked_tokens,
            [temporary_refresh, temporary_refresh],
        )

    def test_unlock_reauthentication_is_forced_and_keeps_primary_session(self):
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
                    }
                ),
                FakeResponse(
                    {
                        "access_token": "unlock-only-access",
                        "token_type": "Bearer",
                        "expires_in": 90,
                    }
                ),
                FakeResponse(
                    {
                        "id": "user-1",
                        "tenant_id": "tenant-1",
                        "email": "operator@example.test",
                        "device_id": "device-1",
                        "role": "operator",
                    }
                ),
                FakeResponse(
                    {
                        "id": "user-1",
                        "tenant_id": "tenant-1",
                        "email": "operator@example.test",
                        "device_id": "device-1",
                        "role": "operator",
                    }
                ),
            ]
        )

        class FakeReceiver:
            redirect_uri = "http://127.0.0.1:54321/callback"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def wait_for_code(self, *, expected_state, timeout, cancelled):
                self.expected_state = expected_state
                return "unlock-code"

        receiver = FakeReceiver()
        urls = []
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("primary-access")

        profile = client.reauthenticate_for_unlock(
            urls.append,
            expected_tenant_id="tenant-1",
            expected_user_id="user-1",
            expected_device_id="device-1",
            loopback_factory=lambda: receiver,
        )
        client.me()

        self.assertEqual(profile["id"], "user-1")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(urls[0]).query)
        self.assertEqual(query["state"], [receiver.expected_state])
        self.assertEqual(query["prompt"], ["login"])
        self.assertEqual(query["max_age"], ["0"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertNotIn("acr_values", query)
        self.assertEqual(
            opener.requests[3][0].get_header("Authorization"),
            "Bearer unlock-only-access",
        )
        self.assertEqual(
            opener.requests[4][0].get_header("Authorization"),
            "Bearer primary-access",
        )
        self.assertEqual(store.load(), "primary-refresh")

    def test_unlock_reauthentication_rejects_different_identity(self):
        store = MemorySessionStore()
        store.save("primary-refresh")
        client = PlatformClient(
            "https://platform.example", session_store=store
        )
        client.set_access_token("primary-access")

        with (
            mock.patch.object(
                client,
                "_reauthenticate_with_pkce",
                return_value=StepUpAuthorization(
                    access_token="unlock-only-access", expires_in=90
                ),
            ),
            mock.patch.object(
                client,
                "_request_json",
                return_value={
                    "id": "other-user",
                    "tenant_id": "tenant-1",
                    "email": "other@example.test",
                    "device_id": "device-1",
                    "role": "operator",
                },
            ) as request_json,
        ):
            with self.assertRaises(PlatformDeviceAuthorizationError) as raised:
                client.reauthenticate_for_unlock(
                    lambda _url: None,
                    expected_tenant_id="tenant-1",
                    expected_user_id="user-1",
                    expected_device_id="device-1",
                )

        self.assertEqual(raised.exception.code, "identity_mismatch")
        self.assertEqual(
            request_json.call_args.kwargs["_access_token_override"],
            "unlock-only-access",
        )
        self.assertTrue(client.is_authenticated)
        self.assertEqual(store.load(), "primary-refresh")

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

    def test_logout_waits_for_late_refresh_and_retries_its_rotated_token(self):
        issuer = "https://identity.example.test/realms/email-platform"
        token_endpoint = f"{issuer}/protocol/openid-connect/token"
        revocation_endpoint = f"{issuer}/protocol/openid-connect/revoke"
        config = {
            "mode": "oidc",
            "issuer": issuer,
            "client_id": "email-platform-web",
            "desktop_client_id": "email-platform-desktop",
            "audience": "email-platform-api",
        }
        discovery = {
            "token_endpoint": token_endpoint,
            "revocation_endpoint": revocation_endpoint,
        }

        class RefreshRaceOpener:
            def __init__(self):
                self.requests = []
                self.refresh_started = threading.Event()
                self.release_refresh = threading.Event()
                self.revoked_tokens = []
                self.late_revocation_attempts = 0
                self.lock = threading.Lock()

            def __call__(self, request, *, timeout):
                with self.lock:
                    self.requests.append((request, timeout))
                if request.full_url.endswith("/auth/config"):
                    return FakeResponse(config)
                if request.full_url.endswith("/.well-known/openid-configuration"):
                    return FakeResponse(discovery)
                if request.full_url == token_endpoint:
                    self.refresh_started.set()
                    self.release_refresh.wait(2)
                    return FakeResponse(
                        {
                            "access_token": "late-access-secret",
                            "refresh_token": "late-refresh-secret",
                            "token_type": "Bearer",
                            "expires_in": 600,
                        }
                    )
                if request.full_url == revocation_endpoint:
                    form = urllib.parse.parse_qs(request.data.decode("ascii"))
                    token = form["token"][0]
                    self.revoked_tokens.append(token)
                    if token == "late-refresh-secret":
                        self.late_revocation_attempts += 1
                        if self.late_revocation_attempts == 1:
                            return FakeResponse(
                                {"error": "temporarily_unavailable"}, status=503
                            )
                    return EmptyResponse()
                if request.full_url.endswith("/auth/logout"):
                    return FakeResponse({"status": "logged_out"})
                raise AssertionError(f"unexpected request: {request.full_url}")

        opener = RefreshRaceOpener()
        store = MemorySessionStore()
        store.save("old-refresh-secret")
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("old-access-secret")
        refresh_errors = []
        refresh_thread = threading.Thread(
            target=lambda: self._capture_thread_error(
                refresh_errors, client.refresh_oidc_session
            )
        )
        refresh_thread.start()
        self.assertTrue(opener.refresh_started.wait(1))

        cleanup = client.prepare_logout_cleanup(None)
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(store.load())
        client._begin_auth_attempt()
        client.set_access_token("new-access-secret")
        store.save("new-refresh-secret")
        cleanup_errors = []
        cleanup_thread = threading.Thread(
            target=lambda: self._capture_thread_error(cleanup_errors, cleanup)
        )
        cleanup_thread.start()
        cleanup_thread.join(0.05)
        self.assertTrue(cleanup_thread.is_alive())
        self.assertEqual(opener.revoked_tokens, [])

        opener.release_refresh.set()
        refresh_thread.join(1)
        cleanup_thread.join(1)
        self.assertFalse(refresh_thread.is_alive())
        self.assertFalse(cleanup_thread.is_alive())
        self.assertEqual(len(refresh_errors), 1)
        self.assertIsInstance(refresh_errors[0], PlatformDeviceAuthorizationError)
        self.assertEqual(refresh_errors[0].code, "cancelled")
        self.assertEqual(len(cleanup_errors), 1)
        self.assertIsInstance(cleanup_errors[0], PlatformDeviceAuthorizationError)
        self.assertEqual(
            opener.revoked_tokens,
            ["old-refresh-secret", "late-refresh-secret"],
        )
        self.assertTrue(client.is_authenticated)
        self.assertEqual(client._access_token, "new-access-secret")
        self.assertEqual(store.load(), "new-refresh-secret")

        cleanup()
        self.assertEqual(
            opener.revoked_tokens,
            ["old-refresh-secret", "late-refresh-secret", "late-refresh-secret"],
        )
        self.assertTrue(client.is_authenticated)
        self.assertEqual(client._access_token, "new-access-secret")
        self.assertEqual(store.load(), "new-refresh-secret")
        combined_repr = repr(client) + repr(refresh_errors) + repr(cleanup_errors)
        for secret in (
            "old-refresh-secret",
            "late-refresh-secret",
            "new-refresh-secret",
            "late-access-secret",
        ):
            self.assertNotIn(secret, combined_repr)

    @staticmethod
    def _capture_thread_error(errors, action):
        try:
            action()
        except Exception as error:
            errors.append(error)

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
        profile = {
            "id": "user-1",
            "tenant_id": "tenant-1",
            "email": "user@example.test",
            "device_id": "device-1",
            "role": "operator",
        }
        opener = RecordingOpener(FakeResponse(profile))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.me()

        request, timeout = opener.requests[0]
        self.assertEqual(result, profile)
        self.assertEqual(request.full_url, "https://platform.example/api/v1/me")
        self.assertEqual(request.get_header("Authorization"), "Bearer access-secret")
        self.assertEqual(timeout, DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(client.last_trace_id, "server-trace")

    def test_me_rejects_unknown_sensitive_fields_and_invalid_identity(self):
        profile = {
            "id": "user-1",
            "tenant_id": "tenant-1",
            "email": "user@example.test",
            "device_id": "device-1",
            "role": "operator",
        }
        for payload in (
            {**profile, "pan": "4111111111111111"},
            {**profile, "session_token": "s" * 32},
            {**profile, "device_id": ""},
            {**profile, "role": 1},
        ):
            with self.subTest(payload=payload):
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("access-secret")
                with self.assertRaises(PlatformProtocolError):
                    client.me()

    def test_create_task_has_a_strict_non_secret_payload(self):
        opener = RecordingOpener(
            FakeResponse(
                task_response_payload(client_reference="desktop-job-1")
            )
        )
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

        task_opener = RecordingOpener(FakeResponse(task_response_payload()))
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
        opener = RecordingOpener(
            FakeResponse(task_response_payload(task_id="task/1"))
        )
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")
        client.get_task("task/1")
        request, _ = opener.requests[0]
        self.assertEqual(
            request.full_url, "https://platform.example/api/v1/tasks/task%2F1"
        )

    def test_create_get_and_close_task_share_strict_response_decoder(self):
        cases = (
            (
                lambda client: client.create_task("mail_code", "request-1"),
                task_response_payload(),
            ),
            (lambda client: client.get_task("task-1"), task_response_payload()),
            (
                lambda client: client.close_task("task-1"),
                task_response_payload(status="closed"),
            ),
        )
        for method, payload in cases:
            with self.subTest(method=method):
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("access-secret")
                self.assertIsInstance(method(client), TaskSnapshot)

                for field, value in (
                    ("pan", "4111111111111111"),
                    ("session_token", "s" * 32),
                ):
                    invalid_client = PlatformClient(
                        "https://platform.example",
                        opener=RecordingOpener(
                            FakeResponse({**payload, field: value})
                        ),
                    )
                    invalid_client.set_access_token("access-secret")
                    with self.assertRaises(PlatformProtocolError):
                        method(invalid_client)

    def test_get_and_close_task_reject_mismatched_response_id(self):
        for method in (
            lambda client: client.get_task("task-1"),
            lambda client: client.close_task("task-1"),
        ):
            with self.subTest(method=method):
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(
                        FakeResponse(task_response_payload(task_id="task-2"))
                    ),
                )
                client.set_access_token("access-secret")
                with self.assertRaises(PlatformProtocolError):
                    method(client)

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

    def test_get_task_timeline_decodes_safe_recovery_projection(self):
        payload = task_timeline_payload()
        opener = RecordingOpener(FakeResponse(payload))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("platform-access")

        snapshot = client.get_task_timeline("task-1")

        self.assertIsInstance(snapshot, TaskRecoverySnapshot)
        self.assertIsInstance(snapshot.task, TaskSnapshot)
        self.assertIsInstance(snapshot.mail_session, TaskTimelineMailSnapshot)
        self.assertIsInstance(
            snapshot.card_allocations[0], TaskTimelineAllocationSnapshot
        )
        self.assertIsInstance(snapshot.card_allocations, tuple)
        self.assertIsInstance(snapshot.uploads, tuple)
        self.assertEqual(snapshot.task.id, "task-1")
        self.assertEqual(snapshot.uploads[0].task_id, "task-1")
        self.assertEqual(snapshot.workbench_step, "uploading")
        self.assertEqual(snapshot.uploads[0].trace_id, snapshot.task.trace_id)
        self.assertTrue(
            opener.requests[0][0].full_url.endswith("/tasks/task-1/timeline")
        )
        serialized = repr(snapshot).lower()
        for forbidden in (
            "idempotency_key",
            "tenant_id",
            "user_id",
            "device_id",
            "event-1",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_task_timeline_accepts_previous_response_without_workbench_step(self):
        payload = task_timeline_payload()
        del payload["workbench_step"]
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse(payload)),
        )
        client.set_access_token("platform-access")

        snapshot = client.get_task_timeline("task-1")

        self.assertIsNone(snapshot.workbench_step)

    def test_task_timeline_rejects_invalid_workbench_step(self):
        payload = task_timeline_payload()
        payload["workbench_step"] = "revealing_secret"
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse(payload)),
        )
        client.set_access_token("platform-access")

        with self.assertRaises(PlatformProtocolError):
            client.get_task_timeline("task-1")

    def test_get_task_timeline_quotes_task_id(self):
        payload = task_timeline_payload()
        payload["task"]["id"] = "task/1"
        opener = RecordingOpener(FakeResponse(payload))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("platform-access")

        client.get_task_timeline("task/1")

        self.assertEqual(
            opener.requests[0][0].full_url,
            "https://platform.example/api/v1/tasks/task%2F1/timeline",
        )

    def test_task_timeline_rejects_mismatched_task_id_or_trace(self):
        cases = (("id", "other-task"), ("trace_id", ""))
        for field, value in cases:
            with self.subTest(field=field):
                payload = task_timeline_payload()
                payload["task"][field] = value
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("platform-access")

                with self.assertRaises(PlatformProtocolError):
                    client.get_task_timeline("task-1")

    def test_task_timeline_rejects_unknown_or_sensitive_fields(self):
        cases = (
            (None, "session_token", "opaque-secret"),
            ("task", "password", "secret"),
            ("mail_session", "session_token", "opaque-secret"),
            ("card_allocations", "pan", "4111111111111111"),
            ("card_allocations", "cvv", "123"),
            ("uploads", "secret_ref", "vault://secret/sub2"),
            ("events", "details", {"credential": "secret"}),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field):
                payload = task_timeline_payload()
                target = payload if section is None else payload[section]
                if isinstance(target, list):
                    target = target[0]
                target[field] = value
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("platform-access")

                with self.assertRaises(PlatformProtocolError):
                    client.get_task_timeline("task-1")

        payload = task_timeline_payload()
        del payload["events"]
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse(payload)),
        )
        client.set_access_token("platform-access")
        with self.assertRaises(PlatformProtocolError):
            client.get_task_timeline("task-1")

    def test_task_timeline_rejects_invalid_resource_status_or_naive_time(self):
        cases = (
            ("mail_session", "status", "ready"),
            ("card_allocations", "status", "available"),
            ("uploads", "status", "retrying"),
            ("mail_session", "expires_at", "2026-08-19T12:20:00"),
            ("card_allocations", "created_at", "2026-08-19T12:02:00"),
            ("uploads", "updated_at", "2026-08-19T12:07:00"),
            ("events", "created_at", "2026-08-19T12:06:00"),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field):
                payload = task_timeline_payload()
                target = payload[section]
                if isinstance(target, list):
                    target = target[0]
                target[field] = value
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("platform-access")

                with self.assertRaises(PlatformProtocolError):
                    client.get_task_timeline("task-1")

    def test_close_task_and_logout_cleanup_use_only_captured_session(self):
        issuer = "https://identity.example.test/realms/email-platform"
        opener = SequenceOpener(
            [
                FakeResponse(
                    task_response_payload(task_id="task/unsafe", status="closed")
                ),
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
        self.assertTrue(second_request.full_url.endswith("/auth/logout"))
        self.assertEqual(
            second_request.headers["Authorization"], "Bearer old-session-token"
        )
        self.assertIsNone(second_request.data)
        self.assertNotIn("task%2Funsafe", second_request.full_url)
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

        logout_request = opener.requests[0][0]
        self.assertTrue(logout_request.full_url.endswith("/auth/logout"))
        self.assertEqual(
            logout_request.headers["Authorization"], "Bearer old-access-token"
        )
        self.assertIsNone(logout_request.data)
        self.assertEqual(store.load(), "new-refresh-token")
        self.assertTrue(client.is_authenticated is False)

    def test_logout_cleanup_retries_same_refresh_when_discovery_lacks_revocation(self):
        issuer = "https://identity.example.test/realms/email-platform"
        revocation_endpoint = f"{issuer}/protocol/openid-connect/revoke"
        refresh_token = "old-refresh-token-secret"
        config = {
            "mode": "oidc",
            "issuer": issuer,
            "client_id": "email-platform-web",
            "desktop_client_id": "email-platform-desktop",
            "audience": "email-platform-api",
        }

        class RevocationDiscoveryOpener:
            def __init__(self):
                self.discovery_attempts = 0
                self.revoked_tokens = []

            def __call__(self, request, *, timeout):
                del timeout
                if request.full_url.endswith("/auth/logout"):
                    return FakeResponse({"status": "logged_out"})
                if request.full_url.endswith("/auth/config"):
                    return FakeResponse(config)
                if request.full_url.endswith("/.well-known/openid-configuration"):
                    self.discovery_attempts += 1
                    if self.discovery_attempts == 1:
                        return FakeResponse({"token_endpoint": f"{issuer}/token"})
                    return FakeResponse({"revocation_endpoint": revocation_endpoint})
                if request.full_url == revocation_endpoint:
                    form = urllib.parse.parse_qs(request.data.decode("ascii"))
                    self.revoked_tokens.append(form["token"][0])
                    return EmptyResponse()
                raise AssertionError(f"unexpected request: {request.full_url}")

        opener = RevocationDiscoveryOpener()
        store = MemorySessionStore()
        store.save(refresh_token)
        client = PlatformClient(
            "https://platform.example", opener=opener, session_store=store
        )
        client.set_access_token("old-access-token-secret")

        cleanup = client.prepare_logout_cleanup(None)
        self.assertFalse(client.is_authenticated)
        self.assertIsNone(store.load())

        with self.assertRaises(PlatformSessionError) as raised:
            cleanup()

        self.assertEqual(
            str(raised.exception), "统一身份服务未提供会话撤销能力"
        )
        failure = repr(raised.exception)
        self.assertNotIn(refresh_token, failure)
        self.assertNotIn(issuer, failure)
        self.assertNotIn("token_endpoint", failure)
        self.assertEqual(opener.revoked_tokens, [])

        cleanup()

        self.assertEqual(opener.revoked_tokens, [refresh_token])
        self.assertIsNone(store.load())

    def test_create_mail_session_quotes_id_and_sends_empty_body(self):
        opener = RecordingOpener(
            FakeResponse(
                {
                    "id": "session-1",
                    "email_masked": "m***@example.com",
                    "status": "waiting",
                    "expires_at": "2026-08-19T12:00:00Z",
                    "session_token": "s" * 43,
                    "polling_interval": 7,
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
                polling_interval=7,
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
        self.assertEqual(result.code, "123456")
        self.assertNotIn("123456", repr(result))
        self.assertEqual(result, MailCodeSnapshot("consumed", "123456"))
        self.assertEqual(
            request.full_url,
            "https://platform.example/api/v1/mail-sessions/session%2F1/code",
        )
        self.assertEqual(
            request.get_header("X-mail-session-token"),
            "opaque-session-token",
        )
        waiting_opener = RecordingOpener(
            FakeResponse({"status": "waiting", "code": None})
        )
        waiting_client = PlatformClient("https://platform.example", opener=waiting_opener)
        waiting_client.set_access_token("access-secret")
        self.assertEqual(
            waiting_client.get_mail_code("session-1", "opaque-session-token"),
            MailCodeSnapshot("waiting"),
        )

    def test_mail_code_accepts_previous_and_extended_response_shapes(self):
        extended = {
            "status": "consumed",
            "code": "123456",
            "received_at": "2026-08-19T12:04:00+00:00",
            "message_id_hash": "a" * 64,
        }
        client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(FakeResponse(extended)),
        )
        client.set_access_token("access-secret")

        self.assertEqual(
            client.get_mail_code("session-1", "s" * 32),
            MailCodeSnapshot(
                "consumed",
                "123456",
                received_at="2026-08-19T12:04:00+00:00",
                message_id_hash="a" * 64,
            ),
        )
        waiting_client = PlatformClient(
            "https://platform.example",
            opener=RecordingOpener(
                FakeResponse(
                    {
                        "status": "waiting",
                        "code": None,
                        "received_at": None,
                        "message_id_hash": None,
                    }
                )
            ),
        )
        waiting_client.set_access_token("access-secret")
        self.assertEqual(
            waiting_client.get_mail_code("session-1", "s" * 32),
            MailCodeSnapshot("waiting"),
        )

    def test_mail_code_rejects_partial_unknown_or_invalid_extended_shape(self):
        valid = {
            "status": "consumed",
            "code": "123456",
            "received_at": "2026-08-19T12:04:00+00:00",
            "message_id_hash": "a" * 64,
        }
        invalid_payloads = (
            {"status": "waiting"},
            {**valid, "message_id_hash": None},
            {key: value for key, value in valid.items() if key != "message_id_hash"},
            {**valid, "body": "message"},
            {**valid, "received_at": "2026-08-19T12:04:00"},
            {**valid, "message_id_hash": "A" * 64},
            {**valid, "message_id_hash": "a" * 63},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("access-secret")
                with self.assertRaises(PlatformProtocolError):
                    client.get_mail_code("session-1", "s" * 32)

    def test_revoke_owned_device_quotes_id_and_strictly_decodes_response(self):
        payload = {
            "id": "device/1",
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "name": "Operator workstation",
            "revoked_at": "2026-08-19T12:05:00+00:00",
            "last_seen_at": "2026-08-19T12:04:00+00:00",
            "created_at": "2026-08-01T12:00:00+00:00",
        }
        opener = RecordingOpener(FakeResponse(payload))
        client = PlatformClient("https://platform.example", opener=opener)
        client.set_access_token("access-secret")

        result = client.revoke_owned_device("device/1")

        self.assertEqual(result.id, "device/1")
        self.assertEqual(
            opener.requests[0][0].full_url,
            "https://platform.example/api/v1/devices/device%2F1/revoke",
        )
        for invalid in (
            {**payload, "session_token": "s" * 32},
            {**payload, "revoked_at": None},
            {**payload, "created_at": "2026-08-01T12:00:00"},
            {**payload, "id": "device-2"},
        ):
            invalid_client = PlatformClient(
                "https://platform.example",
                opener=RecordingOpener(FakeResponse(invalid)),
            )
            invalid_client.set_access_token("access-secret")
            with self.assertRaises(PlatformProtocolError):
                invalid_client.revoke_owned_device("device/1")

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

    def test_card_reveal_rejects_malformed_sensitive_fields(self):
        base = {
            "id": "reveal-1",
            "allocation_id": "allocation-1",
            "trace_id": "task-trace",
            "card_masked": "VISA •••• 1111",
            "brand": "VISA",
            "expiry_month": 12,
            "expiry_year": 2030,
            "pan": "4111111111111111",
            "reveal_expires_at": "2026-08-19T12:00:45Z",
        }
        cases = (
            ("pan", "4111 1111 1111 1111"),
            ("pan", "41111111111"),
            ("pan", "4111111111111111\n"),
            ("expiry_month", 13),
            ("expiry_year", None),
            ("reveal_expires_at", "2026-08-19T12:00:45"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                payload = dict(base)
                payload[field] = value
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("platform-access")

                with self.assertRaises(PlatformProtocolError):
                    client.reveal_card_allocation("allocation-1", "one-shot-grant")

    def test_card_reveal_challenge_and_grant_require_timezone(self):
        cases = (
            (
                "challenge",
                {
                    "challenge_id": "challenge-1",
                    "acr_values": DEFAULT_CARD_REVEAL_ACR_VALUES,
                    "expires_at": "2026-08-19T12:00:30",
                },
            ),
            (
                "grant",
                {
                    "reveal_grant": "opaque-reveal-grant",
                    "expires_at": "2026-08-19T12:00:45",
                },
            ),
        )
        for operation, payload in cases:
            with self.subTest(operation=operation):
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(FakeResponse(payload)),
                )
                client.set_access_token("primary-access")

                with self.assertRaises(PlatformProtocolError):
                    if operation == "challenge":
                        client.create_card_reveal_challenge("allocation-1")
                    else:
                        client.create_card_reveal_grant(
                            "allocation-1", "challenge-1", "step-up-access"
                        )

    def test_rejected_step_up_grant_does_not_clear_primary_session(self):
        headers = Message()
        body = json.dumps(
            {
                "error": {
                    "code": "forbidden",
                    "message": "Required authentication level missing",
                    "recovery_hint": "重新完成卡揭示二次认证后再试",
                    "trace_id": "00000000-0000-0000-0000-000000000018",
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
                    "recovery_hint": "刷新任务列表并确认任务仍然存在",
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
        self.assertEqual(
            caught.exception.recovery_hint,
            "刷新任务列表并确认任务仍然存在",
        )
        self.assertEqual(caught.exception.details, {"task_id": "missing"})
        self.assertEqual(client.last_trace_id, "body-trace")

    def test_error_envelope_requires_safe_recovery_hint_and_exact_fields(self):
        base = {
            "code": "conflict",
            "message": "server-controlled message",
            "recovery_hint": "刷新当前任务状态后继续",
            "trace_id": "00000000-0000-0000-0000-000000000016",
        }
        invalid_envelopes = (
            {key: value for key, value in base.items() if key != "recovery_hint"},
            {**base, "recovery_hint": "retry\nsecret"},
            {**base, "recovery_hint": ""},
            {**base, "trace_id": "bad trace"},
            {**base, "session_token": "s" * 32},
        )
        for envelope in invalid_envelopes:
            with self.subTest(envelope=envelope):
                body = json.dumps({"error": envelope}).encode("utf-8")
                http_error = urllib.error.HTTPError(
                    "https://platform.example/api/v1/tasks/task-1",
                    409,
                    "Conflict",
                    Message(),
                    io.BytesIO(body),
                )
                client = PlatformClient(
                    "https://platform.example",
                    opener=RecordingOpener(http_error),
                )
                client.set_access_token("access-secret")
                with self.assertRaises(PlatformProtocolError):
                    client.get_task("task-1")

    def test_platform_success_json_is_bounded_and_rejects_duplicate_keys(self):
        payload = {
            "mode": "local",
            "issuer": None,
            "client_id": None,
            "desktop_client_id": None,
            "audience": None,
            "admin_role_change_acr": None,
        }
        boundary_response = RawResponse(
            padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES)
        )
        boundary_client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(boundary_response)
        )

        self.assertEqual(boundary_client.get_auth_config(), payload)
        self.assertEqual(
            boundary_response.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
        )

        duplicate = (
            b'{"mode":"local","mode":"local","issuer":null,'
            b'"client_id":null,"desktop_client_id":null,"audience":null,'
            b'"admin_role_change_acr":null}'
        )
        oversized = padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES + 1)
        for raw in (duplicate, oversized):
            with self.subTest(size=len(raw)):
                response = RawResponse(raw)
                client = PlatformClient(
                    "https://platform.example", opener=RecordingOpener(response)
                )
                with self.assertRaises(PlatformProtocolError):
                    client.get_auth_config()
                self.assertEqual(
                    response.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
                )

    def test_platform_error_json_is_bounded_and_rejects_duplicate_keys(self):
        envelope = {
            "error": {
                "code": "conflict",
                "message": "server-controlled message",
                "recovery_hint": "刷新当前任务状态后继续",
                "trace_id": "body-trace",
            }
        }

        def client_for(raw: bytes) -> tuple[PlatformClient, RecordingBytesIO]:
            headers = Message()
            headers["X-Trace-Id"] = "header-trace"
            stream = RecordingBytesIO(raw)
            error = urllib.error.HTTPError(
                "https://platform.example/api/v1/me",
                409,
                "Conflict",
                headers,
                stream,
            )
            client = PlatformClient(
                "https://platform.example", opener=RecordingOpener(error)
            )
            client.set_access_token("access-secret")
            return client, stream

        boundary_client, boundary_stream = client_for(
            padded_json_bytes(envelope, _MAX_TEST_JSON_RESPONSE_BYTES)
        )
        with self.assertRaises(PlatformApiError):
            boundary_client.me()
        self.assertEqual(
            boundary_stream.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
        )

        duplicate = (
            b'{"error":{"code":"conflict","code":"conflict",'
            b'"message":"server-controlled message",'
            b'"recovery_hint":"refresh current task state",'
            b'"trace_id":"body-trace"}}'
        )
        oversized = padded_json_bytes(envelope, _MAX_TEST_JSON_RESPONSE_BYTES + 1)
        for raw in (duplicate, oversized):
            with self.subTest(size=len(raw)):
                client, stream = client_for(raw)
                with self.assertRaises(PlatformProtocolError):
                    client.me()
                self.assertEqual(
                    stream.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
                )

    def test_oidc_success_json_is_bounded_and_rejects_duplicate_keys(self):
        payload = {
            "token_endpoint": "https://identity.example/protocol/openid-connect/token"
        }
        boundary_response = RawResponse(
            padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES)
        )
        boundary_client = PlatformClient(
            "https://platform.example", opener=RecordingOpener(boundary_response)
        )

        self.assertEqual(
            boundary_client._request_external_json(
                "GET", "https://identity.example/.well-known/openid-configuration"
            ),
            payload,
        )
        self.assertEqual(
            boundary_response.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
        )

        duplicate = (
            b'{"token_endpoint":"https://identity.example/token",'
            b'"token_endpoint":"https://identity.example/token"}'
        )
        oversized = padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES + 1)
        for raw in (duplicate, oversized):
            with self.subTest(size=len(raw)):
                response = RawResponse(raw)
                client = PlatformClient(
                    "https://platform.example", opener=RecordingOpener(response)
                )
                with self.assertRaises(PlatformProtocolError):
                    client._request_external_json(
                        "GET",
                        "https://identity.example/.well-known/openid-configuration",
                    )
                self.assertEqual(
                    response.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
                )

    def test_oidc_error_json_is_bounded_and_rejects_duplicate_keys(self):
        payload = {"error": "authorization_pending"}

        def client_for(raw: bytes) -> tuple[PlatformClient, RecordingBytesIO]:
            stream = RecordingBytesIO(raw)
            error = urllib.error.HTTPError(
                "https://identity.example/token",
                400,
                "Bad Request",
                Message(),
                stream,
            )
            return (
                PlatformClient(
                    "https://platform.example", opener=RecordingOpener(error)
                ),
                stream,
            )

        boundary_client, boundary_stream = client_for(
            padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES)
        )
        self.assertEqual(
            boundary_client._request_external_json_with_status(
                "POST", "https://identity.example/token"
            ),
            (400, payload),
        )
        self.assertEqual(
            boundary_stream.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
        )

        duplicate = b'{"error":"authorization_pending","error":"authorization_pending"}'
        oversized = padded_json_bytes(payload, _MAX_TEST_JSON_RESPONSE_BYTES + 1)
        for raw in (duplicate, oversized):
            with self.subTest(size=len(raw)):
                client, stream = client_for(raw)
                with self.assertRaises(PlatformProtocolError):
                    client._request_external_json_with_status(
                        "POST", "https://identity.example/token"
                    )
                self.assertEqual(
                    stream.read_sizes, [_MAX_TEST_JSON_RESPONSE_BYTES + 1]
                )

    def test_classifies_authentication_and_protocol_errors(self):
        auth_body = json.dumps(
            {
                "error": {
                    "code": "unauthorized",
                    "message": "登录已失效",
                    "recovery_hint": "重新登录后再试",
                    "trace_id": "00000000-0000-0000-0000-000000000017",
                }
            }
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
