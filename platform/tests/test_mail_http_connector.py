import json
import unittest
from email.message import Message

from platform.app import create_app
from platform.config import Settings
from platform.mail_connectors import (
    HttpMailConnector,
    MailCodeMessage,
    MailConnectorUnavailable,
    MailboxAccess,
)
from platform.secrets import SecretResolverUnavailable


class FakeResponse:
    def __init__(
        self,
        payload: dict[str, object] | None = None,
        *,
        raw_body: bytes | None = None,
        final_url: str | None = None,
    ) -> None:
        self.body = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
        self.final_url = final_url
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def geturl(self) -> str:
        return self.final_url or "https://mail-api.example/api/v1/watermark"

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingResolver:
    def __init__(self) -> None:
        self.refs: list[str] = []

    def resolve(self, secret_ref: str) -> dict[str, object]:
        self.refs.append(secret_ref)
        if secret_ref != "vault://mailboxes/mail-1":
            raise SecretResolverUnavailable("missing mailbox")
        return {"handle": "mailbox-handle-1", "token": "mailbox-token-secret"}


class SequenceOpener:
    def __init__(self, *payloads: dict[str, object] | FakeResponse) -> None:
        self.payloads = list(payloads)
        self.requests = []

    def __call__(self, request, timeout: int):
        self.requests.append((request, timeout))
        result = self.payloads.pop(0)
        if isinstance(result, FakeResponse):
            return result
        return FakeResponse(result, final_url=request.full_url)


class HttpMailConnectorTests(unittest.TestCase):
    def test_watermark_and_code_use_resolved_secret_without_secret_ref(self) -> None:
        resolver = RecordingResolver()
        opener = SequenceOpener(
            {"data": {"watermark": "100"}},
            {
                "data": {
                    "message_id": "message-101",
                    "watermark": "101",
                    "code": "654321",
                }
            },
        )
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1", resolver, timeout=9, opener=opener
        )
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )

        watermark = connector.current_watermark(mailbox)
        message = connector.find_code_after(mailbox, watermark)

        self.assertEqual(watermark, "100")
        self.assertEqual(
            message,
            MailCodeMessage(message_id="message-101", watermark="101", code="654321"),
        )
        self.assertEqual(
            resolver.refs,
            ["vault://mailboxes/mail-1", "vault://mailboxes/mail-1"],
        )
        watermark_request, watermark_timeout = opener.requests[0]
        code_request, code_timeout = opener.requests[1]
        self.assertEqual(watermark_timeout, 9)
        self.assertEqual(code_timeout, 9)
        self.assertTrue(watermark_request.full_url.endswith("/watermark"))
        self.assertTrue(code_request.full_url.endswith("/code"))
        code_payload = json.loads(code_request.data.decode("utf-8"))
        self.assertEqual(code_payload["after_watermark"], "100")
        self.assertEqual(code_payload["mailbox"]["handle"], "mailbox-handle-1")
        body_text = code_request.data.decode("utf-8")
        for forbidden in ("vault://", "secret_ref"):
            self.assertNotIn(forbidden, body_text)

    def test_waiting_response_returns_none_and_raw_code_name_is_allowed(self) -> None:
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener({"status": "waiting"}),
        )
        self.assertIsNone(
            connector.find_code_after(
                MailboxAccess(
                    mailbox_id="mailbox-1",
                    secret_ref="vault://mailboxes/mail-1",
                ),
                "100",
            )
        )

        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener({"message_id": "101", "code": "123456"}),
        )
        self.assertEqual(
            connector.find_code_after(
                MailboxAccess(
                    mailbox_id="mailbox-1",
                    secret_ref="vault://mailboxes/mail-1",
                ),
                "100",
            ).code,
            "123456",
        )

    def test_invalid_code_and_missing_secret_are_connector_unavailable(self) -> None:
        invalid_code = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener({"message_id": "101", "code": "abc"}),
        )
        with self.assertRaises(MailConnectorUnavailable):
            invalid_code.find_code_after(
                MailboxAccess(
                    mailbox_id="mailbox-1",
                    secret_ref="vault://mailboxes/mail-1",
                ),
                "100",
            )

        missing_secret = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener({"message_id": "101", "code": "123456"}),
        )
        with self.assertRaises(MailConnectorUnavailable):
            missing_secret.find_code_after(
                MailboxAccess(
                    mailbox_id="mailbox-2",
                    secret_ref="vault://mailboxes/missing",
                ),
                "100",
            )

    def test_create_app_registers_http_connector_from_configuration(self) -> None:
        app = create_app(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="mail-http-test-hmac-secret-that-is-not-production",
                mail_api_url="http://localhost:8080/mail",
            )
        )
        try:
            self.assertIn("http", app.state.mail_connectors)
            self.assertIsInstance(app.state.mail_connectors["http"], HttpMailConnector)
        finally:
            app.state.engine.dispose()

    def test_rejects_non_https_non_loopback_url(self) -> None:
        with self.assertRaises(ValueError):
            HttpMailConnector("http://mail-api.example/api/v1", RecordingResolver())

    def test_redirects_and_oversized_responses_are_rejected(self) -> None:
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        redirected = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener(
                FakeResponse(
                    {"watermark": "1"},
                    final_url="https://redirect.example/watermark",
                )
            ),
        )
        with self.assertRaisesRegex(MailConnectorUnavailable, "redirect"):
            redirected.current_watermark(mailbox)

        oversized = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            opener=SequenceOpener(FakeResponse(raw_body=b"x" * (64 * 1024 + 1))),
        )
        with self.assertRaisesRegex(MailConnectorUnavailable, "too large"):
            oversized.current_watermark(mailbox)

        self.assertTrue(
            any(
                handler.__class__.__name__ == "_NoRedirectHandler"
                for handler in redirected._default_opener.handlers
            )
        )


if __name__ == "__main__":
    unittest.main()
