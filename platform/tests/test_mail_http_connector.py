import json
import unittest
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from platform.app import create_app
from platform.config import Settings
from platform.mail_connectors import (
    HttpMailConnector,
    MailCodeMessage,
    MailConnectorUnavailable,
    MailboxAccess,
    call_mail_connector,
)
from platform.secrets import SecretResolverUnavailable


TASK_STARTED_AT = datetime(2026, 8, 29, tzinfo=timezone.utc)


def acknowledged_watermark(
    watermark: object,
    *,
    boundary: str = "2026-08-29T00:00:00Z",
    status: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "watermark": watermark,
        "received_at_or_before": boundary,
        "watermark_basis": "task_created_at",
    }
    if status is not None:
        payload["status"] = status
    return payload


class FakeResponse:
    def __init__(
        self,
        payload: dict[str, object] | None = None,
        *,
        raw_body: bytes | None = None,
        final_url: str | None = None,
        content_type: str = "application/json",
    ) -> None:
        self.body = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
        self.final_url = final_url
        self.read_sizes: list[int] = []
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
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
        return {
            "handle": "mailbox-handle-1",
            "token": "mailbox-token-secret",
            "expected_sender": "no-reply@example.invalid",
            "subject_contains": "verification code",
        }


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


class ExplodingHeaders:
    def get_content_charset(self) -> str:
        raise RuntimeError("header API_SECRET_SENTINEL")


class HttpMailConnectorTests(unittest.TestCase):
    def test_watermark_requires_exact_task_start_acknowledgement(self) -> None:
        mailbox = MailboxAccess("mailbox-1", "vault://mailboxes/mail-1")
        cases = (
            {"watermark": "100"},
            {
                "watermark": "100",
                "received_at_or_before": "2026-08-29T00:00:01Z",
                "watermark_basis": "task_created_at",
            },
            {
                "watermark": "100",
                "received_at_or_before": "2026-08-29T00:00:00Z",
                "watermark_basis": "session_created_at",
            },
            {
                "received_at_or_before": "2026-08-29T00:00:00Z",
                "watermark_basis": "task_created_at",
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(payload),
                )
                with self.assertRaisesRegex(
                    MailConnectorUnavailable,
                    "^Mail API did not confirm task-start watermark$",
                ):
                    connector.watermark_at(mailbox, TASK_STARTED_AT)

        invalid_cursors = (None, "", 100, "x" * 513)
        for cursor in invalid_cursors:
            with self.subTest(cursor=cursor):
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(
                        acknowledged_watermark(cursor, status="empty")
                    ),
                )
                with self.assertRaisesRegex(
                    MailConnectorUnavailable,
                    "^Mail API did not confirm task-start watermark$",
                ):
                    connector.watermark_at(mailbox, TASK_STARTED_AT)

        empty = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(
                acknowledged_watermark("empty:mailbox-1:100", status="empty")
            ),
        )
        self.assertEqual(
            empty.watermark_at(mailbox, TASK_STARTED_AT), "empty:mailbox-1:100"
        )

    def test_watermark_is_anchored_to_the_persisted_task_start(self) -> None:
        opener = SequenceOpener(
            {
                "data": {
                    "watermark": "100",
                    "received_at_or_before": "2026-08-29T01:02:03.456789Z",
                    "watermark_basis": "task_created_at",
                }
            }
        )
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=opener,
        )
        task_started_at = datetime(2026, 8, 29, 1, 2, 3, 456789, tzinfo=timezone.utc)

        watermark = connector.watermark_at(
            MailboxAccess("mailbox-1", "vault://mailboxes/mail-1"),
            task_started_at,
        )

        self.assertEqual(watermark, "100")
        payload = json.loads(opener.requests[0][0].data.decode("utf-8"))
        self.assertEqual(
            payload["received_at_or_before"], "2026-08-29T01:02:03.456789Z"
        )

    def test_watermark_and_code_use_resolved_secret_without_secret_ref(self) -> None:
        resolver = RecordingResolver()
        opener = SequenceOpener(
            {"data": acknowledged_watermark("100")},
            {
                "data": {
                    "message_id": "message-101",
                    "watermark": "101",
                    "code": "654321",
                    "received_at": "2026-08-29T00:00:01Z",
                    "sender": "no-reply@example.invalid",
                    "subject": "Your verification code",
                }
            },
        )
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            resolver,
            allowed_origins=("https://mail-api.example",),
            timeout=9,
            opener=opener,
        )
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )

        watermark = connector.watermark_at(mailbox, TASK_STARTED_AT)
        message = connector.find_code_after(mailbox, watermark)

        self.assertEqual(watermark, "100")
        self.assertEqual(
            message,
            MailCodeMessage(
                message_id="message-101",
                watermark="101",
                code="654321",
                received_at=datetime(2026, 8, 29, 0, 0, 1, tzinfo=timezone.utc),
            ),
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
        watermark_payload = json.loads(watermark_request.data.decode("utf-8"))
        self.assertNotIn("after_watermark", watermark_payload)
        code_payload = json.loads(code_request.data.decode("utf-8"))
        self.assertEqual(code_payload["after_watermark"], "100")
        self.assertNotIn("received_at_or_before", code_payload)
        self.assertEqual(code_payload["mailbox"]["handle"], "mailbox-handle-1")
        body_text = code_request.data.decode("utf-8")
        for forbidden in ("vault://", "secret_ref"):
            self.assertNotIn(forbidden, body_text)

    def test_server_owned_sender_and_subject_filters_are_sent_and_rechecked(self) -> None:
        cases = (
            (
                {
                    "message_id": "101",
                    "watermark": "101",
                    "code": "123456",
                    "received_at": "2026-08-29T00:00:01Z",
                    "sender": "NO-REPLY@example.invalid",
                    "subject": "Your Verification Code is ready",
                },
                True,
            ),
            (
                {
                    "message_id": "102",
                    "watermark": "102",
                    "code": "234567",
                    "sender": "attacker@example.invalid",
                    "subject": "Your verification code is ready",
                },
                False,
            ),
            (
                {
                    "message_id": "103",
                    "watermark": "103",
                    "code": "345678",
                    "sender": "no-reply@example.invalid",
                },
                False,
            ),
        )
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        for payload, matches in cases:
            with self.subTest(payload=payload):
                opener = SequenceOpener(payload)
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=opener,
                )

                if matches:
                    message = connector.find_code_after(mailbox, "100")
                    self.assertIsNotNone(message)
                else:
                    with self.assertRaises(MailConnectorUnavailable):
                        connector.find_code_after(mailbox, "100")
                request_payload = json.loads(
                    opener.requests[0][0].data.decode("utf-8")
                )
                self.assertEqual(
                    request_payload["sender_filter"],
                    "no-reply@example.invalid",
                )
                self.assertEqual(
                    request_payload["subject_filter"],
                    "verification code",
                )
                self.assertNotIn("expected_sender", request_payload["mailbox"])
                self.assertNotIn("subject_contains", request_payload["mailbox"])

    def test_missing_server_owned_filter_configuration_fails_closed(self) -> None:
        resolver = mock.Mock()
        resolver.resolve.return_value = {
            "handle": "mailbox-handle-1",
            "token": "mailbox-token-secret",
        }
        opener = SequenceOpener({"watermark": "101"})
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            resolver,
            allowed_origins=("https://mail-api.example",),
            opener=opener,
        )

        with self.assertRaisesRegex(
            MailConnectorUnavailable,
            "^Mail filter configuration is unavailable$",
        ):
            connector.watermark_at(
                MailboxAccess(
                    mailbox_id="mailbox-1",
                    secret_ref="vault://mailboxes/mail-1",
                ),
                TASK_STARTED_AT,
            )

        self.assertEqual(opener.requests, [])

    def test_waiting_response_returns_none_and_found_requires_canonical_ids(self) -> None:
        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
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

        invalid_found = (
            {
                "message_id": "101",
                "code": "123456",
                "sender": "no-reply@example.invalid",
                "subject": "verification code",
            },
            {
                "message_id": "101",
                "watermark": "100",
                "code": "123456",
                "sender": "no-reply@example.invalid",
                "subject": "verification code",
            },
            {
                "id": "101",
                "watermark": "101",
                "code": "123456",
                "sender": "no-reply@example.invalid",
                "subject": "verification code",
            },
        )
        for payload in invalid_found:
            with self.subTest(payload=payload):
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(payload),
                )
                with self.assertRaises(MailConnectorUnavailable):
                    connector.find_code_after(
                        MailboxAccess(
                            mailbox_id="mailbox-1",
                            secret_ref="vault://mailboxes/mail-1",
                        ),
                        "100",
                    )

    def test_code_response_union_and_filters_fail_closed(self) -> None:
        invalid_responses = (
            {"status": "unknown"},
            {"status": "waiting", "code": "123456"},
            {},
            {
                "message_id": "101",
                "watermark": "101",
                "code": "123456",
                "sender": "attacker@example.invalid",
                "subject": "verification code",
            },
            {
                "message_id": "101",
                "watermark": "101",
                "code": "123456",
                "sender": "no-reply@example.invalid",
            },
        )
        mailbox = MailboxAccess("mailbox-1", "vault://mailboxes/mail-1")
        for payload in invalid_responses:
            with self.subTest(payload=payload):
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(payload),
                )
                with self.assertRaises(MailConnectorUnavailable):
                    connector.find_code_after(mailbox, "100")

    def test_found_requires_authoritative_received_at(self) -> None:
        mailbox = MailboxAccess("mailbox-1", "vault://mailboxes/mail-1")
        base = {
            "message_id": "101",
            "watermark": "101",
            "code": "123456",
            "sender": "no-reply@example.invalid",
            "subject": "verification code",
        }
        for value in (None, "", "2026-08-29T00:00:01", 123):
            with self.subTest(received_at=value):
                payload = {**base, "received_at": value}
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(payload),
                )
                with self.assertRaisesRegex(
                    MailConnectorUnavailable,
                    "^Mail API returned invalid received_at$",
                ):
                    connector.find_code_after(mailbox, "100")

        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(
                {**base, "received_at": "2026-08-29T08:00:01+08:00"}
            ),
        )
        message = connector.find_code_after(mailbox, "100")
        self.assertEqual(
            message.received_at,
            datetime(2026, 8, 29, 0, 0, 1, tzinfo=timezone.utc),
        )

    def test_invalid_code_and_missing_secret_are_connector_unavailable(self) -> None:
        invalid_code = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(
                {
                    "message_id": "101",
                    "code": "abc",
                    "sender": "no-reply@example.invalid",
                    "subject": "verification code",
                }
            ),
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
            allowed_origins=("https://mail-api.example",),
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
        with TemporaryDirectory() as directory:
            allowed_origins = Path(directory) / "allowed-origins"
            allowed_origins.write_text("https://mail-api.example\n", encoding="utf-8")
            app = create_app(
                Settings(
                    environment="test",
                    database_url="sqlite+pysqlite:///:memory:",
                    jwt_hmac_secret="mail-http-test-hmac-secret-that-is-not-production",
                    mail_api_url="https://mail-api.example/mail",
                    mail_allowed_origins_file=str(allowed_origins),
                )
            )
            try:
                self.assertIn("http", app.state.mail_connectors)
                connector = app.state.mail_connectors["http"]
                self.assertIsInstance(connector, HttpMailConnector)
                self.assertEqual(
                    connector.allowed_origins,
                    frozenset({("https", "mail-api.example", 443)}),
                )
            finally:
                app.state.engine.dispose()

    def test_exact_allowed_origin_accepts_business_path_and_default_port(self) -> None:
        resolver = RecordingResolver()
        opener = SequenceOpener(acknowledged_watermark("101"))
        connector = HttpMailConnector(
            "https://MAIL-API.EXAMPLE:443/api/v1",
            resolver,
            allowed_origins=("https://mail-api.example",),
            opener=opener,
        )

        self.assertEqual(
            connector.watermark_at(
                MailboxAccess("mailbox-1", "vault://mailboxes/mail-1"),
                TASK_STARTED_AT,
            ),
            "101",
        )
        self.assertEqual(resolver.refs, ["vault://mailboxes/mail-1"])
        self.assertEqual(len(opener.requests), 1)

    def test_rejects_untrusted_origin_before_secret_or_network_access(self) -> None:
        cases = (
            ("https://mail-api.example/api", ()),
            ("https://mail-api.example/api", ("",)),
            ("https://mail-api.example/api", ("https://*.example",)),
            ("https://mail-api.example/api", ("https://user@mail-api.example",)),
            ("https://mail-api.example/api", ("https://mail-api.example/path",)),
            ("https://mail-api.example/api", ("https://mail-api.example?x=1",)),
            ("https://mail-api.example/api", ("https://mail-api.example#x",)),
            ("https://mail-api.example/api", ("http://mail-api.example",)),
            ("https://localhost/api", ("https://localhost",)),
            ("https://mail.localhost/api", ("https://mail.localhost",)),
            ("https://127.0.0.1/api", ("https://127.0.0.1",)),
            ("https://[::1]/api", ("https://[::1]",)),
            ("https://mail-api.example/api", ("https://mail-api.example:0",)),
            ("https://mail-api.example/api", ("https://mail-api.example:65536",)),
            ("https://mail-api.example/api", ("https://mail-api.example:invalid",)),
            (
                "https://mail-api.example.evil.test/api",
                ("https://mail-api.example",),
            ),
            ("https://mail-api.example:8443/api", ("https://mail-api.example",)),
            ("https://mail-api.example:0/api", ("https://mail-api.example",)),
            ("https://mail-api.example:65536/api", ("https://mail-api.example",)),
            ("http://mail-api.example/api", ("https://mail-api.example",)),
        )
        for base_url, allowed_origins in cases:
            with self.subTest(base_url=base_url, allowed_origins=allowed_origins):
                resolver = RecordingResolver()
                opener = SequenceOpener({"watermark": "1"})
                with self.assertRaises(ValueError):
                    HttpMailConnector(
                        base_url,
                        resolver,
                        allowed_origins=allowed_origins,
                        opener=opener,
                    )
                self.assertEqual(resolver.refs, [])
                self.assertEqual(opener.requests, [])

    def test_allowed_origin_file_is_single_line_and_errors_are_safe(self) -> None:
        with TemporaryDirectory() as directory:
            directory_path = Path(directory)
            policy = directory_path / "allowed-origins"
            policy.write_text(
                "https://mail-a.example, https://mail-b.example:8443\n",
                encoding="utf-8",
            )
            settings = Settings(mail_allowed_origins_file=str(policy))
            self.assertEqual(
                settings.resolved_mail_allowed_origins(),
                ("https://mail-a.example", "https://mail-b.example:8443"),
            )

            invalid_cases = (
                (None, "unavailable"),
                (str(directory_path / "missing-secret-name"), "unavailable"),
            )
            for path, expected in invalid_cases:
                with self.subTest(path=path):
                    with self.assertRaisesRegex(RuntimeError, expected) as raised:
                        Settings(
                            mail_allowed_origins_file=path
                        ).resolved_mail_allowed_origins()
                    self.assertNotIn("missing-secret-name", str(raised.exception))

            invalid_contents = (
                "",
                "\n",
                "https://a.example\nhttps://b.example\n",
                "https://a.example,\n",
            )
            for index, content in enumerate(invalid_contents):
                invalid_policy = directory_path / f"invalid-{index}"
                invalid_policy.write_text(content, encoding="utf-8")
                with self.subTest(content=content):
                    with self.assertRaisesRegex(RuntimeError, "invalid") as raised:
                        Settings(
                            mail_allowed_origins_file=str(invalid_policy)
                        ).resolved_mail_allowed_origins()
                    self.assertNotIn(str(invalid_policy), str(raised.exception))

    def test_redirects_and_oversized_responses_are_rejected(self) -> None:
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        redirected = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(
                FakeResponse(
                    {"watermark": "1"},
                    final_url="https://redirect.example/watermark",
                )
            ),
        )
        with self.assertRaisesRegex(MailConnectorUnavailable, "redirect"):
            redirected.watermark_at(mailbox, TASK_STARTED_AT)

        oversized = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(FakeResponse(raw_body=b"x" * (64 * 1024 + 1))),
        )
        with self.assertRaisesRegex(MailConnectorUnavailable, "too large"):
            oversized.watermark_at(mailbox, TASK_STARTED_AT)

        self.assertTrue(
            any(
                handler.__class__.__name__ == "_NoRedirectHandler"
                for handler in redirected._default_opener.handlers
            )
        )

    def test_json_boundary_accepts_exact_limit_and_ignores_charset_metadata(self) -> None:
        encoded = json.dumps(
            {"data": acknowledged_watermark("101")},
            separators=(",", ":"),
        ).encode("utf-8")
        body = encoded + (b" " * ((64 * 1024) - len(encoded)))
        responses = (
            FakeResponse(
                raw_body=body,
                content_type="application/json; charset=secret-sentinel-codec",
            ),
            FakeResponse(raw_body=body),
        )
        responses[1].headers = ExplodingHeaders()
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        for response in responses:
            with self.subTest(headers=type(response.headers).__name__):
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(response),
                )

                self.assertEqual(
                    connector.watermark_at(mailbox, TASK_STARTED_AT), "101"
                )
                self.assertEqual(response.read_sizes, [(64 * 1024) + 1])

    def test_json_boundary_rejects_duplicate_keys_and_non_utf8(self) -> None:
        cases = (
            b'{"data":{"watermark":"101"},"data":{"watermark":"101"}}',
            b'{"data":{"watermark":"101","watermark":"101"}}',
            b'{"data":{"watermark":"101","ignored":"\xff"}}',
        )
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        for body in cases:
            with self.subTest(body=body):
                response = FakeResponse(
                    raw_body=body,
                    content_type="application/json; charset=iso-8859-1",
                )
                connector = HttpMailConnector(
                    "https://mail-api.example/api/v1",
                    RecordingResolver(),
                    allowed_origins=("https://mail-api.example",),
                    opener=SequenceOpener(response),
                )

                with self.assertRaises(MailConnectorUnavailable) as raised:
                    connector.watermark_at(mailbox, TASK_STARTED_AT)

                self.assertEqual(
                    str(raised.exception), "Mail API returned invalid JSON"
                )
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn("101", str(raised.exception))

    def test_runtime_boundary_redacts_unclassified_response_failures(self) -> None:
        mailbox = MailboxAccess(
            mailbox_id="mailbox-1", secret_ref="vault://mailboxes/mail-1"
        )
        cases = (
            ("invalid_json", FakeResponse(raw_body=b'{"API_SECRET_SENTINEL":')),
        )
        for label, response in cases:
            connector = HttpMailConnector(
                "https://mail-api.example/api/v1",
                RecordingResolver(),
                allowed_origins=("https://mail-api.example",),
                opener=SequenceOpener(response),
            )
            with self.subTest(failure=label):
                with self.assertRaisesRegex(
                    MailConnectorUnavailable, "^Mail connector is unavailable$"
                ) as raised:
                    call_mail_connector(
                        lambda: connector.watermark_at(mailbox, TASK_STARTED_AT)
                    )
                self.assertTrue(raised.exception.__suppress_context__)
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)
                self.assertNotIn("secret-sentinel", str(raised.exception))

        connector = HttpMailConnector(
            "https://mail-api.example/api/v1",
            RecordingResolver(),
            allowed_origins=("https://mail-api.example",),
            opener=SequenceOpener(FakeResponse({"watermark": "1"})),
        )
        with mock.patch(
            "platform.mail_connectors.parse_unique_json_bytes",
            side_effect=RuntimeError("JSON API_SECRET_SENTINEL"),
        ):
            with self.assertRaisesRegex(
                MailConnectorUnavailable, "^Mail connector is unavailable$"
            ) as raised:
                call_mail_connector(
                    lambda: connector.watermark_at(mailbox, TASK_STARTED_AT)
                )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("API_SECRET_SENTINEL", str(raised.exception))

    def test_runtime_boundary_does_not_catch_process_control_exceptions(self) -> None:
        for failure in (KeyboardInterrupt("stop"), SystemExit("stop")):
            def interrupt() -> None:
                raise failure

            with self.subTest(exception=type(failure).__name__):
                with self.assertRaises(type(failure)):
                    call_mail_connector(interrupt)


if __name__ == "__main__":
    unittest.main()
