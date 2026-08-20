import io
import json
import random
import threading
import unittest
import urllib.error
from email.message import Message

from legacy_app import (
    API_ORIGIN,
    API_URL,
    ApiError,
    ClipboardWorkflow,
    ClipboardRecord,
    GeneratedIdentity,
    MailApiClient,
    PasteShortcutDetector,
    SALES_TAX_FREE_LOCATIONS,
    WorkflowStage,
    extract_verification_code,
    generate_test_identity,
    parse_clipboard_record,
    parse_credentials,
    run_polling,
)


class FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")
        self.headers = Message()
        self.headers["Content-Type"] = "application/json; charset=utf-8"

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class CredentialTests(unittest.TestCase):
    def test_parses_complete_clipboard_value(self):
        self.assertEqual(
            parse_credentials(" user@example.com ---- p@ss----tail "),
            ("user@example.com", "p@ss----tail"),
        )


    def test_rejects_invalid_values(self):
        invalid = (
            "user@example.com",
            "----password",
            "user@example.com----",
            "not-an-email----password",
            "user@example.com----line1\nline2",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(parse_credentials(value))

    def test_parses_tab_separated_account_record(self):
        record = parse_clipboard_record(
            "4111111111111111\t321\t9月28\tuser@example.com----secret"
        )
        self.assertEqual(
            record,
            ClipboardRecord(
                email="user@example.com",
                password="secret",
                card_number="4111111111111111",
                second_value="321",
            ),
        )

    def test_parses_credentials_without_card_data(self):
        self.assertEqual(
            parse_clipboard_record("user@example.com----secret"),
            ClipboardRecord(email="user@example.com", password="secret"),
        )

    def test_parses_colon_separated_credentials(self):
        self.assertEqual(
            parse_clipboard_record("user@example.com:secret:with-colon"),
            ClipboardRecord(
                email="user@example.com",
                password="secret:with-colon",
            ),
        )

    def test_parses_colon_credentials_in_tab_record(self):
        self.assertEqual(
            parse_clipboard_record(
                "4111111111111111\t123\t12月30\tuser@example.com:secret"
            ),
            ClipboardRecord(
                email="user@example.com",
                password="secret",
                card_number="4111111111111111",
                second_value="123",
            ),
        )

    def test_rejects_structured_record_with_invalid_card(self):
        self.assertIsNone(
            parse_clipboard_record(
                "not-a-card\t321\t9月28\tuser@example.com----secret"
            )
        )


class IdentityTests(unittest.TestCase):
    def test_generates_name_and_tax_free_state_address(self):
        identity = generate_test_identity(random.Random(7))
        self.assertIsInstance(identity, GeneratedIdentity)
        self.assertRegex(identity.name, r"^[A-Za-z]+ [A-Za-z]+$")
        self.assertRegex(
            identity.address,
            r"^\d{2,4} [A-Za-z]+ (?:Street|Avenue|Road|Lane|Drive|Court|Way), ",
        )
        self.assertTrue(identity.address.endswith(", United States"))
        self.assertTrue(
            any(
                f", {state} {zip_code}, United States" in identity.address
                for _, state, zip_code in SALES_TAX_FREE_LOCATIONS
            )
        )

    def test_successive_generations_have_variety(self):
        rng = random.Random(11)
        identities = {generate_test_identity(rng) for _ in range(20)}
        self.assertGreater(len(identities), 1)


class ClipboardWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.record = ClipboardRecord(
            email="user@example.com",
            password="secret",
            card_number="4111111111111111",
            second_value="321",
        )
        self.identity = GeneratedIdentity(
            name="Mary Example",
            address="57 Elm Street, Salem, Oregon 97310, United States",
        )

    def test_exact_sequence_with_early_code(self):
        workflow = ClipboardWorkflow()
        action = workflow.start(self.record, self.identity)
        self.assertEqual(action.value, self.record.email)
        self.assertEqual(workflow.stage, WorkflowStage.EMAIL_READY)

        self.assertIsNone(workflow.on_code_found("246810"))
        self.assertEqual(workflow.expected_value, self.record.email)

        expected = (
            (self.record.email, "246810", WorkflowStage.CODE_READY),
            ("246810", self.identity.name, WorkflowStage.FIRST_NAME_READY),
            (self.identity.name, self.record.card_number, WorkflowStage.CARD_READY),
            (
                self.record.card_number,
                self.record.second_value,
                WorkflowStage.SECOND_VALUE_READY,
            ),
            (
                self.record.second_value,
                self.identity.name,
                WorkflowStage.SECOND_NAME_READY,
            ),
            (self.identity.name, self.identity.address, WorkflowStage.ADDRESS_READY),
            (self.identity.address, None, WorkflowStage.COMPLETE),
        )
        for pasted, copied, stage in expected:
            with self.subTest(stage=stage):
                action = workflow.on_paste(pasted)
                self.assertIsNotNone(action)
                self.assertEqual(action.value, copied)
                self.assertEqual(workflow.stage, stage)
        self.assertFalse(workflow.active)

    def test_late_code_waits_without_overwriting_email(self):
        workflow = ClipboardWorkflow()
        workflow.start(self.record, self.identity)
        action = workflow.on_paste(self.record.email)
        self.assertIsNone(action.value)
        self.assertEqual(workflow.stage, WorkflowStage.WAITING_CODE)
        self.assertIsNone(workflow.expected_value)

        action = workflow.on_code_found("135790")
        self.assertEqual(action.value, "135790")
        self.assertEqual(workflow.stage, WorkflowStage.CODE_READY)

    def test_wrong_clipboard_value_does_not_advance(self):
        workflow = ClipboardWorkflow()
        workflow.start(self.record, self.identity)
        self.assertIsNone(workflow.on_paste("unrelated OAuth token"))
        self.assertEqual(workflow.stage, WorkflowStage.EMAIL_READY)
        self.assertEqual(workflow.expected_value, self.record.email)

    def test_incomplete_record_disables_chain(self):
        workflow = ClipboardWorkflow()
        action = workflow.start(
            ClipboardRecord(email="user@example.com", password="secret"),
            self.identity,
        )
        self.assertIsNone(action)
        self.assertEqual(workflow.stage, WorkflowStage.DISABLED)

    def test_new_record_resets_pending_state_and_stop_disables(self):
        workflow = ClipboardWorkflow()
        workflow.start(self.record, self.identity)
        workflow.on_code_found("111111")
        replacement = ClipboardRecord(
            email="next@example.com",
            password="next-secret",
            card_number="5555555555554444",
            second_value="999",
        )
        action = workflow.start(replacement, self.identity)
        self.assertEqual(action.value, replacement.email)
        self.assertIsNone(workflow.on_paste(self.record.email))
        workflow.stop()
        self.assertFalse(workflow.active)
        self.assertIsNone(workflow.on_paste(replacement.email))


class PasteShortcutDetectorTests(unittest.TestCase):
    def test_ctrl_v_and_shift_insert_are_debounced(self):
        detector = PasteShortcutDetector()
        self.assertTrue(
            detector.update(control=True, v_key=True, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=True, v_key=True, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=False, v_key=False, shift=False, insert=False)
        )
        self.assertTrue(
            detector.update(control=False, v_key=False, shift=True, insert=True)
        )
        self.assertFalse(
            detector.update(control=False, v_key=False, shift=True, insert=True)
        )

    def test_unrelated_keys_and_right_click_do_not_trigger(self):
        detector = PasteShortcutDetector()
        self.assertFalse(
            detector.update(control=True, v_key=False, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=False, v_key=True, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=False, v_key=False, shift=False, insert=False)
        )


class ExtractionTests(unittest.TestCase):
    def test_prefers_code_near_keyword(self):
        html = "<p>订单号 20260818</p><p>您的验证码是 <b>654321</b></p>"
        self.assertEqual(extract_verification_code(html), "654321")

    def test_accepts_code_before_keyword(self):
        self.assertEqual(
            extract_verification_code("<p><strong>438921</strong> 是您的验证码</p>"),
            "438921",
        )

    def test_reassembles_digits_split_by_inline_tags(self):
        html = "<p>OTP: <span>1</span><span>2</span><span>3</span><span>4</span></p>"
        self.assertEqual(extract_verification_code(html), "1234")

    def test_decodes_entities_and_ignores_script_and_style(self):
        html = (
            "<style>.x{order:1234}</style>"
            "<script>const code = 5678;</script>"
            "<p>security code: &#57;&#48;&#49;&#50;&#51;&#52;</p>"
        )
        self.assertEqual(extract_verification_code(html), "901234")

    def test_falls_back_to_first_independent_number(self):
        self.assertEqual(extract_verification_code("<p>Use 876543 to continue</p>"), "876543")

    def test_rejects_too_short_too_long_and_empty(self):
        for html in ("<p>123</p>", "<p>123456789</p>", "", None):
            with self.subTest(html=html):
                self.assertIsNone(extract_verification_code(html))


class ApiClientTests(unittest.TestCase):
    def test_default_endpoint_and_headers_use_custom_proxy(self):
        requests = []

        def open_fn(request, timeout):
            requests.append(request)
            return FakeResponse(
                {
                    "success": True,
                    "mailList": [{"mailId": "m1"}],
                    "latestBody": "OTP 123456",
                }
            )

        MailApiClient(open_fn=open_fn).fetch_latest_body(
            "test@example.com", "secret"
        )

        self.assertEqual(requests[0].full_url, API_URL)
        self.assertEqual(requests[0].get_header("Origin"), API_ORIGIN)
        self.assertEqual(requests[0].get_header("Referer"), f"{API_ORIGIN}/")

    def test_returns_body_from_initial_response(self):
        requests = []

        def open_fn(request, timeout):
            requests.append((request, timeout))
            return FakeResponse(
                {"success": True, "mailList": [{"mailId": "m1"}], "latestBody": "OTP 123456"}
            )

        body = MailApiClient(open_fn=open_fn).fetch_latest_body(
            "test@example.com", "secret"
        )
        self.assertEqual(body, "OTP 123456")
        self.assertEqual(len(requests), 1)
        payload = json.loads(requests[0][0].data)
        self.assertEqual(payload["days"], 30)
        self.assertEqual(payload["search"], "")
        self.assertEqual(requests[0][1], 15)

    def test_fetches_first_mail_detail_when_body_is_missing(self):
        responses = iter(
            (
                {"success": True, "mailList": [{"mailId": "newest"}]},
                {"success": True, "latestBody": "验证码：778899"},
            )
        )
        payloads = []

        def open_fn(request, timeout):
            del timeout
            payloads.append(json.loads(request.data))
            return FakeResponse(next(responses))

        body = MailApiClient(open_fn=open_fn).fetch_latest_body(
            "test@example.com", "secret"
        )
        self.assertEqual(body, "验证码：778899")
        self.assertEqual(payloads[1]["mailId"], "newest")
        self.assertNotIn("days", payloads[1])

    def test_empty_mailbox_returns_none(self):
        client = MailApiClient(
            open_fn=lambda request, timeout: FakeResponse(
                {"success": True, "mailList": []}
            )
        )
        self.assertIsNone(client.fetch_latest_body("test@example.com", "secret"))

    def test_service_auth_error_is_fatal(self):
        client = MailApiClient(
            open_fn=lambda request, timeout: FakeResponse(
                {"success": False, "error": "Invalid password"}
            )
        )
        with self.assertRaises(ApiError) as caught:
            client.fetch_latest_body("test@example.com", "wrong")
        self.assertTrue(caught.exception.fatal)

    def test_http_rate_limit_is_retryable(self):
        def open_fn(request, timeout):
            del request, timeout
            raise urllib.error.HTTPError(
                "https://example.invalid",
                429,
                "Too Many Requests",
                {},
                io.BytesIO(b'{"error":"rate limit"}'),
            )

        with self.assertRaises(ApiError) as caught:
            MailApiClient(open_fn=open_fn).fetch_latest_body(
                "test@example.com", "secret"
            )
        self.assertFalse(caught.exception.fatal)


class PollingTests(unittest.TestCase):
    def test_retries_empty_mail_then_finds_code(self):
        class Api:
            def __init__(self):
                self.bodies = iter((None, "<p>OTP: 246810</p>"))

            def fetch_latest_body(self, email, password):
                del email, password
                return next(self.bodies)

        events = []
        waits = []
        cancel = threading.Event()

        def wait(seconds):
            waits.append(seconds)
            if len(waits) == 2:
                cancel.set()
                return True
            return False

        run_polling(
            "test@example.com",
            "secret",
            Api(),
            cancel,
            lambda kind, value: events.append((kind, value)),
            wait,
        )
        self.assertEqual(waits, [5, 5])
        self.assertIn(("found", "246810"), events)

    def test_keeps_polling_and_only_reports_new_codes(self):
        class Api:
            def __init__(self):
                self.bodies = iter(
                    (
                        "verification code 111111",
                        "verification code 111111",
                        "verification code 222222",
                    )
                )
                self.calls = 0

            def fetch_latest_body(self, email, password):
                del email, password
                self.calls += 1
                return next(self.bodies)

        api = Api()
        cancel = threading.Event()
        events = []
        waits = []

        def wait(seconds):
            waits.append(seconds)
            if len(waits) == 3:
                cancel.set()
                return True
            return False

        run_polling(
            "test@example.com",
            "secret",
            api,
            cancel,
            lambda kind, value: events.append((kind, value)),
            wait,
        )

        self.assertEqual(api.calls, 3)
        self.assertEqual(waits, [5, 5, 5])
        self.assertEqual(
            [event for event in events if event[0] == "found"],
            [("found", "111111"), ("found", "222222")],
        )
        self.assertIn(("unchanged", 5), events)

    def test_network_backoff_caps_at_thirty_seconds(self):
        class Api:
            def __init__(self):
                self.calls = 0

            def fetch_latest_body(self, email, password):
                del email, password
                self.calls += 1
                if self.calls <= 5:
                    raise ApiError("network", fatal=False)
                return "code 135790"

        waits = []
        cancel = threading.Event()

        def wait(seconds):
            waits.append(seconds)
            if len(waits) == 6:
                cancel.set()
                return True
            return False

        run_polling(
            "test@example.com",
            "secret",
            Api(),
            cancel,
            lambda kind, value: None,
            wait,
        )
        self.assertEqual(waits, [5, 10, 20, 30, 30, 5])

    def test_fatal_error_stops_without_waiting(self):
        class Api:
            def fetch_latest_body(self, email, password):
                del email, password
                raise ApiError("Invalid password", fatal=True)

        events = []
        run_polling(
            "test@example.com",
            "wrong",
            Api(),
            threading.Event(),
            lambda kind, value: events.append((kind, value)),
            lambda seconds: self.fail(f"unexpected wait: {seconds}"),
        )
        self.assertEqual(events[-1], ("fatal", "账号、密码或请求参数无效"))

    def test_cancel_during_wait_stops_polling(self):
        cancel = threading.Event()

        class Api:
            calls = 0

            def fetch_latest_body(self, email, password):
                del email, password
                self.calls += 1
                return None

        api = Api()

        def wait(seconds):
            del seconds
            cancel.set()
            return True

        run_polling(
            "test@example.com",
            "secret",
            api,
            cancel,
            lambda kind, value: None,
            wait,
        )
        self.assertEqual(api.calls, 1)


if __name__ == "__main__":
    unittest.main()
