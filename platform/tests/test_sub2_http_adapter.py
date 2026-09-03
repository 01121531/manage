import io
import json
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

from platform.config import Settings
from platform.secrets import JsonEnvironmentSecretResolver, SecretResolverUnavailable
from platform.uploads import (
    AI1_OBSERVED_CONTROL_PLANE_PATHS,
    HttpSub2Adapter,
    Sub2AdapterError,
    Sub2AdapterUnavailable,
    Sub2Policy,
    Sub2UploadCommand,
    Sub2UploadResult,
    UploadUnknownError,
)

ALLOWED_ORIGINS = ("https://sub2-upload.example",)


class FakeResponse:
    def __init__(
        self,
        payload: object | None = None,
        *,
        status: int = 200,
        raw_body: bytes | None = None,
        final_url: str | None = None,
        content_type: str = "application/json",
    ) -> None:
        self.body = (
            raw_body
            if raw_body is not None
            else json.dumps(payload).encode("utf-8")
        )
        self.status = status
        self.final_url = final_url
        self.read_sizes: list[int] = []
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def geturl(self) -> str:
        return self.final_url or "https://sub2-upload.example/api/upload"

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingResolver:
    def __init__(
        self,
        *,
        credential: dict[str, object] | None = None,
        card: dict[str, object] | None = None,
    ) -> None:
        self.refs: list[str] = []
        self.credential = credential or {"bearer_token": "sub2-token-secret"}
        self.card = card or {
            "pan": "4111111111111111",
            "cvv": "123",
            "expiry_month": 12,
            "expiry_year": 2030,
            "pin": "9876",
            "vault_token": "must-not-leave-card-vault",
        }

    def resolve(self, secret_ref: str) -> dict[str, object]:
        self.refs.append(secret_ref)
        values = {
            "vault://sub2/credential": self.credential,
            "vault://cards/card-1": self.card,
            "vault://sub2/proxy": {"id": 2940, "url": "socks5://proxy.internal"},
        }
        value = values.get(secret_ref)
        if value is None:
            raise SecretResolverUnavailable("missing secret")
        return value


class RecordingOpener:
    def __init__(self, result) -> None:
        self.result = result
        self.requests = []

    def __call__(self, request, timeout: int):
        self.requests.append((request, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class HttpSub2AdapterTests(unittest.TestCase):
    @staticmethod
    def command() -> Sub2UploadCommand:
        return Sub2UploadCommand(
            job_id="job-1",
            task_id="task-1",
            business_name="Example Store",
            card_secret_ref="vault://cards/card-1",
            policy=Sub2Policy(
                version="sub2-policy-1",
                proxy_ref="vault://sub2/proxy",
                group_id=49,
                concurrency=40,
                credential_ref="vault://sub2/credential",
            ),
        )

    def test_upload_origin_must_match_exact_reviewed_https_origin_before_secrets(self) -> None:
        cases = (
            ("https://sub2-upload.example/api/upload", ""),
            ("https://sub2-upload.example/api/upload", "*"),
            ("https://sub2-upload.example/api/upload", "https://*.example"),
            ("https://sub2-upload.example/api/upload", "https://user@sub2-upload.example"),
            ("https://sub2-upload.example/api/upload", "https://sub2-upload.example/path"),
            ("https://sub2-upload.example/api/upload", "https://sub2-upload.example?x=1"),
            ("https://sub2-upload.example/api/upload", "https://sub2-upload.example#fragment"),
            ("https://sub2-upload.example/api/upload", "https://sub2-upload.example."),
            ("https://sub2-upload.example/api/upload", "https://sub2-upload.example:0"),
            ("https://sub2-upload.example/api/upload", "https://127.0.0.1"),
            ("https://sub2-upload.example/api/upload", "https://localhost"),
            ("https://sub2-upload.example.evil/api/upload", "https://sub2-upload.example"),
            ("https://sub2-upload.example:8443/api/upload", "https://sub2-upload.example"),
            ("https://sub2-upload.example:0/api/upload", "https://sub2-upload.example:0"),
            ("http://sub2-upload.example/api/upload", "https://sub2-upload.example"),
        )
        for upload_url, allowed_origin in cases:
            resolver = RecordingResolver()
            opener = RecordingOpener(FakeResponse({"external_ref": "unexpected"}))
            with self.subTest(upload_url=upload_url, allowed_origin=allowed_origin):
                with self.assertRaises(ValueError):
                    HttpSub2Adapter(
                        upload_url,
                        resolver,
                        allowed_origins=(allowed_origin,),
                        opener=opener,
                    )
            self.assertEqual(resolver.refs, [])
            self.assertEqual(opener.requests, [])

    def test_observed_ai1_control_plane_paths_cannot_receive_generic_uploads(self) -> None:
        concrete_paths = (
            AI1_OBSERVED_CONTROL_PLANE_PATHS
            - {"/api/v1/admin/accounts/{account_id}/duplicate"}
        ) | {"/api/v1/admin/accounts/42/duplicate"}
        for path in sorted(concrete_paths):
            resolver = RecordingResolver()
            opener = RecordingOpener(FakeResponse({"external_ref": "unexpected"}))
            with self.subTest(path=path), self.assertRaisesRegex(
                ValueError, "Observed account-control endpoint"
            ) as raised:
                HttpSub2Adapter(
                    f"https://ai1.aisb.shop{path}",
                    resolver,
                    allowed_origins=("https://ai1.aisb.shop",),
                    opener=opener,
                )
            self.assertNotIn(path, str(raised.exception))
            self.assertEqual(resolver.refs, [])
            self.assertEqual(opener.requests, [])

    def test_ai1_unknown_business_path_and_other_hosts_remain_configurable(self) -> None:
        resolver = RecordingResolver()
        opener = RecordingOpener(FakeResponse({"external_ref": "unused"}))

        HttpSub2Adapter(
            "https://ai1.aisb.shop/api/v1/provider-upload",
            resolver,
            allowed_origins=("https://ai1.aisb.shop",),
            opener=opener,
        )
        HttpSub2Adapter(
            "https://provider.example/api/v1/admin/accounts",
            resolver,
            allowed_origins=("https://provider.example",),
            opener=opener,
        )

        self.assertEqual(resolver.refs, [])
        self.assertEqual(opener.requests, [])

    def test_exact_allowed_origin_accepts_business_path_and_effective_default_port(self) -> None:
        resolver = RecordingResolver()
        opener = RecordingOpener(
            FakeResponse(
                {"external_ref": "sub2-job-1"},
                final_url="https://sub2-upload.example:443/api/upload",
            )
        )
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example:443/api/upload",
            resolver,
            allowed_origins=("https://sub2-upload.example",),
            opener=opener,
        )
        self.assertEqual(adapter.submit(self.command()).external_ref, "sub2-job-1")

    def test_allowed_origin_file_is_required_single_line_and_errors_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed-origins"
            allowed.write_text(
                "https://sub2-upload.example,https://sub2-backup.example:8443\n",
                encoding="utf-8",
            )
            settings = Settings(
                _env_file=None,
                sub2_allowed_origins_file=str(allowed),
            )
            self.assertEqual(
                settings.resolved_sub2_allowed_origins(),
                (
                    "https://sub2-upload.example",
                    "https://sub2-backup.example:8443",
                ),
            )

            invalid_files = {
                "empty": "",
                "multiple-lines": "https://sub2-upload.example\nhttps://other.example\n",
                "empty-member": "https://sub2-upload.example,",
            }
            for label, content in invalid_files.items():
                path = root / label
                path.write_text(content, encoding="utf-8")
                with self.subTest(label=label):
                    with self.assertRaises(RuntimeError) as raised:
                        Settings(
                            _env_file=None,
                            sub2_allowed_origins_file=str(path),
                        ).resolved_sub2_allowed_origins()
                    self.assertNotIn(str(path), str(raised.exception))
                    if content.strip():
                        self.assertNotIn(content.strip(), str(raised.exception))

            for path in (None, str(root / "missing")):
                with self.subTest(path=path):
                    with self.assertRaises(RuntimeError) as raised:
                        Settings(
                            _env_file=None,
                            sub2_allowed_origins_file=path,
                        ).resolved_sub2_allowed_origins()
                    self.assertNotIn(str(root), str(raised.exception))

    def test_env_secret_resolver_reads_json_object_and_plain_text(self) -> None:
        resolver = JsonEnvironmentSecretResolver()
        with mock.patch.dict(
            "os.environ",
            {
                "SUB2_CREDENTIAL_JSON": '{"bearer_token":"secret-token"}',
                "PLAIN_SECRET": "plain-secret",
            },
            clear=False,
        ):
            self.assertEqual(
                resolver.resolve("env://SUB2_CREDENTIAL_JSON"),
                {"bearer_token": "secret-token"},
            )
            self.assertEqual(
                resolver.resolve("env://PLAIN_SECRET"),
                {"value": "plain-secret"},
            )

    def test_posts_resolved_server_policy_without_secret_refs_in_body(self) -> None:
        resolver = RecordingResolver()
        opener = RecordingOpener(FakeResponse({"external_ref": "sub2-job-1"}))
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            resolver,
            allowed_origins=ALLOWED_ORIGINS,
            timeout=12,
            opener=opener,
        )
        result = adapter.submit(
            Sub2UploadCommand(
                job_id="job-1",
                task_id="task-1",
                business_name="Example Store",
                card_secret_ref="vault://cards/card-1",
                policy=Sub2Policy(
                    version="sub2-policy-1",
                    proxy_ref="vault://sub2/proxy",
                    group_id=49,
                    concurrency=40,
                    credential_ref="vault://sub2/credential",
                ),
            )
        )

        self.assertEqual(result, Sub2UploadResult(external_ref="sub2-job-1"))
        request, timeout = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(timeout, 12)
        self.assertEqual(request.headers["Authorization"], "Bearer sub2-token-secret")
        self.assertEqual(request.get_header("Idempotency-key"), "job-1")
        self.assertEqual(request.get_header("X-platform-task-id"), "task-1")
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["job_id"], "job-1")
        self.assertEqual(payload["task_id"], "task-1")
        self.assertEqual(payload["business_name"], "Example Store")
        self.assertEqual(
            payload["card"],
            {"pan": "4111111111111111", "expiry_month": 12, "expiry_year": 2030},
        )
        self.assertEqual(payload["policy"]["group_id"], 49)
        self.assertEqual(payload["policy"]["concurrency"], 40)
        self.assertEqual(payload["policy"]["proxy"]["id"], 2940)
        self.assertEqual(
            resolver.refs,
            ["vault://sub2/credential", "vault://cards/card-1", "vault://sub2/proxy"],
        )
        body_text = request.data.decode("utf-8")
        for forbidden in (
            "vault://",
            "credential_ref",
            "secret_ref",
            "sub2-token-secret",
            '"cvv"',
            '"pin"',
            '"vault_token"',
            "must-not-leave-card-vault",
        ):
            self.assertNotIn(forbidden, body_text)

    def test_invalid_card_projection_fails_before_network_without_secret_values(self) -> None:
        invalid_cards = (
            {"cvv": "123"},
            {"pan": "not-a-pan"},
            {"pan": "4111111111111111", "expiry_month": 12},
            {
                "pan": "4111111111111111",
                "expiry_month": 13,
                "expiry_year": 2030,
            },
        )
        for card in invalid_cards:
            opener = RecordingOpener(FakeResponse({"external_ref": "unexpected"}))
            adapter = HttpSub2Adapter(
                "https://sub2-upload.example/api/upload",
                RecordingResolver(card=card),
                allowed_origins=ALLOWED_ORIGINS,
                opener=opener,
            )
            with self.subTest(card_keys=tuple(card)):
                with self.assertRaises(Sub2AdapterUnavailable) as raised:
                    adapter.submit(self.command())
                self.assertEqual(opener.requests, [])
                for value in card.values():
                    self.assertNotIn(str(value), str(raised.exception))

    def test_all_server_errors_are_unknown(self) -> None:
        for status in (500, 501, 502, 503, 504, 599):
            with self.subTest(status=status):
                error = urllib.error.HTTPError(
                    "https://sub2-upload.example/api/upload",
                    status,
                    "server error",
                    Message(),
                    io.BytesIO(b""),
                )
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(error),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

    def test_network_failures_are_unknown(self) -> None:
        for error in (
            TimeoutError("timed out"),
            urllib.error.URLError("connection reset"),
            OSError("disconnected"),
        ):
            with self.subTest(error=type(error).__name__):
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(error),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

    def test_ambiguous_success_responses_are_unknown(self) -> None:
        responses = (
            FakeResponse(raw_body=b"not-json"),
            FakeResponse(["not", "an", "object"]),
            FakeResponse({"success": True}),
            FakeResponse({"success": False}),
            FakeResponse({"id": "alias-is-not-external-ref"}, status=201),
            FakeResponse(raw_body=b"", status=204),
        )
        for response in responses:
            with self.subTest(body=response.body):
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(response),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

    def test_redirects_and_oversized_responses_are_unknown(self) -> None:
        responses = (
            FakeResponse(
                {"external_ref": "sub2-job-1"},
                final_url="https://redirect.example/upload",
            ),
            FakeResponse(raw_body=b"x" * (64 * 1024 + 1)),
        )
        for response in responses:
            with self.subTest(final_url=response.final_url, size=len(response.body)):
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(response),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            allowed_origins=ALLOWED_ORIGINS,
        )
        self.assertTrue(
            any(
                handler.__class__.__name__ == "_NoRedirectHandler"
                for handler in adapter._default_opener.handlers
            )
        )

    def test_json_boundary_accepts_exact_limit_and_ignores_charset(self) -> None:
        encoded = json.dumps(
            {"data": {"external_ref": "sub2-job-1"}},
            separators=(",", ":"),
        ).encode("utf-8")
        response = FakeResponse(
            raw_body=encoded + (b" " * ((64 * 1024) - len(encoded))),
            content_type="application/json; charset=secret-sentinel-codec",
        )
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            allowed_origins=ALLOWED_ORIGINS,
            opener=RecordingOpener(response),
        )

        result = adapter.submit(self.command())

        self.assertEqual(result, Sub2UploadResult(external_ref="sub2-job-1"))
        self.assertEqual(response.read_sizes, [(64 * 1024) + 1])

    def test_json_boundary_rejects_duplicate_keys_and_non_utf8(self) -> None:
        cases = (
            b'{"success":true,"success":true,"external_ref":"sub2-job-1"}',
            b'{"data":{"external_ref":"sub2-job-1"},"data":{"external_ref":"sub2-job-1"}}',
            b'{"external_ref":"sub2-job-1","ignored":"\xff"}',
        )
        for body in cases:
            with self.subTest(body=body):
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(
                        FakeResponse(
                            raw_body=body,
                            content_type="application/json; charset=iso-8859-1",
                        )
                    ),
                )

                with self.assertRaises(UploadUnknownError) as raised:
                    adapter.submit(self.command())

                self.assertEqual(
                    str(raised.exception), "Sub2 upload returned invalid JSON"
                )
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn("sub2-job-1", str(raised.exception))

    def test_only_definitive_4xx_rejections_are_failed(self) -> None:
        for status in (400, 401, 403, 404, 405, 413, 415, 422):
            with self.subTest(status=status):
                error = urllib.error.HTTPError(
                    "https://sub2-upload.example/api/upload",
                    status,
                    "rejected",
                    Message(),
                    io.BytesIO(b""),
                )
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(error),
                )
                with self.assertRaises(Sub2AdapterError):
                    adapter.submit(self.command())

        for status in (408, 409, 425, 429):
            with self.subTest(ambiguous_status=status):
                error = urllib.error.HTTPError(
                    "https://sub2-upload.example/api/upload",
                    status,
                    "ambiguous",
                    Message(),
                    io.BytesIO(b""),
                )
                adapter = HttpSub2Adapter(
                    "https://sub2-upload.example/api/upload",
                    RecordingResolver(),
                    allowed_origins=ALLOWED_ORIGINS,
                    opener=RecordingOpener(error),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

    def test_non_2xx_response_object_is_classified_before_body(self) -> None:
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            allowed_origins=ALLOWED_ORIGINS,
            opener=RecordingOpener(
                FakeResponse({"external_ref": "wrong"}, status=500)
            ),
        )
        with self.assertRaises(UploadUnknownError):
            adapter.submit(self.command())

    def test_missing_secret_is_adapter_unavailable(self) -> None:
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            allowed_origins=ALLOWED_ORIGINS,
            opener=RecordingOpener(FakeResponse({"external_ref": "sub2-job-1"})),
        )
        command = Sub2UploadCommand(
            job_id="job-1",
            task_id="task-1",
            business_name="Example Store",
            card_secret_ref="vault://cards/missing",
            policy=Sub2Policy(
                version="sub2-policy-1",
                proxy_ref="vault://sub2/proxy",
                group_id=49,
                concurrency=40,
                credential_ref="vault://sub2/credential",
            ),
        )
        with self.assertRaises(Sub2AdapterUnavailable):
            adapter.submit(command)

    def test_missing_credential_token_is_adapter_unavailable(self) -> None:
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(credential={"client": "no-token"}),
            allowed_origins=ALLOWED_ORIGINS,
            opener=RecordingOpener(FakeResponse({"external_ref": "sub2-job-1"})),
        )
        command = Sub2UploadCommand(
            job_id="job-1",
            task_id="task-1",
            business_name="Example Store",
            card_secret_ref="vault://cards/card-1",
            policy=Sub2Policy(
                version="sub2-policy-1",
                proxy_ref="vault://sub2/proxy",
                group_id=49,
                concurrency=40,
                credential_ref="vault://sub2/credential",
            ),
        )
        with self.assertRaises(Sub2AdapterUnavailable):
            adapter.submit(command)

    def test_rejects_non_https_non_loopback_url(self) -> None:
        with self.assertRaises(ValueError):
            HttpSub2Adapter(
                "http://sub2-upload.example/api/upload",
                RecordingResolver(),
                allowed_origins=ALLOWED_ORIGINS,
            )


if __name__ == "__main__":
    unittest.main()
