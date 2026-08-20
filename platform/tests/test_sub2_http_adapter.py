import io
import json
import unittest
import urllib.error
from email.message import Message
from unittest import mock

from platform.secrets import JsonEnvironmentSecretResolver, SecretResolverUnavailable
from platform.uploads import (
    HttpSub2Adapter,
    Sub2AdapterError,
    Sub2AdapterUnavailable,
    Sub2Policy,
    Sub2UploadCommand,
    Sub2UploadResult,
    UploadUnknownError,
)


class FakeResponse:
    def __init__(
        self,
        payload: object | None = None,
        *,
        status: int = 200,
        raw_body: bytes | None = None,
    ) -> None:
        self.body = (
            raw_body
            if raw_body is not None
            else json.dumps(payload).encode("utf-8")
        )
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def read(self) -> bytes:
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingResolver:
    def __init__(self, *, credential: dict[str, object] | None = None) -> None:
        self.refs: list[str] = []
        self.credential = credential or {"bearer_token": "sub2-token-secret"}

    def resolve(self, secret_ref: str) -> dict[str, object]:
        self.refs.append(secret_ref)
        values = {
            "vault://sub2/credential": self.credential,
            "vault://cards/card-1": {
                "pan": "4111111111111111",
                "cvv": "123",
                "expiry_month": 12,
                "expiry_year": 2030,
            },
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
        self.assertEqual(payload["card"]["pan"], "4111111111111111")
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
        ):
            self.assertNotIn(forbidden, body_text)

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
                    opener=RecordingOpener(response),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

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
                    opener=RecordingOpener(error),
                )
                with self.assertRaises(UploadUnknownError):
                    adapter.submit(self.command())

    def test_non_2xx_response_object_is_classified_before_body(self) -> None:
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
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
            )


if __name__ == "__main__":
    unittest.main()
