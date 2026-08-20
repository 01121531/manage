import io
import json
import unittest
import urllib.error
from email.message import Message
from unittest import mock

from platform.secrets import JsonEnvironmentSecretResolver, SecretResolverUnavailable
from platform.uploads import (
    HttpSub2Adapter,
    Sub2AdapterUnavailable,
    Sub2Policy,
    Sub2UploadCommand,
    Sub2UploadResult,
    UploadUnknownError,
)


class FakeResponse:
    def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.body = json.dumps(payload).encode("utf-8")
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
        payload = json.loads(request.data.decode("utf-8"))
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

    def test_network_and_gateway_failures_are_unknown_not_retryable_success(self) -> None:
        gateway_error = urllib.error.HTTPError(
            "https://sub2-upload.example/api/upload",
            504,
            "Gateway Timeout",
            Message(),
            io.BytesIO(b""),
        )
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            opener=RecordingOpener(gateway_error),
        )
        command = Sub2UploadCommand(
            job_id="job-1",
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
        with self.assertRaises(UploadUnknownError):
            adapter.submit(command)

    def test_missing_secret_is_adapter_unavailable(self) -> None:
        adapter = HttpSub2Adapter(
            "https://sub2-upload.example/api/upload",
            RecordingResolver(),
            opener=RecordingOpener(FakeResponse({"external_ref": "sub2-job-1"})),
        )
        command = Sub2UploadCommand(
            job_id="job-1",
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
