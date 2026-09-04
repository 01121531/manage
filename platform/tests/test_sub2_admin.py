from __future__ import annotations

from email.message import Message
import io
import json
import unittest
import urllib.error

from platform.sub2_admin import (
    Sub2Account,
    Sub2AdminAccountAdapter,
    Sub2AdminPolicy,
    Sub2AdminProbeResult,
    Sub2AdminUnknown,
    Sub2OAuthCredentials,
)


class StaticResolver:
    def resolve(self, secret_ref):
        if secret_ref != "vault://sub2/admin":
            raise AssertionError("unexpected ref")
        return {"x_api_key": "admin-key"}


class FakeResponse:
    def __init__(self, payload, url):
        self.body = json.dumps(payload).encode("utf-8")
        self.url = url
        self.status = 200
        self.headers = Message()

    def read(self, size=-1):
        return self.body[:size]

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class Sub2AdminAccountAdapterTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.responses = []

        def opener(request, timeout):
            self.requests.append((request, timeout))
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return FakeResponse(response, request.full_url)

        self.adapter = Sub2AdminAccountAdapter(
            "https://sub2.example/api/v1/admin",
            "vault://sub2/admin",
            StaticResolver(),
            allowed_origins=["https://sub2.example"],
            opener=opener,
        )
        self.policy = Sub2AdminPolicy(
            version="policy-1",
            proxy_id=1,
            group_ids=(49,),
            concurrency=40,
            model_mapping={"gpt-5.6": "gpt-5.6"},
        )

    def test_official_oauth_and_account_flow_uses_server_api_key(self):
        self.responses.extend(
            [
                {
                    "code": 0,
                    "message": "success",
                    "data": {
                        "auth_url": "https://auth.openai.com/oauth/authorize?state=state-1",
                        "session_id": "session-1",
                    },
                },
                {
                    "code": 0,
                    "message": "success",
                    "data": {
                        "access_token": "access-token",
                        "refresh_token": "refresh-token",
                        "email": "person@example.invalid",
                        "chatgpt_account_is_fedramp": True,
                    },
                },
                {
                    "code": 0,
                    "message": "success",
                    "data": {
                        "id": 88,
                        "platform": "openai",
                        "type": "oauth",
                        "status": "active",
                    },
                },
                {
                    "code": 0,
                    "message": "success",
                    "data": {
                        "id": 88,
                        "platform": "openai",
                        "type": "oauth",
                        "status": "active",
                    },
                },
            ]
        )

        session = self.adapter.generate_auth_url(
            self.policy, redirect_uri="https://callback.example/oauth"
        )
        credentials = self.adapter.exchange_code(session, "code-1")
        created = self.adapter.create_account(
            "account-1",
            credentials,
            self.policy,
            idempotency_key="job-1",
        )
        fetched = self.adapter.get_account(created.account_id)

        self.assertEqual(created, Sub2Account(88, "openai", "oauth", "active"))
        self.assertEqual(fetched, created)
        self.assertEqual([item[1] for item in self.requests], [30, 30, 30, 30])
        for request, _ in self.requests:
            self.assertEqual(request.get_header("X-api-key"), "admin-key")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("Cookie"))
            self.assertIsNone(request.get_header("Origin"))

        generate = json.loads(self.requests[0][0].data)
        exchange = json.loads(self.requests[1][0].data)
        create = json.loads(self.requests[2][0].data)
        self.assertEqual(
            generate,
            {"proxy_id": 1, "redirect_uri": "https://callback.example/oauth"},
        )
        self.assertEqual(exchange["redirect_uri"], generate["redirect_uri"])
        self.assertEqual(self.requests[2][0].get_header("Idempotency-key"), "job-1")
        self.assertEqual(create["platform"], "openai")
        self.assertEqual(create["type"], "oauth")
        self.assertEqual(create["group_ids"], [49])
        self.assertEqual(create["credentials"]["model_mapping"], {"gpt-5.6": "gpt-5.6"})
        self.assertIs(create["credentials"]["chatgpt_account_is_fedramp"], True)
        self.assertNotIn("card", create)
        self.assertNotIn("pan", json.dumps(create).lower())
        self.assertTrue(self.requests[3][0].full_url.endswith("/accounts/88"))

    def test_create_timeout_is_unknown_and_does_not_echo_secrets(self):
        timeout = TimeoutError("access-token admin-key")
        self.responses.append(timeout)
        credentials = Sub2OAuthCredentials(values={"access_token": "access-token"})

        with self.assertRaises(Sub2AdminUnknown) as caught:
            self.adapter.create_account(
                "account-1",
                credentials,
                self.policy,
                idempotency_key="job-1",
            )

        self.assertEqual(str(caught.exception), "Sub2 admin result is unknown")
        self.assertNotIn("access-token", repr(caught.exception))
        self.assertNotIn("admin-key", repr(caught.exception))

    def test_create_conflict_is_unknown_because_it_can_mean_in_progress(self):
        self.responses.append(
            urllib.error.HTTPError(
                "https://sub2.example/api/v1/admin/accounts",
                409,
                "conflict",
                {},
                io.BytesIO(b"{}"),
            )
        )
        credentials = Sub2OAuthCredentials(values={"access_token": "token"})

        with self.assertRaises(Sub2AdminUnknown):
            self.adapter.create_account(
                "account-1",
                credentials,
                self.policy,
                idempotency_key="job-1",
            )

    def test_credential_probe_is_read_only_and_discards_account_data(self):
        self.responses.append(
            {
                "code": 0,
                "message": "success",
                "data": {
                    "items": [{"id": 88, "email": "person@example.invalid"}],
                    "page": 1,
                    "page_size": 1,
                    "pages": 1,
                    "total": 1,
                },
            }
        )

        result = self.adapter.probe_credentials()

        self.assertEqual(result, Sub2AdminProbeResult(True, True))
        request, timeout = self.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.full_url,
            "https://sub2.example/api/v1/admin/accounts?page=1&page_size=1",
        )
        self.assertIsNone(request.data)
        self.assertIsNone(request.get_header("Idempotency-key"))
        self.assertEqual(timeout, 30)
        self.assertNotIn("person@example.invalid", repr(result))

    def test_rejects_non_admin_base_path_and_unapproved_origin(self):
        for url, origins in (
            ("https://sub2.example/api/v1", ["https://sub2.example"]),
            ("https://other.example/api/v1/admin", ["https://sub2.example"]),
            ("http://sub2.example/api/v1/admin", ["https://sub2.example"]),
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Sub2AdminAccountAdapter(
                    url,
                    "vault://sub2/admin",
                    StaticResolver(),
                    allowed_origins=origins,
                )

    def test_rejects_non_official_or_ambiguous_oauth_url(self):
        for auth_url in (
            "https://login.example/oauth/authorize?state=state-1",
            "https://auth.openai.com/other?state=state-1",
            "https://auth.openai.com/oauth/authorize?state=one&state=two",
        ):
            self.responses.append(
                {
                    "code": 0,
                    "message": "success",
                    "data": {"auth_url": auth_url, "session_id": "session-1"},
                }
            )
            with self.subTest(auth_url=auth_url), self.assertRaises(Sub2AdminUnknown):
                self.adapter.generate_auth_url(self.policy)


if __name__ == "__main__":
    unittest.main()
