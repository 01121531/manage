from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from platform.app import create_app
from platform.config import Settings
from platform.middleware import parse_allowed_origins


class OriginPolicyTests(unittest.TestCase):
    def _client(self, allowed_origins: str) -> TestClient:
        app = create_app(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                allowed_origins=allowed_origins,
            )
        )
        return TestClient(app)

    def test_exact_allowed_origin_and_preflight(self) -> None:
        with self._client("https://platform.example.com") as client:
            response = client.get(
                "/healthz", headers={"Origin": "https://platform.example.com"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.headers["access-control-allow-origin"],
                "https://platform.example.com",
            )
            self.assertIn("Origin", response.headers["vary"])

            preflight = client.options(
                "/api/v1/tasks",
                headers={
                    "Origin": "https://platform.example.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization,content-type",
                },
            )
            self.assertEqual(preflight.status_code, 204)
            self.assertIn(
                "Authorization", preflight.headers["access-control-allow-headers"]
            )

    def test_disallowed_origin_is_safe_403_with_trace(self) -> None:
        trace_id = "11111111-1111-4111-8111-111111111111"
        with self._client("https://platform.example.com") as client:
            response = client.get(
                "/healthz",
                headers={"Origin": "https://evil.example", "X-Trace-Id": trace_id},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "origin_not_allowed")
        self.assertEqual(response.json()["error"]["trace_id"], trace_id)
        self.assertEqual(response.headers["x-trace-id"], trace_id)
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_native_request_without_origin_remains_supported(self) -> None:
        with self._client("https://platform.example.com") as client:
            response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_origin_parser_rejects_wildcards_paths_and_non_loopback_http(self) -> None:
        for invalid in (
            "*",
            "https://platform.example.com/path",
            "https://user@platform.example.com",
            "http://platform.example.com",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_allowed_origins(invalid, require_https=False)
        self.assertEqual(
            parse_allowed_origins("http://127.0.0.1:5173", require_https=False),
            ("http://127.0.0.1:5173",),
        )

    def test_managed_environment_requires_allowlist(self) -> None:
        settings = Settings(
            environment="production",
            auth_mode="oidc",
            oidc_issuer_url="https://identity.example/realms/platform",
            oidc_audience="platform-api",
            oidc_client_id="platform-web",
            oidc_desktop_client_id="platform-desktop",
            oidc_jwks_url="https://identity.example/realms/platform/certs",
            internal_ca_file="/run/secrets/internal-tls/ca.crt",
            rate_limit_enabled=True,
            redis_url="redis://localhost:6379/0",
            allowed_origins="",
        )
        with self.assertRaisesRegex(RuntimeError, "PLATFORM_ALLOWED_ORIGINS"):
            create_app(settings)


if __name__ == "__main__":
    unittest.main()
