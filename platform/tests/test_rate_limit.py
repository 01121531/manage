import asyncio
import unittest
from collections.abc import Callable

import httpx
from fastapi import Request

from platform.app import create_app
from platform.config import Settings
from platform.rate_limit import (
    RateLimitBackendUnavailable,
    RateLimitMiddleware,
    RedisRateLimitBackend,
)


class FakeRateLimitBackend:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.counts: dict[str, int] = {}
        self.keys: list[str] = []

    async def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        if not self.available:
            raise RateLimitBackendUnavailable("offline")
        self.keys.append(key)
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key], window_seconds

    async def ping(self) -> bool:
        if not self.available:
            raise RateLimitBackendUnavailable("offline")
        return True


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_name": "rate-limit-test",
        "environment": "test",
        "database_url": "sqlite+pysqlite:///:memory:",
        "jwt_hmac_secret": "rate-limit-unit-test-secret",
        "rate_limit_enabled": True,
        "rate_limit_window_seconds": 60,
        "rate_limit_login_requests": 2,
        "rate_limit_high_risk_requests": 3,
        "rate_limit_general_requests": 2,
    }
    values.update(overrides)
    return Settings(**values)


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_name": "rate-limit-production-test",
        "environment": "production",
        "database_url": "sqlite+pysqlite:///:memory:",
        "auth_mode": "oidc",
        "oidc_issuer_url": "https://identity.example.test/realms/platform",
        "oidc_audience": "platform-api",
        "oidc_client_id": "platform-web",
        "oidc_desktop_client_id": "platform-desktop",
        "oidc_jwks_url": (
            "https://identity.example.test/realms/platform/"
            "protocol/openid-connect/certs"
        ),
        "internal_ca_file": "/run/secrets/internal-tls/ca.crt",
        "allowed_origins": "https://platform.example.test",
        "mail_poll_mode": "worker",
        "rate_limit_enabled": True,
        "redis_url": "redis://redis.example.test:6379/0",
    }
    values.update(overrides)
    return Settings(**values)


class RateLimitTests(unittest.TestCase):
    def make_app(
        self,
        *,
        backend: FakeRateLimitBackend | None = None,
        settings: Settings | None = None,
        clock: Callable[[], float] | None = None,
    ):
        app = create_app(
            settings or _settings(),
            access_token_verifier=(
                object()
                if settings is not None and settings.auth_mode == "oidc"
                else None
            ),
            rate_limit_backend=backend or FakeRateLimitBackend(),
            rate_limit_clock=clock or (lambda: 1_700_000_000.0),
            secret_resolver=(
                object()
                if settings is not None
                and settings.environment not in {"development", "test"}
                else None
            ),
        )
        self.addCleanup(app.state.engine.dispose)
        return app

    @staticmethod
    def request(app, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def test_success_and_limit_response_headers(self) -> None:
        app = self.make_app()

        first = self.request(app, "GET", "/api/v1/health")
        second = self.request(app, "GET", "/api/v1/health")
        limited = self.request(app, "GET", "/api/v1/health")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.headers["X-RateLimit-Limit"], "2")
        self.assertEqual(first.headers["X-RateLimit-Remaining"], "1")
        self.assertEqual(second.headers["X-RateLimit-Remaining"], "0")
        self.assertEqual(limited.status_code, 429, limited.text)
        self.assertEqual(limited.json()["error"]["code"], "rate_limited")
        self.assertTrue(limited.json()["error"]["trace_id"])
        self.assertEqual(limited.headers["X-RateLimit-Limit"], "2")
        self.assertEqual(limited.headers["X-RateLimit-Remaining"], "0")
        self.assertGreaterEqual(int(limited.headers["Retry-After"]), 1)

    def test_policy_tiers_use_ip_only_for_login_and_identity_ip_for_risk(self) -> None:
        backend = FakeRateLimitBackend()
        app = self.make_app(backend=backend)

        login = self.request(
            app,
            "POST",
            "/api/v1/auth/login",
            headers={"X-Real-IP": "2001:0db8:0:0:0:0:0:1"},
            json={},
        )
        upload = self.request(
            app,
            "POST",
            "/api/v1/uploads",
            headers={
                "Authorization": "Bearer raw-super-secret-token",
                "X-Real-IP": "203.0.113.44",
            },
            json={
                "tenant_id": "raw-tenant-a",
                "email": "raw@example.test",
            },
        )

        self.assertEqual(login.headers["X-RateLimit-Limit"], "2")
        self.assertEqual(upload.headers["X-RateLimit-Limit"], "3")
        self.assertIn(":login:", backend.keys[0])
        self.assertIn(":high_risk:", backend.keys[1])
        combined_keys = " ".join(backend.keys)
        for raw_value in (
            "raw-super-secret-token",
            "raw@example.test",
            "raw-tenant-a",
            "203.0.113.44",
            "2001:db8::1",
        ):
            self.assertNotIn(raw_value, combined_keys)

    def test_login_limit_does_not_trust_client_supplied_real_ip(self) -> None:
        backend = FakeRateLimitBackend()
        app = self.make_app(backend=backend)

        responses = [
            self.request(
                app,
                "POST",
                "/api/v1/auth/login",
                headers={"X-Real-IP": f"203.0.113.{index}"},
                json={},
            )
            for index in range(1, 4)
        ]

        self.assertEqual([response.status_code for response in responses], [422, 422, 429])
        self.assertEqual(len(set(backend.keys)), 1)

    def test_fixed_window_key_isolated_after_window_boundary(self) -> None:
        backend = FakeRateLimitBackend()
        clock_value = [59.9]
        middleware = RateLimitMiddleware(
            app=lambda scope, receive, send: None,
            backend=backend,
            api_prefix="/api/v1",
            login_limit=2,
            high_risk_limit=3,
            general_limit=2,
            window_seconds=60,
            fail_closed=False,
            clock=lambda: clock_value[0],
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/v1/health",
                "raw_path": b"/api/v1/health",
                "query_string": b"",
                "headers": [],
                "scheme": "http",
                "server": ("test", 80),
                "client": ("127.0.0.1", 50000),
            }
        )
        policy = middleware._policy(request)

        first_key = middleware._key(request, policy, clock_value[0])
        clock_value[0] = 60.0
        second_key = middleware._key(request, policy, clock_value[0])

        self.assertNotEqual(first_key, second_key)
        self.assertIn(":0:", first_key)
        self.assertIn(":1:", second_key)

    def test_all_upload_writes_and_card_reveals_use_high_risk_policy(self) -> None:
        middleware = RateLimitMiddleware(
            app=lambda scope, receive, send: None,
            backend=FakeRateLimitBackend(),
            api_prefix="/api/v1",
            login_limit=2,
            high_risk_limit=3,
            general_limit=20,
            window_seconds=60,
            fail_closed=False,
        )

        def request(method: str, path: str) -> Request:
            return Request(
                {
                    "type": "http",
                    "method": method,
                    "path": path,
                    "raw_path": path.encode("ascii"),
                    "query_string": b"",
                    "headers": [],
                    "scheme": "http",
                    "server": ("test", 80),
                    "client": ("127.0.0.1", 50000),
                }
            )

        high_risk_paths = (
            ("POST", "/api/v1/uploads"),
            ("POST", "/api/v1/tasks/task-1/uploads"),
            ("POST", "/api/v1/uploads/job-1/cancel"),
            ("POST", "/api/v1/upload-jobs/job-1/reconcile"),
            ("POST", "/api/v1/card-allocations/card-1/reveal-challenges"),
            ("POST", "/api/v1/card-allocations/card-1/reveal-grants"),
            ("POST", "/api/v1/card-allocations/card-1/reveal"),
        )
        for method, path in high_risk_paths:
            with self.subTest(method=method, path=path):
                self.assertEqual(
                    middleware._policy(request(method, path)).name,
                    "high_risk",
                )

        self.assertEqual(
            middleware._policy(request("GET", "/api/v1/uploads/job-1")).name,
            "general",
        )
        self.assertEqual(
            middleware._policy(request("GET", "/api/v1/admin/uploads")).name,
            "general",
        )

    def test_backend_failure_fails_closed_in_production(self) -> None:
        backend = FakeRateLimitBackend(available=False)
        app = self.make_app(backend=backend, settings=_production_settings())

        response = self.request(app, "GET", "/api/v1/health")

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "service_unavailable")
        self.assertTrue(response.json()["error"]["trace_id"])
        self.assertNotIn("offline", response.text)

    def test_backend_failure_fails_open_only_in_test(self) -> None:
        backend = FakeRateLimitBackend(available=False)
        app = self.make_app(backend=backend)

        response = self.request(app, "GET", "/api/v1/health")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("X-RateLimit-Limit", response.headers)

    def test_production_requires_enabled_rate_limit_and_secret_redis_url(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "RATE_LIMIT_ENABLED"):
            create_app(_production_settings(rate_limit_enabled=False))
        with self.assertRaisesRegex(RuntimeError, "REDIS_URL"):
            create_app(_production_settings(redis_url=None))
        with self.assertRaisesRegex(RuntimeError, "REDIS_URL"):
            create_app(_production_settings(redis_url=""))

        settings = _production_settings()
        self.assertNotIn(
            settings.redis_url.get_secret_value(),
            repr(settings),
        )

    def test_worker_bootstrap_skips_api_only_origin_and_rate_limit_gates(self) -> None:
        app = create_app(
            _production_settings(
                allowed_origins="",
                rate_limit_enabled=False,
                redis_url=None,
            ),
            service_role="worker",
            access_token_verifier=object(),
            secret_resolver=object(),
        )
        try:
            self.assertIsNone(app.state.rate_limit_backend)
        finally:
            app.state.engine.dispose()

    def test_readyz_checks_redis_when_enabled(self) -> None:
        healthy = self.make_app(backend=FakeRateLimitBackend())
        healthy_response = self.request(healthy, "GET", "/readyz")
        self.assertEqual(healthy_response.status_code, 200, healthy_response.text)
        self.assertEqual(healthy_response.json()["checks"]["redis"], "ok")

        unavailable = self.make_app(
            backend=FakeRateLimitBackend(available=False)
        )
        unavailable_response = self.request(unavailable, "GET", "/readyz")
        self.assertEqual(unavailable_response.status_code, 503)
        self.assertEqual(
            unavailable_response.json()["checks"]["redis"], "unavailable"
        )


class FakeRedisClient:
    def __init__(self) -> None:
        self.eval_args: tuple[object, ...] | None = None

    async def eval(self, *args: object) -> list[int]:
        self.eval_args = args
        return [1, 60]

    async def ping(self) -> bool:
        return True


class RedisBackendTests(unittest.TestCase):
    def test_redis_counter_uses_one_atomic_lua_evaluation_with_ttl(self) -> None:
        client = FakeRedisClient()
        backend = RedisRateLimitBackend("redis://unused", client=client)

        count, ttl = asyncio.run(backend.increment("rate-limit:test:key", 60))

        self.assertEqual((count, ttl), (1, 60))
        self.assertIsNotNone(client.eval_args)
        script, key_count, key, window = client.eval_args
        self.assertIn("INCR", script)
        self.assertIn("EXPIRE", script)
        self.assertIn("TTL", script)
        self.assertEqual((key_count, key, window), (1, "rate-limit:test:key", 60))


if __name__ == "__main__":
    unittest.main()
