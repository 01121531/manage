import asyncio
import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import httpx
from sqlalchemy import func, select

from platform.api.v1 import routes
from platform.app import create_app
from platform.auth import decode_access_token
from platform.bootstrap import create_oidc_user_with_device, create_user_with_device
from platform.config import Settings
from platform.models import AuditEvent, RevokedAccessToken, Task, utc_now


class LogoutTokenRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="logout-token-race-")
        database = Path(self.directory.name) / "platform.db"
        self.secret = "logout-token-race-secret-that-is-not-production"
        self.app = create_app(
            Settings(
                environment="test",
                database_url=f"sqlite+pysqlite:///{database.as_posix()}",
                jwt_hmac_secret=self.secret,
            )
        )
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        self.password = "logout-token-race-password"
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-logout-token-race",
            email="logout-token-race@example.test",
            password=self.password,
            device_name="logout-token-race-device",
        )
        with self.app.state.session_factory() as db:
            db.add(
                Task(
                    tenant_id="tenant-logout-token-race",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    task_type="mail_code",
                    idempotency_key="logout-token-race-task",
                    trace_id="logout-token-race-trace",
                    status="created",
                    expires_at=utc_now(),
                )
            )
            db.commit()
        self.token = self._login()

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.directory.cleanup()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def _login(self) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-logout-token-race",
                "email": "logout-token-race@example.test",
                "password": self.password,
                "device_id": self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    def test_local_logins_have_distinct_unpredictable_jti(self) -> None:
        second = self._login()
        first_claims = decode_access_token(self.token, self.secret)
        second_claims = decode_access_token(second, self.secret)
        self.assertNotEqual(self.token, second)
        self.assertNotEqual(first_claims["jti"], second_claims["jti"])
        self.assertGreaterEqual(len(first_claims["jti"]), 32)

    def test_concurrent_logout_claims_once_and_both_callers_succeed(self) -> None:
        both_authenticated = Barrier(2, timeout=5)
        original = routes._revoke_access_token

        def synchronized_claim(*args, **kwargs):
            both_authenticated.wait()
            return original(*args, **kwargs)

        headers = {"Authorization": f"Bearer {self.token}"}
        with patch(
            "platform.api.v1.routes._revoke_access_token",
            side_effect=synchronized_claim,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        self.request,
                        "POST",
                        "/api/v1/auth/logout",
                        headers=headers,
                    )
                    for _ in range(2)
                ]
                responses = [future.result(timeout=10) for future in futures]

        self.assertEqual([response.status_code for response in responses], [200, 200])
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RevokedAccessToken)), 1
            )
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "auth.logout")
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "task.cancelled")
                ),
                1,
            )

    def test_logout_cleans_expired_denylist_without_leaking_token_material(self) -> None:
        claims = decode_access_token(self.token, self.secret)
        token_hash = hashlib.sha256(self.token.encode("utf-8")).hexdigest()
        with self.app.state.session_factory() as db:
            db.add(
                RevokedAccessToken(
                    token_hash="f" * 64,
                    tenant_id="tenant-logout-token-race",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    expires_at=utc_now() - timedelta(minutes=1),
                    reason="expired-test-row",
                )
            )
            db.commit()

        response = self.request(
            "POST",
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(self.token, response.text)
        self.assertNotIn(claims["jti"], response.text)
        self.assertNotIn(token_hash, response.text)
        with self.app.state.session_factory() as db:
            rows = list(db.scalars(select(RevokedAccessToken)))
            audit_json = " ".join(db.scalars(select(AuditEvent.details_json)))
        self.assertEqual([row.token_hash for row in rows], [token_hash])
        self.assertNotIn(self.token, audit_json)
        self.assertNotIn(claims["jti"], audit_json)
        self.assertNotIn(token_hash, audit_json)

    def test_oidc_logout_revokes_normal_use_but_allows_safe_replay(self) -> None:
        oidc_token = "signed-oidc-access-token-without-secret-material"
        oidc_jti = "oidc-logout-token-identifier-0001"
        oidc_app = create_app(
            Settings(
                environment="test",
                auth_mode="oidc",
                database_url="sqlite+pysqlite:///:memory:",
                oidc_issuer_url="https://identity.example.test/realms/platform",
                oidc_audience="email-platform-api",
                oidc_client_id="email-platform-web",
                oidc_desktop_client_id="email-platform-desktop",
                oidc_jwks_url="https://identity.example.test/jwks",
            ),
            access_token_verifier=object(),
        )
        try:
            identity = create_oidc_user_with_device(
                oidc_app.state.session_factory,
                tenant_id="tenant-oidc-logout",
                email="oidc-logout@example.test",
                oidc_subject="oidc-logout-subject",
                device_name="oidc-logout-device",
            )

            class FakeOidcVerifier:
                @staticmethod
                def verify(token: str) -> dict[str, object]:
                    if token != oidc_token:
                        raise ValueError("invalid")
                    return {
                        "sub": "oidc-logout-subject",
                        "tenant_id": "tenant-oidc-logout",
                        "device_id": identity.device_id,
                        "identity_kind": "oidc",
                        "jti": oidc_jti,
                        "exp": int((utc_now() + timedelta(minutes=5)).timestamp()),
                    }

            oidc_app.state.access_token_verifier = FakeOidcVerifier()

            async def oidc_request(method: str, path: str) -> httpx.Response:
                transport = httpx.ASGITransport(app=oidc_app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as client:
                    return await client.request(
                        method,
                        path,
                        headers={"Authorization": f"Bearer {oidc_token}"},
                    )

            first = asyncio.run(oidc_request("POST", "/api/v1/auth/logout"))
            denied = asyncio.run(oidc_request("GET", "/api/v1/me"))
            replay = asyncio.run(oidc_request("POST", "/api/v1/auth/logout"))
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(denied.status_code, 401, denied.text)
            self.assertEqual(replay.status_code, 200, replay.text)
            with oidc_app.state.session_factory() as db:
                self.assertEqual(
                    db.scalar(
                        select(func.count())
                        .select_from(AuditEvent)
                        .where(AuditEvent.event_type == "auth.logout")
                    ),
                    1,
                )
        finally:
            oidc_app.state.engine.dispose()


if __name__ == "__main__":
    unittest.main()
