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
from platform.bootstrap import create_oidc_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Device,
    RevokedAccessToken,
    RevokedOidcSession,
    Task,
    utc_now,
)


class MappingOidcVerifier:
    def __init__(self) -> None:
        self.claims_by_token: dict[str, dict[str, object]] = {}

    def verify(self, token: str) -> dict[str, object]:
        try:
            return dict(self.claims_by_token[token])
        except KeyError as error:
            raise ValueError("invalid") from error


class OidcSessionRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="oidc-session-revoke-")
        database = Path(self.directory.name) / "platform.db"
        self.issuer = "https://identity.example.test/realms/email-platform"
        self.app = create_app(
            Settings(
                environment="test",
                auth_mode="oidc",
                database_url=f"sqlite+pysqlite:///{database.as_posix()}",
                oidc_issuer_url=self.issuer,
                oidc_audience="email-platform-api",
                oidc_client_id="email-platform-web",
                oidc_desktop_client_id="email-platform-desktop",
                oidc_jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
            ),
            access_token_verifier=object(),
        )
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        self.identity = create_oidc_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-oidc-session",
            email="oidc-session@example.test",
            oidc_subject="oidc-session-subject",
            device_name="oidc-session-device-a",
        )
        with self.app.state.session_factory() as db:
            device_b = Device(
                tenant_id="tenant-oidc-session",
                user_id=self.identity.user_id,
                name="oidc-session-device-b",
            )
            db.add(device_b)
            db.commit()
            self.device_b_id = device_b.id
        self.verifier = MappingOidcVerifier()
        self.app.state.access_token_verifier = self.verifier

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.directory.cleanup()

    def add_token(
        self,
        token: str,
        *,
        sid: object = None,
        device_id: str | None = None,
        subject: str = "oidc-session-subject",
    ) -> None:
        claims: dict[str, object] = {
            "sub": subject,
            "iss": self.issuer,
            "tenant_id": "tenant-oidc-session",
            "device_id": device_id or self.identity.device_id,
            "identity_kind": "oidc",
            "jti": f"jti-{token}-0123456789abcdef",
            "exp": int((utc_now() + timedelta(minutes=5)).timestamp()),
        }
        if sid is not None:
            claims["sid"] = sid
        self.verifier.claims_by_token[token] = claims

    def request(self, method: str, path: str, *, token: str) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                )

        return asyncio.run(run())

    def test_logout_revokes_every_access_token_with_same_issuer_and_sid(self) -> None:
        raw_sid = "raw-session-id-must-not-persist"
        self.add_token("access-a", sid=raw_sid)
        self.add_token("access-b", sid=raw_sid)
        with self.app.state.session_factory() as db:
            db.add(
                Task(
                    tenant_id="tenant-oidc-session",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    task_type="mail_code",
                    idempotency_key="sequential-session-task",
                    trace_id="sequential-session-trace",
                    status="created",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            db.commit()

        initial_a = self.request("GET", "/api/v1/me", token="access-a")
        initial_b = self.request("GET", "/api/v1/me", token="access-b")
        self.assertEqual(initial_a.status_code, 200)
        self.assertEqual(initial_b.status_code, 200)
        with self.app.state.session_factory() as db:
            last_seen_before_logout = db.get(Device, self.identity.device_id).last_seen_at
        self.assertIsNotNone(last_seen_before_logout)

        first_logout = self.request(
            "POST", "/api/v1/auth/logout", token="access-a"
        )
        sibling_rejected = self.request("GET", "/api/v1/me", token="access-b")
        sibling_logout = self.request(
            "POST", "/api/v1/auth/logout", token="access-b"
        )
        replay_logout = self.request(
            "POST", "/api/v1/auth/logout", token="access-a"
        )
        self.assertEqual(first_logout.status_code, 200)
        self.assertEqual(sibling_rejected.status_code, 401)
        self.assertEqual(sibling_logout.status_code, 200)
        self.assertEqual(replay_logout.status_code, 200)

        with self.app.state.session_factory() as db:
            sessions = list(db.scalars(select(RevokedOidcSession)))
            tokens = list(db.scalars(select(RevokedAccessToken)))
            audits = list(db.scalars(select(AuditEvent)))
            last_seen_after_replays = db.get(
                Device, self.identity.device_id
            ).last_seen_at
        self.assertEqual(len(sessions), 1)
        expected_session_hash = hashlib.sha256(
            b"email-platform|oidc-session-v1\0"
            + self.issuer.encode("utf-8")
            + b"\0"
            + raw_sid.encode("utf-8")
        ).hexdigest()
        self.assertEqual(sessions[0].session_hash, expected_session_hash)
        self.assertIsNone(sessions[0].expires_at)
        self.assertEqual(len(tokens), 2)
        self.assertTrue(all(len(token.token_hash) == 64 for token in tokens))
        self.assertEqual(last_seen_after_replays, last_seen_before_logout)
        self.assertEqual(
            sum(audit.event_type == "auth.logout" for audit in audits), 1
        )
        self.assertEqual(
            sum(audit.event_type == "task.cancelled" for audit in audits), 1
        )
        response_text = " ".join(
            response.text
            for response in (
                initial_a,
                initial_b,
                first_logout,
                sibling_rejected,
                sibling_logout,
                replay_logout,
            )
        )
        audit_text = " ".join(
            str(getattr(audit, column.name))
            for audit in audits
            for column in AuditEvent.__table__.columns
        )
        revocation_text = " ".join(
            str(getattr(row, column.name))
            for row in (*sessions, *tokens)
            for column in row.__table__.columns
        )
        self.assertNotIn(raw_sid, response_text)
        self.assertNotIn(raw_sid, audit_text)
        self.assertNotIn(raw_sid, revocation_text)

    def test_different_sid_and_legacy_token_only_sessions_remain_compatible(self) -> None:
        self.add_token("sid-a", sid="session-a")
        self.add_token("sid-b", sid="session-b")
        self.assertEqual(
            self.request("POST", "/api/v1/auth/logout", token="sid-a").status_code,
            200,
        )
        self.assertEqual(self.request("GET", "/api/v1/me", token="sid-b").status_code, 200)

        self.add_token("legacy-a")
        self.add_token("legacy-b")
        self.assertEqual(
            self.request("POST", "/api/v1/auth/logout", token="legacy-a").status_code,
            200,
        )
        self.assertEqual(self.request("GET", "/api/v1/me", token="legacy-b").status_code, 200)

    def test_revoked_sid_cannot_move_to_another_device(self) -> None:
        raw_sid = "session-bound-before-device-claim-change"
        self.add_token("device-a-token", sid=raw_sid)
        self.add_token(
            "device-b-token",
            sid=raw_sid,
            device_id=self.device_b_id,
        )
        self.assertEqual(
            self.request("POST", "/api/v1/auth/logout", token="device-a-token").status_code,
            200,
        )
        self.assertEqual(
            self.request("GET", "/api/v1/me", token="device-b-token").status_code,
            401,
        )

    def test_malformed_present_sid_fails_closed_without_side_effects(self) -> None:
        for index, sid in enumerate(("", " spaced", "line\nbreak", 42, [], "x" * 256)):
            token = f"malformed-{index}"
            self.add_token(token, sid=sid)
            with self.subTest(sid=repr(sid)):
                self.assertEqual(
                    self.request("GET", "/api/v1/me", token=token).status_code,
                    401,
                )
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RevokedOidcSession)), 0
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RevokedAccessToken)), 0
            )

    def test_concurrent_different_tokens_same_sid_cleanup_exactly_once(self) -> None:
        sid = "concurrent-oidc-session"
        self.add_token("concurrent-a", sid=sid)
        self.add_token("concurrent-b", sid=sid)
        with self.app.state.session_factory() as db:
            db.add(
                Task(
                    tenant_id="tenant-oidc-session",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    task_type="mail_code",
                    idempotency_key="concurrent-session-task",
                    trace_id="concurrent-session-trace",
                    status="created",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            db.commit()

        both_authenticated = Barrier(2, timeout=5)
        original = routes._revoke_access_token

        def synchronized_claim(*args, **kwargs):
            both_authenticated.wait()
            return original(*args, **kwargs)

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
                        token=token,
                    )
                    for token in ("concurrent-a", "concurrent-b")
                ]
                responses = [future.result(timeout=10) for future in futures]

        self.assertEqual([response.status_code for response in responses], [200, 200])
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RevokedOidcSession)), 1
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(RevokedAccessToken)), 2
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


if __name__ == "__main__":
    unittest.main()
