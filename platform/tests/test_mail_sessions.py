import asyncio
import hashlib
import unittest
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.mail_connectors import MailCodeMessage, MailboxAccess
from platform.mail_worker import process_mail_session
from platform.models import AuditEvent, MailSession, Mailbox, Task, utc_now


class FakeMailConnector:
    def __init__(self) -> None:
        self.messages: list[MailCodeMessage] = []
        self.watermark_calls = 0
        self.find_calls = 0

    def current_watermark(self, mailbox: MailboxAccess) -> str | None:
        self.watermark_calls += 1
        return self.messages[-1].watermark if self.messages else None

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        self.find_calls += 1
        baseline = int(watermark or "0")
        for message in self.messages:
            if int(message.watermark) > baseline:
                return message
        return None


class MailSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connector = FakeMailConnector()
        self.app = create_app(
            Settings(
                app_name="mail-test-platform",
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="mail-test-hmac-secret-that-is-not-production",
                mail_session_ttl_seconds=300,
            ),
            mail_connectors={"fake": self.connector},
        )
        self.password = "mail-test-account-password"
        self.session_tokens: dict[str, str] = {}
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="mail-owner@example.test",
            password=self.password,
            device_name="mail-device",
        )
        with self.app.state.session_factory() as db:
            db.add(
                Mailbox(
                    tenant_id="tenant-mail",
                    email_masked="m***@example.test",
                    connector_type="fake",
                    secret_ref="vault://mailboxes/mail-owner",
                )
            )
            db.commit()

    def tearDown(self) -> None:
        self.app.state.engine.dispose()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def login(self, identity=None, *, email=None, password=None) -> str:
        identity = identity or self.identity
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-mail",
                "email": email or "mail-owner@example.test",
                "password": password or self.password,
                "device_id": identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def create_task(self, token: str, key: str = "mail-task-1") -> str:
        response = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": key},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def create_session(self, token: str, task_id: str) -> httpx.Response:
        response = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/mail-sessions",
            headers=self.bearer(token),
        )
        if response.status_code in {200, 201}:
            payload = response.json()
            self.session_tokens[payload["id"]] = payload["session_token"]
        return response

    def mail_headers(self, access_token: str, session_id: str) -> dict[str, str]:
        headers = self.bearer(access_token)
        headers["X-Mail-Session-Token"] = self.session_tokens[session_id]
        return headers

    def test_session_response_never_exposes_mailbox_secret(self) -> None:
        token = self.login()
        task_id = self.create_task(token)
        response = self.create_session(token, task_id)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(
            set(response.json()),
            {
                "id",
                "trace_id",
                "email_masked",
                "status",
                "expires_at",
                "session_token",
            },
        )
        session_token = response.json()["session_token"]
        self.assertGreaterEqual(len(session_token), 32)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, response.json()["id"])
            self.assertEqual(
                persisted.session_token_hash,
                hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
            )
            self.assertNotEqual(persisted.session_token_hash, session_token)
        task = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(token)
        )
        self.assertEqual(response.json()["trace_id"], task.json()["trace_id"])
        for forbidden in ("secret_ref", "password", "body", "credential"):
            self.assertNotIn(forbidden, response.text.lower())

    def test_old_watermark_is_ignored_and_code_is_one_time(self) -> None:
        self.connector.messages.append(
            MailCodeMessage(message_id="old", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        self.assertEqual(session.status_code, 201)
        session_id = session.json()["id"]

        waiting = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(waiting.status_code, 200)
        self.assertEqual(waiting.headers["Cache-Control"], "no-store")
        self.assertEqual(waiting.headers["Pragma"], "no-cache")
        self.assertEqual(waiting.json(), {"status": "waiting", "code": None})

        self.connector.messages.append(
            MailCodeMessage(message_id="new", watermark="2", code="222222")
        )
        consumed = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(consumed.json(), {"status": "consumed", "code": "222222"})
        consumed_again = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(
            consumed_again.json(), {"status": "consumed", "code": None}
        )

    def test_worker_mode_delivers_code_without_api_polling_connector(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        self.connector.messages.append(
            MailCodeMessage(message_id="old", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        self.assertEqual(session.status_code, 201, session.text)
        self.assertEqual(session.json()["status"], "initializing")
        self.assertEqual(self.connector.watermark_calls, 0)
        self.assertEqual(self.connector.find_calls, 0)
        session_id = session.json()["id"]

        initialized = process_mail_session(
            self.app.state.session_factory,
            session_id,
            connectors={"fake": self.connector},
        )
        self.assertEqual(initialized, "initialized")

        waiting = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(waiting.status_code, 200, waiting.text)
        self.assertEqual(waiting.json(), {"status": "waiting", "code": None})
        self.assertEqual(self.connector.find_calls, 0)

        self.connector.messages.append(
            MailCodeMessage(message_id="new", watermark="2", code="222222")
        )
        delivered = process_mail_session(
            self.app.state.session_factory,
            session_id,
            connectors={"fake": self.connector},
        )
        self.assertEqual(delivered, "code_ready")
        self.assertEqual(self.connector.find_calls, 1)

        consumed = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(consumed.json(), {"status": "consumed", "code": "222222"})
        consumed_again = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(consumed_again.json(), {"status": "consumed", "code": None})
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertIsNotNone(persisted)
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.code_expires_at)

    def test_worker_expired_code_is_erased_and_newer_code_can_arrive(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        self.connector.messages.append(
            MailCodeMessage(message_id="old", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token, "mail-code-ttl")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "initialized",
        )
        self.connector.messages.append(
            MailCodeMessage(message_id="first", watermark="2", code="222222")
        )
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "code_ready",
        )
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.delivered_code, "222222")
            persisted.code_expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "code_expired",
        )
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.code_expires_at)
            self.assertEqual(persisted.status, "waiting")
        self.connector.messages.append(
            MailCodeMessage(message_id="second", watermark="3", code="333333")
        )
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "code_ready",
        )

    def test_database_rejects_two_active_leases_for_one_mailbox(self) -> None:
        token = self.login()
        first_task_id = self.create_task(token, "mail-lease-first")
        first = self.create_session(token, first_task_id)
        self.assertEqual(first.status_code, 201, first.text)
        second_task_id = self.create_task(token, "mail-lease-second")
        unavailable = self.create_session(token, second_task_id)
        self.assertEqual(unavailable.status_code, 503, unavailable.text)

        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            second_task = db.get(Task, second_task_id)
            db.add(
                MailSession(
                    tenant_id="tenant-mail",
                    task_id=second_task_id,
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    mailbox_id=mailbox.id,
                    trace_id=second_task.trace_id,
                    session_token_hash=hashlib.sha256(b"unissued").hexdigest(),
                    status="waiting",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()

    def test_cross_user_cannot_read_session(self) -> None:
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        other_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="other-mail-owner@example.test",
            password="other-mail-account-password",
            device_name="other-mail-device",
        )
        other_token = self.login(
            other_identity,
            email="other-mail-owner@example.test",
            password="other-mail-account-password",
        )
        response = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(other_token, session_id),
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_session_token_is_required_rotated_and_never_audited(self) -> None:
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-token-binding")
        created = self.create_session(access_token, task_id)
        session_id = created.json()["id"]
        first_token = created.json()["session_token"]

        missing = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.bearer(access_token),
        )
        self.assertEqual(missing.status_code, 404, missing.text)
        wrong_headers = self.bearer(access_token)
        wrong_headers["X-Mail-Session-Token"] = "x" * 43
        wrong = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=wrong_headers,
        )
        self.assertEqual(wrong.status_code, 404, wrong.text)
        token_without_bearer = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers={"X-Mail-Session-Token": first_token},
        )
        self.assertEqual(token_without_bearer.status_code, 401, token_without_bearer.text)

        rotated = self.create_session(access_token, task_id)
        self.assertEqual(rotated.status_code, 200, rotated.text)
        second_token = rotated.json()["session_token"]
        self.assertNotEqual(second_token, first_token)
        old_headers = self.bearer(access_token)
        old_headers["X-Mail-Session-Token"] = first_token
        old_token = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=old_headers,
        )
        self.assertEqual(old_token.status_code, 404, old_token.text)
        current = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(access_token, session_id),
        )
        self.assertEqual(current.status_code, 200, current.text)

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(
                persisted.session_token_hash,
                hashlib.sha256(second_token.encode("utf-8")).hexdigest(),
            )
            audit_text = "\n".join(
                event.details_json for event in db.scalars(select(AuditEvent))
            )
        self.assertNotIn(first_token, audit_text)
        self.assertNotIn(second_token, audit_text)

    def test_sse_requires_bearer_and_session_token(self) -> None:
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-sse-token")
        session = self.create_session(access_token, task_id)
        session_id = session.json()["id"]

        missing = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/events",
            headers=self.bearer(access_token),
        )
        self.assertEqual(missing.status_code, 404, missing.text)
        self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/close",
            headers=self.bearer(access_token),
        )
        stream = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/events",
            headers=self.mail_headers(access_token, session_id),
        )
        self.assertEqual(stream.status_code, 200, stream.text)
        self.assertIn("event: revoked", stream.text)

    def test_expired_session_has_explicit_status(self) -> None:
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertIsNotNone(persisted)
            persisted.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        response = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(response.json(), {"status": "expired", "code": None})

    def test_unconfigured_connector_returns_503(self) -> None:
        self.app.state.mail_connectors = {}
        token = self.login()
        task_id = self.create_task(token)
        response = self.create_session(token, task_id)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "service_unavailable")
        self.assertIn("not configured", response.json()["error"]["message"])

    def test_mail_audit_does_not_store_code_or_secret(self) -> None:
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        session_token = session.json()["session_token"]
        self.connector.messages.append(
            MailCodeMessage(message_id="new", watermark="1", code="987654")
        )
        self.request(
            "GET",
            f"/api/v1/mail-sessions/{session.json()['id']}/code",
            headers=self.mail_headers(token, session.json()["id"]),
        )
        with self.app.state.session_factory() as db:
            events = list(db.scalars(select(AuditEvent)))
        event_text = "\n".join(
            f"{event.event_type} {event.details_json}" for event in events
        )
        for forbidden in (
            "987654",
            session_token,
            "vault://mailboxes/mail-owner",
            "secret_ref",
            "body",
        ):
            self.assertNotIn(forbidden, event_text)

    def test_closed_task_revokes_mail_session_and_blocks_recreation(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        self.assertEqual(session.status_code, 201, session.text)

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")
        code = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session.json()['id']}/code",
            headers=self.mail_headers(token, session.json()["id"]),
        )
        self.assertEqual(code.json(), {"status": "revoked", "code": None})
        blocked = self.create_session(token, task_id)
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "conflict")

    def test_owner_can_revoke_waiting_mail_session(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        revoked = self.request(
            "POST",
            f"/api/v1/mail-sessions/{session_id}/revoke",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "revoked")
        code = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(code.json(), {"status": "revoked", "code": None})
        replay = self.request(
            "POST",
            f"/api/v1/mail-sessions/{session_id}/revoke",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        with self.app.state.session_factory() as db:
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "mail_session.revoked"
                    )
                )
            )
        self.assertEqual(len(events), 1)

    def test_mail_openapi_schemas_do_not_expose_internal_mail_fields(self) -> None:
        schema = self.app.openapi()
        for name in ("MailSessionResponse", "MailCodeResponse"):
            properties = schema["components"]["schemas"][name]["properties"]
            for forbidden in (
                "session_token",
                "session_token_hash",
                "secret_ref",
                "password",
                "body",
                "credential",
            ):
                self.assertNotIn(forbidden, properties)
        create_properties = schema["components"]["schemas"][
            "MailSessionCreateResponse"
        ]["properties"]
        self.assertIn("session_token", create_properties)
        self.assertNotIn("session_token_hash", create_properties)
        self.assertIn("/api/v1/tasks/{task_id}/mail-sessions", schema["paths"])
        self.assertIn("/api/v1/mail-sessions/{session_id}/code", schema["paths"])


if __name__ == "__main__":
    unittest.main()
