import asyncio
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock, get_ident
from unittest.mock import patch

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from platform import mail_worker
from platform.app import create_app
from platform.api.v1 import routes
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.database import initialize_database
from platform.lifecycle import sweep_expired_lifecycle
from platform.mail_consumption import claim_connector_message, claim_delivered_code
from platform.mail_connectors import MailCodeMessage, MailboxAccess, MailConnectorUnavailable
from platform.mail_worker import process_mail_session, process_mail_sessions
from platform.models import (
    AuditEvent,
    Device,
    MailSession,
    Mailbox,
    OperationalPolicyDeployment,
    OperationalPolicyVersion,
    Task,
    utc_now,
)
from platform.schemas import MailCodeResponse


MESSAGE_ID_HASH_DOMAIN = b"email-platform:mail-message-id:v1\0"


class FakeMailConnector:
    def __init__(self) -> None:
        self.messages: list[MailCodeMessage] = []
        self.watermark_calls = 0
        self.watermark_boundaries: list[datetime] = []
        self.find_calls = 0
        self.failure_message: str | None = None
        self.unexpected_failures: list[BaseException] = []

    def _raise_if_needed(self) -> None:
        if self.unexpected_failures:
            raise self.unexpected_failures.pop(0)
        if self.failure_message:
            raise MailConnectorUnavailable(self.failure_message)

    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str | None:
        self.watermark_calls += 1
        self.watermark_boundaries.append(task_started_at)
        self._raise_if_needed()
        return self.messages[-1].watermark if self.messages else "0"

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        self.find_calls += 1
        self._raise_if_needed()
        baseline = int(watermark or "0")
        for message in self.messages:
            if int(message.watermark) > baseline:
                return (
                    message
                    if message.received_at is not None
                    else replace(message, received_at=utc_now())
                )
        return None


class BlockingMailConnector:
    def __init__(
        self,
        *,
        block_watermark: bool = False,
        expected_find_calls: int = 1,
        fail_after_release: bool = False,
    ) -> None:
        self.block_watermark = block_watermark
        self.expected_find_calls = expected_find_calls
        self.fail_after_release = fail_after_release
        self.entered = Event()
        self.release = Event()
        self._find_calls = 0
        self._lock = Lock()
        self.lookup_thread_id: int | None = None

    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str:
        if self.block_watermark:
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("watermark test release timed out")
            if self.fail_after_release:
                raise MailConnectorUnavailable("stale secret failed")
        return "1"

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage:
        self.lookup_thread_id = get_ident()
        with self._lock:
            self._find_calls += 1
            if self._find_calls == self.expected_find_calls:
                self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("mail lookup test release timed out")
        if self.fail_after_release:
            raise MailConnectorUnavailable("stale secret failed")
        return MailCodeMessage(
            message_id="new",
            watermark="2",
            code="246810",
            received_at=utc_now(),
        )


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
        self.admin_password = "mail-admin-account-password"
        self.admin_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="mail-admin@example.test",
            password=self.admin_password,
            device_name="mail-admin-device",
            role="ops_admin",
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

    def seed_terminal_code_ready_residue(
        self,
        *,
        task_id: str,
        session_id: str,
        task_status: str,
        code: str,
    ) -> None:
        now = utc_now()
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            session = db.get(MailSession, session_id)
            task.status = task_status
            task.closed_at = now
            session.status = "code_ready"
            session.delivered_code = code
            session.delivered_message_id_hash = hashlib.sha256(
                MESSAGE_ID_HASH_DOMAIN + f"terminal-{task_status}".encode("utf-8")
            ).hexdigest()
            session.delivered_at = now
            session.code_expires_at = now + timedelta(minutes=1)
            db.commit()

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
                "polling_interval",
            },
        )
        self.assertEqual(response.json()["polling_interval"], 5)
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

    def test_task_type_selects_only_its_server_managed_mailbox_pool(self) -> None:
        with self.app.state.session_factory() as db:
            specialized = Mailbox(
                tenant_id="tenant-mail",
                email_masked="r***@example.test",
                connector_type="fake",
                secret_ref="vault://mailboxes/password-reset",
            )
            specialized.task_type = "password_reset"
            db.add(specialized)
            db.commit()
        token = self.login()
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "password_reset",
                "idempotency_key": "password-reset-route",
            },
        )
        self.assertEqual(task.status_code, 201, task.text)

        created = self.create_session(token, task.json()["id"])

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["email_masked"], "r***@example.test")
        with self.app.state.session_factory() as db:
            session = db.get(MailSession, created.json()["id"])
            mailbox = db.get(Mailbox, session.mailbox_id)
            self.assertEqual(mailbox.task_type, "password_reset")
            self.assertEqual(mailbox.connector_type, "fake")

    def test_mail_session_without_matching_task_type_fails_closed(self) -> None:
        with self.app.state.session_factory() as db:
            db.add(
                Mailbox(
                    tenant_id="tenant-mail-other",
                    email_masked="x***@example.test",
                    connector_type="fake",
                    task_type="password_reset",
                    secret_ref="vault://mailboxes/foreign-password-reset",
                )
            )
            db.commit()
        token = self.login()
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "password_reset",
                "idempotency_key": "missing-mail-route",
            },
        )
        self.assertEqual(task.status_code, 201, task.text)

        denied = self.create_session(token, task.json()["id"])

        self.assertEqual(denied.status_code, 503, denied.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(select(MailSession).where(MailSession.task_id == task.json()["id"]))
            )

    def test_worker_never_dereferences_mailbox_after_tenant_relation_changes(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "mailbox-tenant-relation-barrier")
        created = self.create_session(token, task_id)
        self.assertEqual(created.status_code, 201, created.text)

        with self.app.state.session_factory() as db:
            session = db.get(MailSession, created.json()["id"])
            self.assertIsNotNone(session)
            mailbox = db.get(Mailbox, session.mailbox_id)
            self.assertIsNotNone(mailbox)
            mailbox.tenant_id = "tenant-mail-foreign"
            mailbox.secret_ref = "vault://mailboxes/foreign-tenant-secret"
            db.commit()

        result = process_mail_session(
            self.app.state.session_factory,
            created.json()["id"],
            connectors=self.app.state.mail_connectors,
        )

        self.assertEqual(result, "mailbox_unavailable")
        self.assertEqual(self.connector.watermark_calls, 0)
        self.assertEqual(self.connector.find_calls, 0)

    def test_api_never_dereferences_mailbox_after_tenant_relation_changes(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "api-mailbox-tenant-relation-barrier")
        created = self.create_session(token, task_id)
        self.assertEqual(created.status_code, 201, created.text)
        find_calls_before = self.connector.find_calls

        with self.app.state.session_factory() as db:
            session = db.get(MailSession, created.json()["id"])
            self.assertIsNotNone(session)
            mailbox = db.get(Mailbox, session.mailbox_id)
            self.assertIsNotNone(mailbox)
            mailbox.tenant_id = "tenant-mail-foreign"
            mailbox.secret_ref = "vault://mailboxes/foreign-tenant-api-secret"
            db.commit()
        self.connector.messages.append(
            MailCodeMessage(
                message_id="foreign-mailbox-relation",
                watermark="1",
                code="918273",
            )
        )

        response = self.request(
            "GET",
            f"/api/v1/mail-sessions/{created.json()['id']}/code",
            headers=self.mail_headers(token, created.json()["id"]),
        )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(self.connector.find_calls, find_calls_before)
        self.assertNotIn("918273", response.text)
        self.assertNotIn("foreign-tenant-api-secret", response.text)

    def test_mail_session_rejects_client_connector_or_pool_override(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "mail-route-override")

        denied = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/mail-sessions",
            headers=self.bearer(token),
            json={"connector_type": "fake", "pool_name": "default"},
        )

        self.assertEqual(denied.status_code, 422, denied.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(select(MailSession).where(MailSession.task_id == task_id))
            )

    def test_cross_device_cannot_create_mail_session_for_task(self) -> None:
        owner_token = self.login()
        task_id = self.create_task(owner_token, "cross-device-mail-route")
        with self.app.state.session_factory() as db:
            second_device = Device(
                tenant_id="tenant-mail",
                user_id=self.identity.user_id,
                name="mail-second-device",
            )
            db.add(second_device)
            db.commit()
            second_device_id = second_device.id
        second_token = self.login(
            type("Identity", (), {"device_id": second_device_id})()
        )

        denied = self.create_session(second_token, task_id)

        self.assertEqual(denied.status_code, 404, denied.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(select(MailSession).where(MailSession.task_id == task_id))
            )

    def test_session_token_hash_is_unique_and_rotation_collision_fails_closed(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "mail-token-collision")
        created = self.create_session(token, task_id)
        self.assertEqual(created.status_code, 201, created.text)
        session_id = created.json()["id"]
        raw_session_token = created.json()["session_token"]
        token_hash = hashlib.sha256(raw_session_token.encode("utf-8")).hexdigest()

        with patch(
            "platform.api.v1.routes._new_mail_session_token",
            return_value=(raw_session_token, token_hash),
        ):
            collision = self.request(
                "POST",
                f"/api/v1/tasks/{task_id}/mail-sessions",
                headers=self.bearer(token),
            )

        self.assertEqual(collision.status_code, 503, collision.text)
        self.assertEqual(
            collision.json()["error"]["code"],
            "mail_session_token_unavailable",
        )
        self.assertNotIn(raw_session_token, collision.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.session_token_hash, token_hash)
            created_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "mail_session.created",
                        AuditEvent.entity_id == session_id,
                    )
                )
            )
            self.assertEqual(len(created_events), 1)

            duplicate_task = Task(
                tenant_id=persisted.tenant_id,
                user_id=persisted.user_id,
                device_id=persisted.device_id,
                task_type="mail_code",
                idempotency_key="duplicate-token-task",
                trace_id="duplicate-token-trace",
                status="created",
                expires_at=utc_now() + timedelta(minutes=5),
            )
            duplicate_mailbox = Mailbox(
                tenant_id=persisted.tenant_id,
                email_masked="d***@example.test",
                connector_type="fake",
                secret_ref="vault://secret/mailboxes/duplicate-token",
            )
            db.add_all([duplicate_task, duplicate_mailbox])
            db.flush()
            duplicate = MailSession(
                tenant_id=persisted.tenant_id,
                task_id=duplicate_task.id,
                user_id=persisted.user_id,
                device_id=persisted.device_id,
                mailbox_id=duplicate_mailbox.id,
                trace_id="duplicate-token-trace",
                session_token_hash=token_hash,
                status="waiting",
                expires_at=utc_now() + timedelta(minutes=5),
            )
            db.add(duplicate)
            with self.assertRaises(IntegrityError):
                db.flush()

    def test_old_watermark_is_ignored_and_code_is_one_time(self) -> None:
        self.connector.messages.append(
            MailCodeMessage(message_id="old", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token)
        with self.app.state.session_factory() as db:
            task_started_at = db.get(Task, task_id).created_at
        session = self.create_session(token, task_id)
        self.assertEqual(session.status_code, 201)
        self.assertEqual(self.connector.watermark_boundaries, [task_started_at])
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
            MailCodeMessage(
                message_id="new",
                watermark="2",
                code="222222",
                received_at=(provider_received_at := utc_now()),
            )
        )
        consumed = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        consumed_body = consumed.json()
        self.assertEqual(consumed_body["status"], "consumed")
        self.assertEqual(consumed_body["code"], "222222")
        self.assertEqual(
            consumed_body["message_id_hash"],
            hashlib.sha256(MESSAGE_ID_HASH_DOMAIN + b"new").hexdigest(),
        )
        self.assertEqual(
            datetime.fromisoformat(consumed_body["received_at"]),
            provider_received_at,
        )
        consumed_again = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(
            consumed_again.json(), {"status": "consumed", "code": None}
        )

    def test_provider_timestamp_before_task_start_fails_closed(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "pre-task-provider-timestamp")
        with self.app.state.session_factory() as db:
            task_started_at = db.get(Task, task_id).created_at.replace(
                tzinfo=timezone.utc
            )
        session = self.create_session(token, task_id)
        self.connector.messages.append(
            MailCodeMessage(
                message_id="pre-task",
                watermark="1",
                code="123456",
                received_at=task_started_at - timedelta(microseconds=1),
            )
        )

        response = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session.json()['id']}/code",
            headers=self.mail_headers(token, session.json()["id"]),
        )

        self.assertEqual(response.status_code, 503, response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session.json()["id"])
            mailbox = db.get(Mailbox, persisted.mailbox_id)
            self.assertEqual(persisted.status, "waiting")
            self.assertEqual(mailbox.health_status, "unavailable")

    def test_missing_initial_cursor_fails_closed_in_api_and_worker_modes(self) -> None:
        def missing_watermark(
            mailbox: MailboxAccess, task_started_at: datetime
        ) -> None:
            return None

        self.connector.watermark_at = missing_watermark  # type: ignore[method-assign]
        token = self.login()
        api_task_id = self.create_task(token, "missing-api-watermark")

        api_response = self.create_session(token, api_task_id)

        self.assertEqual(api_response.status_code, 503, api_response.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(select(MailSession).where(MailSession.task_id == api_task_id))
            )
            db.get(Task, api_task_id).status = "completed"
            db.commit()

        self.app.state.settings.mail_poll_mode = "worker"
        worker_task_id = self.create_task(token, "missing-worker-watermark")
        worker_session = self.create_session(token, worker_task_id)
        result = process_mail_session(
            self.app.state.session_factory,
            worker_session.json()["id"],
            connectors={"fake": self.connector},
        )

        self.assertEqual(result, "connector_unavailable")
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, worker_session.json()["id"])
            self.assertEqual(persisted.status, "initializing")
            self.assertIsNone(persisted.start_watermark)

    def test_message_between_task_start_and_session_creation_is_delivered(self) -> None:
        self.connector.messages.append(
            MailCodeMessage(message_id="before-task", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token, "task-session-gap")
        with self.app.state.session_factory() as db:
            task_started_at = db.get(Task, task_id).created_at
        self.connector.messages.append(
            MailCodeMessage(message_id="during-gap", watermark="2", code="222222")
        )

        def watermark_at_task_start(
            mailbox: MailboxAccess, received_at_or_before: datetime
        ) -> str:
            self.connector.watermark_calls += 1
            self.connector.watermark_boundaries.append(received_at_or_before)
            return "1"

        self.connector.watermark_at = watermark_at_task_start  # type: ignore[method-assign]
        session = self.create_session(token, task_id)

        self.assertEqual(session.status_code, 201, session.text)
        self.assertEqual(self.connector.watermark_boundaries, [task_started_at])
        consumed = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session.json()['id']}/code",
            headers=self.mail_headers(token, session.json()["id"]),
        )
        self.assertEqual(consumed.status_code, 200, consumed.text)
        self.assertEqual(consumed.json()["status"], "consumed")
        self.assertEqual(consumed.json()["code"], "222222")

    def test_api_poll_with_code_crossing_session_ttl_expires_without_code(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "api-code-ttl-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        before_deadline = utc_now()
        after_deadline = before_deadline + timedelta(minutes=2)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.expires_at = before_deadline + timedelta(minutes=1)
            db.commit()
        self.connector.messages.append(
            MailCodeMessage(message_id="late", watermark="1", code="975310")
        )

        with patch(
            "platform.api.v1.routes._utc_now",
            side_effect=[before_deadline, after_deadline],
        ):
            response = self.request(
                "GET",
                f"/api/v1/mail-sessions/{session_id}/code",
                headers=self.mail_headers(token, session_id),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"status": "expired", "code": None})
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "expired")
            self.assertIsNone(persisted.consumed_at)
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.code_expires_at)
            consumed_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.code_consumed",
                    )
                )
            )
            self.assertEqual(consumed_events, [])

    def test_api_poll_without_code_crossing_session_ttl_expires(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "api-empty-ttl-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        before_deadline = utc_now()
        after_deadline = before_deadline + timedelta(minutes=2)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.expires_at = before_deadline + timedelta(minutes=1)
            db.commit()

        with patch(
            "platform.api.v1.routes._utc_now",
            side_effect=[before_deadline, after_deadline],
        ):
            response = self.request(
                "GET",
                f"/api/v1/mail-sessions/{session_id}/code",
                headers=self.mail_headers(token, session_id),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"status": "expired", "code": None})
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "expired")
            self.assertIsNone(persisted.consumed_at)

    def test_api_poll_returns_revoked_if_session_is_revoked_during_lookup(self) -> None:
        token = self.login()

        for action in ("revoke", "logout"):
            with self.subTest(action=action):
                task_id = self.create_task(token, f"api-{action}-lookup-race")
                session = self.create_session(token, task_id)
                session_id = session.json()["id"]
                connector = BlockingMailConnector()
                self.app.state.mail_connectors["fake"] = connector

                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        self.request,
                        "GET",
                        f"/api/v1/mail-sessions/{session_id}/code",
                        headers=self.mail_headers(token, session_id),
                    )
                    try:
                        self.assertTrue(connector.entered.wait(timeout=5))
                        if action == "revoke":
                            transition = self.request(
                                "POST",
                                f"/api/v1/mail-sessions/{session_id}/revoke",
                                headers=self.mail_headers(token, session_id),
                            )
                        else:
                            transition = self.request(
                                "POST",
                                "/api/v1/auth/logout",
                                headers=self.bearer(token),
                            )
                        self.assertEqual(transition.status_code, 200, transition.text)
                    finally:
                        connector.release.set()
                    response = future.result(timeout=5)

                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json(), {"status": "revoked", "code": None})
                with self.app.state.session_factory() as db:
                    persisted = db.get(MailSession, session_id)
                    self.assertEqual(persisted.status, "revoked")
                    self.assertIsNone(persisted.consumed_at)
                    consumed_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == session_id,
                                AuditEvent.event_type == "mail_session.code_consumed",
                            )
                        )
                    )
                    self.assertEqual(consumed_events, [])
                if action == "revoke":
                    closed = self.request(
                        "POST",
                        f"/api/v1/tasks/{task_id}/close",
                        headers=self.bearer(token),
                    )
                    self.assertEqual(closed.status_code, 200, closed.text)
                self.app.state.mail_connectors["fake"] = self.connector

    def test_concurrent_api_polls_return_code_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-double-poll-") as directory:
            database_path = Path(directory) / "api-double-poll.db"
            connector = BlockingMailConnector(expected_find_calls=2)
            app = create_app(
                Settings(
                    app_name="api-double-poll-platform",
                    environment="test",
                    database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                    jwt_hmac_secret="api-double-poll-hmac-secret",
                    mail_session_ttl_seconds=300,
                ),
                mail_connectors={"fake": connector},
            )
            password = "api-double-poll-password"
            identity = create_user_with_device(
                app.state.session_factory,
                tenant_id="tenant-api-double-poll",
                email="api-double-poll@example.test",
                password=password,
                device_name="api-double-poll-device",
            )
            with app.state.session_factory() as db:
                db.add(
                    Mailbox(
                        tenant_id="tenant-api-double-poll",
                        email_masked="a***@example.test",
                        connector_type="fake",
                        secret_ref="vault://mailboxes/api-double-poll",
                    )
                )
                db.commit()

            def request(method: str, path: str, **kwargs: object) -> httpx.Response:
                async def run() -> httpx.Response:
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(
                        transport=transport, base_url="http://test"
                    ) as client:
                        return await client.request(method, path, **kwargs)

                return asyncio.run(run())

            try:
                login = request(
                    "POST",
                    "/api/v1/auth/login",
                    json={
                        "tenant_id": "tenant-api-double-poll",
                        "email": "api-double-poll@example.test",
                        "password": password,
                        "device_id": identity.device_id,
                    },
                )
                self.assertEqual(login.status_code, 200, login.text)
                token = login.json()["access_token"]
                bearer = {"Authorization": f"Bearer {token}"}
                task = request(
                    "POST",
                    "/api/v1/tasks",
                    headers=bearer,
                    json={"type": "mail_code", "idempotency_key": "api-double-poll"},
                )
                self.assertEqual(task.status_code, 201, task.text)
                session = request(
                    "POST",
                    f"/api/v1/tasks/{task.json()['id']}/mail-sessions",
                    headers=bearer,
                )
                self.assertEqual(session.status_code, 201, session.text)
                session_id = session.json()["id"]
                headers = {
                    **bearer,
                    "X-Mail-Session-Token": session.json()["session_token"],
                }

                def poll() -> httpx.Response:
                    return request(
                        "GET",
                        f"/api/v1/mail-sessions/{session_id}/code",
                        headers=headers,
                    )

                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(poll) for _ in range(2)]
                    try:
                        self.assertTrue(connector.entered.wait(timeout=5))
                    finally:
                        connector.release.set()
                    responses = [future.result(timeout=5) for future in futures]

                self.assertTrue(
                    all(response.status_code == 200 for response in responses)
                )
                codes = [response.json()["code"] for response in responses]
                self.assertEqual(codes.count("246810"), 1)
                self.assertEqual(codes.count(None), 1)
                self.assertTrue(
                    all(
                        response.json()["status"] == "consumed"
                        for response in responses
                    )
                )
                loser_body = next(
                    response.json()
                    for response in responses
                    if response.json()["code"] is None
                )
                self.assertNotIn("received_at", loser_body)
                self.assertNotIn("message_id_hash", loser_body)
                with app.state.session_factory() as db:
                    consumed_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == session_id,
                                AuditEvent.event_type == "mail_session.code_consumed",
                            )
                        )
                    )
                    self.assertEqual(len(consumed_events), 1)
            finally:
                app.state.engine.dispose()

    def test_deployed_mail_policy_is_frozen_on_session_and_used_by_worker(self) -> None:
        with self.app.state.session_factory() as db:
            policy = OperationalPolicyVersion(
                tenant_id="tenant-mail",
                domain="mail",
                version="mail-runtime-v1",
                status="active",
                change_note="runtime proof",
                session_ttl_seconds=777,
                code_ttl_seconds=88,
                poll_interval_seconds=7,
                created_by=self.identity.user_id,
                approved_by=self.admin_identity.user_id,
                approved_at=utc_now(),
            )
            db.add(policy)
            db.flush()
            db.add(
                OperationalPolicyDeployment(
                    tenant_id="tenant-mail",
                    domain="mail",
                    active_policy_id=policy.id,
                    rollout_percent=100,
                    updated_by=self.admin_identity.user_id,
                )
            )
            db.commit()

        self.app.state.settings.mail_poll_mode = "worker"
        self.connector.messages.append(
            MailCodeMessage(message_id="old-policy", watermark="1", code="111111")
        )
        token = self.login()
        task_id = self.create_task(token, "mail-policy-runtime")
        with self.app.state.session_factory() as db:
            task_started_at = db.get(Task, task_id).created_at
        created_at = utc_now()
        response = self.create_session(token, task_id)
        self.assertEqual(response.status_code, 201, response.text)
        session_id = response.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.policy_version, "mail-runtime-v1")
            self.assertEqual(persisted.code_ttl_seconds, 88)
            self.assertEqual(persisted.poll_interval_seconds, 7)
            comparable_created_at = created_at.replace(
                tzinfo=persisted.expires_at.tzinfo
            )
            self.assertGreaterEqual(
                (persisted.expires_at - comparable_created_at).total_seconds(), 775
            )

        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "initialized",
        )
        self.assertEqual(self.connector.watermark_boundaries, [task_started_at])
        self.connector.messages.append(
            MailCodeMessage(message_id="new-policy", watermark="2", code="222222")
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
            self.assertIsNotNone(persisted.delivered_at)
            self.assertIsNotNone(persisted.code_expires_at)
            self.assertGreaterEqual(
                (persisted.code_expires_at - persisted.delivered_at).total_seconds(),
                87,
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
        expected_message_id_hash = hashlib.sha256(
            MESSAGE_ID_HASH_DOMAIN + b"new"
        ).hexdigest()
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(
                persisted.delivered_message_id_hash, expected_message_id_hash
            )
            self.assertIsNotNone(persisted.delivered_at)

        consumed = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        consumed_body = consumed.json()
        self.assertEqual(consumed_body["status"], "consumed")
        self.assertEqual(consumed_body["code"], "222222")
        self.assertEqual(
            consumed_body["message_id_hash"], expected_message_id_hash
        )
        self.assertIsNotNone(consumed_body["received_at"])
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
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.delivered_message_id_hash)
            self.assertIsNone(persisted.code_expires_at)

    def test_worker_does_not_restore_code_after_task_closes_during_lookup(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-close-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "initialized",
        )
        connector = BlockingMailConnector()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                process_mail_session,
                self.app.state.session_factory,
                session_id,
                connectors={"fake": connector},
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                closed = self.request(
                    "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
                )
                self.assertEqual(closed.status_code, 200, closed.text)
            finally:
                connector.release.set()
            self.assertEqual(future.result(timeout=5), "stale")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "revoked")
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.code_expires_at)
            code_ready_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.code_ready",
                    )
                )
            )
            self.assertEqual(code_ready_events, [])

    def test_worker_does_not_poll_or_deliver_for_closed_task_residue(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-closed-task-residue")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "initialized",
        )
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            task.status = "closed"
            task.closed_at = utc_now()
            db.commit()
        self.connector.messages.append(
            MailCodeMessage(
                message_id="after-closed-task",
                watermark="1",
                code="864209",
            )
        )
        find_calls_before = self.connector.find_calls

        result = process_mail_session(
            self.app.state.session_factory,
            session_id,
            connectors={"fake": self.connector},
        )

        self.assertEqual(self.connector.find_calls, find_calls_before)
        self.assertNotEqual(result, "code_ready")
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertNotEqual(persisted.status, "code_ready")
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.delivered_message_id_hash)
            self.assertIsNone(persisted.code_expires_at)

    def test_mailbox_disable_makes_slow_worker_result_stale(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        admin_token = self.login(
            self.admin_identity,
            email="mail-admin@example.test",
            password=self.admin_password,
        )
        task_id = self.create_task(token, "worker-secret-rotation")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            mailbox_id = db.scalar(select(Mailbox.id))
        connector = BlockingMailConnector(block_watermark=True)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                process_mail_session,
                self.app.state.session_factory,
                session_id,
                connectors={"fake": connector},
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                rotated = self.request(
                    "PATCH",
                    f"/api/v1/admin/mailboxes/{mailbox_id}",
                    headers=self.bearer(admin_token),
                    json={"is_active": False},
                )
                self.assertEqual(rotated.status_code, 200, rotated.text)
            finally:
                connector.release.set()
            self.assertEqual(future.result(timeout=5), "stale")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            mailbox = db.get(Mailbox, mailbox_id)
            self.assertEqual(persisted.status, "revoked")
            self.assertIsNone(persisted.delivered_code)
            self.assertEqual(mailbox.health_status, "unknown")
            self.assertIsNone(mailbox.last_checked_at)
            self.assertIsNone(mailbox.last_error_code)
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.revoked",
                    )
                )
            )
            self.assertEqual(len(events), 1)
            self.assertIn("admin_mailbox_disabled", events[0].details_json)
            self.assertNotIn("vault://", events[0].details_json)

    def test_mailbox_disable_makes_slow_api_poll_return_revoked(self) -> None:
        token = self.login()
        admin_token = self.login(
            self.admin_identity,
            email="mail-admin@example.test",
            password=self.admin_password,
        )
        task_id = self.create_task(token, "api-secret-rotation")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            mailbox_id = db.scalar(select(Mailbox.id))
        connector = BlockingMailConnector()
        self.app.state.mail_connectors["fake"] = connector

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                self.request,
                "GET",
                f"/api/v1/mail-sessions/{session_id}/code",
                headers=self.mail_headers(token, session_id),
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                rotated = self.request(
                    "PATCH",
                    f"/api/v1/admin/mailboxes/{mailbox_id}",
                    headers=self.bearer(admin_token),
                    json={"is_active": False},
                )
                self.assertEqual(rotated.status_code, 200, rotated.text)
            finally:
                connector.release.set()
            polled = future.result(timeout=5)

        self.assertEqual(polled.status_code, 200, polled.text)
        self.assertEqual(polled.json(), {"status": "revoked", "code": None})
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            mailbox = db.get(Mailbox, mailbox_id)
            self.assertEqual(persisted.status, "revoked")
            self.assertIsNone(persisted.delivered_code)
            self.assertEqual(mailbox.health_status, "unknown")
            self.assertIsNone(mailbox.last_checked_at)
            self.assertIsNone(mailbox.last_error_code)
            self.assertEqual(
                db.scalar(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.code_ready",
                    )
                    .exists()
                    .select()
                ),
                False,
            )

    def test_mailbox_disable_discards_slow_connector_failure_health(self) -> None:
        token = self.login()
        admin_token = self.login(
            self.admin_identity,
            email="mail-admin@example.test",
            password=self.admin_password,
        )
        task_id = self.create_task(token, "api-failed-secret-rotation")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            mailbox_id = db.scalar(select(Mailbox.id))
        connector = BlockingMailConnector(fail_after_release=True)
        self.app.state.mail_connectors["fake"] = connector

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                self.request,
                "GET",
                f"/api/v1/mail-sessions/{session_id}/code",
                headers=self.mail_headers(token, session_id),
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                rotated = self.request(
                    "PATCH",
                    f"/api/v1/admin/mailboxes/{mailbox_id}",
                    headers=self.bearer(admin_token),
                    json={"is_active": False},
                )
                self.assertEqual(rotated.status_code, 200, rotated.text)
            finally:
                connector.release.set()
            polled = future.result(timeout=5)

        self.assertEqual(polled.status_code, 503, polled.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            mailbox = db.get(Mailbox, mailbox_id)
            self.assertEqual(persisted.status, "revoked")
            self.assertEqual(mailbox.health_status, "unknown")
            self.assertIsNone(mailbox.last_checked_at)
            self.assertIsNone(mailbox.last_error_code)

    def test_worker_does_not_finish_initialization_after_user_revoke(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-revoke-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        connector = BlockingMailConnector(block_watermark=True)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                process_mail_session,
                self.app.state.session_factory,
                session_id,
                connectors={"fake": connector},
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                revoked = self.request(
                    "POST",
                    f"/api/v1/mail-sessions/{session_id}/revoke",
                    headers=self.mail_headers(token, session_id),
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
            finally:
                connector.release.set()
            self.assertEqual(future.result(timeout=5), "stale")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "revoked")
            initialized_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type
                        == "mail_session.watermark_initialized",
                    )
                )
            )
            self.assertEqual(initialized_events, [])

    def test_worker_does_not_restore_code_after_session_ttl_expires(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-ttl-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "initialized",
        )
        connector = BlockingMailConnector()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                process_mail_session,
                self.app.state.session_factory,
                session_id,
                connectors={"fake": connector},
            )
            try:
                self.assertTrue(connector.entered.wait(timeout=5))
                with self.app.state.session_factory() as db:
                    persisted = db.get(MailSession, session_id)
                    persisted.expires_at = utc_now() - timedelta(seconds=1)
                    db.commit()
                swept = sweep_expired_lifecycle(self.app.state.session_factory)
                self.assertEqual(swept.mail_sessions_expired, 1)
            finally:
                connector.release.set()
            self.assertEqual(future.result(timeout=5), "stale")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "expired")
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.code_expires_at)

    def test_two_workers_record_one_code_ready_transition(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mail-worker-race-") as directory:
            database_path = Path(directory) / "mail-worker-race.db"
            engine, session_factory = initialize_database(
                f"sqlite+pysqlite:///{database_path.as_posix()}"
            )
            identity = create_user_with_device(
                session_factory,
                tenant_id="tenant-worker-race",
                email="worker-race@example.test",
                password="worker-race-password",
                device_name="worker-race-device",
            )
            now = utc_now()
            with session_factory() as db:
                task = Task(
                    tenant_id="tenant-worker-race",
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    task_type="mail_code",
                    idempotency_key="worker-duplicate-race",
                    trace_id="worker-duplicate-race",
                    status="created",
                    expires_at=now + timedelta(minutes=5),
                )
                mailbox = Mailbox(
                    tenant_id="tenant-worker-race",
                    email_masked="w***@example.test",
                    connector_type="fake",
                    secret_ref="vault://mailboxes/worker-race",
                )
                db.add_all([task, mailbox])
                db.flush()
                session = MailSession(
                    tenant_id="tenant-worker-race",
                    task_id=task.id,
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    mailbox_id=mailbox.id,
                    trace_id=task.trace_id,
                    status="waiting",
                    start_watermark="1",
                    expires_at=now + timedelta(minutes=5),
                )
                db.add(session)
                db.commit()
                session_id = session.id
            connector = BlockingMailConnector(expected_find_calls=2)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        process_mail_session,
                        session_factory,
                        session_id,
                        connectors={"fake": connector},
                    )
                    for _ in range(2)
                ]
                try:
                    self.assertTrue(connector.entered.wait(timeout=5))
                finally:
                    connector.release.set()
                results = [future.result(timeout=5) for future in futures]

            self.assertEqual(results.count("code_ready"), 1)
            self.assertEqual(results.count("stale"), 1)
            with session_factory() as db:
                events = list(
                    db.scalars(
                        select(AuditEvent).where(
                            AuditEvent.entity_id == session_id,
                            AuditEvent.event_type == "mail_session.code_ready",
                        )
                    )
                )
                self.assertEqual(len(events), 1)
            engine.dispose()

    def test_worker_unclassified_failure_is_safe_and_batch_continues(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        first_token = self.login()
        first_task_id = self.create_task(first_token, "mail-runtime-failure-first")
        first_session = self.create_session(first_token, first_task_id)
        self.assertEqual(first_session.status_code, 201, first_session.text)

        second_password = "mail-second-account-password"
        second_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="mail-second@example.test",
            password=second_password,
            device_name="mail-second-device",
        )
        with self.app.state.session_factory() as db:
            db.add(
                Mailbox(
                    tenant_id="tenant-mail",
                    email_masked="s***@example.test",
                    connector_type="fake",
                    secret_ref="vault://mailboxes/mail-second",
                )
            )
            db.commit()
        second_token = self.login(
            second_identity,
            email="mail-second@example.test",
            password=second_password,
        )
        second_task_id = self.create_task(second_token, "mail-runtime-failure-second")
        second_session = self.create_session(second_token, second_task_id)
        self.assertEqual(second_session.status_code, 201, second_session.text)

        sentinel = "Authorization=Bearer MAIL_CONNECTOR_SECRET_SENTINEL"
        self.connector.unexpected_failures.append(RuntimeError(sentinel))
        counts = process_mail_sessions(
            self.app.state.session_factory,
            connectors={"fake": self.connector},
        )

        self.assertEqual(counts, {"connector_unavailable": 1, "initialized": 1})
        with self.app.state.session_factory() as db:
            persisted_sessions = (
                db.get(MailSession, first_session.json()["id"]),
                db.get(MailSession, second_session.json()["id"]),
            )
            sessions = {session.status for session in persisted_sessions}
            waiting_session_id = next(
                session.id
                for session in persisted_sessions
                if session.status == "waiting"
            )
            health_states = set(
                db.execute(select(Mailbox.health_status, Mailbox.last_error_code)).all()
            )
            audit_text = "\n".join(
                event.details_json for event in db.scalars(select(AuditEvent))
            )
        self.assertEqual(sessions, {"initializing", "waiting"})
        self.assertEqual(
            health_states,
            {("unavailable", "connector_unavailable"), ("healthy", None)},
        )
        self.assertNotIn(sentinel, audit_text)

        self.connector.unexpected_failures.append(RuntimeError(sentinel))
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                waiting_session_id,
                connectors={"fake": self.connector},
            ),
            "connector_unavailable",
        )
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, waiting_session_id)
            audit_text = "\n".join(
                event.details_json for event in db.scalars(select(AuditEvent))
            )
        self.assertEqual(persisted.status, "waiting")
        self.assertIsNone(persisted.delivered_code)
        self.assertNotIn(sentinel, audit_text)

    def test_worker_persists_safe_connector_health_and_recovery(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token)
        session = self.create_session(token, task_id)
        self.assertEqual(session.status_code, 201, session.text)
        session_id = session.json()["id"]
        trace_id = session.json()["trace_id"]

        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "initialized",
        )
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            mailbox_id = mailbox.id
            self.assertEqual(mailbox.health_status, "healthy")
            self.assertIsNotNone(mailbox.last_checked_at)
            self.assertIsNone(mailbox.last_error_code)

        raw_failure = "upstream rejected mailbox password=must-never-persist"
        self.connector.failure_message = raw_failure
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "connector_unavailable",
        )
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            self.assertEqual(mailbox.health_status, "unavailable")
            self.assertEqual(mailbox.last_error_code, "connector_unavailable")
            self.assertNotIn(raw_failure, repr(mailbox.__dict__))

        mailbox_admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="mailbox-health-admin@example.test",
            password="mailbox-health-admin-password",
            device_name="mailbox-health-admin-device",
            role="ops_admin",
        )
        admin_token = self.login(
            mailbox_admin,
            email="mailbox-health-admin@example.test",
            password="mailbox-health-admin-password",
        )
        unavailable = self.request(
            "GET",
            "/api/v1/mailboxes",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(unavailable.status_code, 200, unavailable.text)
        self.assertEqual(unavailable.json()["items"][0]["health_status"], "unavailable")
        self.assertEqual(
            unavailable.json()["items"][0]["last_error_code"], "connector_unavailable"
        )
        self.assertNotIn(raw_failure, unavailable.text)

        self.connector.failure_message = None
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={},
            ),
            "connector_unavailable",
        )
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            self.assertEqual(mailbox.last_error_code, "connector_not_configured")

        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "waiting",
        )
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            self.assertEqual(mailbox.health_status, "healthy")
            self.assertIsNone(mailbox.last_error_code)

        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
            ),
            "waiting",
        )
        with self.app.state.session_factory() as db:
            health_events = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == mailbox_id,
                        AuditEvent.event_type == "mailbox.health_changed",
                    )
                    .order_by(AuditEvent.created_at, AuditEvent.id)
                )
            )
        self.assertEqual(len(health_events), 4)
        self.assertEqual(
            [event.actor_id for event in health_events], ["worker-mail"] * 4
        )
        self.assertEqual(
            [event.user_id for event in health_events], [self.identity.user_id] * 4
        )
        self.assertEqual(
            [event.device_id for event in health_events],
            [self.identity.device_id] * 4,
        )
        self.assertEqual([event.trace_id for event in health_events], [trace_id] * 4)
        self.assertEqual(
            [event.entity_type for event in health_events], ["mailbox"] * 4
        )
        transitions = {
            (
                details["previous_status"],
                details["previous_error_code"],
                details["status"],
                details["error_code"],
            ): event.result
            for event in health_events
            for details in [json.loads(event.details_json)]
        }
        self.assertEqual(
            transitions,
            {
                ("unknown", None, "healthy", None): "success",
                ("healthy", None, "unavailable", "connector_unavailable"): "failure",
                (
                    "unavailable",
                    "connector_unavailable",
                    "unavailable",
                    "connector_not_configured",
                ): "failure",
                (
                    "unavailable",
                    "connector_not_configured",
                    "healthy",
                    None,
                ): "success",
            },
        )
        self.assertNotIn(
            raw_failure, "\n".join(event.details_json for event in health_events)
        )

    def test_worker_delivered_code_is_atomically_consumed_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mail-consume-") as directory:
            database_path = Path(directory) / "mail-consume.db"
            engine, session_factory = initialize_database(
                f"sqlite+pysqlite:///{database_path.as_posix()}"
            )
            identity = create_user_with_device(
                session_factory,
                tenant_id="tenant-atomic-mail",
                email="atomic-mail@example.test",
                password="atomic-mail-password",
                device_name="atomic-mail-device",
            )
            now = utc_now()
            with session_factory() as db:
                task = Task(
                    tenant_id="tenant-atomic-mail",
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    task_type="card_checkout",
                    idempotency_key="atomic-mail-task",
                    trace_id="atomic-mail-trace",
                    status="created",
                    expires_at=now + timedelta(minutes=5),
                )
                mailbox = Mailbox(
                    tenant_id="tenant-atomic-mail",
                    email_masked="a***@example.test",
                    connector_type="fake",
                    secret_ref="vault://mailboxes/atomic-mail",
                )
                db.add_all([task, mailbox])
                db.flush()
                session = MailSession(
                    tenant_id="tenant-atomic-mail",
                    task_id=task.id,
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    mailbox_id=mailbox.id,
                    trace_id=task.trace_id,
                    status="code_ready",
                    delivered_code="42681357",
                    delivered_at=now,
                    delivered_message_id_hash=hashlib.sha256(
                        MESSAGE_ID_HASH_DOMAIN + b"atomic-message"
                    ).hexdigest(),
                    code_expires_at=now + timedelta(minutes=1),
                    expires_at=now + timedelta(minutes=5),
                )
                db.add(session)
                db.commit()
                session_id = session.id

            with session_factory() as db:
                stale_claim = claim_delivered_code(
                    db,
                    session_id=session_id,
                    expected_code="42681357",
                    expected_message_id_hash=hashlib.sha256(
                        MESSAGE_ID_HASH_DOMAIN + b"stale-message"
                    ).hexdigest(),
                    now=utc_now(),
                )
                db.commit()
                self.assertFalse(stale_claim)
                persisted = db.get(MailSession, session_id)
                self.assertEqual(persisted.status, "code_ready")
                self.assertEqual(persisted.delivered_code, "42681357")

            barrier = Barrier(2)

            def consume() -> str | None:
                with session_factory() as db:
                    session = db.get(MailSession, session_id)
                    assert session is not None
                    candidate = session.delivered_code
                    assert candidate is not None
                    barrier.wait(timeout=5)
                    claimed = claim_delivered_code(
                        db,
                        session_id=session_id,
                        expected_code=candidate,
                        expected_message_id_hash=hashlib.sha256(
                            MESSAGE_ID_HASH_DOMAIN + b"atomic-message"
                        ).hexdigest(),
                        now=utc_now(),
                    )
                    db.commit()
                    return candidate if claimed else None

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: consume(), range(2)))

            self.assertEqual(results.count("42681357"), 1)
            self.assertEqual(results.count(None), 1)
            with session_factory() as db:
                persisted = db.get(MailSession, session_id)
                self.assertEqual(persisted.status, "consumed")
                self.assertIsNotNone(persisted.consumed_at)
                self.assertIsNone(persisted.delivered_code)
                self.assertIsNone(persisted.delivered_at)
                self.assertIsNone(persisted.delivered_message_id_hash)
                self.assertIsNone(persisted.code_expires_at)

                connector_task = Task(
                    tenant_id="tenant-atomic-mail",
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    task_type="card_checkout",
                    idempotency_key="atomic-connector-task",
                    trace_id="atomic-connector-trace",
                    status="created",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
                db.add(connector_task)
                db.flush()
                connector_session = MailSession(
                    tenant_id="tenant-atomic-mail",
                    task_id=connector_task.id,
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    mailbox_id=persisted.mailbox_id,
                    trace_id=connector_task.trace_id,
                    status="waiting",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
                db.add(connector_session)
                db.commit()
                connector_session_id = connector_session.id

            connector_barrier = Barrier(2)

            def consume_connector() -> bool:
                with session_factory() as db:
                    connector_barrier.wait(timeout=5)
                    claimed = claim_connector_message(
                        db,
                        session_id=connector_session_id,
                        message_hash="a" * 64,
                        now=utc_now(),
                    )
                    db.commit()
                    return claimed

            with ThreadPoolExecutor(max_workers=2) as executor:
                connector_results = list(
                    executor.map(lambda _: consume_connector(), range(2))
                )
            self.assertEqual(connector_results.count(True), 1)
            self.assertEqual(connector_results.count(False), 1)
            engine.dispose()

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
            self.assertEqual(
                persisted.delivered_message_id_hash,
                hashlib.sha256(MESSAGE_ID_HASH_DOMAIN + b"first").hexdigest(),
            )
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
            self.assertIsNone(persisted.delivered_message_id_hash)
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
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(
            process_mail_session(
                self.app.state.session_factory,
                session_id,
                connectors={"fake": self.connector},
                code_ttl_seconds=1,
            ),
            "expired",
        )
        worker_event_types = {
            "mail_session.watermark_initialized",
            "mail_session.code_ready",
            "mail_session.code_expired",
            "mail_session.expired",
        }
        with self.app.state.session_factory() as db:
            worker_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type.in_(worker_event_types),
                    )
                )
            )
            created_event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == session_id,
                    AuditEvent.event_type == "mail_session.created",
                )
            )
        self.assertEqual(
            {event.event_type for event in worker_events}, worker_event_types
        )
        for event in worker_events:
            self.assertEqual(event.user_id, self.identity.user_id)
            self.assertEqual(event.device_id, self.identity.device_id)
            self.assertEqual(event.actor_id, "worker-mail")
            self.assertNotEqual(event.actor_id, event.user_id)
        self.assertIsNotNone(created_event)
        self.assertEqual(created_event.actor_id, self.identity.user_id)
        audit_text = "\n".join(event.details_json for event in worker_events)
        for forbidden in (
            "111111",
            "222222",
            "333333",
            "vault://mailboxes/mail-owner",
        ):
            self.assertNotIn(forbidden, audit_text)

    def test_worker_code_expiry_cannot_resurrect_revoked_session(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-code-expiry-revoke-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.status = "code_ready"
            persisted.delivered_code = "112233"
            persisted.delivered_at = utc_now() - timedelta(minutes=2)
            persisted.code_expires_at = utc_now() - timedelta(minutes=1)
            db.commit()

        expiry_checked = Event()
        allow_expiry = Event()
        original_is_expired = mail_worker._is_expired

        def block_after_expired_code(value, now):
            result = original_is_expired(value, now)
            if result and not expiry_checked.is_set():
                expiry_checked.set()
                self.assertTrue(allow_expiry.wait(timeout=5))
            return result

        with patch.object(mail_worker, "_is_expired", side_effect=block_after_expired_code):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    process_mail_session,
                    self.app.state.session_factory,
                    session_id,
                    connectors={"fake": self.connector},
                )
                try:
                    self.assertTrue(expiry_checked.wait(timeout=5))
                    revoked = self.request(
                        "POST",
                        f"/api/v1/mail-sessions/{session_id}/revoke",
                        headers=self.mail_headers(token, session_id),
                    )
                    self.assertEqual(revoked.status_code, 200, revoked.text)
                    self.assertEqual(revoked.json()["status"], "revoked")
                finally:
                    allow_expiry.set()
                self.assertEqual(future.result(timeout=5), "revoked")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(
                        AuditEvent.entity_id == session_id
                    )
                )
            )
        self.assertEqual(persisted.status, "revoked")
        self.assertIsNone(persisted.delivered_code)
        self.assertEqual(event_types.count("mail_session.revoked"), 1)
        self.assertEqual(event_types.count("mail_session.code_expired"), 0)

    def test_expired_session_cannot_be_rewritten_by_user_revoke(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        token = self.login()
        task_id = self.create_task(token, "worker-session-expiry-revoke-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.expires_at = utc_now() - timedelta(minutes=1)
            db.commit()

        expiry_checked = Event()
        allow_expiry = Event()
        original_is_expired = mail_worker._is_expired

        def block_after_expired_session(value, now):
            result = original_is_expired(value, now)
            if result and not expiry_checked.is_set():
                expiry_checked.set()
                self.assertTrue(allow_expiry.wait(timeout=5))
            return result

        with patch.object(
            mail_worker, "_is_expired", side_effect=block_after_expired_session
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    process_mail_session,
                    self.app.state.session_factory,
                    session_id,
                    connectors={"fake": self.connector},
                )
                try:
                    self.assertTrue(expiry_checked.wait(timeout=5))
                    revoked = self.request(
                        "POST",
                        f"/api/v1/mail-sessions/{session_id}/revoke",
                        headers=self.mail_headers(token, session_id),
                    )
                    self.assertEqual(revoked.status_code, 409, revoked.text)
                    self.assertEqual(
                        revoked.json()["error"]["code"],
                        "mail_session_revoke_unavailable",
                    )
                finally:
                    allow_expiry.set()
                self.assertEqual(future.result(timeout=5), "expired")

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(
                        AuditEvent.entity_id == session_id
                    )
                )
            )
        self.assertEqual(persisted.status, "expired")
        self.assertEqual(event_types.count("mail_session.revoked"), 0)
        self.assertEqual(event_types.count("mail_session.expired"), 1)

    def test_stale_user_revoke_cannot_overwrite_expired_session(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "user-revoke-session-expiry-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        token_checked = Event()
        release_stale_revoke = Event()
        original_require_token = routes._require_mail_session_token

        def pause_after_first_token_check(
            request, current_session, *, db, principal
        ):
            original_require_token(
                request,
                current_session,
                db=db,
                principal=principal,
            )
            if not token_checked.is_set():
                current_db = object_session(current_session)
                self.assertIsNotNone(current_db)
                # Retain the loaded MailSession values but end its read
                # transaction so the lifecycle winner can commit first.
                current_db.commit()
                token_checked.set()
                self.assertTrue(release_stale_revoke.wait(timeout=5))

        with patch.object(
            routes,
            "_require_mail_session_token",
            side_effect=pause_after_first_token_check,
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/mail-sessions/{session_id}/revoke",
                    headers=self.mail_headers(token, session_id),
                )
                try:
                    self.assertTrue(token_checked.wait(timeout=5))
                    swept = sweep_expired_lifecycle(
                        self.app.state.session_factory,
                        now=utc_now(),
                    )
                    self.assertEqual(swept.tasks_expired, 1)
                    self.assertEqual(swept.mail_sessions_expired, 1)
                finally:
                    release_stale_revoke.set()
                revoked = future.result(timeout=5)

        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "expired")
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            persisted = db.get(MailSession, session_id)
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type.in_(
                            ("mail_session.expired", "mail_session.revoked")
                        ),
                    )
                )
            )
        self.assertEqual(task.status, "expired")
        self.assertEqual(persisted.status, "expired")
        self.assertIsNone(persisted.delivered_code)
        self.assertEqual(
            [event.event_type for event in events].count("mail_session.expired"), 1
        )
        self.assertEqual(
            [event.event_type for event in events].count("mail_session.revoked"), 0
        )

    def test_database_rejects_two_active_leases_for_one_mailbox(self) -> None:
        token = self.login()
        first_task_id = self.create_task(token, "mail-lease-first")
        first = self.create_session(token, first_task_id)
        self.assertEqual(first.status_code, 201, first.text)
        second_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-mail",
            email="mail-lease-contender@example.test",
            password="mail-lease-contender-password",
            device_name="mail-lease-contender-device",
        )
        second_token = self.login(
            second_identity,
            email="mail-lease-contender@example.test",
            password="mail-lease-contender-password",
        )
        second_task_id = self.create_task(second_token, "mail-lease-second")
        unavailable = self.create_session(second_token, second_task_id)
        self.assertEqual(unavailable.status_code, 503, unavailable.text)

        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            second_task = db.get(Task, second_task_id)
            db.add(
                MailSession(
                    tenant_id="tenant-mail",
                    task_id=second_task_id,
                    user_id=second_task.user_id,
                    device_id=second_task.device_id,
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
        missing = self.request(
            "GET",
            "/api/v1/mail-sessions/missing-mail-session/code",
            headers={
                **self.bearer(token),
                "X-Mail-Session-Token": "x" * 43,
            },
        )
        self.assertEqual(missing.status_code, 404, missing.text)
        with self.app.state.session_factory() as db:
            denied_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "mail_session.capability_denied"
                    )
                )
            )
        self.assertEqual(denied_events, [])

    def test_session_token_is_required_rotated_and_never_exposed_in_audit(self) -> None:
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
            events = list(db.scalars(select(AuditEvent)))
            denied_events = [
                event
                for event in events
                if event.entity_id == session_id
                and event.event_type == "mail_session.capability_denied"
            ]
            audit_text = "\n".join(event.details_json for event in events)
        self.assertEqual(len(denied_events), 3)
        for event in denied_events:
            self.assertEqual(event.action, "mail_session.access")
            self.assertEqual(event.result, "failure")
            self.assertEqual(event.actor_id, self.identity.user_id)
            self.assertEqual(event.tenant_id, "tenant-mail")
            self.assertEqual(event.user_id, self.identity.user_id)
            self.assertEqual(event.device_id, self.identity.device_id)
            self.assertEqual(event.entity_id, session_id)
            self.assertEqual(event.trace_id, created.json()["trace_id"])
            self.assertEqual(
                json.loads(event.details_json),
                {"reason": "invalid_or_missing_session_token"},
            )
        forbidden_values = (
            access_token,
            "x" * 43,
            first_token,
            second_token,
            hashlib.sha256(first_token.encode("utf-8")).hexdigest(),
            hashlib.sha256(second_token.encode("utf-8")).hexdigest(),
            "vault://mailboxes/mail-owner",
            self.password,
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, audit_text)
            for response in (missing, wrong, old_token, current):
                self.assertNotIn(forbidden, response.text)

    def test_mail_capability_denial_audit_commit_failure_fails_closed(self) -> None:
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-token-audit-failure")
        created = self.create_session(access_token, task_id)
        self.assertEqual(created.status_code, 201, created.text)
        session_id = created.json()["id"]
        session_token = created.json()["session_token"]

        with patch.object(
            Session,
            "commit",
            side_effect=RuntimeError("audit store Bearer TOP_SECRET unavailable"),
        ):
            blocked = self.request(
                "GET",
                f"/api/v1/mail-sessions/{session_id}/code",
                headers=self.bearer(access_token),
            )

        self.assertEqual(blocked.status_code, 500, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "internal_error")
        for forbidden in ("TOP_SECRET", access_token, session_token):
            self.assertNotIn(forbidden, blocked.text)
        with self.app.state.session_factory() as db:
            denied_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.capability_denied",
                    )
                )
            )
        self.assertEqual(denied_events, [])

        recovered = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(access_token, session_id),
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)

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

    def test_terminal_task_code_ready_residue_never_exposes_code(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        access_token = self.login()
        terminal_statuses = ("closed", "completed", "expired", "cancelled")

        for index, task_status in enumerate(terminal_statuses, start=1):
            with self.subTest(task_status=task_status):
                task_id = self.create_task(
                    access_token, f"terminal-code-residue-{task_status}"
                )
                session = self.create_session(access_token, task_id)
                session_id = session.json()["id"]
                code = f"72{index:04d}"
                self.seed_terminal_code_ready_residue(
                    task_id=task_id,
                    session_id=session_id,
                    task_status=task_status,
                    code=code,
                )

                response = self.request(
                    "GET",
                    f"/api/v1/mail-sessions/{session_id}/code",
                    headers=self.mail_headers(access_token, session_id),
                )

                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn(code, response.text)
                self.assertIsNone(response.json()["code"])
                self.assertIsNone(response.json().get("received_at"))
                self.assertIsNone(response.json().get("message_id_hash"))
                with self.app.state.session_factory() as db:
                    consumed_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == session_id,
                                AuditEvent.event_type == "mail_session.code_consumed",
                            )
                        )
                    )
                self.assertEqual(consumed_events, [])

    def test_sse_terminal_task_residue_never_exposes_code(self) -> None:
        self.app.state.settings.mail_poll_mode = "worker"
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-sse-terminal-residue")
        session = self.create_session(access_token, task_id)
        session_id = session.json()["id"]
        code = "246810"
        self.seed_terminal_code_ready_residue(
            task_id=task_id,
            session_id=session_id,
            task_status="closed",
            code=code,
        )

        stream = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/events",
            headers=self.mail_headers(access_token, session_id),
        )

        self.assertEqual(stream.status_code, 200, stream.text)
        self.assertIn("event: revoked", stream.text)
        self.assertNotIn(code, stream.text)
        data_line = next(
            line.removeprefix("data: ")
            for line in stream.text.splitlines()
            if line.startswith("data: ")
        )
        payload = json.loads(data_line)
        self.assertIsNone(payload["code"])
        self.assertIsNone(payload.get("received_at"))
        self.assertIsNone(payload.get("message_id_hash"))

    def test_sse_success_returns_the_complete_minimal_code_result(self) -> None:
        self.connector.messages.append(
            MailCodeMessage(message_id="old", watermark="1", code="111111")
        )
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-sse-minimal-result")
        session = self.create_session(access_token, task_id)
        session_id = session.json()["id"]
        self.connector.messages.append(
            MailCodeMessage(message_id="new", watermark="2", code="222222")
        )

        stream = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/events",
            headers=self.mail_headers(access_token, session_id),
        )

        self.assertEqual(stream.status_code, 200, stream.text)
        self.assertIn("event: consumed", stream.text)
        data_line = next(
            line.removeprefix("data: ")
            for line in stream.text.splitlines()
            if line.startswith("data: ")
        )
        payload = json.loads(data_line)
        self.assertEqual(
            set(payload),
            {"status", "code", "received_at", "message_id_hash"},
        )
        self.assertEqual(payload["status"], "consumed")
        self.assertEqual(payload["code"], "222222")
        self.assertIsNotNone(payload["received_at"])
        self.assertEqual(
            payload["message_id_hash"],
            hashlib.sha256(MESSAGE_ID_HASH_DOMAIN + b"new").hexdigest(),
        )
        for forbidden in ("body", "password", "credential", "secret_ref"):
            self.assertNotIn(forbidden, stream.text.lower())

    def test_sse_slow_lookup_does_not_block_health_or_revocation(self) -> None:
        access_token = self.login()
        task_id = self.create_task(access_token, "mail-sse-nonblocking")
        session = self.create_session(access_token, task_id)
        session_id = session.json()["id"]
        connector = BlockingMailConnector()
        self.app.state.mail_connectors["fake"] = connector
        mail_headers = self.mail_headers(access_token, session_id)

        async def exercise() -> tuple[
            int, httpx.Response, httpx.Response, httpx.Response
        ]:
            event_loop_thread_id = get_ident()
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                stream_task = asyncio.create_task(
                    client.get(
                        f"/api/v1/mail-sessions/{session_id}/events",
                        headers=mail_headers,
                    )
                )
                try:
                    entered = await asyncio.wait_for(
                        asyncio.to_thread(connector.entered.wait, 2), timeout=3
                    )
                    self.assertTrue(entered)
                    self.assertFalse(connector.release.is_set())
                    health = await asyncio.wait_for(client.get("/healthz"), timeout=1)
                    revoked = await asyncio.wait_for(
                        client.post(
                            f"/api/v1/mail-sessions/{session_id}/revoke",
                            headers=mail_headers,
                        ),
                        timeout=2,
                    )
                finally:
                    connector.release.set()
                stream = await asyncio.wait_for(stream_task, timeout=3)
            return event_loop_thread_id, health, revoked, stream

        event_loop_thread_id, health, revoked, stream = asyncio.run(exercise())
        self.assertEqual(health.status_code, 200, health.text)
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "revoked")
        self.assertIsNotNone(connector.lookup_thread_id)
        self.assertNotEqual(connector.lookup_thread_id, event_loop_thread_id)
        self.assertEqual(stream.status_code, 200, stream.text)
        self.assertEqual(stream.headers["Cache-Control"], "no-store")
        self.assertEqual(stream.headers["Pragma"], "no-cache")
        self.assertEqual(stream.headers["X-Accel-Buffering"], "no")
        self.assertIn("event: revoked", stream.text)
        self.assertNotIn("246810", stream.text)

        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            consumed_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.code_consumed",
                    )
                )
            )
        self.assertEqual(persisted.status, "revoked")
        self.assertIsNone(persisted.delivered_code)
        self.assertIsNone(persisted.delivered_at)
        self.assertIsNone(persisted.code_expires_at)
        self.assertEqual(consumed_events, [])

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
        replayed_response = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(
            replayed_response.json(), {"status": "expired", "code": None}
        )
        with self.app.state.session_factory() as db:
            expiration_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.expired",
                    )
                )
            )
        self.assertEqual(len(expiration_events), 1)

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        replay_task_id = self.create_task(token, "expired-session-replay")
        replay_session = self.create_session(token, replay_task_id)
        replay_session_id = replay_session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, replay_session_id)
            persisted.status = "code_ready"
            persisted.delivered_code = "654321"
            persisted.delivered_at = utc_now()
            persisted.code_expires_at = utc_now() + timedelta(minutes=1)
            persisted.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        expired_replay = self.create_session(token, replay_task_id)
        repeated_replay = self.create_session(token, replay_task_id)
        self.assertEqual(expired_replay.status_code, 200, expired_replay.text)
        self.assertEqual(expired_replay.json()["status"], "expired")
        self.assertEqual(repeated_replay.status_code, 200, repeated_replay.text)
        self.assertEqual(repeated_replay.json()["status"], "expired")
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, replay_session_id)
            replay_expiration_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == replay_session_id,
                        AuditEvent.event_type == "mail_session.expired",
                    )
                )
            )
        self.assertIsNone(persisted.delivered_code)
        self.assertIsNone(persisted.delivered_at)
        self.assertIsNone(persisted.code_expires_at)
        self.assertEqual(len(replay_expiration_events), 1)

    def test_code_expiry_cannot_erase_a_concurrently_delivered_new_code(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "code-expiry-delivery-race")
        session = self.create_session(token, task_id)
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.status = "code_ready"
            persisted.delivered_code = "111111"
            persisted.delivered_at = utc_now() - timedelta(minutes=2)
            persisted.code_expires_at = utc_now() - timedelta(minutes=1)
            db.commit()

        expiry_checked = Event()
        allow_expiry = Event()
        original_is_expired = routes._is_expired

        def block_after_old_code_expiry(value, now):
            result = original_is_expired(value, now)
            if result and not expiry_checked.is_set():
                expiry_checked.set()
                self.assertTrue(allow_expiry.wait(timeout=5))
            return result

        with patch.object(routes, "_is_expired", side_effect=block_after_old_code_expiry):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "GET",
                    f"/api/v1/mail-sessions/{session_id}/code",
                    headers=self.mail_headers(token, session_id),
                )
                try:
                    self.assertTrue(expiry_checked.wait(timeout=5))
                    with self.app.state.session_factory() as db:
                        persisted = db.get(MailSession, session_id)
                        persisted.status = "code_ready"
                        persisted.delivered_code = "222222"
                        persisted.delivered_at = utc_now()
                        persisted.delivered_message_id_hash = hashlib.sha256(
                            MESSAGE_ID_HASH_DOMAIN + b"concurrent-new"
                        ).hexdigest()
                        persisted.code_expires_at = utc_now() + timedelta(minutes=1)
                        db.commit()
                finally:
                    allow_expiry.set()
                response = future.result(timeout=5)

        self.assertEqual(response.status_code, 200, response.text)
        response_body = response.json()
        self.assertEqual(response_body["status"], "consumed")
        self.assertEqual(response_body["code"], "222222")
        self.assertEqual(
            response_body["message_id_hash"],
            hashlib.sha256(
                MESSAGE_ID_HASH_DOMAIN + b"concurrent-new"
            ).hexdigest(),
        )
        self.assertIsNotNone(response_body["received_at"])
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(
                        AuditEvent.entity_id == session_id
                    )
                )
            )
        self.assertEqual(persisted.status, "consumed")
        self.assertIsNone(persisted.delivered_code)
        self.assertEqual(event_types.count("mail_session.code_expired"), 0)
        self.assertEqual(event_types.count("mail_session.code_consumed"), 1)

    def test_unconfigured_connector_returns_503(self) -> None:
        self.app.state.mail_connectors = {}
        token = self.login()
        task_id = self.create_task(token)
        response = self.create_session(token, task_id)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "service_unavailable")
        self.assertIn("not configured", response.json()["error"]["message"])
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            self.assertEqual(mailbox.health_status, "unavailable")
            self.assertEqual(mailbox.last_error_code, "connector_not_configured")

    def test_api_unclassified_connector_failures_use_fixed_safe_503(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "mail-api-runtime-failure")
        sentinel = "vault://mailboxes/private password=API_SECRET_SENTINEL"
        self.connector.unexpected_failures.append(RuntimeError(sentinel))

        failed_create = self.create_session(token, task_id)
        self.assertEqual(failed_create.status_code, 503, failed_create.text)
        self.assertEqual(
            failed_create.json()["error"]["message"],
            "Mail connector is temporarily unavailable",
        )
        self.assertNotIn(sentinel, failed_create.text)

        created = self.create_session(token, task_id)
        self.assertEqual(created.status_code, 201, created.text)
        self.connector.unexpected_failures.append(RuntimeError(sentinel))
        failed_poll = self.request(
            "GET",
            f"/api/v1/mail-sessions/{created.json()['id']}/code",
            headers=self.mail_headers(token, created.json()["id"]),
        )
        self.assertEqual(failed_poll.status_code, 503, failed_poll.text)
        self.assertEqual(
            failed_poll.json()["error"]["message"],
            "Mail connector is temporarily unavailable",
        )
        self.assertNotIn(sentinel, failed_poll.text)
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            persisted = db.get(MailSession, created.json()["id"])
            audit_text = "\n".join(
                event.details_json for event in db.scalars(select(AuditEvent))
            )
        self.assertEqual(mailbox.health_status, "unavailable")
        self.assertEqual(mailbox.last_error_code, "connector_unavailable")
        self.assertEqual(persisted.status, "waiting")
        self.assertIsNone(persisted.delivered_code)
        self.assertNotIn(sentinel, audit_text)

    def test_api_poll_connector_failure_uses_safe_error_and_recovers(self) -> None:
        token = self.login()
        task_id = self.create_task(token)
        watermark_failure = "watermark password=must-never-escape"
        self.connector.failure_message = watermark_failure

        failed_create = self.create_session(token, task_id)
        self.assertEqual(failed_create.status_code, 503, failed_create.text)
        self.assertEqual(
            failed_create.json()["error"]["message"],
            "Mail connector is temporarily unavailable",
        )
        self.assertNotIn(watermark_failure, failed_create.text)

        self.connector.failure_message = None
        created = self.create_session(token, task_id)
        self.assertEqual(created.status_code, 201, created.text)
        code_failure = "poll bearer-token=must-never-escape"
        self.connector.failure_message = code_failure
        failed_poll = self.request(
            "GET",
            f"/api/v1/mail-sessions/{created.json()['id']}/code",
            headers=self.mail_headers(token, created.json()["id"]),
        )
        self.assertEqual(failed_poll.status_code, 503, failed_poll.text)
        self.assertEqual(
            failed_poll.json()["error"]["message"],
            "Mail connector is temporarily unavailable",
        )
        self.assertNotIn(code_failure, failed_poll.text)
        with self.app.state.session_factory() as db:
            mailbox = db.scalar(select(Mailbox))
            task = db.get(Task, task_id)
            self.assertEqual(mailbox.health_status, "unavailable")
            self.assertEqual(mailbox.last_error_code, "connector_unavailable")
            health_events = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == mailbox.id,
                        AuditEvent.event_type == "mailbox.health_changed",
                    )
                    .order_by(AuditEvent.created_at, AuditEvent.id)
                )
            )
            audit_text = "\n".join(event.details_json for event in db.query(AuditEvent))
        self.assertEqual(len(health_events), 3)
        self.assertEqual(
            [event.actor_id for event in health_events], [self.identity.user_id] * 3
        )
        self.assertEqual(
            [event.user_id for event in health_events], [self.identity.user_id] * 3
        )
        self.assertEqual(
            [event.device_id for event in health_events],
            [self.identity.device_id] * 3,
        )
        self.assertEqual(
            [event.trace_id for event in health_events], [task.trace_id] * 3
        )
        self.assertEqual(
            [event.result for event in health_events],
            ["failure", "success", "failure"],
        )
        self.assertNotIn(watermark_failure, audit_text)
        self.assertNotIn(code_failure, audit_text)

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
        session_id = session.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            persisted.status = "consumed"
            persisted.consumed_at = utc_now()
            persisted.delivered_code = "771122"
            persisted.delivered_at = utc_now()
            persisted.code_expires_at = utc_now() + timedelta(minutes=1)
            db.commit()

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")
        code = self.request(
            "GET",
            f"/api/v1/mail-sessions/{session_id}/code",
            headers=self.mail_headers(token, session_id),
        )
        self.assertEqual(code.json(), {"status": "revoked", "code": None})
        with self.app.state.session_factory() as db:
            persisted = db.get(MailSession, session_id)
            self.assertEqual(persisted.status, "revoked")
            self.assertIsNone(persisted.delivered_code)
            self.assertIsNone(persisted.delivered_at)
            self.assertIsNone(persisted.code_expires_at)
            self.assertEqual(
                len(
                    list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.event_type == "mail_session.revoked",
                                AuditEvent.entity_id == session_id,
                            )
                        )
                    )
                ),
                1,
            )
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
        self.assertIn("polling_interval", create_properties)
        self.assertNotIn("session_token_hash", create_properties)
        code_properties = schema["components"]["schemas"]["MailCodeResponse"][
            "properties"
        ]
        self.assertIn("received_at", code_properties)
        self.assertIn("message_id_hash", code_properties)
        self.assertNotIn("delivered_message_id_hash", code_properties)
        self.assertIn("/api/v1/tasks/{task_id}/mail-sessions", schema["paths"])
        self.assertIn("/api/v1/mail-sessions/{session_id}/code", schema["paths"])

    def test_mail_code_response_requires_complete_success_metadata(self) -> None:
        valid_hash = hashlib.sha256(
            MESSAGE_ID_HASH_DOMAIN + b"schema-message"
        ).hexdigest()
        for partial in (
            {"code": "123456"},
            {"received_at": utc_now()},
            {"message_id_hash": valid_hash},
            {"code": "123456", "received_at": utc_now()},
        ):
            with self.subTest(partial=partial):
                with self.assertRaises(ValueError):
                    MailCodeResponse(status="consumed", **partial)

        with self.assertRaises(ValueError):
            MailCodeResponse(
                status="consumed",
                code="123456",
                received_at=utc_now(),
                message_id_hash=valid_hash.upper(),
            )
        with self.assertRaises(ValueError):
            MailCodeResponse(
                status="consumed",
                code="123456",
                received_at=utc_now().replace(tzinfo=None),
                message_id_hash=valid_hash,
            )


class MailWorkerLoopTests(unittest.TestCase):
    def test_nonempty_batch_still_waits_before_polling_again(self) -> None:
        class StopAfterFirstWait:
            def __init__(self) -> None:
                self.waits: list[float] = []
                self.checks = 0

            def is_set(self) -> bool:
                self.checks += 1
                return self.checks > 1

            def wait(self, seconds: float) -> bool:
                self.waits.append(seconds)
                return True

        stop_event = StopAfterFirstWait()
        with (
            patch.object(mail_worker, "sweep_expired_lifecycle"),
            patch.object(
                mail_worker,
                "process_mail_sessions",
                return_value={"waiting": 1},
            ) as process,
        ):
            mail_worker.run_mail_worker(
                object(),
                connectors={},
                stop_event=stop_event,  # type: ignore[arg-type]
                poll_seconds=3.5,
            )

        process.assert_called_once()
        self.assertEqual(stop_event.waits, [3.5])


if __name__ == "__main__":
    unittest.main()
