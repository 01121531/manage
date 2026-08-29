import asyncio
import unittest
from datetime import timedelta

import httpx
from sqlalchemy import func, select

from platform.app import create_app
from platform.auth import ROLE_WORKER_SERVICE, create_access_token
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    Device,
    Mailbox,
    MailSession,
    OutboxEvent,
    RevokedAccessToken,
    Task,
    UploadJob,
    utc_now,
)


class LogoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            Settings(
                app_name="logout-test-platform",
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="logout-test-secret-that-is-not-production",
            )
        )
        self.password = "logout-test-password"
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-logout",
            email="logout@example.test",
            password=self.password,
            device_name="logout-device",
        )
        self.other_device_id = self._seed_resources()

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

    def login(self, *, device_id: str | None = None) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-logout",
                "email": "logout@example.test",
                "password": self.password,
                "device_id": device_id or self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _seed_resources(self) -> str:
        now = utc_now()
        with self.app.state.session_factory() as db:
            other_device = Device(
                tenant_id="tenant-logout",
                user_id=self.identity.user_id,
                name="other-device",
            )
            db.add(other_device)
            db.flush()
            current_task = Task(
                tenant_id="tenant-logout",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="logout-current-task",
                trace_id="logout-current-trace",
                status="created",
                expires_at=now + timedelta(minutes=5),
            )
            current_extra_task = Task(
                tenant_id="tenant-logout",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="logout-current-extra-task",
                trace_id="logout-current-extra-trace",
                status="created",
                expires_at=now + timedelta(minutes=5),
            )
            other_task = Task(
                tenant_id="tenant-logout",
                user_id=self.identity.user_id,
                device_id=other_device.id,
                task_type="mail_code",
                idempotency_key="logout-other-task",
                trace_id="logout-other-trace",
                status="created",
                expires_at=now + timedelta(minutes=5),
            )
            current_mailbox = Mailbox(
                tenant_id="tenant-logout",
                email_masked="c***@example.test",
                connector_type="fake",
                secret_ref="vault://mailboxes/logout-current",
            )
            other_mailbox = Mailbox(
                tenant_id="tenant-logout",
                email_masked="o***@example.test",
                connector_type="fake",
                secret_ref="vault://mailboxes/logout-other",
            )
            current_card = Card(
                tenant_id="tenant-logout",
                provider_ref="logout-current-card",
                brand="visa",
                last4="1111",
                secret_ref="vault://cards/logout-current",
            )
            other_card = Card(
                tenant_id="tenant-logout",
                provider_ref="logout-other-card",
                brand="visa",
                last4="2222",
                secret_ref="vault://cards/logout-other",
            )
            db.add_all(
                [
                    current_task,
                    current_extra_task,
                    other_task,
                    current_mailbox,
                    other_mailbox,
                    current_card,
                    other_card,
                ]
            )
            db.flush()
            current_allocation = CardAllocation(
                tenant_id="tenant-logout",
                task_id=current_task.id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=current_card.id,
                trace_id=current_task.trace_id,
                status="active",
                expires_at=now + timedelta(minutes=5),
            )
            other_allocation = CardAllocation(
                tenant_id="tenant-logout",
                task_id=other_task.id,
                user_id=self.identity.user_id,
                device_id=other_device.id,
                card_id=other_card.id,
                trace_id=other_task.trace_id,
                status="active",
                expires_at=now + timedelta(minutes=5),
            )
            current_session = MailSession(
                tenant_id="tenant-logout",
                task_id=current_task.id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                mailbox_id=current_mailbox.id,
                trace_id=current_task.trace_id,
                status="consumed",
                start_watermark="connector-watermark-before-logout",
                last_message_hash="c" * 64,
                delivered_code="246810",
                delivered_at=now,
                code_expires_at=now + timedelta(minutes=1),
                consumed_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            other_session = MailSession(
                tenant_id="tenant-logout",
                task_id=other_task.id,
                user_id=self.identity.user_id,
                device_id=other_device.id,
                mailbox_id=other_mailbox.id,
                trace_id=other_task.trace_id,
                status="waiting",
                expires_at=now + timedelta(minutes=5),
            )
            db.add_all(
                [
                    current_allocation,
                    other_allocation,
                    current_session,
                    other_session,
                ]
            )
            db.flush()
            current_upload = UploadJob(
                tenant_id="tenant-logout",
                task_id=current_task.id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_allocation_id=current_allocation.id,
                idempotency_key="logout-current-upload",
                business_name="Current business",
                trace_id=current_task.trace_id,
                status="queued",
                policy_version="test-v1",
            )
            other_upload = UploadJob(
                tenant_id="tenant-logout",
                task_id=other_task.id,
                user_id=self.identity.user_id,
                device_id=other_device.id,
                card_allocation_id=other_allocation.id,
                idempotency_key="logout-other-upload",
                business_name="Other business",
                trace_id=other_task.trace_id,
                status="queued",
                policy_version="test-v1",
            )
            db.add_all([current_upload, other_upload])
            db.flush()
            db.add_all(
                [
                    OutboxEvent(
                        tenant_id="tenant-logout",
                        event_type="upload.requested",
                        aggregate_type="upload_job",
                        aggregate_id=current_upload.id,
                    ),
                    OutboxEvent(
                        tenant_id="tenant-logout",
                        event_type="upload.requested",
                        aggregate_type="upload_job",
                        aggregate_id=other_upload.id,
                    ),
                ]
            )
            db.commit()
            self.current_ids = {
                "task": current_task.id,
                "extra_task": current_extra_task.id,
                "allocation": current_allocation.id,
                "session": current_session.id,
                "upload": current_upload.id,
            }
            self.other_ids = {
                "task": other_task.id,
                "allocation": other_allocation.id,
                "session": other_session.id,
                "upload": other_upload.id,
            }
            return other_device.id

    def test_logout_releases_only_current_device_resources_idempotently(self) -> None:
        token = self.login()
        other_token = self.login(device_id=self.other_device_id)
        first = self.request(
            "POST", "/api/v1/auth/logout", headers=self.bearer(token)
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json(), {"status": "logged_out"})

        second = self.request(
            "POST", "/api/v1/auth/logout", headers=self.bearer(token)
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json(), {"status": "logged_out"})
        self.assertEqual(
            self.request("GET", "/api/v1/me", headers=self.bearer(token)).status_code,
            401,
        )
        late_task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "after-logout"},
        )
        self.assertEqual(late_task.status_code, 401, late_task.text)
        self.assertEqual(
            self.request(
                "GET", "/api/v1/me", headers=self.bearer(other_token)
            ).status_code,
            200,
        )

        replacement_token = self.login()
        self.assertNotEqual(replacement_token, token)
        self.assertEqual(
            self.request(
                "GET", "/api/v1/me", headers=self.bearer(replacement_token)
            ).status_code,
            200,
        )

        with self.app.state.session_factory() as db:
            current_task = db.get(Task, self.current_ids["task"])
            current_extra_task = db.get(Task, self.current_ids["extra_task"])
            current_allocation = db.get(
                CardAllocation, self.current_ids["allocation"]
            )
            current_session = db.get(MailSession, self.current_ids["session"])
            current_upload = db.get(UploadJob, self.current_ids["upload"])
            current_outbox = db.scalar(
                select(OutboxEvent).where(
                    OutboxEvent.aggregate_id == current_upload.id
                )
            )
            self.assertEqual(current_task.status, "cancelled")
            self.assertEqual(current_extra_task.status, "cancelled")
            self.assertEqual(current_allocation.status, "released")
            self.assertIsNotNone(current_allocation.released_at)
            self.assertEqual(current_session.status, "revoked")
            self.assertIsNone(current_session.delivered_code)
            self.assertIsNone(current_session.delivered_at)
            self.assertIsNone(current_session.code_expires_at)
            self.assertIsNone(current_session.start_watermark)
            self.assertIsNone(current_session.last_message_hash)
            self.assertEqual(current_upload.status, "cancelled")
            self.assertEqual(current_outbox.status, "processed")

            other_task = db.get(Task, self.other_ids["task"])
            other_allocation = db.get(CardAllocation, self.other_ids["allocation"])
            other_session = db.get(MailSession, self.other_ids["session"])
            other_upload = db.get(UploadJob, self.other_ids["upload"])
            self.assertEqual(other_task.status, "created")
            self.assertEqual(other_allocation.status, "active")
            self.assertIsNone(other_allocation.released_at)
            self.assertEqual(other_session.status, "waiting")
            self.assertEqual(other_upload.status, "queued")
            self.assertIsNone(db.get(Device, self.identity.device_id).revoked_at)
            self.assertIsNone(db.get(Device, self.other_device_id).revoked_at)

            resource_events = db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.event_type.in_(
                        (
                            "task.cancelled",
                            "card.released",
                            "mail_session.revoked",
                            "upload.cancel_requested",
                        )
                    ),
                    AuditEvent.entity_id.in_(tuple(self.current_ids.values())),
                )
            )
            logout_events = db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event_type == "auth.logout")
            )
            revoked_tokens = list(db.scalars(select(RevokedAccessToken)))
            self.assertEqual(resource_events, 5)
            self.assertEqual(logout_events, 1)
            self.assertEqual(len(revoked_tokens), 1)
            self.assertEqual(len(revoked_tokens[0].token_hash), 64)
            self.assertNotIn(token, revoked_tokens[0].token_hash)
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(Task)
                    .where(Task.idempotency_key == "after-logout")
                ),
                0,
            )

    def test_logout_requires_interactive_auth_without_side_effects(self) -> None:
        unauthenticated = self.request("POST", "/api/v1/auth/logout")
        self.assertEqual(unauthenticated.status_code, 401)

        worker = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-logout",
            email="logout-worker@example.test",
            password="logout-worker-password",
            device_name="logout-worker-device",
            role=ROLE_WORKER_SERVICE,
        )
        worker_token = create_access_token(
            secret=self.app.state.jwt_hmac_secret,
            user_id=worker.user_id,
            tenant_id="tenant-logout",
            device_id=worker.device_id,
            ttl_seconds=300,
            role=ROLE_WORKER_SERVICE,
        )
        forbidden = self.request(
            "POST", "/api/v1/auth/logout", headers=self.bearer(worker_token)
        )
        self.assertEqual(forbidden.status_code, 401)

        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, self.current_ids["task"]).status, "created")
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "auth.logout")
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
