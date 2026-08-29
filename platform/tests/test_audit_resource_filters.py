import asyncio
import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx
from sqlalchemy import select

from platform.app import create_app
from platform.audit import record_audit
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    Device,
    Mailbox,
    MailSession,
    Task,
    UploadJob,
    utc_now,
)


class AuditResourceFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="audit-resource-filter-")
        database_path = Path(self.directory.name) / "platform.db"
        self.app = create_app(
            Settings(
                environment="test",
                database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                jwt_hmac_secret="audit-resource-filter-test-secret",
            )
        )
        self.auditor = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="auditor@example.test",
            password="audit-resource-filter-password",
            device_name="auditor-device",
            role="security_auditor",
        )
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-b",
            email="other@example.test",
            password="audit-resource-other-password",
            device_name="other-device",
        )
        self.token = self._login(
            "tenant-a",
            "auditor@example.test",
            "audit-resource-filter-password",
            self.auditor.device_id,
        )
        with self.app.state.session_factory() as db:
            shared_trace = "00000000-0000-4000-8000-000000000099"
            sibling_device = Device(
                tenant_id="tenant-a",
                user_id=self.auditor.user_id,
                name="auditor-sibling-device",
            )
            db.add(sibling_device)
            db.flush()
            task = Task(
                tenant_id="tenant-a",
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                task_type="card_checkout",
                idempotency_key="resource-filter-task",
                trace_id=shared_trace,
                status="completed",
                expires_at=utc_now() + timedelta(minutes=30),
            )
            same_trace_task = Task(
                tenant_id="tenant-a",
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                task_type="card_checkout",
                idempotency_key="resource-filter-same-trace-task",
                trace_id=shared_trace,
                status="completed",
                expires_at=utc_now() + timedelta(minutes=30),
            )
            other_task = Task(
                tenant_id="tenant-b",
                user_id=other.user_id,
                device_id=other.device_id,
                task_type="card_checkout",
                idempotency_key="resource-filter-other-task",
                trace_id="00000000-0000-4000-8000-000000000100",
                status="completed",
                expires_at=utc_now() + timedelta(minutes=30),
            )
            card = Card(
                tenant_id="tenant-a",
                provider_ref="resource-filter-card",
                brand="VISA",
                last4="4242",
                secret_ref="vault://cards/resource-filter-card",
            )
            same_trace_card = Card(
                tenant_id="tenant-a",
                provider_ref="resource-filter-same-trace-card",
                brand="VISA",
                last4="1111",
                secret_ref="vault://cards/resource-filter-same-trace-card",
            )
            other_card = Card(
                tenant_id="tenant-b",
                provider_ref="resource-filter-other-card",
                brand="VISA",
                last4="2222",
                secret_ref="vault://cards/resource-filter-other-card",
            )
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="a***@example.invalid",
                connector_type="test",
                secret_ref="vault://mail/resource-filter",
            )
            db.add_all([task, same_trace_task, other_task, card, same_trace_card, other_card, mailbox])
            db.flush()
            allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=task.id,
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                card_id=card.id,
                trace_id=shared_trace,
                status="released",
                expires_at=utc_now() + timedelta(minutes=10),
                released_at=utc_now(),
            )
            same_trace_allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=same_trace_task.id,
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                card_id=same_trace_card.id,
                trace_id=shared_trace,
                status="released",
                expires_at=utc_now() + timedelta(minutes=10),
                released_at=utc_now(),
            )
            mail_session = MailSession(
                tenant_id="tenant-a",
                task_id=task.id,
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                mailbox_id=mailbox.id,
                trace_id=shared_trace,
                status="revoked",
                expires_at=utc_now() + timedelta(minutes=5),
            )
            db.add_all([allocation, same_trace_allocation, mail_session])
            db.flush()
            upload = UploadJob(
                tenant_id="tenant-a",
                task_id=task.id,
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="resource-filter-upload",
                business_name="Resource Filter",
                trace_id=shared_trace,
                status="succeeded",
                policy_version="test-v1",
            )
            same_trace_upload = UploadJob(
                tenant_id="tenant-a",
                task_id=same_trace_task.id,
                user_id=self.auditor.user_id,
                device_id=self.auditor.device_id,
                card_allocation_id=same_trace_allocation.id,
                idempotency_key="resource-filter-same-trace-upload",
                business_name="Other Resource Filter",
                trace_id=shared_trace,
                status="succeeded",
                policy_version="test-v1",
            )
            db.add_all([upload, same_trace_upload])
            db.flush()
            resources = (
                ("task.created", "task", task.id),
                ("mail_session.created", "mail_session", mail_session.id),
                ("card.allocated", "card_allocation", allocation.id),
                ("upload.succeeded", "upload_job", upload.id),
                ("admin.card_created", "card", card.id),
                ("task.created", "task", same_trace_task.id),
                ("card.allocated", "card_allocation", same_trace_allocation.id),
                ("upload.succeeded", "upload_job", same_trace_upload.id),
            )
            recorded_events: list[tuple[str, str, AuditEvent]] = []
            for event_type, entity_type, entity_id in resources:
                event = record_audit(
                    db,
                    tenant_id="tenant-a",
                    user_id=self.auditor.user_id,
                    device_id=self.auditor.device_id,
                    event_type=event_type,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    trace_id=shared_trace,
                )
                recorded_events.append((event_type, entity_id, event))
            sibling_device_event = record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.auditor.user_id,
                device_id=sibling_device.id,
                event_type="task.reviewed",
                entity_type="task",
                entity_id=task.id,
                trace_id=shared_trace,
            )
            other_event = record_audit(
                db,
                tenant_id="tenant-b",
                user_id=other.user_id,
                device_id=other.device_id,
                event_type="task.created",
                entity_type="task",
                entity_id=other_task.id,
                trace_id=other_task.trace_id,
            )
            target_event = recorded_events[0][2]
            target_event.created_at = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
            db.flush()
            event_ids = {
                (event_type, entity_id): event.id
                for event_type, entity_id, event in recorded_events
            }
            db.commit()
            self.task_id = task.id
            self.card_id = card.id
            self.other_task_id = other_task.id
            self.other_card_id = other_card.id
            self.other_device_id = other.device_id
            self.other_event_id = other_event.id
            self.sibling_device_id = sibling_device.id
            self.sibling_device_event_id = sibling_device_event.id
            self.target_event_id = target_event.id
            self.task_event_ids = {
                event_ids[("task.created", task.id)],
                event_ids[("mail_session.created", mail_session.id)],
                event_ids[("card.allocated", allocation.id)],
                event_ids[("upload.succeeded", upload.id)],
                sibling_device_event.id,
            }
            self.card_event_ids = {
                event_ids[("admin.card_created", card.id)],
                event_ids[("card.allocated", allocation.id)],
                event_ids[("upload.succeeded", upload.id)],
            }

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.directory.cleanup()

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def _login(self, tenant_id: str, email: str, password: str, device_id: str) -> str:
        response = self._request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": tenant_id,
                "email": email,
                "password": password,
                "device_id": device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def test_task_id_replays_only_that_tasks_cross_resource_chain(self) -> None:
        response = self._request(
            "GET",
            "/api/v1/admin/audit?" + urlencode({"task_id": self.task_id, "limit": 200}),
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({event["id"] for event in response.json()}, self.task_event_ids)

    def test_card_id_replays_card_allocation_and_upload_chain(self) -> None:
        response = self._request(
            "GET",
            "/api/v1/admin/audit?" + urlencode({"card_id": self.card_id, "limit": 200}),
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({event["id"] for event in response.json()}, self.card_event_ids)

    def test_resource_filters_are_tenant_scoped_and_shared_by_csv(self) -> None:
        for parameter, resource_id in (
            ("task_id", self.other_task_id),
            ("card_id", self.other_card_id),
        ):
            with self.subTest(parameter=parameter):
                response = self._request(
                    "GET",
                    "/api/v1/admin/audit?" + urlencode({parameter: resource_id}),
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json(), [])
                self.assertNotIn(self.other_event_id, response.text)

        exported = self._request(
            "GET",
            "/api/v1/admin/audit/export?" + urlencode({"task_id": self.task_id}),
            headers=self.headers,
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual({row["id"] for row in rows}, self.task_event_ids)
        with self.app.state.session_factory() as db:
            export_event = db.scalar(
                select(AuditEvent)
                .where(AuditEvent.event_type == "audit.exported")
                .order_by(AuditEvent.created_at.desc())
            )
            self.assertIsNotNone(export_event)
            filters = json.loads(export_event.details_json)["filters"]
        self.assertEqual(filters["task_id"], self.task_id)
        self.assertIsNone(filters["card_id"])

    def test_device_id_is_exact_tenant_scoped_and_shared_by_csv(self) -> None:
        query = {
            "device_id": self.sibling_device_id,
            "trace_id": "00000000-0000-4000-8000-000000000099",
            "limit": 200,
        }
        listed = self._request(
            "GET",
            "/api/v1/admin/audit?" + urlencode(query),
            headers=self.headers,
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(
            [event["id"] for event in listed.json()],
            [self.sibling_device_event_id],
        )

        partial = self._request(
            "GET",
            "/api/v1/admin/audit?"
            + urlencode({"device_id": self.sibling_device_id[:8], "trace_id": query["trace_id"]}),
            headers=self.headers,
        )
        self.assertEqual(partial.status_code, 200, partial.text)
        self.assertEqual(partial.json(), [])

        cross_tenant = self._request(
            "GET",
            "/api/v1/admin/audit?" + urlencode({"device_id": self.other_device_id}),
            headers=self.headers,
        )
        self.assertEqual(cross_tenant.status_code, 200, cross_tenant.text)
        self.assertEqual(cross_tenant.json(), [])

        exported = self._request(
            "GET",
            "/api/v1/admin/audit/export?" + urlencode(query),
            headers=self.headers,
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual([row["id"] for row in rows], [self.sibling_device_event_id])

    def test_user_device_task_time_and_trace_filters_are_combined(self) -> None:
        query = {
            "task_id": self.task_id,
            "user_id": self.auditor.user_id,
            "device_id": self.auditor.device_id,
            "trace_id": "00000000-0000-4000-8000-000000000099",
            "created_from": "2026-08-20T11:59:59+00:00",
            "created_to": "2026-08-20T12:00:01+00:00",
            "limit": 200,
        }
        listed = self._request(
            "GET",
            "/api/v1/admin/audit?" + urlencode(query),
            headers=self.headers,
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual([event["id"] for event in listed.json()], [self.target_event_id])

        exported = self._request(
            "GET",
            "/api/v1/admin/audit/export?" + urlencode(query),
            headers=self.headers,
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual([row["id"] for row in rows], [self.target_event_id])
        with self.app.state.session_factory() as db:
            export_event = db.scalar(
                select(AuditEvent)
                .where(AuditEvent.event_type == "audit.exported")
                .order_by(AuditEvent.created_at.desc())
            )
            self.assertIsNotNone(export_event)
            filters = json.loads(export_event.details_json)["filters"]
        self.assertEqual(filters["device_id"], self.auditor.device_id)


if __name__ == "__main__":
    unittest.main()
