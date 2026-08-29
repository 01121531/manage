import asyncio
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

import httpx
from sqlalchemy import select

from platform.app import create_app
from platform.audit import record_audit
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import AuditEvent


class AuditActionFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="audit-action-filter-")
        database_path = Path(self.directory.name) / "platform.db"
        self.app = create_app(
            Settings(
                environment="test",
                database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                jwt_hmac_secret="audit-action-filter-test-secret",
            )
        )
        self.admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="admin-a@example.test",
            password="audit-action-admin-password",
            device_name="admin-a-device",
            role="platform_admin",
        )
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-b",
            email="admin-b@example.test",
            password="audit-action-other-password",
            device_name="admin-b-device",
            role="platform_admin",
        )
        self.token = self._login(
            tenant_id="tenant-a",
            email="admin-a@example.test",
            password="audit-action-admin-password",
            device_id=self.admin.device_id,
        )
        with self.app.state.session_factory() as db:
            self.read_task = record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="task.created",
                action="resource.read",
                entity_type="task",
                entity_id="task-read",
                trace_id="audit-action-read-task",
            )
            self.write_task = record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="task.created",
                action="resource.write",
                entity_type="task",
                entity_id="task-write",
                trace_id="audit-action-write-task",
            )
            self.read_login = record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="auth.login",
                action="resource.read",
                entity_type="user",
                entity_id=self.admin.user_id,
                trace_id="audit-action-read-login",
            )
            self.other_tenant_read = record_audit(
                db,
                tenant_id="tenant-b",
                user_id=other.user_id,
                device_id=other.device_id,
                event_type="task.created",
                action="resource.read",
                entity_type="task",
                entity_id="other-tenant-task",
                trace_id="audit-action-other-tenant",
            )
            db.commit()
            self.expected_read_ids = {self.read_task.id, self.read_login.id}
            self.read_task_id = self.read_task.id
            self.other_tenant_read_id = self.other_tenant_read.id

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.directory.cleanup()

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def _login(
        self, *, tenant_id: str, email: str, password: str, device_id: str
    ) -> str:
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

    def test_action_filter_is_exact_and_tenant_scoped(self) -> None:
        matched = self._request(
            "GET", "/api/v1/admin/audit?action=resource.read", headers=self.headers
        )
        self.assertEqual(matched.status_code, 200, matched.text)
        self.assertEqual({item["id"] for item in matched.json()}, self.expected_read_ids)
        self.assertNotIn(self.other_tenant_read_id, matched.text)

        missed = self._request(
            "GET", "/api/v1/admin/audit?action=resource", headers=self.headers
        )
        self.assertEqual(missed.status_code, 200, missed.text)
        self.assertEqual(missed.json(), [])

        wrong_case = self._request(
            "GET", "/api/v1/admin/audit?action=Resource.Read", headers=self.headers
        )
        self.assertEqual(wrong_case.status_code, 200, wrong_case.text)
        self.assertEqual(wrong_case.json(), [])

    def test_event_type_and_action_are_intersected(self) -> None:
        query = urlencode({"event_type": "task.created", "action": "resource.read"})
        response = self._request(
            "GET", f"/api/v1/admin/audit?{query}", headers=self.headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([item["id"] for item in response.json()], [self.read_task_id])

    def test_list_and_csv_apply_the_same_action_filter(self) -> None:
        listed = self._request(
            "GET", "/api/v1/admin/audit?action=resource.read", headers=self.headers
        )
        exported = self._request(
            "GET",
            "/api/v1/admin/audit/export?" + urlencode({"action": " resource.read "}),
            headers=self.headers,
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(exported.status_code, 200, exported.text)
        rows = list(
            csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig")))
        )
        self.assertEqual(
            [row["id"] for row in rows], [item["id"] for item in listed.json()]
        )
        self.assertEqual({row["action"] for row in rows}, {"resource.read"})
        with self.app.state.session_factory() as db:
            export_event = db.scalar(
                select(AuditEvent).where(AuditEvent.event_type == "audit.exported")
            )
        self.assertIsNotNone(export_event)
        details = json.loads(export_event.details_json)
        self.assertEqual(set(details), {"filters", "limit", "row_count"})
        self.assertEqual(
            details["filters"],
            {
                "task_id": None,
                "card_id": None,
                "trace_id": None,
                "actor_id": None,
                "user_id": None,
                "device_id": None,
                "entity_type": None,
                "entity_id": None,
                "event_type": None,
                "action": "resource.read",
                "result": None,
                "created_from": None,
                "created_to": None,
            },
        )

    def test_invalid_action_parameters_return_422(self) -> None:
        for action in ("", "   ", "x" * 81):
            with self.subTest(length=len(action)):
                response = self._request(
                    "GET",
                    "/api/v1/admin/audit?" + urlencode({"action": action}),
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 422, response.text)


if __name__ == "__main__":
    unittest.main()
