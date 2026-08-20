import asyncio
import csv
import io
import unittest
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from platform.app import create_app
from platform.bootstrap import create_oidc_user_with_device, create_user_with_device
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
    User,
    utc_now,
)


class PlatformAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.account_password = "test-account-password"
        self.app = create_app(
            Settings(
                app_name="test-platform",
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="unit-test-hmac-secret-that-is-not-for-production",
            )
        )
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="first@example.test",
            password=self.account_password,
            device_name="test-device-1",
        )

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

    def login(
        self,
        *,
        tenant_id: str = "tenant-a",
        email: str = "first@example.test",
        password: str | None = None,
        device_id: str | None = None,
    ) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": tenant_id,
                "email": email,
                "password": password or self.account_password,
                "device_id": device_id or self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_versioned_health_and_trace_header(self) -> None:
        response = self.request(
            "GET", "/api/v1/health", headers={"X-Trace-Id": "00000000-0000-0000-0000-000000000001"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(
            response.headers["X-Trace-Id"], "00000000-0000-0000-0000-000000000001"
        )

    def test_readyz_checks_database_dependency(self) -> None:
        response = self.request("GET", "/readyz")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["checks"]["database"], "ok")

        class BrokenEngine:
            def connect(self):
                raise RuntimeError("database offline")

        original_engine = self.app.state.engine
        self.app.state.engine = BrokenEngine()
        try:
            degraded = self.request("GET", "/readyz")
        finally:
            self.app.state.engine = original_engine
        self.assertEqual(degraded.status_code, 503, degraded.text)
        self.assertEqual(degraded.json()["status"], "degraded")
        self.assertEqual(degraded.json()["checks"]["database"], "unavailable")

    def test_metrics_reports_request_counters_without_sensitive_labels(self) -> None:
        token = self.login()
        self.request("GET", "/api/v1/me", headers=self.bearer(token))
        self.request("GET", "/api/v1/missing")

        response = self.request("GET", "/metrics")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(
            'platform_http_requests_total{method="GET",path="/me",status_code="200"} 1',
            response.text,
        )
        self.assertIn(
            'platform_http_requests_total{method="GET",path="/api/v1/missing",status_code="404"} 1',
            response.text,
        )
        self.assertNotIn(self.account_password, response.text)
        self.assertNotIn(token, response.text)
        self.assertNotIn("first@example.test", response.text)

    def test_dashboard_summary_is_role_scoped_and_aggregate_only(self) -> None:
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="dashboard-admin@example.test",
            password="dashboard-admin-password",
            device_name="dashboard-admin-device",
            role="ops_admin",
        )
        now = utc_now()
        with self.app.state.session_factory() as db:
            own_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="card_checkout",
                idempotency_key="dashboard-own-task",
                status="created",
                expires_at=now + timedelta(minutes=15),
            )
            other_task = Task(
                tenant_id="tenant-a",
                user_id=other.user_id,
                device_id=other.device_id,
                task_type="card_checkout",
                idempotency_key="dashboard-other-task",
                status="created",
                expires_at=now + timedelta(minutes=15),
            )
            closed_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="dashboard-closed-task",
                status="closed",
                closed_at=now,
                expires_at=now + timedelta(minutes=15),
            )
            db.add_all([own_task, other_task, closed_task])
            db.flush()
            own_mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="f***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/private-one",
            )
            other_mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="a***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/private-two",
            )
            own_card = Card(
                tenant_id="tenant-a",
                provider_ref="dashboard-card-private-one",
                brand="VISA",
                last4="4242",
                secret_ref="vault://cards/private-one",
            )
            other_card = Card(
                tenant_id="tenant-a",
                provider_ref="dashboard-card-private-two",
                brand="VISA",
                last4="1881",
                secret_ref="vault://cards/private-two",
            )
            db.add_all([own_mailbox, other_mailbox, own_card, other_card])
            db.flush()
            own_allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=own_task.id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=own_card.id,
                status="active",
                expires_at=now + timedelta(minutes=15),
            )
            other_allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=other_task.id,
                user_id=other.user_id,
                device_id=other.device_id,
                card_id=other_card.id,
                status="active",
                expires_at=now + timedelta(minutes=15),
            )
            db.add_all([own_allocation, other_allocation])
            db.flush()
            db.add_all(
                [
                    MailSession(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        mailbox_id=own_mailbox.id,
                        status="waiting",
                        expires_at=now + timedelta(minutes=5),
                    ),
                    MailSession(
                        tenant_id="tenant-a",
                        task_id=other_task.id,
                        user_id=other.user_id,
                        device_id=other.device_id,
                        mailbox_id=other_mailbox.id,
                        status="waiting",
                        expires_at=now + timedelta(minutes=5),
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_allocation_id=own_allocation.id,
                        idempotency_key="dashboard-own-upload",
                        business_name="Private Store One",
                        status="queued",
                        policy_version="sub2-v1",
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=other_task.id,
                        user_id=other.user_id,
                        device_id=other.device_id,
                        card_allocation_id=other_allocation.id,
                        idempotency_key="dashboard-other-upload",
                        business_name="Private Store Two",
                        status="unknown",
                        policy_version="sub2-v1",
                    ),
                ]
            )
            db.commit()

        operator_token = self.login()
        own_summary = self.request(
            "GET", "/api/v1/dashboard/summary", headers=self.bearer(operator_token)
        )
        self.assertEqual(own_summary.status_code, 200, own_summary.text)
        self.assertEqual(own_summary.json()["scope"], "own")
        self.assertEqual(own_summary.json()["active_tasks"], 1)
        self.assertEqual(own_summary.json()["allocated_cards"], 1)
        self.assertEqual(own_summary.json()["waiting_mail_sessions"], 1)
        self.assertEqual(own_summary.json()["queued_uploads"], 1)
        self.assertEqual(own_summary.json()["unknown_uploads"], 0)
        self.assertEqual(own_summary.json()["task_statuses"], {"closed": 1, "created": 1})

        admin_token = self.login(
            email="dashboard-admin@example.test",
            password="dashboard-admin-password",
            device_id=other.device_id,
        )
        tenant_summary = self.request(
            "GET", "/api/v1/dashboard/summary", headers=self.bearer(admin_token)
        )
        self.assertEqual(tenant_summary.status_code, 200, tenant_summary.text)
        self.assertEqual(tenant_summary.json()["scope"], "tenant")
        self.assertEqual(tenant_summary.json()["active_tasks"], 2)
        self.assertEqual(tenant_summary.json()["allocated_cards"], 2)
        self.assertEqual(tenant_summary.json()["waiting_mail_sessions"], 2)
        self.assertEqual(tenant_summary.json()["queued_uploads"], 1)
        self.assertEqual(tenant_summary.json()["unknown_uploads"], 1)
        for forbidden in (
            "Private Store",
            "vault://",
            "4242",
            "1881",
            "dashboard-card-private",
        ):
            self.assertNotIn(forbidden, tenant_summary.text)

    def test_mailboxes_list_masks_configuration_and_reports_status(self) -> None:
        token = self.login()
        now = utc_now()
        with self.app.state.session_factory() as db:
            task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="mailbox-status-task",
                status="created",
                expires_at=now + timedelta(minutes=15),
            )
            available = Mailbox(
                tenant_id="tenant-a",
                email_masked="a***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/available-secret",
                is_active=True,
            )
            busy = Mailbox(
                tenant_id="tenant-a",
                email_masked="b***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/busy-secret",
                is_active=True,
            )
            disabled = Mailbox(
                tenant_id="tenant-a",
                email_masked="d***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/disabled-secret",
                is_active=False,
            )
            foreign = Mailbox(
                tenant_id="tenant-b",
                email_masked="x***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/foreign-secret",
                is_active=True,
            )
            db.add_all([task, available, busy, disabled, foreign])
            db.flush()
            db.add(
                MailSession(
                    tenant_id="tenant-a",
                    task_id=task.id,
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    mailbox_id=busy.id,
                    status="waiting",
                    expires_at=now + timedelta(minutes=5),
                )
            )
            db.commit()

        response = self.request(
            "GET", "/api/v1/mailboxes", headers=self.bearer(token)
        )
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()
        self.assertEqual(len(rows), 3)
        statuses = {row["email_masked"]: row["status"] for row in rows}
        self.assertEqual(statuses["a***@example.test"], "available")
        self.assertEqual(statuses["b***@example.test"], "busy")
        self.assertEqual(statuses["d***@example.test"], "disabled")
        busy_row = next(row for row in rows if row["email_masked"] == "b***@example.test")
        self.assertEqual(busy_row["active_session_count"], 1)
        for forbidden in (
            "secret_ref",
            "vault://",
            "available-secret",
            "busy-secret",
            "disabled-secret",
            "foreign-secret",
            "x***@example.test",
        ):
            self.assertNotIn(forbidden, response.text)

    def test_not_found_uses_error_envelope(self) -> None:
        response = self.request("GET", "/api/v1/missing")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")
        self.assertTrue(response.json()["error"]["recovery_hint"])
        self.assertTrue(response.json()["error"]["trace_id"])

    def test_me_requires_bearer_authentication(self) -> None:
        response = self.request("GET", "/api/v1/me")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "unauthorized")
        self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")

    def test_login_and_me_use_platform_account(self) -> None:
        token = self.login()
        response = self.request(
            "GET", "/api/v1/me", headers=self.bearer(token)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], self.identity.user_id)
        self.assertEqual(response.json()["device_id"], self.identity.device_id)

    def test_tasks_are_isolated_by_owner(self) -> None:
        first_token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(first_token),
            json={
                "type": "mail_code",
                "idempotency_key": "request-owner-1",
                "client_reference": "client-001",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]

        second_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="second@example.test",
            password="second-account-password",
            device_name="test-device-2",
        )
        second_token = self.login(
            email="second@example.test",
            password="second-account-password",
            device_id=second_identity.device_id,
        )
        hidden = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(second_token)
        )
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.json()["error"]["code"], "not_found")
        listed = self.request(
            "GET", "/api/v1/tasks", headers=self.bearer(second_token)
        )
        self.assertEqual(listed.json(), [])

    def test_task_history_is_newest_first_and_bounded(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        created_ids = []
        for index in range(3):
            response = self.request(
                "POST",
                "/api/v1/tasks",
                headers=headers,
                json={
                    "type": "mail_code",
                    "idempotency_key": f"history-{index}",
                },
            )
            self.assertEqual(response.status_code, 201, response.text)
            created_ids.append(response.json()["id"])

        listed = self.request(
            "GET", "/api/v1/tasks?limit=2", headers=headers
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(len(listed.json()), 2)
        self.assertEqual(listed.json()[0]["id"], created_ids[-1])
        self.assertEqual(listed.json()[1]["id"], created_ids[-2])
        rejected = self.request(
            "GET", "/api/v1/tasks?limit=101", headers=headers
        )
        self.assertEqual(rejected.status_code, 422)

    def test_disabled_user_invalidates_existing_token(self) -> None:
        token = self.login()
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.is_active = False
            db.commit()
        response = self.request(
            "GET", "/api/v1/me", headers=self.bearer(token)
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "unauthorized")

    def test_revoked_device_invalidates_existing_token(self) -> None:
        token = self.login()
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            self.assertIsNotNone(device)
            device.revoked_at = utc_now()
            db.commit()
        response = self.request(
            "GET", "/api/v1/me", headers=self.bearer(token)
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "unauthorized")

    def test_owner_device_revoke_cancels_tasks_and_invalidates_token(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=headers,
            json={"type": "mail_code", "idempotency_key": "self-revoke-task"},
        )
        self.assertEqual(task.status_code, 201, task.text)
        revoked = self.request(
            "POST",
            f"/api/v1/devices/{self.identity.device_id}/revoke",
            headers=headers,
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertIsNotNone(revoked.json()["revoked_at"])
        denied = self.request("GET", "/api/v1/me", headers=headers)
        self.assertEqual(denied.status_code, 401, denied.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(Task, task.json()["id"])
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.status, "cancelled")

    def test_audit_never_contains_credentials(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "mail_code",
                "idempotency_key": "request-audit-1",
                "client_reference": "reference 4111 1111 1111 1111 must redact",
            },
        )
        self.assertEqual(created.status_code, 201)
        with self.app.state.session_factory() as db:
            events = list(db.scalars(select(AuditEvent)))
        self.assertEqual([event.event_type for event in events], ["auth.login", "task.created"])
        audit_text = "\n".join(
            f"{event.event_type} {event.details_json}" for event in events
        )
        self.assertNotIn(self.account_password, audit_text)
        self.assertNotIn(token, audit_text)
        self.assertNotIn("password", audit_text.lower())
        self.assertNotIn("token", audit_text.lower())
        self.assertNotIn("4111 1111 1111 1111", audit_text)
        self.assertIn("[REDACTED_CARD]", audit_text)

    def test_admin_audit_supports_tenant_scoped_trace_filters(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "audit-filter-1"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        trace_id = created.json()["trace_id"]
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.role = "security_auditor"
            db.commit()
        auditor_token = self.login()

        filtered = self.request(
            "GET",
            f"/api/v1/admin/audit?trace_id={trace_id}&event_type=task.created",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(filtered.status_code, 200, filtered.text)
        self.assertEqual(len(filtered.json()), 1)
        self.assertEqual(filtered.json()[0]["trace_id"], trace_id)
        self.assertEqual(filtered.json()[0]["event_type"], "task.created")

    def test_audit_evidence_fields_and_redacted_csv_export(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers={
                **self.bearer(token),
                "X-Real-IP": "203.0.113.18",
                "User-Agent": "Evidence Client/1.0",
            },
            json={
                "type": "mail_code",
                "idempotency_key": "must-not-appear-in-export",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        trace_id = created.json()["trace_id"]
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.role = "security_auditor"
            db.add(
                AuditEvent(
                    tenant_id="tenant-a",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    actor_id=self.identity.user_id,
                    event_type="formula.test",
                    action="formula.test",
                    result="success",
                    entity_type="task",
                    entity_id="=1+1",
                    trace_id="00000000-0000-0000-0000-000000000099",
                    user_agent="@formula-agent",
                    details_json='{"password":"must-not-export"}',
                )
            )
            db.commit()
        auditor_token = self.login()

        response = self.request(
            "GET",
            f"/api/v1/admin/audit?trace_id={trace_id}&result=success",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()), 1)
        event = response.json()[0]
        self.assertEqual(event["actor_id"], self.identity.user_id)
        self.assertEqual(event["action"], "task.created")
        self.assertEqual(event["result"], "success")
        self.assertEqual(event["ip_address"], "203.0.113.18")
        self.assertEqual(event["user_agent"], "Evidence Client/1.0")

        exported = self.request(
            "GET",
            "/api/v1/admin/audit/export?entity_type=task&limit=100",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertIn("text/csv", exported.headers["content-type"])
        self.assertEqual(exported.headers["cache-control"], "no-store")
        csv_text = exported.content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        self.assertTrue(rows)
        self.assertIn("actor_id", rows[0])
        self.assertNotIn("details", rows[0])
        serialized = csv_text.lower()
        self.assertNotIn("must-not-appear-in-export", serialized)
        self.assertNotIn("must-not-export", serialized)
        formula_row = next(row for row in rows if row["action"] == "formula.test")
        self.assertEqual(formula_row["entity_id"], "'=1+1")
        self.assertEqual(formula_row["user_agent"], "'@formula-agent")

        tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
        empty = self.request(
            "GET",
            "/api/v1/admin/audit",
            params={"created_from": tomorrow.isoformat()},
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(empty.status_code, 200, empty.text)
        self.assertEqual(empty.json(), [])

    def test_audit_export_is_tenant_scoped_and_role_protected(self) -> None:
        operator_token = self.login()
        forbidden = self.request(
            "GET",
            "/api/v1/admin/audit/export",
            headers=self.bearer(operator_token),
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)

        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-b",
            email="other-auditor@example.test",
            password="other-auditor-password",
            device_name="other-auditor-device",
            role="security_auditor",
        )
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.role = "security_auditor"
            db.add(
                AuditEvent(
                    tenant_id="tenant-b",
                    user_id=other.user_id,
                    device_id=other.device_id,
                    actor_id=other.user_id,
                    event_type="tenant-b.hidden",
                    action="tenant-b.hidden",
                    result="success",
                    entity_type="task",
                    entity_id="other-tenant-resource",
                    trace_id="00000000-0000-0000-0000-000000000098",
                    details_json="{}",
                )
            )
            db.commit()
        auditor_token = self.login()
        exported = self.request(
            "GET",
            "/api/v1/admin/audit/export",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertNotIn("tenant-b.hidden", exported.text)
        self.assertNotIn("other-tenant-resource", exported.text)

    def test_task_idempotency_is_scoped_to_owner_and_payload(self) -> None:
        token = self.login()
        payload = {
            "type": "mail_code",
            "idempotency_key": "request-idempotent-1",
            "client_reference": "client-123",
        }
        first = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json=payload,
        )
        replay = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json=payload,
        )
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], first.json()["id"])
        self.assertEqual(replay.json()["device_id"], self.identity.device_id)

        conflict = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={**payload, "type": "sub2_upload"},
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "conflict")

        with self.app.state.session_factory() as db:
            task_events = list(
                db.scalars(
                    select(AuditEvent).where(AuditEvent.event_type == "task.created")
                )
            )
        self.assertEqual(len(task_events), 1)

    def test_task_device_is_derived_from_bearer_token(self) -> None:
        token = self.login()
        response = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "mail_code",
                "idempotency_key": "request-device-1",
                "device_id": "caller-controlled-device",
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "validation_error")

    def test_closed_and_expired_tasks_remain_viewable_but_terminal(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        closed = self.request(
            "POST",
            "/api/v1/tasks",
            headers=headers,
            json={"type": "mail_code", "idempotency_key": "task-close-visible"},
        )
        closed_id = closed.json()["id"]
        close_response = self.request(
            "POST", f"/api/v1/tasks/{closed_id}/close", headers=headers
        )
        self.assertEqual(close_response.status_code, 200, close_response.text)
        self.assertEqual(close_response.json()["status"], "closed")
        viewed_closed = self.request(
            "GET", f"/api/v1/tasks/{closed_id}", headers=headers
        )
        self.assertEqual(viewed_closed.status_code, 200, viewed_closed.text)
        self.assertEqual(viewed_closed.json()["status"], "closed")

        expiring = self.request(
            "POST",
            "/api/v1/tasks",
            headers=headers,
            json={"type": "mail_code", "idempotency_key": "task-expire-visible"},
        )
        expiring_id = expiring.json()["id"]
        with self.app.state.session_factory() as db:
            task = db.get(Task, expiring_id)
            self.assertIsNotNone(task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        viewed_expired = self.request(
            "GET", f"/api/v1/tasks/{expiring_id}", headers=headers
        )
        self.assertEqual(viewed_expired.status_code, 200, viewed_expired.text)
        self.assertEqual(viewed_expired.json()["status"], "expired")
        with self.app.state.session_factory() as db:
            expired_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.expired",
                        AuditEvent.entity_id == expiring_id,
                    )
                )
            )
        self.assertEqual(len(expired_events), 1)

    def test_closing_task_atomically_stops_resources_and_audits_each_action(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=headers,
            json={"type": "mail_code", "idempotency_key": "task-close-resources"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        now = utc_now()
        with self.app.state.session_factory() as db:
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="c***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/task-close-resources",
            )
            card = Card(
                tenant_id="tenant-a",
                provider_ref="task-close-card",
                brand="VISA",
                last4="4242",
                secret_ref="vault://cards/task-close-resources",
            )
            db.add_all([mailbox, card])
            db.flush()
            allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=card.id,
                status="active",
                expires_at=now + timedelta(minutes=30),
            )
            session = MailSession(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                mailbox_id=mailbox.id,
                status="code_ready",
                delivered_code="123456",
                delivered_at=now,
                expires_at=now + timedelta(minutes=10),
            )
            db.add_all([allocation, session])
            db.flush()
            queued = UploadJob(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="task-close-upload-queued",
                business_name="Queued Business",
                status="queued",
                policy_version="sub2-v1",
            )
            running = UploadJob(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="task-close-upload-running",
                business_name="Running Business",
                status="running",
                policy_version="sub2-v1",
            )
            db.add_all([queued, running])
            db.commit()
            allocation_id = allocation.id
            session_id = session.id
            queued_id = queued.id
            running_id = running.id

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")

        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocation_id)
            session = db.get(MailSession, session_id)
            queued = db.get(UploadJob, queued_id)
            running = db.get(UploadJob, running_id)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertEqual(queued.status, "cancelled")
            self.assertEqual(running.status, "cancel_pending")
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_(
                            [allocation_id, session_id, queued_id, running_id]
                        )
                    )
                )
            )
            self.assertEqual(
                sorted(event.event_type for event in events),
                [
                    "card.released",
                    "mail_session.revoked",
                    "upload.cancel_requested",
                    "upload.cancel_requested",
                ],
            )

        replay = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        with self.app.state.session_factory() as db:
            replay_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_(
                            [allocation_id, session_id, queued_id, running_id]
                        )
                    )
                )
            )
        self.assertEqual(len(replay_events), 4)

    def test_login_validation_does_not_reflect_password_input(self) -> None:
        rejected_secret = "super-secret-value-" + "x" * 1024
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": rejected_secret,
                "device_id": self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "validation_error")
        self.assertNotIn(rejected_secret, response.text)
        for detail in response.json()["error"]["details"]:
            self.assertNotIn("input", detail)

    def test_openapi_describes_phase_one_contract(self) -> None:
        response = self.request("GET", "/api/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        for path in (
            "/api/v1/auth/login",
            "/api/v1/me",
            "/api/v1/dashboard/summary",
            "/api/v1/mailboxes",
            "/api/v1/tasks",
            "/api/v1/tasks/{task_id}",
        ):
            self.assertIn(path, schema["paths"])
        self.assertIn("HTTPBearer", schema["components"]["securitySchemes"])
        task_schema = schema["components"]["schemas"]["TaskCreate"]
        self.assertEqual(
            set(task_schema["required"]), {"type", "idempotency_key"}
        )
        self.assertNotIn("device_id", task_schema["properties"])

    def test_production_requires_oidc_and_rejects_local_auth(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "AUTH_MODE=oidc"):
            create_app(
                Settings(
                    environment="production",
                    database_url="sqlite+pysqlite:///:memory:",
                )
            )

        with self.assertRaisesRegex(RuntimeError, "OIDC_ISSUER_URL"):
            create_app(
                Settings(
                    environment="production",
                    auth_mode="oidc",
                    database_url="sqlite+pysqlite:///:memory:",
                )
            )

    def test_oidc_mode_uses_external_subject_and_disables_local_login(self) -> None:
        class FakeOidcVerifier:
            def __init__(self, claims: dict[str, str]) -> None:
                self.claims = claims

            def verify(self, token: str) -> dict[str, str]:
                if token != "signed-by-test-issuer":
                    raise ValueError("invalid")
                return self.claims

        oidc_settings = Settings(
            environment="test",
            auth_mode="oidc",
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer_url="https://identity.example.test/realms/platform",
            oidc_audience="email-platform-api",
            oidc_client_id="email-platform-web",
            oidc_desktop_client_id="email-platform-desktop",
            oidc_jwks_url="https://identity.example.test/realms/platform/protocol/openid-connect/certs",
        )
        oidc_app = create_app(oidc_settings, access_token_verifier=FakeOidcVerifier({}))
        identity = create_oidc_user_with_device(
            oidc_app.state.session_factory,
            tenant_id="tenant-oidc",
            email="oidc@example.test",
            oidc_subject="keycloak-user-001",
            device_name="oidc-device",
        )
        oidc_app.state.access_token_verifier = FakeOidcVerifier(
            {
                "sub": "keycloak-user-001",
                "tenant_id": "tenant-oidc",
                "device_id": identity.device_id,
                "identity_kind": "oidc",
            }
        )

        async def run(method: str, path: str, **kwargs: object) -> httpx.Response:
            transport = httpx.ASGITransport(app=oidc_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        config = asyncio.run(run("GET", "/api/v1/auth/config"))
        self.assertEqual(config.status_code, 200)
        self.assertEqual(config.json()["mode"], "oidc")
        self.assertNotIn("secret", config.text.lower())
        local_login = asyncio.run(
            run(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-oidc",
                    "email": "oidc@example.test",
                    "password": "must-not-be-used",
                    "device_id": identity.device_id,
                },
            )
        )
        self.assertEqual(local_login.status_code, 404)
        me = asyncio.run(
            run(
                "GET",
                "/api/v1/me",
                headers={"Authorization": "Bearer signed-by-test-issuer"},
            )
        )
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["email"], "oidc@example.test")
        oidc_app.state.engine.dispose()


if __name__ == "__main__":
    unittest.main()
