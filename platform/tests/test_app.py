import asyncio
import csv
import hashlib
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from platform.app import create_app
from platform.auth import AuthPrincipal, get_current_principal, hash_password
from platform.bootstrap import create_oidc_user_with_device, create_user_with_device
from platform.config import Settings
from platform.lifecycle import LifecycleSweepResult
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

    def test_workbench_step_uses_canonical_resource_progress(self) -> None:
        from platform.api.v1.routes import _workbench_step

        cases = [
            ({}, "logged_in"),
            ({"has_card_allocation": True}, "card_allocated"),
            (
                {"has_card_allocation": True, "mail_status": "waiting"},
                "waiting_code",
            ),
            (
                {"has_card_allocation": True, "mail_status": "code_ready"},
                "waiting_code",
            ),
            (
                {"has_card_allocation": True, "mail_status": "consumed"},
                "code_received",
            ),
            (
                {
                    "has_card_allocation": True,
                    "mail_status": "consumed",
                    "upload_status": "running",
                },
                "uploading",
            ),
            (
                {
                    "has_card_allocation": True,
                    "mail_status": "consumed",
                    "upload_status": "unknown",
                },
                "uploading",
            ),
            (
                {
                    "task_status": "completed",
                    "has_card_allocation": True,
                    "mail_status": "consumed",
                    "upload_status": "succeeded",
                },
                "completed",
            ),
        ]
        for values, expected in cases:
            with self.subTest(expected=expected, values=values):
                self.assertEqual(_workbench_step(**values), expected)
        for upload_status in (
            "queued",
            "running",
            "failed",
            "unknown",
            "cancel_pending",
        ):
            with self.subTest(upload_status=upload_status):
                self.assertEqual(
                    _workbench_step(
                        has_card_allocation=True,
                        mail_status="consumed",
                        upload_status=upload_status,
                    ),
                    "uploading",
                )

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
        self.assertEqual(own_summary.json()["today_completed_uploads"], 0)
        self.assertEqual(own_summary.json()["today_succeeded_uploads"], 0)
        self.assertIsNone(own_summary.json()["available_cards"])
        self.assertLessEqual(len(own_summary.json()["recent_tasks"]), 5)

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
        self.assertEqual(tenant_summary.json()["available_cards"], 0)
        self.assertEqual(tenant_summary.json()["pending_exceptions"], 1)
        for task in tenant_summary.json()["recent_tasks"]:
            self.assertEqual(
                set(task),
                {"id", "type", "status", "trace_id", "created_at", "expires_at"},
            )
        for forbidden in (
            "Private Store",
            "vault://",
            "dashboard-card-private",
        ):
            self.assertNotIn(forbidden, tenant_summary.text)
        serialized_keys = json.dumps(tenant_summary.json(), sort_keys=True)
        for forbidden_key in ('"last4"', '"card_masked"', '"provider_ref"', '"secret_ref"'):
            self.assertNotIn(forbidden_key, serialized_keys)

    def test_dashboard_summary_uses_current_role_after_authentication(self) -> None:
        admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="stale-dashboard-admin@example.test",
            password="stale-dashboard-admin-password",
            device_name="stale-dashboard-admin-device",
            role="platform_admin",
        )
        now = utc_now()
        with self.app.state.session_factory() as db:
            db.add_all(
                [
                    Task(
                        tenant_id="tenant-a",
                        user_id=admin.user_id,
                        device_id=admin.device_id,
                        task_type="mail_code",
                        idempotency_key="stale-dashboard-own",
                        trace_id="trace-dashboard-own",
                        status="created",
                        expires_at=now + timedelta(minutes=15),
                    ),
                    Task(
                        tenant_id="tenant-a",
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        task_type="mail_code",
                        idempotency_key="stale-dashboard-other",
                        trace_id="trace-dashboard-other",
                        status="created",
                        expires_at=now + timedelta(minutes=15),
                    ),
                ]
            )
            current_admin = db.get(User, admin.user_id)
            current_admin.role = "operator"
            db.commit()

        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=admin.user_id,
            tenant_id="tenant-a",
            device_id=admin.device_id,
            email="stale-dashboard-admin@example.test",
            role="platform_admin",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            response = self.request("GET", "/api/v1/dashboard/summary")
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["scope"], "own")
        self.assertEqual(body["today_tasks"], 1)
        self.assertEqual(body["active_tasks"], 1)
        self.assertEqual(
            [task["trace_id"] for task in body["recent_tasks"]],
            ["trace-dashboard-own"],
        )

    def test_dashboard_chapter_nine_metrics_match_device_and_allocator(self) -> None:
        admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="dashboard-metrics-admin@example.test",
            password="dashboard-metrics-admin-password",
            device_name="dashboard-metrics-admin-device",
            role="ops_admin",
        )
        reference_now = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        today_start = reference_now.replace(hour=0, minute=0, second=0, microsecond=0)
        with self.app.state.session_factory() as db:
            other_device = Device(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                name="dashboard-other-device",
            )
            db.add(other_device)
            db.flush()
            own_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="card_checkout",
                idempotency_key="dashboard-metrics-own-task",
                client_reference="private-client-reference",
                trace_id="dashboard-own-trace",
                status="created",
                expires_at=reference_now + timedelta(minutes=30),
                created_at=today_start + timedelta(hours=10),
            )
            other_device_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=other_device.id,
                task_type="card_checkout",
                idempotency_key="dashboard-metrics-other-device-task",
                trace_id="dashboard-other-device-trace",
                status="created",
                expires_at=reference_now + timedelta(minutes=30),
                created_at=today_start + timedelta(hours=9),
            )
            yesterday_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="dashboard-metrics-yesterday-task",
                trace_id="dashboard-yesterday-trace",
                status="closed",
                expires_at=reference_now,
                closed_at=reference_now,
                created_at=today_start - timedelta(hours=1),
            )
            cards = [
                Card(
                    tenant_id="tenant-a",
                    provider_ref="dashboard-blocked-card",
                    brand="VISA",
                    last4="4242",
                    secret_ref="vault://cards/dashboard-blocked",
                ),
                Card(
                    tenant_id="tenant-a",
                    provider_ref="dashboard-other-device-card",
                    brand="VISA",
                    last4="1881",
                    secret_ref="vault://cards/dashboard-other-device",
                ),
                Card(
                    tenant_id="tenant-a",
                    provider_ref="dashboard-available-card",
                    brand="VISA",
                    last4="9000",
                    secret_ref="vault://cards/dashboard-available",
                ),
                Card(
                    tenant_id="tenant-a",
                    provider_ref="dashboard-disabled-card",
                    brand="VISA",
                    last4="0001",
                    secret_ref="vault://cards/dashboard-disabled",
                    is_active=False,
                ),
                Card(
                    tenant_id="tenant-a",
                    provider_ref="dashboard-quarantined-card",
                    brand="VISA",
                    last4="0002",
                    secret_ref="vault://cards/dashboard-quarantined",
                    quarantined_at=reference_now,
                    quarantine_reason_code="suspected_compromise",
                ),
            ]
            db.add_all([own_task, other_device_task, yesterday_task, *cards])
            db.flush()
            own_unavailable_mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="o***@example.test",
                connector_type="imap",
                secret_ref="vault://mailboxes/dashboard-own-unavailable",
                health_status="unavailable",
            )
            other_unavailable_mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="d***@example.test",
                connector_type="imap",
                secret_ref="vault://mailboxes/dashboard-other-unavailable",
                health_status="unavailable",
            )
            db.add_all([own_unavailable_mailbox, other_unavailable_mailbox])
            db.flush()
            db.add_all(
                [
                    MailSession(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        mailbox_id=own_unavailable_mailbox.id,
                        status="waiting",
                        expires_at=reference_now + timedelta(minutes=30),
                    ),
                    MailSession(
                        tenant_id="tenant-a",
                        task_id=other_device_task.id,
                        user_id=self.identity.user_id,
                        device_id=other_device.id,
                        mailbox_id=other_unavailable_mailbox.id,
                        status="waiting",
                        expires_at=reference_now + timedelta(minutes=30),
                    ),
                ]
            )
            own_allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=own_task.id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=cards[0].id,
                status="active",
                expires_at=today_start - timedelta(minutes=1),
            )
            other_allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=other_device_task.id,
                user_id=self.identity.user_id,
                device_id=other_device.id,
                card_id=cards[1].id,
                status="active",
                expires_at=reference_now + timedelta(minutes=30),
            )
            db.add_all([own_allocation, other_allocation])
            db.flush()
            db.add_all(
                [
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_allocation_id=own_allocation.id,
                        idempotency_key="dashboard-own-succeeded",
                        business_name="Sensitive Business One",
                        status="succeeded",
                        policy_version="private-policy",
                        created_at=today_start + timedelta(hours=10, minutes=1),
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_allocation_id=own_allocation.id,
                        idempotency_key="dashboard-own-failed",
                        business_name="Sensitive Business Two",
                        status="failed",
                        policy_version="private-policy",
                        created_at=today_start + timedelta(hours=10, minutes=2),
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=own_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_allocation_id=own_allocation.id,
                        idempotency_key="dashboard-own-unknown",
                        business_name="Sensitive Business Three",
                        status="unknown",
                        policy_version="private-policy",
                        created_at=today_start + timedelta(hours=10, minutes=3),
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=other_device_task.id,
                        user_id=self.identity.user_id,
                        device_id=other_device.id,
                        card_allocation_id=other_allocation.id,
                        idempotency_key="dashboard-other-device-succeeded",
                        business_name="Other Device Business",
                        status="succeeded",
                        policy_version="private-policy",
                        created_at=today_start + timedelta(hours=9, minutes=1),
                    ),
                    UploadJob(
                        tenant_id="tenant-a",
                        task_id=yesterday_task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_allocation_id=own_allocation.id,
                        idempotency_key="dashboard-yesterday-succeeded",
                        business_name="Yesterday Business",
                        status="succeeded",
                        policy_version="private-policy",
                        created_at=today_start - timedelta(hours=1),
                    ),
                ]
            )
            db.commit()

        operator_token = self.login()
        with mock.patch(
            "platform.api.v1.routes._utc_now", return_value=reference_now
        ):
            own_response = self.request(
                "GET",
                "/api/v1/dashboard/summary",
                headers=self.bearer(operator_token),
            )
        self.assertEqual(own_response.status_code, 200, own_response.text)
        own = own_response.json()
        self.assertEqual(datetime.fromisoformat(own["today_started_at"]), today_start)
        self.assertEqual(own["today_tasks"], 1)
        self.assertEqual(own["today_succeeded_uploads"], 1)
        self.assertEqual(own["today_completed_uploads"], 2)
        self.assertEqual(own["unknown_uploads"], 1)
        self.assertEqual(own["unavailable_mailboxes"], 1)
        self.assertEqual(own["pending_exceptions"], 2)
        self.assertIsNone(own["available_cards"])
        self.assertEqual(
            [task["trace_id"] for task in own["recent_tasks"]],
            ["dashboard-own-trace", "dashboard-yesterday-trace"],
        )
        self.assertNotIn("dashboard-other-device-trace", own_response.text)

        admin_token = self.login(
            email="dashboard-metrics-admin@example.test",
            password="dashboard-metrics-admin-password",
            device_id=admin.device_id,
        )
        with mock.patch(
            "platform.api.v1.routes._utc_now", return_value=reference_now
        ):
            tenant_response = self.request(
                "GET",
                "/api/v1/dashboard/summary",
                headers=self.bearer(admin_token),
            )
        self.assertEqual(tenant_response.status_code, 200, tenant_response.text)
        tenant = tenant_response.json()
        self.assertEqual(tenant["today_tasks"], 2)
        self.assertEqual(tenant["today_succeeded_uploads"], 2)
        self.assertEqual(tenant["today_completed_uploads"], 3)
        self.assertEqual(tenant["available_cards"], 1)
        self.assertEqual(tenant["unavailable_mailboxes"], 2)
        self.assertEqual(tenant["pending_exceptions"], 3)
        self.assertIn("dashboard-other-device-trace", tenant_response.text)
        response_without_opaque_ids = {
            **tenant,
            "recent_tasks": [
                {key: value for key, value in task.items() if key != "id"}
                for task in tenant["recent_tasks"]
            ],
        }
        redaction_surface = json.dumps(
            response_without_opaque_ids,
            ensure_ascii=False,
            sort_keys=True,
        )
        for forbidden in (
            "private-client-reference",
            "Sensitive Business",
            "Other Device Business",
            "vault://",
            "private-policy",
            "4242",
            "1881",
            "9000",
        ):
            self.assertNotIn(forbidden, redaction_surface)

    def test_mailboxes_list_masks_configuration_and_reports_status(self) -> None:
        mailbox_admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="mailbox-admin@example.test",
            password="mailbox-admin-password",
            device_name="mailbox-admin-device",
            role="ops_admin",
        )
        token = self.login(
            email="mailbox-admin@example.test",
            password="mailbox-admin-password",
            device_id=mailbox_admin.device_id,
        )
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
        page = response.json()
        rows = page["items"]
        self.assertEqual(len(rows), 3)
        self.assertEqual(page["total_count"], 3)
        self.assertFalse(page["has_more"])
        self.assertIsNone(page["next_cursor"])
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

    def test_successful_local_login_records_device_last_seen(self) -> None:
        with self.app.state.session_factory() as db:
            self.assertIsNone(db.get(Device, self.identity.device_id).last_seen_at)

        self.login()

        with self.app.state.session_factory() as db:
            self.assertIsNotNone(db.get(Device, self.identity.device_id).last_seen_at)

    def test_failed_login_and_invalid_bearer_do_not_touch_device_last_seen(self) -> None:
        failed_password = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": "wrong-account-password",
                "device_id": self.identity.device_id,
            },
        )
        self.assertEqual(failed_password.status_code, 401)
        missing_device = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": self.account_password,
                "device_id": "forged-device-id",
            },
        )
        self.assertEqual(missing_device.status_code, 401)
        invalid_bearer = self.request(
            "GET",
            "/api/v1/me",
            headers=self.bearer("forged.invalid.bearer"),
        )
        self.assertEqual(invalid_bearer.status_code, 401)
        with self.app.state.session_factory() as db:
            self.assertIsNone(db.get(Device, self.identity.device_id).last_seen_at)

    def test_bearer_activity_is_throttled_and_revoked_devices_are_not_touched(self) -> None:
        token = self.login()
        recent = utc_now() - timedelta(seconds=30)
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            device.last_seen_at = recent
            db.commit()

        accepted = self.request("GET", "/api/v1/me", headers=self.bearer(token))
        self.assertEqual(accepted.status_code, 200, accepted.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.get(Device, self.identity.device_id).last_seen_at,
                recent.replace(tzinfo=None),
            )

        stale = utc_now() - timedelta(seconds=61)
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            device.last_seen_at = stale
            db.commit()
        refreshed = self.request("GET", "/api/v1/me", headers=self.bearer(token))
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        with self.app.state.session_factory() as db:
            touched = db.get(Device, self.identity.device_id).last_seen_at
            self.assertNotEqual(touched, stale)
            device = db.get(Device, self.identity.device_id)
            device.revoked_at = utc_now()
            revoked_baseline = device.last_seen_at
            db.commit()

        rejected = self.request("GET", "/api/v1/me", headers=self.bearer(token))
        self.assertEqual(rejected.status_code, 401)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.get(Device, self.identity.device_id).last_seen_at,
                revoked_baseline,
            )

    def test_login_and_me_use_platform_account(self) -> None:
        token = self.login()
        response = self.request(
            "GET", "/api/v1/me", headers=self.bearer(token)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], self.identity.user_id)
        self.assertEqual(response.json()["device_id"], self.identity.device_id)

    def test_me_rechecks_identity_after_authentication(self) -> None:
        observed_at = utc_now()
        stale_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-a",
            device_id=self.identity.device_id,
            email="stale@example.test",
            role="ops_admin",
            identity_kind="local",
            auth_time=observed_at,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            response = self.request("GET", "/api/v1/me")
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["email"], "first@example.test")
        self.assertEqual(response.json()["role"], "operator")

    def test_login_rechecks_device_after_issue_commit(self) -> None:
        original_commit = Session.commit
        revoked = False

        def commit_then_revoke(session: Session) -> None:
            nonlocal revoked
            issuing_login = any(
                isinstance(item, AuditEvent) and item.event_type == "auth.login"
                for item in session.new
            )
            original_commit(session)
            if not issuing_login or revoked:
                return
            revoked = True
            with self.app.state.session_factory() as other:
                device = other.get(Device, self.identity.device_id)
                self.assertIsNotNone(device)
                device.revoked_at = utc_now()
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_revoke):
            response = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-a",
                    "email": "first@example.test",
                    "password": self.account_password,
                    "device_id": self.identity.device_id,
                },
            )

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("access_token", response.text)

    def test_login_rechecks_password_after_audit_commit(self) -> None:
        original_commit = Session.commit
        password_rotated = False

        def commit_then_rotate_password(session: Session) -> None:
            nonlocal password_rotated
            committing_login = any(
                isinstance(item, AuditEvent) and item.event_type == "auth.login"
                for item in session.new
            )
            original_commit(session)
            if not committing_login or password_rotated:
                return
            password_rotated = True
            with self.app.state.session_factory() as other:
                current_user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(current_user)
                current_user.password_hash = hash_password(
                    "rotated-account-password"
                )
                original_commit(other)

        with mock.patch.object(
            Session,
            "commit",
            new=commit_then_rotate_password,
        ):
            response = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-a",
                    "email": "first@example.test",
                    "password": self.account_password,
                    "device_id": self.identity.device_id,
                },
            )

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("access_token", response.text)

    def test_login_rechecks_email_after_audit_commit(self) -> None:
        original_commit = Session.commit
        email_changed = False

        def commit_then_change_email(session: Session) -> None:
            nonlocal email_changed
            committing_login = any(
                isinstance(item, AuditEvent) and item.event_type == "auth.login"
                for item in session.new
            )
            original_commit(session)
            if not committing_login or email_changed:
                return
            email_changed = True
            with self.app.state.session_factory() as other:
                current_user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(current_user)
                current_user.email = "renamed@example.test"
                original_commit(other)

        with mock.patch.object(
            Session,
            "commit",
            new=commit_then_change_email,
        ):
            response = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-a",
                    "email": "first@example.test",
                    "password": self.account_password,
                    "device_id": self.identity.device_id,
                },
            )

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("access_token", response.text)

    def test_login_issues_access_token_after_audit_commit(self) -> None:
        original_commit = Session.commit
        login_committed = False

        def commit_then_mark_login(session: Session) -> None:
            nonlocal login_committed
            committing_login = any(
                isinstance(item, AuditEvent) and item.event_type == "auth.login"
                for item in session.new
            )
            original_commit(session)
            login_committed = login_committed or committing_login

        def issue_token(**_: object) -> str:
            self.assertTrue(login_committed)
            return "issued-after-login-commit"

        with mock.patch.object(
            Session,
            "commit",
            new=commit_then_mark_login,
        ), mock.patch(
            "platform.api.v1.routes.create_access_token",
            side_effect=issue_token,
        ):
            response = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-a",
                    "email": "first@example.test",
                    "password": self.account_password,
                    "device_id": self.identity.device_id,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["access_token"], "issued-after-login-commit")

    def test_task_endpoints_use_current_role_after_authentication(self) -> None:
        admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="stale-task-admin@example.test",
            password="stale-task-admin-password",
            device_name="stale-task-admin-device",
            role="ops_admin",
        )
        with self.app.state.session_factory() as db:
            other_task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="mail_code",
                idempotency_key="stale-task-admin-other",
                trace_id="trace-stale-task-other",
                status="created",
                expires_at=utc_now() + timedelta(minutes=15),
            )
            db.add(other_task)
            current_admin = db.get(User, admin.user_id)
            current_admin.role = "operator"
            db.commit()
            other_task_id = other_task.id

        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=admin.user_id,
            tenant_id="tenant-a",
            device_id=admin.device_id,
            email="stale-task-admin@example.test",
            role="ops_admin",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            listed = self.request("GET", "/api/v1/tasks")
            fetched = self.request("GET", f"/api/v1/tasks/{other_task_id}")
            timeline = self.request(
                "GET", f"/api/v1/tasks/{other_task_id}/timeline"
            )
            closed = self.request(
                "POST", f"/api/v1/tasks/{other_task_id}/close"
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json(), [])
        self.assertEqual(fetched.status_code, 404, fetched.text)
        self.assertEqual(timeline.status_code, 404, timeline.text)
        self.assertEqual(closed.status_code, 404, closed.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, other_task_id).status, "created")

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

    def test_tasks_are_isolated_between_devices_for_the_same_user(self) -> None:
        device_a_token = self.login()
        with self.app.state.session_factory() as db:
            device_b = Device(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                name="same-owner-device-b",
            )
            db.add(device_b)
            db.commit()
            device_b_id = device_b.id
        device_b_token = self.login(device_id=device_b_id)
        device_a_headers = self.bearer(device_a_token)
        device_b_headers = self.bearer(device_b_token)
        payload = {
            "type": "mail_code",
            "idempotency_key": "device-a-private-task",
            "client_reference": "device-a-private-reference",
        }
        created = self.request(
            "POST", "/api/v1/tasks", headers=device_a_headers, json=payload
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        task_trace_id = created.json()["trace_id"]
        same_device_replay = self.request(
            "POST", "/api/v1/tasks", headers=device_a_headers, json=payload
        )
        self.assertEqual(same_device_replay.status_code, 200, same_device_replay.text)
        self.assertEqual(same_device_replay.json()["id"], task_id)

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        device_b_list = self.request(
            "GET", "/api/v1/tasks", headers=device_b_headers
        )
        device_b_detail = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=device_b_headers
        )
        device_b_timeline = self.request(
            "GET", f"/api/v1/tasks/{task_id}/timeline", headers=device_b_headers
        )
        cross_device_replay = self.request(
            "POST", "/api/v1/tasks", headers=device_b_headers, json=payload
        )
        self.assertEqual(device_b_list.status_code, 200, device_b_list.text)
        self.assertEqual(device_b_list.json(), [])
        for hidden in (device_b_detail, device_b_timeline):
            self.assertEqual(hidden.status_code, 404, hidden.text)
            self.assertEqual(hidden.json()["error"]["code"], "not_found")
        self.assertEqual(cross_device_replay.status_code, 409, cross_device_replay.text)
        self.assertEqual(
            cross_device_replay.json()["error"]["code"], "conflict"
        )
        for private_value in (
            task_id,
            self.identity.device_id,
            task_trace_id,
        ):
            self.assertNotIn(private_value, cross_device_replay.text)

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertEqual(task.status, "created")
            self.assertEqual(
                len(
                    list(
                        db.scalars(
                            select(Task).where(
                                Task.user_id == self.identity.user_id
                            )
                        )
                    )
                ),
                1,
            )
            task_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == task_id,
                        AuditEvent.event_type.in_(("task.created", "task.expired")),
                    )
                )
            )
            self.assertEqual(
                [event.event_type for event in task_events], ["task.created"]
            )

        device_b_created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=device_b_headers,
            json={"type": "mail_code", "idempotency_key": "device-b-private-task"},
        )
        self.assertEqual(device_b_created.status_code, 201, device_b_created.text)
        device_b_task_id = device_b_created.json()["id"]
        device_a_list = self.request(
            "GET", "/api/v1/tasks", headers=device_a_headers
        )
        device_b_list = self.request(
            "GET", "/api/v1/tasks", headers=device_b_headers
        )
        self.assertEqual(
            [task["id"] for task in device_a_list.json()], [task_id]
        )
        self.assertEqual(
            [task["id"] for task in device_b_list.json()],
            [device_b_task_id],
        )

    def test_task_timeline_filters_mismatched_child_devices(self) -> None:
        with self.app.state.session_factory() as db:
            device_b = Device(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                name="timeline-device-b",
            )
            db.add(device_b)
            db.commit()
            device_b_id = device_b.id
        device_b_token = self.login(device_id=device_b_id)
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(device_b_token),
            json={"type": "card_checkout", "idempotency_key": "timeline-device-b"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        trace_id = created.json()["trace_id"]
        now = utc_now()
        with self.app.state.session_factory() as db:
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="x***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/cross-device-timeline",
            )
            card = Card(
                tenant_id="tenant-a",
                provider_ref="cross-device-timeline-card",
                brand="VISA",
                last4="9999",
                secret_ref="vault://cards/cross-device-timeline",
            )
            db.add_all([mailbox, card])
            db.flush()
            mail_session = MailSession(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                mailbox_id=mailbox.id,
                trace_id=trace_id,
                status="waiting",
                expires_at=now + timedelta(minutes=5),
            )
            allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=card.id,
                trace_id=trace_id,
                status="active",
                expires_at=now + timedelta(minutes=5),
            )
            db.add_all([mail_session, allocation])
            db.flush()
            upload = UploadJob(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="cross-device-timeline-upload",
                business_name="Cross Device Store",
                trace_id=trace_id,
                status="queued",
                policy_version="cross-device-policy",
            )
            cross_device_event = AuditEvent(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                actor_id=self.identity.user_id,
                event_type="cross_device.event",
                action="cross_device_event",
                result="success",
                entity_type="task",
                entity_id=task_id,
                trace_id=trace_id,
                details_json="{}",
            )
            db.add_all([upload, cross_device_event])
            db.commit()

        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(device_b_token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        response = timeline.json()
        self.assertEqual(response["workbench_step"], "logged_in")
        self.assertIsNone(response["mail_session"])
        self.assertEqual(response["card_allocations"], [])
        self.assertEqual(response["uploads"], [])
        self.assertNotIn(
            "cross_device.event",
            [event["event_type"] for event in response["events"]],
        )

    def test_task_timeline_is_owner_scoped_ordered_and_redacted(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "card_checkout", "idempotency_key": "timeline-task"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        trace_id = created.json()["trace_id"]
        now = utc_now() + timedelta(seconds=1)
        with self.app.state.session_factory() as db:
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="f***@example.test",
                connector_type="http",
                secret_ref="vault://secret/mailboxes/timeline-mailbox",
            )
            card = Card(
                tenant_id="tenant-a",
                provider_ref="timeline-card",
                brand="VISA",
                last4="4242",
                expiry_month=12,
                expiry_year=2030,
                secret_ref="vault://secret/cards/timeline-card",
            )
            db.add_all([mailbox, card])
            db.flush()
            mail_session = MailSession(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                mailbox_id=mailbox.id,
                trace_id=trace_id,
                session_token_hash="f" * 64,
                status="consumed",
                expires_at=now + timedelta(minutes=10),
                consumed_at=now,
                delivered_code="73918426",
                created_at=now,
            )
            allocation = CardAllocation(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_id=card.id,
                trace_id=trace_id,
                status="active",
                expires_at=now + timedelta(minutes=10),
                created_at=now,
            )
            db.add_all([mail_session, allocation])
            db.flush()
            upload = UploadJob(
                tenant_id="tenant-a",
                task_id=task_id,
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="timeline-upload",
                business_name="Timeline Store",
                trace_id=trace_id,
                status="unknown",
                policy_version="timeline-policy-v1",
                error_code="external_unknown",
                created_at=now + timedelta(seconds=1),
                updated_at=now + timedelta(seconds=1),
            )
            db.add(upload)
            db.flush()
            event = AuditEvent(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                actor_id=self.identity.user_id,
                event_type="upload.unknown",
                action="upload_unknown",
                result="unknown",
                entity_type="upload_job",
                entity_id=upload.id,
                trace_id=trace_id,
                policy_version="timeline-policy-v1",
                details_json=json.dumps(
                    {
                        "code": "73918426",
                        "pan": "4242424242424242",
                        "secret_ref": "vault://secret/sub2/private",
                    }
                ),
                created_at=now + timedelta(seconds=2),
            )
            unrelated_same_trace_event = AuditEvent(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                actor_id=self.identity.user_id,
                event_type="unrelated.same_trace",
                action="unrelated_same_trace",
                result="success",
                entity_type="task",
                entity_id="unrelated-task-id",
                trace_id=trace_id,
                details_json="{}",
                created_at=now + timedelta(seconds=3),
            )
            db.add_all([event, unrelated_same_trace_event])
            db.commit()

        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        payload = timeline.json()
        self.assertEqual(payload["task"]["id"], task_id)
        self.assertEqual(payload["workbench_step"], "uploading")
        self.assertEqual(payload["mail_session"]["email_masked"], "f***@example.test")
        self.assertEqual(payload["mail_session"]["status"], "consumed")
        self.assertEqual(payload["card_allocations"][0]["card_masked"], "**** **** **** 4242")
        self.assertEqual(payload["uploads"][0]["status"], "unknown")
        event_times = [item["created_at"] for item in payload["events"]]
        self.assertEqual(event_times, sorted(event_times))
        self.assertEqual(payload["events"][-1]["event_type"], "upload.unknown")
        self.assertNotIn(
            "unrelated.same_trace",
            [item["event_type"] for item in payload["events"]],
        )
        serialized = timeline.text
        for forbidden in (
            "73918426",
            "4242424242424242",
            "vault://secret",
            "session_token_hash",
            "delivered_code",
            "details_json",
        ):
            self.assertNotIn(forbidden, serialized)

        second_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="timeline-other@example.test",
            password="timeline-other-password",
            device_name="timeline-other-device",
        )
        second_token = self.login(
            email="timeline-other@example.test",
            password="timeline-other-password",
            device_id=second_identity.device_id,
        )
        hidden = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(second_token),
        )
        self.assertEqual(hidden.status_code, 404)

    def test_expired_task_timeline_rechecks_operator_after_commit(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "mail_code",
                "idempotency_key": "timeline-expiry-commit-boundary",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        original_commit = Session.commit
        demoted = False

        def commit_then_demote(session: Session) -> None:
            nonlocal demoted
            expiring_task = any(
                isinstance(item, AuditEvent) and item.event_type == "task.expired"
                for item in session.new
            )
            original_commit(session)
            if not expiring_task or demoted:
                return
            demoted = True
            with self.app.state.session_factory() as other:
                user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(user)
                user.role = "security_auditor"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_demote):
            response = self.request(
                "GET",
                f"/api/v1/tasks/{task_id}/timeline",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn(created.json()["trace_id"], response.text)
        self.assertNotIn(task_id, response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(Task, task_id)
            expiry_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.expired",
                        AuditEvent.entity_id == task_id,
                    )
                )
            )
        self.assertEqual(persisted.status, "expired")
        self.assertEqual(len(expiry_events), 1)

    def test_task_history_is_newest_first_and_bounded(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        created_ids = []
        created_at_base = utc_now()
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
            with self.app.state.session_factory() as db:
                task = db.get(Task, response.json()["id"])
                task.created_at = created_at_base + timedelta(seconds=index)
                db.commit()
            closed = self.request(
                "POST",
                f"/api/v1/tasks/{response.json()['id']}/close",
                headers=headers,
            )
            self.assertEqual(closed.status_code, 200, closed.text)

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

    def test_task_list_rechecks_role_scope_after_expiry_commit(self) -> None:
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="task-list-other@example.test",
            password="task-list-other-password",
            device_name="task-list-other-device",
        )
        sensitive_reference = "other-user-expired-sensitive-reference"
        with self.app.state.session_factory() as db:
            actor = db.get(User, self.identity.user_id)
            self.assertIsNotNone(actor)
            actor.role = "ops_admin"
            task = Task(
                tenant_id="tenant-a",
                user_id=other.user_id,
                device_id=other.device_id,
                task_type="mail_code",
                idempotency_key="task-list-role-scope-boundary",
                client_reference=sensitive_reference,
                trace_id="task-list-role-scope-trace",
                status="created",
                expires_at=utc_now() - timedelta(seconds=1),
            )
            db.add(task)
            db.commit()
            task_id = task.id

        token = self.login()
        original_commit = Session.commit
        demoted = False

        def commit_then_demote(session: Session) -> None:
            nonlocal demoted
            expiring_task = any(
                isinstance(item, AuditEvent) and item.event_type == "task.expired"
                for item in session.new
            )
            original_commit(session)
            if not expiring_task or demoted:
                return
            demoted = True
            with self.app.state.session_factory() as other_db:
                actor = other_db.get(User, self.identity.user_id)
                self.assertIsNotNone(actor)
                actor.role = "operator"
                original_commit(other_db)

        with mock.patch.object(Session, "commit", new=commit_then_demote):
            response = self.request(
                "GET",
                "/api/v1/tasks",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [])
        self.assertNotIn(sensitive_reference, response.text)
        self.assertNotIn(task_id, response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(Task, task_id)
            expiry_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.expired",
                        AuditEvent.entity_id == task_id,
                    )
                )
            )
        self.assertEqual(persisted.status, "expired")
        self.assertEqual(len(expiry_events), 1)

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
        with self.app.state.session_factory() as db:
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="d***@example.test",
                connector_type="http",
                secret_ref="vault://mailboxes/device-revoke",
            )
            db.add(mailbox)
            db.flush()
            session = MailSession(
                tenant_id="tenant-a",
                task_id=task.json()["id"],
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                mailbox_id=mailbox.id,
                trace_id=task.json()["trace_id"],
                status="code_ready",
                start_watermark="connector-watermark-before-device-revoke",
                last_message_hash="d" * 64,
                delivered_code="482731",
                delivered_message_id_hash="e" * 64,
                delivered_at=utc_now(),
                code_expires_at=utc_now() + timedelta(minutes=1),
                expires_at=utc_now() + timedelta(minutes=5),
            )
            db.add(session)
            db.commit()
            session_id = session.id
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
            session = db.get(MailSession, session_id)
            self.assertEqual(session.status, "expired")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_message_id_hash)
            self.assertIsNone(session.delivered_at)
            self.assertIsNone(session.code_expires_at)
            self.assertIsNone(session.start_watermark)
            self.assertIsNone(session.last_message_hash)

    def test_owner_device_revoke_rechecks_role_after_final_commit(self) -> None:
        token = self.login()
        original_commit = Session.commit
        revocation_started = False
        revocation_commit_count = 0

        def commit_then_demote(session: Session) -> None:
            nonlocal revocation_started, revocation_commit_count
            if any(
                isinstance(item, AuditEvent) and item.event_type == "device.revoked"
                for item in session.new
            ):
                revocation_started = True
            original_commit(session)
            if not revocation_started:
                return
            revocation_commit_count += 1
            if revocation_commit_count != 2:
                return
            with self.app.state.session_factory() as other:
                user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(user)
                user.role = "worker_service"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_demote):
            response = self.request(
                "POST",
                f"/api/v1/devices/{self.identity.device_id}/revoke",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn("revoked_at", response.text)
        with self.app.state.session_factory() as db:
            self.assertIsNotNone(db.get(Device, self.identity.device_id).revoked_at)
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "device.revoked")
                ),
                1,
            )

    def test_owner_device_revoke_rechecks_token_after_final_commit(self) -> None:
        token = self.login()
        original_commit = Session.commit
        revocation_started = False
        revocation_commit_count = 0

        def commit_then_revoke_token(session: Session) -> None:
            nonlocal revocation_started, revocation_commit_count
            if any(
                isinstance(item, AuditEvent) and item.event_type == "device.revoked"
                for item in session.new
            ):
                revocation_started = True
            original_commit(session)
            if not revocation_started:
                return
            revocation_commit_count += 1
            if revocation_commit_count != 2:
                return
            with self.app.state.session_factory() as other:
                other.add(
                    RevokedAccessToken(
                        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                        tenant_id="tenant-a",
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        expires_at=utc_now() + timedelta(minutes=15),
                        revoked_at=utc_now(),
                        reason="concurrent_logout",
                    )
                )
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_revoke_token):
            response = self.request(
                "POST",
                f"/api/v1/devices/{self.identity.device_id}/revoke",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("revoked_at", response.text)
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            revoke_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "device.revoked",
                        AuditEvent.entity_id == self.identity.device_id,
                    )
                )
            )
        self.assertIsNotNone(device.revoked_at)
        self.assertEqual(len(revoke_events), 1)

    def test_owner_device_revoke_rechecks_token_expiry_after_final_commit(
        self,
    ) -> None:
        observed_at = utc_now()
        principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-a",
            device_id=self.identity.device_id,
            email="first@example.test",
            role="operator",
            identity_kind="local",
            auth_time=observed_at,
            acr=None,
            amr=(),
            access_token_hash="e" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=1),
            access_token_revoked=False,
        )
        original_commit = Session.commit
        revocation_started = False
        revocation_commit_count = 0

        def commit_then_advance_time(session: Session) -> None:
            nonlocal revocation_started, revocation_commit_count
            if any(
                isinstance(item, AuditEvent) and item.event_type == "device.revoked"
                for item in session.new
            ):
                revocation_started = True
            original_commit(session)
            if revocation_started:
                revocation_commit_count += 1

        def current_time() -> datetime:
            if revocation_commit_count >= 2:
                return observed_at + timedelta(minutes=2)
            return observed_at

        self.app.dependency_overrides[get_current_principal] = lambda: principal
        try:
            with mock.patch.object(
                Session,
                "commit",
                new=commit_then_advance_time,
            ), mock.patch(
                "platform.api.v1.routes._utc_now",
                side_effect=current_time,
            ):
                response = self.request(
                    "POST",
                    f"/api/v1/devices/{self.identity.device_id}/revoke",
                )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("revoked_at", response.text)
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            revoke_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "device.revoked",
                        AuditEvent.entity_id == self.identity.device_id,
                    )
                )
            )
        self.assertIsNotNone(device.revoked_at)
        self.assertEqual(len(revoke_events), 1)

    def test_revoked_actor_device_cannot_revoke_another_owned_device(self) -> None:
        observed_at = utc_now()
        with self.app.state.session_factory() as db:
            actor = db.get(Device, self.identity.device_id)
            actor.revoked_at = observed_at
            target = Device(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                name="trusted-target-device",
            )
            db.add(target)
            db.flush()
            task = Task(
                tenant_id="tenant-a",
                user_id=self.identity.user_id,
                device_id=target.id,
                task_type="mail_code",
                idempotency_key="trusted-target-task",
                trace_id="trusted-target-trace",
                status="created",
                expires_at=observed_at + timedelta(minutes=15),
            )
            db.add(task)
            db.commit()
            target_id = target.id
            task_id = task.id

        stale_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-a",
            device_id=self.identity.device_id,
            email="first@example.test",
            role="operator",
            identity_kind="local",
            auth_time=observed_at,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            response = self.request(
                "POST",
                f"/api/v1/devices/{target_id}/revoke",
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 401, response.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(db.get(Device, target_id).revoked_at)
            self.assertEqual(db.get(Task, task_id).status, "created")
            self.assertIsNone(
                db.scalar(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "device.revoked",
                        AuditEvent.entity_id == target_id,
                    )
                )
            )

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
        self.assertEqual(event["ip_address"], "127.0.0.1")
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

    def test_audit_metadata_redacts_sensitive_headers_at_write_and_read(self) -> None:
        token = self.login()
        unsafe_user_agents = (
            "EvidenceClient/1.0 aUtHoRiZaTiOn: Basic AUTH_COLON_SECRET",
            "EvidenceClient/1.0 AUTHORIZATION=Basic AUTH_EQUALS_SECRET",
            "EvidenceClient/1.0 prefix bEaReR BEARER_SECRET",
            "EvidenceClient/1.0 VaUlT://mail/prod",
            "EvidenceClient/1.0 4111111111111111",
        )
        for index, user_agent in enumerate(unsafe_user_agents):
            headers = {**self.bearer(token), "User-Agent": user_agent}
            if index == 0:
                headers["X-Real-IP"] = (
                    "203.0.113.18 Authorization=Bearer AUDIT_IP_SECRET"
                )
            created = self.request(
                "POST",
                "/api/v1/tasks",
                headers=headers,
                json={
                    "type": "mail_code",
                    "idempotency_key": f"unsafe-audit-metadata-{index}",
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            with self.app.state.session_factory() as db:
                event = db.scalar(
                    select(AuditEvent).where(
                        AuditEvent.trace_id == created.json()["trace_id"],
                        AuditEvent.event_type == "task.created",
                    )
                )
                task = db.get(Task, created.json()["id"])
                self.assertIsNotNone(task)
                task.status = "cancelled"
                task.closed_at = utc_now()
                db.commit()
                self.assertIsNotNone(event)
                with self.subTest(user_agent=user_agent):
                    self.assertEqual(event.user_agent, "[REDACTED]")
                if index == 0:
                    with self.subTest(header="X-Real-IP"):
                        self.assertEqual(event.ip_address, "127.0.0.1")

        safe = self.request(
            "POST",
            "/api/v1/tasks",
            headers={
                **self.bearer(token),
                "User-Agent": "Evidence Client/2.0",
                "X-Real-IP": "203.0.113.19",
            },
            json={
                "type": "mail_code",
                "idempotency_key": "safe-audit-metadata",
            },
        )
        self.assertEqual(safe.status_code, 201, safe.text)
        legacy_trace_id = "00000000-0000-4000-8000-000000000097"
        legacy_user_agent = (
            "LegacyEvidence/1.0 Authorization=Bearer LEGACY_UA_SECRET "
            "vault://mail/prod 4111111111111111"
        )
        legacy_ip_address = (
            "203.0.113.20 Authorization=Bearer LEGACY_IP_SECRET"
        )
        with self.app.state.session_factory() as db:
            safe_event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.trace_id == safe.json()["trace_id"],
                    AuditEvent.event_type == "task.created",
                )
            )
            self.assertIsNotNone(safe_event)
            self.assertEqual(safe_event.user_agent, "Evidence Client/2.0")
            self.assertEqual(safe_event.ip_address, "127.0.0.1")
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.role = "security_auditor"
            db.add(
                AuditEvent(
                    tenant_id="tenant-a",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    actor_id=self.identity.user_id,
                    event_type="legacy.metadata.test",
                    action="legacy.metadata.test",
                    result="success",
                    entity_type="task",
                    entity_id="legacy-safe-evidence",
                    trace_id=legacy_trace_id,
                    ip_address=legacy_ip_address,
                    user_agent=legacy_user_agent,
                    details_json="{}",
                )
            )
            db.commit()
        auditor_token = self.login()

        response = self.request(
            "GET",
            f"/api/v1/admin/audit?trace_id={legacy_trace_id}",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["user_agent"], "[REDACTED]")
        self.assertIsNone(response.json()[0]["ip_address"])
        self.assertEqual(response.json()[0]["entity_id"], "legacy-safe-evidence")

        exported = self.request(
            "GET",
            f"/api/v1/admin/audit/export?trace_id={legacy_trace_id}",
            headers=self.bearer(auditor_token),
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        rows = list(
            csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig")))
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["user_agent"], "[REDACTED]")
        self.assertEqual(rows[0]["ip_address"], "")
        self.assertEqual(rows[0]["entity_id"], "legacy-safe-evidence")
        serialized = json.dumps(response.json()) + exported.text
        for forbidden in (
            "LEGACY_UA_SECRET",
            "LEGACY_IP_SECRET",
            "vault://",
            "Bearer",
            "4111111111111111",
        ):
            self.assertNotIn(forbidden, serialized)

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

    def test_task_create_rechecks_access_token_revocation_after_commit(self) -> None:
        token = self.login()
        original_commit = Session.commit
        token_revoked = False

        def commit_then_revoke_token(session: Session) -> None:
            nonlocal token_revoked
            task_created = any(
                isinstance(item, AuditEvent) and item.event_type == "task.created"
                for item in session.new
            )
            original_commit(session)
            if not task_created or token_revoked:
                return
            token_revoked = True
            with self.app.state.session_factory() as other:
                other.add(
                    RevokedAccessToken(
                        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                        tenant_id="tenant-a",
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        expires_at=utc_now() + timedelta(minutes=15),
                        revoked_at=utc_now(),
                        reason="concurrent_logout",
                    )
                )
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_revoke_token):
            response = self.request(
                "POST",
                "/api/v1/tasks",
                headers=self.bearer(token),
                json={
                    "type": "mail_code",
                    "idempotency_key": "task-create-token-revocation-boundary",
                },
            )

        self.assertEqual(response.status_code, 401, response.text)
        with self.app.state.session_factory() as db:
            task = db.scalar(
                select(Task).where(
                    Task.idempotency_key
                    == "task-create-token-revocation-boundary"
                )
            )
            self.assertIsNotNone(task)
            task_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.created",
                        AuditEvent.entity_id == task.id,
                    )
                )
            )
        self.assertNotIn(task.id, response.text)
        self.assertEqual(len(task_events), 1)

    def test_task_create_rechecks_access_token_expiry_after_commit(self) -> None:
        observed_at = utc_now()
        principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-a",
            device_id=self.identity.device_id,
            email="first@example.test",
            role="operator",
            identity_kind="local",
            auth_time=observed_at,
            acr=None,
            amr=(),
            access_token_hash="f" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=1),
            access_token_revoked=False,
        )
        original_commit = Session.commit
        task_created = False

        def commit_then_advance_time(session: Session) -> None:
            nonlocal task_created
            creating = any(
                isinstance(item, AuditEvent) and item.event_type == "task.created"
                for item in session.new
            )
            original_commit(session)
            task_created = task_created or creating

        def current_time() -> datetime:
            if task_created:
                return observed_at + timedelta(minutes=2)
            return observed_at

        self.app.dependency_overrides[get_current_principal] = lambda: principal
        try:
            with mock.patch.object(
                Session,
                "commit",
                new=commit_then_advance_time,
            ), mock.patch(
                "platform.api.v1.routes._utc_now",
                side_effect=current_time,
            ):
                response = self.request(
                    "POST",
                    "/api/v1/tasks",
                    json={
                        "type": "mail_code",
                        "idempotency_key": "task-create-token-expiry-boundary",
                    },
                )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 401, response.text)
        with self.app.state.session_factory() as db:
            task = db.scalar(
                select(Task).where(
                    Task.idempotency_key == "task-create-token-expiry-boundary"
                )
            )
            self.assertIsNotNone(task)
            task_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.created",
                        AuditEvent.entity_id == task.id,
                    )
                )
            )
        self.assertNotIn(task.id, response.text)
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

    def test_default_task_ttl_is_thirty_minutes(self) -> None:
        self.assertEqual(Settings(_env_file=None).task_ttl_seconds, 1_800)

    def test_created_task_uses_the_default_thirty_minute_ttl(self) -> None:
        token = self.login()
        before = utc_now()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "task-default-ttl"},
        )
        after = utc_now()

        self.assertEqual(created.status_code, 201, created.text)
        expires_at = datetime.fromisoformat(created.json()["expires_at"])
        self.assertGreaterEqual(expires_at, before + timedelta(seconds=1_800))
        self.assertLessEqual(expires_at, after + timedelta(seconds=1_800))

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

    def test_expired_task_detail_rechecks_operator_after_commit(self) -> None:
        token = self.login()
        sensitive_reference = "expired-task-detail-sensitive-reference"
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "mail_code",
                "idempotency_key": "task-detail-expiry-commit-boundary",
                "client_reference": sensitive_reference,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        original_commit = Session.commit
        demoted = False

        def commit_then_demote(session: Session) -> None:
            nonlocal demoted
            expiring_task = any(
                isinstance(item, AuditEvent) and item.event_type == "task.expired"
                for item in session.new
            )
            original_commit(session)
            if not expiring_task or demoted:
                return
            demoted = True
            with self.app.state.session_factory() as other:
                user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(user)
                user.role = "security_auditor"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_demote):
            response = self.request(
                "GET",
                f"/api/v1/tasks/{task_id}",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn(sensitive_reference, response.text)
        self.assertNotIn(created.json()["trace_id"], response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(Task, task_id)
            expiry_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.expired",
                        AuditEvent.entity_id == task_id,
                    )
                )
            )
        self.assertEqual(persisted.status, "expired")
        self.assertEqual(len(expiry_events), 1)

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
            db.flush()
            queued_outbox = OutboxEvent(
                tenant_id="tenant-a",
                event_type="upload.requested",
                aggregate_type="upload_job",
                aggregate_id=queued.id,
                status="pending",
            )
            running_outbox = OutboxEvent(
                tenant_id="tenant-a",
                event_type="upload.requested",
                aggregate_type="upload_job",
                aggregate_id=running.id,
                status="processing",
                claimed_at=now,
            )
            db.add_all([queued_outbox, running_outbox])
            db.commit()
            allocation_id = allocation.id
            session_id = session.id
            queued_id = queued.id
            running_id = running.id
            outbox_ids = (queued_outbox.id, running_outbox.id)

        from platform import lifecycle

        original_release = lifecycle.release_task_resources
        skipped_first_phase = False

        def simulate_locked_resources(*args, **kwargs):
            nonlocal skipped_first_phase
            if kwargs.get("skip_locked") and not skipped_first_phase:
                skipped_first_phase = True
                return LifecycleSweepResult()
            return original_release(*args, **kwargs)

        with mock.patch(
            "platform.lifecycle.release_task_resources",
            side_effect=simulate_locked_resources,
        ):
            closed = self.request(
                "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
            )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")
        self.assertTrue(skipped_first_phase)

        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocation_id)
            session = db.get(MailSession, session_id)
            queued = db.get(UploadJob, queued_id)
            running = db.get(UploadJob, running_id)
            outboxes = [db.get(OutboxEvent, outbox_id) for outbox_id in outbox_ids]
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertEqual(queued.status, "cancelled")
            self.assertEqual(running.status, "unknown")
            self.assertEqual(running.error_code, "external_unknown")
            self.assertEqual([event.status for event in outboxes], ["processed", "processed"])
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
                    "upload.unknown",
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
            task_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == task_id,
                        AuditEvent.event_type == "task.closed",
                    )
                )
            )
        self.assertEqual(len(replay_events), 4)
        self.assertEqual(len(task_events), 1)

    def test_close_task_rechecks_operator_after_final_commit(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={
                "type": "mail_code",
                "idempotency_key": "task-close-commit-boundary",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        original_commit = Session.commit
        close_started = False
        close_commit_count = 0

        def commit_then_demote(session: Session) -> None:
            nonlocal close_started, close_commit_count
            if any(
                isinstance(item, AuditEvent) and item.event_type == "task.closed"
                for item in session.new
            ):
                close_started = True
            original_commit(session)
            if not close_started:
                return
            close_commit_count += 1
            if close_commit_count != 2:
                return
            with self.app.state.session_factory() as other:
                user = other.get(User, self.identity.user_id)
                self.assertIsNotNone(user)
                user.role = "security_auditor"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_demote):
            response = self.request(
                "POST",
                f"/api/v1/tasks/{task_id}/close",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn(created.json()["trace_id"], response.text)
        self.assertNotIn('\"status\":\"closed\"', response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(Task, task_id)
            close_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.closed",
                        AuditEvent.entity_id == task_id,
                    )
                )
            )
        self.assertEqual(persisted.status, "closed")
        self.assertEqual(len(close_events), 1)

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

    def test_login_rejects_unknown_request_fields(self) -> None:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": self.account_password,
                "device_id": self.identity.device_id,
                "unexpected": "must-not-be-accepted",
            },
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["error"]["code"], "validation_error")

    def test_unknown_account_still_performs_password_verification(self) -> None:
        with mock.patch(
            "platform.api.v1.routes.verify_password", return_value=False
        ) as verify:
            response = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-a",
                    "email": "unknown-account@example.test",
                    "password": "wrong-password-sentinel",
                    "device_id": "forged-device-id",
                },
            )

        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn("access_token", response.text)
        verify.assert_called_once()
        encoded = verify.call_args.args[1]
        self.assertEqual(encoded.split("$", 2)[:2], ["pbkdf2_sha256", "210000"])

    def test_login_failures_are_audited_without_enumeration_or_secrets(self) -> None:
        bad_password = "wrong-password-sentinel"
        unknown_email = "unknown-account@example.test"
        common_headers = {
            "X-Forwarded-For": "203.0.113.27",
            "User-Agent": "phase-one-login-audit-test",
        }
        wrong = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={**common_headers, "X-Trace-Id": "10000000-0000-4000-8000-000000000001"},
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": bad_password,
                "device_id": self.identity.device_id,
            },
        )
        unknown = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={**common_headers, "X-Trace-Id": "10000000-0000-4000-8000-000000000002"},
            json={
                "tenant_id": "tenant-a",
                "email": unknown_email,
                "password": bad_password,
                "device_id": "forged-device-id",
            },
        )
        invalid_device = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={**common_headers, "X-Trace-Id": "10000000-0000-4000-8000-000000000003"},
            json={
                "tenant_id": "tenant-a",
                "email": "first@example.test",
                "password": self.account_password,
                "device_id": "forged-device-id",
            },
        )
        self.assertEqual(wrong.status_code, 401, wrong.text)
        self.assertEqual(unknown.status_code, 401, unknown.text)
        self.assertEqual(invalid_device.status_code, 401, invalid_device.text)
        self.assertEqual(wrong.json()["error"]["code"], "unauthorized")
        self.assertEqual(unknown.json()["error"]["code"], "unauthorized")
        for field in ("code", "message", "recovery_hint"):
            self.assertEqual(
                invalid_device.json()["error"][field], wrong.json()["error"][field]
            )
            self.assertEqual(unknown.json()["error"][field], wrong.json()["error"][field])
        for denied in (wrong, unknown, invalid_device):
            self.assertNotIn("access_token", denied.text)

        with self.app.state.session_factory() as db:
            failures = list(
                db.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.event_type == "auth.login_failed")
                    .order_by(AuditEvent.created_at, AuditEvent.id)
                )
            )
            target_attempts = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "auth.login_failed",
                        AuditEvent.user_id == self.identity.user_id,
                        AuditEvent.actor_id == "anonymous",
                    )
                )
            )
            misattributed = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "auth.login_failed",
                        AuditEvent.actor_id == self.identity.user_id,
                    )
                )
            )
            self.assertIsNone(db.get(Device, "forged-device-id"))
            self.assertIsNone(db.get(Device, self.identity.device_id).last_seen_at)
        self.assertEqual(len(failures), 3)
        failures_by_trace = {failure.trace_id: failure for failure in failures}
        known = failures_by_trace["10000000-0000-4000-8000-000000000001"]
        anonymous = failures_by_trace["10000000-0000-4000-8000-000000000002"]
        invalid_device_event = failures_by_trace[
            "10000000-0000-4000-8000-000000000003"
        ]
        for failure in failures:
            self.assertEqual(failure.actor_id, "anonymous")
            self.assertEqual(failure.result, "failure")
            self.assertIsNone(failure.device_id)
        self.assertEqual(known.user_id, self.identity.user_id)
        self.assertEqual(known.entity_id, self.identity.user_id)
        self.assertEqual(known.trace_id, "10000000-0000-4000-8000-000000000001")
        self.assertEqual(anonymous.trace_id, "10000000-0000-4000-8000-000000000002")
        self.assertIsNone(anonymous.user_id)
        self.assertIsNone(anonymous.entity_id)
        self.assertEqual(invalid_device_event.user_id, self.identity.user_id)
        self.assertEqual(invalid_device_event.entity_id, self.identity.user_id)
        self.assertEqual(
            invalid_device_event.trace_id,
            "10000000-0000-4000-8000-000000000003",
        )
        self.assertEqual(len(target_attempts), 2)
        self.assertEqual(misattributed, [])
        self.assertEqual(len({failure.trace_id for failure in failures}), 3)
        audit_text = "\n".join(event.details_json for event in failures)
        for secret in (
            bad_password,
            self.account_password,
            "first@example.test",
            unknown_email,
            "forged-device-id",
        ):
            self.assertNotIn(secret, audit_text)
        self.assertIn('"reason": "authentication_failed"', audit_text)

        success_token = self.login()
        with self.app.state.session_factory() as db:
            success = db.scalar(
                select(AuditEvent).where(AuditEvent.event_type == "auth.login")
            )
        self.assertEqual(success.user_id, self.identity.user_id)
        self.assertEqual(success.device_id, self.identity.device_id)
        self.assertEqual(success.actor_id, self.identity.user_id)
        self.assertNotIn(success_token, success.details_json)

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
            "/api/v1/tasks/{task_id}/timeline",
        ):
            self.assertIn(path, schema["paths"])
        self.assertIn("HTTPBearer", schema["components"]["securitySchemes"])
        task_schema = schema["components"]["schemas"]["TaskCreate"]
        self.assertEqual(
            set(task_schema["required"]), {"type", "idempotency_key"}
        )
        self.assertNotIn("device_id", task_schema["properties"])
        timeline_schema = schema["components"]["schemas"]["TaskTimelineResponse"]
        self.assertEqual(
            set(timeline_schema["required"]),
            {
                "task",
                "workbench_step",
                "mail_session",
                "card_allocations",
                "uploads",
                "events",
            },
        )
        serialized_timeline_schema = json.dumps(timeline_schema)
        for forbidden in ("code", "pan", "cvv", "secret_ref", "details"):
            self.assertNotIn(f'"{forbidden}"', serialized_timeline_schema)

    def test_openapi_describes_stable_error_envelope_for_key_api_groups(self) -> None:
        schema = self.app.openapi()
        error_schema = schema["components"]["schemas"]["ApiErrorResponse"]
        error_ref = {"$ref": "#/components/schemas/ApiErrorResponse"}

        self.assertEqual(error_schema["required"], ["error"])
        error_detail_ref = error_schema["properties"]["error"]
        self.assertEqual(
            error_detail_ref,
            {"$ref": "#/components/schemas/ApiErrorDetail"},
        )
        error_detail_schema = schema["components"]["schemas"]["ApiErrorDetail"]
        self.assertEqual(
            set(error_detail_schema["required"]),
            {"code", "message", "recovery_hint", "trace_id"},
        )
        for forbidden in (
            "access_token",
            "password",
            "pan",
            "cvv",
            "session_token",
            "secret_ref",
            "proxy_ref",
            "credential_ref",
        ):
            self.assertNotIn(forbidden, error_detail_schema["properties"])

        key_operations = (
            ("/api/v1/me", "get"),
            ("/api/v1/devices/{device_id}/revoke", "post"),
            ("/api/v1/tasks", "post"),
            ("/api/v1/tasks/{task_id}", "get"),
            ("/api/v1/tasks/{task_id}/card-allocation", "post"),
            ("/api/v1/card-allocations/{allocation_id}/reveal", "post"),
            ("/api/v1/tasks/{task_id}/mail-session", "post"),
            ("/api/v1/mail-sessions/{session_id}/code", "get"),
            ("/api/v1/uploads", "post"),
            ("/api/v1/uploads/{job_id}", "get"),
            ("/api/v1/admin/audit", "get"),
            ("/api/v1/admin/policies/upload/versions/{policy_id}/deploy", "post"),
        )
        for path, method in key_operations:
            with self.subTest(path=path, method=method):
                responses = schema["paths"][path][method]["responses"]
                for status in ("default", "422"):
                    content_schema = responses[status]["content"][
                        "application/json"
                    ]["schema"]
                    self.assertEqual(content_schema, error_ref)

        for path, method in (
            ("/api/v1/mail-sessions/{session_id}/code", "get"),
            ("/api/v1/mail-sessions/{session_id}/revoke", "post"),
            ("/api/v1/mail-sessions/{session_id}/events", "get"),
            ("/api/v1/mail-session/{session_id}/code", "get"),
            ("/api/v1/mail-session/{session_id}/revoke", "post"),
            ("/api/v1/mail-session/{session_id}/events", "get"),
        ):
            with self.subTest(path=path, method=method, parameter="mail token"):
                parameters = schema["paths"][path][method]["parameters"]
                mail_token = next(
                    parameter
                    for parameter in parameters
                    if parameter["name"] == "X-Mail-Session-Token"
                )
                self.assertEqual(mail_token["in"], "header")
                self.assertFalse(mail_token["required"])

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

        with self.assertRaisesRegex(RuntimeError, "INTERNAL_CA_FILE"):
            create_app(
                Settings(
                    environment="production",
                    auth_mode="oidc",
                    database_url="sqlite+pysqlite:///:memory:",
                    oidc_issuer_url="https://identity.example.test/realms/platform",
                    oidc_audience="email-platform-api",
                    oidc_client_id="email-platform-web",
                    oidc_desktop_client_id="email-platform-desktop",
                    oidc_jwks_url="https://identity.example.test/realms/platform/protocol/openid-connect/certs",
                    rate_limit_enabled=True,
                    redis_url="redis://redis.example.test:6379/0",
                    allowed_origins="https://platform.example.test",
                )
            )

    def test_production_requires_worker_owned_mail_polling(self) -> None:
        for environment in ("production", "staging"):
            with self.subTest(environment=environment):
                app = None
                try:
                    with self.assertRaisesRegex(RuntimeError, "MAIL_POLL_MODE=worker"):
                        app = create_app(
                            Settings(
                                environment=environment,
                                auth_mode="oidc",
                                database_url="sqlite+pysqlite:///:memory:",
                                oidc_issuer_url="https://identity.example.test/realms/platform",
                                oidc_audience="email-platform-api",
                                oidc_client_id="email-platform-web",
                                oidc_desktop_client_id="email-platform-desktop",
                                oidc_jwks_url="https://identity.example.test/realms/platform/protocol/openid-connect/certs",
                                internal_ca_file="/run/secrets/internal-tls/ca.crt",
                                rate_limit_enabled=True,
                                redis_url="redis://redis.example.test:6379/0",
                                allowed_origins="https://platform.example.test",
                                mail_poll_mode="api",
                            ),
                            access_token_verifier=object(),
                            rate_limit_backend=object(),
                        )
                finally:
                    if app is not None:
                        app.state.engine.dispose()

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
