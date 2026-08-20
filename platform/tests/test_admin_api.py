import asyncio
import json
import unittest
from datetime import timedelta

import httpx
from sqlalchemy.exc import IntegrityError

from platform.app import create_app
from platform.bootstrap import create_user_with_device, provision_card
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    Mailbox,
    MailSession,
    Task,
    OutboxEvent,
    UploadJob,
    utc_now,
)


class AdminApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            Settings(
                app_name="admin-api-test",
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="admin-api-unit-test-secret-not-for-production",
                sub2_policy_version="sub2-policy-safe-view",
                sub2_proxy_ref="vault://sub2/proxy-private",
                sub2_credential_ref="vault://sub2/credential-private",
                sub2_upload_url="https://sub2.example.test/upload",
            )
        )
        self.admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="admin@example.test",
            password="admin-account-password",
            device_name="admin-device",
            role="platform_admin",
        )
        self.approver = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="approver@example.test",
            password="approver-account-password",
            device_name="approver-device",
            role="platform_admin",
        )
        self.operator = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="operator@example.test",
            password="operator-account-password",
            device_name="operator-device",
            role="operator",
        )
        self.other_tenant = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-b",
            email="other@example.test",
            password="other-account-password",
            device_name="other-device",
            role="platform_admin",
        )

    def tearDown(self) -> None:
        self.app.state.engine.dispose()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def login(self, tenant_id: str, email: str, password: str, device_id: str) -> str:
        response = self.request(
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

    @staticmethod
    def headers(value: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {value}"}

    def test_admin_users_are_tenant_scoped_and_operator_is_forbidden(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        response = self.request("GET", "/api/v1/admin/users", headers=self.headers(admin_token))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            {item["email"] for item in response.json()},
            {
                "admin@example.test",
                "approver@example.test",
                "operator@example.test",
            },
        )
        serialized = json.dumps(response.json())
        self.assertNotIn("password", serialized.lower())

        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        forbidden = self.request(
            "GET", "/api/v1/admin/users", headers=self.headers(operator_token)
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_disable_user_invalidates_existing_session_and_hides_cross_tenant(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        disabled = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/disable",
            headers=self.headers(admin_token),
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertFalse(disabled.json()["is_active"])
        invalidated = self.request("GET", "/api/v1/me", headers=self.headers(operator_token))
        self.assertEqual(invalidated.status_code, 401)

        hidden = self.request(
            "POST",
            f"/api/v1/admin/users/{self.other_tenant.user_id}/disable",
            headers=self.headers(admin_token),
        )
        self.assertEqual(hidden.status_code, 404)

    def test_revoke_device_and_card_projection_are_safe(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        devices = self.request(
            "GET", "/api/v1/admin/devices", headers=self.headers(admin_token)
        )
        self.assertEqual(devices.status_code, 200, devices.text)
        self.assertEqual(
            {item["id"] for item in devices.json()},
            {self.admin.device_id, self.approver.device_id, self.operator.device_id},
        )
        self.assertNotIn(self.other_tenant.device_id, devices.text)
        revoked = self.request(
            "POST",
            f"/api/v1/admin/devices/{self.operator.device_id}/revoke",
            headers=self.headers(admin_token),
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertIsNotNone(revoked.json()["revoked_at"])

        provision_card(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            provider_ref="provider-card-1",
            brand="Visa",
            last4="4242",
            secret_ref="vault://secret/cards/provider-card-1",
        )
        cards = self.request("GET", "/api/v1/admin/cards", headers=self.headers(admin_token))
        self.assertEqual(cards.status_code, 200, cards.text)
        self.assertEqual(cards.json()[0]["last4"], "4242")
        serialized = json.dumps(cards.json()).lower()
        self.assertNotIn("secret_ref", serialized)
        self.assertNotIn("vault://", serialized)

    def test_admin_card_management_rejects_pan_and_releases_active_lease(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        rejected_pan = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "4111111111111111",
                "brand": "Visa",
                "last4": "1111",
                "secret_ref": "vault://secret/cards/card-1",
                "pan": "4111111111111111",
                "cvv": "123",
            },
        )
        self.assertEqual(rejected_pan.status_code, 422, rejected_pan.text)
        rejected_raw_secret = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "provider-card-managed",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "4111111111111111|123",
            },
        )
        self.assertEqual(rejected_raw_secret.status_code, 422, rejected_raw_secret.text)
        for unsafe_payload in (
            {
                "provider_ref": "provider-4111-1111-1111-1111",
                "brand": "Visa",
                "last4": "1111",
                "secret_ref": "vault://secret/cards/unsafe-provider",
            },
            {
                "provider_ref": "safe-provider",
                "brand": "Visa 4111 1111 1111 1111",
                "last4": "1111",
                "secret_ref": "vault://secret/cards/unsafe-brand",
            },
            {
                "provider_ref": "safe-provider",
                "brand": "Visa",
                "last4": "1111",
                "expiry_month": 12,
                "secret_ref": "vault://secret/cards/incomplete-expiry",
            },
            {
                "provider_ref": "safe-provider",
                "brand": "Visa",
                "last4": "1111",
                "secret_ref": "vault://secret/mailboxes/wrong-domain",
            },
            {
                "provider_ref": "safe-provider",
                "brand": "Visa",
                "last4": "1111",
                "secret_ref": "vault://secret/cards/../mailboxes/wrong-domain",
            },
            {
                "provider_ref": "safe-provider",
                "brand": "Visa",
                "last4": "1111",
                "secret_ref": "vault://secret/cards//empty-segment",
            },
        ):
            with self.subTest(unsafe_payload=unsafe_payload):
                rejected = self.request(
                    "POST",
                    "/api/v1/admin/cards",
                    headers=self.headers(admin_token),
                    json=unsafe_payload,
                )
                self.assertEqual(rejected.status_code, 422, rejected.text)

        created = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "provider-card-managed",
                "brand": "Visa",
                "last4": "4242",
                "expiry_month": 12,
                "expiry_year": 2030,
                "secret_ref": "vault://secret/cards/provider-card-managed",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        card_id = created.json()["id"]
        self.assertNotIn("secret_ref", created.text.lower())
        self.assertNotIn("vault://", created.text.lower())

        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "admin-disable-card"},
        )
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/card-allocations",
            headers=self.headers(operator_token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        with self.app.state.session_factory() as db:
            persisted_task = db.get(Task, task.json()["id"])
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="u***@example.test",
                connector_type="http",
                secret_ref="vault://secret/mailboxes/admin-disable-upload",
            )
            db.add(mailbox)
            db.flush()
            db.add(
                MailSession(
                    tenant_id="tenant-a",
                    task_id=persisted_task.id,
                    user_id=self.operator.user_id,
                    device_id=self.operator.device_id,
                    mailbox_id=mailbox.id,
                    trace_id=persisted_task.trace_id,
                    status="consumed",
                    consumed_at=utc_now(),
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            db.commit()
        queued_upload = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/uploads",
            headers=self.headers(operator_token),
            json={"business_name": "Queued", "idempotency_key": "disable-queued"},
        )
        running_upload = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/uploads",
            headers=self.headers(operator_token),
            json={"business_name": "Running", "idempotency_key": "disable-running"},
        )
        with self.app.state.session_factory() as db:
            running = db.get(UploadJob, running_upload.json()["id"])
            running.status = "running"
            db.commit()

        disabled = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertFalse(disabled.json()["is_active"])
        with self.app.state.session_factory() as db:
            persisted = db.get(CardAllocation, allocation.json()["id"])
            self.assertEqual(persisted.status, "released")
            self.assertIsNotNone(persisted.released_at)
            queued = db.get(UploadJob, queued_upload.json()["id"])
            running = db.get(UploadJob, running_upload.json()["id"])
            self.assertEqual(queued.status, "cancelled")
            self.assertEqual(queued.error_code, "card_disabled")
            self.assertEqual(running.status, "unknown")
            self.assertEqual(running.error_code, "external_unknown")
            events = list(
                db.query(OutboxEvent).filter(
                    OutboxEvent.aggregate_id.in_([queued.id, running.id])
                )
            )
            self.assertEqual({event.status for event in events}, {"processed"})

        enabled = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": True},
        )
        self.assertTrue(enabled.json()["is_active"])
        duplicate_secret = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "different-provider-same-secret",
                "brand": "Visa",
                "last4": "9999",
                "secret_ref": "vault://secret/cards/provider-card-managed",
            },
        )
        self.assertEqual(duplicate_secret.status_code, 409, duplicate_secret.text)
        forbidden = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(operator_token),
            json={"is_active": False},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)
        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )
        other_tenant_same_secret = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(other_token),
            json={
                "provider_ref": "tenant-b-card",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "vault://secret/cards/provider-card-managed",
            },
        )
        self.assertEqual(other_tenant_same_secret.status_code, 201, other_tenant_same_secret.text)
        hidden = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(other_token),
            json={"is_active": False},
        )
        self.assertEqual(hidden.status_code, 404, hidden.text)

        with self.app.state.session_factory() as db:
            audit_text = "\n".join(event.details_json for event in db.query(AuditEvent))
        self.assertNotIn("vault://secret/cards/provider-card-managed", audit_text)

    def test_admin_mailbox_management_revokes_sessions_and_rotates_reference(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        wrong_domain = self.request(
            "POST",
            "/api/v1/admin/mailboxes",
            headers=self.headers(admin_token),
            json={
                "email_masked": "m***@example.test",
                "connector_type": "http",
                "secret_ref": "vault://secret/cards/wrong-domain",
            },
        )
        self.assertEqual(wrong_domain.status_code, 422, wrong_domain.text)
        created = self.request(
            "POST",
            "/api/v1/admin/mailboxes",
            headers=self.headers(admin_token),
            json={
                "email_masked": "m***@example.test",
                "connector_type": "http",
                "secret_ref": "vault://secret/mailboxes/managed-v1",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        mailbox_id = created.json()["id"]
        self.assertNotIn("secret_ref", created.text.lower())
        self.assertNotIn("vault://", created.text.lower())
        with self.app.state.session_factory() as db:
            task = Task(
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                device_id=self.operator.device_id,
                task_type="mail_code",
                idempotency_key="admin-disable-mailbox",
                status="created",
                expires_at=utc_now() + timedelta(minutes=10),
            )
            db.add(task)
            db.flush()
            session = MailSession(
                tenant_id="tenant-a",
                task_id=task.id,
                user_id=self.operator.user_id,
                device_id=self.operator.device_id,
                mailbox_id=mailbox_id,
                trace_id=task.trace_id,
                status="code_ready",
                expires_at=utc_now() + timedelta(minutes=5),
                delivered_code="987654",
                delivered_at=utc_now(),
                code_expires_at=utc_now() + timedelta(minutes=1),
            )
            db.add(session)
            db.commit()
            session_id = session.id

        disabled = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertEqual(disabled.json()["status"], "disabled")
        self.assertEqual(disabled.json()["active_session_count"], 0)
        with self.app.state.session_factory() as db:
            session = db.get(MailSession, session_id)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertIsNone(session.code_expires_at)

        rotated = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(admin_token),
            json={"secret_ref": "vault://secret/mailboxes/managed-v2"},
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        self.assertNotIn("vault://", rotated.text.lower())
        rejected_rotation = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(admin_token),
            json={"secret_ref": "vault://secret/cards/wrong-domain"},
        )
        self.assertEqual(rejected_rotation.status_code, 422, rejected_rotation.text)
        enabled = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox_id}",
            headers=self.headers(admin_token),
            json={"is_active": True},
        )
        self.assertTrue(enabled.json()["is_active"])
        with self.app.state.session_factory() as db:
            mailbox = db.get(Mailbox, mailbox_id)
            self.assertEqual(mailbox.secret_ref, "vault://secret/mailboxes/managed-v2")
            audit_text = "\n".join(event.details_json for event in db.query(AuditEvent))
        self.assertNotIn("vault://secret/mailboxes/managed-v1", audit_text)
        self.assertNotIn("vault://secret/mailboxes/managed-v2", audit_text)

        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        forbidden = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(operator_token),
            json={"secret_ref": "vault://secret/mailboxes/forbidden"},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)
        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )
        hidden = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox_id}",
            headers=self.headers(other_token),
            json={"is_active": False},
        )
        self.assertEqual(hidden.status_code, 404, hidden.text)

    def test_card_secret_reference_unique_constraint_closes_concurrent_check_race(self) -> None:
        first = self.app.state.session_factory()
        second = self.app.state.session_factory()
        try:
            first.add(Card(
                tenant_id="tenant-a",
                provider_ref="race-provider-a",
                brand="Visa",
                last4="4242",
                secret_ref="vault://secret/cards/race-shared",
            ))
            second.add(Card(
                tenant_id="tenant-a",
                provider_ref="race-provider-b",
                brand="Visa",
                last4="4242",
                secret_ref="vault://secret/cards/race-shared",
            ))
            first.commit()
            with self.assertRaises(IntegrityError):
                second.commit()
        finally:
            first.close()
            second.close()

    def test_resource_management_role_matrix_allows_only_ops_and_platform_admin(self) -> None:
        ops = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="ops-resource@example.test",
            password="ops-resource-account-password",
            device_name="ops-resource-device",
            role="ops_admin",
        )
        auditor = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="audit-resource@example.test",
            password="audit-resource-account-password",
            device_name="audit-resource-device",
            role="security_auditor",
        )
        ops_token = self.login(
            "tenant-a",
            "ops-resource@example.test",
            "ops-resource-account-password",
            ops.device_id,
        )
        created = self.request(
            "POST",
            "/api/v1/admin/mailboxes",
            headers=self.headers(ops_token),
            json={
                "email_masked": "o***@example.test",
                "connector_type": "http",
                "secret_ref": "vault://secret/mailboxes/ops-resource",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)

        auditor_token = self.login(
            "tenant-a",
            "audit-resource@example.test",
            "audit-resource-account-password",
            auditor.device_id,
        )
        denied = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{created.json()['id']}",
            headers=self.headers(auditor_token),
            json={"is_active": False},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

    def test_audit_and_upload_views_follow_security_roles(self) -> None:
        auditor = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="auditor@example.test",
            password="auditor-account-password",
            device_name="auditor-device",
            role="security_auditor",
        )
        auditor_token = self.login(
            "tenant-a",
            "auditor@example.test",
            "auditor-account-password",
            auditor.device_id,
        )
        audit = self.request("GET", "/api/v1/admin/audit", headers=self.headers(auditor_token))
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertTrue(audit.json())
        serialized = json.dumps(audit.json()).lower()
        self.assertNotIn("auditor-account-password", serialized)

        uploads = self.request(
            "GET", "/api/v1/admin/uploads", headers=self.headers(auditor_token)
        )
        self.assertEqual(uploads.status_code, 200, uploads.text)
        users = self.request("GET", "/api/v1/admin/users", headers=self.headers(auditor_token))
        self.assertEqual(users.status_code, 403)

    def test_upload_policy_status_is_privileged_and_hides_execution_details(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        response = self.request(
            "GET",
            "/api/v1/admin/policies/upload",
            headers=self.headers(admin_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json(),
            {
                "policy_version": "sub2-policy-safe-view",
                "status": "ready",
                "upload_endpoint_configured": True,
                "upload_secret_configured": True,
                "network_route_configured": True,
                "server_managed": True,
                "governance_configured": False,
                "active_version": None,
                "previous_version": None,
                "rollout_percent": None,
            },
        )
        serialized = json.dumps(response.json()).lower()
        for forbidden in (
            "vault://",
            "proxy-private",
            "credential-private",
            "sub2.example.test",
            "group_id",
            "concurrency",
            "token",
            "proxy_ref",
            "credential_ref",
        ):
            self.assertNotIn(forbidden, serialized)

        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        forbidden = self.request(
            "GET",
            "/api/v1/admin/policies/upload",
            headers=self.headers(operator_token),
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_upload_policy_requires_four_eye_approval_and_supports_rollback(self) -> None:
        creator_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        approver_token = self.login(
            "tenant-a",
            "approver@example.test",
            "approver-account-password",
            self.approver.device_id,
        )

        def register(version: str) -> dict[str, object]:
            response = self.request(
                "POST",
                "/api/v1/admin/policies/upload/versions",
                headers=self.headers(creator_token),
                json={"version": version, "change_note": f"review {version}"},
            )
            self.assertEqual(response.status_code, 201, response.text)
            return response.json()

        first = register("sub2-governed-v1")
        self_approval = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{first['id']}/approve",
            headers=self.headers(creator_token),
        )
        self.assertEqual(self_approval.status_code, 409, self_approval.text)
        approved = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{first['id']}/approve",
            headers=self.headers(approver_token),
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["status"], "approved")

        partial_first = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{first['id']}/deploy",
            headers=self.headers(creator_token),
            json={"rollout_percent": 10},
        )
        self.assertEqual(partial_first.status_code, 409, partial_first.text)
        deployed_first = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{first['id']}/deploy",
            headers=self.headers(creator_token),
            json={"rollout_percent": 100},
        )
        self.assertEqual(deployed_first.status_code, 200, deployed_first.text)

        second = register("sub2-governed-v2")
        approved_second = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{second['id']}/approve",
            headers=self.headers(approver_token),
        )
        self.assertEqual(approved_second.status_code, 200, approved_second.text)
        canary = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{second['id']}/deploy",
            headers=self.headers(creator_token),
            json={"rollout_percent": 20},
        )
        self.assertEqual(canary.status_code, 200, canary.text)
        self.assertEqual(
            canary.json(),
            {
                "active_version": "sub2-governed-v2",
                "previous_version": "sub2-governed-v1",
                "rollout_percent": 20,
                "updated_at": canary.json()["updated_at"],
            },
        )

        status = self.request(
            "GET", "/api/v1/admin/policies/upload", headers=self.headers(creator_token)
        )
        self.assertEqual(status.status_code, 200, status.text)
        self.assertTrue(status.json()["governance_configured"])
        self.assertEqual(status.json()["active_version"], "sub2-governed-v2")
        self.assertEqual(status.json()["rollout_percent"], 20)

        rolled_back = self.request(
            "POST",
            "/api/v1/admin/policies/upload/rollback",
            headers=self.headers(creator_token),
        )
        self.assertEqual(rolled_back.status_code, 200, rolled_back.text)
        self.assertEqual(rolled_back.json()["active_version"], "sub2-governed-v1")
        self.assertEqual(rolled_back.json()["previous_version"], "sub2-governed-v2")
        self.assertEqual(rolled_back.json()["rollout_percent"], 100)

        versions = self.request(
            "GET",
            "/api/v1/admin/policies/upload/versions",
            headers=self.headers(creator_token),
        )
        self.assertEqual(versions.status_code, 200, versions.text)
        serialized = json.dumps(versions.json()).lower()
        for forbidden in (
            "vault://",
            "proxy-private",
            "credential-private",
            "group_id",
            "concurrency",
            "credential_ref",
            "proxy_ref",
        ):
            self.assertNotIn(forbidden, serialized)

        with self.app.state.session_factory() as db:
            audit_text = "\n".join(
                event.details_json
                for event in db.query(AuditEvent).filter(
                    AuditEvent.event_type.like("upload_policy.%")
                )
            ).lower()
        self.assertIn("sub2-governed-v1", audit_text)
        for forbidden in (
            "vault://",
            "proxy-private",
            "credential-private",
            "group_id",
            "concurrency",
        ):
            self.assertNotIn(forbidden, audit_text)

        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )
        cross_tenant = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{first['id']}/approve",
            headers=self.headers(other_token),
        )
        self.assertEqual(cross_tenant.status_code, 404)

    def test_admin_audit_redacts_card_secrets_on_write_and_legacy_read(self) -> None:
        with self.app.state.session_factory() as db:
            db.add(
                AuditEvent(
                    tenant_id="tenant-a",
                    user_id=self.operator.user_id,
                    device_id=self.operator.device_id,
                    event_type="legacy.unsafe",
                    entity_type="legacy",
                    entity_id="legacy-1",
                    trace_id="00000000-0000-0000-0000-000000000001",
                    details_json=json.dumps(
                        {
                            "PAN": "4111111111111111",
                            "CVV": "123",
                            "card_number": "5555555555554444",
                            "company_name": "safe-company",
                        }
                    ),
                )
            )
            db.commit()
        admin_token = self.login(
            "tenant-a",
            "admin@example.test",
            "admin-account-password",
            self.admin.device_id,
        )
        response = self.request(
            "GET", "/api/v1/admin/audit", headers=self.headers(admin_token)
        )
        self.assertEqual(response.status_code, 200, response.text)
        serialized = json.dumps(response.json()).lower()
        for forbidden in (
            "4111111111111111",
            "5555555555554444",
            '"pan"',
            '"cvv"',
            '"card_number"',
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("safe-company", serialized)


if __name__ == "__main__":
    unittest.main()
