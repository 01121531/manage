import asyncio
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest import mock

import httpx
from fastapi import Depends
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from platform.app import create_app
from platform.api.v1 import routes
from platform.audit import record_audit
from platform.auth import AuthPrincipal, get_current_principal, get_operator_principal
from platform.bootstrap import create_user_with_device, provision_card
from platform.card_events import safe_card_event_state
from platform.config import Settings
from platform.models import (
    AdminRoleChangeRequest,
    AuditEvent,
    Card,
    CardAllocation,
    CardEvent,
    Device,
    Mailbox,
    MailSession,
    Task,
    OutboxEvent,
    UploadJob,
    User,
    utc_now,
)
from platform.uploads import (
    Sub2UploadResult,
    process_queued_uploads,
    process_upload_job,
)


class AdminApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "admin-api.db"
        self.app = create_app(
            Settings(
                app_name="admin-api-test",
                environment="test",
                database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
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
        self.temp_dir.cleanup()

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

    def request_and_approve_role_change(
        self,
        requester_token: str,
        *,
        target_user_id: str,
        role: str,
    ) -> httpx.Response:
        requested = self.request(
            "POST",
            f"/api/v1/admin/users/{target_user_id}/role-change-requests",
            headers=self.headers(requester_token),
            json={"role": role},
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        return self.approve_role_change(requested.json()["id"])

    def approve_role_change(self, role_change_id: str) -> httpx.Response:
        fresh_auth_time = datetime.now(timezone.utc) + timedelta(seconds=1)
        approver_principal = AuthPrincipal(
            user_id=self.approver.user_id,
            tenant_id="tenant-a",
            device_id=self.approver.device_id,
            email="approver@example.test",
            role="platform_admin",
            identity_kind="oidc",
            auth_time=fresh_auth_time,
            acr="urn:email-platform:acr:mfa",
            amr=("pwd", "otp"),
            access_token_hash="f" * 64,
            access_token_expires_at=fresh_auth_time + timedelta(minutes=15),
            access_token_revoked=False,
        )
        self.app.dependency_overrides[get_current_principal] = lambda: approver_principal
        try:
            return self.request(
                "POST",
                f"/api/v1/admin/role-change-requests/{role_change_id}/approve",
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

    @staticmethod
    def headers(value: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {value}"}

    def create_card_upload_fixture(
        self,
        *,
        admin_token: str,
        operator_token: str,
        suffix: str,
    ) -> tuple[str, str, str, str]:
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": f"provider-card-{suffix}",
                "brand": "Visa",
                "last4": "4242",
                "expiry_month": 12,
                "expiry_year": 2030,
                "secret_ref": f"vault://secret/cards/{suffix}",
            },
        )
        self.assertEqual(card.status_code, 201, card.text)
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": f"task-{suffix}"},
        )
        self.assertEqual(task.status_code, 201, task.text)
        task_id = task.json()["id"]
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.headers(operator_token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        with self.app.state.session_factory() as db:
            persisted_task = db.get(Task, task_id)
            mailbox = Mailbox(
                tenant_id="tenant-a",
                email_masked="u***@example.test",
                connector_type="http",
                secret_ref=f"vault://secret/mailboxes/{suffix}",
            )
            db.add(mailbox)
            db.flush()
            db.add(
                MailSession(
                    tenant_id="tenant-a",
                    task_id=task_id,
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
        upload = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.headers(operator_token),
            json={"business_name": "Example Store", "idempotency_key": f"upload-{suffix}"},
        )
        self.assertEqual(upload.status_code, 201, upload.text)
        return card.json()["id"], task_id, allocation.json()["id"], upload.json()["id"]

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

    def test_user_disable_wins_after_authentication_before_task_insert(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        authenticated = Event()
        resume = Event()

        def delayed_operator(
            principal: AuthPrincipal = Depends(get_current_principal),
        ) -> AuthPrincipal:
            authenticated.set()
            if not resume.wait(timeout=5):
                raise RuntimeError("timed out waiting to resume task creation")
            return principal

        self.app.dependency_overrides[get_operator_principal] = delayed_operator
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(
                    self.request,
                    "POST",
                    "/api/v1/tasks",
                    headers=self.headers(operator_token),
                    json={
                        "type": "card_checkout",
                        "idempotency_key": "disable-wins-late-task",
                    },
                )
                self.assertTrue(authenticated.wait(timeout=5))
                disabled = self.request(
                    "POST",
                    f"/api/v1/admin/users/{self.operator.user_id}/disable",
                    headers=self.headers(admin_token),
                )
                self.assertEqual(disabled.status_code, 200, disabled.text)
                resume.set()
                late = pending.result(timeout=10)
        finally:
            resume.set()
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertEqual(late.status_code, 401, late.text)
        self.assertNotIn("disabled", late.text.lower())
        self.assertNotIn("revoked", late.text.lower())
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(
                    select(Task).where(
                        Task.idempotency_key == "disable-wins-late-task"
                    )
                )
            )
            self.assertIsNone(
                db.scalar(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "task.created",
                        AuditEvent.details_json.contains("disable-wins-late-task"),
                    )
                )
            )

    def test_device_revoke_wins_after_authentication_before_task_insert(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        authenticated = Event()
        resume = Event()

        def delayed_operator(
            principal: AuthPrincipal = Depends(get_current_principal),
        ) -> AuthPrincipal:
            authenticated.set()
            if not resume.wait(timeout=5):
                raise RuntimeError("timed out waiting to resume task creation")
            return principal

        self.app.dependency_overrides[get_operator_principal] = delayed_operator
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(
                    self.request,
                    "POST",
                    "/api/v1/tasks",
                    headers=self.headers(operator_token),
                    json={
                        "type": "card_checkout",
                        "idempotency_key": "revoke-wins-late-task",
                    },
                )
                self.assertTrue(authenticated.wait(timeout=5))
                revoked = self.request(
                    "POST",
                    f"/api/v1/admin/devices/{self.operator.device_id}/revoke",
                    headers=self.headers(admin_token),
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
                resume.set()
                late = pending.result(timeout=10)
        finally:
            resume.set()
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertEqual(late.status_code, 401, late.text)
        self.assertNotIn("disabled", late.text.lower())
        self.assertNotIn("revoked", late.text.lower())
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(
                    select(Task).where(
                        Task.idempotency_key == "revoke-wins-late-task"
                    )
                )
            )

    def test_user_disable_wins_while_local_login_is_verifying(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        password_verified = Event()
        resume = Event()
        original_verify_password = routes.verify_password

        def delayed_verify_password(password: str, password_hash: str) -> bool:
            verified = original_verify_password(password, password_hash)
            if verified and password == "operator-account-password":
                password_verified.set()
                if not resume.wait(timeout=5):
                    raise RuntimeError("timed out waiting to resume login")
            return verified

        try:
            with mock.patch.object(
                routes, "verify_password", side_effect=delayed_verify_password
            ):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    pending = executor.submit(
                        self.request,
                        "POST",
                        "/api/v1/auth/login",
                        json={
                            "tenant_id": "tenant-a",
                            "email": "operator@example.test",
                            "password": "operator-account-password",
                            "device_id": self.operator.device_id,
                        },
                    )
                    self.assertTrue(password_verified.wait(timeout=5))
                    disabled = self.request(
                        "POST",
                        f"/api/v1/admin/users/{self.operator.user_id}/disable",
                        headers=self.headers(admin_token),
                    )
                    self.assertEqual(disabled.status_code, 200, disabled.text)
                    resume.set()
                    late = pending.result(timeout=10)
        finally:
            resume.set()

        self.assertEqual(late.status_code, 401, late.text)
        self.assertNotIn("disabled", late.text.lower())
        self.assertNotIn("revoked", late.text.lower())
        self.assertNotIn("access_token", late.text)
        with self.app.state.session_factory() as db:
            login_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.user_id == self.operator.user_id,
                        AuditEvent.event_type == "auth.login",
                    )
                )
            )
        self.assertEqual(len(login_events), 0)

    def test_role_changes_and_batch_disable_are_scoped_audited_and_fail_closed(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        role_changed = self.request_and_approve_role_change(
            admin_token,
            target_user_id=self.operator.user_id,
            role="security_auditor",
        )
        self.assertEqual(role_changed.status_code, 200, role_changed.text)
        self.assertEqual(role_changed.json()["new_role"], "security_auditor")
        self.assertEqual(role_changed.json()["status"], "applied")
        auditor_access = self.request(
            "GET", "/api/v1/admin/audit", headers=self.headers(operator_token)
        )
        self.assertEqual(auditor_access.status_code, 200, auditor_access.text)

        self_change = self.request(
            "POST",
            f"/api/v1/admin/users/{self.admin.user_id}/role-change-requests",
            headers=self.headers(admin_token),
            json={"role": "operator"},
        )
        self.assertEqual(self_change.status_code, 409)
        worker_role = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/role-change-requests",
            headers=self.headers(admin_token),
            json={"role": "worker_service"},
        )
        self.assertEqual(worker_role.status_code, 422)
        with self.app.state.session_factory() as db:
            approver = db.get(User, self.approver.user_id)
            self.assertIsNotNone(approver)
            approver.role = "ops_admin"
            db.commit()
        ops_token = self.login(
            "tenant-a",
            "approver@example.test",
            "approver-account-password",
            self.approver.device_id,
        )
        forbidden_role_change = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/role-change-requests",
            headers=self.headers(ops_token),
            json={"role": "operator"},
        )
        self.assertEqual(forbidden_role_change.status_code, 403)
        forbidden_admin_disable = self.request(
            "POST",
            f"/api/v1/admin/users/{self.admin.user_id}/disable",
            headers=self.headers(ops_token),
        )
        self.assertEqual(forbidden_admin_disable.status_code, 403)

        second_operator = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="operator-two@example.test",
            password="operator-two-password",
            device_name="operator-two-device",
            role="operator",
        )
        batch = self.request(
            "POST",
            "/api/v1/admin/users/batch-disable",
            headers=self.headers(admin_token),
            json={"user_ids": [self.operator.user_id, second_operator.user_id]},
        )
        self.assertEqual(batch.status_code, 200, batch.text)
        self.assertEqual(
            [item["id"] for item in batch.json()],
            [self.operator.user_id, second_operator.user_id],
        )
        self.assertTrue(all(not item["is_active"] for item in batch.json()))
        invalidated = self.request(
            "GET", "/api/v1/me", headers=self.headers(operator_token)
        )
        self.assertEqual(invalidated.status_code, 401)

        no_partial = self.request(
            "POST",
            "/api/v1/admin/users/batch-disable",
            headers=self.headers(admin_token),
            json={"user_ids": [self.approver.user_id, self.other_tenant.user_id]},
        )
        self.assertEqual(no_partial.status_code, 404)
        with self.app.state.session_factory() as db:
            approver = db.get(User, self.approver.user_id)
            self.assertIsNotNone(approver)
            self.assertTrue(approver.is_active)
            events = list(
                db.query(AuditEvent).filter(
                    AuditEvent.event_type.in_(
                        ["admin.user_role_changed", "admin.user_disabled"]
                    )
                )
            )
        self.assertEqual(
            sum(event.event_type == "admin.user_role_changed" for event in events),
            1,
        )
        batch_events = [
            event for event in events
            if event.event_type == "admin.user_disabled" and '"batch": true' in event.details_json
        ]
        self.assertEqual(len(batch_events), 2)
        self.assertTrue(
            all(
                event.actor_id == self.approver.user_id
                for event in events
                if event.event_type == "admin.user_role_changed"
            )
        )
        self.assertTrue(
            all(
                event.actor_id == self.admin.user_id
                for event in events
                if event.event_type == "admin.user_disabled"
            )
        )

    def test_role_change_revokes_all_devices_and_replays_without_duplicate_audit(
        self,
    ) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        _, task_id, allocation_id, job_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="role-revocation",
        )
        unrelated = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="role-unrelated@example.test",
            password="role-unrelated-password",
            device_name="role-unrelated-device",
        )
        with self.app.state.session_factory() as db:
            second_device = Device(
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                name="operator-role-second-device",
            )
            db.add(second_device)
            db.flush()
            second_task = Task(
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                device_id=second_device.id,
                task_type="card_checkout",
                idempotency_key="role-second-device-task",
                trace_id="role-second-device-trace",
                status="created",
                expires_at=utc_now() + timedelta(minutes=10),
            )
            unrelated_task = Task(
                tenant_id="tenant-a",
                user_id=unrelated.user_id,
                device_id=unrelated.device_id,
                task_type="card_checkout",
                idempotency_key="role-unrelated-task",
                trace_id="role-unrelated-trace",
                status="created",
                expires_at=utc_now() + timedelta(minutes=10),
            )
            db.add_all([second_task, unrelated_task])
            db.commit()
            second_task_id = second_task.id
            unrelated_task_id = unrelated_task.id

        changed = self.request_and_approve_role_change(
            admin_token,
            target_user_id=self.operator.user_id,
            role="security_auditor",
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["new_role"], "security_auditor")
        forbidden = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "role-forbidden-task"},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)
        auditor_access = self.request(
            "GET", "/api/v1/admin/audit", headers=self.headers(operator_token)
        )
        self.assertEqual(auditor_access.status_code, 200, auditor_access.text)

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            job = db.get(UploadJob, job_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            second_task = db.get(Task, second_task_id)
            unrelated_task = db.get(Task, unrelated_task_id)
            self.assertEqual(task.status, "cancelled")
            self.assertEqual(allocation.status, "released")
            self.assertEqual(session.status, "revoked")
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(outbox.status, "processed")
            self.assertEqual(second_task.status, "cancelled")
            self.assertEqual(unrelated_task.status, "created")
            role_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.operator.user_id,
                    )
                )
            )
            resource_events_before = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_(
                            (task_id, allocation_id, session.id, job_id, second_task_id)
                        )
                    )
                )
            )
            cleanup_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.details_json.contains("admin_user_role_changed")
                    )
                )
            )
        self.assertEqual(len(role_events), 1)
        self.assertEqual(role_events[0].actor_id, self.approver.user_id)
        self.assertTrue(cleanup_events)
        self.assertTrue(all(event.user_id == self.operator.user_id for event in cleanup_events))
        self.assertTrue(
            all(event.actor_id == self.approver.user_id for event in cleanup_events)
        )
        serialized_events = " ".join(
            event.details_json.lower() for event in role_events + cleanup_events
        )
        for forbidden_value in ("vault://", "password", "token", "external_ref"):
            self.assertNotIn(forbidden_value, serialized_events)

        replay = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/role-change-requests",
            headers=self.headers(admin_token),
            json={"role": "security_auditor"},
        )
        self.assertEqual(replay.status_code, 409, replay.text)
        with self.app.state.session_factory() as db:
            role_events_after = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.operator.user_id,
                    )
                )
            )
            resource_events_after = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_(
                            (task_id, allocation_id, session.id, job_id, second_task_id)
                        )
                    )
                )
            )
        self.assertEqual(len(role_events_after), 1)
        self.assertEqual(len(resource_events_after), len(resource_events_before))

    def test_repeated_non_operator_role_repairs_phase_two_residue(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "role-residual-task"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        requested = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/role-change-requests",
            headers=self.headers(admin_token),
            json={"role": "security_auditor"},
        )
        self.assertEqual(requested.status_code, 201, requested.text)
        with self.app.state.session_factory() as db:
            user = db.get(User, self.operator.user_id)
            role_change = db.get(AdminRoleChangeRequest, requested.json()["id"])
            user.role = "security_auditor"
            role_change.status = "applied"
            role_change.approved_by = self.approver.user_id
            role_change.approval_trace_id = "role-state-barrier"
            role_change.applied_at = utc_now()
            record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="admin.user_role_changed",
                entity_type="user",
                entity_id=self.operator.user_id,
                trace_id="role-state-barrier",
                details={"previous_role": "operator", "new_role": "security_auditor"},
            )
            db.commit()

        repaired = self.approve_role_change(requested.json()["id"])
        self.assertEqual(repaired.status_code, 409, repaired.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "cancelled")
            state_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.operator.user_id,
                    )
                )
            )
        self.assertEqual(len(state_events), 1)

    def test_role_change_does_not_overwrite_completed_worker_success(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        _, task_id, _, job_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="role-worker-race",
        )
        class SuccessfulAdapter:
            def __init__(self) -> None:
                self.commands = []

            def submit(self, command):
                self.commands.append(command)
                return Sub2UploadResult(external_ref="role-race-success")

        adapter = SuccessfulAdapter()
        worker_result = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )
        changed = self.request_and_approve_role_change(
            admin_token,
            target_user_id=self.operator.user_id,
            role="security_auditor",
        )

        self.assertEqual(worker_result.status, "succeeded")
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(len(adapter.commands), 1)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            task = db.get(Task, task_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(
                        AuditEvent.entity_id.in_((job_id, task_id))
                    )
                )
            )
            role_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.operator.user_id,
                    )
                )
            )
            self.assertEqual(job.status, "succeeded")
            self.assertEqual(job.external_ref, "role-race-success")
            self.assertEqual(task.status, "completed")
            self.assertEqual(event_types.count("upload.succeeded"), 1)
            self.assertEqual(len(role_events), 1)

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
        by_id = {item["id"]: item for item in devices.json()}
        self.assertIsNotNone(by_id[self.admin.device_id]["last_seen_at"])
        self.assertIsNone(by_id[self.operator.device_id]["last_seen_at"])
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
        card_id = cards.json()[0]["id"]
        with self.app.state.session_factory() as db:
            audit_event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_type == "card",
                    AuditEvent.entity_id == card_id,
                    AuditEvent.event_type == "admin.card_created",
                )
            )
            card_event = db.scalar(
                select(CardEvent).where(
                    CardEvent.card_id == card_id,
                    CardEvent.action == "card.created",
                )
            )
            self.assertIsNotNone(audit_event)
            self.assertIsNotNone(card_event)
            self.assertEqual(audit_event.actor_id, "platform-bootstrap")
            self.assertEqual(card_event.actor_id, "platform-bootstrap")
            self.assertEqual(card_event.trace_id, audit_event.trace_id)
            self.assertEqual(
                safe_card_event_state(card_event.after_masked),
                {
                    "card_masked": "**** **** **** 4242",
                    "brand": "Visa",
                    "card_status": "available",
                },
            )

    def test_repeated_user_disable_repairs_resources_without_repeating_state_audit(
        self,
    ) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={
                "type": "card_checkout",
                "idempotency_key": "disabled-user-residual-task",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        with self.app.state.session_factory() as db:
            user = db.get(User, self.operator.user_id)
            self.assertIsNotNone(user)
            user.is_active = False
            record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="admin.user_disabled",
                entity_type="user",
                entity_id=self.operator.user_id,
                trace_id="disabled-user-state-barrier",
                details={"role": "operator"},
            )
            db.commit()

        repaired = self.request(
            "POST",
            f"/api/v1/admin/users/{self.operator.user_id}/disable",
            headers=self.headers(admin_token),
        )
        self.assertEqual(repaired.status_code, 200, repaired.text)
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            self.assertEqual(task.status, "cancelled")
            state_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_disabled",
                        AuditEvent.entity_id == self.operator.user_id,
                    )
                )
            )
        self.assertEqual(len(state_events), 1)

    def test_repeated_device_revoke_repairs_only_that_device_without_duplicate_audit(
        self,
    ) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        target_created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={
                "type": "card_checkout",
                "idempotency_key": "revoked-device-residual-task",
            },
        )
        self.assertEqual(target_created.status_code, 201, target_created.text)
        target_task_id = target_created.json()["id"]
        with self.app.state.session_factory() as db:
            other_device = Device(
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                name="operator-other-device",
            )
            db.add(other_device)
            db.flush()
            other_task = Task(
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                device_id=other_device.id,
                task_type="card_checkout",
                idempotency_key="other-device-open-task",
                trace_id="other-device-open-task-trace",
                status="created",
                expires_at=utc_now() + timedelta(minutes=10),
            )
            db.add(other_task)
            target_device = db.get(Device, self.operator.device_id)
            self.assertIsNotNone(target_device)
            target_device.revoked_at = utc_now()
            record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.admin.user_id,
                device_id=self.admin.device_id,
                event_type="admin.device_revoked",
                entity_type="device",
                entity_id=self.operator.device_id,
                trace_id="revoked-device-state-barrier",
                details={"device_owner_id": self.operator.user_id},
            )
            db.commit()
            other_task_id = other_task.id

        repaired = self.request(
            "POST",
            f"/api/v1/admin/devices/{self.operator.device_id}/revoke",
            headers=self.headers(admin_token),
        )
        self.assertEqual(repaired.status_code, 200, repaired.text)
        with self.app.state.session_factory() as db:
            target_task = db.get(Task, target_task_id)
            other_task = db.get(Task, other_task_id)
            self.assertIsNotNone(target_task)
            self.assertIsNotNone(other_task)
            self.assertEqual(target_task.status, "cancelled")
            self.assertEqual(other_task.status, "created")
            state_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.device_revoked",
                        AuditEvent.entity_id == self.operator.device_id,
                    )
                )
            )
        self.assertEqual(len(state_events), 1)

    def test_admin_card_management_rejects_unsafe_provider_metadata(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        unsafe_values = (
            (
                "provider_ref",
                "vault://x Authorization=Bearer P_SECRET",
            ),
            (
                "brand",
                "vault://x Authorization=Bearer B_SECRET",
            ),
        )
        with self.app.state.session_factory() as db:
            card_count = db.scalar(select(func.count()).select_from(Card))
            audit_count = db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event_type == "admin.card_created")
            )

        for index, (field, sentinel) in enumerate(unsafe_values):
            with self.subTest(field=field):
                payload = {
                    "provider_ref": f"provider-card-unsafe-{index}",
                    "brand": "Visa",
                    "last4": "4242",
                    "expiry_month": 12,
                    "expiry_year": 2030,
                    "secret_ref": f"vault://secret/cards/unsafe-metadata-{index}",
                }
                payload[field] = sentinel
                rejected = self.request(
                    "POST",
                    "/api/v1/admin/cards",
                    headers=self.headers(admin_token),
                    json=payload,
                )

                self.assertEqual(rejected.status_code, 422, rejected.text)
                error = rejected.json()["error"]
                self.assertEqual(error["code"], "validation_error")
                self.assertEqual(error["message"], "Request validation failed")
                self.assertEqual(error["recovery_hint"], "检查请求字段后重新提交")
                for forbidden in (sentinel, "vault://", "Authorization", "Bearer"):
                    self.assertNotIn(forbidden, rejected.text)

        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), card_count)
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "admin.card_created")
                ),
                audit_count,
            )

        safe = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "  provider-card_1:v2  ",
                "brand": "  Visa  ",
                "last4": "4242",
                "expiry_month": 12,
                "expiry_year": 2030,
                "secret_ref": "vault://secret/cards/safe-provider-metadata",
            },
        )
        self.assertEqual(safe.status_code, 201, safe.text)
        self.assertEqual(safe.json()["provider_ref"], "provider-card_1:v2")
        self.assertEqual(safe.json()["brand"], "Visa")

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
        self.assertEqual(queued_upload.status_code, 201, queued_upload.text)
        with self.app.state.session_factory() as db:
            queued = db.get(UploadJob, queued_upload.json()["id"])
            running = UploadJob(
                tenant_id=queued.tenant_id,
                task_id=queued.task_id,
                user_id=queued.user_id,
                device_id=queued.device_id,
                card_allocation_id=queued.card_allocation_id,
                idempotency_key="disable-running",
                business_name="Running",
                trace_id=queued.trace_id,
                status="running",
                policy_version=queued.policy_version,
            )
            db.add(running)
            db.flush()
            db.add(
                OutboxEvent(
                    tenant_id=running.tenant_id,
                    event_type="upload.requested",
                    aggregate_type="upload_job",
                    aggregate_id=running.id,
                    status="processing",
                )
            )
            db.commit()
            running_upload_id = running.id

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
            running = db.get(UploadJob, running_upload_id)
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

    def test_card_quarantine_is_distinct_idempotent_and_requires_explicit_release(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card_id, task_id, allocation_id, upload_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="quarantine",
        )

        listed = self.request(
            "GET", "/api/v1/admin/cards", headers=self.headers(admin_token)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()[0]["status"], "allocated")

        unsafe_reason = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/quarantine",
            headers=self.headers(admin_token),
            json={"reason_code": "free text with spaces"},
        )
        self.assertEqual(unsafe_reason.status_code, 422, unsafe_reason.text)

        quarantined = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/quarantine",
            headers=self.headers(admin_token),
            json={"reason_code": "suspected_compromise"},
        )
        self.assertEqual(quarantined.status_code, 200, quarantined.text)
        self.assertEqual(quarantined.json()["status"], "quarantined")
        self.assertFalse(quarantined.json()["is_active"])
        self.assertEqual(
            quarantined.json()["quarantine_reason_code"], "suspected_compromise"
        )
        self.assertIsNotNone(quarantined.json()["quarantined_at"])
        for forbidden in ("secret_ref", "vault://", "pan", "cvv"):
            self.assertNotIn(forbidden, quarantined.text.lower())

        repeated = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/quarantine",
            headers=self.headers(admin_token),
            json={"reason_code": "compliance_review"},
        )
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(
            repeated.json()["quarantine_reason_code"], "suspected_compromise"
        )

        legacy_enable = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": True},
        )
        self.assertEqual(legacy_enable.status_code, 409, legacy_enable.text)
        self.assertEqual(legacy_enable.json()["error"]["code"], "card_quarantined")

        operator_release = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/release-quarantine",
            headers=self.headers(operator_token),
        )
        self.assertEqual(operator_release.status_code, 403, operator_release.text)

        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocation_id)
            upload = db.get(UploadJob, upload_id)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(upload.status, "cancelled")
            self.assertEqual(upload.error_code, "card_quarantined")
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "admin.card_quarantined")
                ),
                1,
            )

        no_reallocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.headers(operator_token),
        )
        self.assertEqual(no_reallocation.status_code, 503, no_reallocation.text)

        released = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/release-quarantine",
            headers=self.headers(admin_token),
        )
        self.assertEqual(released.status_code, 200, released.text)
        self.assertEqual(released.json()["status"], "disabled")
        self.assertFalse(released.json()["is_active"])
        self.assertIsNone(released.json()["quarantined_at"])
        self.assertIsNone(released.json()["quarantine_reason_code"])

        enabled = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": True},
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertEqual(enabled.json()["status"], "available")

        with self.app.state.session_factory() as db:
            event_types = [event.event_type for event in db.query(AuditEvent)]
        self.assertEqual(event_types.count("admin.card_quarantined"), 1)
        self.assertEqual(event_types.count("admin.card_quarantine_released"), 1)

    def test_card_timeline_and_targeted_recycle_are_safe_idempotent_and_tenant_bound(
        self,
    ) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        next_operator = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="next-operator@example.test",
            password="next-operator-account-password",
            device_name="next-operator-device",
            role="operator",
        )
        next_operator_token = self.login(
            "tenant-a",
            "next-operator@example.test",
            "next-operator-account-password",
            next_operator.device_id,
        )
        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )
        card_id, task_id, allocation_id, upload_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="timeline-recycle",
        )
        with self.app.state.session_factory() as db:
            db.add(
                CardEvent(
                    tenant_id="tenant-a",
                    card_id=card_id,
                    allocation_id=allocation_id,
                    actor_id="legacy-writer",
                    action="card.legacy_dirty",
                    before_masked=json.dumps(
                        {"card_status": "available", "cvv2": "123"}
                    ),
                    after_masked=json.dumps(
                        {
                            "card_status": "allocated",
                            "verification_value": "987",
                            "account_number": "4111111111111111",
                            "nested": {"secret_ref": "vault://must-never-render"},
                        }
                    ),
                    trace_id="00000000-0000-0000-0000-000000000125",
                )
            )
            db.commit()

        timeline = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        timeline_body = timeline.json()
        self.assertEqual(timeline_body["card"]["id"], card_id)
        self.assertEqual(timeline_body["allocations"][0]["id"], allocation_id)
        self.assertEqual(timeline_body["allocations"][0]["status"], "active")
        self.assertIn(
            "card.created", {event["action"] for event in timeline_body["events"]}
        )
        self.assertIn(
            "allocation.allocated",
            {event["action"] for event in timeline_body["events"]},
        )
        allocated_event = next(
            event
            for event in timeline_body["events"]
            if event["action"] == "allocation.allocated"
        )
        self.assertEqual(allocated_event["actor_id"], self.operator.user_id)
        legacy_event = next(
            event
            for event in timeline_body["events"]
            if event["action"] == "card.legacy_dirty"
        )
        self.assertEqual(legacy_event["before_masked"], {"card_status": "available"})
        self.assertEqual(legacy_event["after_masked"], {"card_status": "allocated"})
        serialized_timeline = json.dumps(timeline_body).lower()
        for forbidden in (
            "vault://secret/cards/timeline-recycle",
            "vault://must-never-render",
            "4111111111111111",
            '"cvv"',
            '"cvv2"',
            '"verification_value"',
            '"account_number"',
            '"secret_ref"',
            '"nested"',
        ):
            self.assertNotIn(forbidden, serialized_timeline)

        first_event_page = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
            params={"event_limit": 2},
        )
        self.assertEqual(first_event_page.status_code, 200, first_event_page.text)
        first_event_body = first_event_page.json()
        self.assertEqual(len(first_event_body["events"]), 2)
        self.assertTrue(first_event_body["events_has_more"])
        self.assertIsNotNone(first_event_body["events_next_cursor"])
        second_event_page = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
            params={
                "event_limit": 2,
                "events_cursor": first_event_body["events_next_cursor"],
            },
        )
        self.assertEqual(second_event_page.status_code, 200, second_event_page.text)
        second_event_body = second_event_page.json()
        paged_event_ids = [
            event["id"]
            for event in first_event_body["events"] + second_event_body["events"]
        ]
        self.assertEqual(len(paged_event_ids), len(set(paged_event_ids)))
        self.assertEqual(
            set(paged_event_ids), {event["id"] for event in timeline_body["events"]}
        )
        self.assertFalse(second_event_body["events_has_more"])
        self.assertIsNone(second_event_body["events_next_cursor"])
        invalid_cursor = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
            params={"events_cursor": "not-a-valid-cursor"},
        )
        self.assertEqual(invalid_cursor.status_code, 422, invalid_cursor.text)

        operator_forbidden = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(operator_token),
        )
        self.assertEqual(operator_forbidden.status_code, 403, operator_forbidden.text)
        tenant_hidden = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(other_token),
            params={"events_cursor": first_event_body["events_next_cursor"]},
        )
        self.assertEqual(tenant_hidden.status_code, 404, tenant_hidden.text)
        unsafe_reason = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/allocations/{allocation_id}/recycle",
            headers=self.headers(admin_token),
            json={"reason_code": "unsafe free text"},
        )
        self.assertEqual(unsafe_reason.status_code, 422, unsafe_reason.text)

        recycled = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/allocations/{allocation_id}/recycle",
            headers=self.headers(admin_token),
            json={"reason_code": "manual_reassignment"},
        )
        self.assertEqual(recycled.status_code, 200, recycled.text)
        self.assertEqual(recycled.json()["status"], "released")
        self.assertEqual(
            recycled.json()["release_reason_code"], "manual_reassignment"
        )

        repeated = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/allocations/{allocation_id}/recycle",
            headers=self.headers(admin_token),
            json={"reason_code": "operator_request"},
        )
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(
            repeated.json()["release_reason_code"], "manual_reassignment"
        )

        next_task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(next_operator_token),
            json={
                "type": "card_checkout",
                "idempotency_key": "timeline-next-allocation-owner",
            },
        )
        self.assertEqual(next_task.status_code, 201, next_task.text)
        next_allocation = self.request(
            "POST",
            f"/api/v1/tasks/{next_task.json()['id']}/card-allocations",
            headers=self.headers(next_operator_token),
        )
        self.assertEqual(next_allocation.status_code, 201, next_allocation.text)

        first_allocation_page = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
            params={"allocation_limit": 1},
        )
        self.assertEqual(
            first_allocation_page.status_code, 200, first_allocation_page.text
        )
        first_allocation_body = first_allocation_page.json()
        self.assertTrue(first_allocation_body["allocations_has_more"])
        self.assertIsNotNone(first_allocation_body["allocations_next_cursor"])
        second_allocation_page = self.request(
            "GET",
            f"/api/v1/admin/cards/{card_id}/timeline",
            headers=self.headers(admin_token),
            params={
                "allocation_limit": 1,
                "allocations_cursor": first_allocation_body[
                    "allocations_next_cursor"
                ],
            },
        )
        self.assertEqual(
            second_allocation_page.status_code, 200, second_allocation_page.text
        )
        self.assertEqual(second_allocation_page.json()["card"]["status"], "allocated")
        allocation_ids = {
            first_allocation_body["allocations"][0]["id"],
            second_allocation_page.json()["allocations"][0]["id"],
        }
        self.assertEqual(allocation_ids, {allocation_id, next_allocation.json()["id"]})
        allocation_history = {
            item["id"]: item
            for item in (
                first_allocation_body["allocations"]
                + second_allocation_page.json()["allocations"]
            )
        }
        self.assertEqual(
            allocation_history[allocation_id]["user_id"], self.operator.user_id
        )
        self.assertEqual(allocation_history[allocation_id]["task_id"], task_id)
        self.assertEqual(
            allocation_history[allocation_id]["release_reason_code"],
            "manual_reassignment",
        )
        self.assertEqual(
            allocation_history[next_allocation.json()["id"]]["user_id"],
            next_operator.user_id,
        )
        self.assertEqual(
            allocation_history[next_allocation.json()["id"]]["device_id"],
            next_operator.device_id,
        )
        self.assertEqual(
            allocation_history[next_allocation.json()["id"]]["task_id"],
            next_task.json()["id"],
        )
        self.assertFalse(second_allocation_page.json()["allocations_has_more"])

        old_retry = self.request(
            "POST",
            f"/api/v1/admin/cards/{card_id}/allocations/{allocation_id}/recycle",
            headers=self.headers(admin_token),
            json={"reason_code": "stale_retry"},
        )
        self.assertEqual(old_retry.status_code, 200, old_retry.text)
        with self.app.state.session_factory() as db:
            upload = db.get(UploadJob, upload_id)
            current_allocation = db.get(CardAllocation, next_allocation.json()["id"])
            self.assertEqual(upload.status, "cancelled")
            self.assertEqual(upload.error_code, "card_recycled")
            self.assertEqual(current_allocation.status, "active")
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(CardEvent)
                    .where(
                        CardEvent.allocation_id == allocation_id,
                        CardEvent.action == "allocation.released",
                    )
                ),
                1,
            )
            for event_type in (
                "admin.card_allocation_recycle_requested",
                "admin.card_allocation_recycled",
            ):
                self.assertEqual(
                    db.scalar(
                        select(func.count())
                        .select_from(AuditEvent)
                        .where(
                            AuditEvent.entity_id == allocation_id,
                            AuditEvent.event_type == event_type,
                        )
                    ),
                    1,
                )

    def test_card_disable_barrier_wins_before_late_allocation_claim(self) -> None:
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "disable-before-allocation",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "vault://secret/cards/disable-before-allocation",
            },
        )
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "disable-before-allocation"},
        )
        card_id = card.json()["id"]
        task_id = task.json()["id"]
        claim_entered = Event()
        release_claim = Event()
        blocked_once = False

        def block_allocation_card_claim(
            _connection,
            _cursor,
            statement,
            parameters,
            _context,
            _executemany,
        ) -> None:
            nonlocal blocked_once
            if (
                not blocked_once
                and statement.lstrip().upper().startswith("UPDATE CARDS SET IS_ACTIVE")
                and parameters
                and parameters[0] == 1
            ):
                blocked_once = True
                claim_entered.set()
                if not release_claim.wait(timeout=10):
                    raise TimeoutError("allocation card claim was not released")

        event.listen(
            self.app.state.engine, "before_cursor_execute", block_allocation_card_claim
        )
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                allocation_future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations",
                    headers=self.headers(operator_token),
                )
                self.assertTrue(claim_entered.wait(timeout=5))
                disabled = self.request(
                    "PATCH",
                    f"/api/v1/admin/cards/{card_id}",
                    headers=self.headers(admin_token),
                    json={"is_active": False},
                )
                self.assertEqual(disabled.status_code, 200, disabled.text)
                release_claim.set()
                allocation = allocation_future.result(timeout=10)
        finally:
            release_claim.set()
            event.remove(
                self.app.state.engine,
                "before_cursor_execute",
                block_allocation_card_claim,
            )

        self.assertEqual(allocation.status_code, 503, allocation.text)
        with self.app.state.session_factory() as db:
            persisted_card = db.get(Card, card_id)
            allocations = db.scalar(
                select(func.count())
                .select_from(CardAllocation)
                .where(CardAllocation.card_id == card_id)
            )
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertFalse(persisted_card.is_active)
            self.assertEqual(allocations, 0)
            self.assertEqual(event_types.count("admin.card_disabled"), 1)
            self.assertEqual(event_types.count("card.allocated"), 0)

    def test_allocation_claim_wins_then_disable_compensates_before_return(self) -> None:
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "allocation-before-disable",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "vault://secret/cards/allocation-before-disable",
            },
        )
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "allocation-before-disable"},
        )
        card_id = card.json()["id"]
        task_id = task.json()["id"]
        claim_executed = Event()
        release_claim = Event()
        disable_started = Event()
        blocked_once = False

        def block_after_allocation_claim(
            _connection,
            _cursor,
            statement,
            parameters,
            _context,
            _executemany,
        ) -> None:
            nonlocal blocked_once
            if (
                not blocked_once
                and statement.lstrip().upper().startswith("UPDATE CARDS SET IS_ACTIVE")
                and parameters
                and parameters[0] == 1
            ):
                blocked_once = True
                claim_executed.set()
                if not release_claim.wait(timeout=10):
                    raise TimeoutError("allocation transaction was not released")

        event.listen(
            self.app.state.engine, "after_cursor_execute", block_after_allocation_claim
        )
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                allocation_future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations",
                    headers=self.headers(operator_token),
                )
                self.assertTrue(claim_executed.wait(timeout=5))

                def disable_card() -> httpx.Response:
                    disable_started.set()
                    return self.request(
                        "PATCH",
                        f"/api/v1/admin/cards/{card_id}",
                        headers=self.headers(admin_token),
                        json={"is_active": False},
                    )

                disable_future = executor.submit(
                    disable_card,
                )
                self.assertTrue(disable_started.wait(timeout=5))
                self.assertFalse(disable_future.done())
                release_claim.set()
                allocation = allocation_future.result(timeout=10)
                disabled = disable_future.result(timeout=10)
        finally:
            release_claim.set()
            event.remove(
                self.app.state.engine,
                "after_cursor_execute",
                block_after_allocation_claim,
            )

        self.assertEqual(allocation.status_code, 201, allocation.text)
        self.assertEqual(disabled.status_code, 200, disabled.text)
        with self.app.state.session_factory() as db:
            persisted_card = db.get(Card, card_id)
            persisted_allocation = db.get(CardAllocation, allocation.json()["id"])
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertFalse(persisted_card.is_active)
            self.assertEqual(persisted_allocation.status, "released")
            self.assertIsNotNone(persisted_allocation.released_at)
            self.assertEqual(event_types.count("admin.card_disabled"), 1)
            self.assertEqual(event_types.count("card.allocated"), 1)
            self.assertEqual(event_types.count("card.released"), 1)

    def test_repeated_inactive_card_repairs_residue_without_overwriting_success(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "inactive-residue",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "vault://secret/cards/inactive-residue",
            },
        )
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={"type": "card_checkout", "idempotency_key": "inactive-residue"},
        )
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/card-allocations",
            headers=self.headers(operator_token),
        )
        card_id = card.json()["id"]
        allocation_id = allocation.json()["id"]
        disabled = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)

        with self.app.state.session_factory() as db:
            stale = db.get(CardAllocation, allocation_id)
            stale.status = "active"
            stale.released_at = None
            job = UploadJob(
                tenant_id="tenant-a",
                task_id=task.json()["id"],
                user_id=self.operator.user_id,
                device_id=self.operator.device_id,
                card_allocation_id=allocation_id,
                idempotency_key="inactive-residue-success",
                business_name="Already succeeded",
                trace_id="inactive-residue-trace",
                status="succeeded",
                policy_version=self.app.state.sub2_policy.version,
                external_ref="sub2-existing-success",
            )
            db.add(job)
            db.commit()
            job_id = job.id

        repaired = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(repaired.status_code, 200, repaired.text)
        with self.app.state.session_factory() as db:
            counts_after_repair = {
                event_type: db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == event_type)
                )
                for event_type in ("admin.card_disabled", "card.released")
            }

        repeated = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(repeated.status_code, 200, repeated.text)
        with self.app.state.session_factory() as db:
            persisted_allocation = db.get(CardAllocation, allocation_id)
            persisted_job = db.get(UploadJob, job_id)
            counts_after_repeat = {
                event_type: db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == event_type)
                )
                for event_type in ("admin.card_disabled", "card.released")
            }
            self.assertEqual(persisted_allocation.status, "released")
            self.assertIsNotNone(persisted_allocation.released_at)
            self.assertEqual(persisted_job.status, "succeeded")
            self.assertEqual(persisted_job.external_ref, "sub2-existing-success")
            self.assertEqual(counts_after_repeat, counts_after_repair)
            self.assertEqual(counts_after_repeat["admin.card_disabled"], 1)

    def test_card_disable_cannot_overwrite_a_worker_success(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card_id, task_id, allocation_id, upload_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="worker-success-race",
        )
        adapter_entered = Event()
        release_adapter = Event()
        admin_loaded_running_job = Event()

        class BlockingAdapter:
            def __init__(self) -> None:
                self.commands = []

            def submit(self, command):
                self.commands.append(command)
                adapter_entered.set()
                if not release_adapter.wait(timeout=10):
                    raise RuntimeError("test adapter was not released")
                return Sub2UploadResult(external_ref="sub2-definitive-success")

        adapter = BlockingAdapter()
        real_scalars = Session.scalars
        intercepted_once = False

        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="upload-worker") as worker_pool:
            worker_future = worker_pool.submit(
                process_queued_uploads,
                self.app.state.session_factory,
                adapter=adapter,
                policy=self.app.state.sub2_policy,
            )
            self.assertTrue(adapter_entered.wait(timeout=5))

            def intercept_admin_upload_candidates(session, statement, *args, **kwargs):
                nonlocal intercepted_once
                result = real_scalars(session, statement, *args, **kwargs)
                entity = statement.column_descriptions[0].get("entity")
                if (
                    not intercepted_once
                    and entity is UploadJob
                    and "card_allocation_id IN" in str(statement)
                ):
                    intercepted_once = True
                    stale_rows = list(result)
                    # Release SQLite's read lock while retaining stale ORM values;
                    # the production PostgreSQL path gets this interleaving at READ COMMITTED.
                    session.commit()
                    admin_loaded_running_job.set()
                    release_adapter.set()
                    self.assertEqual(worker_future.result(timeout=10), 1)
                    return iter(stale_rows)
                return result

            try:
                with mock.patch.object(Session, "scalars", new=intercept_admin_upload_candidates):
                    with ThreadPoolExecutor(
                        max_workers=1, thread_name_prefix="admin-disable"
                    ) as admin_pool:
                        disabled = admin_pool.submit(
                            self.request,
                            "PATCH",
                            f"/api/v1/admin/cards/{card_id}",
                            headers=self.headers(admin_token),
                            json={"is_active": False},
                        ).result(timeout=15)
            finally:
                release_adapter.set()

        self.assertTrue(admin_loaded_running_job.is_set())
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertEqual(len(adapter.commands), 1)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, upload_id)
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            card = db.get(Card, card_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == upload_id)
            )
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(job.status, "succeeded")
            self.assertEqual(job.external_ref, "sub2-definitive-success")
            self.assertIsNone(job.error_code)
            self.assertEqual(task.status, "completed")
            self.assertEqual(allocation.status, "released")
            self.assertFalse(card.is_active)
            self.assertEqual(outbox.status, "processed")
            self.assertEqual(event_types.count("upload.succeeded"), 1)
            self.assertEqual(event_types.count("upload.unknown"), 0)
            self.assertEqual(event_types.count("card.released"), 1)

    def test_card_disable_winner_blocks_a_late_worker_external_call(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card_id, task_id, _, upload_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="admin-wins-race",
        )
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, upload_id)
            job.status = "running"
            db.commit()

        disabled = self.request(
            "PATCH",
            f"/api/v1/admin/cards/{card_id}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)

        class RecordingAdapter:
            def __init__(self) -> None:
                self.commands = []

            def submit(self, command):
                self.commands.append(command)
                return Sub2UploadResult(external_ref="must-not-be-created")

        adapter = RecordingAdapter()
        result = process_upload_job(
            self.app.state.session_factory,
            upload_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(result.status, "unknown")
        self.assertEqual(adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, upload_id)
            task = db.get(Task, task_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == upload_id)
            )
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(job.status, "unknown")
            self.assertIsNone(job.external_ref)
            self.assertEqual(task.status, "created")
            self.assertEqual(outbox.status, "processed")
            self.assertEqual(event_types.count("upload.unknown"), 1)
            self.assertEqual(event_types.count("upload.succeeded"), 0)

    def test_repeated_card_disable_does_not_repeat_resource_audits(self) -> None:
        admin_token = self.login(
            "tenant-a", "admin@example.test", "admin-account-password", self.admin.device_id
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        card_id, task_id, allocation_id, upload_id = self.create_card_upload_fixture(
            admin_token=admin_token,
            operator_token=operator_token,
            suffix="repeat-disable",
        )
        for _ in range(2):
            disabled = self.request(
                "PATCH",
                f"/api/v1/admin/cards/{card_id}",
                headers=self.headers(admin_token),
                json={"is_active": False},
            )
            self.assertEqual(disabled.status_code, 200, disabled.text)

        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            task = db.get(Task, task_id)
            resource_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_((allocation_id, upload_id)),
                        AuditEvent.event_type.in_(
                            ("upload.cancel_requested", "card.released")
                        ),
                    )
                )
            )
        self.assertEqual(event_types.count("upload.cancel_requested"), 1)
        self.assertEqual(event_types.count("card.released"), 1)
        self.assertEqual(event_types.count("admin.card_disabled"), 1)
        self.assertEqual(len(resource_events), 2)
        self.assertTrue(
            all(event.user_id == self.operator.user_id for event in resource_events)
        )
        self.assertTrue(
            all(event.device_id == self.operator.device_id for event in resource_events)
        )
        self.assertTrue(
            all(event.actor_id == self.admin.user_id for event in resource_events)
        )
        self.assertNotIn(
            "vault://secret/cards/repeat-disable",
            "\n".join(event.details_json for event in resource_events),
        )

        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.headers(operator_token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        timeline_types = [event["event_type"] for event in timeline.json()["events"]]
        self.assertEqual(timeline_types.count("upload.cancel_requested"), 1)
        self.assertEqual(timeline_types.count("card.released"), 1)

        owner_actor_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(admin_token),
            params={
                "user_id": self.operator.user_id,
                "actor_id": self.admin.user_id,
                "trace_id": task.trace_id,
            },
        )
        self.assertEqual(owner_actor_audit.status_code, 200, owner_actor_audit.text)
        owner_actor_types = [event["event_type"] for event in owner_actor_audit.json()]
        self.assertEqual(owner_actor_types.count("upload.cancel_requested"), 1)
        self.assertEqual(owner_actor_types.count("card.released"), 1)
        admin_subject_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(admin_token),
            params={
                "user_id": self.admin.user_id,
                "actor_id": self.admin.user_id,
                "trace_id": task.trace_id,
            },
        )
        self.assertEqual(admin_subject_audit.status_code, 200, admin_subject_audit.text)
        self.assertEqual(admin_subject_audit.json(), [])

        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )
        cross_tenant_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(other_token),
            params={"trace_id": task.trace_id},
        )
        self.assertEqual(cross_tenant_audit.status_code, 200, cross_tenant_audit.text)
        self.assertEqual(cross_tenant_audit.json(), [])

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
        self.assertEqual(created.json()["health_status"], "unknown")
        self.assertIsNone(created.json()["last_checked_at"])
        self.assertIsNone(created.json()["last_error_code"])
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
                start_watermark="connector-watermark-before-admin-reclaim",
                last_message_hash="e" * 64,
                expires_at=utc_now() + timedelta(minutes=5),
                delivered_code="987654",
                delivered_at=utc_now(),
                code_expires_at=utc_now() + timedelta(minutes=1),
            )
            db.add(session)
            db.commit()
            session_id = session.id
            task_id = task.id
            task_trace_id = task.trace_id

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
            self.assertIsNone(session.start_watermark)
            self.assertIsNone(session.last_message_hash)
            # Credential rotation must also invalidate a consumed capability;
            # unlike active states it is not covered by the mailbox busy index.
            session.status = "consumed"
            session.consumed_at = utc_now()
            session.start_watermark = "connector-watermark-before-rotation"
            session.last_message_hash = "f" * 64
            session.delivered_code = "112233"
            session.delivered_at = utc_now()
            session.code_expires_at = utc_now() + timedelta(minutes=1)
            mailbox = db.get(Mailbox, mailbox_id)
            mailbox.health_status = "unavailable"
            mailbox.last_checked_at = utc_now()
            mailbox.last_error_code = "connector_unavailable"
            db.commit()

        rotated = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(admin_token),
            json={"secret_ref": "vault://secret/mailboxes/managed-v2"},
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        self.assertEqual(rotated.json()["health_status"], "unknown")
        self.assertIsNone(rotated.json()["last_checked_at"])
        self.assertIsNone(rotated.json()["last_error_code"])
        self.assertNotIn("vault://", rotated.text.lower())
        self.assertEqual(rotated.json()["active_session_count"], 0)
        replayed_rotation = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(admin_token),
            json={"secret_ref": "vault://secret/mailboxes/managed-v2"},
        )
        self.assertEqual(replayed_rotation.status_code, 200, replayed_rotation.text)
        rejected_rotation = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            headers=self.headers(admin_token),
            json={"secret_ref": "vault://secret/cards/wrong-domain"},
        )
        self.assertEqual(rejected_rotation.status_code, 422, rejected_rotation.text)
        with self.app.state.session_factory() as db:
            mailbox = db.get(Mailbox, mailbox_id)
            mailbox.health_status = "unavailable"
            mailbox.last_checked_at = utc_now()
            mailbox.last_error_code = "connector_unavailable"
            db.commit()
        enabled = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox_id}",
            headers=self.headers(admin_token),
            json={"is_active": True},
        )
        self.assertTrue(enabled.json()["is_active"])
        self.assertEqual(enabled.json()["health_status"], "unknown")
        self.assertIsNone(enabled.json()["last_checked_at"])
        self.assertIsNone(enabled.json()["last_error_code"])
        with self.app.state.session_factory() as db:
            mailbox = db.get(Mailbox, mailbox_id)
            session = db.get(MailSession, session_id)
            self.assertEqual(mailbox.secret_ref, "vault://secret/mailboxes/managed-v2")
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertIsNone(session.code_expires_at)
            self.assertIsNone(session.start_watermark)
            self.assertIsNone(session.last_message_hash)
            self.assertEqual(mailbox.health_status, "unknown")
            self.assertIsNone(mailbox.last_checked_at)
            self.assertIsNone(mailbox.last_error_code)
            audit_text = "\n".join(event.details_json for event in db.query(AuditEvent))
            rotation_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.mailbox_secret_rotated",
                        AuditEvent.entity_id == mailbox_id,
                    )
                )
            )
            revoked_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "mail_session.revoked",
                        AuditEvent.entity_id == session_id,
                    )
                )
            )
        self.assertEqual(len(rotation_events), 1)
        self.assertEqual(len(revoked_events), 2)
        self.assertTrue(
            all(event.user_id == self.operator.user_id for event in revoked_events)
        )
        self.assertTrue(
            all(event.device_id == self.operator.device_id for event in revoked_events)
        )
        self.assertTrue(
            all(event.actor_id == self.admin.user_id for event in revoked_events)
        )
        self.assertEqual(
            sum(
                "admin_mailbox_secret_rotated" in event.details_json
                for event in revoked_events
            ),
            1,
        )
        self.assertNotIn("vault://secret/mailboxes/managed-v1", audit_text)
        self.assertNotIn("vault://secret/mailboxes/managed-v2", audit_text)

        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.headers(operator_token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        self.assertEqual(
            sum(
                event["event_type"] == "mail_session.revoked"
                for event in timeline.json()["events"]
            ),
            2,
        )
        owner_actor_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(admin_token),
            params={
                "user_id": self.operator.user_id,
                "actor_id": self.admin.user_id,
                "trace_id": task_trace_id,
                "event_type": "mail_session.revoked",
            },
        )
        self.assertEqual(owner_actor_audit.status_code, 200, owner_actor_audit.text)
        self.assertEqual(len(owner_actor_audit.json()), 2)
        admin_subject_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(admin_token),
            params={
                "user_id": self.admin.user_id,
                "actor_id": self.admin.user_id,
                "trace_id": task_trace_id,
                "event_type": "mail_session.revoked",
            },
        )
        self.assertEqual(admin_subject_audit.status_code, 200, admin_subject_audit.text)
        self.assertEqual(admin_subject_audit.json(), [])
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
        cross_tenant_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.headers(other_token),
            params={"trace_id": task_trace_id},
        )
        self.assertEqual(cross_tenant_audit.status_code, 200, cross_tenant_audit.text)
        self.assertEqual(cross_tenant_audit.json(), [])

    def test_mailbox_disable_revokes_consumed_upload_authority_and_repairs_residue(self) -> None:
        admin_token = self.login(
            "tenant-a",
            "admin@example.test",
            "admin-account-password",
            self.admin.device_id,
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        mailbox = self.request(
            "POST",
            "/api/v1/admin/mailboxes",
            headers=self.headers(admin_token),
            json={
                "email_masked": "r***@example.test",
                "connector_type": "http",
                "secret_ref": "vault://secret/mailboxes/disable-consumed",
            },
        )
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers=self.headers(admin_token),
            json={
                "provider_ref": "disable-consumed-card",
                "brand": "Visa",
                "last4": "4242",
                "secret_ref": "vault://secret/cards/disable-consumed",
            },
        )
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers(operator_token),
            json={
                "type": "card_checkout",
                "idempotency_key": "disable-consumed-task",
            },
        )
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/card-allocations",
            headers=self.headers(operator_token),
        )
        self.assertEqual(mailbox.status_code, 201, mailbox.text)
        self.assertEqual(card.status_code, 201, card.text)
        self.assertEqual(task.status_code, 201, task.text)
        self.assertEqual(allocation.status_code, 201, allocation.text)

        now = utc_now()
        with self.app.state.session_factory() as db:
            persisted_task = db.get(Task, task.json()["id"])
            session = MailSession(
                tenant_id="tenant-a",
                task_id=persisted_task.id,
                user_id=self.operator.user_id,
                device_id=self.operator.device_id,
                mailbox_id=mailbox.json()["id"],
                trace_id=persisted_task.trace_id,
                status="consumed",
                consumed_at=now,
                expires_at=now + timedelta(minutes=5),
                delivered_code="481516",
                delivered_at=now,
                code_expires_at=now + timedelta(minutes=1),
            )
            db.add(session)
            db.commit()
            session_id = session.id

        disabled = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox.json()['id']}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        blocked_upload = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/uploads",
            headers=self.headers(operator_token),
            json={
                "business_name": "Disabled Mailbox Upload",
                "idempotency_key": "disable-consumed-upload",
            },
        )
        self.assertEqual(blocked_upload.status_code, 409, blocked_upload.text)
        self.assertEqual(
            blocked_upload.json()["error"]["code"], "verification_required"
        )

        with self.app.state.session_factory() as db:
            session = db.get(MailSession, session_id)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertIsNone(session.code_expires_at)
            session.status = "consumed"
            session.delivered_code = "234567"
            session.delivered_at = utc_now()
            session.code_expires_at = utc_now() + timedelta(minutes=1)
            db.commit()

        repaired = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox.json()['id']}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        replay = self.request(
            "PATCH",
            f"/api/v1/admin/mailboxes/{mailbox.json()['id']}",
            headers=self.headers(admin_token),
            json={"is_active": False},
        )
        self.assertEqual(repaired.status_code, 200, repaired.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        with self.app.state.session_factory() as db:
            session = db.get(MailSession, session_id)
            revoked_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.revoked",
                    )
                )
            )
            disabled_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == mailbox.json()["id"],
                        AuditEvent.event_type == "admin.mailbox_disabled",
                    )
                )
            )
        self.assertEqual(session.status, "revoked")
        self.assertIsNone(session.delivered_code)
        self.assertIsNone(session.delivered_at)
        self.assertIsNone(session.code_expires_at)
        self.assertEqual(len(revoked_events), 2)
        self.assertEqual(len(disabled_events), 1)
        self.assertTrue(
            all(event.user_id == self.operator.user_id for event in revoked_events)
        )
        self.assertTrue(
            all(event.actor_id == self.admin.user_id for event in revoked_events)
        )
        self.assertTrue(
            all("admin_mailbox_disabled" in event.details_json for event in revoked_events)
        )

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

        operator = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="upload-ops@example.test",
            password="upload-ops-account-password",
            device_name="upload-ops-device",
            role="ops_admin",
        )
        ops_token = self.login(
            "tenant-a",
            "upload-ops@example.test",
            "upload-ops-account-password",
            operator.device_id,
        )
        ops_uploads = self.request(
            "GET", "/api/v1/admin/uploads", headers=self.headers(ops_token)
        )
        self.assertEqual(ops_uploads.status_code, 200, ops_uploads.text)
        ops_audit = self.request(
            "GET", "/api/v1/admin/audit", headers=self.headers(ops_token)
        )
        self.assertEqual(ops_audit.status_code, 403, ops_audit.text)

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

        self.app.state.settings.environment = "production"
        managed = self.request(
            "GET",
            "/api/v1/admin/policies/upload",
            headers=self.headers(admin_token),
        )
        self.assertEqual(managed.status_code, 200, managed.text)
        self.assertEqual(managed.json()["status"], "not_configured")
        self.assertFalse(managed.json()["governance_configured"])

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

        completed = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{second['id']}/deploy",
            headers=self.headers(creator_token),
            json={"rollout_percent": 100},
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["rollout_percent"], 100)
        with self.app.state.session_factory() as db:
            deployed_audits_before = db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.event_type == "upload_policy.deployed"
                )
            )

        reopened = self.request(
            "POST",
            f"/api/v1/admin/policies/upload/versions/{second['id']}/deploy",
            headers=self.headers(creator_token),
            json={"rollout_percent": 20},
        )
        self.assertEqual(reopened.status_code, 409, reopened.text)
        status_after_reopen = self.request(
            "GET", "/api/v1/admin/policies/upload", headers=self.headers(creator_token)
        )
        self.assertEqual(status_after_reopen.status_code, 200, status_after_reopen.text)
        self.assertEqual(status_after_reopen.json()["active_version"], "sub2-governed-v2")
        self.assertEqual(status_after_reopen.json()["previous_version"], "sub2-governed-v1")
        self.assertEqual(status_after_reopen.json()["rollout_percent"], 100)
        versions_after_reopen = self.request(
            "GET",
            "/api/v1/admin/policies/upload/versions",
            headers=self.headers(creator_token),
        )
        self.assertEqual(versions_after_reopen.status_code, 200, versions_after_reopen.text)
        statuses_after_reopen = {
            version["version"]: version["status"]
            for version in versions_after_reopen.json()
        }
        self.assertEqual(statuses_after_reopen["sub2-governed-v2"], "active")
        self.assertEqual(statuses_after_reopen["sub2-governed-v1"], "retired")
        with self.app.state.session_factory() as db:
            deployed_audits_after = db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.event_type == "upload_policy.deployed"
                )
            )
        self.assertEqual(deployed_audits_after, deployed_audits_before)

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
        legacy_details = {
            "provider_note_colon": (
                "legacy evidence aUtHoRiZaTiOn: Basic LEGACY_AUTH_SECRET"
            ),
            "bearer_evidence": "legacy evidence prefix bEaReR LEGACY_BEARER_SECRET",
            "vault_evidence": "legacy evidence VaUlT://mail/prod",
            "pan_evidence": "legacy reference 4111111111111111",
            "company_name": "safe-company",
        }
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
                    details_json=json.dumps(legacy_details),
                )
            )
            record_audit(
                db,
                tenant_id="tenant-a",
                user_id=self.operator.user_id,
                device_id=self.operator.device_id,
                event_type="current.unsafe",
                entity_type="current",
                entity_id="current-1",
                trace_id="00000000-0000-0000-0000-000000000002",
                details={
                    "provider_note_equals": (
                        "current evidence AUTHORIZATION=Basic CURRENT_AUTH_SECRET"
                    ),
                    "bearer_evidence": (
                        "current evidence prefix bEaReR CURRENT_BEARER_SECRET"
                    ),
                    "vault_evidence": "current evidence vault://mail/prod",
                    "pan_evidence": "current reference 5555555555554444",
                    "company_name": "current-safe-company",
                },
            )
            db.commit()
            current_event = db.scalar(
                select(AuditEvent).where(AuditEvent.event_type == "current.unsafe")
            )
            self.assertIsNotNone(current_event)
            with self.subTest(boundary="record_audit"):
                self.assertEqual(
                    json.loads(current_event.details_json),
                    {
                        "provider_note_equals": "[REDACTED]",
                        "bearer_evidence": "[REDACTED]",
                        "vault_evidence": "[REDACTED]",
                        "pan_evidence": "current reference [REDACTED_CARD]",
                        "company_name": "current-safe-company",
                    },
                )
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
        by_event_type = {event["event_type"]: event for event in response.json()}
        with self.subTest(boundary="legacy_read"):
            self.assertEqual(
                by_event_type["legacy.unsafe"]["details"],
                {
                    "provider_note_colon": "[REDACTED]",
                    "bearer_evidence": "[REDACTED]",
                    "vault_evidence": "[REDACTED]",
                    "pan_evidence": "legacy reference [REDACTED_CARD]",
                    "company_name": "safe-company",
                },
            )
        serialized = json.dumps(response.json())
        for forbidden in (
            "LEGACY_AUTH_SECRET",
            "LEGACY_BEARER_SECRET",
            "CURRENT_AUTH_SECRET",
            "CURRENT_BEARER_SECRET",
            "vault://",
            "VaUlT://",
            "Authorization",
            "AUTHORIZATION",
            "Bearer",
            "bEaReR",
            "4111111111111111",
            "5555555555554444",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("safe-company", serialized)
        self.assertIn("current-safe-company", serialized)

    def test_mail_and_card_policy_governance_is_tenant_scoped_and_four_eyes(self) -> None:
        creator_token = self.login(
            "tenant-a",
            "admin@example.test",
            "admin-account-password",
            self.admin.device_id,
        )
        approver_token = self.login(
            "tenant-a",
            "approver@example.test",
            "approver-account-password",
            self.approver.device_id,
        )
        operator_token = self.login(
            "tenant-a",
            "operator@example.test",
            "operator-account-password",
            self.operator.device_id,
        )
        other_token = self.login(
            "tenant-b",
            "other@example.test",
            "other-account-password",
            self.other_tenant.device_id,
        )

        payloads = {
            "mail": {
                "version": "mail-v1",
                "change_note": "baseline mail timing",
                "session_ttl_seconds": 600,
                "code_ttl_seconds": 90,
                "poll_interval_seconds": 7,
            },
            "card": {
                "version": "card-v1",
                "change_note": "baseline card timing",
                "lease_ttl_seconds": 1_800,
                "reveal_ttl_seconds": 120,
                "allocation_order": "oldest_available",
            },
        }
        created: dict[str, dict[str, object]] = {}
        for domain, payload in payloads.items():
            response = self.request(
                "POST",
                f"/api/v1/admin/policies/{domain}/versions",
                headers=self.headers(creator_token),
                json=payload,
            )
            self.assertEqual(response.status_code, 201, response.text)
            created[domain] = response.json()
            self.assertEqual(response.json()["status"], "draft")
            if domain == "card":
                self.assertEqual(
                    response.json()["selection_rules"],
                    [
                        {
                            "task_type": "card_checkout",
                            "pool_key": "legacy-unclassified",
                            "region": "legacy-unclassified",
                            "brands": [],
                            "minimum_validity_days": 0,
                            "allocation_order": "oldest_available",
                        }
                    ],
                )

            same_creator = self.request(
                "POST",
                f"/api/v1/admin/policies/{domain}/versions/{response.json()['id']}/approve",
                headers=self.headers(creator_token),
            )
            self.assertEqual(same_creator.status_code, 409, same_creator.text)

            approved = self.request(
                "POST",
                f"/api/v1/admin/policies/{domain}/versions/{response.json()['id']}/approve",
                headers=self.headers(approver_token),
            )
            self.assertEqual(approved.status_code, 200, approved.text)
            self.assertEqual(approved.json()["approved_by"], self.approver.user_id)

            first_partial = self.request(
                "POST",
                f"/api/v1/admin/policies/{domain}/versions/{response.json()['id']}/deploy",
                headers=self.headers(approver_token),
                json={"rollout_percent": 10},
            )
            self.assertEqual(first_partial.status_code, 409, first_partial.text)
            deployed = self.request(
                "POST",
                f"/api/v1/admin/policies/{domain}/versions/{response.json()['id']}/deploy",
                headers=self.headers(approver_token),
                json={"rollout_percent": 100},
            )
            self.assertEqual(deployed.status_code, 200, deployed.text)
            self.assertEqual(deployed.json()["domain"], domain)

            status = self.request(
                "GET",
                f"/api/v1/admin/policies/{domain}",
                headers=self.headers(creator_token),
            )
            self.assertEqual(status.status_code, 200, status.text)
            self.assertEqual(status.json()["active_version"], payload["version"])

            forbidden = self.request(
                "GET",
                f"/api/v1/admin/policies/{domain}/versions",
                headers=self.headers(operator_token),
            )
            self.assertEqual(forbidden.status_code, 403, forbidden.text)
            isolated = self.request(
                "GET",
                f"/api/v1/admin/policies/{domain}/versions",
                headers=self.headers(other_token),
            )
            self.assertEqual(isolated.status_code, 200, isolated.text)
            self.assertEqual(isolated.json(), [])

        second = self.request(
            "POST",
            "/api/v1/admin/policies/mail/versions",
            headers=self.headers(creator_token),
            json={
                **payloads["mail"],
                "version": "mail-v2",
                "change_note": "canary mail timing",
                "session_ttl_seconds": 900,
            },
        )
        self.assertEqual(second.status_code, 201, second.text)
        approved_second = self.request(
            "POST",
            f"/api/v1/admin/policies/mail/versions/{second.json()['id']}/approve",
            headers=self.headers(approver_token),
        )
        self.assertEqual(approved_second.status_code, 200, approved_second.text)
        canary = self.request(
            "POST",
            f"/api/v1/admin/policies/mail/versions/{second.json()['id']}/deploy",
            headers=self.headers(approver_token),
            json={"rollout_percent": 25},
        )
        self.assertEqual(canary.status_code, 200, canary.text)
        self.assertEqual(canary.json()["previous_version"], "mail-v1")
        self.assertEqual(canary.json()["rollout_percent"], 25)
        rollback = self.request(
            "POST",
            "/api/v1/admin/policies/mail/rollback",
            headers=self.headers(creator_token),
        )
        self.assertEqual(rollback.status_code, 200, rollback.text)
        self.assertEqual(rollback.json()["active_version"], "mail-v1")
        self.assertEqual(rollback.json()["rollout_percent"], 100)

        rejected_extra = self.request(
            "POST",
            "/api/v1/admin/policies/card/versions",
            headers=self.headers(creator_token),
            json={**payloads["card"], "version": "card-v2", "proxy_ref": "vault://forbidden"},
        )
        self.assertEqual(rejected_extra.status_code, 422, rejected_extra.text)


if __name__ == "__main__":
    unittest.main()
