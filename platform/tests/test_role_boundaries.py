import asyncio
import unittest
from datetime import timedelta

import httpx
from sqlalchemy import func, select

from platform.app import create_app
from platform.bootstrap import create_oidc_user_with_device, create_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    CardRevealChallenge,
    Device,
    Mailbox,
    MailSession,
    OutboxEvent,
    Task,
    UploadJob,
    utc_now,
)


class RoleBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            Settings(
                app_name="role-boundary-test",
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="role-boundary-unit-test-secret-not-for-production",
            )
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

    @staticmethod
    def bearer(token: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", **extra}

    def create_and_login(
        self,
        role: str,
        *,
        suffix: str = "",
        tenant_id: str = "tenant-role-boundary",
    ) -> tuple[str, str]:
        email = f"{role}{suffix}@example.test"
        password = f"{role}{suffix}-account-password"
        identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id=tenant_id,
            email=email,
            password=password,
            device_name=f"{role}{suffix}-device",
            role=role,
        )
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": tenant_id,
                "email": email,
                "password": password,
                "device_id": identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return identity.device_id, response.json()["access_token"]

    def persisted_counts(self) -> tuple[int, ...]:
        models = (
            Task,
            MailSession,
            CardAllocation,
            CardRevealChallenge,
            UploadJob,
            OutboxEvent,
            AuditEvent,
        )
        with self.app.state.session_factory() as db:
            return tuple(
                int(db.scalar(select(func.count()).select_from(model)) or 0)
                for model in models
            )

    def test_only_operator_can_access_owner_business_routes(self) -> None:
        tokens = {
            role: self.create_and_login(role)[1]
            for role in ("security_auditor", "ops_admin", "platform_admin")
        }
        counts_before = self.persisted_counts()
        route_cases: tuple[tuple[str, str, dict[str, object]], ...] = (
            (
                "POST",
                "/api/v1/tasks",
                {"json": {"type": "mail_code", "idempotency_key": "denied"}},
            ),
            ("POST", "/api/v1/tasks/missing/mail-session", {}),
            (
                "GET",
                "/api/v1/mail-session/missing/code",
                {"extra_headers": {"X-Mail-Session-Token": "opaque-token"}},
            ),
            (
                "POST",
                "/api/v1/mail-session/missing/revoke",
                {"extra_headers": {"X-Mail-Session-Token": "opaque-token"}},
            ),
            (
                "GET",
                "/api/v1/mail-session/missing/events",
                {"extra_headers": {"X-Mail-Session-Token": "opaque-token"}},
            ),
            ("POST", "/api/v1/tasks/missing/card-allocation", {}),
            ("GET", "/api/v1/card-allocations/missing?task_id=missing", {}),
            ("POST", "/api/v1/card-allocations/missing/release", {}),
            (
                "POST",
                "/api/v1/card-allocations/missing/reveal-challenges",
                {},
            ),
            (
                "POST",
                "/api/v1/card-allocations/missing/reveal-grants",
                {"json": {"challenge_id": "missing"}},
            ),
            (
                "POST",
                "/api/v1/card-allocations/missing/reveal",
                {"json": {"reveal_grant": "x" * 32, "fields": ["pan"]}},
            ),
            (
                "POST",
                "/api/v1/uploads",
                {
                    "json": {
                        "task_id": "missing",
                        "business_name": "denied",
                        "idempotency_key": "denied",
                    }
                },
            ),
            (
                "POST",
                "/api/v1/tasks/missing/uploads",
                {
                    "json": {
                        "business_name": "denied",
                        "idempotency_key": "denied",
                    }
                },
            ),
            ("GET", "/api/v1/uploads/missing", {}),
            ("POST", "/api/v1/uploads/missing/cancel", {}),
        )

        for role, token in tokens.items():
            for method, path, options in route_cases:
                with self.subTest(role=role, method=method, path=path):
                    request_options = dict(options)
                    extra_headers = request_options.pop("extra_headers", {})
                    response = self.request(
                        method,
                        path,
                        headers=self.bearer(token, **extra_headers),
                        **request_options,
                    )
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.json()["error"]["code"], "forbidden")
                    self.assertEqual(
                        response.json()["error"]["message"], "Insufficient role"
                    )

        task_governance_cases = (
            ("GET", "/api/v1/tasks"),
            ("GET", "/api/v1/tasks/missing"),
            ("GET", "/api/v1/tasks/missing/timeline"),
            ("POST", "/api/v1/tasks/missing/close"),
        )
        for role in ("security_auditor", "platform_admin"):
            for method, path in task_governance_cases:
                with self.subTest(role=role, method=method, path=path):
                    response = self.request(
                        method, path, headers=self.bearer(tokens[role])
                    )
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.json()["error"]["code"], "forbidden")

        self.assertEqual(self.persisted_counts(), counts_before)

    def test_operator_owner_task_flow_still_works(self) -> None:
        _device_id, token = self.create_and_login("operator")
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "operator-task"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        listed = self.request("GET", "/api/v1/tasks", headers=self.bearer(token))
        self.assertEqual([task["id"] for task in listed.json()], [task_id])
        fetched = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(token)
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")

    def test_ops_admin_governs_same_tenant_tasks_without_sensitive_values(self) -> None:
        operator_device_id, operator_token = self.create_and_login(
            "operator", suffix="-governed"
        )
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(operator_token),
            json={"type": "mail_code", "idempotency_key": "governed-task"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        task_id = created.json()["id"]
        trace_id = created.json()["trace_id"]

        now = utc_now()
        with self.app.state.session_factory() as db:
            operator_device = db.get(Device, operator_device_id)
            self.assertIsNotNone(operator_device)
            operator_user_id = operator_device.user_id
            mailbox = Mailbox(
                tenant_id="tenant-role-boundary",
                email_masked="o***@example.test",
                connector_type="http",
                secret_ref="vault://secret/mailboxes/ops-task",
            )
            card = Card(
                tenant_id="tenant-role-boundary",
                provider_ref="ops-task-card",
                brand="VISA",
                last4="4242",
                expiry_month=12,
                expiry_year=2029,
                secret_ref="vault://secret/cards/ops-task",
            )
            db.add_all((mailbox, card))
            db.flush()
            mail_session = MailSession(
                tenant_id="tenant-role-boundary",
                task_id=task_id,
                user_id=operator_user_id,
                device_id=operator_device_id,
                mailbox_id=mailbox.id,
                trace_id=trace_id,
                session_token_hash="a" * 64,
                status="waiting",
                expires_at=now + timedelta(minutes=5),
            )
            allocation = CardAllocation(
                tenant_id="tenant-role-boundary",
                task_id=task_id,
                user_id=operator_user_id,
                device_id=operator_device_id,
                card_id=card.id,
                trace_id=trace_id,
                status="active",
                expires_at=now + timedelta(minutes=15),
            )
            db.add_all((mail_session, allocation))
            db.commit()
            mail_session_id = mail_session.id
            allocation_id = allocation.id

        _ops_device_id, ops_token = self.create_and_login(
            "ops_admin", suffix="-task-governor"
        )
        filters = f"status=created&user_id={operator_user_id}&trace_id={trace_id}"
        listed = self.request(
            "GET", f"/api/v1/tasks?{filters}", headers=self.bearer(ops_token)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual([item["id"] for item in listed.json()], [task_id])
        wrong_filter = self.request(
            "GET",
            "/api/v1/tasks?status=closed&user_id=missing-user",
            headers=self.bearer(ops_token),
        )
        self.assertEqual(wrong_filter.status_code, 200, wrong_filter.text)
        self.assertEqual(wrong_filter.json(), [])

        detail = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(ops_token)
        )
        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(ops_token),
        )
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["user_id"], operator_user_id)
        self.assertEqual(detail.json()["device_id"], operator_device_id)
        self.assertEqual(timeline.status_code, 200, timeline.text)
        self.assertEqual(timeline.json()["mail_session"]["email_masked"], "o***@example.test")
        self.assertEqual(
            timeline.json()["card_allocations"][0]["card_masked"],
            "**** **** **** 4242",
        )
        for sensitive in (
            "vault://secret/mailboxes/ops-task",
            "vault://secret/cards/ops-task",
            "4111111111114242",
            "a" * 64,
        ):
            self.assertNotIn(sensitive, timeline.text)

        _other_device_id, other_tenant_token = self.create_and_login(
            "ops_admin",
            suffix="-other-tenant",
            tenant_id="tenant-role-boundary-other",
        )
        other_list = self.request(
            "GET", "/api/v1/tasks", headers=self.bearer(other_tenant_token)
        )
        self.assertEqual(other_list.status_code, 200, other_list.text)
        self.assertEqual(other_list.json(), [])
        for method, path in (
            ("GET", f"/api/v1/tasks/{task_id}"),
            ("GET", f"/api/v1/tasks/{task_id}/timeline"),
            ("POST", f"/api/v1/tasks/{task_id}/close"),
        ):
            hidden = self.request(
                method, path, headers=self.bearer(other_tenant_token)
            )
            self.assertEqual(hidden.status_code, 404, hidden.text)

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(ops_token)
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertEqual(closed.json()["status"], "closed")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(MailSession, mail_session_id).status, "revoked")
            closed_allocation = db.get(CardAllocation, allocation_id)
            self.assertEqual(closed_allocation.status, "released")
            self.assertIsNotNone(closed_allocation.released_at)

    def test_mailbox_summary_is_admin_only(self) -> None:
        tokens = {
            role: self.create_and_login(role, suffix="-mailbox")[1]
            for role in (
                "operator",
                "ops_admin",
                "security_auditor",
                "platform_admin",
            )
        }
        for role, token in tokens.items():
            with self.subTest(role=role):
                response = self.request(
                    "GET", "/api/v1/mailboxes", headers=self.bearer(token)
                )
                expected = 200 if role in {"ops_admin", "platform_admin"} else 403
                self.assertEqual(response.status_code, expected, response.text)
                if expected == 403:
                    self.assertEqual(response.json()["error"]["code"], "forbidden")

    def test_all_interactive_roles_can_revoke_their_own_device(self) -> None:
        for role in (
            "operator",
            "ops_admin",
            "security_auditor",
            "platform_admin",
        ):
            with self.subTest(role=role):
                device_id, token = self.create_and_login(role, suffix="-revoke")
                response = self.request(
                    "POST",
                    f"/api/v1/devices/{device_id}/revoke",
                    headers=self.bearer(token),
                )
                self.assertEqual(response.status_code, 200, response.text)
                self.assertIsNotNone(response.json()["revoked_at"])

    def test_worker_service_cannot_login_or_use_an_oidc_token(self) -> None:
        password = "worker-service-account-password"
        local_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-role-boundary",
            email="worker-service@example.test",
            password=password,
            device_name="worker-service-device",
            role="worker_service",
        )
        correct = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-role-boundary",
                "email": "worker-service@example.test",
                "password": password,
                "device_id": local_identity.device_id,
            },
        )
        unknown = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-role-boundary",
                "email": "unknown-worker@example.test",
                "password": password,
                "device_id": "unknown-device",
            },
        )
        self.assertEqual(correct.status_code, 401, correct.text)
        self.assertEqual(unknown.status_code, 401, unknown.text)
        for field in ("code", "message", "recovery_hint"):
            self.assertEqual(
                correct.json()["error"][field], unknown.json()["error"][field]
            )
        self.assertNotIn("access_token", correct.text)

        oidc_identity = create_oidc_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-role-boundary",
            email="worker-oidc@example.test",
            oidc_subject="worker-oidc-subject",
            device_name="worker-oidc-device",
            role="worker_service",
        )

        class WorkerOidcVerifier:
            @staticmethod
            def verify(_token: str) -> dict[str, str]:
                return {
                    "sub": "worker-oidc-subject",
                    "tenant_id": "tenant-role-boundary",
                    "device_id": oidc_identity.device_id,
                    "identity_kind": "oidc",
                }

        self.app.state.access_token_verifier = WorkerOidcVerifier()
        counts_before = self.persisted_counts()
        for method, path, options in (
            ("GET", "/api/v1/me", {}),
            ("GET", "/api/v1/mailboxes", {}),
            (
                "POST",
                "/api/v1/tasks",
                {"json": {"type": "mail_code", "idempotency_key": "worker"}},
            ),
        ):
            response = self.request(
                method,
                path,
                headers=self.bearer("signed-worker-oidc-token"),
                **options,
            )
            self.assertEqual(response.status_code, 401, response.text)
            self.assertEqual(response.json()["error"]["code"], "unauthorized")
        self.assertEqual(self.persisted_counts(), counts_before)

        with self.app.state.session_factory() as db:
            self.assertIsNone(db.get(Device, local_identity.device_id).last_seen_at)
            self.assertIsNone(db.get(Device, oidc_identity.device_id).last_seen_at)
            login_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "auth.login_failed"
                    )
                )
            )
            worker_attempts = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "auth.login_failed",
                        AuditEvent.user_id == local_identity.user_id,
                        AuditEvent.actor_id == "anonymous",
                    )
                )
            )
            misattributed = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "auth.login_failed",
                        AuditEvent.actor_id == local_identity.user_id,
                    )
                )
            )
        self.assertEqual(len(login_events), 2)
        self.assertEqual(len(worker_attempts), 1)
        self.assertEqual(misattributed, [])
        self.assertEqual(len({event.trace_id for event in login_events}), 2)
        worker_event = worker_attempts[0]
        anonymous_event = next(event for event in login_events if event.user_id is None)
        self.assertEqual(worker_event.entity_id, local_identity.user_id)
        self.assertIsNone(worker_event.device_id)
        self.assertEqual(anonymous_event.actor_id, "anonymous")
        self.assertIsNone(anonymous_event.entity_id)
        self.assertIsNone(anonymous_event.device_id)
        self.assertTrue(
            all(
                event.actor_id == "anonymous" and event.details_json
                == '{"method": "local_account", "reason": "authentication_failed"}'
                for event in login_events
            )
        )
        audit_text = "\n".join(event.details_json for event in login_events)
        for secret in (
            password,
            "worker-service@example.test",
            "unknown-worker@example.test",
            "unknown-device",
        ):
            self.assertNotIn(secret, audit_text)


if __name__ == "__main__":
    unittest.main()
