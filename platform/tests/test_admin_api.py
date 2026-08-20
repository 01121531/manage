import asyncio
import json
import unittest

import httpx

from platform.app import create_app
from platform.bootstrap import create_user_with_device, provision_card
from platform.config import Settings
from platform.models import AuditEvent


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
            secret_ref="vault://cards/provider-card-1",
        )
        cards = self.request("GET", "/api/v1/admin/cards", headers=self.headers(admin_token))
        self.assertEqual(cards.status_code, 200, cards.text)
        self.assertEqual(cards.json()[0]["last4"], "4242")
        serialized = json.dumps(cards.json()).lower()
        self.assertNotIn("secret_ref", serialized)
        self.assertNotIn("vault://", serialized)

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
