"""Contract tests for four-eyes approval of administrator role changes.

The intended API is deliberately separate from the legacy direct mutation:

* ``POST /admin/users/{user_id}/role-change-requests`` creates a pending request.
* ``POST /admin/role-change-requests/{request_id}/approve`` applies it once.

Approval requires a different platform administrator whose MFA authentication
occurred after the request was created.
"""

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock
from unittest import mock

import httpx
from sqlalchemy import func, select

from platform import auth
from platform.api.v1 import routes
from platform.app import create_app
from platform.bootstrap import BootstrapIdentity, create_user_with_device
from platform.config import Settings
from platform.models import AdminRoleChangeRequest, AuditEvent, User, utc_now


_MISSING = object()
_MFA_ACR = "urn:email-platform:acr:mfa"
_REAL_UTC_NOW = routes._utc_now
_REAL_IS_EXPIRED = routes._is_expired


class ClaimVerifier:
    """Small auth seam matching the claims consumed by ``AuthPrincipal``."""

    def __init__(self) -> None:
        self._claims: dict[str, dict[str, object]] = {}
        self._lock = Lock()

    def issue(
        self,
        identity: BootstrapIdentity,
        *,
        tenant_id: str,
        auth_time: datetime,
        acr: str | object = "urn:email-platform:acr:password",
        amr: tuple[str, ...] = ("pwd",),
    ) -> str:
        with self._lock:
            token = f"role-change-token-{len(self._claims) + 1}"
            claims: dict[str, object] = {
                "sub": identity.user_id,
                "tenant_id": tenant_id,
                "device_id": identity.device_id,
                "identity_kind": "oidc",
                "auth_time": int(auth_time.timestamp()),
                "amr": list(amr),
                "jti": f"role-change-jti-{len(self._claims) + 1:04d}",
                "exp": int((auth_time + timedelta(days=730)).timestamp()),
            }
            if acr is not _MISSING:
                claims["acr"] = acr
            self._claims[token] = claims
            return token

    def verify(self, token: str) -> dict[str, object]:
        try:
            return dict(self._claims[token])
        except KeyError as error:
            raise ValueError("invalid token") from error


class AdminRoleChangeApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="admin-role-change-")
        database_path = Path(self.directory.name) / "platform.db"
        self.settings = Settings(
            app_name="admin-role-change-test",
            environment="test",
            database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
            jwt_hmac_secret="admin-role-change-test-secret-not-for-production",
            card_step_up_acr=_MFA_ACR,
        )
        self.app = create_app(self.settings)
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")

        self.requester = self.create_identity(
            "tenant-a", "requester@example.test", "platform_admin"
        )
        self.approver = self.create_identity(
            "tenant-a", "approver@example.test", "platform_admin"
        )
        self.concurrent_approver = self.create_identity(
            "tenant-a", "approver-two@example.test", "platform_admin"
        )
        self.target = self.create_identity(
            "tenant-a", "target@example.test", "operator"
        )
        self.other_tenant_admin = self.create_identity(
            "tenant-b", "other-admin@example.test", "platform_admin"
        )
        self.other_tenant_target = self.create_identity(
            "tenant-b", "other-target@example.test", "operator"
        )

        self.verifier = ClaimVerifier()
        self.app.state.access_token_verifier = self.verifier
        self.requested_at = utc_now().replace(microsecond=0) - timedelta(seconds=30)
        self.requester_token = self.verifier.issue(
            self.requester,
            tenant_id="tenant-a",
            auth_time=self.requested_at - timedelta(minutes=1),
        )

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.directory.cleanup()
        observed_clock = routes._utc_now
        observed_expiry = routes._is_expired
        routes._utc_now = _REAL_UTC_NOW
        routes._is_expired = _REAL_IS_EXPIRED
        self.assertIs(observed_clock, _REAL_UTC_NOW)
        self.assertIs(observed_expiry, _REAL_IS_EXPIRED)

    def create_identity(
        self, tenant_id: str, email: str, role: str
    ) -> BootstrapIdentity:
        identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id=tenant_id,
            email=email,
            password=f"{email}-password-long-enough",
            device_name=f"{email}-device",
            role=role,
        )
        # OIDC principal resolution uses the database subject, while keeping
        # the compact BootstrapIdentity factory used throughout platform tests.
        with self.app.state.session_factory() as db:
            user = db.get(User, identity.user_id)
            self.assertIsNotNone(user)
            user.oidc_subject = identity.user_id
            db.commit()
        return identity

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def user_role(self, user_id: str) -> str:
        with self.app.state.session_factory() as db:
            user = db.get(User, user_id)
            self.assertIsNotNone(user)
            return user.role

    def create_role_change(
        self,
        *,
        target: BootstrapIdentity | None = None,
        token: str | None = None,
        role: str = "security_auditor",
        requested_at: datetime | None = None,
    ) -> dict[str, object]:
        target = target or self.target
        with mock.patch.object(
            routes, "_utc_now", return_value=requested_at or self.requested_at
        ):
            response = self.request(
                "POST",
                f"/api/v1/admin/users/{target.user_id}/role-change-requests",
                headers=self.bearer(token or self.requester_token),
                json={"role": role},
            )
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        self.assertEqual(body["target_user_id"], target.user_id)
        self.assertEqual(body["expected_old_role"], "operator")
        self.assertEqual(body["new_role"], role)
        self.assertEqual(body["requested_by"], self.requester.user_id)
        self.assertEqual(body["status"], "pending")
        return body

    def mfa_token(
        self,
        identity: BootstrapIdentity | None = None,
        *,
        tenant_id: str = "tenant-a",
        auth_time: datetime | None = None,
        acr: str | object = _MFA_ACR,
    ) -> str:
        return self.verifier.issue(
            identity or self.approver,
            tenant_id=tenant_id,
            auth_time=auth_time or self.requested_at + timedelta(seconds=5),
            acr=acr,
            amr=("pwd", "otp"),
        )

    def approve(
        self,
        request_id: str,
        token: str,
        *,
        now: datetime | None = None,
    ) -> httpx.Response:
        with mock.patch.object(
            routes, "_utc_now", return_value=now or self.requested_at + timedelta(seconds=10)
        ):
            return self.request(
                "POST",
                f"/api/v1/admin/role-change-requests/{request_id}/approve",
                headers=self.bearer(token),
            )

    def test_legacy_direct_patch_no_longer_applies_a_role_immediately(self) -> None:
        response = self.request(
            "PATCH",
            f"/api/v1/admin/users/{self.target.user_id}/role",
            headers=self.bearer(self.requester_token),
            json={"role": "security_auditor"},
        )

        self.assertIn(response.status_code, {202, 404, 405, 409, 410}, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_creating_a_request_keeps_the_role_pending(self) -> None:
        created = self.create_role_change()

        self.assertTrue(created["id"])
        self.assertIsNone(created.get("approved_by"))
        self.assertIsNone(created.get("applied_at"))
        self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_target_claim_restarts_once_after_an_inconsistent_empty_read(self) -> None:
        db = mock.Mock()
        target = mock.Mock(spec=User)
        db.scalar.side_effect = [None, target]

        claimed = routes._claim_admin_role_change_target(
            db,
            user_id=self.target.user_id,
            tenant_id="tenant-a",
        )

        self.assertIs(claimed, target)
        self.assertEqual(db.execute.call_count, 2)
        db.rollback.assert_called_once_with()

    def test_two_concurrent_requests_for_one_target_have_one_winner(self) -> None:
        async def create_pair() -> list[httpx.Response]:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return list(
                    await asyncio.gather(
                        *(
                            client.post(
                                f"/api/v1/admin/users/{self.target.user_id}/role-change-requests",
                                headers=self.bearer(self.requester_token),
                                json={"role": "security_auditor"},
                            )
                            for _ in range(2)
                        )
                    )
                )

        with mock.patch.object(routes, "_utc_now", return_value=self.requested_at):
            responses = asyncio.run(create_pair())

        self.assertEqual(
            sorted(response.status_code for response in responses),
            [201, 409],
            [(response.status_code, response.text) for response in responses],
        )
        with self.app.state.session_factory() as db:
            pending = db.scalar(
                select(func.count(AdminRoleChangeRequest.id)).where(
                    AdminRoleChangeRequest.target_user_id == self.target.user_id,
                    AdminRoleChangeRequest.status == "pending",
                )
            )
        self.assertEqual(pending, 1)

    def test_requester_cannot_approve_their_own_request(self) -> None:
        created = self.create_role_change()
        requester_mfa = self.mfa_token(self.requester)

        response = self.approve(str(created["id"]), requester_mfa)

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_approval_requires_the_exact_mfa_acr(self) -> None:
        created = self.create_role_change()
        for label, acr in (
            ("missing", _MISSING),
            ("wrong", "urn:email-platform:acr:password"),
        ):
            with self.subTest(acr=label):
                response = self.approve(
                    str(created["id"]), self.mfa_token(acr=acr)
                )
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_mfa_authentication_must_postdate_the_request(self) -> None:
        created = self.create_role_change()
        stale_mfa = self.mfa_token(
            auth_time=self.requested_at - timedelta(seconds=1)
        )

        response = self.approve(str(created["id"]), stale_mfa)

        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_approval_rechecks_approver_after_authentication(self) -> None:
        created = self.create_role_change()
        original_resolve = auth._resolve_principal
        demoted = False

        def demote_after_authentication(*args, **kwargs):
            nonlocal demoted
            principal = original_resolve(*args, **kwargs)
            if not demoted:
                with self.app.state.session_factory() as db:
                    approver = db.get(User, self.approver.user_id)
                    self.assertIsNotNone(approver)
                    approver.role = "security_auditor"
                    db.commit()
                demoted = True
            return principal

        with mock.patch.object(
            auth, "_resolve_principal", side_effect=demote_after_authentication
        ):
            response = self.approve(str(created["id"]), self.mfa_token())

        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")
        with self.app.state.session_factory() as db:
            role_change = db.get(AdminRoleChangeRequest, str(created["id"]))
        self.assertEqual(role_change.status, "pending")

    def test_second_admin_applies_once_and_existing_token_sees_role_only_afterward(
        self,
    ) -> None:
        target_token = self.verifier.issue(
            self.target,
            tenant_id="tenant-a",
            auth_time=self.requested_at - timedelta(minutes=1),
        )
        before = self.request(
            "GET", "/api/v1/admin/audit", headers=self.bearer(target_token)
        )
        self.assertEqual(before.status_code, 403, before.text)

        created = self.create_role_change()
        while_pending = self.request(
            "GET", "/api/v1/admin/audit", headers=self.bearer(target_token)
        )
        self.assertEqual(while_pending.status_code, 403, while_pending.text)

        approver_mfa = self.mfa_token()
        applied = self.approve(str(created["id"]), approver_mfa)
        replay = self.approve(str(created["id"]), approver_mfa)

        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertEqual(applied.json()["status"], "applied")
        self.assertEqual(applied.json()["approved_by"], self.approver.user_id)
        self.assertEqual(replay.status_code, 409, replay.text)
        self.assertEqual(self.user_role(self.target.user_id), "security_auditor")
        after = self.request(
            "GET", "/api/v1/admin/audit", headers=self.bearer(target_token)
        )
        self.assertEqual(after.status_code, 200, after.text)

        with self.app.state.session_factory() as db:
            requested_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.tenant_id == "tenant-a",
                        AuditEvent.event_type == "admin.user_role_change_requested",
                    )
                )
            )
            applied_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.tenant_id == "tenant-a",
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.target.user_id,
                    )
                )
            )
        self.assertEqual(len(requested_events), 1)
        self.assertEqual(len(applied_events), 1)
        self.assertEqual(requested_events[0].actor_id, self.requester.user_id)
        self.assertEqual(applied_events[0].actor_id, self.approver.user_id)
        self.assertNotEqual(requested_events[0].actor_id, applied_events[0].actor_id)
        applied_details = json.loads(applied_events[0].details_json)
        self.assertEqual(applied_details["requested_by"], self.requester.user_id)
        self.assertEqual(applied_details["approved_by"], self.approver.user_id)

    def test_two_concurrent_approvals_have_one_winner(self) -> None:
        created = self.create_role_change()
        tokens = (
            self.mfa_token(self.approver),
            self.mfa_token(self.concurrent_approver),
        )
        both_read_pending = Barrier(2)
        original_is_expired = routes._is_expired

        def synchronize_after_pending_read(value: datetime, now: datetime) -> bool:
            both_read_pending.wait(timeout=5)
            return original_is_expired(value, now)

        async def approve_pair() -> list[httpx.Response]:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return list(
                    await asyncio.gather(
                        *(
                            client.post(
                                f"/api/v1/admin/role-change-requests/{created['id']}/approve",
                                headers=self.bearer(token),
                            )
                            for token in tokens
                        )
                    )
                )

        with mock.patch.object(
            routes,
            "_utc_now",
            return_value=self.requested_at + timedelta(seconds=10),
        ), mock.patch.object(
            routes, "_is_expired", side_effect=synchronize_after_pending_read
        ):
            responses = asyncio.run(approve_pair())

        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        self.assertEqual(self.user_role(self.target.user_id), "security_auditor")
        with self.app.state.session_factory() as db:
            applied_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "admin.user_role_changed",
                        AuditEvent.entity_id == self.target.user_id,
                    )
                )
            )
        self.assertEqual(len(applied_events), 1)

    def test_cross_tenant_targets_and_requests_are_hidden(self) -> None:
        target_response = self.request(
            "POST",
            f"/api/v1/admin/users/{self.other_tenant_target.user_id}/role-change-requests",
            headers=self.bearer(self.requester_token),
            json={"role": "security_auditor"},
        )
        self.assertEqual(target_response.status_code, 404, target_response.text)

        created = self.create_role_change()
        other_tenant_mfa = self.mfa_token(
            self.other_tenant_admin,
            tenant_id="tenant-b",
        )
        request_response = self.approve(str(created["id"]), other_tenant_mfa)
        self.assertEqual(request_response.status_code, 404, request_response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")

    def test_target_role_drift_prevents_approval(self) -> None:
        created = self.create_role_change()
        with self.app.state.session_factory() as db:
            target = db.get(User, self.target.user_id)
            self.assertIsNotNone(target)
            target.role = "ops_admin"
            db.commit()

        response = self.approve(str(created["id"]), self.mfa_token())

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "ops_admin")

    def test_expired_request_prevents_approval(self) -> None:
        created = self.create_role_change()
        approval_time = self.requested_at + timedelta(days=365)
        fresh_mfa = self.mfa_token(auth_time=approval_time - timedelta(seconds=1))

        response = self.approve(
            str(created["id"]), fresh_mfa, now=approval_time
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.user_role(self.target.user_id), "operator")


if __name__ == "__main__":
    unittest.main()
