import asyncio
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier
from unittest import mock

import httpx
from sqlalchemy import func, select
from pydantic import ValidationError

from platform import auth
from platform.app import create_app
from platform.auth import hash_password
from platform.bootstrap import create_oidc_user_with_device, create_user_with_device
from platform.config import Settings
from platform.models import AuditEvent, Device, User


@dataclass(frozen=True)
class SeededIdentity:
    user_id: str
    device_id: str | None
    tenant_id: str
    email: str
    password: str


class FakeOidcVerifier:
    def __init__(self, claims: dict[str, object]) -> None:
        self.claims = claims

    def verify(self, token: str) -> dict[str, object]:
        if token != "signed-device-limit-test-token":
            raise ValueError("invalid token")
        return dict(self.claims)


class DeviceLimitHarness:
    def __init__(self, *, limit: int, auth_mode: str = "local") -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="device-limit-")
        database_path = Path(self.temp_dir.name) / "platform.db"
        settings_kwargs: dict[str, object] = {
            "environment": "test",
            "auth_mode": auth_mode,
            "database_url": f"sqlite+pysqlite:///{database_path.as_posix()}",
            "max_active_devices_per_user": limit,
        }
        verifier = None
        if auth_mode == "local":
            settings_kwargs["jwt_hmac_secret"] = "device-limit-unit-test-secret"
        else:
            settings_kwargs.update(
                {
                    "oidc_issuer_url": "https://identity.example.test/realms/platform",
                    "oidc_audience": "email-platform-api",
                    "oidc_client_id": "email-platform-web",
                    "oidc_desktop_client_id": "email-platform-desktop",
                    "oidc_jwks_url": (
                        "https://identity.example.test/realms/platform/"
                        "protocol/openid-connect/certs"
                    ),
                }
            )
            verifier = FakeOidcVerifier({})
        self.app = create_app(Settings(**settings_kwargs), access_token_verifier=verifier)
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        self.app.state.engine.dispose()
        self.temp_dir.cleanup()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def seed_identity(
        self,
        *,
        tenant_id: str,
        email: str,
        role: str = "operator",
        password: str = "device-limit-account-password",
        device_name: str | None = None,
        oidc_subject: str | None = None,
        is_active: bool = True,
    ) -> SeededIdentity:
        with self.app.state.session_factory() as db:
            user = User(
                tenant_id=tenant_id,
                email=email,
                password_hash=(hash_password(password) if oidc_subject is None else None),
                oidc_subject=oidc_subject,
                role=role,
                is_active=is_active,
            )
            db.add(user)
            db.flush()
            device_id = None
            if device_name is not None:
                device = Device(
                    tenant_id=tenant_id,
                    user_id=user.id,
                    name=device_name,
                )
                db.add(device)
                db.flush()
                device_id = device.id
            db.commit()
            return SeededIdentity(
                user_id=user.id,
                device_id=device_id,
                tenant_id=tenant_id,
                email=email,
                password=password,
            )

    def login(self, identity: SeededIdentity) -> str:
        if identity.device_id is None:
            raise AssertionError("login fixture requires a pre-provisioned device")
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": identity.tenant_id,
                "email": identity.email,
                "password": identity.password,
                "device_id": identity.device_id,
            },
        )
        if response.status_code != 200:
            raise AssertionError(response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def register(
        self,
        token: str,
        *,
        user_id: str,
        name: str,
    ) -> httpx.Response:
        return self.request(
            "POST",
            f"/api/v1/admin/users/{user_id}/devices",
            headers=self.bearer(token),
            json={"name": name},
        )

    def revoke(self, token: str, device_id: str) -> httpx.Response:
        return self.request(
            "POST",
            f"/api/v1/admin/devices/{device_id}/revoke",
            headers=self.bearer(token),
        )

    def device_rows(self, user_id: str) -> list[Device]:
        with self.app.state.session_factory() as db:
            return list(
                db.scalars(
                    select(Device)
                    .where(Device.user_id == user_id)
                    .order_by(Device.created_at, Device.id)
                )
            )

    def audit_count(self, event_type: str, *, entity_id: str | None = None) -> int:
        with self.app.state.session_factory() as db:
            statement = (
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.event_type == event_type)
            )
            if entity_id is not None:
                statement = statement.where(AuditEvent.entity_id == entity_id)
            return int(db.scalar(statement) or 0)


class DeviceLimitConfigurationTests(unittest.TestCase):
    def test_zero_one_and_n_are_valid_explicit_limits(self) -> None:
        for limit in (0, 1, 7):
            with self.subTest(limit=limit):
                settings = Settings(max_active_devices_per_user=limit)
                self.assertEqual(settings.max_active_devices_per_user, limit)

    def test_negative_limit_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            Settings(max_active_devices_per_user=-1)


class DeviceLimitApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = DeviceLimitHarness(limit=2)
        self.admin = self.harness.seed_identity(
            tenant_id="tenant-a",
            email="admin@example.test",
            role="platform_admin",
            device_name="admin-device",
        )
        self.target = self.harness.seed_identity(
            tenant_id="tenant-a",
            email="target@example.test",
        )
        self.admin_token = self.harness.login(self.admin)

    def tearDown(self) -> None:
        self.harness.close()

    def test_registration_is_created_then_active_same_name_is_idempotent(self) -> None:
        created = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="target-workstation",
        )
        replay = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="target-workstation",
        )

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], created.json()["id"])
        self.assertEqual(created.json()["user_id"], self.target.user_id)
        self.assertEqual(created.json()["name"], "target-workstation")
        rows = self.harness.device_rows(self.target.user_id)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].last_seen_at)
        self.assertEqual(
            self.harness.audit_count(
                "admin.device_registered",
                entity_id=created.json()["id"],
            ),
            1,
        )

    def test_registration_rechecks_admin_after_authentication(self) -> None:
        original_resolve = auth._resolve_principal
        demoted = False

        def demote_after_authentication(*args, **kwargs):
            nonlocal demoted
            principal = original_resolve(*args, **kwargs)
            if not demoted:
                with self.harness.app.state.session_factory() as db:
                    admin = db.get(User, self.admin.user_id)
                    self.assertIsNotNone(admin)
                    admin.role = "security_auditor"
                    db.commit()
                demoted = True
            return principal

        with mock.patch.object(
            auth, "_resolve_principal", side_effect=demote_after_authentication
        ):
            response = self.harness.register(
                self.admin_token,
                user_id=self.target.user_id,
                name="late-provisioned-device",
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.harness.device_rows(self.target.user_id), [])
        self.assertEqual(self.harness.audit_count("admin.device_registered"), 0)

    def test_revocation_rechecks_admin_after_authentication(self) -> None:
        created = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="target-device-to-revoke",
        )
        self.assertEqual(created.status_code, 201, created.text)
        original_resolve = auth._resolve_principal
        demoted = False

        def demote_after_authentication(*args, **kwargs):
            nonlocal demoted
            principal = original_resolve(*args, **kwargs)
            if not demoted:
                with self.harness.app.state.session_factory() as db:
                    admin = db.get(User, self.admin.user_id)
                    self.assertIsNotNone(admin)
                    admin.role = "security_auditor"
                    db.commit()
                demoted = True
            return principal

        with mock.patch.object(
            auth, "_resolve_principal", side_effect=demote_after_authentication
        ):
            response = self.harness.revoke(
                self.admin_token,
                created.json()["id"],
            )

        self.assertEqual(response.status_code, 403, response.text)
        rows = self.harness.device_rows(self.target.user_id)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].revoked_at)
        self.assertEqual(self.harness.audit_count("admin.device_revoked"), 0)

    def test_revoked_name_is_a_tombstone_and_cannot_be_reactivated(self) -> None:
        created = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="revoked-workstation",
        )
        self.assertEqual(created.status_code, 201, created.text)
        revoked = self.harness.revoke(self.admin_token, created.json()["id"])
        self.assertEqual(revoked.status_code, 200, revoked.text)

        replay = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="revoked-workstation",
        )

        self.assertEqual(replay.status_code, 409, replay.text)
        rows = self.harness.device_rows(self.target.user_id)
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0].revoked_at)
        self.assertEqual(
            self.harness.audit_count("admin.device_registered"),
            1,
        )
        self.assertNotIn("access_token", replay.text)

    def test_n_plus_one_fails_and_revocation_releases_one_slot(self) -> None:
        first = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="slot-a",
        )
        second = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="slot-b",
        )
        blocked_name = "private-over-limit-device"
        blocked = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name=blocked_name,
        )

        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertNotIn(blocked_name, blocked.text)
        self.assertNotIn(self.target.user_id, blocked.text)
        self.assertNotIn("access_token", blocked.text)
        before_replacement = self.harness.device_rows(self.target.user_id)
        self.assertEqual(len(before_replacement), 2)
        self.assertTrue(all(device.last_seen_at is None for device in before_replacement))
        self.assertEqual(self.harness.audit_count("admin.device_registered"), 2)

        revoked = self.harness.revoke(self.admin_token, first.json()["id"])
        replacement = self.harness.register(
            self.admin_token,
            user_id=self.target.user_id,
            name="slot-c",
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(replacement.status_code, 201, replacement.text)
        rows = self.harness.device_rows(self.target.user_id)
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(row.revoked_at is None for row in rows), 2)
        self.assertEqual(self.harness.audit_count("admin.device_registered"), 3)

    def test_limit_one_and_zero_fail_without_registration_side_effects(self) -> None:
        for limit in (0, 1):
            with self.subTest(limit=limit):
                harness = DeviceLimitHarness(limit=limit)
                try:
                    admin = harness.seed_identity(
                        tenant_id=f"tenant-{limit}",
                        email=f"admin-{limit}@example.test",
                        role="platform_admin",
                        device_name="pre-existing-admin-device",
                    )
                    target = harness.seed_identity(
                        tenant_id=f"tenant-{limit}",
                        email=f"target-{limit}@example.test",
                        device_name=("pre-existing-target-device" if limit == 1 else None),
                    )
                    token = harness.login(admin)
                    attempted_name = f"sensitive-limit-{limit}-device"
                    blocked = harness.register(
                        token,
                        user_id=target.user_id,
                        name=attempted_name,
                    )

                    self.assertEqual(blocked.status_code, 409, blocked.text)
                    self.assertNotIn(attempted_name, blocked.text)
                    self.assertNotIn(target.user_id, blocked.text)
                    self.assertNotIn("access_token", blocked.text)
                    rows = harness.device_rows(target.user_id)
                    self.assertEqual(len(rows), limit)
                    self.assertTrue(all(row.last_seen_at is None for row in rows))
                    self.assertEqual(harness.audit_count("admin.device_registered"), 0)
                finally:
                    harness.close()

    def test_tenant_and_role_boundaries_do_not_create_devices(self) -> None:
        ops_admin = self.harness.seed_identity(
            tenant_id="tenant-a",
            email="ops-admin@example.test",
            role="ops_admin",
            device_name="ops-admin-device",
        )
        operator = self.harness.seed_identity(
            tenant_id="tenant-a",
            email="operator@example.test",
            role="operator",
            device_name="operator-device",
        )
        foreign_target = self.harness.seed_identity(
            tenant_id="tenant-b",
            email="foreign-target@example.test",
        )
        denied_responses = [
            self.harness.register(
                self.harness.login(ops_admin),
                user_id=self.target.user_id,
                name="ops-admin-forbidden-device",
            ),
            self.harness.register(
                self.harness.login(operator),
                user_id=self.target.user_id,
                name="operator-forbidden-device",
            ),
            self.harness.register(
                self.admin_token,
                user_id=foreign_target.user_id,
                name="cross-tenant-forbidden-device",
            ),
        ]

        self.assertEqual([response.status_code for response in denied_responses], [403, 403, 404])
        for response, private_name in zip(
            denied_responses,
            (
                "ops-admin-forbidden-device",
                "operator-forbidden-device",
                "cross-tenant-forbidden-device",
            ),
            strict=True,
        ):
            self.assertNotIn(private_name, response.text)
            self.assertNotIn("access_token", response.text)
        self.assertEqual(self.harness.device_rows(self.target.user_id), [])
        self.assertEqual(self.harness.device_rows(foreign_target.user_id), [])
        self.assertEqual(self.harness.audit_count("admin.device_registered"), 0)

    def test_same_name_isolated_between_users_and_tenants(self) -> None:
        peer = self.harness.seed_identity(
            tenant_id="tenant-a",
            email="peer@example.test",
        )
        tenant_b_admin = self.harness.seed_identity(
            tenant_id="tenant-b",
            email="tenant-b-admin@example.test",
            role="platform_admin",
            device_name="tenant-b-admin-device",
        )
        tenant_b_target = self.harness.seed_identity(
            tenant_id="tenant-b",
            email="tenant-b-target@example.test",
        )
        common_name = "shared-display-name"

        responses = [
            self.harness.register(
                self.admin_token,
                user_id=user_id,
                name=common_name,
            )
            for user_id in (self.target.user_id, peer.user_id)
        ]
        responses.append(
            self.harness.register(
                self.harness.login(tenant_b_admin),
                user_id=tenant_b_target.user_id,
                name=common_name,
            )
        )

        self.assertEqual([response.status_code for response in responses], [201, 201, 201])
        self.assertEqual(len({response.json()["id"] for response in responses}), 3)


class DeviceLimitConcurrencyTests(unittest.TestCase):
    def test_sqlite_wal_different_names_compete_for_last_slot(self) -> None:
        harness = DeviceLimitHarness(limit=2)
        try:
            admin = harness.seed_identity(
                tenant_id="tenant-race",
                email="race-admin@example.test",
                role="platform_admin",
                device_name="race-admin-device",
            )
            target = harness.seed_identity(
                tenant_id="tenant-race",
                email="race-target@example.test",
            )
            token = harness.login(admin)
            first = harness.register(token, user_id=target.user_id, name="occupied-slot")
            self.assertEqual(first.status_code, 201, first.text)
            barrier = Barrier(2)

            def compete(name: str) -> httpx.Response:
                barrier.wait(timeout=5)
                return harness.register(token, user_id=target.user_id, name=name)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(compete, name)
                    for name in ("race-private-a", "race-private-b")
                ]
                responses = [future.result(timeout=15) for future in futures]

            self.assertEqual(
                sorted(response.status_code for response in responses),
                [201, 409],
            )
            blocked = next(response for response in responses if response.status_code == 409)
            self.assertNotIn("race-private-a", blocked.text)
            self.assertNotIn("race-private-b", blocked.text)
            rows = harness.device_rows(target.user_id)
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(row.revoked_at is None for row in rows), 2)
            self.assertEqual(harness.audit_count("admin.device_registered"), 2)
        finally:
            harness.close()


class DeviceLimitAuthenticationBoundaryTests(unittest.TestCase):
    def test_local_login_with_unknown_device_never_registers_it(self) -> None:
        harness = DeviceLimitHarness(limit=3)
        try:
            identity = harness.seed_identity(
                tenant_id="tenant-local-login",
                email="local-login@example.test",
            )
            unknown_device_id = "00000000-0000-4000-8000-000000000099"
            response = harness.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": identity.tenant_id,
                    "email": identity.email,
                    "password": identity.password,
                    "device_id": unknown_device_id,
                },
            )
            self.assertEqual(response.status_code, 401, response.text)
            self.assertNotIn(unknown_device_id, response.text)
            self.assertNotIn("access_token", response.text)
            self.assertEqual(harness.device_rows(identity.user_id), [])
            self.assertEqual(harness.audit_count("admin.device_registered"), 0)
        finally:
            harness.close()

    def test_oidc_claim_with_unknown_device_never_registers_it(self) -> None:
        harness = DeviceLimitHarness(limit=3, auth_mode="oidc")
        try:
            identity = harness.seed_identity(
                tenant_id="tenant-oidc-login",
                email="oidc-login@example.test",
                oidc_subject="oidc-device-limit-user",
            )
            unknown_device_id = "00000000-0000-4000-8000-000000000088"
            harness.app.state.access_token_verifier = FakeOidcVerifier(
                {
                    "sub": "oidc-device-limit-user",
                    "tenant_id": identity.tenant_id,
                    "device_id": unknown_device_id,
                    "identity_kind": "oidc",
                }
            )
            response = harness.request(
                "GET",
                "/api/v1/me",
                headers={"Authorization": "Bearer signed-device-limit-test-token"},
            )
            self.assertEqual(response.status_code, 401, response.text)
            self.assertNotIn(unknown_device_id, response.text)
            self.assertEqual(harness.device_rows(identity.user_id), [])
            self.assertEqual(harness.audit_count("admin.device_registered"), 0)
        finally:
            harness.close()


class DeviceLimitBootstrapTests(unittest.TestCase):
    def test_zero_limit_rolls_back_local_and_oidc_user_with_first_device(self) -> None:
        harness = DeviceLimitHarness(limit=0)
        try:
            calls = (
                (
                    create_user_with_device,
                    {
                        "tenant_id": "tenant-bootstrap-local",
                        "email": "bootstrap-local@example.test",
                        "password": "bootstrap-local-password",
                        "device_name": "bootstrap-local-device",
                    },
                ),
                (
                    create_oidc_user_with_device,
                    {
                        "tenant_id": "tenant-bootstrap-oidc",
                        "email": "bootstrap-oidc@example.test",
                        "oidc_subject": "bootstrap-oidc-subject",
                        "device_name": "bootstrap-oidc-device",
                    },
                ),
            )
            for create_identity, kwargs in calls:
                with self.subTest(create_identity=create_identity.__name__):
                    with self.assertRaises(Exception) as caught:
                        create_identity(
                            harness.app.state.session_factory,
                            max_active_devices_per_user=0,
                            **kwargs,
                        )
                    self.assertNotIsInstance(caught.exception, TypeError)

            with harness.app.state.session_factory() as db:
                self.assertEqual(db.scalar(select(func.count()).select_from(User)), 0)
                self.assertEqual(db.scalar(select(func.count()).select_from(Device)), 0)
                self.assertEqual(db.scalar(select(func.count()).select_from(AuditEvent)), 0)
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()
