import asyncio
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from sqlalchemy import func, select

from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import AuditEvent, Card, Mailbox, PoolImportReceipt
from platform.pool_imports import VerifiedPoolImportReceipt


class _FakeVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(
        self,
        token: str,
        *,
        tenant_id: str,
        pool_type: str,
        ordered_manifest_digest: str,
        item_count: int,
    ) -> VerifiedPoolImportReceipt:
        self.calls += 1
        receipt_id = str(UUID(token))
        now = datetime.now(timezone.utc)
        return VerifiedPoolImportReceipt(
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            pool_type=pool_type,
            ordered_manifest_digest=ordered_manifest_digest,
            item_count=item_count,
            issued_at=now - timedelta(seconds=10),
            expires_at=now + timedelta(minutes=5),
            key_version=1,
        )


class SecurePoolImportApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "secure-import-api.db"
        self.verifier = _FakeVerifier()
        self.app = create_app(
            Settings(
                environment="test",
                database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                jwt_hmac_secret="secure-import-test-secret-not-for-production",
            ),
            pool_import_receipt_verifier=self.verifier,
        )
        self.admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-a",
            email="admin@example.test",
            password="admin-password",
            device_name="admin-device",
            role="platform_admin",
        )
        login = self.request("POST", "/api/v1/auth/login", json={
            "tenant_id": "tenant-a",
            "email": "admin@example.test",
            "password": "admin-password",
            "device_id": self.admin.device_id,
        })
        self.assertEqual(login.status_code, 200, login.text)
        self.authorization = f"Bearer {login.json()['access_token']}"

    def tearDown(self) -> None:
        self.app.state.engine.dispose()
        self.temp_dir.cleanup()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def headers(self, receipt_id: str, key: str) -> dict[str, str]:
        return {
            "Authorization": self.authorization,
            "Idempotency-Key": key,
            "Secure-Import-Receipt": receipt_id,
        }

    def test_card_import_derives_refs_and_replays_without_reverification(self) -> None:
        receipt_id = str(uuid4())
        payload = [{
            "provider_ref": "provider-card-1",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        first = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(receipt_id, f"spi:{receipt_id}"),
            json=payload,
        )
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(self.verifier.calls, 1)
        first_receipt = first.json()
        self.assertEqual(first_receipt["status"], "committed")
        self.assertEqual(first_receipt["key_version"], 1)
        self.assertEqual(
            first_receipt["secure_receipt_fingerprint"],
            hashlib.sha256(receipt_id.encode("ascii")).hexdigest(),
        )
        self.assertRegex(first_receipt["ordered_manifest_digest"], r"^[0-9a-f]{64}$")
        self.assertIsInstance(first_receipt["consumed_at"], str)
        replay_headers = self.headers(str(uuid4()), f"spi:{receipt_id}")
        replay_headers.pop("Secure-Import-Receipt")
        replay = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=replay_headers,
            json=payload,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(self.verifier.calls, 1)
        with self.app.state.session_factory() as db:
            card = db.scalar(select(Card).where(Card.provider_ref == "provider-card-1"))
            assert card is not None
            self.assertRegex(
                card.secret_ref,
                rf"^vault://secret/cards/imports/[0-9a-f]{{24}}/{receipt_id}/000$",
            )
            self.assertEqual(db.scalar(select(func.count()).select_from(PoolImportReceipt)), 1)
            audit_json = "\n".join(item.details_json for item in db.scalars(select(AuditEvent)))
            self.assertNotIn(receipt_id, audit_json)
            self.assertNotIn("vault://", audit_json)
            self.assertIn(first_receipt["ordered_manifest_digest"], audit_json)
            self.assertIn(first_receipt["secure_receipt_fingerprint"], audit_json)

    def test_mailbox_import_and_receipt_one_time_consumption(self) -> None:
        receipt_id = str(uuid4())
        payload = [{
            "email_masked": "m***@example.test",
            "connector_type": "http",
            "task_type": "mail_code",
        }]
        first = self.request(
            "POST",
            "/api/v1/admin/mailboxes/imports",
            headers=self.headers(receipt_id, f"spi:{receipt_id}"),
            json=payload,
        )
        self.assertEqual(first.status_code, 201, first.text)
        consumed = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(receipt_id, f"spi:{receipt_id}"),
            json=[{
                "provider_ref": "provider-cross-pool",
                "pool_key": "checkout-cn",
                "region": "cn-east",
                "brand": "Visa",
                "last4": "4242",
            }],
        )
        self.assertEqual(consumed.status_code, 409, consumed.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Mailbox)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(PoolImportReceipt)), 1)

    def test_first_import_requires_submission_key_bound_to_signed_receipt(self) -> None:
        receipt_id = str(uuid4())
        payload = [{
            "provider_ref": "provider-card-bound-key",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]

        rejected = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(receipt_id, f"spi:{uuid4()}"),
            json=payload,
        )

        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertEqual(self.verifier.calls, 1)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), 0)
            self.assertEqual(db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0)

    def test_import_rejects_secret_fields_and_unreceipted_first_write(self) -> None:
        payload = [{
            "provider_ref": "unsafe-card",
            "brand": "Visa",
            "last4": "4242",
            "secret_ref": "vault://secret/cards/caller-selected",
            "pan": "4111111111111111",
            "cvv": "123",
        }]
        rejected = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(str(uuid4()), "unsafe-import"),
            json=payload,
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertNotIn("4111111111111111", rejected.text)
        missing = self.request(
            "POST",
            "/api/v1/admin/mailboxes/imports",
            headers={
                "Authorization": self.authorization,
                "Idempotency-Key": "missing-receipt",
            },
            json=[{
                "email_masked": "m***@example.test",
                "connector_type": "http",
            }],
        )
        self.assertEqual(missing.status_code, 422, missing.text)

    def test_arbitrary_reference_side_doors_are_retired(self) -> None:
        card = self.request(
            "POST",
            "/api/v1/admin/cards",
            headers={"Authorization": self.authorization},
            json={"secret_ref": "vault://secret/cards/caller-selected"},
        )
        mailbox = self.request(
            "POST",
            "/api/v1/admin/mailboxes",
            headers={"Authorization": self.authorization},
            json={"secret_ref": "vault://secret/mailboxes/caller-selected"},
        )
        rotation = self.request(
            "POST",
            f"/api/v1/admin/mailboxes/{uuid4()}/secret-rotations",
            headers={"Authorization": self.authorization},
            json={"secret_ref": "vault://secret/mailboxes/caller-selected-v2"},
        )
        self.assertEqual(card.status_code, 410, card.text)
        self.assertEqual(mailbox.status_code, 410, mailbox.text)
        self.assertEqual(rotation.status_code, 410, rotation.text)

    def test_public_contract_exposes_only_secure_pool_import_writes(self) -> None:
        paths = self.app.openapi()["paths"]

        self.assertNotIn("post", paths["/api/v1/admin/cards"])
        self.assertNotIn("/api/v1/admin/mailboxes", paths)
        self.assertNotIn(
            "/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations",
            paths,
        )
        self.assertIn("post", paths["/api/v1/admin/cards/imports"])
        self.assertIn("post", paths["/api/v1/admin/mailboxes/imports"])


if __name__ == "__main__":
    unittest.main()
