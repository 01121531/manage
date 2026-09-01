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
from platform.models import (
    AuditEvent,
    Card,
    Mailbox,
    PoolImportContext,
    PoolImportReceipt,
)
from platform.pool_imports import VerifiedPoolImportReceipt, pool_import_digest
from platform.schemas import AdminCardImportItem


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

    def headers(
        self,
        receipt_id: str,
        key: str,
        context_token: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Authorization": self.authorization,
            "Idempotency-Key": key,
            "Secure-Import-Receipt": receipt_id,
        }
        if context_token is not None:
            headers["Secure-Import-Context"] = context_token
        return headers

    def import_headers(
        self,
        pool_type: str,
        payload: list[dict[str, object]],
        *,
        idempotency_key: str | None = None,
    ) -> tuple[str, dict[str, str]]:
        item_type = AdminCardImportItem if pool_type == "card" else None
        normalized = (
            [item_type.model_validate(item) for item in payload]
            if item_type is not None
            else payload
        )
        digest = pool_import_digest(pool_type, normalized)
        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": pool_type,
                "ordered_manifest_digest": digest,
                "item_count": len(payload),
            },
        )
        self.assertEqual(issued.status_code, 201, issued.text)
        context = issued.json()
        receipt_id = context["receipt_id"]
        return receipt_id, self.headers(
            receipt_id,
            idempotency_key or f"spi:{receipt_id}",
            context["context_token"],
        )

    def test_target_issues_authoritative_secret_free_import_context(self) -> None:
        payload = [{
            "provider_ref": "provider-context-1",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        digest = pool_import_digest(
            "card",
            [AdminCardImportItem.model_validate(item) for item in payload],
        )

        rejected_override = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": digest,
                "item_count": 1,
                "tenant_id": "tenant-b",
                "audience": "attacker-selected",
            },
        )
        self.assertEqual(rejected_override.status_code, 422, rejected_override.text)
        self.assertNotIn("tenant-b", rejected_override.text)
        self.assertNotIn("attacker-selected", rejected_override.text)

        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": digest,
                "item_count": 1,
            },
        )

        self.assertEqual(issued.status_code, 201, issued.text)
        context = issued.json()
        self.assertEqual(context["schema_version"], 1)
        self.assertEqual(context["tenant_id"], "tenant-a")
        self.assertEqual(
            context["audience"], "email-platform:pool-import:test"
        )
        self.assertEqual(context["pool_type"], "card")
        self.assertEqual(context["ordered_manifest_digest"], digest)
        self.assertEqual(context["item_count"], 1)
        self.assertRegex(context["receipt_id"], r"^[0-9a-f-]{36}$")
        self.assertRegex(context["context_token"], r"^[A-Za-z0-9_-]{43,128}$")
        with self.app.state.session_factory() as db:
            row = db.get(PoolImportContext, context["receipt_id"])
            assert row is not None
            self.assertEqual(row.tenant_id, "tenant-a")
            self.assertEqual(row.audience, "email-platform:pool-import:test")
            self.assertNotEqual(row.context_token_hash, context["context_token"])

    def test_card_import_derives_refs_and_replays_without_reverification(self) -> None:
        payload = [{
            "provider_ref": "provider-card-1",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        receipt_id, import_headers = self.import_headers("card", payload)
        first = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
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
            context = db.get(PoolImportContext, receipt_id)
            assert context is not None
            self.assertIsNotNone(context.consumed_at)
            self.assertEqual(context.pool_import_receipt_id, first_receipt["id"])
            audit_json = "\n".join(item.details_json for item in db.scalars(select(AuditEvent)))
            self.assertNotIn(receipt_id, audit_json)
            self.assertNotIn("vault://", audit_json)
            self.assertIn(first_receipt["ordered_manifest_digest"], audit_json)
            self.assertIn(first_receipt["secure_receipt_fingerprint"], audit_json)

    def test_mailbox_import_and_receipt_one_time_consumption(self) -> None:
        payload = [{
            "email_masked": "m***@example.test",
            "connector_type": "http",
            "task_type": "mail_code",
        }]
        receipt_id, import_headers = self.import_headers("mailbox", payload)
        first = self.request(
            "POST",
            "/api/v1/admin/mailboxes/imports",
            headers=import_headers,
            json=payload,
        )
        self.assertEqual(first.status_code, 201, first.text)
        consumed = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
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

    def test_mailbox_import_rejects_pseudo_masks_without_side_effects(self) -> None:
        with self.app.state.session_factory() as db:
            baseline_audits = db.scalar(select(func.count()).select_from(AuditEvent))

        for email_masked in (
            "alice@example.test*",
            "alice*@example.test",
            "ab***@example.test",
            "***@example.test",
            "a***@example.test/credential",
        ):
            receipt_id = str(uuid4())
            with self.subTest(email_masked=email_masked):
                rejected = self.request(
                    "POST",
                    "/api/v1/admin/mailboxes/imports",
                    headers=self.headers(receipt_id, f"spi:{receipt_id}"),
                    json=[{
                        "email_masked": email_masked,
                        "connector_type": "http",
                        "task_type": "mail_code",
                    }],
                )
                self.assertEqual(rejected.status_code, 422, rejected.text)
                self.assertNotIn(email_masked, rejected.text)

        self.assertEqual(self.verifier.calls, 0)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Mailbox)), 0)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(AuditEvent)), baseline_audits
            )

    def test_first_import_requires_submission_key_bound_to_signed_receipt(self) -> None:
        payload = [{
            "provider_ref": "provider-card-bound-key",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        receipt_id, import_headers = self.import_headers(
            "card", payload, idempotency_key=f"spi:{uuid4()}"
        )

        rejected = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
            json=payload,
        )

        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertEqual(self.verifier.calls, 1)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), 0)
            self.assertEqual(db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0)

    def test_first_import_requires_exact_target_context_without_side_effects(self) -> None:
        payload = [{
            "provider_ref": "provider-context-bound",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        receipt_id, import_headers = self.import_headers("card", payload)
        missing_headers = dict(import_headers)
        missing_headers.pop("Secure-Import-Context")

        missing = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=missing_headers,
            json=payload,
        )
        self.assertEqual(missing.status_code, 422, missing.text)

        changed_payload = [{**payload[0], "provider_ref": "provider-context-other"}]
        mismatched = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
            json=changed_payload,
        )
        self.assertEqual(mismatched.status_code, 409, mismatched.text)
        with self.app.state.session_factory() as db:
            context = db.get(PoolImportContext, receipt_id)
            assert context is not None
            self.assertIsNone(context.consumed_at)
            self.assertIsNone(context.pool_import_receipt_id)
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), 0)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0
            )

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
        self.assertIn("post", paths["/api/v1/admin/pool-import-contexts"])


if __name__ == "__main__":
    unittest.main()
