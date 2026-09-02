import asyncio
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
from sqlalchemy import event, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    Mailbox,
    PoolImportCardClaimMutation,
    PoolImportCardIdentityClaim,
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
        context_body: dict[str, object] = {
            "pool_type": pool_type,
            "ordered_manifest_digest": digest,
            "item_count": len(payload),
        }
        if pool_type == "card":
            context_body["card_provider_refs"] = [
                item.provider_ref for item in normalized
            ]
        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=context_body,
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
                "card_provider_refs": ["provider-context-1"],
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
                "card_provider_refs": ["provider-context-1"],
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

    def test_card_identity_claim_inserts_use_stable_provider_order(self) -> None:
        inserted_claims: list[tuple[int, str]] = []

        def capture_claim_insert(
            connection,
            cursor,
            statement,
            parameters,
            context,
            executemany,
        ) -> None:
            del connection, cursor, context
            if not statement.startswith(
                "INSERT INTO pool_import_card_identity_claims"
            ):
                return
            batches = parameters if executemany else [parameters]
            inserted_claims.extend(
                (int(batch[1]), str(batch[3])) for batch in batches
            )

        event.listen(
            self.app.state.engine,
            "before_cursor_execute",
            capture_claim_insert,
        )
        try:
            issued = self.request(
                "POST",
                "/api/v1/admin/pool-import-contexts",
                headers={"Authorization": self.authorization},
                json={
                    "pool_type": "card",
                    "ordered_manifest_digest": "9" * 64,
                    "item_count": 3,
                    "card_provider_refs": [
                        "provider-z-last",
                        "provider-a-first",
                        "provider-m-middle",
                    ],
                },
            )
        finally:
            event.remove(
                self.app.state.engine,
                "before_cursor_execute",
                capture_claim_insert,
            )

        self.assertEqual(issued.status_code, 201, issued.text)
        self.assertEqual(
            inserted_claims,
            [
                (1, "provider-a-first"),
                (2, "provider-m-middle"),
                (0, "provider-z-last"),
            ],
        )
        with self.app.state.session_factory() as db:
            stored_refs = list(db.scalars(
                select(PoolImportCardIdentityClaim.provider_ref)
                .where(
                    PoolImportCardIdentityClaim.context_id
                    == issued.json()["receipt_id"]
                )
                .order_by(PoolImportCardIdentityClaim.position)
            ))
        self.assertEqual(
            stored_refs,
            [
                "provider-z-last",
                "provider-a-first",
                "provider-m-middle",
            ],
        )

    def test_card_context_rejects_an_existing_identity_before_creation(self) -> None:
        payload = [{
            "provider_ref": "provider-already-present",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        normalized = [AdminCardImportItem.model_validate(item) for item in payload]
        with self.app.state.session_factory() as db:
            db.add(Card(
                tenant_id="tenant-a",
                provider_ref="provider-already-present",
                pool_key="checkout-cn",
                region="cn-east",
                brand="Visa",
                last4="4242",
                secret_ref="vault://secret/cards/imports/tenant/receipt/000",
                is_active=True,
            ))
            db.commit()

        rejected = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": pool_import_digest("card", normalized),
                "item_count": 1,
                "card_provider_refs": ["provider-already-present"],
            },
        )

        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertNotIn("provider-already-present", rejected.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportContext)), 0
            )

    def test_card_context_reserves_identity_against_a_second_context(self) -> None:
        payload = [{
            "provider_ref": "provider-reserved",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        digest = pool_import_digest(
            "card", [AdminCardImportItem.model_validate(item) for item in payload]
        )
        body = {
            "pool_type": "card",
            "ordered_manifest_digest": digest,
            "item_count": 1,
            "card_provider_refs": ["provider-reserved"],
        }

        first = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )
        second = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )

        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 409, second.text)
        self.assertNotIn("provider-reserved", second.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportContext)), 1
            )

    def test_mailbox_context_rejects_card_identity_fields(self) -> None:
        rejected = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "mailbox",
                "ordered_manifest_digest": "a" * 64,
                "item_count": 1,
                "card_provider_refs": ["provider-cross-pool"],
            },
        )

        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertNotIn("provider-cross-pool", rejected.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportContext)), 0
            )

    def test_card_context_requires_normalized_unique_count_bound_identities(self) -> None:
        cases = (
            {"item_count": 1},
            {
                "item_count": 2,
                "card_provider_refs": [" provider-duplicate ", "provider-duplicate"],
            },
            {
                "item_count": 2,
                "card_provider_refs": ["provider-count-mismatch"],
            },
            {
                "item_count": 1,
                "card_provider_refs": ["4111111111111111"],
            },
        )
        for extra in cases:
            with self.subTest(extra=extra):
                rejected = self.request(
                    "POST",
                    "/api/v1/admin/pool-import-contexts",
                    headers={"Authorization": self.authorization},
                    json={
                        "pool_type": "card",
                        "ordered_manifest_digest": "d" * 64,
                        **extra,
                    },
                )
                self.assertEqual(rejected.status_code, 422, rejected.text)
                self.assertNotIn("provider-duplicate", rejected.text)
                self.assertNotIn("4111111111111111", rejected.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportContext)), 0
            )

    def test_card_import_must_match_the_context_identity_claims(self) -> None:
        final_payload = [{
            "provider_ref": "provider-final-payload",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        digest = pool_import_digest(
            "card",
            [AdminCardImportItem.model_validate(item) for item in final_payload],
        )
        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": digest,
                "item_count": 1,
                "card_provider_refs": ["provider-preflight-other"],
            },
        )
        self.assertEqual(issued.status_code, 201, issued.text)
        context = issued.json()

        rejected = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(
                context["receipt_id"],
                f"spi:{context['receipt_id']}",
                context["context_token"],
            ),
            json=final_payload,
        )

        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertNotIn("provider-final-payload", rejected.text)
        self.assertNotIn("provider-preflight-other", rejected.text)
        self.assertEqual(self.verifier.calls, 1)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), 0)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0
            )
            stored = db.get(PoolImportContext, context["receipt_id"])
            assert stored is not None
            self.assertIsNone(stored.consumed_at)

    def test_expired_unconsumed_card_identity_claim_can_be_reclaimed(self) -> None:
        body = {
            "pool_type": "card",
            "ordered_manifest_digest": "b" * 64,
            "item_count": 1,
            "card_provider_refs": ["provider-expired-claim"],
        }
        first = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )
        self.assertEqual(first.status_code, 201, first.text)
        first_context = first.json()
        with self.app.state.session_factory() as db:
            stored = db.get(PoolImportContext, first_context["receipt_id"])
            assert stored is not None
            stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        claim_mutations: list[str] = []

        def capture_claim_mutation(
            connection,
            cursor,
            statement,
            parameters,
            context,
            executemany,
        ) -> None:
            del connection, cursor, parameters, context, executemany
            if statement.startswith((
                "DELETE FROM pool_import_card_identity_claims",
                "UPDATE pool_import_card_identity_claims",
            )):
                claim_mutations.append(statement)

        event.listen(
            self.app.state.engine,
            "before_cursor_execute",
            capture_claim_mutation,
        )
        try:
            replacement = self.request(
                "POST",
                "/api/v1/admin/pool-import-contexts",
                headers={"Authorization": self.authorization},
                json=body,
            )
        finally:
            event.remove(
                self.app.state.engine,
                "before_cursor_execute",
                capture_claim_mutation,
            )

        self.assertEqual(replacement.status_code, 201, replacement.text)
        self.assertFalse(
            any(statement.startswith("DELETE") for statement in claim_mutations),
            claim_mutations,
        )
        self.assertTrue(
            any(statement.startswith("UPDATE") for statement in claim_mutations),
            claim_mutations,
        )
        self.assertNotEqual(
            replacement.json()["receipt_id"], first_context["receipt_id"]
        )
        lost_renewal = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": first_context["context_token"],
            },
        )
        self.assertEqual(lost_renewal.status_code, 409, lost_renewal.text)
        with self.app.state.session_factory() as db:
            claims = list(db.scalars(select(PoolImportCardIdentityClaim)))
            self.assertEqual(len(claims), 1)
            self.assertEqual(
                claims[0].context_id, replacement.json()["receipt_id"]
            )

    def test_card_identity_claim_reclamation_is_tenant_scoped(self) -> None:
        other_admin = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-b",
            email="admin-b@example.test",
            password="admin-b-password",
            device_name="admin-b-device",
            role="platform_admin",
        )
        other_login = self.request("POST", "/api/v1/auth/login", json={
            "tenant_id": "tenant-b",
            "email": "admin-b@example.test",
            "password": "admin-b-password",
            "device_id": other_admin.device_id,
        })
        self.assertEqual(other_login.status_code, 200, other_login.text)
        other_authorization = f"Bearer {other_login.json()['access_token']}"
        body = {
            "pool_type": "card",
            "ordered_manifest_digest": "d" * 64,
            "item_count": 1,
            "card_provider_refs": ["provider-tenant-scoped-claim"],
        }
        first = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )
        self.assertEqual(first.status_code, 201, first.text)
        with self.app.state.session_factory() as db:
            stored = db.get(PoolImportContext, first.json()["receipt_id"])
            assert stored is not None
            stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        other = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": other_authorization},
            json=body,
        )
        self.assertEqual(other.status_code, 201, other.text)
        renewed = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": first.json()["context_token"],
            },
        )

        self.assertEqual(renewed.status_code, 200, renewed.text)
        with self.app.state.session_factory() as db:
            claims = list(db.scalars(
                select(PoolImportCardIdentityClaim).order_by(
                    PoolImportCardIdentityClaim.tenant_id
                )
            ))
            self.assertEqual(
                [(claim.tenant_id, claim.provider_ref) for claim in claims],
                [
                    ("tenant-a", "provider-tenant-scoped-claim"),
                    ("tenant-b", "provider-tenant-scoped-claim"),
                ],
            )

    def test_card_identity_claim_tenant_drift_fails_closed(self) -> None:
        import_payload = [{
            "provider_ref": "provider-tenant-drifted-claim",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        body = {
            "pool_type": "card",
            "ordered_manifest_digest": pool_import_digest(
                "card",
                [
                    AdminCardImportItem.model_validate(item)
                    for item in import_payload
                ],
            ),
            "item_count": 1,
            "card_provider_refs": ["provider-tenant-drifted-claim"],
        }
        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )
        self.assertEqual(issued.status_code, 201, issued.text)
        original = issued.json()
        with self.app.state.session_factory() as db:
            claim = db.scalar(select(PoolImportCardIdentityClaim).where(
                PoolImportCardIdentityClaim.context_id == original["receipt_id"]
            ))
            assert claim is not None
            claim.tenant_id = "tenant-b"
            db.commit()

        final_import = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(
                original["receipt_id"],
                f"spi:{original['receipt_id']}",
                original["context_token"],
            ),
            json=import_payload,
        )
        renewal = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": original["context_token"],
            },
        )
        with self.app.state.session_factory() as db:
            context = db.get(PoolImportContext, original["receipt_id"])
            assert context is not None
            context.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        replacement = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json=body,
        )

        self.assertEqual(final_import.status_code, 409, final_import.text)
        self.assertEqual(renewal.status_code, 409, renewal.text)
        self.assertEqual(replacement.status_code, 409, replacement.text)
        self.assertNotIn("provider-tenant-drifted-claim", replacement.text)
        with self.app.state.session_factory() as db:
            claim = db.scalar(select(PoolImportCardIdentityClaim))
            assert claim is not None
            self.assertEqual(claim.context_id, original["receipt_id"])
            self.assertEqual(claim.tenant_id, "tenant-b")
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportContext)),
                1,
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.event_type
                    == "admin.pool_import_card_identity_claims_reclaimed"
                )),
                0,
            )

    def test_card_identity_claim_reclamation_only_takes_requested_refs(self) -> None:
        original = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": "e" * 64,
                "item_count": 1,
                "card_provider_refs": ["provider-unrelated-renewal"],
            },
        )
        self.assertEqual(original.status_code, 201, original.text)
        with self.app.state.session_factory() as db:
            stored = db.get(PoolImportContext, original.json()["receipt_id"])
            assert stored is not None
            stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        unrelated = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": "f" * 64,
                "item_count": 1,
                "card_provider_refs": ["provider-new-unrelated-claim"],
            },
        )
        self.assertEqual(unrelated.status_code, 201, unrelated.text)
        renewed = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": original.json()["context_token"],
            },
        )

        self.assertEqual(renewed.status_code, 200, renewed.text)
        with self.app.state.session_factory() as db:
            refs = list(db.scalars(
                select(PoolImportCardIdentityClaim.provider_ref).order_by(
                    PoolImportCardIdentityClaim.provider_ref
                )
            ))
            self.assertEqual(refs, [
                "provider-new-unrelated-claim",
                "provider-unrelated-renewal",
            ])

    def test_card_identity_claim_reclamation_is_explicitly_audited(self) -> None:
        original = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": "1" * 64,
                "item_count": 1,
                "card_provider_refs": ["provider-audited-reclamation"],
            },
        )
        self.assertEqual(original.status_code, 201, original.text)
        original_context = original.json()
        with self.app.state.session_factory() as db:
            stored = db.get(PoolImportContext, original_context["receipt_id"])
            assert stored is not None
            stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()

        locked_statements = []
        session_scalars = Session.scalars

        def capture_locked_statement(session, statement, *args, **kwargs):
            if getattr(statement, "_for_update_arg", None) is not None:
                locked_statements.append(statement)
            return session_scalars(session, statement, *args, **kwargs)

        with patch.object(Session, "scalars", new=capture_locked_statement):
            replacement = self.request(
                "POST",
                "/api/v1/admin/pool-import-contexts",
                headers={"Authorization": self.authorization},
                json={
                    "pool_type": "card",
                    "ordered_manifest_digest": "2" * 64,
                    "item_count": 1,
                    "card_provider_refs": ["provider-audited-reclamation"],
                },
            )

        self.assertEqual(replacement.status_code, 201, replacement.text)
        locked_sql = [
            " ".join(str(statement.compile(
                dialect=postgresql.dialect(),
            )).split())
            for statement in locked_statements
        ]
        self.assertTrue(any(
            "FOR UPDATE OF pool_import_contexts" in sql
            for sql in locked_sql
        ))
        self.assertTrue(any(
            sql.startswith("SELECT pool_import_contexts.id")
            and "ORDER BY pool_import_contexts.id "
                "FOR UPDATE OF pool_import_contexts" in sql
            for sql in locked_sql
        ))
        with self.app.state.session_factory() as db:
            audits = list(db.scalars(select(AuditEvent).where(
                AuditEvent.event_type
                == "admin.pool_import_card_identity_claims_reclaimed"
            )))
            self.assertEqual(len(audits), 1)
            audit = audits[0]
            self.assertEqual(audit.entity_type, "card_pool")
            self.assertEqual(audit.entity_id, replacement.json()["receipt_id"])
            self.assertIn('"reclaimed_claim_count": 1', audit.details_json)
            self.assertIn('"reclaimed_context_count": 1', audit.details_json)
            self.assertIn(
                hashlib.sha256(
                    original_context["receipt_id"].encode("ascii")
                ).hexdigest(),
                audit.details_json,
            )
            self.assertNotIn(
                "provider-audited-reclamation",
                audit.details_json,
            )
            self.assertNotIn(original_context["context_token"], audit.details_json)
            mutations = list(db.scalars(select(PoolImportCardClaimMutation)))
            self.assertEqual(len(mutations), 1)
            mutation = mutations[0]
            self.assertEqual(mutation.tenant_id, "tenant-a")
            self.assertEqual(
                mutation.source_context_id,
                original_context["receipt_id"],
            )
            self.assertEqual(
                mutation.destination_context_id,
                replacement.json()["receipt_id"],
            )
            self.assertEqual(
                mutation.destination_trace_id,
                replacement.headers["X-Trace-Id"],
            )

    def test_consumed_card_identity_claim_is_not_reclaimed(self) -> None:
        payload = [{
            "provider_ref": "provider-consumed-claim",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        _, import_headers = self.import_headers("card", payload)
        imported = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
            json=payload,
        )
        self.assertEqual(imported.status_code, 201, imported.text)
        rejected = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "card",
                "ordered_manifest_digest": "c" * 64,
                "item_count": 1,
                "card_provider_refs": ["provider-consumed-claim"],
            },
        )

        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertNotIn("provider-consumed-claim", rejected.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(PoolImportCardIdentityClaim)
                ),
                1,
            )

    def test_expired_context_can_be_idempotently_renewed_within_bounded_window(self) -> None:
        digest = "a" * 64
        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "mailbox",
                "ordered_manifest_digest": digest,
                "item_count": 1,
            },
        )
        self.assertEqual(issued.status_code, 201, issued.text)
        original = issued.json()
        with self.app.state.session_factory() as db:
            row = db.get(PoolImportContext, original["receipt_id"])
            assert row is not None
            original_hash = row.context_token_hash
            row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.commit()

        renewed = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": original["context_token"],
            },
        )

        self.assertEqual(renewed.status_code, 200, renewed.text)
        replacement = renewed.json()
        self.assertEqual(replacement["context_token"], original["context_token"])
        self.assertEqual(replacement["receipt_id"], original["receipt_id"])
        self.assertEqual(replacement["ordered_manifest_digest"], digest)
        renewed_expiry = datetime.fromisoformat(replacement["expires_at"])
        if renewed_expiry.tzinfo is None:
            renewed_expiry = renewed_expiry.replace(tzinfo=timezone.utc)
        self.assertGreater(renewed_expiry, datetime.now(timezone.utc))
        retried = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": original["context_token"],
            },
        )
        self.assertEqual(retried.status_code, 200, retried.text)
        self.assertEqual(retried.json()["context_token"], original["context_token"])
        self.assertEqual(retried.json()["receipt_id"], original["receipt_id"])
        with self.app.state.session_factory() as db:
            row = db.get(PoolImportContext, original["receipt_id"])
            assert row is not None
            self.assertEqual(row.context_token_hash, original_hash)
            renew_audits = list(db.scalars(select(AuditEvent).where(
                AuditEvent.event_type == "admin.pool_import_context_renewed"
            )))
            self.assertEqual(len(renew_audits), 2)
            self.assertTrue(all(
                original["context_token"] not in audit.details_json
                for audit in renew_audits
            ))

    def test_context_renewal_rejects_consumed_or_out_of_window_context(self) -> None:
        payload = [{
            "provider_ref": "provider-renew-consumed",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "last4": "4242",
        }]
        receipt_id, import_headers = self.import_headers("card", payload)
        consumed = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=import_headers,
            json=payload,
        )
        self.assertEqual(consumed.status_code, 201, consumed.text)
        consumed_renewal = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts/renew",
            headers={
                "Authorization": self.authorization,
                "Secure-Import-Context": import_headers["Secure-Import-Context"],
            },
        )
        self.assertEqual(consumed_renewal.status_code, 409, consumed_renewal.text)

        issued = self.request(
            "POST",
            "/api/v1/admin/pool-import-contexts",
            headers={"Authorization": self.authorization},
            json={
                "pool_type": "mailbox",
                "ordered_manifest_digest": "b" * 64,
                "item_count": 1,
            },
        )
        self.assertEqual(issued.status_code, 201, issued.text)
        context = issued.json()
        with self.app.state.session_factory() as db:
            row = db.get(PoolImportContext, context["receipt_id"])
            assert row is not None
            created_at = row.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            out_of_window_now = created_at + timedelta(
                seconds=(
                    self.app.state.settings
                    .pool_import_context_renewal_window_seconds
                    + 1
                )
            )
            row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()
        with patch(
            "platform.api.v1.routes._utc_now",
            return_value=out_of_window_now,
        ):
            out_of_window = self.request(
                "POST",
                "/api/v1/admin/pool-import-contexts/renew",
                headers={
                    "Authorization": self.authorization,
                    "Secure-Import-Context": context["context_token"],
                },
            )
        self.assertEqual(out_of_window.status_code, 410, out_of_window.text)

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

    def test_duplicate_card_provider_refs_fail_before_receipt_verification(self) -> None:
        receipt_id = str(uuid4())
        payload = [
            {
                "provider_ref": "provider-duplicate",
                "pool_key": "checkout-cn",
                "region": "cn-east",
                "brand": "Visa",
                "last4": "4242",
            },
            {
                "provider_ref": "provider-duplicate",
                "pool_key": "checkout-us",
                "region": "us-east",
                "brand": "Mastercard",
                "last4": "4444",
            },
        ]

        rejected = self.request(
            "POST",
            "/api/v1/admin/cards/imports",
            headers=self.headers(receipt_id, f"spi:{receipt_id}"),
            json=payload,
        )

        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertNotIn("provider-duplicate", rejected.text)
        self.assertEqual(self.verifier.calls, 0)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Card)), 0)
            self.assertEqual(
                db.scalar(select(func.count()).select_from(PoolImportReceipt)), 0
            )

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
        self.assertIn("post", paths["/api/v1/admin/pool-import-contexts/renew"])


if __name__ == "__main__":
    unittest.main()
