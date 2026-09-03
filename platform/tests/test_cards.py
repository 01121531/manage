import asyncio
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier, Event, Lock
from unittest import mock

import httpx
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from platform.api.v1 import routes
from platform.app import create_app
from platform.auth import AuthPrincipal, get_operator_principal
from platform.bootstrap import create_user_with_device
from platform.cards import CardSecret, CardSecretUnavailable, SecretCardSecretResolver
from platform.config import Settings
from platform.lifecycle import sweep_expired_lifecycle
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    CardAllocationReplacement,
    CardEvent,
    CardRevealChallenge,
    Device,
    Mailbox,
    MailSession,
    OperationalPolicyDeployment,
    OperationalPolicyVersion,
    OutboxEvent,
    Task,
    UploadJob,
    User,
    utc_now,
)


class MixedStepUpVerifier:
    def __init__(
        self,
        *,
        main_token: str,
        user_id: str,
        oidc_subject: str,
        tenant_id: str,
        device_id: str,
        acr: str = "urn:email-platform:acr:mfa",
        auth_time_offset_seconds: int = 0,
    ) -> None:
        now = utc_now() + timedelta(seconds=auth_time_offset_seconds)
        self.claims = {
            main_token: {
                "sub": user_id,
                "tenant_id": tenant_id,
                "device_id": device_id,
                "identity_kind": "local",
                "auth_time": int(now.timestamp()),
                "acr": "urn:email-platform:acr:password",
                "amr": ["pwd"],
            },
            "step-up-token": {
                "sub": oidc_subject,
                "tenant_id": tenant_id,
                "device_id": device_id,
                "identity_kind": "oidc",
                "auth_time": int(now.timestamp()),
                "acr": acr,
                "amr": ["pwd", "otp"],
            },
        }

    def verify(self, token: str) -> dict[str, object]:
        try:
            return self.claims[token]
        except KeyError as error:
            raise ValueError("invalid token") from error


class FakeCardSecretResolver:
    def __init__(self) -> None:
        self.secret_refs: list[str] = []

    def resolve(self, secret_ref: str) -> CardSecret:
        self.secret_refs.append(secret_ref)
        return CardSecret(pan="4111111111111111")


class StaticSecretResolver:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value

    def resolve(self, _secret_ref: str) -> dict[str, object]:
        return self.value


class CardSecretBoundaryTests(unittest.TestCase):
    def test_security_code_aliases_fail_closed_without_retaining_values(self) -> None:
        aliases = (
            "cvv",
            "cvc",
            "cid",
            "security_code",
            "card_verification_value",
        )
        for alias in (*aliases, *(alias.upper() for alias in aliases)):
            with self.subTest(alias=alias):
                marker = "731"
                resolver = SecretCardSecretResolver(
                    StaticSecretResolver({
                        "pan": "4242 4242 4242 4242", alias: marker,
                    })
                )
                with self.assertRaises(CardSecretUnavailable) as raised:
                    resolver.resolve("vault://secret/cards/test-card")

                serialized_error = (
                    f"{raised.exception!r} {raised.exception.__dict__!r}"
                )
                self.assertNotIn(marker, serialized_error)

    def test_pan_resolution_ignores_expiry_metadata_and_has_no_security_code_field(
        self,
    ) -> None:
        resolver = SecretCardSecretResolver(
            StaticSecretResolver(
                {
                    "pan": "4242 4242-4242 4242",
                    "expiry_month": 12,
                    "expiry_year": 2030,
                }
            )
        )

        secret = resolver.resolve("vault://secret/cards/test-card")

        self.assertEqual(secret.pan, "4242424242424242")
        self.assertFalse(hasattr(secret, "cvv"))
        self.assertNotIn(secret.pan, repr(secret))


class CardAllocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.card_secret_resolver = FakeCardSecretResolver()
        self.app = create_app(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="card-test-hmac-secret-that-is-not-production",
                card_lease_ttl_seconds=600,
                card_reveal_ttl_seconds=45,
            ),
            card_secret_resolver=self.card_secret_resolver,
        )
        self.password = "card-owner-account-password"
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-card",
            email="card-owner@example.test",
            password=self.password,
            device_name="card-device",
        )
        with self.app.state.session_factory() as db:
            db.add(
                Card(
                    tenant_id="tenant-card",
                    provider_ref="provider-card-1",
                    brand="VISA",
                    last4="1111",
                    expiry_month=12,
                    expiry_year=2030,
                    secret_ref="vault://cards/card-1",
                )
            )
            db.commit()

    def tearDown(self) -> None:
        self.app.state.engine.dispose()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def login(self) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-card",
                "email": "card-owner@example.test",
                "password": self.password,
                "device_id": self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def create_task(self, token: str, key: str) -> str:
        response = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "card_checkout", "idempotency_key": key},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def grant_with_step_up(
        self,
        token: str,
        allocation_id: str,
        *,
        acr: str = "urn:email-platform:acr:mfa",
        auth_time_offset_seconds: int = 0,
    ) -> tuple[httpx.Response, httpx.Response]:
        challenge = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-challenges",
            headers=self.bearer(token),
        )
        self.assertEqual(challenge.status_code, 201, challenge.text)
        oidc_subject = "oidc-card-owner"
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            self.assertIsNotNone(user)
            user.oidc_subject = oidc_subject
            db.commit()
        self.app.state.access_token_verifier = MixedStepUpVerifier(
            main_token=token,
            user_id=self.identity.user_id,
            oidc_subject=oidc_subject,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            acr=acr,
            auth_time_offset_seconds=auth_time_offset_seconds,
        )
        grant = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-grants",
            headers=self.bearer("step-up-token"),
            json={"challenge_id": challenge.json()["challenge_id"]},
        )
        return challenge, grant

    def reveal_with_step_up(
        self,
        token: str,
        allocation_id: str,
        *,
        acr: str = "urn:email-platform:acr:mfa",
        auth_time_offset_seconds: int = 0,
        fields: tuple[str, ...] = ("pan", "expiry"),
    ) -> tuple[httpx.Response, httpx.Response, httpx.Response]:
        challenge, grant = self.grant_with_step_up(
            token,
            allocation_id,
            acr=acr,
            auth_time_offset_seconds=auth_time_offset_seconds,
        )
        if grant.status_code != 200:
            return challenge, grant, grant
        revealed = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=self.bearer(token),
            json={
                "reveal_grant": grant.json()["reveal_grant"],
                "fields": list(fields),
            },
        )
        return challenge, grant, revealed

    def test_allocation_is_masked_owner_bound_and_idempotent(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-task-1")
        first = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(
            set(first.json()),
            {
                "id",
                "trace_id",
                "card_masked",
                "brand",
                "expiry_month",
                "expiry_year",
                "status",
                "expires_at",
                "allocation_reason_code",
            },
        )
        self.assertEqual(first.json()["allocation_reason_code"], "task_assigned")
        task = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(token)
        )
        self.assertEqual(first.json()["trace_id"], task.json()["trace_id"])
        self.assertEqual(first.json()["card_masked"], "VISA •••• 1111")
        for forbidden in ("vault://", "secret_ref", "password", "pan", "cvv"):
            self.assertNotIn(forbidden, first.text.lower())

        replay = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["id"], first.json()["id"])

        with self.app.state.session_factory() as db:
            persisted = db.get(CardAllocation, first.json()["id"])
            events = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "card.allocated")))
        self.assertEqual(persisted.allocation_reason_code, "task_assigned")
        self.assertEqual(len(events), 1)
        self.assertEqual(
            json.loads(events[0].details_json)["allocation_reason_code"],
            "task_assigned",
        )
        self.assertNotIn("vault://cards/card-1", events[0].details_json)

    def test_allocation_read_never_dereferences_card_after_tenant_relation_changes(
        self,
    ) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-tenant-relation-barrier")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)

        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocated.json()["id"])
            self.assertIsNotNone(allocation)
            card = db.get(Card, allocation.card_id)
            self.assertIsNotNone(card)
            card.tenant_id = "tenant-card-foreign"
            card.last4 = "9876"
            card.secret_ref = "vault://cards/foreign-tenant-secret"
            db.commit()

        response = self.request(
            "GET",
            f"/api/v1/card-allocations/{allocated.json()['id']}?task_id={task_id}",
            headers=self.bearer(token),
        )

        self.assertEqual(response.status_code, 404, response.text)
        self.assertNotIn("9876", response.text)
        self.assertNotIn("foreign-tenant-secret", response.text)
        self.assertEqual(self.card_secret_resolver.secret_refs, [])

        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        self.assertEqual(timeline.json()["card_allocations"], [])
        self.assertNotIn("9876", timeline.text)

    def test_deployed_card_policy_is_frozen_on_allocation_and_reveal(self) -> None:
        with self.app.state.session_factory() as db:
            policy = OperationalPolicyVersion(
                tenant_id="tenant-card",
                domain="card",
                version="card-runtime-v1",
                status="active",
                change_note="runtime proof",
                lease_ttl_seconds=777,
                reveal_ttl_seconds=119,
                allocation_order="oldest_available",
                selection_rules_json=json.dumps(
                    [
                        {
                            "task_type": "card_checkout",
                            "pool_key": "legacy-unclassified",
                            "region": "legacy-unclassified",
                            "brands": [],
                            "minimum_validity_days": 0,
                            "allocation_order": "oldest_available",
                        }
                    ]
                ),
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add(policy)
            db.flush()
            db.add(
                OperationalPolicyDeployment(
                    tenant_id="tenant-card",
                    domain="card",
                    active_policy_id=policy.id,
                    rollout_percent=100,
                    updated_by=self.identity.user_id,
                )
            )
            db.commit()

        token = self.login()
        task_id = self.create_task(token, "card-policy-runtime")
        created_at = utc_now()
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)
        allocation_id = allocated.json()["id"]
        with self.app.state.session_factory() as db:
            persisted = db.get(CardAllocation, allocation_id)
            self.assertEqual(persisted.policy_version, "card-runtime-v1")
            self.assertEqual(persisted.reveal_ttl_seconds, 119)
            comparable_created_at = created_at.replace(
                tzinfo=persisted.expires_at.tzinfo
            )
            self.assertGreaterEqual(
                (persisted.expires_at - comparable_created_at).total_seconds(), 775
            )

        _, grant, revealed = self.reveal_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        self.assertEqual(revealed.status_code, 200, revealed.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(CardAllocation, allocation_id)
            self.assertIsNotNone(persisted.revealed_at)
            self.assertIsNotNone(persisted.reveal_expires_at)
            self.assertGreaterEqual(
                (persisted.reveal_expires_at - persisted.revealed_at).total_seconds(),
                118,
            )

    def test_card_policy_selects_only_exact_pool_region_brand_and_validity(self) -> None:
        selection_rules = [
            {
                "task_type": "card_checkout",
                "pool_key": "checkout-cn",
                "region": "cn-east",
                "brands": ["VISA"],
                "minimum_validity_days": 720,
                "allocation_order": "expiry_soonest",
            }
        ]
        with self.app.state.session_factory() as db:
            policy = OperationalPolicyVersion(
                tenant_id="tenant-card",
                domain="card",
                version="card-selector-v1",
                status="active",
                change_note="exact selector proof",
                lease_ttl_seconds=600,
                reveal_ttl_seconds=45,
                allocation_order="oldest_available",
                selection_rules_json=json.dumps(selection_rules),
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add(policy)
            db.flush()
            db.add(
                OperationalPolicyDeployment(
                    tenant_id="tenant-card",
                    domain="card",
                    active_policy_id=policy.id,
                    rollout_percent=100,
                    updated_by=self.identity.user_id,
                )
            )
            db.add_all(
                [
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="wrong-pool",
                        pool_key="other-pool",
                        region="cn-east",
                        brand="VISA",
                        last4="2001",
                        expiry_month=1,
                        expiry_year=2032,
                        secret_ref="vault://cards/wrong-pool",
                    ),
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="wrong-region",
                        pool_key="checkout-cn",
                        region="eu-west",
                        brand="VISA",
                        last4="2002",
                        expiry_month=1,
                        expiry_year=2032,
                        secret_ref="vault://cards/wrong-region",
                    ),
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="wrong-brand",
                        pool_key="checkout-cn",
                        region="cn-east",
                        brand="MASTERCARD",
                        last4="2003",
                        expiry_month=1,
                        expiry_year=2032,
                        secret_ref="vault://cards/wrong-brand",
                    ),
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="too-short-validity",
                        pool_key="checkout-cn",
                        region="cn-east",
                        brand="VISA",
                        last4="2004",
                        expiry_month=1,
                        expiry_year=2027,
                        secret_ref="vault://cards/too-short-validity",
                    ),
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="exact-match",
                        pool_key="checkout-cn",
                        region="cn-east",
                        brand="VISA",
                        last4="2999",
                        expiry_month=3,
                        expiry_year=2031,
                        secret_ref="vault://cards/exact-match",
                    ),
                ]
            )
            db.commit()

        token = self.login()
        task_id = self.create_task(token, "card-selector-exact")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)
        self.assertEqual(allocated.json()["card_masked"], "VISA •••• 2999")
        with self.app.state.session_factory() as db:
            stored = db.get(CardAllocation, allocated.json()["id"])
        self.assertEqual(stored.policy_version, "card-selector-v1")
        self.assertEqual(json.loads(stored.selection_rule_json), selection_rules[0])

    def test_card_policy_without_exact_match_fails_closed(self) -> None:
        with self.app.state.session_factory() as db:
            card = db.scalar(select(Card).where(Card.tenant_id == "tenant-card"))
            card.pool_key = "default"
            card.region = "global"
            policy = OperationalPolicyVersion(
                tenant_id="tenant-card",
                domain="card",
                version="card-selector-no-match",
                status="active",
                change_note="no fallback proof",
                lease_ttl_seconds=600,
                reveal_ttl_seconds=45,
                allocation_order="oldest_available",
                selection_rules_json=json.dumps(
                    [
                        {
                            "task_type": "card_checkout",
                            "pool_key": "restricted",
                            "region": "cn-east",
                            "brands": ["VISA"],
                            "minimum_validity_days": 0,
                            "allocation_order": "oldest_available",
                        }
                    ]
                ),
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add(policy)
            db.flush()
            db.add(
                OperationalPolicyDeployment(
                    tenant_id="tenant-card",
                    domain="card",
                    active_policy_id=policy.id,
                    rollout_percent=100,
                    updated_by=self.identity.user_id,
                )
            )
            db.commit()

        token = self.login()
        task_id = self.create_task(token, "card-selector-no-match")
        blocked = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(blocked.status_code, 503, blocked.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(select(CardAllocation).where(CardAllocation.task_id == task_id))
            )

    def test_task_type_without_server_card_rule_fails_closed(self) -> None:
        token = self.login()
        created = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "no-card-rule"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        blocked = self.request(
            "POST",
            f"/api/v1/tasks/{created.json()['id']}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(blocked.status_code, 503, blocked.text)
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(
                    select(CardAllocation).where(
                        CardAllocation.task_id == created.json()["id"]
                    )
                )
            )
            allocated_events = list(
                db.scalars(
                    select(AuditEvent).where(AuditEvent.event_type == "card.allocated")
                )
            )
        self.assertEqual(allocated_events, [])

    def test_quarantine_marker_blocks_stale_allocation_fast_path_and_reveal(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-quarantine-residue")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)

        with self.app.state.session_factory() as db:
            card = db.scalar(select(Card).where(Card.tenant_id == "tenant-card"))
            card.is_active = False
            card.quarantined_at = utc_now()
            card.quarantine_reason_code = "suspected_compromise"
            db.commit()

        retried = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(retried.status_code, 503, retried.text)

        challenge = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocated.json()['id']}/reveal-challenges",
            headers=self.bearer(token),
        )
        self.assertEqual(challenge.status_code, 409, challenge.text)
        self.assertEqual(self.card_secret_resolver.secret_refs, [])

    def test_card_cannot_be_double_leased_and_release_makes_it_available(self) -> None:
        token = self.login()
        first_task = self.create_task(token, "card-task-2")
        first = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 201)
        second_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-card",
            email="card-contender@example.test",
            password="card-contender-password",
            device_name="card-contender-device",
        )
        second_login = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-card",
                "email": "card-contender@example.test",
                "password": "card-contender-password",
                "device_id": second_identity.device_id,
            },
        )
        self.assertEqual(second_login.status_code, 200, second_login.text)
        second_token = second_login.json()["access_token"]
        second_task = self.create_task(second_token, "card-task-3")
        unavailable = self.request(
            "POST",
            f"/api/v1/tasks/{second_task}/card-allocations",
            headers=self.bearer(second_token),
        )
        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(unavailable.json()["error"]["code"], "service_unavailable")

        released = self.request(
            "POST",
            f"/api/v1/card-allocations/{first.json()['id']}/release",
            headers=self.bearer(token),
        )
        self.assertEqual(released.status_code, 200)
        self.assertEqual(released.json()["status"], "released")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{second_task}/card-allocations",
            headers=self.bearer(second_token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)

    def test_replace_card_is_transactional_masked_and_idempotent(self) -> None:
        with self.app.state.session_factory() as db:
            db.add(
                Card(
                    tenant_id="tenant-card",
                    provider_ref="provider-card-2",
                    brand="MASTERCARD",
                    last4="2222",
                    expiry_month=11,
                    expiry_year=2031,
                    secret_ref="vault://cards/card-2",
                )
            )
            db.commit()

        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-replacement")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(original.status_code, 201, original.text)

        replaced = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
            headers=headers,
        )
        self.assertEqual(replaced.status_code, 201, replaced.text)
        self.assertNotEqual(replaced.json()["id"], original.json()["id"])
        self.assertNotEqual(replaced.json()["card_masked"], original.json()["card_masked"])
        self.assertIn(
            replaced.json()["card_masked"],
            {"VISA •••• 1111", "MASTERCARD •••• 2222"},
        )
        self.assertEqual(replaced.json()["allocation_reason_code"], "replacement")
        self.assertNotIn("vault://", replaced.text)

        replay = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
            headers=headers,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], replaced.json()["id"])

        with self.app.state.session_factory() as db:
            original_row = db.get(CardAllocation, original.json()["id"])
            replacement_row = db.get(CardAllocation, replaced.json()["id"])
            replacement_link = db.get(
                CardAllocationReplacement, original.json()["id"]
            )
            active = list(
                db.scalars(
                    select(CardAllocation).where(
                        CardAllocation.task_id == task_id,
                        CardAllocation.released_at.is_(None),
                    )
                )
            )
            audits = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id.in_(
                            [original_row.id, replacement_row.id]
                        ),
                        AuditEvent.event_type.in_(
                            ["card.released", "card.allocated"]
                        ),
                    )
                    .order_by(AuditEvent.created_at, AuditEvent.id)
                )
            )
            card_events = list(
                db.scalars(
                    select(CardEvent)
                    .where(
                        CardEvent.allocation_id.in_(
                            [original_row.id, replacement_row.id]
                        ),
                        CardEvent.reason_code == "replacement",
                    )
                    .order_by(CardEvent.created_at, CardEvent.id)
                )
            )

        self.assertEqual(original_row.status, "released")
        self.assertEqual(original_row.release_reason_code, "replacement")
        self.assertEqual(
            replacement_link.replacement_allocation_id, replacement_row.id
        )
        self.assertEqual(replacement_link.tenant_id, "tenant-card")
        self.assertEqual(replacement_link.task_id, task_id)
        self.assertEqual(replacement_row.allocation_reason_code, "replacement")
        self.assertEqual([row.id for row in active], [replacement_row.id])
        replacement_audits = [
            (event.entity_id, event.event_type)
            for event in audits
            if (event.entity_id, event.event_type)
            != (original_row.id, "card.allocated")
        ]
        self.assertCountEqual(
            replacement_audits,
            [
                (original_row.id, "card.released"),
                (replacement_row.id, "card.allocated"),
            ],
        )
        self.assertCountEqual(
            [event.action for event in card_events],
            ["allocation.released", "allocation.allocated"],
        )

    def test_replacement_replay_rechecks_operator_after_rollback(self) -> None:
        with self.app.state.session_factory() as db:
            db.add(
                Card(
                    tenant_id="tenant-card",
                    provider_ref="provider-card-stale-replay",
                    brand="MASTERCARD",
                    last4="2222",
                    expiry_month=11,
                    expiry_year=2031,
                    secret_ref="vault://cards/stale-replay",
                )
            )
            db.commit()

        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-replacement-stale-replay")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        replaced = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
            headers=headers,
        )
        self.assertEqual(replaced.status_code, 201, replaced.text)
        now = utc_now()
        captured_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            email="card-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=now,
            acr=None,
            amr=(),
            access_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            access_token_expires_at=now + timedelta(minutes=15),
            access_token_revoked=False,
        )
        original_lookup = routes._card_replacement_for
        role_changed = False

        def change_role_after_replay_found(db, allocation, principal):
            nonlocal role_changed
            replay = original_lookup(db, allocation, principal)
            if replay is not None and not role_changed:
                db.get(User, self.identity.user_id).role = "ops_admin"
                db.commit()
                role_changed = True
            return replay

        self.app.dependency_overrides[get_operator_principal] = (
            lambda: captured_principal
        )
        try:
            with mock.patch.object(
                routes,
                "_card_replacement_for",
                side_effect=change_role_after_replay_found,
            ):
                replay = self.request(
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
                    headers=headers,
                )
        finally:
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertTrue(role_changed)
        self.assertEqual(replay.status_code, 403, replay.text)
        for sensitive in (
            replaced.json()["card_masked"],
            str(replaced.json()["expiry_year"]),
            replaced.json()["trace_id"],
        ):
            self.assertNotIn(sensitive, replay.text)

    def test_card_mutations_recheck_operator_before_tenant_compensation(self) -> None:
        token = self.login()
        replacement_task_id = self.create_task(token, "card-preflight-replacement")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{replacement_task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(original.status_code, 201, original.text)
        now = utc_now()
        captured_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            email="card-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=now,
            acr=None,
            amr=(),
            access_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            access_token_expires_at=now + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            db.get(User, self.identity.user_id).role = "security_auditor"
            db.commit()

        self.app.dependency_overrides[get_operator_principal] = (
            lambda: captured_principal
        )
        try:
            with mock.patch.object(
                routes,
                "_compensate_expired_card_leases",
            ) as compensate:
                allocation = self.request(
                    "POST",
                    f"/api/v1/tasks/{replacement_task_id}/card-allocations",
                )
                replacement = self.request(
                    "POST",
                    f"/api/v1/tasks/{replacement_task_id}/card-allocations/"
                    f"{original.json()['id']}/replace",
                )
        finally:
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertEqual(allocation.status_code, 403, allocation.text)
        self.assertEqual(replacement.status_code, 403, replacement.text)
        compensate.assert_not_called()

    def test_replacement_reuses_original_frozen_selection_rule(self) -> None:
        legacy_rule = {
            "task_type": "card_checkout",
            "pool_key": "legacy-unclassified",
            "region": "legacy-unclassified",
            "brands": [],
            "minimum_validity_days": 0,
            "allocation_order": "oldest_available",
        }
        with self.app.state.session_factory() as db:
            v1 = OperationalPolicyVersion(
                tenant_id="tenant-card",
                domain="card",
                version="selector-v1",
                status="active",
                change_note="original selector",
                lease_ttl_seconds=777,
                reveal_ttl_seconds=119,
                allocation_order="oldest_available",
                selection_rules_json=json.dumps([legacy_rule]),
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add(v1)
            db.flush()
            deployment = OperationalPolicyDeployment(
                tenant_id="tenant-card",
                domain="card",
                active_policy_id=v1.id,
                rollout_percent=100,
                updated_by=self.identity.user_id,
            )
            db.add(deployment)
            db.commit()

        token = self.login()
        task_id = self.create_task(token, "frozen-selector-replacement")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(original.status_code, 201, original.text)

        with self.app.state.session_factory() as db:
            db.add_all(
                [
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="frozen-rule-match",
                        brand="VISA",
                        last4="3111",
                        expiry_month=12,
                        expiry_year=2032,
                        secret_ref="vault://cards/frozen-rule-match",
                    ),
                    Card(
                        tenant_id="tenant-card",
                        provider_ref="new-policy-only",
                        pool_key="new-pool",
                        region="cn-east",
                        brand="VISA",
                        last4="3222",
                        expiry_month=12,
                        expiry_year=2032,
                        secret_ref="vault://cards/new-policy-only",
                    ),
                ]
            )
            v2 = OperationalPolicyVersion(
                tenant_id="tenant-card",
                domain="card",
                version="selector-v2",
                status="active",
                change_note="new selector must not affect replacement",
                lease_ttl_seconds=60,
                reveal_ttl_seconds=30,
                allocation_order="oldest_available",
                selection_rules_json=json.dumps(
                    [{**legacy_rule, "pool_key": "new-pool", "region": "cn-east"}]
                ),
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add(v2)
            db.flush()
            deployment = db.scalar(
                select(OperationalPolicyDeployment).where(
                    OperationalPolicyDeployment.tenant_id == "tenant-card",
                    OperationalPolicyDeployment.domain == "card",
                )
            )
            deployment.active_policy_id = v2.id
            db.commit()

        replaced = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
            headers=self.bearer(token),
        )
        self.assertEqual(replaced.status_code, 201, replaced.text)
        self.assertEqual(replaced.json()["card_masked"], "VISA •••• 3111")
        with self.app.state.session_factory() as db:
            original_row = db.get(CardAllocation, original.json()["id"])
            replacement_row = db.get(CardAllocation, replaced.json()["id"])
        self.assertEqual(replacement_row.policy_version, "selector-v1")
        self.assertEqual(replacement_row.reveal_ttl_seconds, 119)
        self.assertEqual(
            replacement_row.selection_rule_json, original_row.selection_rule_json
        )

    def test_replace_card_without_an_alternative_preserves_original_lease(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-replacement-unavailable")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(original.status_code, 201, original.text)

        blocked = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
            headers=headers,
        )
        self.assertEqual(blocked.status_code, 503, blocked.text)

        with self.app.state.session_factory() as db:
            original_row = db.get(CardAllocation, original.json()["id"])
            replacements = list(
                db.scalars(
                    select(CardAllocationReplacement).where(
                        CardAllocationReplacement.original_allocation_id
                        == original_row.id
                    )
                )
            )
            replacement_events = list(
                db.scalars(
                    select(CardEvent).where(CardEvent.reason_code == "replacement")
                )
            )
        self.assertEqual(original_row.status, "active")
        self.assertIsNone(original_row.released_at)
        self.assertIsNone(original_row.release_reason_code)
        self.assertEqual(replacements, [])
        self.assertEqual(replacement_events, [])

    def test_replace_card_is_bound_to_task_user_and_device(self) -> None:
        with self.app.state.session_factory() as db:
            db.add(
                Card(
                    tenant_id="tenant-card",
                    provider_ref="provider-card-boundary-2",
                    brand="VISA",
                    last4="2222",
                    expiry_month=11,
                    expiry_year=2031,
                    secret_ref="vault://cards/card-boundary-2",
                )
            )
            db.commit()

        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-replacement-boundary")
        original = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(original.status_code, 201, original.text)

        with self.app.state.session_factory() as db:
            wrong_task = Task(
                tenant_id="tenant-card",
                user_id=self.identity.user_id,
                device_id=self.identity.device_id,
                task_type="card_checkout",
                idempotency_key="card-replacement-wrong-task",
                status="created",
                expires_at=utc_now() + timedelta(minutes=10),
            )
            second_device = Device(
                tenant_id="tenant-card",
                user_id=self.identity.user_id,
                name="card-second-device",
            )
            db.add_all([wrong_task, second_device])
            db.commit()
            wrong_task_id = wrong_task.id
            second_device_id = second_device.id

        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-card",
            email="replacement-other@example.test",
            password="replacement-other-password",
            device_name="replacement-other-device",
        )
        other_login = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-card",
                "email": "replacement-other@example.test",
                "password": "replacement-other-password",
                "device_id": other.device_id,
            },
        )
        second_device_login = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-card",
                "email": "card-owner@example.test",
                "password": self.password,
                "device_id": second_device_id,
            },
        )
        self.assertEqual(other_login.status_code, 200, other_login.text)
        self.assertEqual(second_device_login.status_code, 200, second_device_login.text)

        attempts = (
            (wrong_task_id, token),
            (task_id, other_login.json()["access_token"]),
            (task_id, second_device_login.json()["access_token"]),
        )
        for attempted_task_id, attempted_token in attempts:
            denied = self.request(
                "POST",
                f"/api/v1/tasks/{attempted_task_id}/card-allocations/{original.json()['id']}/replace",
                headers=self.bearer(attempted_token),
            )
            self.assertEqual(denied.status_code, 404, denied.text)

        with self.app.state.session_factory() as db:
            original_row = db.get(CardAllocation, original.json()["id"])
            replacement = db.scalar(
                select(CardAllocationReplacement).where(
                    CardAllocationReplacement.original_allocation_id
                    == original_row.id
                )
            )
        self.assertEqual(original_row.status, "active")
        self.assertIsNone(replacement)

    def test_concurrent_replace_has_one_winner_and_one_idempotent_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="card-replacement-") as directory:
            database_url = f"sqlite+pysqlite:///{(Path(directory) / 'cards.db').as_posix()}"
            app = create_app(
                Settings(
                    environment="test",
                    database_url=database_url,
                    jwt_hmac_secret="replacement-concurrency-test-secret",
                    card_lease_ttl_seconds=600,
                    card_reveal_ttl_seconds=45,
                )
            )
            password = "replacement-concurrency-password"
            identity = create_user_with_device(
                app.state.session_factory,
                tenant_id="tenant-card-race",
                email="replacement-race@example.test",
                password=password,
                device_name="replacement-race-device",
            )
            with app.state.session_factory() as db:
                db.add_all(
                    [
                        Card(
                            tenant_id="tenant-card-race",
                            provider_ref="provider-card-concurrent-1",
                            brand="VISA",
                            last4="1111",
                            expiry_month=12,
                            expiry_year=2030,
                            secret_ref="vault://cards/card-concurrent-1",
                        ),
                        Card(
                            tenant_id="tenant-card-race",
                            provider_ref="provider-card-concurrent-2",
                            brand="VISA",
                            last4="2222",
                            expiry_month=11,
                            expiry_year=2031,
                            secret_ref="vault://cards/card-concurrent-2",
                        ),
                    ]
                )
                db.commit()

            def request(method: str, path: str, **kwargs: object) -> httpx.Response:
                async def run() -> httpx.Response:
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(
                        transport=transport, base_url="http://test"
                    ) as client:
                        return await client.request(method, path, **kwargs)

                return asyncio.run(run())

            login = request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-card-race",
                    "email": "replacement-race@example.test",
                    "password": password,
                    "device_id": identity.device_id,
                },
            )
            self.assertEqual(login.status_code, 200, login.text)
            headers = self.bearer(login.json()["access_token"])
            task = request(
                "POST",
                "/api/v1/tasks",
                headers=headers,
                json={
                    "type": "card_checkout",
                    "idempotency_key": "card-replacement-concurrent",
                },
            )
            self.assertEqual(task.status_code, 201, task.text)
            task_id = task.json()["id"]
            original = request(
                "POST",
                f"/api/v1/tasks/{task_id}/card-allocations",
                headers=headers,
            )
            self.assertEqual(original.status_code, 201, original.text)
            start = Barrier(2)

            def replace() -> httpx.Response:
                start.wait(timeout=5)
                return request(
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations/{original.json()['id']}/replace",
                    headers=headers,
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(lambda _: replace(), range(2)))

            self.assertCountEqual(
                [item.status_code for item in responses],
                [200, 201],
                [(item.status_code, item.text) for item in responses],
            )
            self.assertEqual(len({item.json()["id"] for item in responses}), 1)
            with app.state.session_factory() as db:
                replacements = list(
                    db.scalars(
                        select(CardAllocationReplacement).where(
                            CardAllocationReplacement.original_allocation_id
                            == original.json()["id"]
                        )
                    )
                )
                active = list(
                    db.scalars(
                        select(CardAllocation).where(
                            CardAllocation.task_id == task_id,
                            CardAllocation.released_at.is_(None),
                        )
                    )
                )
            self.assertEqual(len(replacements), 1)
            self.assertEqual(
                [row.id for row in active],
                [replacements[0].replacement_allocation_id],
            )
            app.state.engine.dispose()

    def test_stale_release_cannot_overwrite_expired_card_lease(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-release-expiry-race")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        stale_read_completed = Event()
        release_stale_writer = Event()
        original_owned_allocation = routes._owned_card_allocation

        def pause_after_stale_read(db, requested_allocation_id, principal):
            result = original_owned_allocation(
                db, requested_allocation_id, principal
            )
            if result is not None:
                # The application Session retains loaded values across commit.
                # Ending the read transaction makes the lifecycle winner
                # deterministic while this request keeps its stale ORM row.
                db.commit()
                stale_read_completed.set()
                self.assertTrue(release_stale_writer.wait(timeout=5))
            return result

        with mock.patch.object(
            routes,
            "_owned_card_allocation",
            side_effect=pause_after_stale_read,
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/card-allocations/{allocation_id}/release",
                    headers=self.bearer(token),
                )
                try:
                    self.assertTrue(stale_read_completed.wait(timeout=5))
                    swept = sweep_expired_lifecycle(
                        self.app.state.session_factory,
                        now=utc_now(),
                    )
                    self.assertEqual(swept.tasks_expired, 1)
                    self.assertEqual(swept.card_allocations_expired, 1)
                finally:
                    release_stale_writer.set()
                released = future.result(timeout=5)

        self.assertEqual(released.status_code, 200, released.text)
        self.assertEqual(released.json()["status"], "expired")
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            persisted = db.get(CardAllocation, allocation_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(
                        AuditEvent.entity_id == allocation_id
                    )
                )
            )
        self.assertEqual(task.status, "expired")
        self.assertEqual(persisted.status, "expired")
        self.assertIsNotNone(persisted.released_at)
        self.assertEqual(event_types.count("card.expired"), 1)
        self.assertEqual(event_types.count("card.released"), 0)

    def test_cross_user_allocation_is_hidden(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-task-4")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        allocation_id = allocation.json()["id"]
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-card",
            email="other-card@example.test",
            password="other-card-account-password",
            device_name="other-card-device",
        )
        other_login = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-card",
                "email": "other-card@example.test",
                "password": "other-card-account-password",
                "device_id": other.device_id,
            },
        )
        other_token = other_login.json()["access_token"]
        hidden = self.request(
            "GET",
            f"/api/v1/card-allocations/{allocation_id}?task_id={task_id}",
            headers=self.bearer(other_token),
        )
        self.assertEqual(hidden.status_code, 404)
        hidden_reveal = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=self.bearer(other_token),
            json={"reveal_grant": "x" * 32, "fields": ["pan"]},
        )
        self.assertEqual(hidden_reveal.status_code, 404, hidden_reveal.text)
        self.assertEqual(self.card_secret_resolver.secret_refs, [])

    def test_expired_lease_is_reclaimed_without_exposing_secret(self) -> None:
        token = self.login()
        first_task = self.create_task(token, "card-task-5")
        first = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/card-allocations",
            headers=self.bearer(token),
        )
        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, first.json()["id"])
            self.assertIsNotNone(allocation)
            allocation.expires_at = utc_now() - timedelta(seconds=1)
            task = db.get(Task, first_task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            mailbox = Mailbox(
                tenant_id="tenant-card",
                email_masked="c***@example.test",
                connector_type="fake",
                secret_ref="vault://mailboxes/expired-card-lease",
            )
            db.add(mailbox)
            db.flush()
            mail_session = MailSession(
                tenant_id="tenant-card",
                task_id=task.id,
                user_id=task.user_id,
                device_id=task.device_id,
                mailbox_id=mailbox.id,
                trace_id=task.trace_id,
                status="code_ready",
                delivered_code="123456",
                delivered_at=utc_now(),
                code_expires_at=utc_now() + timedelta(minutes=1),
                expires_at=utc_now() + timedelta(minutes=5),
            )
            upload = UploadJob(
                tenant_id="tenant-card",
                task_id=task.id,
                user_id=task.user_id,
                device_id=task.device_id,
                card_allocation_id=allocation.id,
                idempotency_key="expired-card-lease-upload",
                business_name="Expired lease upload",
                trace_id=task.trace_id,
                status="queued",
                policy_version="card-test-v1",
            )
            db.add_all([mail_session, upload])
            db.flush()
            outbox = OutboxEvent(
                tenant_id="tenant-card",
                event_type="upload.requested",
                aggregate_type="upload_job",
                aggregate_id=upload.id,
            )
            db.add(outbox)
            db.commit()
            mail_session_id = mail_session.id
            upload_id = upload.id
            outbox_id = outbox.id
        second_task = self.create_task(token, "card-task-6")
        locked_resources: list[tuple[str, bool]] = []

        def capture_compensation_locks(execute_state: object) -> None:
            statement = getattr(execute_state, "statement", None)
            lock = getattr(statement, "_for_update_arg", None)
            if statement is None or lock is None:
                return
            sql = str(statement).lower()
            for table in ("tasks", "card_allocations"):
                if f"from {table}" in sql:
                    locked_resources.append((table, bool(lock.skip_locked)))
                    return

        event.listen(Session, "do_orm_execute", capture_compensation_locks)
        try:
            second = self.request(
                "POST",
                f"/api/v1/tasks/{second_task}/card-allocations",
                headers=self.bearer(token),
            )
        finally:
            event.remove(Session, "do_orm_execute", capture_compensation_locks)
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(second.json()["card_masked"], "VISA •••• 1111")
        self.assertEqual(
            locked_resources[:2],
            [("tasks", True), ("card_allocations", True)],
        )
        with self.app.state.session_factory() as db:
            expired_task = db.get(Task, first_task)
            expired_allocation = db.get(CardAllocation, first.json()["id"])
            expired_session = db.get(MailSession, mail_session_id)
            cancelled_upload = db.get(UploadJob, upload_id)
            finalized_outbox = db.get(OutboxEvent, outbox_id)
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(expired_task.status, "cancelled")
            self.assertEqual(expired_allocation.status, "expired")
            self.assertIsNotNone(expired_allocation.released_at)
            self.assertEqual(expired_session.status, "expired")
            self.assertIsNone(expired_session.delivered_code)
            self.assertEqual(cancelled_upload.status, "cancelled")
            self.assertEqual(cancelled_upload.error_code, "card_lease_invalid")
            self.assertEqual(finalized_outbox.status, "processed")
            self.assertEqual(finalized_outbox.last_error_code, "card_lease_invalid")
            for event_type in (
                "task.cancelled",
                "card.expired",
                "mail_session.expired",
                "upload.cancelled",
            ):
                self.assertEqual(event_types.count(event_type), 1)

        released = self.request(
            "POST",
            f"/api/v1/card-allocations/{second.json()['id']}/release",
            headers=self.bearer(token),
        )
        self.assertEqual(released.status_code, 200, released.text)
        closed = self.request(
            "POST",
            f"/api/v1/tasks/{second_task}/close",
            headers=self.bearer(token),
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        third_task = self.create_task(token, "card-task-expiry-replay")
        replay = self.request(
            "POST",
            f"/api/v1/tasks/{third_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(replay.status_code, 201, replay.text)
        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
        for event_type in (
            "task.cancelled",
            "card.expired",
            "mail_session.expired",
            "upload.cancelled",
        ):
            self.assertEqual(event_types.count(event_type), 1)

    def test_skipped_expired_lease_remains_occupied_and_cannot_be_reallocated(self) -> None:
        token = self.login()
        first_task = self.create_task(token, "card-task-expired-lock-owner")
        first = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 201, first.text)
        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, first.json()["id"])
            allocation.expires_at = utc_now() - timedelta(seconds=1)
            task = db.get(Task, first_task)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        second_task = self.create_task(token, "card-task-expired-lock-contender")
        with mock.patch(
            "platform.api.v1.routes._compensate_expired_card_leases",
            create=True,
        ):
            blocked = self.request(
                "POST",
                f"/api/v1/tasks/{second_task}/card-allocations",
                headers=self.bearer(token),
            )

        self.assertEqual(blocked.status_code, 503, blocked.text)
        with self.app.state.session_factory() as db:
            stored = db.get(CardAllocation, first.json()["id"])
            allocations = list(db.scalars(select(CardAllocation)))
        self.assertIsNone(stored.released_at)
        self.assertEqual(len(allocations), 1)

    def test_expired_lease_request_compensation_is_bounded(self) -> None:
        token = self.login()
        now = utc_now()
        seeded_task_ids: list[str] = []
        with self.app.state.session_factory() as db:
            for index in range(26):
                task = Task(
                    tenant_id="tenant-card",
                    user_id=self.identity.user_id,
                    device_id=self.identity.device_id,
                    task_type="card_checkout",
                    idempotency_key=f"bounded-expired-task-{index:02d}",
                    trace_id=f"bounded-expired-trace-{index:02d}",
                    status="created",
                    # Historical expired-lease residue is constructed directly;
                    # it must not represent a second API-active task.
                    expires_at=now - timedelta(seconds=1),
                )
                card = Card(
                    tenant_id="tenant-card",
                    provider_ref=f"bounded-expired-card-{index:02d}",
                    brand="VISA",
                    last4=f"{index:04d}",
                    secret_ref=f"vault://cards/bounded-expired-{index:02d}",
                )
                db.add_all([task, card])
                db.flush()
                db.add(
                    CardAllocation(
                        tenant_id="tenant-card",
                        task_id=task.id,
                        user_id=self.identity.user_id,
                        device_id=self.identity.device_id,
                        card_id=card.id,
                        trace_id=task.trace_id,
                        status="active",
                        expires_at=now - timedelta(seconds=1),
                    )
                )
                seeded_task_ids.append(task.id)
            db.commit()

        current_task = self.create_task(token, "bounded-compensation-current")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{current_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)

        with self.app.state.session_factory() as db:
            seeded_tasks = list(
                db.scalars(select(Task).where(Task.id.in_(seeded_task_ids)))
            )
            seeded_allocations = list(
                db.scalars(
                    select(CardAllocation).where(
                        CardAllocation.task_id.in_(seeded_task_ids)
                    )
                )
            )
            event_types = list(db.scalars(select(AuditEvent.event_type)))
        self.assertEqual(
            sum(task.status == "cancelled" for task in seeded_tasks), 25
        )
        self.assertEqual(sum(task.status == "created" for task in seeded_tasks), 1)
        self.assertEqual(
            sum(allocation.released_at is None for allocation in seeded_allocations),
            1,
        )
        self.assertEqual(event_types.count("task.cancelled"), 25)
        self.assertEqual(event_types.count("card.expired"), 25)

    def test_closing_task_releases_card_and_blocks_new_allocation(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-close")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        released = self.request(
            "GET",
            f"/api/v1/card-allocations/{allocation.json()['id']}?task_id={task_id}",
            headers=headers,
        )
        self.assertEqual(released.status_code, 200, released.text)
        self.assertEqual(released.json()["status"], "released")
        blocked = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "conflict")

    def test_allocation_read_is_bound_to_the_requested_task(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        first_task = self.create_task(token, "card-task-read-boundary-a")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        closed = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/close",
            headers=headers,
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        second_task = self.create_task(token, "card-task-read-boundary-b")

        hidden = self.request(
            "GET",
            f"/api/v1/card-allocations/{allocation.json()['id']}?task_id={second_task}",
            headers=headers,
        )
        self.assertEqual(hidden.status_code, 404, hidden.text)

    def test_reveal_is_one_time_owner_bound_and_audited_without_secret(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-reveal")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)

        challenge, grant, revealed = self.reveal_with_step_up(
            token, allocation.json()["id"]
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.json()["allocation_id"], allocation.json()["id"])
        self.assertEqual(revealed.json()["trace_id"], allocation.json()["trace_id"])
        self.assertEqual(revealed.json()["card_masked"], "VISA •••• 1111")
        self.assertEqual(revealed.json()["pan"], "4111111111111111")
        self.assertNotIn("cvv", revealed.json())
        self.assertEqual(challenge.headers["cache-control"], "no-store")
        self.assertEqual(grant.headers["cache-control"], "no-store")
        self.assertEqual(revealed.headers["cache-control"], "no-store")
        self.assertEqual(self.card_secret_resolver.secret_refs, ["vault://cards/card-1"])

        replay = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
            headers=headers,
            json={
                "reveal_grant": grant.json()["reveal_grant"],
                "fields": ["pan", "expiry"],
            },
        )
        self.assertEqual(replay.status_code, 409, replay.text)

        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)

        with self.app.state.session_factory() as db:
            events = list(
                db.scalars(
                    select(AuditEvent).order_by(AuditEvent.created_at, AuditEvent.id)
                )
            )

        event_types = [event.event_type for event in events]
        self.assertEqual(event_types.count("card.revealed"), 1)
        self.assertEqual(event_types.count("card.released"), 1)
        self.assertLess(
            event_types.index("card.revealed"), event_types.index("card.released")
        )

        def _string_values(value: object) -> list[str]:
            if isinstance(value, dict):
                values: list[str] = []
                for item in value.values():
                    values.extend(_string_values(item))
                return values
            if isinstance(value, list):
                values: list[str] = []
                for item in value:
                    values.extend(_string_values(item))
                return values
            if isinstance(value, str):
                return [value]
            return []

        forbidden_values = {"4111111111111111", "123", "vault://cards/card-1"}
        for event in events:
            payload = json.loads(event.details_json)
            self.assertNotIn("secret_ref", payload)
            values = set(_string_values(payload))
            self.assertTrue(forbidden_values.isdisjoint(values))
        with self.app.state.session_factory() as db:
            stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])
            self.assertIsNotNone(stored)
            self.assertIsNone(stored.grant_token_hash)
        self.assertIsNotNone(stored.consumed_at)
        self.assertNotIn(grant.json()["reveal_grant"], str(events))

    def test_reveal_resolver_failure_is_sanitized_and_grant_remains_retryable(
        self,
    ) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-reveal-resolver-failure")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        challenge, grant = self.grant_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        reveal_payload = {
            "reveal_grant": grant.json()["reveal_grant"],
            "fields": ["pan"],
        }
        leaked_vault_uri = "vault://cards/tenant-card/card-1"
        leaked_bearer = "Bearer TOP_SECRET"
        leaked_pan = "4111111111111111"
        provider_error = CardSecretUnavailable(
            f"{leaked_vault_uri} Authorization={leaked_bearer} PAN={leaked_pan}"
        )

        with mock.patch.object(
            self.card_secret_resolver,
            "resolve",
            side_effect=[
                provider_error,
                CardSecret(pan=leaked_pan),
            ],
        ):
            unavailable = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation_id}/reveal",
                headers=headers,
                json=reveal_payload,
            )
            self.assertEqual(unavailable.status_code, 503, unavailable.text)
            error = unavailable.json()["error"]
            self.assertEqual(error["code"], "card_secret_unavailable")
            self.assertEqual(
                error["message"], "Card details are temporarily unavailable"
            )
            self.assertEqual(
                error["recovery_hint"],
                "稍后重试；持续失败时携带 trace_id 联系管理员",
            )
            for forbidden in (leaked_vault_uri, leaked_bearer, leaked_pan):
                self.assertNotIn(forbidden, unavailable.text)

            with self.app.state.session_factory() as db:
                stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])
                self.assertIsNotNone(stored)
                self.assertIsNone(stored.consumed_at)
                self.assertIsNotNone(stored.grant_token_hash)
                reveal_events = list(
                    db.scalars(
                        select(AuditEvent).where(
                            AuditEvent.entity_id == allocation_id,
                            AuditEvent.event_type == "card.revealed",
                        )
                    )
                )
            self.assertEqual(reveal_events, [])

            retried = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation_id}/reveal",
                headers=headers,
                json=reveal_payload,
            )

        self.assertEqual(retried.status_code, 200, retried.text)
        self.assertEqual(retried.json()["pan"], leaked_pan)
        with self.app.state.session_factory() as db:
            stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])
            self.assertIsNotNone(stored)
            self.assertIsNotNone(stored.consumed_at)
            self.assertIsNone(stored.grant_token_hash)
            reveal_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == allocation_id,
                        AuditEvent.event_type == "card.revealed",
                    )
                )
            )
        self.assertEqual(len(reveal_events), 1)

    def test_invalid_reveal_grant_is_audited_and_valid_grant_remains_retryable(
        self,
    ) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-invalid-reveal-grant")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        challenge, grant = self.grant_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        valid_grant = grant.json()["reveal_grant"]
        invalid_grant = "x" * 32
        self.assertNotEqual(invalid_grant, valid_grant)

        denied = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=headers,
            json={"reveal_grant": invalid_grant, "fields": ["pan"]},
        )

        self.assertEqual(denied.status_code, 403, denied.text)
        forbidden_values = (
            invalid_grant,
            valid_grant,
            challenge.json()["challenge_id"],
            "4111111111111111",
            "vault://cards/card-1",
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, denied.text)
        with self.app.state.session_factory() as db:
            failure_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == allocation_id,
                        AuditEvent.event_type == "card.reveal_failed",
                    )
                )
            )
            stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])

        self.assertEqual(len(failure_events), 1)
        failure = failure_events[0]
        self.assertEqual(failure.action, "card.reveal")
        self.assertEqual(failure.result, "failure")
        self.assertEqual(failure.actor_id, self.identity.user_id)
        self.assertEqual(failure.tenant_id, "tenant-card")
        self.assertEqual(failure.user_id, self.identity.user_id)
        self.assertEqual(failure.device_id, self.identity.device_id)
        self.assertEqual(failure.entity_id, allocation_id)
        self.assertEqual(failure.trace_id, allocation.json()["trace_id"])
        self.assertEqual(
            json.loads(failure.details_json),
            {"reason": "invalid_or_expired_grant"},
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, failure.details_json)
        self.assertIsNotNone(stored)
        self.assertEqual(
            stored.grant_token_hash,
            hashlib.sha256(valid_grant.encode("utf-8")).hexdigest(),
        )
        self.assertIsNone(stored.consumed_at)

        revealed = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=headers,
            json={"reveal_grant": valid_grant, "fields": ["pan"]},
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.json()["pan"], "4111111111111111")
        with self.app.state.session_factory() as db:
            failure_count = len(
                list(
                    db.scalars(
                        select(AuditEvent).where(
                            AuditEvent.entity_id == allocation_id,
                            AuditEvent.event_type == "card.reveal_failed",
                        )
                    )
                )
            )
            reveal_count = len(
                list(
                    db.scalars(
                        select(AuditEvent).where(
                            AuditEvent.entity_id == allocation_id,
                            AuditEvent.event_type == "card.revealed",
                        )
                    )
                )
            )
        self.assertEqual(failure_count, 1)
        self.assertEqual(reveal_count, 1)

    def test_invalid_reveal_grant_audit_commit_failure_fails_closed(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-reveal-failure-audit-store")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        challenge, grant = self.grant_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        valid_grant = grant.json()["reveal_grant"]

        with mock.patch.object(
            Session,
            "commit",
            side_effect=RuntimeError("audit store Bearer TOP_SECRET unavailable"),
        ):
            blocked = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation_id}/reveal",
                headers=headers,
                json={"reveal_grant": "x" * 32, "fields": ["pan"]},
            )

        self.assertEqual(blocked.status_code, 500, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "internal_error")
        self.assertNotIn("TOP_SECRET", blocked.text)
        with self.app.state.session_factory() as db:
            failure = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == allocation_id,
                    AuditEvent.event_type == "card.reveal_failed",
                )
            )
            stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])
        self.assertIsNone(failure)
        self.assertIsNotNone(stored)
        self.assertEqual(
            stored.grant_token_hash,
            hashlib.sha256(valid_grant.encode("utf-8")).hexdigest(),
        )
        self.assertIsNone(stored.consumed_at)

        revealed = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=headers,
            json={"reveal_grant": valid_grant, "fields": ["pan"]},
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)

    def test_concurrent_reveal_grant_returns_pan_exactly_once(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-concurrent-reveal")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        _challenge, grant = self.grant_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        reveal_payload = {
            "reveal_grant": grant.json()["reveal_grant"],
            "fields": ["pan"],
        }

        first_resolver_entered = Event()
        release_first_resolver = Event()
        call_lock = Lock()
        resolver_calls = 0

        def blocking_resolve(secret_ref: str) -> CardSecret:
            nonlocal resolver_calls
            with call_lock:
                resolver_calls += 1
                call_number = resolver_calls
            if call_number == 1:
                first_resolver_entered.set()
                self.assertTrue(release_first_resolver.wait(timeout=5))
            return CardSecret(pan="4111111111111111")

        with mock.patch.object(
            self.card_secret_resolver,
            "resolve",
            side_effect=blocking_resolve,
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                first_future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/card-allocations/{allocation_id}/reveal",
                    headers=headers,
                    json=reveal_payload,
                )
                try:
                    self.assertTrue(first_resolver_entered.wait(timeout=5))
                    second = self.request(
                        "POST",
                        f"/api/v1/card-allocations/{allocation_id}/reveal",
                        headers=headers,
                        json=reveal_payload,
                    )
                finally:
                    release_first_resolver.set()
                first = first_future.result(timeout=5)

        responses = (first, second)
        self.assertEqual(
            [response.status_code for response in responses].count(200), 1
        )
        self.assertEqual(
            [response.status_code for response in responses].count(409), 1
        )
        for response in responses:
            if response.status_code == 200:
                self.assertEqual(response.json()["pan"], "4111111111111111")
            else:
                self.assertNotIn("4111111111111111", response.text)

        with self.app.state.session_factory() as db:
            reveal_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == allocation_id,
                        AuditEvent.event_type == "card.revealed",
                    )
                )
            )
            challenge = db.scalar(
                select(CardRevealChallenge).where(
                    CardRevealChallenge.allocation_id == allocation_id
                )
            )
        self.assertEqual(resolver_calls, 2)
        self.assertEqual(len(reveal_events), 1)
        self.assertIsNotNone(challenge)
        self.assertIsNotNone(challenge.consumed_at)
        self.assertIsNone(challenge.grant_token_hash)

    def test_terminal_task_with_active_lease_cannot_reveal_or_resolve_pan(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-terminal-reveal")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        _challenge, grant = self.grant_with_step_up(
            token, allocation.json()["id"]
        )
        self.assertEqual(grant.status_code, 200, grant.text)

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            self.assertIsNotNone(task)
            task.status = "completed"
            task.closed_at = utc_now()
            db.commit()

        blocked = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
            headers=headers,
            json={
                "reveal_grant": grant.json()["reveal_grant"],
                "fields": ["pan"],
            },
        )
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(
            blocked.json()["error"]["code"], "card_reveal_unavailable"
        )
        self.assertNotIn("completed", blocked.text.lower())
        self.assertEqual(self.card_secret_resolver.secret_refs, [])
        with self.app.state.session_factory() as db:
            stored = db.scalar(
                select(CardRevealChallenge).where(
                    CardRevealChallenge.grant_token_hash.is_not(None)
                )
            )
            reveal_events = list(
                db.scalars(
                    select(AuditEvent).where(AuditEvent.event_type == "card.revealed")
                )
            )
        self.assertIsNotNone(stored)
        self.assertIsNone(stored.consumed_at)
        self.assertEqual(reveal_events, [])

    def test_reveal_rechecks_task_and_lease_ttl_before_resolving_pan(self) -> None:
        token = self.login()
        headers = self.bearer(token)

        for expired_resource in ("task", "lease"):
            with self.subTest(expired_resource=expired_resource):
                task_id = self.create_task(
                    token, f"card-task-expired-{expired_resource}-reveal"
                )
                allocation = self.request(
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations",
                    headers=headers,
                )
                self.assertEqual(allocation.status_code, 201, allocation.text)
                _challenge, grant = self.grant_with_step_up(
                    token, allocation.json()["id"]
                )
                self.assertEqual(grant.status_code, 200, grant.text)

                with self.app.state.session_factory() as db:
                    if expired_resource == "task":
                        task = db.get(Task, task_id)
                        self.assertIsNotNone(task)
                        task.expires_at = utc_now() - timedelta(seconds=1)
                    else:
                        stored_allocation = db.get(
                            CardAllocation, allocation.json()["id"]
                        )
                        self.assertIsNotNone(stored_allocation)
                        stored_allocation.expires_at = utc_now() - timedelta(seconds=1)
                    db.commit()

                blocked = self.request(
                    "POST",
                    f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
                    headers=headers,
                    json={
                        "reveal_grant": grant.json()["reveal_grant"],
                        "fields": ["pan"],
                    },
                )
                self.assertEqual(blocked.status_code, 409, blocked.text)
                self.assertEqual(
                    blocked.json()["error"]["code"], "card_reveal_unavailable"
                )
                cleanup = self.request(
                    "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
                )
                self.assertEqual(cleanup.status_code, 200, cleanup.text)

        self.assertEqual(self.card_secret_resolver.secret_refs, [])

    def test_reveal_locks_task_allocation_and_challenge_in_order(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-reveal-lock-order")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        _challenge, grant = self.grant_with_step_up(
            token, allocation.json()["id"]
        )
        self.assertEqual(grant.status_code, 200, grant.text)

        locked_tables: list[str] = []

        def capture_lock(execute_state: object) -> None:
            statement = getattr(execute_state, "statement", None)
            if statement is None or getattr(statement, "_for_update_arg", None) is None:
                return
            sql = str(statement).lower()
            for table in (
                "tasks",
                "users",
                "devices",
                "card_allocations",
                "card_reveal_challenges",
            ):
                if f"from {table}" in sql:
                    locked_tables.append(table)
                    break

        event.listen(Session, "do_orm_execute", capture_lock)
        try:
            revealed = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
                headers=headers,
                json={
                    "reveal_grant": grant.json()["reveal_grant"],
                    "fields": ["pan"],
                },
            )
        finally:
            event.remove(Session, "do_orm_execute", capture_lock)

        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(
            locked_tables,
            [
                "tasks",
                "users",
                "devices",
                "card_allocations",
                "card_reveal_challenges",
            ],
        )

    def test_reveal_rechecks_principal_before_resolving_pan(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        now = utc_now()
        captured_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            email="card-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=now,
            acr=None,
            amr=(),
            access_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            access_token_expires_at=now + timedelta(minutes=15),
            access_token_revoked=False,
        )

        for boundary in ("user_disabled", "device_revoked"):
            with self.subTest(boundary=boundary):
                task_id = self.create_task(token, f"card-reveal-{boundary}")
                allocation = self.request(
                    "POST",
                    f"/api/v1/tasks/{task_id}/card-allocations",
                    headers=headers,
                )
                self.assertEqual(allocation.status_code, 201, allocation.text)
                allocation_id = allocation.json()["id"]
                _challenge, grant = self.grant_with_step_up(token, allocation_id)
                self.assertEqual(grant.status_code, 200, grant.text)

                with self.app.state.session_factory() as db:
                    if boundary == "user_disabled":
                        db.get(User, self.identity.user_id).is_active = False
                    else:
                        db.get(Device, self.identity.device_id).revoked_at = now
                    db.commit()

                self.app.dependency_overrides[get_operator_principal] = (
                    lambda: captured_principal
                )
                try:
                    blocked = self.request(
                        "POST",
                        f"/api/v1/card-allocations/{allocation_id}/reveal",
                        headers=headers,
                        json={
                            "reveal_grant": grant.json()["reveal_grant"],
                            "fields": ["pan"],
                        },
                    )
                finally:
                    self.app.dependency_overrides.pop(get_operator_principal, None)
                    with self.app.state.session_factory() as db:
                        db.get(User, self.identity.user_id).is_active = True
                        db.get(Device, self.identity.device_id).revoked_at = None
                        task = db.get(Task, task_id)
                        task.status = "closed"
                        task.closed_at = utc_now()
                        stored_allocation = db.get(CardAllocation, allocation_id)
                        stored_allocation.status = "released"
                        stored_allocation.released_at = utc_now()
                        db.commit()

                self.assertEqual(blocked.status_code, 401, blocked.text)
                self.assertNotIn("4111111111111111", blocked.text)
                with self.app.state.session_factory() as db:
                    stored_allocation = db.get(CardAllocation, allocation_id)
                    challenge = db.scalar(
                        select(CardRevealChallenge).where(
                            CardRevealChallenge.allocation_id == allocation_id
                        )
                    )
                    reveal_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == allocation_id,
                                AuditEvent.event_type == "card.revealed",
                            )
                        )
                    )
                self.assertIsNone(stored_allocation.revealed_at)
                self.assertIsNone(challenge.consumed_at)
                self.assertIsNotNone(challenge.grant_token_hash)
                self.assertEqual(reveal_events, [])

        self.assertEqual(self.card_secret_resolver.secret_refs, [])

    def test_reveal_rechecks_device_after_consumption_commit(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-reveal-commit-boundary")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        _challenge, grant = self.grant_with_step_up(token, allocation_id)
        self.assertEqual(grant.status_code, 200, grant.text)
        original_commit = Session.commit
        revoked = False

        def commit_then_revoke(session: Session) -> None:
            nonlocal revoked
            committing_reveal = any(
                isinstance(item, AuditEvent) and item.event_type == "card.revealed"
                for item in session.new
            )
            original_commit(session)
            if not committing_reveal or revoked:
                return
            revoked = True
            with self.app.state.session_factory() as other:
                device = other.get(Device, self.identity.device_id)
                self.assertIsNotNone(device)
                device.revoked_at = utc_now()
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_revoke):
            revealed = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation_id}/reveal",
                headers=self.bearer(token),
                json={
                    "reveal_grant": grant.json()["reveal_grant"],
                    "fields": ["pan"],
                },
            )

        self.assertEqual(revealed.status_code, 401, revealed.text)
        self.assertNotIn("4111111111111111", revealed.text)
        self.assertNotIn('"pan"', revealed.text)
        with self.app.state.session_factory() as db:
            challenge = db.scalar(
                select(CardRevealChallenge).where(
                    CardRevealChallenge.allocation_id == allocation_id
                )
            )
            reveal_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == allocation_id,
                        AuditEvent.event_type == "card.revealed",
                    )
                )
            )
        self.assertIsNotNone(challenge.consumed_at)
        self.assertEqual(len(reveal_events), 1)

    def test_card_allocation_read_rechecks_device_after_authentication(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-read-revoked-device")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)
        allocation_id = allocated.json()["id"]
        now = utc_now()
        captured_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            email="card-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=now,
            acr=None,
            amr=(),
            access_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            access_token_expires_at=now + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            db.get(Device, self.identity.device_id).revoked_at = now
            db.commit()

        self.app.dependency_overrides[get_operator_principal] = (
            lambda: captured_principal
        )
        try:
            response = self.request(
                "GET",
                f"/api/v1/card-allocations/{allocation_id}",
                params={"task_id": task_id},
            )
        finally:
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertEqual(response.status_code, 401, response.text)
        for sensitive in (
            allocated.json()["card_masked"],
            str(allocated.json()["expiry_year"]),
            allocated.json()["trace_id"],
        ):
            self.assertNotIn(sensitive, response.text)

    def test_card_release_rechecks_operator_after_authentication(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-release-stale-operator")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        allocation_id = allocated.json()["id"]
        now = utc_now()
        captured_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
            email="card-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=now,
            acr=None,
            amr=(),
            access_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            access_token_expires_at=now + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            db.get(User, self.identity.user_id).role = "security_auditor"
            db.commit()

        self.app.dependency_overrides[get_operator_principal] = (
            lambda: captured_principal
        )
        try:
            response = self.request(
                "POST", f"/api/v1/card-allocations/{allocation_id}/release"
            )
        finally:
            self.app.dependency_overrides.pop(get_operator_principal, None)

        self.assertEqual(response.status_code, 403, response.text)
        with self.app.state.session_factory() as db:
            persisted = db.get(CardAllocation, allocation_id)
            release_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "card.released",
                        AuditEvent.entity_id == allocation_id,
                    )
                )
            )
        self.assertEqual(persisted.status, "active")
        self.assertIsNone(persisted.released_at)
        self.assertEqual(release_events, [])

    def test_reveal_rejects_missing_or_insufficient_step_up(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-step-up-required")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        allocation_id = allocation.json()["id"]
        missing = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=headers,
            json={"reveal_grant": "x" * 32, "fields": ["pan"]},
        )
        self.assertEqual(missing.status_code, 403, missing.text)

        local_challenge = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-challenges",
            headers=headers,
        )
        self.assertEqual(local_challenge.status_code, 201, local_challenge.text)
        local_identity = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-grants",
            headers=headers,
            json={"challenge_id": local_challenge.json()["challenge_id"]},
        )
        wrong_challenge, wrong_acr, _ = self.reveal_with_step_up(
            token, allocation_id, acr="urn:email-platform:acr:password"
        )
        stale_challenge, stale_auth, _ = self.reveal_with_step_up(
            token, allocation_id, auth_time_offset_seconds=-600
        )
        denied = (local_identity, wrong_acr, stale_auth)
        for response in denied:
            self.assertEqual(response.status_code, 403, response.text)
        forbidden_values = (
            token,
            "step-up-token",
            local_challenge.json()["challenge_id"],
            wrong_challenge.json()["challenge_id"],
            stale_challenge.json()["challenge_id"],
            "urn:email-platform:acr:password",
            "urn:email-platform:acr:mfa",
            "4111111111111111",
            "vault://cards/card-1",
        )
        for response in denied:
            for forbidden in forbidden_values:
                self.assertNotIn(forbidden, response.text)
        self.assertEqual(self.card_secret_resolver.secret_refs, [])

        challenge_ids = (
            local_challenge.json()["challenge_id"],
            wrong_challenge.json()["challenge_id"],
            stale_challenge.json()["challenge_id"],
        )
        with self.app.state.session_factory() as db:
            failures = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == allocation_id,
                        AuditEvent.event_type == "card.reveal_step_up_failed",
                    )
                )
            )
            stored_challenges = [
                db.get(CardRevealChallenge, challenge_id)
                for challenge_id in challenge_ids
            ]

        self.assertEqual(len(failures), 3)
        self.assertCountEqual(
            [json.loads(event.details_json) for event in failures],
            [
                {"reason": "oidc_required"},
                {"reason": "insufficient_acr"},
                {"reason": "stale_authentication"},
            ],
        )
        for event in failures:
            self.assertEqual(event.action, "card.reveal_step_up")
            self.assertEqual(event.result, "failure")
            self.assertEqual(event.actor_id, self.identity.user_id)
            self.assertEqual(event.tenant_id, "tenant-card")
            self.assertEqual(event.user_id, self.identity.user_id)
            self.assertEqual(event.device_id, self.identity.device_id)
            self.assertEqual(event.entity_id, allocation_id)
            self.assertEqual(event.trace_id, allocation.json()["trace_id"])
            self.assertEqual(set(json.loads(event.details_json)), {"reason"})
            for forbidden in forbidden_values:
                self.assertNotIn(forbidden, event.details_json)
        for challenge in stored_challenges:
            self.assertIsNotNone(challenge)
            self.assertIsNone(challenge.granted_at)
            self.assertIsNone(challenge.grant_expires_at)
            self.assertIsNone(challenge.grant_token_hash)
            self.assertIsNone(challenge.consumed_at)

        self.app.state.access_token_verifier = MixedStepUpVerifier(
            main_token=token,
            user_id=self.identity.user_id,
            oidc_subject="oidc-card-owner",
            tenant_id="tenant-card",
            device_id=self.identity.device_id,
        )
        recovered_grant = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-grants",
            headers=self.bearer("step-up-token"),
            json={"challenge_id": local_challenge.json()["challenge_id"]},
        )
        self.assertEqual(recovered_grant.status_code, 200, recovered_grant.text)
        recovered_reveal = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal",
            headers=headers,
            json={
                "reveal_grant": recovered_grant.json()["reveal_grant"],
                "fields": ["pan"],
            },
        )
        self.assertEqual(recovered_reveal.status_code, 200, recovered_reveal.text)
        self.assertEqual(recovered_reveal.json()["pan"], "4111111111111111")

    def test_reveal_step_up_audit_commit_failure_fails_closed(self) -> None:
        token = self.login()
        headers = self.bearer(token)
        task_id = self.create_task(token, "card-task-step-up-audit-failure")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=headers,
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        allocation_id = allocation.json()["id"]
        challenge = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation_id}/reveal-challenges",
            headers=headers,
        )
        self.assertEqual(challenge.status_code, 201, challenge.text)

        with mock.patch.object(
            Session,
            "commit",
            side_effect=RuntimeError("audit store Bearer TOP_SECRET unavailable"),
        ):
            blocked = self.request(
                "POST",
                f"/api/v1/card-allocations/{allocation_id}/reveal-grants",
                headers=headers,
                json={"challenge_id": challenge.json()["challenge_id"]},
            )

        self.assertEqual(blocked.status_code, 500, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "internal_error")
        self.assertNotIn("TOP_SECRET", blocked.text)
        with self.app.state.session_factory() as db:
            stored = db.get(CardRevealChallenge, challenge.json()["challenge_id"])
            failure = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == allocation_id,
                    AuditEvent.event_type == "card.reveal_step_up_failed",
                )
            )
        self.assertIsNotNone(stored)
        self.assertIsNone(stored.granted_at)
        self.assertIsNone(stored.grant_expires_at)
        self.assertIsNone(stored.grant_token_hash)
        self.assertIsNone(stored.consumed_at)
        self.assertIsNone(failure)

    def test_expiry_only_reveal_does_not_resolve_or_return_pan(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-task-expiry-only")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)

        challenge, grant, revealed = self.reveal_with_step_up(
            token,
            allocation.json()["id"],
            fields=("expiry",),
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.json()["expiry_month"], 12)
        self.assertEqual(revealed.json()["expiry_year"], 2030)
        self.assertNotIn("pan", revealed.json())
        self.assertEqual(self.card_secret_resolver.secret_refs, [])
        for response in (challenge, grant, revealed):
            self.assertEqual(response.headers["cache-control"], "no-store")

        replay = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
            headers=self.bearer(token),
            json={
                "reveal_grant": grant.json()["reveal_grant"],
                "fields": ["expiry"],
            },
        )
        self.assertEqual(replay.status_code, 409, replay.text)
        with self.app.state.session_factory() as db:
            event = db.scalar(
                select(AuditEvent).where(AuditEvent.event_type == "card.revealed")
            )
        self.assertIsNotNone(event)
        details = json.loads(event.details_json)
        self.assertEqual(details["fields"], ["expiry"])
        self.assertNotIn("pan", event.details_json.lower())
        self.assertNotIn("secret", event.details_json.lower())
        self.assertNotIn(grant.json()["reveal_grant"], event.details_json)

    def test_pan_only_reveal_returns_pan_without_expiry(self) -> None:
        token = self.login()
        task_id = self.create_task(token, "card-task-pan-only")
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)

        challenge, grant, revealed = self.reveal_with_step_up(
            token,
            allocation.json()["id"],
            fields=("pan",),
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.json()["pan"], "4111111111111111")
        self.assertNotIn("expiry_month", revealed.json())
        self.assertNotIn("expiry_year", revealed.json())
        self.assertEqual(
            self.card_secret_resolver.secret_refs,
            ["vault://cards/card-1"],
        )
        for response in (challenge, grant, revealed):
            self.assertEqual(response.headers["cache-control"], "no-store")
        with self.app.state.session_factory() as db:
            event = db.scalar(
                select(AuditEvent).where(AuditEvent.event_type == "card.revealed")
            )
        self.assertIsNotNone(event)
        self.assertEqual(json.loads(event.details_json)["fields"], ["pan"])

    def test_default_card_resolver_can_reveal_env_secret(self) -> None:
        with mock.patch.dict(
            "os.environ", {"CARD_ENV_JSON": '{"pan":"4242424242424242"}'}, clear=False
        ):
            app = create_app(
                Settings(
                    environment="test",
                    database_url="sqlite+pysqlite:///:memory:",
                    jwt_hmac_secret="card-env-test-hmac-secret-that-is-not-production",
                )
            )
            try:
                secret = app.state.card_secret_resolver.resolve("env://CARD_ENV_JSON")
                self.assertEqual(secret.pan, "4242424242424242")
                self.assertFalse(hasattr(secret, "cvv"))
            finally:
                app.state.engine.dispose()

    def test_openapi_has_no_raw_card_fields(self) -> None:
        openapi = self.app.openapi()
        schemas = openapi["components"]["schemas"]
        properties = schemas["CardAllocationResponse"]["properties"]
        for forbidden in ("pan", "cvv", "secret_ref", "provider_ref"):
            self.assertNotIn(forbidden, properties)
        reveal_schema = schemas["CardRevealResponse"]
        reveal_properties = reveal_schema["properties"]
        self.assertIn("pan", reveal_properties)
        self.assertNotIn("pan", reveal_schema.get("required", []))
        self.assertNotIn("cvv", reveal_properties)
        self.assertIn("CardRevealRequest", schemas)
        self.assertNotIn("cvv", json.dumps(schemas["CardRevealRequest"]).lower())
        replacement = openapi["paths"][
            "/api/v1/tasks/{task_id}/card-allocations/{allocation_id}/replace"
        ]["post"]
        for status in ("200", "201"):
            response_schema = replacement["responses"][status]["content"][
                "application/json"
            ]["schema"]
            self.assertEqual(
                response_schema["$ref"],
                "#/components/schemas/CardAllocationResponse",
            )


if __name__ == "__main__":
    unittest.main()
