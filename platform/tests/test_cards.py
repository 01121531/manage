import asyncio
import json
import unittest
from datetime import timedelta
from unittest import mock

import httpx
from sqlalchemy import select

from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.cards import CardSecret
from platform.config import Settings
from platform.models import AuditEvent, Card, CardAllocation, utc_now


class FakeCardSecretResolver:
    def __init__(self) -> None:
        self.secret_refs: list[str] = []

    def resolve(self, secret_ref: str) -> CardSecret:
        self.secret_refs.append(secret_ref)
        return CardSecret(pan="4111111111111111", cvv="123")


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
            },
        )
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
            events = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "card.allocated")))
        self.assertEqual(len(events), 1)
        self.assertNotIn("vault://cards/card-1", events[0].details_json)

    def test_card_cannot_be_double_leased_and_release_makes_it_available(self) -> None:
        token = self.login()
        first_task = self.create_task(token, "card-task-2")
        first = self.request(
            "POST",
            f"/api/v1/tasks/{first_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 201)
        second_task = self.create_task(token, "card-task-3")
        unavailable = self.request(
            "POST",
            f"/api/v1/tasks/{second_task}/card-allocations",
            headers=self.bearer(token),
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
            headers=self.bearer(token),
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)

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
            f"/api/v1/card-allocations/{allocation_id}",
            headers=self.bearer(other_token),
        )
        self.assertEqual(hidden.status_code, 404)

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
            db.commit()
        second_task = self.create_task(token, "card-task-6")
        second = self.request(
            "POST",
            f"/api/v1/tasks/{second_task}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(second.json()["card_masked"], "VISA •••• 1111")

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
            f"/api/v1/card-allocations/{allocation.json()['id']}",
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

        revealed = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
            headers=headers,
        )
        self.assertEqual(revealed.status_code, 200, revealed.text)
        self.assertEqual(revealed.json()["allocation_id"], allocation.json()["id"])
        self.assertEqual(revealed.json()["trace_id"], allocation.json()["trace_id"])
        self.assertEqual(revealed.json()["card_masked"], "VISA •••• 1111")
        self.assertEqual(revealed.json()["pan"], "4111111111111111")
        self.assertEqual(revealed.json()["cvv"], "123")
        self.assertEqual(self.card_secret_resolver.secret_refs, ["vault://cards/card-1"])

        replay = self.request(
            "POST",
            f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
            headers=headers,
        )
        self.assertEqual(replay.status_code, 409, replay.text)

        with self.app.state.session_factory() as db:
            events = list(db.scalars(select(AuditEvent)))

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

    def test_default_card_resolver_can_reveal_env_secret(self) -> None:
        app = create_app(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="card-env-test-hmac-secret-that-is-not-production",
            )
        )
        try:
            identity = create_user_with_device(
                app.state.session_factory,
                tenant_id="tenant-card-env",
                email="card-env@example.test",
                password="card-env-account-password",
                device_name="card-env-device",
            )
            with app.state.session_factory() as db:
                db.add(
                    Card(
                        tenant_id="tenant-card-env",
                        provider_ref="provider-card-env",
                        brand="VISA",
                        last4="4242",
                        secret_ref="env://CARD_ENV_JSON",
                    )
                )
                db.commit()

            async def run() -> tuple[httpx.Response, httpx.Response]:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as client:
                    login = await client.post(
                        "/api/v1/auth/login",
                        json={
                            "tenant_id": "tenant-card-env",
                            "email": "card-env@example.test",
                            "password": "card-env-account-password",
                            "device_id": identity.device_id,
                        },
                    )
                    token = login.json()["access_token"]
                    headers = {"Authorization": f"Bearer {token}"}
                    task = await client.post(
                        "/api/v1/tasks",
                        headers=headers,
                        json={"type": "card_checkout", "idempotency_key": "env-card-task"},
                    )
                    allocation = await client.post(
                        f"/api/v1/tasks/{task.json()['id']}/card-allocations",
                        headers=headers,
                    )
                    reveal = await client.post(
                        f"/api/v1/card-allocations/{allocation.json()['id']}/reveal",
                        headers=headers,
                    )
                    return allocation, reveal

            with mock.patch.dict(
                "os.environ",
                {"CARD_ENV_JSON": '{"pan":"4242424242424242","cvv":"321"}'},
            ):
                allocation, reveal = asyncio.run(run())
            self.assertEqual(allocation.json()["card_masked"], "VISA •••• 4242")
            self.assertEqual(reveal.status_code, 200, reveal.text)
            self.assertEqual(reveal.json()["pan"], "4242424242424242")
            self.assertEqual(reveal.json()["cvv"], "321")
        finally:
            app.state.engine.dispose()

    def test_openapi_has_no_raw_card_fields(self) -> None:
        schemas = self.app.openapi()["components"]["schemas"]
        properties = schemas["CardAllocationResponse"]["properties"]
        for forbidden in ("pan", "cvv", "secret_ref", "provider_ref"):
            self.assertNotIn(forbidden, properties)
        reveal_properties = schemas["CardRevealResponse"]["properties"]
        self.assertIn("pan", reveal_properties)
        self.assertIn("cvv", reveal_properties)


if __name__ == "__main__":
    unittest.main()
