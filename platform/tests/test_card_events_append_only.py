import unittest

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from platform.card_events import record_card_event, safe_card_event_state
from platform.database import initialize_database
from platform.models import Card, CardEvent


class CardEventAppendOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine, self.SessionLocal = initialize_database(
            "sqlite+pysqlite:///:memory:"
        )

    def tearDown(self) -> None:
        self.engine.dispose()

    def test_card_events_are_masked_tenant_bound_and_append_only(self) -> None:
        with self.SessionLocal() as db:
            card = Card(
                id="card-event-card",
                tenant_id="tenant-a",
                provider_ref="provider-event",
                brand="VISA",
                last4="4242",
                secret_ref="vault://secret/cards/event",
            )
            db.add(card)
            db.flush()
            event = record_card_event(
                db,
                tenant_id="tenant-a",
                card_id=card.id,
                actor_id="actor-a",
                action="card.created",
                trace_id="00000000-0000-0000-0000-000000000123",
                before_masked={},
                after_masked={
                    "card_masked": "**** **** **** 4242",
                    "brand": "VISA",
                    "card_status": "available",
                    "allocation_status": "released",
                    "revealed": True,
                    "fields": ["pan", "expiry", "cvv2", "pan"],
                    "pan": "4111111111111111",
                    "cvv2": "123",
                    "cvc2": "456",
                    "verification_value": "987",
                    "account_number": "5555555555554444",
                    "nested": {"cvv": "321", "secret": "must-never-persist"},
                    "secret_ref": card.secret_ref,
                },
            )
            db.commit()
            db.refresh(event)
            state = safe_card_event_state(event.after_masked)
            self.assertEqual(
                state,
                {
                    "card_masked": "**** **** **** 4242",
                    "brand": "VISA",
                    "card_status": "available",
                    "allocation_status": "released",
                    "revealed": True,
                    "fields": ["pan", "expiry"],
                },
            )
            persisted = event.after_masked.lower()
            for forbidden in (
                "4111111111111111",
                "5555555555554444",
                "must-never-persist",
                "cvv2",
                "cvc2",
                "verification_value",
                "account_number",
                "secret_ref",
                "nested",
            ):
                self.assertNotIn(forbidden, persisted)

            legacy_state = safe_card_event_state(
                '{"card_status":"available","cvv2":"123",'
                '"verification_value":"987","brand":"4111111111111111",'
                '"card_masked":"4111111111111111","revealed":1,'
                '"nested":{"pan":"4111111111111111"}}'
            )
            self.assertEqual(legacy_state, {"card_status": "available"})

        for statement in (
            "UPDATE card_events SET action = 'changed' WHERE id = :event_id",
            "DELETE FROM card_events WHERE id = :event_id",
        ):
            with self.assertRaises(IntegrityError):
                with self.engine.begin() as connection:
                    connection.execute(text(statement), {"event_id": event.id})

        with self.SessionLocal() as db:
            db.add(
                CardEvent(
                    tenant_id="tenant-b",
                    card_id="card-event-card",
                    actor_id="actor-b",
                    action="card.created",
                    before_masked="{}",
                    after_masked="{}",
                    trace_id="00000000-0000-0000-0000-000000000124",
                )
            )
            with self.assertRaises(IntegrityError):
                db.commit()


if __name__ == "__main__":
    unittest.main()
