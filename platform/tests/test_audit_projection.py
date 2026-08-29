from datetime import datetime, timedelta, timezone
import json
import unittest

from platform.audit import project_audit_event, safe_audit_details
from platform.models import AuditEvent


class AuditProjectionTests(unittest.TestCase):
    def _event(self, *, details_json: str) -> AuditEvent:
        return AuditEvent(
            id="event-1",
            tenant_id="tenant-a",
            user_id="user-1",
            device_id="device-1",
            actor_id="Bearer LEGACY_ACTOR_SECRET",
            event_type="legacy.audit",
            action="Authorization=LEGACY_ACTION_SECRET",
            result="success",
            entity_type="task",
            entity_id="reference 4111111111111111",
            trace_id="trace-1",
            ip_address="203.0.113.8 Authorization=LEGACY_IP_SECRET",
            user_agent="LegacyAgent/1.0 vault://mail/prod",
            policy_version="vault://policy/private",
            details_json=details_json,
            created_at=datetime(
                2026,
                8,
                24,
                20,
                30,
                15,
                1234,
                tzinfo=timezone(timedelta(hours=8)),
            ),
        )

    def test_project_audit_event_has_fixed_schema_and_defensive_redaction(self) -> None:
        event = self._event(
            details_json=(
                '{"password":"hidden","safe":"kept",'
                '"note":"Bearer DETAILS_SECRET",'
                '"card":"4111111111111111",'
                '"nested":{"vault://private":"value"},'
                '"not_a_number":NaN,"positive_infinity":Infinity,'
                '"negative_infinity":-Infinity}'
            )
        )

        projected = project_audit_event(event)

        self.assertEqual(
            set(projected),
            {
                "schema_version",
                "redaction_version",
                "id",
                "tenant_id",
                "created_at",
                "actor_id",
                "user_id",
                "device_id",
                "event_type",
                "action",
                "result",
                "entity_type",
                "entity_id",
                "trace_id",
                "policy_version",
                "ip_address",
                "user_agent",
                "details",
            },
        )
        self.assertEqual(projected["schema_version"], "audit-event-archive.v1")
        self.assertEqual(projected["redaction_version"], "audit-read.v1")
        self.assertEqual(projected["created_at"], "2026-08-24T12:30:15.001234Z")
        self.assertEqual(projected["actor_id"], "[REDACTED]")
        self.assertEqual(projected["action"], "[REDACTED]")
        self.assertEqual(projected["entity_id"], "reference [REDACTED_CARD]")
        self.assertEqual(projected["policy_version"], "[REDACTED]")
        self.assertIsNone(projected["ip_address"])
        self.assertEqual(projected["user_agent"], "[REDACTED]")
        self.assertEqual(
            projected["details"],
            {
                "safe": "kept",
                "note": "[REDACTED]",
                "card": "[REDACTED_CARD]",
                "nested": {"[REDACTED]": "value"},
                "not_a_number": None,
                "positive_infinity": None,
                "negative_infinity": None,
            },
        )
        serialized = json.dumps(projected, allow_nan=False, sort_keys=True)
        for forbidden in (
            "LEGACY_ACTOR_SECRET",
            "LEGACY_ACTION_SECRET",
            "LEGACY_IP_SECRET",
            "DETAILS_SECRET",
            "vault://",
            "4111111111111111",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_safe_audit_details_rejects_malformed_and_non_object_history(self) -> None:
        for details_json in ("{", "[]", "null", "NaN"):
            with self.subTest(details_json=details_json):
                self.assertEqual(
                    safe_audit_details(self._event(details_json=details_json)),
                    {},
                )

    def test_project_audit_event_treats_naive_database_time_as_utc(self) -> None:
        event = self._event(details_json="{}")
        event.created_at = datetime(2026, 8, 24, 1, 2, 3, 4)
        event.actor_id = None
        event.user_agent = "Safe Agent/1.0"
        event.ip_address = "2001:0db8:0000:0000:0000:0000:0000:0001"

        projected = project_audit_event(event)

        self.assertEqual(projected["created_at"], "2026-08-24T01:02:03.000004Z")
        self.assertIsNone(projected["actor_id"])
        self.assertEqual(projected["user_agent"], "Safe Agent/1.0")
        self.assertEqual(projected["ip_address"], "2001:db8::1")

    def test_uuid_segments_are_not_misclassified_as_luhn_card_numbers(self) -> None:
        identifier = "f4959613-7556-4429-bd45-fee9439e9b7b"
        event = self._event(
            details_json=json.dumps(
                {
                    "resource_id": identifier,
                    "card": "4111111111111111",
                }
            )
        )
        event.id = identifier
        event.user_id = identifier
        event.entity_id = identifier
        event.trace_id = identifier
        event.user_agent = f"SafeAgent/1.0 resource/{identifier}"

        projected = project_audit_event(event)

        for field in ("id", "user_id", "entity_id", "trace_id"):
            with self.subTest(field=field):
                self.assertEqual(projected[field], identifier)
        self.assertEqual(projected["details"]["resource_id"], identifier)
        self.assertEqual(
            projected["user_agent"], f"SafeAgent/1.0 resource/{identifier}"
        )
        self.assertEqual(projected["details"]["card"], "[REDACTED_CARD]")

    def test_projected_mapping_is_idempotent(self) -> None:
        first = project_audit_event(
            self._event(
                details_json=(
                    '{"note":"Bearer MAPPING_SECRET",'
                    '"not_a_number":NaN,"safe":"kept"}'
                )
            )
        )

        self.assertEqual(project_audit_event(first), first)

        decrypted: dict[str, object] = dict(first)
        decrypted["created_at"] = "2026-08-24T20:30:15.001234+08:00"
        decrypted["entity_id"] = "vault://archive/private"
        decrypted["ip_address"] = "203.0.113.9 Bearer MAPPING_IP_SECRET"
        decrypted["user_agent"] = "Bearer MAPPING_UA_SECRET"
        decrypted["details"] = {
            "safe": "kept",
            "note": "Bearer MAPPING_DETAILS_SECRET",
            "not_a_number": float("nan"),
        }
        second = project_audit_event(decrypted)

        self.assertEqual(project_audit_event(second), second)
        self.assertEqual(len(second), 18)
        self.assertEqual(second["created_at"], "2026-08-24T12:30:15.001234Z")
        self.assertEqual(second["entity_id"], "[REDACTED]")
        self.assertIsNone(second["ip_address"])
        self.assertEqual(second["user_agent"], "[REDACTED]")
        self.assertEqual(second["details"]["note"], "[REDACTED]")
        self.assertEqual(second["details"]["not_a_number"], None)
        serialized = json.dumps(second, allow_nan=False, sort_keys=True)
        for forbidden in (
            "MAPPING_IP_SECRET",
            "MAPPING_UA_SECRET",
            "MAPPING_DETAILS_SECRET",
            "vault://",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
