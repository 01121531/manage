import unittest

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from platform.database import initialize_database
from platform.models import AuditEvent, Device, User


class AuditAppendOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        _, self.session_factory = initialize_database("sqlite+pysqlite:///:memory:")

    def test_audit_events_reject_updates_and_deletes(self) -> None:
        with self.session_factory() as db:
            db.add(
                AuditEvent(
                    tenant_id="tenant-audit",
                    user_id=None,
                    device_id=None,
                    event_type="task.created",
                    entity_type="task",
                    entity_id="task-1",
                    trace_id="trace-1",
                    details_json='{"created":true}',
                )
            )
            db.commit()

        with self.session_factory() as db:
            event = db.scalar(select(AuditEvent))
            assert event is not None
            event.details_json = '{"tampered":true}'
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()
            self.assertEqual(
                db.scalar(select(AuditEvent)).details_json, '{"created":true}'
            )

        with self.session_factory() as db:
            event = db.scalar(select(AuditEvent))
            assert event is not None
            db.delete(event)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()
            self.assertIsNotNone(db.scalar(select(AuditEvent)))

    def test_audit_subjects_must_match_tenant_and_device_owner(self) -> None:
        with self.session_factory() as db:
            user_a = User(
                tenant_id="tenant-a",
                email="user-a@example.test",
                role="operator",
            )
            other_user_a = User(
                tenant_id="tenant-a",
                email="other-user-a@example.test",
                role="operator",
            )
            user_b = User(
                tenant_id="tenant-b",
                email="user-b@example.test",
                role="operator",
            )
            db.add_all((user_a, other_user_a, user_b))
            db.flush()
            device_a = Device(
                tenant_id="tenant-a", user_id=user_a.id, name="device-a"
            )
            other_device_a = Device(
                tenant_id="tenant-a",
                user_id=other_user_a.id,
                name="other-device-a",
            )
            device_b = Device(
                tenant_id="tenant-b", user_id=user_b.id, name="device-b"
            )
            db.add_all((device_a, other_device_a, device_b))
            db.commit()
            bindings = {
                "user_a": user_a.id,
                "device_a": device_a.id,
                "user_b": user_b.id,
                "device_b": device_b.id,
                "other_device_a": other_device_a.id,
            }

        invalid_subjects = (
            (None, bindings["device_a"]),
            (bindings["user_b"], None),
            (bindings["user_b"], bindings["device_b"]),
            (bindings["user_a"], bindings["device_b"]),
            (bindings["user_a"], bindings["other_device_a"]),
        )
        for index, (user_id, device_id) in enumerate(invalid_subjects):
            with self.subTest(user_id=user_id, device_id=device_id):
                with self.session_factory() as db:
                    db.add(
                        AuditEvent(
                            tenant_id="tenant-a",
                            user_id=user_id,
                            device_id=device_id,
                            event_type="security.test",
                            entity_type="test",
                            entity_id=f"invalid-{index}",
                            trace_id=f"invalid-trace-{index}",
                            details_json="{}",
                        )
                    )
                    with self.assertRaisesRegex(
                        IntegrityError, "audit_events subject binding invalid"
                    ):
                        db.commit()

        with self.session_factory() as db:
            db.add(
                AuditEvent(
                    tenant_id="tenant-a",
                    user_id=bindings["user_a"],
                    device_id=bindings["device_a"],
                    event_type="security.test",
                    entity_type="test",
                    entity_id="valid-subject",
                    trace_id="valid-subject-trace",
                    details_json="{}",
                )
            )
            db.commit()

    def test_system_audit_event_without_user_or_device_is_allowed(self) -> None:
        with self.session_factory() as db:
            db.add(
                AuditEvent(
                    tenant_id="tenant-system",
                    user_id=None,
                    device_id=None,
                    event_type="system.test",
                    entity_type="system",
                    entity_id=None,
                    trace_id="system-trace",
                    details_json="{}",
                )
            )
            db.commit()
            self.assertIsNotNone(
                db.scalar(
                    select(AuditEvent).where(AuditEvent.event_type == "system.test")
                )
            )
