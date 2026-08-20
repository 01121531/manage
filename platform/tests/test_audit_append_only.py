import unittest

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from platform.database import initialize_database
from platform.models import AuditEvent


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
            self.assertEqual(db.scalar(select(AuditEvent)).details_json, '{"created":true}')

        with self.session_factory() as db:
            event = db.scalar(select(AuditEvent))
            assert event is not None
            db.delete(event)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()
            self.assertIsNotNone(db.scalar(select(AuditEvent)))

