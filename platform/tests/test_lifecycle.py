import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from threading import Event
from unittest import mock

from sqlalchemy import func, select

from platform.bootstrap import create_user_with_device
from platform.database import initialize_database
from platform.lifecycle import sweep_expired_lifecycle, transition_task_to_terminal
from platform.mail_worker import run_mail_worker
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    Device,
    Mailbox,
    MailSession,
    OutboxEvent,
    Task,
    UploadJob,
    utc_now,
)
from platform.uploads import Sub2Policy, UnconfiguredSub2Adapter, run_upload_worker


class LifecycleSweepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine, self.session_factory = initialize_database(
            "sqlite+pysqlite:///:memory:"
        )
        self.identity = create_user_with_device(
            self.session_factory,
            tenant_id="tenant-lifecycle",
            email="lifecycle@example.test",
            password="lifecycle-account-password",
            device_name="lifecycle-device",
        )

    def tearDown(self) -> None:
        self.engine.dispose()

    def _add_task_resources(
        self,
        db,
        *,
        suffix: str,
        task_expires_at,
        allocation_expires_at,
        mail_expires_at,
        mail_status: str,
        delivered_code: str | None,
        code_expires_at,
        upload_status: str,
        outbox_status: str,
    ) -> tuple[Task, CardAllocation, MailSession, UploadJob, OutboxEvent]:
        task = Task(
            tenant_id="tenant-lifecycle",
            user_id=self.identity.user_id,
            device_id=self.identity.device_id,
            task_type="card_checkout",
            idempotency_key=f"lifecycle-{suffix}",
            trace_id=f"trace-{suffix}",
            status="created",
            expires_at=task_expires_at,
        )
        card = Card(
            tenant_id="tenant-lifecycle",
            provider_ref=f"provider-{suffix}",
            brand="Visa",
            last4=suffix[-4:].zfill(4),
            secret_ref=f"vault://secret/cards/{suffix}",
        )
        mailbox = Mailbox(
            tenant_id="tenant-lifecycle",
            email_masked=f"{suffix[0]}***@example.test",
            connector_type="fake",
            secret_ref=f"vault://secret/mailboxes/{suffix}",
        )
        db.add_all([task, card, mailbox])
        db.flush()
        allocation = CardAllocation(
            tenant_id=task.tenant_id,
            task_id=task.id,
            user_id=task.user_id,
            device_id=task.device_id,
            card_id=card.id,
            trace_id=task.trace_id,
            status="active",
            expires_at=allocation_expires_at,
        )
        mail_session = MailSession(
            tenant_id=task.tenant_id,
            task_id=task.id,
            user_id=task.user_id,
            device_id=task.device_id,
            mailbox_id=mailbox.id,
            trace_id=task.trace_id,
            status=mail_status,
            delivered_code=delivered_code,
            delivered_at=utc_now() if delivered_code else None,
            code_expires_at=code_expires_at,
            expires_at=mail_expires_at,
        )
        db.add_all([allocation, mail_session])
        db.flush()
        upload = UploadJob(
            tenant_id=task.tenant_id,
            task_id=task.id,
            user_id=task.user_id,
            device_id=task.device_id,
            card_allocation_id=allocation.id,
            idempotency_key=f"upload-{suffix}",
            business_name=f"Business {suffix}",
            trace_id=task.trace_id,
            status=upload_status,
            policy_version="policy-test",
        )
        db.add(upload)
        db.flush()
        outbox = OutboxEvent(
            tenant_id=task.tenant_id,
            event_type="upload.requested",
            aggregate_type="upload_job",
            aggregate_id=upload.id,
            status=outbox_status,
            claimed_at=utc_now() if outbox_status == "processing" else None,
        )
        db.add(outbox)
        db.flush()
        return task, allocation, mail_session, upload, outbox

    def test_sweep_reclaims_expired_tasks_and_uploads_without_http(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            queued = self._add_task_resources(
                db,
                suffix="1001",
                task_expires_at=now - timedelta(seconds=1),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=10),
                mail_status="code_ready",
                delivered_code="482731",
                code_expires_at=now + timedelta(minutes=1),
                upload_status="queued",
                outbox_status="pending",
            )
            queued[2].start_watermark = "connector-watermark-before-timeout"
            queued[2].last_message_hash = "a" * 64
            running = self._add_task_resources(
                db,
                suffix="1002",
                task_expires_at=now - timedelta(seconds=1),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=10),
                mail_status="consumed",
                delivered_code=None,
                code_expires_at=None,
                upload_status="running",
                outbox_status="processing",
            )
            ids = {
                "queued": tuple(item.id for item in queued),
                "running": tuple(item.id for item in running),
            }
            db.commit()

        result = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(result.tasks_expired, 2)
        self.assertEqual(result.card_allocations_expired, 2)
        self.assertEqual(result.mail_sessions_expired, 2)
        self.assertEqual(result.uploads_cancelled, 1)
        self.assertEqual(result.uploads_unknown, 1)

        with self.session_factory() as db:
            for group in ids.values():
                task = db.get(Task, group[0])
                allocation = db.get(CardAllocation, group[1])
                session = db.get(MailSession, group[2])
                self.assertEqual(task.status, "expired")
                self.assertEqual(allocation.status, "expired")
                self.assertIsNotNone(allocation.released_at)
                self.assertEqual(session.status, "expired")
                self.assertIsNone(session.delivered_code)
                self.assertIsNone(session.delivered_at)
                self.assertIsNone(session.code_expires_at)
                self.assertIsNone(session.start_watermark)
                self.assertIsNone(session.last_message_hash)

            queued_job = db.get(UploadJob, ids["queued"][3])
            queued_outbox = db.get(OutboxEvent, ids["queued"][4])
            self.assertEqual(queued_job.status, "cancelled")
            self.assertEqual(queued_job.error_code, "task_expired")
            self.assertEqual(queued_outbox.status, "processed")
            self.assertEqual(queued_outbox.last_error_code, "task_expired")

            running_job = db.get(UploadJob, ids["running"][3])
            running_outbox = db.get(OutboxEvent, ids["running"][4])
            self.assertEqual(running_job.status, "unknown")
            self.assertEqual(running_job.error_code, "external_unknown")
            self.assertEqual(running_outbox.status, "processed")
            self.assertEqual(running_outbox.last_error_code, "external_unknown")

            events = list(db.scalars(select(AuditEvent)))
            event_types = [event.event_type for event in events]
            self.assertEqual(event_types.count("task.expired"), 2)
            self.assertEqual(event_types.count("card.expired"), 2)
            self.assertEqual(event_types.count("mail_session.expired"), 2)
            self.assertEqual(event_types.count("upload.cancelled"), 1)
            self.assertEqual(event_types.count("upload.unknown"), 1)
            serialized = json.dumps([event.details_json for event in events])
            self.assertNotIn("482731", serialized)
            audit_count = len(events)

        replay = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(replay.total, 0)
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(AuditEvent)), audit_count)

    def test_expired_card_lease_compensates_its_open_task(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            resources = self._add_task_resources(
                db,
                suffix="2001",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now - timedelta(seconds=1),
                mail_expires_at=now + timedelta(minutes=10),
                mail_status="waiting",
                delivered_code=None,
                code_expires_at=None,
                upload_status="queued",
                outbox_status="pending",
            )
            ids = tuple(item.id for item in resources)
            db.commit()

        result = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(result.tasks_cancelled, 1)
        self.assertEqual(result.card_allocations_expired, 1)
        self.assertEqual(result.mail_sessions_expired, 1)
        self.assertEqual(result.uploads_cancelled, 1)
        with self.session_factory() as db:
            self.assertEqual(db.get(Task, ids[0]).status, "cancelled")
            self.assertEqual(db.get(CardAllocation, ids[1]).status, "expired")
            self.assertEqual(db.get(MailSession, ids[2]).status, "expired")
            upload = db.get(UploadJob, ids[3])
            self.assertEqual(upload.status, "cancelled")
            self.assertEqual(upload.error_code, "card_lease_invalid")
            outbox = db.get(OutboxEvent, ids[4])
            self.assertEqual(outbox.status, "processed")
            self.assertEqual(outbox.last_error_code, "card_lease_invalid")

    def test_sweep_expires_mail_code_and_session_independently(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            code_resources = self._add_task_resources(
                db,
                suffix="3001",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=5),
                mail_status="code_ready",
                delivered_code="918273",
                code_expires_at=now - timedelta(seconds=1),
                upload_status="succeeded",
                outbox_status="processed",
            )
            session_resources = self._add_task_resources(
                db,
                suffix="3002",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now - timedelta(seconds=1),
                mail_status="code_ready",
                delivered_code="827364",
                code_expires_at=now + timedelta(minutes=1),
                upload_status="succeeded",
                outbox_status="processed",
            )
            code_task_id, code_session_id = code_resources[0].id, code_resources[2].id
            session_task_id, session_id = session_resources[0].id, session_resources[2].id
            db.commit()

        result = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(result.mail_codes_expired, 1)
        self.assertEqual(result.mail_sessions_expired, 1)
        with self.session_factory() as db:
            code_session = db.get(MailSession, code_session_id)
            expired_session = db.get(MailSession, session_id)
            self.assertEqual(code_session.status, "waiting")
            self.assertEqual(expired_session.status, "expired")
            for session in (code_session, expired_session):
                self.assertIsNone(session.delivered_code)
                self.assertIsNone(session.delivered_at)
                self.assertIsNone(session.code_expires_at)
            self.assertEqual(db.get(Task, code_task_id).status, "created")
            self.assertEqual(db.get(Task, session_task_id).status, "created")
            events = list(db.scalars(select(AuditEvent)))
            self.assertEqual(
                {event.event_type for event in events},
                {"mail_session.code_expired", "mail_session.expired"},
            )
            serialized = json.dumps([event.details_json for event in events])
            self.assertNotIn("918273", serialized)
            self.assertNotIn("827364", serialized)

    def test_completed_transition_releases_active_resources_once(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            resources = self._add_task_resources(
                db,
                suffix="completed",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=5),
                mail_status="consumed",
                delivered_code="246810",
                code_expires_at=now + timedelta(minutes=1),
                upload_status="succeeded",
                outbox_status="processed",
            )
            ids = tuple(item.id for item in resources)
            resources[2].start_watermark = "connector-watermark-before-completion"
            resources[2].last_message_hash = "b" * 64
            first = transition_task_to_terminal(
                resources[0],
                db,
                now=now,
                task_status="completed",
                card_status="released",
                mail_status="revoked",
                release_reason="upload_succeeded",
                actor_user_id="worker-sub2",
                actor_device_id=None,
            )
            db.commit()

        self.assertEqual(first.tasks_completed, 1)
        self.assertEqual(first.tasks_cancelled, 0)
        self.assertEqual(first.card_allocations_released, 1)
        self.assertEqual(first.mail_sessions_expired, 1)
        with self.session_factory() as db:
            task = db.get(Task, ids[0])
            allocation = db.get(CardAllocation, ids[1])
            session = db.get(MailSession, ids[2])
            upload = db.get(UploadJob, ids[3])
            self.assertEqual(task.status, "completed")
            self.assertIsNotNone(task.closed_at)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertIsNone(session.delivered_at)
            self.assertIsNone(session.code_expires_at)
            self.assertIsNone(session.start_watermark)
            self.assertIsNone(session.last_message_hash)
            self.assertEqual(upload.status, "succeeded")
            events = list(db.scalars(select(AuditEvent)))
            event_types = [event.event_type for event in events]
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("task.cancelled"), 0)
            self.assertEqual(event_types.count("card.released"), 1)
            self.assertEqual(event_types.count("mail_session.revoked"), 1)
            self.assertNotIn("246810", " ".join(event.details_json for event in events))
            replay = transition_task_to_terminal(
                task,
                db,
                now=now + timedelta(seconds=1),
                task_status="completed",
                card_status="released",
                mail_status="revoked",
                release_reason="upload_succeeded",
                actor_user_id="worker-sub2",
                actor_device_id=None,
            )
            db.commit()
        self.assertEqual(replay.total, 0)
        with self.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event_type == "task.completed")
                ),
                1,
            )

    def test_losing_terminal_transition_recovers_from_persisted_winner_once(self) -> None:
        now = utc_now()
        cases = (
            (
                "completed",
                "expired",
                "released",
                "revoked",
                "card.released",
                "mail_session.revoked",
            ),
            (
                "expired",
                "completed",
                "expired",
                "expired",
                "card.expired",
                "mail_session.expired",
            ),
        )
        for (
            winner_status,
            loser_status,
            expected_card_status,
            expected_mail_status,
            expected_card_event,
            expected_mail_event,
        ) in cases:
            with self.subTest(winner=winner_status, loser=loser_status):
                with self.session_factory() as db:
                    resources = self._add_task_resources(
                        db,
                        suffix=f"winner-{winner_status}",
                        task_expires_at=now + timedelta(minutes=30),
                        allocation_expires_at=now + timedelta(minutes=10),
                        mail_expires_at=now + timedelta(minutes=5),
                        mail_status="code_ready",
                        delivered_code="975310",
                        code_expires_at=now + timedelta(minutes=1),
                        upload_status="queued",
                        outbox_status="pending",
                    )
                    task = resources[0]
                    task.status = winner_status
                    task.closed_at = now
                    ids = tuple(item.id for item in resources)
                    db.commit()

                    recovered = transition_task_to_terminal(
                        task,
                        db,
                        now=now + timedelta(seconds=1),
                        task_status=loser_status,
                        card_status=(
                            "expired" if loser_status == "expired" else "released"
                        ),
                        mail_status=(
                            "expired" if loser_status == "expired" else "revoked"
                        ),
                        release_reason=f"losing_{loser_status}_transition",
                        actor_user_id="worker-race-loser",
                        actor_device_id=None,
                        running_upload_status="unknown",
                        upload_error_code=(
                            "task_expired"
                            if loser_status == "expired"
                            else "upload_succeeded"
                        ),
                        finalize_upload_outbox=True,
                    )
                    db.commit()

                    replay = transition_task_to_terminal(
                        task,
                        db,
                        now=now + timedelta(seconds=2),
                        task_status=loser_status,
                        card_status=(
                            "expired" if loser_status == "expired" else "released"
                        ),
                        mail_status=(
                            "expired" if loser_status == "expired" else "revoked"
                        ),
                        release_reason=f"losing_{loser_status}_transition",
                        actor_user_id="worker-race-loser",
                        actor_device_id=None,
                        finalize_upload_outbox=True,
                    )
                    db.commit()

                self.assertEqual(recovered.tasks_completed, 0)
                self.assertEqual(recovered.tasks_expired, 0)
                self.assertEqual(replay.total, 0)
                swept = sweep_expired_lifecycle(
                    self.session_factory, now=now + timedelta(seconds=3)
                )
                self.assertEqual(swept.total, 0)

                with self.session_factory() as db:
                    task = db.get(Task, ids[0])
                    allocation = db.get(CardAllocation, ids[1])
                    session = db.get(MailSession, ids[2])
                    upload = db.get(UploadJob, ids[3])
                    outbox = db.get(OutboxEvent, ids[4])
                    events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id.in_(ids[1:4])
                            )
                        )
                    )
                self.assertEqual(task.status, winner_status)
                self.assertEqual(allocation.status, expected_card_status)
                self.assertEqual(session.status, expected_mail_status)
                self.assertIsNone(session.delivered_code)
                self.assertEqual(upload.status, "cancelled")
                self.assertEqual(outbox.status, "processed")
                self.assertEqual(
                    sorted(event.event_type for event in events),
                    sorted(
                        (
                            expected_card_event,
                            expected_mail_event,
                            "upload.cancelled",
                        )
                    ),
                )
                for event in events:
                    self.assertIn("terminal_task_recovery", event.details_json)

    def test_sweep_repairs_terminal_task_resource_residue_once(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            resources = self._add_task_resources(
                db,
                suffix="terminal-residue",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=5),
                mail_status="code_ready",
                delivered_code="135790",
                code_expires_at=now + timedelta(minutes=1),
                upload_status="queued",
                outbox_status="pending",
            )
            resources[0].status = "closed"
            resources[0].closed_at = now
            ids = tuple(item.id for item in resources)
            db.commit()

        repaired = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(repaired.tasks_expired, 0)
        self.assertEqual(repaired.card_allocations_released, 1)
        self.assertEqual(repaired.mail_sessions_expired, 1)
        self.assertEqual(repaired.uploads_cancelled, 1)

        replay = sweep_expired_lifecycle(
            self.session_factory, now=now + timedelta(seconds=1)
        )
        self.assertEqual(replay.total, 0)
        with self.session_factory() as db:
            allocation = db.get(CardAllocation, ids[1])
            session = db.get(MailSession, ids[2])
            upload = db.get(UploadJob, ids[3])
            outbox = db.get(OutboxEvent, ids[4])
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertEqual(upload.status, "cancelled")
            self.assertEqual(outbox.status, "processed")
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_((ids[1], ids[2], ids[3]))
                    )
                )
            )
            self.assertEqual(
                sorted(event.event_type for event in events),
                ["card.released", "mail_session.revoked", "upload.cancelled"],
            )
            self.assertNotIn("135790", " ".join(event.details_json for event in events))

    def test_sweep_repairs_revoked_device_resources_before_ttl(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            resources = self._add_task_resources(
                db,
                suffix="revoked-principal",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=20),
                mail_expires_at=now + timedelta(minutes=10),
                mail_status="code_ready",
                delivered_code="246810",
                code_expires_at=now + timedelta(minutes=5),
                upload_status="queued",
                outbox_status="pending",
            )
            device = db.get(Device, self.identity.device_id)
            assert device is not None
            device.revoked_at = now
            ids = tuple(item.id for item in resources)
            db.commit()

        repaired = sweep_expired_lifecycle(self.session_factory, now=now)

        self.assertEqual(repaired.tasks_cancelled, 1)
        self.assertEqual(repaired.card_allocations_released, 1)
        self.assertEqual(repaired.mail_sessions_expired, 1)
        self.assertEqual(repaired.uploads_cancelled, 1)
        with self.session_factory() as db:
            task = db.get(Task, ids[0])
            allocation = db.get(CardAllocation, ids[1])
            session = db.get(MailSession, ids[2])
            upload = db.get(UploadJob, ids[3])
            outbox = db.get(OutboxEvent, ids[4])
            self.assertEqual(task.status, "cancelled")
            self.assertEqual(allocation.status, "released")
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertEqual(upload.status, "cancelled")
            self.assertEqual(outbox.status, "processed")

    def test_sweep_marks_processed_cancel_pending_residue_unknown_once(self) -> None:
        now = utc_now()
        with self.session_factory() as db:
            resources = self._add_task_resources(
                db,
                suffix="cancel-pending-residue",
                task_expires_at=now + timedelta(minutes=30),
                allocation_expires_at=now + timedelta(minutes=10),
                mail_expires_at=now + timedelta(minutes=5),
                mail_status="revoked",
                delivered_code=None,
                code_expires_at=None,
                upload_status="cancel_pending",
                outbox_status="processed",
            )
            task, allocation, _mail_session, upload, outbox = resources
            task.status = "closed"
            task.closed_at = now
            allocation.status = "released"
            allocation.released_at = now
            outbox.processed_at = now
            ids = tuple(item.id for item in resources)
            db.commit()

        repaired = sweep_expired_lifecycle(self.session_factory, now=now)
        self.assertEqual(repaired.uploads_unknown, 1)
        self.assertEqual(repaired.total, 1)

        replay = sweep_expired_lifecycle(
            self.session_factory, now=now + timedelta(seconds=1)
        )
        self.assertEqual(replay.total, 0)
        with self.session_factory() as db:
            upload = db.get(UploadJob, ids[3])
            outbox = db.get(OutboxEvent, ids[4])
            unknown_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == upload.id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
        self.assertEqual(upload.status, "unknown")
        self.assertEqual(upload.error_code, "external_unknown")
        self.assertEqual(outbox.status, "processed")
        self.assertEqual(len(unknown_audits), 1)

    def test_concurrent_sweeps_emit_one_terminal_transition(self) -> None:
        self.engine.dispose()
        with tempfile.TemporaryDirectory(prefix="lifecycle-sweep-") as directory:
            database_path = Path(directory) / "lifecycle.db"
            engine, session_factory = initialize_database(
                f"sqlite+pysqlite:///{database_path.as_posix()}"
            )
            identity = create_user_with_device(
                session_factory,
                tenant_id="tenant-concurrent-lifecycle",
                email="concurrent-lifecycle@example.test",
                password="concurrent-lifecycle-password",
                device_name="concurrent-lifecycle-device",
            )
            now = utc_now()
            with session_factory() as db:
                task = Task(
                    tenant_id="tenant-concurrent-lifecycle",
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    task_type="card_checkout",
                    idempotency_key="concurrent-lifecycle-task",
                    trace_id="concurrent-lifecycle-trace",
                    status="created",
                    expires_at=now - timedelta(seconds=1),
                )
                db.add(task)
                db.commit()
                task_id = task.id

            barrier = Barrier(2)

            def sweep() -> int:
                barrier.wait(timeout=5)
                return sweep_expired_lifecycle(session_factory, now=now).tasks_expired

            with ThreadPoolExecutor(max_workers=2) as executor:
                counts = list(executor.map(lambda _: sweep(), range(2)))
            self.assertEqual(sum(counts), 1)
            with session_factory() as db:
                self.assertEqual(db.get(Task, task_id).status, "expired")
                self.assertEqual(
                    db.scalar(
                        select(func.count())
                        .select_from(AuditEvent)
                        .where(AuditEvent.event_type == "task.expired")
                    ),
                    1,
                )
            engine.dispose()

    def test_competing_terminal_transitions_emit_exactly_one_terminal_event(self) -> None:
        self.engine.dispose()
        with tempfile.TemporaryDirectory(prefix="lifecycle-terminal-race-") as directory:
            database_path = Path(directory) / "lifecycle.db"
            engine, session_factory = initialize_database(
                f"sqlite+pysqlite:///{database_path.as_posix()}"
            )
            identity = create_user_with_device(
                session_factory,
                tenant_id="tenant-terminal-race",
                email="terminal-race@example.test",
                password="terminal-race-password",
                device_name="terminal-race-device",
            )
            with session_factory() as db:
                task = Task(
                    tenant_id="tenant-terminal-race",
                    user_id=identity.user_id,
                    device_id=identity.device_id,
                    task_type="card_checkout",
                    idempotency_key="terminal-race-task",
                    trace_id="terminal-race-trace",
                    status="created",
                    expires_at=utc_now() + timedelta(minutes=5),
                )
                db.add(task)
                db.commit()
                task_id = task.id

            barrier = Barrier(2)

            def transition(status: str) -> None:
                with session_factory() as db:
                    task = db.get(Task, task_id)
                    assert task is not None
                    barrier.wait(timeout=5)
                    transition_task_to_terminal(
                        task,
                        db,
                        now=utc_now(),
                        task_status=status,
                        card_status="released",
                        mail_status="revoked",
                        release_reason=f"terminal_race_{status}",
                        actor_user_id=identity.user_id,
                        actor_device_id=identity.device_id,
                    )
                    db.commit()

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(transition, status)
                    for status in ("closed", "completed")
                ]
                for future in futures:
                    future.result(timeout=10)

            with session_factory() as db:
                task = db.get(Task, task_id)
                terminal_events = list(
                    db.scalars(
                        select(AuditEvent.event_type).where(
                            AuditEvent.entity_id == task_id,
                            AuditEvent.event_type.in_(("task.closed", "task.completed")),
                        )
                    )
                )
            self.assertIn(task.status, {"closed", "completed"})
            self.assertEqual(terminal_events, [f"task.{task.status}"])
            engine.dispose()

    def test_both_worker_loops_run_the_lifecycle_sweep(self) -> None:
        mail_stop = Event()

        def stop_mail(*_args, **_kwargs):
            mail_stop.set()
            return {}

        with mock.patch(
            "platform.mail_worker.sweep_expired_lifecycle"
        ) as mail_sweep, mock.patch(
            "platform.mail_worker.process_mail_sessions", side_effect=stop_mail
        ):
            run_mail_worker(
                self.session_factory,
                connectors={},
                stop_event=mail_stop,
                poll_seconds=0.01,
            )
        mail_sweep.assert_called_once_with(self.session_factory)

        upload_stop = Event()

        def stop_upload(*_args, **_kwargs):
            upload_stop.set()
            return 0

        with mock.patch(
            "platform.uploads.sweep_expired_lifecycle"
        ) as upload_sweep, mock.patch(
            "platform.uploads.process_queued_uploads", side_effect=stop_upload
        ):
            run_upload_worker(
                self.session_factory,
                adapter=UnconfiguredSub2Adapter(),
                policy=Sub2Policy(
                    version="policy-test",
                    proxy_ref=None,
                    group_id=49,
                    concurrency=1,
                    credential_ref=None,
                ),
                stop_event=upload_stop,
                poll_seconds=0.01,
            )
        upload_sweep.assert_called_once_with(self.session_factory)


if __name__ == "__main__":
    unittest.main()
