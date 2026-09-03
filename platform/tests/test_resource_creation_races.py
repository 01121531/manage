import asyncio
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from unittest.mock import patch

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from platform.api.v1 import routes
from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.mail_connectors import MailboxAccess
from platform.models import (
    AuditEvent,
    Card,
    CardAllocation,
    Device,
    MailSession,
    Mailbox,
    OutboxEvent,
    Task,
    UploadJob,
    User,
    utc_now,
)


class BlockingWatermarkConnector:
    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()

    def watermark_at(
        self, mailbox: MailboxAccess, task_started_at: datetime
    ) -> str:
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("watermark test release timed out")
        return "1"

    def find_code_after(self, mailbox: MailboxAccess, watermark: str | None):
        return None


class ResourceCreationRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="resource-create-race-")
        database_path = Path(self.directory.name) / "platform.db"
        self.connector = BlockingWatermarkConnector()
        self.app = create_app(
            Settings(
                environment="test",
                database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                jwt_hmac_secret="resource-create-race-test-secret",
                sub2_policy_version="race-v1",
            ),
            mail_connectors={"fake": self.connector},
        )
        with self.app.state.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        self.password = "resource-create-race-password"
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-resource-race",
            email="resource-race@example.test",
            password=self.password,
            device_name="resource-race-device",
        )
        with self.app.state.session_factory() as db:
            db.add_all(
                [
                    Mailbox(
                        tenant_id="tenant-resource-race",
                        email_masked="r***@example.test",
                        connector_type="fake",
                        task_type="card_checkout",
                        secret_ref="vault://mailboxes/resource-race",
                    ),
                    Card(
                        tenant_id="tenant-resource-race",
                        provider_ref="resource-race-card",
                        brand="VISA",
                        last4="1111",
                        secret_ref="vault://cards/resource-race",
                    ),
                ]
            )
            db.commit()
        self.token = self.login()
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self) -> None:
        self.connector.release.set()
        self.app.state.engine.dispose()
        self.directory.cleanup()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def login(self, *, device_id: str | None = None) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-resource-race",
                "email": "resource-race@example.test",
                "password": self.password,
                "device_id": device_id or self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    def create_task(self, key: str) -> str:
        response = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": key},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def close_task(self, task_id: str) -> httpx.Response:
        return self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.headers
        )

    def assert_no_success_side_effects(
        self, task_id: str, *, resource_type: type, event_type: str
    ) -> None:
        with self.app.state.session_factory() as db:
            resource_count = db.scalar(
                select(func.count()).select_from(resource_type).where(
                    resource_type.task_id == task_id
                )
            )
            audit_count = db.scalar(
                select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.event_type == event_type,
                    AuditEvent.details_json.contains(task_id),
                )
            )
            self.assertEqual(resource_count, 0)
            self.assertEqual(audit_count, 0)

    def test_same_device_concurrent_task_replay_creates_one_task_and_audit(self) -> None:
        barrier = Barrier(2)

        def create() -> httpx.Response:
            barrier.wait(timeout=5)
            return self.request(
                "POST",
                "/api/v1/tasks",
                headers=self.headers,
                json={"type": "card_checkout", "idempotency_key": "same-device-race"},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(lambda _: create(), range(2)))
        self.assertEqual(sorted(response.status_code for response in responses), [200, 201])
        self.assertEqual(len({response.json()["id"] for response in responses}), 1)
        task_id = responses[0].json()["id"]
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(Task).where(
                        Task.idempotency_key == "same-device-race"
                    )
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.entity_id == task_id,
                        AuditEvent.event_type == "task.created",
                    )
                ),
                1,
            )

    def test_task_idempotent_replay_returns_status_after_concurrent_close(
        self,
    ) -> None:
        task_id = self.create_task("task-replay-close")
        entered = Event()
        release = Event()
        original_find = routes._find_idempotent_task
        blocked = False

        def block_after_stale_task_read(db, principal, idempotency_key):
            nonlocal blocked
            task = original_find(db, principal, idempotency_key)
            if not blocked and task is not None and task.id == task_id:
                blocked = True
                db.commit()
                entered.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("task replay release timed out")
            return task

        with patch(
            "platform.api.v1.routes._find_idempotent_task",
            side_effect=block_after_stale_task_read,
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    "/api/v1/tasks",
                    headers=self.headers,
                    json={
                        "type": "card_checkout",
                        "idempotency_key": "task-replay-close",
                    },
                )
                self.assertTrue(entered.wait(timeout=5))
                closed = self.close_task(task_id)
                self.assertEqual(closed.status_code, 200, closed.text)
                release.set()
                replay = future.result(timeout=10)

        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "closed")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "closed")
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(Task).where(Task.id == task_id)
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.entity_id == task_id,
                        AuditEvent.event_type == "task.created",
                    )
                ),
                1,
            )

    def test_active_task_blocks_a_fresh_key_until_it_is_terminal_or_expired(self) -> None:
        first = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": "active-task-first"},
        )
        replay = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": "active-task-first"},
        )
        blocked = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": "active-task-second"},
        )

        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], first.json()["id"])
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "active_task_exists")
        for private_value in (first.json()["id"], first.json()["trace_id"]):
            self.assertNotIn(private_value, blocked.text)

        closed = self.close_task(first.json()["id"])
        self.assertEqual(closed.status_code, 200, closed.text)
        replacement = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": "active-task-second"},
        )
        self.assertEqual(replacement.status_code, 201, replacement.text)

        with self.app.state.session_factory() as db:
            replacement_task = db.get(Task, replacement.json()["id"])
            replacement_task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()
        after_expiry = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.headers,
            json={"type": "card_checkout", "idempotency_key": "active-task-third"},
        )
        self.assertEqual(after_expiry.status_code, 201, after_expiry.text)

    def test_concurrent_fresh_task_keys_create_only_one_active_task(self) -> None:
        barrier = Barrier(2)

        def create(key: str) -> httpx.Response:
            barrier.wait(timeout=5)
            return self.request(
                "POST",
                "/api/v1/tasks",
                headers=self.headers,
                json={"type": "card_checkout", "idempotency_key": key},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(create, key)
                for key in ("active-task-race-a", "active-task-race-b")
            ]
            responses = [future.result(timeout=10) for future in futures]

        self.assertEqual(sorted(response.status_code for response in responses), [201, 409])
        conflict = next(response for response in responses if response.status_code == 409)
        self.assertEqual(conflict.json()["error"]["code"], "active_task_exists")
        with self.app.state.session_factory() as db:
            tasks = list(db.scalars(select(Task)))
            created_events = list(
                db.scalars(
                    select(AuditEvent).where(AuditEvent.event_type == "task.created")
                )
            )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(len(created_events), 1)

    def test_cross_device_concurrent_same_task_key_has_one_safe_conflict(self) -> None:
        with self.app.state.session_factory() as db:
            device_b = Device(
                tenant_id="tenant-resource-race",
                user_id=self.identity.user_id,
                name="resource-race-device-b",
            )
            db.add(device_b)
            db.commit()
            device_b_id = device_b.id
        device_b_headers = {"Authorization": f"Bearer {self.login(device_id=device_b_id)}"}
        barrier = Barrier(2)

        def create(headers: dict[str, str]) -> httpx.Response:
            barrier.wait(timeout=5)
            return self.request(
                "POST",
                "/api/v1/tasks",
                headers=headers,
                json={"type": "card_checkout", "idempotency_key": "cross-device-race"},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(create, headers)
                for headers in (self.headers, device_b_headers)
            ]
            responses = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(response.status_code for response in responses), [201, 409])
        created = next(response for response in responses if response.status_code == 201)
        conflict = next(response for response in responses if response.status_code == 409)
        self.assertEqual(
            conflict.json()["error"]["code"], "active_task_exists"
        )
        self.assertNotIn(created.json()["id"], conflict.text)
        with self.app.state.session_factory() as db:
            tasks = list(
                db.scalars(
                    select(Task).where(Task.idempotency_key == "cross-device-race")
                )
            )
            events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id.in_(task.id for task in tasks),
                        AuditEvent.event_type == "task.created",
                    )
                )
            )
        self.assertEqual(len(tasks), 1)
        self.assertIn(tasks[0].device_id, {self.identity.device_id, device_b_id})
        self.assertEqual(len(events), 1)

    def test_same_device_concurrent_upload_replay_creates_one_job_and_outbox(self) -> None:
        task_id = self.create_task("same-device-upload-race-task")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.headers,
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            mailbox_id = db.scalar(select(Mailbox.id))
            db.add(
                MailSession(
                    tenant_id=task.tenant_id,
                    task_id=task.id,
                    user_id=task.user_id,
                    device_id=task.device_id,
                    mailbox_id=mailbox_id,
                    trace_id=task.trace_id,
                    status="consumed",
                    consumed_at=utc_now(),
                    expires_at=utc_now() + timedelta(minutes=5),
                )
            )
            db.commit()
        barrier = Barrier(2)

        def create() -> httpx.Response:
            barrier.wait(timeout=5)
            return self.request(
                "POST",
                f"/api/v1/tasks/{task_id}/uploads",
                headers=self.headers,
                json={
                    "business_name": "Race Business",
                    "idempotency_key": "same-device-upload-race",
                },
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(lambda _: create(), range(2)))
        self.assertEqual(sorted(response.status_code for response in responses), [200, 201])
        job_ids = {response.json()["id"] for response in responses}
        self.assertEqual(len(job_ids), 1)
        job_id = next(iter(job_ids))
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(UploadJob).where(
                        UploadJob.idempotency_key == "same-device-upload-race"
                    )
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(OutboxEvent).where(
                        OutboxEvent.aggregate_id == job_id,
                        OutboxEvent.event_type == "upload.requested",
                    )
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.queued",
                    )
                ),
                1,
            )

    def test_upload_idempotent_replay_returns_status_after_concurrent_task_close(
        self,
    ) -> None:
        task_id = self.create_task("upload-replay-close-task")
        allocated = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.headers,
        )
        self.assertEqual(allocated.status_code, 201, allocated.text)
        now = utc_now()
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            mailbox_id = db.scalar(select(Mailbox.id).limit(1))
            db.add(
                MailSession(
                    tenant_id=task.tenant_id,
                    task_id=task.id,
                    user_id=task.user_id,
                    device_id=task.device_id,
                    mailbox_id=mailbox_id,
                    trace_id=task.trace_id,
                    status="consumed",
                    consumed_at=now,
                    expires_at=now + timedelta(minutes=5),
                )
            )
            db.commit()

        payload = {
            "business_name": "Replay Close Store",
            "idempotency_key": "upload-replay-close",
        }
        created = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.headers,
            json=payload,
        )
        self.assertEqual(created.status_code, 201, created.text)
        job_id = created.json()["id"]
        entered = Event()
        release = Event()
        original_scalar = Session.scalar
        blocked = False

        def block_after_stale_upload_read(session, statement, *args, **kwargs):
            nonlocal blocked
            result = original_scalar(session, statement, *args, **kwargs)
            if not blocked and isinstance(result, UploadJob) and result.id == job_id:
                blocked = True
                session.commit()
                entered.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("upload replay release timed out")
            return result

        with patch.object(Session, "scalar", new=block_after_stale_upload_read):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/uploads",
                    headers=self.headers,
                    json=payload,
                )
                self.assertTrue(entered.wait(timeout=5))
                closed = self.close_task(task_id)
                self.assertEqual(closed.status_code, 200, closed.text)
                release.set()
                replay = future.result(timeout=10)

        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "cancelled")
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(outbox.status, "processed")

    def test_mail_session_replay_returns_status_after_concurrent_task_close(
        self,
    ) -> None:
        self.connector.release.set()
        task_id = self.create_task("mail-replay-close")
        created = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/mail-sessions",
            headers=self.headers,
        )
        self.assertEqual(created.status_code, 201, created.text)
        session_id = created.json()["id"]
        entered = Event()
        release = Event()
        rotation_ready = Event()
        original_commit = Session.commit
        original_new_token = routes._new_unique_mail_session_token
        blocked = False

        def mark_rotation(db: Session) -> tuple[str, str]:
            token = original_new_token(db)
            rotation_ready.set()
            return token

        def block_after_rotation_commit(session: Session) -> None:
            nonlocal blocked
            should_block = (
                not blocked
                and rotation_ready.is_set()
            )
            original_commit(session)
            if should_block:
                blocked = True
                entered.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("mail replay release timed out")

        with patch.object(Session, "commit", new=block_after_rotation_commit), patch(
            "platform.api.v1.routes._new_unique_mail_session_token",
            side_effect=mark_rotation,
        ):
            with ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="mail-replay"
            ) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/mail-sessions",
                    headers=self.headers,
                )
                self.assertTrue(entered.wait(timeout=5))
                closed = self.close_task(task_id)
                self.assertEqual(closed.status_code, 200, closed.text)
                release.set()
                replay = future.result(timeout=10)

        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "revoked")
        with self.app.state.session_factory() as db:
            mail_session = db.get(MailSession, session_id)
        self.assertEqual(mail_session.status, "revoked")

    def test_initial_mail_session_returns_status_after_concurrent_task_close(
        self,
    ) -> None:
        self.connector.release.set()
        task_id = self.create_task("mail-create-close")
        entered = Event()
        release = Event()
        token_created = Event()
        original_commit = Session.commit
        original_new_token = routes._new_unique_mail_session_token
        blocked = False

        def mark_token(db: Session) -> tuple[str, str]:
            token = original_new_token(db)
            token_created.set()
            return token

        def block_after_create_commit(session: Session) -> None:
            nonlocal blocked
            should_block = not blocked and token_created.is_set()
            original_commit(session)
            if should_block:
                blocked = True
                entered.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("mail create release timed out")

        with patch.object(Session, "commit", new=block_after_create_commit), patch(
            "platform.api.v1.routes._new_unique_mail_session_token",
            side_effect=mark_token,
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/mail-sessions",
                    headers=self.headers,
                )
                self.assertTrue(entered.wait(timeout=5))
                with self.app.state.session_factory() as db:
                    session_id = db.scalar(
                        select(MailSession.id).where(MailSession.task_id == task_id)
                    )
                self.assertIsNotNone(session_id)
                closed = self.close_task(task_id)
                self.assertEqual(closed.status_code, 200, closed.text)
                release.set()
                created = future.result(timeout=10)

        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["status"], "revoked")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(MailSession, session_id).status, "revoked")
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(MailSession).where(
                        MailSession.task_id == task_id
                    )
                ),
                1,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.entity_id == session_id,
                        AuditEvent.event_type == "mail_session.created",
                    )
                ),
                1,
            )

    def test_close_during_mail_watermark_cannot_create_session_afterward(self) -> None:
        task_id = self.create_task("mail-close-wins")

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                self.request,
                "POST",
                f"/api/v1/tasks/{task_id}/mail-sessions",
                headers=self.headers,
            )
            self.assertTrue(self.connector.entered.wait(timeout=5))
            closed = self.close_task(task_id)
            self.assertEqual(closed.status_code, 200, closed.text)
            self.connector.release.set()
            created = future.result(timeout=10)

        self.assertEqual(created.status_code, 409, created.text)
        self.assertEqual(created.json()["error"]["message"], "Task is closed or expired")
        self.assert_no_success_side_effects(
            task_id, resource_type=MailSession, event_type="mail_session.created"
        )

    def _close_before_task_lock(self, task_id: str, create_request) -> httpx.Response:
        entered = Event()
        release = Event()
        original = routes._lock_owned_open_task

        def blocked_lock(*args, **kwargs):
            args[0].rollback()
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("task lock test release timed out")
            return original(*args, **kwargs)

        with patch(
            "platform.api.v1.routes._lock_owned_open_task", side_effect=blocked_lock
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(create_request)
                self.assertTrue(entered.wait(timeout=5))
                closed = self.close_task(task_id)
                self.assertEqual(closed.status_code, 200, closed.text)
                release.set()
                return future.result(timeout=10)

    def test_close_before_card_lock_cannot_create_allocation_afterward(self) -> None:
        task_id = self.create_task("card-close-wins")
        created = self._close_before_task_lock(
            task_id,
            lambda: self.request(
                "POST",
                f"/api/v1/tasks/{task_id}/card-allocations",
                headers=self.headers,
            ),
        )

        self.assertEqual(created.status_code, 409, created.text)
        self.assertEqual(created.json()["error"]["message"], "Task is closed or expired")
        self.assert_no_success_side_effects(
            task_id, resource_type=CardAllocation, event_type="card.allocated"
        )

    def test_principal_revocation_before_card_lock_cannot_allocate_afterward(self) -> None:
        for boundary in ("user_disabled", "device_revoked"):
            with self.subTest(boundary=boundary):
                with self.app.state.session_factory() as db:
                    db.add(
                        Card(
                            tenant_id="tenant-resource-race",
                            provider_ref=f"principal-race-{boundary}",
                            brand="VISA",
                            last4="1111",
                            secret_ref=f"vault://cards/principal-race-{boundary}",
                        )
                    )
                    db.commit()
                task_id = self.create_task(f"card-principal-{boundary}")
                entered = Event()
                release = Event()
                original = routes._lock_owned_open_task

                def blocked_lock(*args, **kwargs):
                    args[0].rollback()
                    entered.set()
                    if not release.wait(timeout=5):
                        raise TimeoutError("principal lock test release timed out")
                    return original(*args, **kwargs)

                with patch(
                    "platform.api.v1.routes._lock_owned_open_task",
                    side_effect=blocked_lock,
                ):
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(
                            self.request,
                            "POST",
                            f"/api/v1/tasks/{task_id}/card-allocations",
                            headers=self.headers,
                        )
                        self.assertTrue(entered.wait(timeout=5))
                        with self.app.state.session_factory() as db:
                            if boundary == "user_disabled":
                                db.get(User, self.identity.user_id).is_active = False
                            else:
                                db.get(Device, self.identity.device_id).revoked_at = (
                                    utc_now()
                                )
                            db.commit()
                        release.set()
                        created = future.result(timeout=10)

                with self.app.state.session_factory() as db:
                    db.get(User, self.identity.user_id).is_active = True
                    db.get(Device, self.identity.device_id).revoked_at = None
                    task = db.get(Task, task_id)
                    task.status = "closed"
                    task.closed_at = utc_now()
                    db.commit()
                self.assertEqual(created.status_code, 401, created.text)
                self.assert_no_success_side_effects(
                    task_id,
                    resource_type=CardAllocation,
                    event_type="card.allocated",
                )

    def test_logout_before_upload_lock_cannot_queue_job_or_outbox_afterward(self) -> None:
        task_id = self.create_task("upload-logout-wins")
        now = utc_now()
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            mailbox = db.scalar(select(Mailbox).limit(1))
            card = db.scalar(select(Card).limit(1))
            allocation = CardAllocation(
                tenant_id=task.tenant_id,
                task_id=task.id,
                user_id=task.user_id,
                device_id=task.device_id,
                card_id=card.id,
                trace_id=task.trace_id,
                status="active",
                expires_at=now + timedelta(minutes=5),
            )
            verification = MailSession(
                tenant_id=task.tenant_id,
                task_id=task.id,
                user_id=task.user_id,
                device_id=task.device_id,
                mailbox_id=mailbox.id,
                trace_id=task.trace_id,
                status="consumed",
                consumed_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            db.add_all([allocation, verification])
            db.commit()

        entered = Event()
        release = Event()
        original = routes._lock_owned_open_task

        def blocked_lock(*args, **kwargs):
            args[0].rollback()
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("task lock test release timed out")
            return original(*args, **kwargs)

        with patch(
            "platform.api.v1.routes._lock_owned_open_task", side_effect=blocked_lock
        ):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/tasks/{task_id}/uploads",
                    headers=self.headers,
                    json={
                        "business_name": "Example Store",
                        "idempotency_key": "upload-close-wins",
                    },
                )
                self.assertTrue(entered.wait(timeout=5))
                logged_out = self.request(
                    "POST", "/api/v1/auth/logout", headers=self.headers
                )
                self.assertEqual(logged_out.status_code, 200, logged_out.text)
                release.set()
                created = future.result(timeout=10)

        self.assertEqual(created.status_code, 409, created.text)
        self.assertEqual(created.json()["error"]["message"], "Task is closed or expired")
        self.assert_no_success_side_effects(
            task_id, resource_type=UploadJob, event_type="upload.queued"
        )
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(select(func.count()).select_from(OutboxEvent)), 0
            )

    def test_creations_that_commit_first_are_all_reclaimed_by_logout(self) -> None:
        self.connector.release.set()
        task_id = self.create_task("create-first-then-logout")
        mail = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/mail-sessions",
            headers=self.headers,
        )
        card = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.headers,
        )
        self.assertEqual(mail.status_code, 201, mail.text)
        self.assertEqual(card.status_code, 201, card.text)
        now = utc_now()
        with self.app.state.session_factory() as db:
            session = db.get(MailSession, mail.json()["id"])
            session.status = "consumed"
            session.consumed_at = now
            db.commit()

        upload = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.headers,
            json={
                "business_name": "Example Store",
                "idempotency_key": "create-first-upload",
            },
        )
        self.assertEqual(upload.status_code, 201, upload.text)

        logged_out = self.request("POST", "/api/v1/auth/logout", headers=self.headers)
        self.assertEqual(logged_out.status_code, 200, logged_out.text)

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            session = db.get(MailSession, mail.json()["id"])
            allocation = db.get(CardAllocation, card.json()["id"])
            job = db.get(UploadJob, upload.json()["id"])
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job.id)
            )
            self.assertEqual(task.status, "cancelled")
            self.assertEqual(session.status, "revoked")
            self.assertIsNone(session.delivered_code)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(outbox.status, "processed")
            for event_type in (
                "mail_session.created",
                "card.allocated",
                "upload.queued",
            ):
                self.assertEqual(
                    db.scalar(
                        select(func.count()).select_from(AuditEvent).where(
                            AuditEvent.event_type == event_type
                        )
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
