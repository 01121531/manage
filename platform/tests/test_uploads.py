import asyncio
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock, current_thread
from unittest import mock

import httpx
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from platform.app import create_app
from platform.auth import AuthPrincipal, get_current_principal
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.lifecycle import LifecycleSweepResult, transition_task_to_terminal
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
    UploadPolicyDeployment,
    UploadPolicyVersion,
    User,
    utc_now,
)
from platform.policies import select_policy_for_task
from platform.uploads import (
    Sub2AdapterError,
    Sub2ConcurrencyBackendUnavailable,
    Sub2ConcurrencyLimiter,
    Sub2LookupResult,
    Sub2LookupState,
    Sub2Policy,
    Sub2UploadResult,
    UploadUnknownError,
    _finish_outbox_event,
    process_upload_job,
    process_queued_uploads,
    reconcile_unknown_upload_job,
    run_upload_worker,
    upload_job_status_counts,
    worker_heartbeat_is_fresh,
    write_worker_heartbeat,
)


class FakeSub2Adapter:
    def __init__(
        self,
        *,
        unknown: bool = False,
        error: BaseException | None = None,
    ) -> None:
        self.unknown = unknown
        self.error = error
        self.commands = []

    def submit(self, command):
        self.commands.append(command)
        if self.unknown:
            raise UploadUnknownError("network result unknown")
        if self.error is not None:
            raise self.error
        return Sub2UploadResult(external_ref="sub2-job-123")


class FakeSub2ReconciliationAdapter:
    def __init__(
        self,
        result: Sub2LookupResult | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.result = result or Sub2LookupResult(state=Sub2LookupState.UNKNOWN)
        self.error = error
        self.commands = []

    def query(self, command):
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


class GateSub2ConcurrencyLimiter:
    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()

    @contextmanager
    def slot(self, _tenant_id, _policy):
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("worker did not receive capacity release")
        yield


class Sub2ConcurrencyLimiterTests(unittest.TestCase):
    @staticmethod
    def policy(version: str, concurrency: int) -> Sub2Policy:
        return Sub2Policy(
            version=version,
            proxy_ref=None,
            group_id=49,
            concurrency=concurrency,
            credential_ref=None,
        )

    def test_snapshot_concurrency_is_a_proven_maximum(self) -> None:
        limiter = Sub2ConcurrencyLimiter()
        policy = self.policy("bounded-v1", 2)
        release = Event()
        at_capacity = Event()
        lock = Lock()
        active = 0
        maximum = 0

        def submit() -> None:
            nonlocal active, maximum
            with limiter.slot("tenant-a", policy):
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                    if active == policy.concurrency:
                        at_capacity.set()
                release.wait(timeout=10)
                with lock:
                    active -= 1

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(submit) for _ in range(5)]
            try:
                self.assertTrue(at_capacity.wait(timeout=5))
                with lock:
                    self.assertEqual(maximum, 2)
            finally:
                release.set()
            for future in futures:
                future.result(timeout=10)

        self.assertEqual(active, 0)
        self.assertEqual(maximum, policy.concurrency)

    def test_tenant_and_policy_budgets_are_isolated(self) -> None:
        limiter = Sub2ConcurrencyLimiter()
        release = Event()
        all_entered = Event()
        lock = Lock()
        active = 0
        maximum = 0
        scopes = (
            ("tenant-a", self.policy("isolated-v1", 1)),
            ("tenant-a", self.policy("isolated-v2", 1)),
            ("tenant-b", self.policy("isolated-v1", 1)),
        )

        def submit(tenant_id: str, policy: Sub2Policy) -> None:
            nonlocal active, maximum
            with limiter.slot(tenant_id, policy):
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                    if active == len(scopes):
                        all_entered.set()
                release.wait(timeout=10)
                with lock:
                    active -= 1

        with ThreadPoolExecutor(max_workers=len(scopes)) as executor:
            futures = [executor.submit(submit, *scope) for scope in scopes]
            try:
                self.assertTrue(all_entered.wait(timeout=5))
            finally:
                release.set()
            for future in futures:
                future.result(timeout=10)

        self.assertEqual(active, 0)
        self.assertEqual(maximum, len(scopes))

    def test_exception_releases_policy_capacity(self) -> None:
        limiter = Sub2ConcurrencyLimiter()
        policy = self.policy("exception-v1", 1)

        with self.assertRaisesRegex(RuntimeError, "adapter failed"):
            with limiter.slot("tenant-a", policy):
                raise RuntimeError("adapter failed")

        acquired_after_failure = False
        with limiter.slot("tenant-a", policy):
            acquired_after_failure = True
        self.assertTrue(acquired_after_failure)

    def test_same_policy_version_cannot_change_limit_between_batches(self) -> None:
        limiter = Sub2ConcurrencyLimiter()
        with limiter.slot("tenant-a", self.policy("immutable-v1", 2)):
            pass

        with self.assertRaisesRegex(ValueError, "same version"):
            with limiter.slot("tenant-a", self.policy("immutable-v1", 3)):
                self.fail("an inconsistent immutable policy must not acquire a slot")


class UploadJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = FakeSub2Adapter()
        self.app = create_app(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="upload-test-hmac-secret-that-is-not-production",
                sub2_policy_version="sub2-policy-test",
                sub2_proxy_ref="vault://proxy/default",
                sub2_group_id=49,
                sub2_concurrency=40,
                sub2_credential_ref="vault://sub2/credential",
            ),
            sub2_adapter=self.adapter,
        )
        self.password = "upload-owner-account-password"
        self.identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-upload",
            email="upload-owner@example.test",
            password=self.password,
            device_name="upload-device",
        )
        with self.app.state.session_factory() as db:
            card = Card(
                tenant_id="tenant-upload",
                provider_ref="provider-upload-card",
                brand="VISA",
                last4="2222",
                secret_ref="vault://cards/upload-card",
            )
            mailbox = Mailbox(
                tenant_id="tenant-upload",
                email_masked="u***@example.test",
                connector_type="http",
                secret_ref="vault://secret/mailboxes/upload-test",
            )
            db.add_all([card, mailbox])
            db.flush()
            self.mailbox_id = mailbox.id
            db.commit()

    def tearDown(self) -> None:
        self.app.state.engine.dispose()

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def run() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(run())

    def login(self, *, device_id: str | None = None) -> str:
        response = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": "tenant-upload",
                "email": "upload-owner@example.test",
                "password": self.password,
                "device_id": device_id or self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def create_role_session(self, role: str, *, tenant_id: str = "tenant-upload"):
        password = f"upload-{tenant_id}-{role}-password"
        identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id=tenant_id,
            email=f"upload-{tenant_id}-{role}@example.test",
            password=password,
            device_name=f"upload-{tenant_id}-{role}-device",
            role=role,
        )
        login = self.request(
            "POST",
            "/api/v1/auth/login",
            json={
                "tenant_id": tenant_id,
                "email": f"upload-{tenant_id}-{role}@example.test",
                "password": password,
                "device_id": identity.device_id,
            },
        )
        self.assertEqual(login.status_code, 200, login.text)
        return identity, login.json()["access_token"]

    def create_task_with_card(
        self,
        token: str,
        *,
        with_verification: bool = True,
        task_key: str = "upload-task-1",
    ) -> tuple[str, str]:
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "card_checkout", "idempotency_key": task_key},
        )
        self.assertEqual(task.status_code, 201, task.text)
        task_id = task.json()["id"]
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        if with_verification:
            self.add_mail_verification(task_id)
        return task_id, allocation.json()["id"]

    def add_mail_verification(
        self,
        task_id: str,
        *,
        status: str = "consumed",
        consumed_at: datetime | None = None,
        expires_at: datetime | None = None,
        device_id: str | None = None,
    ) -> str:
        now = utc_now()
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            assert task is not None
            session = MailSession(
                tenant_id=task.tenant_id,
                task_id=task.id,
                user_id=task.user_id,
                device_id=device_id or task.device_id,
                mailbox_id=self.mailbox_id,
                trace_id=task.trace_id,
                status=status,
                consumed_at=(now if consumed_at is None and status == "consumed" else consumed_at),
                expires_at=expires_at or now + timedelta(minutes=5),
            )
            db.add(session)
            db.commit()
            return session.id

    def create_upload(self, token: str, task_id: str, key: str = "upload-1") -> httpx.Response:
        return self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={"business_name": "Example Store", "idempotency_key": key},
        )

    def create_unknown_upload(
        self,
        token: str,
        *,
        task_key: str,
        upload_key: str,
    ) -> tuple[str, str, str]:
        task_id, allocation_id = self.create_task_with_card(token, task_key=task_key)
        queued = self.create_upload(token, task_id, upload_key)
        self.assertEqual(queued.status_code, 201, queued.text)
        job_id = queued.json()["id"]
        result = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "unknown")
        return task_id, allocation_id, job_id

    @contextmanager
    def single_connection_file_app(self):
        """Use a file database whose only pooled connection exposes worker leaks."""

        original_app = self.app
        original_identity = self.identity
        original_password = self.password
        original_mailbox_id = self.mailbox_id
        with tempfile.TemporaryDirectory(prefix="upload-capacity-wait-") as directory:
            database_path = Path(directory) / "uploads.db"
            database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
            app = create_app(
                Settings(
                    environment="test",
                    database_url=database_url,
                    jwt_hmac_secret="upload-wait-hmac-secret-that-is-not-production",
                    sub2_policy_version="sub2-policy-capacity-wait",
                    sub2_group_id=49,
                    sub2_concurrency=1,
                ),
                sub2_adapter=self.adapter,
            )
            self.app = app
            self.password = "upload-capacity-wait-owner-password"
            self.identity = create_user_with_device(
                app.state.session_factory,
                tenant_id="tenant-upload",
                email="upload-owner@example.test",
                password=self.password,
                device_name="upload-capacity-wait-device",
            )
            with app.state.session_factory() as db:
                card = Card(
                    tenant_id="tenant-upload",
                    provider_ref="provider-upload-capacity-wait-card",
                    brand="VISA",
                    last4="4444",
                    secret_ref="vault://cards/upload-capacity-wait-card",
                )
                mailbox = Mailbox(
                    tenant_id="tenant-upload",
                    email_masked="w***@example.test",
                    connector_type="http",
                    secret_ref="vault://secret/mailboxes/upload-capacity-wait",
                )
                db.add_all([card, mailbox])
                db.flush()
                self.mailbox_id = mailbox.id
                db.commit()

            def activate_single_connection_pool() -> None:
                app.state.engine.dispose()
                engine = sqlalchemy_create_engine(
                    database_url,
                    connect_args={"check_same_thread": False},
                    poolclass=QueuePool,
                    pool_size=1,
                    max_overflow=0,
                    pool_timeout=1,
                )

                @event.listens_for(engine, "connect")
                def enable_foreign_keys(
                    dbapi_connection, _connection_record
                ) -> None:
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA foreign_keys=ON")
                    cursor.close()

                app.state.engine = engine
                app.state.session_factory = sessionmaker(
                    bind=engine, expire_on_commit=False
                )

            try:
                yield activate_single_connection_pool
            finally:
                self.app = original_app
                self.identity = original_identity
                self.password = original_password
                self.mailbox_id = original_mailbox_id
                app.state.engine.dispose()

    def test_queue_contract_has_no_sub2_infrastructure_fields(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        rejected = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={
                "business_name": "Example Store",
                "idempotency_key": "client-phase-forbidden",
                "phase": "provider_result",
            },
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        queued = self.create_upload(token, task_id)
        self.assertEqual(queued.status_code, 201, queued.text)
        self.assertEqual(
            set(queued.json()),
            {
                "id",
                "task_id",
                "trace_id",
                "status",
                "phase",
                "phase_sequence",
                "phase_updated_at",
                "business_name",
                "policy_version",
                "external_ref",
                "error_code",
                "created_at",
                "updated_at",
            },
        )
        task = self.request(
            "GET", f"/api/v1/tasks/{task_id}", headers=self.bearer(token)
        )
        self.assertEqual(queued.json()["trace_id"], task.json()["trace_id"])
        self.assertEqual(queued.json()["status"], "queued")
        for forbidden in ("password", "token", "proxy", "group", "concurrency", "credential", "secret_ref"):
            self.assertNotIn(forbidden, queued.text.lower())

    def test_upload_requires_card_and_idempotency_is_device_scoped(self) -> None:
        token = self.login()
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "mail_code", "idempotency_key": "upload-no-card-task"},
        )
        response = self.create_upload(token, task.json()["id"])
        self.assertEqual(response.status_code, 409)
        self.assertIn("card allocation", response.json()["error"]["message"])
        closed = self.request(
            "POST",
            f"/api/v1/tasks/{task.json()['id']}/close",
            headers=self.bearer(token),
        )
        self.assertEqual(closed.status_code, 200, closed.text)

        task_id, _ = self.create_task_with_card(token)
        first = self.create_upload(token, task_id, "upload-idempotent")
        replay = self.create_upload(token, task_id, "upload-idempotent")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(first.json()["id"], replay.json()["id"])
        conflict = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={"business_name": "Other Store", "idempotency_key": "upload-idempotent"},
        )
        self.assertEqual(conflict.status_code, 409)

        with self.app.state.session_factory() as db:
            events = list(db.scalars(select(OutboxEvent)))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].aggregate_id, first.json()["id"])
        self.assertEqual(events[0].event_type, "upload.requested")
        self.assertEqual(events[0].status, "pending")
        for forbidden in ("payload", "secret", "credential", "proxy", "token"):
            self.assertNotIn(forbidden, OutboxEvent.__table__.columns)

    def test_cross_device_upload_idempotency_conflict_does_not_leak_owner_job(self) -> None:
        device_a_token = self.login()
        with self.app.state.session_factory() as db:
            device_b = Device(
                tenant_id="tenant-upload",
                user_id=self.identity.user_id,
                name="upload-device-b",
            )
            second_card = Card(
                tenant_id="tenant-upload",
                provider_ref="provider-upload-card-b",
                brand="VISA",
                last4="3333",
                secret_ref="vault://cards/upload-card-b",
            )
            db.add_all([device_b, second_card])
            db.commit()
            device_b_id = device_b.id
        device_b_token = self.login(device_id=device_b_id)

        task_a, _ = self.create_task_with_card(
            device_a_token, task_key="same-upload-key-task-a"
        )
        first = self.create_upload(device_a_token, task_a, "same-upload-key")
        closed = self.request(
            "POST",
            f"/api/v1/tasks/{task_a}/close",
            headers=self.bearer(device_a_token),
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        task_b, _ = self.create_task_with_card(
            device_b_token, task_key="same-upload-key-task-b"
        )
        second = self.create_upload(device_b_token, task_b, "same-upload-key")
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 409, second.text)
        self.assertEqual(second.json()["error"]["code"], "conflict")
        self.assertNotIn(first.json()["id"], second.text)
        self.assertNotIn(self.identity.device_id, second.text)

        replay_a = self.create_upload(device_a_token, task_a, "same-upload-key")
        replay_b = self.create_upload(device_b_token, task_b, "same-upload-key")
        self.assertEqual(replay_a.status_code, 200, replay_a.text)
        self.assertEqual(replay_b.status_code, 409, replay_b.text)
        self.assertEqual(replay_a.json()["id"], first.json()["id"])
        with self.app.state.session_factory() as db:
            jobs = list(
                db.scalars(
                    select(UploadJob).where(
                        UploadJob.idempotency_key == "same-upload-key"
                    )
                )
            )
            queued_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "upload.queued",
                        AuditEvent.entity_id == first.json()["id"],
                    )
                )
            )
        self.assertEqual([job.device_id for job in jobs], [self.identity.device_id])
        self.assertEqual(len(queued_events), 1)

    def test_first_upload_requires_consumed_verification_for_same_task_and_device(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token, with_verification=False)

        def assert_verification_required(key: str) -> None:
            response = self.create_upload(token, task_id, key)
            self.assertEqual(response.status_code, 409, response.text)
            error = response.json()["error"]
            self.assertEqual(error["code"], "verification_required")
            self.assertEqual(
                set(error), {"code", "message", "recovery_hint", "trace_id"}
            )
            serialized = str(error).lower()
            for forbidden in ("mailbox", "email", "session_id", "secret", "token"):
                self.assertNotIn(forbidden, serialized)

        assert_verification_required("verification-none")
        session_id = self.add_mail_verification(
            task_id, status="waiting", consumed_at=None
        )
        assert_verification_required("verification-waiting")

        cases = (
            ("code_ready", None, utc_now() + timedelta(minutes=5), self.identity.device_id),
            ("expired", None, utc_now() + timedelta(minutes=5), self.identity.device_id),
            ("revoked", None, utc_now() + timedelta(minutes=5), self.identity.device_id),
            ("consumed", None, utc_now() + timedelta(minutes=5), self.identity.device_id),
            ("consumed", utc_now(), utc_now() - timedelta(seconds=1), self.identity.device_id),
        )
        for index, (status, consumed_at, expires_at, device_id) in enumerate(cases):
            with self.subTest(status=status, consumed_at=consumed_at, expires_at=expires_at):
                with self.app.state.session_factory() as db:
                    session = db.get(MailSession, session_id)
                    session.status = status
                    session.consumed_at = consumed_at
                    session.expires_at = expires_at
                    session.device_id = device_id
                    db.commit()
                assert_verification_required(f"verification-state-{index}")

        with self.app.state.session_factory() as db:
            alternate_device = Device(
                tenant_id="tenant-upload",
                user_id=self.identity.user_id,
                name="alternate-upload-device",
            )
            db.add(alternate_device)
            db.flush()
            session = db.get(MailSession, session_id)
            session.status = "consumed"
            session.consumed_at = utc_now()
            session.expires_at = utc_now() + timedelta(minutes=5)
            session.device_id = alternate_device.id
            db.commit()
        assert_verification_required("verification-cross-device")

        other_identity = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-upload",
            email="other-verification-owner@example.test",
            password="other-verification-owner-password",
            device_name="other-verification-device",
        )
        with self.app.state.session_factory() as db:
            session = db.get(MailSession, session_id)
            session.user_id = other_identity.user_id
            session.device_id = other_identity.device_id
            db.commit()
        assert_verification_required("verification-cross-user")

        with self.app.state.session_factory() as db:
            session = db.get(MailSession, session_id)
            session.user_id = self.identity.user_id
            session.device_id = self.identity.device_id
            db.commit()
        accepted = self.create_upload(token, task_id, "verification-valid")
        self.assertEqual(accepted.status_code, 201, accepted.text)

    def test_upload_idempotent_replay_survives_later_verification_revocation(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        created = self.create_upload(token, task_id, "verification-replay")
        self.assertEqual(created.status_code, 201, created.text)
        with self.app.state.session_factory() as db:
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            session.status = "revoked"
            session.consumed_at = None
            db.commit()
        replay = self.create_upload(token, task_id, "verification-replay")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], created.json()["id"])

    def test_worker_consumes_transactional_outbox(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-outbox")
        self.assertEqual(queued.json()["phase"], "queued")
        self.assertEqual(queued.json()["phase_sequence"], 1)
        self.assertIsNotNone(queued.json()["phase_updated_at"])

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(processed, 1)
        self.assertEqual(len(self.adapter.commands), 1)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            event = db.scalar(
                select(OutboxEvent).where(
                    OutboxEvent.aggregate_id == queued.json()["id"]
                )
            )
            queued_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job.id,
                    AuditEvent.event_type == "upload.queued",
                )
            )
            succeeded_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job.id,
                    AuditEvent.event_type == "upload.succeeded",
                )
            )
            self.assertEqual(job.status, "succeeded")
            self.assertEqual(job.phase, "provider_result")
            self.assertEqual(job.phase_sequence, 4)
            self.assertEqual(job.external_ref, "sub2-job-123")
            self.assertEqual(task.status, "completed")
            self.assertIsNotNone(task.closed_at)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertEqual(event.status, "processed")
            self.assertEqual(event.attempts, 1)
            self.assertIsNotNone(event.processed_at)
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(event_types.count("upload.succeeded"), 1)
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("card.released"), 1)
            self.assertEqual(event_types.count("mail_session.revoked"), 1)
            self.assertEqual(queued_audit.user_id, self.identity.user_id)
            self.assertEqual(queued_audit.actor_id, self.identity.user_id)
            self.assertEqual(succeeded_audit.user_id, self.identity.user_id)
            self.assertEqual(succeeded_audit.device_id, self.identity.device_id)
            self.assertEqual(succeeded_audit.actor_id, "worker-sub2")
            self.assertNotEqual(succeeded_audit.actor_id, succeeded_audit.user_id)
            self.assertNotIn("vault://", succeeded_audit.details_json)
            self.assertNotIn("sub2-job-123", succeeded_audit.details_json)
            phase_events = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == job.id,
                        AuditEvent.aggregate_sequence.is_not(None),
                    )
                    .order_by(AuditEvent.aggregate_sequence)
                )
            )
            self.assertEqual(
                [event.event_type for event in phase_events],
                [
                    "upload.queued",
                    "upload.preflight_started",
                    "upload.provider_submit_started",
                    "upload.provider_result_received",
                ],
            )
            self.assertEqual(
                [event.aggregate_sequence for event in phase_events], [1, 2, 3, 4]
            )
            self.assertTrue(
                all(event.trace_id == job.trace_id for event in phase_events)
            )
            self.assertTrue(
                all(event.policy_version == job.policy_version for event in phase_events)
            )
            self.assertEqual(
                [json.loads(event.details_json)["phase"] for event in phase_events],
                ["queued", "worker_preflight", "provider_submit", "provider_result"],
            )

        replay = process_upload_job(
            self.app.state.session_factory,
            queued.json()["id"],
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(replay.status, "succeeded")
        self.assertEqual(len(self.adapter.commands), 1)
        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(event_types.count("upload.succeeded"), 1)
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("card.released"), 1)
            self.assertEqual(event_types.count("mail_session.revoked"), 1)

        close_replay = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
        )
        self.assertEqual(close_replay.status_code, 200, close_replay.text)
        self.assertEqual(close_replay.json()["status"], "completed")
        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("task.closed"), 0)

    def test_concurrency_backend_failure_requeues_before_external_call(self) -> None:
        class UnavailableLimiter:
            @contextmanager
            def slot(self, tenant_id, policy):
                raise Sub2ConcurrencyBackendUnavailable("redis unavailable")
                yield

        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "concurrency-store-down")

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
            concurrency_limiter=UnavailableLimiter(),
        )

        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job.id)
            )
            allocation = db.get(CardAllocation, allocation_id)
            deferred = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job.id,
                    AuditEvent.event_type == "upload.deferred",
                )
            )
            self.assertEqual(job.status, "queued")
            self.assertEqual(job.error_code, "concurrency_backend_unavailable")
            self.assertEqual(event.status, "pending")
            self.assertEqual(event.last_error_code, job.error_code)
            self.assertGreater(
                event.available_at.replace(tzinfo=timezone.utc), utc_now()
            )
            self.assertEqual(allocation.status, "active")
            self.assertIsNotNone(deferred)

    def test_capacity_wait_releases_connection_and_allows_queued_cancel(self) -> None:
        with self.single_connection_file_app() as activate_single_connection_pool:
            token = self.login()
            task_id, _ = self.create_task_with_card(
                token, task_key="capacity-wait-cancel-task"
            )
            queued = self.create_upload(token, task_id, "capacity-wait-cancel")
            job_id = queued.json()["id"]
            activate_single_connection_pool()
            limiter = GateSub2ConcurrencyLimiter()

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    process_upload_job,
                    self.app.state.session_factory,
                    job_id,
                    adapter=self.adapter,
                    policy=self.app.state.sub2_policy,
                    concurrency_limiter=limiter,
                )
                try:
                    self.assertTrue(limiter.entered.wait(timeout=5))
                    with self.app.state.session_factory() as db:
                        job = db.get(UploadJob, job_id)
                        job.status = "cancelled"
                        job.error_code = "cancelled_by_user"
                        job.updated_at = utc_now()
                        db.commit()
                finally:
                    limiter.release.set()
                result = future.result(timeout=10)

            self.assertEqual(result.status, "cancelled")
            self.assertEqual(self.adapter.commands, [])
            with self.app.state.session_factory() as db:
                job = db.get(UploadJob, job_id)
                self.assertEqual(job.status, "cancelled")
                self.assertEqual(job.error_code, "cancelled_by_user")

    def test_capacity_wait_revalidates_device_revocation_before_submit(self) -> None:
        with self.single_connection_file_app() as activate_single_connection_pool:
            token = self.login()
            task_id, allocation_id = self.create_task_with_card(
                token, task_key="capacity-wait-revocation-task"
            )
            queued = self.create_upload(token, task_id, "capacity-wait-revocation")
            job_id = queued.json()["id"]
            activate_single_connection_pool()
            limiter = GateSub2ConcurrencyLimiter()

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    process_upload_job,
                    self.app.state.session_factory,
                    job_id,
                    adapter=self.adapter,
                    policy=self.app.state.sub2_policy,
                    concurrency_limiter=limiter,
                )
                try:
                    self.assertTrue(limiter.entered.wait(timeout=5))
                    with self.app.state.session_factory() as db:
                        device = db.get(Device, self.identity.device_id)
                        device.revoked_at = utc_now()
                        db.commit()
                finally:
                    limiter.release.set()
                result = future.result(timeout=10)

            self.assertEqual(result.status, "cancelled")
            self.assertEqual(result.error_code, "authorization_revoked")
            self.assertEqual(self.adapter.commands, [])
            with self.app.state.session_factory() as db:
                task = db.get(Task, task_id)
                allocation = db.get(CardAllocation, allocation_id)
                self.assertEqual(task.status, "cancelled")
                self.assertEqual(allocation.status, "released")

    def test_worker_rejects_unsafe_adapter_external_ref_as_unknown(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(
            token,
            task_key="upload-unsafe-adapter-ref-task",
        )
        queued = self.create_upload(token, task_id, "upload-unsafe-adapter-ref")
        job_id = queued.json()["id"]
        unsafe_external_ref = (
            "vault://sub2/prod Authorization=Bearer PROVIDER_SECRET"
        )

        class UnsafeExternalRefAdapter:
            def submit(self, command):
                return Sub2UploadResult(external_ref=unsafe_external_ref)

        processed = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=UnsafeExternalRefAdapter(),
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(processed.status, "unknown")
        self.assertEqual(processed.phase, "provider_submit")
        self.assertEqual(processed.phase_sequence, 3)
        self.assertEqual(processed.error_code, "external_unknown")
        self.assertIsNone(processed.external_ref)
        visible = self.request(
            "GET",
            f"/api/v1/upload-jobs/{job_id}",
            headers=self.bearer(token),
        )
        self.assertEqual(visible.status_code, 200, visible.text)
        self.assertEqual(visible.json()["status"], "unknown")
        self.assertEqual(visible.json()["phase"], "provider_submit")
        self.assertEqual(visible.json()["phase_sequence"], 3)
        self.assertIsNone(visible.json()["external_ref"])
        self.assertNotIn(unsafe_external_ref, visible.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            unknown_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
            succeeded_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.succeeded",
                    )
                )
            )
        self.assertEqual(job.status, "unknown")
        self.assertEqual(job.error_code, "external_unknown")
        self.assertIsNone(job.external_ref)
        self.assertEqual(task.status, "created")
        self.assertEqual(allocation.status, "active")
        self.assertEqual(len(unknown_events), 1)
        self.assertEqual(succeeded_events, [])
        self.assertNotIn(unsafe_external_ref, unknown_events[0].details_json)
        with self.app.state.session_factory() as db:
            phase_events = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.aggregate_sequence.is_not(None),
                    )
                    .order_by(AuditEvent.aggregate_sequence)
                )
            )
        self.assertEqual(
            [event.event_type for event in phase_events],
            [
                "upload.queued",
                "upload.preflight_started",
                "upload.provider_submit_started",
            ],
        )

    def test_upload_replay_survives_worker_completion_without_side_effects(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="upload-completed-replay-task"
        )
        queued = self.create_upload(token, task_id, "upload-completed-replay")
        processed = process_upload_job(
            self.app.state.session_factory,
            queued.json()["id"],
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed.status, "succeeded")

        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "completed")
            jobs_before = list(db.scalars(select(UploadJob)))
            outbox_before = list(db.scalars(select(OutboxEvent)))
            audits_before = list(db.scalars(select(AuditEvent)))

        replay = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={
                "business_name": "  Example Store  ",
                "idempotency_key": "upload-completed-replay",
            },
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], queued.json()["id"])
        self.assertEqual(replay.json()["status"], "succeeded")
        self.assertEqual(replay.json()["external_ref"], "sub2-job-123")

        wrong_payload = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={
                "business_name": "Different Store",
                "idempotency_key": "upload-completed-replay",
            },
        )
        self.assertEqual(wrong_payload.status_code, 409, wrong_payload.text)
        self.assertNotIn(queued.json()["id"], wrong_payload.text)
        self.assertNotIn("sub2-job-123", wrong_payload.text)

        wrong_task = self.create_upload(
            token, "different-task-id", "upload-completed-replay"
        )
        self.assertEqual(wrong_task.status_code, 409, wrong_task.text)
        self.assertNotIn(queued.json()["id"], wrong_task.text)
        self.assertNotIn("sub2-job-123", wrong_task.text)

        new_key = self.create_upload(token, task_id, "upload-after-completion")
        self.assertEqual(new_key.status_code, 409, new_key.text)

        with self.app.state.session_factory() as db:
            self.assertEqual(len(list(db.scalars(select(UploadJob)))), len(jobs_before))
            self.assertEqual(
                len(list(db.scalars(select(OutboxEvent)))), len(outbox_before)
            )
            self.assertEqual(len(list(db.scalars(select(AuditEvent)))), len(audits_before))
        self.assertEqual(len(self.adapter.commands), 1)

    def test_upload_replay_returns_existing_job_for_every_persisted_status(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="upload-all-status-replay-task"
        )
        queued = self.create_upload(token, task_id, "upload-all-status-replay")
        job_id = queued.json()["id"]

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            task.status = "cancelled"
            task.closed_at = utc_now()
            db.commit()

        for status in ("succeeded", "failed", "unknown", "cancelled"):
            with self.subTest(status=status):
                with self.app.state.session_factory() as db:
                    job = db.get(UploadJob, job_id)
                    job.status = status
                    db.commit()
                    jobs_before = len(list(db.scalars(select(UploadJob))))
                    outbox_before = len(list(db.scalars(select(OutboxEvent))))
                    audits_before = len(list(db.scalars(select(AuditEvent))))

                replay = self.create_upload(
                    token, task_id, "upload-all-status-replay"
                )
                self.assertEqual(replay.status_code, 200, replay.text)
                self.assertEqual(replay.json()["id"], job_id)
                self.assertEqual(replay.json()["status"], status)

                with self.app.state.session_factory() as db:
                    self.assertEqual(len(list(db.scalars(select(UploadJob)))), jobs_before)
                    self.assertEqual(
                        len(list(db.scalars(select(OutboxEvent)))), outbox_before
                    )
                    self.assertEqual(
                        len(list(db.scalars(select(AuditEvent)))), audits_before
                    )
        self.assertEqual(self.adapter.commands, [])

    def test_worker_cancels_expired_task_before_external_call(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "expired-before-worker")
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            task.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            job = db.get(UploadJob, queued.json()["id"])
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job.id)
            )
            audit_types = set(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(task.status, "expired")
            self.assertEqual(allocation.status, "expired")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "task_expired")
            self.assertEqual(event.status, "processed")
            self.assertIn("task.expired", audit_types)
            self.assertIn("upload.cancelled", audit_types)

    def test_worker_rechecks_user_and_device_authorization(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "revoked-before-worker")
        with self.app.state.session_factory() as db:
            device = db.get(Device, self.identity.device_id)
            device.revoked_at = utc_now()
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            job = db.get(UploadJob, queued.json()["id"])
            self.assertEqual(task.status, "cancelled")
            self.assertEqual(allocation.status, "released")
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "authorization_revoked")

    def test_worker_rechecks_verification_expiry(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "verification-expired-worker")
        with self.app.state.session_factory() as db:
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            session.expires_at = utc_now() - timedelta(seconds=1)
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            task = db.get(Task, task_id)
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "verification_invalid")
            self.assertEqual(task.status, "cancelled")

    def test_worker_fails_closed_on_cross_resource_binding(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "binding-before-worker")
        other = create_user_with_device(
            self.app.state.session_factory,
            tenant_id="tenant-upload",
            email="binding-other@example.test",
            password="binding-other-password",
            device_name="binding-other-device",
        )
        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocation_id)
            allocation.device_id = other.device_id
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            self.assertEqual(job.status, "failed")
            self.assertEqual(job.error_code, "resource_binding_invalid")

    def test_worker_rechecks_disabled_user_before_external_call(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "disabled-before-worker")
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            user.is_active = False
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "authorization_revoked")

    def test_worker_rechecks_quarantine_marker_before_external_call(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "quarantined-before-worker")
        with self.app.state.session_factory() as db:
            allocation = db.get(CardAllocation, allocation_id)
            card = db.get(Card, allocation.card_id)
            card.quarantined_at = utc_now()
            card.quarantine_reason_code = "suspected_compromise"
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            task = db.get(Task, task_id)
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "card_lease_invalid")
            self.assertEqual(task.status, "cancelled")

    def test_worker_rechecks_operator_role_before_external_call(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "role-revoked-before-worker")
        with self.app.state.session_factory() as db:
            user = db.get(User, self.identity.user_id)
            user.role = "security_auditor"
            db.commit()

        process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            job = db.get(UploadJob, queued.json()["id"])
            self.assertEqual(task.status, "cancelled")
            self.assertEqual(allocation.status, "released")
            self.assertEqual(session.status, "expired")
            self.assertEqual(job.status, "cancelled")
            self.assertEqual(job.error_code, "authorization_revoked")
            worker_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job.id,
                        AuditEvent.event_type == "upload.cancelled",
                    )
                )
            )
        self.assertEqual(len(worker_audits), 1)
        self.assertEqual(worker_audits[0].actor_id, "worker-sub2")
        for forbidden in ("vault://", "password", "token", "external_ref"):
            self.assertNotIn(forbidden, worker_audits[0].details_json.lower())

    def test_stale_running_outbox_becomes_unknown_without_resubmission(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-stale-outbox")
        stale_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job.id)
            )
            job.status = "running"
            event.status = "processing"
            event.claimed_at = stale_time
            db.commit()

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job.id)
            )
            self.assertEqual(job.status, "unknown")
            self.assertEqual(job.error_code, "external_unknown")
            self.assertEqual(event.status, "failed")
            self.assertEqual(event.last_error_code, "worker_interrupted")
            unknown_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job.id,
                    AuditEvent.event_type == "upload.unknown",
                )
            )
            self.assertEqual(unknown_audit.user_id, self.identity.user_id)
            self.assertEqual(unknown_audit.device_id, self.identity.device_id)
            self.assertEqual(unknown_audit.actor_id, "worker-sub2")

    def test_reclaimed_outbox_fences_a_late_previous_attempt(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="reclaimed-outbox-fencing-task"
        )
        queued = self.create_upload(token, task_id, "reclaimed-outbox-fencing")
        job_id = queued.json()["id"]
        stale_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        with self.app.state.session_factory() as db:
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            event.status = "processing"
            event.claimed_at = stale_time
            event.attempts = 1
            db.commit()
            event_id = event.id

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed, 1)

        _finish_outbox_event(
            self.app.state.session_factory,
            event_id,
            job_id,
            claim_attempt=1,
            error_code="worker_interrupted",
            force_unknown=True,
        )

        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            event = db.get(OutboxEvent, event_id)
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(AuditEvent.entity_id == job_id)
                )
            )
        self.assertEqual(job.status, "succeeded")
        self.assertEqual(event.status, "processed")
        self.assertEqual(event.attempts, 2)
        self.assertIsNone(event.last_error_code)
        self.assertEqual(event_types.count("upload.succeeded"), 1)
        self.assertEqual(event_types.count("upload.unknown"), 0)

    def test_reclaimed_outbox_fences_a_late_provider_result(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="late-provider-result-task"
        )
        queued = self.create_upload(token, task_id, "late-provider-result")
        job_id = queued.json()["id"]
        with self.app.state.session_factory() as db:
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            event.status = "processing"
            event.attempts = 1
            event.claimed_at = utc_now()
            db.commit()

        session_factory = self.app.state.session_factory

        class ReclaimedDuringSubmitAdapter:
            def submit(self, command):
                with session_factory() as db:
                    event = db.scalar(
                        select(OutboxEvent).where(
                            OutboxEvent.aggregate_id == command.job_id
                        )
                    )
                    job = db.get(UploadJob, command.job_id)
                    event.attempts = 2
                    event.claimed_at = utc_now()
                    job.status = "unknown"
                    job.error_code = "external_unknown"
                    db.commit()
                return Sub2UploadResult(external_ref="late-success-must-not-win")

        result = process_upload_job(
            session_factory,
            job_id,
            adapter=ReclaimedDuringSubmitAdapter(),
            policy=self.app.state.sub2_policy,
            claim_attempt=1,
        )

        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.phase, "provider_submit")
        self.assertIsNone(result.external_ref)
        with session_factory() as db:
            event_types = list(
                db.scalars(
                    select(AuditEvent.event_type).where(AuditEvent.entity_id == job_id)
                )
            )
        self.assertNotIn("upload.provider_result_received", event_types)
        self.assertNotIn("upload.succeeded", event_types)

    def test_previous_attempt_cannot_finalize_current_processing_claim(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="current-outbox-fencing-task"
        )
        queued = self.create_upload(token, task_id, "current-outbox-fencing")
        job_id = queued.json()["id"]
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            event = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            job.status = "running"
            event.status = "processing"
            event.claimed_at = datetime.now(timezone.utc)
            event.attempts = 2
            db.commit()
            event_id = event.id

        _finish_outbox_event(
            self.app.state.session_factory,
            event_id,
            job_id,
            claim_attempt=1,
            error_code="worker_interrupted",
            force_unknown=True,
        )

        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            event = db.get(OutboxEvent, event_id)
            unknown_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
        self.assertEqual(job.status, "running")
        self.assertEqual(event.status, "processing")
        self.assertEqual(event.attempts, 2)
        self.assertIsNone(event.last_error_code)
        self.assertEqual(unknown_audits, [])

    def test_same_worker_cancel_after_claim_finishes_cancelled_before_submit(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="cancel-after-worker-claim-task"
        )
        queued = self.create_upload(token, task_id, "cancel-after-worker-claim")
        job_id = queued.json()["id"]
        original_commit = Session.commit
        cancellation_injected = False

        def commit_and_cancel_after_claim(session: Session) -> None:
            nonlocal cancellation_injected
            original_commit(session)
            if cancellation_injected:
                return
            with self.app.state.session_factory() as probe:
                job = probe.get(UploadJob, job_id)
                if job is None or job.status != "running":
                    return
                job.status = "cancel_pending"
                job.updated_at = utc_now()
                original_commit(probe)
                cancellation_injected = True

        with mock.patch.object(Session, "commit", commit_and_cancel_after_claim):
            processed = process_queued_uploads(
                self.app.state.session_factory,
                adapter=self.adapter,
                policy=self.app.state.sub2_policy,
            )

        self.assertTrue(cancellation_injected)
        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            cancelled_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancelled",
                    )
                )
            )
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(job.error_code, "cancelled_before_external_call")
        self.assertEqual(outbox.status, "processed")
        self.assertEqual(len(cancelled_audits), 1)
        self.assertEqual(cancelled_audits[0].actor_id, "worker-sub2")

    def test_finisher_marks_ambiguous_cancel_pending_unknown_once(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="ambiguous-cancel-pending-task"
        )
        queued = self.create_upload(token, task_id, "ambiguous-cancel-pending")
        job_id = queued.json()["id"]
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == job_id)
            )
            job.status = "cancel_pending"
            outbox.status = "processing"
            outbox.attempts = 2
            outbox.claimed_at = utc_now()
            db.commit()
            event_id = outbox.id

        _finish_outbox_event(
            self.app.state.session_factory,
            event_id,
            job_id,
            claim_attempt=2,
        )
        _finish_outbox_event(
            self.app.state.session_factory,
            event_id,
            job_id,
            claim_attempt=2,
        )

        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            outbox = db.get(OutboxEvent, event_id)
            unknown_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
        self.assertEqual(job.status, "unknown")
        self.assertEqual(job.error_code, "external_unknown")
        self.assertEqual(outbox.status, "processed")
        self.assertIsNone(outbox.last_error_code)
        self.assertEqual(len(unknown_audits), 1)
        self.assertEqual(unknown_audits[0].actor_id, "worker-sub2")

    def test_worker_uses_server_policy_and_card_secret_reference_only(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id)
        job_id = queued.json()["id"]
        processed = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertIsNotNone(processed)
        self.assertEqual(processed.status, "succeeded")
        self.assertEqual(processed.external_ref, "sub2-job-123")
        command = self.adapter.commands[0]
        self.assertEqual(command.job_id, job_id)
        self.assertEqual(command.task_id, task_id)
        self.assertEqual(command.card_secret_ref, "vault://cards/upload-card")
        self.assertEqual(command.policy.group_id, 49)
        self.assertEqual(command.policy.concurrency, 40)
        self.assertNotIn("vault://", repr(command))
        self.assertNotIn("vault://", repr(command.policy))
        self.assertNotIn("vault://", str(processed))
        with self.app.state.session_factory() as db:
            audit_text = "\n".join(event.details_json for event in db.scalars(select(AuditEvent)))
        self.assertNotIn("vault://", audit_text)

    def test_rollout_is_deterministic_and_queued_job_keeps_snapshot_after_rollback(self) -> None:
        with self.app.state.session_factory() as db:
            first = UploadPolicyVersion(
                tenant_id="tenant-upload",
                version="governed-v1",
                status="active",
                change_note="baseline",
                group_id=101,
                concurrency=11,
                proxy_ref="vault://proxy/v1",
                credential_ref="vault://credential/v1",
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            second = UploadPolicyVersion(
                tenant_id="tenant-upload",
                version="governed-v2",
                status="active",
                change_note="canary",
                group_id=202,
                concurrency=22,
                proxy_ref="vault://proxy/v2",
                credential_ref="vault://credential/v2",
                created_by=self.identity.user_id,
                approved_by=self.identity.user_id,
                approved_at=utc_now(),
            )
            db.add_all([first, second])
            db.flush()
            deployment = UploadPolicyDeployment(
                tenant_id="tenant-upload",
                active_policy_id=second.id,
                previous_policy_id=first.id,
                rollout_percent=50,
                updated_by=self.identity.user_id,
            )
            db.add(deployment)
            db.commit()

            selected = {
                select_policy_for_task(
                    db,
                    tenant_id="tenant-upload",
                    task_id=f"task-{index}",
                    fallback=self.app.state.sub2_policy,
                ).version
                for index in range(200)
            }
            self.assertEqual(selected, {"governed-v1", "governed-v2"})
            self.assertEqual(
                select_policy_for_task(
                    db,
                    tenant_id="tenant-upload",
                    task_id="stable-task",
                    fallback=self.app.state.sub2_policy,
                ).version,
                select_policy_for_task(
                    db,
                    tenant_id="tenant-upload",
                    task_id="stable-task",
                    fallback=self.app.state.sub2_policy,
                ).version,
            )
            deployment.rollout_percent = 100
            db.commit()

        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-policy-snapshot")
        self.assertEqual(queued.json()["policy_version"], "governed-v2")

        with self.app.state.session_factory() as db:
            deployment = db.scalar(select(UploadPolicyDeployment))
            first = db.scalar(
                select(UploadPolicyVersion).where(
                    UploadPolicyVersion.version == "governed-v1"
                )
            )
            second = db.scalar(
                select(UploadPolicyVersion).where(
                    UploadPolicyVersion.version == "governed-v2"
                )
            )
            deployment.active_policy_id = first.id
            deployment.previous_policy_id = second.id
            deployment.rollout_percent = 100
            db.commit()

        limiter = Sub2ConcurrencyLimiter()
        with mock.patch.object(limiter, "slot", wraps=limiter.slot) as slot:
            processed = process_queued_uploads(
                self.app.state.session_factory,
                adapter=self.adapter,
                policy=self.app.state.sub2_policy,
                concurrency_limiter=limiter,
            )
        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands[0].policy.version, "governed-v2")
        self.assertEqual(self.adapter.commands[0].policy.group_id, 202)
        self.assertEqual(self.adapter.commands[0].policy.concurrency, 22)
        slot.assert_called_once()
        limited_tenant, limited_policy = slot.call_args.args
        self.assertEqual(limited_tenant, "tenant-upload")
        self.assertEqual(limited_policy.version, "governed-v2")
        self.assertEqual(limited_policy.concurrency, 22)

    def test_managed_environment_requires_a_deployed_upload_policy(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        self.app.state.settings.environment = "production"

        response = self.create_upload(token, task_id, "managed-policy-required")

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "upload_policy_unavailable")
        with self.app.state.session_factory() as db:
            self.assertIsNone(
                db.scalar(
                    select(UploadJob).where(
                        UploadJob.idempotency_key == "managed-policy-required"
                    )
                )
            )

    def test_managed_worker_never_executes_a_runtime_fallback_policy(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "managed-worker-policy-required")
        adapter = FakeSub2Adapter()

        processed = process_upload_job(
            self.app.state.session_factory,
            queued.json()["id"],
            adapter=adapter,
            policy=self.app.state.sub2_policy,
            allow_policy_fallback=False,
        )

        self.assertEqual(processed.status, "failed")
        self.assertEqual(processed.error_code, "policy_version_unapproved")
        self.assertEqual(adapter.commands, [])

    def test_worker_batch_dispatches_claimed_events_concurrently(self) -> None:
        now = utc_now()
        with self.app.state.session_factory() as db:
            db.add_all(
                [
                    OutboxEvent(
                        tenant_id="tenant-upload",
                        event_type="upload.requested",
                        aggregate_type="upload_job",
                        aggregate_id=f"parallel-job-{index}",
                        available_at=now,
                    )
                    for index in range(2)
                ]
            )
            db.commit()

        entered_together = Event()
        lock = Lock()
        active = 0
        maximum = 0

        def fake_process(*args, **kwargs):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    entered_together.set()
            entered_together.wait(timeout=5)
            with lock:
                active -= 1
            return None

        with (
            mock.patch("platform.uploads.process_upload_job", side_effect=fake_process),
            mock.patch("platform.uploads._finish_outbox_event") as finish_outbox,
        ):
            processed = process_queued_uploads(
                self.app.state.session_factory,
                adapter=self.adapter,
                policy=self.app.state.sub2_policy,
            )

        self.assertEqual(processed, 2)
        self.assertEqual(maximum, 2)
        self.assertEqual(finish_outbox.call_count, 2)
        self.assertEqual(
            {call.kwargs["claim_attempt"] for call in finish_outbox.call_args_list},
            {1},
        )

    def test_unknown_external_result_is_not_retried(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id)
        unknown_adapter = FakeSub2Adapter(unknown=True)
        processed = process_upload_job(
            self.app.state.session_factory,
            queued.json()["id"],
            adapter=unknown_adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed.status, "unknown")
        again = process_upload_job(
            self.app.state.session_factory,
            queued.json()["id"],
            adapter=unknown_adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(again.status, "unknown")
        self.assertEqual(len(unknown_adapter.commands), 1)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "created")
            allocation = db.get(CardAllocation, allocation_id)
            self.assertEqual(allocation.status, "active")
            self.assertIsNone(allocation.released_at)
            self.assertEqual(
                db.scalar(
                    select(AuditEvent)
                    .where(AuditEvent.event_type == "task.completed")
                    .exists()
                    .select()
                ),
                False,
            )

    def test_unknown_upload_blocks_fresh_key_until_reconciled_failed(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="unknown-fresh-key-task"
        )
        first = self.create_upload(token, task_id, "unknown-attempt-a")
        first_id = first.json()["id"]
        processed = process_upload_job(
            self.app.state.session_factory,
            first_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed.status, "unknown")

        with self.app.state.session_factory() as db:
            jobs_before = db.scalar(
                select(func.count()).select_from(UploadJob).where(
                    UploadJob.task_id == task_id
                )
            )
            outbox_before = db.scalar(
                select(func.count()).select_from(OutboxEvent)
            )
            queued_audits_before = db.scalar(
                select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.event_type == "upload.queued",
                    AuditEvent.trace_id == processed.trace_id,
                )
            )

        blocked = self.create_upload(token, task_id, "unknown-attempt-b")
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(
            blocked.json()["error"]["code"], "upload_reconciliation_required"
        )
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(UploadJob).where(
                        UploadJob.task_id == task_id
                    )
                ),
                jobs_before,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(OutboxEvent)
                ),
                outbox_before,
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.event_type == "upload.queued",
                        AuditEvent.trace_id == processed.trace_id,
                    )
                ),
                queued_audits_before,
            )

        _, admin_token = self.create_role_session("ops_admin")
        reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{first_id}/reconcile",
            headers=self.bearer(admin_token),
            json={"status": "failed", "error_code": "not_created"},
        )
        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        retry = self.create_upload(token, task_id, "unknown-attempt-b")
        self.assertEqual(retry.status_code, 201, retry.text)
        self.assertEqual(retry.json()["status"], "queued")

    def test_active_upload_blocks_fresh_idempotency_key(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="active-fresh-key-task"
        )
        first = self.create_upload(token, task_id, "active-attempt-a")
        first_id = first.json()["id"]

        for status in ("queued", "running", "cancel_pending"):
            with self.subTest(status=status):
                with self.app.state.session_factory() as db:
                    job = db.get(UploadJob, first_id)
                    job.status = status
                    db.commit()

                blocked = self.create_upload(
                    token, task_id, f"active-attempt-{status}"
                )
                self.assertEqual(blocked.status_code, 409, blocked.text)
                self.assertEqual(
                    blocked.json()["error"]["code"], "upload_in_progress"
                )

        replay = self.create_upload(token, task_id, "active-attempt-a")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], first_id)
        with self.app.state.session_factory() as db:
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(UploadJob).where(
                        UploadJob.task_id == task_id
                    )
                ),
                1,
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(OutboxEvent)), 1
            )
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.event_type == "upload.queued",
                        AuditEvent.entity_id == first_id,
                    )
                ),
                1,
            )

    def test_worker_does_not_submit_sibling_while_result_is_unknown(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(
            token, task_key="unknown-worker-sibling-task"
        )
        first = self.create_upload(token, task_id, "unknown-worker-attempt-a")
        first_id = first.json()["id"]
        first_result = process_upload_job(
            self.app.state.session_factory,
            first_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(first_result.status, "unknown")

        with self.app.state.session_factory() as db:
            first_job = db.get(UploadJob, first_id)
            self.assertIsNotNone(first_job)
            sibling = UploadJob(
                tenant_id=first_job.tenant_id,
                task_id=first_job.task_id,
                user_id=first_job.user_id,
                device_id=first_job.device_id,
                card_allocation_id=first_job.card_allocation_id,
                idempotency_key="unknown-worker-attempt-b",
                business_name=first_job.business_name,
                trace_id=first_job.trace_id,
                status="queued",
                policy_version=first_job.policy_version,
            )
            db.add(sibling)
            db.commit()
            sibling_id = sibling.id

        adapter = FakeSub2Adapter()
        blocked = process_upload_job(
            self.app.state.session_factory,
            sibling_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(blocked.status, "failed")
        self.assertEqual(blocked.error_code, "upload_reconciliation_required")
        self.assertEqual(adapter.commands, [])
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(UploadJob, first_id).status, "unknown")
            self.assertEqual(db.get(Task, task_id).status, "created")
            allocation = db.get(CardAllocation, allocation_id)
            self.assertEqual(allocation.status, "active")
            self.assertIsNone(allocation.released_at)

    def test_only_definitive_adapter_rejection_becomes_failed(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        rejected = self.create_upload(token, task_id, "upload-rejected")
        rejected_adapter = FakeSub2Adapter(
            error=Sub2AdapterError("definitive 4xx rejection")
        )
        rejected_job = process_upload_job(
            self.app.state.session_factory,
            rejected.json()["id"],
            adapter=rejected_adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(rejected_job.status, "failed")
        self.assertEqual(rejected_job.error_code, "external_rejected")

        ambiguous = self.create_upload(token, task_id, "upload-ambiguous")
        ambiguous_adapter = FakeSub2Adapter(
            error=RuntimeError("unexpected disconnect")
        )
        ambiguous_job = process_upload_job(
            self.app.state.session_factory,
            ambiguous.json()["id"],
            adapter=ambiguous_adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(ambiguous_job.status, "unknown")
        self.assertEqual(ambiguous_job.error_code, "external_unknown")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "created")
            allocation = db.get(CardAllocation, allocation_id)
            self.assertEqual(allocation.status, "active")
            self.assertIsNone(allocation.released_at)
            rejected_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == rejected.json()["id"],
                    AuditEvent.event_type == "upload.failed",
                )
            )
            ambiguous_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == ambiguous.json()["id"],
                    AuditEvent.event_type == "upload.unknown",
                )
            )
            for worker_audit in (rejected_audit, ambiguous_audit):
                self.assertEqual(worker_audit.user_id, self.identity.user_id)
                self.assertEqual(worker_audit.device_id, self.identity.device_id)
                self.assertEqual(worker_audit.actor_id, "worker-sub2")
                self.assertNotEqual(worker_audit.actor_id, worker_audit.user_id)

    def test_closed_task_blocks_upload_before_card_validation(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        headers = self.bearer(token)
        closed = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=headers
        )
        self.assertEqual(closed.status_code, 200, closed.text)
        blocked = self.create_upload(token, task_id, "upload-after-close")
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertEqual(blocked.json()["error"]["code"], "conflict")
        self.assertIn("closed or expired", blocked.json()["error"]["message"])

    def test_owner_can_cancel_queued_upload_idempotently(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-cancel")
        job_id = queued.json()["id"]
        cancelled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(token),
        )
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancelled")
        replay = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(token),
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
        self.assertEqual(len(cancel_events), 1)

    def test_cancel_response_rechecks_operator_role_after_commit(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="upload-cancel-response-role-task"
        )
        queued = self.create_upload(token, task_id, "upload-cancel-response-role")
        job_id = queued.json()["id"]
        original_commit = Session.commit
        role_changed = False

        def commit_then_change_role(session: Session) -> None:
            nonlocal role_changed
            cancelling = any(
                isinstance(item, AuditEvent)
                and item.event_type == "upload.cancel_requested"
                for item in session.new
            )
            original_commit(session)
            if not cancelling or role_changed:
                return
            role_changed = True
            with self.app.state.session_factory() as other:
                actor = other.get(User, self.identity.user_id)
                self.assertIsNotNone(actor)
                actor.role = "security_auditor"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_change_role):
            response = self.request(
                "POST",
                f"/api/v1/upload-jobs/{job_id}/cancel",
                headers=self.bearer(token),
            )

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn('"status":"cancelled"', response.text)
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(UploadJob, job_id).status, "cancelled")
            self.assertEqual(
                db.scalar(
                    select(func.count()).select_from(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                ),
                1,
            )

    def test_admin_cancel_rechecks_target_after_commit(self) -> None:
        owner_token = self.login()
        task_id, _ = self.create_task_with_card(
            owner_token, task_key="upload-admin-cancel-target-task"
        )
        queued = self.create_upload(
            owner_token,
            task_id,
            "upload-admin-cancel-target",
        )
        job_id = queued.json()["id"]
        admin, admin_token = self.create_role_session("ops_admin")
        original_commit = Session.commit
        target_moved = False

        def commit_then_move_target(session: Session) -> None:
            nonlocal target_moved
            cancelling = any(
                isinstance(item, AuditEvent)
                and item.event_type == "upload.cancel_requested"
                for item in session.new
            )
            original_commit(session)
            if not cancelling or target_moved:
                return
            target_moved = True
            with self.app.state.session_factory() as other:
                job = other.get(UploadJob, job_id)
                self.assertIsNotNone(job)
                job.tenant_id = "tenant-other"
                original_commit(other)

        with mock.patch.object(Session, "commit", new=commit_then_move_target):
            response = self.request(
                "POST",
                f"/api/v1/upload-jobs/{job_id}/cancel",
                headers=self.bearer(admin_token),
            )

        self.assertEqual(response.status_code, 404, response.text)
        self.assertNotIn('"status":"cancelled"', response.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            cancel_event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job_id,
                    AuditEvent.event_type == "upload.cancel_requested",
                )
            )
        self.assertEqual(job.tenant_id, "tenant-other")
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(cancel_event.actor_id, admin.user_id)

    def test_admin_cancel_rechecks_actor_after_authentication(self) -> None:
        owner_token = self.login()
        task_id, _ = self.create_task_with_card(owner_token)
        queued = self.create_upload(owner_token, task_id, "upload-stale-admin-cancel")
        job_id = queued.json()["id"]
        admin, _admin_token = self.create_role_session("ops_admin")
        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=admin.user_id,
            tenant_id="tenant-upload",
            device_id=admin.device_id,
            email="upload-tenant-upload-ops_admin@example.test",
            role="ops_admin",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            actor = db.get(User, admin.user_id)
            actor.role = "operator"
            db.commit()

        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            cancelled = self.request(
                "POST", f"/api/v1/upload-jobs/{job_id}/cancel"
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(cancelled.status_code, 403, cancelled.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
        self.assertEqual(job.status, "queued")
        self.assertEqual(cancel_events, [])

    def test_operator_upload_reads_and_cancel_recheck_current_role(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-stale-operator-access")
        job_id = queued.json()["id"]
        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-upload",
            device_id=self.identity.device_id,
            email="upload-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            actor = db.get(User, self.identity.user_id)
            actor.role = "security_auditor"
            db.commit()

        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            replayed = self.request(
                "POST",
                f"/api/v1/tasks/{task_id}/uploads",
                json={
                    "business_name": "Example Store",
                    "idempotency_key": "upload-stale-operator-access",
                },
            )
            reads = [
                self.request("GET", f"/api/v1/uploads/{job_id}"),
                self.request("GET", f"/api/v1/upload-jobs/{job_id}"),
            ]
            cancelled = self.request(
                "POST", f"/api/v1/upload-jobs/{job_id}/cancel"
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(replayed.status_code, 403, replayed.text)
        self.assertEqual([response.status_code for response in reads], [403, 403])
        self.assertEqual(cancelled.status_code, 403, cancelled.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
        self.assertEqual(job.status, "queued")
        self.assertEqual(cancel_events, [])

    def test_upload_conflict_rechecks_operator_after_rollback(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        created = self.create_upload(token, task_id, "upload-rollback-recheck")
        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=self.identity.user_id,
            tenant_id="tenant-upload",
            device_id=self.identity.device_id,
            email="upload-owner@example.test",
            role="operator",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        original_scalar = Session.scalar
        original_rollback = Session.rollback
        upload_lookups = 0
        role_changed = False

        def scalar(session, statement, *args, **kwargs):
            nonlocal upload_lookups
            entity = statement.column_descriptions[0].get("entity")
            if entity is UploadJob:
                upload_lookups += 1
                if upload_lookups == 1:
                    return None
            return original_scalar(session, statement, *args, **kwargs)

        def rollback(session):
            nonlocal role_changed
            result = original_rollback(session)
            if not role_changed:
                role_changed = True
                with self.app.state.session_factory() as other:
                    other.get(User, self.identity.user_id).role = "security_auditor"
                    other.commit()
            return result

        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            with mock.patch.object(Session, "scalar", scalar), mock.patch.object(
                Session,
                "rollback",
                rollback,
            ):
                replay = self.request(
                    "POST",
                    f"/api/v1/tasks/{task_id}/uploads",
                    json={
                        "business_name": "Example Store",
                        "idempotency_key": "upload-rollback-recheck",
                    },
                )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(replay.status_code, 403, replay.text)
        for sensitive in (
            created.json()["business_name"],
            created.json()["trace_id"],
            created.json()["id"],
        ):
            self.assertNotIn(sensitive, replay.text)

    def test_admin_roles_cancel_tenant_uploads_with_actor_subject_audit(self) -> None:
        owner_token = self.login()
        with self.app.state.session_factory() as db:
            db.add(
                Card(
                    tenant_id="tenant-upload",
                    provider_ref="provider-upload-admin-cancel-card",
                    brand="VISA",
                    last4="4444",
                    secret_ref="vault://cards/upload-admin-cancel-card",
                )
            )
            db.commit()

        privileged = {
            role: self.create_role_session(role)
            for role in ("ops_admin", "platform_admin")
        }
        cases = (
            ("ops_admin", "queued", "cancelled"),
            ("platform_admin", "running", "cancel_pending"),
        )
        for index, (role, source_status, expected_status) in enumerate(cases):
            with self.subTest(role=role, source_status=source_status):
                task_id, _ = self.create_task_with_card(
                    owner_token,
                    task_key=f"upload-admin-cancel-task-{index}",
                )
                queued = self.create_upload(
                    owner_token,
                    task_id,
                    f"upload-admin-cancel-{index}",
                )
                job_id = queued.json()["id"]
                if source_status == "running":
                    with self.app.state.session_factory() as db:
                        job = db.get(UploadJob, job_id)
                        job.status = "running"
                        db.commit()

                admin_identity, admin_token = privileged[role]
                cancelled = self.request(
                    "POST",
                    f"/api/v1/upload-jobs/{job_id}/cancel",
                    headers=self.bearer(admin_token),
                )
                replay = self.request(
                    "POST",
                    f"/api/v1/upload-jobs/{job_id}/cancel",
                    headers=self.bearer(admin_token),
                )
                self.assertEqual(cancelled.status_code, 200, cancelled.text)
                self.assertEqual(cancelled.json()["status"], expected_status)
                self.assertEqual(replay.status_code, 200, replay.text)
                self.assertEqual(replay.json()["status"], expected_status)

                if index == 0:
                    closed = self.request(
                        "POST",
                        f"/api/v1/tasks/{task_id}/close",
                        headers=self.bearer(owner_token),
                    )
                    self.assertEqual(closed.status_code, 200, closed.text)

                with self.app.state.session_factory() as db:
                    cancel_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == job_id,
                                AuditEvent.event_type == "upload.cancel_requested",
                            )
                        )
                    )
                self.assertEqual(len(cancel_events), 1)
                self.assertEqual(cancel_events[0].user_id, self.identity.user_id)
                self.assertEqual(cancel_events[0].device_id, self.identity.device_id)
                self.assertEqual(cancel_events[0].actor_id, admin_identity.user_id)

    def test_auditor_and_cross_tenant_admin_cannot_cancel_upload(self) -> None:
        owner_token = self.login()
        task_id, _ = self.create_task_with_card(
            owner_token,
            task_key="upload-cancel-role-boundary-task",
        )
        queued = self.create_upload(
            owner_token,
            task_id,
            "upload-cancel-role-boundary",
        )
        job_id = queued.json()["id"]
        _, auditor_token = self.create_role_session("security_auditor")
        _, cross_tenant_token = self.create_role_session(
            "ops_admin",
            tenant_id="tenant-other",
        )

        auditor_response = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(auditor_token),
        )
        cross_tenant_response = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(cross_tenant_token),
        )
        self.assertEqual(auditor_response.status_code, 403, auditor_response.text)
        self.assertEqual(cross_tenant_response.status_code, 404, cross_tenant_response.text)

        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(UploadJob, job_id).status, "queued")
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
        self.assertEqual(cancel_events, [])

    def test_owner_can_replay_running_upload_cancellation(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-cancel-running")
        job_id = queued.json()["id"]
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            job.status = "running"
            db.commit()

        cancelled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(token),
        )
        replay = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(token),
        )
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancel_pending")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "cancel_pending")

        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(self.adapter.commands, [])
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
            unknown_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
        self.assertEqual(job.status, "unknown")
        self.assertEqual(job.error_code, "external_unknown")
        self.assertEqual(len(cancel_events), 1)
        self.assertEqual(len(unknown_events), 1)
        self.assertEqual(unknown_events[0].actor_id, "worker-sub2")

    def test_cancellation_replay_returns_concurrent_worker_unknown_state(
        self,
    ) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="upload-cancel-replay-worker-task"
        )
        queued = self.create_upload(
            token, task_id, "upload-cancel-replay-worker"
        )
        job_id = queued.json()["id"]
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            job.status = "running"
            db.commit()
        first = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/cancel",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["status"], "cancel_pending")

        entered = Event()
        release = Event()
        original_scalar = Session.scalar
        blocked = False

        def block_after_stale_cancel_read(session, statement, *args, **kwargs):
            nonlocal blocked
            result = original_scalar(session, statement, *args, **kwargs)
            if (
                not blocked
                and isinstance(result, UploadJob)
                and result.id == job_id
                and result.status == "cancel_pending"
            ):
                blocked = True
                session.commit()
                entered.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("cancel replay release timed out")
            return result

        with mock.patch.object(Session, "scalar", new=block_after_stale_cancel_read):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.request,
                    "POST",
                    f"/api/v1/upload-jobs/{job_id}/cancel",
                    headers=self.bearer(token),
                )
                self.assertTrue(entered.wait(timeout=5))
                process_upload_job(
                    self.app.state.session_factory,
                    job_id,
                    adapter=self.adapter,
                    policy=self.app.state.sub2_policy,
                )
                with self.app.state.session_factory() as db:
                    worker_result = db.get(UploadJob, job_id)
                    self.assertEqual(worker_result.status, "unknown")
                    self.assertEqual(worker_result.error_code, "external_unknown")
                release.set()
                replay = future.result(timeout=10)

        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "unknown")
        self.assertEqual(replay.json()["error_code"], "external_unknown")
        with self.app.state.session_factory() as db:
            cancel_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.cancel_requested",
                    )
                )
            )
            unknown_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.unknown",
                    )
                )
            )
        self.assertEqual(len(cancel_events), 1)
        self.assertEqual(len(unknown_events), 1)

    def test_terminal_uploads_return_stable_cancel_conflict_without_audit(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(
            token, task_key="upload-cancel-terminal-task"
        )
        queued = self.create_upload(token, task_id, "upload-cancel-terminal")
        job_id = queued.json()["id"]
        for status in ("succeeded", "failed", "unknown"):
            with self.subTest(status=status):
                with self.app.state.session_factory() as db:
                    job = db.get(UploadJob, job_id)
                    job.status = status
                    db.commit()

                rejected = self.request(
                    "POST",
                    f"/api/v1/upload-jobs/{job_id}/cancel",
                    headers=self.bearer(token),
                )
                self.assertEqual(rejected.status_code, 409, rejected.text)
                self.assertEqual(
                    rejected.json()["error"]["code"], "upload_not_cancellable"
                )
                with self.app.state.session_factory() as db:
                    self.assertEqual(db.get(UploadJob, job_id).status, status)
                    cancel_events = list(
                        db.scalars(
                            select(AuditEvent).where(
                                AuditEvent.entity_id == job_id,
                                AuditEvent.event_type == "upload.cancel_requested",
                            )
                        )
                    )
                self.assertEqual(cancel_events, [])

    def test_cancel_cas_cannot_overwrite_concurrent_worker_success(self) -> None:
        original_app = self.app
        original_identity = self.identity
        original_password = self.password
        original_mailbox_id = self.mailbox_id
        release_cancel_update = Event()
        listener_installed = False

        with tempfile.TemporaryDirectory(prefix="upload-cancel-race-") as directory:
            database_path = Path(directory) / "uploads.db"
            race_adapter = FakeSub2Adapter()
            race_app = create_app(
                Settings(
                    environment="test",
                    database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
                    jwt_hmac_secret="upload-race-hmac-secret-that-is-not-production",
                    sub2_policy_version="sub2-policy-race",
                    sub2_group_id=49,
                    sub2_concurrency=4,
                ),
                sub2_adapter=race_adapter,
            )
            try:
                with race_app.state.engine.connect() as connection:
                    connection.exec_driver_sql("PRAGMA journal_mode=WAL")
                self.app = race_app
                self.password = "upload-race-owner-password"
                self.identity = create_user_with_device(
                    race_app.state.session_factory,
                    tenant_id="tenant-upload",
                    email="upload-owner@example.test",
                    password=self.password,
                    device_name="upload-race-device",
                )
                with race_app.state.session_factory() as db:
                    card = Card(
                        tenant_id="tenant-upload",
                        provider_ref="provider-upload-race-card",
                        brand="VISA",
                        last4="3333",
                        secret_ref="vault://cards/upload-race-card",
                    )
                    mailbox = Mailbox(
                        tenant_id="tenant-upload",
                        email_masked="r***@example.test",
                        connector_type="http",
                        secret_ref="vault://secret/mailboxes/upload-race",
                    )
                    db.add_all([card, mailbox])
                    db.flush()
                    self.mailbox_id = mailbox.id
                    db.commit()

                token = self.login()
                task_id, _ = self.create_task_with_card(token)
                queued = self.create_upload(token, task_id, "upload-cancel-race")
                job_id = queued.json()["id"]
                cancel_update_seen = Event()

                def block_first_cancel_update(
                    _connection,
                    _cursor,
                    statement,
                    _parameters,
                    _context,
                    _executemany,
                ) -> None:
                    if (
                        statement.lstrip().upper().startswith("UPDATE UPLOAD_JOBS")
                        and not cancel_update_seen.is_set()
                    ):
                        cancel_update_seen.set()
                        release_cancel_update.wait(timeout=10)

                event.listen(
                    race_app.state.engine,
                    "before_cursor_execute",
                    block_first_cancel_update,
                )
                listener_installed = True
                with ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="cancel-request"
                ) as executor:
                    cancel_future = executor.submit(
                        self.request,
                        "POST",
                        f"/api/v1/upload-jobs/{job_id}/cancel",
                        headers=self.bearer(token),
                    )
                    self.assertTrue(cancel_update_seen.wait(timeout=5))
                    try:
                        worker_result = process_upload_job(
                            race_app.state.session_factory,
                            job_id,
                            adapter=race_adapter,
                            policy=race_app.state.sub2_policy,
                        )
                    finally:
                        release_cancel_update.set()
                    cancel_response = cancel_future.result(timeout=10)

                self.assertEqual(worker_result.status, "succeeded")
                self.assertEqual(cancel_response.status_code, 409, cancel_response.text)
                self.assertEqual(
                    cancel_response.json()["error"]["code"],
                    "upload_not_cancellable",
                )
                self.assertEqual(len(race_adapter.commands), 1)
                with race_app.state.session_factory() as db:
                    job = db.get(UploadJob, job_id)
                    task = db.get(Task, task_id)
                    event_types = list(
                        db.scalars(
                            select(AuditEvent.event_type).where(
                                AuditEvent.entity_id == job_id
                            )
                        )
                    )
                    self.assertEqual(job.status, "succeeded")
                    self.assertEqual(task.status, "completed")
                    self.assertEqual(event_types.count("upload.succeeded"), 1)
                    self.assertEqual(event_types.count("upload.cancel_requested"), 0)
            finally:
                release_cancel_update.set()
                if listener_installed:
                    event.remove(
                        race_app.state.engine,
                        "before_cursor_execute",
                        block_first_cancel_update,
                    )
                self.app = original_app
                self.identity = original_identity
                self.password = original_password
                self.mailbox_id = original_mailbox_id
                race_app.state.engine.dispose()

    def test_reconcile_rechecks_admin_after_authentication(self) -> None:
        token = self.login()
        task_id, _allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "stale-admin-reconcile")
        job_id = queued.json()["id"]
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        actor, _actor_token = self.create_role_session("ops_admin")
        observed_at = datetime.now(timezone.utc)
        stale_principal = AuthPrincipal(
            user_id=actor.user_id,
            tenant_id="tenant-upload",
            device_id=actor.device_id,
            email="upload-tenant-upload-ops_admin@example.test",
            role="ops_admin",
            identity_kind="local",
            auth_time=None,
            acr=None,
            amr=(),
            access_token_hash="a" * 64,
            access_token_expires_at=observed_at + timedelta(minutes=15),
            access_token_revoked=False,
        )
        with self.app.state.session_factory() as db:
            current_actor = db.get(User, actor.user_id)
            current_actor.role = "operator"
            db.commit()

        self.app.dependency_overrides[get_current_principal] = lambda: stale_principal
        try:
            response = self.request(
                "POST",
                f"/api/v1/upload-jobs/{job_id}/reconcile",
                json={"status": "failed", "error_code": "not_created"},
            )
        finally:
            self.app.dependency_overrides.pop(get_current_principal, None)

        self.assertEqual(response.status_code, 403, response.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            reconciled_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.reconciled",
                    )
                )
            )
        self.assertEqual(job.status, "unknown")
        self.assertEqual(job.error_code, "external_unknown")
        self.assertEqual(reconciled_audits, [])

    def test_security_auditor_can_reconcile_unknown_upload(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "auditor-reconcile")
        job_id = queued.json()["id"]
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        auditor, auditor_token = self.create_role_session("security_auditor")

        unsafe_error_code = "vault://sub2/prod Authorization=Bearer TOP_SECRET"
        rejected = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(auditor_token),
            json={"status": "failed", "error_code": unsafe_error_code},
        )

        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertEqual(rejected.json()["error"]["code"], "validation_error")
        for forbidden in (
            unsafe_error_code,
            "vault://sub2/prod",
            "Bearer TOP_SECRET",
        ):
            self.assertNotIn(forbidden, rejected.text)
        with self.app.state.session_factory() as db:
            unchanged_job = db.get(UploadJob, job_id)
            rejected_audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.reconciled",
                    )
                )
            )
        self.assertEqual(unchanged_job.status, "unknown")
        self.assertEqual(unchanged_job.error_code, "external_unknown")
        self.assertEqual(rejected_audits, [])

        reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(auditor_token),
            json={"status": "failed", "error_code": "  not_created  "},
        )

        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        self.assertEqual(reconciled.json()["status"], "failed")
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            audits = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.reconciled",
                    )
                )
            )
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.error_code, "not_created")
        self.assertEqual(task.status, "created")
        self.assertEqual(allocation.status, "active")
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0].user_id, self.identity.user_id)
        self.assertEqual(audits[0].device_id, self.identity.device_id)
        self.assertEqual(audits[0].actor_id, auditor.user_id)
        self.assertNotIn("external_ref", audits[0].details_json)

    def test_reconcile_rejects_unsafe_external_ref_without_mutation(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(
            token,
            task_key="unsafe-reconcile-external-ref-task",
        )
        queued = self.create_upload(token, task_id, "unsafe-reconcile-external-ref")
        job_id = queued.json()["id"]
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        _admin, admin_token = self.create_role_session("ops_admin")
        unsafe_external_ref = (
            "vault://sub2/prod Authorization=Bearer RECONCILE_SECRET"
        )

        rejected = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(admin_token),
            json={"status": "succeeded", "external_ref": unsafe_external_ref},
        )

        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertEqual(rejected.json()["error"]["code"], "validation_error")
        for forbidden in (
            unsafe_external_ref,
            "vault://sub2/prod",
            "Bearer RECONCILE_SECRET",
        ):
            self.assertNotIn(forbidden, rejected.text)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, job_id)
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            reconciled_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.event_type == "upload.reconciled",
                    )
                )
            )
        self.assertEqual(job.status, "unknown")
        self.assertEqual(job.error_code, "external_unknown")
        self.assertIsNone(job.external_ref)
        self.assertEqual(task.status, "created")
        self.assertEqual(allocation.status, "active")
        self.assertEqual(reconciled_events, [])

        reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(admin_token),
            json={
                "status": "succeeded",
                "external_ref": "  sub2-confirmed-1  ",
            },
        )
        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        self.assertEqual(reconciled.json()["external_ref"], "sub2-confirmed-1")

    def test_confirmed_upload_success_does_not_overwrite_expired_task(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(
            token, task_key="expired-before-reconcile-task"
        )
        queued = self.create_upload(token, task_id, "expired-before-reconcile")
        job_id = queued.json()["id"]
        processed = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed.status, "unknown")

        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            transition_task_to_terminal(
                task,
                db,
                now=utc_now(),
                task_status="expired",
                card_status="expired",
                mail_status="expired",
                release_reason="task_ttl_expired",
                actor_user_id="worker-lifecycle",
                actor_device_id=None,
                finalize_upload_outbox=True,
            )
            db.commit()

        _, admin_token = self.create_role_session("ops_admin")
        reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(admin_token),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-expired"},
        )

        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        self.assertEqual(reconciled.json()["status"], "succeeded")
        self.assertEqual(
            reconciled.json()["external_ref"], "sub2-confirmed-expired"
        )
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            job = db.get(UploadJob, job_id)
            event_types = list(db.scalars(select(AuditEvent.event_type)))
        self.assertEqual(task.status, "expired")
        self.assertEqual(allocation.status, "expired")
        self.assertIsNotNone(allocation.released_at)
        self.assertEqual(job.status, "succeeded")
        self.assertEqual(event_types.count("upload.reconciled"), 1)
        self.assertEqual(event_types.count("task.expired"), 1)
        self.assertEqual(event_types.count("task.completed"), 0)

    def test_status_lookup_success_completes_task_and_releases_resources(self) -> None:
        token = self.login()
        task_id, allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-success-task",
            upload_key="lookup-success-upload",
        )
        adapter = FakeSub2ReconciliationAdapter(
            Sub2LookupResult(
                state=Sub2LookupState.SUCCEEDED,
                external_ref="sub2-looked-up-1",
            )
        )

        reconciled = reconcile_unknown_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertIsNotNone(reconciled)
        self.assertEqual(reconciled.status, "succeeded")
        self.assertEqual(reconciled.phase, "reconciliation_result")
        self.assertEqual(reconciled.phase_sequence, 5)
        self.assertEqual(reconciled.external_ref, "sub2-looked-up-1")
        self.assertEqual(len(adapter.commands), 1)
        command = adapter.commands[0]
        self.assertEqual(command.job_id, job_id)
        self.assertEqual(command.task_id, task_id)
        self.assertEqual(command.provider_idempotency_key, job_id)
        self.assertNotIn("lookup-success-upload", repr(command))
        self.assertNotIn("vault://sub2/credential", repr(command))
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "completed")
            self.assertEqual(db.get(CardAllocation, allocation_id).status, "released")
            session = db.scalar(select(MailSession).where(MailSession.task_id == task_id))
            self.assertEqual(session.status, "revoked")
            audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job_id,
                    AuditEvent.event_type == "upload.reconciled",
                    AuditEvent.actor_id == "worker-sub2",
                )
            )
            self.assertIsNotNone(audit)
            self.assertNotIn("sub2-looked-up-1", audit.details_json)
            phase_events = list(
                db.scalars(
                    select(AuditEvent)
                    .where(
                        AuditEvent.entity_id == job_id,
                        AuditEvent.aggregate_sequence.is_not(None),
                    )
                    .order_by(AuditEvent.aggregate_sequence)
                )
            )
            self.assertEqual(
                [event.event_type for event in phase_events[-2:]],
                [
                    "upload.reconciliation_started",
                    "upload.reconciliation_result_received",
                ],
            )
            self.assertEqual(
                [event.aggregate_sequence for event in phase_events],
                list(range(1, 6)),
            )

    def test_status_lookup_failure_allows_controlled_retry_without_releasing_resources(self) -> None:
        token = self.login()
        task_id, allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-failed-task",
            upload_key="lookup-failed-upload",
        )
        adapter = FakeSub2ReconciliationAdapter(
            Sub2LookupResult(state=Sub2LookupState.FAILED)
        )

        reconciled = reconcile_unknown_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(reconciled.status, "failed")
        self.assertEqual(reconciled.error_code, "reconciled_external_rejected")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "created")
            allocation = db.get(CardAllocation, allocation_id)
            self.assertEqual(allocation.status, "active")
            self.assertIsNone(allocation.released_at)

    def test_nonterminal_lookup_results_never_authorize_retry(self) -> None:
        token = self.login()
        task_id, allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-nonterminal-task",
            upload_key="lookup-nonterminal-upload",
        )
        expected_errors = {
            Sub2LookupState.PROCESSING: "external_processing",
            Sub2LookupState.NOT_FOUND: "external_not_found_unconfirmed",
            Sub2LookupState.UNKNOWN: "external_unknown",
        }
        for state, expected_error in expected_errors.items():
            with self.subTest(state=state.value):
                reconciled = reconcile_unknown_upload_job(
                    self.app.state.session_factory,
                    job_id,
                    adapter=FakeSub2ReconciliationAdapter(
                        Sub2LookupResult(state=state)
                    ),
                    policy=self.app.state.sub2_policy,
                )
                self.assertEqual(reconciled.status, "unknown")
                self.assertEqual(reconciled.error_code, expected_error)
                with self.app.state.session_factory() as db:
                    self.assertEqual(db.get(Task, task_id).status, "created")
                    self.assertEqual(
                        db.get(CardAllocation, allocation_id).status, "active"
                    )

    def test_lookup_transport_error_and_invalid_success_remain_unknown(self) -> None:
        token = self.login()
        _task_id, _allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-ambiguous-task",
            upload_key="lookup-ambiguous-upload",
        )
        adapters = (
            FakeSub2ReconciliationAdapter(error=TimeoutError("supplier timeout secret")),
            FakeSub2ReconciliationAdapter(
                Sub2LookupResult(state=Sub2LookupState.SUCCEEDED)
            ),
        )
        for index, adapter in enumerate(adapters):
            with self.subTest(index=index):
                reconciled = reconcile_unknown_upload_job(
                    self.app.state.session_factory,
                    job_id,
                    adapter=adapter,
                    policy=self.app.state.sub2_policy,
                )
                self.assertEqual(reconciled.status, "unknown")
                self.assertEqual(reconciled.error_code, "external_unknown")
                self.assertNotIn("supplier timeout secret", repr(reconciled))

    def test_lookup_does_not_query_a_job_that_is_no_longer_unknown(self) -> None:
        token = self.login()
        task_id, _allocation_id = self.create_task_with_card(
            token, task_key="lookup-terminal-task"
        )
        queued = self.create_upload(token, task_id, "lookup-terminal-upload")
        job_id = queued.json()["id"]
        processed = process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=FakeSub2Adapter(),
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed.status, "succeeded")
        adapter = FakeSub2ReconciliationAdapter(
            Sub2LookupResult(state=Sub2LookupState.FAILED)
        )

        unchanged = reconcile_unknown_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(unchanged.status, "succeeded")
        self.assertEqual(adapter.commands, [])

    def test_lookup_result_cannot_overwrite_a_concurrent_reconciliation(self) -> None:
        token = self.login()
        _task_id, _allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-race-task",
            upload_key="lookup-race-upload",
        )
        session_factory = self.app.state.session_factory

        class RacingAdapter:
            def query(self, _command):
                with session_factory() as db:
                    raced_job = db.get(UploadJob, job_id)
                    raced_job.status = "failed"
                    raced_job.error_code = "manual_winner"
                    db.commit()
                return Sub2LookupResult(
                    state=Sub2LookupState.SUCCEEDED,
                    external_ref="late-external-ref",
                )

        result = reconcile_unknown_upload_job(
            session_factory,
            job_id,
            adapter=RacingAdapter(),
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error_code, "manual_winner")
        self.assertIsNone(result.external_ref)

    def test_lookup_response_refreshes_after_concurrent_reconciliation(self) -> None:
        token = self.login()
        _task_id, _allocation_id, job_id = self.create_unknown_upload(
            token,
            task_key="lookup-response-race-task",
            upload_key="lookup-response-race-upload",
        )
        session_factory = self.app.state.session_factory
        lookup_observed = Event()
        commit_entered = Event()
        release_commit = Event()

        class ProcessingAdapter:
            def query(self, _command):
                lookup_observed.set()
                return Sub2LookupResult(state=Sub2LookupState.PROCESSING)

        original_commit = Session.commit

        def pause_after_stale_commit(session):
            if (
                current_thread().name.startswith("lookup-stale")
                and lookup_observed.is_set()
                and not commit_entered.is_set()
            ):
                original_commit(session)
                commit_entered.set()
                self.assertTrue(release_commit.wait(timeout=5))
                return None
            return original_commit(session)

        try:
            with mock.patch.object(Session, "commit", pause_after_stale_commit):
                with ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="lookup-stale"
                ) as executor:
                    stale = executor.submit(
                        reconcile_unknown_upload_job,
                        session_factory,
                        job_id,
                        adapter=ProcessingAdapter(),
                        policy=self.app.state.sub2_policy,
                    )
                    self.assertTrue(commit_entered.wait(timeout=5))
                    winner = reconcile_unknown_upload_job(
                        session_factory,
                        job_id,
                        adapter=FakeSub2ReconciliationAdapter(
                            Sub2LookupResult(
                                state=Sub2LookupState.SUCCEEDED,
                                external_ref="reconciled-winner",
                            )
                        ),
                        policy=self.app.state.sub2_policy,
                    )
                    self.assertEqual(winner.status, "succeeded")
                    release_commit.set()
                    stale_result = stale.result(timeout=5)
        finally:
            release_commit.set()

        self.assertEqual(stale_result.status, "succeeded")
        self.assertEqual(stale_result.external_ref, "reconciled-winner")

    def test_unknown_upload_requires_privileged_reconciliation(self) -> None:
        token = self.login()
        task_id, allocation_id = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-reconcile")
        job_id = queued.json()["id"]
        unknown_adapter = FakeSub2Adapter(unknown=True)
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=unknown_adapter,
            policy=self.app.state.sub2_policy,
        )
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "created")
            self.assertEqual(db.get(CardAllocation, allocation_id).status, "active")
        close_unknown = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
        )
        self.assertEqual(close_unknown.status_code, 409, close_unknown.text)
        self.assertEqual(close_unknown.json()["error"]["code"], "upload_result_unknown")
        with self.app.state.session_factory() as db:
            self.assertEqual(db.get(Task, task_id).status, "created")
            self.assertEqual(db.get(UploadJob, job_id).status, "unknown")
            self.assertEqual(db.get(CardAllocation, allocation_id).status, "active")
        forbidden = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(token),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)

        role_tokens: dict[str, str] = {}
        role_identities = {}
        for role in ("security_auditor", "ops_admin", "platform_admin"):
            password = f"upload-{role}-account-password"
            email = f"upload-{role}@example.test"
            identity = create_user_with_device(
                self.app.state.session_factory,
                tenant_id="tenant-upload",
                email=email,
                password=password,
                device_name=f"upload-{role}-device",
                role=role,
            )
            login = self.request(
                "POST",
                "/api/v1/auth/login",
                json={
                    "tenant_id": "tenant-upload",
                    "email": email,
                    "password": password,
                    "device_id": identity.device_id,
                },
            )
            self.assertEqual(login.status_code, 200, login.text)
            role_tokens[role] = login.json()["access_token"]
            role_identities[role] = identity

        from platform import lifecycle

        original_release = lifecycle.release_task_resources
        skipped_first_phase = False

        def simulate_locked_resources(*args, **kwargs):
            nonlocal skipped_first_phase
            if kwargs.get("skip_locked") and not skipped_first_phase:
                skipped_first_phase = True
                return LifecycleSweepResult()
            return original_release(*args, **kwargs)

        with mock.patch(
            "platform.lifecycle.release_task_resources",
            side_effect=simulate_locked_resources,
        ):
            reconciled = self.request(
                "POST",
                f"/api/v1/upload-jobs/{job_id}/reconcile",
                headers=self.bearer(role_tokens["ops_admin"]),
                json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
            )
        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        self.assertTrue(skipped_first_phase)
        self.assertEqual(reconciled.json()["status"], "succeeded")
        self.assertEqual(reconciled.json()["external_ref"], "sub2-confirmed-1")
        with self.app.state.session_factory() as db:
            task = db.get(Task, task_id)
            allocation = db.get(CardAllocation, allocation_id)
            session = db.scalar(
                select(MailSession).where(MailSession.task_id == task_id)
            )
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(task.status, "completed")
            self.assertIsNotNone(task.closed_at)
            self.assertEqual(allocation.status, "released")
            self.assertIsNotNone(allocation.released_at)
            self.assertEqual(session.status, "revoked")
            self.assertEqual(event_types.count("upload.reconciled"), 1)
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("card.released"), 1)
            self.assertEqual(event_types.count("mail_session.revoked"), 1)
            reconciled_audit = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.entity_id == job_id,
                    AuditEvent.event_type == "upload.reconciled",
                )
            )
            self.assertEqual(reconciled_audit.user_id, self.identity.user_id)
            self.assertEqual(reconciled_audit.device_id, self.identity.device_id)
            self.assertEqual(
                reconciled_audit.actor_id,
                role_identities["ops_admin"].user_id,
            )
            self.assertNotIn("sub2-confirmed-1", reconciled_audit.details_json)
            task_trace_id = task.trace_id

        timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(token),
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        timeline_upload = timeline.json()["uploads"][-1]
        self.assertEqual(timeline_upload["phase"], "reconciliation_result")
        self.assertGreaterEqual(timeline_upload["phase_sequence"], 4)
        self.assertEqual(timeline_upload["trace_id"], task_trace_id)
        self.assertIsNotNone(timeline_upload["phase_updated_at"])
        self.assertEqual(
            sum(
                event["event_type"] == "upload.reconciled"
                for event in timeline.json()["events"]
            ),
            1,
        )
        upload_phase_events = [
            event
            for event in timeline.json()["events"]
            if event["event_type"].startswith("upload.") and event["phase"] is not None
        ]
        self.assertTrue(upload_phase_events)
        self.assertTrue(
            all(event["trace_id"] == task_trace_id for event in upload_phase_events)
        )
        owner_actor_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.bearer(role_tokens["platform_admin"]),
            params={
                "user_id": self.identity.user_id,
                "actor_id": role_identities["ops_admin"].user_id,
                "trace_id": task_trace_id,
                "event_type": "upload.reconciled",
            },
        )
        self.assertEqual(owner_actor_audit.status_code, 200, owner_actor_audit.text)
        self.assertEqual(len(owner_actor_audit.json()), 1)
        misattributed_audit = self.request(
            "GET",
            "/api/v1/admin/audit",
            headers=self.bearer(role_tokens["platform_admin"]),
            params={
                "user_id": role_identities["ops_admin"].user_id,
                "actor_id": role_identities["ops_admin"].user_id,
                "trace_id": task_trace_id,
                "event_type": "upload.reconciled",
            },
        )
        self.assertEqual(misattributed_audit.status_code, 200, misattributed_audit.text)
        self.assertEqual(misattributed_audit.json(), [])

        with self.app.state.session_factory() as db:
            sibling_device = Device(
                tenant_id="tenant-upload",
                user_id=self.identity.user_id,
                name="upload-sibling-device",
            )
            db.add(sibling_device)
            db.commit()
            sibling_device_id = sibling_device.id
        sibling_token = self.login(device_id=sibling_device_id)
        sibling_timeline = self.request(
            "GET",
            f"/api/v1/tasks/{task_id}/timeline",
            headers=self.bearer(sibling_token),
        )
        self.assertEqual(sibling_timeline.status_code, 404, sibling_timeline.text)

        close_replay = self.request(
            "POST", f"/api/v1/tasks/{task_id}/close", headers=self.bearer(token)
        )
        self.assertEqual(close_replay.status_code, 200, close_replay.text)
        self.assertEqual(close_replay.json()["status"], "completed")
        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("task.closed"), 0)

        reconcile_replay = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(role_tokens["ops_admin"]),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
        )
        self.assertEqual(reconcile_replay.status_code, 409, reconcile_replay.text)
        with self.app.state.session_factory() as db:
            event_types = list(db.scalars(select(AuditEvent.event_type)))
            self.assertEqual(event_types.count("upload.reconciled"), 1)
            self.assertEqual(event_types.count("task.completed"), 1)
            self.assertEqual(event_types.count("card.released"), 1)
            self.assertEqual(event_types.count("mail_session.revoked"), 1)

        second_task_id, second_allocation_id = self.create_task_with_card(
            token,
            task_key="upload-reconcile-failed-task",
        )
        second = self.create_upload(
            token, second_task_id, "upload-reconcile-admin"
        )
        second_id = second.json()["id"]
        process_upload_job(
            self.app.state.session_factory,
            second_id,
            adapter=FakeSub2Adapter(unknown=True),
            policy=self.app.state.sub2_policy,
        )
        admin_reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{second_id}/reconcile",
            headers=self.bearer(role_tokens["platform_admin"]),
            json={"status": "failed", "error_code": "not_created"},
        )
        self.assertEqual(admin_reconciled.status_code, 200, admin_reconciled.text)
        self.assertEqual(admin_reconciled.json()["status"], "failed")
        with self.app.state.session_factory() as db:
            second_task = db.get(Task, second_task_id)
            second_allocation = db.get(CardAllocation, second_allocation_id)
            self.assertEqual(second_task.status, "created")
            self.assertEqual(second_allocation.status, "active")
            self.assertIsNone(second_allocation.released_at)

    def test_openapi_does_not_expose_policy_secrets(self) -> None:
        schemas = self.app.openapi()["components"]["schemas"]
        props = schemas["UploadJobResponse"]["properties"]
        for forbidden in ("proxy_ref", "proxy_id", "group_id", "concurrency", "credential_ref", "token"):
            self.assertNotIn(forbidden, props)
        self.assertIn("/api/v1/tasks/{task_id}/uploads", self.app.openapi()["paths"])

    def test_worker_heartbeat_freshness_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            heartbeat_path = Path(temp_dir) / "worker.heartbeat"
            self.assertFalse(
                worker_heartbeat_is_fresh(heartbeat_path, max_age_seconds=10)
            )
            write_worker_heartbeat(heartbeat_path)
            timestamp = float(heartbeat_path.read_text(encoding="utf-8"))
            self.assertTrue(
                worker_heartbeat_is_fresh(
                    heartbeat_path, max_age_seconds=10, now=timestamp + 1
                )
            )
            self.assertFalse(
                worker_heartbeat_is_fresh(
                    heartbeat_path, max_age_seconds=10, now=timestamp + 11
                )
            )

    def test_worker_loop_writes_heartbeat(self) -> None:
        stop_event = Event()
        reported_statuses = []

        def fake_process(*args, **kwargs):
            stop_event.set()
            return 0

        with tempfile.TemporaryDirectory() as temp_dir:
            heartbeat_path = Path(temp_dir) / "worker.heartbeat"
            with mock.patch(
                "platform.uploads.process_queued_uploads",
                side_effect=fake_process,
            ) as process_mock:
                run_upload_worker(
                    self.app.state.session_factory,
                    adapter=self.adapter,
                    policy=Sub2Policy(
                        version="sub2-policy-test",
                        proxy_ref=None,
                        group_id=49,
                        concurrency=40,
                        credential_ref=None,
                    ),
                    stop_event=stop_event,
                    poll_seconds=0.01,
                    heartbeat_path=heartbeat_path,
                    batch_reporter=reported_statuses.append,
                )
            process_mock.assert_called_once()
            self.assertTrue(
                worker_heartbeat_is_fresh(heartbeat_path, max_age_seconds=10)
            )
            self.assertEqual(reported_statuses, [upload_job_status_counts(self.app.state.session_factory)])

    def test_metrics_reports_upload_status_counts_without_payload_details(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-metrics")
        self.assertEqual(queued.status_code, 201, queued.text)

        metrics = self.request("GET", "/metrics")
        self.assertEqual(metrics.status_code, 200, metrics.text)
        self.assertIn('platform_upload_jobs_total{status="queued"} 1', metrics.text)
        self.assertNotIn("Example Store", metrics.text)
        self.assertNotIn("vault://", metrics.text)
        self.assertNotIn("2222", metrics.text)


if __name__ == "__main__":
    unittest.main()
