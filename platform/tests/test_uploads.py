import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest import mock

import httpx
from sqlalchemy import select

from platform.app import create_app
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.models import (
    AuditEvent,
    Card,
    OutboxEvent,
    UploadJob,
    UploadPolicyDeployment,
    UploadPolicyVersion,
)
from platform.policies import select_policy_for_task
from platform.uploads import (
    Sub2AdapterError,
    Sub2Policy,
    Sub2UploadResult,
    UploadUnknownError,
    process_upload_job,
    process_queued_uploads,
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
            db.add(
                Card(
                    tenant_id="tenant-upload",
                    provider_ref="provider-upload-card",
                    brand="VISA",
                    last4="2222",
                    secret_ref="vault://cards/upload-card",
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
                "tenant_id": "tenant-upload",
                "email": "upload-owner@example.test",
                "password": self.password,
                "device_id": self.identity.device_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def create_task_with_card(self, token: str) -> tuple[str, str]:
        task = self.request(
            "POST",
            "/api/v1/tasks",
            headers=self.bearer(token),
            json={"type": "card_checkout", "idempotency_key": "upload-task-1"},
        )
        self.assertEqual(task.status_code, 201, task.text)
        task_id = task.json()["id"]
        allocation = self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=self.bearer(token),
        )
        self.assertEqual(allocation.status_code, 201, allocation.text)
        return task_id, allocation.json()["id"]

    def create_upload(self, token: str, task_id: str, key: str = "upload-1") -> httpx.Response:
        return self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=self.bearer(token),
            json={"business_name": "Example Store", "idempotency_key": key},
        )

    def test_queue_contract_has_no_sub2_infrastructure_fields(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id)
        self.assertEqual(queued.status_code, 201, queued.text)
        self.assertEqual(
            set(queued.json()),
            {
                "id",
                "task_id",
                "trace_id",
                "status",
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

    def test_upload_requires_card_and_idempotency_is_owner_scoped(self) -> None:
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

    def test_worker_consumes_transactional_outbox(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-outbox")

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )

        self.assertEqual(processed, 1)
        self.assertEqual(len(self.adapter.commands), 1)
        with self.app.state.session_factory() as db:
            job = db.get(UploadJob, queued.json()["id"])
            event = db.scalar(
                select(OutboxEvent).where(
                    OutboxEvent.aggregate_id == queued.json()["id"]
                )
            )
            self.assertEqual(job.status, "succeeded")
            self.assertEqual(event.status, "processed")
            self.assertEqual(event.attempts, 1)
            self.assertIsNotNone(event.processed_at)

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

        processed = process_queued_uploads(
            self.app.state.session_factory,
            adapter=self.adapter,
            policy=self.app.state.sub2_policy,
        )
        self.assertEqual(processed, 1)
        self.assertEqual(self.adapter.commands[0].policy.version, "governed-v2")
        self.assertEqual(self.adapter.commands[0].policy.group_id, 202)
        self.assertEqual(self.adapter.commands[0].policy.concurrency, 22)

    def test_unknown_external_result_is_not_retried(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
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

    def test_only_definitive_adapter_rejection_becomes_failed(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
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

    def test_unknown_upload_requires_privileged_reconciliation(self) -> None:
        token = self.login()
        task_id, _ = self.create_task_with_card(token)
        queued = self.create_upload(token, task_id, "upload-reconcile")
        job_id = queued.json()["id"]
        unknown_adapter = FakeSub2Adapter(unknown=True)
        process_upload_job(
            self.app.state.session_factory,
            job_id,
            adapter=unknown_adapter,
            policy=self.app.state.sub2_policy,
        )
        forbidden = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(token),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
        )
        self.assertEqual(forbidden.status_code, 403, forbidden.text)

        role_tokens: dict[str, str] = {}
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

        auditor_forbidden = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(role_tokens["security_auditor"]),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
        )
        self.assertEqual(auditor_forbidden.status_code, 403, auditor_forbidden.text)

        reconciled = self.request(
            "POST",
            f"/api/v1/upload-jobs/{job_id}/reconcile",
            headers=self.bearer(role_tokens["ops_admin"]),
            json={"status": "succeeded", "external_ref": "sub2-confirmed-1"},
        )
        self.assertEqual(reconciled.status_code, 200, reconciled.text)
        self.assertEqual(reconciled.json()["status"], "succeeded")
        self.assertEqual(reconciled.json()["external_ref"], "sub2-confirmed-1")

        second = self.create_upload(token, task_id, "upload-reconcile-admin")
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
