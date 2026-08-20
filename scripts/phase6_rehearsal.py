"""Run and verify the in-process Phase 6 business-flow rehearsal.

This is CI preflight evidence.  It intentionally does not claim that a real
Keycloak, Mail provider, Sub2 service, or production environment was tested.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import io
import json
import logging
import os
import re
import sys
import tempfile
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

import httpx
from sqlalchemy import inspect as sqlalchemy_inspect
from sqlalchemy import select

from platform.app import create_app
from platform.auth import create_access_token
from platform.bootstrap import create_user_with_device
from platform.config import Settings
from platform.mail_connectors import MailCodeMessage, MailboxAccess
from platform.mail_worker import process_mail_session
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
    User,
)
from platform.uploads import Sub2UploadResult, process_queued_uploads


SCHEMA_VERSION = "phase6-ci-rehearsal/v1"
EVIDENCE_KIND = "phase6_ci_rehearsal"
SCENARIO = "login-task-card-mail-code-upload-close-audit"
TASK_TRACE_ID = "00000000-0000-4000-8000-000000000006"
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_MAX_EVIDENCE_BYTES = 64 * 1024
_EXPECTED_EVENTS = frozenset(
    {
        "card.allocated",
        "card.released",
        "mail_session.code_consumed",
        "mail_session.code_ready",
        "mail_session.created",
        "mail_session.watermark_initialized",
        "task.closed",
        "task.created",
        "upload.queued",
        "upload.succeeded",
    }
)
_EXPECTED_EVENT_TYPES = sorted(_EXPECTED_EVENTS | {"mail_session.code_checked"})
_CHECK_KEYS = frozenset(
    {
        "authenticated_platform_session",
        "audit_trace_replay",
        "authorization_isolation",
        "full_business_flow",
        "one_time_verification",
        "persistent_secret_scan",
        "resource_cleanup",
        "server_side_upload",
    }
)
_RESOURCE_STATES = {
    "card_allocation": "released",
    "mail_session": "consumed_and_erased",
    "outbox": "processed",
    "task": "closed",
    "upload_job": "succeeded",
}
_PERSISTENT_SURFACES = [
    "admin_audit_csv",
    "admin_audit_json",
    "application_logs",
    "database_rows",
    "metrics",
    "non_ephemeral_http_responses",
]
_EPHEMERAL_ORIGINS = [
    "auth.login.access_token",
    "mail_session.code.consume",
    "mail_session.create.session_token",
]


class RehearsalError(RuntimeError):
    """A safe failure category for the CI rehearsal."""


class RehearsalMailConnector:
    def __init__(self) -> None:
        self.messages: list[MailCodeMessage] = []
        self.raw_email = "phase6-upstream-7c0bd3@example.invalid"
        self.raw_password = "MAIL_PASSWORD_SENTINEL_71fd3bc0d8154f4a"
        self.calls = 0

    def current_watermark(self, mailbox: MailboxAccess) -> str | None:
        self._assert_opaque_boundary(mailbox)
        self.calls += 1
        return self.messages[-1].watermark if self.messages else None

    def find_code_after(
        self, mailbox: MailboxAccess, watermark: str | None
    ) -> MailCodeMessage | None:
        self._assert_opaque_boundary(mailbox)
        self.calls += 1
        baseline = int(watermark or "0")
        for message in self.messages:
            if int(message.watermark) > baseline:
                return message
        return None

    def _assert_opaque_boundary(self, mailbox: MailboxAccess) -> None:
        serialized = json.dumps(
            {
                "mailbox_id": mailbox.mailbox_id,
                "secret_ref": mailbox.secret_ref,
            }
        )
        if self.raw_email in serialized or self.raw_password in serialized:
            raise RehearsalError("mail connector boundary failed")


class RehearsalSub2Adapter:
    def __init__(self) -> None:
        self.raw_token = "SUB2_TOKEN_SENTINEL_b6fb2e0768b448bc"
        self.proxy_password = "PROXY_PASSWORD_SENTINEL_4d40464f723e46a5"
        self.card_pan = "4242424242424242"
        self.card_cvv = "731"
        self.commands: list[Any] = []

    def submit(self, command: Any) -> Sub2UploadResult:
        serialized = repr(command)
        for secret in (
            self.raw_token,
            self.proxy_password,
            self.card_pan,
            self.card_cvv,
        ):
            if secret in serialized:
                raise RehearsalError("Sub2 command boundary failed")
        self.commands.append(command)
        return Sub2UploadResult(external_ref="sub2-rehearsal-job-1")


def _request(app: Any, method: str, path: str, **kwargs: Any) -> httpx.Response:
    async def run() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://phase6.test"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def _expect(response: httpx.Response, status_code: int, checkpoint: str) -> None:
    if response.status_code != status_code:
        raise RehearsalError(f"rehearsal checkpoint failed: {checkpoint}")


def _response_surface(response: httpx.Response) -> str:
    safe_headers = {
        key.lower(): value
        for key, value in response.headers.items()
        if key.lower()
        in {"cache-control", "content-type", "pragma", "x-trace-id"}
    }
    return json.dumps(
        {
            "status_code": response.status_code,
            "headers": safe_headers,
            "body": response.text,
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _headers(token: str, trace_id: str = TASK_TRACE_ID) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": "Phase6-CI-Rehearsal/1.0",
        "X-Real-IP": "192.0.2.60",
        "X-Trace-Id": trace_id,
    }


def _login(
    app: Any,
    *,
    tenant_id: str,
    email: str,
    password: str,
    device_id: str,
    trace_id: str,
) -> str:
    response = _request(
        app,
        "POST",
        "/api/v1/auth/login",
        headers={
            "User-Agent": "Phase6-CI-Rehearsal/1.0",
            "X-Real-IP": "192.0.2.60",
            "X-Trace-Id": trace_id,
        },
        json={
            "tenant_id": tenant_id,
            "email": email,
            "password": password,
            "device_id": device_id,
        },
    )
    _expect(response, 200, "platform login")
    payload = response.json()
    token = payload.get("access_token")
    if not isinstance(token, str) or len(token) < 32:
        raise RehearsalError("platform login token was invalid")
    return token


def _model_rows(db: Any, model: type[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for instance in db.scalars(select(model)).all():
        values: dict[str, Any] = {}
        for attribute in sqlalchemy_inspect(instance).mapper.column_attrs:
            value = getattr(instance, attribute.key)
            values[attribute.key] = value.isoformat() if isinstance(value, datetime) else value
        rows.append(values)
    return rows


def _secret_variants(value: str) -> set[str]:
    if value.isdigit() and len(value) <= 3:
        return {
            f'"cvc":"{value}"',
            f'"cvc": "{value}"',
            f'"cvv":"{value}"',
            f'"cvv": "{value}"',
            f"cvc={value}",
            f"cvv={value}",
        }
    encoded = value.encode("utf-8")
    variants = {
        value,
        f"Bearer {value}",
        urllib.parse.quote(value, safe=""),
        base64.b64encode(encoded).decode("ascii"),
        json.dumps(value, ensure_ascii=True)[1:-1],
    }
    if value.isdigit() and len(value) >= 12:
        variants.add(" ".join(value[index : index + 4] for index in range(0, len(value), 4)))
        variants.add("-".join(value[index : index + 4] for index in range(0, len(value), 4)))
    return {item for item in variants if item}


def _assert_no_secret(surfaces: list[str], sentinels: list[str]) -> None:
    combined = "\n".join(surfaces)
    for sentinel in sentinels:
        for variant in _secret_variants(sentinel):
            if variant in combined:
                raise RehearsalError("persistent secret scan failed")


def _payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "integrity": {"payload_sha256": _payload_digest(payload)}}


def run_rehearsal(source_commit: str) -> dict[str, Any]:
    """Execute the full in-process flow and return sealed, redacted evidence."""

    if _COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise RehearsalError("source commit is invalid")

    connector = RehearsalMailConnector()
    adapter = RehearsalSub2Adapter()
    verification_code = "73918426"
    owner_password = "PLATFORM_PASSWORD_SENTINEL_1db20c34b3844b7d"
    auditor_password = "AUDITOR_PASSWORD_SENTINEL_986a091fc4124c78"
    attacker_password = "ATTACKER_PASSWORD_SENTINEL_ea9188b345e24fe8"
    connector.messages.append(
        MailCodeMessage(message_id="old", watermark="1", code="11111111")
    )
    app = create_app(
        Settings(
            app_name="phase6-ci-rehearsal",
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            jwt_hmac_secret="phase6-rehearsal-hmac-secret-not-for-production",
            mail_poll_mode="worker",
            mail_session_ttl_seconds=300,
            mail_code_ttl_seconds=60,
            card_lease_ttl_seconds=600,
            sub2_policy_version="phase6-policy-v1",
            sub2_proxy_ref="vault://proxy/phase6-rehearsal",
            sub2_group_id=49,
            sub2_concurrency=4,
            sub2_credential_ref="vault://sub2/phase6-rehearsal",
        ),
        mail_connectors={"rehearsal": connector},
        sub2_adapter=adapter,
    )
    log_stream = io.StringIO()
    log_handler = logging.StreamHandler(log_stream)
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)
    response_surfaces: list[str] = []
    try:
        owner = create_user_with_device(
            app.state.session_factory,
            tenant_id="tenant-phase6",
            email="operator@example.test",
            password=owner_password,
            device_name="operator-device-a",
        )
        auditor = create_user_with_device(
            app.state.session_factory,
            tenant_id="tenant-phase6",
            email="auditor@example.test",
            password=auditor_password,
            device_name="auditor-device",
            role="security_auditor",
        )
        attacker = create_user_with_device(
            app.state.session_factory,
            tenant_id="tenant-other",
            email="attacker@example.test",
            password=attacker_password,
            device_name="attacker-device",
        )
        with app.state.session_factory() as db:
            second_device = Device(
                tenant_id="tenant-phase6",
                user_id=owner.user_id,
                name="operator-device-b",
            )
            db.add_all(
                [
                    second_device,
                    Mailbox(
                        tenant_id="tenant-phase6",
                        email_masked="p***@example.invalid",
                        connector_type="rehearsal",
                        secret_ref="vault://mailboxes/phase6-rehearsal",
                    ),
                    Card(
                        tenant_id="tenant-phase6",
                        provider_ref="phase6-card-provider-ref",
                        brand="VISA",
                        last4="4242",
                        expiry_month=12,
                        expiry_year=2030,
                        secret_ref="vault://cards/phase6-rehearsal",
                    ),
                ]
            )
            db.commit()
            db.refresh(second_device)
            second_device_id = second_device.id

        owner_token = _login(
            app,
            tenant_id="tenant-phase6",
            email="operator@example.test",
            password=owner_password,
            device_id=owner.device_id,
            trace_id="00000000-0000-4000-8000-000000000001",
        )
        auditor_token = _login(
            app,
            tenant_id="tenant-phase6",
            email="auditor@example.test",
            password=auditor_password,
            device_id=auditor.device_id,
            trace_id="00000000-0000-4000-8000-000000000002",
        )
        attacker_trace = "00000000-0000-4000-8000-000000000003"
        attacker_token = _login(
            app,
            tenant_id="tenant-other",
            email="attacker@example.test",
            password=attacker_password,
            device_id=attacker.device_id,
            trace_id=attacker_trace,
        )
        second_device_token = create_access_token(
            secret=app.state.jwt_hmac_secret,
            user_id=owner.user_id,
            tenant_id="tenant-phase6",
            device_id=second_device_id,
            ttl_seconds=300,
        )

        me = _request(app, "GET", "/api/v1/me", headers=_headers(owner_token))
        _expect(me, 200, "authenticated profile")
        response_surfaces.append(_response_surface(me))

        task = _request(
            app,
            "POST",
            "/api/v1/tasks",
            headers=_headers(owner_token),
            json={
                "type": "card_checkout",
                "idempotency_key": "phase6-ci-rehearsal-task",
            },
        )
        _expect(task, 201, "task creation")
        response_surfaces.append(_response_surface(task))
        task_payload = task.json()
        task_id = task_payload["id"]
        if task_payload.get("trace_id") != TASK_TRACE_ID:
            raise RehearsalError("task trace binding failed")

        allocation = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/card-allocations",
            headers=_headers(owner_token),
        )
        _expect(allocation, 201, "card allocation")
        response_surfaces.append(_response_surface(allocation))
        allocation_payload = allocation.json()
        allocation_id = allocation_payload["id"]
        if allocation_payload.get("trace_id") != TASK_TRACE_ID:
            raise RehearsalError("card trace binding failed")
        if any(key in allocation_payload for key in ("pan", "cvv", "secret_ref")):
            raise RehearsalError("card masking boundary failed")

        mail_session = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/mail-sessions",
            headers=_headers(owner_token),
        )
        _expect(mail_session, 201, "mail session creation")
        if mail_session.headers.get("cache-control") != "no-store":
            raise RehearsalError("mail session cache policy failed")
        mail_payload = mail_session.json()
        mail_session_id = mail_payload["id"]
        mail_session_token = mail_payload["session_token"]
        if mail_payload.get("trace_id") != TASK_TRACE_ID:
            raise RehearsalError("mail trace binding failed")
        if any(key in mail_payload for key in ("password", "secret_ref", "body")):
            raise RehearsalError("mail response boundary failed")

        if process_mail_session(
            app.state.session_factory,
            mail_session_id,
            connectors={"rehearsal": connector},
        ) != "initialized":
            raise RehearsalError("mail watermark initialization failed")
        connector.messages.append(
            MailCodeMessage(
                message_id="new", watermark="2", code=verification_code
            )
        )
        if process_mail_session(
            app.state.session_factory,
            mail_session_id,
            connectors={"rehearsal": connector},
        ) != "code_ready":
            raise RehearsalError("mail code delivery failed")

        mail_headers = _headers(owner_token)
        mail_headers["X-Mail-Session-Token"] = mail_session_token
        consumed = _request(
            app,
            "GET",
            f"/api/v1/mail-sessions/{mail_session_id}/code",
            headers=mail_headers,
        )
        _expect(consumed, 200, "mail code consumption")
        if consumed.headers.get("cache-control") != "no-store" or consumed.json() != {
            "status": "consumed",
            "code": verification_code,
        }:
            raise RehearsalError("mail code consumption contract failed")
        consumed_again = _request(
            app,
            "GET",
            f"/api/v1/mail-sessions/{mail_session_id}/code",
            headers=mail_headers,
        )
        _expect(consumed_again, 200, "one-time mail code")
        if consumed_again.json() != {"status": "consumed", "code": None}:
            raise RehearsalError("mail code was not one-time")
        response_surfaces.append(_response_surface(consumed_again))

        upload = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=_headers(owner_token),
            json={
                "business_name": "Phase6 Rehearsal Store",
                "idempotency_key": "phase6-ci-rehearsal-upload",
            },
        )
        _expect(upload, 201, "upload queue")
        response_surfaces.append(_response_surface(upload))
        upload_payload = upload.json()
        upload_id = upload_payload["id"]
        replay = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/uploads",
            headers=_headers(owner_token),
            json={
                "business_name": "Phase6 Rehearsal Store",
                "idempotency_key": "phase6-ci-rehearsal-upload",
            },
        )
        _expect(replay, 200, "upload idempotency replay")
        response_surfaces.append(_response_surface(replay))
        if replay.json().get("id") != upload_id:
            raise RehearsalError("upload idempotency failed")

        if process_queued_uploads(
            app.state.session_factory,
            adapter=adapter,
            policy=app.state.sub2_policy,
        ) != 1:
            raise RehearsalError("upload worker did not process one job")
        if len(adapter.commands) != 1:
            raise RehearsalError("upload worker crossed the boundary more than once")
        completed_upload = _request(
            app,
            "GET",
            f"/api/v1/uploads/{upload_id}",
            headers=_headers(owner_token),
        )
        _expect(completed_upload, 200, "upload result")
        response_surfaces.append(_response_surface(completed_upload))
        if completed_upload.json().get("status") != "succeeded":
            raise RehearsalError("upload did not succeed")

        attack_headers = _headers(attacker_token, attacker_trace)
        cross_tenant_requests = [
            ("GET", f"/api/v1/tasks/{task_id}", {}),
            ("POST", f"/api/v1/tasks/{task_id}/mail-sessions", {}),
            (
                "GET",
                f"/api/v1/mail-sessions/{mail_session_id}/code",
                {"headers": {**attack_headers, "X-Mail-Session-Token": mail_session_token}},
            ),
            ("GET", f"/api/v1/card-allocations/{allocation_id}", {}),
            ("GET", f"/api/v1/uploads/{upload_id}", {}),
        ]
        for method, path, options in cross_tenant_requests:
            options.setdefault("headers", attack_headers)
            denied = _request(app, method, path, **options)
            _expect(denied, 404, "cross-tenant resource isolation")
            response_surfaces.append(_response_surface(denied))

        second_headers = _headers(
            second_device_token, "00000000-0000-4000-8000-000000000004"
        )
        second_mail_headers = {
            **second_headers,
            "X-Mail-Session-Token": mail_session_token,
        }
        cross_device_requests = [
            ("POST", f"/api/v1/tasks/{task_id}/close", second_headers),
            (
                "GET",
                f"/api/v1/mail-sessions/{mail_session_id}/code",
                second_mail_headers,
            ),
            ("GET", f"/api/v1/card-allocations/{allocation_id}", second_headers),
            ("GET", f"/api/v1/uploads/{upload_id}", second_headers),
        ]
        for method, path, request_headers in cross_device_requests:
            denied = _request(app, method, path, headers=request_headers)
            _expect(denied, 404, "cross-device resource isolation")
            response_surfaces.append(_response_surface(denied))

        operator_audit = _request(
            app,
            "GET",
            f"/api/v1/admin/audit?trace_id={TASK_TRACE_ID}",
            headers=_headers(owner_token),
        )
        _expect(operator_audit, 403, "audit role isolation")
        response_surfaces.append(_response_surface(operator_audit))

        closed = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/close",
            headers=_headers(owner_token),
        )
        _expect(closed, 200, "task close")
        response_surfaces.append(_response_surface(closed))
        if closed.json().get("status") != "closed":
            raise RehearsalError("task did not close")
        close_replay = _request(
            app,
            "POST",
            f"/api/v1/tasks/{task_id}/close",
            headers=_headers(owner_token),
        )
        _expect(close_replay, 200, "task close replay")
        response_surfaces.append(_response_surface(close_replay))

        closed_code = _request(
            app,
            "GET",
            f"/api/v1/mail-sessions/{mail_session_id}/code",
            headers=mail_headers,
        )
        _expect(closed_code, 200, "closed task code state")
        response_surfaces.append(_response_surface(closed_code))
        if closed_code.json() != {"status": "consumed", "code": None}:
            raise RehearsalError("closed task retained a verification code")

        audit = _request(
            app,
            "GET",
            f"/api/v1/admin/audit?trace_id={TASK_TRACE_ID}&limit=200",
            headers=_headers(
                auditor_token, "00000000-0000-4000-8000-000000000005"
            ),
        )
        _expect(audit, 200, "audit replay")
        audit_payload = audit.json()
        audit_event_types = sorted(
            {
                event["event_type"]
                for event in audit_payload
                if isinstance(event, dict) and isinstance(event.get("event_type"), str)
            }
        )
        if audit_event_types != _EXPECTED_EVENT_TYPES:
            raise RehearsalError("audit replay was incomplete")
        for required_event in _EXPECTED_EVENTS:
            if sum(
                1
                for event in audit_payload
                if event.get("event_type") == required_event
            ) != 1:
                raise RehearsalError("audit replay was not idempotent")
        if any(event.get("trace_id") != TASK_TRACE_ID for event in audit_payload):
            raise RehearsalError("audit replay trace binding failed")
        response_surfaces.append(_response_surface(audit))

        audit_export = _request(
            app,
            "GET",
            f"/api/v1/admin/audit/export?trace_id={TASK_TRACE_ID}&limit=200",
            headers=_headers(
                auditor_token, "00000000-0000-4000-8000-000000000005"
            ),
        )
        _expect(audit_export, 200, "audit CSV export")
        if audit_export.headers.get("cache-control") != "no-store":
            raise RehearsalError("audit export cache policy failed")
        csv_rows = list(csv.DictReader(io.StringIO(audit_export.content.decode("utf-8-sig"))))
        if not csv_rows or "details" in csv_rows[0]:
            raise RehearsalError("audit export redaction failed")
        response_surfaces.append(_response_surface(audit_export))

        hidden_other_tenant_audit = _request(
            app,
            "GET",
            f"/api/v1/admin/audit?trace_id={attacker_trace}",
            headers=_headers(auditor_token),
        )
        _expect(hidden_other_tenant_audit, 200, "cross-tenant audit filter")
        response_surfaces.append(_response_surface(hidden_other_tenant_audit))
        if hidden_other_tenant_audit.json() != []:
            raise RehearsalError("cross-tenant audit data was visible")

        metrics = _request(app, "GET", "/metrics")
        _expect(metrics, 200, "metrics")

        with app.state.session_factory() as db:
            persisted_task = db.get(Task, task_id)
            persisted_session = db.get(MailSession, mail_session_id)
            persisted_allocation = db.get(CardAllocation, allocation_id)
            persisted_upload = db.get(UploadJob, upload_id)
            outbox = db.scalar(
                select(OutboxEvent).where(OutboxEvent.aggregate_id == upload_id)
            )
            if (
                persisted_task is None
                or persisted_session is None
                or persisted_allocation is None
                or persisted_upload is None
                or outbox is None
            ):
                raise RehearsalError("resource persistence check failed")
            if any(
                resource.trace_id != TASK_TRACE_ID
                for resource in (
                    persisted_task,
                    persisted_session,
                    persisted_allocation,
                    persisted_upload,
                )
            ):
                raise RehearsalError("resource trace chain failed")
            if persisted_task.status != "closed":
                raise RehearsalError("closed task state failed")
            if persisted_session.status != "consumed" or any(
                value is not None
                for value in (
                    persisted_session.delivered_code,
                    persisted_session.delivered_at,
                    persisted_session.code_expires_at,
                )
            ):
                raise RehearsalError("mail secret cleanup failed")
            expected_session_hash = hashlib.sha256(
                mail_session_token.encode("utf-8")
            ).hexdigest()
            if persisted_session.session_token_hash != expected_session_hash:
                raise RehearsalError("mail session token hashing failed")
            if (
                persisted_allocation.status != "released"
                or persisted_allocation.released_at is None
            ):
                raise RehearsalError("card lease cleanup failed")
            if persisted_upload.status != "succeeded" or outbox.status != "processed":
                raise RehearsalError("upload/outbox state failed")
            if outbox.attempts != 1:
                raise RehearsalError("outbox was processed more than once")

            database_snapshot = {
                model.__tablename__: _model_rows(db, model)
                for model in (
                    User,
                    Device,
                    Task,
                    Mailbox,
                    MailSession,
                    Card,
                    CardAllocation,
                    UploadJob,
                    OutboxEvent,
                    AuditEvent,
                )
            }

        persistent_surfaces = [
            *response_surfaces,
            audit.text,
            audit_export.text,
            log_stream.getvalue(),
            metrics.text,
            json.dumps(database_snapshot, ensure_ascii=False, default=str),
        ]
        sentinels = [
            owner_password,
            auditor_password,
            attacker_password,
            owner_token,
            auditor_token,
            attacker_token,
            second_device_token,
            mail_session_token,
            verification_code,
            connector.raw_email,
            connector.raw_password,
            adapter.raw_token,
            adapter.proxy_password,
            adapter.card_pan,
            adapter.card_cvv,
        ]
        _assert_no_secret(persistent_surfaces, sentinels)

        evidence_payload = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "pilot_id": f"phase6-ci-rehearsal-{source_commit[:12]}",
            "production_acceptance": False,
            "source_commit": source_commit,
            "identity_mode": "local_test",
            "scenario": SCENARIO,
            "status": "passed",
            "task_trace_id": TASK_TRACE_ID,
            "checks": {key: True for key in sorted(_CHECK_KEYS)},
            "resource_states": dict(sorted(_RESOURCE_STATES.items())),
            "audit_event_types": audit_event_types,
            "security": {
                "ephemeral_secret_origins_excluded": list(_EPHEMERAL_ORIGINS),
                "forbidden_sentinels_found": 0,
                "persistent_surfaces": list(_PERSISTENT_SURFACES),
            },
        }
        return _seal_evidence(evidence_payload)
    finally:
        root_logger.removeHandler(log_handler)
        app.state.engine.dispose()


def _validate_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RehearsalError("evidence is not an object")
    expected_top_level = {
        "schema_version",
        "evidence_kind",
        "pilot_id",
        "production_acceptance",
        "source_commit",
        "identity_mode",
        "scenario",
        "status",
        "task_trace_id",
        "checks",
        "resource_states",
        "audit_event_types",
        "security",
        "integrity",
    }
    if set(value) != expected_top_level:
        raise RehearsalError("evidence schema is invalid")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["evidence_kind"] != EVIDENCE_KIND
        or value["production_acceptance"] is not False
        or value["identity_mode"] != "local_test"
        or value["scenario"] != SCENARIO
        or value["status"] != "passed"
        or value["task_trace_id"] != TASK_TRACE_ID
    ):
        raise RehearsalError("evidence identity is invalid")
    source_commit = value["source_commit"]
    if not isinstance(source_commit, str) or _COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise RehearsalError("evidence commit is invalid")
    if value["pilot_id"] != f"phase6-ci-rehearsal-{source_commit[:12]}":
        raise RehearsalError("evidence pilot id is invalid")
    checks = value["checks"]
    if (
        not isinstance(checks, dict)
        or set(checks) != _CHECK_KEYS
        or any(result is not True for result in checks.values())
    ):
        raise RehearsalError("evidence checks are incomplete")
    if value["resource_states"] != _RESOURCE_STATES:
        raise RehearsalError("evidence resource states are invalid")
    event_types = value["audit_event_types"]
    if (
        not isinstance(event_types, list)
        or any(not isinstance(item, str) for item in event_types)
        or event_types != _EXPECTED_EVENT_TYPES
    ):
        raise RehearsalError("evidence audit replay is incomplete")
    security = value["security"]
    if not isinstance(security, dict) or set(security) != {
        "ephemeral_secret_origins_excluded",
        "forbidden_sentinels_found",
        "persistent_surfaces",
    }:
        raise RehearsalError("evidence security schema is invalid")
    if (
        security["ephemeral_secret_origins_excluded"] != _EPHEMERAL_ORIGINS
        or security["forbidden_sentinels_found"] != 0
        or security["persistent_surfaces"] != _PERSISTENT_SURFACES
    ):
        raise RehearsalError("evidence security result is invalid")
    integrity = value["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        raise RehearsalError("evidence integrity schema is invalid")
    digest = integrity["payload_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RehearsalError("evidence digest is invalid")
    payload = {key: item for key, item in value.items() if key != "integrity"}
    if digest != _payload_digest(payload):
        raise RehearsalError("evidence integrity check failed")
    return value


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    """Atomically publish evidence and verify the bytes that were published."""

    path.unlink(missing_ok=True)
    _validate_evidence(evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(evidence, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        verify_evidence(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def verify_evidence(
    path: Path, *, expected_commit: str | None = None
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RehearsalError("evidence cannot be read") from error
    if not raw or len(raw) > _MAX_EVIDENCE_BYTES:
        raise RehearsalError("evidence size is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RehearsalError("evidence JSON is invalid") from error
    evidence = _validate_evidence(value)
    if expected_commit is not None:
        if _COMMIT_PATTERN.fullmatch(expected_commit) is None:
            raise RehearsalError("expected commit is invalid")
        if evidence["source_commit"] != expected_commit:
            raise RehearsalError("evidence commit does not match release")
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--commit", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--input", type=Path, required=True)
    verify_parser.add_argument("--expected-commit")
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    output = options.output if options.command == "run" else None
    if output is not None:
        output.unlink(missing_ok=True)
    try:
        if options.command == "run":
            evidence = run_rehearsal(options.commit)
            write_evidence(options.output, evidence)
            verified = evidence
        else:
            verified = verify_evidence(
                options.input, expected_commit=options.expected_commit
            )
    except (RehearsalError, OSError):
        if output is not None:
            output.unlink(missing_ok=True)
        print("phase6-ci-rehearsal-failed", file=sys.stderr)
        return 1
    print(
        "phase6-ci-rehearsal-ok "
        f"kind={verified['evidence_kind']} "
        f"production_acceptance={str(verified['production_acceptance']).lower()} "
        f"payload_sha256={verified['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
