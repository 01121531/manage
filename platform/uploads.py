"""Server-side Sub2 upload policy, adapter contract, and outbox worker."""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from collections.abc import Mapping
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.models import Card, CardAllocation, OutboxEvent, UploadJob
from platform.secrets import SecretResolver, SecretResolverUnavailable
from platform.worker_metrics import WorkerMetrics


class Sub2AdapterUnavailable(RuntimeError):
    """The server has no configured Sub2 adapter."""


class UploadUnknownError(RuntimeError):
    """The external result is unknown and must not be retried automatically."""


class Sub2AdapterError(RuntimeError):
    """The Sub2 service rejected or returned an invalid response."""


@dataclass(frozen=True)
class Sub2Policy:
    version: str
    proxy_ref: str | None = field(repr=False)
    group_id: int
    concurrency: int
    credential_ref: str | None = field(repr=False)


@dataclass(frozen=True)
class Sub2UploadCommand:
    job_id: str
    business_name: str
    card_secret_ref: str = field(repr=False)
    policy: Sub2Policy


@dataclass(frozen=True)
class Sub2UploadResult:
    external_ref: str


class Sub2Adapter(Protocol):
    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        """Submit using server-owned policy and secret references only."""


class UnconfiguredSub2Adapter:
    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        raise Sub2AdapterUnavailable("Sub2 adapter is not configured")


ResponseOpener = Callable[..., Any]


def _normalize_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Sub2 upload URL must be HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Sub2 upload URL must not contain credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Sub2 upload URL must use HTTPS outside localhost")
    if parsed.query or parsed.fragment:
        raise ValueError("Sub2 upload URL must not contain query or fragment")
    return urllib.parse.urlunsplit(parsed).rstrip("/")


def _secret_text(secret: Mapping[str, object], *names: str) -> str:
    for name in names:
        value = secret.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise SecretResolverUnavailable("Required secret value is missing")


class HttpSub2Adapter:
    """Call the server-owned Sub2 upload endpoint with resolved secrets."""

    def __init__(
        self,
        upload_url: str,
        secret_resolver: SecretResolver,
        *,
        timeout: int = 30,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.upload_url = _normalize_https_url(upload_url)
        self.secret_resolver = secret_resolver
        self.timeout = timeout
        self._opener = opener

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)

    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        if command.policy.credential_ref is None:
            raise Sub2AdapterUnavailable("Sub2 credential ref is not configured")
        try:
            credential = self.secret_resolver.resolve(command.policy.credential_ref)
            card = dict(self.secret_resolver.resolve(command.card_secret_ref))
            proxy = (
                dict(self.secret_resolver.resolve(command.policy.proxy_ref))
                if command.policy.proxy_ref
                else None
            )
            token = _secret_text(credential, "bearer_token", "access_token", "token", "value")
        except SecretResolverUnavailable as error:
            raise Sub2AdapterUnavailable(str(error)) from error
        payload: dict[str, object] = {
            "job_id": command.job_id,
            "business_name": command.business_name,
            "card": card,
            "policy": {
                "version": command.policy.version,
                "group_id": command.policy.group_id,
                "concurrency": command.policy.concurrency,
                "proxy": proxy,
            },
        }
        request = urllib.request.Request(
            self.upload_url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "EmailPlatformWorker/1.0",
            },
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as error:
            if error.code in {502, 503, 504}:
                raise UploadUnknownError("Sub2 gateway result is unknown") from error
            raise Sub2AdapterError(f"Sub2 upload rejected with HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise UploadUnknownError("Sub2 upload result is unknown") from error

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise Sub2AdapterError("Sub2 upload returned invalid JSON") from error
        if not isinstance(data, dict):
            raise Sub2AdapterError("Sub2 upload returned invalid data")
        if data.get("success") is False:
            raise Sub2AdapterError("Sub2 upload returned failure")
        nested = data.get("data")
        if isinstance(nested, dict):
            data = nested
        external_ref = data.get("external_ref") or data.get("id") or data.get("job_id")
        if not isinstance(external_ref, str) or not external_ref.strip():
            raise Sub2AdapterError("Sub2 upload response missing external_ref")
        return Sub2UploadResult(external_ref=external_ref.strip())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now


def process_upload_job(
    session_factory: sessionmaker[Session],
    job_id: str,
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
) -> UploadJob | None:
    """Process one queued job exactly once from the worker side.

    A network/adapter ambiguity becomes ``unknown`` and is intentionally not
    retried automatically. The caller can reconcile it with the external
    service before any subsequent action.
    """

    with session_factory() as db:
        job = db.get(UploadJob, job_id)
        if job is None:
            return None
        if job.status != "queued":
            return job
        claimed = db.execute(
            update(UploadJob)
            .where(UploadJob.id == job_id, UploadJob.status == "queued")
            .values(status="running", updated_at=utc_now())
        )
        if claimed.rowcount != 1:
            db.rollback()
            return db.get(UploadJob, job_id)
        db.commit()
        job = db.get(UploadJob, job_id)
        if job is None:
            return None
        from platform.policies import resolve_policy_for_job

        resolved_policy = resolve_policy_for_job(db, job=job, fallback=policy)
        if resolved_policy is None:
            job.status = "failed"
            job.error_code = "policy_version_mismatch"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job
        policy = resolved_policy

        allocation = db.get(CardAllocation, job.card_allocation_id)
        card = db.get(Card, allocation.card_id) if allocation is not None else None
        if (
            allocation is None
            or card is None
            or allocation.released_at is not None
            or _is_expired(allocation.expires_at, utc_now())
        ):
            job.status = "failed"
            job.error_code = "card_lease_invalid"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job

        command = Sub2UploadCommand(
            job_id=job.id,
            business_name=job.business_name,
            card_secret_ref=card.secret_ref,
            policy=policy,
        )
        try:
            result = adapter.submit(command)
        except UploadUnknownError:
            job.status = "unknown"
            job.error_code = "external_unknown"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job
        except Sub2AdapterUnavailable:
            job.status = "failed"
            job.error_code = "adapter_unavailable"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job
        except Exception:
            job.status = "failed"
            job.error_code = "adapter_error"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job

        job.status = "succeeded"
        job.external_ref = result.external_ref
        job.error_code = None
        record_audit(
            db,
            tenant_id=job.tenant_id,
            user_id=job.user_id,
            device_id=job.device_id,
            event_type="upload.succeeded",
            entity_type="upload_job",
            entity_id=job.id,
            trace_id=job.trace_id,
            details={"status": "succeeded"},
        )
        db.commit()
        return job


def process_queued_uploads(
    session_factory: sessionmaker[Session],
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
    limit: int = 20,
) -> int:
    """Claim and process upload events from the transactional outbox.

    A stale event whose job is still ``queued`` is safe to reclaim: the worker
    had not crossed the external-call boundary.  A stale ``running`` job is
    instead marked ``unknown`` so it is never submitted blindly a second time.
    """

    if limit <= 0:
        raise ValueError("limit must be positive")
    now = utc_now()
    stale_before = now - timedelta(minutes=5)
    with session_factory() as db:
        candidates = list(
            db.scalars(
                select(OutboxEvent)
                .where(
                    OutboxEvent.event_type == "upload.requested",
                    OutboxEvent.available_at <= now,
                    or_(
                        OutboxEvent.status == "pending",
                        and_(
                            OutboxEvent.status == "processing",
                            or_(
                                OutboxEvent.claimed_at.is_(None),
                                OutboxEvent.claimed_at < stale_before,
                            ),
                        ),
                    ),
                )
                .order_by(OutboxEvent.created_at, OutboxEvent.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        claimed: list[tuple[str, str]] = []
        for event in candidates:
            event.status = "processing"
            event.claimed_at = now
            event.attempts += 1
            event.last_error_code = None
            claimed.append((event.id, event.aggregate_id))
        db.commit()

    processed = 0
    for event_id, job_id in claimed:
        try:
            result = process_upload_job(
                session_factory, job_id, adapter=adapter, policy=policy
            )
        except Exception:
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                error_code="worker_processing_error",
                force_unknown=True,
            )
            processed += 1
            continue

        if result is None:
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                error_code="aggregate_not_found",
            )
        elif result.status == "running":
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                error_code="worker_interrupted",
                force_unknown=True,
            )
        else:
            _finish_outbox_event(session_factory, event_id, job_id)
        processed += 1
    return processed


def _finish_outbox_event(
    session_factory: sessionmaker[Session],
    event_id: str,
    job_id: str,
    *,
    error_code: str | None = None,
    force_unknown: bool = False,
) -> None:
    """Finalize a claimed event without ever re-queueing an ambiguous upload."""

    with session_factory() as db:
        event = db.get(OutboxEvent, event_id)
        job = db.get(UploadJob, job_id)
        if force_unknown and job is not None and job.status == "running":
            job.status = "unknown"
            job.error_code = "external_unknown"
            job.updated_at = utc_now()
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
        if event is not None:
            event.status = "processed" if error_code is None else "failed"
            event.processed_at = utc_now()
            event.last_error_code = error_code
        db.commit()


def upload_job_status_counts(session_factory: sessionmaker[Session]) -> dict[str, int]:
    """Return upload job counts by status for operational dashboards."""

    with session_factory() as db:
        rows = db.execute(
            select(UploadJob.status, func.count()).group_by(UploadJob.status)
        ).all()
    return {str(status): int(count) for status, count in rows}


def write_worker_heartbeat(path: str | Path) -> None:
    """Write an upload-worker liveness timestamp for container health checks."""

    heartbeat_path = Path(path)
    heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
    heartbeat_path.write_text(str(time.time()), encoding="utf-8")


def worker_heartbeat_is_fresh(
    path: str | Path, *, max_age_seconds: float, now: float | None = None
) -> bool:
    """Return whether the upload-worker heartbeat exists and is recent."""

    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    try:
        raw_value = Path(path).read_text(encoding="utf-8").strip()
        timestamp = float(raw_value)
    except (OSError, ValueError):
        return False
    current_time = time.time() if now is None else now
    return 0 <= current_time - timestamp <= max_age_seconds


def run_upload_worker(
    session_factory: sessionmaker[Session],
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
    stop_event: Event,
    poll_seconds: float = 2.0,
    heartbeat_path: str | Path | None = None,
    batch_reporter: Callable[[dict[str, int]], None] | None = None,
    metrics: WorkerMetrics | None = None,
) -> None:
    """Run the dedicated upload worker loop until ``stop_event`` is set."""

    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be positive")
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
    while not stop_event.is_set():
        processed = process_queued_uploads(
            session_factory, adapter=adapter, policy=policy
        )
        status_counts = upload_job_status_counts(session_factory)
        if batch_reporter is not None:
            batch_reporter(status_counts)
        if metrics is not None:
            metrics.record_batch(status_counts)
        if heartbeat_path is not None:
            write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()
        if processed == 0:
            stop_event.wait(poll_seconds)
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
    if metrics is not None:
        metrics.mark_heartbeat()
