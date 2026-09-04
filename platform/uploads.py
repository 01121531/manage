"""Server-side Sub2 upload policy, adapter contract, and outbox worker."""

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import Condition, Event, Thread
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.auth import ROLE_OPERATOR
from platform.file_boundary import read_stable_runtime_bytes
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.lifecycle import (
    TERMINAL_TASK_STATUSES,
    sweep_expired_lifecycle,
    transition_task_to_terminal,
)
from platform.models import (
    Card,
    CardAllocation,
    Device,
    MailSession,
    OutboxEvent,
    Task,
    UploadJob,
    User,
)
from platform.secrets import SecretResolver, SecretResolverUnavailable
from platform.worker_metrics import WorkerMetrics


class Sub2AdapterUnavailable(RuntimeError):
    """The server has no configured Sub2 adapter."""


class UploadUnknownError(RuntimeError):
    """The external result is unknown and must not be retried automatically."""


class Sub2AdapterError(RuntimeError):
    """The Sub2 service definitively rejected the upload before creation."""


class Sub2ConcurrencyConfigurationError(ValueError):
    """An immutable policy version has inconsistent concurrency settings."""


class Sub2ConcurrencyBackendUnavailable(RuntimeError):
    """The shared concurrency store cannot safely grant an outbound slot."""


EXTERNAL_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_EXTERNAL_REF_RE = re.compile(EXTERNAL_REF_PATTERN)
_LOGGER = logging.getLogger(__name__)

UPLOAD_PHASE_EVENT_TYPES = {
    "worker_preflight": "upload.preflight_started",
    "provider_submit": "upload.provider_submit_started",
    "provider_result": "upload.provider_result_received",
    "reconciliation_check": "upload.reconciliation_started",
    "reconciliation_result": "upload.reconciliation_result_received",
}

_ACQUIRE_SUB2_SLOT_LUA = """
local now_parts = redis.call('TIME')
local now_ms = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
local active = redis.call('ZCARD', KEYS[1])
local configured_limit = redis.call('GET', KEYS[2])
if configured_limit and tonumber(configured_limit) ~= tonumber(ARGV[1]) then
  return {-1, 0}
end
if not configured_limit then
  redis.call('SET', KEYS[2], ARGV[1])
end
if active < tonumber(ARGV[1]) then
  redis.call('ZADD', KEYS[1], now_ms + tonumber(ARGV[2]), ARGV[3])
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return {1, 0}
end
local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return {0, math.max(1, tonumber(first[2]) - now_ms)}
"""

_RELEASE_SUB2_SLOT_LUA = """
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
if redis.call('ZCARD', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1])
end
return removed
"""

_RENEW_SUB2_SLOT_LUA = """
if not redis.call('ZSCORE', KEYS[1], ARGV[2]) then
  return 0
end
local now_parts = redis.call('TIME')
local now_ms = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
redis.call('ZADD', KEYS[1], 'XX', now_ms + tonumber(ARGV[1]), ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return 1
"""


def normalize_external_ref(value: object) -> str:
    if not isinstance(value, str):
        raise UploadUnknownError("Sub2 upload result is unknown")
    normalized = value.strip()
    if _EXTERNAL_REF_RE.fullmatch(normalized) is None:
        raise UploadUnknownError("Sub2 upload result is unknown")
    return normalized


@dataclass(frozen=True)
class Sub2Policy:
    version: str
    proxy_ref: str | None = field(repr=False)
    group_id: int
    concurrency: int
    credential_ref: str | None = field(repr=False)


@dataclass
class _ConcurrencyBudget:
    limit: int
    active: int = 0


class Sub2ConcurrencyLimiter:
    """Bound outbound calls by the tenant and immutable policy snapshot."""

    def __init__(self) -> None:
        self._condition = Condition()
        self._budgets: dict[tuple[str, str], _ConcurrencyBudget] = {}
        self._limits: dict[tuple[str, str], int] = {}

    @contextmanager
    def slot(self, tenant_id: str, policy: Sub2Policy) -> Iterator[None]:
        if policy.concurrency <= 0:
            raise Sub2ConcurrencyConfigurationError(
                "Sub2 policy concurrency must be positive"
            )
        key = (tenant_id, policy.version)
        with self._condition:
            configured_limit = self._limits.get(key)
            if configured_limit is None:
                self._limits[key] = policy.concurrency
            elif configured_limit != policy.concurrency:
                raise Sub2ConcurrencyConfigurationError(
                    "Sub2 policy concurrency changed for the same version"
                )
            while True:
                budget = self._budgets.get(key)
                if budget is None:
                    budget = _ConcurrencyBudget(limit=policy.concurrency)
                    self._budgets[key] = budget
                if budget.active < budget.limit:
                    budget.active += 1
                    break
                self._condition.wait()
        try:
            yield
        finally:
            with self._condition:
                budget = self._budgets[key]
                budget.active -= 1
                if budget.active == 0:
                    del self._budgets[key]
                self._condition.notify_all()


class RedisSub2ConcurrencyLimiter:
    """Redis-backed lease budget shared by every Sub2 worker replica."""

    def __init__(
        self,
        redis_url: str,
        *,
        lease_seconds: int,
        client: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if client is None:
            from redis import Redis

            client = Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        self._client = client
        self._lease_ms = lease_seconds * 1_000
        self._renew_interval_seconds = max(lease_seconds / 3, 1)
        self._sleep = sleep

    @staticmethod
    def _keys(tenant_id: str, policy_version: str) -> tuple[str, str]:
        scope = hashlib.sha256(
            f"{tenant_id}\0{policy_version}".encode("utf-8")
        ).hexdigest()
        prefix = f"sub2-concurrency:{{{scope}}}"
        return f"{prefix}:leases", f"{prefix}:limit"

    @contextmanager
    def slot(self, tenant_id: str, policy: Sub2Policy) -> Iterator[None]:
        if policy.concurrency <= 0:
            raise Sub2ConcurrencyConfigurationError(
                "Sub2 policy concurrency must be positive"
            )
        leases_key, limit_key = self._keys(tenant_id, policy.version)
        lease_token = secrets.token_hex(16)
        while True:
            try:
                result = self._client.eval(
                    _ACQUIRE_SUB2_SLOT_LUA,
                    2,
                    leases_key,
                    limit_key,
                    policy.concurrency,
                    self._lease_ms,
                    lease_token,
                )
                acquired, retry_ms = int(result[0]), int(result[1])
            except Exception as exc:
                raise Sub2ConcurrencyBackendUnavailable(
                    "Sub2 concurrency backend unavailable"
                ) from exc
            if acquired == -1:
                raise Sub2ConcurrencyConfigurationError(
                    "Sub2 policy concurrency changed for the same version"
                )
            if acquired == 1:
                break
            self._sleep(min(max(retry_ms / 1_000, 0.01), 0.25))
        renew_stop = Event()

        def renew_lease() -> None:
            while not renew_stop.wait(self._renew_interval_seconds):
                try:
                    renewed = self._client.eval(
                        _RENEW_SUB2_SLOT_LUA,
                        2,
                        leases_key,
                        limit_key,
                        self._lease_ms,
                        lease_token,
                    )
                    if int(renewed) != 1:
                        _LOGGER.error("Sub2 concurrency lease was lost")
                        return
                except Exception:
                    _LOGGER.warning("Sub2 concurrency lease renewal failed")

        renew_thread = Thread(
            target=renew_lease,
            name="sub2-concurrency-renewal",
            daemon=True,
        )
        renew_thread.start()
        try:
            yield
        finally:
            renew_stop.set()
            renew_thread.join(timeout=3)
            try:
                self._client.eval(
                    _RELEASE_SUB2_SLOT_LUA,
                    2,
                    leases_key,
                    limit_key,
                    lease_token,
                )
            except Exception:
                # The exact-token lease expires server-side. Never hide a known
                # external result merely because cleanup could not reach Redis.
                _LOGGER.warning("Sub2 concurrency lease release failed")


_SUB2_CONCURRENCY_LIMITER = Sub2ConcurrencyLimiter()


@dataclass(frozen=True)
class Sub2UploadCommand:
    job_id: str
    task_id: str
    business_name: str
    card_secret_ref: str = field(repr=False)
    policy: Sub2Policy


@dataclass(frozen=True)
class Sub2UploadResult:
    external_ref: str


class Sub2LookupState(str, Enum):
    """Provider-independent outcomes for a reviewed status/idempotency lookup."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PROCESSING = "processing"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Sub2LookupCommand:
    """Stable platform identifiers available to a supplier-specific lookup."""

    job_id: str
    task_id: str
    provider_idempotency_key: str = field(repr=False)
    external_ref: str | None
    policy: Sub2Policy


@dataclass(frozen=True)
class Sub2LookupResult:
    state: Sub2LookupState
    external_ref: str | None = None


class Sub2Adapter(Protocol):
    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        """Submit using server-owned policy and secret references only."""


class Sub2ReconciliationAdapter(Protocol):
    def query(self, command: Sub2LookupCommand) -> Sub2LookupResult:
        """Query by reviewed external reference and/or idempotency mapping."""


class UnconfiguredSub2Adapter:
    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        raise Sub2AdapterUnavailable("Sub2 adapter is not configured")


ResponseOpener = Callable[..., Any]
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_WORKER_HEARTBEAT_BYTES = 64
_SUB2_AUTH_LOCATION = "authorization_header"
_SUB2_SUBMIT_METHOD = "POST"
_SUB2_IDEMPOTENCY_LOCATION = "header"
_SUB2_IDEMPOTENCY_NAME = "Idempotency-Key"
_SUB2_PROVIDER_IDEMPOTENCY_VALUE = "upload_job_id"
_SUB2_TASK_CORRELATION_LOCATION = "header"
_SUB2_TASK_CORRELATION_NAME = "X-Platform-Task-ID"
_SUB2_SUCCESS_REFERENCE_FIELD = "external_ref"
_SUB2_LOOKUP_PROTOCOL_SUPPORTED = True
_SUB2_LOOKUP_OUTCOMES = tuple(state.value for state in Sub2LookupState)
_SUB2_STATUS_QUERY_SUPPORTED = False
_SUB2_IDEMPOTENCY_LOOKUP_SUPPORTED = False
AI1_OBSERVED_CONTROL_PLANE_PATHS = frozenset(
    {
        "/api/v1/admin/accounts",
        "/api/v1/admin/accounts/{account_id}",
        "/api/v1/admin/accounts/{account_id}/usage",
        "/api/v1/admin/openai/accounts/{account_id}/quota",
        "/api/v1/admin/openai/generate-auth-url",
        "/api/v1/admin/openai/exchange-code",
        "/api/v1/admin/accounts/today-stats/batch",
        "/api/v1/admin/accounts/{account_id}/duplicate",
    }
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

# Statuses that establish that the request was rejected before an upload could
# be created. Ambiguous client statuses (timeout, conflict, too early, and rate
# limiting) deliberately remain outside this set.
_DEFINITIVE_REJECTION_STATUSES = frozenset(
    {
        400,
        401,
        403,
        404,
        405,
        406,
        410,
        411,
        412,
        413,
        414,
        415,
        416,
        417,
        421,
        422,
        426,
        428,
        431,
    }
)


def sub2_adapter_contract_capabilities() -> dict[str, object]:
    """Return generic HTTP adapter behavior used by contract preflight."""

    return {
        "auth_location": _SUB2_AUTH_LOCATION,
        "submit_method": _SUB2_SUBMIT_METHOD,
        "idempotency_location": _SUB2_IDEMPOTENCY_LOCATION,
        "idempotency_name": _SUB2_IDEMPOTENCY_NAME,
        "provider_idempotency_value": _SUB2_PROVIDER_IDEMPOTENCY_VALUE,
        "task_correlation_location": _SUB2_TASK_CORRELATION_LOCATION,
        "task_correlation_name": _SUB2_TASK_CORRELATION_NAME,
        "success_reference_field": _SUB2_SUCCESS_REFERENCE_FIELD,
        "pagination": "not_applicable",
        "rate_limit_strategy": "unknown_on_429",
        "definitive_rejection_statuses": tuple(sorted(_DEFINITIVE_REJECTION_STATUSES)),
        "lookup_protocol_supported": _SUB2_LOOKUP_PROTOCOL_SUPPORTED,
        "lookup_outcomes": _SUB2_LOOKUP_OUTCOMES,
        "status_query_supported": _SUB2_STATUS_QUERY_SUPPORTED,
        "idempotency_lookup_supported": _SUB2_IDEMPOTENCY_LOOKUP_SUPPORTED,
        "max_response_bytes": _MAX_RESPONSE_BYTES,
    }


def _normalize_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Sub2 upload URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Sub2 upload URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Sub2 upload URL must not contain query or fragment")
    return urllib.parse.urlunsplit(parsed).rstrip("/")


def _origin_key(value: str, *, allow_path: bool) -> tuple[str, str, int]:
    candidate = value.strip()
    if not candidate or "*" in candidate:
        raise ValueError("Sub2 allowed origin is invalid")
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise ValueError("Sub2 allowed origin is invalid")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Sub2 allowed origin is invalid")
    if (not allow_path and parsed.path) or parsed.query or parsed.fragment:
        raise ValueError("Sub2 allowed origin is invalid")
    hostname = parsed.hostname.lower()
    if (
        not hostname
        or hostname.endswith(".")
        or hostname == "localhost"
        or hostname.endswith(".localhost")
    ):
        raise ValueError("Sub2 allowed origin is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Sub2 allowed origin is invalid")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Sub2 allowed origin is invalid") from exc
    port = 443 if parsed_port is None else parsed_port
    if not 1 <= port <= 65_535:
        raise ValueError("Sub2 allowed origin is invalid")
    return ("https", hostname, port)


def _is_ai1_observed_control_plane_url(value: str) -> bool:
    if _origin_key(value, allow_path=True) != ("https", "ai1.aisb.shop", 443):
        return False
    path = urllib.parse.unquote(urllib.parse.urlsplit(value).path).rstrip("/")
    if path == "/api/v1/admin/accounts" or path.startswith(
        "/api/v1/admin/accounts/"
    ):
        return True
    if path.startswith("/api/v1/admin/openai/"):
        return True
    return path in AI1_OBSERVED_CONTROL_PLANE_PATHS


def normalize_generic_sub2_upload_url(value: str) -> str:
    normalized = _normalize_https_url(value)
    if _is_ai1_observed_control_plane_url(normalized):
        raise ValueError(
            "Observed account-control endpoint cannot be used as the generic "
            "Sub2 upload URL"
        )
    return normalized


def validate_generic_sub2_upload_endpoint(
    value: str,
    allowed_origins: Sequence[str],
) -> str:
    normalized = normalize_generic_sub2_upload_url(value)
    origin_keys = tuple(
        _origin_key(origin, allow_path=False) for origin in allowed_origins
    )
    if not origin_keys or len(set(origin_keys)) != len(origin_keys):
        raise ValueError("Sub2 allowed origins policy is invalid")
    if _origin_key(normalized, allow_path=True) not in origin_keys:
        raise ValueError("Sub2 upload origin is not allowed")
    return normalized


def sub2_upload_endpoint_configured(value: str | None) -> bool:
    if not value:
        return False
    try:
        normalize_generic_sub2_upload_url(value)
    except ValueError:
        return False
    return True


def sub2_unknown_reconciliation_configured() -> bool:
    """Report whether the runtime can verify ambiguous provider outcomes."""

    return _SUB2_STATUS_QUERY_SUPPORTED and _SUB2_IDEMPOTENCY_LOOKUP_SUPPORTED


def _secret_text(secret: Mapping[str, object], *names: str) -> str:
    for name in names:
        value = secret.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise SecretResolverUnavailable("Required secret value is missing")


def _sub2_card_payload(secret: Mapping[str, object]) -> dict[str, object]:
    """Project a Card Vault object onto the reviewed Sub2 egress contract."""

    pan = _secret_text(secret, "pan", "card_number", "number")
    normalized_pan = pan.replace(" ", "").replace("-", "")
    if not normalized_pan.isdigit() or not 12 <= len(normalized_pan) <= 19:
        raise SecretResolverUnavailable("Card secret is invalid")
    payload: dict[str, object] = {"pan": normalized_pan}
    expiry_month = secret.get("expiry_month")
    expiry_year = secret.get("expiry_year")
    if (expiry_month is None) != (expiry_year is None):
        raise SecretResolverUnavailable("Card secret is invalid")
    if expiry_month is not None:
        if (
            not isinstance(expiry_month, int)
            or isinstance(expiry_month, bool)
            or not 1 <= expiry_month <= 12
            or not isinstance(expiry_year, int)
            or isinstance(expiry_year, bool)
            or not 2000 <= expiry_year <= 9999
        ):
            raise SecretResolverUnavailable("Card secret is invalid")
        payload["expiry_month"] = expiry_month
        payload["expiry_year"] = expiry_year
    return payload


class HttpSub2Adapter:
    """Call the server-owned Sub2 upload endpoint with resolved secrets."""

    def __init__(
        self,
        upload_url: str,
        secret_resolver: SecretResolver,
        *,
        allowed_origins: Sequence[str],
        timeout: int = 30,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.upload_url = validate_generic_sub2_upload_endpoint(
            upload_url, allowed_origins
        )
        self.allowed_origins = frozenset(
            _origin_key(origin, allow_path=False) for origin in allowed_origins
        )
        self.secret_resolver = secret_resolver
        self.timeout = timeout
        self._opener = opener
        self._default_opener = urllib.request.build_opener(_NoRedirectHandler())

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return self._default_opener.open(request, timeout=timeout)

    def submit(self, command: Sub2UploadCommand) -> Sub2UploadResult:
        if command.policy.credential_ref is None:
            raise Sub2AdapterUnavailable("Sub2 credential ref is not configured")
        try:
            credential = self.secret_resolver.resolve(command.policy.credential_ref)
            card = _sub2_card_payload(
                self.secret_resolver.resolve(command.card_secret_ref)
            )
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
            "task_id": command.task_id,
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
            method=_SUB2_SUBMIT_METHOD,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                _SUB2_IDEMPOTENCY_NAME: command.job_id,
                "User-Agent": "EmailPlatformWorker/1.0",
                _SUB2_TASK_CORRELATION_NAME: command.task_id,
            },
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                status = int(getattr(response, "status", 200))
                get_url = getattr(response, "geturl", None)
                if callable(get_url) and get_url() != request.full_url:
                    raise UploadUnknownError("Sub2 upload result is unknown")
                response_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(response_bytes) > _MAX_RESPONSE_BYTES:
                    raise UploadUnknownError("Sub2 upload result is unknown")
        except urllib.error.HTTPError as error:
            if error.code in _DEFINITIVE_REJECTION_STATUSES:
                raise Sub2AdapterError(
                    f"Sub2 upload rejected with HTTP {error.code}"
                ) from error
            raise UploadUnknownError("Sub2 upload result is unknown") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise UploadUnknownError("Sub2 upload result is unknown") from error

        if status not in range(200, 300):
            if status in _DEFINITIVE_REJECTION_STATUSES:
                raise Sub2AdapterError(f"Sub2 upload rejected with HTTP {status}")
            raise UploadUnknownError("Sub2 upload result is unknown")

        try:
            data = parse_unique_json_bytes(response_bytes)
        except JsonBoundaryError:
            raise UploadUnknownError("Sub2 upload returned invalid JSON") from None
        if not isinstance(data, dict):
            raise UploadUnknownError("Sub2 upload returned invalid data")
        if data.get("success") is False:
            raise UploadUnknownError("Sub2 upload returned ambiguous failure")
        nested = data.get("data")
        if isinstance(nested, dict):
            data = nested
        external_ref = normalize_external_ref(data.get(_SUB2_SUCCESS_REFERENCE_FIELD))
        return Sub2UploadResult(external_ref=external_ref)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def transition_upload_phase(
    db: Session,
    job: UploadJob,
    phase: str,
    *,
    actor_id: str,
) -> bool:
    """Append one durable, monotonically ordered upload phase transition."""

    if job.phase == phase:
        return False
    event_type = UPLOAD_PHASE_EVENT_TYPES.get(phase)
    if event_type is None:
        raise ValueError(f"Unsupported upload phase: {phase}")
    previous_phase = job.phase
    changed_at = utc_now()
    job.phase = phase
    job.phase_sequence += 1
    job.phase_updated_at = changed_at
    job.updated_at = changed_at
    record_audit(
        db,
        tenant_id=job.tenant_id,
        user_id=job.user_id,
        device_id=job.device_id,
        actor_id=actor_id,
        event_type=event_type,
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        policy_version=job.policy_version,
        aggregate_sequence=job.phase_sequence,
        details={
            "from_phase": previous_phase,
            "phase": phase,
            "phase_sequence": job.phase_sequence,
            "status": job.status,
        },
    )
    return True


def _is_expired(value: datetime, now: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= now


def _reject_upload_before_external_call(
    db: Session,
    job: UploadJob,
    *,
    error_code: str,
    status: str = "failed",
) -> UploadJob:
    """Finish a local preflight rejection without exposing resource details."""

    transition_upload_phase(db, job, "worker_preflight", actor_id="worker-sub2")
    job.status = status
    job.error_code = error_code
    job.updated_at = utc_now()
    record_audit(
        db,
        tenant_id=job.tenant_id,
        user_id=job.user_id,
        device_id=job.device_id,
        actor_id="worker-sub2",
        event_type="upload.cancelled" if status == "cancelled" else "upload.failed",
        entity_type="upload_job",
        entity_id=job.id,
        trace_id=job.trace_id,
        policy_version=job.policy_version,
        details={
            "error_code": error_code,
            "phase": job.phase,
            "phase_sequence": job.phase_sequence,
        },
    )
    db.commit()
    return job


def _cancel_task_before_external_call(
    db: Session,
    *,
    job: UploadJob,
    task: Task,
    now: datetime,
    task_status: str,
    error_code: str,
) -> UploadJob:
    """Close an invalid task and release every resource before any outbound call."""

    transition_task_to_terminal(
        task,
        db,
        now=now,
        task_status=task_status,
        card_status="expired" if task_status == "expired" else "released",
        mail_status="expired",
        release_reason=error_code,
        actor_user_id="worker-sub2",
        actor_device_id=None,
    )
    return _reject_upload_before_external_call(
        db,
        job,
        error_code=error_code,
        status="cancelled",
    )


def process_upload_job(
    session_factory: sessionmaker[Session],
    job_id: str,
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
    concurrency_limiter: Sub2ConcurrencyLimiter | RedisSub2ConcurrencyLimiter | None = None,
    allow_policy_fallback: bool = True,
    claim_attempt: int | None = None,
) -> UploadJob | None:
    """Process one queued job exactly once from the worker side.

    Capacity is acquired before the job claim and before any database row is
    locked. Once capacity is available, the claimed job revalidates every
    authorization and resource binding immediately before the external call.

    A network/adapter ambiguity becomes ``unknown`` and is intentionally not
    retried automatically. The caller can reconcile it with the external
    service before any subsequent action.
    """

    with session_factory() as db:
        queued_job = db.get(UploadJob, job_id)
        if queued_job is None:
            return None
        is_queued = queued_job.status == "queued"
        tenant_id = queued_job.tenant_id
        if is_queued:
            from platform.policies import resolve_policy_for_job

            resolved_policy = resolve_policy_for_job(
                db,
                job=queued_job,
                fallback=policy,
                allow_fallback=allow_policy_fallback,
            )
        else:
            resolved_policy = None

    if not is_queued:
        return _process_upload_job_with_capacity(
            session_factory,
            job_id,
            adapter=adapter,
            policy=policy,
            allow_policy_fallback=allow_policy_fallback,
            claim_attempt=claim_attempt,
        )

    if resolved_policy is None or resolved_policy.concurrency <= 0:
        return _process_upload_job_with_capacity(
            session_factory,
            job_id,
            adapter=adapter,
            policy=policy,
            allow_policy_fallback=allow_policy_fallback,
            claim_attempt=claim_attempt,
        )

    limiter = concurrency_limiter or _SUB2_CONCURRENCY_LIMITER
    try:
        with limiter.slot(tenant_id, resolved_policy):
            return _process_upload_job_with_capacity(
                session_factory,
                job_id,
                adapter=adapter,
                policy=resolved_policy,
                allow_policy_fallback=allow_policy_fallback,
                claim_attempt=claim_attempt,
            )
    except Sub2ConcurrencyConfigurationError:
        with session_factory() as db:
            job = db.scalar(
                select(UploadJob).where(UploadJob.id == job_id).with_for_update()
            )
            if job is None:
                return None
            if job.status != "queued":
                return job
            return _reject_upload_before_external_call(
                db, job, error_code="policy_concurrency_invalid"
            )
    except Sub2ConcurrencyBackendUnavailable:
        with session_factory() as db:
            job = db.scalar(
                select(UploadJob).where(UploadJob.id == job_id).with_for_update()
            )
            if job is None:
                return None
            if job.status != "queued":
                return job
            job.error_code = "concurrency_backend_unavailable"
            job.updated_at = utc_now()
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.deferred",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job


def _upload_claim_is_current(
    db: Session,
    job_id: str,
    claim_attempt: int | None,
) -> bool:
    if claim_attempt is None:
        return True
    return (
        db.scalar(
            select(OutboxEvent.id).where(
                OutboxEvent.event_type == "upload.requested",
                OutboxEvent.aggregate_id == job_id,
                OutboxEvent.status == "processing",
                OutboxEvent.attempts == claim_attempt,
            )
        )
        is not None
    )


def _process_upload_job_with_capacity(
    session_factory: sessionmaker[Session],
    job_id: str,
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
    allow_policy_fallback: bool = True,
    claim_attempt: int | None = None,
) -> UploadJob | None:
    """Claim and process a job after the caller has acquired shared capacity."""

    with session_factory() as db:
        job = db.get(UploadJob, job_id)
        if job is None:
            return None
        if not _upload_claim_is_current(db, job_id, claim_attempt):
            return job
        if job.status == "cancel_pending":
            job.status = "unknown"
            job.error_code = "external_unknown"
            job.updated_at = utc_now()
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job
        if job.status != "queued":
            return job
        claim_time = utc_now()
        claimed = db.execute(
            update(UploadJob)
            .where(UploadJob.id == job_id, UploadJob.status == "queued")
            .values(
                status="running",
                phase="worker_preflight",
                phase_sequence=UploadJob.phase_sequence + 1,
                phase_updated_at=claim_time,
                error_code=None,
                updated_at=claim_time,
            )
        )
        if claimed.rowcount != 1:
            db.rollback()
            return db.get(UploadJob, job_id)
        job = db.scalar(
            select(UploadJob)
            .where(UploadJob.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if job is None:
            return None
        record_audit(
            db,
            tenant_id=job.tenant_id,
            user_id=job.user_id,
            device_id=job.device_id,
            actor_id="worker-sub2",
            event_type="upload.preflight_started",
            entity_type="upload_job",
            entity_id=job.id,
            trace_id=job.trace_id,
            policy_version=job.policy_version,
            aggregate_sequence=job.phase_sequence,
            details={
                "from_phase": "queued",
                "phase": job.phase,
                "phase_sequence": job.phase_sequence,
                "status": job.status,
            },
        )
        db.commit()
        job = db.scalar(
            select(UploadJob)
            .where(UploadJob.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if job is None:
            return None
        if job.status == "cancel_pending":
            return _reject_upload_before_external_call(
                db,
                job,
                error_code="cancelled_before_external_call",
                status="cancelled",
            )
        if job.status != "running":
            return job

        now = utc_now()
        task = db.scalar(select(Task).where(Task.id == job.task_id).with_for_update())
        user = db.scalar(select(User).where(User.id == job.user_id).with_for_update())
        device = db.scalar(
            select(Device).where(Device.id == job.device_id).with_for_update()
        )
        allocation = db.scalar(
            select(CardAllocation)
            .where(CardAllocation.id == job.card_allocation_id)
            .with_for_update()
        )
        card = (
            db.scalar(select(Card).where(Card.id == allocation.card_id).with_for_update())
            if allocation is not None
            else None
        )
        mail_session = db.scalar(
            select(MailSession)
            .where(MailSession.task_id == job.task_id)
            .with_for_update()
        )

        binding_is_valid = (
            task is not None
            and task.tenant_id == job.tenant_id
            and task.user_id == job.user_id
            and task.device_id == job.device_id
            and user is not None
            and user.tenant_id == job.tenant_id
            and device is not None
            and device.tenant_id == job.tenant_id
            and device.user_id == job.user_id
            and allocation is not None
            and allocation.tenant_id == job.tenant_id
            and allocation.task_id == job.task_id
            and allocation.user_id == job.user_id
            and allocation.device_id == job.device_id
            and card is not None
            and card.tenant_id == job.tenant_id
            and mail_session is not None
            and mail_session.tenant_id == job.tenant_id
            and mail_session.task_id == job.task_id
            and mail_session.user_id == job.user_id
            and mail_session.device_id == job.device_id
        )
        if not binding_is_valid:
            return _reject_upload_before_external_call(
                db, job, error_code="resource_binding_invalid"
            )
        assert task is not None
        assert user is not None
        assert device is not None
        assert allocation is not None
        assert card is not None
        assert mail_session is not None

        if task.expires_at is not None and _is_expired(task.expires_at, now):
            return _cancel_task_before_external_call(
                db,
                job=job,
                task=task,
                now=now,
                task_status="expired",
                error_code="task_expired",
            )
        if task.status in TERMINAL_TASK_STATUSES:
            return _cancel_task_before_external_call(
                db,
                job=job,
                task=task,
                now=now,
                task_status=task.status,
                error_code="task_inactive",
            )
        if (
            not user.is_active
            or user.role != ROLE_OPERATOR
            or device.revoked_at is not None
        ):
            return _cancel_task_before_external_call(
                db,
                job=job,
                task=task,
                now=now,
                task_status="cancelled",
                error_code="authorization_revoked",
            )
        if (
            mail_session.status != "consumed"
            or mail_session.consumed_at is None
            or _is_expired(mail_session.expires_at, now)
        ):
            return _cancel_task_before_external_call(
                db,
                job=job,
                task=task,
                now=now,
                task_status="cancelled",
                error_code="verification_invalid",
            )
        if (
            not card.is_active
            or card.quarantined_at is not None
            or allocation.status != "active"
            or allocation.released_at is not None
            or _is_expired(allocation.expires_at, now)
        ):
            return _cancel_task_before_external_call(
                db,
                job=job,
                task=task,
                now=now,
                task_status="cancelled",
                error_code="card_lease_invalid",
            )

        unknown_sibling_id = db.scalar(
            select(UploadJob.id).where(
                UploadJob.task_id == job.task_id,
                UploadJob.tenant_id == job.tenant_id,
                UploadJob.id != job.id,
                UploadJob.status == "unknown",
            )
        )
        if unknown_sibling_id is not None:
            return _reject_upload_before_external_call(
                db, job, error_code="upload_reconciliation_required"
            )

        from platform.policies import resolve_policy_for_job

        resolved_policy = resolve_policy_for_job(
            db,
            job=job,
            fallback=policy,
            allow_fallback=allow_policy_fallback,
        )
        if resolved_policy is None:
            job.status = "failed"
            job.error_code = (
                "policy_version_unapproved"
                if not allow_policy_fallback and job.policy_version == policy.version
                else "policy_version_mismatch"
            )
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
            db.commit()
            return job
        policy = resolved_policy

        if policy.concurrency <= 0:
            return _reject_upload_before_external_call(
                db, job, error_code="policy_concurrency_invalid"
            )

        command = Sub2UploadCommand(
            job_id=job.id,
            task_id=job.task_id,
            business_name=job.business_name,
            card_secret_ref=card.secret_ref,
            policy=policy,
        )
        transition_upload_phase(db, job, "provider_submit", actor_id="worker-sub2")
        db.commit()
        try:
            result = adapter.submit(command)
            external_ref = normalize_external_ref(result.external_ref)
        except UploadUnknownError:
            job = db.scalar(
                select(UploadJob)
                .where(UploadJob.id == job_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if job is None:
                return None
            if not _upload_claim_is_current(db, job_id, claim_attempt):
                return job
            job.status = "unknown"
            job.error_code = "external_unknown"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                policy_version=job.policy_version,
                details={
                    "error_code": job.error_code,
                    "phase": job.phase,
                    "phase_sequence": job.phase_sequence,
                },
            )
            db.commit()
            return job
        except Sub2AdapterUnavailable:
            job = db.scalar(
                select(UploadJob)
                .where(UploadJob.id == job_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if job is None:
                return None
            if not _upload_claim_is_current(db, job_id, claim_attempt):
                return job
            job.status = "failed"
            job.error_code = "adapter_unavailable"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                policy_version=job.policy_version,
                details={
                    "error_code": job.error_code,
                    "phase": job.phase,
                    "phase_sequence": job.phase_sequence,
                },
            )
            db.commit()
            return job
        except Sub2AdapterError:
            job = db.scalar(
                select(UploadJob)
                .where(UploadJob.id == job_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if job is None:
                return None
            if not _upload_claim_is_current(db, job_id, claim_attempt):
                return job
            transition_upload_phase(
                db, job, "provider_result", actor_id="worker-sub2"
            )
            job.status = "failed"
            job.error_code = "external_rejected"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.failed",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                policy_version=job.policy_version,
                details={
                    "error_code": job.error_code,
                    "phase": job.phase,
                    "phase_sequence": job.phase_sequence,
                },
            )
            db.commit()
            return job
        except Exception:
            job = db.scalar(
                select(UploadJob)
                .where(UploadJob.id == job_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if job is None:
                return None
            if not _upload_claim_is_current(db, job_id, claim_attempt):
                return job
            job.status = "unknown"
            job.error_code = "external_unknown"
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                policy_version=job.policy_version,
                details={
                    "error_code": job.error_code,
                    "phase": job.phase,
                    "phase_sequence": job.phase_sequence,
                },
            )
            db.commit()
            return job

        job = db.scalar(
            select(UploadJob)
            .where(UploadJob.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if job is None:
            return None
        if not _upload_claim_is_current(db, job_id, claim_attempt):
            return job
        transition_upload_phase(db, job, "provider_result", actor_id="worker-sub2")
        completed_at = utc_now()
        job.status = "succeeded"
        job.external_ref = external_ref
        job.error_code = None
        job.updated_at = completed_at
        record_audit(
            db,
            tenant_id=job.tenant_id,
            user_id=job.user_id,
            device_id=job.device_id,
            actor_id="worker-sub2",
            event_type="upload.succeeded",
            entity_type="upload_job",
            entity_id=job.id,
            trace_id=job.trace_id,
            policy_version=job.policy_version,
            details={
                "status": "succeeded",
                "phase": job.phase,
                "phase_sequence": job.phase_sequence,
            },
        )
        transition_task_to_terminal(
            task,
            db,
            now=completed_at,
            task_status="completed",
            card_status="released",
            mail_status="revoked",
            release_reason="upload_succeeded",
            actor_user_id="worker-sub2",
            actor_device_id=None,
            skip_locked=True,
        )
        db.commit()
        return job


def _normalize_lookup_result(
    result: object,
) -> tuple[Sub2LookupState, str | None]:
    """Fail closed when a supplier adapter returns an incomplete typed result."""

    if not isinstance(result, Sub2LookupResult) or not isinstance(
        result.state, Sub2LookupState
    ):
        return Sub2LookupState.UNKNOWN, None
    if result.state == Sub2LookupState.SUCCEEDED:
        try:
            return result.state, normalize_external_ref(result.external_ref)
        except UploadUnknownError:
            return Sub2LookupState.UNKNOWN, None
    if result.external_ref is not None:
        return Sub2LookupState.UNKNOWN, None
    return result.state, None


def reconcile_unknown_upload_job(
    session_factory: sessionmaker[Session],
    job_id: str,
    *,
    adapter: Sub2ReconciliationAdapter,
    policy: Sub2Policy,
    allow_policy_fallback: bool = True,
) -> UploadJob | None:
    """Apply one explicit lookup to an unknown upload without inferring retries.

    The provider call is made without an open database session. ``processing``,
    ``not_found`` and ``unknown`` remain unknown because eventual consistency or
    a transport failure cannot prove that the original upload was not created.
    """

    with session_factory() as db:
        job = db.get(UploadJob, job_id)
        if job is None or job.status != "unknown":
            return job
        transition_upload_phase(
            db, job, "reconciliation_check", actor_id="worker-sub2"
        )
        from platform.policies import resolve_policy_for_job

        resolved_policy = resolve_policy_for_job(
            db,
            job=job,
            fallback=policy,
            allow_fallback=allow_policy_fallback,
        )
        command = (
            Sub2LookupCommand(
                job_id=job.id,
                task_id=job.task_id,
                provider_idempotency_key=job.id,
                external_ref=job.external_ref,
                policy=resolved_policy,
            )
            if resolved_policy is not None
            else None
        )
        db.commit()

    if command is None:
        lookup_state, external_ref = Sub2LookupState.UNKNOWN, None
        observation_error = "reconciliation_policy_unavailable"
    else:
        observation_error = None
        try:
            lookup_state, external_ref = _normalize_lookup_result(adapter.query(command))
        except Exception:
            lookup_state, external_ref = Sub2LookupState.UNKNOWN, None

    task_id: str | None
    with session_factory() as db:
        task_id = db.scalar(select(UploadJob.task_id).where(UploadJob.id == job_id))
        task = (
            db.scalar(select(Task).where(Task.id == task_id).with_for_update())
            if task_id is not None
            else None
        )
        job = db.scalar(
            select(UploadJob).where(UploadJob.id == job_id).with_for_update()
        )
        if job is None or job.status != "unknown":
            return job

        now = utc_now()
        if lookup_state == Sub2LookupState.SUCCEEDED and task is None:
            lookup_state = Sub2LookupState.UNKNOWN
            external_ref = None
            observation_error = "reconciliation_task_unavailable"

        if lookup_state == Sub2LookupState.SUCCEEDED:
            assert task is not None
            assert external_ref is not None
            job.status = "succeeded"
            job.external_ref = external_ref
            job.error_code = None
            event_type = "upload.reconciled"
            transition_upload_phase(
                db, job, "reconciliation_result", actor_id="worker-sub2"
            )
            transition_task_to_terminal(
                task,
                db,
                now=now,
                task_status="completed",
                card_status="released",
                mail_status="revoked",
                release_reason="upload_lookup_succeeded",
                actor_user_id="worker-sub2",
                actor_device_id=None,
                finalize_upload_outbox=True,
            )
        elif lookup_state == Sub2LookupState.FAILED:
            job.status = "failed"
            job.external_ref = None
            job.error_code = "reconciled_external_rejected"
            event_type = "upload.reconciled"
            transition_upload_phase(
                db, job, "reconciliation_result", actor_id="worker-sub2"
            )
        else:
            error_by_state = {
                Sub2LookupState.PROCESSING: "external_processing",
                Sub2LookupState.NOT_FOUND: "external_not_found_unconfirmed",
                Sub2LookupState.UNKNOWN: "external_unknown",
            }
            job.error_code = observation_error or error_by_state[lookup_state]
            event_type = "upload.reconciliation_checked"
        job.updated_at = now
        record_audit(
            db,
            tenant_id=job.tenant_id,
            user_id=job.user_id,
            device_id=job.device_id,
            actor_id="worker-sub2",
            event_type=event_type,
            entity_type="upload_job",
            entity_id=job.id,
            trace_id=job.trace_id,
            details={
                "status": job.status,
                "lookup_state": lookup_state.value,
                "error_code": job.error_code,
                "policy_version": job.policy_version,
                "phase": job.phase,
                "phase_sequence": job.phase_sequence,
            },
            policy_version=job.policy_version,
        )
        db.commit()
        if task_id is not None:
            db.scalar(
                select(Task)
                .where(Task.id == task_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        return db.scalar(
            select(UploadJob)
            .where(UploadJob.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )


def process_queued_uploads(
    session_factory: sessionmaker[Session],
    *,
    adapter: Sub2Adapter,
    policy: Sub2Policy,
    limit: int = 20,
    concurrency_limiter: Sub2ConcurrencyLimiter | RedisSub2ConcurrencyLimiter | None = None,
    allow_policy_fallback: bool = True,
) -> int:
    """Claim and process upload events from the transactional outbox.

    A stale event whose job is still ``queued`` is safe to reclaim: the worker
    had not crossed the external-call boundary.  A stale ``running`` job is
    instead marked ``unknown`` so it is never submitted blindly a second time.
    Claimed events run concurrently, while each outbound call is bounded by
    its tenant and immutable policy-version snapshot.
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
        claimed: list[tuple[str, str, int]] = []
        for event in candidates:
            event.status = "processing"
            event.claimed_at = now
            event.attempts += 1
            event.last_error_code = None
            claimed.append((event.id, event.aggregate_id, event.attempts))
        db.commit()

    def process_claimed_event(
        event_id: str, job_id: str, claim_attempt: int
    ) -> None:
        try:
            result = process_upload_job(
                session_factory,
                job_id,
                adapter=adapter,
                policy=policy,
                concurrency_limiter=concurrency_limiter,
                allow_policy_fallback=allow_policy_fallback,
                claim_attempt=claim_attempt,
            )
        except Exception:
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                claim_attempt=claim_attempt,
                error_code="worker_processing_error",
                force_unknown=True,
            )
            return

        if result is None:
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                claim_attempt=claim_attempt,
                error_code="aggregate_not_found",
            )
        elif result.status == "running":
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                claim_attempt=claim_attempt,
                error_code="worker_interrupted",
                force_unknown=True,
            )
        else:
            _finish_outbox_event(
                session_factory,
                event_id,
                job_id,
                claim_attempt=claim_attempt,
            )

    if len(claimed) == 1:
        process_claimed_event(*claimed[0])
    elif claimed:
        with ThreadPoolExecutor(
            max_workers=len(claimed), thread_name_prefix="sub2-upload"
        ) as executor:
            futures = [
                executor.submit(
                    process_claimed_event, event_id, job_id, claim_attempt
                )
                for event_id, job_id, claim_attempt in claimed
            ]
            for future in futures:
                future.result()
    return len(claimed)


def _finish_outbox_event(
    session_factory: sessionmaker[Session],
    event_id: str,
    job_id: str,
    *,
    claim_attempt: int,
    error_code: str | None = None,
    force_unknown: bool = False,
) -> None:
    """Finalize only the worker generation that still owns the claimed event."""

    with session_factory() as db:
        # Keep the established aggregate -> outbox lock order used by lifecycle
        # cleanup.  ``attempts`` is the monotonic fencing token for a reclaimed
        # lease, so a late previous owner becomes a side-effect-free no-op.
        job = db.scalar(
            select(UploadJob).where(UploadJob.id == job_id).with_for_update()
        )
        event = db.scalar(
            select(OutboxEvent)
            .where(
                OutboxEvent.id == event_id,
                OutboxEvent.status == "processing",
                OutboxEvent.attempts == claim_attempt,
            )
            .with_for_update()
        )
        if event is None:
            db.rollback()
            return

        final_error_code = error_code
        if (
            job is not None
            and job.status == "queued"
            and job.error_code == "concurrency_backend_unavailable"
        ):
            event.status = "pending"
            event.available_at = utc_now() + timedelta(seconds=5)
            event.claimed_at = None
            event.processed_at = None
            event.last_error_code = job.error_code
            db.commit()
            return
        if job is not None and job.status == "cancel_pending":
            job.status = "unknown"
            job.error_code = "external_unknown"
            job.updated_at = utc_now()
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
        if job is not None and job.status in {
            "succeeded",
            "failed",
            "unknown",
            "cancelled",
        }:
            final_error_code = None
        if force_unknown and job is not None and job.status == "running":
            job.status = "unknown"
            job.error_code = "external_unknown"
            job.updated_at = utc_now()
            record_audit(
                db,
                tenant_id=job.tenant_id,
                user_id=job.user_id,
                device_id=job.device_id,
                actor_id="worker-sub2",
                event_type="upload.unknown",
                entity_type="upload_job",
                entity_id=job.id,
                trace_id=job.trace_id,
                details={"error_code": job.error_code},
            )
        event.status = "processed" if final_error_code is None else "failed"
        event.processed_at = utc_now()
        event.last_error_code = final_error_code
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
    payload = str(time.time()).encode("ascii")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=heartbeat_path.parent,
            prefix=f".{heartbeat_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, heartbeat_path)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def worker_heartbeat_is_fresh(
    path: str | Path, *, max_age_seconds: float, now: float | None = None
) -> bool:
    """Return whether the upload-worker heartbeat exists and is recent."""

    if not math.isfinite(max_age_seconds) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    try:
        raw_value = read_stable_runtime_bytes(
            Path(path),
            max_bytes=_MAX_WORKER_HEARTBEAT_BYTES,
        )
        timestamp = float(raw_value.decode("ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return False
    if not math.isfinite(timestamp):
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
    concurrency_limiter: Sub2ConcurrencyLimiter | RedisSub2ConcurrencyLimiter | None = None,
    allow_policy_fallback: bool = True,
) -> None:
    """Run the dedicated upload worker loop until ``stop_event`` is set."""

    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be positive")
    heartbeat_stop = Event()
    heartbeat_thread: Thread | None = None
    if heartbeat_path is not None:
        write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()

        def maintain_heartbeat() -> None:
            interval = min(max(poll_seconds, 0.1), 5)
            while not heartbeat_stop.wait(interval):
                write_worker_heartbeat(heartbeat_path)
                if metrics is not None:
                    metrics.mark_heartbeat()

        heartbeat_thread = Thread(
            target=maintain_heartbeat,
            name="sub2-worker-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
    try:
        while not stop_event.is_set():
            sweep_expired_lifecycle(session_factory)
            processed = process_queued_uploads(
                session_factory,
                adapter=adapter,
                policy=policy,
                concurrency_limiter=concurrency_limiter,
                allow_policy_fallback=allow_policy_fallback,
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
    finally:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1)
        if heartbeat_path is not None:
            write_worker_heartbeat(heartbeat_path)
        if metrics is not None:
            metrics.mark_heartbeat()
