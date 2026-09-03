"""Distributed, privacy-preserving request rate limiting."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


_FIXED_WINDOW_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
"""


class RateLimitBackendUnavailable(RuntimeError):
    """The shared rate-limit store cannot make a safe decision."""


class RateLimitBackend(Protocol):
    """Minimal asynchronous backend contract, injectable in tests."""

    async def increment(self, key: str, window_seconds: int) -> tuple[int, int]: ...

    async def ping(self) -> bool: ...


class RedisRateLimitBackend:
    """Redis-backed atomic fixed-window counter."""

    def __init__(self, redis_url: str, *, client: Any | None = None) -> None:
        if client is None:
            from redis.asyncio import Redis

            client = Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        self._client = client

    async def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        try:
            result = await self._client.eval(
                _FIXED_WINDOW_LUA, 1, key, int(window_seconds)
            )
            count, ttl = int(result[0]), int(result[1])
            return count, max(ttl, 1)
        except Exception as exc:
            raise RateLimitBackendUnavailable(
                "rate-limit backend unavailable"
            ) from exc

    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception as exc:
            raise RateLimitBackendUnavailable(
                "rate-limit backend unavailable"
            ) from exc


@dataclass(frozen=True)
class RateLimitPolicy:
    name: str
    limit: int
    window_seconds: int


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clean_ip(request: Request) -> str:
    """Return the normalized ASGI peer IP without trusting request headers."""

    candidate = request.client.host if request.client is not None else None
    if candidate:
        try:
            return ipaddress.ip_address(candidate.strip()).compressed
        except ValueError:
            pass
    return "unknown"


def _bearer_fingerprint(request: Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token.strip():
        return _fingerprint(token.strip())
    return None


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    recovery_hint: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "recovery_hint": recovery_hint,
                "trace_id": getattr(request.state, "trace_id", ""),
            }
        },
        headers=headers,
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply policy tiers without putting user-controlled identifiers in keys."""

    _EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})

    def __init__(
        self,
        app: Any,
        *,
        backend: RateLimitBackend,
        api_prefix: str,
        login_limit: int,
        high_risk_limit: int,
        general_limit: int,
        window_seconds: int,
        fail_closed: bool,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(app)
        self.backend = backend
        self.api_prefix = api_prefix.rstrip("/")
        self.policies = {
            "login": RateLimitPolicy("login", login_limit, window_seconds),
            "high_risk": RateLimitPolicy(
                "high_risk", high_risk_limit, window_seconds
            ),
            "general": RateLimitPolicy("general", general_limit, window_seconds),
        }
        self.fail_closed = fail_closed
        self.clock = clock

    def _policy(self, request: Request) -> RateLimitPolicy:
        path = request.url.path
        if path == f"{self.api_prefix}/auth/login":
            return self.policies["login"]
        relative_path = path[len(self.api_prefix) :] if path.startswith(self.api_prefix) else path
        is_upload_write = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and (
            relative_path == "/uploads"
            or relative_path.endswith("/uploads")
            or relative_path.startswith("/uploads/")
            or relative_path.startswith("/upload-jobs/")
        )
        is_card_reveal = (
            request.method.upper() == "POST"
            and relative_path.startswith("/card-allocations/")
            and "/reveal" in relative_path
        )
        if is_upload_write or is_card_reveal:
            return self.policies["high_risk"]
        return self.policies["general"]

    def _key(self, request: Request, policy: RateLimitPolicy, now: float) -> str:
        ip_fingerprint = _fingerprint(_clean_ip(request))
        if policy.name == "login":
            identity = f"ip:{ip_fingerprint}"
        else:
            token_fingerprint = _bearer_fingerprint(request) or "anonymous"
            identity = f"auth:{token_fingerprint}|ip:{ip_fingerprint}"
        identity_fingerprint = _fingerprint(identity)
        window = int(now) // policy.window_seconds
        return f"rate-limit:{policy.name}:{window}:{identity_fingerprint}"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)

        policy = self._policy(request)
        now = float(self.clock())
        key = self._key(request, policy, now)
        next_window = (int(now) // policy.window_seconds + 1) * policy.window_seconds
        cleanup_ttl = max(1, math.ceil(next_window - now))
        try:
            count, ttl = await self.backend.increment(key, cleanup_ttl)
        except Exception:
            if self.fail_closed:
                return _error_response(
                    request,
                    status_code=503,
                    code="service_unavailable",
                    message="Rate limit service unavailable",
                    recovery_hint="稍后重试；持续失败时携带 trace_id 联系管理员",
                )
            return await call_next(request)

        remaining = max(policy.limit - count, 0)
        reset_at = int(now) + max(ttl, 1)
        headers = {
            "X-RateLimit-Limit": str(policy.limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }
        if count > policy.limit:
            headers["Retry-After"] = str(max(ttl, 1))
            return _error_response(
                request,
                status_code=429,
                code="rate_limited",
                message="Too many requests",
                recovery_hint="请在 Retry-After 指定时间后重试",
                headers=headers,
            )

        response = await call_next(request)
        response.headers.update(headers)
        return response


__all__ = [
    "RateLimitBackend",
    "RateLimitBackendUnavailable",
    "RateLimitMiddleware",
    "RedisRateLimitBackend",
]
