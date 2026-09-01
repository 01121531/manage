"""Request tracing, browser-origin enforcement, and safe error handling."""

from collections.abc import Iterable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from platform.audit import bind_audit_request_metadata, reset_audit_request_metadata


_CORS_ALLOW_HEADERS = (
    "Authorization, Content-Type, X-Trace-Id, X-Mail-Session-Token, "
    "Secure-Import-Context, Secure-Import-Receipt"
)
_CORS_ALLOW_METHODS = "GET, POST, PATCH, DELETE, OPTIONS"
_CORS_EXPOSE_HEADERS = "X-Trace-Id, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining"


def parse_allowed_origins(value: str, *, require_https: bool) -> tuple[str, ...]:
    """Parse a comma-separated exact-origin allowlist.

    Origins may not contain credentials, paths, queries, fragments, or a
    wildcard. Managed environments require HTTPS. Development may use HTTP for
    loopback hosts only.
    """

    origins: list[str] = []
    for raw_origin in value.split(","):
        origin = raw_origin.strip()
        if not origin:
            continue
        parsed = urlsplit(origin)
        hostname = (parsed.hostname or "").lower()
        is_loopback = hostname in {"localhost", "127.0.0.1", "::1"}
        valid_scheme = parsed.scheme == "https" or (
            not require_https and parsed.scheme == "http" and is_loopback
        )
        if (
            origin == "*"
            or not valid_scheme
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("allowed_origins contains an invalid origin")
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        if normalized not in origins:
            origins.append(normalized)
    return tuple(origins)


class OriginPolicyMiddleware(BaseHTTPMiddleware):
    """Reject browser requests from unapproved origins and answer preflight."""

    def __init__(self, app, *, allowed_origins: Iterable[str]) -> None:
        super().__init__(app)
        self._allowed_origins = frozenset(allowed_origins)

    @staticmethod
    def _apply_cors_headers(response: Response, origin: str) -> None:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = _CORS_ALLOW_METHODS
        response.headers["Access-Control-Allow-Headers"] = _CORS_ALLOW_HEADERS
        response.headers["Access-Control-Expose-Headers"] = _CORS_EXPOSE_HEADERS
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers.add_vary_header("Origin")

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        origin = request.headers.get("Origin")
        if origin is None:
            return await call_next(request)
        if origin not in self._allowed_origins:
            trace_id = getattr(request.state, "trace_id", "")
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "origin_not_allowed",
                        "message": "Request origin is not allowed",
                        "recovery_hint": "请从受信任的平台入口重试",
                        "trace_id": trace_id,
                    }
                },
            )
        if request.method == "OPTIONS" and request.headers.get(
            "Access-Control-Request-Method"
        ):
            response = Response(status_code=204)
        else:
            response = await call_next(request)
        self._apply_cors_headers(response, origin)
        return response


def _trace_id(value: str | None) -> str:
    """Use a caller supplied UUID when valid, otherwise create one."""

    if value:
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


class TraceAndErrorMiddleware(BaseHTTPMiddleware):
    """Attach a trace id and normalize uncaught exceptions."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        trace_id = _trace_id(request.headers.get("X-Trace-Id"))
        request.state.trace_id = trace_id
        audit_context = bind_audit_request_metadata(
            ip_address=request.headers.get("X-Real-IP")
            or (request.client.host if request.client is not None else None),
            user_agent=request.headers.get("User-Agent"),
        )
        try:
            try:
                response = await call_next(request)
            except Exception:
                # Do not expose exception details or credentials to clients.
                response = JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": "internal_error",
                            "message": "Internal server error",
                            "recovery_hint": "携带 trace_id 联系管理员",
                            "trace_id": trace_id,
                        }
                    },
                )
            registry = getattr(request.app.state, "metrics", None)
            if registry is not None:
                route = request.scope.get("route")
                route_path = getattr(route, "path", request.url.path)
                registry.increment(
                    "platform_http_requests_total",
                    {
                        "method": request.method,
                        "path": route_path,
                        "status_code": response.status_code,
                    },
                )
            response.headers["X-Trace-Id"] = trace_id
            return response
        finally:
            reset_audit_request_metadata(audit_context)
