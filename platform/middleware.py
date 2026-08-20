"""Request tracing and last-resort error handling middleware."""

from uuid import UUID, uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from platform.audit import bind_audit_request_metadata, reset_audit_request_metadata


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
