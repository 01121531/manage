"""Shared API error response helpers."""

from collections.abc import Mapping
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class BusinessHTTPException(StarletteHTTPException):
    """HTTP error with a stable, non-sensitive business error contract."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        recovery_hint: str,
    ) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.code = code
        self.recovery_hint = recovery_hint


_HTTP_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    410: "gone",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}

_HTTP_ERROR_MESSAGES = {
    400: "Request could not be processed",
    401: "Authentication required or no longer valid",
    403: "Insufficient role",
    404: "Requested resource was not found",
    405: "HTTP method is not allowed",
    409: "Request conflicts with current state",
    410: "Requested resource is no longer available",
    413: "Request payload is too large",
    422: "Request validation failed",
    429: "Too many requests",
    500: "Internal server error",
    503: "Service is temporarily unavailable",
}

_HTTP_ERROR_RECOVERY_HINTS = {
    400: "检查请求内容后重新提交",
    401: "重新登录后再试",
    403: "联系管理员确认账号角色和资源权限",
    404: "刷新列表并确认资源仍然存在",
    405: "确认请求方法和接口地址后重试",
    409: "刷新当前状态后按页面提示继续",
    410: "刷新列表并选择仍然有效的资源",
    413: "缩小请求或文件大小后重试",
    422: "检查请求字段后重新提交",
    429: "稍后重试；持续失败时携带 trace_id 联系管理员",
    500: "携带 trace_id 联系管理员",
    503: "稍后重试；持续失败时携带 trace_id 联系管理员",
}

_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)


def _safe_http_exception_headers(
    status_code: int, headers: Mapping[str, str] | None
) -> dict[str, str] | None:
    """Retain only reviewed protocol headers with validated values."""

    if not headers:
        return None
    normalized = {name.lower(): value for name, value in headers.items()}
    if status_code == 401 and normalized.get("www-authenticate") == "Bearer":
        return {"WWW-Authenticate": "Bearer"}
    if status_code == 405 and "allow" in normalized:
        methods = [item.strip() for item in normalized["allow"].split(",")]
        if (
            methods
            and all(method in _ALLOWED_HTTP_METHODS for method in methods)
            and len(methods) == len(set(methods))
        ):
            return {"Allow": ", ".join(methods)}
    return None


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    recovery_hint: str,
    details: Any | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the stable error envelope used by every API error."""

    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "recovery_hint": recovery_hint,
            "trace_id": getattr(request.state, "trace_id", ""),
        }
    }
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload, headers=headers)


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    if isinstance(exc, BusinessHTTPException):
        code = exc.code
        message = str(exc.detail)
        recovery_hint = exc.recovery_hint
    else:
        code = _HTTP_ERROR_CODES.get(exc.status_code, "http_error")
        message = _HTTP_ERROR_MESSAGES.get(exc.status_code, "Request failed")
        recovery_hint = _HTTP_ERROR_RECOVERY_HINTS.get(
            exc.status_code, "携带 trace_id 联系管理员"
        )
    return error_response(
        request,
        status_code=exc.status_code,
        code=code,
        message=message,
        recovery_hint=recovery_hint,
        headers=_safe_http_exception_headers(exc.status_code, exc.headers),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Pydantic includes the rejected raw input by default. Keep only location
    # and error type so credentials or arbitrary request values are never
    # reflected to the caller.
    safe_details = [
        {
            key: error[key]
            for key in ("type", "loc")
            if key in error
        }
        for error in exc.errors()
    ]
    return error_response(
        request,
        status_code=422,
        code="validation_error",
        message="Request validation failed",
        recovery_hint="检查请求字段后重新提交",
        details=safe_details,
    )
