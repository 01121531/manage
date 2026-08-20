"""Shared API error response helpers."""

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


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
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    codes = {
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        503: "service_unavailable",
    }
    recovery_hints = {
        401: "重新登录后再试",
        403: "联系管理员确认账号角色和资源权限",
        404: "刷新列表并确认资源仍然存在",
        409: "刷新当前状态后按页面提示继续",
        503: "稍后重试；持续失败时携带 trace_id 联系管理员",
    }
    return error_response(
        request,
        status_code=exc.status_code,
        code=codes.get(exc.status_code, "http_error"),
        message=detail,
        recovery_hint=recovery_hints.get(
            exc.status_code, "携带 trace_id 联系管理员"
        ),
        headers=exc.headers,
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
