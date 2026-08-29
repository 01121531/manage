from __future__ import annotations

import asyncio
import json
import unittest

from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from platform.errors import BusinessHTTPException, http_exception_handler


TRACE_ID = "00000000-0000-4000-8000-000000000024"


def _request() -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/test-error-boundary",
            "raw_path": b"/test-error-boundary",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("platform.example.test", 443),
        }
    )
    request.state.trace_id = TRACE_ID
    return request


def _handle(error: StarletteHTTPException):
    return asyncio.run(http_exception_handler(_request(), error))


def _payload(response) -> dict[str, object]:
    return json.loads(response.body.decode("utf-8"))


class HttpErrorBoundaryTests(unittest.TestCase):
    def test_plain_http_exception_never_reflects_detail_or_arbitrary_headers(self) -> None:
        sentinels = (
            "Bearer upstream-secret",
            "vault://tenant/private/path",
            "SENSITIVE_PROVIDER_BODY",
        )
        response = _handle(
            StarletteHTTPException(
                status_code=503,
                detail=" | ".join(sentinels),
                headers={
                    "Authorization": sentinels[0],
                    "X-Upstream-Error": sentinels[2],
                    "WWW-Authenticate": sentinels[0],
                    "Retry-After": sentinels[1],
                },
            )
        )

        serialized = response.body.decode("utf-8") + repr(dict(response.headers))
        for sentinel in sentinels:
            self.assertNotIn(sentinel, serialized)
        self.assertEqual(
            _payload(response)["error"],
            {
                "code": "service_unavailable",
                "message": "Service is temporarily unavailable",
                "recovery_hint": "稍后重试；持续失败时携带 trace_id 联系管理员",
                "trace_id": TRACE_ID,
            },
        )

    def test_only_valid_standard_challenge_and_method_headers_survive(self) -> None:
        unauthorized = _handle(
            StarletteHTTPException(
                status_code=401,
                detail="private auth detail",
                headers={"WWW-Authenticate": "Bearer"},
            )
        )
        method = _handle(
            StarletteHTTPException(
                status_code=405,
                detail="private router detail",
                headers={"Allow": "GET, HEAD"},
            )
        )

        self.assertEqual(unauthorized.headers["www-authenticate"], "Bearer")
        self.assertEqual(method.headers["allow"], "GET, HEAD")

    def test_malformed_allowed_header_values_are_dropped(self) -> None:
        cases = (
            (401, {"WWW-Authenticate": "Bearer leaked-token"}),
            (401, {"WWW-Authenticate": "Basic realm=private"}),
            (405, {"Allow": "GET\r\nX-Leak: secret"}),
            (405, {"Allow": "GET, UNREVIEWED"}),
        )
        for status_code, headers in cases:
            with self.subTest(status_code=status_code, headers=headers):
                response = _handle(
                    StarletteHTTPException(
                        status_code=status_code,
                        detail="private detail",
                        headers=headers,
                    )
                )
                self.assertNotIn("www-authenticate", response.headers)
                self.assertNotIn("allow", response.headers)

    def test_explicit_business_exception_preserves_reviewed_contract(self) -> None:
        response = _handle(
            BusinessHTTPException(
                status_code=409,
                code="reviewed_conflict",
                message="Reviewed business message",
                recovery_hint="Refresh the reviewed state",
            )
        )
        self.assertEqual(
            _payload(response)["error"],
            {
                "code": "reviewed_conflict",
                "message": "Reviewed business message",
                "recovery_hint": "Refresh the reviewed state",
                "trace_id": TRACE_ID,
            },
        )

    def test_plain_forbidden_uses_a_fixed_safe_contract(self) -> None:
        response = _handle(
            StarletteHTTPException(
                status_code=403,
                detail="private role engine detail",
            )
        )
        self.assertEqual(_payload(response)["error"]["message"], "Insufficient role")
        self.assertEqual(_payload(response)["error"]["code"], "forbidden")


if __name__ == "__main__":
    unittest.main()
