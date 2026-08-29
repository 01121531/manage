from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_http_error_boundary import http_error_boundary_errors


ROOT = Path(__file__).resolve().parents[1]


class HttpErrorBoundaryAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.errors = (ROOT / "platform" / "errors.py").read_text(encoding="utf-8")
        cls.app = (ROOT / "platform" / "app.py").read_text(encoding="utf-8")
        cls.routes = (
            (ROOT / "platform" / "auth.py").read_text(encoding="utf-8"),
            (ROOT / "platform" / "api" / "v1" / "routes.py").read_text(
                encoding="utf-8"
            ),
        )

    def _errors(
        self,
        *,
        errors: str | None = None,
        app: str | None = None,
        routes: tuple[str, ...] | None = None,
    ) -> list[str]:
        return http_error_boundary_errors(
            self.errors if errors is None else errors,
            self.app if app is None else app,
            self.routes if routes is None else routes,
        )

    def test_repository_boundary_is_safe(self) -> None:
        self.assertEqual(self._errors(), [])

    def test_handler_registration_is_required(self) -> None:
        changed = self.app.replace(
            "application.add_exception_handler(\n        StarletteHTTPException, http_exception_handler\n    )",
            "application.add_exception_handler(\n        StarletteHTTPException, validation_exception_handler\n    )",
            1,
        )
        self.assertNotEqual(changed, self.app)
        self.assertIn("handler-registration", self._errors(app=changed))

    def test_plain_detail_and_raw_headers_are_rejected(self) -> None:
        detail = self.errors.replace(
            'message = _HTTP_ERROR_MESSAGES.get(exc.status_code, "Request failed")',
            "message = str(exc.detail)",
            1,
        )
        headers = self.errors.replace(
            "headers=_safe_http_exception_headers(exc.status_code, exc.headers)",
            "headers=exc.headers",
            1,
        )
        self.assertNotEqual(detail, self.errors)
        self.assertNotEqual(headers, self.errors)
        self.assertIn("ordinary-detail-flow", self._errors(errors=detail))
        self.assertIn("arbitrary-header-flow", self._errors(errors=headers))

    def test_header_allowlist_and_exact_bearer_check_are_closed(self) -> None:
        methods = self.errors.replace(
            '"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"',
            '"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"',
            1,
        )
        bearer = self.errors.replace(
            'normalized.get("www-authenticate") == "Bearer"',
            'normalized.get("www-authenticate", "").startswith("Bearer")',
            1,
        )
        self.assertNotEqual(methods, self.errors)
        self.assertNotEqual(bearer, self.errors)
        self.assertIn("unsafe-header-allowlist", self._errors(errors=methods))
        self.assertIn("unsafe-header-validation", self._errors(errors=bearer))

    def test_ordinary_route_detail_must_remain_literal(self) -> None:
        changed_route = self.routes[0].replace(
            'detail="Insufficient role"',
            "detail=str(error)",
            1,
        )
        self.assertNotEqual(changed_route, self.routes[0])
        self.assertIn(
            "dynamic-ordinary-detail",
            self._errors(routes=(changed_route, self.routes[1])),
        )


if __name__ == "__main__":
    unittest.main()
