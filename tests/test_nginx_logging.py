import unittest

from scripts.verify_nginx_logging import load_assets, validate_nginx_logging


class NginxLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configs = load_assets()

    def validate(self) -> list[str]:
        return validate_nginx_logging(self.configs)

    def test_repository_uses_safe_logging_in_both_layers(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_missing_layer_is_rejected(self) -> None:
        self.configs.pop("web")
        self.assertTrue(any("missing" in error for error in self.validate()))

    def test_missing_explicit_access_log_is_rejected(self) -> None:
        self.configs["edge"] = self.configs["edge"].replace(
            "access_log /dev/stdout platform_safe;", ""
        )
        self.assertTrue(any("access log" in error for error in self.validate()))

    def test_dangerous_variables_are_rejected_without_prefix_false_positive(self) -> None:
        dangerous = (
            "$request",
            "$request_uri",
            "$args",
            "$query_string",
            "$request_body",
            "$http_cookie",
            "$http_authorization",
            "$http_x_mail_session_token",
            "$upstream_http_set_cookie",
        )
        for variable in dangerous:
            with self.subTest(variable=variable):
                configs = load_assets()
                configs["edge"] = configs["edge"].replace(
                    '"uri":"$uri"', f'"uri":"{variable}"'
                )
                errors = validate_nginx_logging(configs)
                self.assertTrue(any("allowlist" in error for error in errors), errors)

    def test_escape_json_is_required(self) -> None:
        self.configs["web"] = self.configs["web"].replace(" escape=json", "")
        self.assertTrue(any("escape=json" in error for error in self.validate()))

    def test_client_supplied_trace_header_is_rejected(self) -> None:
        self.configs["edge"] = self.configs["edge"].replace(
            '"upstream_response_time":"$upstream_response_time"}\';',
            '"upstream_response_time":"$upstream_response_time",'
            '"trace":"$http_x_trace_id"}\';',
        )
        self.assertTrue(any("allowlist" in error for error in self.validate()))

    def test_request_level_error_logging_is_rejected(self) -> None:
        for level in ("alert", "crit", "error", "warn", "notice", "info", "debug"):
            with self.subTest(level=level):
                configs = load_assets()
                configs["web"] = configs["web"].replace(
                    "error_log /dev/stderr emerg;",
                    f"error_log /dev/stderr {level};",
                )
                errors = validate_nginx_logging(configs)
                self.assertTrue(any("error log" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
