"""Verify both Nginx layers use query-free, bounded-field request logging."""

from __future__ import annotations

from pathlib import Path
import re
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
CONFIGS = {
    "edge": ROOT / "infra" / "nginx" / "email-platform.conf.template",
    "web": ROOT / "infra" / "nginx" / "web.conf",
}
EXPECTED_FORMAT = (
    "'{\"method\":\"$request_method\",\"uri\":\"$uri\",\"status\":$status,"
    "\"bytes\":$body_bytes_sent,\"request_time\":$request_time,"
    "\"upstream_response_time\":\"$upstream_response_time\"}'"
)
EXPECTED_VARIABLES = {
    "$request_method",
    "$uri",
    "$status",
    "$body_bytes_sent",
    "$request_time",
    "$upstream_response_time",
}
LOG_FORMAT = re.compile(
    r"(?m)^[ \t]*log_format[ \t]+platform_safe[ \t]+escape=json[ \t]+(.+);[ \t]*$"
)
ANY_PLATFORM_FORMAT = re.compile(
    r"(?m)^[ \t]*log_format[ \t]+platform_safe\b.*;[ \t]*$"
)
ACCESS_LOG = re.compile(r"(?m)^[ \t]*access_log\s+([^;]+);[ \t]*$")
ERROR_LOG = re.compile(r"(?m)^[ \t]*error_log\s+([^;]+);[ \t]*$")


def load_assets() -> dict[str, str]:
    return {name: load_stable_text(path) for name, path in CONFIGS.items()}


def validate_nginx_logging(configs: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for name in CONFIGS:
        text = configs.get(name)
        if text is None:
            errors.append(f"missing Nginx logging layer: {name}")
            continue

        formats = LOG_FORMAT.findall(text)
        all_formats = ANY_PLATFORM_FORMAT.findall(text)
        if len(formats) != 1 or len(all_formats) != 1:
            errors.append(f"{name} must define one platform_safe format with escape=json")
        elif formats[0].strip() != EXPECTED_FORMAT:
            variables = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", formats[0]))
            unexpected = sorted(variables - EXPECTED_VARIABLES)
            errors.append(
                f"{name} platform_safe format is not the reviewed allowlist"
                + (f": {', '.join(unexpected)}" if unexpected else "")
            )

        access_logs = [value.strip() for value in ACCESS_LOG.findall(text)]
        if access_logs != ["/dev/stdout platform_safe"]:
            errors.append(f"{name} must use only the explicit platform_safe access log")

        error_logs = [value.strip() for value in ERROR_LOG.findall(text)]
        if error_logs != ["/dev/stderr emerg"]:
            errors.append(f"{name} request error log must be restricted to emerg")
    return errors


def main() -> int:
    try:
        errors = validate_nginx_logging(load_assets())
    except OSError:
        print("Unable to load Nginx logging assets", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("nginx-logging-ok query-free-json-access-and-emerg-error-logs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
