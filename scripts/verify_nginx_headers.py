"""Verify security headers are present on every relevant Nginx location."""

from __future__ import annotations

from pathlib import Path
import re
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "infra" / "nginx" / "email-platform.conf.template"
WEB_CONF = ROOT / "infra" / "nginx" / "web.conf"


_REQUIRED = (
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _location_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    pattern = re.compile(r"location\s+([^{]+)\{\n", re.MULTILINE)
    matches = list(pattern.finditer(text))
    for index, match in enumerate(matches):
        start = match.end()
        depth = 1
        pos = start
        while pos < len(text) and depth > 0:
            char = text[pos]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            pos += 1
        blocks.append((match.group(1).strip(), text[start : pos - 1]))
    return blocks


def _check_file(path: Path, *, allow_missing_csp_for: set[str] | None = None) -> tuple[bool, str]:
    text = load_stable_text(path)
    missing: list[str] = []
    for label, body in _location_blocks(text):
        for header in _REQUIRED:
            if header not in body:
                missing.append(f"{path.name}:{label}:{header}")
        if "Content-Security-Policy" not in body:
            if allow_missing_csp_for and label in allow_missing_csp_for:
                continue
            missing.append(f"{path.name}:{label}:Content-Security-Policy")
    if missing:
        return False, ", ".join(missing)
    return True, ""


def main() -> int:
    try:
        template_ok, template_errors = _check_file(TEMPLATE)
    except OSError:
        return _fail("Unable to load Nginx header assets")
    if not template_ok:
        return _fail("Missing Nginx headers: " + template_errors)
    try:
        web_ok, web_errors = _check_file(WEB_CONF)
    except OSError:
        return _fail("Unable to load Nginx header assets")
    if not web_ok:
        return _fail("Missing Nginx headers: " + web_errors)
    print("nginx-headers-ok location-level-security-headers-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
