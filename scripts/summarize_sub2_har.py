"""Create a value-free Sub2 request/response shape summary from a browser HAR."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from scripts.backup_output_policy import (
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import read_stable_bytes_with_metadata

MAX_HAR_BYTES = 32 * 1024 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_ENTRIES = 500
MAX_FIELD_PATHS = 256
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")
_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
_LONG_HEX = re.compile(r"[0-9a-fA-F]{16,}")
_LONG_DIGITS = re.compile(r"\d{12,}")
_JWT = re.compile(r"(?:^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}")
_SAFE_REQUEST_HEADERS = {
    "api-key",
    "authorization",
    "content-type",
    "cookie",
    "idempotency-key",
    "if-none-match",
    "x-admin-ui-request",
    "x-api-key",
}
_SAFE_RESPONSE_HEADERS = {
    "content-type",
    "etag",
    "location",
    "retry-after",
}
_ACCOUNT_COLLECTION_SEGMENTS = {
    "antigravity",
    "batch",
    "batch-clear-error",
    "batch-refresh",
    "batch-update-credentials",
    "bulk-update",
    "check-mixed-channel",
    "data",
    "import",
    "models",
    "ollama-cloud-usage",
    "sync",
    "today-stats",
    "upstream-billing-probe",
}


class Sub2HarSummaryError(RuntimeError):
    """The HAR cannot be summarized without weakening the redaction boundary."""


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
    try:
        port = parsed.port or 443
    except ValueError:
        raise Sub2HarSummaryError("Sub2 HAR summary input is invalid") from None
    return parsed.scheme, parsed.hostname.lower(), port


def _field_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not _FIELD.fullmatch(normalized) or _looks_sensitive_identifier(normalized):
        return None
    return normalized


def _looks_sensitive_identifier(value: str) -> bool:
    decoded = urllib.parse.unquote(value)
    compact = decoded.strip()
    if not compact or "@" in compact or _JWT.search(compact):
        return True
    if _LONG_HEX.search(compact) or _LONG_DIGITS.search(compact):
        return True
    if len(compact) > 48:
        return True
    if compact.count(".") >= 2:
        return True
    return False


def _field_paths(value: object) -> list[str]:
    paths: set[str] = set()

    def visit(item: object, prefix: str, depth: int) -> None:
        if depth > 8 or len(paths) >= MAX_FIELD_PATHS:
            return
        if isinstance(item, dict):
            for raw_name, child in item.items():
                name = _field_name(raw_name)
                if name is None:
                    continue
                path = f"{prefix}.{name}" if prefix else name
                paths.add(path)
                visit(child, path, depth + 1)
        elif isinstance(item, list):
            array_prefix = f"{prefix}[]" if prefix else "[]"
            for child in item[:20]:
                visit(child, array_prefix, depth + 1)

    visit(value, "", 0)
    return sorted(paths)[:MAX_FIELD_PATHS]


def _json_shape(text: object, *, encoded: bool = False) -> tuple[str, list[str]]:
    if encoded:
        return "encoded_uninspected", []
    if not isinstance(text, str) or not text:
        return "unavailable", []
    raw = text.encode("utf-8", errors="strict")
    if len(raw) > MAX_BODY_BYTES:
        return "oversized_uninspected", []
    try:
        value = parse_unique_json_bytes(raw)
    except (JsonBoundaryError, UnicodeError):
        return "non_json", []
    kind = (
        "json_object"
        if isinstance(value, dict)
        else "json_array"
        if isinstance(value, list)
        else "json_scalar"
    )
    return kind, _field_paths(value)


def _header_names(value: object, *, response: bool = False) -> list[str]:
    if not isinstance(value, list):
        return []
    selected: set[str] = set()
    safe = _SAFE_RESPONSE_HEADERS if response else _SAFE_REQUEST_HEADERS
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        normalized = name.strip().lower() if isinstance(name, str) else ""
        if normalized in safe or (
            response
            and (
                normalized.startswith("ratelimit-")
                or normalized.startswith("x-ratelimit-")
            )
            and _field_name(normalized) is not None
        ):
            selected.add(normalized)
    return sorted(selected)


def _query_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    names = {
        name
        for item in value
        if isinstance(item, dict)
        and (name := _field_name(item.get("name"))) is not None
    }
    return sorted(names)


def _template_path(path: str) -> str:
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if index <= 4 or not segment:
            continue
        decoded = urllib.parse.unquote(segment)
        if (
            _looks_sensitive_identifier(segment)
            or not re.fullmatch(r"[a-z][a-z-]{0,39}", decoded)
        ):
            segments[index] = "{value}"
        else:
            segments[index] = decoded
    if len(segments) > 5 and segments[1:5] == ["api", "v1", "admin", "accounts"]:
        if segments[5] not in _ACCOUNT_COLLECTION_SEGMENTS:
            segments[5] = "{account_id}"
    if (
        len(segments) > 6
        and segments[1:6] == ["api", "v1", "admin", "openai", "accounts"]
    ):
        segments[6] = "{account_id}"
    return "/".join(segments)


def summarize_har(raw: bytes, *, expected_origin: str) -> dict[str, object]:
    try:
        document = parse_unique_json_bytes(raw)
        expected = _origin(expected_origin)
        entries = document["log"]["entries"]
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
        summarized: list[dict[str, object]] = []
        for source_index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
            request = entry.get("request")
            response = entry.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
            method = request.get("method")
            url = request.get("url")
            status = response.get("status")
            if not isinstance(method, str) or not isinstance(url, str):
                raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
            normalized_method = method.strip().upper()
            if normalized_method not in _METHODS:
                raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
            parsed = urllib.parse.urlsplit(url)
            try:
                observed = (
                    parsed.scheme,
                    (parsed.hostname or "").lower(),
                    parsed.port or 443,
                )
            except ValueError:
                continue
            if (
                parsed.username is not None
                or parsed.password is not None
                or observed != expected
                or not parsed.path.startswith("/api/v1/admin/")
            ):
                continue
            if type(status) is not int or not 0 <= status <= 599:
                raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
            post_data = request.get("postData")
            request_kind, request_fields = _json_shape(
                post_data.get("text") if isinstance(post_data, dict) else None
            )
            content = response.get("content")
            response_kind, response_fields = _json_shape(
                content.get("text") if isinstance(content, dict) else None,
                encoded=(
                    isinstance(content, dict)
                    and content.get("encoding") == "base64"
                ),
            )
            request_headers = _header_names(request.get("headers"))
            summarized.append(
                {
                    "source_index": source_index,
                    "method": normalized_method,
                    "path": _template_path(parsed.path),
                    "query_fields": _query_names(request.get("queryString")),
                    "request_header_names": request_headers,
                    "auth_location": (
                        "authorization_header"
                        if "authorization" in request_headers
                        else "cookie"
                        if "cookie" in request_headers
                        else "not_observed"
                    ),
                    "request_body_kind": request_kind,
                    "request_fields": request_fields,
                    "status": status,
                    "response_header_names": _header_names(
                        response.get("headers"), response=True
                    ),
                    "response_body_kind": response_kind,
                    "response_fields": response_fields,
                }
            )
    except (
        KeyError,
        RecursionError,
        TypeError,
        UnicodeError,
        JsonBoundaryError,
        Sub2HarSummaryError,
    ):
        raise Sub2HarSummaryError("Sub2 HAR summary input is invalid") from None
    if not summarized:
        raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
    return {
        "schema_version": 1,
        "record_type": "sub2_har_shape_summary",
        "provider_origin": f"https://{expected[1]}"
        + ("" if expected[2] == 443 else f":{expected[2]}"),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "production_acceptance": False,
        "entry_count": len(summarized),
        "entries": summarized,
        "redaction": {
            "contains_header_values": False,
            "contains_query_values": False,
            "contains_request_values": False,
            "contains_response_values": False,
            "contains_source_path": False,
        },
    }


def summarize_file(input_path: Path, output_path: Path, *, expected_origin: str) -> int:
    temporary: Path | None = None
    try:
        if not input_path.is_absolute() or input_path.resolve(strict=True).is_relative_to(
            ROOT.resolve()
        ):
            raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
        destination = prepare_write_once_file(output_path)
        raw, metadata = read_stable_bytes_with_metadata(
            input_path,
            max_bytes=MAX_HAR_BYTES,
        )
        if metadata.st_nlink != 1:
            raise Sub2HarSummaryError("Sub2 HAR summary input is invalid")
        summary = summarize_har(raw, expected_origin=expected_origin)
        encoded = (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode(
            "utf-8"
        )
        temporary = write_fsynced_temporary_bytes(destination, encoded)
        publish_write_once_file(temporary, destination)
        temporary = None
    except (OSError, ValueError, Sub2HarSummaryError):
        raise Sub2HarSummaryError("Sub2 HAR summary input is invalid") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    return int(summary["entry_count"])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-origin", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        count = summarize_file(
            options.input,
            options.output,
            expected_origin=options.expected_origin,
        )
    except Sub2HarSummaryError:
        print("sub2-har-summary-invalid", file=sys.stderr)
        return 1
    print(f"sub2-har-summary-ok entries={count} production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
