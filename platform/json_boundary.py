"""Strict JSON decoding at bounded trust boundaries."""

from __future__ import annotations

import json


MAX_PERSISTED_JSON_BYTES = 64 * 1024


class JsonBoundaryError(ValueError):
    pass


class _DuplicateJsonKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError
        value[key] = item
    return value


def parse_unique_json_bytes(raw: bytes) -> object:
    """Decode strict UTF-8 JSON while rejecting duplicate keys at every depth."""

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateJsonKeyError, RecursionError):
        raise JsonBoundaryError("invalid JSON") from None


def parse_persisted_json_text(raw: str) -> object:
    """Decode one legacy database JSON value within its fixed byte boundary."""

    if not isinstance(raw, str):
        raise JsonBoundaryError("invalid JSON") from None
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError:
        raise JsonBoundaryError("invalid JSON") from None
    if len(encoded) > MAX_PERSISTED_JSON_BYTES:
        raise JsonBoundaryError("invalid JSON") from None
    return parse_unique_json_bytes(encoded)
