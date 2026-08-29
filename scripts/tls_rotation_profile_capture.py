"""Capture or verify one read-only TLS rotation runtime-profile snapshot."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Callable, Mapping, Sequence

from scripts.backup_output_policy import (
    REPOSITORY_ROOT,
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.compose_tls_rotation_backend import (
    PROFILE_SCHEMA_VERSION as COMPOSE_PROFILE_SCHEMA,
    _TARGETS as COMPOSE_TARGETS,
    validate_compose_rotation_profile,
)
from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
from scripts.kubernetes_tls_rotation_backend import (
    PROFILE_SCHEMA_VERSION as KUBERNETES_PROFILE_SCHEMA,
    _TARGETS as KUBERNETES_TARGETS,
    validate_kubernetes_rotation_profile,
)
from scripts.release_control_lock import release_control_lock
from scripts.tls_rotation_evidence import utc_now
from scripts.tls_rotation_support import parse_utc


SCHEMA_VERSION = 1
CAPTURE_KIND = "tls_rotation_runtime_profile_live_capture"
REQUEST_KIND = "tls_rotation_profile_capture_request"
MAX_JSON_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INSTANCE_ID = re.compile(
    r"^(?:[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
_CONTAINER_ID = re.compile(r"^(?:(?:docker|containerd)://)?[0-9a-f]{64}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTEXT = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
_PLACEHOLDERS = frozenset({"development", "example", "local", "placeholder", "tbd", "test"})
_COMMON_REQUEST_FIELDS = {
    "schema_version", "request_kind", "runtime_kind",
    "target_environment", "service",
}
_KUBERNETES_REQUEST_FIELDS = _COMMON_REQUEST_FIELDS | {
    "kubeconfig_path", "context", "namespace",
    "direct_observer", "route_observers",
}
_LOCATOR_FIELDS = {"logical_name", "namespace", "deployment", "container"}
_CAPTURE_FIELDS = {
    "schema_version", "capture_kind", "production_acceptance",
    "runtime_kind", "capture_request_sha256", "captured_at",
    "candidate_profile", "runtime_summary",
}
_SUMMARY_FIELDS = {
    "instances", "captured_observers", "blocked_observers",
}
_INSTANCE_FIELDS = {"instance_id", "container_id", "started_at"}


class TlsRotationProfileCaptureError(ValueError):
    """A read-only runtime profile capture could not be accepted safely."""


CaptureProvider = Callable[
    [Mapping[str, object]], tuple[dict[str, object], dict[str, object]]
]


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationProfileCaptureError("TLS rotation capture path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationProfileCaptureError("TLS rotation capture path is invalid")


def _canonical_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_capture_request(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    runtime_kind = value.get("runtime_kind")
    expected_fields = (
        _COMMON_REQUEST_FIELDS if runtime_kind == "compose" else _KUBERNETES_REQUEST_FIELDS
    )
    environment = value.get("target_environment")
    targets = COMPOSE_TARGETS if runtime_kind == "compose" else KUBERNETES_TARGETS
    if (
        set(value) != expected_fields
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("request_kind") != REQUEST_KIND
        or runtime_kind not in {"compose", "kubernetes"}
        or not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
        or value.get("service") not in targets
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    if runtime_kind == "compose":
        return dict(value)
    try:
        kubeconfig = _external_path(Path(value["kubeconfig_path"]))
    except (TypeError, ValueError):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid") from None
    if (
        not isinstance(value["context"], str)
        or _CONTEXT.fullmatch(value["context"]) is None
        or not isinstance(value["namespace"], str)
        or _NAME.fullmatch(value["namespace"]) is None
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    contract = KUBERNETES_TARGETS[str(value["service"])]
    direct = value["direct_observer"]
    routes = value["route_observers"]
    if not isinstance(direct, dict) or set(direct) != _LOCATOR_FIELDS:
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    if direct.get("logical_name") != "direct-instance":
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    if not isinstance(routes, list):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    locators = [direct, *routes]
    if any(
        not isinstance(item, dict)
        or set(item) != _LOCATOR_FIELDS
        or any(
            not isinstance(item[field], str) or _NAME.fullmatch(item[field]) is None
            for field in ("logical_name", "namespace", "deployment", "container")
        )
        for item in locators
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture request is invalid")
    route_names = [item["logical_name"] for item in routes]
    if (
        route_names != list(contract.required_observers)
        or direct["container"] != direct["deployment"]
        or any(item["deployment"] != item["logical_name"] for item in routes)
        or any(item["container"] != item["deployment"] for item in routes)
    ):
        raise TlsRotationProfileCaptureError("TLS rotation observer request is invalid")
    result = json.loads(json.dumps(value))
    result["kubeconfig_path"] = str(kubeconfig)
    return result


def load_capture_request(path: Path) -> dict[str, object]:
    raw = read_stable_bytes(_external_path(path), max_bytes=MAX_JSON_BYTES)
    return validate_capture_request(parse_unique_json_bytes(raw))


def _validate_candidate(runtime_kind: str, candidate: object) -> dict[str, object]:
    if not isinstance(candidate, dict) or "live_capture_sha256" in candidate:
        raise TlsRotationProfileCaptureError("TLS rotation capture candidate is invalid")
    value = dict(candidate)
    value["live_capture_sha256"] = "0" * 64
    try:
        if runtime_kind == "compose":
            if value.get("schema_version") != COMPOSE_PROFILE_SCHEMA:
                raise ValueError
            validate_compose_rotation_profile(value)
        else:
            if value.get("schema_version") != KUBERNETES_PROFILE_SCHEMA:
                raise ValueError
            validate_kubernetes_rotation_profile(value)
    except (TypeError, ValueError):
        raise TlsRotationProfileCaptureError("TLS rotation capture candidate is invalid") from None
    return dict(candidate)


def reviewed_profile_from_capture(capture: Mapping[str, object]) -> dict[str, object]:
    candidate = dict(capture["candidate_profile"])
    candidate["live_capture_sha256"] = capture["integrity"]["payload_sha256"]
    runtime_kind = str(capture["runtime_kind"])
    if runtime_kind == "compose":
        validate_compose_rotation_profile(candidate)
    else:
        validate_kubernetes_rotation_profile(candidate)
    return candidate


def _validate_summary(value: object, candidate: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _SUMMARY_FIELDS:
        raise TlsRotationProfileCaptureError("TLS rotation capture summary is invalid")
    instances = value["instances"]
    observers = value["captured_observers"]
    blocked = value["blocked_observers"]
    if (
        not isinstance(instances, list)
        or len(instances) != candidate["expected_instance_count"]
        or any(
            not isinstance(item, dict)
            or set(item) != _INSTANCE_FIELDS
            or not isinstance(item["instance_id"], str)
            or _INSTANCE_ID.fullmatch(item["instance_id"]) is None
            or not isinstance(item["container_id"], str)
            or _CONTAINER_ID.fullmatch(item["container_id"]) is None
            or not isinstance(item["started_at"], str)
            for item in instances
        )
        or not isinstance(observers, list)
        or observers != sorted(set(observers))
        or "direct-instance" not in observers
        or not isinstance(blocked, list)
        or blocked != candidate["blocked_observers"]
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture summary is invalid")
    for instance in instances:
        parse_utc(instance["started_at"])
    expected_observers = sorted(
        ["direct-instance"]
        + [item["logical_name"] for item in candidate["route_observers"]]
    )
    if observers != expected_observers:
        raise TlsRotationProfileCaptureError("TLS rotation capture summary is invalid")
    return dict(value)


def _seal(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != _CAPTURE_FIELDS:
        raise TlsRotationProfileCaptureError("TLS rotation capture is invalid")
    runtime_kind = payload["runtime_kind"]
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["capture_kind"] != CAPTURE_KIND
        or payload["production_acceptance"] is not False
        or runtime_kind not in {"compose", "kubernetes"}
        or not isinstance(payload["capture_request_sha256"], str)
        or _SHA256.fullmatch(payload["capture_request_sha256"]) is None
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture is invalid")
    parse_utc(payload["captured_at"])
    candidate = _validate_candidate(str(runtime_kind), payload["candidate_profile"])
    _validate_summary(payload["runtime_summary"], candidate)
    sealed = dict(payload)
    sealed["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return sealed


def validate_capture(
    value: object, request: Mapping[str, object] | None = None
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {*_CAPTURE_FIELDS, "integrity"}:
        raise TlsRotationProfileCaptureError("TLS rotation capture is invalid")
    integrity = value["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        raise TlsRotationProfileCaptureError("TLS rotation capture is invalid")
    payload = {key: item for key, item in value.items() if key != "integrity"}
    expected = _seal(payload)
    actual = integrity.get("payload_sha256")
    if (
        not isinstance(actual, str)
        or _SHA256.fullmatch(actual) is None
        or not hmac.compare_digest(actual, expected["integrity"]["payload_sha256"])
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture integrity is invalid")
    if request is not None and (
        payload["runtime_kind"] != request["runtime_kind"]
        or payload["capture_request_sha256"] != _canonical_digest(request)
        or payload["candidate_profile"]["target_environment"]
        != request["target_environment"]
        or payload["candidate_profile"]["service"] != request["service"]
    ):
        raise TlsRotationProfileCaptureError("TLS rotation capture binding is invalid")
    reviewed_profile_from_capture(value)
    return dict(value)


def load_capture(
    path: Path, request: Mapping[str, object] | None = None
) -> dict[str, object]:
    raw = read_stable_bytes(_external_path(path), max_bytes=MAX_JSON_BYTES)
    return validate_capture(parse_unique_json_bytes(raw), request)


def _default_provider(request: Mapping[str, object]):
    from scripts.tls_rotation_profile_live import capture_runtime_profile

    return capture_runtime_profile(request)


def capture_profile(
    request_path: Path,
    capture_output: Path,
    *,
    provider: CaptureProvider | None = None,
    clock=utc_now,
) -> str:
    source = _external_path(request_path)
    output = prepare_write_once_file(_external_path(capture_output))
    if source.resolve(strict=False) == output.resolve(strict=False):
        raise TlsRotationProfileCaptureError("TLS rotation capture paths are invalid")
    with release_control_lock():
        request = load_capture_request(source)
        candidate, summary = (provider or _default_provider)(request)
        sealed = _seal({
            "schema_version": SCHEMA_VERSION,
            "capture_kind": CAPTURE_KIND,
            "production_acceptance": False,
            "runtime_kind": request["runtime_kind"],
            "capture_request_sha256": _canonical_digest(request),
            "captured_at": clock(),
            "candidate_profile": candidate,
            "runtime_summary": summary,
        })
        validate_capture(sealed, request)
        raw = (json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = write_fsynced_temporary_bytes(output, raw)
        try:
            publish_write_once_file(temporary, output)
        finally:
            discard_claimed_temporary_file(temporary)
        verified = load_capture(output, request)
        if verified != sealed:
            raise TlsRotationProfileCaptureError("TLS rotation capture publication failed")
    return str(sealed["integrity"]["payload_sha256"])


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationProfileCaptureError("TLS rotation capture CLI input is invalid") from None


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    capture = sub.add_parser("capture", allow_abbrev=False)
    capture.add_argument("--request", type=Path, required=True)
    capture.add_argument("--capture-output", type=Path, required=True)
    verify = sub.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--request", type=Path, required=True)
    verify.add_argument("--capture", type=Path, required=True)
    return parser.parse_args(list(arguments))


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parse(list(sys.argv[1:] if arguments is None else arguments))
        if options.mode == "capture":
            digest = capture_profile(options.request, options.capture_output)
        else:
            request = load_capture_request(options.request)
            capture = load_capture(options.capture, request)
            digest = capture["integrity"]["payload_sha256"]
    except (KeyboardInterrupt, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("tls-rotation-profile-capture-failed", file=sys.stderr)
        return 1
    print(
        "tls-rotation-profile-capture-ok production_acceptance=false "
        f"schema_version={SCHEMA_VERSION} capture_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
