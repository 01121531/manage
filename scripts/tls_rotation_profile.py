"""Review a live capture into one closed repository-external runtime profile."""

from __future__ import annotations

import argparse
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Sequence

from scripts.backup_output_policy import (
    REPOSITORY_ROOT,
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_write_once_file,
    write_fsynced_temporary_bytes,
)
from scripts.compose_tls_rotation_backend import (
    PROFILE_SCHEMA_VERSION as COMPOSE_SCHEMA_VERSION,
    load_compose_rotation_profile,
)
from scripts.external_json import read_stable_bytes
from scripts.kubernetes_tls_rotation_backend import (
    PROFILE_SCHEMA_VERSION as KUBERNETES_SCHEMA_VERSION,
    load_kubernetes_rotation_profile,
)
from scripts.release_control_lock import release_control_lock
from scripts.tls_rotation_profile_capture import (
    MAX_JSON_BYTES,
    load_capture,
    load_capture_request,
    reviewed_profile_from_capture,
)


RUNTIME_KINDS = frozenset({"compose", "kubernetes"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TlsRotationProfileError(ValueError):
    """A reviewed profile artifact could not be processed safely."""


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationProfileError("TLS rotation profile path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationProfileError("TLS rotation profile path is invalid")


def _schema_version(runtime_kind: str) -> int:
    if runtime_kind == "compose":
        return COMPOSE_SCHEMA_VERSION
    if runtime_kind == "kubernetes":
        return KUBERNETES_SCHEMA_VERSION
    raise TlsRotationProfileError("TLS rotation profile runtime is invalid")


def _load(runtime_kind: str, path: Path):
    if runtime_kind == "compose":
        return load_compose_rotation_profile(path)
    if runtime_kind == "kubernetes":
        return load_kubernetes_rotation_profile(path)
    raise TlsRotationProfileError("TLS rotation profile runtime is invalid")


def review_profile(
    request_path: Path,
    capture_path: Path,
    profile_output: Path,
    *,
    confirm_live_capture_sha256: str,
) -> tuple[str, int, str]:
    request_source = _external_path(request_path)
    capture_source = _external_path(capture_path)
    output = prepare_write_once_file(_external_path(profile_output))
    paths = {
        str(path.resolve(strict=False)).casefold()
        for path in (request_source, capture_source, output)
    }
    if len(paths) != 3:
        raise TlsRotationProfileError("TLS rotation profile paths are invalid")
    with release_control_lock():
        request = load_capture_request(request_source)
        capture = load_capture(capture_source, request)
        capture_digest = capture["integrity"]["payload_sha256"]
        if (
            not isinstance(confirm_live_capture_sha256, str)
            or _SHA256.fullmatch(confirm_live_capture_sha256) is None
            or not hmac.compare_digest(confirm_live_capture_sha256, capture_digest)
        ):
            raise TlsRotationProfileError("TLS rotation capture confirmation failed")
        runtime_kind = str(capture["runtime_kind"])
        profile = reviewed_profile_from_capture(capture)
        canonical = (
            json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(canonical) > MAX_JSON_BYTES:
            raise TlsRotationProfileError("TLS rotation profile is invalid")
        temporary = write_fsynced_temporary_bytes(output, canonical)
        try:
            publish_write_once_file(temporary, output)
        finally:
            discard_claimed_temporary_file(temporary)
        readback = read_stable_bytes(output, max_bytes=MAX_JSON_BYTES)
        if not hmac.compare_digest(readback, canonical):
            raise TlsRotationProfileError("TLS rotation profile publication failed")
        loaded = _load(runtime_kind, output)
        if not hmac.compare_digest(
            loaded.live_capture_sha256, str(capture_digest)
        ):
            raise TlsRotationProfileError("TLS rotation profile publication failed")
    return runtime_kind, _schema_version(runtime_kind), loaded.profile_sha256


def verify_profile(runtime_kind: str, profile_path: Path) -> tuple[int, str]:
    profile = _load(runtime_kind, _external_path(profile_path))
    return _schema_version(runtime_kind), profile.profile_sha256


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationProfileError("TLS rotation profile CLI input is invalid") from None


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    review = subparsers.add_parser("review", allow_abbrev=False)
    review.add_argument("--request", type=Path, required=True)
    review.add_argument("--capture", type=Path, required=True)
    review.add_argument("--profile-output", type=Path, required=True)
    review.add_argument("--confirm-live-capture-sha256", required=True)
    verify = subparsers.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--runtime-kind", choices=sorted(RUNTIME_KINDS), required=True)
    verify.add_argument("--profile", type=Path, required=True)
    return parser.parse_args(list(arguments))


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parse(list(sys.argv[1:] if arguments is None else arguments))
        if options.mode == "review":
            runtime_kind, schema_version, digest = review_profile(
                options.request,
                options.capture,
                options.profile_output,
                confirm_live_capture_sha256=options.confirm_live_capture_sha256,
            )
        else:
            runtime_kind = options.runtime_kind
            schema_version, digest = verify_profile(runtime_kind, options.profile)
    except (KeyboardInterrupt, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("tls-rotation-profile-failed", file=sys.stderr)
        return 1
    print(
        "tls-rotation-profile-ok production_acceptance=false "
        f"runtime_kind={runtime_kind} schema_version={schema_version} "
        f"profile_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
