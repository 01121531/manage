"""Bind reviewed certificate fingerprints to live verified TLS peers."""

from __future__ import annotations

from datetime import datetime
import hmac
import json
from pathlib import Path
import re
from typing import Any

from scripts.check_internal_tls_expiry import CertificateInputError, evaluate_inventory
from scripts.external_json import parse_unique_json_bytes


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TLS_VERSIONS = frozenset({"TLSv1.2", "TLSv1.3"})
_OBSERVATION_FIELDS = {"peer_sha256", "tls_version"}
EVIDENCE_OBSERVATION_FIELDS = {
    "expected_sha256",
    "peer_sha256",
    "tls_version",
}
INTERNAL_ENDPOINT_SERVICES = {
    "api": "api",
    "web": "web",
    "keycloak-health": "keycloak",
    "keycloak-oidc": "keycloak",
    "worker-mail": "worker-mail",
    "worker-sub2": "worker-sub2",
    "prometheus": "prometheus",
}
EXTERNAL_ENDPOINTS = ("platform", "identity")
MAX_OBSERVATION_BYTES = 512


class TlsRuntimeIdentityError(ValueError):
    """A live TLS peer could not be bound to its reviewed leaf certificate."""


TLS_HTTP_PROBE_PROGRAM = """\
import hashlib
import http.client
import json
import socket
import ssl
import sys
import urllib.parse

url = urllib.parse.urlsplit(sys.argv[1])
if (
    url.scheme != "https"
    or not url.hostname
    or url.username is not None
    or url.password is not None
    or url.fragment
):
    raise SystemExit(10)
ca_file = None if sys.argv[2] == "-" else sys.argv[2]
maximum = int(sys.argv[3])
content_type = None if sys.argv[4] == "-" else sys.argv[4]
require_nonempty = sys.argv[5] == "1"
expected_json = None if sys.argv[6] == "-" else json.loads(sys.argv[6])
if len(sys.argv) not in {7, 8}:
    raise SystemExit(17)
connect_host = url.hostname if len(sys.argv) == 7 else sys.argv[7]
if (
    not connect_host
    or len(connect_host) > 253
    or any(character.isspace() or character in "/@" for character in connect_host)
):
    raise SystemExit(17)
context = ssl.create_default_context(cafile=ca_file)
context.minimum_version = ssl.TLSVersion.TLSv1_2

class DirectHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        if self._tunnel_host is not None:
            raise SystemExit(18)
        plain = socket.create_connection(
            (connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(plain, server_hostname=self.host)

connection = DirectHTTPSConnection(
    url.hostname,
    url.port or 443,
    context=context,
    timeout=10,
)
connection.connect()
peer = connection.sock.getpeercert(binary_form=True)
tls_version = connection.sock.version()
if not peer or tls_version not in {"TLSv1.2", "TLSv1.3"}:
    raise SystemExit(11)
request_target = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
connection.request("GET", request_target)
response = connection.getresponse()
if response.status != 200 or response.getheader("Location") is not None:
    raise SystemExit(12)
if content_type is not None and response.headers.get_content_type() != content_type:
    raise SystemExit(13)
raw = response.read(maximum + 1)
if len(raw) > maximum or (require_nonempty and not raw):
    raise SystemExit(14)
if expected_json is not None:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError):
        raise SystemExit(15)
    if body != expected_json:
        raise SystemExit(16)
print(json.dumps(
    {
        "peer_sha256": hashlib.sha256(peer).hexdigest(),
        "tls_version": tls_version,
    },
    sort_keys=True,
    separators=(",", ":"),
))
connection.close()
"""


def parse_tls_probe_result(output: str) -> dict[str, str]:
    """Parse one verified-handshake result without trusting an expected digest."""

    try:
        raw = output.encode("utf-8")
    except UnicodeEncodeError as error:
        raise TlsRuntimeIdentityError("TLS probe output is invalid") from error
    if not raw or len(raw) > MAX_OBSERVATION_BYTES:
        raise TlsRuntimeIdentityError("TLS probe output is invalid")
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TlsRuntimeIdentityError("TLS probe output is invalid") from error
    if not isinstance(value, dict) or set(value) != _OBSERVATION_FIELDS:
        raise TlsRuntimeIdentityError("TLS probe output is invalid")
    peer = value["peer_sha256"]
    version = value["tls_version"]
    if (
        not isinstance(peer, str)
        or _SHA256.fullmatch(peer) is None
        or not isinstance(version, str)
        or version not in _TLS_VERSIONS
    ):
        raise TlsRuntimeIdentityError("live TLS peer identity is invalid")
    return {"peer_sha256": peer, "tls_version": version}


def parse_tls_probe_observation(
    output: str,
    *,
    expected_sha256: str,
) -> dict[str, str]:
    if _SHA256.fullmatch(expected_sha256) is None:
        raise TlsRuntimeIdentityError("expected TLS identity is invalid")
    result = parse_tls_probe_result(output)
    if not hmac.compare_digest(result["peer_sha256"], expected_sha256):
        raise TlsRuntimeIdentityError("live TLS peer identity is invalid")
    return {
        "expected_sha256": expected_sha256,
        **result,
    }


def valid_evidence_observation(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != EVIDENCE_OBSERVATION_FIELDS:
        return False
    expected = value["expected_sha256"]
    peer = value["peer_sha256"]
    version = value["tls_version"]
    return (
        isinstance(expected, str)
        and _SHA256.fullmatch(expected) is not None
        and isinstance(peer, str)
        and _SHA256.fullmatch(peer) is not None
        and hmac.compare_digest(expected, peer)
        and isinstance(version, str)
        and version in _TLS_VERSIONS
    )


def expected_internal_fingerprints(
    env_file: Path,
    *,
    now: datetime,
) -> dict[str, str]:
    try:
        report, _ = evaluate_inventory(env_file, now=now)
    except (CertificateInputError, OSError, TypeError, ValueError) as error:
        raise TlsRuntimeIdentityError("internal TLS preflight is invalid") from error
    certificates = report.get("certificates")
    if not isinstance(certificates, list):
        raise TlsRuntimeIdentityError("internal TLS preflight is invalid")
    result: dict[str, str] = {}
    for item in certificates:
        if not isinstance(item, dict) or not {
            "service",
            "fingerprint_sha256",
        }.issubset(item):
            raise TlsRuntimeIdentityError("internal TLS preflight is invalid")
        service = item.get("service")
        fingerprint = item.get("fingerprint_sha256")
        if (
            not isinstance(service, str)
            or not service
            or service in result
            or not isinstance(fingerprint, str)
            or _SHA256.fullmatch(fingerprint) is None
        ):
            raise TlsRuntimeIdentityError("internal TLS preflight is invalid")
        result[service] = fingerprint
    if not result:
        raise TlsRuntimeIdentityError("internal TLS preflight is invalid")
    return result


def probe_arguments(
    url: str,
    *,
    ca_file: str | None,
    max_body_bytes: int,
    content_type: str | None = None,
    require_nonempty: bool = False,
    expected_json: dict[str, Any] | None = None,
    connect_host: str | None = None,
) -> list[str]:
    arguments = [
        url,
        ca_file or "-",
        str(max_body_bytes),
        content_type or "-",
        "1" if require_nonempty else "0",
        "-"
        if expected_json is None
        else json.dumps(expected_json, sort_keys=True, separators=(",", ":")),
    ]
    if connect_host is not None:
        arguments.append(connect_host)
    return arguments


def tls_probe_contract_errors(program: str = TLS_HTTP_PROBE_PROGRAM) -> list[str]:
    required = (
        "http.client.HTTPSConnection",
        "socket.create_connection",
        "server_hostname=self.host",
        "context.minimum_version = ssl.TLSVersion.TLSv1_2",
        "connection.connect()",
        "connection.sock.getpeercert(binary_form=True)",
        "connection.sock.version()",
        'connection.request("GET", request_target)',
        "response.status != 200",
        'response.getheader("Location") is not None',
        '"peer_sha256": hashlib.sha256(peer).hexdigest()',
    )
    errors = [f"TLS probe is missing {marker}" for marker in required if marker not in program]
    for marker in (
        "urllib.request.urlopen",
        "CERT_NONE",
        "check_hostname = False",
        "_create_unverified_context",
    ):
        if marker in program:
            errors.append("TLS probe disables the reviewed verification boundary")
    return errors
