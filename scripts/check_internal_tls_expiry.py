"""Emit a redacted, machine-readable expiry result for internal TLS leaves."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

try:
    from scripts.external_json import StableFileError, read_stable_bytes
    from scripts.private_secret_file import read_private_secret_bytes
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import StableFileError, read_stable_bytes
    from private_secret_file import read_private_secret_bytes


CERTIFICATE_ENV = {
    "api": "PLATFORM_INTERNAL_API_CERT_FILE",
    "web": "PLATFORM_INTERNAL_WEB_CERT_FILE",
    "api-green": "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
    "web-green": "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
    "keycloak": "PLATFORM_INTERNAL_KEYCLOAK_CERT_FILE",
    "worker-mail": "PLATFORM_INTERNAL_WORKER_MAIL_CERT_FILE",
    "worker-sub2": "PLATFORM_INTERNAL_WORKER_SUB2_CERT_FILE",
    "prometheus": "PLATFORM_INTERNAL_PROMETHEUS_CERT_FILE",
    "alertmanager": "PLATFORM_INTERNAL_ALERTMANAGER_CERT_FILE",
}
KEY_ENV = {
    "api": "PLATFORM_INTERNAL_API_KEY_FILE",
    "web": "PLATFORM_INTERNAL_WEB_KEY_FILE",
    "api-green": "PLATFORM_ROLLING_GREEN_API_KEY_FILE",
    "web-green": "PLATFORM_ROLLING_GREEN_WEB_KEY_FILE",
    "keycloak": "PLATFORM_INTERNAL_KEYCLOAK_KEY_FILE",
    "worker-mail": "PLATFORM_INTERNAL_WORKER_MAIL_KEY_FILE",
    "worker-sub2": "PLATFORM_INTERNAL_WORKER_SUB2_KEY_FILE",
    "prometheus": "PLATFORM_INTERNAL_PROMETHEUS_KEY_FILE",
    "alertmanager": "PLATFORM_INTERNAL_ALERTMANAGER_KEY_FILE",
}
CA_ENV = "PLATFORM_INTERNAL_CA_FILE"
THRESHOLDS_DAYS = (30, 14, 7)
PAGE_BELOW_DAYS = 7
EXIT_OK = 0
EXIT_ALERT = 1
EXIT_PAGE = 2
EXIT_INPUT = 3
MAX_CA_BUNDLE_BYTES = 256 * 1024
MAX_LEAF_CERTIFICATE_BYTES = 64 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_ENV_INVENTORY_BYTES = 64 * 1024

_PEM_CERTIFICATE = re.compile(
    br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)
_PEM_PRIVATE_KEY = re.compile(
    br"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    br"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CertificateInputError(ValueError):
    """A fail-closed inventory or certificate input error."""


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def classify_remaining(remaining: timedelta) -> tuple[str, int]:
    if remaining <= timedelta(0):
        return "expired", EXIT_PAGE
    if remaining < timedelta(days=PAGE_BELOW_DAYS):
        return "page", EXIT_PAGE
    if remaining <= timedelta(days=7):
        return "alert_7", EXIT_ALERT
    if remaining <= timedelta(days=14):
        return "alert_14", EXIT_ALERT
    if remaining <= timedelta(days=30):
        return "alert_30", EXIT_ALERT
    return "ok", EXIT_OK


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.is_absolute():
        raise CertificateInputError("inventory: env file is not an absolute regular file")
    try:
        raw = read_stable_bytes(path, max_bytes=MAX_ENV_INVENTORY_BYTES)
    except StableFileError as error:
        message = (
            "inventory: env file is not an absolute regular file"
            if error.reason == "read"
            else "inventory: env file is unreadable UTF-8"
        )
        raise CertificateInputError(message) from error
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise CertificateInputError("inventory: env file is unreadable UTF-8") from error
    values: dict[str, str] = {}
    required = {CA_ENV, *CERTIFICATE_ENV.values(), *KEY_ENV.values()}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise CertificateInputError(f"inventory: malformed line {line_number}")
        name, value = (part.strip() for part in line.split("=", 1))
        if _ENV_NAME.fullmatch(name) is None:
            raise CertificateInputError(f"inventory: malformed name on line {line_number}")
        if name not in required:
            continue
        if name in values:
            raise CertificateInputError(f"inventory: duplicate setting {name}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[name] = value
    return values


def _certificate_path(service: str, variable: str, env: dict[str, str]) -> Path:
    return _inventory_path(service, "certificate", variable, env)


def _inventory_path(
    service: str, kind: str, variable: str, env: dict[str, str]
) -> Path:
    value = env.get(variable, "").strip()
    if not value:
        raise CertificateInputError(f"{service}: missing {variable}")
    if "change_me" in value.lower():
        raise CertificateInputError(f"{service}: {variable} is still a placeholder")
    path = Path(value)
    if not path.is_absolute():
        raise CertificateInputError(f"{service}: {variable} must be absolute")
    if path.is_symlink() or not path.is_file():
        raise CertificateInputError(
            f"{service}: {kind} must be a regular non-symlink file"
        )
    return path


def _load_certificate(service: str, path: Path) -> x509.Certificate:
    try:
        content = read_stable_bytes(path, max_bytes=MAX_LEAF_CERTIFICATE_BYTES)
    except OSError as error:
        raise CertificateInputError(f"{service}: certificate is unreadable") from error
    matches = _PEM_CERTIFICATE.findall(content)
    if len(matches) != 1 or content.strip() != matches[0].strip():
        raise CertificateInputError(f"{service}: certificate must contain one PEM certificate")
    try:
        return x509.load_pem_x509_certificate(matches[0])
    except ValueError as error:
        raise CertificateInputError(f"{service}: certificate PEM is invalid") from error


def _load_ca_bundle(path: Path, *, now: datetime) -> tuple[x509.Certificate, ...]:
    try:
        content = read_stable_bytes(path, max_bytes=MAX_CA_BUNDLE_BYTES)
    except OSError as error:
        raise CertificateInputError("ca: certificate bundle is unreadable") from error
    matches = _PEM_CERTIFICATE.findall(content)
    if not matches or _PEM_CERTIFICATE.sub(b"", content).strip():
        raise CertificateInputError("ca: bundle must contain only PEM certificates")
    certificates: list[x509.Certificate] = []
    fingerprints: set[bytes] = set()
    for pem in matches:
        try:
            certificate = x509.load_pem_x509_certificate(pem)
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except (ValueError, x509.ExtensionNotFound) as error:
            raise CertificateInputError("ca: bundle contains an invalid CA certificate") from error
        if not constraints.ca:
            raise CertificateInputError("ca: bundle contains a non-CA certificate")
        if now < certificate.not_valid_before_utc or now >= certificate.not_valid_after_utc:
            raise CertificateInputError("ca: bundle contains a CA outside its validity window")
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint in fingerprints:
            raise CertificateInputError("ca: bundle contains a duplicate certificate")
        fingerprints.add(fingerprint)
        certificates.append(certificate)
    return tuple(certificates)


def _load_private_key(service: str, path: Path) -> object:
    try:
        content = read_private_secret_bytes(path, max_bytes=MAX_PRIVATE_KEY_BYTES)
    except OSError as error:
        raise CertificateInputError(f"{service}: private key is unreadable") from error
    matches = _PEM_PRIVATE_KEY.findall(content)
    if len(matches) != 1 or content.strip() != matches[0].strip():
        raise CertificateInputError(f"{service}: private key must contain one PEM key")
    try:
        return serialization.load_pem_private_key(matches[0], password=None)
    except (TypeError, ValueError) as error:
        raise CertificateInputError(f"{service}: private key PEM is invalid") from error


def _public_key_bytes(key: object) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _validate_leaf(
    service: str,
    certificate: x509.Certificate,
    private_key: object,
    ca_certificates: tuple[x509.Certificate, ...],
) -> None:
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as error:
        raise CertificateInputError(f"{service}: certificate extensions are incomplete") from error
    if len(san) != 1 or san.get_values_for_type(x509.DNSName) != [service]:
        raise CertificateInputError(f"{service}: certificate SAN is invalid")
    if constraints.ca:
        raise CertificateInputError(f"{service}: leaf certificate cannot be a CA")
    if _public_key_bytes(certificate.public_key()) != _public_key_bytes(
        private_key.public_key()
    ):
        raise CertificateInputError(f"{service}: certificate and private key do not match")
    issuers = 0
    for ca_certificate in ca_certificates:
        try:
            certificate.verify_directly_issued_by(ca_certificate)
        except (InvalidSignature, ValueError):
            continue
        issuers += 1
    if issuers != 1:
        raise CertificateInputError(f"{service}: certificate is not issued by exactly one trusted CA")


def evaluate_inventory(env_file: Path, *, now: datetime) -> tuple[dict[str, object], int]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    checked_at = now.astimezone(timezone.utc)
    env = _load_env_file(env_file)
    ca_path = _inventory_path("ca", "certificate bundle", CA_ENV, env)
    certificate_paths: dict[str, Path] = {}
    key_paths: dict[str, Path] = {}
    normalized_paths: set[str] = set()
    normalized_paths.add(os.path.normcase(os.path.abspath(ca_path)))
    for service, variable in CERTIFICATE_ENV.items():
        certificate_path = _certificate_path(service, variable, env)
        key_path = _inventory_path(service, "private key", KEY_ENV[service], env)
        for path in (certificate_path, key_path):
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized in normalized_paths:
                raise CertificateInputError(
                    f"{service}: every CA, certificate and key path must be distinct"
                )
            normalized_paths.add(normalized)
        certificate_paths[service] = certificate_path
        key_paths[service] = key_path

    ca_certificates = _load_ca_bundle(ca_path, now=checked_at)

    results: list[dict[str, object]] = []
    exit_code = EXIT_OK
    for service, variable in CERTIFICATE_ENV.items():
        certificate = _load_certificate(service, certificate_paths[service])
        private_key = _load_private_key(service, key_paths[service])
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        if checked_at < not_before:
            raise CertificateInputError(f"{service}: certificate is not yet valid")
        _validate_leaf(service, certificate, private_key, ca_certificates)
        remaining = not_after - checked_at
        state, certificate_exit = classify_remaining(remaining)
        exit_code = max(exit_code, certificate_exit)
        results.append(
            {
                "service": service,
                "source_env": variable,
                "state": state,
                "not_before": _utc_text(not_before),
                "not_after": _utc_text(not_after),
                "remaining_seconds": int(remaining.total_seconds()),
                "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            }
        )

    overall = "page" if exit_code == EXIT_PAGE else "alert" if exit_code else "ok"
    return (
        {
            "schema": 1,
            "checked_at": _utc_text(checked_at),
            "thresholds_days": list(THRESHOLDS_DAYS),
            "page_below_days": PAGE_BELOW_DAYS,
            "overall": overall,
            "certificates": results,
        },
        exit_code,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the nine production internal TLS leaf expiries"
    )
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help="absolute protected production environment file",
    )
    return parser


def main(
    argv: Sequence[str] | None = None, *, now: datetime | None = None
) -> int:
    args = build_parser().parse_args(argv)
    checked_at = now or datetime.now(timezone.utc)
    try:
        payload, exit_code = evaluate_inventory(args.env_file, now=checked_at)
    except CertificateInputError as error:
        print(
            json.dumps(
                {
                    "schema": 1,
                    "error": "certificate_input_invalid",
                    "detail": str(error),
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return EXIT_INPUT
    print(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
