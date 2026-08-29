"""Validate public Edge TLS material before a production deployment mutates state."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

try:
    from scripts.external_json import read_stable_bytes
    from scripts.private_secret_file import read_private_secret_bytes
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import read_stable_bytes
    from private_secret_file import read_private_secret_bytes


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_ENV = "PLATFORM_TLS_CERT_FILE"
PRIVATE_KEY_ENV = "PLATFORM_TLS_KEY_FILE"
MAX_CERTIFICATE_CHAIN_BYTES = 256 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_ENV_INVENTORY_BYTES = 64 * 1024
_DOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class EdgeTlsError(RuntimeError):
    """Public Edge TLS input failed a pre-deployment invariant."""


def _read_inventory(path: Path) -> dict[str, str]:
    if not path.is_absolute():
        raise EdgeTlsError("edge TLS inventory is invalid")
    values: dict[str, str] = {}
    try:
        raw = read_stable_bytes(path, max_bytes=MAX_ENV_INVENTORY_BYTES)
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise EdgeTlsError("edge TLS inventory is invalid") from error
    required = {CERTIFICATE_ENV, PRIVATE_KEY_ENV}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name not in required:
            continue
        if name in values or not value.strip():
            raise EdgeTlsError("edge TLS inventory is invalid")
        values[name] = value.strip()
    if set(values) != required:
        raise EdgeTlsError("edge TLS inventory is invalid")
    return values


def _external_file(
    value: str,
    *,
    repository_root: Path,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise EdgeTlsError("edge TLS file input is invalid")
    try:
        resolved = path.resolve(strict=True)
        repository = repository_root.resolve(strict=True)
    except OSError as error:
        raise EdgeTlsError("edge TLS file input is invalid") from error
    if resolved.is_relative_to(repository):
        raise EdgeTlsError("edge TLS file input is invalid")
    return resolved


def _public_key_bytes(key: object) -> bytes:
    try:
        return key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise EdgeTlsError("edge TLS key input is invalid") from error


def _validate_material(
    certificate_path: Path,
    private_key_path: Path,
    domain: str,
    now: datetime,
) -> str:
    try:
        certificate_bytes = read_stable_bytes(
            certificate_path,
            max_bytes=MAX_CERTIFICATE_CHAIN_BYTES,
        )
        private_key_bytes = read_private_secret_bytes(
            private_key_path,
            max_bytes=MAX_PRIVATE_KEY_BYTES,
        )
        certificates = x509.load_pem_x509_certificates(certificate_bytes)
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )
    except (OSError, TypeError, ValueError) as error:
        raise EdgeTlsError("edge TLS material is invalid") from error
    if not certificates:
        raise EdgeTlsError("edge TLS certificate chain is invalid")
    leaf = certificates[0]
    try:
        basic_constraints = leaf.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound as error:
        raise EdgeTlsError("edge TLS leaf extensions are invalid") from error
    required_names = {domain, f"identity.{domain}"}
    if basic_constraints.ca or not required_names.issubset(
        {name.lower() for name in names}
    ):
        raise EdgeTlsError("edge TLS leaf identity is invalid")
    if not (leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc):
        raise EdgeTlsError("edge TLS leaf validity is invalid")
    if _public_key_bytes(leaf.public_key()) != _public_key_bytes(
        private_key.public_key()
    ):
        raise EdgeTlsError("edge TLS private key does not match")
    return leaf.fingerprint(hashes.SHA256()).hex()


def validate_edge_tls(
    env_file: Path,
    domain: str,
    *,
    now: datetime | None = None,
    repository_root: Path = ROOT,
) -> str:
    """Validate platform/identity leaf validity and private-key binding without output."""

    if _DOMAIN.fullmatch(domain) is None:
        raise EdgeTlsError("edge TLS domain is invalid")
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        raise EdgeTlsError("edge TLS validation time is invalid")
    checked_at = checked_at.astimezone(timezone.utc)
    inventory = _read_inventory(env_file)
    certificate_path = _external_file(
        inventory[CERTIFICATE_ENV],
        repository_root=repository_root,
    )
    private_key_path = _external_file(
        inventory[PRIVATE_KEY_ENV],
        repository_root=repository_root,
    )
    if certificate_path == private_key_path:
        raise EdgeTlsError("edge TLS certificate and key must be distinct")
    return _validate_material(certificate_path, private_key_path, domain, checked_at)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--domain", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    now: datetime | None = None,
) -> int:
    args = _parser().parse_args(argv)
    try:
        validate_edge_tls(args.env_file, args.domain, now=now)
    except EdgeTlsError:
        print("edge-tls-input-invalid", file=sys.stderr)
        return 1
    print("edge-tls-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
