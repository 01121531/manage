"""Integrity-checked Vault integrated-storage snapshot helpers.

The Vault token is read from a local file and used only in an in-process HTTPS
request header. It is never passed to a child process, accepted on the command
line, or written to metadata.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from typing import BinaryIO, Iterator, Sequence
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from scripts.backup_crypto import key_id, load_key_file
from scripts.backup_output_policy import (
    CLEANUP_UNCONFIRMED_NOTE,
    cleanup_created_directory_after_failure,
    cleanup_unconfirmed,
    create_write_once_directory,
    discard_claimed_temporary_file,
    publish_bundle_write_once_file,
    require_exact_regular_files,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    load_unique_json,
    open_stable_binary,
    parse_unique_json_bytes,
    read_stable_bytes,
)
from scripts.postgres_maintenance import (
    BACKUP_MANIFEST_HMAC_FIELD,
    BACKUP_MANIFEST_NAME,
    BACKUP_RELEASE_MANIFEST_SCHEMA,
    RELEASE_BINDING_FIELDS,
)
from scripts.private_secret_file import (
    PrivateSecretFileError,
    read_private_secret_bytes,
)


SNAPSHOT_NAME = "vault.snap"
MANIFEST_NAME = "vault-manifest.json"
MANIFEST_SCHEMA = 2
MANIFEST_HMAC_FIELD = "manifest_hmac_sha256"
MANIFEST_HKDF_INFO = b"email-platform/vault-snapshot-manifest/v2/hmac-sha256"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECOVERY_SET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_MANIFEST_BYTES = 64 * 1024
BACKUP_BUNDLE_LEAVES = frozenset({SNAPSHOT_NAME, MANIFEST_NAME})
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_RAFT_SNAPSHOT_PATH = "/v1/sys/storage/raft/snapshot"
_SNAPSHOT_TIMEOUT_SECONDS = 900
_OFFLINE_ENVIRONMENT_VARIABLES = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
)
_VAULT_MANIFEST_FIELDS = {
    "schema_version",
    "created_at",
    "artifact",
    "size_bytes",
    "sha256",
    "recovery_set",
    "postgres_manifest_sha256",
    MANIFEST_HMAC_FIELD,
}
_POSTGRES_MANIFEST_FIELDS = {
    "schema_version",
    "created_at",
    "databases",
    *RELEASE_BINDING_FIELDS,
    BACKUP_MANIFEST_HMAC_FIELD,
}


def _validated_address(value: str, *, allow_loopback_http: bool = False) -> str:
    address = value.strip().rstrip("/")
    parsed = urlparse(address)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Vault address must be an origin without credentials or query data")
    if parsed.path not in ("", "/"):
        raise ValueError("Vault address must not contain a path")
    if parsed.scheme == "https":
        return address
    if (
        allow_loopback_http
        and parsed.scheme == "http"
        and parsed.hostname.lower() in _LOOPBACK_HOSTS
    ):
        return address
    raise ValueError("Vault address must use HTTPS")


def _read_token_file(path_value: Path | str) -> str:
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError("Vault token file must be an absolute path")
    try:
        data = read_private_secret_bytes(path, max_bytes=4096)
    except PrivateSecretFileError as error:
        raise ValueError("Vault token file is invalid") from error
    try:
        token = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Vault token file is invalid") from error
    if not token or any(character.isspace() for character in token):
        raise ValueError("Vault token file is invalid")
    return token


def _offline_environment() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in _OFFLINE_ENVIRONMENT_VARIABLES
        if name in os.environ
    }


def _validated_ca_file(path_value: Path | str | None, *, https: bool) -> Path | None:
    if not https:
        return None
    if path_value is None:
        raise ValueError("Vault HTTPS requires an explicit CA file")
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Vault CA file is invalid")
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError("Vault CA file is invalid") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError("Vault CA file is invalid")
    return path


def _snapshot_request_inputs(
    *,
    address: str,
    token_file: Path | str,
    ca_file: Path | str | None,
    namespace: str | None,
    allow_loopback_http: bool,
) -> tuple[str, str, Path | None, str | None]:
    if "VAULT_SKIP_VERIFY" in os.environ:
        raise ValueError("inherited Vault TLS verification override is forbidden")
    reviewed_address = _validated_address(
        address, allow_loopback_http=allow_loopback_http
    )
    reviewed_ca_file = _validated_ca_file(
        ca_file,
        https=urlparse(reviewed_address).scheme == "https",
    )
    reviewed_namespace = namespace.strip() if namespace else None
    if reviewed_namespace and any(
        character in reviewed_namespace for character in ("\r", "\n")
    ):
        raise ValueError("Vault namespace is invalid")
    return (
        reviewed_address,
        _read_token_file(token_file),
        reviewed_ca_file,
        reviewed_namespace,
    )


def _open_connection(
    address: str,
    *,
    ca_file: Path | None,
) -> http.client.HTTPConnection:
    parsed = urlparse(address)
    port = parsed.port
    if parsed.scheme == "http":
        return http.client.HTTPConnection(
            parsed.hostname,
            port,
            timeout=_SNAPSHOT_TIMEOUT_SECONDS,
        )
    if ca_file is None:
        raise ValueError("Vault HTTPS requires an explicit CA file")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_file))
    except (OSError, ssl.SSLError) as error:
        raise ValueError("Vault CA file is invalid") from error
    return http.client.HTTPSConnection(
        parsed.hostname,
        port,
        timeout=_SNAPSHOT_TIMEOUT_SECONDS,
        context=context,
    )


def _request_headers(token: str, namespace: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/octet-stream",
        "X-Vault-Token": token,
    }
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    return headers


def _download_snapshot(
    output_path: Path,
    *,
    address: str,
    token: str,
    ca_file: Path | None,
    namespace: str | None,
) -> None:
    connection = _open_connection(address, ca_file=ca_file)
    try:
        connection.request(
            "GET",
            _RAFT_SNAPSHOT_PATH,
            headers=_request_headers(token, namespace),
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Vault snapshot request failed")
        with output_path.open("xb") as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
    except ValueError:
        raise
    except (OSError, http.client.HTTPException) as error:
        raise ValueError("Vault snapshot request failed") from error
    finally:
        connection.close()


def _upload_snapshot(
    snapshot: BinaryIO,
    *,
    size_bytes: int,
    address: str,
    token: str,
    ca_file: Path | None,
    namespace: str | None,
) -> None:
    connection = _open_connection(address, ca_file=ca_file)
    headers = _request_headers(token, namespace)
    headers["Content-Type"] = "application/octet-stream"
    headers["Content-Length"] = str(size_bytes)
    try:
        connection.request(
            "POST",
            _RAFT_SNAPSHOT_PATH,
            body=snapshot,
            headers=headers,
        )
        response = connection.getresponse()
        if response.status not in (200, 204):
            raise ValueError("Vault snapshot restore failed")
    except ValueError:
        raise
    except (OSError, http.client.HTTPException) as error:
        raise ValueError("Vault snapshot restore failed") from error
    finally:
        connection.close()


def _inspect_snapshot(path: Path, *, vault_bin: str) -> None:
    subprocess.run(
        [vault_bin, "operator", "raft", "snapshot", "inspect", str(path)],
        check=True,
        capture_output=True,
        text=True,
        env=_offline_environment(),
    )


def _hash_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


def _read_json_manifest(
    path: Path,
    *,
    label: str,
    expected_identity: StableFileIdentity | None = None,
) -> dict[str, object]:
    try:
        value = load_unique_json(
            path,
            max_bytes=_MAX_MANIFEST_BYTES,
            expected_identity=expected_identity,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} is invalid") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} is invalid")
    return value


def _require_recovery_set(value: str) -> str:
    if not isinstance(value, str) or not _RECOVERY_SET.fullmatch(value):
        raise ValueError("recovery set is invalid")
    return value


def _load_manifest_key_file(path_value: Path | str) -> bytes:
    path = Path(path_value)
    return load_key_file(path, require_read_only=True)


def _postgres_manifest_binding(path_value: Path | str) -> tuple[str, set[str]]:
    path = Path(path_value)
    if path.name != BACKUP_MANIFEST_NAME or path.is_symlink():
        raise ValueError("PostgreSQL release manifest is invalid")
    try:
        manifest_bytes = read_stable_bytes(
            path,
            max_bytes=_MAX_MANIFEST_BYTES,
        )
        manifest = parse_unique_json_bytes(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("PostgreSQL release manifest is invalid") from error
    if not isinstance(manifest, dict):
        raise ValueError("PostgreSQL release manifest is invalid")
    if (
        manifest.get("schema_version") != BACKUP_RELEASE_MANIFEST_SCHEMA
        or set(manifest) != _POSTGRES_MANIFEST_FIELDS
    ):
        raise ValueError("PostgreSQL release manifest must be verified schema v5")
    databases = manifest.get("databases")
    if not isinstance(databases, dict) or set(databases) != {"platform", "keycloak"}:
        raise ValueError("PostgreSQL release manifest must be verified schema v5")
    if any(
        not isinstance(entry, dict) or not isinstance(entry.get("key_id"), str)
        for entry in databases.values()
    ):
        raise ValueError("PostgreSQL release manifest must be verified schema v5")
    database_key_ids = {entry["key_id"] for entry in databases.values()}
    if len(database_key_ids) != 1:
        raise ValueError("PostgreSQL release manifest must use one reviewed backup key")
    return hashlib.sha256(manifest_bytes).hexdigest(), database_key_ids


def _snapshot_binding_inputs(
    *,
    recovery_set: str,
    postgres_manifest: Path | str,
    manifest_key_file: Path | str,
) -> tuple[str, str, bytes]:
    reviewed_recovery_set = _require_recovery_set(recovery_set)
    postgres_manifest_sha256, postgres_key_ids = _postgres_manifest_binding(
        postgres_manifest
    )
    manifest_key = _load_manifest_key_file(manifest_key_file)
    if key_id(manifest_key) in postgres_key_ids:
        raise ValueError("Vault manifest key must be independent from PostgreSQL backup key")
    return reviewed_recovery_set, postgres_manifest_sha256, manifest_key


def _canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    authenticated = {
        field: value
        for field, value in manifest.items()
        if field != MANIFEST_HMAC_FIELD
    }
    return json.dumps(
        authenticated,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _manifest_hmac_sha256(manifest: dict[str, object], key: bytes) -> str:
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=MANIFEST_HKDF_INFO,
    ).derive(key)
    return hmac.new(
        mac_key,
        _canonical_manifest_bytes(manifest),
        hashlib.sha256,
    ).hexdigest()


def _manifest_payload(
    path: Path,
    *,
    recovery_set: str,
    postgres_manifest_sha256: str,
    manifest_key: bytes,
) -> dict[str, object]:
    sha256, size_bytes = _hash_and_size(path)
    if size_bytes <= 0:
        raise ValueError("Vault snapshot is empty")
    payload: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact": SNAPSHOT_NAME,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "recovery_set": recovery_set,
        "postgres_manifest_sha256": postgres_manifest_sha256,
    }
    payload[MANIFEST_HMAC_FIELD] = _manifest_hmac_sha256(payload, manifest_key)
    return payload


def create_snapshot(
    output_dir: Path | str,
    *,
    address: str,
    token_file: Path | str,
    manifest_key_file: Path | str,
    recovery_set: str,
    postgres_manifest: Path | str,
    namespace: str | None = None,
    vault_bin: str = "vault",
    allow_loopback_http: bool = False,
    ca_file: Path | str | None = None,
) -> Path:
    directory_claim = create_write_once_directory(output_dir)
    directory = directory_claim.path
    manifest_path = directory / MANIFEST_NAME
    temporary_path: Path | None = None
    try:
        reviewed_recovery_set, postgres_manifest_sha256, manifest_key = (
            _snapshot_binding_inputs(
                recovery_set=recovery_set,
                postgres_manifest=postgres_manifest,
                manifest_key_file=manifest_key_file,
            )
        )
        reviewed_address, token, reviewed_ca_file, reviewed_namespace = (
            _snapshot_request_inputs(
                address=address,
                token_file=token_file,
                ca_file=ca_file,
                namespace=namespace,
                allow_loopback_http=allow_loopback_http,
            )
        )
        with tempfile.NamedTemporaryFile(
            dir=directory,
            prefix=f".{SNAPSHOT_NAME}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
        temporary_path.unlink()
        _download_snapshot(
            temporary_path,
            address=reviewed_address,
            token=token,
            ca_file=reviewed_ca_file,
            namespace=reviewed_namespace,
        )
        _inspect_snapshot(temporary_path, vault_bin=vault_bin)
        snapshot_path = directory / SNAPSHOT_NAME
        publishing_path = temporary_path
        temporary_path = None
        publish_bundle_write_once_file(publishing_path, snapshot_path)
        payload = _manifest_payload(
            snapshot_path,
            recovery_set=reviewed_recovery_set,
            postgres_manifest_sha256=postgres_manifest_sha256,
            manifest_key=manifest_key,
        )
        temporary_manifest = write_fsynced_temporary_bytes(
            manifest_path,
            (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        publish_bundle_write_once_file(temporary_manifest, manifest_path)
        return manifest_path
    except BaseException as error:
        discard_claimed_temporary_file(temporary_path)
        cleanup_created_directory_after_failure(directory_claim, error)
        raise


@contextmanager
def _verified_snapshot(
    input_dir: Path | str,
    *,
    manifest_key_file: Path | str,
    recovery_set: str,
    postgres_manifest: Path | str,
    vault_bin: str = "vault",
) -> Iterator[tuple[Path, BinaryIO, int, dict[str, StableFileIdentity]]]:
    directory = Path(input_dir)
    identities = require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)
    reviewed_recovery_set, postgres_manifest_sha256, manifest_key = (
        _snapshot_binding_inputs(
            recovery_set=recovery_set,
            postgres_manifest=postgres_manifest,
            manifest_key_file=manifest_key_file,
        )
    )
    manifest_path = directory / MANIFEST_NAME
    manifest = _read_json_manifest(
        manifest_path,
        label="Vault snapshot manifest",
        expected_identity=identities[MANIFEST_NAME],
    )
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("Vault snapshot manifest schema v2 is required for restore")
    if set(manifest) != _VAULT_MANIFEST_FIELDS:
        raise ValueError("Vault snapshot manifest is invalid")
    actual_mac = manifest.get(MANIFEST_HMAC_FIELD)
    if not isinstance(actual_mac, str) or not _SHA256.fullmatch(actual_mac):
        raise ValueError("Vault snapshot manifest authentication is invalid")
    expected_mac = _manifest_hmac_sha256(manifest, manifest_key)
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("Vault snapshot manifest authentication failed")
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str):
        raise ValueError("Vault snapshot creation time is invalid")
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise ValueError("Vault snapshot creation time is invalid") from error
    if parsed_created_at.tzinfo is None:
        raise ValueError("Vault snapshot creation time is invalid")
    if manifest.get("artifact") != SNAPSHOT_NAME:
        raise ValueError("Vault snapshot artifact name is invalid")
    if manifest.get("recovery_set") != reviewed_recovery_set:
        raise ValueError("Vault snapshot recovery set binding mismatch")
    if manifest.get("postgres_manifest_sha256") != postgres_manifest_sha256:
        raise ValueError("Vault snapshot PostgreSQL manifest binding mismatch")
    size_bytes = manifest.get("size_bytes")
    expected_hash = manifest.get("sha256")
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes <= 0
        or not isinstance(expected_hash, str)
        or not _SHA256.fullmatch(expected_hash)
    ):
        raise ValueError("Vault snapshot manifest is invalid")
    snapshot_path = directory / SNAPSHOT_NAME
    staged_path: Path | None = None
    try:
        digest = hashlib.sha256()
        actual_size = 0
        with (
            open_stable_binary(
                snapshot_path,
                expected_identity=identities[SNAPSHOT_NAME],
            ) as (source, _),
            tempfile.NamedTemporaryFile(
                prefix="email-platform-vault-verify-",
                suffix=".snap",
                delete=False,
            ) as destination,
        ):
            staged_path = Path(destination.name)
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                actual_size += len(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if actual_size != size_bytes or not hmac.compare_digest(
            digest.hexdigest(), expected_hash
        ):
            raise ValueError("Vault snapshot integrity check failed")
        if require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities:
            raise ValueError("Vault snapshot bundle changed during verification")
        with open_stable_binary(staged_path) as (staged, staged_metadata):
            _inspect_snapshot(staged_path, vault_bin=vault_bin)
            if require_exact_regular_files(
                directory, BACKUP_BUNDLE_LEAVES
            ) != identities:
                raise ValueError("Vault snapshot bundle changed during inspection")
            try:
                yield snapshot_path, staged, staged_metadata.st_size, identities
            except BaseException:
                raise
            else:
                if require_exact_regular_files(
                    directory, BACKUP_BUNDLE_LEAVES
                ) != identities:
                    raise ValueError("Vault snapshot bundle changed during use")
    except StableFileError as error:
        raise ValueError("Vault snapshot artifact cannot be opened safely") from error
    finally:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)


def verify_snapshot(
    input_dir: Path | str,
    *,
    manifest_key_file: Path | str,
    recovery_set: str,
    postgres_manifest: Path | str,
    vault_bin: str = "vault",
) -> Path:
    with _verified_snapshot(
        input_dir,
        manifest_key_file=manifest_key_file,
        recovery_set=recovery_set,
        postgres_manifest=postgres_manifest,
        vault_bin=vault_bin,
    ) as (snapshot_path, _, _, _):
        return snapshot_path


def restore_snapshot(
    input_dir: Path | str,
    *,
    address: str,
    token_file: Path | str,
    manifest_key_file: Path | str,
    recovery_set: str,
    postgres_manifest: Path | str,
    confirm_restore: bool,
    namespace: str | None = None,
    vault_bin: str = "vault",
    allow_loopback_http: bool = False,
    ca_file: Path | str | None = None,
) -> None:
    if not confirm_restore:
        raise ValueError("Vault restore requires explicit --confirm-restore")
    with _verified_snapshot(
        input_dir,
        manifest_key_file=manifest_key_file,
        recovery_set=recovery_set,
        postgres_manifest=postgres_manifest,
        vault_bin=vault_bin,
    ) as (_, snapshot_stream, size_bytes, identities):
        reviewed_address, token, reviewed_ca_file, reviewed_namespace = (
            _snapshot_request_inputs(
                address=address,
                token_file=token_file,
                ca_file=ca_file,
                namespace=namespace,
                allow_loopback_http=allow_loopback_http,
            )
        )
        if require_exact_regular_files(
            Path(input_dir), BACKUP_BUNDLE_LEAVES
        ) != identities:
            raise ValueError("Vault snapshot bundle changed before restore")
        snapshot_stream.seek(0)
        _upload_snapshot(
            snapshot_stream,
            size_bytes=size_bytes,
            address=reviewed_address,
            token=token,
            ca_file=reviewed_ca_file,
            namespace=reviewed_namespace,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup")
    backup.add_argument("--output-dir", required=True)
    backup.add_argument("--address", required=True)
    backup.add_argument("--token-file", required=True)
    backup.add_argument("--manifest-key-file", required=True)
    backup.add_argument("--recovery-set", required=True)
    backup.add_argument("--postgres-manifest", required=True)
    backup.add_argument("--namespace")
    backup.add_argument("--vault-bin", default="vault")
    backup.add_argument("--allow-loopback-http", action="store_true")
    backup.add_argument("--ca-file", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--input-dir", required=True)
    verify.add_argument("--manifest-key-file", required=True)
    verify.add_argument("--recovery-set", required=True)
    verify.add_argument("--postgres-manifest", required=True)
    verify.add_argument("--vault-bin", default="vault")

    restore = subparsers.add_parser("restore")
    restore.add_argument("--input-dir", required=True)
    restore.add_argument("--address", required=True)
    restore.add_argument("--token-file", required=True)
    restore.add_argument("--manifest-key-file", required=True)
    restore.add_argument("--recovery-set", required=True)
    restore.add_argument("--postgres-manifest", required=True)
    restore.add_argument("--namespace")
    restore.add_argument("--vault-bin", default="vault")
    restore.add_argument("--allow-loopback-http", action="store_true")
    restore.add_argument("--ca-file", required=True)
    restore.add_argument("--confirm-restore", action="store_true")
    return parser


def _run_cli_command(args: argparse.Namespace) -> int:
    if args.command == "backup":
        print(
            create_snapshot(
                args.output_dir,
                address=args.address,
                token_file=args.token_file,
                manifest_key_file=args.manifest_key_file,
                recovery_set=args.recovery_set,
                postgres_manifest=args.postgres_manifest,
                namespace=args.namespace,
                vault_bin=args.vault_bin,
                allow_loopback_http=args.allow_loopback_http,
                ca_file=args.ca_file,
            )
        )
        return 0
    if args.command == "verify":
        print(
            verify_snapshot(
                args.input_dir,
                manifest_key_file=args.manifest_key_file,
                recovery_set=args.recovery_set,
                postgres_manifest=args.postgres_manifest,
                vault_bin=args.vault_bin,
            )
        )
        return 0
    if args.command == "restore":
        restore_snapshot(
            args.input_dir,
            address=args.address,
            token_file=args.token_file,
            manifest_key_file=args.manifest_key_file,
            recovery_set=args.recovery_set,
            postgres_manifest=args.postgres_manifest,
            confirm_restore=args.confirm_restore,
            namespace=args.namespace,
            vault_bin=args.vault_bin,
            allow_loopback_http=args.allow_loopback_http,
            ca_file=args.ca_file,
        )
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run_cli_command(args)
    except Exception as error:
        suffix = (
            f"; {CLEANUP_UNCONFIRMED_NOTE}" if cleanup_unconfirmed(error) else ""
        )
        print(
            f"vault-maintenance-error: {args.command} failed{suffix}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
