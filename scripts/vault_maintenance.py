"""Integrity-checked Vault integrated-storage snapshot helpers.

The Vault token is read from a local file and passed only in the child process
environment. It is never accepted on the command line or written to metadata.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import urlparse


SNAPSHOT_NAME = "vault.snap"
MANIFEST_NAME = "vault-manifest.json"
MANIFEST_SCHEMA = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


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
    if path.is_symlink():
        raise ValueError("Vault token file is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 4096:
                raise ValueError("Vault token file is invalid")
            if os.name != "nt" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("Vault token file is invalid")
            data = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as error:
        raise ValueError("Vault token file is invalid") from error
    try:
        token = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Vault token file is invalid") from error
    if not token or any(character.isspace() for character in token):
        raise ValueError("Vault token file is invalid")
    return token


def _vault_environment(
    *,
    address: str,
    token_file: Path | str,
    namespace: str | None,
    allow_loopback_http: bool,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["VAULT_ADDR"] = _validated_address(
        address, allow_loopback_http=allow_loopback_http
    )
    environment["VAULT_TOKEN"] = _read_token_file(token_file)
    if namespace:
        environment["VAULT_NAMESPACE"] = namespace.strip()
    else:
        environment.pop("VAULT_NAMESPACE", None)
    return environment


def _inspect_snapshot(path: Path, *, vault_bin: str) -> None:
    subprocess.run(
        [vault_bin, "operator", "raft", "snapshot", "inspect", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )


def _hash_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


def _manifest_payload(path: Path) -> dict[str, object]:
    sha256, size_bytes = _hash_and_size(path)
    if size_bytes <= 0:
        raise ValueError("Vault snapshot is empty")
    return {
        "schema_version": MANIFEST_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact": SNAPSHOT_NAME,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def create_snapshot(
    output_dir: Path | str,
    *,
    address: str,
    token_file: Path | str,
    namespace: str | None = None,
    vault_bin: str = "vault",
    allow_loopback_http: bool = False,
) -> Path:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / MANIFEST_NAME
    manifest_path.unlink(missing_ok=True)
    environment = _vault_environment(
        address=address,
        token_file=token_file,
        namespace=namespace,
        allow_loopback_http=allow_loopback_http,
    )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=directory,
            prefix=f".{SNAPSHOT_NAME}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
        temporary_path.unlink()
        subprocess.run(
            [vault_bin, "operator", "raft", "snapshot", "save", str(temporary_path)],
            check=True,
            env=environment,
        )
        _inspect_snapshot(temporary_path, vault_bin=vault_bin)
        snapshot_path = directory / SNAPSHOT_NAME
        os.replace(temporary_path, snapshot_path)
        temporary_path = None
        payload = _manifest_payload(snapshot_path)
        temporary_manifest = directory / f".{MANIFEST_NAME}.tmp"
        temporary_manifest.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary_manifest, manifest_path)
        return manifest_path
    finally:
        environment.pop("VAULT_TOKEN", None)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def verify_snapshot(input_dir: Path | str, *, vault_bin: str = "vault") -> Path:
    directory = Path(input_dir)
    manifest_path = directory / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Vault snapshot manifest is invalid") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("Vault snapshot manifest is invalid")
    if manifest.get("artifact") != SNAPSHOT_NAME:
        raise ValueError("Vault snapshot artifact name is invalid")
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
    try:
        actual_hash, actual_size = _hash_and_size(snapshot_path)
    except OSError as error:
        raise ValueError("Vault snapshot artifact is missing") from error
    if actual_size != size_bytes or actual_hash != expected_hash:
        raise ValueError("Vault snapshot integrity check failed")
    _inspect_snapshot(snapshot_path, vault_bin=vault_bin)
    return snapshot_path


def restore_snapshot(
    input_dir: Path | str,
    *,
    address: str,
    token_file: Path | str,
    confirm_restore: bool,
    namespace: str | None = None,
    vault_bin: str = "vault",
    allow_loopback_http: bool = False,
) -> None:
    if not confirm_restore:
        raise ValueError("Vault restore requires explicit --confirm-restore")
    snapshot_path = verify_snapshot(input_dir, vault_bin=vault_bin)
    environment = _vault_environment(
        address=address,
        token_file=token_file,
        namespace=namespace,
        allow_loopback_http=allow_loopback_http,
    )
    try:
        subprocess.run(
            [
                vault_bin,
                "operator",
                "raft",
                "snapshot",
                "restore",
                "-force",
                str(snapshot_path),
            ],
            check=True,
            env=environment,
        )
    finally:
        environment.pop("VAULT_TOKEN", None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup")
    backup.add_argument("--output-dir", required=True)
    backup.add_argument("--address", required=True)
    backup.add_argument("--token-file", required=True)
    backup.add_argument("--namespace")
    backup.add_argument("--vault-bin", default="vault")
    backup.add_argument("--allow-loopback-http", action="store_true")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--input-dir", required=True)
    verify.add_argument("--vault-bin", default="vault")

    restore = subparsers.add_parser("restore")
    restore.add_argument("--input-dir", required=True)
    restore.add_argument("--address", required=True)
    restore.add_argument("--token-file", required=True)
    restore.add_argument("--namespace")
    restore.add_argument("--vault-bin", default="vault")
    restore.add_argument("--allow-loopback-http", action="store_true")
    restore.add_argument("--confirm-restore", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "backup":
        print(
            create_snapshot(
                args.output_dir,
                address=args.address,
                token_file=args.token_file,
                namespace=args.namespace,
                vault_bin=args.vault_bin,
                allow_loopback_http=args.allow_loopback_http,
            )
        )
        return 0
    if args.command == "verify":
        print(verify_snapshot(args.input_dir, vault_bin=args.vault_bin))
        return 0
    if args.command == "restore":
        restore_snapshot(
            args.input_dir,
            address=args.address,
            token_file=args.token_file,
            confirm_restore=args.confirm_restore,
            namespace=args.namespace,
            vault_bin=args.vault_bin,
            allow_loopback_http=args.allow_loopback_http,
        )
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
