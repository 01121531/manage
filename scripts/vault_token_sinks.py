"""Validate production Vault token sink metadata without reading token values."""

from __future__ import annotations

import os
from pathlib import Path
import stat

import yaml

try:
    from scripts.external_json import read_stable_bytes
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import read_stable_bytes
    from external_yaml import load_unique_yaml


ROOT = Path(__file__).resolve().parents[1]
TOKEN_DIRECTORY_VARIABLES = (
    "PLATFORM_VAULT_API_TOKEN_DIR",
    "PLATFORM_VAULT_MAIL_TOKEN_DIR",
    "PLATFORM_VAULT_SUB2_TOKEN_DIR",
)
SERVICE_TOKEN_DIRECTORIES = {
    "api": TOKEN_DIRECTORY_VARIABLES[0],
    "worker-mail": TOKEN_DIRECTORY_VARIABLES[1],
    "worker-sub2": TOKEN_DIRECTORY_VARIABLES[2],
}
TOKEN_LEAF = "token"
CONTAINER_TOKEN_FILE = "/run/secrets/email-platform-vault/token"
CONTAINER_TOKEN_DIRECTORY = "/run/secrets/email-platform-vault"
MAX_TOKEN_BYTES = 4096
MAX_ENV_INVENTORY_BYTES = 64 * 1024
CONTAINER_UID = 10001
CONTAINER_GID = 10001
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class VaultTokenSinkError(RuntimeError):
    """A production token sink failed a non-secret metadata invariant."""


class _InvalidSink(RuntimeError):
    pass


def _metadata(path: Path) -> os.stat_result:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    ):
        raise _InvalidSink
    return metadata


def _reject_link_or_reparse_ancestors(path: Path) -> None:
    current = path
    while True:
        _metadata(current)
        if current.parent == current:
            return
        current = current.parent


def _read_inventory(env_file: Path) -> dict[str, str]:
    if not env_file.is_absolute():
        raise _InvalidSink
    raw = read_stable_bytes(env_file, max_bytes=MAX_ENV_INVENTORY_BYTES)
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name not in TOKEN_DIRECTORY_VARIABLES:
            continue
        cleaned = value.strip()
        if name in values or not cleaned:
            raise _InvalidSink
        values[name] = cleaned
    if set(values) != set(TOKEN_DIRECTORY_VARIABLES):
        raise _InvalidSink
    return values


def _validate_compose_contract(compose_file: Path) -> None:
    _reject_link_or_reparse_ancestors(compose_file)
    if not stat.S_ISREG(_metadata(compose_file).st_mode):
        raise _InvalidSink
    loaded = load_unique_yaml(compose_file)
    services = loaded["services"]
    for service_name, variable in SERVICE_TOKEN_DIRECTORIES.items():
        service = services[service_name]
        if str(service.get("user")) != f"{CONTAINER_UID}:{CONTAINER_GID}":
            raise _InvalidSink
        if (service.get("environment") or {}).get(
            "PLATFORM_VAULT_TOKEN_FILE"
        ) != CONTAINER_TOKEN_FILE:
            raise _InvalidSink
        mounts = [
            mount
            for mount in service.get("volumes", [])
            if isinstance(mount, dict)
            and mount.get("target") == CONTAINER_TOKEN_DIRECTORY
        ]
        if len(mounts) != 1:
            raise _InvalidSink
        mount = mounts[0]
        if (
            mount.get("type") != "bind"
            or mount.get("source")
            != f"${{{variable}:?set {variable} in .env}}"
            or mount.get("read_only") is not True
            or (mount.get("bind") or {}).get("create_host_path") is not False
        ):
            raise _InvalidSink


def _posix_identity_can_read(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o400, 0o440}:
        return False
    owner_can_read = metadata.st_uid == CONTAINER_UID and bool(mode & stat.S_IRUSR)
    group_can_read = metadata.st_gid == CONTAINER_GID and bool(mode & stat.S_IRGRP)
    return owner_can_read or group_can_read


def validate_vault_token_sinks(
    env_file: Path,
    compose_file: Path,
    *,
    repository_root: Path = ROOT,
) -> None:
    """Validate three isolated token sink leaves using metadata only."""

    try:
        repository = repository_root.resolve(strict=True)
        if env_file.resolve(strict=True) != repository / ".env":
            raise _InvalidSink
        if compose_file.resolve(strict=True) != repository / "docker-compose.yml":
            raise _InvalidSink
        inventory = _read_inventory(env_file)
        _validate_compose_contract(compose_file)
        directory_identities: set[tuple[int, int]] = set()
        token_identities: set[tuple[int, int]] = set()
        resolved_directories: set[Path] = set()

        for name in TOKEN_DIRECTORY_VARIABLES:
            directory = Path(inventory[name])
            if (
                not directory.is_absolute()
                or ".." in directory.parts
                or "~" in directory.parts
                or "CHANGE_ME" in directory.parts
                or any(character in inventory[name] for character in "$'\"")
            ):
                raise _InvalidSink
            _reject_link_or_reparse_ancestors(directory)
            directory_metadata = _metadata(directory)
            if not stat.S_ISDIR(directory_metadata.st_mode):
                raise _InvalidSink
            if os.name != "nt" and stat.S_IMODE(directory_metadata.st_mode) & 0o022:
                raise _InvalidSink
            resolved_directory = directory.resolve(strict=True)
            if resolved_directory.is_relative_to(repository):
                raise _InvalidSink

            directory_identity = (
                directory_metadata.st_dev,
                directory_metadata.st_ino,
            )
            if (
                resolved_directory in resolved_directories
                or directory_identity in directory_identities
            ):
                raise _InvalidSink
            resolved_directories.add(resolved_directory)
            directory_identities.add(directory_identity)

            token_file = directory / TOKEN_LEAF
            token_metadata = _metadata(token_file)
            if (
                not stat.S_ISREG(token_metadata.st_mode)
                or token_metadata.st_size <= 0
                or token_metadata.st_size > MAX_TOKEN_BYTES
                or token_metadata.st_nlink != 1
            ):
                raise _InvalidSink
            if os.name != "nt" and not _posix_identity_can_read(token_metadata):
                raise _InvalidSink

            token_identity = (token_metadata.st_dev, token_metadata.st_ino)
            if token_identity in token_identities:
                raise _InvalidSink
            token_identities.add(token_identity)
        for directory in resolved_directories:
            if any(
                directory != other
                and (
                    directory.is_relative_to(other)
                    or other.is_relative_to(directory)
                )
                for other in resolved_directories
            ):
                raise _InvalidSink
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        yaml.YAMLError,
        _InvalidSink,
    ):
        raise VaultTokenSinkError(
            "Vault token sink metadata is invalid"
        ) from None
