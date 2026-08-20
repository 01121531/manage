"""Small server-side secret resolver contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import posixpath
import stat
from collections.abc import Mapping
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request


class SecretResolverUnavailable(RuntimeError):
    """A secret reference cannot be resolved by this process."""


class SecretResolver(Protocol):
    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        """Resolve an opaque server-side secret reference."""


class JsonEnvironmentSecretResolver:
    """Resolve ``env://NAME`` references from JSON environment values."""

    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        if not secret_ref.startswith("env://"):
            raise SecretResolverUnavailable("Secret resolver only supports env:// refs")
        name = secret_ref.removeprefix("env://").strip()
        if not name:
            raise SecretResolverUnavailable("Secret environment name is empty")
        raw = os.environ.get(name)
        if raw is None:
            raise SecretResolverUnavailable("Secret environment value is missing")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {"value": raw}
        if not isinstance(value, dict):
            raise SecretResolverUnavailable("Secret environment JSON must be an object")
        return value


ResponseOpener = Callable[..., Any]
_MAX_VAULT_TOKEN_BYTES = 4096
_PRODUCTION_VAULT_TOKEN_ROOTS = ("/run/secrets/", "/var/run/secrets/")


def _normalize_vault_addr(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip().rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Vault address must be HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Vault address must not contain credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1", "vault"}:
        raise ValueError("Vault address must use HTTPS outside localhost/internal vault")
    if parsed.query or parsed.fragment:
        raise ValueError("Vault address must not contain query or fragment")
    return urllib.parse.urlunsplit(parsed)


def _vault_ref_path(secret_ref: str) -> str:
    parsed = urllib.parse.urlsplit(secret_ref)
    if parsed.scheme != "vault" or not parsed.netloc:
        raise SecretResolverUnavailable("Secret resolver only supports vault:// refs")
    raw_path = parsed.path
    if parsed.query or parsed.fragment or not raw_path.startswith("/"):
        raise SecretResolverUnavailable("Vault secret ref must be vault://mount/path")
    parts = raw_path[1:].split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise SecretResolverUnavailable("Vault secret ref contains an invalid path segment")
    mount = urllib.parse.quote(parsed.netloc.strip("/"), safe="")
    key_path = "/".join(urllib.parse.quote(part, safe="") for part in parts)
    return f"/v1/{mount}/data/{key_path}"


class VaultSecretResolver:
    """Resolve ``vault://mount/path`` references through Vault KV v2."""

    def __init__(
        self,
        addr: str,
        token: str | None = None,
        *,
        token_file: str | None = None,
        namespace: str | None = None,
        timeout: int = 10,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        cleaned_token = token.strip() if isinstance(token, str) else ""
        cleaned_token_file = token_file.strip() if isinstance(token_file, str) else ""
        if bool(cleaned_token) == bool(cleaned_token_file):
            raise ValueError("Configure exactly one Vault token source")
        if cleaned_token_file and not (
            Path(cleaned_token_file).is_absolute() or cleaned_token_file.startswith("/")
        ):
            raise ValueError("Vault token file path must be absolute")
        self.addr = _normalize_vault_addr(addr)
        self._static_token = cleaned_token or None
        self._token_file = cleaned_token_file or None
        self.namespace = namespace.strip() if isinstance(namespace, str) and namespace.strip() else None
        self.timeout = timeout
        self._opener = opener

    def __repr__(self) -> str:
        source = "file" if self._token_file is not None else "environment"
        return f"VaultSecretResolver(addr={self.addr!r}, token_source={source!r})"

    def _token(self) -> str:
        if self._static_token is not None:
            return self._static_token
        assert self._token_file is not None
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._token_file, flags)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_size <= 0
                    or metadata.st_size > _MAX_VAULT_TOKEN_BYTES
                ):
                    raise OSError("invalid token file")
                if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & (
                    stat.S_IWGRP | stat.S_IWOTH
                ):
                    raise OSError("insecure token file permissions")
                raw = os.read(descriptor, _MAX_VAULT_TOKEN_BYTES + 1)
            finally:
                os.close(descriptor)
            token = raw.decode("utf-8").strip()
            if (
                not token
                or len(raw) > _MAX_VAULT_TOKEN_BYTES
                or any(character.isspace() for character in token)
            ):
                raise ValueError("invalid token file contents")
            return token
        except (OSError, UnicodeError, ValueError) as error:
            raise SecretResolverUnavailable("Vault token file is unavailable") from None

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)

    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        url = self.addr + _vault_ref_path(secret_ref)
        headers = {
            "Accept": "application/json",
            "X-Vault-Token": self._token(),
        }
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with self._open(request, timeout=self.timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as error:
            raise SecretResolverUnavailable(f"Vault returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise SecretResolverUnavailable("Vault is unavailable") from error
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SecretResolverUnavailable("Vault returned invalid JSON") from error
        if not isinstance(value, dict):
            raise SecretResolverUnavailable("Vault returned invalid data")
        data = value.get("data")
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            return data["data"]
        if isinstance(data, dict):
            return data
        raise SecretResolverUnavailable("Vault response missing secret data")


class SchemeSecretResolver:
    """Route supported secret-ref schemes to concrete resolvers."""

    def __init__(
        self,
        *,
        env: SecretResolver,
        vault: SecretResolver | None = None,
        allow_env: bool = True,
    ) -> None:
        self.env = env
        self.vault = vault
        self.allow_env = allow_env

    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        if secret_ref.startswith("env://"):
            if not self.allow_env:
                raise SecretResolverUnavailable(
                    "Environment secret references are disabled in production"
                )
            return self.env.resolve(secret_ref)
        if secret_ref.startswith("vault://") and self.vault is not None:
            return self.vault.resolve(secret_ref)
        if secret_ref.startswith("vault://"):
            raise SecretResolverUnavailable("Vault resolver is not configured")
        raise SecretResolverUnavailable("Unsupported secret ref scheme")


def secret_resolver_from_settings(settings: Any) -> SecretResolver:
    env_resolver = JsonEnvironmentSecretResolver()
    vault_addr = getattr(settings, "vault_addr", None)
    vault_token = getattr(settings, "vault_token", None)
    vault_token_file = getattr(settings, "vault_token_file", None)
    token_value = (
        vault_token.get_secret_value()
        if vault_token is not None and hasattr(vault_token, "get_secret_value")
        else vault_token
    )
    environment = str(getattr(settings, "environment", "development")).strip().lower()
    is_local = environment in {"development", "test"}
    if vault_addr:
        cleaned_token = token_value.strip() if isinstance(token_value, str) else ""
        cleaned_token_file = (
            vault_token_file.strip() if isinstance(vault_token_file, str) else ""
        )
        if bool(cleaned_token) == bool(cleaned_token_file):
            raise RuntimeError(
                "Configure exactly one of PLATFORM_VAULT_TOKEN_FILE or "
                "PLATFORM_VAULT_TOKEN when PLATFORM_VAULT_ADDR is set"
            )
        if cleaned_token and not is_local:
            raise RuntimeError(
                "PLATFORM_VAULT_TOKEN_FILE is required outside development/test"
            )
        if cleaned_token_file and not is_local:
            normalized = posixpath.normpath(cleaned_token_file.replace("\\", "/"))
            if not any(
                normalized.startswith(root) for root in _PRODUCTION_VAULT_TOKEN_ROOTS
            ):
                raise RuntimeError(
                    "PLATFORM_VAULT_TOKEN_FILE must be under /run/secrets or "
                    "/var/run/secrets outside development/test"
                )
        return SchemeSecretResolver(
            env=env_resolver,
            allow_env=is_local,
            vault=VaultSecretResolver(
                vault_addr,
                cleaned_token or None,
                token_file=cleaned_token_file or None,
                namespace=getattr(settings, "vault_namespace", None),
                timeout=getattr(settings, "vault_timeout_seconds", 10),
            ),
        )
    return SchemeSecretResolver(env=env_resolver, allow_env=is_local)
