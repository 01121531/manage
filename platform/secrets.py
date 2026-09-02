"""Small server-side secret resolver contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import posixpath
import ssl
import stat
from collections.abc import Mapping
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes


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
_MAX_VAULT_RESPONSE_BYTES = 64 * 1024
_MAX_VAULT_NAMESPACE_BYTES = 8 * 1024
_MAX_VAULT_CA_BYTES = 256 * 1024
_PRODUCTION_VAULT_TOKEN_ROOTS = ("/run/secrets/", "/var/run/secrets/")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


def _normalize_vault_addr(value: str) -> str:
    try:
        if not isinstance(value, str) or not value or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in value
        ):
            raise ValueError
        parsed = urllib.parse.urlsplit(value.rstrip("/"))
        hostname = parsed.hostname
        hostname_key = hostname.rstrip(".") if hostname is not None else ""
        if not hostname_key:
            raise ValueError
        hostname_key.encode("idna")
        port = parsed.port
    except (AttributeError, UnicodeError, ValueError):
        raise ValueError("Vault address is invalid") from None
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Vault address must be HTTP(S)")
    if parsed.scheme == "http" and hostname_key.lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
        "vault",
    }:
        raise ValueError("Vault address must use HTTPS outside localhost/internal vault")
    if (
        not parsed.netloc
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Vault address is invalid")
    return urllib.parse.urlunsplit(parsed)


def normalize_vault_namespace(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        encoded = value.encode("ascii")
    except (AttributeError, UnicodeError):
        raise ValueError("Vault namespace is invalid") from None
    if len(encoded) > _MAX_VAULT_NAMESPACE_BYTES or any(
        byte <= 0x20 or byte == 0x7F for byte in encoded
    ):
        raise ValueError("Vault namespace is invalid")
    return value


def create_internal_tls_context(ca_file: str | None) -> ssl.SSLContext:
    """Build a hostname-verifying context from one stable internal CA snapshot."""
    try:
        if ca_file is None or ca_file == "":
            context = ssl.create_default_context()
        else:
            if (
                not isinstance(ca_file, str)
                or not Path(ca_file).is_absolute()
                or ca_file != ca_file.strip()
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in ca_file
                )
            ):
                raise ValueError
            raw, metadata = read_stable_runtime_bytes_with_metadata(
                Path(ca_file),
                max_bytes=_MAX_VAULT_CA_BYTES,
            )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                raise OSError("insecure CA file permissions")
            context = ssl.create_default_context(cadata=raw.decode("ascii"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        return context
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        raise ValueError("Internal TLS trust is unavailable or invalid") from None


def create_vault_tls_context(ca_file: str | None) -> ssl.SSLContext:
    """Map the shared internal trust boundary to Vault's public error contract."""

    try:
        return create_internal_tls_context(ca_file)
    except ValueError:
        raise ValueError("Vault TLS trust is unavailable or invalid") from None


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
        ssl_context: ssl.SSLContext | None = None,
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
        self.namespace = normalize_vault_namespace(namespace)
        self.timeout = timeout
        self._opener = opener
        handlers: list[Any] = [
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        ]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._default_opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        source = "file" if self._token_file is not None else "environment"
        return f"VaultSecretResolver(addr={self.addr!r}, token_source={source!r})"

    def _token(self) -> str:
        if self._static_token is not None:
            return self._static_token
        assert self._token_file is not None
        try:
            raw, metadata = read_stable_runtime_bytes_with_metadata(
                Path(self._token_file),
                max_bytes=_MAX_VAULT_TOKEN_BYTES,
            )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                raise OSError("insecure token file permissions")
            token = raw.decode("utf-8").strip()
            if (
                not token
                or len(raw) > _MAX_VAULT_TOKEN_BYTES
                or any(character.isspace() for character in token)
            ):
                raise ValueError("invalid token file contents")
            return token
        except (OSError, UnicodeError, ValueError):
            raise SecretResolverUnavailable("Vault token file is unavailable") from None

    def validate_token_source(self) -> None:
        """Validate a file-backed token without caching it or contacting Vault."""

        if self._token_file is not None:
            self._token()

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return self._default_opener.open(request, timeout=timeout)

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
                raw = response.read(_MAX_VAULT_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_VAULT_RESPONSE_BYTES:
                    raise SecretResolverUnavailable("Vault returned invalid JSON")
        except urllib.error.HTTPError as error:
            raise SecretResolverUnavailable(f"Vault returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise SecretResolverUnavailable("Vault is unavailable") from error
        try:
            value = parse_unique_json_bytes(raw)
        except JsonBoundaryError:
            raise SecretResolverUnavailable("Vault returned invalid JSON") from None
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
    raw_vault_addr = vault_addr if isinstance(vault_addr, str) else ""
    has_vault_addr = bool(raw_vault_addr.strip())
    if not has_vault_addr and not is_local:
        raise RuntimeError(
            "PLATFORM_VAULT_ADDR is required outside development/test"
        )
    if has_vault_addr:
        try:
            normalized_vault_addr = _normalize_vault_addr(raw_vault_addr)
        except ValueError:
            raise RuntimeError("PLATFORM_VAULT_ADDR is invalid") from None
        if not is_local and not normalized_vault_addr.startswith("https://"):
            raise RuntimeError(
                "PLATFORM_VAULT_ADDR must use HTTPS outside development/test"
            )
        normalized_namespace = normalize_vault_namespace(
            getattr(settings, "vault_namespace", None)
        )
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
        try:
            vault_tls_context = create_vault_tls_context(
                getattr(settings, "internal_ca_file", None)
            )
        except ValueError:
            raise RuntimeError(
                "PLATFORM_INTERNAL_CA_FILE is unavailable or invalid for Vault"
            ) from None
        vault_resolver = VaultSecretResolver(
            normalized_vault_addr,
            cleaned_token or None,
            token_file=cleaned_token_file or None,
            namespace=normalized_namespace,
            timeout=getattr(settings, "vault_timeout_seconds", 10),
            ssl_context=vault_tls_context,
        )
        if not is_local:
            vault_resolver.validate_token_source()
        return SchemeSecretResolver(
            env=env_resolver,
            allow_env=is_local,
            vault=vault_resolver,
        )
    return SchemeSecretResolver(env=env_resolver, allow_env=is_local)
