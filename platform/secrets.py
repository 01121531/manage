"""Small server-side secret resolver contracts."""

from __future__ import annotations

import json
import os
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
    path = parsed.path.strip("/")
    if parsed.query or parsed.fragment or not path:
        raise SecretResolverUnavailable("Vault secret ref must be vault://mount/path")
    mount = urllib.parse.quote(parsed.netloc.strip("/"), safe="")
    key_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/") if part)
    return f"/v1/{mount}/data/{key_path}"


class VaultSecretResolver:
    """Resolve ``vault://mount/path`` references through Vault KV v2."""

    def __init__(
        self,
        addr: str,
        token: str,
        *,
        namespace: str | None = None,
        timeout: int = 10,
        opener: ResponseOpener | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        cleaned_token = token.strip()
        if not cleaned_token:
            raise ValueError("Vault token must not be empty")
        self.addr = _normalize_vault_addr(addr)
        self.token = cleaned_token
        self.namespace = namespace.strip() if isinstance(namespace, str) and namespace.strip() else None
        self.timeout = timeout
        self._opener = opener

    def _open(self, request: urllib.request.Request, timeout: int) -> Any:
        if self._opener is not None:
            return self._opener(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)

    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        url = self.addr + _vault_ref_path(secret_ref)
        headers = {
            "Accept": "application/json",
            "X-Vault-Token": self.token,
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

    def __init__(self, *, env: SecretResolver, vault: SecretResolver | None = None) -> None:
        self.env = env
        self.vault = vault

    def resolve(self, secret_ref: str) -> Mapping[str, object]:
        if secret_ref.startswith("env://"):
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
    token_value = (
        vault_token.get_secret_value()
        if vault_token is not None and hasattr(vault_token, "get_secret_value")
        else vault_token
    )
    if vault_addr:
        if not isinstance(token_value, str) or not token_value.strip():
            raise RuntimeError("PLATFORM_VAULT_TOKEN is required when PLATFORM_VAULT_ADDR is set")
        return SchemeSecretResolver(
            env=env_resolver,
            vault=VaultSecretResolver(
                vault_addr,
                token_value,
                namespace=getattr(settings, "vault_namespace", None),
                timeout=getattr(settings, "vault_timeout_seconds", 10),
            ),
        )
    return SchemeSecretResolver(env=env_resolver)
