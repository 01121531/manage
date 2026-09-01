"""Application configuration loaded from environment variables.

Only non-sensitive runtime settings live here. Credentials and external service
configuration are intentionally not part of this scaffold.
"""

from functools import lru_cache
import os
from pathlib import Path
import stat

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from platform.file_boundary import (
    RuntimeFileError,
    read_stable_runtime_bytes_with_metadata,
    read_stable_runtime_text,
)


_DEFAULT_DATABASE = Path(__file__).resolve().parent / "platform.db"
MAX_RUNTIME_SECRET_BYTES = 8 * 1024
MAX_ORIGIN_POLICY_BYTES = 8 * 1024


class Settings(BaseSettings):
    """Runtime settings for the platform API.

    Environment variables use the ``PLATFORM_`` prefix, for example
    ``PLATFORM_ENV=production``.
    """

    app_name: str = "email-platform"
    environment: str = "development"
    release_tag: str = "unidentified"
    release_commit: str = "unidentified"
    release_migration_head: str = "unidentified"
    release_slot: str = "unidentified"
    api_prefix: str = "/api"
    api_version: str = "v1"
    debug: bool = False
    allowed_origins: str = ""
    database_url: str = f"sqlite+pysqlite:///{_DEFAULT_DATABASE.as_posix()}"
    database_url_file: str | None = None
    redis_url: SecretStr | None = None
    redis_url_file: str | None = None
    rate_limit_enabled: bool = False
    rate_limit_window_seconds: int = Field(default=60, gt=0, le=3_600)
    rate_limit_login_requests: int = Field(default=5, gt=0, le=100_000)
    rate_limit_high_risk_requests: int = Field(default=30, gt=0, le=100_000)
    rate_limit_general_requests: int = Field(default=300, gt=0, le=100_000)
    auth_mode: str = "local"
    jwt_hmac_secret: SecretStr | None = None
    access_token_ttl_seconds: int = Field(default=900, gt=0, le=86_400)
    max_active_devices_per_user: int = Field(default=5, ge=0, le=100)
    oidc_issuer_url: str | None = None
    oidc_audience: str | None = None
    oidc_client_id: str | None = None
    oidc_desktop_client_id: str | None = None
    oidc_jwks_url: str | None = None
    internal_ca_file: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_device_claim: str = "device_id"
    vault_addr: str | None = None
    vault_token: SecretStr | None = None
    vault_token_file: str | None = None
    vault_namespace: str | None = None
    vault_timeout_seconds: int = Field(default=10, gt=0, le=60)
    pool_import_receipt_audience: str | None = Field(default=None, max_length=160)
    pool_import_context_ttl_seconds: int = Field(default=900, gt=0, le=3_600)
    mail_api_url: str | None = None
    mail_allowed_origins_file: str | None = None
    mail_timeout_seconds: int = Field(default=20, gt=0, le=300)
    mail_poll_mode: str = "api"
    mail_session_ttl_seconds: int = Field(default=300, gt=0, le=3_600)
    mail_code_ttl_seconds: int = Field(default=60, gt=0, le=300)
    mail_poll_interval_seconds: int = Field(default=5, gt=0, le=60)
    card_lease_ttl_seconds: int = Field(default=900, gt=0, le=86_400)
    card_reveal_ttl_seconds: int = Field(default=60, gt=0, le=300)
    card_step_up_challenge_ttl_seconds: int = Field(default=120, gt=0, le=600)
    card_step_up_grant_ttl_seconds: int = Field(default=60, gt=0, le=300)
    card_step_up_acr: str = Field(
        default="urn:email-platform:acr:mfa", min_length=1, max_length=255
    )
    admin_role_change_ttl_seconds: int = Field(default=900, gt=0, le=3_600)
    admin_role_change_acr: str = Field(
        default="urn:email-platform:acr:mfa", min_length=1, max_length=255
    )
    task_ttl_seconds: int = Field(default=1_800, gt=0, le=86_400)
    sub2_policy_version: str = "sub2-v1"
    sub2_group_id: int = Field(default=49, gt=0)
    sub2_concurrency: int = Field(default=10, gt=0, le=1_000)
    sub2_proxy_ref: str | None = None
    sub2_credential_ref: SecretStr | None = None
    sub2_upload_url: str | None = None
    sub2_allowed_origins_file: str | None = None
    sub2_timeout_seconds: int = Field(default=30, gt=0, le=300)

    model_config = SettingsConfigDict(
        env_prefix="PLATFORM_",
        env_file=".env",
        extra="ignore",
    )

    @field_validator("card_step_up_acr", "admin_role_change_acr")
    @classmethod
    def validate_step_up_acr(cls, value: str) -> str:
        normalized = value.strip()
        if (
            any(character.isspace() for character in normalized)
            or not normalized.startswith(("urn:", "https://"))
        ):
            raise ValueError("step-up ACR must be one URI-like value")
        return normalized

    @field_validator("pool_import_receipt_audience")
    @classmethod
    def validate_pool_import_receipt_audience(
        cls, value: str | None
    ) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if (
            not normalized
            or len(normalized) > 160
            or any(character.isspace() for character in normalized)
        ):
            raise ValueError("pool import receipt audience must be one token")
        return normalized

    @property
    def versioned_api_prefix(self) -> str:
        """Return the normalized versioned API prefix."""

        return f"{self.api_prefix.rstrip('/')}/{self.api_version.strip('/')}"

    @staticmethod
    def _read_runtime_secret(path: str | None, setting_name: str) -> str:
        if not path:
            raise RuntimeError(f"{setting_name}_FILE is required outside development")
        try:
            raw, metadata = read_stable_runtime_bytes_with_metadata(
                Path(path),
                max_bytes=MAX_RUNTIME_SECRET_BYTES,
                allow_empty=True,
            )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                raise RuntimeFileError("runtime secret permissions are invalid")
            value = raw.decode("utf-8")
        except (RuntimeFileError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Cannot read {setting_name}_FILE") from exc
        lines = value.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise RuntimeError(f"{setting_name}_FILE must contain one non-empty line")
        return lines[0].strip()

    def resolved_database_url(self, *, require_file: bool = False) -> str:
        """Resolve the database URL without exposing file contents in settings."""

        if require_file and self.database_url != f"sqlite+pysqlite:///{_DEFAULT_DATABASE.as_posix()}":
            raise RuntimeError(
                "PLATFORM_DATABASE_URL is forbidden outside development; use "
                "PLATFORM_DATABASE_URL_FILE"
            )
        if self.database_url_file:
            return self._read_runtime_secret(
                self.database_url_file, "PLATFORM_DATABASE_URL"
            )
        if require_file:
            raise RuntimeError(
                "PLATFORM_DATABASE_URL_FILE is required outside development"
            )
        return self.database_url

    def resolved_redis_url(self, *, require_file: bool = False) -> str:
        """Resolve the Redis URL, preferring the production secret file."""

        if require_file and self.redis_url is not None:
            raise RuntimeError(
                "PLATFORM_REDIS_URL is forbidden outside development; use "
                "PLATFORM_REDIS_URL_FILE"
            )
        if self.redis_url_file:
            return self._read_runtime_secret(self.redis_url_file, "PLATFORM_REDIS_URL")
        if require_file:
            raise RuntimeError("PLATFORM_REDIS_URL_FILE is required outside development")
        return (
            self.redis_url.get_secret_value().strip()
            if self.redis_url is not None
            else ""
        )

    def resolved_sub2_allowed_origins(self) -> tuple[str, ...]:
        """Read the external single-line Sub2 origin policy without disclosing it."""

        if not self.sub2_allowed_origins_file:
            raise RuntimeError("Sub2 allowed origins policy is unavailable")
        try:
            value = read_stable_runtime_text(
                Path(self.sub2_allowed_origins_file),
                max_bytes=MAX_ORIGIN_POLICY_BYTES,
                allow_empty=True,
            )
        except RuntimeFileError as exc:
            raise RuntimeError("Sub2 allowed origins policy is unavailable") from exc
        lines = value.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise RuntimeError("Sub2 allowed origins policy is invalid")
        origins = tuple(item.strip() for item in lines[0].split(","))
        if not origins or any(not item for item in origins):
            raise RuntimeError("Sub2 allowed origins policy is invalid")
        return origins

    def resolved_mail_allowed_origins(self) -> tuple[str, ...]:
        """Read the external single-line mail origin policy without disclosing it."""

        if not self.mail_allowed_origins_file:
            raise RuntimeError("Mail allowed origins policy is unavailable")
        try:
            value = read_stable_runtime_text(
                Path(self.mail_allowed_origins_file),
                max_bytes=MAX_ORIGIN_POLICY_BYTES,
                allow_empty=True,
            )
        except RuntimeFileError as exc:
            raise RuntimeError("Mail allowed origins policy is unavailable") from exc
        lines = value.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise RuntimeError("Mail allowed origins policy is invalid")
        origins = tuple(item.strip() for item in lines[0].split(","))
        if not origins or any(not item for item in origins):
            raise RuntimeError("Mail allowed origins policy is invalid")
        return origins


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance for the process."""

    return Settings()
