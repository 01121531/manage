"""Application configuration loaded from environment variables.

Only non-sensitive runtime settings live here. Credentials and external service
configuration are intentionally not part of this scaffold.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEFAULT_DATABASE = Path(__file__).resolve().parent / "platform.db"


class Settings(BaseSettings):
    """Runtime settings for the platform API.

    Environment variables use the ``PLATFORM_`` prefix, for example
    ``PLATFORM_ENV=production``.
    """

    app_name: str = "email-platform"
    environment: str = "development"
    api_prefix: str = "/api"
    api_version: str = "v1"
    debug: bool = False
    database_url: str = f"sqlite+pysqlite:///{_DEFAULT_DATABASE.as_posix()}"
    auth_mode: str = "local"
    jwt_hmac_secret: SecretStr | None = None
    access_token_ttl_seconds: int = Field(default=900, gt=0, le=86_400)
    oidc_issuer_url: str | None = None
    oidc_audience: str | None = None
    oidc_client_id: str | None = None
    oidc_desktop_client_id: str | None = None
    oidc_jwks_url: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_device_claim: str = "device_id"
    vault_addr: str | None = None
    vault_token: SecretStr | None = None
    vault_namespace: str | None = None
    vault_timeout_seconds: int = Field(default=10, gt=0, le=60)
    mail_api_url: str | None = None
    mail_timeout_seconds: int = Field(default=20, gt=0, le=300)
    mail_poll_mode: str = "api"
    mail_session_ttl_seconds: int = Field(default=300, gt=0, le=3_600)
    mail_poll_interval_seconds: int = Field(default=5, gt=0, le=60)
    card_lease_ttl_seconds: int = Field(default=900, gt=0, le=86_400)
    card_reveal_ttl_seconds: int = Field(default=60, gt=0, le=300)
    task_ttl_seconds: int = Field(default=3_600, gt=0, le=86_400)
    sub2_policy_version: str = "sub2-v1"
    sub2_group_id: int = Field(default=49, gt=0)
    sub2_concurrency: int = Field(default=40, gt=0, le=1_000)
    sub2_proxy_ref: str | None = None
    sub2_credential_ref: SecretStr | None = None
    sub2_upload_url: str | None = None
    sub2_timeout_seconds: int = Field(default=30, gt=0, le=300)

    model_config = SettingsConfigDict(
        env_prefix="PLATFORM_",
        env_file=".env",
        extra="ignore",
    )

    @property
    def versioned_api_prefix(self) -> str:
        """Return the normalized versioned API prefix."""

        return f"{self.api_prefix.rstrip('/')}/{self.api_version.strip('/')}"


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance for the process."""

    return Settings()
