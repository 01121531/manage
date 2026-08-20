"""Pydantic request and response contracts for the Phase 1 API."""

from datetime import datetime
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LoginRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    device_id: str = Field(min_length=1, max_length=36)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AuthConfigResponse(BaseModel):
    mode: str
    issuer: str | None = None
    client_id: str | None = None
    desktop_client_id: str | None = None
    audience: str | None = None


class MeResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    device_id: str
    role: str


class DashboardSummaryResponse(BaseModel):
    scope: Literal["own", "tenant"]
    generated_at: datetime
    active_tasks: int
    allocated_cards: int
    waiting_mail_sessions: int
    queued_uploads: int
    unknown_uploads: int
    task_statuses: dict[str, int]
    mail_session_statuses: dict[str, int]
    card_allocation_statuses: dict[str, int]
    upload_statuses: dict[str, int]


class MailboxStatusResponse(BaseModel):
    id: str
    email_masked: str
    connector_type: str
    is_active: bool
    status: Literal["available", "busy", "disabled"]
    active_session_count: int
    created_at: datetime


class AdminUserResponse(BaseModel):
    """Safe user projection; password hashes are never part of the API."""

    id: str
    tenant_id: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class AdminDeviceResponse(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    name: str
    revoked_at: datetime | None
    created_at: datetime


class AdminAuditResponse(BaseModel):
    id: str
    tenant_id: str
    user_id: str | None
    device_id: str | None
    actor_id: str | None
    event_type: str
    action: str
    result: str
    entity_type: str
    entity_id: str | None
    trace_id: str
    ip_address: str | None
    user_agent: str | None
    policy_version: str | None
    details: dict[str, object]
    created_at: datetime


class AdminCardResponse(BaseModel):
    id: str
    tenant_id: str
    provider_ref: str
    brand: str
    last4: str
    expiry_month: int | None
    expiry_year: int | None
    is_active: bool
    created_at: datetime


def _normalize_opaque_secret_ref(value: str, *, vault_prefix: str) -> str:
    normalized = value.strip()
    if re.fullmatch(r"(?:vault|env)://[A-Za-z0-9][A-Za-z0-9._/-]*", normalized) is None:
        raise ValueError("secret_ref must be an opaque vault:// or env:// reference")
    path = normalized.split("://", maxsplit=1)[1]
    if any(segment in {"", ".", ".."} for segment in path.split("/")):
        raise ValueError("secret_ref path must not contain empty, dot, or parent segments")
    if normalized.startswith("vault://") and not normalized.startswith(vault_prefix):
        raise ValueError(f"secret_ref must use {vault_prefix} or an env:// development reference")
    return normalized


def _contains_pan_like_digits(value: str) -> bool:
    for candidate in re.split(r"[A-Za-z]+", value):
        digit_count = len(re.sub(r"\D", "", candidate))
        if 12 <= digit_count <= 19:
            return True
    return False


class AdminCardCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_ref: str = Field(min_length=1, max_length=160)
    brand: str = Field(min_length=1, max_length=40)
    last4: str = Field(pattern=r"^\d{4}$")
    expiry_month: int | None = Field(default=None, ge=1, le=12)
    expiry_year: int | None = Field(default=None, ge=2000, le=9999)
    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("provider_ref", "brand")
    @classmethod
    def normalize_card_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty")
        if _contains_pan_like_digits(normalized):
            raise ValueError("provider_ref and brand must not contain a PAN")
        return normalized

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(value, vault_prefix="vault://secret/cards/")

    @model_validator(mode="after")
    def validate_expiry_pair(self) -> "AdminCardCreate":
        if (self.expiry_month is None) != (self.expiry_year is None):
            raise ValueError("expiry_month and expiry_year must be provided together")
        return self


class AdminCardStateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class AdminMailboxCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_masked: str = Field(min_length=3, max_length=320)
    connector_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")
    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("email_masked")
    @classmethod
    def validate_masked_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "*" not in normalized:
            raise ValueError("email_masked must contain a masked email address")
        return normalized

    @field_validator("connector_type")
    @classmethod
    def normalize_connector_type(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(value, vault_prefix="vault://secret/mailboxes/")


class AdminMailboxStateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class AdminMailboxSecretRotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(value, vault_prefix="vault://secret/mailboxes/")


class AdminUploadResponse(BaseModel):
    id: str
    tenant_id: str
    task_id: str
    user_id: str
    device_id: str
    card_allocation_id: str
    status: str
    business_name: str
    trace_id: str
    policy_version: str
    external_ref: str | None
    error_code: str | None
    created_at: datetime
    updated_at: datetime


class UploadPolicyStatusResponse(BaseModel):
    policy_version: str
    status: Literal["ready", "not_configured"]
    upload_endpoint_configured: bool
    upload_secret_configured: bool
    network_route_configured: bool
    server_managed: bool = True
    governance_configured: bool = False
    active_version: str | None = None
    previous_version: str | None = None
    rollout_percent: int | None = None


class UploadPolicyVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    change_note: str = Field(min_length=1, max_length=500)


class UploadPolicyDeployRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rollout_percent: int = Field(ge=1, le=100)


class UploadPolicyVersionResponse(BaseModel):
    id: str
    version: str
    status: Literal["draft", "approved", "active", "retired"]
    change_note: str
    created_by: str
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime


class UploadPolicyDeploymentResponse(BaseModel):
    active_version: str
    previous_version: str | None
    rollout_percent: int
    updated_at: datetime


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=80)
    idempotency_key: str = Field(min_length=1, max_length=160)
    client_reference: str | None = Field(default=None, max_length=160)


class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: str
    device_id: str
    type: str = Field(validation_alias="task_type")
    idempotency_key: str
    client_reference: str | None
    trace_id: str
    status: str
    expires_at: datetime | None
    closed_at: datetime | None
    created_at: datetime


class MailSessionResponse(BaseModel):
    id: str
    trace_id: str
    email_masked: str
    status: str
    expires_at: datetime


class MailSessionCreateResponse(MailSessionResponse):
    session_token: str = Field(min_length=32, max_length=128, repr=False)


class MailCodeResponse(BaseModel):
    status: str
    code: str | None = None


class CardAllocationResponse(BaseModel):
    id: str
    trace_id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    status: str
    expires_at: datetime


class CardRevealResponse(BaseModel):
    id: str
    allocation_id: str
    trace_id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    pan: str
    reveal_expires_at: datetime


class CardRevealChallengeResponse(BaseModel):
    challenge_id: str
    acr_values: str
    expires_at: datetime


class CardRevealGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=36)


class CardRevealGrantResponse(BaseModel):
    reveal_grant: str
    expires_at: datetime


class CardRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reveal_grant: str = Field(min_length=32, max_length=256)
    fields: list[Literal["pan", "expiry"]] = Field(
        default_factory=lambda: ["pan", "expiry"], min_length=1, max_length=2
    )

    @field_validator("fields")
    @classmethod
    def validate_reveal_fields(
        cls, value: list[Literal["pan", "expiry"]]
    ) -> list[Literal["pan", "expiry"]]:
        if len(set(value)) != len(value):
            raise ValueError("fields must be unique")
        return value


class UploadCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_name: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=1, max_length=160)

    @field_validator("business_name", "idempotency_key")
    @classmethod
    def normalize_upload_value(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value


class UploadDirectCreate(UploadCreate):
    task_id: str = Field(min_length=1, max_length=36)


class UploadJobResponse(BaseModel):
    id: str
    task_id: str
    status: str
    business_name: str
    trace_id: str
    policy_version: str
    external_ref: str | None
    error_code: str | None
    created_at: datetime
    updated_at: datetime


class UploadReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["succeeded", "failed", "unknown"]
    external_ref: str | None = Field(default=None, max_length=160)
    error_code: str | None = Field(default=None, max_length=80)

    @field_validator("external_ref", "error_code")
    @classmethod
    def normalize_optional_upload_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None
