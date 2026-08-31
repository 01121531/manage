"""Pydantic request and response contracts for the Phase 1 API."""

from datetime import datetime
import re
from typing import Any, Literal, TypedDict

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from platform.uploads import EXTERNAL_REF_PATTERN


class ApiErrorDetail(BaseModel):
    """Stable, non-secret error fields shared by every API operation."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    recovery_hint: str
    trace_id: str
    details: Any | None = None


class ApiErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ApiErrorDetail


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class LogoutResponse(BaseModel):
    status: Literal["logged_out"] = "logged_out"


class AuthConfigResponse(BaseModel):
    mode: str
    issuer: str | None = None
    client_id: str | None = None
    desktop_client_id: str | None = None
    audience: str | None = None
    admin_role_change_acr: str | None = None


class MeResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    device_id: str
    role: str


class DashboardRecentTaskResponse(BaseModel):
    id: str
    type: str
    status: str
    trace_id: str
    created_at: datetime
    expires_at: datetime | None


class DashboardSummaryResponse(BaseModel):
    scope: Literal["own", "tenant"]
    generated_at: datetime
    today_started_at: datetime
    today_tasks: int = Field(ge=0)
    pending_exceptions: int = Field(ge=0)
    available_cards: int | None = Field(default=None, ge=0)
    today_succeeded_uploads: int = Field(ge=0)
    today_completed_uploads: int = Field(ge=0)
    unavailable_mailboxes: int = Field(ge=0)
    recent_tasks: list[DashboardRecentTaskResponse]
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
    task_type: str
    is_active: bool
    status: Literal["available", "busy", "disabled"]
    health_status: Literal["unknown", "healthy", "unavailable"]
    last_checked_at: datetime | None
    last_error_code: Literal[
        "connector_not_configured", "connector_unavailable"
    ] | None
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


class AdminUserRoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["operator", "ops_admin", "security_auditor", "platform_admin"]


class AdminRoleChangeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    target_user_id: str
    expected_old_role: Literal[
        "operator", "ops_admin", "security_auditor", "platform_admin"
    ]
    new_role: Literal[
        "operator", "ops_admin", "security_auditor", "platform_admin"
    ]
    status: Literal["pending", "applied", "expired"]
    requested_by: str
    approved_by: str | None
    request_trace_id: str
    approval_trace_id: str | None
    created_at: datetime
    expires_at: datetime
    applied_at: datetime | None


class AdminUserBatchDisable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("user_ids")
    @classmethod
    def validate_user_ids(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value or len(value) > 36 for value in normalized):
            raise ValueError("user_ids must contain valid identifiers")
        if len(set(normalized)) != len(normalized):
            raise ValueError("user_ids must be unique")
        return normalized


class AdminDeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class AdminDeviceResponse(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    name: str
    revoked_at: datetime | None
    last_seen_at: datetime | None
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
    pool_key: str
    region: str
    brand: str
    last4: str
    expiry_month: int | None
    expiry_year: int | None
    status: Literal["available", "allocated", "disabled", "quarantined"]
    quarantine_reason_code: str | None
    quarantined_at: datetime | None
    is_active: bool
    created_at: datetime


class PoolImportReceiptResponse(BaseModel):
    id: str
    pool_type: Literal["card", "mailbox"]
    imported_count: int
    trace_id: str
    created_at: datetime


class AdminCardAllocationResponse(BaseModel):
    id: str
    card_id: str
    card_masked: str
    brand: str
    user_id: str
    task_id: str
    device_id: str
    status: str
    allocation_reason_code: str
    expires_at: datetime
    released_at: datetime | None
    release_reason_code: str | None
    trace_id: str
    created_at: datetime


class CardEventMaskedState(TypedDict, total=False):
    card_masked: str
    brand: str
    card_status: Literal["available", "allocated", "disabled", "quarantined"]
    allocation_status: Literal["active", "released", "expired"]
    revealed: bool
    fields: list[Literal["pan", "expiry"]]


class AdminCardEventResponse(BaseModel):
    id: str
    card_id: str
    allocation_id: str | None
    actor_id: str | None
    action: str
    reason_code: str | None
    before_masked: CardEventMaskedState
    after_masked: CardEventMaskedState
    trace_id: str
    created_at: datetime


class AdminCardTimelineResponse(BaseModel):
    card: AdminCardResponse
    allocations: list[AdminCardAllocationResponse]
    events: list[AdminCardEventResponse]
    allocations_has_more: bool
    events_has_more: bool
    allocations_next_cursor: str | None
    events_next_cursor: str | None


class AdminCardRecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")


def _normalize_opaque_secret_ref(
    value: str,
    *,
    vault_prefix: str,
    env_prefix: str,
) -> str:
    normalized = value.strip()
    if re.fullmatch(r"(?:vault|env)://[A-Za-z0-9][A-Za-z0-9._/-]*", normalized) is None:
        raise ValueError("secret_ref must be an opaque vault:// or env:// reference")
    path = normalized.split("://", maxsplit=1)[1]
    if any(segment in {"", ".", ".."} for segment in path.split("/")):
        raise ValueError("secret_ref path must not contain empty, dot, or parent segments")
    if normalized.startswith("vault://") and not normalized.startswith(vault_prefix):
        raise ValueError(f"secret_ref must use the {vault_prefix} namespace")
    if normalized.startswith("env://") and not normalized.startswith(env_prefix):
        raise ValueError(f"development secret_ref must use the {env_prefix} namespace")
    return normalized


def _contains_pan_like_digits(value: str) -> bool:
    for candidate in re.split(r"[A-Za-z]+", value):
        digit_count = len(re.sub(r"\D", "", candidate))
        if 12 <= digit_count <= 19:
            return True
    return False


class AdminCardCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
    pool_key: str = Field(
        default="legacy-unclassified", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$"
    )
    region: str = Field(
        default="legacy-unclassified", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$"
    )
    brand: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
    last4: str = Field(pattern=r"^\d{4}$")
    expiry_month: int | None = Field(default=None, ge=1, le=12)
    expiry_year: int | None = Field(default=None, ge=2000, le=9999)
    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("provider_ref", "brand", mode="before")
    @classmethod
    def normalize_card_text(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty")
        if _contains_pan_like_digits(normalized):
            raise ValueError("provider_ref and brand must not contain a PAN")
        return normalized

    @field_validator("pool_key", "region", mode="before")
    @classmethod
    def normalize_routing_text(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(
            value,
            vault_prefix="vault://secret/cards/",
            env_prefix="env://CARD_",
        )

    @model_validator(mode="after")
    def validate_expiry_pair(self) -> "AdminCardCreate":
        if (self.expiry_month is None) != (self.expiry_year is None):
            raise ValueError("expiry_month and expiry_year must be provided together")
        return self


class AdminCardImportItem(BaseModel):
    """Secret-free card metadata emitted by the trusted Vault importer."""

    model_config = ConfigDict(extra="forbid")

    provider_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
    pool_key: str = Field(
        default="legacy-unclassified", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$"
    )
    region: str = Field(
        default="legacy-unclassified", pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$"
    )
    brand: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
    last4: str = Field(pattern=r"^\d{4}$")
    expiry_month: int | None = Field(default=None, ge=1, le=12)
    expiry_year: int | None = Field(default=None, ge=2000, le=9999)

    @field_validator("provider_ref", "brand", mode="before")
    @classmethod
    def normalize_card_text(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        if not normalized or _contains_pan_like_digits(normalized):
            raise ValueError("card metadata must not contain a PAN")
        return normalized

    @field_validator("pool_key", "region", mode="before")
    @classmethod
    def normalize_routing_text(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_expiry_pair(self) -> "AdminCardImportItem":
        if (self.expiry_month is None) != (self.expiry_year is None):
            raise ValueError("expiry_month and expiry_year must be provided together")
        return self


class AdminCardStateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class AdminCardQuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")


class AdminMailboxCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_masked: str = Field(min_length=3, max_length=320)
    connector_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")
    task_type: str = Field(
        default="mail_code", pattern=r"^[a-z][a-z0-9_-]{0,79}$"
    )
    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("email_masked")
    @classmethod
    def validate_masked_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "*" not in normalized:
            raise ValueError("email_masked must contain a masked email address")
        return normalized

    @field_validator("connector_type", "task_type")
    @classmethod
    def normalize_connector_type(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(
            value,
            vault_prefix="vault://secret/mailboxes/",
            env_prefix="env://MAILBOX_",
        )


class AdminMailboxImportItem(BaseModel):
    """Secret-free mailbox metadata emitted by the trusted Vault importer."""

    model_config = ConfigDict(extra="forbid")

    email_masked: str = Field(min_length=3, max_length=320)
    connector_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")
    task_type: str = Field(
        default="mail_code", pattern=r"^[a-z][a-z0-9_-]{0,79}$"
    )

    @field_validator("email_masked")
    @classmethod
    def validate_masked_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "*" not in normalized:
            raise ValueError("email_masked must contain a masked email address")
        return normalized

    @field_validator("connector_type", "task_type")
    @classmethod
    def normalize_connector_type(cls, value: str) -> str:
        return value.strip().lower()


class AdminMailboxStateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class AdminMailboxSecretRotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_ref: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return _normalize_opaque_secret_ref(
            value,
            vault_prefix="vault://secret/mailboxes/",
            env_prefix="env://MAILBOX_",
        )


class AdminUploadResponse(BaseModel):
    id: str
    tenant_id: str
    task_id: str
    user_id: str
    device_id: str
    card_allocation_id: str
    status: str
    phase: str
    phase_sequence: int
    phase_updated_at: datetime
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


class OperationalPolicyStatusResponse(BaseModel):
    domain: Literal["mail", "card"]
    governance_configured: bool
    active_version: str | None
    previous_version: str | None
    rollout_percent: int | None


class OperationalPolicyDeployRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rollout_percent: int = Field(ge=1, le=100)


class MailPolicyVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    change_note: str = Field(min_length=1, max_length=500)
    session_ttl_seconds: int = Field(ge=60, le=3_600)
    code_ttl_seconds: int = Field(ge=30, le=300)
    poll_interval_seconds: int = Field(ge=1, le=60)


class CardSelectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")
    pool_key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    region: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    brands: list[str] = Field(default_factory=list, max_length=20)
    minimum_validity_days: int = Field(default=0, ge=0, le=3_650)
    allocation_order: Literal["oldest_available", "expiry_soonest"] = (
        "oldest_available"
    )

    @field_validator("task_type", "pool_key", "region", mode="before")
    @classmethod
    def normalize_rule_key(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("brands", mode="after")
    @classmethod
    def normalize_brands(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            brand = value.strip().upper()
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9 ._-]{0,39}", brand):
                raise ValueError("brand is invalid")
            if brand not in normalized:
                normalized.append(brand)
        return normalized


class CardPolicyVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    change_note: str = Field(min_length=1, max_length=500)
    lease_ttl_seconds: int = Field(ge=60, le=86_400)
    reveal_ttl_seconds: int = Field(ge=30, le=300)
    allocation_order: Literal["oldest_available"] = "oldest_available"
    selection_rules: list[CardSelectionRule] = Field(
        default_factory=lambda: [
            CardSelectionRule(
                task_type="card_checkout",
                pool_key="legacy-unclassified",
                region="legacy-unclassified",
            )
        ],
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_unique_task_types(self) -> "CardPolicyVersionCreate":
        task_types = [rule.task_type for rule in self.selection_rules]
        if len(task_types) != len(set(task_types)):
            raise ValueError("selection_rules must contain one rule per task_type")
        return self


class OperationalPolicyVersionBaseResponse(BaseModel):
    id: str
    version: str
    status: Literal["draft", "approved", "active", "retired"]
    change_note: str
    created_by: str
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime


class MailPolicyVersionResponse(OperationalPolicyVersionBaseResponse):
    session_ttl_seconds: int
    code_ttl_seconds: int
    poll_interval_seconds: int


class CardPolicyVersionResponse(OperationalPolicyVersionBaseResponse):
    lease_ttl_seconds: int
    reveal_ttl_seconds: int
    allocation_order: Literal["oldest_available"]
    selection_rules: list[CardSelectionRule]


class OperationalPolicyDeploymentResponse(BaseModel):
    domain: Literal["mail", "card"]
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


class TaskTimelineEventResponse(BaseModel):
    id: str
    event_type: str
    action: str
    result: str
    entity_type: str
    entity_id: str | None
    trace_id: str
    policy_version: str | None
    phase: str | None = None
    phase_sequence: int | None = None
    created_at: datetime


class TaskTimelineMailSessionResponse(BaseModel):
    id: str
    email_masked: str
    status: str
    expires_at: datetime
    consumed_at: datetime | None
    created_at: datetime


class TaskTimelineCardAllocationResponse(BaseModel):
    id: str
    card_masked: str
    brand: str
    status: str
    expires_at: datetime
    released_at: datetime | None
    created_at: datetime


class TaskTimelineUploadResponse(BaseModel):
    id: str
    business_name: str
    status: str
    trace_id: str
    phase: str
    phase_sequence: int
    phase_updated_at: datetime
    policy_version: str
    external_ref: str | None
    error_code: str | None
    created_at: datetime
    updated_at: datetime


class TaskTimelineResponse(BaseModel):
    task: TaskResponse
    workbench_step: Literal[
        "logged_in",
        "card_allocated",
        "waiting_code",
        "code_received",
        "uploading",
        "completed",
    ]
    mail_session: TaskTimelineMailSessionResponse | None
    card_allocations: list[TaskTimelineCardAllocationResponse]
    uploads: list[TaskTimelineUploadResponse]
    events: list[TaskTimelineEventResponse]


class MailSessionResponse(BaseModel):
    id: str
    trace_id: str
    email_masked: str
    status: str
    expires_at: datetime


class MailSessionCreateRequest(BaseModel):
    """An intentionally empty operator contract; routing is server-owned."""

    model_config = ConfigDict(extra="forbid")


class MailSessionCreateResponse(MailSessionResponse):
    session_token: str = Field(min_length=32, max_length=128, repr=False)
    polling_interval: int = Field(ge=1, le=60)


class MailCodeResponse(BaseModel):
    status: str
    code: str | None = None
    received_at: datetime | None = None
    message_id_hash: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def validate_code_metadata_pair(self) -> "MailCodeResponse":
        has_code = self.code is not None
        has_received_at = self.received_at is not None
        has_message_id_hash = self.message_id_hash is not None
        if len({has_code, has_received_at, has_message_id_hash}) != 1:
            raise ValueError(
                "code, received_at, and message_id_hash must be provided together"
            )
        if has_code and self.status != "consumed":
            raise ValueError("mail code metadata requires consumed status")
        if (
            self.received_at is not None
            and (
                self.received_at.tzinfo is None
                or self.received_at.utcoffset() is None
            )
        ):
            raise ValueError("received_at must include a timezone")
        return self

    @model_serializer(mode="wrap")
    def serialize_optional_metadata(self, handler: Any):
        data = handler(self)
        if self.received_at is None:
            data.pop("received_at", None)
            data.pop("message_id_hash", None)
        return data


class CardAllocationResponse(BaseModel):
    id: str
    trace_id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    status: str
    allocation_reason_code: str
    expires_at: datetime


class CardRevealResponse(BaseModel):
    id: str
    allocation_id: str
    trace_id: str
    card_masked: str
    brand: str
    expiry_month: int | None
    expiry_year: int | None
    pan: str | None = None
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
    phase: str
    phase_sequence: int
    phase_updated_at: datetime
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
    external_ref: str | None = Field(
        default=None,
        max_length=160,
        pattern=EXTERNAL_REF_PATTERN,
    )
    error_code: str | None = Field(
        default=None,
        max_length=80,
        pattern=r"^[a-z][a-z0-9_]{0,79}$",
    )

    @field_validator("external_ref", "error_code", mode="before")
    @classmethod
    def normalize_optional_upload_value(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_result_fields(self) -> "UploadReconcileRequest":
        if self.status == "succeeded":
            if self.external_ref is None:
                raise ValueError("external_ref is required for succeeded reconciliation")
            if self.error_code is not None:
                raise ValueError("error_code is not allowed for succeeded reconciliation")
        elif self.external_ref is not None:
            raise ValueError("external_ref is only allowed for succeeded reconciliation")
        return self
