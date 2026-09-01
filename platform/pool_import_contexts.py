"""Target-issued, secret-free authorization for secure pool imports."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from platform.models import PoolImportContext


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


class PoolImportContextInvalid(ValueError):
    pass


class PoolImportContextExpired(ValueError):
    pass


class PoolImportContextBindingMismatch(ValueError):
    pass


class PoolImportContextConsumed(ValueError):
    pass


class PoolImportContextRenewalExpired(ValueError):
    pass


def configured_pool_import_audience(settings: Any) -> str:
    configured = getattr(settings, "pool_import_receipt_audience", None)
    if configured:
        return str(configured).strip()
    environment = str(getattr(settings, "environment", "development")).strip().lower()
    return f"email-platform:pool-import:{environment}"


def pool_import_context_token_hash(token: str) -> str:
    if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
        raise PoolImportContextInvalid("Secure import context is invalid")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def renew_pool_import_context(
    db: Session,
    token: str,
    *,
    tenant_id: str,
    user_id: str,
    device_id: str,
    audience: str,
    ttl_seconds: int,
    renewal_window_seconds: int,
    now: datetime,
) -> PoolImportContext:
    """Extend one caller-bound context without rotating its retry token."""

    token_hash = pool_import_context_token_hash(token)
    context = db.scalar(
        select(PoolImportContext)
        .where(PoolImportContext.context_token_hash == token_hash)
        .with_for_update()
    )
    if context is None:
        raise PoolImportContextInvalid("Secure import context is invalid")
    if context.consumed_at is not None or context.pool_import_receipt_id is not None:
        raise PoolImportContextConsumed("Secure import context was already consumed")
    if (
        context.tenant_id != tenant_id
        or context.created_by != user_id
        or context.device_id != device_id
        or context.audience != audience
    ):
        raise PoolImportContextBindingMismatch(
            "Secure import context does not match this caller"
        )
    current = _aware_utc(now)
    renewal_deadline = _aware_utc(context.created_at) + timedelta(
        seconds=renewal_window_seconds
    )
    if renewal_deadline <= current:
        raise PoolImportContextRenewalExpired(
            "Secure import context renewal window has expired"
        )
    context.expires_at = min(
        current + timedelta(seconds=ttl_seconds),
        renewal_deadline,
    )
    return context


class PoolImportContextVerifier(Protocol):
    def verify(
        self,
        db: Session,
        token: str,
        *,
        tenant_id: str,
        user_id: str,
        device_id: str,
        audience: str,
        pool_type: str,
        ordered_manifest_digest: str,
        item_count: int,
        receipt_id: str,
    ) -> PoolImportContext | None: ...


class DatabasePoolImportContextVerifier:
    def __init__(self, *, clock: Any | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def verify(
        self,
        db: Session,
        token: str,
        *,
        tenant_id: str,
        user_id: str,
        device_id: str,
        audience: str,
        pool_type: str,
        ordered_manifest_digest: str,
        item_count: int,
        receipt_id: str,
    ) -> PoolImportContext:
        token_hash = pool_import_context_token_hash(token)
        context = db.scalar(
            select(PoolImportContext)
            .where(PoolImportContext.context_token_hash == token_hash)
            .with_for_update()
        )
        if context is None:
            raise PoolImportContextInvalid("Secure import context is invalid")
        expires_at = _aware_utc(context.expires_at)
        if expires_at <= self._clock():
            raise PoolImportContextExpired("Secure import context has expired")
        if context.consumed_at is not None or context.pool_import_receipt_id is not None:
            raise PoolImportContextConsumed("Secure import context was already consumed")
        if (
            context.id != receipt_id
            or context.tenant_id != tenant_id
            or context.created_by != user_id
            or context.device_id != device_id
            or context.audience != audience
            or context.pool_type != pool_type
            or context.ordered_manifest_digest != ordered_manifest_digest
            or context.item_count != item_count
        ):
            raise PoolImportContextBindingMismatch(
                "Secure import context does not match this import"
            )
        return context
