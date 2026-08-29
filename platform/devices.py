"""Controlled device registration with an active-device quota."""

from dataclasses import dataclass

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from platform.models import Device, User


class DeviceRegistrationError(Exception):
    """Base class for expected device-registration failures."""


class DeviceOwnerNotFoundError(DeviceRegistrationError):
    pass


class DeviceNameRetiredError(DeviceRegistrationError):
    pass


class ActiveDeviceLimitReachedError(DeviceRegistrationError):
    pass


@dataclass(frozen=True)
class DeviceRegistrationResult:
    device: Device
    created: bool


def _lock_owner(db: Session, *, tenant_id: str, user_id: str) -> User | None:
    """Serialize device changes before any device row or active count is read."""

    if db.get_bind().dialect.name == "sqlite":
        claimed = db.execute(
            update(User)
            .where(User.id == user_id, User.tenant_id == tenant_id)
            .values(is_active=User.is_active)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            return None
    return db.scalar(
        select(User)
        .where(User.id == user_id, User.tenant_id == tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def register_device(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    name: str,
    max_active_devices: int,
) -> DeviceRegistrationResult:
    """Create or idempotently reuse one named device without committing."""

    normalized_name = name.strip()
    if not normalized_name or len(normalized_name) > 120:
        raise ValueError("Device name must contain between 1 and 120 characters")
    if (
        isinstance(max_active_devices, bool)
        or not isinstance(max_active_devices, int)
        or max_active_devices < 0
    ):
        raise ValueError("max_active_devices must be a non-negative integer")

    owner = _lock_owner(db, tenant_id=tenant_id, user_id=user_id)
    if owner is None:
        raise DeviceOwnerNotFoundError

    existing = db.scalar(
        select(Device)
        .where(
            Device.tenant_id == tenant_id,
            Device.user_id == user_id,
            Device.name == normalized_name,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if existing is not None:
        if existing.revoked_at is not None:
            raise DeviceNameRetiredError
        return DeviceRegistrationResult(device=existing, created=False)

    active_count = db.scalar(
        select(func.count())
        .select_from(Device)
        .where(
            Device.tenant_id == tenant_id,
            Device.user_id == user_id,
            Device.revoked_at.is_(None),
        )
    )
    if int(active_count or 0) >= max_active_devices:
        raise ActiveDeviceLimitReachedError

    device = Device(
        tenant_id=tenant_id,
        user_id=user_id,
        name=normalized_name,
    )
    db.add(device)
    db.flush()
    return DeviceRegistrationResult(device=device, created=True)


__all__ = [
    "ActiveDeviceLimitReachedError",
    "DeviceNameRetiredError",
    "DeviceOwnerNotFoundError",
    "DeviceRegistrationResult",
    "register_device",
]
