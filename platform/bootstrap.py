"""Explicit CLI for creating the first platform user and bound device."""

import argparse
import getpass
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from platform.audit import record_audit
from platform.auth import USER_ROLES, hash_password
from platform.card_events import record_card_event
from platform.config import Settings
from platform.database import initialize_database
from platform.devices import register_device
from platform.models import Card, User, new_id


@dataclass(frozen=True)
class BootstrapIdentity:
    user_id: str
    device_id: str


@dataclass(frozen=True)
class ProvisionedCard:
    card_id: str
    provider_ref: str


def create_oidc_user_with_device(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
    email: str,
    oidc_subject: str,
    device_name: str,
    role: str = "operator",
    max_active_devices_per_user: int = 5,
) -> BootstrapIdentity:
    """Pre-provision a Keycloak identity without storing a platform password."""

    normalized_role = role.strip().lower()
    if normalized_role not in USER_ROLES:
        raise ValueError(f"Unsupported user role: {role}")
    if not oidc_subject.strip():
        raise ValueError("oidc_subject is required")
    with session_factory() as db:
        user = User(
            tenant_id=tenant_id.strip(),
            email=email.strip().lower(),
            password_hash=None,
            oidc_subject=oidc_subject.strip(),
            role=normalized_role,
        )
        db.add(user)
        db.flush()
        registration = register_device(
            db,
            tenant_id=user.tenant_id,
            user_id=user.id,
            name=device_name.strip(),
            max_active_devices=max_active_devices_per_user,
        )
        db.commit()
        return BootstrapIdentity(user_id=user.id, device_id=registration.device.id)


def create_user_with_device(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
    email: str,
    password: str,
    device_name: str,
    role: str = "operator",
    max_active_devices_per_user: int = 5,
) -> BootstrapIdentity:
    """Create one identity explicitly; there are deliberately no defaults."""

    normalized_email = email.strip().lower()
    normalized_role = role.strip().lower()
    if normalized_role not in USER_ROLES:
        raise ValueError(f"Unsupported user role: {role}")
    with session_factory() as db:
        if db.scalar(
            select(User).where(
                User.tenant_id == tenant_id, User.email == normalized_email
            )
        ):
            raise ValueError("A user with this tenant and email already exists")
        user = User(
            tenant_id=tenant_id,
            email=normalized_email,
            password_hash=hash_password(password),
            role=normalized_role,
        )
        db.add(user)
        db.flush()
        registration = register_device(
            db,
            tenant_id=tenant_id,
            user_id=user.id,
            name=device_name,
            max_active_devices=max_active_devices_per_user,
        )
        db.commit()
        return BootstrapIdentity(user_id=user.id, device_id=registration.device.id)


def provision_card(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
    provider_ref: str,
    brand: str,
    last4: str,
    secret_ref: str,
    expiry_month: int | None = None,
    expiry_year: int | None = None,
) -> ProvisionedCard:
    """Register a card reference without accepting PAN/CVV material.

    ``secret_ref`` must point to a server-side secret manager entry. The raw
    card number and security code deliberately have no parameter in this API.
    """

    normalized_last4 = last4.strip()
    if len(normalized_last4) != 4 or not normalized_last4.isdigit():
        raise ValueError("last4 must contain exactly four digits")
    if not secret_ref.strip():
        raise ValueError("secret_ref is required")
    with session_factory() as db:
        card = Card(
            tenant_id=tenant_id.strip(),
            provider_ref=provider_ref.strip(),
            brand=brand.strip(),
            last4=normalized_last4,
            expiry_month=expiry_month,
            expiry_year=expiry_year,
            secret_ref=secret_ref.strip(),
        )
        db.add(card)
        db.flush()
        trace_id = new_id()
        actor_id = "platform-bootstrap"
        record_audit(
            db,
            tenant_id=card.tenant_id,
            user_id=None,
            device_id=None,
            actor_id=actor_id,
            event_type="admin.card_created",
            entity_type="card",
            entity_id=card.id,
            trace_id=trace_id,
            details={
                "provider_ref": card.provider_ref,
                "brand": card.brand,
                "last4": card.last4,
            },
        )
        record_card_event(
            db,
            tenant_id=card.tenant_id,
            card_id=card.id,
            actor_id=actor_id,
            action="card.created",
            trace_id=trace_id,
            after_masked={
                "card_masked": f"**** **** **** {card.last4}",
                "brand": card.brand,
                "card_status": "available",
            },
        )
        db.commit()
        return ProvisionedCard(card_id=card.id, provider_ref=card.provider_ref)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create an initial platform user and device"
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--device-name", required=True)
    parser.add_argument(
        "--oidc-subject",
        help="Keycloak subject for production OIDC provisioning; omits local password storage",
    )
    parser.add_argument(
        "--role",
        choices=sorted(USER_ROLES),
        default="operator",
        help="Initial user role (no password is stored or supplied by default)",
    )
    args = parser.parse_args()
    settings = Settings()
    managed_environment = settings.environment.strip().lower() not in {
        "development",
        "test",
    }
    _, session_factory = initialize_database(
        settings.resolved_database_url(require_file=managed_environment)
    )
    if args.oidc_subject:
        identity = create_oidc_user_with_device(
            session_factory,
            tenant_id=args.tenant_id,
            email=args.email,
            oidc_subject=args.oidc_subject,
            device_name=args.device_name,
            role=args.role,
            max_active_devices_per_user=settings.max_active_devices_per_user,
        )
    else:
        if settings.auth_mode.strip().lower() != "local":
            raise SystemExit("--oidc-subject is required when PLATFORM_AUTH_MODE=oidc")
        password = getpass.getpass("Platform account password (minimum 12 characters): ")
        identity = create_user_with_device(
            session_factory,
            tenant_id=args.tenant_id,
            email=args.email,
            password=password,
            device_name=args.device_name,
            role=args.role,
            max_active_devices_per_user=settings.max_active_devices_per_user,
        )
    print(f"user_id={identity.user_id}")
    print(f"device_id={identity.device_id}")


if __name__ == "__main__":
    main()
