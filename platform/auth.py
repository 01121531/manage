"""Password hashing, short-lived HS256 JWTs, and the shared auth dependency."""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

import jwt
from jwt import PyJWKClient

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from platform.database import get_db
from platform.models import Device, User


ROLE_OPERATOR = "operator"
ROLE_OPS_ADMIN = "ops_admin"
ROLE_SECURITY_AUDITOR = "security_auditor"
ROLE_PLATFORM_ADMIN = "platform_admin"
ROLE_WORKER_SERVICE = "worker_service"
USER_ROLES = frozenset(
    {
        ROLE_OPERATOR,
        ROLE_OPS_ADMIN,
        ROLE_SECURITY_AUDITOR,
        ROLE_PLATFORM_ADMIN,
        ROLE_WORKER_SERVICE,
    }
)


_PASSWORD_ITERATIONS = 210_000
_bearer_scheme = HTTPBearer(auto_error=False)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PASSWORD_ITERATIONS
    )
    return "$".join(
        (
            "pbkdf2_sha256",
            str(_PASSWORD_ITERATIONS),
            _b64url_encode(salt),
            _b64url_encode(digest),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _b64url_decode(salt),
            int(iterations),
        )
        return hmac.compare_digest(_b64url_encode(digest), expected)
    except (ValueError, TypeError):
        return False


def create_access_token(
    *,
    secret: str,
    user_id: str,
    tenant_id: str,
    device_id: str,
    ttl_seconds: int,
    role: str = ROLE_OPERATOR,
    now: datetime | None = None,
) -> str:
    issued_at = now or datetime.now(timezone.utc)
    issued_timestamp = int(issued_at.timestamp())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "role": role,
        "iat": issued_timestamp,
        "exp": issued_timestamp + ttl_seconds,
    }
    unsigned = ".".join(
        (
            _b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
        )
    )
    signature = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
    return f"{unsigned}.{_b64url_encode(signature)}"


def decode_access_token(token: str, secret: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        unsigned = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(
            secret.encode(), unsigned.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64url_decode(encoded_signature), expected):
            raise ValueError("Invalid signature")
        header = json.loads(_b64url_decode(encoded_header))
        payload = json.loads(_b64url_decode(encoded_payload))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("Invalid token JSON")
        if header.get("alg") != "HS256":
            raise ValueError("Unsupported algorithm")
        required = ("sub", "tenant_id", "device_id", "exp")
        if any(not payload.get(name) for name in required):
            raise ValueError("Missing claim")
        if int(payload["exp"]) <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Expired token")
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid access token") from exc


class AccessTokenVerifier(Protocol):
    def verify(self, token: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class LocalAccessTokenVerifier:
    secret: str

    def verify(self, token: str) -> dict[str, Any]:
        claims = decode_access_token(token, self.secret)
        claims["identity_kind"] = "local"
        return claims


class OidcAccessTokenVerifier:
    """Validate an OIDC access token against a pinned issuer, audience and JWKS.

    The JWKS client caches signing keys. Only RS256 is accepted; algorithm
    selection is never taken from application configuration or token claims.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        tenant_claim: str = "tenant_id",
        device_claim: str = "device_id",
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.tenant_claim = tenant_claim
        self.device_claim = device_claim
        self.jwks_client = PyJWKClient(jwks_url, cache_keys=True)

    def verify(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            tenant_id = claims.get(self.tenant_claim)
            device_id = claims.get(self.device_claim)
            if not isinstance(tenant_id, str) or not tenant_id:
                raise ValueError("Missing tenant claim")
            if not isinstance(device_id, str) or not device_id:
                raise ValueError("Missing device claim")
            return {
                **claims,
                "tenant_id": tenant_id,
                "device_id": device_id,
                "identity_kind": "oidc",
            }
        except (jwt.PyJWTError, ValueError) as exc:
            raise ValueError("Invalid OIDC access token") from exc


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: str
    tenant_id: str
    device_id: str
    email: str
    role: str


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Authentication required or no longer valid",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()
    try:
        claims = request.app.state.access_token_verifier.verify(credentials.credentials)
    except ValueError:
        raise unauthorized() from None

    identity_filter = (
        User.oidc_subject == claims["sub"]
        if claims.get("identity_kind") == "oidc"
        else User.id == claims["sub"]
    )
    user = db.scalar(
        select(User).where(
            identity_filter,
            User.tenant_id == claims["tenant_id"],
            User.is_active.is_(True),
        )
    )
    device = db.scalar(
        select(Device).where(
            Device.id == claims["device_id"],
            Device.tenant_id == claims["tenant_id"],
            Device.user_id == (user.id if user is not None else ""),
            Device.revoked_at.is_(None),
        )
    )
    if user is None or device is None:
        raise unauthorized()
    return AuthPrincipal(
        user_id=user.id,
        tenant_id=user.tenant_id,
        device_id=device.id,
        email=user.email,
        role=user.role,
    )


def require_roles(*roles: str) -> Callable[..., AuthPrincipal]:
    """Return a FastAPI dependency allowing only the supplied user roles.

    The role is read from the current database-backed principal rather than
    trusted from the JWT claim.  This makes a role change effective without
    waiting for token expiry.  An empty role list is rejected at declaration
    time so an endpoint cannot accidentally become public.
    """

    allowed = frozenset(roles)
    if not allowed or not allowed.issubset(USER_ROLES):
        raise ValueError("require_roles needs one or more known user roles")

    def dependency(
        principal: AuthPrincipal = Depends(get_current_principal),
    ) -> AuthPrincipal:
        if principal.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal

    return dependency
