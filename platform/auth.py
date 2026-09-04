"""Password hashing, short-lived HS256 JWTs, and the shared auth dependency."""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

import jwt
from jwt import PyJWKClient

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from platform.database import get_db
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.models import Device, RevokedAccessToken, RevokedOidcSession, User
from platform.secrets import create_internal_tls_context


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
INTERACTIVE_ROLES = frozenset(
    {
        ROLE_OPERATOR,
        ROLE_OPS_ADMIN,
        ROLE_SECURITY_AUDITOR,
        ROLE_PLATFORM_ADMIN,
    }
)


_PASSWORD_ITERATIONS = 210_000
# A fixed non-account hash keeps unknown local-login attempts on the same dominant
# password-verification path as known accounts without creating startup work.
DUMMY_PASSWORD_HASH = (
    "pbkdf2_sha256$210000$bG9jYWwtbG9naW4tZHVtbXk$"
    "w9GNWj28W6GubetFqiIi4zEZ1zlE6avwxY4ZCORdy-U"
)
_DEVICE_LAST_SEEN_INTERVAL = timedelta(seconds=60)
_OIDC_SESSION_HASH_DOMAIN = b"email-platform|oidc-session-v1\0"
_MAX_ACCESS_TOKEN_CHARS = 8 * 1024
_MAX_JWT_HEADER_BYTES = 2 * 1024
_MAX_JWT_PAYLOAD_BYTES = 6 * 1024
_MAX_JWT_SIGNATURE_BYTES = 1024
_MAX_OIDC_ENDPOINT_CHARS = 2048
_MAX_OIDC_JWKS_BYTES = 64 * 1024
_OIDC_JWKS_CACHE_SECONDS = 300
_OIDC_JWKS_TIMEOUT_SECONDS = 10
_bearer_scheme = HTTPBearer(auto_error=False)


def _validated_oidc_url(value: str) -> urllib.parse.SplitResult:
    try:
        if (
            type(value) is not str
            or not value
            or len(value) > _MAX_OIDC_ENDPOINT_CHARS
            or value != value.strip()
            or "\\" in value
            or any(
                ord(character) <= 0x20 or ord(character) == 0x7F
                for character in value
            )
        ):
            raise ValueError
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        if hostname is None or not hostname.rstrip("."):
            raise ValueError
        hostname.rstrip(".").encode("idna")
        parsed.port
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
    except (AttributeError, UnicodeError, ValueError):
        raise ValueError("OIDC endpoint configuration is invalid") from None
    return parsed


def validate_oidc_endpoint_pair(issuer: str, jwks_url: str) -> None:
    """Validate the reviewed Keycloak issuer/JWKS relationship exactly."""

    _validated_oidc_url(issuer)
    _validated_oidc_url(jwks_url)
    issuer_base = issuer[:-1] if issuer.endswith("/") else issuer
    expected_jwks_url = f"{issuer_base}/protocol/openid-connect/certs"
    if jwks_url != expected_jwks_url:
        raise ValueError("OIDC endpoint configuration is invalid") from None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


class _ControlledOidcJwksClient(PyJWKClient):
    def __init__(
        self,
        uri: str,
        *,
        ssl_context: Any,
    ) -> None:
        super().__init__(
            uri,
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=_OIDC_JWKS_CACHE_SECONDS,
            timeout=_OIDC_JWKS_TIMEOUT_SECONDS,
            ssl_context=ssl_context,
        )
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def fetch_data(self) -> dict[str, object]:
        try:
            request = urllib.request.Request(url=self.uri, headers=self.headers)
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_OIDC_JWKS_BYTES + 1)
            if type(raw) is not bytes or len(raw) > _MAX_OIDC_JWKS_BYTES:
                raise JsonBoundaryError("invalid JSON")
            jwk_set = parse_unique_json_bytes(raw)
            if not isinstance(jwk_set, dict):
                raise JsonBoundaryError("invalid JSON")
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise jwt.PyJWKClientConnectionError(
                "OIDC JWKS endpoint is unavailable or invalid"
            ) from None

        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        return jwk_set


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _decode_compact_jwt_segment(value: str, *, max_bytes: int) -> bytes:
    max_chars = (max_bytes * 8 + 5) // 6
    if not value or len(value) > max_chars or "=" in value:
        raise ValueError("Invalid compact JWT segment")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeError, binascii.Error):
        raise ValueError("Invalid compact JWT segment") from None
    if len(decoded) > max_bytes or _b64url_encode(decoded) != value:
        raise ValueError("Invalid compact JWT segment")
    return decoded


def _preflight_compact_access_token(
    token: str,
) -> tuple[str, str, bytes, dict[str, Any], dict[str, Any]]:
    if type(token) is not str or not token or len(token) > _MAX_ACCESS_TOKEN_CHARS:
        raise ValueError("Invalid compact JWT")
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError:
        raise ValueError("Invalid compact JWT") from None
    raw_header = _decode_compact_jwt_segment(
        encoded_header, max_bytes=_MAX_JWT_HEADER_BYTES
    )
    raw_payload = _decode_compact_jwt_segment(
        encoded_payload, max_bytes=_MAX_JWT_PAYLOAD_BYTES
    )
    signature = _decode_compact_jwt_segment(
        encoded_signature, max_bytes=_MAX_JWT_SIGNATURE_BYTES
    )
    try:
        header = parse_unique_json_bytes(raw_header)
        payload = parse_unique_json_bytes(raw_payload)
    except JsonBoundaryError:
        raise ValueError("Invalid compact JWT JSON") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Invalid compact JWT JSON")
    return encoded_header, encoded_payload, signature, header, payload


def _validated_oidc_sid(claims: dict[str, Any]) -> str | None:
    raw_sid = claims.get("sid")
    if raw_sid is None:
        return None
    if (
        not isinstance(raw_sid, str)
        or not raw_sid
        or len(raw_sid) > 255
        or raw_sid != raw_sid.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_sid)
    ):
        raise ValueError("Invalid sid claim")
    return raw_sid


def _oidc_session_fingerprint(claims: dict[str, Any]) -> str | None:
    if claims.get("identity_kind") != "oidc":
        return None
    sid = _validated_oidc_sid(claims)
    if sid is None:
        return None
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("Missing issuer claim for OIDC session")
    digest = hashlib.sha256()
    digest.update(_OIDC_SESSION_HASH_DOMAIN)
    digest.update(issuer.encode("utf-8"))
    digest.update(b"\0")
    digest.update(sid.encode("utf-8"))
    return digest.hexdigest()


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
    auth_time: datetime | None = None,
    acr: str = "urn:email-platform:acr:password",
    amr: tuple[str, ...] = ("pwd",),
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
        "auth_time": int((auth_time or issued_at).timestamp()),
        "acr": acr,
        "amr": list(amr),
        "jti": secrets.token_urlsafe(24),
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
        encoded_header, encoded_payload, signature, header, payload = (
            _preflight_compact_access_token(token)
        )
        unsigned = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(
            secret.encode(), unsigned.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid signature")
        if header.get("alg") != "HS256":
            raise ValueError("Unsupported algorithm")
        required = ("sub", "tenant_id", "device_id", "jti", "exp")
        if any(not payload.get(name) for name in required):
            raise ValueError("Missing claim")
        if int(payload["exp"]) <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Expired token")
        return payload
    except (ValueError, TypeError, KeyError):
        raise ValueError("Invalid access token") from None


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
        allowed_client_ids: tuple[str, ...],
        internal_ca_file: str | None = None,
        tenant_claim: str = "tenant_id",
        device_claim: str = "device_id",
    ) -> None:
        validate_oidc_endpoint_pair(issuer, jwks_url)
        if type(allowed_client_ids) is not tuple or not allowed_client_ids:
            raise ValueError("OIDC allowed client IDs must be a non-empty tuple")
        client_ids = allowed_client_ids
        if any(
            type(client_id) is not str
            or not client_id
            or len(client_id) > 255
            or client_id != client_id.strip()
            for client_id in client_ids
        ):
            raise ValueError("OIDC allowed client IDs must be exact non-empty strings")
        if len(set(client_ids)) != len(client_ids):
            raise ValueError("OIDC allowed client IDs must be unique")
        self.issuer = issuer
        self.audience = audience
        self.allowed_client_ids = frozenset(client_ids)
        self.tenant_claim = tenant_claim
        self.device_claim = device_claim
        ssl_context = None
        if internal_ca_file:
            try:
                ssl_context = create_internal_tls_context(internal_ca_file)
            except ValueError:
                raise ValueError(
                    "OIDC TLS trust is unavailable or invalid"
                ) from None
        self.jwks_client = _ControlledOidcJwksClient(
            jwks_url,
            ssl_context=ssl_context,
        )

    def verify(self, token: str) -> dict[str, Any]:
        try:
            _preflight_compact_access_token(token)
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub", "jti", "azp"]
                },
            )
            authorized_party = claims.get("azp")
            if (
                type(authorized_party) is not str
                or authorized_party not in self.allowed_client_ids
            ):
                raise ValueError("Invalid authorized party claim")
            tenant_id = claims.get(self.tenant_claim)
            device_id = claims.get(self.device_claim)
            if not isinstance(tenant_id, str) or not tenant_id:
                raise ValueError("Missing tenant claim")
            if not isinstance(device_id, str) or not device_id:
                raise ValueError("Missing device claim")
            jti = claims.get("jti")
            if not isinstance(jti, str) or len(jti) < 16:
                raise ValueError("Invalid jti claim")
            _validated_oidc_sid(claims)
            return {
                **claims,
                "tenant_id": tenant_id,
                "device_id": device_id,
                "identity_kind": "oidc",
            }
        except (jwt.PyJWTError, ValueError):
            raise ValueError("Invalid OIDC access token") from None


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: str
    tenant_id: str
    device_id: str
    email: str
    role: str
    identity_kind: str
    auth_time: datetime | None
    acr: str | None
    amr: tuple[str, ...]
    access_token_hash: str
    access_token_expires_at: datetime
    access_token_revoked: bool
    oidc_session_hash: str | None = None
    oidc_session_revoked: bool = False


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Authentication required or no longer valid",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _touch_device_last_seen(
    request: Request,
    *,
    tenant_id: str,
    user_id: str,
    device_id: str,
    observed_at: datetime,
) -> None:
    """Persist throttled activity without committing a route's DB session."""

    cutoff = observed_at - _DEVICE_LAST_SEEN_INTERVAL
    try:
        with request.app.state.session_factory.begin() as activity_db:
            activity_db.execute(
                update(Device)
                .where(
                    Device.id == device_id,
                    Device.tenant_id == tenant_id,
                    Device.user_id == user_id,
                    Device.revoked_at.is_(None),
                    or_(
                        Device.last_seen_at.is_(None),
                        Device.last_seen_at <= cutoff,
                    ),
                )
                .values(last_seen_at=observed_at)
            )
    except SQLAlchemyError:
        # Activity telemetry must not turn a valid authenticated request into
        # a failure when the independent best-effort write is contended.
        return


def _resolve_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    db: Session,
    *,
    allow_revoked: bool,
    touch_last_seen: bool,
) -> AuthPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()
    try:
        claims = request.app.state.access_token_verifier.verify(credentials.credentials)
        oidc_session_hash = _oidc_session_fingerprint(claims)
    except ValueError:
        raise unauthorized() from None

    observed_at = datetime.now(timezone.utc)
    token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
    token_revoked = db.scalar(
        select(RevokedAccessToken.token_hash).where(
            RevokedAccessToken.token_hash == token_hash,
            RevokedAccessToken.expires_at > observed_at,
        )
    ) is not None
    oidc_session_revoked = False
    if oidc_session_hash is not None:
        oidc_session_revoked = db.scalar(
            select(RevokedOidcSession.session_hash).where(
                RevokedOidcSession.session_hash == oidc_session_hash,
                or_(
                    RevokedOidcSession.expires_at.is_(None),
                    RevokedOidcSession.expires_at > observed_at,
                ),
            )
        ) is not None
    if (token_revoked or oidc_session_revoked) and not allow_revoked:
        raise unauthorized()

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
    if (
        user is None
        or device is None
        or user.role not in INTERACTIVE_ROLES
    ):
        raise unauthorized()
    if touch_last_seen and not token_revoked and not oidc_session_revoked:
        _touch_device_last_seen(
            request,
            tenant_id=user.tenant_id,
            user_id=user.id,
            device_id=device.id,
            observed_at=observed_at,
        )
    auth_time: datetime | None = None
    raw_auth_time = claims.get("auth_time")
    if isinstance(raw_auth_time, (int, float)) and not isinstance(raw_auth_time, bool):
        try:
            auth_time = datetime.fromtimestamp(raw_auth_time, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            auth_time = None
    raw_acr = claims.get("acr")
    acr = raw_acr if isinstance(raw_acr, str) and raw_acr else None
    raw_amr = claims.get("amr")
    amr = (
        tuple(value for value in raw_amr if isinstance(value, str) and value)
        if isinstance(raw_amr, list)
        else ()
    )
    raw_exp = claims.get("exp")
    try:
        access_token_expires_at = datetime.fromtimestamp(
            int(raw_exp), tz=timezone.utc
        )
    except (OverflowError, OSError, TypeError, ValueError):
        # Injected test verifiers may omit exp. Real local/OIDC verifiers require it.
        access_token_expires_at = observed_at + timedelta(
            seconds=request.app.state.settings.access_token_ttl_seconds
        )
    return AuthPrincipal(
        user_id=user.id,
        tenant_id=user.tenant_id,
        device_id=device.id,
        email=user.email,
        role=user.role,
        identity_kind=str(claims.get("identity_kind") or "unknown"),
        auth_time=auth_time,
        acr=acr,
        amr=amr,
        access_token_hash=token_hash,
        access_token_expires_at=access_token_expires_at,
        access_token_revoked=token_revoked,
        oidc_session_hash=oidc_session_hash,
        oidc_session_revoked=oidc_session_revoked,
    )


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    return _resolve_principal(
        request,
        credentials,
        db,
        allow_revoked=False,
        touch_last_seen=True,
    )


def get_logout_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    """Authenticate logout retries without re-enabling a revoked bearer token."""

    return _resolve_principal(
        request,
        credentials,
        db,
        allow_revoked=True,
        touch_last_seen=False,
    )


def get_interactive_principal(
    principal: AuthPrincipal = Depends(get_current_principal),
) -> AuthPrincipal:
    """Allow only human identities on interactive API surfaces."""

    if principal.role not in INTERACTIVE_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return principal


def get_operator_principal(
    principal: AuthPrincipal = Depends(get_current_principal),
) -> AuthPrincipal:
    """Allow only operators to access owner-bound business resources."""

    if principal.role != ROLE_OPERATOR:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return principal


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
