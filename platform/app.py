"""FastAPI application factory for the platform backend."""

import secrets
import time
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from platform import __version__
from platform.api.v1.routes import router as v1_router
from platform.cards import CardSecretResolver, SecretCardSecretResolver
from platform.config import Settings, get_settings
from platform.database import database_schema_is_current, initialize_database
from platform.errors import http_exception_handler, validation_exception_handler
from platform.auth import AccessTokenVerifier, LocalAccessTokenVerifier, OidcAccessTokenVerifier
from platform.middleware import (
    OriginPolicyMiddleware,
    TraceAndErrorMiddleware,
    parse_allowed_origins,
)
from platform.metrics import MetricsRegistry
from platform.mail_connectors import HttpMailConnector, MailConnector
from platform.rate_limit import (
    RateLimitBackend,
    RateLimitMiddleware,
    RedisRateLimitBackend,
)
from platform.secrets import SecretResolver, secret_resolver_from_settings
from platform.pool_imports import (
    PoolImportReceiptVerifier,
    pool_import_receipt_verifier_from_settings,
)
from platform.pool_import_contexts import (
    DatabasePoolImportContextVerifier,
    PoolImportContextVerifier,
    configured_pool_import_audience,
)
from platform.uploads import (
    Sub2Adapter,
    Sub2Policy,
    UnconfiguredSub2Adapter,
    upload_job_status_counts,
)

# Import model declarations before creating tables.
from platform import models as _models  # noqa: F401


def create_app(
    settings: Settings | None = None,
    *,
    service_role: str = "api",
    mail_connectors: Mapping[str, MailConnector] | None = None,
    sub2_adapter: Sub2Adapter | None = None,
    card_secret_resolver: CardSecretResolver | None = None,
    secret_resolver: SecretResolver | None = None,
    pool_import_receipt_verifier: PoolImportReceiptVerifier | None = None,
    pool_import_context_verifier: PoolImportContextVerifier | None = None,
    access_token_verifier: AccessTokenVerifier | None = None,
    rate_limit_backend: RateLimitBackend | None = None,
    rate_limit_clock: Callable[[], float] = time.time,
) -> FastAPI:
    """Create a configured FastAPI application.

    ``settings`` is injectable for tests. Production runs use the factory
    entry point (`uvicorn platform.app:create_app --factory`) so importing the
    module does not create or mutate a local database.
    """

    resolved_settings = settings or get_settings()
    normalized_service_role = service_role.strip().lower()
    if normalized_service_role not in {"api", "worker"}:
        raise RuntimeError("service_role must be api or worker")
    serves_http_api = normalized_service_role == "api"
    auth_mode = resolved_settings.auth_mode.strip().lower()
    if auth_mode not in {"local", "oidc"}:
        raise RuntimeError("PLATFORM_AUTH_MODE must be local or oidc")
    mail_poll_mode = resolved_settings.mail_poll_mode.strip().lower()
    if mail_poll_mode not in {"api", "worker"}:
        raise RuntimeError("PLATFORM_MAIL_POLL_MODE must be api or worker")
    environment = resolved_settings.environment.strip().lower()
    managed_environment = environment not in {"development", "test"}
    if managed_environment and auth_mode != "oidc":
        raise RuntimeError("PLATFORM_AUTH_MODE=oidc is required outside development")
    require_secret_files = managed_environment and settings is None
    redis_url = (
        resolved_settings.resolved_redis_url(require_file=require_secret_files)
        if serves_http_api
        else ""
    )

    jwt_hmac_secret: str | None = None
    if auth_mode == "local" and resolved_settings.jwt_hmac_secret is not None:
        jwt_hmac_secret = resolved_settings.jwt_hmac_secret.get_secret_value()
        if not jwt_hmac_secret:
            raise RuntimeError("PLATFORM_JWT_HMAC_SECRET cannot be empty")
    elif auth_mode == "local":
        # A process-local key keeps first-run development safe without shipping a
        # reusable credential. Set PLATFORM_JWT_HMAC_SECRET for stable sessions.
        jwt_hmac_secret = secrets.token_urlsafe(48)
    else:
        required_oidc = {
            "PLATFORM_OIDC_ISSUER_URL": resolved_settings.oidc_issuer_url,
            "PLATFORM_OIDC_AUDIENCE": resolved_settings.oidc_audience,
            "PLATFORM_OIDC_CLIENT_ID": resolved_settings.oidc_client_id,
            "PLATFORM_OIDC_DESKTOP_CLIENT_ID": resolved_settings.oidc_desktop_client_id,
            "PLATFORM_OIDC_JWKS_URL": resolved_settings.oidc_jwks_url,
        }
        missing = [name for name, value in required_oidc.items() if not value]
        if missing:
            raise RuntimeError(f"Missing OIDC configuration: {', '.join(missing)}")
        if managed_environment:
            if urlsplit(resolved_settings.oidc_jwks_url or "").scheme.lower() != "https":
                raise RuntimeError(
                    "PLATFORM_OIDC_JWKS_URL must use HTTPS outside development"
                )
            if not resolved_settings.internal_ca_file:
                raise RuntimeError(
                    "PLATFORM_INTERNAL_CA_FILE is required for OIDC JWKS outside development"
                )
    if (
        serves_http_api
        and managed_environment
        and not resolved_settings.rate_limit_enabled
    ):
        raise RuntimeError(
            "PLATFORM_RATE_LIMIT_ENABLED=true is required outside development"
        )
    if serves_http_api and managed_environment and not redis_url:
        raise RuntimeError("PLATFORM_REDIS_URL is required outside development")
    try:
        allowed_origins = (
            parse_allowed_origins(
                resolved_settings.allowed_origins,
                require_https=managed_environment,
            )
            if serves_http_api
            else ()
        )
    except ValueError as exc:
        raise RuntimeError("PLATFORM_ALLOWED_ORIGINS is invalid") from exc
    if serves_http_api and managed_environment and not allowed_origins:
        raise RuntimeError(
            "PLATFORM_ALLOWED_ORIGINS is required outside development"
        )
    if managed_environment and mail_poll_mode != "worker":
        raise RuntimeError(
            "PLATFORM_MAIL_POLL_MODE=worker is required outside development/test"
        )
    resolved_secret_resolver = (
        secret_resolver
        if secret_resolver is not None
        else secret_resolver_from_settings(resolved_settings)
    )
    resolved_access_token_verifier = access_token_verifier or (
        LocalAccessTokenVerifier(jwt_hmac_secret)
        if auth_mode == "local" and jwt_hmac_secret is not None
        else OidcAccessTokenVerifier(
            issuer=resolved_settings.oidc_issuer_url or "",
            audience=resolved_settings.oidc_audience or "",
            jwks_url=resolved_settings.oidc_jwks_url or "",
            allowed_client_ids=(
                resolved_settings.oidc_client_id or "",
                resolved_settings.oidc_desktop_client_id or "",
            ),
            internal_ca_file=resolved_settings.internal_ca_file,
            tenant_claim=resolved_settings.oidc_tenant_claim,
            device_claim=resolved_settings.oidc_device_claim,
        )
    )

    manages_local_schema = environment in {"development", "test"}
    engine, session_factory = initialize_database(
        resolved_settings.resolved_database_url(require_file=require_secret_files),
        create_schema=manages_local_schema,
    )
    application = FastAPI(
        title=resolved_settings.app_name,
        version=__version__,
        debug=resolved_settings.debug,
        docs_url=f"{resolved_settings.api_prefix}/docs",
        redoc_url=f"{resolved_settings.api_prefix}/redoc",
        openapi_url=f"{resolved_settings.api_prefix}/openapi.json",
    )
    application.state.settings = resolved_settings
    application.state.engine = engine
    application.state.session_factory = session_factory
    application.state.requires_current_migrations = not manages_local_schema
    application.state.metrics = MetricsRegistry()
    application.state.jwt_hmac_secret = jwt_hmac_secret
    application.state.access_token_verifier = resolved_access_token_verifier
    application.state.secret_resolver = resolved_secret_resolver
    application.state.pool_import_receipt_verifier = (
        pool_import_receipt_verifier
        if pool_import_receipt_verifier is not None
        else pool_import_receipt_verifier_from_settings(resolved_settings)
    )
    application.state.pool_import_context_audience = configured_pool_import_audience(
        resolved_settings
    )
    application.state.pool_import_context_verifier = (
        pool_import_context_verifier or DatabasePoolImportContextVerifier()
    )
    configured_mail_connectors = dict(mail_connectors or {})
    if resolved_settings.mail_api_url and "http" not in configured_mail_connectors:
        configured_mail_connectors["http"] = HttpMailConnector(
            resolved_settings.mail_api_url,
            resolved_secret_resolver,
            allowed_origins=resolved_settings.resolved_mail_allowed_origins(),
            timeout=resolved_settings.mail_timeout_seconds,
        )
    application.state.mail_connectors = configured_mail_connectors
    application.state.card_secret_resolver = (
        card_secret_resolver or SecretCardSecretResolver(resolved_secret_resolver)
    )
    credential_ref = (
        resolved_settings.sub2_credential_ref.get_secret_value()
        if resolved_settings.sub2_credential_ref is not None
        else None
    )
    application.state.sub2_policy = Sub2Policy(
        version=resolved_settings.sub2_policy_version,
        proxy_ref=resolved_settings.sub2_proxy_ref,
        group_id=resolved_settings.sub2_group_id,
        concurrency=resolved_settings.sub2_concurrency,
        credential_ref=credential_ref,
    )
    application.state.sub2_adapter = sub2_adapter or UnconfiguredSub2Adapter()
    resolved_rate_limit_backend = rate_limit_backend
    if (
        serves_http_api
        and resolved_settings.rate_limit_enabled
        and resolved_rate_limit_backend is None
    ):
        if not redis_url:
            raise RuntimeError(
                "PLATFORM_REDIS_URL is required when rate limiting is enabled"
            )
        resolved_rate_limit_backend = RedisRateLimitBackend(redis_url)
    application.state.rate_limit_backend = resolved_rate_limit_backend
    application.add_middleware(
        OriginPolicyMiddleware,
        allowed_origins=allowed_origins,
    )
    if (
        serves_http_api
        and resolved_settings.rate_limit_enabled
        and resolved_rate_limit_backend is not None
    ):
        application.add_middleware(
            RateLimitMiddleware,
            backend=resolved_rate_limit_backend,
            api_prefix=resolved_settings.versioned_api_prefix,
            login_limit=resolved_settings.rate_limit_login_requests,
            high_risk_limit=resolved_settings.rate_limit_high_risk_requests,
            general_limit=resolved_settings.rate_limit_general_requests,
            window_seconds=resolved_settings.rate_limit_window_seconds,
            fail_closed=managed_environment,
            clock=rate_limit_clock,
        )
    application.add_middleware(TraceAndErrorMiddleware)
    application.add_exception_handler(
        StarletteHTTPException, http_exception_handler
    )
    application.add_exception_handler(
        RequestValidationError, validation_exception_handler
    )
    application.include_router(
        v1_router, prefix=resolved_settings.versioned_api_prefix
    )

    @application.get("/healthz", include_in_schema=False)
    async def healthz(request: Request) -> dict[str, str]:
        """Simple infrastructure health probe."""

        return {"status": "ok", "service": request.app.state.settings.app_name}

    @application.get("/releasez", include_in_schema=False)
    async def releasez(request: Request) -> JSONResponse:
        """Expose non-secret release identity for route verification."""

        settings = request.app.state.settings
        return JSONResponse(
            content={
                "service": settings.app_name,
                "tag": settings.release_tag,
                "commit": settings.release_commit,
                "migration_head": settings.release_migration_head,
                "slot": settings.release_slot,
            },
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> JSONResponse:
        """Readiness probe that verifies required backend dependencies."""

        try:
            with request.app.state.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except (SQLAlchemyError, RuntimeError, OSError):
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "service": request.app.state.settings.app_name,
                    "checks": {"database": "unavailable"},
                },
            )
        if (
            request.app.state.requires_current_migrations
            and not database_schema_is_current(request.app.state.engine)
        ):
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "service": request.app.state.settings.app_name,
                    "checks": {"database": "ok", "migrations": "pending"},
                },
            )
        redis_check = "not_required"
        if request.app.state.settings.rate_limit_enabled:
            try:
                redis_ok = await request.app.state.rate_limit_backend.ping()
            except Exception:
                redis_ok = False
            if not redis_ok:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "degraded",
                        "service": request.app.state.settings.app_name,
                        "checks": {
                            "database": "ok",
                            "migrations": (
                                "ok"
                                if request.app.state.requires_current_migrations
                                else "not_required"
                            ),
                            "redis": "unavailable",
                        },
                    },
                )
            redis_check = "ok"
        return JSONResponse(
            content={
                "status": "ok",
                "service": request.app.state.settings.app_name,
                "release": {
                    "tag": request.app.state.settings.release_tag,
                    "commit": request.app.state.settings.release_commit,
                    "migration_head": (
                        request.app.state.settings.release_migration_head
                    ),
                    "slot": request.app.state.settings.release_slot,
                },
                "checks": {
                    "database": "ok",
                    "migrations": (
                        "ok"
                        if request.app.state.requires_current_migrations
                        else "not_required"
                    ),
                    "redis": redis_check,
                },
            }
        )

    @application.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> PlainTextResponse:
        """Prometheus-compatible operational metrics without sensitive labels."""

        upload_statuses = upload_job_status_counts(request.app.state.session_factory)
        body = request.app.state.metrics.render_prometheus(
            {"platform_upload_jobs_total": upload_statuses}
        )
        return PlainTextResponse(body, media_type="text/plain; version=0.0.4")

    return application


__all__ = ["create_app"]
