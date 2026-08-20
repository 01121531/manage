"""FastAPI application factory for the platform backend."""

import secrets
from collections.abc import Mapping

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
from platform.middleware import TraceAndErrorMiddleware
from platform.metrics import MetricsRegistry
from platform.mail_connectors import HttpMailConnector, MailConnector
from platform.secrets import SecretResolver, secret_resolver_from_settings
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
    mail_connectors: Mapping[str, MailConnector] | None = None,
    sub2_adapter: Sub2Adapter | None = None,
    card_secret_resolver: CardSecretResolver | None = None,
    secret_resolver: SecretResolver | None = None,
    access_token_verifier: AccessTokenVerifier | None = None,
) -> FastAPI:
    """Create a configured FastAPI application.

    ``settings`` is injectable for tests. Production runs use the factory
    entry point (`uvicorn platform.app:create_app --factory`) so importing the
    module does not create or mutate a local database.
    """

    resolved_settings = settings or get_settings()
    auth_mode = resolved_settings.auth_mode.strip().lower()
    if auth_mode not in {"local", "oidc"}:
        raise RuntimeError("PLATFORM_AUTH_MODE must be local or oidc")
    mail_poll_mode = resolved_settings.mail_poll_mode.strip().lower()
    if mail_poll_mode not in {"api", "worker"}:
        raise RuntimeError("PLATFORM_MAIL_POLL_MODE must be api or worker")
    if resolved_settings.environment.lower() not in {"development", "test"} and auth_mode != "oidc":
        raise RuntimeError("PLATFORM_AUTH_MODE=oidc is required outside development")

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

    environment = resolved_settings.environment.strip().lower()
    manages_local_schema = environment in {"development", "test"}
    engine, session_factory = initialize_database(
        resolved_settings.database_url,
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
    application.state.access_token_verifier = access_token_verifier or (
        LocalAccessTokenVerifier(jwt_hmac_secret)
        if auth_mode == "local" and jwt_hmac_secret is not None
        else OidcAccessTokenVerifier(
            issuer=resolved_settings.oidc_issuer_url or "",
            audience=resolved_settings.oidc_audience or "",
            jwks_url=resolved_settings.oidc_jwks_url or "",
            tenant_claim=resolved_settings.oidc_tenant_claim,
            device_claim=resolved_settings.oidc_device_claim,
        )
    )
    resolved_secret_resolver = secret_resolver or secret_resolver_from_settings(resolved_settings)
    application.state.secret_resolver = resolved_secret_resolver
    configured_mail_connectors = dict(mail_connectors or {})
    if resolved_settings.mail_api_url and "http" not in configured_mail_connectors:
        configured_mail_connectors["http"] = HttpMailConnector(
            resolved_settings.mail_api_url,
            resolved_secret_resolver,
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
        return JSONResponse(
            content={
                "status": "ok",
                "service": request.app.state.settings.app_name,
                "checks": {
                    "database": "ok",
                    "migrations": (
                        "ok"
                        if request.app.state.requires_current_migrations
                        else "not_required"
                    ),
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
