import asyncio
import unittest
from unittest.mock import patch

import httpx
from sqlalchemy import inspect

from platform.app import create_app
from platform.config import Settings
from platform.database import Base, initialize_database


def production_settings() -> Settings:
    return Settings(
        app_name="test-platform",
        environment="production",
        auth_mode="oidc",
        database_url="sqlite+pysqlite:///:memory:",
        oidc_issuer_url="https://identity.example.test/realms/platform",
        oidc_audience="email-platform-api",
        oidc_client_id="email-platform-web",
        oidc_desktop_client_id="email-platform-desktop",
        oidc_jwks_url=(
            "https://identity.example.test/realms/platform/"
            "protocol/openid-connect/certs"
        ),
        rate_limit_enabled=True,
        redis_url="redis://redis.example.test:6379/0",
    )


class DatabaseInitializationTests(unittest.TestCase):
    def test_production_app_initialization_does_not_run_ddl(self) -> None:
        with (
            patch.object(Base.metadata, "create_all") as create_all,
            patch("platform.database._install_audit_append_only_constraints") as install,
        ):
            app = create_app(production_settings())
        try:
            create_all.assert_not_called()
            install.assert_not_called()
            self.assertEqual(inspect(app.state.engine).get_table_names(), [])
        finally:
            app.state.engine.dispose()

    def test_development_initialization_keeps_local_schema_setup(self) -> None:
        with (
            patch.object(Base.metadata, "create_all") as create_all,
            patch("platform.database._install_audit_append_only_constraints") as install,
        ):
            engine, _ = initialize_database(
                "sqlite+pysqlite:///:memory:", create_schema=True
            )
        try:
            create_all.assert_called_once_with(engine)
            install.assert_called_once_with(engine)
        finally:
            engine.dispose()

    def test_production_readiness_fails_when_migrations_are_missing(self) -> None:
        app = create_app(production_settings())

        async def request_ready() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                return await client.get("/readyz")

        try:
            response = asyncio.run(request_ready())
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(response.json()["checks"]["database"], "ok")
            self.assertEqual(response.json()["checks"]["migrations"], "pending")
            self.assertEqual(inspect(app.state.engine).get_table_names(), [])
        finally:
            app.state.engine.dispose()


if __name__ == "__main__":
    unittest.main()
