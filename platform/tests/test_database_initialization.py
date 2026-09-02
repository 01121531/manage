import asyncio
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import httpx
from sqlalchemy import inspect

from platform.app import create_app
from platform.config import Settings
from platform.database import Base, initialize_database
from platform.secrets import SecretResolverUnavailable


class FalseySecretResolver:
    def __bool__(self) -> bool:
        return False

    def resolve(self, _secret_ref: str) -> dict[str, object]:
        return {"value": "unused"}


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
        internal_ca_file="/run/secrets/internal-tls/ca.crt",
        allowed_origins="https://platform.example.test",
        mail_poll_mode="worker",
        rate_limit_enabled=True,
        redis_url="redis://redis.example.test:6379/0",
    )


class DatabaseInitializationTests(unittest.TestCase):
    def test_production_app_initialization_does_not_run_ddl(self) -> None:
        with (
            patch.object(Base.metadata, "create_all") as create_all,
            patch("platform.database._install_audit_append_only_constraints") as install,
            patch(
                "platform.database._install_card_event_append_only_constraints"
            ) as install_card_events,
        ):
            app = create_app(
                production_settings(),
                access_token_verifier=object(),
                secret_resolver=FalseySecretResolver(),
            )
        try:
            create_all.assert_not_called()
            install.assert_not_called()
            install_card_events.assert_not_called()
            self.assertEqual(inspect(app.state.engine).get_table_names(), [])
        finally:
            app.state.engine.dispose()

    def test_development_initialization_keeps_local_schema_setup(self) -> None:
        with (
            patch.object(Base.metadata, "create_all") as create_all,
            patch("platform.database._install_audit_append_only_constraints") as install,
            patch(
                "platform.database._install_card_event_append_only_constraints"
            ) as install_card_events,
        ):
            engine, _ = initialize_database(
                "sqlite+pysqlite:///:memory:", create_schema=True
            )
        try:
            create_all.assert_called_once_with(engine)
            install.assert_called_once_with(engine)
            install_card_events.assert_called_once_with(engine)
        finally:
            engine.dispose()

    def test_production_readiness_fails_when_migrations_are_missing(self) -> None:
        app = create_app(
            production_settings(),
            access_token_verifier=object(),
            secret_resolver=FalseySecretResolver(),
        )

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

    def test_missing_production_vault_fails_before_database_initialization(self) -> None:
        with patch("platform.app.initialize_database") as initialize:
            with self.assertRaisesRegex(
                RuntimeError,
                "^PLATFORM_VAULT_ADDR is required outside development/test$",
            ):
                create_app(
                    production_settings(),
                    access_token_verifier=object(),
                )
        initialize.assert_not_called()

    def test_unavailable_production_vault_token_fails_before_database_initialization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_root = Path(directory).resolve()
            settings = production_settings().model_copy(
                update={
                    "vault_addr": "https://vault.example",
                    "vault_token_file": str(token_root / "missing-token"),
                }
            )
            with (
                patch(
                    "platform.secrets._PRODUCTION_VAULT_TOKEN_ROOTS",
                    (f"{token_root.as_posix()}/",),
                ),
                patch(
                    "platform.secrets.create_vault_tls_context",
                    return_value=ssl.create_default_context(),
                ),
                patch("platform.app.initialize_database") as initialize,
                self.assertRaisesRegex(
                    SecretResolverUnavailable,
                    "^Vault token file is unavailable$",
                ),
            ):
                create_app(settings, access_token_verifier=object())

        initialize.assert_not_called()

    def test_unavailable_oidc_ca_fails_before_database_initialization(self) -> None:
        private_path = str(
            (Path.cwd() / "private-oidc-internal-ca-detail.pem").resolve()
        )
        settings = production_settings().model_copy(
            update={"internal_ca_file": private_path}
        )
        with (
            patch(
                "platform.secrets.read_stable_runtime_bytes_with_metadata",
                side_effect=OSError("private OIDC CA path detail"),
            ),
            patch(
                "platform.app.initialize_database",
                side_effect=AssertionError("database must not be initialized"),
            ) as initialize,
            self.assertRaises(ValueError) as raised,
        ):
            create_app(settings, secret_resolver=FalseySecretResolver())

        self.assertEqual(
            str(raised.exception),
            "OIDC TLS trust is unavailable or invalid",
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn(private_path, str(raised.exception))
        self.assertNotIn("private OIDC CA path detail", str(raised.exception))
        initialize.assert_not_called()

    def test_explicit_falsey_secret_resolver_replaces_default_vault(self) -> None:
        resolver = FalseySecretResolver()
        app = create_app(
            production_settings(),
            access_token_verifier=object(),
            secret_resolver=resolver,
        )
        try:
            self.assertIs(app.state.secret_resolver, resolver)
        finally:
            app.state.engine.dispose()


if __name__ == "__main__":
    unittest.main()
