import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_compose_env.py"
SPEC = importlib.util.spec_from_file_location("verify_compose_env", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_compose_env = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_compose_env
SPEC.loader.exec_module(verify_compose_env)


class ComposeDatabaseRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.env = (ROOT / ".env.example").read_text(encoding="utf-8")
        cls.init = (
            ROOT / "infra" / "postgres" / "init" / "02-create-platform-runtime-role.sh"
        ).read_text(encoding="utf-8")

    def errors(
        self,
        *,
        compose: str | None = None,
        env: str | None = None,
        init: str | None = None,
    ) -> list[str]:
        return verify_compose_env.verification_errors(
            compose_text=self.compose if compose is None else compose,
            env_text=self.env if env is None else env,
            init_text=self.init if init is None else init,
        )

    def test_current_assets_enforce_keycloak_database_role_isolation(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_rejects_missing_or_hardcoded_api_device_limit(self) -> None:
        reviewed = (
            "      PLATFORM_MAX_ACTIVE_DEVICES_PER_USER: "
            "${PLATFORM_MAX_ACTIVE_DEVICES_PER_USER:-5}"
        )
        mutations = (
            self.compose.replace(reviewed + "\n", "", 1),
            self.compose.replace(reviewed, "      PLATFORM_MAX_ACTIVE_DEVICES_PER_USER: 5", 1),
        )
        for compose in mutations:
            with self.subTest(compose=compose):
                self.assertTrue(self.errors(compose=compose))

    def test_rejects_keycloak_bootstrap_credentials_or_missing_provisioning(self) -> None:
        mutations = (
            self.compose.replace(
                "      KEYCLOAK_DB_USER: ${KEYCLOAK_DB_USER:?set KEYCLOAK_DB_USER in .env}",
                "      KEYCLOAK_DB_USER: ${POSTGRES_USER:?set POSTGRES_USER in .env}",
            ),
            self.compose.replace(
                "      KEYCLOAK_DB_PASSWORD_FILE: /run/secrets/postgres/keycloak-password",
                "      KEYCLOAK_DB_PASSWORD_FILE: /run/secrets/postgres/superuser-password",
            ),
            self.compose.replace(
                "      KEYCLOAK_DB_USER: ${KEYCLOAK_DB_USER:?set KEYCLOAK_DB_USER in .env}\n",
                "",
                1,
            ),
        )
        for compose in mutations:
            with self.subTest(compose=compose):
                self.assertTrue(self.errors(compose=compose))

    def test_rejects_reused_role_or_password_placeholder(self) -> None:
        reused_user = self.env.replace(
            "KEYCLOAK_DB_USER=keycloak_app",
            "KEYCLOAK_DB_USER=platform_app",
        )
        reused_password = self.env.replace(
            "KEYCLOAK_DB_PASSWORD_FILE=/CHANGE_ME/runtime-secrets/postgres/keycloak-password",
            "KEYCLOAK_DB_PASSWORD_FILE=/CHANGE_ME/runtime-secrets/postgres/superuser-password",
        )
        self.assertTrue(self.errors(env=reused_user))
        self.assertTrue(self.errors(env=reused_password))

    def test_rejects_missing_least_privilege_flags_or_database_owner(self) -> None:
        for marker in (
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOINHERIT",
            "ALTER DATABASE keycloak OWNER TO %I",
            r"\getenv bootstrap_user POSTGRES_USER",
            'REASSIGN OWNED BY :"bootstrap_user" TO :"keycloak_user"',
        ):
            with self.subTest(marker=marker):
                self.assertTrue(self.errors(init=self.init.replace(marker, "", 1)))

    def test_rejects_password_in_argv_or_missing_role_separation_guard(self) -> None:
        password_in_argv = self.init.replace(
            r"\getenv keycloak_password KEYCLOAK_DB_PASSWORD",
            '--set=keycloak_password="$KEYCLOAK_DB_PASSWORD"',
        )
        missing_guard = self.init.replace(
            '"$KEYCLOAK_DB_USER" = "$POSTGRES_USER"',
            '"$KEYCLOAK_DB_USER" = "disabled"',
        )
        missing_password_guard = self.init.replace(
            '"$KEYCLOAK_DB_PASSWORD" = "$POSTGRES_BOOTSTRAP_PASSWORD"',
            '"$KEYCLOAK_DB_PASSWORD" = "disabled"',
        )
        self.assertTrue(self.errors(init=password_in_argv))
        self.assertTrue(self.errors(init=missing_guard))
        self.assertTrue(self.errors(init=missing_password_guard))


if __name__ == "__main__":
    unittest.main()
