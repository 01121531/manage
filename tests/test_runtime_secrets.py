import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

from platform.config import Settings


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_runtime_secrets", ROOT / "scripts/verify_runtime_secrets.py"
)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


class RuntimeSecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.env = (ROOT / ".env.example").read_text(encoding="utf-8")
        cls.init = (ROOT / "infra/postgres/init/02-create-platform-runtime-role.sh").read_text(encoding="utf-8")
        cls.health = (ROOT / "infra/redis-healthcheck.sh").read_text(encoding="utf-8")
        postgres_healthcheck = ROOT / "infra/postgres-healthcheck.sh"
        cls.postgres_health = (
            postgres_healthcheck.read_text(encoding="utf-8")
            if postgres_healthcheck.exists()
            else ""
        )

    def errors(self, **overrides: str) -> list[str]:
        values = {
            "compose_text": self.compose,
            "env_text": self.env,
            "postgres_init_text": self.init,
            "redis_healthcheck_text": self.health,
            "postgres_healthcheck_text": self.postgres_health,
        }
        values.update(overrides)
        return verify.verification_errors(**values)

    def test_current_assets_are_file_only(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_rejects_inline_database_or_keycloak_password(self) -> None:
        inline_dsn = self.compose.replace(
            "PLATFORM_DATABASE_URL_FILE: /run/secrets/runtime/database-url",
            "PLATFORM_DATABASE_URL: postgresql://user:password@postgres/db",
            1,
        )
        keycloak_password = self.compose.replace(
            '      KC_HEALTH_ENABLED: "true"',
            '      KC_DB_PASSWORD: "password"\n      KC_HEALTH_ENABLED: "true"',
            1,
        )
        self.assertTrue(self.errors(compose_text=inline_dsn))
        self.assertTrue(self.errors(compose_text=keycloak_password))

    def test_rejects_raw_sub2_admin_api_key(self) -> None:
        inline = self.compose.replace(
            "      PLATFORM_SUB2_ADMIN_API_KEY_REF:",
            "      PLATFORM_SUB2_ADMIN_API_KEY: live-secret\n"
            "      PLATFORM_SUB2_ADMIN_API_KEY_REF:",
            1,
        )
        env_inline = self.env + "\nPLATFORM_SUB2_ADMIN_API_KEY=live-secret\n"
        self.assertTrue(self.errors(compose_text=inline))
        self.assertTrue(self.errors(env_text=env_inline))

    def test_rejects_missing_or_writable_secret_mount(self) -> None:
        missing = self.compose.replace(
            "        target: /run/secrets/runtime/redis-url\n", "", 1
        )
        writable = self.compose.replace(
            "        target: /run/secrets/postgres/platform-password\n        read_only: true",
            "        target: /run/secrets/postgres/platform-password\n        read_only: false",
            1,
        )
        self.assertTrue(self.errors(compose_text=missing))
        self.assertTrue(self.errors(compose_text=writable))

    def test_sub2_worker_requires_its_own_read_only_redis_url_mount(self) -> None:
        marker = "        target: /run/secrets/runtime/redis-url\n"
        first = self.compose.index(marker)
        second = self.compose.index(marker, first + len(marker))
        missing = self.compose[:second] + self.compose[second + len(marker) :]
        writable = (
            self.compose[:second]
            + self.compose[second:].replace(
                "        target: /run/secrets/runtime/redis-url\n        read_only: true",
                "        target: /run/secrets/runtime/redis-url\n        read_only: false",
                1,
            )
        )
        self.assertTrue(self.errors(compose_text=missing))
        self.assertTrue(self.errors(compose_text=writable))

    def test_rejects_redis_password_argv_and_unsafe_init(self) -> None:
        redis_argv = self.compose.replace(
            'command: ["redis-server", "/run/config/redis.conf"]',
            'command: ["redis-server", "--requirepass", "password"]',
            1,
        )
        unsafe_init = self.init.replace("POSTGRES_APP_PASSWORD_FILE", "POSTGRES_APP_PASSWORD", 1)
        unsafe_health = self.health.replace(
            "--askpass --user healthcheck", '-a "$password" --user healthcheck'
        )
        self.assertTrue(self.errors(compose_text=redis_argv))
        self.assertTrue(self.errors(postgres_init_text=unsafe_init))
        self.assertTrue(self.errors(redis_healthcheck_text=unsafe_health))

    def test_rejects_postgres_probe_that_does_not_authenticate_all_roles(self) -> None:
        readiness_only = self.compose.replace(
            '["CMD", "sh", "/usr/local/bin/postgres-healthcheck"]',
            '["CMD-SHELL", "pg_isready -U \\"$$POSTGRES_USER\\" -d \\"$$POSTGRES_DB\\""]',
            1,
        )
        self.assertTrue(self.errors(compose_text=readiness_only))
        mappings = (
            'check_database "$POSTGRES_DB" "$POSTGRES_USER" "$POSTGRES_PASSWORD_FILE"',
            'check_database "$POSTGRES_DB" "$POSTGRES_APP_USER" "$POSTGRES_APP_PASSWORD_FILE"',
            'check_database "keycloak" "$KEYCLOAK_DB_USER" "$KEYCLOAK_DB_PASSWORD_FILE"',
        )
        for mapping in mappings:
            with self.subTest(mapping=mapping):
                self.assertTrue(
                    self.errors(
                        postgres_healthcheck_text=self.postgres_health.replace(
                            mapping, "", 1
                        )
                    )
                )

    def test_rejects_unsafe_postgres_healthcheck_secret_handling(self) -> None:
        missing_cleanup = self.postgres_health.replace(
            "trap 'rm -f \"$pgpass_file\"' EXIT", "", 1
        )
        password_argv = self.postgres_health.replace(
            "PGPASSFILE=\"$pgpass_file\" psql",
            'psql --password="$password"',
            1,
        )
        missing_sql_failure = self.postgres_health.replace(
            "--set=ON_ERROR_STOP=1", "", 1
        )
        password_echo = self.postgres_health.replace(
            'IFS= read -r password <&9 || true',
            'IFS= read -r password <&9 || true\n  echo "$password"',
            1,
        )
        unsafe_variants = (
            missing_cleanup,
            self.postgres_health.replace("umask 077", "umask 022", 1),
            self.postgres_health.replace(
                "mktemp /tmp/postgres-healthcheck.XXXXXX",
                "/tmp/postgres-healthcheck",
                1,
            ),
            self.postgres_health.replace('chmod 600 "$pgpass_file"', "", 1),
            self.postgres_health.replace(
                'if ! exec 9<"$password_file"; then',
                'if [ -r "$password_file" ]; then',
                1,
            ),
            self.postgres_health.replace(
                'if [ -z "$password" ]', 'if [ -z "$password_file" ]', 1
            ),
        )
        for variant in unsafe_variants:
            self.assertTrue(self.errors(postgres_healthcheck_text=variant))
        self.assertTrue(self.errors(postgres_healthcheck_text=password_argv))
        self.assertTrue(self.errors(postgres_healthcheck_text=password_echo))
        self.assertTrue(
            self.errors(postgres_healthcheck_text=missing_sql_failure)
        )

    def test_descriptor_secret_readers_reject_path_reopen_and_identity_downgrades(
        self,
    ) -> None:
        cases = (
            (
                "postgres_healthcheck_text",
                self.postgres_health,
                'IFS= read -r password <&9 || true',
                'IFS= read -r password < "$password_file" || true',
                '[ ! -f "/proc/self/fd/9" ] || ',
                '"$password_file" -ef "/proc/self/fd/9"',
            ),
            (
                "redis_healthcheck_text",
                self.health,
                'IFS= read -r password <&9 || true',
                'IFS= read -r password < "$password_file" || true',
                '[ ! -f "/proc/self/fd/9" ] || ',
                '"$password_file" -ef "/proc/self/fd/9"',
            ),
            (
                "postgres_init_text",
                self.init,
                'IFS= read -r value <&9 || true',
                'IFS= read -r value < "$file_path" || true',
                '[ ! -f "/proc/self/fd/9" ] || ',
                '"$file_path" -ef "/proc/self/fd/9"',
            ),
        )
        for argument, source, descriptor_read, path_read, regular, identity in cases:
            mutations = (
                source.replace(descriptor_read, path_read, 1),
                source.replace(regular, "", 1),
                source.replace(identity, '"/missing" -ef "/proc/self/fd/9"', 1),
            )
            for index, mutation in enumerate(mutations):
                with self.subTest(argument=argument, mutation=index):
                    self.assertTrue(self.errors(**{argument: mutation}))

    def test_rejects_missing_or_writable_postgres_healthcheck_mount(self) -> None:
        missing = self.compose.replace(
            "        target: /usr/local/bin/postgres-healthcheck\n",
            "        target: /usr/local/bin/postgres-healthcheck-removed\n",
            1,
        )
        writable = self.compose.replace(
            "        target: /usr/local/bin/postgres-healthcheck\n        read_only: true",
            "        target: /usr/local/bin/postgres-healthcheck\n        read_only: false",
            1,
        )
        self.assertTrue(self.errors(compose_text=missing))
        self.assertTrue(self.errors(compose_text=writable))

    def test_settings_reads_one_line_and_requires_file_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "database-url"
            path.write_text("sqlite+pysqlite:///:memory:\n", encoding="utf-8")
            settings = Settings(database_url_file=str(path))
            self.assertEqual(settings.resolved_database_url(require_file=True), "sqlite+pysqlite:///:memory:")
            path.write_text("first\nsecond\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "one non-empty line"):
                settings.resolved_database_url(require_file=True)
        with self.assertRaisesRegex(RuntimeError, "DATABASE_URL_FILE"):
            Settings().resolved_database_url(require_file=True)
        with self.assertRaisesRegex(RuntimeError, "is forbidden"):
            Settings(
                database_url="postgresql://user:password@postgres/db",
                database_url_file="/unused",
            ).resolved_database_url(require_file=True)
        with self.assertRaisesRegex(RuntimeError, "is forbidden"):
            Settings(
                redis_url="redis://:password@redis/0",
                redis_url_file="/unused",
            ).resolved_redis_url(require_file=True)


if __name__ == "__main__":
    unittest.main()
