from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_runbooks import key_rotation_runbook_errors


RUNBOOK = Path("deploy/runbooks/key-rotation.md")
DOCKER_ENVIRONMENT_GATE = """$forbiddenDockerEnvironment = @(
  "DOCKER_HOST",
  "DOCKER_CONTEXT",
  "DOCKER_CONFIG",
  "DOCKER_TLS",
  "DOCKER_TLS_VERIFY",
  "DOCKER_CERT_PATH"
)
$presentDockerEnvironment = @(
  $forbiddenDockerEnvironment | Where-Object {
    Test-Path -LiteralPath "Env:$_"
  }
)
if ($presentDockerEnvironment.Count -ne 0) {
  throw "production credential rotation Docker environment preflight failed"
}"""
PRODUCTION_COMPOSE_INITIALIZATION = """$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"
$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path
$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path
$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path
$dockerContext = docker context show
docker context inspect $dockerContext"""
PRODUCTION_COMPOSE_PREFIX = (
    "docker compose --project-directory $projectDirectory --env-file $envFile "
    "--project-name email-platform --file $composeFile"
)
PRODUCTION_COMPOSE_SUFFIXES = (
    "config --quiet",
    "stop edge",
    "ps edge",
    "stop $consumers",
    "up -d --no-build --pull never $consumers",
    "up -d --no-build --pull never edge",
)


class KeyRotationRunbookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = RUNBOOK.read_text(encoding="utf-8")

    def assert_rejected_after_replace(self, old: str, new: str) -> None:
        self.assertIn(old, self.text)
        mutated = self.text.replace(old, new, 1)
        self.assertTrue(key_rotation_runbook_errors(mutated))

    def test_current_runbook_passes_structured_contract(self) -> None:
        self.assertEqual(key_rotation_runbook_errors(self.text), [])

    def test_compose_identity_and_environment_gate_are_fixed_before_docker(self) -> None:
        self.assertIn(DOCKER_ENVIRONMENT_GATE, self.text)
        self.assertIn(PRODUCTION_COMPOSE_INITIALIZATION, self.text)
        self.assertLess(
            self.text.index(DOCKER_ENVIRONMENT_GATE),
            self.text.index(PRODUCTION_COMPOSE_INITIALIZATION),
        )
        self.assertNotIn("Resolve-Path .", self.text)
        commands = tuple(
            line.strip()
            for line in self.text.splitlines()
            if line.strip().startswith("docker compose ")
        )
        self.assertEqual(
            commands,
            tuple(
                f"{PRODUCTION_COMPOSE_PREFIX} {suffix}"
                for suffix in PRODUCTION_COMPOSE_SUFFIXES
            ),
        )

    def test_rejects_environment_gate_or_compose_identity_mutation(self) -> None:
        self.assertIn(DOCKER_ENVIRONMENT_GATE, self.text)
        self.assertIn(PRODUCTION_COMPOSE_INITIALIZATION, self.text)
        mutations = [
            self.text.replace(DOCKER_ENVIRONMENT_GATE, "", 1),
            self.text.replace(PRODUCTION_COMPOSE_INITIALIZATION, "", 1),
            self.text.replace(
                '$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"',
                '$productionInstallRoot = "."',
                1,
            ),
            self.text.replace(
                '$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"',
                '$productionInstallRoot = "C:\\Temp\\unreviewed"',
                1,
            ),
            self.text.replace(
                'Test-Path -LiteralPath "Env:$_"',
                '$env:$_',
                1,
            ),
            self.text.replace(
                'Test-Path -LiteralPath "Env:$_"',
                '$env.Get($_)',
                1,
            ),
            self.text.replace(
                DOCKER_ENVIRONMENT_GATE,
                "",
                1,
            ).replace(
                "$dockerContext = docker context show",
                "$dockerContext = docker context show\n" + DOCKER_ENVIRONMENT_GATE,
                1,
            ),
        ]
        for variable in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            mutations.append(self.text.replace(f'  "{variable}"', "", 1))
        mutations.append(
            self.text.replace(
                '  "DOCKER_CERT_PATH"',
                '  "DOCKER_CERT_PATH",\n  "DOCKER_API_VERSION"',
                1,
            )
        )
        for suffix in PRODUCTION_COMPOSE_SUFFIXES:
            command = f"{PRODUCTION_COMPOSE_PREFIX} {suffix}"
            mutations.append(
                self.text.replace(
                    command,
                    command.replace("--env-file $envFile ", "", 1),
                    1,
                )
            )
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(key_rotation_runbook_errors(mutation))

    def test_rejects_missing_file_topology_or_single_class_boundary(self) -> None:
        markers = (
            "Rotate exactly one credential class per maintenance change",
            "POSTGRES_APP_PASSWORD_FILE",
            "PLATFORM_DATABASE_URL_FILE",
            "POSTGRES_PASSWORD_FILE",
            "PLATFORM_MIGRATION_DATABASE_URL_FILE",
            "KEYCLOAK_DB_PASSWORD_FILE",
            "KEYCLOAK_CONFIG_FILE",
            "REDIS_ACL_FILE",
            "PLATFORM_REDIS_URL_FILE",
            "REDIS_HEALTHCHECK_PASSWORD_FILE",
            "PLATFORM_VAULT_API_TOKEN_DIR/token",
            "PLATFORM_VAULT_MAIL_TOKEN_DIR/token",
            "PLATFORM_VAULT_SUB2_TOKEN_DIR/token",
            "RoleID is a role selector",
            "SecretID is a one-use login input",
            "Only an independent approved rotator",
            "auth/token/revoke-accessor",
            "never record a Vault token-sink SHA-256 value",
            "never restore a revoked token or a consumed SecretID",
        )
        for marker in markers:
            with self.subTest(marker=marker):
                self.assert_rejected_after_replace(marker, "REMOVED_CONTROL")

    def test_rejects_inline_secret_settings_and_plaintext_probe(self) -> None:
        mutations = (
            ("POSTGRES_APP_PASSWORD_FILE", "POSTGRES_APP_PASSWORD"),
            ("PLATFORM_DATABASE_URL_FILE", "PLATFORM_DATABASE_URL"),
            ("PLATFORM_REDIS_URL_FILE", "PLATFORM_REDIS_URL"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.assert_rejected_after_replace(old, new)
        self.assertTrue(
            key_rotation_runbook_errors(
                self.text + "\ncurl.exe http://127.0.0.1:8000/readyz\n"
            )
        )

    def test_rejects_init_script_or_batch_restart_as_rotation(self) -> None:
        self.assert_rejected_after_replace(
            "PostgreSQL initialization scripts are not\n"
            "a rotation mechanism",
            "PostgreSQL initialization scripts are\n"
            "the rotation mechanism",
        )
        unsafe = self.text + (
            "\n```powershell\n"
            f"{PRODUCTION_COMPOSE_PREFIX} up -d --no-build --pull never "
            "postgres redis keycloak api worker-mail worker-sub2 web\n"
            "```\n"
        )
        self.assertTrue(key_rotation_runbook_errors(unsafe))

    def test_rejects_unpinned_or_mutable_compose_commands(self) -> None:
        self.assert_rejected_after_replace(
            f"{PRODUCTION_COMPOSE_PREFIX} stop edge",
            "docker compose stop edge",
        )
        self.assert_rejected_after_replace(
            "up -d --no-build --pull never $consumers",
            "up -d $consumers",
        )
        self.assertTrue(
            key_rotation_runbook_errors(
                self.text + "\ndocker-compose up -d api worker-mail worker-sub2\n"
            )
        )

    def test_rejects_edge_or_cutover_evidence_reordering(self) -> None:
        edge_stop = f"{PRODUCTION_COMPOSE_PREFIX} stop edge"
        edge_start = f"{PRODUCTION_COMPOSE_PREFIX} up -d --no-build --pull never edge"
        swapped = self.text.replace(edge_stop, "ROTATION_EDGE_MARKER", 1)
        swapped = swapped.replace(edge_start, edge_stop, 1)
        swapped = swapped.replace("ROTATION_EDGE_MARKER", edge_start, 1)
        self.assertTrue(key_rotation_runbook_errors(swapped))

        for marker in (
            "Prove the new credential succeeds",
            "Revoke the old credential",
            "Prove the old credential fails",
            "Create redacted evidence only after both authentication proofs pass",
            "Any partial rotation is a failed change",
        ):
            with self.subTest(marker=marker):
                self.assert_rejected_after_replace(marker, "REMOVED_CONTROL")


if __name__ == "__main__":
    unittest.main()
