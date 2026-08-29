import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts import verify_backup_tools
from scripts.restore_readiness import (
    CA_FILE,
    EDGE_STOP_COMMAND,
    PROBES,
    RestoreReadinessError,
    TLS_PROBE_PROGRAM,
    restore_contract_errors,
    verify_restored_services,
)
from scripts.verify_runbooks import restore_runbook_errors


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE_PREFIX = (
    "docker",
    "compose",
    "--project-directory",
    str(ROOT),
    "--env-file",
    str(ROOT / ".env"),
    "--project-name",
    "email-platform",
    "--file",
    str(ROOT / "docker-compose.yml"),
)
RUNBOOK_COMPOSE_PREFIX = (
    "docker compose --project-directory $projectDirectory --env-file $envFile "
    "--project-name email-platform --file $composeFile"
)
RUNBOOK_COMPOSE_INITIALIZATION = (
    '$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"\n'
    "$projectDirectory = (Resolve-Path -LiteralPath $productionInstallRoot).Path\n"
    '$envFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory ".env")).Path\n'
    '$composeFile = (Resolve-Path -LiteralPath (Join-Path $projectDirectory "docker-compose.yml")).Path'
)


class RecordingRunner:
    def __init__(self, fail_url: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_url = fail_url

    def __call__(self, command) -> None:
        call = tuple(command)
        self.calls.append(call)
        if self.fail_url and self.fail_url in call:
            raise subprocess.CalledProcessError(1, call)


class RestoreReadinessTests(unittest.TestCase):
    def test_docker_environment_overrides_fail_before_contract_or_runner(self) -> None:
        forbidden = (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        )
        for name in forbidden:
            runner = RecordingRunner()
            with self.subTest(name=name), mock.patch.dict(
                os.environ, {name: ""}, clear=True
            ), mock.patch(
                "scripts.restore_readiness.restore_contract_errors"
            ) as contract:
                with self.assertRaisesRegex(
                    RestoreReadinessError,
                    "^restore readiness Docker environment preflight failed$",
                ):
                    verify_restored_services(runner)
            contract.assert_not_called()
            self.assertEqual(runner.calls, [])

    def test_static_verifier_rejects_removed_or_late_docker_environment_gate(self) -> None:
        source = Path("scripts/restore_readiness.py").read_text(encoding="utf-8")
        verifier = getattr(
            verify_backup_tools,
            "restore_readiness_docker_environment_contract_errors",
            None,
        )
        self.assertIsNotNone(verifier)
        assert verifier is not None
        self.assertEqual(verifier(source), [])
        gate = (
            "    try:\n"
            "        _validate_production_docker_environment()\n"
            "    except ProductionDockerEnvironmentError as error:\n"
            "        raise RestoreReadinessError(\n"
            '            "restore readiness Docker environment preflight failed"\n'
            "        ) from error\n"
        )
        mutations = (
            source.replace(
                "from scripts.production_docker_environment import (",
                "from scripts.production_docker_environment_removed import (",
                1,
            ),
            source.replace("        _validate_production_docker_environment()\n", "", 1),
            source.replace(gate, "", 1).replace(
                "    contract_errors = restore_contract_errors()\n",
                "    contract_errors = restore_contract_errors()\n" + gate,
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(verifier(mutation))

    def test_repository_contract_is_strict_and_complete(self) -> None:
        self.assertEqual(restore_contract_errors(), [])
        self.assertEqual(
            set(PROBES),
            {
                "https://api:8443/readyz",
                "https://web:8443/",
                "https://keycloak:9000/health/ready",
                "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
                "https://worker-mail:9101/metrics",
                "https://worker-sub2:9102/metrics",
                "https://prometheus:9090/-/ready",
            },
        )

    def test_success_checks_every_service_and_leaves_edge_stopped(self) -> None:
        runner = RecordingRunner()
        verify_restored_services(runner)
        self.assertEqual(runner.calls[0], EDGE_STOP_COMMAND)
        self.assertEqual(runner.calls[-1], EDGE_STOP_COMMAND)
        for call in runner.calls:
            self.assertEqual(
                call[: len(PRODUCTION_COMPOSE_PREFIX)],
                PRODUCTION_COMPOSE_PREFIX,
            )
        self.assertEqual(
            {
                call[-1]
                for call in runner.calls
                if call[len(PRODUCTION_COMPOSE_PREFIX) : len(PRODUCTION_COMPOSE_PREFIX) + 2]
                == ("exec", "-T")
            },
            set(PROBES),
        )
        for call in runner.calls[1:-1]:
            self.assertEqual(
                call[
                    len(PRODUCTION_COMPOSE_PREFIX) + 2 : len(PRODUCTION_COMPOSE_PREFIX) + 6
                ],
                ("api", "python", "-c", TLS_PROBE_PROGRAM),
            )

    def test_probe_failure_retries_edge_stop_and_never_starts_it(self) -> None:
        runner = RecordingRunner("https://worker-mail:9101/metrics")
        with self.assertRaises(subprocess.CalledProcessError):
            verify_restored_services(runner)
        self.assertEqual(runner.calls[0], EDGE_STOP_COMMAND)
        self.assertEqual(runner.calls[-1], EDGE_STOP_COMMAND)
        self.assertFalse(any("up" in call for call in runner.calls))

    def test_tls_contract_rejects_downgrade_and_missing_probe(self) -> None:
        programs = (
            TLS_PROBE_PROGRAM.replace(f"cafile='{CA_FILE}'", "cafile=None", 1),
            TLS_PROBE_PROGRAM.replace("TLSv1_2", "TLSv1_1", 1),
            TLS_PROBE_PROGRAM.replace(
                "context.minimum_version=ssl.TLSVersion.TLSv1_2; ",
                "context.check_hostname=False; ",
                1,
            ),
            TLS_PROBE_PROGRAM.replace("ssl.create_default_context", "ssl._create_unverified_context", 1),
            TLS_PROBE_PROGRAM.replace("context=context,", "", 1),
        )
        for program in programs:
            with self.subTest(program=program):
                self.assertTrue(restore_contract_errors(program, PROBES))
        self.assertTrue(
            restore_contract_errors(TLS_PROBE_PROGRAM, ("http://api:8000/readyz",))
        )
        for changed_probes in (
            PROBES[:-1],
            (PROBES[0].replace(":8443", ":8000"), *PROBES[1:]),
            (PROBES[0].replace("api", "127.0.0.1"), *PROBES[1:]),
        ):
            with self.subTest(probes=changed_probes):
                self.assertTrue(restore_contract_errors(TLS_PROBE_PROGRAM, changed_probes))
        self.assertTrue(
            restore_contract_errors(
                TLS_PROBE_PROGRAM.replace(
                    "response.geturl()==sys.argv[1] or sys.exit(3); ", ""
                ),
                PROBES,
            )
        )

    def test_restore_runbook_rejects_obsolete_or_reordered_gate(self) -> None:
        text = Path("deploy/runbooks/restore.md").read_text(encoding="utf-8")
        self.assertEqual(restore_runbook_errors(text), [])
        mutations = (
            text.replace("python -m scripts.restore_readiness", "Write-Host skip", 1),
            text.replace("https://api:8443/readyz", "http://127.0.0.1:8000/readyz", 1),
            text.replace("TLS 1.2", "TLS 1.1", 1),
            text.replace("/run/secrets/internal-tls/ca.crt", "cafile=None", 1),
            text.replace("absolute, repository-external", "repository-relative", 1),
            text.replace("must not already exist", "may be refreshed", 1),
            text.replace(
                "python -m scripts.restore_readiness",
                "docker compose up -d --no-build --pull never edge\npython -m scripts.restore_readiness",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(restore_runbook_errors(mutation))

    def test_every_restore_runbook_compose_command_pins_production_identity(self) -> None:
        text = Path("deploy/runbooks/restore.md").read_text(encoding="utf-8")
        self.assertIn(RUNBOOK_COMPOSE_INITIALIZATION, text)
        self.assertNotIn("Resolve-Path .", text)
        commands = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("docker compose ")
        ]
        self.assertEqual(len(commands), 5)
        self.assertEqual(
            [command for command in commands if not command.startswith(RUNBOOK_COMPOSE_PREFIX)],
            [],
        )

    def test_restore_runbook_verifier_rejects_compose_identity_drift(self) -> None:
        text = Path("deploy/runbooks/restore.md").read_text(encoding="utf-8")
        mutations = (
            text.replace("--project-directory $projectDirectory ", "", 1),
            text.replace("--env-file $envFile ", "", 1),
            text.replace("--project-name email-platform ", "", 1),
            text.replace("--file $composeFile ", "", 1),
            text.replace(
                '$productionInstallRoot = "C:\\ProgramData\\EmailPlatform\\current"',
                '$productionInstallRoot = "."',
                1,
            ),
            text.replace(RUNBOOK_COMPOSE_INITIALIZATION, "", 1),
        )
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(restore_runbook_errors(mutation))


if __name__ == "__main__":
    unittest.main()
