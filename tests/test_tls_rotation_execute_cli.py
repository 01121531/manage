from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest import mock

from scripts.tls_rotation_execute import main


def _arguments() -> list[str]:
    return [
        "--projection", "D:/external/projection.json",
        "--runtime-profile", "D:/external/profile.json",
        "--evidence-output", "D:/external/evidence.json",
        "--confirm-rotation-plan-sha256", "a" * 64,
    ]


class TlsRotationExecuteCliTests(unittest.TestCase):
    def invoke(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(arguments, shell_environment={"PATH": "safe"})
        return result, stdout.getvalue(), stderr.getvalue()

    def test_exact_cli_invokes_coordinator_with_confirmation(self) -> None:
        with mock.patch(
            "scripts.tls_rotation_execute.execute_tls_rotation", return_value={}
        ) as execute:
            result, stdout, stderr = self.invoke(_arguments())
        self.assertEqual(result, 0)
        self.assertEqual(stdout, "tls-rotation-execution-ok production_acceptance=false\n")
        self.assertEqual(stderr, "")
        self.assertEqual(execute.call_args.args, (Path("D:/external/projection.json"),))
        self.assertEqual(
            execute.call_args.kwargs["confirm_rotation_plan_sha256"], "a" * 64
        )

    def test_backend_factory_dispatches_only_from_validated_runtime_kind(self) -> None:
        captured = {}

        def execute_stub(*args, **kwargs):
            captured["factory"] = kwargs["backend_factory"]
            return {}

        with mock.patch(
            "scripts.tls_rotation_execute.execute_tls_rotation", side_effect=execute_stub
        ), mock.patch(
            "scripts.tls_rotation_execute.build_compose_rotation_backend", return_value="compose"
        ) as compose, mock.patch(
            "scripts.tls_rotation_execute.build_kubernetes_rotation_backend", return_value="kubernetes"
        ) as kubernetes:
            self.assertEqual(self.invoke(_arguments())[0], 0)
            factory = captured["factory"]
            self.assertEqual(factory({"runtime_kind": "compose"}), "compose")
            self.assertEqual(factory({"runtime_kind": "kubernetes"}), "kubernetes")
            with self.assertRaisesRegex(ValueError, "invalid"):
                factory({"runtime_kind": "canary"})
        self.assertEqual(compose.call_count, 1)
        self.assertEqual(kubernetes.call_count, 1)

    def test_unknown_missing_duplicate_and_secret_bearing_arguments_are_redacted(self) -> None:
        canary = "https://secret.invalid/token-value"
        cases = (
            ["--url", canary],
            _arguments()[:-2],
            [*_arguments(), "--projection", canary],
            [*_arguments(), canary],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result, stdout, stderr = self.invoke(arguments)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "tls-rotation-execution-failed\n")
                self.assertNotIn(canary, stdout + stderr)

    def test_coordinator_failure_and_interrupt_have_fixed_outputs(self) -> None:
        for error, expected in (
            (TlsRotationCliFixtureError(), 1),
            (KeyboardInterrupt(), 130),
        ):
            with self.subTest(error=type(error).__name__), mock.patch(
                "scripts.tls_rotation_execute.execute_tls_rotation", side_effect=error
            ):
                result, stdout, stderr = self.invoke(_arguments())
                self.assertEqual(result, expected)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "tls-rotation-execution-failed\n")


class TlsRotationCliFixtureError(ValueError):
    pass


if __name__ == "__main__":
    unittest.main()
