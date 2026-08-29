from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from scripts.tls_rotation_runner import (
    FORBIDDEN_ROTATION_ENVIRONMENT,
    SanitizedSubprocessRunner,
    sanitized_subprocess_environment,
)
from scripts.tls_rotation_runtime import RotationRuntimeError


class TlsRotationRunnerTests(unittest.TestCase):
    def test_environment_is_presence_rejected_and_allowlisted(self) -> None:
        base = {"PATH": "safe-bin", "SYSTEMROOT": "safe-root", "UNRELATED": "drop"}
        self.assertEqual(
            sanitized_subprocess_environment(base),
            {"PATH": "safe-bin", "SYSTEMROOT": "safe-root"},
        )
        for name in FORBIDDEN_ROTATION_ENVIRONMENT:
            with self.subTest(name=name):
                with self.assertRaisesRegex(RotationRuntimeError, "environment preflight"):
                    sanitized_subprocess_environment({**base, name: ""})

    def test_runner_suppresses_stderr_freezes_env_and_uses_bounded_stdin(self) -> None:
        completed = subprocess.CompletedProcess(["docker"], 0, stdout="ok", stderr=None)
        with mock.patch("scripts.tls_rotation_runner.subprocess.run", return_value=completed) as run:
            runner = SanitizedSubprocessRunner({"PATH": "safe-bin", "UNRELATED": "drop"})
            self.assertEqual(
                runner.run(["docker", "version"], capture_output=True, input_text='{"x":1}'),
                "ok",
            )
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["env"], {"PATH": "safe-bin"})
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "strict")
        self.assertEqual(kwargs["input"], '{"x":1}')

    def test_runner_redacts_child_errors_and_rejects_invalid_boundaries(self) -> None:
        canary = "https://secret.invalid/token"
        with mock.patch(
            "scripts.tls_rotation_runner.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, ["docker", canary], stderr=canary),
        ):
            with self.assertRaisesRegex(RotationRuntimeError, "runtime command failed") as raised:
                SanitizedSubprocessRunner({"PATH": "safe"}).run(["docker", "version"])
        self.assertNotIn(canary, str(raised.exception))

        runner = SanitizedSubprocessRunner({"PATH": "safe"})
        for command in ([], ["docker", ""], ["docker", "bad\x00arg"]):
            with self.subTest(command=command), self.assertRaises(RotationRuntimeError):
                runner.run(command)
        with self.assertRaisesRegex(RotationRuntimeError, "input"):
            runner.run(["docker"], input_text="x" * 9000)


if __name__ == "__main__":
    unittest.main()
