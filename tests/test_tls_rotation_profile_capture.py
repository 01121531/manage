from __future__ import annotations

import unittest

from scripts.tls_rotation_profile_capture import (
    TlsRotationProfileCaptureError,
    validate_capture_request,
)
from scripts.tls_rotation_profile_live import ReadOnlyCaptureRunner


class Delegate:
    def __init__(self) -> None:
        self.calls = []

    def run(self, command, *, capture_output=False, input_text=None):
        self.calls.append((list(command), capture_output, input_text))
        return "metadata"


class TlsRotationProfileCaptureTests(unittest.TestCase):
    def test_compose_request_is_closed_and_rejects_placeholders(self) -> None:
        request = {
            "schema_version": 1,
            "request_kind": "tls_rotation_profile_capture_request",
            "runtime_kind": "compose",
            "target_environment": "production-cn",
            "service": "api",
        }
        self.assertEqual(validate_capture_request(request), request)
        for mutation in (
            {**request, "extra": True},
            {**request, "target_environment": "test"},
            {**request, "runtime_kind": "nomad"},
        ):
            with self.assertRaises(TlsRotationProfileCaptureError):
                validate_capture_request(mutation)

    def test_runner_allows_only_capture_output_metadata_reads(self) -> None:
        delegate = Delegate()
        runner = ReadOnlyCaptureRunner(delegate)
        compose = [
            "docker", "compose", "--project-directory", "D:/project/email-1",
            "-f", "docker-compose.yml",
        ]
        self.assertEqual(
            runner.run([*compose, "config", "--images", "api"], capture_output=True),
            "metadata",
        )
        runner.run(
            ["docker", "inspect", "--format", "{{.Id}}", "1" * 64],
            capture_output=True,
        )
        runner.run([
            "kubectl", "--kubeconfig", "C:/protected/kubeconfig",
            "--context", "prod", "--request-timeout=30s",
            "--namespace", "email-platform",
            "get", "deployment", "api", "-o", "json",
        ], capture_output=True)
        self.assertEqual(len(delegate.calls), 3)

    def test_runner_rejects_mutation_probe_and_secret_reads(self) -> None:
        runner = ReadOnlyCaptureRunner(Delegate())
        commands = (
            ["docker", "compose", "up", "config", "--images", "api"],
            ["docker", "compose", "exec", "api", "python"],
            ["kubectl", "get", "secret", "tls", "-o", "json"],
            [
                "kubectl", "--kubeconfig", "C:/protected/kubeconfig",
                "--context", "prod", "--request-timeout=30s",
                "get", "secret/name", "-o", "json",
            ],
            [
                "kubectl", "--kubeconfig", "C:/protected/kubeconfig",
                "--context", "prod", "--request-timeout=30s",
                "get", "--raw=/api/v1/namespaces/x/secrets/name", "-o", "json",
            ],
            [
                "kubectl", "--kubeconfig", "C:/protected/kubeconfig",
                "--context", "prod", "--request-timeout=30s",
                "auth", "can-i", "get", "pods",
            ],
            [
                "kubectl", "--kubeconfig", "C:/protected/kubeconfig",
                "--context", "prod", "--request-timeout=30s",
                "--namespace", "email-platform", "get", "pods", "-l",
                "app.kubernetes.io/name=email-platform,app.kubernetes.io/component=web,extra=value",
                "-o", "json",
            ],
            ["kubectl", "exec", "pod", "--", "openssl"],
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaises(
                TlsRotationProfileCaptureError
            ):
                runner.run(command, capture_output=True)
        with self.assertRaises(TlsRotationProfileCaptureError):
            runner.run(["kubectl", "get", "pod", "api"], capture_output=False)


if __name__ == "__main__":
    unittest.main()
