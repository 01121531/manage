from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

from scripts.scan_third_party_images import (
    ThirdPartyScanError,
    scan_third_party_images,
)


DIGEST_ENV = {
    "POSTGRES_IMAGE_SHA256": "1" * 64,
    "REDIS_IMAGE_SHA256": "2" * 64,
    "KEYCLOAK_IMAGE_SHA256": "3" * 64,
    "ALERTMANAGER_IMAGE_SHA256": "4" * 64,
    "PROMETHEUS_IMAGE_SHA256": "5" * 64,
}


class ScanRunner:
    def __init__(
        self,
        *,
        wrong_target: bool = False,
        findings: bool = False,
        malformed: bool = False,
        tool_name: str = "Trivy",
        fail_on: str | None = None,
    ) -> None:
        self.wrong_target = wrong_target
        self.findings = findings
        self.malformed = malformed
        self.tool_name = tool_name
        self.fail_on = fail_on
        self.calls: list[list[str]] = []

    def run(self, command, *, env=None, capture_output=False):
        command = list(command)
        self.calls.append(command)
        if self.fail_on and self.fail_on in command[-1]:
            raise subprocess.CalledProcessError(1, command)
        output = Path(command[command.index("--output") + 1])
        if self.malformed:
            output.write_text("not-json", encoding="utf-8")
            return ""
        target = "postgres@sha256:" + "f" * 64 if self.wrong_target else command[-1]
        output.write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "tool": {"driver": {"name": self.tool_name}},
                            "properties": {"imageName": target},
                            "results": (
                                [{"ruleId": "CVE-TEST", "message": {"text": "blocked"}}]
                                if self.findings
                                else []
                            ),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return ""


class ThirdPartyImageScanTests(unittest.TestCase):
    def test_scans_exactly_five_digest_bound_images(self) -> None:
        runner = ScanRunner()
        scan_third_party_images(DIGEST_ENV, runner)

        self.assertEqual(len(runner.calls), 5)
        references = [command[-1] for command in runner.calls]
        self.assertEqual(
            references,
            [
                "postgres@sha256:" + "1" * 64,
                "redis@sha256:" + "2" * 64,
                "quay.io/keycloak/keycloak@sha256:" + "3" * 64,
                "prom/alertmanager@sha256:" + "4" * 64,
                "prom/prometheus@sha256:" + "5" * 64,
            ],
        )
        self.assertNotIn("vault", " ".join(references))
        for command in runner.calls:
            self.assertEqual(command[:2], ["trivy", "image"])
            self.assertIn("--exit-code", command)
            self.assertIn("HIGH,CRITICAL", command)
            self.assertIn("--ignore-unfixed=false", command)
            self.assertIn("--scanners", command)
            self.assertIn("vuln", command)
            self.assertIn("--pkg-types", command)
            self.assertIn("os,library", command)

    def test_missing_tag_or_malformed_digest_fails_before_scan(self) -> None:
        for value in ("", "postgres:16-alpine", "A" * 64, "a" * 63):
            runner = ScanRunner()
            environment = {**DIGEST_ENV, "POSTGRES_IMAGE_SHA256": value}
            with self.subTest(value=value):
                with self.assertRaises(ThirdPartyScanError):
                    scan_third_party_images(environment, runner)
                self.assertEqual(runner.calls, [])

    def test_report_must_be_trivy_clean_and_bound_to_exact_image(self) -> None:
        for runner in (
            ScanRunner(wrong_target=True),
            ScanRunner(findings=True),
            ScanRunner(malformed=True),
            ScanRunner(tool_name="not-trivy"),
        ):
            with self.subTest(runner=type(runner).__name__, state=vars(runner)):
                with self.assertRaises(ThirdPartyScanError):
                    scan_third_party_images(DIGEST_ENV, runner)

    def test_scanner_failure_stops_remaining_images(self) -> None:
        runner = ScanRunner(fail_on="redis@sha256:")
        with self.assertRaises(subprocess.CalledProcessError):
            scan_third_party_images(DIGEST_ENV, runner)
        self.assertEqual(len(runner.calls), 2)


if __name__ == "__main__":
    unittest.main()
