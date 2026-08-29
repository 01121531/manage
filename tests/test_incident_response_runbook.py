from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_runbooks import incident_response_runbook_errors


RUNBOOK = Path("deploy/runbooks/incident-response.md")


class IncidentResponseRunbookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = RUNBOOK.read_text(encoding="utf-8")

    def assert_rejected_after_replace(self, old: str, new: str) -> None:
        self.assertIn(old, self.text)
        mutated = self.text.replace(old, new, 1)
        self.assertTrue(incident_response_runbook_errors(mutated))

    def test_current_runbook_passes_structured_contract(self) -> None:
        self.assertEqual(incident_response_runbook_errors(self.text), [])

    def test_rejects_plaintext_or_unverified_monitoring(self) -> None:
        mutations = (
            ("https://prometheus:9090/-/ready", "http://prometheus:9090/-/ready"),
            ("--cacert $internalCa", "--insecure"),
            (
                "--resolve prometheus:9090:127.0.0.1",
                "--resolve prometheus:9090:127.0.0.2",
            ),
            (
                "--tlsv1.2 `\n     https://prometheus:9090/-/ready",
                "--tlsv1.0 `\n     https://prometheus:9090/-/ready",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assert_rejected_after_replace(old, new)

    def test_rejects_missing_role_object_or_terminal_evidence(self) -> None:
        mutations = (
            ("security_auditor", "read_only_user"),
            ("ops_admin", "operator"),
            (
                "exact upload ID, task ID, business name, trace ID",
                "exact upload ID and trace ID",
            ),
            (
                "row whose upload ID, task ID, business name",
                "row whose upload ID",
            ),
            ("status=succeeded", "success"),
            ("external_ref", "reference"),
            ("status=failed", "failure"),
            ("error_code", "error"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assert_rejected_after_replace(old, new)

    def test_rejects_missing_ambiguous_response_recovery(self) -> None:
        mutations = (
            ("response is missing or ambiguous", "request failed"),
            ("refresh the same upload first", "submit again"),
            ("Do not\n     replay reconciliation", "Retry reconciliation"),
            ("Never create a new idempotency key", "Create a new idempotency key"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assert_rejected_after_replace(old, new)

    def test_rejects_raw_privileged_curl_example(self) -> None:
        mutated = self.text + (
            "\n```powershell\n"
            "curl.exe https://platform.example/api/v1/upload-jobs/{job_id}/reconcile\n"
            "```\n"
        )
        self.assertTrue(incident_response_runbook_errors(mutated))


if __name__ == "__main__":
    unittest.main()
