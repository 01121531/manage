import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.report_trivy_sarif import _github_escape, findings


class TrivySarifReporterTests(unittest.TestCase):
    def test_extracts_findings_and_escapes_workflow_commands(self) -> None:
        with TemporaryDirectory() as directory:
            report = Path(directory) / "report.sarif"
            report.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "results": [
                                    {
                                        "ruleId": "CVE-TEST-1",
                                        "message": {"text": "package%name\nfixed version"},
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                [("CVE-TEST-1", "package%name\nfixed version")],
                findings(report),
            )
            self.assertEqual(
                "package%25name%0Afixed",
                _github_escape("package%name\nfixed"),
            )

    def test_rejects_non_sarif_shape(self) -> None:
        with TemporaryDirectory() as directory:
            report = Path(directory) / "report.sarif"
            report.write_text('{"runs": {}}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "runs"):
                findings(report)


if __name__ == "__main__":
    unittest.main()
