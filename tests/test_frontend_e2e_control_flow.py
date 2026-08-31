from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_E2E = ROOT / "frontend" / "e2e" / "platform.spec.ts"
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"


class FrontendE2EControlFlowTests(unittest.TestCase):
    def test_playwright_cases_do_not_silently_return_early(self) -> None:
        source = PLATFORM_E2E.read_text(encoding="utf-8")
        unconditional_returns = [
            line_number
            for line_number, line in enumerate(source.splitlines(), start=1)
            if re.fullmatch(r"\s+return\s*;?", line)
        ]
        self.assertEqual(
            unconditional_returns,
            [],
            f"standalone return truncates Playwright coverage at lines {unconditional_returns}",
        )

    def test_quality_gate_runs_playwright_before_success(self) -> None:
        source = QUALITY_GATE.read_text(encoding="utf-8")
        self.assertLess(source.index("npm run build"), source.index("npm run test:e2e"))
        self.assertLess(
            source.index("npm run test:e2e"),
            source.index('Write-Host "Quality gate passed."'),
        )


if __name__ == "__main__":
    unittest.main()
