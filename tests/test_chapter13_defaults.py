from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from scripts.verify_chapter13_defaults import DECISIONS, decision_errors


class Chapter13DefaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(DECISIONS.read_text(encoding="utf-8"))

    def test_reviewed_defaults_match_runtime_contracts(self) -> None:
        self.assertEqual(decision_errors(self.document), [])
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_chapter13_defaults.py", quality_gate)

    def test_rejects_claimed_acceptance_or_default_drift(self) -> None:
        mutations = []
        accepted = copy.deepcopy(self.document)
        accepted["production_acceptance"] = True
        mutations.append(accepted)
        browser_default = copy.deepcopy(self.document)
        browser_default["decisions"]["sub2_adapter"]["default"] = "browser_automation"
        mutations.append(browser_default)
        raised_capacity = copy.deepcopy(self.document)
        raised_capacity["decisions"]["capacity_basis"]["concurrent_tasks"] = 40
        mutations.append(raised_capacity)
        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(decision_errors(document))

    def test_rejects_runtime_concurrency_default_drift(self) -> None:
        from platform.config import Settings

        with mock.patch.object(Settings.model_fields["sub2_concurrency"], "default", 40):
            self.assertIn(
                "chapter-13 runtime defaults have drifted",
                decision_errors(self.document),
            )

    def test_compose_concurrency_fallback_matches_the_reviewed_default(self) -> None:
        compose_text = Path("docker-compose.yml").read_text(encoding="utf-8")
        self.assertEqual(decision_errors(self.document), [])
        self.assertIn("PLATFORM_SUB2_CONCURRENCY:-10", compose_text)
        self.assertNotIn("PLATFORM_SUB2_CONCURRENCY:-40", compose_text)

        drifted = compose_text.replace(
            "PLATFORM_SUB2_CONCURRENCY:-10",
            "PLATFORM_SUB2_CONCURRENCY:-40",
        )
        self.assertIn(
            "chapter-13 Compose concurrency default has drifted",
            decision_errors(self.document, compose_text=drifted),
        )


if __name__ == "__main__":
    unittest.main()
