from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_target_intake_runtime_attestation_release_handoff import (
    QUALITY_GATE,
    RUNBOOK,
    SIGNOFF,
    SOURCE,
    PRODUCTION_CONSUMERS,
    verification_errors,
)


class RuntimeAttestationReleaseHandoffStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SOURCE.read_text(encoding="utf-8")
        self.quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        self.runbook = RUNBOOK.read_text(encoding="utf-8")
        self.signoff = SIGNOFF.read_text(encoding="utf-8")
        self.consumers = tuple(path.read_text(encoding="utf-8") for path in PRODUCTION_CONSUMERS)

    def errors(self, *, source: str | None = None, quality_gate: str | None = None, runbook: str | None = None, signoff: str | None = None, consumers: tuple[str, ...] | None = None):
        return verification_errors(
            self.source if source is None else source,
            self.quality_gate if quality_gate is None else quality_gate,
            self.runbook if runbook is None else runbook,
            self.signoff if signoff is None else signoff,
            self.consumers if consumers is None else consumers,
        )

    def test_repository_contract_is_registered_and_negative(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_network_write_process_and_host_time_capabilities_are_rejected(self) -> None:
        for mutation in (
            "\nimport requests\n",
            "\nimport subprocess\n",
            "\nimport time\n",
            "\ndef unsafe(path):\n    path.write_text('x')\n",
        ):
            with self.subTest(mutation=mutation):
                self.assertTrue(self.errors(source=self.source + mutation))

    def test_pins_cross_image_binding_docs_and_consumer_isolation_are_locked(self) -> None:
        mutations = (
            ("source", self.source.replace('EXPECTED_NAMES = ("api", "web", "edge")', 'EXPECTED_NAMES = ("api", "web")', 1)),
            ("source", self.source.replace('"runtime_authority": "unverified"', '"runtime_authority": "verified"', 1)),
            ("quality_gate", self.quality_gate.replace("python scripts/verify_target_intake_runtime_attestation_release_handoff.py", "python scripts/removed.py", 1)),
            ("runbook", self.runbook.replace("caller-supplied handoff pin", "self-derived handoff pin", 1)),
            ("signoff", self.signoff.replace("GitHub Release persistence is not provider-native custody", "GitHub Release is provider custody", 1)),
            ("consumers", self.consumers + ("import target_intake_runtime_attestation_release_handoff",)),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                self.assertTrue(self.errors(**{field: value}))


if __name__ == "__main__":
    unittest.main()
