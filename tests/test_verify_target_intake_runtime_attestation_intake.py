from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_target_intake_runtime_attestation_intake import (
    ATTRIBUTES,
    CONSUMER_PATHS,
    CONTRACT,
    EVIDENCE,
    POLICY,
    PROFILE,
    QUALITY_GATE,
    REQUIREMENTS,
    RUNBOOK,
    SIGNOFF,
    intake_contract_errors,
)


class RuntimeAttestationIntakeStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.values = {
            "source": CONTRACT.read_text(encoding="utf-8"),
            "policy_raw": POLICY.read_bytes(),
            "profile_raw": PROFILE.read_bytes(),
            "evidence_raw": EVIDENCE.read_bytes(),
            "quality_gate": QUALITY_GATE.read_text(encoding="utf-8"),
            "attributes": ATTRIBUTES.read_text(encoding="utf-8"),
            "runbook": RUNBOOK.read_text(encoding="utf-8"),
            "signoff": SIGNOFF.read_text(encoding="utf-8"),
            "requirements": REQUIREMENTS.read_text(encoding="utf-8"),
            "consumer_sources": tuple(
                path.read_text(encoding="utf-8") for path in CONSUMER_PATHS
            ),
        }

    def errors(self, **overrides: object) -> list[str]:
        values = dict(self.values)
        values.update(overrides)
        return intake_contract_errors(**values)

    def test_current_contract_and_assets_pass(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_import_allowlist_and_core_capability_mutations_fail(self) -> None:
        self.assertTrue(
            any(
                "imports exceed" in error
                for error in self.errors(source=self.values["source"] + "\nimport requests\n")
            )
        )
        mutated = self.values["source"].replace(
            "parse_policy(policy_raw)", "open(policy_raw)", 1
        )
        self.assertTrue(any("external I/O" in error for error in self.errors(source=mutated)))

    def test_provider_literals_and_subject_anchor_mutations_fail(self) -> None:
        mutated = self.values["source"].replace(
            'SIGSTORE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"',
            'SIGSTORE_MEDIA_TYPE = "application/json"',
            1,
        )
        self.assertTrue(any("anchors drifted" in error for error in self.errors(source=mutated)))
        mutated = self.values["source"].replace(
            "5f5d42ed25b9d4c5ad62f53aa4368273642dcdace47c5eb61d2e3997abd6d4bf",
            "0" * 64,
            1,
        )
        self.assertTrue(any("anchors drifted" in error for error in self.errors(source=mutated)))

    def test_caller_pins_and_canonical_parser_mutations_fail(self) -> None:
        before, separator, after = self.values["source"].rpartition(
            "expected_runtime_subject_sha256=expected_runtime_subject_sha256,"
        )
        self.assertTrue(separator)
        mutated = before + "expected_runtime_subject_sha256=actual_policy," + after
        self.assertTrue(any("caller pins" in error for error in self.errors(source=mutated)))
        mutated = self.values["source"].replace(
            "if raw != _artifact_bytes(value):",
            "if False:",
            1,
        )
        self.assertTrue(any("canonical JSON" in error for error in self.errors(source=mutated)))

    def test_caller_authored_assertions_are_forbidden(self) -> None:
        mutated = self.values["source"] + '\n_CALLER_FIELD = "assertions"\n'
        self.assertTrue(
            any("caller-authored" in error for error in self.errors(source=mutated))
        )

    def test_quality_gate_and_lf_attributes_are_required(self) -> None:
        quality = self.values["quality_gate"].replace(
            "python scripts/verify_target_intake_runtime_attestation_intake.py",
            "python scripts/disabled_runtime_attestation_intake.py",
            1,
        )
        self.assertTrue(any("quality gate" in error for error in self.errors(quality_gate=quality)))
        attributes = self.values["attributes"].replace(
            "deploy/target-intake-runtime-attestation-profile.synthetic.json text eol=lf",
            "",
            1,
        )
        self.assertTrue(any("LF-stable" in error for error in self.errors(attributes=attributes)))

    def test_existing_consumers_and_documentation_cannot_silently_integrate(self) -> None:
        consumers = list(self.values["consumer_sources"])
        consumers[0] += "\nimport scripts.target_intake_runtime_attestation_intake\n"
        self.assertTrue(
            any("must not be consumed" in error for error in self.errors(consumer_sources=tuple(consumers)))
        )
        runbook = self.values["runbook"].replace("protocol bindings only", "protocol acceptance", 1)
        self.assertTrue(any("runbook" in error for error in self.errors(runbook=runbook)))
        signoff = self.values["signoff"].replace(
            "Runtime-attestation protocol-only acknowledgement", "Runtime acknowledgement", 1
        )
        self.assertTrue(any("signoff" in error for error in self.errors(signoff=signoff)))
        requirements = self.values["requirements"].replace(
            "protocol bindings do not authenticate", "protocol bindings authenticate", 1
        )
        self.assertTrue(
            any("requirement boundary" in error for error in self.errors(requirements=requirements))
        )

    def test_raw_anchor_drift_fails_before_semantic_equivalence(self) -> None:
        profile = self.values["profile_raw"].replace(b"\n", b"\r\n")
        self.assertTrue(any("raw anchors drifted" in error for error in self.errors(profile_raw=profile)))
        evidence = self.values["evidence_raw"] + b" "
        self.assertTrue(any("raw anchors drifted" in error for error in self.errors(evidence_raw=evidence)))


if __name__ == "__main__":
    unittest.main()
