from __future__ import annotations

import unittest

from scripts.verify_tls_rotation_artifacts import (
    ASSESSMENT,
    ATTEMPT_RECEIPT,
    CAPTURE,
    HANDOFF,
    KUBECONFIG_INTAKE,
    KUBERNETES_BACKEND,
    LIVE_CAPTURE,
    PROFILE,
    PUBLISHER_POLICY,
    PUBLISHER_POLICY_SOURCE,
    SUPPORT,
    validate_sources,
)


class VerifyTlsRotationArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = PROFILE.read_text(encoding="utf-8")
        cls.assessment = ASSESSMENT.read_text(encoding="utf-8")
        cls.handoff = HANDOFF.read_text(encoding="utf-8")
        cls.support = SUPPORT.read_text(encoding="utf-8")
        cls.capture = CAPTURE.read_text(encoding="utf-8")
        cls.live_capture = LIVE_CAPTURE.read_text(encoding="utf-8")
        cls.attempt_receipt = ATTEMPT_RECEIPT.read_text(encoding="utf-8")
        cls.kubeconfig_intake = KUBECONFIG_INTAKE.read_text(encoding="utf-8")
        cls.kubernetes_backend = KUBERNETES_BACKEND.read_text(encoding="utf-8")
        cls.publisher_policy_source = PUBLISHER_POLICY_SOURCE.read_text(encoding="utf-8")
        cls.publisher_policy = PUBLISHER_POLICY.read_bytes()

    def validate(
        self, *, profile=None, assessment=None, handoff=None, support=None,
        capture=None, live_capture=None, attempt_receipt=None,
        kubeconfig_intake=None, kubernetes_backend=None,
        publisher_policy_source=None, publisher_policy=None,
    ):
        return validate_sources(
            self.profile if profile is None else profile,
            self.assessment if assessment is None else assessment,
            self.handoff if handoff is None else handoff,
            self.support if support is None else support,
            self.capture if capture is None else capture,
            self.live_capture if live_capture is None else live_capture,
            self.attempt_receipt if attempt_receipt is None else attempt_receipt,
            self.kubeconfig_intake if kubeconfig_intake is None else kubeconfig_intake,
            self.kubernetes_backend if kubernetes_backend is None else kubernetes_backend,
            self.publisher_policy_source if publisher_policy_source is None else publisher_policy_source,
            self.publisher_policy if publisher_policy is None else publisher_policy,
        )

    def test_current_contract_passes(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_profile_validator_and_write_once_mutations_fail(self) -> None:
        self.assertTrue(self.validate(profile=self.profile.replace(
            "load_capture(capture_source, request)", "dict(capture={})", 1
        )))
        self.assertTrue(self.validate(profile=self.profile.replace(
            "publish_write_once_file(temporary, output)", "output.write_bytes(canonical)", 1
        )))

    def test_assessment_entity_review_and_plan_binding_mutations_fail(self) -> None:
        self.assertTrue(self.validate(assessment=self.assessment.replace(
            "_confirm(projection, confirm_rotation_plan_sha256)", "pass", 1
        )))
        self.assertTrue(self.validate(assessment=self.assessment.replace(
            "generate.add_argument(\"--projection\"",
            "generate.add_argument(\"--runtime-state\"",
            1,
        )))
        self.assertTrue(self.validate(assessment=self.assessment.replace(
            "load_support(", "unchecked_support(", 1
        )))

    def test_support_derivation_mutations_fail(self) -> None:
        self.assertTrue(self.validate(support=self.support.replace(
            "validate_evidence(dict(evidence))", "dict(evidence)", 1
        )))
        self.assertTrue(self.validate(support=self.support.replace(
            "assert_expected_rotation(validated, projection)", "pass", 1
        )))

    def test_mutation_capability_and_handoff_validator_removal_fail(self) -> None:
        self.assertTrue(self.validate(capture=self.capture.replace(
            "request = load_capture_request(source)",
            "ComposeRotationBackend(value, runner).act()\n        request = load_capture_request(source)",
            1,
        )))
        self.assertTrue(self.validate(handoff=self.handoff.replace(
            "assessment = load_assessment(", "assessment = unchecked_assessment(", 1
        )))

    def test_live_capture_probe_or_secret_boundary_mutations_fail(self) -> None:
        self.assertTrue(self.validate(live_capture=self.live_capture.replace(
            "collect_compose_generation(", "compose_probe_command(", 1
        )))
        self.assertTrue(self.validate(live_capture=self.live_capture.replace(
            "def _allowed_kubernetes_get(", "def unchecked_kubernetes_get(", 1
        )))
        self.assertTrue(self.validate(live_capture=self.live_capture.replace(
            "validate_self_contained_kubeconfig(", "unchecked_kubeconfig(", 1
        )))
        self.assertTrue(self.validate(live_capture=self.live_capture.replace(
            "materialize_private_secret_bytes(", "unchecked_materialization(", 1
        )))
        self.assertTrue(self.validate(live_capture=self.live_capture.replace(
            "materialized.verify()", "pass", 1
        )))

    def test_kubeconfig_intake_and_backend_binding_mutations_fail(self) -> None:
        self.assertTrue(self.validate(kubeconfig_intake=self.kubeconfig_intake.replace(
            'parsed.scheme != "https"', "False", 1
        )))
        self.assertTrue(self.validate(
            kubeconfig_intake="import subprocess\n" + self.kubeconfig_intake
        ))
        self.assertTrue(self.validate(kubernetes_backend=self.kubernetes_backend.replace(
            "validate_self_contained_kubeconfig(", "unchecked_kubeconfig(", 1
        )))

    def test_attempt_receipt_authentication_and_purity_mutations_fail(self) -> None:
        self.assertTrue(self.validate(attempt_receipt=self.attempt_receipt.replace(
            "def verify_authenticated_attempt(", "def unchecked_attempt(", 1
        )))
        self.assertTrue(self.validate(attempt_receipt=self.attempt_receipt.replace(
            'payload["not_committed_eligible"] is not False', "False", 1
        )))
        self.assertTrue(self.validate(
            attempt_receipt="import subprocess\n" + self.attempt_receipt
        ))

    def test_publisher_prerequisite_policy_mutations_fail(self) -> None:
        self.assertTrue(self.validate(
            publisher_policy=self.publisher_policy.replace(
                b'"publisher_integration_enabled": false',
                b'"publisher_integration_enabled": true',
                1,
            )
        ))
        self.assertTrue(self.validate(
            publisher_policy_source=self.publisher_policy_source.replace(
                'ordering["state"] != "not_implemented"', "False", 1
            )
        ))
        self.assertTrue(self.validate(
            publisher_policy_source="import subprocess\n" + self.publisher_policy_source
        ))


if __name__ == "__main__":
    unittest.main()
