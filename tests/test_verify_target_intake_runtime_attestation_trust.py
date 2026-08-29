from __future__ import annotations

from copy import deepcopy
import json
import unittest

from scripts.target_intake_runtime_attestation_trust import _canonical_digest
from scripts.verify_target_intake_runtime_attestation_trust import (
    ATTRIBUTES,
    CONSUMER_PATHS,
    CONTRACT,
    POLICY,
    QUALITY_GATE,
    READINESS,
    REQUIREMENTS,
    RUNBOOK,
    SIGNOFF,
    trust_contract_errors,
)


class RuntimeAttestationTrustStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = CONTRACT.read_text(encoding="utf-8")
        self.policy_raw = POLICY.read_bytes()
        self.readiness_raw = READINESS.read_bytes()
        self.quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        self.attributes = ATTRIBUTES.read_text(encoding="utf-8")
        self.consumer_sources = tuple(
            path.read_text(encoding="utf-8") for path in CONSUMER_PATHS
        )
        self.documentation_sources = (
            RUNBOOK.read_text(encoding="utf-8"),
            SIGNOFF.read_text(encoding="utf-8"),
            REQUIREMENTS.read_text(encoding="utf-8"),
        )

    def errors(
        self,
        *,
        source: str | None = None,
        policy_raw: bytes | None = None,
        readiness_raw: bytes | None = None,
        quality_gate: str | None = None,
        attributes: str | None = None,
        consumer_sources: tuple[str, ...] | None = None,
        documentation_sources: tuple[str, str, str] | None = None,
    ) -> list[str]:
        return trust_contract_errors(
            self.source if source is None else source,
            self.policy_raw if policy_raw is None else policy_raw,
            self.readiness_raw if readiness_raw is None else readiness_raw,
            self.quality_gate if quality_gate is None else quality_gate,
            self.attributes if attributes is None else attributes,
            self.consumer_sources if consumer_sources is None else consumer_sources,
            (
                self.documentation_sources
                if documentation_sources is None
                else documentation_sources
            ),
        )

    @staticmethod
    def raw(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=True, indent=2).encode("ascii") + b"\n"

    def test_current_contract_passes_and_is_in_quality_gate(self) -> None:
        self.assertEqual(self.errors(), [])
        for command in (
            "python scripts/target_intake_runtime_attestation_trust.py verify-repository",
            "python scripts/verify_target_intake_runtime_attestation_trust.py",
        ):
            self.assertIn(command, self.quality_gate)

    def test_independent_role_scope_domain_and_subject_anchors_cannot_drift(self) -> None:
        for old, new in (
            (
                "target_intake_runtime_publisher_v1_only",
                "target_intake_generation_context_authority_v1_only",
            ),
            (
                "target_intake_runtime_provenance_authority",
                "target_intake_runtime_publisher_authority",
            ),
            (
                "email-platform/target-intake-runtime-attestation-handoff/target-observer/v1",
                "email-platform/target-intake-generation-context-handoff/context-authority/v1",
            ),
            ('    "target_loaded_evidence_sha256",\n', ""),
        ):
            with self.subTest(old=old):
                mutated = self.source.replace(old, new, 1)
                self.assertNotEqual(mutated, self.source)
                self.assertTrue(self.errors(source=mutated))

    def test_capability_allowlist_rejects_network_host_time_signing_and_writes(self) -> None:
        additions = (
            "\nimport socket\n",
            "\nimport datetime\n",
            "\nimport subprocess\n",
            "\nimport cryptography\n",
            "\nopen('x', 'w')\n",
            "\nPath('x').write_bytes(b'x')\n",
            "\nkey.sign(b'x')\n",
            "\nEd25519PrivateKey.generate()\n",
        )
        for addition in additions:
            with self.subTest(addition=addition):
                self.assertTrue(self.errors(source=self.source + addition))

    def test_stable_read_and_unverified_outputs_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                "read_stable_bytes_with_metadata(\n            path, max_bytes=MAX_INTAKE_JSON_BYTES\n        )",
                "path.read_bytes()",
            ),
            ("metadata.st_nlink != 1", "False"),
            ("target-loaded-evidence=unverified", "target-loaded-evidence=verified"),
            ("runtime-authority=unverified", "runtime-authority=verified"),
            ("original-execution=unverified", "original-execution=verified"),
        ):
            with self.subTest(old=old):
                mutated = self.source.replace(old, new, 1)
                self.assertNotEqual(mutated, self.source)
                self.assertTrue(self.errors(source=mutated))

    def test_quality_gate_lf_and_no_consumption_guards_cannot_be_removed(self) -> None:
        mutated_gate = self.quality_gate.replace(
            "    python scripts/target_intake_runtime_attestation_trust.py verify-repository\n",
            "",
            1,
        )
        self.assertTrue(self.errors(quality_gate=mutated_gate))
        mutated_attributes = self.attributes.replace(
            "deploy/target-intake-runtime-attestation-policy.synthetic.json text eol=lf\n",
            "",
            1,
        )
        self.assertTrue(self.errors(attributes=mutated_attributes))
        consumers = self.consumer_sources + (
            "from scripts import target_intake_runtime_attestation_trust\n",
        )
        self.assertTrue(self.errors(consumer_sources=consumers))
        documents = (
            self.documentation_sources[0].replace(
                "five distinct runtime-specific", "shared runtime", 1
            ),
            self.documentation_sources[1],
            self.documentation_sources[2],
        )
        self.assertTrue(self.errors(documentation_sources=documents))

    def test_default_policy_cannot_claim_configuration_or_weaken_runtime_binding(self) -> None:
        policy = json.loads(self.policy_raw)
        mutations = (
            lambda value: value.update({"policy_status": "configured"}),
            lambda value: value.update({"deployment_integration_enabled": True}),
            lambda value: value.update(
                {"runtime_acceptance_integration_enabled": True}
            ),
            lambda value: value["publisher_signature"].update(
                {"trust_anchor_sha256": "a" * 64}
            ),
            lambda value: value["provenance_attestation"].update(
                {"builder_identity": "claimed-builder"}
            ),
            lambda value: value["target_runtime_observation"].update(
                {"process_identity_required": False}
            ),
            lambda value: value["provider_head"].update(
                {"automatic_retry_forbidden": False}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(policy)
                mutate(candidate)
                self.assertTrue(self.errors(policy_raw=self.raw(candidate)))

    def test_pending_readiness_cannot_be_promoted_even_when_resealed(self) -> None:
        readiness = json.loads(self.readiness_raw)
        mutations = (
            lambda value: value.update({"readiness_status": "ready"}),
            lambda value: value.update({"publisher_signature": {}}),
            lambda value: value.update({"target_runtime_observation": {}}),
            lambda value: value["assertions"].update(
                {"target_process_identity_bound": True}
            ),
            lambda value: value["assertions"].update(
                {"global_fork_absence_proven": True}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(readiness)
                mutate(candidate)
                payload = {
                    key: item for key, item in candidate.items() if key != "integrity"
                }
                candidate["integrity"] = {
                    "payload_sha256": _canonical_digest(payload)
                }
                self.assertTrue(self.errors(readiness_raw=self.raw(candidate)))


if __name__ == "__main__":
    unittest.main()
