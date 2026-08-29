from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from scripts.target_intake_generation_context_trust import _canonical_digest
from scripts.verify_target_intake_generation_context_trust import (
    ATTRIBUTES,
    CONTRACT,
    POLICY,
    QUALITY_GATE,
    READINESS,
    trust_contract_errors,
)


class GenerationContextTrustStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = CONTRACT.read_text(encoding="utf-8")
        self.policy_raw = POLICY.read_bytes()
        self.readiness_raw = READINESS.read_bytes()
        self.quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        self.attributes = ATTRIBUTES.read_text(encoding="utf-8")

    def errors(
        self,
        *,
        source: str | None = None,
        policy_raw: bytes | None = None,
        readiness_raw: bytes | None = None,
        quality_gate: str | None = None,
        attributes: str | None = None,
    ) -> list[str]:
        return trust_contract_errors(
            self.source if source is None else source,
            self.policy_raw if policy_raw is None else policy_raw,
            self.readiness_raw if readiness_raw is None else readiness_raw,
            self.quality_gate if quality_gate is None else quality_gate,
            self.attributes if attributes is None else attributes,
        )

    @staticmethod
    def raw(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=True, indent=2).encode("ascii") + b"\n"
        )

    def test_current_contract_passes_and_is_in_quality_gate(self) -> None:
        self.assertEqual(self.errors(), [])
        self.assertIn(
            "python scripts/target_intake_generation_context_trust.py verify-repository",
            self.quality_gate,
        )
        self.assertIn(
            "python scripts/verify_target_intake_generation_context_trust.py",
            self.quality_gate,
        )

    def test_role_scope_domain_and_subject_inventory_cannot_drift(self) -> None:
        for old, new in (
            (
                "target_intake_generation_context_authority_v1_only",
                "private_secret_target_storage_receipt_v1_only",
            ),
            (
                "target_intake_generation_trusted_time_authority",
                "opaque_time_claim",
            ),
            (
                "email-platform/target-intake-generation-context-handoff/provider-head/v1",
                "email-platform/private-secret/provider-head/v1",
            ),
            (
                '    "cas_request_id",\n',
                "",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.source.replace(old, new, 1)
                self.assertNotEqual(mutated, self.source)
                self.assertTrue(self.errors(source=mutated))

    def test_read_path_and_unverified_outputs_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                "read_stable_bytes_with_metadata(\n            path, max_bytes=MAX_INTAKE_JSON_BYTES\n        )",
                "path.read_bytes()",
            ),
            ("metadata.st_nlink != 1", "False"),
            (
                "provider-head-cas=unverified",
                "provider-head-cas=verified",
            ),
            (
                "global-rollback-protection=unverified",
                "global-rollback-protection=verified",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.source.replace(old, new, 1)
                self.assertNotEqual(mutated, self.source)
                self.assertTrue(self.errors(source=mutated))

    def test_network_host_time_and_write_capabilities_are_rejected(self) -> None:
        for addition in ("\nimport socket\n", "\nimport time\n", "\nopen('x', 'w')\n"):
            with self.subTest(addition=addition):
                self.assertTrue(self.errors(source=self.source + addition))

    def test_quality_gate_registration_cannot_be_removed(self) -> None:
        mutated = self.quality_gate.replace(
            "    python scripts/target_intake_generation_context_trust.py verify-repository\n",
            "",
            1,
        )
        self.assertNotEqual(mutated, self.quality_gate)
        self.assertTrue(self.errors(quality_gate=mutated))

    def test_policy_and_readiness_bytes_remain_lf_stable_across_checkouts(self) -> None:
        mutated = self.attributes.replace(
            "deploy/target-intake-generation-context-handoff-policy.synthetic.json text eol=lf\n",
            "",
            1,
        )
        self.assertNotEqual(mutated, self.attributes)
        self.assertTrue(self.errors(attributes=mutated))

    def test_default_policy_cannot_claim_configuration_or_weaken_cas(self) -> None:
        policy = json.loads(self.policy_raw)
        for mutate in (
            lambda value: value.update({"policy_status": "configured"}),
            lambda value: value.update({"authoring_integration_enabled": True}),
            lambda value: value["trusted_timestamp"].update(
                {"authority_kind": "rfc3161_tsa"}
            ),
            lambda value: value["provider_head"].update(
                {"automatic_retry_forbidden": False}
            ),
        ):
            with self.subTest(mutate=mutate):
                candidate = deepcopy(policy)
                mutate(candidate)
                self.assertTrue(self.errors(policy_raw=self.raw(candidate)))

    def test_pending_readiness_cannot_be_promoted_even_when_resealed(self) -> None:
        readiness = json.loads(self.readiness_raw)
        for mutate in (
            lambda value: value.update({"readiness_status": "ready"}),
            lambda value: value.update({"provider_head": {}}),
            lambda value: value["assertions"].update(
                {"global_fork_absence_proven": True}
            ),
        ):
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
