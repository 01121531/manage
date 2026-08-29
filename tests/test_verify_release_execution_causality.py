from __future__ import annotations

from pathlib import Path
import re
import unittest

from scripts.verify_release_execution_causality import (
    BINDING,
    CONSUMERS,
    INTAKE,
    INTAKE_MANIFEST,
    INTAKE_ONLY_CONSUMERS,
    causality_errors,
)


class ReleaseExecutionCausalityStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binding = BINDING.read_text(encoding="utf-8")
        self.intake = INTAKE.read_text(encoding="utf-8")
        self.intake_manifest = INTAKE_MANIFEST.read_text(encoding="utf-8")
        self.consumers = {
            name: path.read_text(encoding="utf-8")
            for name, path in CONSUMERS.items()
        }
        self.intake_only_consumers = {
            name: path.read_text(encoding="utf-8")
            for name, path in INTAKE_ONLY_CONSUMERS.items()
        }

    def errors(
        self,
        *,
        binding: str | None = None,
        intake: str | None = None,
        consumers: dict[str, str] | None = None,
        intake_manifest: str | None = None,
        intake_only_consumers: dict[str, str] | None = None,
    ) -> list[str]:
        return causality_errors(
            self.binding if binding is None else binding,
            self.intake if intake is None else intake,
            self.consumers if consumers is None else consumers,
            self.intake_manifest if intake_manifest is None else intake_manifest,
            (
                self.intake_only_consumers
                if intake_only_consumers is None
                else intake_only_consumers
            ),
        )

    def test_current_contract_passes_and_is_in_the_quality_gate(self) -> None:
        self.assertEqual(self.errors(), [])
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_release_execution_causality.py", gate)

    def test_shared_intake_manifest_requires_one_stable_dual_pin_read(self) -> None:
        for old, new in (
            ("load_unique_json_with_bytes(", "load_unique_json("),
            (
                "not hmac.compare_digest(actual_file_sha256, expected_file_sha256)\n",
                "actual_file_sha256 != expected_file_sha256\n",
            ),
            (
                "not hmac.compare_digest(actual_payload_sha256, expected_payload_sha256)\n",
                "actual_payload_sha256 != expected_payload_sha256\n",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.intake_manifest.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake_manifest)
                self.assertTrue(self.errors(intake_manifest=mutated))

    def test_shared_intake_manifest_inventory_is_exact_and_ordered(self) -> None:
        mutated = self.intake_manifest.replace(
            '    "mail_contract",\n',
            "",
            1,
        )
        self.assertNotEqual(mutated, self.intake_manifest)
        self.assertTrue(self.errors(intake_manifest=mutated))

    def test_shared_artifact_binding_requires_raw_sha256_comparison(self) -> None:
        mutated = self.intake_manifest.replace(
            "and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected)",
            "and hashlib.sha256(raw).hexdigest() == expected",
            1,
        )
        self.assertNotEqual(mutated, self.intake_manifest)
        self.assertTrue(self.errors(intake_manifest=mutated))

    def test_each_consumer_requires_both_pins_and_reports_boundary(self) -> None:
        name = "sub2_execution_evidence.py"
        for removed in (
            '        "--expected-intake-manifest-payload-sha256", required=True\n',
            '        "intake-manifest-caller-pin=payload-and-file-matched "\n',
        ):
            with self.subTest(removed=removed):
                mutated = dict(self.consumers)
                mutated[name] = mutated[name].replace(removed, "", 1)
                self.assertNotEqual(mutated[name], self.consumers[name])
                self.assertTrue(self.errors(consumers=mutated))

    def test_consumer_must_pin_manifest_before_other_evidence_reads(self) -> None:
        name = "sub2_execution_evidence.py"
        source = self.consumers[name]
        old = """    try:
        manifest = load_pinned_intake_manifest(
"""
        new = """    document = _load(arguments.input)
    try:
        manifest = load_pinned_intake_manifest(
"""
        mutated = dict(self.consumers)
        mutated[name] = source.replace(old, new, 1)
        self.assertNotEqual(mutated[name], source)
        self.assertTrue(self.errors(consumers=mutated))

    def test_non_release_consumers_use_the_same_closed_dual_pin_boundary(self) -> None:
        for name in self.intake_only_consumers:
            with self.subTest(name=name):
                mutated = dict(self.intake_only_consumers)
                mutated[name] = mutated[name].replace(
                    '    check.add_argument("--expected-intake-manifest-file-sha256", required=True)\n',
                    "",
                    1,
                )
                self.assertNotEqual(mutated[name], self.intake_only_consumers[name])
                self.assertTrue(self.errors(intake_only_consumers=mutated))

    def test_all_standalone_consumers_bind_their_own_stable_input_bytes(self) -> None:
        for sources_argument, sources in (
            ("consumers", self.consumers),
            ("intake_only_consumers", self.intake_only_consumers),
        ):
            for name, source in sources.items():
                with self.subTest(name=name):
                    mutated = dict(sources)
                    mutated[name] = source.replace(
                        "if not manifest_artifact_sha256_matches(",
                        "if not manifest_artifact_sha256_ignored(",
                        1,
                    )
                    self.assertNotEqual(mutated[name], source)
                    self.assertTrue(self.errors(**{sources_argument: mutated}))

    def test_identity_cannot_replace_finish_with_start(self) -> None:
        mutated = self.binding.replace(
            '"finished_at": evidence["finished_at"],',
            '"finished_at": evidence["started_at"],',
            1,
        )
        self.assertNotEqual(mutated, self.binding)
        self.assertTrue(self.errors(binding=mutated))

    def test_review_time_must_select_the_exact_ledger_digest(self) -> None:
        mutated = self.binding.replace(
            'and item.get("sha256") == selector["evidence_sha256"]',
            'and item.get("sha256") != selector["evidence_sha256"]',
            1,
        )
        self.assertNotEqual(mutated, self.binding)
        self.assertTrue(self.errors(binding=mutated))

    def test_review_must_bind_the_closed_full_selector_subject(self) -> None:
        for old, new in (
            (
                'item.get("release_execution_review_subject") == expected_subject',
                'item.get("release_execution_review_subject") != expected_subject',
            ),
            (
                '            "evidence_object_reference": selector["evidence_object_reference"],\n',
                "",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.binding.replace(old, new, 1)
                self.assertNotEqual(mutated, self.binding)
                self.assertTrue(self.errors(binding=mutated))

    def test_review_time_requires_an_opaque_reviewer_reference(self) -> None:
        mutated = self.binding.replace(
            '        and _reviewer_reference(item.get("reviewed_by"))\n',
            "",
            1,
        )
        self.assertNotEqual(mutated, self.binding)
        self.assertTrue(self.errors(binding=mutated))

    def test_release_storage_reference_cannot_claim_worm_semantics(self) -> None:
        for old, new in (
            ("never WORM semantics", "proves WORM semantics"),
            (
                "_opaque_execution_reference(\n        selector.get(",
                "_execution_reference(\n        selector.get(",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.binding.replace(old, new, 1)
                self.assertNotEqual(mutated, self.binding)
                self.assertTrue(self.errors(binding=mutated))

    def test_consumer_order_and_forwarding_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                "release_reviewed_at: str,\n    consumer_started_at: str,",
                "release_reviewed_at: str | None = None,\n    consumer_started_at: str | None = None,",
            ),
            ("consumer_started < finished_at", "consumer_started > finished_at"),
            ("reviewed_at < finished_at", "reviewed_at > finished_at"),
            ("consumer_started < reviewed_at", "consumer_started > reviewed_at"),
            (
                "release_reviewed_at=release_reviewed_at,",
                "release_reviewed_at=None,",
            ),
            (
                "consumer_started_at=consumer_started_at,",
                "consumer_started_at=None,",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.binding.replace(old, new, 1)
                self.assertNotEqual(mutated, self.binding)
                self.assertTrue(self.errors(binding=mutated))

    def test_selection_review_order_cannot_be_reversed(self) -> None:
        for old, new in (
            ("reviewed_at < finished_at", "reviewed_at > finished_at"),
            ("reviewed_at > evaluated_at", "reviewed_at < evaluated_at"),
        ):
            with self.subTest(old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

    def test_every_consumer_window_start_is_required(self) -> None:
        mutated, count = re.subn(
            r'(release_reviewed_at=release_execution_reviewed_at\(\s*document,\s*)'
            r'artifact\.get\("release_execution"\)',
            r"\1None",
            self.intake,
            count=1,
        )
        self.assertEqual(count, 1)
        self.assertTrue(self.errors(intake=mutated))
        mutated = self.intake.replace(
            'consumer_started_at=artifact.get("window", {}).get(',
            'ignored_consumer_started_at=artifact.get("window", {}).get(',
            1,
        )
        self.assertNotEqual(mutated, self.intake)
        self.assertTrue(self.errors(intake=mutated))

    def test_final_intake_start_replay_cannot_be_removed(self) -> None:
        mutated = self.intake.replace(
            "checkpoint_identity.contains_release_start(",
            "checkpoint_identity.ignores_release_start(",
            1,
        )
        self.assertNotEqual(mutated, self.intake)
        self.assertTrue(self.errors(intake=mutated))

    def test_final_manifest_publication_and_caller_pins_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                "publish_write_once_file(temporary, output)",
                "ignored_publish_write_once_file(temporary, output)",
            ),
            (
                "expected_payload_sha256,\n            requirements_sha256(manifest),",
                "requirements_sha256(manifest),\n            requirements_sha256(manifest),",
            ),
            (
                "expected_file_sha256,\n            hashlib.sha256(manifest_raw).hexdigest(),",
                "hashlib.sha256(manifest_raw).hexdigest(),\n            hashlib.sha256(manifest_raw).hexdigest(),",
            ),
            (
                "final-manifest-custody=unverified",
                "final-manifest-custody=verified",
            ),
            (
                "final-manifest-rollback-protection=unverified",
                "final-manifest-rollback-protection=verified",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

    def test_final_intake_consumer_selector_comparison_cannot_be_removed(self) -> None:
        for old, new in (
            ("selector != baseline", "selector == baseline"),
            (
                "_release_execution_consumer_selector_errors(\n            release_execution_consumers,",
                "_ignored_release_execution_consumer_selector_errors(\n            release_execution_consumers,",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))
        for consumer in (
            "sub2_evidence",
            "vault_egress_evidence",
            "phase6_pilot_evidence",
            "phase6_operations_evidence",
        ):
            old = f"            {consumer},\n"
            with self.subTest(consumer=consumer):
                collector_offset = self.intake.index(
                    "    release_execution_consumers.extend("
                )
                prefix = self.intake[:collector_offset]
                collector = self.intake[collector_offset:]
                mutated = prefix + collector.replace(old, "", 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

    def test_intake_schema_v2_and_review_subject_projection_cannot_be_weakened(self) -> None:
        for old, new in (
            ('"schema_version": 2,', '"schema_version": 1,'),
            (
                "review_subject != expected_subject",
                "review_subject == expected_subject",
            ),
            (
                "review_subject=release_review_subject,",
                "review_subject=None,",
            ),
            (
                "release_execution_review_subject_errors(\n",
                "ignored_release_execution_review_subject_errors(\n",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

    def test_each_standalone_consumer_must_pass_its_window_start(self) -> None:
        for name, source in self.consumers.items():
            mutated, count = re.subn(
                r'(release_reviewed_at=release_execution_reviewed_at\(\s*manifest,\s*)'
                r'document\.get\("release_execution"\)',
                r"\1None",
                source,
                count=1,
            )
            with self.subTest(name=name, mutation="selector"):
                self.assertEqual(count, 1)
                consumers = {**self.consumers, name: mutated}
                self.assertTrue(self.errors(consumers=consumers))
            mutated = source.replace(
                'consumer_started_at=document.get("window", {}).get("started_at"),',
                "consumer_started_at=None,",
                1,
            )
            with self.subTest(name=name, mutation="window"):
                self.assertNotEqual(mutated, source)
                consumers = {**self.consumers, name: mutated}
                self.assertTrue(self.errors(consumers=consumers))

    def test_standalone_verifier_scope_is_explicit(self) -> None:
        for path in (
            Path("deploy/runbooks/deploy.md"),
            Path("deploy/runbooks/rolling-release.md"),
        ):
            with self.subTest(path=path):
                text = " ".join(path.read_text(encoding="utf-8").casefold().split())
                self.assertIn("does not read the frozen phase 0 checkpoint", text)
                self.assertIn("final strict intake", text)

    def test_every_consumer_reports_the_unverified_release_boundaries(self) -> None:
        for marker in (
            "release-reviewer-authentication=unverified",
            "release-review-trusted-time=unverified",
            "release-review-replay-protection=unverified",
            "release-storage-provider-native=unverified",
            "release-storage-retention=unverified",
            "release-storage-delete-denial=unverified",
            "release-storage-readback=unverified",
            "release-storage-namespace-authority=unverified",
            "release-storage-version-identity=unverified",
            "release-storage-cross-manifest-rebinding=unverified",
        ):
            mutated = self.intake.replace(marker, marker.replace("unverified", "verified"), 1)
            with self.subTest(source="intake", marker=marker):
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))
            for name, source in self.consumers.items():
                with self.subTest(source=name, marker=marker):
                    mutated = source.replace(
                        marker,
                        marker.replace("unverified", "verified"),
                        1,
                    )
                    self.assertNotEqual(mutated, source)
                    consumers = {**self.consumers, name: mutated}
                    self.assertTrue(self.errors(consumers=consumers))

    def test_every_consumer_reports_exact_manifest_review_subject_binding(self) -> None:
        marker = "release-review-selector-subject=manifest-exact"
        mutated = self.intake.replace(marker, marker.replace("exact", "digest-only"), 1)
        self.assertNotEqual(mutated, self.intake)
        self.assertTrue(self.errors(intake=mutated))
        for name, source in self.consumers.items():
            with self.subTest(source=name):
                mutated = source.replace(
                    marker,
                    marker.replace("exact", "digest-only"),
                    1,
                )
                self.assertNotEqual(mutated, source)
                consumers = {**self.consumers, name: mutated}
                self.assertTrue(self.errors(consumers=consumers))

    def test_release_review_trust_model_boundary_is_documented(self) -> None:
        runbook = " ".join(
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .split()
        )
        for required in (
            "release-review signer role",
            "pinned public-key trust anchor",
            "private-key custody/ rotation/revocation policy",
            "signature domain and canonical signed payload",
            "trusted timestamp receipt",
            "nonce/sequence/ledger-head replay policy",
            "remain an opaque attribution claim",
            "only a compatibility namespace for an opaque storage locator",
            "provider-native enforcement, retention, delete denial, and readback all remain `unverified`",
            "local no-replace write, or ledger digest cannot upgrade them",
            "every reviewed phase 1-5, sub2, vault/egress, phase 6 pilot, and phase 6 operations consumer",
            "it proves only equality of the claims presented in that intake",
            "namespace authority, version identity, and cross-manifest rebinding protection therefore remain `unverified`",
            "delete-then-recreate with identical bytes also remains indistinguishable from continuous retention",
            "target-intake schema v2",
            "release_execution_selector_v1",
            "rebinding all consumers together",
            "cannot inherit the old selector review",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runbook)
        for path in (
            Path("deploy/private-secret-target-provenance-policy.json"),
            Path("deploy/private-secret-worm-collection-policy.synthetic.json"),
        ):
            with self.subTest(path=path):
                policy = path.read_text(encoding="utf-8").casefold()
                self.assertIn("v1_only", policy)
                self.assertIn("unconfigured", policy)
        requirements = Path("deploy/target-intake-requirements.json").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "reviewer authentication, trusted time and replay protection remain explicitly unverified",
            requirements,
        )
        self.assertIn(
            "local no-replace publication and SHA-256 do not prove provider-native enforcement, retention, delete denial or post-denial readback",
            requirements,
        )
        self.assertIn(
            "this same-manifest equality is not a provider namespace authority or immutable version identity and cannot detect later cross-manifest or cross-environment rebinding",
            requirements,
        )
        self.assertIn(
            "a locator-only or all-consumer rebind cannot inherit the prior review claim",
            requirements,
        )
        self.assertIn(
            "final strict preflight requires independent caller pins for both its canonical payload SHA-256 and whole-file SHA-256",
            requirements,
        )
        self.assertIn(
            "pin authority, post-publication custody and global rollback protection remain explicitly unverified",
            requirements,
        )
        signoff = Path("deploy/production-signoff-template.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "Release-selection opaque reviewer reference/time plus reviewer-authentication, trusted-time and replay-protection `unverified` acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Release-execution opaque storage locator plus provider-native enforcement, retention, delete-denial and post-denial readback `unverified` acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Final-strict all-consumer exact release selector equality, including the opaque locator, result:",
            signoff,
        )
        self.assertIn(
            "Target-intake schema-v2 release review subject kind and exact full-selector projection result:",
            signoff,
        )
        self.assertIn(
            "Release-execution namespace authority, immutable version identity and cross-manifest rebinding protection `unverified` acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Finalized target-intake repository-external path, canonical payload SHA-256, whole-file SHA-256 and local no-replace/readback result:",
            signoff,
        )
        self.assertIn(
            "Final strict caller-pinned payload/file SHA-256 match plus pin-authority, post-publication custody and global rollback-protection `unverified` acknowledgement:",
            signoff,
        )


if __name__ == "__main__":
    unittest.main()
