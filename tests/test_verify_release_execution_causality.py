from __future__ import annotations

from pathlib import Path
import re
import unittest

from scripts.verify_release_execution_causality import (
    BINDING,
    CONSUMERS,
    INTAKE,
    causality_errors,
)


class ReleaseExecutionCausalityStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binding = BINDING.read_text(encoding="utf-8")
        self.intake = INTAKE.read_text(encoding="utf-8")
        self.consumers = {
            name: path.read_text(encoding="utf-8")
            for name, path in CONSUMERS.items()
        }

    def errors(
        self,
        *,
        binding: str | None = None,
        intake: str | None = None,
        consumers: dict[str, str] | None = None,
    ) -> list[str]:
        return causality_errors(
            self.binding if binding is None else binding,
            self.intake if intake is None else intake,
            self.consumers if consumers is None else consumers,
        )

    def test_current_contract_passes_and_is_in_the_quality_gate(self) -> None:
        self.assertEqual(self.errors(), [])
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_release_execution_causality.py", gate)

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


if __name__ == "__main__":
    unittest.main()
