from __future__ import annotations

from pathlib import Path
import re
import unittest

from scripts.verify_release_execution_causality import (
    ACCEPTANCE,
    BINDING,
    CONSUMERS,
    EXTERNAL_JSON,
    GENERATION,
    INTAKE,
    INTAKE_MANIFEST,
    INTAKE_ONLY_CONSUMERS,
    VALIDATOR_CONTRACT,
    EXPECTED_VALIDATOR_SOURCES,
    causality_errors,
)


class ReleaseExecutionCausalityStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binding = BINDING.read_text(encoding="utf-8")
        self.intake = INTAKE.read_text(encoding="utf-8")
        self.intake_manifest = INTAKE_MANIFEST.read_text(encoding="utf-8")
        self.external_json = EXTERNAL_JSON.read_text(encoding="utf-8")
        self.generation = GENERATION.read_text(encoding="utf-8")
        self.acceptance = ACCEPTANCE.read_text(encoding="utf-8")
        self.validator_contract = VALIDATOR_CONTRACT.read_text(encoding="utf-8")
        self.validator_sources = {
            path: Path(path).read_text(encoding="utf-8")
            for path in EXPECTED_VALIDATOR_SOURCES
        }
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
        external_json: str | None = None,
        generation: str | None = None,
        acceptance: str | None = None,
        validator_contract: str | None = None,
        validator_sources: dict[str, str] | None = None,
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
            self.external_json if external_json is None else external_json,
            self.generation if generation is None else generation,
            self.acceptance if acceptance is None else acceptance,
            (
                self.validator_contract
                if validator_contract is None
                else validator_contract
            ),
            self.validator_sources if validator_sources is None else validator_sources,
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

    def test_shared_locator_is_exact_case_preserving_and_identity_rechecked(self) -> None:
        manifest_mutated = self.intake_manifest.replace(
            "os.path.abspath(expected) != os.path.abspath(supplied_path)",
            "os.path.normcase(os.path.abspath(expected)) != os.path.normcase(os.path.abspath(supplied_path))",
            1,
        )
        self.assertNotEqual(manifest_mutated, self.intake_manifest)
        self.assertTrue(self.errors(intake_manifest=manifest_mutated))

        for old, new in (
            ("expected_identity=stable_file_identity(metadata)", "expected_identity=None"),
            ("current_metadata.st_nlink != 1", "current_metadata.st_nlink < 1"),
        ):
            with self.subTest(old=old):
                mutated = self.external_json.replace(old, new, 1)
                self.assertNotEqual(mutated, self.external_json)
                self.assertTrue(self.errors(external_json=mutated))

    def test_each_consumer_reads_and_rechecks_the_manifest_locator(self) -> None:
        name = "sub2_execution_evidence.py"
        for old, new in (
            ("document_path = manifest_artifact_path(", "document_path = Path("),
            (
                "load_unique_json_with_bytes_and_metadata(document_path)",
                "load_unique_json_with_bytes_and_metadata(arguments.input)",
            ),
            ("        recheck_stable_bytes(\n", "        recheck_ignored_bytes(\n"),
            ("            require_single_link=True,\n", "            require_single_link=False,\n"),
        ):
            with self.subTest(old=old):
                mutated = dict(self.consumers)
                mutated[name] = mutated[name].replace(old, new, 1)
                self.assertNotEqual(mutated[name], self.consumers[name])
                self.assertTrue(self.errors(consumers=mutated))

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
        old_publish = "publish_write_once_file(temporary, output)"
        prefix, separator, suffix = self.intake.rpartition(old_publish)
        self.assertEqual(separator, old_publish)
        mutated = prefix + "ignored_publish_write_once_file(temporary, output)" + suffix
        self.assertTrue(self.errors(intake=mutated))
        for old, new in (
            (
                "expected_manifest_payload_sha256=expected_payload_sha256,",
                "expected_manifest_payload_sha256=requirements_sha256(manifest),",
            ),
            (
                "expected_manifest_file_sha256=expected_file_sha256,",
                "expected_manifest_file_sha256=hashlib.sha256(manifest_raw).hexdigest(),",
            ),
            (
                "arguments.expected_finalization_receipt_payload_sha256\n                ),",
                "requirements_sha256(receipt)\n                ),",
            ),
            (
                "arguments.expected_finalization_receipt_file_sha256\n                ),",
                "hashlib.sha256(receipt_raw).hexdigest()\n                ),",
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

    def test_snapshot_and_finalization_acceptance_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                'snapshot.add_argument("--receipt-output", required=True, type=Path)',
                'snapshot.add_argument("--receipt-output", required=False, type=Path)',
            ),
            (
                'finalize.add_argument("--phase0-checkpoint-receipt", required=True, type=Path)',
                'finalize.add_argument("--phase0-checkpoint-receipt", required=False, type=Path)',
            ),
            (
                "receipt = create_snapshot_receipt(",
                "receipt = ignored_create_snapshot_receipt(",
            ),
            (
                "receipt = create_finalization_receipt(",
                "receipt = ignored_create_finalization_receipt(",
            ),
            (
                "snapshot_identity_errors = _snapshot_acceptance_identity_errors(",
                "snapshot_identity_errors = ignored_snapshot_acceptance_identity_errors(",
            ),
            (
                "target-intake-snapshot-orphaned-unaccepted",
                "target-intake-snapshot-accepted",
            ),
            (
                "target-intake-finalization-commit-state=unknown",
                "target-intake-finalization-commit-state=known",
            ),
            (
                "finalization-receipt-authority=unverified",
                "finalization-receipt-authority=verified",
            ),
            (
                'verify_receipt = commands.add_parser("verify-receipt")',
                'verify_receipt = commands.add_parser("ignored-verify-receipt")',
            ),
            (
                '"--expected-receipt-payload-sha256",\n        required=True,',
                '"--expected-receipt-payload-sha256",\n        required=False,',
            ),
            (
                'evaluated_at = _parse_utc(acceptance.receipt.get("evaluated_at"))',
                'evaluated_at = ignored_parse_utc(acceptance.receipt.get("evaluated_at"))',
            ),
            (
                "parent-directory-race-protection=unverified",
                "parent-directory-race-protection=verified",
            ),
            (
                "publication-crash-durability=unverified",
                "publication-crash-durability=verified",
            ),
        ):
            with self.subTest(intake_old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

        for old, new in (
            (
                'document.get("kind") != SNAPSHOT_RECEIPT_KIND',
                'document.get("kind") != IGNORED_SNAPSHOT_RECEIPT_KIND',
            ),
            (
                'document.get("kind") != FINALIZATION_RECEIPT_KIND',
                'document.get("kind") != IGNORED_FINALIZATION_RECEIPT_KIND',
            ),
            (
                'document.get("schema_version") != 2',
                'document.get("schema_version") != 1',
            ),
            (
                'os.path.abspath(receipt_path) != receipt.get("receipt_path")',
                'os.path.abspath(receipt_path) == receipt.get("receipt_path")',
            ),
            (
                '"receipt_path": os.path.abspath(receipt_path),',
                '"ignored_receipt_path": os.path.abspath(receipt_path),',
            ),
            ("generation_lineage_contains(", "ignored_generation_lineage_contains("),
            ("require_single_link=True", "require_single_link=False"),
            ("load_snapshot_acceptance(", "ignored_load_snapshot_acceptance("),
        ):
            with self.subTest(acceptance_old=old):
                mutated = self.acceptance.replace(old, new, 1)
                self.assertNotEqual(mutated, self.acceptance)
                self.assertTrue(self.errors(acceptance=mutated))

    def test_authoring_generation_registration_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                'register = commands.add_parser("register")',
                'register = commands.add_parser("ignored-register")',
            ),
            (
                'verify_generation_lineage = commands.add_parser("verify-generation-lineage")',
                'verify_generation_lineage = commands.add_parser("ignored-verify-generation-lineage")',
            ),
            (
                'verify_generation_lineage.add_argument(\n        "--expected-receipt-payload-sha256",\n        required=True,',
                'verify_generation_lineage.add_argument(\n        "--expected-receipt-payload-sha256",\n        required=False,',
            ),
            (
                "            recheck_generation_lineage(lineage)\n        except GenerationLineageError:",
                "            ignored_recheck_generation_lineage(lineage)\n        except GenerationLineageError:",
            ),
            (
                '"--expected-input-manifest-payload-sha256",\n        required=True,',
                '"--expected-input-manifest-payload-sha256",\n        required=False,',
            ),
            (
                'register.add_argument("--input", required=True, type=Path)',
                'register.add_argument("--ignored-input", required=True, type=Path)',
            ),
            (
                '"--expected-input-receipt-payload-sha256",\n        required=True,',
                '"--expected-input-receipt-payload-sha256",\n        required=False,',
            ),
            (
                "lineage = load_generation_lineage(",
                "lineage = ignored_load_generation_lineage(",
            ),
            (
                "receipt = create_registration_receipt(",
                "receipt = ignored_create_registration_receipt(",
            ),
            (
                "receipt_path=arguments.receipt_output,",
                "receipt_path=arguments.output,",
            ),
            (
                "verify-generation-lineage-required",
                "verify-generation-lineage-disabled",
            ),
            (
                "authoring-rollback-protection=unverified",
                "authoring-rollback-protection=verified",
            ),
            (
                "authoring-publication-crash-durability=unverified",
                "authoring-publication-crash-durability=verified",
            ),
            (
                "generation=orphaned-unaccepted",
                "generation=accepted",
            ),
            (
                "commit-state=unknown",
                "commit-state=known",
            ),
            (
                "hashlib.sha256(artifact_raw).hexdigest(),\n                registered_item[\"sha256\"],",
                "registered_item[\"sha256\"],\n                registered_item[\"sha256\"],",
            ),
            (
                "require_single_link=True,",
                "require_single_link=False,",
            ),
            (
                "errors = intake_errors(\n            candidate,",
                "errors = intake_errors(\n            base,",
            ),
            (
                "output_bytes = _final_manifest_bytes(candidate)",
                "output_bytes = _final_manifest_bytes(base)",
            ),
            (
                "authoring-generation-fork-protection=unverified",
                "authoring-generation-fork-protection=verified",
            ),
            (
                "authoring-latest-head=unverified",
                "authoring-latest-head=verified",
            ),
            (
                "validator_contract=validator_contract,",
                "validator_contract={},",
            ),
            (
                "validator_contract=historical_validator_contract,",
                "validator_contract={},",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.intake.replace(old, new, 1)
                self.assertNotEqual(mutated, self.intake)
                self.assertTrue(self.errors(intake=mutated))

        for old, new in (
            (
                'RECEIPT_KIND = "target_intake_generation_receipt_v8"',
                'RECEIPT_KIND = "target_intake_generation_receipt_v1"',
            ),
            (
                'document.get("schema_version") != 8',
                'document.get("schema_version") != 1',
            ),
            (
                '"receipt_path": os.path.abspath(receipt_path),',
                '"ignored_receipt_path": os.path.abspath(receipt_path),',
            ),
            (
                'or os.path.abspath(path) != receipt.get("receipt_path")',
                'or os.path.abspath(path) == receipt.get("receipt_path")',
            ),
            (
                'or os.path.abspath(current_receipt_path)\n                != receipt.get("receipt_path")',
                'or os.path.abspath(current_receipt_path)\n                == receipt.get("receipt_path")',
            ),
            ("if len(changed) != 1:", "if len(changed) == 1:"),
            ("if before != after", "if before == after"),
            ("base[key] != candidate[key]", "base[key] == candidate[key]"),
            ("before.get(key) is not None", "before.get(key) is None"),
            (
                'before.get("status") != "missing"',
                'before.get("status") != "provided"',
            ),
            ("seen_manifests.add", "ignored_seen_manifests.add"),
            ("seen_receipts.add", "ignored_seen_receipts.add"),
            (
                "item_id = manifest_registration_item_id(manifest, child_manifest)",
                "item_id = None",
            ),
            ("require_single_link=True", "require_single_link=False"),
        ):
            with self.subTest(generation_old=old):
                mutated = self.generation.replace(old, new, 1)
                self.assertNotEqual(mutated, self.generation)
                self.assertTrue(self.errors(generation=mutated))

    def test_generation_validator_contract_cannot_be_weakened(self) -> None:
        for old, new in (
            (
                '    "scripts/provider_contract_conformance.py",\n',
                "",
            ),
            (
                '    "platform/api/v1/routes.py",\n',
                "",
            ),
            (
                '    ("cryptography", "cryptography"),\n',
                "",
            ),
            (
                '"authoring_entrypoint",\n',
                '"ignored_authoring_entrypoint",\n',
            ),
            (
                "return [] if document == expected else [",
                "return [\"generation validator contract is invalid\"] if document == expected else [] # ",
            ),
            (
                "raw, metadata = read_stable_bytes_with_metadata(",
                "raw, metadata = ignored_read_stable_bytes_with_metadata(",
            ),
            (
                "(require_single_link and before.st_nlink != 1)",
                "(require_single_link and before.st_nlink == 1)",
            ),
            (
                '"runtime_environment": runtime_environment,',
                '"runtime_environment": {},',
            ),
            (
                "_distribution_closure(\n        tuple(selected[\"owner_names\"]),",
                "_ignored_distribution_closure(\n        tuple(selected[\"owner_names\"]),",
            ),
            (
                '"payload_tree_sha256": payload_sha256,',
                '"payload_tree_sha256": "0" * 64,',
            ),
            (
                "if audit_import_tree and unlisted_import_files:",
                "if False:",
            ),
        ):
            with self.subTest(old=old):
                mutated = self.validator_contract.replace(old, new, 1)
                self.assertNotEqual(mutated, self.validator_contract)
                self.assertTrue(self.errors(validator_contract=mutated))

        moved_outside_loop = self.intake.replace(
            "                or validator_contract_errors(\n"
            "                    context[\"validator_contract\"], expected_validator_contract\n"
            "                )\n",
            "",
            1,
        )
        self.assertNotEqual(moved_outside_loop, self.intake)
        self.assertTrue(self.errors(intake=moved_outside_loop))

        reachable_write = self.validator_contract.replace(
            "def current_validator_contract() -> dict[str, Any]:\n",
            "def current_validator_contract() -> dict[str, Any]:\n"
            "    Path('forbidden').write_bytes(b'x')\n",
            1,
        )
        mutated_sources = dict(self.validator_sources)
        mutated_sources["scripts/target_intake_validator_contract.py"] = (
            reachable_write
        )
        self.assertTrue(
            self.errors(
                validator_contract=reachable_write,
                validator_sources=mutated_sources,
            )
        )

    def test_generation_external_handoff_boundaries_cannot_be_promoted(self) -> None:
        for old, new in (
            (
                "authoring-validation-context-external-handoff=not-consumed",
                "authoring-validation-context-external-handoff=consumed",
            ),
            (
                "authoring-validation-context-signature=unverified",
                "authoring-validation-context-signature=verified",
            ),
            (
                "authoring-trusted-timestamp-receipt=unverified",
                "authoring-trusted-timestamp-receipt=verified",
            ),
            (
                "authoring-provider-head-cas=unverified",
                "authoring-provider-head-cas=verified",
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
            "a checkpoint/final leaf left without its receipt is `orphaned-unaccepted`",
            "the recorded host evaluation instant is not trusted time",
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
            "Final strict preflight requires independent caller pins for the final manifest payload/file SHA-256 and finalization-receipt payload/file SHA-256",
            requirements,
        )
        self.assertIn(
            "they do not authenticate the pin or receipt source, make host time trusted, prevent rollback of the result/receipt/four-pin set as one unit, distinguish same-path same-bytes deletion and recreation",
            requirements,
        )
        self.assertIn(
            "Each receipt self-binds its case-preserving lexical absolute locator",
            requirements,
        )
        self.assertIn(
            "read-only verify-receipt command",
            requirements,
        )
        self.assertIn(
            "schema-v8 local receipt whose case-preserving lexical absolute receipt_path equals every terminal and predecessor receipt locator",
            requirements,
        )
        self.assertIn(
            "Recovery replays every receipt/manifest pair to genesis with its own embedded validation context and recorded time",
            requirements,
        )
        self.assertIn(
            "closed-v5 validator contract containing declarative authoring/replay entrypoints, an exact ordered 65-file local source inventory with raw whole-file SHA-256 values",
            requirements,
        )
        self.assertIn(
            "a clean-snapshot execution-profile-v2 binding the caller-retained snapshot manifest payload/file SHA-256 pins and exact isolated launch controls",
            requirements,
        )
        self.assertIn(
            "read-only verify-generation-lineage command",
            requirements,
        )
        self.assertIn(
            "rollback of an older manifest/receipt/four-pin tuple as one unit",
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
            "Finalized target-intake repository-external path, canonical payload SHA-256, whole-file SHA-256, finalization-receipt path and caller-pinned receipt payload/file SHA-256:",
            signoff,
        )
        self.assertIn(
            "Schema-v2 snapshot receipt self-bound locator, exact source-generation/result-checkpoint binding, recorded host evaluation window, local no-replace/readback, orphan/unknown disposition, and receipt-authority/trusted-time/parent-directory-race/publication-crash-durability/post-publication-custody `unverified` acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Schema-v8 generation receipt self-bound locator, exact terminal and predecessor-hop result, and schema-v1/v2/v3/v4/v5/v6/v7/mixed-chain rejection evidence:",
            signoff,
        )
        self.assertIn(
            "Generation validator-contract canonical SHA-256 plus closed-v5 authoring/replay entrypoints, exact ordered 65-file on-disk source inventory, Python/OS/non-cache-stdlib/core-native/fixed-root metadata-closure and observed loaded-owner distribution payload replay-runtime fingerprint, caller-pinned interpreter digest, isolated missing-pycache-prefix selection, and clean-snapshot execution-profile match:",
            signoff,
        )
        self.assertIn(
            "Historical generation replay acknowledgement: embedded validation-context authority, host trusted time, validator source/pin/launcher/interpreter authority, executed in-memory code and loader authority, transient load/unload, in-window ABA exclusion, filesystem-atomic snapshot identity, non-RECORD import-tree completeness for non-root transitive/loaded owners, post-observation bytecode/native mutation, original authoring runtime identity, original validator execution, Git/portable release identity, receipt/reviewer authority, and post-verification custody remain `unverified`:",
            signoff,
        )
        self.assertIn(
            "Generation-receipt unknown-state read-only verification record (or explicit none), including the four independently retained manifest/receipt pins, `production_acceptance=false`, and no file repair/deletion/promotion acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Whole generation/receipt/four-pin rollback, same-path same-bytes delete/recreate and authoring locator-continuity `unverified` acknowledgement:",
            signoff,
        )
        self.assertIn(
            "Final strict caller-pinned payload/file SHA-256 match plus pin-authority, post-publication custody and global rollback-protection `unverified` acknowledgement:",
            signoff,
        )


if __name__ == "__main__":
    unittest.main()
