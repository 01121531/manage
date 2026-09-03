from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.vault_egress_evidence import (
    EVIDENCE_INDEX,
    REQUIRED_SCENARIO_OBSERVATIONS,
    SECURE_IMPORT_CONTRACT,
    index_errors,
    intake_binding_errors,
    main,
    repository_control_errors,
    seal_index,
)
from tests.intake_manifest_support import (
    bind_manifest_item_bytes,
    closed_manifest,
    manifest_pin_arguments,
)


class VaultEgressEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(EVIDENCE_INDEX.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        payload = {key: value for key, value in document.items() if key != "integrity"}
        return seal_index(payload)

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.template)
        document.update(
            {
                "index_reference": "vault-egress-index-record-42",
                "synthetic": False,
                "index_status": "reviewed",
                "review_reference": "vault-egress-independent-review-42",
                "reviewed_at": "2026-08-26T10:15:00Z",
                "valid_until": "2099-08-26T10:15:00Z",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "sub2_contract_sha256": "c" * 64,
                    "target_platform_inventory_sha256": "d" * 64,
                },
                "window": {
                    "started_at": "2026-08-26T09:00:00Z",
                    "finished_at": "2026-08-26T10:00:00Z",
                },
                "release_execution": {
                    "ledger_type": "forward",
                    "evidence_object_reference": "worm-release-execution:record-42",
                    "evidence_sha256": "f" * 64,
                    "target_intake": {
                        "environment": "staging",
                        "manifest_payload_sha256": "1" * 64,
                        "requirements_sha256": "e" * 64,
                        "checkpoint_phase": 0,
                    },
                },
            }
        )
        document["scenarios"] = {
            scenario: {
                "execution_reference": f"control-execution-record-{index}",
                "executor_reference": f"control-operator-record-{index}",
                "reviewer_reference": f"control-reviewer-record-{index}",
                "trace_reference": f"control-trace-record-{index}",
                "executed_at": f"2026-08-26T09:{index:02d}:00Z",
                "observation": observation,
                "result": "passed",
                "evidence_object_reference": f"worm-control-object-{index}",
                "evidence_sha256": f"{index:064x}",
                "redaction_confirmed": True,
            }
            for index, (scenario, observation) in enumerate(
                REQUIRED_SCENARIO_OBSERVATIONS.items(), start=1
            )
        }
        return self._reseal(document)

    @staticmethod
    def _manifest(bindings: dict[str, str]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": "e" * 64,
            "items": [
                {
                    "id": "sub2_contract",
                    "status": "provided",
                    "sha256": bindings["sub2_contract_sha256"],
                },
                {
                    "id": "target_platform_inventory",
                    "status": "provided",
                    "sha256": bindings["target_platform_inventory_sha256"],
                },
                {
                    "id": "vault_egress_evidence",
                    "status": "provided",
                    "reviewed_by": "vault-egress-independent-review-42",
                    "reviewed_at": "2026-08-26T10:15:00Z",
                },
            ],
        }

    def test_repository_template_is_safe_closed_sealed_aligned_and_gated(self) -> None:
        self.assertEqual(index_errors(self.template), [])
        self.assertEqual(repository_control_errors(), [])
        self.assertEqual(
            json.loads(SECURE_IMPORT_CONTRACT.read_text(encoding="utf-8"))[
                "schema_version"
            ],
            41,
        )
        self.assertTrue(self.template["synthetic"])
        self.assertEqual(self.template["index_status"], "pending")
        self.assertFalse(self.template["production_acceptance"])
        self.assertEqual(self.template["schema_version"], 3)
        self.assertIsNone(self.template["reviewed_at"])
        self.assertIsNone(self.template["valid_until"])
        self.assertTrue(all(value is None for value in self.template["scenarios"].values()))
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/vault_egress_evidence.py verify-repository", gate)

    def test_repository_control_rejects_secure_import_evidence_contract_drift(
        self,
    ) -> None:
        with mock.patch(
            "scripts.vault_egress_evidence.load_unique_json",
            return_value={
                "schema_version": 5,
                "production_acceptance": False,
                "required_target_evidence": [
                    "three_distinct_external_principals",
                ],
            },
        ):
            self.assertIn(
                "secure import target evidence contract does not match the evidence index",
                repository_control_errors(),
            )

    def test_inventory_is_exact_full_vault_matrix_plus_egress_controls(self) -> None:
        self.assertEqual(len(REQUIRED_SCENARIO_OBSERVATIONS), 31)
        self.assertEqual(
            {name for name in REQUIRED_SCENARIO_OBSERVATIONS if name.startswith("vault_")},
            {
                "vault_api_cards_allowed",
                "vault_api_mailboxes_denied",
                "vault_api_sub2_credential_denied",
                "vault_api_sub2_proxy_denied",
                "vault_mail_cards_denied",
                "vault_mail_mailboxes_allowed",
                "vault_mail_sub2_credential_denied",
                "vault_mail_sub2_proxy_denied",
                "vault_sub2_cards_allowed",
                "vault_sub2_mailboxes_denied",
                "vault_sub2_credential_allowed",
                "vault_sub2_proxy_allowed",
            },
        )
        self.assertEqual(
            {
                name: observation
                for name, observation in REQUIRED_SCENARIO_OBSERVATIONS.items()
                if name.startswith("secure_import_")
            },
            {
                "secure_import_principals_distinct": "three_external_principals_verified",
                "secure_import_create_only_cas": "importer_create_only_and_cas_zero_observed",
                "secure_import_cross_pool_denied": "card_and_mailbox_cross_pool_access_denied",
                "secure_import_api_sign_denied": "api_transit_sign_permission_denied",
                "secure_import_importer_verify_denied": "importer_transit_verify_permission_denied",
                "secure_import_transit_rotation": "non_exportable_transit_keys_rotated",
                "secure_import_vault_audit": "vault_audit_trace_independently_reviewed",
                "secure_import_receipt_concurrency": "single_receipt_consumed_once_under_concurrency",
                "secure_import_context_prewrite_binding": "wrong_tenant_and_audience_rejected_before_vault_write",
                "secure_import_canary_cleanup": "exact_run_canaries_permanently_deleted_with_receipt",
                "secure_import_card_manual_batch": "administrator_card_pool_batch_committed",
                "secure_import_mailbox_manual_batch": "administrator_mailbox_pool_batch_committed",
                "secure_import_recovery_read_only": "both_pool_execution_records_assessed_without_automatic_resume",
            },
        )

    def test_reviewed_index_requires_every_exact_passed_scenario(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(index_errors(reviewed), [])
        missing = copy.deepcopy(reviewed)
        missing["scenarios"].pop("vault_sub2_mailboxes_denied")
        wrong = copy.deepcopy(reviewed)
        wrong["scenarios"]["sub2_application_similar_suffix_denied"]["observation"] = "allowed"
        failed = copy.deepcopy(reviewed)
        failed["scenarios"]["sub2_network_unapproved_destination_denied"]["result"] = "failed"
        for document in (missing, wrong, failed):
            with self.subTest():
                self.assertTrue(index_errors(self._reseal(document)))

    def test_references_are_unique_independently_reviewed_and_redacted(self) -> None:
        reviewed = self._reviewed()
        duplicate = copy.deepcopy(reviewed)
        duplicate["scenarios"]["vault_mail_cards_denied"]["evidence_sha256"] = duplicate[
            "scenarios"
        ]["vault_api_mailboxes_denied"]["evidence_sha256"]
        same_reviewer = copy.deepcopy(reviewed)
        scenario = same_reviewer["scenarios"]["vault_sub2_cards_allowed"]
        scenario["reviewer_reference"] = scenario["executor_reference"]
        unredacted = copy.deepcopy(reviewed)
        unredacted["scenarios"]["sub2_network_approved_destination_allowed"][
            "redaction_confirmed"
        ] = False
        for document in (duplicate, same_reviewer, unredacted):
            with self.subTest():
                self.assertTrue(index_errors(self._reseal(document)))

    def test_window_release_integrity_and_sensitive_claims_fail_closed(self) -> None:
        reviewed = self._reviewed()
        outside = copy.deepcopy(reviewed)
        outside["scenarios"]["vault_api_cards_allowed"]["executed_at"] = "2026-08-26T11:00:00Z"
        bad_commit = copy.deepcopy(reviewed)
        bad_commit["bindings"]["release_commit"] = "not-a-commit"
        sensitive = copy.deepcopy(reviewed)
        sensitive["prohibited_content"]["contains_vault_responses"] = True
        accepted = copy.deepcopy(reviewed)
        accepted["production_acceptance"] = True
        tampered = copy.deepcopy(reviewed)
        tampered["environment"] = "production"
        for document in (outside, bad_commit, sensitive, accepted):
            with self.subTest():
                self.assertTrue(index_errors(self._reseal(document)))
        self.assertIn("Vault/egress evidence index integrity is invalid", index_errors(tampered))
        expires = copy.deepcopy(reviewed)
        expires["valid_until"] = "2026-08-26T11:00:00Z"
        expires = self._reseal(expires)
        self.assertEqual(
            index_errors(
                expires,
                evaluated_at=datetime(2026, 8, 26, 10, 30, tzinfo=timezone.utc),
            ),
            [],
        )
        self.assertIn(
            "reviewed Vault/egress evidence is not currently valid",
            index_errors(
                expires,
                evaluated_at=datetime(2026, 8, 26, 11, 0, tzinfo=timezone.utc),
            ),
        )

    def test_binding_requires_same_environment_contract_and_inventory(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])
        manifest["items"][0]["sha256"] = "f" * 64
        self.assertIn(
            "Vault/egress evidence sub2_contract binding does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        manifest["items"][2]["reviewed_at"] = "2026-08-26T10:16:00Z"
        self.assertIn(
            "Vault/egress evidence review metadata does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )

    def test_cli_distinguishes_content_control_and_binding_failures(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index_path = root / "vault-egress-index.json"
            manifest_path = root / "intake.json"
            release_path = root / "release.json"
            release_path.write_text("{}", encoding="utf-8")
            bound_args = [
                "--release-execution-evidence",
                str(release_path),
            ]
            manifest = closed_manifest(manifest)
            reviewed_raw = json.dumps(reviewed).encode("utf-8")
            bind_manifest_item_bytes(
                manifest,
                "vault_egress_evidence",
                reviewed_raw,
                path=index_path,
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            pin_arguments = manifest_pin_arguments(manifest_path)
            index_path.write_text(json.dumps(self.template), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(index_path), "--intake-manifest", str(manifest_path), *pin_arguments]), 1)
            index_path.write_bytes(reviewed_raw)
            with mock.patch(
                "scripts.vault_egress_evidence.release_execution_alignment_errors",
                return_value=[],
            ):
                self.assertEqual(
                    main(
                        [
                            "check",
                            "--input",
                            str(index_path),
                            "--intake-manifest",
                            str(manifest_path),
                            *pin_arguments,
                            *bound_args,
                        ]
                    ),
                    0,
                )
            with mock.patch(
                "scripts.vault_egress_evidence.repository_control_errors",
                return_value=["repository control drift"],
            ):
                self.assertEqual(
                    main(
                        [
                            "check",
                            "--input",
                            str(index_path),
                            "--intake-manifest",
                            str(manifest_path),
                            *pin_arguments,
                            *bound_args,
                        ]
                    ),
                    3,
                )
            next(
                item
                for item in manifest["items"]
                if item["id"] == "target_platform_inventory"
            )["sha256"] = "f" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(index_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                        *bound_args,
                    ]
                ),
                2,
            )

    def test_runbook_states_external_scope_and_evidence_limit(self) -> None:
        rendered = json.dumps(self.template, ensure_ascii=False).casefold()
        for forbidden in ("4111111111111111", "bearer ", "client_secret", "https://provider", "vault-token"):
            self.assertNotIn(forbidden, rendered)
        text = Path("deploy/runbooks/target-intake-preflight.md").read_text(encoding="utf-8").casefold().replace("\n", " ")
        for expected in (
            "vault_egress_evidence.py check",
            "12-cell vault identity/path matrix",
            "12 secure import scenarios",
            "administrator card pool batch",
            "administrator mailbox pool batch",
            "exact-run canary cleanup receipt",
            "application origin validation",
            "network egress enforcement",
            "does not verify the external evidence content",
        ):
            self.assertIn(expected, text)

        requirements = json.loads(
            Path("deploy/target-intake-requirements.json").read_text(encoding="utf-8")
        )
        requirement = next(
            item for item in requirements["requirements"]
            if item["id"] == "vault_egress_evidence"
        )
        for expected in (
            "secure dual-pool import",
            "manual card and mailbox batch commits",
            "exact canary cleanup",
        ):
            self.assertIn(expected, requirement["purpose"])


if __name__ == "__main__":
    unittest.main()
