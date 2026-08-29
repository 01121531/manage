from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.sub2_execution_evidence import (
    EVIDENCE_INDEX,
    REQUIRED_SCENARIO_OBSERVATIONS,
    index_errors,
    intake_binding_errors,
    main,
    seal_index,
)


class Sub2ExecutionEvidenceTests(unittest.TestCase):
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
                "index_reference": "sub2-execution-index-record-42",
                "synthetic": False,
                "index_status": "reviewed",
                "review_reference": "sub2-independent-review-record-42",
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
            }
        )
        scenarios = {}
        for index, (scenario, observation) in enumerate(
            REQUIRED_SCENARIO_OBSERVATIONS.items(),
            start=1,
        ):
            scenarios[scenario] = {
                "execution_reference": f"sub2-execution-record-{index}",
                "executor_reference": f"sub2-operator-record-{index}",
                "reviewer_reference": f"sub2-reviewer-record-{index}",
                "trace_reference": f"sub2-trace-record-{index}",
                "executed_at": f"2026-08-26T09:{index:02d}:00Z",
                "observation": observation,
                "result": "passed",
                "evidence_object_reference": f"worm-evidence-object-{index}",
                "evidence_sha256": f"{index:064x}",
                "redaction_confirmed": True,
            }
        document["scenarios"] = scenarios
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
            ],
        }

    def test_repository_template_is_safe_closed_sealed_and_in_quality_gate(self) -> None:
        self.assertEqual(index_errors(self.template), [])
        self.assertTrue(self.template["synthetic"])
        self.assertEqual(self.template["index_status"], "pending")
        self.assertFalse(self.template["production_acceptance"])
        self.assertTrue(all(value is None for value in self.template["scenarios"].values()))
        self.assertRegex(self.template["integrity"]["payload_sha256"], r"^[0-9a-f]{64}$")
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/sub2_execution_evidence.py verify-repository",
            quality_gate,
        )

    def test_reviewed_index_requires_all_exact_workflow_and_query_scenarios(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(index_errors(reviewed), [])

        missing = copy.deepcopy(reviewed)
        missing["scenarios"].pop("authorization_exchange")
        missing = self._reseal(missing)
        wrong_observation = copy.deepcopy(reviewed)
        wrong_observation["scenarios"]["status_not_found"]["observation"] = (
            "submission_succeeded"
        )
        wrong_observation = self._reseal(wrong_observation)
        failed = copy.deepcopy(reviewed)
        failed["scenarios"]["successful_create"]["result"] = "failed"
        failed = self._reseal(failed)

        for document in (missing, wrong_observation, failed):
            with self.subTest(document=document):
                self.assertTrue(index_errors(document))

    def test_scenario_references_are_independent_unique_and_redacted(self) -> None:
        reviewed = self._reviewed()
        duplicate_object = copy.deepcopy(reviewed)
        duplicate_object["scenarios"]["definitive_failure"][
            "evidence_object_reference"
        ] = duplicate_object["scenarios"]["successful_create"][
            "evidence_object_reference"
        ]
        duplicate_object = self._reseal(duplicate_object)
        same_actor_reviewer = copy.deepcopy(reviewed)
        same_actor_reviewer["scenarios"]["submission_timeout"][
            "reviewer_reference"
        ] = same_actor_reviewer["scenarios"]["submission_timeout"][
            "executor_reference"
        ]
        same_actor_reviewer = self._reseal(same_actor_reviewer)
        not_redacted = copy.deepcopy(reviewed)
        not_redacted["scenarios"]["status_processing"][
            "redaction_confirmed"
        ] = False
        not_redacted = self._reseal(not_redacted)

        for document in (duplicate_object, same_actor_reviewer, not_redacted):
            with self.subTest(document=document):
                self.assertTrue(index_errors(document))

    def test_scenarios_must_be_inside_a_canonical_utc_window(self) -> None:
        reviewed = self._reviewed()
        outside = copy.deepcopy(reviewed)
        outside["scenarios"]["successful_create"]["executed_at"] = (
            "2026-08-26T11:00:00Z"
        )
        outside = self._reseal(outside)
        bad_window = copy.deepcopy(reviewed)
        bad_window["window"]["finished_at"] = "2026-08-26T08:00:00Z"
        bad_window = self._reseal(bad_window)
        offset = copy.deepcopy(reviewed)
        offset["window"]["started_at"] = "2026-08-26T09:00:00+08:00"
        offset = self._reseal(offset)

        for document in (outside, bad_window, offset):
            with self.subTest(document=document):
                self.assertTrue(index_errors(document))

    def test_release_binding_and_integrity_tamper_fail_closed(self) -> None:
        reviewed = self._reviewed()
        invalid_commit = copy.deepcopy(reviewed)
        invalid_commit["bindings"]["release_commit"] = "not-a-commit"
        invalid_commit = self._reseal(invalid_commit)
        tampered = copy.deepcopy(reviewed)
        tampered["environment"] = "production"

        self.assertTrue(index_errors(invalid_commit))
        self.assertIn("Sub2 evidence index integrity is invalid", index_errors(tampered))

    def test_unknown_fields_acceptance_and_sensitive_claims_fail_closed(self) -> None:
        reviewed = self._reviewed()
        mutations = []
        accepted = copy.deepcopy(reviewed)
        accepted["production_acceptance"] = True
        mutations.append(self._reseal(accepted))
        unknown = copy.deepcopy(reviewed)
        unknown["provider_response"] = "redacted"
        mutations.append(self._reseal(unknown))
        sensitive = copy.deepcopy(reviewed)
        sensitive["prohibited_content"]["contains_provider_payloads"] = True
        mutations.append(self._reseal(sensitive))

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(index_errors(document))

    def test_binding_must_match_same_environment_contract_and_inventory(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])

        replaced_contract = copy.deepcopy(manifest)
        replaced_contract["items"][0]["sha256"] = "f" * 64
        missing_inventory = copy.deepcopy(manifest)
        missing_inventory["items"][1]["status"] = "missing"
        wrong_environment = copy.deepcopy(manifest)
        wrong_environment["environment"] = "production"

        self.assertIn(
            "Sub2 evidence sub2_contract binding does not match this intake manifest",
            intake_binding_errors(reviewed, replaced_contract),
        )
        self.assertIn(
            "Sub2 evidence target_platform_inventory binding target is not provided",
            intake_binding_errors(reviewed, missing_inventory),
        )
        self.assertIn(
            "Sub2 evidence environment does not match this intake manifest",
            intake_binding_errors(reviewed, wrong_environment),
        )

    def test_cli_distinguishes_invalid_content_from_binding_mismatch(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index_path = root / "sub2-evidence-index.json"
            manifest_path = root / "intake.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            index_path.write_text(json.dumps(self.template), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(index_path),
                        "--intake-manifest",
                        str(manifest_path),
                    ]
                ),
                1,
            )
            index_path.write_text(json.dumps(reviewed), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(index_path),
                        "--intake-manifest",
                        str(manifest_path),
                    ]
                ),
                0,
            )
            manifest["items"][0]["sha256"] = "f" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(index_path),
                        "--intake-manifest",
                        str(manifest_path),
                    ]
                ),
                2,
            )

    def test_runbook_documents_external_index_and_evidence_limit(self) -> None:
        rendered = json.dumps(self.template, ensure_ascii=False).casefold()
        for forbidden in (
            "4111111111111111",
            "bearer ",
            "client_secret",
            "https://provider",
            "@example",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

        text = (
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .replace("\n", " ")
        )
        for expected in (
            "sub2_execution_evidence.py check",
            "balance check",
            "authorization exchange",
            "successful create",
            "definitive failure",
            "submission timeout",
            "five normalized status outcomes",
            "same-provider-key duplicate replay",
            "unknown reconciliation",
            "index metadata only",
            "does not verify the external evidence content",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
