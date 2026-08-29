from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.target_phase_artifacts import (
    ARTIFACT_PATHS,
    SCENARIO_CONTRACTS,
    artifact_errors,
    intake_binding_errors,
    main,
    phase5_windows_alignment_errors,
    repository_errors,
    seal_artifact,
)
from tests.intake_manifest_support import (
    bind_manifest_item_bytes,
    closed_manifest,
    manifest_pin_arguments,
)


class TargetPhaseArtifactTests(unittest.TestCase):
    EVALUATED_AT = datetime(2026, 8, 26, 12, 30, tzinfo=timezone.utc)

    def setUp(self) -> None:
        self.templates = {
            identifier: json.loads(path.read_text(encoding="utf-8"))
            for identifier, path in ARTIFACT_PATHS.items()
        }

    def test_repository_templates_are_sealed_pending_and_non_accepting(self) -> None:
        self.assertEqual(repository_errors(), [])
        for identifier, document in self.templates.items():
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    artifact_errors(document, expected_type=identifier), []
                )
                self.assertTrue(document["synthetic"])
                self.assertEqual(
                    document.get("index_status", document.get("inventory_status")),
                    "pending",
                )
                self.assertFalse(document["production_acceptance"])
                self.assertIsNone(document["reviewed_at"])
                self.assertIsNone(document["valid_until"])
                self.assertEqual(
                    document["schema_version"],
                    2 if identifier == "windows_pilot_inputs" else 3,
                )

    def _reviewed(self, identifier: str) -> dict[str, object]:
        document = copy.deepcopy(self.templates[identifier])
        document.update(
            {
                "synthetic": False,
                "review_reference": f"{identifier.replace('_', '-')}-review-42",
                "reviewed_at": "2026-08-26T12:15:00Z",
                "valid_until": "2026-08-26T13:00:00Z",
                "environment": "staging",
            }
        )
        if identifier == "windows_pilot_inputs":
            document.update(
                {
                    "inventory_reference": "windows-pilot-input-record-42",
                    "inventory_status": "reviewed",
                    "reviewed_at": "2026-08-26T10:30:00Z",
                    "bindings": {"target_platform_inventory_sha256": "d" * 64},
                    "windows_target": {
                        "environment_reference": "windows-host-record-42",
                        "os_family": "windows",
                        "architecture": "x86_64",
                        "update_channel_reference": "windows-channel-record-42",
                    },
                    "business_page": {
                        "page_reference": "business-page-record-42",
                        "field_sequence": ["account_identifier", "verification_code"],
                        "continuous_paste_required": True,
                    },
                }
            )
            return seal_artifact(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        document.update(
            {
                "index_reference": f"{identifier.replace('_', '-')}-record-42",
                "index_status": "reviewed",
                "bindings": {
                    key: (
                        "v1.2.3"
                        if key == "release_tag"
                        else "a" * 40
                        if key == "release_commit"
                        else "d" * 64
                    )
                    for key in document["bindings"]
                },
                "window": {
                    "started_at": "2026-08-26T11:00:00Z",
                    "finished_at": "2026-08-26T12:00:00Z",
                },
                "release_execution": {
                    "ledger_type": "forward",
                    "evidence_object_reference": "worm-release-execution:record-42",
                    "evidence_sha256": "e" * 64,
                    "target_intake": {
                        "environment": "staging",
                        "manifest_payload_sha256": "f" * 64,
                        "requirements_sha256": "1" * 64,
                        "checkpoint_phase": 0,
                    },
                },
            }
        )
        document["scenarios"] = {
            scenario: {
                "execution_reference": f"phase-execution-record-{index}",
                "executor_reference": f"phase-operator-record-{index}",
                "reviewer_reference": f"phase-reviewer-record-{index}",
                "correlation_reference": f"phase-correlation-record-{index}",
                "executed_at": f"2026-08-26T11:{index:02d}:00Z",
                "observation": observation,
                "result": "passed",
                "evidence_object_reference": f"worm-phase-object-{index}",
                "evidence_sha256": f"{index:064x}",
                "redaction_confirmed": True,
            }
            for index, (scenario, observation) in enumerate(
                SCENARIO_CONTRACTS[identifier].items(),
                start=1,
            )
        }
        return seal_artifact(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def test_integrity_and_closed_type_contract_reject_substitution(self) -> None:
        for identifier, document in self.templates.items():
            tampered = copy.deepcopy(document)
            tampered["production_acceptance"] = True
            wrong_type = next(
                candidate for candidate in self.templates if candidate != identifier
            )
            extra = copy.deepcopy(document)
            extra["approved"] = True
            synthetic_impersonation = copy.deepcopy(document)
            synthetic_impersonation["synthetic"] = False
            if "index_status" in synthetic_impersonation:
                synthetic_impersonation["index_status"] = "reviewed"
            else:
                synthetic_impersonation["inventory_status"] = "reviewed"
            synthetic_impersonation = seal_artifact(
                {
                    key: value
                    for key, value in synthetic_impersonation.items()
                    if key != "integrity"
                }
            )
            with self.subTest(identifier=identifier, attack="unsealed-tamper"):
                self.assertTrue(artifact_errors(tampered, expected_type=identifier))
            with self.subTest(identifier=identifier, attack="wrong-type"):
                self.assertTrue(
                    artifact_errors(document, expected_type=wrong_type)
                )
            with self.subTest(identifier=identifier, attack="extra-field"):
                self.assertTrue(
                    artifact_errors(
                        seal_artifact(
                            {
                                key: value
                                for key, value in extra.items()
                                if key != "integrity"
                            }
                        ),
                        expected_type=identifier,
                    )
                )
            with self.subTest(identifier=identifier, attack="synthetic-impersonation"):
                self.assertTrue(
                    artifact_errors(
                        synthetic_impersonation,
                        expected_type=identifier,
                    )
                )

    def test_reviewed_artifacts_are_post_window_current_and_exclusively_bounded(self) -> None:
        for identifier in self.templates:
            reviewed = self._reviewed(identifier)
            with self.subTest(identifier=identifier, state="current"):
                self.assertEqual(
                    artifact_errors(
                        reviewed,
                        expected_type=identifier,
                        evaluated_at=self.EVALUATED_AT,
                    ),
                    [],
                )
            future_review = copy.deepcopy(reviewed)
            future_review["reviewed_at"] = "2026-08-26T12:31:00Z"
            future_review = seal_artifact(
                {key: value for key, value in future_review.items() if key != "integrity"}
            )
            with self.subTest(identifier=identifier, state="future-review"):
                self.assertTrue(
                    artifact_errors(
                        future_review,
                        expected_type=identifier,
                        evaluated_at=self.EVALUATED_AT,
                    )
                )
            with self.subTest(identifier=identifier, state="exclusive-expiry"):
                self.assertTrue(
                    artifact_errors(
                        reviewed,
                        expected_type=identifier,
                        evaluated_at=datetime(2026, 8, 26, 13, 0, tzinfo=timezone.utc),
                    )
                )
                self.assertEqual(
                    artifact_errors(
                        reviewed,
                        expected_type=identifier,
                        evaluated_at=datetime(2026, 8, 26, 13, 0, tzinfo=timezone.utc)
                        - timedelta(microseconds=1),
                    ),
                    [],
                )
        evidence = self._reviewed("phase1_platform_evidence")
        evidence["reviewed_at"] = "2026-08-26T11:59:59Z"
        evidence = seal_artifact(
            {key: value for key, value in evidence.items() if key != "integrity"}
        )
        self.assertIn(
            "reviewed phase1 platform evidence review validity is invalid",
            artifact_errors(
                evidence,
                expected_type="phase1_platform_evidence",
                evaluated_at=self.EVALUATED_AT,
            ),
        )

    def test_phase5_window_is_inside_the_bound_windows_input_validity(self) -> None:
        inputs = self._reviewed("windows_pilot_inputs")
        evidence = self._reviewed("phase5_windows_evidence")
        self.assertEqual(phase5_windows_alignment_errors(evidence, inputs), [])
        too_early = copy.deepcopy(evidence)
        too_early["window"]["started_at"] = "2026-08-26T10:29:59Z"
        self.assertTrue(phase5_windows_alignment_errors(too_early, inputs))
        expires_at_finish = copy.deepcopy(evidence)
        expires_at_finish["window"]["finished_at"] = inputs["valid_until"]
        self.assertTrue(phase5_windows_alignment_errors(expires_at_finish, inputs))

    def test_binding_requires_the_exact_same_manifest_artifact_hashes(self) -> None:
        manifest = {
            "environment": "staging",
            "requirements_sha256": "e" * 64,
            "items": [
                {
                    "id": identifier,
                    "status": "provided",
                    "sha256": f"{index:064x}",
                }
                for index, identifier in enumerate(
                    (
                        "mail_contract",
                        "card_pci_boundary",
                        "oidc_deployment_identity",
                        "target_platform_inventory",
                        "windows_pilot_inputs",
                    ),
                    start=1,
                )
            ],
        }
        targets = {
            "phase1_platform_evidence": ("target_platform_inventory",),
            "phase2_mail_evidence": (
                "mail_contract",
                "target_platform_inventory",
            ),
            "phase3_card_evidence": (
                "card_pci_boundary",
                "oidc_deployment_identity",
                "target_platform_inventory",
            ),
            "windows_pilot_inputs": ("target_platform_inventory",),
            "phase5_windows_evidence": (
                "windows_pilot_inputs",
                "target_platform_inventory",
            ),
        }
        hashes = {item["id"]: item["sha256"] for item in manifest["items"]}
        for identifier, dependencies in targets.items():
            document = copy.deepcopy(self.templates[identifier])
            document["environment"] = "staging"
            for dependency in dependencies:
                document["bindings"][f"{dependency}_sha256"] = hashes[dependency]
            if identifier != "windows_pilot_inputs":
                document["release_execution"]["target_intake"].update(
                    {
                        "environment": "staging",
                        "requirements_sha256": "e" * 64,
                        "checkpoint_phase": 0,
                    }
                )
            own_item = next(
                (item for item in manifest["items"] if item["id"] == identifier),
                None,
            )
            if own_item is None:
                own_item = {"id": identifier, "sha256": "9" * 64}
                manifest["items"].append(own_item)
            own_item.update(
                {
                    "status": "provided",
                    "reviewed_by": document.get("review_reference"),
                    "reviewed_at": document.get("reviewed_at"),
                }
            )
            with self.subTest(identifier=identifier, state="aligned"):
                self.assertEqual(
                    intake_binding_errors(
                        document,
                        manifest,
                        expected_type=identifier,
                    ),
                    [],
                )
            document["bindings"][f"{dependencies[0]}_sha256"] = "f" * 64
            with self.subTest(identifier=identifier, state="hash-substitution"):
                self.assertTrue(
                    intake_binding_errors(
                        document,
                        manifest,
                        expected_type=identifier,
                    )
                )
            own_item["reviewed_by"] = "different-review-record-42"
            with self.subTest(identifier=identifier, state="review-substitution"):
                self.assertTrue(
                    intake_binding_errors(
                        document,
                        manifest,
                        expected_type=identifier,
                    )
                )
            own_item["reviewed_by"] = document.get("review_reference")
            document["environment"] = "production"
            with self.subTest(identifier=identifier, state="environment-substitution"):
                self.assertTrue(
                    intake_binding_errors(
                        document,
                        manifest,
                        expected_type=identifier,
                    )
                )

    def test_cli_rejects_synthetic_and_duplicate_key_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "intake.json"
            synthetic_template = ARTIFACT_PATHS["phase1_platform_evidence"]
            synthetic = root / "synthetic.json"
            synthetic.write_bytes(synthetic_template.read_bytes())
            intake = closed_manifest(
                {
                    "environment": "staging",
                    "items": [{"id": "phase1_platform_evidence"}],
                }
            )
            bind_manifest_item_bytes(
                intake,
                "phase1_platform_evidence",
                synthetic.read_bytes(),
                path=synthetic,
            )
            manifest.write_text(json.dumps(intake), encoding="utf-8")
            pin_arguments = manifest_pin_arguments(manifest)
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(synthetic),
                        "--expected-type",
                        "phase1_platform_evidence",
                        "--intake-manifest",
                        str(manifest),
                        *pin_arguments,
                    ]
                ),
                1,
            )
            duplicate = root / "duplicate.json"
            encoded = synthetic.read_text(encoding="utf-8")
            duplicate.write_text(
                encoded.replace(
                    '  "synthetic": true,',
                    '  "synthetic": true,\n  "synthetic": true,',
                    1,
                ),
                encoding="utf-8",
            )
            bind_manifest_item_bytes(
                intake,
                "phase1_platform_evidence",
                duplicate.read_bytes(),
                path=duplicate,
            )
            manifest.write_text(json.dumps(intake), encoding="utf-8")
            pin_arguments = manifest_pin_arguments(manifest)
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(duplicate),
                        "--expected-type",
                        "phase1_platform_evidence",
                        "--intake-manifest",
                        str(manifest),
                        *pin_arguments,
                    ]
                ),
                1,
            )

    def test_phase5_cli_requires_and_binds_windows_pilot_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows_inputs = self._reviewed("windows_pilot_inputs")
            windows_inputs["valid_until"] = "2099-08-26T13:00:00Z"
            windows_inputs = seal_artifact(
                {
                    key: value
                    for key, value in windows_inputs.items()
                    if key != "integrity"
                }
            )
            windows_path = root / "windows-inputs.json"
            windows_path.write_text(json.dumps(windows_inputs), encoding="utf-8")
            windows_digest = hashlib.sha256(windows_path.read_bytes()).hexdigest()

            evidence = self._reviewed("phase5_windows_evidence")
            evidence["valid_until"] = "2099-08-26T13:00:00Z"
            evidence["bindings"]["windows_pilot_inputs_sha256"] = windows_digest
            evidence = seal_artifact(
                {key: value for key, value in evidence.items() if key != "integrity"}
            )
            evidence_path = root / "phase5-evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            manifest = {
                "environment": "staging",
                "requirements_sha256": "1" * 64,
                "items": [
                    {
                        "id": "target_platform_inventory",
                        "status": "provided",
                        "sha256": "d" * 64,
                    },
                    {
                        "id": "windows_pilot_inputs",
                        "status": "provided",
                        "sha256": windows_digest,
                        "reviewed_by": windows_inputs["review_reference"],
                        "reviewed_at": windows_inputs["reviewed_at"],
                    },
                    {
                        "id": "phase5_windows_evidence",
                        "status": "provided",
                        "reviewed_by": evidence["review_reference"],
                        "reviewed_at": evidence["reviewed_at"],
                    },
                ],
            }
            manifest_path = root / "intake.json"
            manifest = closed_manifest(manifest)
            bind_manifest_item_bytes(
                manifest,
                "phase5_windows_evidence",
                evidence_path.read_bytes(),
                path=evidence_path,
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            pin_arguments = manifest_pin_arguments(manifest_path)
            arguments = [
                "check",
                "--input",
                str(evidence_path),
                "--expected-type",
                "phase5_windows_evidence",
                "--intake-manifest",
                str(manifest_path),
                "--release-execution-evidence",
                str(root / "release.json"),
                *pin_arguments,
            ]
            with mock.patch(
                "scripts.target_phase_artifacts.release_execution_alignment_errors",
                return_value=[],
            ):
                self.assertEqual(main(arguments), 2)
                self.assertEqual(
                    main(arguments + ["--windows-pilot-inputs", str(windows_path)]),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
