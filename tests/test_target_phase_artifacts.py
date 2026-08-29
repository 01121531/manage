from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.target_phase_artifacts import (
    ARTIFACT_PATHS,
    artifact_errors,
    intake_binding_errors,
    main,
    repository_errors,
    seal_artifact,
)


class TargetPhaseArtifactTests(unittest.TestCase):
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

    def test_binding_requires_the_exact_same_manifest_artifact_hashes(self) -> None:
        manifest = {
            "environment": "staging",
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
            manifest.write_text(
                json.dumps({"environment": "staging", "items": []}),
                encoding="utf-8",
            )
            synthetic = ARTIFACT_PATHS["phase1_platform_evidence"]
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
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
