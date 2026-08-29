from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.phase0_boundary_approval import (
    APPROVAL,
    approval_errors,
    intake_binding_errors,
    main,
)
from tests.intake_manifest_support import (
    bind_manifest_item_bytes,
    closed_manifest,
    manifest_pin_arguments,
)


class Phase0BoundaryApprovalTests(unittest.TestCase):
    EVALUATED_AT = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

    def setUp(self) -> None:
        self.approval = json.loads(APPROVAL.read_text(encoding="utf-8"))

    @staticmethod
    def _canonical_sha256(document: object) -> str:
        rendered = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(rendered).hexdigest()

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.approval)
        document.update(
            {
                "approval_reference": "phase0-approval-record-42",
                "synthetic": False,
                "approval_status": "approved",
                "review_reference": "phase0-independent-review-42",
                "reviewed_at": "2026-08-27T12:00:00Z",
                "valid_until": "2099-08-27T12:00:00Z",
            }
        )
        document["reviewers"] = {
            "security_reference": "security-review-record-42",
            "privacy_reference": "privacy-review-record-42",
            "platform_owner_reference": "platform-owner-record-42",
        }
        document["bindings"] = {
            "mail_contract": "1" * 64,
            "sub2_contract": "2" * 64,
            "card_pci_boundary": "3" * 64,
            "oidc_deployment_identity": "4" * 64,
            "target_platform_inventory": "6" * 64,
            "target_intake_requirements_sha256": "5" * 64,
        }
        return document

    @staticmethod
    def _manifest(bindings: dict[str, str]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": bindings["target_intake_requirements_sha256"],
            "items": [
                {
                    "id": identifier,
                    "status": "provided",
                    "artifact_path": f"D:\\external\\{identifier}.json",
                    "sha256": bindings[identifier],
                    "reviewed_by": "review-record-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
                for identifier in (
                    "sub2_contract",
                    "mail_contract",
                    "card_pci_boundary",
                    "oidc_deployment_identity",
                    "target_platform_inventory",
                )
            ]
            + [
                {
                    "id": "phase0_boundary_approval",
                    "status": "provided",
                    "artifact_path": "D:\\external\\phase0-boundary-approval.json",
                    "sha256": "7" * 64,
                    "reviewed_by": "phase0-independent-review-42",
                    "reviewed_at": "2026-08-27T12:00:00Z",
                    "redaction_confirmed": True,
                }
            ],
        }

    def test_repository_template_is_safe_closed_and_in_quality_gate(self) -> None:
        self.assertEqual(approval_errors(self.approval), [])
        self.assertTrue(self.approval["synthetic"])
        self.assertEqual(self.approval["approval_status"], "pending")
        self.assertFalse(self.approval["production_acceptance"])
        self.assertTrue(all(value is None for value in self.approval["bindings"].values()))
        self.assertEqual(
            self.approval["data_classification_sha256"],
            self._canonical_sha256(self.approval["data_classification"]),
        )
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/phase0_boundary_approval.py verify-repository",
            quality_gate,
        )

    def test_schema_acceptance_and_sensitive_claims_fail_closed(self) -> None:
        mutations = []
        accepted = copy.deepcopy(self.approval)
        accepted["production_acceptance"] = True
        mutations.append(accepted)
        unknown = copy.deepcopy(self.approval)
        unknown["approver_email"] = "redacted"
        mutations.append(unknown)
        sensitive = copy.deepcopy(self.approval)
        sensitive["prohibited_content"]["contains_verification_code_values"] = True
        mutations.append(sensitive)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(approval_errors(document))

    def test_classification_policy_and_its_digest_are_immutable(self) -> None:
        policy_drift = copy.deepcopy(self.approval)
        policy_drift["data_classification"]["cvv"]["logs"] = "redacted_only"
        policy_drift["data_classification_sha256"] = self._canonical_sha256(
            policy_drift["data_classification"]
        )
        digest_drift = copy.deepcopy(self.approval)
        digest_drift["data_classification_sha256"] = "0" * 64

        self.assertTrue(approval_errors(policy_drift))
        self.assertTrue(approval_errors(digest_drift))

    def test_reviewed_approval_requires_distinct_opaque_references_and_hashes(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(approval_errors(reviewed), [])

        duplicate = copy.deepcopy(reviewed)
        duplicate["reviewers"]["security_reference"] = duplicate["review_reference"]
        missing_hash = copy.deepcopy(reviewed)
        missing_hash["bindings"]["mail_contract"] = None
        synthetic_reference = copy.deepcopy(reviewed)
        synthetic_reference["approval_reference"] = "synthetic-phase0-boundary-approval"

        for document in (duplicate, missing_hash, synthetic_reference):
            with self.subTest(document=document):
                self.assertTrue(approval_errors(document))

    def test_reviewed_approval_validity_is_canonical_current_and_exclusive(self) -> None:
        reviewed = self._reviewed()
        reviewed["valid_until"] = "2026-08-28T12:00:00Z"
        self.assertEqual(
            approval_errors(reviewed, evaluated_at=self.EVALUATED_AT),
            [],
        )

        expired = copy.deepcopy(reviewed)
        expired["valid_until"] = "2026-08-27T12:00:00Z"
        future = copy.deepcopy(reviewed)
        future["reviewed_at"] = "2026-08-27T12:00:01Z"
        noncanonical = copy.deepcopy(reviewed)
        noncanonical["reviewed_at"] = "2026-08-27T20:00:00+08:00"
        reversed_window = copy.deepcopy(reviewed)
        reversed_window["valid_until"] = reviewed["reviewed_at"]

        for document in (expired, future, noncanonical, reversed_window):
            with self.subTest(document=document):
                self.assertTrue(
                    approval_errors(document, evaluated_at=self.EVALUATED_AT)
                )

    def test_binding_must_match_the_same_intake_manifest(self) -> None:
        reviewed = self._reviewed()
        bindings = reviewed["bindings"]
        manifest = self._manifest(bindings)
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])

        replaced = copy.deepcopy(manifest)
        replaced["items"][1]["sha256"] = "a" * 64
        missing = copy.deepcopy(manifest)
        missing["items"][0]["status"] = "missing"

        self.assertIn(
            "phase0 approval mail_contract binding does not match this intake manifest",
            intake_binding_errors(reviewed, replaced),
        )
        self.assertIn(
            "phase0 approval sub2_contract binding target is not provided",
            intake_binding_errors(reviewed, missing),
        )

        future_dependency = copy.deepcopy(manifest)
        future_dependency["items"][0]["reviewed_at"] = "2026-08-27T12:00:01Z"
        self.assertIn(
            "phase0 approval predates the reviewed sub2_contract input",
            intake_binding_errors(reviewed, future_dependency),
        )

        invalid_dependency_time = copy.deepcopy(manifest)
        invalid_dependency_time["items"][0]["reviewed_at"] = (
            "2026-08-26T20:00:00+08:00"
        )
        self.assertIn(
            "phase0 approval sub2_contract review time is invalid",
            intake_binding_errors(reviewed, invalid_dependency_time),
        )

        projected = copy.deepcopy(manifest)
        projected["items"][-1]["reviewed_by"] = "different-review-record"
        self.assertIn(
            "phase0 approval review metadata does not match this intake manifest",
            intake_binding_errors(reviewed, projected),
        )

    def test_cli_distinguishes_invalid_content_from_binding_mismatch(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            approval_path = root / "approval.json"
            manifest_path = root / "manifest.json"
            approval_path.write_text(json.dumps(self.approval), encoding="utf-8")
            manifest = closed_manifest(manifest)
            reviewed_raw = json.dumps(reviewed).encode("utf-8")
            bind_manifest_item_bytes(
                manifest,
                "phase0_boundary_approval",
                reviewed_raw,
            )
            manifest_encoded = json.dumps(manifest)
            manifest_path.write_text(manifest_encoded, encoding="utf-8")
            pin_arguments = manifest_pin_arguments(manifest_path)
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(approval_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                    ]
                ),
                1,
            )

            approval_path.write_bytes(reviewed_raw)
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(approval_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                    ]
                ),
                0,
            )

            approval_path.write_text(json.dumps(reviewed, indent=2), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(approval_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                    ]
                ),
                2,
            )
            approval_path.write_bytes(reviewed_raw)

            manifest["requirements_sha256"] = "a" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(approval_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                    ]
                ),
                2,
            )

            manifest_path.write_text(manifest_encoded, encoding="utf-8")
            approval_path.write_text('{"kind":"approval"}', encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(approval_path),
                        "--intake-manifest",
                        str(manifest_path),
                        *pin_arguments,
                    ]
                ),
                1,
            )

    def test_template_contains_policy_shapes_not_sensitive_values(self) -> None:
        rendered = json.dumps(self.approval, ensure_ascii=False).casefold()
        for forbidden in (
            "4111111111111111",
            "bearer ",
            "client_secret",
            "private_key",
            "@example",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

    def test_runbook_documents_same_manifest_binding_and_non_acceptance(self) -> None:
        text = (
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .replace("\n", " ")
        )
        for expected in (
            "phase0_boundary_approval.py check",
            "same intake manifest",
            "requirements_sha256",
            "target platform inventory",
            "approval review time must not predate",
            "does not prove production acceptance, reviewer identity or authority",
            "synthetic phase 0 approval cannot satisfy strict intake",
            "does not prove production acceptance",
            "exit code 2",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
