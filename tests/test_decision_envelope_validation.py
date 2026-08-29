from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from scripts.decision_envelope_validation import (
    CARD_PCI_DECISION,
    OIDC_IDENTITY_DECISION,
    decision_errors,
    main,
    runtime_alignment_errors,
)


class DecisionEnvelopeValidationTests(unittest.TestCase):
    EVALUATED_AT = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)

    def setUp(self) -> None:
        self.card = json.loads(CARD_PCI_DECISION.read_text(encoding="utf-8"))
        self.oidc = json.loads(OIDC_IDENTITY_DECISION.read_text(encoding="utf-8"))

    def test_repository_templates_are_safe_closed_and_runtime_aligned(self) -> None:
        self.assertEqual(
            decision_errors(self.card, expected_type="card_pci_boundary"), []
        )
        self.assertEqual(
            decision_errors(self.oidc, expected_type="oidc_deployment_identity"),
            [],
        )
        self.assertEqual(runtime_alignment_errors(self.card), [])
        self.assertEqual(runtime_alignment_errors(self.oidc), [])
        self.assertTrue(self.card["synthetic"])
        self.assertTrue(self.oidc["synthetic"])
        self.assertEqual(self.card["decision_status"], "pending")
        self.assertEqual(self.oidc["decision_status"], "pending")
        self.assertFalse(self.card["production_acceptance"])
        self.assertFalse(self.oidc["production_acceptance"])
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/decision_envelope_validation.py verify-repository",
            quality_gate,
        )

    def test_card_decision_cannot_enable_cvv_or_raw_database_storage(self) -> None:
        mutations = []
        for path, value in (
            (("field_inventory", "pan", "platform_database_storage"), True),
            (("field_inventory", "cvv", "source"), "external_card_vault"),
            (("field_inventory", "cvv", "api_reveal"), "mfa_one_time"),
            (("field_inventory", "cvv", "sub2_egress"), "reviewed_contract_only"),
        ):
            changed = copy.deepcopy(self.card)
            changed[path[0]][path[1]][path[2]] = value
            mutations.append(changed)

        for document in mutations:
            with self.subTest(inventory=document["field_inventory"]):
                self.assertTrue(
                    decision_errors(document, expected_type="card_pci_boundary")
                )

    def test_oidc_decision_requires_exact_claims_acr_public_clients_and_s256(self) -> None:
        mutations = []
        for mutate in (
            lambda item: item["acr_to_loa"].update(
                required_acr="urn:email-platform:acr:password"
            ),
            lambda item: item["deployment_identity"].update(tenant_claim="tenant"),
            lambda item: item["deployment_identity"].update(device_claim="device"),
            lambda item: item["clients"]["web"].update(client_type="confidential"),
            lambda item: item["clients"]["desktop"].update(pkce_method="plain"),
        ):
            changed = copy.deepcopy(self.oidc)
            mutate(changed)
            mutations.append(changed)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(
                    decision_errors(
                        document, expected_type="oidc_deployment_identity"
                    )
                )

    def test_real_decisions_require_approval_and_independent_references(self) -> None:
        card = copy.deepcopy(self.card)
        card.update(
            {
                "synthetic": False,
                "decision_reference": "card-decision-record-42",
                "decision_status": "approved",
                "review_reference": "security-review-record-42",
                "reviewed_at": "2026-08-26T12:00:00Z",
                "valid_until": "2099-08-26T12:00:00Z",
            }
        )
        card["pci_scope"].update(
            {
                "classification": "in_scope",
                "assessment_reference": "pci-assessment-record-42",
                "card_vault_owner_reference": "card-vault-owner-record-42",
            }
        )
        oidc = copy.deepcopy(self.oidc)
        oidc.update(
            {
                "synthetic": False,
                "decision_reference": "oidc-decision-record-42",
                "decision_status": "approved",
                "review_reference": "identity-review-record-42",
                "reviewed_at": "2026-08-26T12:00:00Z",
                "valid_until": "2099-08-26T12:00:00Z",
            }
        )
        oidc["deployment_identity"]["issuer_reference"] = "issuer-record-42"
        oidc["acr_to_loa"]["mapping_review_reference"] = "mapping-review-record-42"

        for document in (card, oidc):
            with self.subTest(decision=document["decision_type"]):
                self.assertEqual(
                    decision_errors(document, expected_type=document["decision_type"]),
                    [],
                )
                not_independent = copy.deepcopy(document)
                if document["decision_type"] == "card_pci_boundary":
                    not_independent["pci_scope"]["assessment_reference"] = document[
                        "review_reference"
                    ]
                else:
                    not_independent["acr_to_loa"]["mapping_review_reference"] = (
                        document["review_reference"]
                    )
                self.assertTrue(
                    decision_errors(
                        not_independent,
                        expected_type=document["decision_type"],
                    )
                )

        incomplete = copy.deepcopy(self.card)
        incomplete["synthetic"] = False
        incomplete["decision_reference"] = "approved-decision-record-42"
        self.assertTrue(
            decision_errors(incomplete, expected_type="card_pci_boundary")
        )

    def test_reviewed_decision_validity_is_canonical_current_and_exclusive(self) -> None:
        reviewed = copy.deepcopy(self.card)
        reviewed.update(
            {
                "synthetic": False,
                "decision_reference": "card-decision-record-42",
                "decision_status": "approved",
                "review_reference": "security-review-record-42",
                "reviewed_at": "2026-08-26T12:00:00Z",
                "valid_until": "2026-08-28T12:00:00Z",
            }
        )
        reviewed["pci_scope"].update(
            {
                "classification": "in_scope",
                "assessment_reference": "pci-assessment-record-42",
                "card_vault_owner_reference": "card-vault-owner-record-42",
            }
        )
        self.assertEqual(
            decision_errors(
                reviewed,
                expected_type="card_pci_boundary",
                evaluated_at=self.EVALUATED_AT,
            ),
            [],
        )

        expired = copy.deepcopy(reviewed)
        expired["valid_until"] = "2026-08-27T12:00:00Z"
        future = copy.deepcopy(reviewed)
        future["reviewed_at"] = "2026-08-27T12:00:01Z"
        noncanonical = copy.deepcopy(reviewed)
        noncanonical["reviewed_at"] = "2026-08-26T20:00:00+08:00"
        reversed_window = copy.deepcopy(reviewed)
        reversed_window["valid_until"] = reviewed["reviewed_at"]

        for document in (expired, future, noncanonical, reversed_window):
            with self.subTest(document=document):
                self.assertTrue(
                    decision_errors(
                        document,
                        expected_type="card_pci_boundary",
                        evaluated_at=self.EVALUATED_AT,
                    )
                )

    def test_unknown_fields_acceptance_and_sensitive_claims_fail_closed(self) -> None:
        mutations = []
        accepted = copy.deepcopy(self.card)
        accepted["production_acceptance"] = True
        mutations.append(accepted)
        unknown = copy.deepcopy(self.oidc)
        unknown["approver_email"] = "redacted"
        mutations.append(unknown)
        sensitive = copy.deepcopy(self.card)
        sensitive["prohibited_content"]["contains_cvv_values"] = True
        mutations.append(sensitive)

        for document in mutations:
            with self.subTest(decision=document.get("decision_type")):
                self.assertTrue(decision_errors(document))

    def test_webauthn_decision_is_valid_but_reports_current_realm_gap(self) -> None:
        changed = copy.deepcopy(self.oidc)
        changed["acr_to_loa"]["authentication_methods"] = ["webauthn"]

        self.assertEqual(
            decision_errors(changed, expected_type="oidc_deployment_identity"), []
        )
        self.assertIn(
            "Keycloak realm does not implement the decided WebAuthn method",
            runtime_alignment_errors(changed),
        )

    def test_templates_contain_shapes_not_sensitive_values(self) -> None:
        rendered = json.dumps([self.card, self.oidc], ensure_ascii=False).casefold()
        for forbidden in (
            "4111111111111111",
            '"cvv_value"',
            "bearer ",
            "client_secret",
            "private_key",
            "eyj",
            "@example",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

    def test_intake_runbook_documents_decision_checks_and_non_acceptance(self) -> None:
        text = (
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .replace("\n", " ")
        )
        for expected in (
            "decision_envelope_validation.py check",
            "--expected-type card_pci_boundary",
            "--expected-type oidc_deployment_identity",
            "synthetic decision envelopes cannot satisfy strict intake",
            "does not authorize cvv storage",
            "[reviewed_at, valid_until)",
            "host clock is not evidence of a trusted external time source",
            "exit code 2",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_cli_distinguishes_invalid_envelope_from_runtime_gap(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid_path = root / "invalid.json"
            invalid_path.write_text('{"kind":"decision"}', encoding="utf-8")
            webauthn = copy.deepcopy(self.oidc)
            webauthn["acr_to_loa"]["authentication_methods"] = ["webauthn"]
            webauthn_path = root / "webauthn.json"
            webauthn_path.write_text(json.dumps(webauthn), encoding="utf-8")

            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(invalid_path),
                        "--expected-type",
                        "card_pci_boundary",
                    ]
                ),
                1,
            )
            self.assertEqual(
                main(
                    [
                        "check",
                        "--input",
                        str(webauthn_path),
                        "--expected-type",
                        "oidc_deployment_identity",
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
