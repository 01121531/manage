from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import scripts.external_json as external_json
import scripts.target_intake_preflight as target_intake

from scripts.decision_envelope_validation import (
    CARD_PCI_DECISION,
    OIDC_IDENTITY_DECISION,
)
from scripts.deploy_release_evidence import DeploymentReleaseEvidenceRecorder
from scripts.phase0_boundary_approval import APPROVAL
from scripts.phase6_pilot_inputs import (
    INVENTORY as PILOT_INPUT_INVENTORY,
    REQUIRED_ROLE_RESPONSIBILITIES as PILOT_ROLE_RESPONSIBILITIES,
    seal_inventory as seal_pilot_input_inventory,
)
from scripts.phase6_pilot_evidence import (
    EVIDENCE_INDEX as PILOT_EVIDENCE_INDEX,
    REQUIRED_SCENARIOS as PILOT_EVIDENCE_SCENARIOS,
    seal_index as seal_pilot_evidence_index,
)
from scripts.phase6_operations_evidence import (
    EVIDENCE_INDEX as OPERATIONS_EVIDENCE_INDEX,
    REQUIRED_ARTIFACT_DIGESTS as OPERATIONS_ARTIFACT_DIGESTS,
    REQUIRED_SCENARIOS as OPERATIONS_SCENARIOS,
    seal_index as seal_operations_evidence_index,
)
from scripts.provider_contract_conformance import MAIL_CONTRACT, SUB2_CONTRACT
from scripts.sub2_execution_evidence import (
    EVIDENCE_INDEX,
    REQUIRED_SCENARIO_OBSERVATIONS,
    seal_index,
)
from scripts.target_platform_inventory import INVENTORY
from scripts.target_phase_artifacts import (
    ARTIFACT_PATHS as TARGET_PHASE_ARTIFACTS,
    SCENARIO_CONTRACTS as TARGET_PHASE_SCENARIOS,
    artifact_errors as target_phase_artifact_errors,
    intake_binding_errors as target_phase_binding_errors,
    seal_artifact as seal_target_phase_artifact,
)
from scripts.vault_egress_evidence import (
    EVIDENCE_INDEX as VAULT_EGRESS_INDEX,
    REQUIRED_SCENARIO_OBSERVATIONS as VAULT_EGRESS_SCENARIOS,
    seal_index as seal_vault_egress_index,
)
from scripts.target_intake_preflight import (
    MATRIX,
    REQUIREMENTS,
    create_intake_manifest,
    intake_errors,
    load_phase_checkpoint,
    main,
    phase_checkpoint_errors,
    phase_requirement_ids,
    requirements_errors,
    requirements_sha256,
)
from tests.test_deploy_release_evidence import (
    IMAGES as DEPLOY_IMAGES,
    ROLLBACK as DEPLOY_ROLLBACK,
    _complete_success as complete_deploy_success,
    _seal_recorder as seal_deploy_recorder,
)


class TargetIntakePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        self.requirements = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))
        runtime_patch = mock.patch.object(
            target_intake,
            "runtime_conformance_errors",
            return_value=[],
        )
        runtime_patch.start()
        self.addCleanup(runtime_patch.stop)

    @staticmethod
    def _artifact_document(
        identifier: str,
        manifest: dict[str, object] | None = None,
        phase0_manifest_sha256: str = "8" * 64,
    ) -> dict[str, object]:
        if identifier == "mail_contract":
            document = json.loads(MAIL_CONTRACT.read_text(encoding="utf-8"))
        elif identifier == "sub2_contract":
            document = json.loads(SUB2_CONTRACT.read_text(encoding="utf-8"))
            workflow = document["capabilities"]["workflow"]
            workflow["provider_mode"] = "ordered_multi_step"
            for operation, details in workflow["operations"].items():
                details.update(
                    {
                        "provider_operation_reference": f"sub2-operation-{operation}",
                        "method": "GET" if operation == "status_query" else "POST",
                        "request_fields": ["correlation_id"],
                        "response_fields": ["result"],
                    }
                )
            workflow["idempotency"].update(
                {
                    "scope": "provider_account",
                    "minimum_retention_seconds": 86400,
                    "same_key_same_payload": "same_result",
                    "same_key_different_payload": "reject",
                }
            )
            workflow["status_consistency"].update(
                {
                    "model": "eventual",
                    "maximum_visibility_delay_seconds": 30,
                    "minimum_retention_seconds": 86400,
                }
            )
        elif identifier == "card_pci_boundary":
            document = json.loads(CARD_PCI_DECISION.read_text(encoding="utf-8"))
            document["pci_scope"].update(
                {
                    "classification": "in_scope",
                    "assessment_reference": "pci-assessment-ticket-42",
                    "card_vault_owner_reference": "card-vault-owner-record-42",
                }
            )
        elif identifier == "oidc_deployment_identity":
            document = json.loads(OIDC_IDENTITY_DECISION.read_text(encoding="utf-8"))
            document["deployment_identity"].update(
                {
                    "issuer_reference": "production-issuer-record-42",
                    "token_sample_policy": "irreversibly_redacted_external_evidence",
                }
            )
            document["acr_to_loa"]["mapping_review_reference"] = (
                "keycloak-mapping-review-42"
            )
        elif identifier == "phase0_boundary_approval":
            if manifest is None:
                raise ValueError("phase0 approval requires the current manifest")
            document = json.loads(APPROVAL.read_text(encoding="utf-8"))
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"]
                in {
                    "mail_contract",
                    "sub2_contract",
                    "card_pci_boundary",
                    "oidc_deployment_identity",
                }
            }
            document.update(
                {
                    "approval_reference": "phase0-approval-record-42",
                    "synthetic": False,
                    "approval_status": "approved",
                    "review_reference": "phase0-independent-review-42",
                }
            )
            document["reviewers"] = {
                "security_reference": "security-review-record-42",
                "privacy_reference": "privacy-review-record-42",
                "platform_owner_reference": "platform-owner-record-42",
            }
            document["bindings"] = {
                **hashes,
                "target_intake_requirements_sha256": manifest[
                    "requirements_sha256"
                ],
            }
            return document
        elif identifier == "target_platform_inventory":
            if manifest is None:
                raise ValueError("target inventory requires the current manifest")
            document = json.loads(INVENTORY.read_text(encoding="utf-8"))
            document.update(
                {
                    "inventory_reference": "target-platform-inventory-record-42",
                    "synthetic": False,
                    "inventory_status": "reviewed",
                    "review_reference": "target-platform-review-record-42",
                    "environment": manifest["environment"],
                }
            )
            document["public_endpoints"] = {
                "platform_domain": "mail.company.net",
                "application_origin": "https://mail.company.net",
                "identity_issuer": "https://identity.mail.company.net/realms/email-platform",
                "external_dns_owner_reference": "public-dns-owner-record-42",
                "external_certificate_owner_reference": "public-tls-owner-record-42",
            }
            document["control_planes"] = {
                "keycloak_owner_reference": "keycloak-owner-record-42",
                "vault_owner_reference": "vault-owner-record-42",
                "internal_dns_owner_reference": "internal-dns-owner-record-42",
            }
            document["certificate_ownership"].update(
                {
                    "internal_ca_owner_reference": "internal-ca-owner-record-42",
                    "issuance_owner_reference": "certificate-issuance-record-42",
                    "rotation_owner_reference": "certificate-rotation-record-42",
                }
            )
            locations = document["runtime_locations"]
            locations["repository_external_confirmed"] = True
            for key in locations["secret_files"]:
                locations["secret_files"][key] = (
                    "/srv/email-platform/runtime/" + key.casefold().replace("_", "-")
                )
            for key in locations["vault_token_directories"]:
                locations["vault_token_directories"][key] = (
                    "/srv/email-platform/vault-agent/"
                    + key.removeprefix("PLATFORM_VAULT_")
                    .removesuffix("_TOKEN_DIR")
                    .casefold()
                )
            for key in locations["policy_files"]:
                locations["policy_files"][key] = (
                    "/srv/email-platform/policy/" + key.casefold().replace("_", "-")
                )
            locations.update(
                {
                    "internal_tls_root": "/srv/email-platform/internal-tls",
                    "rolling_route_directory": "/srv/email-platform/rolling-edge-routing",
                    "evidence_root": "/srv/email-platform/evidence",
                }
            )
            return document
        elif identifier == "windows_pilot_inputs":
            if manifest is None:
                raise ValueError("Windows pilot inputs require the current manifest")
            document = json.loads(
                TARGET_PHASE_ARTIFACTS[identifier].read_text(encoding="utf-8")
            )
            target_inventory_sha256 = next(
                item["sha256"]
                for item in manifest["items"]
                if item["id"] == "target_platform_inventory"
            )
            document.update(
                {
                    "inventory_reference": "windows-pilot-inventory-record-42",
                    "synthetic": False,
                    "inventory_status": "reviewed",
                    "review_reference": "windows-pilot-review-record-42",
                    "reviewed_at": "2026-08-26T10:30:00Z",
                    "valid_until": "2099-08-26T10:30:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "target_platform_inventory_sha256": target_inventory_sha256,
                    },
                    "windows_target": {
                        "environment_reference": "windows-pilot-host-record-42",
                        "os_family": "windows",
                        "architecture": "x86_64",
                        "update_channel_reference": "windows-update-channel-42",
                    },
                    "business_page": {
                        "page_reference": "business-page-contract-42",
                        "field_sequence": [
                            "account_identifier",
                            "verification_code",
                            "card_reference",
                        ],
                        "continuous_paste_required": True,
                    },
                }
            )
            return seal_target_phase_artifact(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier in TARGET_PHASE_SCENARIOS:
            if manifest is None:
                raise ValueError("target phase evidence requires the current manifest")
            document = json.loads(
                TARGET_PHASE_ARTIFACTS[identifier].read_text(encoding="utf-8")
            )
            dependencies = {
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
                "phase5_windows_evidence": (
                    "windows_pilot_inputs",
                    "target_platform_inventory",
                ),
            }[identifier]
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"] in dependencies
            }
            document.update(
                {
                    "index_reference": f"{identifier.replace('_', '-')}-record-42",
                    "synthetic": False,
                    "index_status": "reviewed",
                    "review_reference": f"{identifier.replace('_', '-')}-review-42",
                    "reviewed_at": "2026-08-26T12:15:00Z",
                    "valid_until": "2099-08-26T12:15:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        **{
                            f"{dependency}_sha256": hashes[dependency]
                            for dependency in dependencies
                        },
                    },
                    "window": {
                        "started_at": "2026-08-26T11:00:00Z",
                        "finished_at": "2026-08-26T12:00:00Z",
                    },
                    "release_execution": {
                        "ledger_type": "forward",
                        "evidence_object_reference": "worm-release-execution:record-42a",
                        "evidence_sha256": next(
                            (
                                item["sha256"]
                                for item in manifest["items"]
                                if item["id"] == "release_execution_evidence"
                                and item["status"] == "provided"
                            ),
                            "f" * 64,
                        ),
                        "target_intake": {
                            "environment": manifest["environment"],
                            "manifest_payload_sha256": phase0_manifest_sha256,
                            "requirements_sha256": manifest["requirements_sha256"],
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
                    "evidence_sha256": f"{index + 60:064x}",
                    "redaction_confirmed": True,
                }
                for index, (scenario, observation) in enumerate(
                    TARGET_PHASE_SCENARIOS[identifier].items(), start=1
                )
            }
            return seal_target_phase_artifact(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier == "sub2_execution_evidence":
            if manifest is None:
                raise ValueError("Sub2 evidence requires the current manifest")
            document = json.loads(EVIDENCE_INDEX.read_text(encoding="utf-8"))
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"] in {"sub2_contract", "target_platform_inventory"}
            }
            document.update(
                {
                    "index_reference": "sub2-execution-index-record-42",
                    "synthetic": False,
                    "index_status": "reviewed",
                    "review_reference": "sub2-independent-review-record-42",
                    "reviewed_at": "2026-08-26T10:15:00Z",
                    "valid_until": "2099-08-26T10:15:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        "sub2_contract_sha256": hashes["sub2_contract"],
                        "target_platform_inventory_sha256": hashes[
                            "target_platform_inventory"
                        ],
                    },
                    "window": {
                        "started_at": "2026-08-26T09:00:00Z",
                        "finished_at": "2026-08-26T10:00:00Z",
                    },
                    "release_execution": {
                        "ledger_type": "forward",
                        "evidence_object_reference": "worm-release-execution:record-42a",
                        "evidence_sha256": next(
                            (
                                item["sha256"]
                                for item in manifest["items"]
                                if item["id"] == "release_execution_evidence"
                                and item["status"] == "provided"
                            ),
                            "f" * 64,
                        ),
                        "target_intake": {
                            "environment": manifest["environment"],
                            "manifest_payload_sha256": phase0_manifest_sha256,
                            "requirements_sha256": manifest["requirements_sha256"],
                            "checkpoint_phase": 0,
                        },
                    },
                }
            )
            document["scenarios"] = {
                scenario: {
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
                for index, (scenario, observation) in enumerate(
                    REQUIRED_SCENARIO_OBSERVATIONS.items(),
                    start=1,
                )
            }
            return seal_index(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier == "vault_egress_evidence":
            if manifest is None:
                raise ValueError("Vault/egress evidence requires the current manifest")
            document = json.loads(VAULT_EGRESS_INDEX.read_text(encoding="utf-8"))
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"] in {"sub2_contract", "target_platform_inventory"}
            }
            document.update(
                {
                    "index_reference": "vault-egress-index-record-42",
                    "synthetic": False,
                    "index_status": "reviewed",
                    "review_reference": "vault-egress-independent-review-42",
                    "reviewed_at": "2026-08-26T10:15:00Z",
                    "valid_until": "2099-08-26T10:15:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        "sub2_contract_sha256": hashes["sub2_contract"],
                        "target_platform_inventory_sha256": hashes[
                            "target_platform_inventory"
                        ],
                    },
                    "window": {
                        "started_at": "2026-08-26T09:00:00Z",
                        "finished_at": "2026-08-26T10:00:00Z",
                    },
                    "release_execution": {
                        "ledger_type": "forward",
                        "evidence_object_reference": "worm-release-execution:record-42a",
                        "evidence_sha256": next(
                            (
                                item["sha256"]
                                for item in manifest["items"]
                                if item["id"] == "release_execution_evidence"
                                and item["status"] == "provided"
                            ),
                            "f" * 64,
                        ),
                        "target_intake": {
                            "environment": manifest["environment"],
                            "manifest_payload_sha256": phase0_manifest_sha256,
                            "requirements_sha256": manifest["requirements_sha256"],
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
                    VAULT_EGRESS_SCENARIOS.items(), start=1
                )
            }
            return seal_vault_egress_index(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier == "phase6_pilot_inputs":
            if manifest is None:
                raise ValueError("Phase 6 pilot inputs require the current manifest")
            document = json.loads(PILOT_INPUT_INVENTORY.read_text(encoding="utf-8"))
            target_inventory_sha256 = next(
                item["sha256"]
                for item in manifest["items"]
                if item["id"] == "target_platform_inventory"
            )
            document.update(
                {
                    "inventory_reference": "pilot-input-inventory:record-42",
                    "synthetic": False,
                    "inventory_status": "reviewed",
                    "review_reference": "pilot-review-ref:record-42",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        "target_platform_inventory_sha256": target_inventory_sha256,
                    },
                    "ownership": {
                        "pilot_coordinator_reference": "pilot-owner-ref:coordinator-42",
                        "target_operator_owner_reference": "pilot-owner-ref:operations-42",
                        "alert_receiver_owner_reference": "pilot-owner-ref:alerting-42",
                        "maintenance_owner_reference": "pilot-owner-ref:maintenance-42",
                    },
                    "maintenance_window": {
                        "change_reference": "change-record:pilot-42",
                        "approval_reference": "change-approval:pilot-42",
                        "starts_at": "2026-08-27T01:00:00Z",
                        "rollback_decision_deadline": "2026-08-27T01:30:00Z",
                        "finishes_at": "2026-08-27T02:00:00Z",
                    },
                }
            )
            document["pilot_roles"] = {
                role: {
                    "participant_reference": f"pilot-subject-ref:subject-{index}a",
                    "roster_entry_reference": f"pilot-roster-entry:entry-{index}a",
                    "responsibility": responsibility,
                }
                for index, (role, responsibility) in enumerate(
                    PILOT_ROLE_RESPONSIBILITIES.items(), start=1
                )
            }
            return seal_pilot_input_inventory(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier == "phase6_pilot_evidence":
            if manifest is None:
                raise ValueError("Phase 6 pilot evidence requires the current manifest")
            document = json.loads(PILOT_EVIDENCE_INDEX.read_text(encoding="utf-8"))
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"]
                in {
                    "release_execution_evidence",
                    "phase6_pilot_inputs",
                    "sub2_execution_evidence",
                    "target_platform_inventory",
                }
            }
            document.update(
                {
                    "index_reference": "pilot-evidence-index:record-42",
                    "synthetic": False,
                    "index_status": "reviewed",
                    "review_reference": "pilot-evidence-review:record-42",
                    "reviewed_at": "2026-08-27T02:00:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        "phase6_pilot_inputs_sha256": hashes["phase6_pilot_inputs"],
                        "sub2_execution_evidence_sha256": hashes[
                            "sub2_execution_evidence"
                        ],
                        "target_platform_inventory_sha256": hashes[
                            "target_platform_inventory"
                        ],
                    },
                    "pilot_subjects": {
                        "operator": "pilot-subject-ref:subject-1a",
                        "security_auditor": "pilot-subject-ref:subject-3a",
                    },
                    "trace_set_reference": "pilot-trace-set:record-42",
                    "window": {
                        "started_at": "2026-08-27T01:05:00Z",
                        "finished_at": "2026-08-27T01:55:00Z",
                    },
                    "release_execution": {
                        "ledger_type": "forward",
                        "evidence_object_reference": "worm-release-execution:record-42a",
                        "evidence_sha256": hashes[
                            "release_execution_evidence"
                        ],
                        "target_intake": {
                            "environment": manifest["environment"],
                            "manifest_payload_sha256": phase0_manifest_sha256,
                            "requirements_sha256": manifest["requirements_sha256"],
                            "checkpoint_phase": 0,
                        },
                    },
                }
            )
            document["scenarios"] = {
                scenario: {
                    "execution_reference": f"pilot-execution:record-{index}a",
                    "actor_role": contract["actor_role"],
                    "reviewer_reference": "pilot-reviewer-ref:record-42",
                    "executed_at": f"2026-08-27T01:{index + 5:02d}:00Z",
                    "observation": contract["observation"],
                    "result": "passed",
                    "evidence_object_reference": f"worm-pilot-evidence:object-{index}a",
                    "evidence_sha256": f"{index:064x}",
                    "redaction_confirmed": True,
                }
                for index, (scenario, contract) in enumerate(
                    PILOT_EVIDENCE_SCENARIOS.items(), start=1
                )
            }
            return seal_pilot_evidence_index(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        elif identifier == "release_execution_evidence":
            if manifest is None:
                raise ValueError("release execution requires the current manifest")
            target_release = {
                "tag": "v1.2.3",
                "commit": "a" * 40,
                "migration_head": "0028_operational_policy_governance",
                "container_manifest_sha256": "b" * 64,
            }
            target_intake = {
                "environment": manifest["environment"],
                "manifest_payload_sha256": phase0_manifest_sha256,
                "requirements_sha256": manifest["requirements_sha256"],
                "checkpoint_phase": 0,
            }
            recorder = DeploymentReleaseEvidenceRecorder(
                target_release=target_release,
                rollback=DEPLOY_ROLLBACK,
                images=DEPLOY_IMAGES,
                target_intake=target_intake,
            )
            recorder.validate_initial()
            complete_deploy_success(recorder)
            return seal_deploy_recorder(recorder)
        elif identifier == "phase6_operations_evidence":
            if manifest is None:
                raise ValueError("Phase 6 operations evidence requires the current manifest")
            document = json.loads(
                OPERATIONS_EVIDENCE_INDEX.read_text(encoding="utf-8")
            )
            hashes = {
                item["id"]: item["sha256"]
                for item in manifest["items"]
                if item["id"]
                in {
                    "phase6_pilot_inputs",
                    "phase6_pilot_evidence",
                    "release_execution_evidence",
                    "target_platform_inventory",
                }
            }
            document.update(
                {
                    "index_reference": "operations-evidence-index:record-43",
                    "synthetic": False,
                    "index_status": "reviewed",
                    "review_reference": "operations-evidence-review:record-43",
                    "reviewed_at": "2026-08-27T04:15:00Z",
                    "environment": manifest["environment"],
                    "bindings": {
                        "release_tag": "v1.2.3",
                        "release_commit": "a" * 40,
                        "container_manifest_sha256": "b" * 64,
                        "phase6_pilot_inputs_sha256": hashes["phase6_pilot_inputs"],
                        "phase6_pilot_evidence_sha256": hashes[
                            "phase6_pilot_evidence"
                        ],
                        "target_platform_inventory_sha256": hashes[
                            "target_platform_inventory"
                        ],
                    },
                    "role_subjects": {
                        role: f"pilot-subject-ref:subject-{index}a"
                        for index, role in enumerate(
                            PILOT_ROLE_RESPONSIBILITIES, start=1
                        )
                    },
                    "pilot_trace_set_reference": "pilot-trace-set:record-42",
                    "window": {
                        "started_at": "2026-08-27T00:00:00Z",
                        "finished_at": "2026-08-27T04:00:00Z",
                    },
                    "release_execution": {
                        "ledger_type": "forward",
                        "evidence_object_reference": "worm-release-execution:record-42a",
                        "evidence_sha256": hashes[
                            "release_execution_evidence"
                        ],
                        "target_intake": {
                            "environment": manifest["environment"],
                            "manifest_payload_sha256": phase0_manifest_sha256,
                            "requirements_sha256": manifest["requirements_sha256"],
                            "checkpoint_phase": 0,
                        },
                    },
                }
            )
            document["artifact_digests"] = {
                name: f"{index + 20:064x}"
                for index, name in enumerate(OPERATIONS_ARTIFACT_DIGESTS)
            }
            document["scenarios"] = {
                scenario: {
                    "execution_reference": f"operations-execution:record-{index}a",
                    "actor_role": contract["actor_role"],
                    "reviewer_reference": "operations-reviewer-ref:record-43",
                    "executed_at": f"2026-08-27T02:{index:02d}:00Z",
                    "observation": contract["observation"],
                    "result": "passed",
                    "evidence_object_reference": (
                        f"worm-operations-evidence:object-{index}a"
                    ),
                    "evidence_sha256": f"{index + 40:064x}",
                    "redaction_confirmed": True,
                }
                for index, (scenario, contract) in enumerate(
                    OPERATIONS_SCENARIOS.items(), start=1
                )
            }
            return seal_operations_evidence_index(
                {key: value for key, value in document.items() if key != "integrity"}
            )
        else:
            return {"kind": identifier, "redacted": True}
        document["synthetic"] = False
        if "provider_reference" in document:
            document["provider_reference"] = f"{identifier}-provider-record-42"
            document["reviewed_at"] = "2026-08-26T12:00:00Z"
            document["source_provenance"] = {
                "provider_scope": {
                    "environment": "staging",
                    "provider_account_reference": f"{identifier}-account-scope-42",
                },
                "source_document_reference": f"{identifier}-source-document-42",
                "source_version_reference": f"{identifier}-source-version-42",
                "source_sha256": "a" * 64,
                "captured_at": "2026-08-26T10:00:00Z",
                "valid_until": "2099-08-26T10:00:00Z",
            }
        else:
            document["decision_reference"] = f"{identifier}-decision-record-42"
            document["decision_status"] = "approved"
        document["review_reference"] = "security-review-ticket-42"
        return document

    def test_registry_covers_every_phase_input_and_target_evidence(self) -> None:
        self.assertEqual(requirements_errors(self.requirements, self.matrix), [])
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/target_intake_preflight.py verify-requirements",
            quality_gate,
        )
        self.assertIn(
            "python scripts/target_phase_artifacts.py verify-repository",
            quality_gate,
        )

    def test_registry_fails_closed_when_any_new_phase_reference_is_removed(self) -> None:
        for phase in (1, 2, 3, 5):
            mutated = copy.deepcopy(self.requirements)
            candidates = [
                item
                for item in mutated["requirements"]
                if any(reference["phase"] == phase for reference in item["matrix_refs"])
            ]
            self.assertTrue(candidates, f"phase {phase} must have a typed requirement")
            candidates[0]["matrix_refs"] = [
                reference
                for reference in candidates[0]["matrix_refs"]
                if reference["phase"] != phase
            ]
            with self.subTest(phase=phase):
                self.assertIn(
                    "target intake requirements do not exactly cover phases 0 through 6",
                    requirements_errors(mutated, self.matrix),
                )

    def test_new_phase_templates_are_closed_pending_contracts(self) -> None:
        manifest = create_intake_manifest("staging", self.requirements)
        for item in manifest["items"]:
            if item["id"] in {
                "mail_contract",
                "card_pci_boundary",
                "oidc_deployment_identity",
                "target_platform_inventory",
                "windows_pilot_inputs",
            }:
                item.update({"status": "provided", "sha256": "a" * 64})
        for identifier, path in TARGET_PHASE_ARTIFACTS.items():
            template = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(identifier=identifier, state="synthetic"):
                self.assertEqual(
                    target_phase_artifact_errors(template, expected_type=identifier),
                    [],
                )
                self.assertTrue(template["synthetic"])
                self.assertFalse(template["production_acceptance"])

            reviewed = self._artifact_document(identifier, manifest)
            own_item = next(
                item for item in manifest["items"] if item["id"] == identifier
            )
            own_item.update(
                {
                    "status": "provided",
                    "sha256": own_item.get("sha256") or "a" * 64,
                    "reviewed_by": reviewed["review_reference"],
                    "reviewed_at": reviewed["reviewed_at"],
                }
            )
            with self.subTest(identifier=identifier, state="reviewed"):
                self.assertEqual(
                    target_phase_artifact_errors(reviewed, expected_type=identifier),
                    [],
                )
                self.assertEqual(
                    target_phase_binding_errors(
                        reviewed,
                        manifest,
                        expected_type=identifier,
                    ),
                    [],
                )
            mutated = copy.deepcopy(reviewed)
            if identifier == "windows_pilot_inputs":
                mutated["business_page"]["field_sequence"].append("card_reference")
            else:
                mutated["scenarios"].pop(next(iter(mutated["scenarios"])))
            mutated = seal_target_phase_artifact(
                {key: value for key, value in mutated.items() if key != "integrity"}
            )
            with self.subTest(identifier=identifier, state="mutated"):
                self.assertTrue(
                    target_phase_artifact_errors(mutated, expected_type=identifier)
                )

    def test_final_and_intermediate_checkpoints_require_new_phase_items(self) -> None:
        manifest = create_intake_manifest("staging", self.requirements)
        new_ids_by_phase = (
            (1, "phase1_platform_evidence"),
            (2, "phase2_mail_evidence"),
            (3, "phase3_card_evidence"),
            (5, "windows_pilot_inputs"),
            (5, "phase5_windows_evidence"),
        )
        final_errors = intake_errors(
            manifest,
            self.requirements,
            repository_root=Path("repository-root-that-does-not-exist"),
            require_complete=True,
        )
        for phase, identifier in new_ids_by_phase:
            with self.subTest(phase=phase, identifier=identifier, checkpoint="final"):
                self.assertIn(f"{identifier} is incomplete", final_errors)
        for phase in (1, 2, 3, 5):
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=Path("repository-root-that-does-not-exist"),
                require_complete=True,
                required_ids=frozenset(phase_requirement_ids(self.requirements, phase)),
            )
            expected = {
                identifier
                for declared_phase, identifier in new_ids_by_phase
                if declared_phase <= phase
            }
            observed = {
                identifier
                for identifier in expected
                if f"{identifier} is incomplete" in errors
            }
            with self.subTest(phase=phase, checkpoint="intermediate"):
                self.assertEqual(observed, expected)

    def test_registry_rejects_acceptance_schema_and_coverage_drift(self) -> None:
        mutations = []

        accepted = copy.deepcopy(self.requirements)
        accepted["production_acceptance"] = True
        mutations.append(accepted)

        unknown = copy.deepcopy(self.requirements)
        unknown["requirements"][0]["approved"] = True
        mutations.append(unknown)

        missing_requirement = copy.deepcopy(self.requirements)
        missing_requirement["requirements"].pop()
        mutations.append(missing_requirement)

        missing_reference = copy.deepcopy(self.requirements)
        missing_reference["requirements"][0]["matrix_refs"].pop()
        mutations.append(missing_reference)

        duplicate_reference = copy.deepcopy(self.requirements)
        duplicate_reference["requirements"][1]["matrix_refs"].append(
            copy.deepcopy(
                duplicate_reference["requirements"][0]["matrix_refs"][0]
            )
        )
        mutations.append(duplicate_reference)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(requirements_errors(document, self.matrix))

        accepted_matrix = copy.deepcopy(self.matrix)
        accepted_matrix["production_acceptance"] = True
        self.assertIn(
            "phase acceptance matrix is invalid",
            requirements_errors(self.requirements, accepted_matrix),
        )

    def test_new_manifest_is_closed_incomplete_and_never_accepted(self) -> None:
        manifest = create_intake_manifest("staging", self.requirements)

        self.assertFalse(manifest["production_acceptance"])
        self.assertEqual(
            manifest["requirements_sha256"],
            requirements_sha256(self.requirements),
        )
        self.assertTrue(all(item["status"] == "missing" for item in manifest["items"]))
        self.assertTrue(
            intake_errors(
                manifest,
                self.requirements,
                repository_root=Path("repository-root-that-does-not-exist"),
                require_complete=True,
            )
        )

        accepted = copy.deepcopy(manifest)
        accepted["production_acceptance"] = True
        self.assertIn(
            "intake manifest must not claim production acceptance",
            intake_errors(
                accepted,
                self.requirements,
                repository_root=Path("repository-root-that-does-not-exist"),
                require_complete=False,
            ),
        )

    def test_intake_captures_one_evaluation_time_when_not_supplied(self) -> None:
        manifest = create_intake_manifest("staging", self.requirements)
        evaluation_time = datetime(2026, 8, 28, tzinfo=timezone.utc)
        with mock.patch.object(
            target_intake, "_utc_now", return_value=evaluation_time
        ) as clock:
            self.assertEqual(
                intake_errors(
                    manifest,
                    self.requirements,
                    require_complete=False,
                ),
                [],
            )
        clock.assert_called_once_with()

    def test_phase_checkpoints_break_the_predeployment_evidence_cycle(self) -> None:
        checkpoints = {
            phase: phase_requirement_ids(self.requirements, phase)
            for phase in range(7)
        }
        phase0 = checkpoints[0]
        phase6 = checkpoints[6]
        self.assertEqual(
            phase0,
            (
                "sub2_contract",
                "mail_contract",
                "card_pci_boundary",
                "oidc_deployment_identity",
                "phase0_boundary_approval",
                "target_platform_inventory",
            ),
        )
        self.assertEqual(
            {phase: len(identifiers) for phase, identifiers in checkpoints.items()},
            {0: 6, 1: 8, 2: 9, 3: 10, 4: 12, 5: 14, 6: 17},
        )
        self.assertIn("release_execution_evidence", phase6)
        self.assertEqual(phase6, tuple(item["id"] for item in self.requirements["requirements"]))

        manifest = create_intake_manifest("staging", self.requirements)
        errors = intake_errors(
            manifest,
            self.requirements,
            repository_root=Path("repository-root-that-does-not-exist"),
            require_complete=True,
            required_ids=frozenset(phase0),
        )
        self.assertEqual(
            [error for error in errors if error.endswith(" is incomplete")],
            [f"{identifier} is incomplete" for identifier in phase0],
        )
        narrowed = intake_errors(
            manifest,
            self.requirements,
            repository_root=Path("repository-root-that-does-not-exist"),
            require_complete=True,
            required_ids=frozenset({"mail_contract"}),
        )
        self.assertIn("intake checkpoint requirement inventory is invalid", narrowed)

    def test_phase0_checkpoint_accepts_six_reviewed_items_before_phase4_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            artifacts = root / "external-artifacts"
            artifacts.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            phase0 = phase_requirement_ids(self.requirements, 0)

            for identifier in (
                "sub2_contract",
                "mail_contract",
                "card_pci_boundary",
                "oidc_deployment_identity",
                "target_platform_inventory",
                "phase0_boundary_approval",
            ):
                item = next(entry for entry in manifest["items"] if entry["id"] == identifier)
                document = self._artifact_document(identifier, manifest)
                artifact = artifacts / f"{identifier}.json"
                artifact.write_text(json.dumps(document), encoding="utf-8")
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": document.get(
                            "review_reference", "review-ticket-2026-42"
                        ),
                        "reviewed_at": document.get(
                            "reviewed_at", "2026-08-26T12:00:00Z"
                        ),
                        "redaction_confirmed": True,
                    }
                )

            self.assertEqual(
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    required_ids=frozenset(phase0),
                ),
                [],
            )
            manifest_path = root / "phase0-target-intake.json"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                main(
                    [
                        "preflight",
                        "--input",
                        str(manifest_path.resolve()),
                        "--through-phase",
                        "0",
                    ]
                ),
                0,
            )
            self.assertEqual(
                phase_checkpoint_errors(
                    manifest_path.resolve(),
                    environment="staging",
                    through_phase=0,
                ),
                [],
            )
            identity = load_phase_checkpoint(
                manifest_path.resolve(),
                environment="staging",
                through_phase=0,
            )
            self.assertEqual(identity.environment, "staging")
            self.assertEqual(identity.requirements_sha256, manifest["requirements_sha256"])
            self.assertEqual(identity.checkpoint_phase, 0)
            self.assertRegex(identity.manifest_payload_sha256, r"^[0-9a-f]{64}$")
            self.assertNotIn(str(manifest_path), json.dumps(identity.as_evidence()))
            self.assertIn(
                "intake manifest environment does not match the target environment",
                phase_checkpoint_errors(
                    manifest_path.resolve(),
                    environment="production",
                    through_phase=0,
                ),
            )
            stale = copy.deepcopy(manifest)
            stale["requirements_sha256"] = "0" * 64
            manifest_path.write_text(
                json.dumps(stale, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.assertIn(
                "intake manifest is not bound to the current requirements",
                phase_checkpoint_errors(
                    manifest_path.resolve(),
                    environment="staging",
                    through_phase=0,
                ),
            )
            self.assertTrue(
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                )
            )

        extra = copy.deepcopy(manifest)
        extra["approved"] = True
        self.assertIn(
            "intake manifest top-level schema is invalid",
            intake_errors(
                extra,
                self.requirements,
                repository_root=Path("repository-root-that-does-not-exist"),
                require_complete=False,
            ),
        )

    def test_sub2_runtime_alignment_is_deferred_at_phase0_and_required_at_phase4(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            artifact = root / "sub2-contract.json"
            manifest = create_intake_manifest("staging", self.requirements)
            document = self._artifact_document("sub2_contract", manifest)
            artifact.write_text(json.dumps(document), encoding="utf-8")
            item = next(
                entry for entry in manifest["items"] if entry["id"] == "sub2_contract"
            )
            item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )
            with mock.patch.object(
                target_intake,
                "runtime_conformance_errors",
                return_value=["reviewed runtime gap"],
            ):
                phase0_errors = intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    required_ids=frozenset(
                        phase_requirement_ids(self.requirements, 0)
                    ),
                )
                phase4_errors = intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    required_ids=frozenset(
                        phase_requirement_ids(self.requirements, 4)
                    ),
                )

            runtime_error = (
                "sub2_contract runtime is not conformant with the reviewed "
                "provider contract"
            )
            self.assertNotIn(runtime_error, phase0_errors)
            self.assertIn(runtime_error, phase4_errors)

    def test_complete_reviewed_external_artifacts_pass_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            artifacts = root / "external-artifacts"
            artifacts.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            def provide(item: dict[str, object], phase0_digest: str = "8" * 64) -> None:
                artifact = artifacts / f"{item['id']}.json"
                document = self._artifact_document(
                    item["id"],
                    manifest,
                    phase0_manifest_sha256=phase0_digest,
                )
                artifact.write_text(
                    json.dumps(document),
                    encoding="utf-8",
                )
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": document.get(
                            "review_reference", "security-review-ticket-42"
                        ),
                        "reviewed_at": document.get(
                            "reviewed_at", "2026-08-26T12:00:00Z"
                        ),
                        "redaction_confirmed": True,
                    }
                )

            phase0_ids = frozenset(phase_requirement_ids(self.requirements, 0))
            for item in manifest["items"]:
                if item["id"] in phase0_ids:
                    provide(item)
            checkpoint_manifest = copy.deepcopy(manifest)
            checkpoint_path = root / "phase0-checkpoint.json"
            checkpoint_path.write_text(
                json.dumps(checkpoint_manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            phase0_digest = requirements_sha256(checkpoint_manifest)
            release_item = next(
                item for item in manifest["items"]
                if item["id"] == "release_execution_evidence"
            )
            provide(release_item, phase0_digest)
            for item in manifest["items"]:
                if item["id"] not in phase0_ids and item is not release_item:
                    provide(item, phase0_digest)

            self.assertEqual(
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    phase0_checkpoint_manifest=checkpoint_path.resolve(),
                ),
                [],
            )
            for identifier in (
                "phase1_platform_evidence",
                "phase2_mail_evidence",
                "phase3_card_evidence",
                "windows_pilot_inputs",
                "phase5_windows_evidence",
            ):
                missing_one = copy.deepcopy(manifest)
                missing_item = next(
                    item for item in missing_one["items"] if item["id"] == identifier
                )
                missing_item.update(
                    {
                        "status": "missing",
                        "artifact_path": None,
                        "sha256": None,
                        "reviewed_by": None,
                        "reviewed_at": None,
                        "redaction_confirmed": None,
                    }
                )
                with self.subTest(identifier=identifier, checkpoint="phase6-final"):
                    self.assertIn(
                        f"{identifier} is incomplete",
                        intake_errors(
                            missing_one,
                            self.requirements,
                            repository_root=repository,
                            require_complete=True,
                            phase0_checkpoint_manifest=checkpoint_path.resolve(),
                        ),
                    )
            changed = copy.deepcopy(manifest)
            changed_sub2 = next(
                item for item in changed["items"] if item["id"] == "sub2_contract"
            )
            changed_sub2_path = artifacts / "sub2-contract-reapproved.json"
            changed_sub2_document = self._artifact_document("sub2_contract", changed)
            changed_sub2_document["provider_reference"] = (
                "sub2-contract-provider-record-43"
            )
            changed_sub2_path.write_text(
                json.dumps(changed_sub2_document), encoding="utf-8"
            )
            changed_sub2.update(
                {
                    "artifact_path": str(changed_sub2_path.resolve()),
                    "sha256": hashlib.sha256(
                        changed_sub2_path.read_bytes()
                    ).hexdigest(),
                    "reviewed_by": "security-review-ticket-43",
                    "reviewed_at": "2026-08-27T12:00:00Z",
                }
            )
            changed_approval = next(
                item
                for item in changed["items"]
                if item["id"] == "phase0_boundary_approval"
            )
            changed_approval_path = artifacts / "phase0-approval-reapproved.json"
            changed_approval_path.write_text(
                json.dumps(
                    self._artifact_document("phase0_boundary_approval", changed)
                ),
                encoding="utf-8",
            )
            changed_approval.update(
                {
                    "artifact_path": str(changed_approval_path.resolve()),
                    "sha256": hashlib.sha256(
                        changed_approval_path.read_bytes()
                    ).hexdigest(),
                    "reviewed_by": "security-review-ticket-43",
                    "reviewed_at": "2026-08-27T12:00:00Z",
                }
            )
            self.assertIn(
                "current Phase 0 intake items do not match the release checkpoint snapshot",
                intake_errors(
                    changed,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    phase0_checkpoint_manifest=checkpoint_path.resolve(),
                ),
            )
            changed_checkpoint = copy.deepcopy(checkpoint_manifest)
            changed_checkpoint_sub2 = next(
                item
                for item in changed_checkpoint["items"]
                if item["id"] == "card_pci_boundary"
            )
            changed_checkpoint_sub2["reviewed_at"] = "2026-08-27T12:00:00Z"
            matching_current = copy.deepcopy(manifest)
            next(
                item
                for item in matching_current["items"]
                if item["id"] == "card_pci_boundary"
            )["reviewed_at"] = "2026-08-27T12:00:00Z"
            changed_checkpoint_path = root / "changed-phase0-checkpoint.json"
            changed_checkpoint_path.write_text(
                json.dumps(changed_checkpoint, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.assertIn(
                "release execution intake does not match the Phase 0 checkpoint snapshot",
                intake_errors(
                    matching_current,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    phase0_checkpoint_manifest=changed_checkpoint_path.resolve(),
                ),
            )
            sub2_item = next(
                item for item in manifest["items"]
                if item["id"] == "sub2_execution_evidence"
            )
            sub2_path = Path(sub2_item["artifact_path"])
            original_sub2_bytes = sub2_path.read_bytes()
            old_release = json.loads(original_sub2_bytes)
            old_release["bindings"]["release_tag"] = "v9.9.9"
            old_release = seal_index(
                {
                    key: value
                    for key, value in old_release.items()
                    if key != "integrity"
                }
            )
            sub2_path.write_text(json.dumps(old_release), encoding="utf-8")
            sub2_item["sha256"] = hashlib.sha256(sub2_path.read_bytes()).hexdigest()
            replay_errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=True,
                phase0_checkpoint_manifest=checkpoint_path.resolve(),
            )
            self.assertIn(
                "release execution target release does not match its index",
                replay_errors,
            )
            self.assertIn(
                "Phase 6 pilot evidence sub2_execution_evidence binding does not match this intake manifest",
                replay_errors,
            )
            for identifier, reseal in (
                ("phase1_platform_evidence", seal_target_phase_artifact),
                ("vault_egress_evidence", seal_vault_egress_index),
            ):
                item = next(
                    entry for entry in manifest["items"] if entry["id"] == identifier
                )
                path = Path(item["artifact_path"])
                original = path.read_bytes()
                changed = json.loads(original)
                changed["release_execution"]["evidence_sha256"] = "f" * 64
                changed = reseal(
                    {key: value for key, value in changed.items() if key != "integrity"}
                )
                path.write_text(json.dumps(changed), encoding="utf-8")
                item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.subTest(identifier=identifier):
                    self.assertIn(
                        "release execution whole-file digest does not match its selector",
                        intake_errors(
                            manifest,
                            self.requirements,
                            repository_root=repository,
                            require_complete=True,
                            phase0_checkpoint_manifest=checkpoint_path.resolve(),
                        ),
                    )
                path.write_bytes(original)
                item["sha256"] = hashlib.sha256(original).hexdigest()
            sub2_path.write_bytes(original_sub2_bytes)
            sub2_item["sha256"] = hashlib.sha256(original_sub2_bytes).hexdigest()
            sub2_item["reviewed_by"] = "sub2-independent-review-record-99"
            self.assertIn(
                "Sub2 evidence review metadata does not match this intake manifest",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    phase0_checkpoint_manifest=checkpoint_path.resolve(),
                ),
            )
            sub2_item["reviewed_by"] = "sub2-independent-review-record-42"
            release_item = next(
                item
                for item in manifest["items"]
                if item["id"] == "release_execution_evidence"
            )
            release_path = Path(release_item["artifact_path"])
            release_path.write_text('{"schema_version": 2}', encoding="utf-8")
            release_item["sha256"] = hashlib.sha256(
                release_path.read_bytes()
            ).hexdigest()
            self.assertIn(
                "release_execution_evidence ledger is invalid",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=True,
                    phase0_checkpoint_manifest=checkpoint_path.resolve(),
                ),
            )

    def test_preflight_rejects_repository_artifact_hash_drift_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            artifact = repository / "sample.json"
            artifact.write_text('{"redacted": true}', encoding="utf-8")
            manifest = create_intake_manifest("example", self.requirements)
            first = manifest["items"][0]
            first.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": "0" * 64,
                    "reviewed_by": "TBD",
                    "reviewed_at": "2026-08-26T12:00:00+08:00",
                    "redaction_confirmed": False,
                }
            )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )

            self.assertIn("intake environment is invalid or a placeholder", errors)
            self.assertIn(
                f"{first['id']} artifact must be outside the repository", errors
            )
            self.assertIn(f"{first['id']} artifact sha256 does not match", errors)
            self.assertIn(f"{first['id']} reviewer reference is invalid", errors)
            self.assertIn(
                f"{first['id']} reviewed_at must be canonical UTC", errors
            )
            self.assertIn(
                f"{first['id']} redaction must be explicitly confirmed", errors
            )

    def test_preflight_rejects_malformed_or_synthetic_provider_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            contracts = {
                "sub2_contract": {"kind": "sub2", "redacted": True},
                "mail_contract": json.loads(
                    MAIL_CONTRACT.read_text(encoding="utf-8")
                ),
            }
            for item in manifest["items"]:
                document = contracts.get(item["id"])
                if document is None:
                    continue
                artifact = root / f"{item['id']}.json"
                artifact.write_text(json.dumps(document), encoding="utf-8")
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": "security-review-ticket-42",
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "redaction_confirmed": True,
                    }
                )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )

            self.assertIn("sub2_contract provider contract envelope is invalid", errors)
            self.assertIn(
                "mail_contract provider contract must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_binds_provider_scope_and_sealed_review_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            document = self._artifact_document("mail_contract", manifest)
            artifact = root / "mail-contract.json"
            artifact.write_text(json.dumps(document), encoding="utf-8")
            item = next(
                entry for entry in manifest["items"] if entry["id"] == "mail_contract"
            )
            item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "different-review-record-42",
                    "reviewed_at": document["reviewed_at"],
                    "redaction_confirmed": True,
                }
            )
            self.assertIn(
                "mail_contract review metadata does not match this intake manifest",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                ),
            )

            item["reviewed_by"] = document["review_reference"]
            document["source_provenance"]["provider_scope"]["environment"] = (
                "production"
            )
            artifact.write_text(json.dumps(document), encoding="utf-8")
            item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertIn(
                "mail_contract provider scope does not match this intake manifest",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                ),
            )

    def test_preflight_rejects_duplicate_keys_in_registered_json_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            document = self._artifact_document("mail_contract", manifest)
            encoded = json.dumps(document, ensure_ascii=False, indent=2)
            duplicate = encoded.replace(
                '  "synthetic": false,',
                '  "synthetic": false,\n  "synthetic": false,',
                1,
            )
            self.assertNotEqual(encoded, duplicate)
            artifact = root / "mail-contract-duplicate.json"
            artifact.write_text(duplicate + "\n", encoding="utf-8")
            item = next(
                entry for entry in manifest["items"] if entry["id"] == "mail_contract"
            )
            item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )

            self.assertIn(
                "mail_contract provider contract envelope is invalid",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                ),
            )

    def test_preflight_rejects_registered_artifact_shape_drift_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            artifact = root / "mail-contract-drifting.json"
            artifact.write_text(
                json.dumps(self._artifact_document("mail_contract", manifest)),
                encoding="utf-8",
            )
            item = next(
                entry for entry in manifest["items"] if entry["id"] == "mail_contract"
            )
            item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )
            real_fstat = external_json.os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                errors = intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                )
            self.assertEqual(calls, 2)
            self.assertIn("mail_contract artifact could not be read", errors)

    def test_preflight_rejects_registered_artifact_over_five_mib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            artifact = root / "mail-contract-oversized.json"
            artifact.write_bytes(b"{" + b" " * target_intake._MAX_ARTIFACT_BYTES)
            item = next(
                entry for entry in manifest["items"] if entry["id"] == "mail_contract"
            )
            item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": "0" * 64,
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )

            self.assertEqual(
                artifact.stat().st_size,
                target_intake._MAX_ARTIFACT_BYTES + 1,
            )
            self.assertIn(
                "mail_contract artifact size is invalid",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                ),
            )

    def test_preflight_rejects_malformed_or_synthetic_decision_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            decisions = {
                "card_pci_boundary": {"kind": "pci-decision", "approved": True},
                "oidc_deployment_identity": json.loads(
                    OIDC_IDENTITY_DECISION.read_text(encoding="utf-8")
                ),
            }
            for item in manifest["items"]:
                document = decisions.get(item["id"])
                if document is None:
                    continue
                artifact = root / f"{item['id']}.json"
                artifact.write_text(json.dumps(document), encoding="utf-8")
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": "security-review-ticket-42",
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "redaction_confirmed": True,
                    }
                )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )

            self.assertIn(
                "card_pci_boundary decision envelope is invalid", errors
            )
            self.assertIn(
                "oidc_deployment_identity decision envelope must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_rejects_invalid_synthetic_or_mismatched_phase0_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            for item in manifest["items"][:4]:
                artifact = root / f"{item['id']}.json"
                artifact.write_text(
                    json.dumps(self._artifact_document(item["id"], manifest)),
                    encoding="utf-8",
                )
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": "security-review-ticket-42",
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "redaction_confirmed": True,
                    }
                )

            approval_item = manifest["items"][4]
            approval = self._artifact_document(approval_item["id"], manifest)
            approval["bindings"]["mail_contract"] = "a" * 64
            artifact = root / "phase0-approval.json"
            artifact.write_text(json.dumps(approval), encoding="utf-8")
            approval_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "phase0 approval mail_contract binding does not match this intake manifest",
                errors,
            )

            synthetic = json.loads(APPROVAL.read_text(encoding="utf-8"))
            artifact.write_text(json.dumps(synthetic), encoding="utf-8")
            approval_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "phase0_boundary_approval must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_rejects_invalid_synthetic_or_wrong_environment_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)
            inventory_item = manifest["items"][5]
            inventory = self._artifact_document(inventory_item["id"], manifest)
            inventory["environment"] = "production"
            artifact = root / "target-platform-inventory.json"
            artifact.write_text(json.dumps(inventory), encoding="utf-8")
            inventory_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "target_platform_inventory environment does not match this intake manifest",
                errors,
            )

            synthetic = json.loads(INVENTORY.read_text(encoding="utf-8"))
            artifact.write_text(json.dumps(synthetic), encoding="utf-8")
            inventory_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "target_platform_inventory must be reviewed non-synthetic material",
                errors,
            )

            artifact.write_text('{"kind":"inventory"}', encoding="utf-8")
            inventory_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn("target_platform_inventory envelope is invalid", errors)

    def test_preflight_rejects_invalid_synthetic_or_mismatched_sub2_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            for item in (manifest["items"][0], manifest["items"][5]):
                artifact = root / f"{item['id']}.json"
                artifact.write_text(
                    json.dumps(self._artifact_document(item["id"], manifest)),
                    encoding="utf-8",
                )
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": "security-review-ticket-42",
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "redaction_confirmed": True,
                    }
                )

            evidence_item = manifest["items"][9]
            evidence = self._artifact_document(evidence_item["id"], manifest)
            evidence["bindings"]["sub2_contract_sha256"] = "f" * 64
            evidence = seal_index(
                {key: value for key, value in evidence.items() if key != "integrity"}
            )
            artifact = root / "sub2-execution-evidence.json"
            artifact.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": evidence["review_reference"],
                    "reviewed_at": evidence["reviewed_at"],
                    "redaction_confirmed": True,
                }
            )

            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "Sub2 evidence sub2_contract binding does not match this intake manifest",
                errors,
            )

            synthetic = json.loads(EVIDENCE_INDEX.read_text(encoding="utf-8"))
            artifact.write_text(json.dumps(synthetic), encoding="utf-8")
            evidence_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "sub2_execution_evidence must be reviewed non-synthetic material",
                errors,
            )

            artifact.write_text('{"kind":"evidence"}', encoding="utf-8")
            evidence_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn("sub2_execution_evidence envelope is invalid", errors)

    def test_preflight_rejects_synthetic_or_mismatched_vault_egress_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            for item in (manifest["items"][0], manifest["items"][5]):
                artifact = root / f"{item['id']}.json"
                artifact.write_text(
                    json.dumps(self._artifact_document(item["id"], manifest)),
                    encoding="utf-8",
                )
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": "security-review-ticket-42",
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "redaction_confirmed": True,
                    }
                )

            evidence_item = manifest["items"][10]
            evidence = self._artifact_document(evidence_item["id"], manifest)
            evidence["bindings"]["target_platform_inventory_sha256"] = "f" * 64
            evidence = seal_vault_egress_index(
                {key: value for key, value in evidence.items() if key != "integrity"}
            )
            artifact = root / "vault-egress-evidence.json"
            artifact.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "Vault/egress evidence target_platform_inventory binding does not match this intake manifest",
                errors,
            )

            synthetic = json.loads(VAULT_EGRESS_INDEX.read_text(encoding="utf-8"))
            artifact.write_text(json.dumps(synthetic), encoding="utf-8")
            evidence_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "vault_egress_evidence must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_rejects_synthetic_or_mismatched_phase6_pilot_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            inventory_item = manifest["items"][5]
            target_inventory = root / "target-platform-inventory.json"
            target_inventory.write_text(
                json.dumps(self._artifact_document(inventory_item["id"], manifest)),
                encoding="utf-8",
            )
            inventory_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(target_inventory.resolve()),
                    "sha256": hashlib.sha256(target_inventory.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )

            pilot_item = manifest["items"][14]
            pilot_inputs = self._artifact_document(pilot_item["id"], manifest)
            pilot_inputs["bindings"]["target_platform_inventory_sha256"] = "f" * 64
            pilot_inputs = seal_pilot_input_inventory(
                {key: value for key, value in pilot_inputs.items() if key != "integrity"}
            )
            artifact = root / "phase6-pilot-inputs.json"
            artifact.write_text(json.dumps(pilot_inputs), encoding="utf-8")
            pilot_item.update(
                {
                    "status": "provided",
                    "artifact_path": str(artifact.resolve()),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "reviewed_by": "security-review-ticket-42",
                    "reviewed_at": "2026-08-26T12:00:00Z",
                    "redaction_confirmed": True,
                }
            )
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "Phase 6 pilot inputs target_platform_inventory binding does not match this intake manifest",
                errors,
            )

            synthetic = json.loads(PILOT_INPUT_INVENTORY.read_text(encoding="utf-8"))
            artifact.write_text(json.dumps(synthetic), encoding="utf-8")
            pilot_item["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "phase6_pilot_inputs must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_binds_phase6_pilot_evidence_to_roster_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            def provide(index: int) -> tuple[dict[str, object], Path]:
                item = manifest["items"][index]
                document = self._artifact_document(item["id"], manifest)
                artifact = root / f"{item['id']}.json"
                artifact.write_text(json.dumps(document), encoding="utf-8")
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": document.get(
                            "review_reference", "security-review-ticket-42"
                        ),
                        "reviewed_at": document.get(
                            "reviewed_at", "2026-08-26T12:00:00Z"
                        ),
                        "redaction_confirmed": True,
                    }
                )
                return document, artifact

            provide(5)
            provide(13)
            provide(9)
            provide(14)
            evidence, evidence_path = provide(15)
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertFalse(any("pilot evidence" in error.casefold() for error in errors))

            evidence["release_execution"]["evidence_sha256"] = "f" * 64
            evidence = seal_pilot_evidence_index(
                {key: value for key, value in evidence.items() if key != "integrity"}
            )
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            manifest["items"][15]["sha256"] = hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest()
            self.assertIn(
                "release execution whole-file digest does not match its selector",
                intake_errors(
                    manifest,
                    self.requirements,
                    repository_root=repository,
                    require_complete=False,
                ),
            )

            evidence = self._artifact_document("phase6_pilot_evidence", manifest)

            evidence["pilot_subjects"]["operator"] = "pilot-subject-ref:replacement-9a"
            evidence = seal_pilot_evidence_index(
                {key: value for key, value in evidence.items() if key != "integrity"}
            )
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            manifest["items"][15]["sha256"] = hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "Phase 6 pilot evidence subjects do not match the reviewed pilot inputs",
                errors,
            )

            synthetic = json.loads(PILOT_EVIDENCE_INDEX.read_text(encoding="utf-8"))
            evidence_path.write_text(json.dumps(synthetic), encoding="utf-8")
            manifest["items"][15]["sha256"] = hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "phase6_pilot_evidence must be reviewed non-synthetic material",
                errors,
            )

    def test_preflight_binds_phase6_operations_to_pilot_chain_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            manifest = create_intake_manifest("staging", self.requirements)

            def provide(index: int) -> tuple[dict[str, object], Path]:
                item = manifest["items"][index]
                document = self._artifact_document(item["id"], manifest)
                artifact = root / f"{item['id']}.json"
                artifact.write_text(json.dumps(document), encoding="utf-8")
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": document.get(
                            "review_reference", "security-review-ticket-43"
                        ),
                        "reviewed_at": document.get(
                            "reviewed_at", "2026-08-26T13:00:00Z"
                        ),
                        "redaction_confirmed": True,
                    }
                )
                return document, artifact

            provide(5)
            provide(13)
            provide(9)
            provide(14)
            provide(15)
            operations, operations_path = provide(16)
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertFalse(
                any("operations evidence" in error.casefold() for error in errors)
            )

            operations["pilot_trace_set_reference"] = (
                "pilot-trace-set:replacement-9a"
            )
            operations = seal_operations_evidence_index(
                {key: value for key, value in operations.items() if key != "integrity"}
            )
            operations_path.write_text(json.dumps(operations), encoding="utf-8")
            manifest["items"][16]["sha256"] = hashlib.sha256(
                operations_path.read_bytes()
            ).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "Phase 6 operations evidence trace set does not match the reviewed pilot evidence",
                errors,
            )

            synthetic = json.loads(
                OPERATIONS_EVIDENCE_INDEX.read_text(encoding="utf-8")
            )
            operations_path.write_text(json.dumps(synthetic), encoding="utf-8")
            manifest["items"][16]["sha256"] = hashlib.sha256(
                operations_path.read_bytes()
            ).hexdigest()
            errors = intake_errors(
                manifest,
                self.requirements,
                repository_root=repository,
                require_complete=False,
            )
            self.assertIn(
                "phase6_operations_evidence must be reviewed non-synthetic material",
                errors,
            )

    def test_cli_initializes_write_once_external_manifest_and_preflights_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "target-intake.json"
            self.assertEqual(
                main(
                    [
                        "init",
                        "--output",
                        str(manifest_path),
                        "--environment",
                        "staging",
                    ]
                ),
                0,
            )
            original = manifest_path.read_bytes()
            self.assertEqual(
                main(
                    [
                        "init",
                        "--output",
                        str(manifest_path),
                        "--environment",
                        "staging",
                    ]
                ),
                1,
            )
            self.assertEqual(manifest_path.read_bytes(), original)

            manifest = json.loads(original)

            def provide(item: dict[str, object], phase0_digest: str = "8" * 64) -> None:
                artifact = root / f"{item['id']}.md"
                document = self._artifact_document(
                    item["id"],
                    manifest,
                    phase0_manifest_sha256=phase0_digest,
                )
                artifact.write_text(
                    json.dumps(document),
                    encoding="utf-8",
                )
                item.update(
                    {
                        "status": "provided",
                        "artifact_path": str(artifact.resolve()),
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewed_by": document.get(
                            "review_reference", "review-ticket-2026-42"
                        ),
                        "reviewed_at": document.get(
                            "reviewed_at", "2026-08-26T12:00:00Z"
                        ),
                        "redaction_confirmed": True,
                    }
                )

            phase0_ids = frozenset(phase_requirement_ids(self.requirements, 0))
            for item in manifest["items"]:
                if item["id"] in phase0_ids:
                    provide(item)
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            checkpoint_path = root / "phase0-checkpoint.json"
            self.assertEqual(
                main(
                    [
                        "snapshot",
                        "--input",
                        str(manifest_path),
                        "--output",
                        str(checkpoint_path),
                        "--environment",
                        "staging",
                    ]
                ),
                0,
            )
            checkpoint_bytes = checkpoint_path.read_bytes()
            self.assertEqual(
                main(
                    [
                        "snapshot",
                        "--input",
                        str(manifest_path),
                        "--output",
                        str(checkpoint_path),
                        "--environment",
                        "staging",
                    ]
                ),
                1,
            )
            self.assertEqual(checkpoint_path.read_bytes(), checkpoint_bytes)
            phase0_digest = requirements_sha256(json.loads(checkpoint_bytes))
            release_item = next(
                item for item in manifest["items"]
                if item["id"] == "release_execution_evidence"
            )
            provide(release_item, phase0_digest)
            for item in manifest["items"]:
                if item["id"] not in phase0_ids and item is not release_item:
                    provide(item, phase0_digest)
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                main(["preflight", "--input", str(manifest_path)]),
                1,
            )
            self.assertEqual(
                main(
                    [
                        "preflight",
                        "--input",
                        str(manifest_path),
                        "--phase0-checkpoint-manifest",
                        str(checkpoint_path),
                    ]
                ),
                0,
            )

    def test_cli_rejects_duplicate_manifest_keys_before_checkpoint_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "duplicate-target-intake.json"
            manifest = create_intake_manifest("staging", self.requirements)
            encoded = json.dumps(manifest, ensure_ascii=False, indent=2)
            duplicate = encoded.replace(
                '  "environment": "staging",',
                '  "environment": "staging",\n  "environment": "staging",',
                1,
            )
            self.assertNotEqual(encoded, duplicate)
            manifest_path.write_text(duplicate + "\n", encoding="utf-8")

            self.assertEqual(
                main(
                    [
                        "preflight",
                        "--input",
                        str(manifest_path.resolve()),
                        "--allow-incomplete",
                    ]
                ),
                1,
            )
            self.assertEqual(
                phase_checkpoint_errors(
                    manifest_path.resolve(),
                    environment="staging",
                    through_phase=0,
                ),
                ["target intake checkpoint material is invalid"],
            )
            checkpoint_path = Path(temporary) / "duplicate-checkpoint.json"
            self.assertEqual(
                main(
                    [
                        "snapshot",
                        "--input",
                        str(manifest_path.resolve()),
                        "--output",
                        str(checkpoint_path.resolve()),
                        "--environment",
                        "staging",
                    ]
                ),
                1,
            )
            self.assertFalse(checkpoint_path.exists())

    def test_cli_rejects_oversized_manifest_even_when_json_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "oversized-target-intake.json"
            manifest = create_intake_manifest("staging", self.requirements)
            encoded = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            padding = b" " * (target_intake._MAX_MANIFEST_BYTES + 1 - len(encoded))
            manifest_path.write_bytes(encoded + padding)

            self.assertGreater(
                manifest_path.stat().st_size,
                target_intake._MAX_MANIFEST_BYTES,
            )
            self.assertEqual(
                main(
                    [
                        "preflight",
                        "--input",
                        str(manifest_path.resolve()),
                        "--allow-incomplete",
                    ]
                ),
                1,
            )

    def test_manifest_read_rejects_open_file_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "drifting-target-intake.json"
            manifest_path.write_text(
                json.dumps(
                    create_intake_manifest("staging", self.requirements),
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            real_fstat = external_json.os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                with self.assertRaises(target_intake._IntakeJsonError):
                    target_intake._load_json(manifest_path.resolve())
            self.assertEqual(calls, 2)

    def test_runbook_keeps_intake_external_and_non_accepting(self) -> None:
        runbook = Path("deploy/runbooks/target-intake-preflight.md")
        self.assertTrue(runbook.is_file())
        text = runbook.read_text(encoding="utf-8")
        for expected in (
            "target_intake_preflight.py init",
            "target_intake_preflight.py preflight",
            "target_intake_preflight.py snapshot",
            "repository-external",
            "production_acceptance=false",
            "never copy live credentials",
            "redaction_confirmed",
            "--through-phase 0",
            "--phase0-checkpoint-manifest",
            "limited to 64 KiB",
            "rejects duplicate JSON keys",
            "Every artifact uses the same bounded",
            "parses the returned bytes once",
            "Standalone `check` commands reuse",
            "Six generated evidence readers",
            "A replacement, expansion, shape",
            "every Phase 0–6 acceptance-matrix entry",
            "target_phase_artifacts.py check",
            "they are not target evidence",
            "--through-phase 1",
            "--through-phase 2",
            "--through-phase 3",
            "--through-phase 4",
            "--through-phase 5",
            "--through-phase 6",
            "all seventeen items",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
