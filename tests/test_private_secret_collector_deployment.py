from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.private_secret_collector_deployment import (
    API_VERSION,
    GITHUB_ENDPOINTS,
    GITHUB_PERMISSIONS,
    POLICY,
    ROLE_DOMAINS,
    CollectorDeploymentError,
    parse_policy,
    validate_policy,
    verify_acceptance_transaction,
    verify_readiness_preflight,
)


SHA = "1" * 64
SHA2 = "2" * 64
SHA3 = "3" * 64
SHA4 = "4" * 64
SHA5 = "5" * 64
SHA6 = "6" * 64
SHA7 = "7" * 64
SHA8 = "8" * 64
SHA9 = "9" * 64
COMMIT = "a" * 40
ATTEMPT_ID = "12345678-1234-4234-9234-123456789abc"
OPERATION_ID = "87654321-4321-4321-8321-cba987654321"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def raw_json(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"


def seal(value: dict[str, object]) -> dict[str, object]:
    result = deepcopy(value)
    result["integrity"] = {"payload_sha256": digest(result)}
    return result


def key_material() -> tuple[Ed25519PrivateKey, dict[str, str]]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = "ed25519-sha256:" + hashlib.sha256(public).hexdigest()
    return private, {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "public_key_b64url": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
    }


def signature(private: Ed25519PrivateKey, anchor: dict[str, str], role: str, payload: dict[str, object]) -> dict[str, str]:
    message = ROLE_DOMAINS[role].encode("ascii") + b"\0" + canonical(payload)
    return {
        "algorithm": "Ed25519",
        "key_id": anchor["key_id"],
        "value_b64url": base64.urlsafe_b64encode(private.sign(message)).rstrip(b"=").decode(),
    }


class CollectorDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private: dict[str, Ed25519PrivateKey] = {}
        anchors: dict[str, dict[str, str]] = {}
        for role, domain in ROLE_DOMAINS.items():
            private, anchor = key_material()
            self.private[role] = private
            anchors[role] = {**anchor, "signature_domain": domain}
        self.policy = seal({
            "schema_version": 1,
            "policy_kind": "private_secret_external_collector_deployment_policy",
            "synthetic": False,
            "policy_status": "reviewed",
            "policy_effect": "offline_assertion_authentication_only",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "executor_integration_enabled": False,
            "handoff_integration_enabled": False,
            "deployment": {
                "deployment_id": "collector-prod-001",
                "environment": "production",
                "account_fingerprint_sha256": SHA,
                "cluster_fingerprint_sha256": SHA2,
                "release_commit": COMMIT,
                "release_manifest_sha256": SHA3,
                "target_intake_sha256": SHA4,
            },
            "github": {
                "repository": "acme/email-platform",
                "repository_id": "12345",
                "repository_owner_id": "67890",
                "app_id": "24680",
                "client_id": "Iv1.collector-prod",
                "installation_id": "13579",
                "repository_selection": "selected",
                "jwt_algorithm": "RS256",
                "jwt_issuer": "Iv1.collector-prod",
                "jwt_audience": None,
                "jwt_max_ttl_seconds": 600,
                "jwt_issued_at_backdate_seconds": 60,
                "credential_type": "github_app_installation_token",
                "token_max_ttl_seconds": 3600,
                "token_repository_ids": ["12345"],
                "permissions": list(GITHUB_PERMISSIONS),
                "api_origin": "https://api.github.com",
                "api_version": API_VERSION,
                "endpoint_allowlist": list(GITHUB_ENDPOINTS),
                "redirect_mode": "manual_allowlisted_https_origin_only",
                "artifact_redirect_origins": ["https://artifacts.example.com"],
                "attestation_bundle_origins": ["https://bundles.example.com"],
                "authorization_on_redirect": "forbidden",
                "proxy_enabled": False,
                "netrc_enabled": False,
                "webhook_subscription_enabled": False,
            },
            "target": {
                "provider_kind": "aws_s3_object_lock",
                "provider_account_fingerprint_sha256": SHA5,
                "storage_identity_fingerprint_sha256": SHA6,
                "workload_issuer": "https://issuer.example.com",
                "workload_subject": "workload:collector-prod",
                "workload_audience": "sts.amazonaws.com",
                "workload_identity_fingerprint_sha256": SHA7,
                "credential_type": "federated_short_lived_workload_identity",
                "maximum_session_age_seconds": 900,
                "static_credentials": "forbidden",
                "long_lived_tokens": "forbidden",
                "retention_mode": "compliance",
                "minimum_retention_seconds": 86400,
            },
            "runner": {
                "oci_manifest_digest": "ghcr.io/acme/collector@sha256:" + SHA8,
                "collector_binary_sha256": SHA9,
                "entrypoint_contract_sha256": SHA,
                "source_commit": COMMIT,
                "immutable_image_required": True,
                "read_only_filesystem_required": True,
                "private_keys_absent_required": True,
                "default_deny_network_required": True,
            },
            "raw_sink": {
                "service_origin": "https://sink.example.com",
                "storage_identity_fingerprint_sha256": SHA2,
                "namespace_fingerprint_sha256": SHA3,
                "key_prefix": "private-secret/prod/",
                "conditional_create_required": True,
                "immutable_version_required": True,
                "overwrite_forbidden": True,
                "readback_required": True,
                "repository_local_sink_forbidden": True,
            },
            "trusted_time": {
                "authority_kind": "rfc3161_tsa",
                "authority_identity_fingerprint_sha256": SHA4,
                "trust_root_sha256": SHA5,
                "nonce_binding_required": True,
                "maximum_assertion_age_seconds": 300,
            },
            "latest_head": {
                "service_origin": "https://ledger.example.com",
                "service_identity_fingerprint_sha256": "0" * 64,
                "ledger_id": "production-ledger-001",
                "semantics": "provider_native_compare_and_swap_append_only_v1",
                "caller_prior_head_required": True,
                "sequence_precondition_required": True,
                "generation_precondition_required": True,
                "append_only_history_required": True,
                "stale_write_rejection_required": True,
                "automatic_retry_forbidden": True,
            },
            "upstream_bindings": {
                "t141_github_policy_sha256": "b" * 64,
                "t142_github_policy_sha256": "c" * 64,
                "t141_target_policy_sha256": "d" * 64,
                "t142_worm_policy_sha256": "e" * 64,
                "producer_workflow_sha256": "f" * 64,
                "github_collector_key_id": "ed25519-sha256:" + "1" * 64,
                "github_ledger_key_id": "ed25519-sha256:" + "2" * 64,
                "worm_provider_key_id": "ed25519-sha256:" + "3" * 64,
                "worm_ledger_key_id": "ed25519-sha256:" + "4" * 64,
            },
            "trust_anchors": anchors,
            "review": {
                "reviewer_reference": "security-review-143",
                "reviewed_at": "2026-08-27T08:00:00Z",
                "decision": "approved_for_offline_acceptance_transaction_authentication",
            },
        })
        self.policy_raw = raw_json(self.policy)
        self.policy_sha = hashlib.sha256(self.policy_raw).hexdigest()
        common = {
            "schema_version": 1,
            "synthetic": False,
            "production_acceptance": False,
            "not_committed_eligible": False,
            "attempt_id": ATTEMPT_ID,
            "deployment_id": "collector-prod-001",
            "policy_artifact_sha256": self.policy_sha,
            "request_artifact_sha256": SHA2,
            "environment": "production",
            "account_fingerprint_sha256": SHA,
            "cluster_fingerprint_sha256": SHA2,
            "release_commit": COMMIT,
            "release_manifest_sha256": SHA3,
            "target_intake_sha256": SHA4,
        }
        self.readiness_payload = {
            **common,
            "receipt_kind": "private_secret_external_collector_readiness",
            "readiness_status": "authenticated_external_signer_assertion",
            "observed_at": "2026-08-27T08:01:00Z",
            "runner_manifest_digest": "ghcr.io/acme/collector@sha256:" + SHA8,
            "collector_binary_sha256": SHA9,
            "entrypoint_contract_sha256": SHA,
            "workload_identity_fingerprint_sha256": SHA7,
            "previous_github_collection_head_sha256": SHA4,
            "current_worm_collection_head_sha256": SHA5,
            "collection_ledger_id": "github-rest-ledger-142",
            "collection_expected_sequence": 1,
            "collection_prior_head_sha256": SHA4,
            "assertions": {
                "profile_loaded": True,
                "release_bindings_loaded": True,
                "short_lived_identity_configured": True,
                "token_persistence_forbidden": True,
                "endpoint_allowlist_loaded": True,
                "redirect_auth_stripping_loaded": True,
                "raw_sink_create_only_loaded": True,
                "latest_head_cas_loaded": True,
                "no_execution_performed": True,
            },
        }
        self.readiness = self._readiness(self.readiness_payload)
        self.readiness_raw = raw_json(self.readiness)
        readiness_sha = hashlib.sha256(self.readiness_raw).hexdigest()
        self.execution_payload = {
            **common,
            "receipt_kind": "private_secret_external_collector_execution_receipt",
            "execution_status": "externally_asserted_completed",
            "readiness_receipt_sha256": readiness_sha,
            "operation_id": OPERATION_ID,
            "github_collection_head_sha256": SHA5,
            "worm_collection_head_sha256": SHA6,
            "ledger_id": "production-ledger-001",
            "expected_sequence": 42,
            "prior_head_sha256": SHA7,
            "prior_generation": "generation-0041",
            "github_execution": {
                "credential_type": "github_app_installation_token",
                "token_ttl_seconds": 900,
                "repository_ids": ["12345"],
                "permissions": list(GITHUB_PERMISSIONS),
                "endpoint_allowlist": list(GITHUB_ENDPOINTS),
                "authorization_redirected": False,
                "proxy_used": False,
                "netrc_used": False,
                "raw_response_set_sha256": SHA8,
                "collection_receipt_sha256": SHA9,
                "collection_ledger_id": "github-rest-ledger-142",
                "collection_sequence": 1,
            },
            "worm_execution": {
                "provider_kind": "aws_s3_object_lock",
                "workload_identity_fingerprint_sha256": SHA7,
                "storage_identity_fingerprint_sha256": SHA6,
                "retention_mode": "compliance",
                "configuration_snapshot_sha256": SHA9,
                "collection_receipt_sha256": SHA6,
                "collection_ledger_id": "worm-replay-ledger-142",
                "collection_sequence": 1,
            },
            "raw_sink_result": {
                "storage_identity_fingerprint_sha256": SHA2,
                "namespace_fingerprint_sha256": SHA3,
                "object_reference": "private-secret/prod/attempt-001",
                "immutable_version_reference": "version-001",
                "content_sha256": SHA4,
                "conditional_create": True,
                "overwrite_attempted": False,
                "commit_response_sha256": SHA5,
                "readback_sha256": SHA4,
            },
            "trusted_time_result": {
                "authority_identity_fingerprint_sha256": SHA4,
                "nonce_sha256": SHA6,
                "imprint_sha256": SHA7,
                "assertion_artifact_sha256": SHA8,
                "observed_at": "2026-08-27T08:02:00Z",
            },
            "latest_head_result": {
                "service_identity_fingerprint_sha256": "0" * 64,
                "operation_id": OPERATION_ID,
                "ledger_id": "production-ledger-001",
                "expected_sequence": 42,
                "prior_head_sha256": SHA7,
                "prior_generation": "generation-0041",
                "compare_token_sha256": SHA8,
                "new_head_sha256": SHA9,
                "new_sequence": 42,
                "new_generation": "generation-0042",
                "result": "updated",
                "automatic_retry": False,
                "request_sha256": SHA,
                "response_sha256": SHA2,
            },
            "claim_boundary": {
                "runtime_byte_execution": "unverified",
                "token_current_validity": "unverified",
                "token_revocation": "unverified",
                "permission_enforcement": "unverified",
                "egress_enforcement": "unverified",
                "provider_native": "unverified",
                "trusted_time": "unverified",
                "global_cas_linearizability": "unverified",
                "fork_protection": "unverified",
                "rollback_protection": "unverified",
                "sink_immutability": "unverified",
                "durability": "unverified",
                "reviewer_independence": "unverified",
            },
        }
        self.execution = self._execution(self.execution_payload)
        self.execution_raw = raw_json(self.execution)

    def _readiness(self, payload: dict[str, object]) -> dict[str, object]:
        anchor = self.policy["trust_anchors"]["readiness"]
        return seal({
            "payload": deepcopy(payload),
            "signature": signature(self.private["readiness"], anchor, "readiness", payload),
        })

    def _execution(self, payload: dict[str, object]) -> dict[str, object]:
        signatures = {
            role: signature(self.private[role], self.policy["trust_anchors"][role], role, payload)
            for role in ("github_execution", "worm_execution", "trusted_time", "latest_head")
        }
        return seal({"payload": deepcopy(payload), "signatures": signatures})

    def _verify(self, *, policy_raw: bytes | None = None, readiness_raw: bytes | None = None, execution_raw: bytes | None = None, **pins: object):
        policy_raw = policy_raw or self.policy_raw
        readiness_raw = readiness_raw or self.readiness_raw
        execution_raw = execution_raw or self.execution_raw
        values = {
            "expected_policy_sha256": self.policy_sha,
            "expected_readiness_sha256": hashlib.sha256(self.readiness_raw).hexdigest(),
            "expected_execution_sha256": hashlib.sha256(self.execution_raw).hexdigest(),
            "expected_request_sha256": SHA2,
            "expected_previous_github_collection_head_sha256": SHA4,
            "expected_current_worm_collection_head_sha256": SHA5,
            "expected_github_collection_head_sha256": SHA5,
            "expected_worm_collection_head_sha256": SHA6,
            "expected_collection_prior_head_sha256": SHA4,
            "expected_collection_ledger_id": "github-rest-ledger-142",
            "expected_collection_sequence": 1,
            "expected_prior_head_sha256": SHA7,
            "expected_ledger_id": "production-ledger-001",
            "expected_sequence": 42,
            "expected_prior_generation": "generation-0041",
        }
        values.update(pins)
        return verify_acceptance_transaction(policy_raw, readiness_raw, execution_raw, **values)

    def test_synthetic_policy_remains_unconfigured_and_disabled(self) -> None:
        policy = parse_policy(POLICY.read_bytes(), allow_synthetic=True)
        self.assertTrue(policy["synthetic"])
        self.assertEqual(policy["policy_status"], "unconfigured")
        self.assertFalse(policy["production_acceptance"])
        self.assertFalse(policy["executor_integration_enabled"])

    def test_configured_policy_and_transaction_authenticate_only_assertions(self) -> None:
        validate_policy(self.policy)
        result = self._verify()
        self.assertEqual(result.new_sequence, 42)
        self.assertEqual(result.new_generation, "generation-0042")
        self.assertEqual(UUID(result.attempt_id).version, 4)

    def test_readiness_preflight_is_pure_and_collection_domain_bound(self) -> None:
        readiness_raw = raw_json(self.readiness)
        verified = verify_readiness_preflight(
            self.policy_raw,
            readiness_raw,
            expected_policy_sha256=self.policy_sha,
            expected_readiness_sha256=hashlib.sha256(readiness_raw).hexdigest(),
            expected_request_sha256=SHA2,
            expected_previous_github_collection_head_sha256=SHA4,
            expected_current_worm_collection_head_sha256=SHA5,
            expected_collection_prior_head_sha256=SHA4,
            expected_collection_ledger_id="github-rest-ledger-142",
            expected_collection_sequence=1,
        )
        self.assertEqual(verified.attempt_id, ATTEMPT_ID)
        self.assertEqual(verified.collection_ledger_id, "github-rest-ledger-142")
        self.assertEqual(verified.request_sha256, SHA2)
        self.assertEqual(
            verified.upstream_github_collector_key_id,
            self.policy["upstream_bindings"]["github_collector_key_id"],
        )
        with self.assertRaises(CollectorDeploymentError):
            verify_readiness_preflight(
                self.policy_raw,
                readiness_raw,
                expected_policy_sha256=self.policy_sha,
                expected_readiness_sha256=hashlib.sha256(readiness_raw).hexdigest(),
                expected_request_sha256=SHA3,
                expected_previous_github_collection_head_sha256=SHA4,
                expected_current_worm_collection_head_sha256=SHA5,
                expected_collection_prior_head_sha256=SHA4,
                expected_collection_ledger_id="github-rest-ledger-142",
                expected_collection_sequence=1,
            )

    def test_policy_rejects_permission_identity_runtime_and_cas_expansion(self) -> None:
        mutations = (
            ("write permission", lambda p: p["github"].__setitem__("permissions", ["actions:write", "attestations:read"])),
            ("extra repository", lambda p: p["github"].__setitem__("token_repository_ids", ["12345", "99999"])),
            ("jwt audience", lambda p: p["github"].__setitem__("jwt_audience", "collector")),
            ("long jwt", lambda p: p["github"].__setitem__("jwt_max_ttl_seconds", 601)),
            ("mutable image", lambda p: p["runner"].__setitem__("oci_manifest_digest", "ghcr.io/acme/collector:latest")),
            ("static credential", lambda p: p["target"].__setitem__("static_credentials", "allowed")),
            ("automatic retry", lambda p: p["latest_head"].__setitem__("automatic_retry_forbidden", False)),
            ("shared sink and head", lambda p: p["latest_head"].__setitem__("service_identity_fingerprint_sha256", SHA2)),
            ("redirect auth", lambda p: p["github"].__setitem__("authorization_on_redirect", "allowed")),
            ("IP redirect origin", lambda p: p["github"].__setitem__("artifact_redirect_origins", ["https://127.0.0.1"])),
            ("local bundle origin", lambda p: p["github"].__setitem__("attestation_bundle_origins", ["https://bundles.internal"])),
            ("userinfo origin", lambda p: p["github"].__setitem__("artifact_redirect_origins", ["https://user@example.com"])),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                value = deepcopy(self.policy)
                value.pop("integrity")
                mutation(value)
                with self.assertRaises(CollectorDeploymentError):
                    validate_policy(seal(value))

    def test_policy_rejects_role_key_reuse(self) -> None:
        value = deepcopy(self.policy)
        value.pop("integrity")
        value["trust_anchors"]["latest_head"] = deepcopy(value["trust_anchors"]["readiness"])
        value["trust_anchors"]["latest_head"]["signature_domain"] = ROLE_DOMAINS["latest_head"]
        with self.assertRaises(CollectorDeploymentError):
            validate_policy(seal(value))

        value = deepcopy(self.policy)
        value.pop("integrity")
        value["upstream_bindings"]["worm_ledger_key_id"] = value["trust_anchors"]["readiness"]["key_id"]
        with self.assertRaises(CollectorDeploymentError):
            validate_policy(seal(value))

    def test_caller_pins_reject_whole_document_replacement_and_replay(self) -> None:
        readiness_payload = deepcopy(self.readiness_payload)
        readiness_payload["observed_at"] = "2026-08-27T08:00:59Z"
        replaced_raw = raw_json(self._readiness(readiness_payload))
        with self.assertRaises(CollectorDeploymentError):
            self._verify(readiness_raw=replaced_raw)
        for pin, value in (
            ("expected_request_sha256", SHA3),
            ("expected_previous_github_collection_head_sha256", SHA3),
            ("expected_current_worm_collection_head_sha256", SHA4),
            ("expected_github_collection_head_sha256", SHA4),
            ("expected_worm_collection_head_sha256", SHA5),
            ("expected_collection_prior_head_sha256", SHA3),
            ("expected_collection_ledger_id", "other-collection-ledger"),
            ("expected_collection_sequence", 2),
            ("expected_prior_head_sha256", SHA6),
            ("expected_ledger_id", "other-ledger"),
            ("expected_sequence", 41),
            ("expected_prior_generation", "generation-0040"),
        ):
            with self.subTest(pin=pin), self.assertRaises(CollectorDeploymentError):
                self._verify(**{pin: value})

    def test_execution_rejects_permission_redirect_sink_and_claim_overstatement(self) -> None:
        mutations = (
            ("token too long", lambda p: p["github_execution"].__setitem__("token_ttl_seconds", 3601)),
            ("redirect auth", lambda p: p["github_execution"].__setitem__("authorization_redirected", True)),
            ("proxy", lambda p: p["github_execution"].__setitem__("proxy_used", True)),
            ("sink overwrite", lambda p: p["raw_sink_result"].__setitem__("overwrite_attempted", True)),
            ("sink readback", lambda p: p["raw_sink_result"].__setitem__("readback_sha256", SHA5)),
            ("cas ABA", lambda p: p["latest_head_result"].__setitem__("new_generation", "generation-0041")),
            ("cas no head advance", lambda p: p["latest_head_result"].__setitem__("new_head_sha256", SHA7)),
            ("cas retry", lambda p: p["latest_head_result"].__setitem__("automatic_retry", True)),
            ("global CAS claim", lambda p: p["claim_boundary"].__setitem__("global_cas_linearizability", "verified")),
            ("production", lambda p: p.__setitem__("production_acceptance", True)),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                payload = deepcopy(self.execution_payload)
                mutation(payload)
                raw = raw_json(self._execution(payload))
                with self.assertRaises(CollectorDeploymentError):
                    self._verify(
                        execution_raw=raw,
                        expected_execution_sha256=hashlib.sha256(raw).hexdigest(),
                    )

    def test_receipts_reject_extra_fields_duplicate_keys_and_cross_role_signatures(self) -> None:
        payload = deepcopy(self.execution_payload)
        payload["extra"] = "forbidden"
        raw = raw_json(self._execution(payload))
        with self.assertRaises(CollectorDeploymentError):
            self._verify(execution_raw=raw, expected_execution_sha256=hashlib.sha256(raw).hexdigest())

        duplicate = self.execution_raw.replace(b'"payload": {', b'"payload": null, "payload": {', 1)
        with self.assertRaises(CollectorDeploymentError):
            self._verify(execution_raw=duplicate, expected_execution_sha256=hashlib.sha256(duplicate).hexdigest())

        envelope = deepcopy(self.execution)
        envelope.pop("integrity")
        envelope["signatures"]["latest_head"] = deepcopy(envelope["signatures"]["github_execution"])
        raw = raw_json(seal(envelope))
        with self.assertRaises(CollectorDeploymentError):
            self._verify(execution_raw=raw, expected_execution_sha256=hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
