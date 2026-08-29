from __future__ import annotations

import base64
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import private_secret_github_rest_collection as collection
from scripts import private_secret_github_attestation as github_attestation
from tests import test_private_secret_collector_deployment as deployment_fixture


REPOSITORY = "octo/email-platform"
REPOSITORY_ID = "14101"
OWNER_ID = "14102"
COMMIT = "c" * 40
SUBJECT_SHA256 = "a" * 64
SUBJECT_PAYLOAD_SHA256 = "b" * 64
ARCHIVE_BYTES = b"authenticated workflow artifact archive bytes\n"
BUNDLE_BYTES = b"authenticated attestation bundle bytes\n"
ARCHIVE_SHA256 = hashlib.sha256(ARCHIVE_BYTES).hexdigest()
BUNDLE_SHA256 = hashlib.sha256(BUNDLE_BYTES).hexdigest()
ATTEMPT_ID = "00000000-0000-4000-8000-000000000142"
REQUEST_ID = "00000000-0000-4000-8000-000000000143"
LEDGER_ID = "github-rest-ledger-142"
SOURCE_REF = "refs/heads/main"
WORKFLOW_PATH = ".github/workflows/ci.yml"
JOB_NAME = "postgres-migration-gate"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(payload: dict[str, object]) -> dict[str, object]:
    return {**payload, "integrity": {"payload_sha256": _digest(payload)}}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _anchor(private_key: Ed25519PrivateKey, domain: str) -> dict[str, str]:
    public = _public(private_key)
    return {
        "algorithm": "Ed25519",
        "key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(),
        "public_key_b64url": _b64url(public),
        "signature_domain": domain,
    }


def _sign(
    private_key: Ed25519PrivateKey,
    domain: str,
    payload: dict[str, object],
) -> dict[str, str]:
    public = _public(private_key)
    raw = private_key.sign(domain.encode("ascii") + b"\0" + _canonical(payload))
    return {
        "algorithm": "Ed25519",
        "key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(),
        "value_b64url": _b64url(raw),
    }


def _write(path: Path, value: object) -> bytes:
    raw = _canonical(value)
    path.write_bytes(raw)
    return raw


class GitHubRestCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.collector_key = Ed25519PrivateKey.generate()
        self.ledger_key = Ed25519PrivateKey.generate()
        self.policy_path = self.root / "policy.json"
        self.request_path = self.root / "request.json"
        self.previous_path = self.root / "previous-head.json"
        self.receipt_path = self.root / "receipt.json"
        self.github_origin_path = self.root / "github-origin.json"
        self.deployment_policy_path = self.root / "deployment-policy.json"
        self.readiness_path = self.root / "readiness.json"
        self.archive_path = self.root / "artifact.zip"
        self.bundle_path = self.root / "attestation.bundle"

        self.policy = self._policy()
        self.policy_raw = _write(self.policy_path, self.policy)
        self.policy_sha256 = hashlib.sha256(self.policy_raw).hexdigest()
        self.deployment_fixture = deployment_fixture.CollectorDeploymentTests(
            methodName="test_configured_policy_and_transaction_authenticate_only_assertions"
        )
        self.deployment_fixture.setUp()
        deployment_policy = copy.deepcopy(self.deployment_fixture.policy)
        deployment_policy["github"]["repository"] = REPOSITORY
        deployment_policy["github"]["repository_id"] = REPOSITORY_ID
        deployment_policy["github"]["repository_owner_id"] = OWNER_ID
        deployment_policy["github"]["token_repository_ids"] = [REPOSITORY_ID]
        deployment_policy["upstream_bindings"]["t142_github_policy_sha256"] = self.policy_sha256
        deployment_policy["upstream_bindings"]["t141_github_policy_sha256"] = "1" * 64
        deployment_policy["upstream_bindings"]["github_collector_key_id"] = self.policy["collector"]["key_id"]
        deployment_policy["upstream_bindings"]["github_ledger_key_id"] = self.policy["replay_ledger"]["key_id"]
        deployment_policy["review"]["reviewed_at"] = "2026-08-27T00:00:00Z"
        self.deployment_policy = deployment_fixture.seal(
            {key: value for key, value in deployment_policy.items() if key != "integrity"}
        )
        self.deployment_policy_raw = deployment_fixture.raw_json(self.deployment_policy)
        self.deployment_policy_path.write_bytes(self.deployment_policy_raw)
        self.deployment_policy_sha256 = hashlib.sha256(self.deployment_policy_raw).hexdigest()
        self.previous_head = self._head(self._genesis_checkpoint())
        self.previous_raw = _write(self.previous_path, self.previous_head)
        self.previous_sha256 = hashlib.sha256(self.previous_raw).hexdigest()
        self.github_origin = self._github_origin()
        self.github_origin_raw = _write(self.github_origin_path, self.github_origin)
        self.github_origin_sha256 = hashlib.sha256(self.github_origin_raw).hexdigest()
        self.request = self._request(sequence=1)
        self.request_raw = _write(self.request_path, self.request)
        self.request_sha256 = hashlib.sha256(self.request_raw).hexdigest()
        readiness_payload = copy.deepcopy(self.deployment_fixture.readiness_payload)
        readiness_payload.update({
            "attempt_id": ATTEMPT_ID,
            "policy_artifact_sha256": self.deployment_policy_sha256,
            "request_artifact_sha256": self.request_sha256,
            "previous_github_collection_head_sha256": self.previous_sha256,
            "current_worm_collection_head_sha256": "9" * 64,
            "collection_ledger_id": LEDGER_ID,
            "collection_expected_sequence": 1,
            "collection_prior_head_sha256": self.previous_sha256,
            "observed_at": "2026-08-27T00:01:30Z",
        })
        readiness_payload.update(self.deployment_policy["deployment"])
        readiness_payload["runner_manifest_digest"] = self.deployment_policy["runner"]["oci_manifest_digest"]
        readiness_payload["collector_binary_sha256"] = self.deployment_policy["runner"]["collector_binary_sha256"]
        readiness_payload["entrypoint_contract_sha256"] = self.deployment_policy["runner"]["entrypoint_contract_sha256"]
        readiness_payload["workload_identity_fingerprint_sha256"] = self.deployment_policy["target"]["workload_identity_fingerprint_sha256"]
        self.readiness = self.deployment_fixture._readiness(readiness_payload)
        self.readiness_raw = deployment_fixture.raw_json(self.readiness)
        self.readiness_path.write_bytes(self.readiness_raw)
        self.readiness_sha256 = hashlib.sha256(self.readiness_raw).hexdigest()
        self.archive_path.write_bytes(ARCHIVE_BYTES)
        self.bundle_path.write_bytes(BUNDLE_BYTES)
        self.receipt = self._receipt(sequence=1)
        self.receipt_raw = _write(self.receipt_path, self.receipt)
        self.receipt_sha256 = hashlib.sha256(self.receipt_raw).hexdigest()

    def tearDown(self) -> None:
        self.deployment_fixture.tearDown()
        self.temporary.cleanup()

    def _policy(self) -> dict[str, object]:
        payload = {
            "schema_version": 1,
            "policy_kind": collection.POLICY_KIND,
            "synthetic": False,
            "policy_status": "reviewed",
            "policy_effect": "offline_external_collection_authentication_only",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "repository": {
                "name": REPOSITORY,
                "repository_id": REPOSITORY_ID,
                "repository_owner_id": OWNER_ID,
                "visibility": "private",
            },
            "allowed_workflow_paths": [WORKFLOW_PATH],
            "allowed_job_names": [JOB_NAME],
            "source": {"event": "push", "source_ref": SOURCE_REF},
            "api": {
                "origin": collection.API_ORIGIN,
                "version": collection.API_VERSION,
                "endpoint_kinds": list(collection._ENDPOINT_KINDS),
                "max_pages": 4,
            },
            "collector": _anchor(self.collector_key, collection.COLLECTOR_DOMAIN),
            "replay_ledger": _anchor(self.ledger_key, collection.LEDGER_DOMAIN),
            "time_constraints": {
                "max_request_to_acquisition_seconds": 300,
                "max_acquisition_seconds": 300,
                "max_acquisition_to_signature_seconds": 60,
                "max_signature_to_record_seconds": 60,
            },
            "review": {
                "reviewer_reference": "github-rest-policy-review-142",
                "reviewed_at": "2026-08-27T00:00:00Z",
                "decision": "approved_for_external_collection_authentication",
            },
        }
        return _seal(payload)

    def _refresh_readiness(self, *, sequence: int) -> None:
        payload = copy.deepcopy(self.readiness["payload"])
        payload["request_artifact_sha256"] = self.request_sha256
        payload["previous_github_collection_head_sha256"] = self.previous_sha256
        payload["collection_prior_head_sha256"] = self.previous_sha256
        payload["collection_expected_sequence"] = sequence
        self.readiness = self.deployment_fixture._readiness(payload)
        self.readiness_raw = deployment_fixture.raw_json(self.readiness)
        self.readiness_path.write_bytes(self.readiness_raw)
        self.readiness_sha256 = hashlib.sha256(self.readiness_raw).hexdigest()

    def _request(self, *, sequence: int) -> dict[str, object]:
        payload = {
            "schema_version": 1,
            "request_kind": collection.REQUEST_KIND,
            "synthetic": False,
            "production_acceptance": False,
            "not_committed_eligible": False,
            "request_id": REQUEST_ID,
            "nonce_b64url": _b64url(bytes(range(32))),
            "requested_at": "2026-08-27T00:01:00Z",
            "expires_at": "2026-08-27T00:10:00Z",
            "trust_policy_sha256": self.policy_sha256,
            "collector_profile": {
                "policy_artifact_sha256": self.deployment_policy_sha256,
                "deployment_id": self.deployment_policy["deployment"]["deployment_id"],
                "environment": self.deployment_policy["deployment"]["environment"],
                "account_fingerprint_sha256": self.deployment_policy["deployment"]["account_fingerprint_sha256"],
                "cluster_fingerprint_sha256": self.deployment_policy["deployment"]["cluster_fingerprint_sha256"],
                "release_commit": self.deployment_policy["deployment"]["release_commit"],
                "release_manifest_sha256": self.deployment_policy["deployment"]["release_manifest_sha256"],
                "target_intake_sha256": self.deployment_policy["deployment"]["target_intake_sha256"],
                "runner_manifest_digest": self.deployment_policy["runner"]["oci_manifest_digest"],
                "collector_binary_sha256": self.deployment_policy["runner"]["collector_binary_sha256"],
                "entrypoint_contract_sha256": self.deployment_policy["runner"]["entrypoint_contract_sha256"],
                "workload_identity_fingerprint_sha256": self.deployment_policy["target"]["workload_identity_fingerprint_sha256"],
            },
            "github_origin": {"artifact_sha256": self.github_origin_sha256},
            "previous_head": {
                "ledger_id": LEDGER_ID,
                "expected_sequence": sequence,
                "artifact_sha256": self.previous_sha256,
            },
            "subject": {
                "artifact_sha256": SUBJECT_SHA256,
                "payload_sha256": SUBJECT_PAYLOAD_SHA256,
                "attempt_id": ATTEMPT_ID,
            },
            "repository": self.policy["repository"],
            "workflow": {
                "run_id": 142,
                "run_attempt": 2,
                "workflow_path": WORKFLOW_PATH,
                "source_commit": COMMIT,
                "source_ref": SOURCE_REF,
                "event": "push",
            },
            "job": {"name": JOB_NAME},
            "artifact": {
                "artifact_id": 14205,
                "name": "private-secret-crash-142",
                "subject_member_path": "private-secret-crash.json",
                "archive_sha256": ARCHIVE_SHA256,
            },
        }
        return _seal(payload)

    def _github_origin(self) -> dict[str, object]:
        payload = {
            "schema_version": 1,
            "evidence_kind": github_attestation.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "ready_for_verification",
            "origin_authentication": "pending_cryptographic_verification",
            "production_acceptance": False,
            "subject": {
                "artifact_sha256": SUBJECT_SHA256,
                "payload_sha256": SUBJECT_PAYLOAD_SHA256,
                "attempt_id": ATTEMPT_ID,
            },
            "bundle": {
                "artifact_sha256": BUNDLE_SHA256,
                "acquired_at": "2026-08-27T00:00:30Z",
                "api_version": collection.API_VERSION,
                "predicate_type": collection.PREDICATE_TYPE,
            },
            "trust_policy": {"artifact_sha256": "1" * 64},
            "verification": {
                "expected_commit": COMMIT,
                "expected_workflow_sha256": "2" * 64,
                "expected_runtime_policy_sha256": "3" * 64,
                "gh_executable_sha256": "4" * 64,
            },
            "review": {
                "reviewer_reference": "github-origin-review-record-142",
                "reviewed_at": "2026-08-27T00:00:45Z",
                "decision": "approved_for_offline_verification",
            },
            "prohibited_content": {
                field: False for field in github_attestation._PROHIBITED_FIELDS
            },
        }
        return _seal(payload)

    def _genesis_checkpoint(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "checkpoint_kind": collection.CHECKPOINT_KIND,
            "ledger_id": LEDGER_ID,
            "sequence": 0,
            "genesis": True,
            "collection_payload_sha256": None,
            "collector_signature_sha256": None,
            "request_artifact_sha256": None,
            "previous_head_artifact_sha256": None,
            "previous_checkpoint_payload_sha256": None,
            "recorded_at": "2026-08-27T00:00:30Z",
        }

    def _head(self, checkpoint: dict[str, object]) -> dict[str, object]:
        return {
            "checkpoint": checkpoint,
            "signature": _sign(
                self.ledger_key, collection.LEDGER_DOMAIN, checkpoint
            ),
        }

    def _payload(self) -> dict[str, object]:
        response_digests = {
            name: hashlib.sha256(name.encode("ascii")).hexdigest()
            for name in collection._ENDPOINT_KINDS
        }
        endpoints = {
            name: {
                "endpoint_kind": name,
                "pagination_complete": True,
                "raw_response_sha256s": [response_digests[name]],
            }
            for name in collection._ENDPOINT_KINDS
            if name not in {
                "get_workflow_artifact_redirect",
                "download_workflow_artifact",
                "download_attestation_bundle",
            }
        }
        archive_url_sha = hashlib.sha256(b"https://artifacts.example.com/archive/142").hexdigest()
        bundle_url_sha = hashlib.sha256(b"https://bundles.example.com/bundle/142").hexdigest()
        endpoints["get_workflow_artifact_redirect"] = {
            "endpoint_kind": "get_workflow_artifact_redirect",
            "request_method": "GET",
            "request_origin": collection.API_ORIGIN,
            "response_status": 302,
            "location_count": 1,
            "location_url_sha256": archive_url_sha,
            "location_origin": "https://artifacts.example.com",
            "redirect_mode": "manual",
            "followed_automatically": False,
            "authorization_sent_to_source": True,
            "authorization_forwarded": False,
            "cookie_forwarded": False,
            "proxy_authorization_forwarded": False,
            "raw_response_sha256s": [response_digests["get_workflow_artifact_redirect"]],
        }
        endpoints["download_workflow_artifact"] = {
            "endpoint_kind": "download_workflow_artifact",
            "request_method": "GET",
            "request_url_sha256": archive_url_sha,
            "request_origin": "https://artifacts.example.com",
            "authorization_sent": False,
            "cookie_sent": False,
            "proxy_authorization_sent": False,
            "response_status": 200,
            "further_redirect": False,
            "raw_body_sha256": ARCHIVE_SHA256,
            "raw_body_size": len(ARCHIVE_BYTES),
        }
        endpoints["download_attestation_bundle"] = {
            "endpoint_kind": "download_attestation_bundle",
            "request_method": "GET",
            "request_url_sha256": bundle_url_sha,
            "request_origin": "https://bundles.example.com",
            "authorization_sent": False,
            "cookie_sent": False,
            "proxy_authorization_sent": False,
            "response_status": 200,
            "further_redirect": False,
            "raw_body_sha256": BUNDLE_SHA256,
            "raw_body_size": len(BUNDLE_BYTES),
        }
        return {
            "request_binding": {
                "artifact_sha256": self.request_sha256,
                "payload_sha256": self.request["integrity"]["payload_sha256"],
                "github_origin_artifact_sha256": self.github_origin_sha256,
                "request_id": REQUEST_ID,
                "nonce_b64url": self.request["nonce_b64url"],
                "collector_readiness_artifact_sha256": self.readiness_sha256,
            },
            "trust_policy_sha256": self.policy_sha256,
            "acquisition": {
                "api_origin": collection.API_ORIGIN,
                "api_version": collection.API_VERSION,
                "started_at": "2026-08-27T00:02:00Z",
                "completed_at": "2026-08-27T00:03:00Z",
                "signed_at": "2026-08-27T00:03:30Z",
            },
            "endpoint_snapshots": endpoints,
            "projection": {
                "repository": self.policy["repository"],
                "workflow": {
                    "run_id": 142,
                    "run_attempt": 2,
                    "workflow_id": 14201,
                    "workflow_path": WORKFLOW_PATH,
                    "source_commit": COMMIT,
                    "source_ref": SOURCE_REF,
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "repository_id": REPOSITORY_ID,
                    "head_repository_id": REPOSITORY_ID,
                    "check_suite_id": 14202,
                },
                "job": {
                    "job_id": 14203,
                    "name": JOB_NAME,
                    "run_id": 142,
                    "head_sha": COMMIT,
                    "status": "completed",
                    "conclusion": "success",
                    "check_run_id": 14204,
                    "check_run_url": (
                        f"https://api.github.com/repos/{REPOSITORY}/check-runs/14204"
                    ),
                    "matching_job_count": 1,
                },
                "artifact": {
                    "artifact_id": 14205,
                    "name": "private-secret-crash-142",
                    "archive_digest_sha256": ARCHIVE_SHA256,
                    "subject_artifact_sha256": SUBJECT_SHA256,
                    "subject_payload_sha256": SUBJECT_PAYLOAD_SHA256,
                    "subject_member_path": "private-secret-crash.json",
                    "subject_binding_method": "bounded_archive_member_sha256",
                    "workflow_run_id": 142,
                    "repository_id": REPOSITORY_ID,
                    "head_repository_id": REPOSITORY_ID,
                    "head_sha": COMMIT,
                    "expired": False,
                    "matching_artifact_count": 1,
                },
                "attestation": {
                    "subject_digest": "sha256:" + SUBJECT_SHA256,
                    "repository_id": REPOSITORY_ID,
                    "bundle_artifact_sha256": BUNDLE_SHA256,
                    "bundle_url_sha256": bundle_url_sha,
                    "bundle_origin": "https://bundles.example.com",
                    "predicate_type": collection.PREDICATE_TYPE,
                    "matching_bundle_count": 1,
                },
            },
        }

    def _receipt(self, *, sequence: int) -> dict[str, object]:
        payload = self._payload()
        collector_signature = _sign(
            self.collector_key, collection.COLLECTOR_DOMAIN, payload
        )
        checkpoint = {
            "schema_version": 1,
            "checkpoint_kind": collection.CHECKPOINT_KIND,
            "ledger_id": LEDGER_ID,
            "sequence": sequence,
            "genesis": False,
            "collection_payload_sha256": _digest(payload),
            "collector_signature_sha256": _digest(collector_signature),
            "request_artifact_sha256": self.request_sha256,
            "previous_head_artifact_sha256": self.previous_sha256,
            "previous_checkpoint_payload_sha256": _digest(
                self.previous_head["checkpoint"]
            ),
            "recorded_at": "2026-08-27T00:04:00Z",
        }
        return {
            "schema_version": 1,
            "evidence_kind": collection.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "ready_for_verification",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "collection_payload": payload,
            "collector_signature": collector_signature,
            "replay_head": self._head(checkpoint),
            "claim_boundary": {
                field: "unverified" for field in collection._CLAIM_BOUNDARY_FIELDS
            },
            "prohibited_content": {
                field: False for field in collection._PROHIBITED_FIELDS
            },
        }

    def _verify(self, **overrides) -> collection.VerifiedCollection:
        arguments = {
            "expected_receipt_sha256": self.receipt_sha256,
            "expected_policy_sha256": self.policy_sha256,
            "expected_request_sha256": self.request_sha256,
            "expected_previous_head_sha256": self.previous_sha256,
            "expected_github_origin_sha256": self.github_origin_sha256,
            "expected_deployment_policy_sha256": self.deployment_policy_sha256,
            "expected_readiness_sha256": self.readiness_sha256,
            "expected_archive_sha256": ARCHIVE_SHA256,
            "expected_bundle_sha256": BUNDLE_SHA256,
            "expected_current_worm_collection_head_sha256": "9" * 64,
            "expected_ledger_id": LEDGER_ID,
            "expected_sequence": 1,
        }
        arguments.update(overrides)
        return collection.verify_collection(
            self.receipt_path,
            self.request_path,
            self.previous_path,
            self.policy_path,
            self.github_origin_path,
            self.deployment_policy_path,
            self.readiness_path,
            self.archive_path,
            self.bundle_path,
            **arguments,
        )

    def _resign_receipt(self, receipt: dict[str, object]) -> None:
        payload = receipt["collection_payload"]
        receipt["collector_signature"] = _sign(
            self.collector_key, collection.COLLECTOR_DOMAIN, payload
        )
        checkpoint = receipt["replay_head"]["checkpoint"]
        checkpoint["collection_payload_sha256"] = _digest(payload)
        checkpoint["collector_signature_sha256"] = _digest(
            receipt["collector_signature"]
        )
        receipt["replay_head"]["signature"] = _sign(
            self.ledger_key, collection.LEDGER_DOMAIN, checkpoint
        )
        _write(self.receipt_path, receipt)

    def test_repository_templates_are_closed_unconfigured_and_honest(self) -> None:
        policy, evidence = collection.verify_repository_assets()
        self.assertTrue(policy["synthetic"])
        self.assertEqual(policy["policy_status"], "pending")
        self.assertTrue(evidence["synthetic"])
        with self.assertRaises(collection.GitHubRestCollectionError):
            collection.validate_policy(policy)
        with self.assertRaises(collection.GitHubRestCollectionError):
            collection.validate_evidence(evidence)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(collection.main(["verify-repository"]), 0)
        output = stdout.getvalue()
        for marker in (
            "status=unconfigured",
            "t141-origin-envelope=unverified",
            "t141-consistency=unverified",
            "rest-snapshot=unverified",
            "job-artifact-causality=unverified",
            "trusted-time=unverified",
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "production_acceptance=false",
            "not_committed_eligible=false",
        ):
            self.assertIn(marker, output)

    def test_configured_receipt_binds_projection_signatures_and_one_hop(self) -> None:
        verified = self._verify()
        self.assertEqual(verified.ledger_id, LEDGER_ID)
        self.assertEqual(verified.sequence, 1)
        self.assertEqual(
            verified.receipt_sha256,
            hashlib.sha256(self.receipt_path.read_bytes()).hexdigest(),
        )
        self.assertNotEqual(verified.collector_key_id, verified.ledger_key_id)

    def test_bytes_core_matches_path_wrapper_without_filesystem_reads(self) -> None:
        expected = self._verify()
        arguments = {
            "input_raw": self.receipt_path.read_bytes(),
            "request_raw": self.request_path.read_bytes(),
            "previous_head_raw": self.previous_path.read_bytes(),
            "policy_raw": self.policy_path.read_bytes(),
            "github_origin_raw": self.github_origin_path.read_bytes(),
            "deployment_policy_raw": self.deployment_policy_path.read_bytes(),
            "readiness_raw": self.readiness_path.read_bytes(),
            "archive_raw": self.archive_path.read_bytes(),
            "bundle_raw": self.bundle_path.read_bytes(),
            "expected_receipt_sha256": self.receipt_sha256,
            "expected_policy_sha256": self.policy_sha256,
            "expected_request_sha256": self.request_sha256,
            "expected_previous_head_sha256": self.previous_sha256,
            "expected_github_origin_sha256": self.github_origin_sha256,
            "expected_deployment_policy_sha256": self.deployment_policy_sha256,
            "expected_readiness_sha256": self.readiness_sha256,
            "expected_archive_sha256": ARCHIVE_SHA256,
            "expected_bundle_sha256": BUNDLE_SHA256,
            "expected_current_worm_collection_head_sha256": "9" * 64,
            "expected_ledger_id": LEDGER_ID,
            "expected_sequence": 1,
        }
        with mock.patch.object(collection, "_read_blob", side_effect=AssertionError("I/O forbidden")), mock.patch.object(collection, "_unchanged", side_effect=AssertionError("I/O forbidden")):
            actual = collection.verify_collection_bytes(**arguments)
        self.assertEqual(actual, expected)

    def test_caller_pins_policy_request_previous_head_origin_ledger_and_sequence(self) -> None:
        mutations = (
            {"expected_receipt_sha256": "f" * 64},
            {"expected_policy_sha256": "f" * 64},
            {"expected_request_sha256": "f" * 64},
            {"expected_previous_head_sha256": "f" * 64},
            {"expected_github_origin_sha256": "f" * 64},
            {"expected_deployment_policy_sha256": "f" * 64},
            {"expected_readiness_sha256": "f" * 64},
            {"expected_archive_sha256": "f" * 64},
            {"expected_bundle_sha256": "f" * 64},
            {"expected_current_worm_collection_head_sha256": "f" * 64},
            {"expected_ledger_id": "replacement-ledger-142"},
            {"expected_sequence": 2},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                collection.GitHubRestCollectionError
            ):
                self._verify(**mutation)

    def test_projection_rejects_cross_run_job_check_artifact_and_subject_mutations(self) -> None:
        changes = (
            ("workflow", "run_attempt", 3),
            ("workflow", "head_repository_id", "999"),
            ("job", "name", "replacement-job"),
            ("job", "check_run_url", f"https://api.github.com/repos/{REPOSITORY}/check-runs/9"),
            ("artifact", "artifact_id", 0),
            ("artifact", "subject_artifact_sha256", "f" * 64),
            ("artifact", "workflow_run_id", 999),
            ("attestation", "subject_digest", "sha256:" + "f" * 64),
        )
        for section, field, value in changes:
            receipt = copy.deepcopy(self.receipt)
            receipt["collection_payload"]["projection"][section][field] = value
            self._resign_receipt(receipt)
            with self.subTest(section=section, field=field), self.assertRaises(
                collection.GitHubRestCollectionError
            ):
                self._verify()
            _write(self.receipt_path, self.receipt)

    def test_t141_origin_subject_commit_and_bundle_must_match_the_t142_chain(self) -> None:
        changes = (
            ("subject", "artifact_sha256", "5" * 64),
            ("subject", "payload_sha256", "6" * 64),
            ("subject", "attempt_id", "00000000-0000-4000-8000-000000000199"),
            ("verification", "expected_commit", "7" * 40),
            ("bundle", "artifact_sha256", "8" * 64),
        )
        base_origin = copy.deepcopy(self.github_origin)
        for section, field, value in changes:
            origin = copy.deepcopy(base_origin)
            origin[section][field] = value
            origin = _seal(
                {key: item for key, item in origin.items() if key != "integrity"}
            )
            self.github_origin_raw = _write(self.github_origin_path, origin)
            self.github_origin_sha256 = hashlib.sha256(
                self.github_origin_raw
            ).hexdigest()
            self.request = self._request(sequence=1)
            self.request_raw = _write(self.request_path, self.request)
            self.request_sha256 = hashlib.sha256(self.request_raw).hexdigest()
            self._refresh_readiness(sequence=1)
            self.receipt = self._receipt(sequence=1)
            _write(self.receipt_path, self.receipt)
            with self.subTest(section=section, field=field), self.assertRaises(
                collection.GitHubRestCollectionError
            ):
                self._verify()

    def test_endpoint_set_page_bounds_and_archive_digest_are_exact(self) -> None:
        mutations = []
        missing = copy.deepcopy(self.receipt)
        del missing["collection_payload"]["endpoint_snapshots"]["list_jobs_for_workflow_run_attempt"]
        mutations.append(missing)
        duplicate = copy.deepcopy(self.receipt)
        duplicate["collection_payload"]["endpoint_snapshots"]["list_jobs_for_workflow_run_attempt"]["raw_response_sha256s"] = [
            duplicate["collection_payload"]["endpoint_snapshots"]["get_workflow_run_attempt"]["raw_response_sha256s"][0]
        ]
        mutations.append(duplicate)
        wrong_archive = copy.deepcopy(self.receipt)
        wrong_archive["collection_payload"]["endpoint_snapshots"]["download_workflow_artifact"]["raw_body_sha256"] = "f" * 64
        mutations.append(wrong_archive)
        too_many = copy.deepcopy(self.receipt)
        too_many["collection_payload"]["endpoint_snapshots"]["list_workflow_run_artifacts"]["raw_response_sha256s"] = [
            hashlib.sha256(str(index).encode()).hexdigest() for index in range(5)
        ]
        mutations.append(too_many)
        for receipt in mutations:
            self._resign_receipt(receipt)
            with self.assertRaises(collection.GitHubRestCollectionError):
                self._verify()
        _write(self.receipt_path, self.receipt)

    def test_redirect_download_credentials_origins_and_external_bytes_fail_closed(self) -> None:
        mutations = (
            ("get_workflow_artifact_redirect", "followed_automatically", True),
            ("get_workflow_artifact_redirect", "authorization_forwarded", True),
            ("get_workflow_artifact_redirect", "location_origin", "https://artifacts.example.com.evil"),
            ("download_workflow_artifact", "authorization_sent", True),
            ("download_workflow_artifact", "request_url_sha256", "f" * 64),
            ("download_attestation_bundle", "cookie_sent", True),
            ("download_attestation_bundle", "further_redirect", True),
            ("download_attestation_bundle", "raw_body_sha256", "f" * 64),
        )
        for endpoint, field, value in mutations:
            receipt = copy.deepcopy(self.receipt)
            receipt["collection_payload"]["endpoint_snapshots"][endpoint][field] = value
            self._resign_receipt(receipt)
            with self.subTest(endpoint=endpoint, field=field), self.assertRaises(
                collection.GitHubRestCollectionError
            ):
                self._verify()
        _write(self.receipt_path, self.receipt)

        self.archive_path.write_bytes(b"replacement archive bytes")
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify(expected_archive_sha256=hashlib.sha256(self.archive_path.read_bytes()).hexdigest())
        self.archive_path.write_bytes(ARCHIVE_BYTES)

        readiness = copy.deepcopy(self.readiness)
        readiness["payload"]["collection_ledger_id"] = "replacement-ledger-142"
        readiness = self.deployment_fixture._readiness(readiness["payload"])
        replacement_raw = deployment_fixture.raw_json(readiness)
        self.readiness_path.write_bytes(replacement_raw)
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify(expected_readiness_sha256=hashlib.sha256(replacement_raw).hexdigest())

    def test_genesis_and_non_genesis_previous_heads_are_both_one_hop_bounded(self) -> None:
        previous_checkpoint = {
            "schema_version": 1,
            "checkpoint_kind": collection.CHECKPOINT_KIND,
            "ledger_id": LEDGER_ID,
            "sequence": 4,
            "genesis": False,
            "collection_payload_sha256": "1" * 64,
            "collector_signature_sha256": "2" * 64,
            "request_artifact_sha256": "3" * 64,
            "previous_head_artifact_sha256": "4" * 64,
            "previous_checkpoint_payload_sha256": "5" * 64,
            "recorded_at": "2026-08-27T00:00:30Z",
        }
        self.previous_head = self._head(previous_checkpoint)
        self.previous_raw = _write(self.previous_path, self.previous_head)
        self.previous_sha256 = hashlib.sha256(self.previous_raw).hexdigest()
        self.request = self._request(sequence=5)
        self.request_raw = _write(self.request_path, self.request)
        self.request_sha256 = hashlib.sha256(self.request_raw).hexdigest()
        self._refresh_readiness(sequence=5)
        self.receipt = self._receipt(sequence=5)
        self.receipt_raw = _write(self.receipt_path, self.receipt)
        self.receipt_sha256 = hashlib.sha256(self.receipt_raw).hexdigest()
        verified = self._verify(expected_sequence=5)
        self.assertEqual(verified.sequence, 5)

        broken = copy.deepcopy(self.previous_head)
        broken["checkpoint"]["sequence"] = 3
        broken["signature"] = _sign(
            self.ledger_key, collection.LEDGER_DOMAIN, broken["checkpoint"]
        )
        broken_raw = _write(self.previous_path, broken)
        broken_sha = hashlib.sha256(broken_raw).hexdigest()
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify(
                expected_sequence=5,
                expected_previous_head_sha256=broken_sha,
            )

    def test_signature_domains_keys_and_time_chain_fail_closed(self) -> None:
        same_key_policy = copy.deepcopy(self.policy)
        same_key_policy["replay_ledger"] = same_key_policy["collector"]
        same_key_policy = _seal(
            {key: value for key, value in same_key_policy.items() if key != "integrity"}
        )
        with self.assertRaises(collection.GitHubRestCollectionError):
            collection.validate_policy(same_key_policy)

        receipt = copy.deepcopy(self.receipt)
        receipt["collection_payload"]["acquisition"]["completed_at"] = "2026-08-27T00:01:30Z"
        self._resign_receipt(receipt)
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify()

        receipt = copy.deepcopy(self.receipt)
        receipt["collector_signature"] = _sign(
            self.collector_key, collection.LEDGER_DOMAIN, receipt["collection_payload"]
        )
        _write(self.receipt_path, receipt)
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify()

    def test_stateless_reverification_does_not_overclaim_replay_protection(self) -> None:
        first = self._verify()
        second = self._verify()
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        stdout = io.StringIO()
        arguments = [
            "verify",
            "--input",
            str(self.receipt_path),
            "--request",
            str(self.request_path),
            "--previous-head",
            str(self.previous_path),
            "--policy",
            str(self.policy_path),
            "--github-origin",
            str(self.github_origin_path),
            "--deployment-policy",
            str(self.deployment_policy_path),
            "--readiness",
            str(self.readiness_path),
            "--archive",
            str(self.archive_path),
            "--bundle",
            str(self.bundle_path),
            "--expected-receipt-sha256",
            hashlib.sha256(self.receipt_path.read_bytes()).hexdigest(),
            "--expected-policy-sha256",
            self.policy_sha256,
            "--expected-request-sha256",
            self.request_sha256,
            "--expected-previous-head-sha256",
            self.previous_sha256,
            "--expected-github-origin-sha256",
            self.github_origin_sha256,
            "--expected-deployment-policy-sha256",
            self.deployment_policy_sha256,
            "--expected-readiness-sha256",
            self.readiness_sha256,
            "--expected-archive-sha256",
            ARCHIVE_SHA256,
            "--expected-bundle-sha256",
            BUNDLE_SHA256,
            "--expected-current-worm-collection-head-sha256",
            "9" * 64,
            "--expected-ledger-id",
            LEDGER_ID,
            "--expected-sequence",
            "1",
        ]
        with redirect_stdout(stdout):
            self.assertEqual(collection.main(arguments), 0)
        output = stdout.getvalue()
        self.assertIn("replay-ledger-checkpoint-authenticated=true", output)
        self.assertIn("t141-origin-envelope=caller-pinned-schema-validated", output)
        self.assertIn("t141-consistency=verified", output)
        for marker in (
            "job-artifact-causality=unverified",
            "provider-native=unverified",
            "trusted-time=unverified",
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "production_acceptance=false",
            "not_committed_eligible=false",
        ):
            self.assertIn(marker, output)

    def test_duplicate_keys_hardlinks_nonabsolute_paths_and_cli_failure_are_rejected(self) -> None:
        duplicate = self.request_raw.replace(
            b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
        )
        self.request_path.write_bytes(duplicate)
        with self.assertRaises(collection.GitHubRestCollectionError):
            self._verify(expected_request_sha256=hashlib.sha256(duplicate).hexdigest())

        _write(self.request_path, self.request)
        linked = self.root / "linked-receipt.json"
        try:
            os.link(self.receipt_path, linked)
        except OSError:
            linked = None
        if linked is not None:
            with self.assertRaises(collection.GitHubRestCollectionError):
                collection.verify_collection(
                    linked,
                    self.request_path,
                    self.previous_path,
                    self.policy_path,
                    self.github_origin_path,
                    self.deployment_policy_path,
                    self.readiness_path,
                    self.archive_path,
                    self.bundle_path,
                    expected_receipt_sha256=hashlib.sha256(linked.read_bytes()).hexdigest(),
                    expected_policy_sha256=self.policy_sha256,
                    expected_request_sha256=self.request_sha256,
                    expected_previous_head_sha256=self.previous_sha256,
                    expected_github_origin_sha256=self.github_origin_sha256,
                    expected_deployment_policy_sha256=self.deployment_policy_sha256,
                    expected_readiness_sha256=self.readiness_sha256,
                    expected_archive_sha256=ARCHIVE_SHA256,
                    expected_bundle_sha256=BUNDLE_SHA256,
                    expected_current_worm_collection_head_sha256="9" * 64,
                    expected_ledger_id=LEDGER_ID,
                    expected_sequence=1,
                )
        with self.assertRaises(collection.GitHubRestCollectionError):
            collection.verify_collection(
                "relative.json",
                self.request_path,
                self.previous_path,
                self.policy_path,
                self.github_origin_path,
                self.deployment_policy_path,
                self.readiness_path,
                self.archive_path,
                self.bundle_path,
                expected_receipt_sha256=hashlib.sha256(self.receipt_path.read_bytes()).hexdigest(),
                expected_policy_sha256=self.policy_sha256,
                expected_request_sha256=self.request_sha256,
                expected_previous_head_sha256=self.previous_sha256,
                expected_github_origin_sha256=self.github_origin_sha256,
                expected_deployment_policy_sha256=self.deployment_policy_sha256,
                expected_readiness_sha256=self.readiness_sha256,
                expected_archive_sha256=ARCHIVE_SHA256,
                expected_bundle_sha256=BUNDLE_SHA256,
                expected_current_worm_collection_head_sha256="9" * 64,
                expected_ledger_id=LEDGER_ID,
                expected_sequence=1,
            )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(collection.main(["verify"]), 1)
        self.assertEqual(stderr.getvalue(), "private-secret-github-rest-collection-failed\n")


if __name__ == "__main__":
    unittest.main()
