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

from scripts import private_secret_crash_evidence as crash
from scripts import private_secret_target_provenance as provenance
from scripts.deploy_release_evidence import seal_evidence, utc_now
from scripts.release_execution_binding import release_execution_identity
from tests.test_deploy_release_evidence import _complete_success, _recorder
from tests.test_private_secret_crash_evidence import (
    APPROVAL_SHA256,
    CLAIM_ID,
    SIBLING_ID,
    _reviewed_target_inventory,
    _seal,
    _write_residue,
)


CLUSTER_FINGERPRINT = "7" * 64
VERIFICATION_TIME = "2026-08-27T00:10:00Z"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _public_key(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


class PrivateSecretTargetProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target_private = Ed25519PrivateKey.generate()
        self.storage_private = Ed25519PrivateKey.generate()
        self.policy = json.loads(provenance.POLICY.read_text(encoding="utf-8"))
        self.policy["state"] = "pinned"
        for field, private in (
            ("target_signer", self.target_private),
            ("storage_signer", self.storage_private),
        ):
            raw = _public_key(private)
            self.policy[field].update(
                {
                    "state": "pinned",
                    "key_id": "ed25519-sha256:" + hashlib.sha256(raw).hexdigest(),
                    "public_key_b64url": base64.urlsafe_b64encode(raw)
                    .rstrip(b"=")
                    .decode("ascii"),
                }
            )
        self.policy_path = self.root / "trust-policy.json"
        self.policy_path.write_bytes(_canonical(self.policy))
        self.policy_sha256 = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()

        self.alert_path = self.root / "alert-receipt.bin"
        self.worm_path = self.root / "provider-receipt.bin"
        self.delete_path = self.root / "delete-probe.bin"
        self.custody_path = self.root / "custody-evidence.bin"
        self.alert_path.write_bytes(b"alert-firing-and-resolved-receiver-receipt")
        self.worm_path.write_bytes(b"provider-object-lock-commit-and-readback-receipt")
        self.delete_path.write_bytes(b"provider-deny-delete-probe-receipt")
        self.custody_path.write_bytes(b"external-two-key-custody-review-bundle")

        self.before_path = self.root / "before.json"
        self.after_path = self.root / "after.json"
        self.before = _write_residue(
            self.before_path,
            [
                {
                    "claim_id": CLAIM_ID,
                    "state": "cleanup_candidate",
                    "approval_sha256": APPROVAL_SHA256,
                },
                {"claim_id": SIBLING_ID, "state": "active"},
            ],
        )
        self.after = _write_residue(
            self.after_path,
            [{"claim_id": SIBLING_ID, "state": "active"}],
        )

        target = _reviewed_target_inventory()
        self.target_path = self.root / "target-inventory.json"
        target_raw = _canonical(target)
        self.target_path.write_bytes(target_raw)
        runtime_policy_sha256 = crash.load_runtime_policy()[1]
        crash_payload = {
            "schema_version": 1,
            "evidence_kind": crash.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "reviewed",
            "origin_authentication": "unverified",
            "production_acceptance": False,
            "attempt_id": "00000000-0000-4000-8000-000000000141",
            "scope": {
                "kind": "kubernetes_target_host",
                "environment": "staging",
                "target_inventory_artifact_sha256": hashlib.sha256(target_raw).hexdigest(),
                "target_inventory_reference": "target-platform-inventory-record-140",
                "execution_host_reference": "kubernetes-execution-host-record-140",
                "kubernetes_context_reference": "kubernetes-context-record-140",
            },
            "runtime_root_policy_sha256": runtime_policy_sha256,
            "claim_id": CLAIM_ID,
            "before_inventory": {
                **self.before,
                "captured_at": "2026-08-27T00:01:00Z",
            },
            "cleanup": {
                "result": "succeeded",
                "exit_code": 0,
                "finished_at": "2026-08-27T00:03:00Z",
                "execution_reference": "residue-cleanup-execution-record-140",
            },
            "after_inventory": {
                **self.after,
                "captured_at": "2026-08-27T00:04:00Z",
            },
            "alert": {
                "result": "delivered",
                "observed_at": "2026-08-27T00:02:00Z",
                "delivery_reference": "residue-alert-delivery-record-140",
                "artifact_sha256": hashlib.sha256(self.alert_path.read_bytes()).hexdigest(),
            },
            "review": {
                "operator_reference": "residue-operator-record-140",
                "cleanup_approver_reference": "residue-approver-record-140",
                "reviewer_reference": "residue-reviewer-record-140",
                "reviewed_at": "2026-08-27T00:05:00Z",
                "decision": "accepted_for_manual_review",
            },
            "prohibited_content": {field: False for field in crash._PROHIBITED_FIELDS},
        }
        self.crash_path = self.root / "crash-evidence.json"
        self.crash_path.write_bytes(_canonical(_seal(crash_payload)))

        recorder = _recorder()
        _complete_success(recorder)
        recorder.payload["finished_at"] = utc_now()
        release = seal_evidence(recorder.payload)
        self.release_path = self.root / "release-execution.json"
        self.release_path.write_bytes(_canonical(release))

        self.snapshot = crash.verify_evidence_snapshot(
            self.crash_path,
            self.before_path,
            self.after_path,
            expected_runtime_policy_sha256=runtime_policy_sha256,
            target_inventory_path=self.target_path,
        )
        release_identity = release_execution_identity(self.release_path.read_bytes())
        policy_digest = self.policy_sha256
        target_release = release_identity["target_release"]
        target_intake = release_identity["target_intake"]
        self.payload = {
            "schema_version": 1,
            "receipt_kind": provenance.RECEIPT_KIND,
            "statement": provenance.STATEMENT,
            "production_acceptance": False,
            "not_committed_eligible": False,
            "attempt_id": crash_payload["attempt_id"],
            "trust_policy_sha256": policy_digest,
            "target": {
                "environment": "staging",
                "target_inventory_artifact_sha256": self.snapshot.target_inventory_artifact_sha256,
                "target_inventory_reference": "target-platform-inventory-record-140",
                "cluster_identity_fingerprint_sha256": CLUSTER_FINGERPRINT,
            },
            "release": {
                "ledger_type": release_identity["ledger_type"],
                "evidence_artifact_sha256": release_identity["evidence_sha256"],
                "tag": target_release["tag"],
                "commit": target_release["commit"],
                "container_manifest_sha256": target_release["container_manifest_sha256"],
                "target_intake_manifest_payload_sha256": target_intake["manifest_payload_sha256"],
                "target_intake_requirements_sha256": target_intake["requirements_sha256"],
            },
            "crash_evidence": {
                "evidence_artifact_sha256": self.snapshot.evidence_artifact_sha256,
                "evidence_payload_sha256": self.snapshot.envelope["integrity"]["payload_sha256"],
                "runtime_root_policy_sha256": runtime_policy_sha256,
                "before_inventory_artifact_sha256": self.snapshot.before_inventory_artifact_sha256,
                "after_inventory_artifact_sha256": self.snapshot.after_inventory_artifact_sha256,
                "alert_delivery_reference": "residue-alert-delivery-record-140",
                "alert_artifact_sha256": hashlib.sha256(self.alert_path.read_bytes()).hexdigest(),
            },
            "publication": {
                "storage_identity_fingerprint_sha256": "8" * 64,
                "object_reference": "worm-private-secret-crash:object-141a",
                "immutable_version_reference": "immutable-version-record-141",
                "provider_receipt_artifact_sha256": hashlib.sha256(
                    self.worm_path.read_bytes()
                ).hexdigest(),
                "delete_probe_artifact_sha256": hashlib.sha256(
                    self.delete_path.read_bytes()
                ).hexdigest(),
                "evidence_readback_sha256": self.snapshot.evidence_artifact_sha256,
            },
            "custody": {
                "evidence_reference": "external-key-custody-record-141",
                "artifact_sha256": hashlib.sha256(self.custody_path.read_bytes()).hexdigest(),
            },
            "review": {
                "reviewer_reference": "target-origin-review-record-141",
                "decision": "accepted_for_provenance_only",
            },
            "timeline": {
                "crash_reviewed_at": "2026-08-27T00:05:00Z",
                "committed_at": "2026-08-27T00:06:00Z",
                "read_back_at": "2026-08-27T00:07:00Z",
                "reviewed_at": "2026-08-27T00:08:00Z",
                "signed_at": "2026-08-27T00:09:00Z",
                "retention_until": "2027-08-27T00:09:00Z",
            },
        }
        self.bundle_path = self.root / "target-origin.json"
        self._write_bundle(self.payload)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _bundle(self, payload: dict[str, object]) -> dict[str, object]:
        signatures: dict[str, object] = {}
        for role, private, policy_field in (
            ("target_signer", self.target_private, "target_signer"),
            ("storage_signer", self.storage_private, "storage_signer"),
        ):
            signature = private.sign(provenance.signature_message(payload, role=role))
            signatures[role] = {
                "algorithm": "Ed25519",
                "key_id": self.policy[policy_field]["key_id"],
                "value_b64url": base64.urlsafe_b64encode(signature)
                .rstrip(b"=")
                .decode("ascii"),
            }
        return {
            "schema_version": 1,
            "record_type": provenance.RECORD_TYPE,
            "synthetic": False,
            "evidence_status": "signed_assertion",
            "origin_authentication": "unverified",
            "provider_receipt_authentication": "unverified",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "payload": payload,
            "signatures": signatures,
        }

    def _write_bundle(self, payload: dict[str, object], *, canonical: bool = True) -> None:
        bundle = self._bundle(payload)
        raw = _canonical(bundle) if canonical else json.dumps(bundle, indent=2).encode("ascii")
        self.bundle_path.write_bytes(raw)

    def _verify(self, **changes) -> provenance.VerifiedTargetOrigin:
        arguments = {
            "input_path": self.bundle_path,
            "crash_evidence_path": self.crash_path,
            "before_inventory_path": self.before_path,
            "after_inventory_path": self.after_path,
            "target_inventory_path": self.target_path,
            "release_execution_path": self.release_path,
            "alert_evidence_path": self.alert_path,
            "worm_receipt_path": self.worm_path,
            "delete_probe_path": self.delete_path,
            "custody_evidence_path": self.custody_path,
            "expected_cluster_fingerprint_sha256": CLUSTER_FINGERPRINT,
            "expected_policy_sha256": self.policy_sha256,
            "verification_time": VERIFICATION_TIME,
        }
        arguments.update(changes)
        with mock.patch.object(provenance, "POLICY", self.policy_path):
            return provenance.verify_target_origin(**arguments)

    def test_repository_assets_remain_unconfigured_and_non_accepting(self) -> None:
        template, _ = provenance.verify_repository_assets()
        self.assertTrue(template["synthetic"])
        self.assertEqual(template["origin_authentication"], "unverified")
        self.assertEqual(template["provider_receipt_authentication"], "unverified")
        self.assertFalse(template["production_acceptance"])
        self.assertFalse(template["not_committed_eligible"])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(provenance.main(["verify-repository"]), 0)
        self.assertIn("status=unconfigured", stdout.getvalue())
        self.assertIn("origin-authentication=unverified", stdout.getvalue())
        for boundary in (
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
        ):
            self.assertIn(boundary, stdout.getvalue())

    def test_two_pinned_domains_authenticate_exact_artifacts_only(self) -> None:
        verified = self._verify()
        self.assertEqual(verified.attempt_id, self.payload["attempt_id"])
        self.assertEqual(
            verified.alert_fingerprint_sha256,
            hashlib.sha256(self.alert_path.read_bytes()).hexdigest(),
        )

        self.assertEqual(
            verified.storage_identity_fingerprint_sha256,
            self.payload["publication"]["storage_identity_fingerprint_sha256"],
        )
        self.assertEqual(
            verified.object_reference,
            self.payload["publication"]["object_reference"],
        )
        self.assertEqual(
            verified.immutable_version_reference,
            self.payload["publication"]["immutable_version_reference"],
        )
        self.assertEqual(
            verified.evidence_readback_sha256,
            self.payload["publication"]["evidence_readback_sha256"],
        )
        self.assertNotEqual(verified.target_signer_key_id, verified.storage_signer_key_id)
        stdout = io.StringIO()
        arguments = [
            "verify",
            "--input", str(self.bundle_path),
            "--crash-evidence", str(self.crash_path),
            "--before-inventory", str(self.before_path),
            "--after-inventory", str(self.after_path),
            "--target-inventory", str(self.target_path),
            "--release-execution", str(self.release_path),
            "--alert-evidence", str(self.alert_path),
            "--worm-receipt", str(self.worm_path),
            "--delete-probe", str(self.delete_path),
            "--custody-evidence", str(self.custody_path),
            "--expected-cluster-fingerprint-sha256", CLUSTER_FINGERPRINT,
            "--expected-policy-sha256", self.policy_sha256,
            "--verification-time", VERIFICATION_TIME,
        ]
        with mock.patch.object(provenance, "POLICY", self.policy_path), redirect_stdout(stdout):
            self.assertEqual(provenance.main(arguments), 0)
        output = stdout.getvalue()
        self.assertIn("authenticated-external-signer-assertion", output)
        self.assertIn("provider-receipt-authenticated=true", output)
        for boundary in (
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
        ):
            self.assertIn(boundary, output)
        self.assertIn("production_acceptance=false", output)
        self.assertNotIn("worm-verified", output.casefold())
        self.assertNotIn("target-execution-verified", output.casefold())

    def test_bytes_core_matches_path_wrapper_without_filesystem_reads(self) -> None:
        expected = self._verify()
        arguments = {
            "input_raw": self.bundle_path.read_bytes(),
            "policy_raw": self.policy_path.read_bytes(),
            "runtime_policy_raw": provenance.RUNTIME_POLICY.read_bytes(),
            "crash_evidence_raw": self.crash_path.read_bytes(),
            "before_inventory_raw": self.before_path.read_bytes(),
            "after_inventory_raw": self.after_path.read_bytes(),
            "target_inventory_raw": self.target_path.read_bytes(),
            "release_execution_raw": self.release_path.read_bytes(),
            "alert_evidence_raw": self.alert_path.read_bytes(),
            "worm_receipt_raw": self.worm_path.read_bytes(),
            "delete_probe_raw": self.delete_path.read_bytes(),
            "custody_evidence_raw": self.custody_path.read_bytes(),
            "expected_cluster_fingerprint_sha256": CLUSTER_FINGERPRINT,
            "expected_policy_sha256": self.policy_sha256,
            "verification_time": VERIFICATION_TIME,
        }
        with mock.patch.object(provenance, "_read_external_bytes", side_effect=AssertionError("I/O forbidden")), mock.patch.object(provenance, "read_stable_bytes", side_effect=AssertionError("I/O forbidden")):
            actual = provenance.verify_target_origin_bytes(**arguments)
        self.assertEqual(actual, expected)

    def test_default_unconfigured_policy_cannot_authenticate(self) -> None:
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            provenance.verify_target_origin(
                self.bundle_path,
                self.crash_path,
                self.before_path,
                self.after_path,
                self.target_path,
                self.release_path,
                self.alert_path,
                self.worm_path,
                self.delete_path,
                self.custody_path,
                expected_cluster_fingerprint_sha256=CLUSTER_FINGERPRINT,
                expected_policy_sha256=hashlib.sha256(
                    provenance.POLICY.read_bytes()
                ).hexdigest(),
                verification_time=VERIFICATION_TIME,
            )

    def test_re_signed_binding_mutations_fail_against_actual_snapshots(self) -> None:
        mutations = []
        for section, field in (
            ("target", "target_inventory_artifact_sha256"),
            ("target", "cluster_identity_fingerprint_sha256"),
            ("release", "evidence_artifact_sha256"),
            ("release", "commit"),
            ("crash_evidence", "evidence_artifact_sha256"),
            ("crash_evidence", "evidence_payload_sha256"),
            ("crash_evidence", "runtime_root_policy_sha256"),
            ("crash_evidence", "before_inventory_artifact_sha256"),
            ("crash_evidence", "after_inventory_artifact_sha256"),
            ("crash_evidence", "alert_artifact_sha256"),
            ("publication", "provider_receipt_artifact_sha256"),
            ("publication", "delete_probe_artifact_sha256"),
            ("publication", "evidence_readback_sha256"),
            ("custody", "artifact_sha256"),
        ):
            changed = copy.deepcopy(self.payload)
            changed[section][field] = "9" * 64
            mutations.append(changed)
        changed = copy.deepcopy(self.payload)
        changed["trust_policy_sha256"] = "9" * 64
        mutations.append(changed)
        for index, payload in enumerate(mutations):
            with self.subTest(index=index):
                self._write_bundle(payload)
                with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
                    self._verify()

    def test_actual_opaque_artifact_replacement_fails(self) -> None:
        for path in (
            self.alert_path,
            self.worm_path,
            self.delete_path,
            self.custody_path,
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"-replaced")
                with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
                    self._verify()
                path.write_bytes(original)

        original = self.delete_path.read_bytes()
        self.delete_path.write_bytes(self.worm_path.read_bytes())
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()
        self.delete_path.write_bytes(original)

    def test_signature_role_key_and_payload_tampering_fail(self) -> None:
        bundle = json.loads(self.bundle_path.read_text(encoding="ascii"))
        bundle["signatures"]["target_signer"], bundle["signatures"]["storage_signer"] = (
            bundle["signatures"]["storage_signer"],
            bundle["signatures"]["target_signer"],
        )
        self.bundle_path.write_bytes(_canonical(bundle))
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()

        self._write_bundle(self.payload)
        bundle = json.loads(self.bundle_path.read_text(encoding="ascii"))
        bundle["signatures"]["target_signer"]["value_b64url"] = "A" * 86
        self.bundle_path.write_bytes(_canonical(bundle))
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()

        self._write_bundle(self.payload)
        bundle = json.loads(self.bundle_path.read_text(encoding="ascii"))
        bundle["payload"]["production_acceptance"] = True
        self.bundle_path.write_bytes(_canonical(bundle))
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()

    def test_policy_rejects_same_keys_self_selected_anchor_and_enabled_integration(self) -> None:
        same = copy.deepcopy(self.policy)
        same["storage_signer"] = copy.deepcopy(same["target_signer"])
        same["storage_signer"]["usage_scope"] = (
            "private_secret_target_storage_receipt_v1_only"
        )
        receipt_selected = copy.deepcopy(self.policy)
        receipt_selected["target_signer"]["source"] = "receipt_selected"
        enabled = copy.deepcopy(self.policy)
        enabled["executor_integration_enabled"] = True
        for policy in (same, receipt_selected, enabled):
            with self.subTest(policy=policy), self.assertRaises(
                provenance.PrivateSecretTargetProvenanceError
            ):
                provenance.validate_trust_policy(policy)

    def test_replaced_policy_and_receipt_signed_by_attacker_fail_caller_pin(self) -> None:
        attacker_target = Ed25519PrivateKey.generate()
        attacker_storage = Ed25519PrivateKey.generate()
        attacker_policy = copy.deepcopy(self.policy)
        for field, private in (
            ("target_signer", attacker_target),
            ("storage_signer", attacker_storage),
        ):
            raw = _public_key(private)
            attacker_policy[field]["key_id"] = (
                "ed25519-sha256:" + hashlib.sha256(raw).hexdigest()
            )
            attacker_policy[field]["public_key_b64url"] = (
                base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            )
        attacker_policy_raw = _canonical(attacker_policy)
        self.policy_path.write_bytes(attacker_policy_raw)
        payload = copy.deepcopy(self.payload)
        payload["trust_policy_sha256"] = hashlib.sha256(attacker_policy_raw).hexdigest()
        signatures = {}
        for role, private, field in (
            ("target_signer", attacker_target, "target_signer"),
            ("storage_signer", attacker_storage, "storage_signer"),
        ):
            raw = private.sign(provenance.signature_message(payload, role=role))
            signatures[role] = {
                "algorithm": "Ed25519",
                "key_id": attacker_policy[field]["key_id"],
                "value_b64url": base64.urlsafe_b64encode(raw)
                .rstrip(b"=")
                .decode("ascii"),
            }
        bundle = self._bundle(payload)
        bundle["signatures"] = signatures
        self.bundle_path.write_bytes(_canonical(bundle))
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()

    def test_time_order_gaps_retention_and_reference_independence_fail(self) -> None:
        cases = (
            ("committed_at", "2026-08-27T00:04:59Z"),
            ("read_back_at", "2026-08-27T00:30:00Z"),
            ("reviewed_at", "2026-08-27T00:30:00Z"),
            ("signed_at", "2026-08-27T00:30:00Z"),
            ("retention_until", "2026-08-27T00:09:30Z"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.payload)
                changed["timeline"][field] = value
                self._write_bundle(changed)
                with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
                    self._verify()
        changed = copy.deepcopy(self.payload)
        changed["review"]["reviewer_reference"] = "residue-reviewer-record-140"
        self._write_bundle(changed)
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()

    def test_noncanonical_duplicate_extra_and_hardlinked_inputs_fail_redacted(self) -> None:
        self._write_bundle(self.payload, canonical=False)
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()
        self._write_bundle(self.payload)
        duplicate = self.bundle_path.read_bytes().replace(
            b'{"evidence_status":', b'{"evidence_status":"signed_assertion","evidence_status":', 1
        )
        self.bundle_path.write_bytes(duplicate)
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()
        self._write_bundle(self.payload)
        linked = self.root / "alert-hardlink.bin"
        os.link(self.alert_path, linked)
        with self.assertRaises(provenance.PrivateSecretTargetProvenanceError):
            self._verify()
        linked.unlink()

        canary = "https://secret.invalid/token-value"
        self.bundle_path.write_text(json.dumps({"canary": canary}), encoding="utf-8")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with mock.patch.object(provenance, "POLICY", self.policy_path):
                result = provenance.main(
                    [
                        "verify",
                        "--input", str(self.bundle_path),
                        "--crash-evidence", str(self.crash_path),
                        "--before-inventory", str(self.before_path),
                        "--after-inventory", str(self.after_path),
                        "--target-inventory", str(self.target_path),
                        "--release-execution", str(self.release_path),
                        "--alert-evidence", str(self.alert_path),
                        "--worm-receipt", str(self.worm_path),
                        "--delete-probe", str(self.delete_path),
                        "--custody-evidence", str(self.custody_path),
                        "--expected-cluster-fingerprint-sha256", CLUSTER_FINGERPRINT,
                        "--expected-policy-sha256", self.policy_sha256,
                        "--verification-time", VERIFICATION_TIME,
                    ]
                )
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "private-secret-target-origin-failed\n")
        self.assertNotIn(canary, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
