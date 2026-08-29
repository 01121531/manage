from __future__ import annotations

import base64
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import private_secret_target_provenance as target_provenance
from scripts import private_secret_worm_collection as worm
from tests.test_private_secret_target_provenance import (
    CLUSTER_FINGERPRINT,
    VERIFICATION_TIME,
    PrivateSecretTargetProvenanceTests,
    _canonical,
    _public_key,
)


LEDGER_ID = "worm-replay-ledger-142"
PROVIDER_KIND = "object-lock-provider-142"
DELETE_REASON = "object-lock-retention-denied"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _seal(value: dict[str, object]) -> dict[str, object]:
    sealed = copy.deepcopy(value)
    sealed["integrity"] = {
        "payload_sha256": _sha(
            _canonical({key: item for key, item in sealed.items() if key != "integrity"})
        )
    }
    return sealed


class PrivateSecretWormCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = PrivateSecretTargetProvenanceTests(
            "test_two_pinned_domains_authenticate_exact_artifacts_only"
        )
        self.target.setUp()
        self.root = self.target.root
        self.provider_private = Ed25519PrivateKey.generate()
        self.ledger_private = Ed25519PrivateKey.generate()

        self.policy = json.loads(worm.POLICY.read_text(encoding="utf-8"))
        self.policy.update({"synthetic": False, "policy_status": "reviewed"})
        self.policy["provider_contract"] = {
            "state": "configured",
            "provider_kind": PROVIDER_KIND,
            "ledger_id": LEDGER_ID,
            "required_retention_mode": "compliance",
            "denied_delete_reason_code": DELETE_REASON,
        }
        for field, private in (
            ("provider_observer", self.provider_private),
            ("ledger_signer", self.ledger_private),
        ):
            raw = _public_key(private)
            self.policy[field].update(
                {
                    "state": "pinned",
                    "key_id": "ed25519-sha256:" + _sha(raw),
                    "public_key_b64url": base64.urlsafe_b64encode(raw)
                    .rstrip(b"=")
                    .decode("ascii"),
                }
            )
        self.policy = _seal(self.policy)
        self.policy_path = self.root / "worm-policy.json"
        self.policy_path.write_bytes(_canonical(self.policy))
        self.policy_sha256 = _sha(self.policy_path.read_bytes())

        self.provider_config_path = self.root / "provider-config.bin"
        self.object_metadata_path = self.root / "object-metadata.bin"
        self.delete_observation_path = self.root / "delete-observation.bin"
        self.trusted_time_path = self.root / "trusted-time.bin"
        self.readback_path = self.root / "target-origin-readback.bin"
        self.provider_config_path.write_bytes(b"provider configuration snapshot 142")
        self.object_metadata_path.write_bytes(b"provider object metadata snapshot 142")
        self.delete_observation_path.write_bytes(b"provider denied delete record 142")
        self.trusted_time_path.write_bytes(b"external trusted time record 142")
        self.readback_path.write_bytes(self.target.crash_path.read_bytes())

        with mock.patch.object(target_provenance, "POLICY", self.target.policy_path):
            target = self.target._verify()
        self.observation = {
            "schema_version": 1,
            "observation_kind": worm.OBSERVATION_KIND,
            "statement": worm.OBSERVATION_STATEMENT,
            "production_acceptance": False,
            "not_committed_eligible": False,
            "observation_id": "00000000-0000-4000-8000-000000000142",
            "trust_policy_sha256": self.policy_sha256,
            "target_origin": {
                "attempt_id": target.attempt_id,
                "receipt_fingerprint_sha256": target.receipt_fingerprint_sha256,
            },
            "provider": {
                "provider_kind": PROVIDER_KIND,
                "account_identity_fingerprint_sha256": "1" * 64,
                "storage_identity_fingerprint_sha256": target.storage_identity_fingerprint_sha256,
                "configuration_snapshot_sha256": _sha(
                    self.provider_config_path.read_bytes()
                ),
                "configuration_version_fingerprint_sha256": "3" * 64,
            },
            "object": {
                "object_reference": target.object_reference,
                "immutable_version_reference": target.immutable_version_reference,
                "content_sha256": target.evidence_readback_sha256,
                "metadata_snapshot_sha256": _sha(
                    self.object_metadata_path.read_bytes()
                ),
                "retention_mode": "compliance",
                "retention_until": "2027-08-27T00:09:30Z",
            },
            "delete_observation": {
                "artifact_sha256": _sha(self.delete_observation_path.read_bytes()),
                "request_fingerprint_sha256": "4" * 64,
                "result": "denied",
                "reason_code": DELETE_REASON,
                "attempted_at": "2026-08-27T00:09:15Z",
                "post_denial_readback_sha256": target.evidence_readback_sha256,
            },
            "trusted_time": {
                "artifact_sha256": _sha(self.trusted_time_path.read_bytes()),
                "authority_identity_fingerprint_sha256": "5" * 64,
                "observed_at": "2026-08-27T00:09:30Z",
            },
            "timeline": {
                "configuration_captured_at": "2026-08-27T00:09:01Z",
                "object_observed_at": "2026-08-27T00:09:10Z",
                "delete_observed_at": "2026-08-27T00:09:20Z",
            },
            "prohibited_content": {
                field: False for field in worm._PROHIBITED_FIELDS
            },
        }
        self.input_path = self.root / "worm-collection.json"
        self.collection = self._make_collection()
        self.input_path.write_bytes(_canonical(self.collection))
        self.collection_sha256 = _sha(self.input_path.read_bytes())

    def tearDown(self) -> None:
        self.target.tearDown()

    def _signature(
        self,
        payload: dict[str, object],
        *,
        role: str,
        private: Ed25519PrivateKey,
        key_id: str,
    ) -> dict[str, str]:
        raw = private.sign(worm.signature_message(payload, role=role))
        return {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value_b64url": base64.urlsafe_b64encode(raw)
            .rstrip(b"=")
            .decode("ascii"),
        }

    def _make_collection(
        self,
        *,
        observation: dict[str, object] | None = None,
        sequence: int = 1,
        previous: dict[str, object] | None = None,
        checkpoint_id: str = "00000000-0000-4000-8000-000000000143",
        checkpointed_at: str = "2026-08-27T00:09:40Z",
        provider_private: Ed25519PrivateKey | None = None,
        ledger_private: Ed25519PrivateKey | None = None,
        provider_key_id: str | None = None,
        ledger_key_id: str | None = None,
    ) -> dict[str, object]:
        observation = copy.deepcopy(observation or self.observation)
        provider_private = provider_private or self.provider_private
        ledger_private = ledger_private or self.ledger_private
        provider_key_id = provider_key_id or self.policy["provider_observer"]["key_id"]
        ledger_key_id = ledger_key_id or self.policy["ledger_signer"]["key_id"]
        observation_envelope = {
            "payload": observation,
            "signature": self._signature(
                observation,
                role="provider_observer",
                private=provider_private,
                key_id=provider_key_id,
            ),
        }
        if previous is None:
            previous = {
                "kind": "genesis",
                "sequence": 0,
                "artifact_sha256": worm.ZERO_SHA256,
                "payload_sha256": worm.ZERO_SHA256,
            }
        checkpoint = {
            "schema_version": 1,
            "checkpoint_kind": worm.CHECKPOINT_KIND,
            "statement": worm.CHECKPOINT_STATEMENT,
            "production_acceptance": False,
            "not_committed_eligible": False,
            "checkpoint_id": checkpoint_id,
            "trust_policy_sha256": observation["trust_policy_sha256"],
            "ledger_id": LEDGER_ID,
            "sequence": sequence,
            "previous": previous,
            "observation_artifact_sha256": _sha(_canonical(observation_envelope)),
            "observation_payload_sha256": _sha(_canonical(observation)),
            "target_origin_receipt_sha256": observation["target_origin"][
                "receipt_fingerprint_sha256"
            ],
            "attempt_id": observation["target_origin"]["attempt_id"],
            "trusted_time_artifact_sha256": observation["trusted_time"][
                "artifact_sha256"
            ],
            "checkpointed_at": checkpointed_at,
        }
        checkpoint_envelope = {
            "payload": checkpoint,
            "signature": self._signature(
                checkpoint,
                role="ledger_signer",
                private=ledger_private,
                key_id=ledger_key_id,
            ),
        }
        return _seal(
            {
                "schema_version": 1,
                "record_type": worm.RECORD_TYPE,
                "synthetic": False,
                "collection_status": "signed_assertion",
                "provider_observation_authentication": "unverified",
                "checkpoint_authentication": "unverified",
                "production_acceptance": False,
                "not_committed_eligible": False,
                "observation": observation_envelope,
                "checkpoint": checkpoint_envelope,
            }
        )

    def _verify(self, **changes) -> worm.VerifiedCollection:
        arguments = {
            "input_path": self.input_path,
            "policy_path": self.policy_path,
            "target_policy_path": self.target.policy_path,
            "target_origin_path": self.target.bundle_path,
            "crash_evidence_path": self.target.crash_path,
            "before_inventory_path": self.target.before_path,
            "after_inventory_path": self.target.after_path,
            "target_inventory_path": self.target.target_path,
            "release_execution_path": self.target.release_path,
            "alert_evidence_path": self.target.alert_path,
            "worm_receipt_path": self.target.worm_path,
            "target_delete_probe_path": self.target.delete_path,
            "custody_evidence_path": self.target.custody_path,
            "provider_config_path": self.provider_config_path,
            "object_metadata_path": self.object_metadata_path,
            "delete_observation_path": self.delete_observation_path,
            "readback_path": self.readback_path,
            "trusted_time_path": self.trusted_time_path,
            "expected_collection_sha256": self.collection_sha256,
            "expected_policy_sha256": self.policy_sha256,
            "expected_target_policy_sha256": self.target.policy_sha256,
            "expected_cluster_fingerprint_sha256": CLUSTER_FINGERPRINT,
            "expected_ledger_id": LEDGER_ID,
            "expected_sequence": 1,
            "expected_prior_head_sha256": worm.ZERO_SHA256,
            "verification_time": VERIFICATION_TIME,
        }
        arguments.update(changes)
        with mock.patch.object(target_provenance, "POLICY", self.target.policy_path):
            return worm.verify_collection(**arguments)

    def _rewrite(self, collection: dict[str, object]) -> None:
        self.collection = collection
        self.input_path.write_bytes(_canonical(collection))

    def _cli_arguments(self) -> list[str]:
        return [
            "verify",
            "--input", str(self.input_path),
            "--policy", str(self.policy_path),
            "--target-policy", str(self.target.policy_path),
            "--target-origin", str(self.target.bundle_path),
            "--crash-evidence", str(self.target.crash_path),
            "--before-inventory", str(self.target.before_path),
            "--after-inventory", str(self.target.after_path),
            "--target-inventory", str(self.target.target_path),
            "--release-execution", str(self.target.release_path),
            "--alert-evidence", str(self.target.alert_path),
            "--worm-receipt", str(self.target.worm_path),
            "--target-delete-probe", str(self.target.delete_path),
            "--custody-evidence", str(self.target.custody_path),
            "--provider-config", str(self.provider_config_path),
            "--object-metadata", str(self.object_metadata_path),
            "--delete-observation", str(self.delete_observation_path),
            "--readback", str(self.readback_path),
            "--trusted-time", str(self.trusted_time_path),
            "--expected-collection-sha256", self.collection_sha256,
            "--expected-policy-sha256", self.policy_sha256,
            "--expected-target-policy-sha256", self.target.policy_sha256,
            "--expected-cluster-fingerprint-sha256", CLUSTER_FINGERPRINT,
            "--expected-ledger-id", LEDGER_ID,
            "--expected-sequence", "1",
            "--expected-prior-head-sha256", worm.ZERO_SHA256,
            "--verification-time", VERIFICATION_TIME,
        ]

    def test_repository_assets_are_synthetic_unconfigured_and_non_accepting(self) -> None:
        policy, template, policy_sha = worm.verify_repository_assets()
        self.assertTrue(policy["synthetic"])
        self.assertEqual(policy["provider_observer"]["state"], "unconfigured")
        self.assertEqual(policy["ledger_signer"]["state"], "unconfigured")
        self.assertIsNone(template["observation"])
        self.assertFalse(template["production_acceptance"])
        self.assertRegex(policy_sha, r"^[0-9a-f]{64}$")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(worm.main(["verify-repository"]), 0)
        output = stdout.getvalue()
        for claim in (
            "provider-observation=unverified",
            "checkpoint-signature=unverified",
            "provider-native=unverified",
            "trusted-time=unverified",
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "production_acceptance=false",
            "not_committed_eligible=false",
        ):
            self.assertIn(claim, output)

    def test_genesis_authenticates_exact_bytes_with_limited_truth_claims(self) -> None:
        verified = self._verify()
        self.assertEqual(verified.attempt_id, self.target.payload["attempt_id"])
        self.assertEqual(verified.sequence, 1)
        self.assertEqual(verified.head_sha256, _sha(self.input_path.read_bytes()))
        self.assertNotEqual(
            verified.provider_signer_key_id, verified.ledger_signer_key_id
        )
        stdout = io.StringIO()
        with mock.patch.object(target_provenance, "POLICY", self.target.policy_path):
            with redirect_stdout(stdout):
                self.assertEqual(worm.main(self._cli_arguments()), 0)
        output = stdout.getvalue()
        self.assertIn(
            "provider-observation=authenticated-external-signer-assertion", output
        )
        self.assertIn("checkpoint-signature=authenticated", output)
        self.assertIn("checkpoint-chain-binding=validated", output)
        for boundary in (
            "provider-native=unverified",
            "trusted-time=unverified",
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "production_acceptance=false",
            "not_committed_eligible=false",
        ):
            self.assertIn(boundary, output)
        self.assertNotIn("worm-verified", output)

    def test_bytes_core_matches_path_wrapper_without_filesystem_reads(self) -> None:
        expected = self._verify()
        arguments = {
            "input_raw": self.input_path.read_bytes(),
            "policy_raw": self.policy_path.read_bytes(),
            "target_policy_raw": self.target.policy_path.read_bytes(),
            "runtime_policy_raw": target_provenance.RUNTIME_POLICY.read_bytes(),
            "target_origin_raw": self.target.bundle_path.read_bytes(),
            "crash_evidence_raw": self.target.crash_path.read_bytes(),
            "before_inventory_raw": self.target.before_path.read_bytes(),
            "after_inventory_raw": self.target.after_path.read_bytes(),
            "target_inventory_raw": self.target.target_path.read_bytes(),
            "release_execution_raw": self.target.release_path.read_bytes(),
            "alert_evidence_raw": self.target.alert_path.read_bytes(),
            "worm_receipt_raw": self.target.worm_path.read_bytes(),
            "target_delete_probe_raw": self.target.delete_path.read_bytes(),
            "custody_evidence_raw": self.target.custody_path.read_bytes(),
            "provider_config_raw": self.provider_config_path.read_bytes(),
            "object_metadata_raw": self.object_metadata_path.read_bytes(),
            "delete_observation_raw": self.delete_observation_path.read_bytes(),
            "readback_raw": self.readback_path.read_bytes(),
            "trusted_time_raw": self.trusted_time_path.read_bytes(),
            "expected_collection_sha256": self.collection_sha256,
            "expected_policy_sha256": self.policy_sha256,
            "expected_target_policy_sha256": self.target.policy_sha256,
            "expected_cluster_fingerprint_sha256": CLUSTER_FINGERPRINT,
            "expected_ledger_id": LEDGER_ID,
            "expected_sequence": 1,
            "expected_prior_head_sha256": worm.ZERO_SHA256,
            "verification_time": VERIFICATION_TIME,
        }
        with mock.patch.object(worm, "_read_external_bytes", side_effect=AssertionError("I/O forbidden")), mock.patch.object(worm, "read_stable_bytes", side_effect=AssertionError("I/O forbidden")):
            actual = worm.verify_collection_bytes(**arguments)
        self.assertEqual(actual, expected)

    def test_path_wrapper_acquires_each_target_input_once(self) -> None:
        calls: list[Path] = []
        original = worm._read_external_bytes

        def recording(path: Path | str, *, max_bytes: int) -> bytes:
            calls.append(Path(path))
            return original(path, max_bytes=max_bytes)

        with mock.patch.object(worm, "_read_external_bytes", side_effect=recording):
            self._verify()
        self.assertEqual(calls.count(self.target.bundle_path), 1)
        self.assertEqual(calls.count(self.readback_path), 1)
        self.assertEqual(len(calls), len(set(calls)))

    def test_raw_policy_pin_blocks_policy_and_key_replacement(self) -> None:
        substitute_provider = Ed25519PrivateKey.generate()
        substitute_ledger = Ed25519PrivateKey.generate()
        substitute = copy.deepcopy(self.policy)
        substitute["provider_contract"]["provider_kind"] = "replacement-provider-142"
        for field, private in (
            ("provider_observer", substitute_provider),
            ("ledger_signer", substitute_ledger),
        ):
            raw = _public_key(private)
            substitute[field]["key_id"] = "ed25519-sha256:" + _sha(raw)
            substitute[field]["public_key_b64url"] = (
                base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            )
        substitute = _seal(substitute)
        self.policy_path.write_bytes(_canonical(substitute))
        observation = copy.deepcopy(self.observation)
        observation["provider"]["provider_kind"] = "replacement-provider-142"
        observation["trust_policy_sha256"] = _sha(self.policy_path.read_bytes())
        self._rewrite(
            self._make_collection(
                observation=observation,
                provider_private=substitute_provider,
                ledger_private=substitute_ledger,
                provider_key_id=substitute["provider_observer"]["key_id"],
                ledger_key_id=substitute["ledger_signer"]["key_id"],
            )
        )
        with self.assertRaises(worm.PrivateSecretWormCollectionError):
            self._verify(expected_policy_sha256=self.policy_sha256)

    def test_resigned_semantic_mutations_fail_closed(self) -> None:
        mutations = {
            "target receipt": lambda value: value["target_origin"].__setitem__(
                "receipt_fingerprint_sha256", "a" * 64
            ),
            "provider kind": lambda value: value["provider"].__setitem__(
                "provider_kind", "other-provider-142"
            ),
            "storage identity": lambda value: value["provider"].__setitem__(
                "storage_identity_fingerprint_sha256", "a" * 64
            ),
            "config digest": lambda value: value["provider"].__setitem__(
                "configuration_snapshot_sha256", "a" * 64
            ),
            "metadata digest": lambda value: value["object"].__setitem__(
                "metadata_snapshot_sha256", "a" * 64
            ),
            "content digest": lambda value: value["object"].__setitem__(
                "content_sha256", "a" * 64
            ),
            "object reference": lambda value: value["object"].__setitem__(
                "object_reference", "worm-private-secret-crash:object-999a"
            ),
            "immutable version": lambda value: value["object"].__setitem__(
                "immutable_version_reference", "immutable-version-record-999"
            ),
            "retention expired": lambda value: value["object"].__setitem__(
                "retention_until", "2026-08-27T00:09:59Z"
            ),
            "delete reason": lambda value: value["delete_observation"].__setitem__(
                "reason_code", "different-denial-reason"
            ),
            "readback digest": lambda value: value["delete_observation"].__setitem__(
                "post_denial_readback_sha256", "a" * 64
            ),
            "trusted time digest": lambda value: value["trusted_time"].__setitem__(
                "artifact_sha256", "a" * 64
            ),
            "prohibited content": lambda value: value["prohibited_content"].__setitem__(
                "contains_secret_values", True
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation = copy.deepcopy(self.observation)
                mutate(observation)
                try:
                    collection = self._make_collection(observation=observation)
                except worm.PrivateSecretWormCollectionError:
                    continue
                self._rewrite(collection)
                with self.assertRaises(worm.PrivateSecretWormCollectionError):
                    self._verify()
                self._rewrite(self._make_collection())

    def test_replaced_provider_artifacts_and_alias_paths_fail(self) -> None:
        for path in (
            self.provider_config_path,
            self.object_metadata_path,
            self.delete_observation_path,
            self.readback_path,
            self.trusted_time_path,
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"-replacement")
                with self.assertRaises(worm.PrivateSecretWormCollectionError):
                    self._verify()
                path.write_bytes(original)
        with self.assertRaises(worm.PrivateSecretWormCollectionError):
            self._verify(object_metadata_path=self.provider_config_path)

    def test_signature_role_key_and_encoding_mutations_fail(self) -> None:
        cases = []
        wrong_key = copy.deepcopy(self.collection)
        wrong_key["observation"]["signature"]["key_id"] = self.policy[
            "ledger_signer"
        ]["key_id"]
        cases.append(wrong_key)
        tampered = copy.deepcopy(self.collection)
        encoded = tampered["checkpoint"]["signature"]["value_b64url"]
        tampered["checkpoint"]["signature"]["value_b64url"] = (
            ("A" if encoded[0] != "A" else "B") + encoded[1:]
        )
        cases.append(tampered)
        padded = copy.deepcopy(self.collection)
        padded["observation"]["signature"]["value_b64url"] += "="
        cases.append(padded)
        for value in cases:
            value = _seal(value)
            self._rewrite(value)
            with self.assertRaises(worm.PrivateSecretWormCollectionError):
                self._verify()

    def test_non_genesis_requires_exact_signed_caller_pinned_prior(self) -> None:
        prior_path = self.root / "prior-collection.json"
        prior_path.write_bytes(_canonical(self.collection))
        prior_sha = _sha(prior_path.read_bytes())
        prior_checkpoint = self.collection["checkpoint"]["payload"]
        observation = copy.deepcopy(self.observation)
        observation["observation_id"] = "00000000-0000-4000-8000-000000000144"
        previous = {
            "kind": "checkpoint",
            "sequence": 1,
            "artifact_sha256": prior_sha,
            "payload_sha256": _sha(_canonical(prior_checkpoint)),
        }
        current = self._make_collection(
            observation=observation,
            sequence=2,
            previous=previous,
            checkpoint_id="00000000-0000-4000-8000-000000000145",
        )
        self._rewrite(current)
        self.collection_sha256 = _sha(self.input_path.read_bytes())
        verified = self._verify(
            expected_sequence=2,
            expected_prior_head_sha256=prior_sha,
            prior_checkpoint_path=prior_path,
        )
        self.assertEqual(verified.sequence, 2)
        for changes in (
            {"prior_checkpoint_path": None},
            {"expected_prior_head_sha256": "a" * 64},
            {"expected_sequence": 3},
        ):
            with self.subTest(changes=changes):
                arguments = {
                    "expected_sequence": 2,
                    "expected_prior_head_sha256": prior_sha,
                    "prior_checkpoint_path": prior_path,
                }
                arguments.update(changes)
                with self.assertRaises(worm.PrivateSecretWormCollectionError):
                    self._verify(**arguments)

    def test_non_genesis_rejects_replayed_ids_and_chain_mutations(self) -> None:
        prior_path = self.root / "prior-collection.json"
        prior_path.write_bytes(_canonical(self.collection))
        prior_sha = _sha(prior_path.read_bytes())
        previous = {
            "kind": "checkpoint",
            "sequence": 1,
            "artifact_sha256": prior_sha,
            "payload_sha256": _sha(
                _canonical(self.collection["checkpoint"]["payload"])
            ),
        }
        cases = []
        cases.append(
            self._make_collection(
                sequence=2,
                previous=previous,
                checkpoint_id="00000000-0000-4000-8000-000000000145",
            )
        )
        observation = copy.deepcopy(self.observation)
        observation["observation_id"] = "00000000-0000-4000-8000-000000000144"
        cases.append(
            self._make_collection(
                observation=observation,
                sequence=2,
                previous=previous,
                checkpoint_id="00000000-0000-4000-8000-000000000143",
            )
        )
        bad_previous = copy.deepcopy(previous)
        bad_previous["payload_sha256"] = "a" * 64
        cases.append(
            self._make_collection(
                observation=observation,
                sequence=2,
                previous=bad_previous,
                checkpoint_id="00000000-0000-4000-8000-000000000145",
            )
        )
        for collection in cases:
            self._rewrite(collection)
            with self.assertRaises(worm.PrivateSecretWormCollectionError):
                self._verify(
                    expected_sequence=2,
                    expected_prior_head_sha256=prior_sha,
                    prior_checkpoint_path=prior_path,
                )
        corrupted_prior = copy.deepcopy(self.collection)
        signature = corrupted_prior["checkpoint"]["signature"]["value_b64url"]
        corrupted_prior["checkpoint"]["signature"]["value_b64url"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
        corrupted_prior = _seal(corrupted_prior)
        prior_path.write_bytes(_canonical(corrupted_prior))
        with self.assertRaises(worm.PrivateSecretWormCollectionError):
            self._verify(
                expected_sequence=2,
                expected_prior_head_sha256=_sha(prior_path.read_bytes()),
                prior_checkpoint_path=prior_path,
            )

    def test_time_order_gap_future_and_retention_fail_closed(self) -> None:
        cases = (
            ("object_observed_at", "2026-08-27T00:09:00Z", None),
            ("delete_observed_at", "2026-08-27T00:09:14Z", None),
            ("configuration_captured_at", "2026-08-26T23:00:00Z", None),
            (None, None, "2026-08-27T00:08:00Z"),
        )
        for field, value, checkpointed in cases:
            with self.subTest(field=field, checkpointed=checkpointed):
                observation = copy.deepcopy(self.observation)
                if field is not None:
                    observation["timeline"][field] = value
                self._rewrite(
                    self._make_collection(
                        observation=observation,
                        checkpointed_at=checkpointed or "2026-08-27T00:09:40Z",
                    )
                )
                with self.assertRaises(worm.PrivateSecretWormCollectionError):
                    self._verify()

    def test_noncanonical_duplicate_json_hardlink_and_cli_errors_are_redacted(self) -> None:
        self.input_path.write_text(json.dumps(self.collection, indent=2), encoding="ascii")
        with self.assertRaises(worm.PrivateSecretWormCollectionError):
            self._verify()
        self.input_path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(worm.PrivateSecretWormCollectionError):
            self._verify()
        self._rewrite(self._make_collection())
        hardlink = self.root / "provider-config-hardlink.bin"
        try:
            os.link(self.provider_config_path, hardlink)
        except OSError:
            pass
        else:
            with self.assertRaises(worm.PrivateSecretWormCollectionError):
                self._verify()
            hardlink.unlink()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(worm.main(["verify", "--input", "secret-path"]), 1)
        self.assertEqual(stderr.getvalue().strip(), "private-secret-worm-collection-failed")

    def test_policy_rejects_collapsed_domains_and_enabled_integration(self) -> None:
        for mutate in (
            lambda value: value["ledger_signer"].update(
                {
                    "key_id": value["provider_observer"]["key_id"],
                    "public_key_b64url": value["provider_observer"][
                        "public_key_b64url"
                    ],
                }
            ),
            lambda value: value.__setitem__("executor_integration_enabled", True),
            lambda value: value["provider_observer"].__setitem__(
                "source", "receipt_selected_key"
            ),
            lambda value: value["requirements"].__setitem__(
                "caller_head_pin_required", False
            ),
        ):
            candidate = copy.deepcopy(self.policy)
            mutate(candidate)
            candidate = _seal(candidate)
            with self.assertRaises(worm.PrivateSecretWormCollectionError):
                worm.validate_policy(candidate, require_configured=True)


if __name__ == "__main__":
    unittest.main()
