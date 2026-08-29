from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from scripts.target_intake_runtime_attestation_intake import (
    EXPECTED_FIXTURE_SUBJECT_SHA256,
    RuntimeAttestationIntakeError,
    _artifact_bytes,
    _canonical_digest,
    verify_repository_fixture,
    verify_runtime_attestation_protocol_bytes,
)
from tests.runtime_attestation_fixture import build_fixture, fixture_bytes


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
PROFILE = ROOT / "deploy" / "target-intake-runtime-attestation-profile.synthetic.json"
EVIDENCE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-runtime-attestation-evidence.synthetic.json"
)


def _seal(document: dict[str, object]) -> bytes:
    payload = {key: value for key, value in document.items() if key != "integrity"}
    document["integrity"] = {"payload_sha256": _canonical_digest(payload)}
    return _artifact_bytes(document)


class RuntimeAttestationIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy_raw = POLICY.read_bytes()
        cls.profile_raw = PROFILE.read_bytes()
        cls.evidence_raw = EVIDENCE.read_bytes()

    def verify(
        self,
        *,
        policy_raw: bytes | None = None,
        profile_raw: bytes | None = None,
        evidence_raw: bytes | None = None,
        policy_pin: str | None = None,
        profile_pin: str | None = None,
        subject_pin: str = EXPECTED_FIXTURE_SUBJECT_SHA256,
    ):
        selected_policy = self.policy_raw if policy_raw is None else policy_raw
        selected_profile = self.profile_raw if profile_raw is None else profile_raw
        return verify_runtime_attestation_protocol_bytes(
            policy_raw=selected_policy,
            profile_raw=selected_profile,
            evidence_raw=self.evidence_raw if evidence_raw is None else evidence_raw,
            expected_policy_sha256=(
                hashlib.sha256(selected_policy).hexdigest()
                if policy_pin is None
                else policy_pin
            ),
            expected_profile_sha256=(
                hashlib.sha256(selected_profile).hexdigest()
                if profile_pin is None
                else profile_pin
            ),
            expected_runtime_subject_sha256=subject_pin,
        )

    def test_repository_fixture_and_builder_are_exact(self) -> None:
        self.assertEqual(self.evidence_raw, fixture_bytes())
        verified = self.verify()
        self.assertEqual(
            verified.runtime_artifact_digest,
            build_fixture()["runtime_subject"]["runtime_artifact_digest"],
        )
        output = verify_repository_fixture()
        self.assertIn("protocol-bindings=verified", output)
        self.assertIn("publisher-authentication=unverified", output)
        self.assertIn("runtime-authority=unverified", output)
        self.assertIn("production_acceptance=false", output)

    def test_caller_policy_profile_and_subject_pins_are_independent(self) -> None:
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(policy_pin="0" * 64)
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(profile_pin="0" * 64)
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(subject_pin="0" * 64)

    def test_noncanonical_and_duplicate_json_are_rejected(self) -> None:
        profile = json.loads(self.profile_raw)
        noncanonical = json.dumps(profile, indent=4, sort_keys=True).encode("ascii")
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(profile_raw=noncanonical)
        duplicate = self.profile_raw.replace(
            b'  "bytes_core": {',
            b'  "bytes_core": null,\n  "bytes_core": {',
            1,
        )
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(profile_raw=duplicate)

    def test_profile_cannot_enable_authentication_or_production(self) -> None:
        profile = json.loads(self.profile_raw)
        for mutation in (
            lambda value: value.update({"synthetic": False}),
            lambda value: value.update({"production_acceptance": True}),
            lambda value: value["bytes_core"].update({"network_access": True}),
            lambda value: value["bytes_core"].update(
                {"production_authentication": True}
            ),
            lambda value: value["provider_profiles"]["sigstore_cosign"].update(
                {"bundle_media_type": "application/json"}
            ),
        ):
            candidate = copy.deepcopy(profile)
            mutation(candidate)
            raw = _seal(candidate)
            with self.assertRaises(RuntimeAttestationIntakeError):
                self.verify(profile_raw=raw)

    def test_runtime_subject_and_sigstore_bundle_must_cross_bind(self) -> None:
        evidence = json.loads(self.evidence_raw)
        evidence["runtime_subject"]["runtime_artifact_immutable_reference"] = (
            "ghcr.io/01121531/email-api:v0.0.0-fixture"
        )
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["sigstore_cosign"]["artifact_digest"] = "sha256:" + "1" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["sigstore_cosign"]["verification_state"] = "verified"
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_github_provenance_is_closed_and_does_not_invent_hermeticity(self) -> None:
        evidence = json.loads(self.evidence_raw)
        statement = evidence["github_provenance"]["statement"]
        statement["subject"].append(copy.deepcopy(statement["subject"][0]))
        evidence["github_provenance"]["raw_statement_sha256"] = _canonical_digest(
            statement
        )
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["github_provenance"]["repository_id"] = "fixture-id"
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["deployment_selection"]["release_commit"] = "8" * 40
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        statement = evidence["github_provenance"]["statement"]
        statement["predicate"]["buildDefinition"]["internalParameters"][
            "hermetic_build_claim"
        ] = True
        evidence["github_provenance"]["raw_statement_sha256"] = _canonical_digest(
            statement
        )
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_trust_checkpoint_and_deployment_selection_are_bound(self) -> None:
        evidence = json.loads(self.evidence_raw)
        evidence["trust_state"]["transparency_checkpoint_sha256"] = "2" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["deployment_selection"]["publisher_record_sha256"] = "3" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_target_observation_requires_more_than_config_image(self) -> None:
        evidence = json.loads(self.evidence_raw)
        del evidence["target_observation"]["image_object_id"]
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["target_observation"]["repo_digests"] = [
            "ghcr.io/01121531/email-api@sha256:" + "4" * 64
        ]
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["target_observation"]["observed_at"] = "2026-01-02T03:09:59Z"
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_timestamp_nonce_and_imprint_cannot_be_resealed_away(self) -> None:
        evidence = json.loads(self.evidence_raw)
        evidence["trusted_timestamp"]["nonce"] = "short"
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["target_observation"]["readback_artifact_sha256"] = "5" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_provider_head_rejects_stale_or_retry_semantics(self) -> None:
        evidence = json.loads(self.evidence_raw)
        evidence["provider_head"]["expected_prior_head"] = "6" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["provider_head"]["automatic_retry_performed"] = True
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

        evidence = json.loads(self.evidence_raw)
        evidence["provider_head"]["read_after_current_head"] = "7" * 64
        with self.assertRaises(RuntimeAttestationIntakeError):
            self.verify(evidence_raw=_seal(evidence))

    def test_evidence_cannot_promote_fixture_to_production(self) -> None:
        evidence = json.loads(self.evidence_raw)
        for mutation in (
            lambda value: value.update({"synthetic": False}),
            lambda value: value.update({"evidence_status": "verified"}),
            lambda value: value.update({"production_acceptance": True}),
            lambda value: value.update({"not_committed_eligible": True}),
        ):
            candidate = copy.deepcopy(evidence)
            mutation(candidate)
            with self.assertRaises(RuntimeAttestationIntakeError):
                self.verify(evidence_raw=_seal(candidate))


if __name__ == "__main__":
    unittest.main()
