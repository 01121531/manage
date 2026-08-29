from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.target_intake_runtime_attestation_trust import (
    POLICY,
    READINESS,
    RuntimeAttestationTrustError,
    _canonical_digest,
    _read_single_link,
    main,
    parse_policy,
    parse_readiness,
    validate_policy,
    validate_readiness,
    verify_repository,
)


class RuntimeAttestationTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_raw = POLICY.read_bytes()
        self.policy = json.loads(self.policy_raw)
        self.policy_sha256 = hashlib.sha256(self.policy_raw).hexdigest()
        self.readiness_raw = READINESS.read_bytes()
        self.readiness = json.loads(self.readiness_raw)

    def _reseal_readiness(self, value: dict[str, object]) -> None:
        payload = {key: item for key, item in value.items() if key != "integrity"}
        value["integrity"] = {"payload_sha256": _canonical_digest(payload)}

    def test_repository_contract_is_pending_and_read_only(self) -> None:
        before = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (POLICY, READINESS)
        }
        output = verify_repository()
        self.assertIn("status=unconfigured readiness=pending", output)
        self.assertIn("production_acceptance=false", output)
        self.assertIn("provenance-attestation=unverified", output)
        self.assertIn("target-process-identity=unverified", output)
        self.assertIn("runtime-authority=unverified", output)
        self.assertIn("original-execution=unverified", output)
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(["verify-repository"]), 0)
        self.assertEqual(stream.getvalue().strip(), output)
        after = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (POLICY, READINESS)
        }
        self.assertEqual(after, before)

    def test_policy_schema_subject_and_artifact_requirements_are_closed(self) -> None:
        mutations = (
            lambda value: value.update({"unexpected": None}),
            lambda value: value.pop("artifact_requirements"),
            lambda value: value["required_subject_bindings"].reverse(),
            lambda value: value["required_subject_bindings"].remove(
                "target_loaded_evidence_sha256"
            ),
            lambda value: value["artifact_requirements"].update(
                {"tag_only_reference_forbidden": False}
            ),
            lambda value: value["artifact_requirements"].update(
                {"digest_algorithm": "sha512"}
            ),
            lambda value: value["artifact_requirements"].update(
                {"allowed_artifact_kinds": ["oci-tag"]}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(self.policy)
                mutate(candidate)
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_policy(candidate)

    def test_runtime_authorities_cannot_reuse_generation_context_or_each_other(self) -> None:
        generation_context = {
            "signer_role": "target_intake_generation_context_authority",
            "usage_scope": "target_intake_generation_context_authority_v1_only",
            "signature_domain": (
                "email-platform/target-intake-generation-context-handoff/"
                "context-authority/v1"
            ),
        }
        sections = (
            "publisher_signature",
            "provenance_attestation",
            "target_runtime_observation",
            "trusted_timestamp",
            "provider_head",
        )
        for section in sections:
            for key, replacement in generation_context.items():
                with self.subTest(section=section, key=key):
                    candidate = deepcopy(self.policy)
                    candidate[section][key] = replacement
                    with self.assertRaises(RuntimeAttestationTrustError):
                        validate_policy(candidate)
        for target in sections[1:]:
            for key in ("signer_role", "usage_scope", "signature_domain"):
                with self.subTest(target=target, key=key):
                    candidate = deepcopy(self.policy)
                    candidate[target][key] = candidate["publisher_signature"][key]
                    with self.assertRaises(RuntimeAttestationTrustError):
                        validate_policy(candidate)

    def test_unconfigured_publisher_cannot_smuggle_trust_or_signature_claims(self) -> None:
        for key, replacement in (
            ("state", "configured"),
            ("algorithm", "Ed25519"),
            ("issuer_identity", "claimed-publisher"),
            ("key_id", "ed25519-sha256:" + "a" * 64),
            ("trust_anchor_sha256", "a" * 64),
            ("valid_from", "2026-01-01T00:00:00Z"),
            ("valid_until", "2099-01-01T00:00:00Z"),
            ("revocation_registry_sha256", "b" * 64),
            ("transparency_log_reference", "claimed-log"),
            ("subject_digest_required", False),
            ("revocation_freshness_required", False),
        ):
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["publisher_signature"][key] = replacement
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_policy(candidate)

    def test_unconfigured_provenance_cannot_smuggle_builder_or_predicate_claims(self) -> None:
        for key, replacement in (
            ("state", "configured"),
            ("attestation_format", "in-toto"),
            ("issuer_identity", "claimed-issuer"),
            ("builder_identity", "claimed-builder"),
            ("source_repository", "claimed-repository"),
            ("source_commit", "a" * 40),
            ("predicate_type", "https://slsa.dev/provenance/v1"),
            ("trust_anchor_sha256", "a" * 64),
            ("materials_digest_binding_required", False),
            ("hermetic_build_claim_required", False),
        ):
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["provenance_attestation"][key] = replacement
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_policy(candidate)

    def test_target_observation_claims_cannot_be_injected_or_weakened(self) -> None:
        for key, replacement in (
            ("state", "configured"),
            ("authority_identity", "claimed-observer"),
            ("target_environment", "production"),
            ("target_account", "claimed-account"),
            ("target_cluster_or_host", "claimed-host"),
            ("observation_kind", "container-config-image-string"),
            ("deployment_digest_selection_required", False),
            ("container_image_id_or_executable_digest_required", False),
            ("process_identity_required", False),
            ("loaded_module_native_evidence_required", False),
            ("signed_observation_required", False),
        ):
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["target_runtime_observation"][key] = replacement
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_policy(candidate)

    def test_timestamp_replay_and_provider_cas_weakening_are_rejected(self) -> None:
        for section, key, replacement in (
            ("trusted_timestamp", "state", "configured"),
            ("trusted_timestamp", "authority_kind", "rfc3161_tsa"),
            ("trusted_timestamp", "nonce_binding_required", False),
            ("trusted_timestamp", "imprint_binding_required", False),
            ("trusted_timestamp", "maximum_assertion_age_seconds", 300),
            ("provider_head", "state", "configured"),
            ("provider_head", "provider_kind", "claimed-provider"),
            ("provider_head", "artifact_digest_precondition_required", False),
            ("provider_head", "signed_cas_outcome_required", False),
            ("provider_head", "read_after_cas_current_head_required", False),
            ("provider_head", "stale_write_rejection_required", False),
            ("provider_head", "automatic_retry_forbidden", False),
        ):
            with self.subTest(section=section, key=key):
                candidate = deepcopy(self.policy)
                candidate[section][key] = replacement
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_policy(candidate)

    def test_readiness_cannot_embed_local_evidence_or_promote_assertions(self) -> None:
        mutations = (
            lambda value: value.update({"readiness_status": "ready"}),
            lambda value: value.update({"production_acceptance": True}),
            lambda value: value.update({"not_committed_eligible": True}),
            lambda value: value.update({"runtime_subject": {}}),
            lambda value: value.update({"publisher_signature": {}}),
            lambda value: value.update({"provenance_attestation": {}}),
            lambda value: value.update({"target_runtime_observation": {}}),
            lambda value: value.update({"trusted_timestamp": {}}),
            lambda value: value.update({"provider_head": {}}),
            lambda value: value["assertions"].update(
                {"target_digest_matched": True}
            ),
            lambda value: value["assertions"].update(
                {"global_rollback_protection_proven": True}
            ),
            lambda value: value["assertions"].update(
                {"no_repository_signature_generated": False}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(self.readiness)
                mutate(candidate)
                self._reseal_readiness(candidate)
                with self.assertRaises(RuntimeAttestationTrustError):
                    validate_readiness(
                        candidate,
                        policy_artifact_sha256=self.policy_sha256,
                    )

    def test_policy_pin_integrity_duplicate_keys_and_hardlinks_fail_closed(self) -> None:
        with self.assertRaises(RuntimeAttestationTrustError):
            validate_readiness(
                self.readiness,
                policy_artifact_sha256="0" * 64,
            )
        candidate = deepcopy(self.readiness)
        candidate["integrity"]["payload_sha256"] = "0" * 64
        with self.assertRaises(RuntimeAttestationTrustError):
            validate_readiness(
                candidate,
                policy_artifact_sha256=self.policy_sha256,
            )
        duplicate = self.policy_raw.replace(
            b'{\n  "schema_version": 1,',
            b'{\n  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        with self.assertRaises(RuntimeAttestationTrustError):
            parse_policy(duplicate)
        with self.assertRaises(RuntimeAttestationTrustError):
            parse_readiness(b"{}", policy_artifact_sha256=self.policy_sha256)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            alias = Path(directory) / "alias.json"
            source.write_bytes(b"{}")
            os.link(source, alias)
            with self.assertRaises(RuntimeAttestationTrustError):
                _read_single_link(source)


if __name__ == "__main__":
    unittest.main()
