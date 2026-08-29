from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import unittest

from scripts.target_intake_generation_context_trust import (
    POLICY,
    READINESS,
    GenerationContextTrustError,
    _canonical_digest,
    main,
    parse_policy,
    parse_readiness,
    validate_policy,
    validate_readiness,
    verify_repository,
)


class GenerationContextTrustTests(unittest.TestCase):
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
        self.assertIn("no-generation-publication-performed=true", output)
        self.assertIn("trusted-timestamp=unverified", output)
        self.assertIn("provider-head-cas=unverified", output)
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(["verify-repository"]), 0)
        self.assertEqual(stream.getvalue().strip(), output)
        after = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (POLICY, READINESS)
        }
        self.assertEqual(after, before)

    def test_policy_schema_and_subject_binding_are_closed(self) -> None:
        for mutate in (
            lambda value: value.update({"unexpected": None}),
            lambda value: value.pop("custody_requirements"),
            lambda value: value["required_subject_bindings"].reverse(),
            lambda value: value.update(
                {"subject_domain": "email-platform/private-secret/v1"}
            ),
        ):
            with self.subTest(mutate=mutate):
                candidate = deepcopy(self.policy)
                mutate(candidate)
                with self.assertRaises(GenerationContextTrustError):
                    validate_policy(candidate)

    def test_cross_domain_signer_role_scope_and_domain_are_rejected(self) -> None:
        mutations = (
            ("signer_role", "private_secret_target_storage_signer"),
            ("usage_scope", "private_secret_target_storage_receipt_v1_only"),
            (
                "signature_domain",
                "email-platform/private-secret-target-origin/storage-signer/v1",
            ),
        )
        for section in ("context_authority", "trusted_timestamp", "provider_head"):
            for key, replacement in mutations:
                if key not in self.policy[section]:
                    continue
                with self.subTest(section=section, key=key):
                    candidate = deepcopy(self.policy)
                    candidate[section][key] = replacement
                    with self.assertRaises(GenerationContextTrustError):
                        validate_policy(candidate)

    def test_unconfigured_anchor_cannot_smuggle_key_window_or_revocation_claims(self) -> None:
        mutations = (
            ("algorithm", "Ed25519"),
            ("key_id", "ed25519-sha256:" + "a" * 64),
            ("valid_from", "2026-01-01T00:00:00Z"),
            ("valid_until", "2099-01-01T00:00:00Z"),
            ("revocation_registry_reference", "registry:claimed-current"),
            ("revocation_registry_sha256", "b" * 64),
        )
        for key, replacement in mutations:
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["context_authority"][key] = replacement
                with self.assertRaises(GenerationContextTrustError):
                    validate_policy(candidate)

    def test_timestamp_claims_and_replay_weakening_are_rejected_while_unconfigured(self) -> None:
        for key, replacement in (
            ("state", "configured"),
            ("authority_kind", "rfc3161_tsa"),
            ("authority_identity_fingerprint_sha256", "a" * 64),
            ("trust_root_sha256", "b" * 64),
            ("policy_oid", "1.2.3.4"),
            ("nonce_binding_required", False),
            ("imprint_binding_required", False),
            ("maximum_assertion_age_seconds", 300),
        ):
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["trusted_timestamp"][key] = replacement
                with self.assertRaises(GenerationContextTrustError):
                    validate_policy(candidate)

    def test_provider_head_and_cas_claims_cannot_be_enabled_or_weakened_locally(self) -> None:
        for key, replacement in (
            ("state", "configured"),
            ("provider_kind", "claimed-provider"),
            ("namespace", "claimed-namespace"),
            ("ledger_id", "claimed-ledger"),
            ("caller_prior_head_required", False),
            ("sequence_precondition_required", False),
            ("signed_cas_outcome_required", False),
            ("read_after_cas_current_head_required", False),
            ("stale_write_rejection_required", False),
            ("automatic_retry_forbidden", False),
        ):
            with self.subTest(key=key):
                candidate = deepcopy(self.policy)
                candidate["provider_head"][key] = replacement
                with self.assertRaises(GenerationContextTrustError):
                    validate_policy(candidate)

    def test_readiness_cannot_promote_pending_or_embed_unverified_evidence(self) -> None:
        mutations = (
            lambda value: value.update({"readiness_status": "ready"}),
            lambda value: value.update({"production_acceptance": True}),
            lambda value: value.update({"not_committed_eligible": True}),
            lambda value: value.update({"generation_subject": {}}),
            lambda value: value.update({"context_signature": {}}),
            lambda value: value.update({"trusted_timestamp": {}}),
            lambda value: value.update({"provider_head": {}}),
            lambda value: value["assertions"].update(
                {"context_signature_authenticated": True}
            ),
            lambda value: value["assertions"].update(
                {"global_fork_absence_proven": True}
            ),
            lambda value: value["assertions"].update(
                {"no_generation_publication_performed": False}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(self.readiness)
                mutate(candidate)
                self._reseal_readiness(candidate)
                with self.assertRaises(GenerationContextTrustError):
                    validate_readiness(
                        candidate,
                        policy_artifact_sha256=self.policy_sha256,
                    )

    def test_policy_pin_integrity_and_duplicate_keys_fail_closed(self) -> None:
        with self.assertRaises(GenerationContextTrustError):
            validate_readiness(
                self.readiness,
                policy_artifact_sha256="0" * 64,
            )
        candidate = deepcopy(self.readiness)
        candidate["integrity"]["payload_sha256"] = "0" * 64
        with self.assertRaises(GenerationContextTrustError):
            validate_readiness(
                candidate,
                policy_artifact_sha256=self.policy_sha256,
            )
        duplicate = self.policy_raw.replace(
            b'{\n  "schema_version": 1,',
            b'{\n  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.assertNotEqual(duplicate, self.policy_raw)
        with self.assertRaises(GenerationContextTrustError):
            parse_policy(duplicate)
        with self.assertRaises(GenerationContextTrustError):
            parse_readiness(
                b"{}",
                policy_artifact_sha256=self.policy_sha256,
            )


if __name__ == "__main__":
    unittest.main()
