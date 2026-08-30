from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from scripts.target_intake_runtime_attestation_provider_selection import (
    EXPECTED_POLICY_SHA256,
    EXPECTED_SYNTHETIC_PROFILE_SHA256,
    POLICY,
    PREDECESSOR_POLICY_SHA256,
    ProviderSelectionError,
    SYNTHETIC_PROFILE,
    verify_external_profile,
    verify_provider_selection_bytes,
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )


class ProviderSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_raw = POLICY.read_bytes()
        self.profile = json.loads(SYNTHETIC_PROFILE.read_bytes())

    def verify_profile(self, profile: dict[str, object], *, synthetic: bool = True):
        raw = canonical(profile)
        return verify_provider_selection_bytes(
            policy_raw=self.policy_raw,
            profile_raw=raw,
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
            expected_profile_sha256=hashlib.sha256(raw).hexdigest(),
            allow_synthetic=synthetic,
        )

    def assert_profile_invalid(
        self, profile: dict[str, object], *, synthetic: bool = True
    ) -> None:
        with self.assertRaises(ProviderSelectionError):
            self.verify_profile(profile, synthetic=synthetic)

    def test_repository_fixture_selects_one_provider_without_authority(self) -> None:
        result = verify_provider_selection_bytes(
            policy_raw=self.policy_raw,
            profile_raw=SYNTHETIC_PROFILE.read_bytes(),
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
            expected_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
            allow_synthetic=True,
        )
        self.assertEqual(result.selected_provider_kind, "aws_s3_object_lock")
        self.assertTrue(result.predecessor_verified)
        self.assertTrue(result.selection_shape_verified)
        self.assertFalse(result.reviewer_authority_verified)
        self.assertFalse(result.provider_native_cas_verified)
        self.assertFalse(result.provider_custody_verified)
        self.assertFalse(result.production_acceptance)

    def test_all_provider_semantics_are_closed_and_accepted(self) -> None:
        semantics = json.loads(self.policy_raw)["provider_semantics"]
        for selected, contract in semantics.items():
            with self.subTest(selected=selected):
                profile = json.loads(canonical(self.profile))
                profile["selected_provider_kind"] = selected
                for field, value in contract.items():
                    profile["provider"][field] = value
                result = self.verify_profile(profile)
                self.assertEqual(result.selected_provider_kind, selected)

    def test_multiple_or_missing_selection_fails_closed(self) -> None:
        for selected in (
            None,
            ["aws_s3_object_lock", "azure_blob_immutable"],
            "unlisted_provider",
        ):
            with self.subTest(selected=selected):
                profile = json.loads(canonical(self.profile))
                profile["selected_provider_kind"] = selected
                self.assert_profile_invalid(profile)

    def test_provider_semantic_drift_and_retry_fail_closed(self) -> None:
        mutations = (
            ("head_precondition", "if_none_match"),
            ("version_identity_field", "etag"),
            ("stale_failure_outcomes", ["http_200_ok"]),
            ("no_automatic_retry", False),
            ("post_write_readback_required", False),
            ("protected_version_delete_denial_required", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                profile = json.loads(canonical(self.profile))
                profile["provider"][field] = value
                self.assert_profile_invalid(profile)

    def test_entry_and_head_references_must_be_distinct(self) -> None:
        profile = json.loads(canonical(self.profile))
        profile["provider"]["mutable_head_locator_ref"] = profile["provider"][
            "immutable_entry_namespace_ref"
        ]
        self.assert_profile_invalid(profile)

    def test_predecessor_and_policy_binding_cannot_be_replaced(self) -> None:
        for field in ("policy_sha256", "predecessor_policy_sha256"):
            with self.subTest(field=field):
                profile = json.loads(canonical(self.profile))
                profile[field] = "0" * 64
                self.assert_profile_invalid(profile)
        self.assertEqual(self.profile["predecessor_policy_sha256"], PREDECESSOR_POLICY_SHA256)

    def test_unknown_and_duplicate_fields_fail_closed(self) -> None:
        profile = json.loads(canonical(self.profile))
        profile["provider"]["extra"] = True
        self.assert_profile_invalid(profile)

        raw = SYNTHETIC_PROFILE.read_bytes().replace(
            b'{\n  "approval":', b'{\n  "schema_version": 1,\n  "approval":', 1
        )
        with self.assertRaises(ProviderSelectionError):
            verify_provider_selection_bytes(
                policy_raw=self.policy_raw,
                profile_raw=raw,
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_profile_sha256=hashlib.sha256(raw).hexdigest(),
                allow_synthetic=True,
            )

    def test_real_profile_shape_remains_negative_authority(self) -> None:
        profile = json.loads(canonical(self.profile))
        profile["synthetic"] = False
        profile["approval"].update(
            {
                "decision_id": "provider-selection-2026-0001",
                "provider_account_ref": "arn:aws:s3:::custody-prod",
                "reviewer_ref": "review-system://decisions/8291",
                "target_environment": "production-cn",
            }
        )
        profile["provider"].update(
            {
                "immutable_entry_namespace_ref": "s3://custody-prod/entries",
                "mutable_head_locator_ref": "s3://custody-prod/head/latest.json",
                "namespace_ref": "s3://custody-prod",
                "workload_identity_ref": "arn:aws:iam::123456789012:role/custody-writer",
            }
        )
        result = self.verify_profile(profile, synthetic=False)
        self.assertTrue(result.selection_shape_verified)
        self.assertFalse(result.reviewer_authority_verified)
        self.assertFalse(result.provider_native_cas_verified)
        self.assertFalse(result.production_acceptance)

    def test_real_profile_rejects_fixture_placeholders(self) -> None:
        profile = json.loads(canonical(self.profile))
        profile["synthetic"] = False
        self.assert_profile_invalid(profile, synthetic=False)

    def test_external_profile_must_be_absolute_and_repository_external(self) -> None:
        with self.assertRaises(ProviderSelectionError):
            verify_external_profile(
                Path("relative.json"),
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_profile_sha256="0" * 64,
            )
        with self.assertRaises(ProviderSelectionError):
            verify_external_profile(
                SYNTHETIC_PROFILE.resolve(),
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
            )

    def test_policy_is_caller_pinned_and_closed(self) -> None:
        policy = json.loads(self.policy_raw)
        policy["selected_provider_kind"] = "aws_s3_object_lock"
        raw = canonical(policy)
        with self.assertRaises(ProviderSelectionError):
            verify_provider_selection_bytes(
                policy_raw=raw,
                profile_raw=SYNTHETIC_PROFILE.read_bytes(),
                expected_policy_sha256=hashlib.sha256(raw).hexdigest(),
                expected_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                allow_synthetic=True,
            )


if __name__ == "__main__":
    unittest.main()
