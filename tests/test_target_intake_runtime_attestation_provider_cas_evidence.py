from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.target_intake_runtime_attestation_provider_cas_evidence import (
    EXPECTED_POLICY_SHA256,
    EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
    EXPECTED_SYNTHETIC_PROFILE_SHA256,
    EXTERNAL_MANIFEST_NAME,
    POLICY,
    SELECTION_POLICY,
    SYNTHETIC_ARTIFACT_ROOT,
    SYNTHETIC_EVIDENCE,
    SYNTHETIC_PROFILE,
    ProviderCasEvidenceError,
    verify_external_evidence_package,
    verify_provider_cas_evidence_bytes,
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "ascii"
    )


class ProviderCasEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = json.loads(SYNTHETIC_PROFILE.read_bytes())
        self.evidence = json.loads(SYNTHETIC_EVIDENCE.read_bytes())
        self.artifacts = {
            item["path"]: (SYNTHETIC_ARTIFACT_ROOT / item["path"]).read_bytes()
            for item in self.evidence["artifacts"]
        }

    def verify(
        self,
        *,
        profile: dict[str, object] | None = None,
        evidence: dict[str, object] | None = None,
        artifacts: dict[str, bytes] | None = None,
        synthetic: bool = True,
    ):
        profile_raw = canonical(profile or self.profile)
        evidence_raw = canonical(evidence or self.evidence)
        return verify_provider_cas_evidence_bytes(
            selection_policy_raw=SELECTION_POLICY.read_bytes(),
            selection_profile_raw=profile_raw,
            policy_raw=POLICY.read_bytes(),
            evidence_raw=evidence_raw,
            artifact_bytes=artifacts or self.artifacts,
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
            expected_selection_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
            expected_evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
            allow_synthetic=synthetic,
        )

    def assert_invalid(self, **kwargs: object) -> None:
        with self.assertRaises(ProviderCasEvidenceError):
            self.verify(**kwargs)

    def real_package(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, bytes]]:
        profile = copy.deepcopy(self.profile)
        profile["synthetic"] = False
        profile["approval"].update(
            {
                "decision_id": "provider-selection-2026-0001",
                "provider_account_ref": "arn:aws:s3:::custody-prod-cn",
                "reviewer_ref": "review-system://decisions/8291",
                "target_environment": "production-cn",
            }
        )
        profile["provider"].update(
            {
                "immutable_entry_namespace_ref": "s3://custody-prod-cn/entries",
                "mutable_head_locator_ref": "s3://custody-prod-cn/head/latest.json",
                "namespace_ref": "s3://custody-prod-cn",
                "workload_identity_ref": "arn:aws:iam::123456789012:role/custody-writer",
            }
        )
        profile_raw = canonical(profile)

        evidence = copy.deepcopy(self.evidence)
        evidence.update(
            {
                "synthetic": False,
                "provider_account_ref": profile["approval"]["provider_account_ref"],
                "selection_profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
                "target_environment": "production-cn",
            }
        )
        evidence["actors"].update(
            {
                "successful_writer_host_ref": "host://custody-writer-a",
                "stale_writer_host_ref": "host://custody-writer-b",
                "workload_identity_ref": profile["provider"]["workload_identity_ref"],
            }
        )
        evidence["execution"]["entry"]["immutable_entry_ref"] = (
            "s3://custody-prod-cn/entries/runtime-attestation-0001.json"
        )
        evidence["execution"]["head"]["mutable_head_locator_ref"] = profile[
            "provider"
        ]["mutable_head_locator_ref"]
        evidence["execution"]["retention"]["retention_configuration_ref"] = (
            "s3://custody-prod-cn/object-lock/configuration"
        )
        evidence["review"]["reviewer_ref"] = "review-system://reviews/8292"
        artifacts = {
            item["path"]: canonical(
                {"provider_record": item["kind"], "record_status": "captured"}
            )
            for item in evidence["artifacts"]
        }
        for item in evidence["artifacts"]:
            raw = artifacts[item["path"]]
            item["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            item["size"] = len(raw)
        return profile, evidence, artifacts

    def test_repository_fixture_binds_bytes_without_authority(self) -> None:
        result = verify_provider_cas_evidence_bytes(
            selection_policy_raw=SELECTION_POLICY.read_bytes(),
            selection_profile_raw=SYNTHETIC_PROFILE.read_bytes(),
            policy_raw=POLICY.read_bytes(),
            evidence_raw=SYNTHETIC_EVIDENCE.read_bytes(),
            artifact_bytes=self.artifacts,
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
            expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
            expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
            allow_synthetic=True,
        )
        self.assertEqual(result.artifact_count, 9)
        self.assertTrue(result.selection_shape_verified)
        self.assertTrue(result.evidence_shape_verified)
        self.assertTrue(result.artifact_bytes_bound)
        self.assertTrue(result.cross_host_writers_distinct)
        self.assertFalse(result.reviewer_authority_verified)
        self.assertFalse(result.provider_response_authentication_verified)
        self.assertFalse(result.provider_native_cas_verified)
        self.assertFalse(result.retention_delete_denial_verified)
        self.assertFalse(result.provider_custody_verified)
        self.assertFalse(result.trusted_time_verified)
        self.assertFalse(result.production_acceptance)

    def test_all_selected_provider_semantics_are_supported(self) -> None:
        policy = json.loads(POLICY.read_bytes())
        selection_policy = json.loads(SELECTION_POLICY.read_bytes())
        for selected, semantics in policy["provider_semantics"].items():
            with self.subTest(selected=selected):
                profile = copy.deepcopy(self.profile)
                profile["selected_provider_kind"] = selected
                for field, value in selection_policy["provider_semantics"][selected].items():
                    profile["provider"][field] = value
                evidence = copy.deepcopy(self.evidence)
                evidence["selected_provider_kind"] = selected
                evidence["selection_profile_sha256"] = hashlib.sha256(
                    canonical(profile)
                ).hexdigest()
                entry = evidence["execution"]["entry"]
                head = evidence["execution"]["head"]
                retention = evidence["execution"]["retention"]
                entry["version_identity_field"] = semantics["version_identity_field"]
                head["version_identity_field"] = semantics["version_identity_field"]
                head["head_precondition_kind"] = semantics["head_precondition"]
                head["stale_outcome"] = semantics["stale_failure_outcomes"][-1]
                retention["immutability_control"] = semantics["immutability_control"]
                result = self.verify(profile=profile, evidence=evidence)
                self.assertEqual(result.selected_provider_kind, selected)

    def test_artifact_inventory_bytes_and_order_fail_closed(self) -> None:
        artifacts = dict(self.artifacts)
        first = next(iter(artifacts))
        artifacts[first] += b"tampered"
        self.assert_invalid(artifacts=artifacts)

        evidence = copy.deepcopy(self.evidence)
        evidence["artifacts"].reverse()
        self.assert_invalid(evidence=evidence)

        artifacts = dict(self.artifacts)
        artifacts["extra.json"] = b"extra"
        self.assert_invalid(artifacts=artifacts)

    def test_precondition_retry_and_stale_outcome_fail_closed(self) -> None:
        mutations = (
            ("head_precondition_kind", "if_none_match"),
            ("stale_precondition", "different-etag"),
            ("stale_outcome", "http_200_ok"),
            ("stale_automatic_retry_count", 1),
            ("success_outcome", "unknown"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence["execution"]["head"][field] = value
                self.assert_invalid(evidence=evidence)

    def test_readback_version_and_payload_drift_fail_closed(self) -> None:
        mutations = (
            ("entry", "readback_payload_sha256", "0" * 64),
            ("entry", "readback_version_identity", "wrong-version"),
            ("head", "readback_head_value", "head-fixture-0000"),
            ("head", "readback_payload_sha256", "0" * 64),
            ("delete_denial", "post_denial_payload_sha256", "0" * 64),
            ("delete_denial", "post_denial_version_identity", "wrong-version"),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence["execution"][section][field] = value
                self.assert_invalid(evidence=evidence)

    def test_cross_host_retention_delete_and_timeline_fail_closed(self) -> None:
        evidence = copy.deepcopy(self.evidence)
        evidence["actors"]["stale_writer_host_ref"] = evidence["actors"][
            "successful_writer_host_ref"
        ]
        self.assert_invalid(evidence=evidence)

    def test_selection_binding_request_identity_and_retention_horizon_fail_closed(
        self,
    ) -> None:
        for field in ("selection_profile_sha256", "selection_policy_sha256"):
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence[field] = "0" * 64
                self.assert_invalid(evidence=evidence)

        evidence = copy.deepcopy(self.evidence)
        evidence["execution"]["head"]["stale_request_id"] = evidence["execution"][
            "head"
        ]["success_request_id"]
        self.assert_invalid(evidence=evidence)

        evidence = copy.deepcopy(self.evidence)
        evidence["execution"]["retention"]["protected_until"] = evidence["review"][
            "valid_until"
        ]
        self.assert_invalid(evidence=evidence)

        for section, field, value in (
            ("retention", "locked", False),
            ("delete_denial", "outcome", "succeeded"),
            ("cross_host_review", "fork_detected", True),
            ("cross_host_review", "rollback_detected", True),
        ):
            with self.subTest(section=section, field=field):
                evidence = copy.deepcopy(self.evidence)
                evidence["execution"][section][field] = value
                self.assert_invalid(evidence=evidence)

        evidence = copy.deepcopy(self.evidence)
        evidence["execution"]["head"]["stale_observed_at"] = evidence["execution"][
            "head"
        ]["success_observed_at"]
        self.assert_invalid(evidence=evidence)

    def test_policy_profile_manifest_pins_and_closed_json_are_required(self) -> None:
        evidence_raw = SYNTHETIC_EVIDENCE.read_bytes()
        with self.assertRaises(ProviderCasEvidenceError):
            verify_provider_cas_evidence_bytes(
                selection_policy_raw=SELECTION_POLICY.read_bytes(),
                selection_profile_raw=SYNTHETIC_PROFILE.read_bytes(),
                policy_raw=POLICY.read_bytes(),
                evidence_raw=evidence_raw,
                artifact_bytes=self.artifacts,
                expected_policy_sha256="0" * 64,
                expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
                allow_synthetic=True,
            )

        evidence = copy.deepcopy(self.evidence)
        evidence["unexpected"] = True
        self.assert_invalid(evidence=evidence)

        duplicate = evidence_raw.replace(
            b'{\n  "actors":', b'{\n  "schema_version": 1,\n  "actors":', 1
        )
        with self.assertRaises(ProviderCasEvidenceError):
            verify_provider_cas_evidence_bytes(
                selection_policy_raw=SELECTION_POLICY.read_bytes(),
                selection_profile_raw=SYNTHETIC_PROFILE.read_bytes(),
                policy_raw=POLICY.read_bytes(),
                evidence_raw=duplicate,
                artifact_bytes=self.artifacts,
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                expected_evidence_sha256=hashlib.sha256(duplicate).hexdigest(),
                allow_synthetic=True,
            )

    def test_real_package_shape_remains_negative_authority(self) -> None:
        profile, evidence, artifacts = self.real_package()
        result = self.verify(
            profile=profile, evidence=evidence, artifacts=artifacts, synthetic=False
        )
        self.assertTrue(result.evidence_shape_verified)
        self.assertTrue(result.artifact_bytes_bound)
        self.assertFalse(result.provider_native_cas_verified)
        self.assertFalse(result.provider_custody_verified)
        self.assertFalse(result.production_acceptance)

    def test_real_package_rejects_synthetic_raw_artifact(self) -> None:
        profile, evidence, artifacts = self.real_package()
        first = evidence["artifacts"][0]
        artifacts[first["path"]] = self.artifacts[first["path"]]
        first["raw_sha256"] = hashlib.sha256(artifacts[first["path"]]).hexdigest()
        first["size"] = len(artifacts[first["path"]])
        self.assert_invalid(
            profile=profile, evidence=evidence, artifacts=artifacts, synthetic=False
        )

    def test_external_package_is_exact_repository_external_and_single_link(self) -> None:
        profile, evidence, artifacts = self.real_package()
        profile_raw = canonical(profile)
        evidence_raw = canonical(evidence)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            profile_path = base / "provider-selection.json"
            root = base / "provider-cas-package"
            root.mkdir()
            manifest_path = root / EXTERNAL_MANIFEST_NAME
            profile_path.write_bytes(profile_raw)
            manifest_path.write_bytes(evidence_raw)
            for name, raw in artifacts.items():
                (root / name).write_bytes(raw)
            result = verify_external_evidence_package(
                selection_profile_path=profile_path,
                evidence_manifest_path=manifest_path,
                evidence_root=root,
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_selection_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
                expected_evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
            )
            self.assertEqual(result.artifact_count, 9)

            extra = root / "extra.txt"
            extra.write_text("extra", encoding="utf-8")
            with self.assertRaises(ProviderCasEvidenceError):
                verify_external_evidence_package(
                    selection_profile_path=profile_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=root,
                    expected_policy_sha256=EXPECTED_POLICY_SHA256,
                    expected_selection_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
                    expected_evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
                )
            extra.unlink()

            hardlink = base / "retained-hardlink.json"
            try:
                os.link(root / "immutable-entry-write.json", hardlink)
            except OSError:
                self.skipTest("hard links unavailable")
            with self.assertRaises(ProviderCasEvidenceError):
                verify_external_evidence_package(
                    selection_profile_path=profile_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=root,
                    expected_policy_sha256=EXPECTED_POLICY_SHA256,
                    expected_selection_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
                    expected_evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
                )

    def test_relative_and_repository_paths_are_rejected(self) -> None:
        with self.assertRaises(ProviderCasEvidenceError):
            verify_external_evidence_package(
                selection_profile_path=Path("provider-selection.json"),
                evidence_manifest_path=Path("evidence.json"),
                evidence_root=Path("evidence"),
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
            )

    def test_external_symlink_input_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_link = Path(directory) / "provider-selection-link.json"
            try:
                profile_link.symlink_to(SYNTHETIC_PROFILE.resolve())
            except OSError:
                self.skipTest("symbolic links unavailable")
            with self.assertRaises(ProviderCasEvidenceError):
                verify_external_evidence_package(
                    selection_profile_path=profile_link,
                    evidence_manifest_path=Path(directory) / EXTERNAL_MANIFEST_NAME,
                    evidence_root=Path(directory),
                    expected_policy_sha256=EXPECTED_POLICY_SHA256,
                    expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                    expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
                )
        with self.assertRaises(ProviderCasEvidenceError):
            verify_external_evidence_package(
                selection_profile_path=SYNTHETIC_PROFILE.resolve(),
                evidence_manifest_path=SYNTHETIC_EVIDENCE.resolve(),
                evidence_root=SYNTHETIC_ARTIFACT_ROOT.resolve(),
                expected_policy_sha256=EXPECTED_POLICY_SHA256,
                expected_selection_profile_sha256=EXPECTED_SYNTHETIC_PROFILE_SHA256,
                expected_evidence_sha256=EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
            )


if __name__ == "__main__":
    unittest.main()
