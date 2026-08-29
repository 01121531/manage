from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import private_secret_collection_backed_acceptance as backed
from scripts import private_secret_collection_review_decision as review
from scripts import private_secret_github_rest_collection as github
from scripts import private_secret_worm_collection as worm
from tests import test_private_secret_collection_backed_acceptance as backed_tests


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def raw_json(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"


def seal(value: dict[str, object]) -> dict[str, object]:
    payload = {key: item for key, item in value.items() if key != "integrity"}
    return {
        **payload,
        "integrity": {"payload_sha256": hashlib.sha256(canonical(payload)).hexdigest()},
    }


class CollectionReviewDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backed_fixture = backed_tests.CollectionBackedAcceptanceTests(
            "test_invokes_both_verifiers_and_reconciles_frozen_results"
        )
        self.backed_fixture.setUp()
        self.root = self.backed_fixture.root
        self.manifest_raw = self.backed_fixture._manifest_raw()
        self.manifest_path = self.root / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_raw)
        self.manifest_sha = hashlib.sha256(self.manifest_raw).hexdigest()
        with mock.patch.object(
            github,
            "verify_collection_bytes",
            return_value=self.backed_fixture.github_result,
        ), mock.patch.object(
            worm,
            "verify_collection_bytes",
            return_value=self.backed_fixture.worm_result,
        ):
            self.projection = backed.verify_input_manifest_projection(
                self.manifest_path,
                expected_manifest_sha256=self.manifest_sha,
            )

        self.private = Ed25519PrivateKey.generate()
        self.source_raw = review.SOURCE.read_bytes()
        self.source_sha = hashlib.sha256(self.source_raw).hexdigest()
        self.decision_path = self.root / "review-decision.json"
        self.policy_path = self.root / "review-policy.json"
        self.decision_id = "14700000-0000-4000-8000-000000000147"
        self.verification_time = "2026-08-27T08:02:00Z"
        self._configure(self.projection)

    def tearDown(self) -> None:
        self.backed_fixture.tearDown()

    def _anchor(self, private: Ed25519PrivateKey) -> dict[str, str]:
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "algorithm": "Ed25519",
            "key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(),
            "public_key_b64url": base64.urlsafe_b64encode(public)
            .rstrip(b"=")
            .decode(),
            "signature_domain": review.SIGNATURE_DOMAIN,
            "usage_scope": "private_secret_collection_review_v1_only",
        }

    def _configure(
        self,
        projection: backed.VerifiedCollectionBackedAcceptance,
        *,
        private: Ed25519PrivateKey | None = None,
        payload_changes: dict[str, object] | None = None,
        policy_changes: dict[str, object] | None = None,
    ) -> None:
        signer = private or self.private
        anchor = self._anchor(signer)
        readiness = projection.readiness
        policy: dict[str, object] = {
            "schema_version": 1,
            "policy_kind": review.POLICY_KIND,
            "synthetic": False,
            "policy_status": "reviewed",
            "policy_effect": "offline_review_authentication_only",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "reviewer": anchor,
            "verifier_identity": {
                "source_sha256": self.source_sha,
                "release_commit": readiness.release_commit,
                "release_manifest_sha256": readiness.release_manifest_sha256,
            },
            "time_constraints": {
                "max_policy_to_decision_seconds": 3600,
                "max_decision_validity_seconds": 3600,
            },
            "review": {
                "reviewer_reference": "change-ticket-143",
                "reviewed_at": "2026-08-27T08:00:00Z",
                "decision": "approved_for_external_review_authentication",
            },
        }
        if policy_changes:
            policy.update(policy_changes)
        self.policy = seal(policy)
        self.policy_raw = raw_json(self.policy)
        self.policy_sha = hashlib.sha256(self.policy_raw).hexdigest()

        payload: dict[str, object] = {
            "decision_id": self.decision_id,
            "reviewer_reference": "review-session-147",
            "reviewed_at": "2026-08-27T08:01:00Z",
            "expires_at": "2026-08-27T09:01:00Z",
            "policy_sha256": self.policy_sha,
            "input_manifest_sha256": projection.manifest_sha256,
            **review._projection_digests(projection),
            "release_commit": readiness.release_commit,
            "release_manifest_sha256": readiness.release_manifest_sha256,
            "verifier_source_sha256": self.source_sha,
        }
        if payload_changes:
            payload.update(payload_changes)
        signature = signer.sign(
            review.SIGNATURE_DOMAIN.encode("ascii") + b"\0" + canonical(payload)
        )
        self.decision = seal(
            {
                "schema_version": 1,
                "decision_kind": review.DECISION_KIND,
                "synthetic": False,
                "decision_status": "reviewed",
                "production_acceptance": False,
                "not_committed_eligible": False,
                "payload": payload,
                "signature": {
                    "algorithm": "Ed25519",
                    "key_id": anchor["key_id"],
                    "value_b64url": base64.urlsafe_b64encode(signature)
                    .rstrip(b"=")
                    .decode(),
                },
                "claim_boundary": {
                    field: "unverified" for field in review._CLAIM_BOUNDARY_FIELDS
                },
                "prohibited_content": {
                    field: False for field in review._PROHIBITED_FIELDS
                },
            }
        )
        self.decision_raw = raw_json(self.decision)
        self.decision_sha = hashlib.sha256(self.decision_raw).hexdigest()
        self.policy_path.write_bytes(self.policy_raw)
        self.decision_path.write_bytes(self.decision_raw)

    def _pins(self, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "expected_decision_sha256": self.decision_sha,
            "expected_policy_sha256": self.policy_sha,
            "expected_input_manifest_sha256": self.manifest_sha,
            "expected_verifier_source_sha256": self.source_sha,
            "expected_release_commit": self.projection.readiness.release_commit,
            "expected_release_manifest_sha256": (
                self.projection.readiness.release_manifest_sha256
            ),
            "expected_decision_id": self.decision_id,
            "verification_time": self.verification_time,
        }
        values.update(changes)
        return values

    def _verify(self, **pins: object) -> review.VerifiedReviewDecision:
        with mock.patch.object(
            backed, "verify_input_manifest_projection", return_value=self.projection
        ) as upstream:
            result = review.verify_decision(
                self.decision_path,
                self.policy_path,
                self.manifest_path,
                **self._pins(**pins),
            )
        upstream.assert_called_once_with(
            self.manifest_path, expected_manifest_sha256=self.manifest_sha
        )
        return result

    def _verify_bytes(
        self,
        projection: backed.VerifiedCollectionBackedAcceptance | None = None,
        **pins: object,
    ) -> review.VerifiedReviewDecision:
        return review.verify_decision_bytes(
            decision_raw=self.decision_raw,
            policy_raw=self.policy_raw,
            verifier_source_raw=self.source_raw,
            verified_acceptance=projection or self.projection,
            **self._pins(**pins),
        )

    def test_repository_templates_are_closed_pending_and_cli_safe(self) -> None:
        policy, decision = review.verify_repository_assets()
        self.assertTrue(policy["synthetic"])
        self.assertTrue(decision["synthetic"])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = review.main(["verify-repository"])
        self.assertEqual(status, 0)
        self.assertIn("reviewer-authentication=unverified", stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_configured_path_and_cli_authenticate_exact_projection_only(self) -> None:
        result = self._verify()
        self.assertEqual(result.decision_id, self.decision_id)
        self.assertEqual(result.input_manifest_sha256, self.manifest_sha)
        self.assertFalse(result.production_acceptance)

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(
            backed, "verify_input_manifest_projection", return_value=self.projection
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            status = review.main(
                [
                    "verify",
                    "--decision", str(self.decision_path),
                    "--policy", str(self.policy_path),
                    "--input-manifest", str(self.manifest_path),
                    "--expected-decision-sha256", self.decision_sha,
                    "--expected-policy-sha256", self.policy_sha,
                    "--expected-input-manifest-sha256", self.manifest_sha,
                    "--expected-verifier-source-sha256", self.source_sha,
                    "--expected-release-commit", self.projection.readiness.release_commit,
                    "--expected-release-manifest-sha256", self.projection.readiness.release_manifest_sha256,
                    "--expected-decision-id", self.decision_id,
                    "--verification-time", self.verification_time,
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("reviewer-authentication=verified", stdout.getvalue())
        self.assertIn("trusted-time=unverified", stdout.getvalue())
        self.assertIn("decision-id-uniqueness=unverified", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_pure_bytes_core_performs_no_file_io(self) -> None:
        with mock.patch.object(review, "_read_blob") as read_blob, mock.patch.object(
            review, "_unchanged"
        ) as unchanged, mock.patch.object(review, "read_stable_bytes") as stable_read:
            result = self._verify_bytes()
        self.assertEqual(result.decision_sha256, self.decision_sha)
        read_blob.assert_not_called()
        unchanged.assert_not_called()
        stable_read.assert_not_called()

    def test_raw_pins_fail_before_upstream_verification(self) -> None:
        for field in (
            "expected_decision_sha256",
            "expected_policy_sha256",
            "expected_verifier_source_sha256",
        ):
            with self.subTest(field=field), mock.patch.object(
                backed, "verify_input_manifest_projection"
            ) as upstream:
                with self.assertRaises(review.CollectionReviewDecisionError):
                    review.verify_decision(
                        self.decision_path,
                        self.policy_path,
                        self.manifest_path,
                        **self._pins(**{field: "f" * 64}),
                    )
                upstream.assert_not_called()

    def test_projection_release_manifest_and_decision_id_drift_fail(self) -> None:
        changed_projection = replace(
            self.projection,
            github_collection=replace(
                self.projection.github_collection, sequence=2
            ),
        )
        with self.assertRaises(review.CollectionReviewDecisionError):
            self._verify_bytes(changed_projection)
        for field, value in (
            ("expected_release_commit", "b" * 40),
            ("expected_release_manifest_sha256", "f" * 64),
            ("expected_decision_id", "14700000-0000-4000-8000-000000000148"),
            ("expected_input_manifest_sha256", "e" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(
                review.CollectionReviewDecisionError
            ):
                self._verify_bytes(**{field: value})

    def test_reviewer_key_cannot_reuse_any_upstream_role(self) -> None:
        reviewer_key_id = self._anchor(self.private)["key_id"]
        candidates = [
            replace(
                self.projection,
                t143_trust_anchor_key_ids=(
                    reviewer_key_id,
                    *self.projection.t143_trust_anchor_key_ids[1:],
                ),
            ),
            replace(
                self.projection,
                github_collection=replace(
                    self.projection.github_collection,
                    collector_key_id=reviewer_key_id,
                ),
            ),
            replace(
                self.projection,
                github_collection=replace(
                    self.projection.github_collection,
                    ledger_key_id=reviewer_key_id,
                ),
            ),
            replace(
                self.projection,
                worm_collection=replace(
                    self.projection.worm_collection,
                    provider_signer_key_id=reviewer_key_id,
                ),
            ),
            replace(
                self.projection,
                worm_collection=replace(
                    self.projection.worm_collection,
                    ledger_signer_key_id=reviewer_key_id,
                ),
            ),
        ]
        for projection in candidates:
            with self.subTest(projection=projection):
                self._configure(projection)
                with self.assertRaises(review.CollectionReviewDecisionError):
                    self._verify_bytes(projection)

    def test_signature_references_time_window_and_closed_fields_are_enforced(self) -> None:
        attacks = (
            ({"reviewer_reference": "change-ticket-143"}, None),
            ({"reviewed_at": "2026-08-27T07:59:59Z"}, None),
            ({"expires_at": "2026-08-27T09:01:01Z"}, None),
        )
        for payload_changes, policy_changes in attacks:
            with self.subTest(payload=payload_changes):
                self._configure(
                    self.projection,
                    payload_changes=payload_changes,
                    policy_changes=policy_changes,
                )
                with self.assertRaises(review.CollectionReviewDecisionError):
                    self._verify_bytes()

        self._configure(self.projection)
        changed = json.loads(self.decision_raw)
        changed["extra"] = "forbidden"
        changed = seal(changed)
        self.decision_raw = raw_json(changed)
        self.decision_sha = hashlib.sha256(self.decision_raw).hexdigest()
        with self.assertRaises(review.CollectionReviewDecisionError):
            self._verify_bytes()

    def test_duplicate_json_keys_and_invalid_raw_types_fail_closed(self) -> None:
        duplicate = b'{"schema_version":1,"schema_version":1}'
        self.decision_raw = duplicate
        self.decision_sha = hashlib.sha256(duplicate).hexdigest()
        with self.assertRaises(review.CollectionReviewDecisionError):
            self._verify_bytes()
        with self.assertRaises(review.CollectionReviewDecisionError):
            review.verify_decision_bytes(
                decision_raw="not-bytes",  # type: ignore[arg-type]
                policy_raw=self.policy_raw,
                verifier_source_raw=self.source_raw,
                verified_acceptance=self.projection,
                **self._pins(),
            )

    def test_external_hardlink_and_same_byte_inode_replacement_fail(self) -> None:
        alias = self.root / "decision-hardlink.json"
        try:
            os.link(self.decision_path, alias)
        except OSError as error:
            self.skipTest(f"hardlinks unavailable: {error}")
        try:
            with mock.patch.object(
                backed,
                "verify_input_manifest_projection",
                return_value=self.projection,
            ), self.assertRaises(review.CollectionReviewDecisionError):
                review.verify_decision(
                    alias,
                    self.policy_path,
                    self.manifest_path,
                    **self._pins(),
                )
        finally:
            alias.unlink(missing_ok=True)

        replacement = self.root / "replacement.json"
        replacement.write_bytes(self.decision_raw)

        def replace_during_upstream(*args: object, **kwargs: object):
            os.replace(replacement, self.decision_path)
            return self.projection

        with mock.patch.object(
            backed,
            "verify_input_manifest_projection",
            side_effect=replace_during_upstream,
        ), self.assertRaises(review.CollectionReviewDecisionError):
            review.verify_decision(
                self.decision_path,
                self.policy_path,
                self.manifest_path,
                **self._pins(),
            )

    def test_failure_output_is_fixed_and_redacted(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        secret = "must-not-appear"
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = review.main(
                [
                    "verify",
                    "--decision", str(self.decision_path),
                    "--policy", str(self.policy_path),
                    "--input-manifest", str(self.manifest_path),
                    "--expected-decision-sha256", secret,
                    "--expected-policy-sha256", self.policy_sha,
                    "--expected-input-manifest-sha256", self.manifest_sha,
                    "--expected-verifier-source-sha256", self.source_sha,
                    "--expected-release-commit", self.projection.readiness.release_commit,
                    "--expected-release-manifest-sha256", self.projection.readiness.release_manifest_sha256,
                    "--expected-decision-id", self.decision_id,
                    "--verification-time", self.verification_time,
                ]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(), "private-secret-collection-review-failed\n"
        )
        self.assertNotIn(secret, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
