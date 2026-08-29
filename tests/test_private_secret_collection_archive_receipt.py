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

from scripts import private_secret_collection_archive_receipt as archive
from scripts import private_secret_collection_review_decision as review
from tests import test_private_secret_collection_review_decision as review_tests


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


class CollectionArchiveReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.review_fixture = review_tests.CollectionReviewDecisionTests(
            "test_configured_path_and_cli_authenticate_exact_projection_only"
        )
        self.review_fixture.setUp()
        self.root = self.review_fixture.root
        self.verified_review = self.review_fixture._verify_bytes()
        self.provider_private = Ed25519PrivateKey.generate()
        self.custody_private = Ed25519PrivateKey.generate()
        self.source_raw = archive.SOURCE.read_bytes()
        self.source_sha = hashlib.sha256(self.source_raw).hexdigest()
        self.archive_raw = b"archive-readback-index-148\n"
        self.config_raw = b"provider-configuration-snapshot-148\n"
        self.retention_raw = b"retention-observation-snapshot-148\n"
        self.archive_path = self.root / "archive-readback.bin"
        self.config_path = self.root / "provider-config.bin"
        self.retention_path = self.root / "retention-snapshot.bin"
        self.archive_path.write_bytes(self.archive_raw)
        self.config_path.write_bytes(self.config_raw)
        self.retention_path.write_bytes(self.retention_raw)
        self.policy_path = self.root / "archive-policy.json"
        self.receipt_path = self.root / "archive-receipt.json"
        self.receipt_id = "14800000-0000-4000-8000-000000000148"
        self.ledger_id = "collection-archive-ledger-148"
        self.verification_time = "2026-08-27T08:05:00Z"
        self._configure(sequence=1, prior_raw=None)

    def tearDown(self) -> None:
        self.review_fixture.tearDown()

    def _anchor(
        self, private: Ed25519PrivateKey, *, domain: str, usage_scope: str
    ) -> dict[str, str]:
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "algorithm": "Ed25519",
            "key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(),
            "public_key_b64url": base64.urlsafe_b64encode(public)
            .rstrip(b"=")
            .decode(),
            "signature_domain": domain,
            "usage_scope": usage_scope,
        }

    def _policy_document(
        self,
        *,
        provider_private: Ed25519PrivateKey | None = None,
        custody_private: Ed25519PrivateKey | None = None,
        changes: dict[str, object] | None = None,
    ) -> dict[str, object]:
        provider = provider_private or self.provider_private
        custody = custody_private or self.custody_private
        policy: dict[str, object] = {
            "schema_version": 1,
            "policy_kind": archive.POLICY_KIND,
            "synthetic": False,
            "policy_status": "reviewed",
            "policy_effect": "offline_archive_receipt_authentication_only",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "archive_contract": {
                "provider_kind": "aws_s3_object_lock",
                "ledger_id": self.ledger_id,
                "write_mode": "create_only",
                "immutable_version_required": True,
                "required_retention_mode": "compliance",
            },
            "provider_signer": self._anchor(
                provider,
                domain=archive.PROVIDER_DOMAIN,
                usage_scope="private_secret_collection_archive_provider_v1_only",
            ),
            "custody_signer": self._anchor(
                custody,
                domain=archive.CUSTODY_DOMAIN,
                usage_scope="private_secret_collection_archive_custody_v1_only",
            ),
            "verifier_identity": {
                "archive_source_sha256": self.source_sha,
                "review_source_sha256": self.verified_review.verifier_source_sha256,
                "release_commit": self.verified_review.release_commit,
                "release_manifest_sha256": self.verified_review.release_manifest_sha256,
            },
            "time_constraints": {
                "max_policy_to_archive_seconds": 3600,
                "max_archive_to_readback_seconds": 3600,
                "max_receipt_validity_seconds": 3600,
            },
            "review": {
                "reviewer_reference": "archive-policy-review-148",
                "reviewed_at": "2026-08-27T08:02:00Z",
                "decision": "approved_for_archive_receipt_authentication",
            },
        }
        if changes:
            policy.update(changes)
        return seal(policy)

    def _receipt_document(
        self,
        *,
        policy_sha: str,
        sequence: int,
        prior_sha: str,
        prior_checkpoint_sha: str,
        receipt_id: str | None = None,
        decision_id: str | None = None,
        archive_sha: str | None = None,
        object_reference: str = "archive/object/148-current",
        immutable_version_reference: str = "archive-version-148-current",
        payload_changes: dict[str, object] | None = None,
        provider_private: Ed25519PrivateKey | None = None,
        custody_private: Ed25519PrivateKey | None = None,
    ) -> dict[str, object]:
        provider = provider_private or self.provider_private
        custody = custody_private or self.custody_private
        payload: dict[str, object] = {
            "receipt_id": receipt_id or self.receipt_id,
            "decision_id": decision_id or self.verified_review.decision_id,
            "provider_reference": "provider-observation-148",
            "custody_reference": "custody-observation-148",
            "archived_at": "2026-08-27T08:03:00Z",
            "readback_at": "2026-08-27T08:04:00Z",
            "expires_at": "2026-08-27T09:03:00Z",
            "archive_policy_sha256": policy_sha,
            "review_decision_sha256": self.verified_review.decision_sha256,
            "review_policy_sha256": self.verified_review.policy_sha256,
            "input_manifest_sha256": self.verified_review.input_manifest_sha256,
            "review_verifier_source_sha256": self.verified_review.verifier_source_sha256,
            "archive_verifier_source_sha256": self.source_sha,
            "release_commit": self.verified_review.release_commit,
            "release_manifest_sha256": self.verified_review.release_manifest_sha256,
            "archive_readback_sha256": archive_sha
            or hashlib.sha256(self.archive_raw).hexdigest(),
            "provider_config_sha256": hashlib.sha256(self.config_raw).hexdigest(),
            "retention_snapshot_sha256": hashlib.sha256(self.retention_raw).hexdigest(),
            "provider_kind": "aws_s3_object_lock",
            "storage_identity_fingerprint_sha256": "8" * 64,
            "object_reference": object_reference,
            "immutable_version_reference": immutable_version_reference,
            "write_mode": "create_only",
            "retention_mode": "compliance",
            "ledger_id": self.ledger_id,
            "sequence": sequence,
            "prior_receipt_sha256": prior_sha,
            "prior_checkpoint_sha256": prior_checkpoint_sha,
        }
        if payload_changes:
            payload.update(payload_changes)
        checkpoint = archive._checkpoint_for(payload)
        provider_signature = provider.sign(
            archive.PROVIDER_DOMAIN.encode("ascii") + b"\0" + canonical(payload)
        )
        custody_signature = custody.sign(
            archive.CUSTODY_DOMAIN.encode("ascii") + b"\0" + canonical(checkpoint)
        )
        return seal(
            {
                "schema_version": 1,
                "receipt_kind": archive.RECEIPT_KIND,
                "synthetic": False,
                "receipt_status": "reviewed",
                "production_acceptance": False,
                "not_committed_eligible": False,
                "payload": payload,
                "provider_signature": {
                    "algorithm": "Ed25519",
                    "key_id": self._anchor(
                        provider,
                        domain=archive.PROVIDER_DOMAIN,
                        usage_scope="private_secret_collection_archive_provider_v1_only",
                    )["key_id"],
                    "value_b64url": base64.urlsafe_b64encode(provider_signature)
                    .rstrip(b"=")
                    .decode(),
                },
                "custody_checkpoint": checkpoint,
                "custody_signature": {
                    "algorithm": "Ed25519",
                    "key_id": self._anchor(
                        custody,
                        domain=archive.CUSTODY_DOMAIN,
                        usage_scope="private_secret_collection_archive_custody_v1_only",
                    )["key_id"],
                    "value_b64url": base64.urlsafe_b64encode(custody_signature)
                    .rstrip(b"=")
                    .decode(),
                },
                "claim_boundary": {
                    field: "unverified" for field in archive._CLAIM_FIELDS
                },
                "prohibited_content": {
                    field: False for field in archive._PROHIBITED_FIELDS
                },
            }
        )

    def _configure(
        self,
        *,
        sequence: int,
        prior_raw: bytes | None,
        policy_changes: dict[str, object] | None = None,
        payload_changes: dict[str, object] | None = None,
        provider_private: Ed25519PrivateKey | None = None,
        custody_private: Ed25519PrivateKey | None = None,
    ) -> None:
        self.policy = self._policy_document(
            provider_private=provider_private,
            custody_private=custody_private,
            changes=policy_changes,
        )
        self.policy_raw = raw_json(self.policy)
        self.policy_sha = hashlib.sha256(self.policy_raw).hexdigest()
        self.prior_raw = prior_raw
        self.prior_sha = (
            hashlib.sha256(prior_raw).hexdigest()
            if prior_raw is not None
            else archive.ZERO_SHA256
        )
        self.prior_checkpoint_sha = (
            archive._canonical_digest(json.loads(prior_raw)["custody_checkpoint"])
            if prior_raw is not None
            else archive.ZERO_SHA256
        )
        self.receipt = self._receipt_document(
            policy_sha=self.policy_sha,
            sequence=sequence,
            prior_sha=self.prior_sha,
            prior_checkpoint_sha=self.prior_checkpoint_sha,
            payload_changes=payload_changes,
            provider_private=provider_private,
            custody_private=custody_private,
        )
        self.receipt_raw = raw_json(self.receipt)
        self.receipt_sha = hashlib.sha256(self.receipt_raw).hexdigest()
        self.policy_path.write_bytes(self.policy_raw)
        self.receipt_path.write_bytes(self.receipt_raw)
        self.prior_path = self.root / "prior-archive-receipt.json"
        if prior_raw is not None:
            self.prior_path.write_bytes(prior_raw)

    def _pins(self, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "expected_receipt_sha256": self.receipt_sha,
            "expected_policy_sha256": self.policy_sha,
            "expected_archive_readback_sha256": hashlib.sha256(self.archive_raw).hexdigest(),
            "expected_provider_config_sha256": hashlib.sha256(self.config_raw).hexdigest(),
            "expected_retention_snapshot_sha256": hashlib.sha256(self.retention_raw).hexdigest(),
            "expected_verifier_source_sha256": self.source_sha,
            "expected_prior_receipt_sha256": self.prior_sha,
            "expected_prior_checkpoint_sha256": self.prior_checkpoint_sha,
            "expected_review_decision_sha256": self.verified_review.decision_sha256,
            "expected_review_policy_sha256": self.verified_review.policy_sha256,
            "expected_input_manifest_sha256": self.verified_review.input_manifest_sha256,
            "expected_review_verifier_source_sha256": self.verified_review.verifier_source_sha256,
            "expected_release_commit": self.verified_review.release_commit,
            "expected_release_manifest_sha256": self.verified_review.release_manifest_sha256,
            "expected_decision_id": self.verified_review.decision_id,
            "expected_receipt_id": self.receipt_id,
            "expected_ledger_id": self.ledger_id,
            "expected_sequence": self.receipt["payload"]["sequence"],
            "verification_time": self.verification_time,
        }
        values.update(changes)
        return values

    def _verify_bytes(
        self,
        verified_review: review.VerifiedReviewDecision | None = None,
        **pins: object,
    ) -> archive.VerifiedArchiveReceipt:
        return archive.verify_archive_receipt_bytes(
            receipt_raw=self.receipt_raw,
            policy_raw=self.policy_raw,
            archive_readback_raw=self.archive_raw,
            provider_config_raw=self.config_raw,
            retention_snapshot_raw=self.retention_raw,
            verifier_source_raw=self.source_raw,
            verified_review=verified_review or self.verified_review,
            prior_receipt_raw=self.prior_raw,
            **self._pins(**pins),
        )

    def _verify_path(self, **pins: object) -> archive.VerifiedArchiveReceipt:
        with mock.patch.object(
            review, "verify_decision", return_value=self.verified_review
        ) as upstream:
            result = archive.verify_archive_receipt(
                self.receipt_path,
                self.policy_path,
                self.archive_path,
                self.config_path,
                self.retention_path,
                self.review_fixture.decision_path,
                self.review_fixture.policy_path,
                self.review_fixture.manifest_path,
                prior_receipt_path=self.prior_path if self.prior_raw is not None else None,
                **self._pins(**pins),
            )
        upstream.assert_called_once()
        return result

    def test_repository_templates_and_cli_are_pending(self) -> None:
        policy, receipt = archive.verify_repository_assets()
        self.assertTrue(policy["synthetic"])
        self.assertTrue(receipt["synthetic"])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = archive.main(["verify-repository"])
        self.assertEqual(status, 0)
        self.assertIn("provider-signature=unverified", stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_genesis_path_core_and_cli_authenticate_exact_bytes(self) -> None:
        result = self._verify_path()
        self.assertEqual(result.receipt_id, self.receipt_id)
        self.assertEqual(result.sequence, 1)
        self.assertEqual(result.prior_receipt_sha256, archive.ZERO_SHA256)
        self.assertFalse(result.production_acceptance)
        core = self._verify_bytes()
        self.assertEqual(core.head_sha256, result.head_sha256)

        args = [
            "verify",
            "--receipt", str(self.receipt_path),
            "--policy", str(self.policy_path),
            "--archive-readback", str(self.archive_path),
            "--provider-config", str(self.config_path),
            "--retention-snapshot", str(self.retention_path),
            "--review-decision", str(self.review_fixture.decision_path),
            "--review-policy", str(self.review_fixture.policy_path),
            "--input-manifest", str(self.review_fixture.manifest_path),
        ]
        for name, value in self._pins().items():
            args.extend(["--" + name.replace("_", "-"), str(value)])
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(
            review, "verify_decision", return_value=self.verified_review
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            status = archive.main(args)
        self.assertEqual(status, 0)
        self.assertIn("provider-signature=verified", stdout.getvalue())
        self.assertIn("one-hop-chain=verified", stdout.getvalue())
        self.assertIn("provider-native=unverified", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_pure_core_has_no_file_or_upstream_io(self) -> None:
        with mock.patch.object(archive, "_read_blob") as reader, mock.patch.object(
            archive, "_unchanged"
        ) as unchanged, mock.patch.object(review, "verify_decision") as upstream:
            result = self._verify_bytes()
        self.assertEqual(result.sequence, 1)
        reader.assert_not_called()
        unchanged.assert_not_called()
        upstream.assert_not_called()

    def test_all_local_raw_pins_fail_before_t147(self) -> None:
        fields = (
            "expected_receipt_sha256", "expected_policy_sha256",
            "expected_archive_readback_sha256", "expected_provider_config_sha256",
            "expected_retention_snapshot_sha256", "expected_verifier_source_sha256",
            "expected_prior_receipt_sha256",
        )
        for field in fields:
            with self.subTest(field=field), mock.patch.object(
                review, "verify_decision"
            ) as upstream:
                with self.assertRaises(archive.CollectionArchiveReceiptError):
                    archive.verify_archive_receipt(
                        self.receipt_path,
                        self.policy_path,
                        self.archive_path,
                        self.config_path,
                        self.retention_path,
                        self.review_fixture.decision_path,
                        self.review_fixture.policy_path,
                        self.review_fixture.manifest_path,
                        prior_receipt_path=None,
                        **self._pins(**{field: "f" * 64}),
                    )
                upstream.assert_not_called()

    def test_provider_and_custody_keys_cannot_reuse_review_chain_roles(self) -> None:
        provider_id = self.policy["provider_signer"]["key_id"]
        custody_id = self.policy["custody_signer"]["key_id"]
        candidates = (
            replace(self.verified_review, reviewer_key_id=provider_id),
            replace(
                self.verified_review,
                upstream_key_ids=(
                    provider_id, *self.verified_review.upstream_key_ids[1:]
                ),
            ),
            replace(self.verified_review, reviewer_key_id=custody_id),
            replace(
                self.verified_review,
                upstream_key_ids=(
                    custody_id, *self.verified_review.upstream_key_ids[1:]
                ),
            ),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                archive.CollectionArchiveReceiptError
            ):
                self._verify_bytes(candidate)

        self._configure(
            sequence=1,
            prior_raw=None,
            custody_private=self.provider_private,
        )
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            self._verify_bytes()

    def _prior_receipt(
        self,
        *,
        decision_id: str = "14800000-0000-4000-8000-000000000147",
        archive_sha: str = "a" * 64,
        object_reference: str = "archive/object/148-prior",
        immutable_version_reference: str = "archive-version-148-prior",
        sequence: int = 1,
    ) -> bytes:
        prior = self._receipt_document(
            policy_sha=self.policy_sha,
            sequence=sequence,
            prior_sha=archive.ZERO_SHA256,
            prior_checkpoint_sha=archive.ZERO_SHA256,
            receipt_id="14800000-0000-4000-8000-000000000147",
            decision_id=decision_id,
            archive_sha=archive_sha,
            object_reference=object_reference,
            immutable_version_reference=immutable_version_reference,
        )
        return raw_json(prior)

    def test_next_sequence_accepts_one_prior_and_rejects_replay_aba_or_fork(self) -> None:
        prior_raw = self._prior_receipt()
        self._configure(sequence=2, prior_raw=prior_raw)
        result = self._verify_bytes()
        self.assertEqual(result.sequence, 2)
        self.assertEqual(result.prior_receipt_sha256, hashlib.sha256(prior_raw).hexdigest())

        attacks = (
            self._prior_receipt(decision_id=self.verified_review.decision_id),
            self._prior_receipt(
                archive_sha=hashlib.sha256(self.archive_raw).hexdigest()
            ),
            self._prior_receipt(object_reference="archive/object/148-current"),
            self._prior_receipt(
                immutable_version_reference="archive-version-148-current"
            ),
            self._prior_receipt(sequence=2),
        )
        for prior in attacks:
            with self.subTest(prior=prior[:50]):
                self._configure(sequence=2, prior_raw=prior)
                with self.assertRaises(archive.CollectionArchiveReceiptError):
                    self._verify_bytes()

        self._configure(sequence=2, prior_raw=prior_raw)
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            self._verify_bytes(expected_prior_receipt_sha256="f" * 64)
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            self._verify_bytes(expected_prior_checkpoint_sha256="e" * 64)

    def test_cross_decision_release_snapshot_and_signature_mutations_fail(self) -> None:
        attacks = (
            {"review_decision_sha256": "f" * 64},
            {"review_policy_sha256": "e" * 64},
            {"input_manifest_sha256": "d" * 64},
            {"review_verifier_source_sha256": "c" * 64},
            {"archive_readback_sha256": "b" * 64},
            {"provider_config_sha256": "a" * 64},
            {"retention_snapshot_sha256": "9" * 64},
            {"release_commit": "b" * 40},
        )
        for changes in attacks:
            with self.subTest(changes=changes):
                self._configure(sequence=1, prior_raw=None, payload_changes=changes)
                with self.assertRaises(archive.CollectionArchiveReceiptError):
                    self._verify_bytes()

        self._configure(sequence=1, prior_raw=None)
        changed = json.loads(self.receipt_raw)
        signature = changed["provider_signature"]["value_b64url"]
        changed["provider_signature"]["value_b64url"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
        changed = seal(changed)
        self.receipt_raw = raw_json(changed)
        self.receipt_sha = hashlib.sha256(self.receipt_raw).hexdigest()
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            self._verify_bytes()

    def test_time_reference_schema_duplicate_and_type_attacks_fail(self) -> None:
        for changes in (
            {"archived_at": "2026-08-27T08:01:59Z"},
            {"readback_at": "2026-08-27T09:03:01Z"},
            {"expires_at": "2026-08-27T09:03:01Z"},
            {"provider_reference": "archive-policy-review-148"},
            {"custody_reference": "provider-observation-148"},
            {"sequence": True},
        ):
            with self.subTest(changes=changes):
                self._configure(sequence=1, prior_raw=None, payload_changes=changes)
                with self.assertRaises(archive.CollectionArchiveReceiptError):
                    self._verify_bytes()

        duplicate = b'{"schema_version":1,"schema_version":1}'
        self.receipt_raw = duplicate
        self.receipt_sha = hashlib.sha256(duplicate).hexdigest()
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            self._verify_bytes()
        with self.assertRaises(archive.CollectionArchiveReceiptError):
            archive.verify_archive_receipt_bytes(
                receipt_raw="not-bytes",  # type: ignore[arg-type]
                policy_raw=self.policy_raw,
                archive_readback_raw=self.archive_raw,
                provider_config_raw=self.config_raw,
                retention_snapshot_raw=self.retention_raw,
                verifier_source_raw=self.source_raw,
                verified_review=self.verified_review,
                prior_receipt_raw=None,
                **self._pins(),
            )

    def test_path_alias_hardlink_and_same_byte_replacement_fail(self) -> None:
        with mock.patch.object(review, "verify_decision") as upstream, self.assertRaises(
            archive.CollectionArchiveReceiptError
        ):
            archive.verify_archive_receipt(
                self.receipt_path,
                self.policy_path,
                self.archive_path,
                self.archive_path,
                self.retention_path,
                self.review_fixture.decision_path,
                self.review_fixture.policy_path,
                self.review_fixture.manifest_path,
                prior_receipt_path=None,
                **self._pins(),
            )
        upstream.assert_not_called()

        alias = self.root / "receipt-hardlink.json"
        try:
            os.link(self.receipt_path, alias)
        except OSError as error:
            self.skipTest(f"hardlinks unavailable: {error}")
        try:
            with mock.patch.object(
                review, "verify_decision", return_value=self.verified_review
            ), self.assertRaises(archive.CollectionArchiveReceiptError):
                archive.verify_archive_receipt(
                    alias,
                    self.policy_path,
                    self.archive_path,
                    self.config_path,
                    self.retention_path,
                    self.review_fixture.decision_path,
                    self.review_fixture.policy_path,
                    self.review_fixture.manifest_path,
                    prior_receipt_path=None,
                    **self._pins(),
                )
        finally:
            alias.unlink(missing_ok=True)

        replacement = self.root / "receipt-replacement.json"
        replacement.write_bytes(self.receipt_raw)

        def replace_during_review(*args: object, **kwargs: object):
            os.replace(replacement, self.receipt_path)
            return self.verified_review

        with mock.patch.object(
            review, "verify_decision", side_effect=replace_during_review
        ), self.assertRaises(archive.CollectionArchiveReceiptError):
            archive.verify_archive_receipt(
                self.receipt_path,
                self.policy_path,
                self.archive_path,
                self.config_path,
                self.retention_path,
                self.review_fixture.decision_path,
                self.review_fixture.policy_path,
                self.review_fixture.manifest_path,
                prior_receipt_path=None,
                **self._pins(),
            )

    def test_failure_output_is_fixed_and_redacted(self) -> None:
        secret = "must-not-appear"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = archive.main(
                [
                    "verify",
                    "--receipt", str(self.receipt_path),
                    "--policy", str(self.policy_path),
                    "--archive-readback", str(self.archive_path),
                    "--provider-config", str(self.config_path),
                    "--retention-snapshot", str(self.retention_path),
                    "--review-decision", str(self.review_fixture.decision_path),
                    "--review-policy", str(self.review_fixture.policy_path),
                    "--input-manifest", str(self.review_fixture.manifest_path),
                    "--expected-receipt-sha256", secret,
                ]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "private-secret-collection-archive-failed\n")
        self.assertNotIn(secret, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
