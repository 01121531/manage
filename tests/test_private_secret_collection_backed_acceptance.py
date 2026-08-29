from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

from scripts import private_secret_collection_backed_acceptance as backed
from scripts import private_secret_github_rest_collection as github
from scripts import private_secret_worm_collection as worm
from tests.test_private_secret_collector_deployment import (
    CollectorDeploymentTests, SHA, SHA2, SHA3, SHA4, SHA5, SHA6, SHA7, SHA8, SHA9,
    raw_json,
)


class CollectionBackedAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CollectorDeploymentTests(
            "test_configured_policy_and_transaction_authenticate_only_assertions"
        )
        self.fixture.setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        readiness_payload = dict(self.fixture.readiness_payload)
        readiness_payload["current_worm_collection_head_sha256"] = SHA6
        self.readiness = self.fixture._readiness(readiness_payload)
        self.readiness_raw = raw_json(self.readiness)
        readiness_sha = hashlib.sha256(self.readiness_raw).hexdigest()
        execution_payload = dict(self.fixture.execution_payload)
        execution_payload["readiness_receipt_sha256"] = readiness_sha
        self.execution = self.fixture._execution(execution_payload)
        self.execution_raw = raw_json(self.execution)
        self.policy_path = self.root / "policy.json"
        self.readiness_path = self.root / "readiness.json"
        self.execution_path = self.root / "execution.json"
        self.policy_path.write_bytes(self.fixture.policy_raw)
        self.readiness_path.write_bytes(self.readiness_raw)
        self.execution_path.write_bytes(self.execution_raw)
        self.pins = {
            "expected_policy_sha256": hashlib.sha256(self.fixture.policy_raw).hexdigest(),
            "expected_readiness_sha256": readiness_sha,
            "expected_execution_sha256": hashlib.sha256(self.execution_raw).hexdigest(),
            "expected_request_sha256": SHA2,
            "expected_previous_github_collection_head_sha256": SHA4,
            "expected_current_worm_collection_head_sha256": SHA6,
            "expected_github_collection_head_sha256": SHA5,
            "expected_worm_collection_head_sha256": SHA6,
            "expected_collection_prior_head_sha256": SHA4,
            "expected_collection_ledger_id": "github-rest-ledger-142",
            "expected_collection_sequence": 1,
            "expected_prior_head_sha256": SHA7,
            "expected_ledger_id": "production-ledger-001",
            "expected_sequence": 42,
            "expected_prior_generation": "generation-0041",
        }
        names = sorted(backed._GITHUB_PATHS)
        self.github_inputs = {name: self.root / f"github-{index}.bin" for index, name in enumerate(names)}
        for name, path in self.github_inputs.items():
            path.write_bytes(f"github:{name}".encode("ascii"))
        self.github_inputs.update({
            "expected_receipt_sha256": SHA9,
            "expected_policy_sha256": self.fixture.policy["upstream_bindings"]["t142_github_policy_sha256"],
            "expected_request_sha256": SHA2,
            "expected_previous_head_sha256": SHA4,
            "expected_github_origin_sha256": SHA3,
            "expected_archive_sha256": SHA4,
            "expected_bundle_sha256": SHA5,
            "expected_ledger_id": "github-rest-ledger-142",
            "expected_sequence": 1,
        })
        names = sorted(backed._WORM_PATHS - {"prior_checkpoint_path"})
        self.worm_inputs = {name: self.root / f"worm-{index}.bin" for index, name in enumerate(names)}
        for name, path in self.worm_inputs.items():
            path.write_bytes(f"worm:{name}".encode("ascii"))
        self.worm_inputs["prior_checkpoint_path"] = None
        self.worm_inputs.update({
            "expected_collection_sha256": SHA6,
            "expected_policy_sha256": self.fixture.policy["upstream_bindings"]["t142_worm_policy_sha256"],
            "expected_target_policy_sha256": self.fixture.policy["upstream_bindings"]["t141_target_policy_sha256"],
            "expected_cluster_fingerprint_sha256": SHA2,
            "expected_ledger_id": "worm-replay-ledger-142",
            "expected_sequence": 1,
            "expected_prior_head_sha256": "0" * 64,
            "expected_runtime_policy_sha256": hashlib.sha256(
                worm.RUNTIME_POLICY.read_bytes()
            ).hexdigest(),
            "verification_time": "2026-08-27T08:03:00Z",
        })
        upstream = self.fixture.policy["upstream_bindings"]
        self.github_result = github.VerifiedCollection(
            attempt_id=self.readiness["payload"]["attempt_id"], deployment_id="collector-prod-001",
            request_id="request-143", collector_key_id=upstream["github_collector_key_id"],
            ledger_key_id=upstream["github_ledger_key_id"], ledger_id="github-rest-ledger-142",
            sequence=1, receipt_sha256=SHA9, request_sha256=SHA2,
            replay_head_sha256=SHA5, raw_response_set_sha256=SHA8,
            policy_sha256=upstream["t142_github_policy_sha256"],
            deployment_policy_sha256=self.pins["expected_policy_sha256"],
            readiness_sha256=readiness_sha, previous_head_sha256=SHA4,
            current_worm_collection_head_sha256=SHA6,
        )
        self.worm_result = worm.VerifiedCollection(
            attempt_id=self.readiness["payload"]["attempt_id"],
            policy_sha256=upstream["t142_worm_policy_sha256"],
            target_policy_sha256=upstream["t141_target_policy_sha256"],
            cluster_fingerprint_sha256=SHA2, ledger_id="worm-replay-ledger-142",
            sequence=1, prior_head_sha256="0" * 64, receipt_sha256=SHA6,
            head_sha256=SHA6, observation_payload_sha256=SHA3,
            provider_kind="aws_s3_object_lock", provider_account_fingerprint_sha256=SHA5,
            storage_identity_fingerprint_sha256=SHA6, configuration_snapshot_sha256=SHA9,
            retention_mode="compliance", provider_signer_key_id=upstream["worm_provider_key_id"],
            ledger_signer_key_id=upstream["worm_ledger_key_id"],
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _verify(self):
        with mock.patch.object(github, "verify_collection_bytes", return_value=self.github_result) as github_verify, mock.patch.object(worm, "verify_collection_bytes", return_value=self.worm_result) as worm_verify:
            result = backed.verify_collection_backed_acceptance(
                self.policy_path, self.readiness_path, self.execution_path,
                acceptance_pins=self.pins, github_inputs=self.github_inputs, worm_inputs=self.worm_inputs,
            )
        return result, github_verify, worm_verify

    def _manifest_raw(self, **changes) -> bytes:
        manifest = {
            "schema_version": 1,
            "manifest_kind": backed.MANIFEST_KIND,
            "policy_path": str(self.policy_path),
            "readiness_path": str(self.readiness_path),
            "execution_path": str(self.execution_path),
            "acceptance_pins": dict(self.pins),
            "github_inputs": {key: str(value) if key in backed._GITHUB_PATHS else value for key, value in self.github_inputs.items()},
            "worm_inputs": {
                key: (str(value) if key in backed._WORM_PATHS and value is not None else value)
                for key, value in self.worm_inputs.items()
            },
        }
        manifest.update(changes)
        return raw_json(manifest)

    def _verify_manifest(self, raw: bytes):
        path = self.root / "manifest.json"
        path.write_bytes(raw)
        with mock.patch.object(github, "verify_collection_bytes", return_value=self.github_result) as github_verify, mock.patch.object(worm, "verify_collection_bytes", return_value=self.worm_result) as worm_verify:
            result = backed.verify_input_manifest(
                path, expected_manifest_sha256=hashlib.sha256(raw).hexdigest()
            )
        return result, github_verify, worm_verify

    def test_invokes_both_verifiers_and_reconciles_frozen_results(self) -> None:
        result, github_verify, worm_verify = self._verify()
        self.assertEqual(result.github_collection_head_sha256, SHA5)
        github_verify.assert_called_once()
        worm_verify.assert_called_once()
        self.assertEqual(
            github_verify.call_args.kwargs["readiness_raw"], self.readiness_raw
        )

    def test_rejects_frozen_result_execution_mismatch_and_path_alias(self) -> None:
        self.github_result = github.VerifiedCollection(
            **{**self.github_result.__dict__, "raw_response_set_sha256": SHA7}
        )
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            self._verify()

    def test_caller_pinned_closed_manifest_and_cli(self) -> None:
        raw = self._manifest_raw()
        result, github_verify, worm_verify = self._verify_manifest(raw)
        self.assertEqual(result.worm_collection_head_sha256, SHA6)
        github_verify.assert_called_once()
        worm_verify.assert_called_once()
        path = self.root / "manifest-cli.json"
        path.write_bytes(raw)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(github, "verify_collection_bytes", return_value=self.github_result), mock.patch.object(worm, "verify_collection_bytes", return_value=self.worm_result), redirect_stdout(stdout), redirect_stderr(stderr):
            status = backed.main([
                "verify", "--input-manifest", str(path),
                "--expected-input-manifest-sha256", hashlib.sha256(raw).hexdigest(),
            ])
        self.assertEqual(status, 0)
        self.assertIn("manifest-authentication=caller-pinned-raw-sha256", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_manifest_pin_schema_types_and_paths_fail_before_nested_verifiers(self) -> None:
        raw = self._manifest_raw()
        path = self.root / "manifest-invalid.json"
        path.write_bytes(raw)
        with mock.patch.object(backed, "parse_input_manifest") as parser, mock.patch.object(github, "verify_collection_bytes") as github_verify, mock.patch.object(worm, "verify_collection_bytes") as worm_verify:
            with self.assertRaises(backed.CollectionBackedAcceptanceError):
                backed.verify_input_manifest(path, expected_manifest_sha256="f" * 64)
        parser.assert_not_called()
        github_verify.assert_not_called()
        worm_verify.assert_not_called()

        invalid_pins = dict(self.pins)
        invalid_pins["expected_sequence"] = True
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            backed.parse_input_manifest(self._manifest_raw(acceptance_pins=invalid_pins))
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            backed.parse_input_manifest(self._manifest_raw(extra="forbidden"))
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            backed.parse_input_manifest(self._manifest_raw(policy_path=str(backed.deployment.ROOT / "inside.json")))

    def test_manifest_rejects_pin_disagreement_and_self_alias(self) -> None:
        github_inputs = dict(self.github_inputs)
        github_inputs["expected_request_sha256"] = SHA3
        github_inputs = {key: str(value) if key in backed._GITHUB_PATHS else value for key, value in github_inputs.items()}
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            backed.parse_input_manifest(self._manifest_raw(github_inputs=github_inputs))
        raw = self._manifest_raw(policy_path=str(self.root / "manifest-alias.json"))
        path = self.root / "manifest-alias.json"
        path.write_bytes(raw)
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            backed.verify_input_manifest(path, expected_manifest_sha256=hashlib.sha256(raw).hexdigest())
        self.github_inputs["archive_path"] = self.policy_path
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            self._verify()

    def test_rejects_hardlinked_inputs_before_bytes_cores(self) -> None:
        alias = self.root / "hardlinked-archive.bin"
        os.link(self.policy_path, alias)
        self.github_inputs["archive_path"] = alias
        with mock.patch.object(github, "verify_collection_bytes") as github_verify, mock.patch.object(worm, "verify_collection_bytes") as worm_verify:
            with self.assertRaises(backed.CollectionBackedAcceptanceError):
                backed.verify_collection_backed_acceptance(
                    self.policy_path,
                    self.readiness_path,
                    self.execution_path,
                    acceptance_pins=self.pins,
                    github_inputs=self.github_inputs,
                    worm_inputs=self.worm_inputs,
                )
        github_verify.assert_not_called()
        worm_verify.assert_not_called()

    def test_rejects_same_bytes_replacement_during_verification(self) -> None:
        target = self.github_inputs["archive_path"]

        def replace_after_acquisition(**kwargs):
            replacement = self.root / "replacement-archive.bin"
            replacement.write_bytes(target.read_bytes())
            os.replace(replacement, target)
            return self.github_result

        with mock.patch.object(
            github, "verify_collection_bytes", side_effect=replace_after_acquisition
        ), mock.patch.object(
            worm, "verify_collection_bytes", return_value=self.worm_result
        ):
            with self.assertRaises(backed.CollectionBackedAcceptanceError):
                backed.verify_collection_backed_acceptance(
                    self.policy_path,
                    self.readiness_path,
                    self.execution_path,
                    acceptance_pins=self.pins,
                    github_inputs=self.github_inputs,
                    worm_inputs=self.worm_inputs,
                )

    def test_runtime_policy_pin_fails_before_bytes_cores(self) -> None:
        self.worm_inputs["expected_runtime_policy_sha256"] = "f" * 64
        with mock.patch.object(github, "verify_collection_bytes") as github_verify, mock.patch.object(worm, "verify_collection_bytes") as worm_verify:
            with self.assertRaises(backed.CollectionBackedAcceptanceError):
                backed.verify_collection_backed_acceptance(
                    self.policy_path,
                    self.readiness_path,
                    self.execution_path,
                    acceptance_pins=self.pins,
                    github_inputs=self.github_inputs,
                    worm_inputs=self.worm_inputs,
                )
        github_verify.assert_not_called()
        worm_verify.assert_not_called()

    def test_rejects_cross_attempt_deployment_ledger_and_sequence_results(self) -> None:
        cases = (
            ("github", "attempt_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            ("github", "deployment_id", "collector-prod-002"),
            ("github", "ledger_id", "github-rest-ledger-other"),
            ("github", "sequence", 2),
            ("worm", "attempt_id", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            ("worm", "ledger_id", "worm-replay-ledger-other"),
            ("worm", "sequence", 2),
        )
        for scope, field, value in cases:
            with self.subTest(scope=scope, field=field):
                original = self.github_result if scope == "github" else self.worm_result
                changed = type(original)(**{**original.__dict__, field: value})
                if scope == "github":
                    self.github_result = changed
                else:
                    self.worm_result = changed
                with self.assertRaises(backed.CollectionBackedAcceptanceError):
                    self._verify()
                if scope == "github":
                    self.github_result = original
                else:
                    self.worm_result = original

    def test_rejects_old_execution_with_new_collection_heads(self) -> None:
        self.github_result = github.VerifiedCollection(
            **{
                **self.github_result.__dict__,
                "replay_head_sha256": SHA7,
                "current_worm_collection_head_sha256": SHA8,
            }
        )
        self.worm_result = worm.VerifiedCollection(
            **{**self.worm_result.__dict__, "head_sha256": SHA8}
        )
        self.pins["expected_github_collection_head_sha256"] = SHA7
        self.pins["expected_current_worm_collection_head_sha256"] = SHA8
        self.pins["expected_worm_collection_head_sha256"] = SHA8
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            self._verify()

    def test_rejects_new_execution_with_old_collection_heads(self) -> None:
        payload = dict(self.fixture.execution_payload)
        payload["readiness_receipt_sha256"] = self.pins["expected_readiness_sha256"]
        payload["github_collection_head_sha256"] = SHA7
        updated = self.fixture._execution(payload)
        updated_raw = raw_json(updated)
        self.execution_path.write_bytes(updated_raw)
        self.pins["expected_execution_sha256"] = hashlib.sha256(updated_raw).hexdigest()
        self.pins["expected_github_collection_head_sha256"] = SHA7
        with self.assertRaises(backed.CollectionBackedAcceptanceError):
            self._verify()


if __name__ == "__main__":
    unittest.main()
