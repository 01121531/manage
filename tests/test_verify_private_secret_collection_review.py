from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import unittest

from scripts import verify_private_secret_collection_review as gate


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def sealed_raw(value: dict[str, object]) -> bytes:
    payload = {key: item for key, item in value.items() if key != "integrity"}
    value = {
        **payload,
        "integrity": {"payload_sha256": hashlib.sha256(canonical(payload)).hexdigest()},
    }
    return json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"


class PrivateSecretCollectionReviewStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = gate.REVIEW.read_text(encoding="utf-8")
        cls.backed_source = gate.BACKED.read_text(encoding="utf-8")
        cls.policy = json.loads(gate.POLICY.read_bytes())
        cls.decision = json.loads(gate.TEMPLATE.read_bytes())

    def test_repository_assets_and_cli_are_fail_closed(self) -> None:
        self.assertEqual([], gate.collect_errors())
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = gate.main()
        self.assertEqual(status, 0)
        self.assertIn("reviewer-authentication=unverified", stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_network_private_signing_process_and_writes_are_forbidden(self) -> None:
        mutations = (
            "import socket\n" + self.source,
            self.source + "\ndef forbidden(key, raw):\n    return key.sign(raw)\n",
            self.source + "\ndef forbidden():\n    Path('x').write_bytes(b'x')\n",
            self.source + "\ndef forbidden():\n    return subprocess.run(['x'])\n",
        )
        for source in mutations:
            with self.subTest(source=source[-70:]):
                self.assertTrue(gate.collect_errors(review_source=source))

    def test_pure_core_cannot_gain_filesystem_io(self) -> None:
        source = self.source.replace(
            '    """Authenticate exact bytes and a previously verified T146 projection."""',
            '    """Authenticate exact bytes and a previously verified T146 projection."""\n'
            '    Path("forbidden").read_bytes()',
            1,
        )
        errors = gate.collect_errors(review_source=source)
        self.assertTrue(any("pure bytes core performs filesystem I/O" in item for item in errors))

    def test_domain_payload_schema_and_role_separation_cannot_drift(self) -> None:
        mutations = (
            self.source.replace(gate.DOMAIN, "email-platform/wrong/v1", 1),
            self.source.replace(
                '"release_commit", "release_manifest_sha256", "verifier_source_sha256",',
                '"release_commit", "release_manifest_sha256", "verifier_source_sha256", "extra",',
                1,
            ),
            self.source.replace(
                "verified_acceptance.github_collection.collector_key_id,",
                '"ed25519-sha256:" + "0" * 64,',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:60]):
                self.assertTrue(gate.collect_errors(review_source=source))

    def test_single_acquisition_wrapper_and_required_pins_are_locked(self) -> None:
        mutations = (
            self.source.replace("decision_blob = _read_blob(", "decision_blob = _read_blobs(", 1),
            self.source.replace(
                "expected_decision_sha256: str,",
                'expected_decision_sha256: str = "0" * 64,',
                1,
            ),
            self.source.replace(
                "verified_acceptance = backed.verify_input_manifest_projection(",
                "verified_acceptance = backed.verify_input_manifest(",
                1,
            ),
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                self.assertTrue(gate.collect_errors(review_source=source))

    def test_t146_projection_type_and_acquisition_cannot_be_bypassed(self) -> None:
        for source in (
            self.backed_source.replace(
                "class VerifiedCollectionBackedAcceptance:",
                "class ConstructedCollectionBackedAcceptance:",
                1,
            ),
            self.backed_source.replace(
                "_verify_collection_backed_acceptance(",
                "verify_collection_backed_acceptance(",
                1,
            ),
        ):
            with self.subTest(source=source[:50]):
                self.assertTrue(gate.collect_errors(backed_source=source))

    def test_synthetic_assets_are_closed_sealed_pending_and_unconfigured(self) -> None:
        duplicate = b'{"schema_version":1,"schema_version":1}'
        self.assertTrue(gate.collect_errors(policy_raw=duplicate))

        policy = dict(self.policy)
        policy["production_acceptance"] = True
        self.assertTrue(gate.collect_errors(policy_raw=sealed_raw(policy)))

        decision = dict(self.decision)
        decision["payload"] = {"attacker": "constructed"}
        self.assertTrue(gate.collect_errors(decision_raw=sealed_raw(decision)))

        decision = dict(self.decision)
        decision["extra"] = False
        self.assertTrue(gate.collect_errors(decision_raw=sealed_raw(decision)))

    def test_unverified_status_and_claim_axes_cannot_be_upgraded(self) -> None:
        source = self.source.replace("trusted-time=unverified", "trusted-time=verified")
        self.assertTrue(gate.collect_errors(review_source=source))
        decision = dict(self.decision)
        decision["claim_boundary"] = dict(decision["claim_boundary"])
        decision["claim_boundary"]["trusted_time"] = "verified"
        self.assertTrue(gate.collect_errors(decision_raw=sealed_raw(decision)))


if __name__ == "__main__":
    unittest.main()
