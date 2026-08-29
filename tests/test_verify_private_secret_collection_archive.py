from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import unittest

from scripts import verify_private_secret_collection_archive as gate


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


class PrivateSecretCollectionArchiveStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = gate.ARCHIVE.read_text(encoding="utf-8")
        cls.review_source = gate.REVIEW.read_text(encoding="utf-8")
        cls.policy = json.loads(gate.POLICY.read_bytes())
        cls.receipt = json.loads(gate.TEMPLATE.read_bytes())

    def test_repository_assets_and_cli_are_fail_closed(self) -> None:
        self.assertEqual([], gate.collect_errors())
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = gate.main()
        self.assertEqual(status, 0)
        self.assertIn("provider-signature=unverified", stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_network_process_private_signing_and_writes_are_forbidden(self) -> None:
        mutations = (
            "import socket\n" + self.source,
            self.source + "\ndef forbidden(key, raw):\n    return key.sign(raw)\n",
            self.source + "\ndef forbidden():\n    Path('x').write_bytes(b'x')\n",
            self.source + "\ndef forbidden():\n    return subprocess.run(['x'])\n",
        )
        for source in mutations:
            with self.subTest(source=source[-70:]):
                self.assertTrue(gate.collect_errors(archive_source=source))

    def test_pure_bytes_core_cannot_gain_file_or_t147_io(self) -> None:
        mutations = (
            self.source.replace(
                '    """Authenticate exact bytes, one T147 result, and one custody-chain hop."""',
                '    """Authenticate exact bytes, one T147 result, and one custody-chain hop."""\n'
                '    Path("forbidden").read_bytes()',
                1,
            ),
            self.source.replace(
                '    """Authenticate exact bytes, one T147 result, and one custody-chain hop."""',
                '    """Authenticate exact bytes, one T147 result, and one custody-chain hop."""\n'
                '    review.verify_decision()',
                1,
            ),
        )
        for source in mutations:
            errors = gate.collect_errors(archive_source=source)
            self.assertTrue(
                any("pure bytes core performs filesystem or upstream I/O" in item for item in errors)
            )

    def test_domains_schemas_and_key_separation_cannot_drift(self) -> None:
        mutations = (
            self.source.replace(gate.PROVIDER_DOMAIN, "email-platform/wrong/v1", 1),
            self.source.replace(gate.CUSTODY_DOMAIN, "email-platform/wrong/v1", 1),
            self.source.replace(
                '"ledger_id", "sequence", "prior_receipt_sha256",',
                '"ledger_id", "sequence", "prior_receipt_sha256", "extra",',
                1,
            ),
            self.source.replace("*verified_review.upstream_key_ids,", "", 1),
            self.source.replace("verified_review.reviewer_key_id,", '"ed25519-sha256:" + "0" * 64,', 1),
        )
        for source in mutations:
            with self.subTest(source=source[:50]):
                self.assertTrue(gate.collect_errors(archive_source=source))

    def test_single_t147_acquisition_stable_reads_and_pins_are_locked(self) -> None:
        mutations = (
            self.source.replace("_read_blob(receipt_path", "_read_blobs(receipt_path", 1),
            self.source.replace("review.verify_decision(", "review.verify_decisions(", 1),
            self.source.replace(
                "expected_receipt_sha256: str,",
                'expected_receipt_sha256: str = "0" * 64,',
                1,
            ),
            self.source.replace("_unchanged(blob)", "pass", 1),
        )
        for source in mutations:
            with self.subTest(source=source[-60:]):
                self.assertTrue(gate.collect_errors(archive_source=source))

    def test_genesis_next_replay_and_aba_guards_cannot_be_removed(self) -> None:
        markers = (
            'prior_payload["sequence"] != expected_sequence - 1',
            "prior_checkpoint_sha256, expected_prior_checkpoint_sha256",
            'payload["prior_checkpoint_sha256"] != prior_checkpoint_sha256',
            'prior_payload["decision_id"] == payload["decision_id"]',
            'prior_payload["archive_readback_sha256"] == payload["archive_readback_sha256"]',
            'prior_payload["object_reference"] == payload["object_reference"]',
            'expected_prior_receipt_sha256 != ZERO_SHA256',
        )
        for marker in markers:
            source = self.source.replace(marker, "False", 1)
            with self.subTest(marker=marker):
                self.assertTrue(gate.collect_errors(archive_source=source))

    def test_synthetic_assets_are_closed_sealed_pending_and_unconfigured(self) -> None:
        self.assertTrue(gate.collect_errors(policy_raw=b'{"x":1,"x":2}'))
        policy = dict(self.policy)
        policy["production_acceptance"] = True
        self.assertTrue(gate.collect_errors(policy_raw=sealed_raw(policy)))
        receipt = dict(self.receipt)
        receipt["payload"] = {"attacker": "constructed"}
        self.assertTrue(gate.collect_errors(receipt_raw=sealed_raw(receipt)))
        receipt = dict(self.receipt)
        receipt["extra"] = False
        self.assertTrue(gate.collect_errors(receipt_raw=sealed_raw(receipt)))

    def test_t147_frozen_keys_and_unverified_axes_cannot_be_upgraded(self) -> None:
        review_source = self.review_source.replace(
            "upstream_key_ids: tuple[str, ...]", "constructed_keys: tuple[str, ...]", 1
        )
        self.assertTrue(gate.collect_errors(review_source=review_source))
        source = self.source.replace("trusted-time=unverified", "trusted-time=verified")
        self.assertTrue(gate.collect_errors(archive_source=source))
        receipt = dict(self.receipt)
        receipt["claim_boundary"] = dict(receipt["claim_boundary"])
        receipt["claim_boundary"]["provider_native"] = "verified"
        self.assertTrue(gate.collect_errors(receipt_raw=sealed_raw(receipt)))


if __name__ == "__main__":
    unittest.main()
