from __future__ import annotations

import base64
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.tls_rotation_attempt_receipt import (
    CRASH_MATRIX,
    PinnedEd25519TrustAnchor,
    TlsRotationAttemptReceiptError,
    attempt_signature_message,
    verify_authenticated_attempt,
)


ATTEMPT_ID = "123e4567-e89b-42d3-a456-426614174000"
WINDOWS_SINK = r"D:\protected\tls-rotation-evidence.json"


class TlsRotationAttemptReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.anchor = PinnedEd25519TrustAnchor(public)
        self.payload = {
            "schema_version": 1,
            "receipt_kind": "tls_rotation_publication_attempt",
            "statement": "ready_before_link",
            "production_acceptance": False,
            "not_committed_eligible": False,
            "attempt_id": ATTEMPT_ID,
            "rotation_plan_sha256": "1" * 64,
            "runtime_profile_sha256": "2" * 64,
            "evidence_payload_sha256": "3" * 64,
            "evidence_artifact_sha256": "4" * 64,
            "ready_at": "2026-08-27T00:00:00.000000Z",
        }

    def _raw(self, payload=None, *, sink=WINDOWS_SINK, private=None, extra=None) -> bytes:
        value = dict(self.payload if payload is None else payload)
        signer = self.private if private is None else private
        signature = signer.sign(attempt_signature_message(
            value, expected_evidence_output=sink, path_flavor="windows"
        ))
        envelope = {
            "payload": value,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": self.anchor.key_id,
                "value_b64url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
            },
        }
        if extra:
            envelope.update(extra)
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _verify(self, raw=None, **changes):
        arguments = {
            "expected_attempt_id": ATTEMPT_ID,
            "expected_rotation_plan_sha256": "1" * 64,
            "expected_runtime_profile_sha256": "2" * 64,
            "expected_evidence_payload_sha256": "3" * 64,
            "expected_evidence_artifact_sha256": "4" * 64,
            "expected_evidence_output": WINDOWS_SINK,
            "path_flavor": "windows",
            "trusted_anchor": self.anchor,
        }
        arguments.update(changes)
        return verify_authenticated_attempt(self._raw() if raw is None else raw, **arguments)

    def test_valid_assertion_authenticates_every_expected_binding(self) -> None:
        result = self._verify()
        self.assertEqual(result.attempt_id, ATTEMPT_ID)
        self.assertEqual(result.signer_key_id, self.anchor.key_id)
        self.assertEqual(result.evidence_artifact_sha256, "4" * 64)

    def test_expected_context_signature_sink_and_anchor_mutations_fail(self) -> None:
        mutations = (
            {"expected_attempt_id": "223e4567-e89b-42d3-a456-426614174000"},
            {"expected_rotation_plan_sha256": "5" * 64},
            {"expected_runtime_profile_sha256": "5" * 64},
            {"expected_evidence_payload_sha256": "5" * 64},
            {"expected_evidence_artifact_sha256": "5" * 64},
            {"expected_evidence_output": r"D:\protected\other.json"},
            {"path_flavor": "posix"},
            {"trusted_anchor": PinnedEd25519TrustAnchor(
                Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                TlsRotationAttemptReceiptError
            ):
                self._verify(**mutation)

        tampered = json.loads(self._raw())
        tampered["signature"]["value_b64url"] = "A" * 86
        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(json.dumps(tampered).encode())

        noncanonical = json.loads(self._raw())
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        encoded = noncanonical["signature"]["value_b64url"]
        last_index = alphabet.index(encoded[-1])
        noncanonical["signature"]["value_b64url"] = encoded[:-1] + alphabet[last_index + 1]
        self.assertEqual(
            base64.urlsafe_b64decode(encoded + "=="),
            base64.urlsafe_b64decode(noncanonical["signature"]["value_b64url"] + "=="),
        )
        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(json.dumps(noncanonical).encode())

    def test_closed_payload_and_envelope_reject_noncanonical_or_self_declared_trust(self) -> None:
        mutations = []
        for field, value in (
            ("schema_version", True),
            ("production_acceptance", True),
            ("not_committed_eligible", True),
            ("attempt_id", ATTEMPT_ID.upper()),
            ("rotation_plan_sha256", "A" * 64),
            ("ready_at", "2026-08-27T00:00:00Z"),
        ):
            changed = dict(self.payload)
            changed[field] = value
            mutations.append(changed)
        changed = dict(self.payload)
        changed["public_key"] = "self-declared"
        mutations.append(changed)
        for payload in mutations:
            with self.subTest(payload=payload), self.assertRaises(
                TlsRotationAttemptReceiptError
            ):
                self._raw(payload)

        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(self._raw(extra={"public_key": "self-declared"}))
        duplicate = self._raw().replace(b'{"payload":', b'{"payload":{},"payload":', 1)
        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(duplicate)

    def test_ready_assertion_never_creates_a_negative_publication_state(self) -> None:
        self.assertEqual(set(CRASH_MATRIX.values()), {"unknown", "committed"})
        self.assertEqual(CRASH_MATRIX["after_ready_before_link"], "unknown")
        self.assertEqual(CRASH_MATRIX["during_link"], "unknown")
        self.assertEqual(CRASH_MATRIX["after_verified_stable_readback"], "committed")

    def test_anchor_receipt_and_path_boundaries_are_bounded(self) -> None:
        with self.assertRaises(TlsRotationAttemptReceiptError):
            PinnedEd25519TrustAnchor(b"short")
        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(b"x" * (16 * 1024 + 1))
        with self.assertRaises(TlsRotationAttemptReceiptError):
            self._verify(expected_evidence_output=r"relative\evidence.json")


if __name__ == "__main__":
    unittest.main()
