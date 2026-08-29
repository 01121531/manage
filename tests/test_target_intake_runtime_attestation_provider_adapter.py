from __future__ import annotations

import base64
from dataclasses import replace
import json
import unittest

from scripts.target_intake_runtime_attestation_provider_adapter import RuntimeAttestationProviderError
from tests.runtime_attestation_provider_fixture import load_fixture, repin_input, verify


class RuntimeAttestationProviderAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixed, self.inputs, self.pins = load_fixture()

    def assert_invalid(self, fixed=None, inputs=None, pins=None) -> None:
        with self.assertRaises(RuntimeAttestationProviderError):
            verify(fixed or self.fixed, inputs or self.inputs, pins or self.pins)

    def test_pinned_fixture_verifies_crypto_without_production_authority(self) -> None:
        result = verify(self.fixed, self.inputs, self.pins)
        self.assertTrue(result.fixture_signature_cryptography_verified)
        self.assertTrue(result.fixture_tsa_cryptography_verified)
        self.assertTrue(result.fixture_transparency_inclusion_verified)
        self.assertTrue(result.fixture_receipt_cryptography_verified)
        self.assertFalse(result.trust_root_currentness_verified)
        self.assertFalse(result.revocation_freshness_verified)
        self.assertFalse(result.provider_native_cas_verified)
        self.assertFalse(result.original_execution_verified)
        self.assertFalse(result.runtime_authority_verified)
        self.assertFalse(result.production_acceptance)

    def test_all_independent_caller_pins_fail_closed(self) -> None:
        for field in self.pins.__dataclass_fields__:
            with self.subTest(field=field):
                self.assert_invalid(pins=replace(self.pins, **{field: "0" * 64}))

    def test_each_raw_asset_pin_fails_closed(self) -> None:
        for field in self.inputs.__dataclass_fields__:
            with self.subTest(field=field):
                raw = getattr(self.inputs, field)
                mutated = raw[:-1] + bytes([raw[-1] ^ 1])
                self.assert_invalid(inputs=replace(self.inputs, **{field: mutated}))

    def test_semantically_equivalent_cosign_payload_bytes_do_not_inherit_signature(self) -> None:
        payload = json.loads(self.inputs.cosign_payload)
        rewritten = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.assertNotEqual(rewritten, self.inputs.cosign_payload)
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "cosign_payload", rewritten)
        self.assert_invalid(fixed, inputs, pins)

    def test_semantically_equivalent_dsse_statement_bytes_do_not_inherit_signature(self) -> None:
        bundle = json.loads(self.inputs.github_bundle)
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True))
        rewritten = json.dumps(statement, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(rewritten).decode("ascii")
        raw = (json.dumps(bundle, ensure_ascii=True, separators=(", ", ": ")) + "\n").encode("ascii")
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "github_bundle", raw)
        self.assert_invalid(fixed, inputs, pins)

    def test_cli_success_record_cannot_mask_direct_signature_failure(self) -> None:
        payload = self.inputs.cosign_payload.replace(b"v3.0.6-fixture", b"v3.0.7-fixture")
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "cosign_payload", payload)
        self.assert_invalid(fixed, inputs, pins)

    def test_rfc3161_imprint_is_bound_to_exact_signature(self) -> None:
        bundle = json.loads(self.inputs.cosign_bundle)
        signature = bytearray(base64.b64decode(bundle["messageSignature"]["signature"], validate=True))
        signature[-1] ^= 1
        bundle["messageSignature"]["signature"] = base64.b64encode(signature).decode("ascii")
        raw = (json.dumps(bundle, ensure_ascii=True, separators=(", ", ": ")) + "\n").encode("ascii")
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "cosign_bundle", raw)
        self.assert_invalid(fixed, inputs, pins)

    def test_checkpoint_signature_and_inclusion_root_fail_closed(self) -> None:
        raw = self.inputs.rekor_checkpoint.replace(b"\n2\n", b"\n3\n", 1)
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "rekor_checkpoint", raw)
        self.assert_invalid(fixed, inputs, pins)

    def test_target_observer_signature_cannot_be_reused_for_changed_payload(self) -> None:
        envelope = json.loads(self.inputs.target_observer)
        payload = bytearray(base64.b64decode(envelope["payload"], validate=True))
        payload[payload.index(b"2026") + 3] = ord("7")
        envelope["payload"] = base64.b64encode(payload).decode("ascii")
        raw = (json.dumps(envelope, ensure_ascii=True, separators=(", ", ": ")) + "\n").encode("ascii")
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "target_observer", raw)
        self.assert_invalid(fixed, inputs, pins)

    def test_provider_write_and_read_receipts_are_not_caller_claims(self) -> None:
        for field in ("provider_write_receipt", "provider_read_receipt"):
            with self.subTest(field=field):
                envelope = json.loads(getattr(self.inputs, field))
                signature = bytearray(base64.b64decode(envelope["signature"], validate=True))
                signature[0] ^= 1
                envelope["signature"] = base64.b64encode(signature).decode("ascii")
                raw = (json.dumps(envelope, ensure_ascii=True, separators=(", ", ": ")) + "\n").encode("ascii")
                fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, field, raw)
                self.assert_invalid(fixed, inputs, pins)

    def test_duplicate_key_in_provider_json_fails_closed(self) -> None:
        raw = self.inputs.cosign_payload.replace(b'{"critical":', b'{"critical": {}, "critical":', 1)
        fixed, inputs, pins = repin_input(self.fixed, self.inputs, self.pins, "cosign_payload", raw)
        self.assert_invalid(fixed, inputs, pins)


if __name__ == "__main__":
    unittest.main()
