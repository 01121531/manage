from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_target_intake_runtime_attestation_provider_adapter as static_gate


class RuntimeAttestationProviderStaticGateTests(unittest.TestCase):
    def test_repository_static_contract_passes(self) -> None:
        self.assertEqual([], static_gate.verify_static_contract())

    def test_parse_reserialize_signature_mutation_is_rejected(self) -> None:
        source = static_gate.ADAPTER.read_text(encoding="utf-8")
        source = source.replace(
            "verify_ecdsa_signature(cosign_cert.public_key(), cosign_signature, raw_inputs.cosign_payload)",
            "verify_ecdsa_signature(cosign_cert.public_key(), cosign_signature, _artifact_bytes(_raw_json(raw_inputs.cosign_payload)))",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "adapter.py"
            mutated.write_text(source, encoding="utf-8")
            with patch.object(static_gate, "ADAPTER", mutated):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("exact-byte signature" in error for error in errors))

    def test_network_or_signing_capability_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "adapter.py"
            mutated.write_text("import socket\ndef verify():\n    return socket.socket()\n", encoding="utf-8")
            errors = static_gate._check_pure(mutated)
        self.assertTrue(any("external-I/O" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
