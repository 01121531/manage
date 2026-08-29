from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.sub2_execution_evidence import main as sub2_main
from scripts.target_intake_manifest import (
    PinnedIntakeManifestError,
    canonical_payload_sha256,
    load_pinned_intake_manifest,
    manifest_shape_errors,
)
from tests.intake_manifest_support import closed_manifest


class TargetIntakeManifestTests(unittest.TestCase):
    def _write(self, root: Path, document: object, *, compact: bool = False) -> Path:
        path = root / "intake.json"
        if compact:
            encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
        else:
            encoded = json.dumps(document, indent=2)
        path.write_text(encoded, encoding="utf-8")
        return path

    @staticmethod
    def _load(path: Path, document: object) -> dict[str, object]:
        raw = path.read_bytes()
        return load_pinned_intake_manifest(
            path,
            expected_payload_sha256=canonical_payload_sha256(document),
            expected_file_sha256=hashlib.sha256(raw).hexdigest(),
        )

    def test_minimal_partial_manifest_is_rejected_by_closed_schema(self) -> None:
        minimal = {
            "schema_version": 2,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": "a" * 64,
            "items": [{"id": "sub2_execution_evidence", "status": "provided"}],
        }
        self.assertTrue(manifest_shape_errors(minimal))
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), minimal)
            with self.assertRaises(PinnedIntakeManifestError):
                self._load(path, minimal)

    def test_both_semantic_and_raw_file_pins_are_required(self) -> None:
        manifest = closed_manifest({"items": []})
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), manifest)
            raw_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            payload_digest = canonical_payload_sha256(manifest)
            self.assertEqual(self._load(path, manifest), manifest)
            for payload_pin, file_pin in (
                ("f" * 64, raw_digest),
                (payload_digest, "f" * 64),
                ("invalid", raw_digest),
                (payload_digest, "invalid"),
            ):
                with self.subTest(payload_pin=payload_pin, file_pin=file_pin):
                    with self.assertRaises(PinnedIntakeManifestError):
                        load_pinned_intake_manifest(
                            path,
                            expected_payload_sha256=payload_pin,
                            expected_file_sha256=file_pin,
                        )

    def test_semantic_reformat_keeps_payload_pin_but_breaks_file_pin(self) -> None:
        manifest = closed_manifest({"items": []})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._write(root, manifest)
            original_file_pin = hashlib.sha256(path.read_bytes()).hexdigest()
            payload_pin = canonical_payload_sha256(manifest)
            path = self._write(root, manifest, compact=True)
            self.assertEqual(canonical_payload_sha256(json.loads(path.read_bytes())), payload_pin)
            with self.assertRaises(PinnedIntakeManifestError):
                load_pinned_intake_manifest(
                    path,
                    expected_payload_sha256=payload_pin,
                    expected_file_sha256=original_file_pin,
                )

    def test_coordinated_manifest_replacement_fails_old_external_pins(self) -> None:
        original = closed_manifest({"items": []})
        replacement = json.loads(json.dumps(original))
        replacement["environment"] = "staging-replacement"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._write(root, original)
            payload_pin = canonical_payload_sha256(original)
            file_pin = hashlib.sha256(path.read_bytes()).hexdigest()
            self._write(root, replacement)
            with self.assertRaises(PinnedIntakeManifestError):
                load_pinned_intake_manifest(
                    path,
                    expected_payload_sha256=payload_pin,
                    expected_file_sha256=file_pin,
                )

    def test_bad_pin_fails_before_consumer_reads_other_evidence(self) -> None:
        manifest = closed_manifest({"items": []})
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), manifest)
            with mock.patch("scripts.sub2_execution_evidence._load") as evidence_load:
                self.assertEqual(
                    sub2_main(
                        [
                            "check",
                            "--input",
                            str(path.parent / "evidence.json"),
                            "--intake-manifest",
                            str(path),
                            "--expected-intake-manifest-payload-sha256",
                            "f" * 64,
                            "--expected-intake-manifest-file-sha256",
                            hashlib.sha256(path.read_bytes()).hexdigest(),
                            "--release-execution-evidence",
                            str(path.parent / "release.json"),
                        ]
                    ),
                    2,
                )
                evidence_load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
