from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.phase0_boundary_approval import main as phase0_main
from scripts.phase6_pilot_inputs import main as pilot_inputs_main
from scripts.sub2_execution_evidence import main as sub2_main
from scripts.external_json import (
    StableFileError,
    load_unique_json_with_bytes_and_metadata,
    recheck_stable_bytes,
)
from scripts.target_intake_manifest import (
    PinnedIntakeManifestError,
    canonical_payload_sha256,
    load_pinned_intake_manifest,
    manifest_artifact_path,
    manifest_artifact_sha256_matches,
    manifest_shape_errors,
)
from tests.intake_manifest_support import (
    bind_manifest_item_bytes,
    closed_manifest,
    manifest_pin_arguments,
)


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

    def test_artifact_binding_uses_exact_stable_bytes(self) -> None:
        raw = b'{"reviewed":true}'
        manifest = closed_manifest(
            {
                "items": [
                    {
                        "id": "phase0_boundary_approval",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ]
            }
        )
        self.assertTrue(
            manifest_artifact_sha256_matches(
                manifest,
                "phase0_boundary_approval",
                raw,
            )
        )
        self.assertFalse(
            manifest_artifact_sha256_matches(
                manifest,
                "phase0_boundary_approval",
                b'{"reviewed": true}',
            )
        )

    def test_artifact_locator_is_exact_absolute_and_case_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reviewed = root / "Reviewed.json"
            reviewed.write_text('{"reviewed":true}', encoding="utf-8")
            manifest = closed_manifest(
                {"items": [{"id": "phase0_boundary_approval"}]}
            )
            bind_manifest_item_bytes(
                manifest,
                "phase0_boundary_approval",
                reviewed.read_bytes(),
                path=reviewed,
            )
            self.assertEqual(
                manifest_artifact_path(
                    manifest,
                    "phase0_boundary_approval",
                    root / "unused" / ".." / reviewed.name,
                ),
                reviewed,
            )
            self.assertIsNone(
                manifest_artifact_path(
                    manifest,
                    "phase0_boundary_approval",
                    root / "reviewed.json",
                )
            )
            self.assertIsNone(
                manifest_artifact_path(
                    manifest,
                    "phase0_boundary_approval",
                    Path(reviewed.name),
                )
            )

    def test_stable_recheck_rejects_replacement_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reviewed.json"
            path.write_text('{"reviewed":true}', encoding="utf-8")
            _, raw, metadata = load_unique_json_with_bytes_and_metadata(path)
            replacement = root / "replacement.json"
            replacement.write_bytes(raw)
            os.replace(replacement, path)
            with self.assertRaises(StableFileError):
                recheck_stable_bytes(
                    path,
                    raw,
                    metadata,
                    require_single_link=True,
                )

            _, raw, metadata = load_unique_json_with_bytes_and_metadata(path)
            alias = root / "alias.json"
            try:
                os.link(path, alias)
            except OSError as error:
                self.skipTest(f"hardlinks unavailable: {error}")
            with self.assertRaises(StableFileError):
                recheck_stable_bytes(
                    path,
                    raw,
                    metadata,
                    require_single_link=True,
                )

    def test_consumer_rejects_same_bytes_at_a_different_locator_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reviewed = root / "reviewed.json"
            alias = root / "alias.json"
            raw = b'{"reviewed":true}'
            reviewed.write_bytes(raw)
            alias.write_bytes(raw)
            manifest = closed_manifest(
                {"items": [{"id": "phase0_boundary_approval"}]}
            )
            bind_manifest_item_bytes(
                manifest,
                "phase0_boundary_approval",
                raw,
                path=reviewed,
            )
            manifest_path = self._write(root, manifest)
            with mock.patch(
                "scripts.phase0_boundary_approval.load_unique_json_with_bytes_and_metadata"
            ) as input_load:
                self.assertEqual(
                    phase0_main(
                        [
                            "check",
                            "--input",
                            str(alias),
                            "--intake-manifest",
                            str(manifest_path),
                            *manifest_pin_arguments(manifest_path),
                        ]
                    ),
                    2,
                )
                input_load.assert_not_called()

    def test_bad_pin_fails_before_consumer_reads_other_evidence(self) -> None:
        manifest = closed_manifest({"items": []})
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), manifest)
            with mock.patch(
                "scripts.sub2_execution_evidence.load_unique_json_with_bytes_and_metadata"
            ) as evidence_load:
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

    def test_non_release_consumers_reject_partial_manifest_before_input_read(self) -> None:
        partial = {
            "schema_version": 2,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": "a" * 64,
            "items": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write(Path(temporary), partial)
            pins = [
                "--expected-intake-manifest-payload-sha256",
                canonical_payload_sha256(partial),
                "--expected-intake-manifest-file-sha256",
                hashlib.sha256(path.read_bytes()).hexdigest(),
            ]
            for main, patch_target in (
                (
                    phase0_main,
                    "scripts.phase0_boundary_approval.load_unique_json_with_bytes_and_metadata",
                ),
                (
                    pilot_inputs_main,
                    "scripts.phase6_pilot_inputs.load_unique_json_with_bytes_and_metadata",
                ),
            ):
                with self.subTest(main=main.__module__), mock.patch(
                    patch_target
                ) as input_load:
                    self.assertEqual(
                        main(
                            [
                                "check",
                                "--input",
                                str(path.parent / "input.json"),
                                "--intake-manifest",
                                str(path),
                                *pins,
                            ]
                        ),
                        2,
                    )
                    input_load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
