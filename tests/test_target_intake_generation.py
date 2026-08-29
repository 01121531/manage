from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.target_intake_generation import (
    GenerationLineageError,
    create_genesis_receipt,
    create_registration_receipt,
    load_generation_lineage,
    receipt_bytes,
)
from scripts.target_intake_manifest import canonical_payload_sha256
from scripts.target_intake_preflight import create_intake_manifest


class TargetIntakeGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements = json.loads(
            Path("deploy/target-intake-requirements.json").read_text(encoding="utf-8")
        )

    @staticmethod
    def _pins(document: dict, raw: bytes) -> tuple[str, str]:
        return canonical_payload_sha256(document), hashlib.sha256(raw).hexdigest()

    def _genesis(self, root: Path):
        manifest = create_intake_manifest("staging", self.requirements)
        manifest_path = root / "generation-000.json"
        manifest_raw = receipt_bytes(manifest)
        manifest_path.write_bytes(manifest_raw)
        receipt = create_genesis_receipt(manifest_path, manifest, manifest_raw)
        receipt_path = root / "generation-000.receipt.json"
        receipt_raw = receipt_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        receipt_pins = self._pins(receipt, receipt_raw)
        lineage = load_generation_lineage(
            manifest_path,
            receipt_path,
            expected_receipt_payload_sha256=receipt_pins[0],
            expected_receipt_file_sha256=receipt_pins[1],
            expected_manifest_payload_sha256=canonical_payload_sha256(manifest),
            expected_manifest_file_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        )
        return manifest_path, receipt_path, lineage

    def _child(self, root: Path, predecessor):
        manifest = copy.deepcopy(predecessor.manifest)
        item = manifest["items"][0]
        item.update(
            {
                "status": "provided",
                "artifact_path": str(root / "artifact.json"),
                "sha256": "a" * 64,
                "reviewed_by": "review-record-42",
                "reviewed_at": "2026-08-29T01:00:00Z",
                "redaction_confirmed": True,
            }
        )
        manifest_path = root / "generation-001.json"
        manifest_raw = receipt_bytes(manifest)
        manifest_path.write_bytes(manifest_raw)
        candidate_raw = receipt_bytes(manifest)
        receipt = create_registration_receipt(
            manifest_path=manifest_path,
            manifest=manifest,
            manifest_raw=manifest_raw,
            predecessor=predecessor,
            predecessor_manifest_path=root / "generation-000.json",
            predecessor_receipt_path=root / "generation-000.receipt.json",
            registered_item_id=item["id"],
            artifact_sha256=item["sha256"],
            candidate_raw=candidate_raw,
        )
        receipt_path = root / "generation-001.receipt.json"
        receipt_raw = receipt_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        return manifest, manifest_path, receipt, receipt_path, receipt_raw

    def test_loads_complete_caller_pinned_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, predecessor = self._genesis(root)
            manifest, manifest_path, receipt, receipt_path, receipt_raw = self._child(
                root, predecessor
            )
            pins = self._pins(receipt, receipt_raw)

            lineage = load_generation_lineage(
                manifest_path,
                receipt_path,
                expected_receipt_payload_sha256=pins[0],
                expected_receipt_file_sha256=pins[1],
            )

            self.assertEqual(lineage.manifest, manifest)
            self.assertEqual(lineage.receipt["sequence"], 1)
            self.assertEqual(len(lineage.snapshots), 4)

    def test_rejects_wrong_pin_detached_leaf_and_locator_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, predecessor = self._genesis(root)
            manifest, manifest_path, receipt, receipt_path, receipt_raw = self._child(
                root, predecessor
            )
            pins = self._pins(receipt, receipt_raw)
            with self.assertRaises(GenerationLineageError):
                load_generation_lineage(
                    manifest_path,
                    receipt_path,
                    expected_receipt_payload_sha256="f" * 64,
                    expected_receipt_file_sha256=pins[1],
                )

            detached = root / "detached-identical.json"
            detached.write_bytes(receipt_bytes(manifest))
            with self.assertRaises(GenerationLineageError):
                load_generation_lineage(
                    detached,
                    receipt_path,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                )

    def test_rejects_broken_predecessor_selector_and_registered_item_lie(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, predecessor = self._genesis(root)
            _, manifest_path, receipt, _, _ = self._child(root, predecessor)
            receipt["predecessor"]["manifest"]["file_sha256"] = "b" * 64
            receipt["registered_item"]["id"] = receipt["manifest"]["path"]
            bad_path = root / "bad.receipt.json"
            bad_raw = receipt_bytes(receipt)
            bad_path.write_bytes(bad_raw)
            pins = self._pins(receipt, bad_raw)

            with self.assertRaises(GenerationLineageError):
                load_generation_lineage(
                    manifest_path,
                    bad_path,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                )


if __name__ == "__main__":
    unittest.main()
