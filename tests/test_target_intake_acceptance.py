from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.target_intake_acceptance import (
    AcceptanceReceiptError,
    acceptance_receipt_bytes,
    create_finalization_receipt,
    create_snapshot_receipt,
    finalization_receipt_errors,
    load_finalization_acceptance,
    load_snapshot_acceptance,
    snapshot_receipt_errors,
)
from scripts.target_intake_generation import (
    create_genesis_receipt,
    load_generation_lineage,
    receipt_bytes,
)
from scripts.target_intake_manifest import canonical_payload_sha256
from scripts.target_intake_preflight import create_intake_manifest


class TargetIntakeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements = json.loads(
            Path("deploy/target-intake-requirements.json").read_text(
                encoding="utf-8"
            )
        )

    @staticmethod
    def _pins(document: dict, raw: bytes) -> tuple[str, str]:
        return canonical_payload_sha256(document), hashlib.sha256(raw).hexdigest()

    def _generation(self, root: Path, stem: str):
        manifest = create_intake_manifest("staging", self.requirements)
        manifest_path = root / f"{stem}.json"
        manifest_raw = receipt_bytes(manifest)
        manifest_path.write_bytes(manifest_raw)
        receipt_path = root / f"{stem}.receipt.json"
        receipt = create_genesis_receipt(
            manifest_path,
            receipt_path,
            manifest,
            manifest_raw,
        )
        receipt_raw = receipt_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        pins = self._pins(receipt, receipt_raw)
        lineage = load_generation_lineage(
            manifest_path,
            receipt_path,
            expected_receipt_payload_sha256=pins[0],
            expected_receipt_file_sha256=pins[1],
        )
        return manifest_path, receipt_path, lineage

    def _snapshot(self, root: Path, stem: str = "generation-000"):
        manifest_path, generation_receipt_path, lineage = self._generation(
            root,
            stem,
        )
        checkpoint_path = root / f"{stem}.phase0.json"
        checkpoint_path.write_bytes(lineage.manifest_raw)
        receipt_path = root / f"{stem}.phase0.receipt.json"
        receipt = create_snapshot_receipt(
            source_lineage=lineage,
            source_manifest_path=manifest_path,
            source_receipt_path=generation_receipt_path,
            checkpoint_path=checkpoint_path,
            receipt_path=receipt_path,
            checkpoint=lineage.manifest,
            checkpoint_raw=lineage.manifest_raw,
            evaluated_at="2026-08-29T01:00:00.000000Z",
            valid_from="2026-08-29T00:00:00.000000Z",
            valid_until="2026-08-30T00:00:00.000000Z",
        )
        receipt_raw = acceptance_receipt_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        pins = self._pins(receipt, receipt_raw)
        acceptance = load_snapshot_acceptance(
            checkpoint_path,
            receipt_path,
            expected_receipt_payload_sha256=pins[0],
            expected_receipt_file_sha256=pins[1],
        )
        return (
            manifest_path,
            generation_receipt_path,
            lineage,
            checkpoint_path,
            receipt_path,
            acceptance,
        )

    def test_loads_closed_snapshot_and_finalization_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                manifest_path,
                generation_receipt_path,
                lineage,
                checkpoint_path,
                snapshot_receipt_path,
                snapshot,
            ) = self._snapshot(root)
            self.assertEqual(snapshot.receipt["schema_version"], 2)
            self.assertEqual(snapshot.receipt["receipt_path"], str(snapshot_receipt_path))
            self.assertEqual(snapshot.receipt["checkpoint_phase"], 0)
            self.assertEqual(snapshot.receipt["result_checkpoint"]["path"], str(checkpoint_path))

            final_path = root / "final.json"
            final_path.write_bytes(lineage.manifest_raw)
            receipt_path = root / "final.receipt.json"
            receipt = create_finalization_receipt(
                source_lineage=lineage,
                source_manifest_path=manifest_path,
                source_receipt_path=generation_receipt_path,
                phase0_snapshot=snapshot,
                phase0_checkpoint_path=checkpoint_path,
                phase0_receipt_path=snapshot_receipt_path,
                finalized_path=final_path,
                receipt_path=receipt_path,
                finalized_manifest=lineage.manifest,
                finalized_raw=lineage.manifest_raw,
                evaluated_at="2026-08-29T02:00:00.000000Z",
            )
            receipt_raw = acceptance_receipt_bytes(receipt)
            receipt_path.write_bytes(receipt_raw)
            pins = self._pins(receipt, receipt_raw)
            finalization = load_finalization_acceptance(
                final_path,
                receipt_path,
                checkpoint_path,
                expected_receipt_payload_sha256=pins[0],
                expected_receipt_file_sha256=pins[1],
                expected_manifest_payload_sha256=canonical_payload_sha256(
                    lineage.manifest
                ),
                expected_manifest_file_sha256=hashlib.sha256(
                    lineage.manifest_raw
                ).hexdigest(),
            )
            self.assertEqual(finalization.receipt["schema_version"], 2)
            self.assertEqual(finalization.receipt["receipt_path"], str(receipt_path))
            self.assertEqual(
                finalization.receipt["evaluated_at"],
                "2026-08-29T02:00:00.000000Z",
            )
            self.assertEqual(finalization.finalized_manifest, lineage.manifest)
            alias = root / "final.receipt.alias.json"
            alias.write_bytes(receipt_raw)
            with self.assertRaises(AcceptanceReceiptError):
                load_finalization_acceptance(
                    final_path,
                    alias,
                    checkpoint_path,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                    expected_manifest_payload_sha256=canonical_payload_sha256(
                        lineage.manifest
                    ),
                    expected_manifest_file_sha256=hashlib.sha256(
                        lineage.manifest_raw
                    ).hexdigest(),
                )

    def test_rejects_locator_alias_and_checkpoint_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                manifest_path,
                generation_receipt_path,
                lineage,
                checkpoint_path,
                snapshot_receipt_path,
                snapshot,
            ) = self._snapshot(root, "fork-a")
            alias = root / "checkpoint-alias.json"
            alias.write_bytes(snapshot.checkpoint_raw)
            pins = self._pins(snapshot.receipt, snapshot.receipt_raw)
            with self.assertRaises(AcceptanceReceiptError):
                load_snapshot_acceptance(
                    alias,
                    snapshot_receipt_path,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                )

            receipt_alias = root / "snapshot-receipt-alias.json"
            receipt_alias.write_bytes(snapshot.receipt_raw)
            with self.assertRaises(AcceptanceReceiptError):
                load_snapshot_acceptance(
                    checkpoint_path,
                    receipt_alias,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                )

            other_manifest_path, other_receipt_path, other_lineage = self._generation(
                root,
                "fork-b",
            )
            self.assertEqual(other_lineage.manifest, lineage.manifest)
            final_path = root / "fork-b-final.json"
            final_path.write_bytes(other_lineage.manifest_raw)
            final_receipt_path = root / "fork-b-final.receipt.json"
            with self.assertRaises(AcceptanceReceiptError):
                create_finalization_receipt(
                    source_lineage=other_lineage,
                    source_manifest_path=other_manifest_path,
                    source_receipt_path=other_receipt_path,
                    phase0_snapshot=snapshot,
                    phase0_checkpoint_path=checkpoint_path,
                    phase0_receipt_path=snapshot_receipt_path,
                    finalized_path=final_path,
                    receipt_path=final_receipt_path,
                    finalized_manifest=other_lineage.manifest,
                    finalized_raw=other_lineage.manifest_raw,
                    evaluated_at="2026-08-29T02:00:00.000000Z",
                )

    def test_rejects_open_schema_invalid_window_and_tampered_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, snapshot = self._snapshot(root)
            invalid = copy.deepcopy(snapshot.receipt)
            invalid["unknown"] = True
            self.assertTrue(snapshot_receipt_errors(invalid))
            invalid = copy.deepcopy(snapshot.receipt)
            invalid["evaluated_at"] = invalid["valid_until"]
            self.assertTrue(snapshot_receipt_errors(invalid))

            final_shape = {
                "schema_version": 2,
                "kind": "target_intake_finalization_receipt_v2",
                "production_acceptance": False,
                "receipt_path": str((root / "final.receipt.json").resolve()),
                "evaluated_at": "2026-08-29T02:00:00.000000Z",
                "source_generation": snapshot.receipt["source_generation"],
                "phase0_snapshot": {
                    "checkpoint": snapshot.receipt["result_checkpoint"],
                    "receipt": {
                        "path": str((root / "missing.json").resolve()),
                        "payload_sha256": "a" * 64,
                        "file_sha256": "b" * 64,
                    },
                },
                "result_final_manifest": snapshot.receipt["result_checkpoint"],
            }
            self.assertTrue(finalization_receipt_errors({**final_shape, "extra": 1}))

    def test_same_path_same_bytes_recreation_remains_an_external_custody_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_, checkpoint_path, receipt_path, acceptance = self._snapshot(root)
            checkpoint_raw = acceptance.checkpoint_raw
            receipt_raw = acceptance.receipt_raw
            pins = self._pins(acceptance.receipt, receipt_raw)

            checkpoint_path.unlink()
            receipt_path.unlink()
            checkpoint_path.write_bytes(checkpoint_raw)
            receipt_path.write_bytes(receipt_raw)

            recreated = load_snapshot_acceptance(
                checkpoint_path,
                receipt_path,
                expected_receipt_payload_sha256=pins[0],
                expected_receipt_file_sha256=pins[1],
            )
            self.assertEqual(recreated.checkpoint_raw, checkpoint_raw)
            self.assertEqual(recreated.receipt_raw, receipt_raw)


if __name__ == "__main__":
    unittest.main()
