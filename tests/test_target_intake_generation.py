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
from scripts.target_intake_preflight import (
    _generation_semantic_replay_errors,
    create_intake_manifest,
)
from scripts.target_intake_validator_contract import current_validator_contract


class TargetIntakeGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements = json.loads(
            Path("deploy/target-intake-requirements.json").read_text(encoding="utf-8")
        )
        self.matrix = json.loads(
            Path("deploy/phase-acceptance-matrix.json").read_text(encoding="utf-8")
        )
        self.validator_contract = current_validator_contract()

    @staticmethod
    def _pins(document: dict, raw: bytes) -> tuple[str, str]:
        return canonical_payload_sha256(document), hashlib.sha256(raw).hexdigest()

    def _genesis(self, root: Path):
        manifest = create_intake_manifest("staging", self.requirements)
        manifest_path = root / "generation-000.json"
        manifest_raw = receipt_bytes(manifest)
        manifest_path.write_bytes(manifest_raw)
        receipt_path = root / "generation-000.receipt.json"
        receipt = create_genesis_receipt(
            manifest_path,
            receipt_path,
            manifest,
            manifest_raw,
            evaluated_at="2026-08-29T00:00:00.000000Z",
            requirements=self.requirements,
            phase_acceptance_matrix=self.matrix,
            validator_contract=self.validator_contract,
        )
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
        receipt_path = root / "generation-001.receipt.json"
        receipt = create_registration_receipt(
            manifest_path=manifest_path,
            manifest=manifest,
            manifest_raw=manifest_raw,
            receipt_path=receipt_path,
            predecessor=predecessor,
            predecessor_manifest_path=root / "generation-000.json",
            predecessor_receipt_path=root / "generation-000.receipt.json",
            registered_item_id=item["id"],
            artifact_sha256=item["sha256"],
            candidate_raw=candidate_raw,
            evaluated_at="2026-08-29T01:00:00.000000Z",
            requirements=self.requirements,
            phase_acceptance_matrix=self.matrix,
            validator_contract=self.validator_contract,
        )
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
            self.assertEqual(lineage.receipt["schema_version"], 8)
            self.assertEqual(
                lineage.receipt["kind"],
                "target_intake_generation_receipt_v8",
            )
            self.assertEqual(lineage.receipt["receipt_path"], str(receipt_path))
            self.assertEqual(len(lineage.snapshots), 4)
            self.assertNotEqual(_generation_semantic_replay_errors(lineage), [])

    def test_genesis_replays_embedded_historical_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical = copy.deepcopy(self.requirements)
            historical["requirements"][0]["purpose"] += " (historical snapshot)"
            manifest = create_intake_manifest("staging", historical)
            manifest_path = root / "historical.json"
            manifest_raw = receipt_bytes(manifest)
            manifest_path.write_bytes(manifest_raw)
            receipt_path = root / "historical.receipt.json"
            receipt = create_genesis_receipt(
                manifest_path,
                receipt_path,
                manifest,
                manifest_raw,
                evaluated_at="2026-08-29T00:00:00.000000Z",
                requirements=historical,
                phase_acceptance_matrix=self.matrix,
                validator_contract=self.validator_contract,
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

            self.assertNotEqual(
                manifest["requirements_sha256"],
                canonical_payload_sha256(self.requirements),
            )
            self.assertEqual(_generation_semantic_replay_errors(lineage), [])

    def test_rejects_legacy_receipts_and_non_monotonic_receipt_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, predecessor = self._genesis(root)
            _, manifest_path, receipt, receipt_path, _ = self._child(root, predecessor)
            for name, mutation in (
                ("v2", lambda value: value.update({"schema_version": 2})),
                (
                    "v3",
                    lambda value: value.update(
                        {
                            "schema_version": 3,
                            "kind": "target_intake_generation_receipt_v3",
                        }
                    ),
                ),
                (
                    "v4",
                    lambda value: value.update(
                        {
                            "schema_version": 4,
                            "kind": "target_intake_generation_receipt_v4",
                        }
                    ),
                ),
                (
                    "v5",
                    lambda value: value.update(
                        {
                            "schema_version": 5,
                            "kind": "target_intake_generation_receipt_v5",
                        }
                    ),
                ),
                (
                    "v6",
                    lambda value: value.update(
                        {
                            "schema_version": 15,
                            "kind": "target_intake_generation_receipt_v6",
                        }
                    ),
                ),
                (
                    "v7",
                    lambda value: value.update(
                        {
                            "schema_version": 7,
                            "kind": "target_intake_generation_receipt_v7",
                        }
                    ),
                ),
                (
                    "backdated",
                    lambda value: value["validation_context"].update(
                        {"evaluated_at": "2026-08-28T23:59:59.000000Z"}
                    ),
                ),
            ):
                invalid = copy.deepcopy(receipt)
                invalid_path = root / f"{name}.receipt.json"
                invalid["receipt_path"] = str(invalid_path)
                mutation(invalid)
                invalid_raw = receipt_bytes(invalid)
                invalid_path.write_bytes(invalid_raw)
                pins = self._pins(invalid, invalid_raw)
                with self.assertRaises(GenerationLineageError):
                    load_generation_lineage(
                        manifest_path,
                        invalid_path,
                        expected_receipt_payload_sha256=pins[0],
                        expected_receipt_file_sha256=pins[1],
                    )

    def test_semantic_replay_rejects_re_pinned_on_disk_source_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, receipt_path, lineage = self._genesis(root)
            changed = copy.deepcopy(lineage.receipt)
            changed["validation_context"]["validator_contract"]["source_files"][0][
                "sha256"
            ] = "0" * 64
            changed_raw = receipt_bytes(changed)
            receipt_path.write_bytes(changed_raw)
            pins = self._pins(changed, changed_raw)
            re_pinned = load_generation_lineage(
                manifest_path,
                receipt_path,
                expected_receipt_payload_sha256=pins[0],
                expected_receipt_file_sha256=pins[1],
            )

            before = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in (manifest_path, receipt_path)
            }
            self.assertTrue(_generation_semantic_replay_errors(re_pinned))
            self.assertEqual(
                before,
                {
                    path: (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in (manifest_path, receipt_path)
                },
            )

    def test_semantic_replay_rejects_re_pinned_runtime_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, receipt_path, lineage = self._genesis(root)
            changed = copy.deepcopy(lineage.receipt)
            changed["validation_context"]["validator_contract"][
                "runtime_environment"
            ]["python"]["version"] = "0.0.0"
            changed_raw = receipt_bytes(changed)
            receipt_path.write_bytes(changed_raw)
            pins = self._pins(changed, changed_raw)
            re_pinned = load_generation_lineage(
                manifest_path,
                receipt_path,
                expected_receipt_payload_sha256=pins[0],
                expected_receipt_file_sha256=pins[1],
            )

            self.assertTrue(_generation_semantic_replay_errors(re_pinned))

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

            receipt_alias = root / "generation-001-receipt-alias.json"
            receipt_alias.write_bytes(receipt_raw)
            with self.assertRaises(GenerationLineageError):
                load_generation_lineage(
                    manifest_path,
                    receipt_alias,
                    expected_receipt_payload_sha256=pins[0],
                    expected_receipt_file_sha256=pins[1],
                )

            predecessor_receipt_alias = root / "generation-000-receipt-alias.json"
            predecessor_receipt_alias.write_bytes(predecessor.receipt_raw)
            with self.assertRaises(GenerationLineageError):
                create_registration_receipt(
                    manifest_path=manifest_path,
                    manifest=manifest,
                    manifest_raw=receipt_bytes(manifest),
                    receipt_path=root / "laundered.receipt.json",
                    predecessor=predecessor,
                    predecessor_manifest_path=root / "generation-000.json",
                    predecessor_receipt_path=predecessor_receipt_alias,
                    registered_item_id=receipt["registered_item"]["id"],
                    artifact_sha256=receipt["registered_item"]["artifact_sha256"],
                    candidate_raw=receipt_bytes(manifest),
                    evaluated_at="2026-08-29T01:00:00.000000Z",
                    requirements=self.requirements,
                    phase_acceptance_matrix=self.matrix,
                    validator_contract=self.validator_contract,
                )

    def test_rejects_broken_predecessor_selector_and_registered_item_lie(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, predecessor = self._genesis(root)
            _, manifest_path, receipt, _, _ = self._child(root, predecessor)
            valid_receipt = copy.deepcopy(receipt)
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

            for field, value in (
                ("schema_version", 1),
                ("receipt_path", "relative-receipt.json"),
            ):
                invalid_path = root / f"invalid-{field}.receipt.json"
                invalid = copy.deepcopy(valid_receipt)
                invalid["receipt_path"] = str(invalid_path)
                invalid[field] = value
                invalid_raw = receipt_bytes(invalid)
                invalid_path.write_bytes(invalid_raw)
                invalid_pins = self._pins(invalid, invalid_raw)
                with self.assertRaises(GenerationLineageError):
                    load_generation_lineage(
                        manifest_path,
                        invalid_path,
                        expected_receipt_payload_sha256=invalid_pins[0],
                        expected_receipt_file_sha256=invalid_pins[1],
                    )

    def test_same_path_recreation_and_whole_generation_rollback_are_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, receipt_path, old_lineage = self._genesis(root)
            old_manifest_raw = manifest_path.read_bytes()
            old_receipt_raw = receipt_path.read_bytes()
            old_manifest_pins = self._pins(old_lineage.manifest, old_manifest_raw)
            old_receipt_pins = self._pins(old_lineage.receipt, old_receipt_raw)
            self._child(root, old_lineage)

            manifest_path.unlink()
            receipt_path.unlink()
            manifest_path.write_bytes(old_manifest_raw)
            receipt_path.write_bytes(old_receipt_raw)
            recovered = load_generation_lineage(
                manifest_path,
                receipt_path,
                expected_receipt_payload_sha256=old_receipt_pins[0],
                expected_receipt_file_sha256=old_receipt_pins[1],
                expected_manifest_payload_sha256=old_manifest_pins[0],
                expected_manifest_file_sha256=old_manifest_pins[1],
            )

            self.assertEqual(recovered.receipt["sequence"], 0)

    def test_self_reported_host_time_remains_untrusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = create_intake_manifest("staging", self.requirements)
            manifest_path = root / "future.json"
            manifest_raw = receipt_bytes(manifest)
            manifest_path.write_bytes(manifest_raw)
            receipt_path = root / "future.receipt.json"
            receipt = create_genesis_receipt(
                manifest_path,
                receipt_path,
                manifest,
                manifest_raw,
                evaluated_at="2099-12-31T23:59:59.000000Z",
                requirements=self.requirements,
                phase_acceptance_matrix=self.matrix,
                validator_contract=self.validator_contract,
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

            self.assertEqual(
                lineage.receipt["validation_context"]["evaluated_at"],
                "2099-12-31T23:59:59.000000Z",
            )
            self.assertEqual(_generation_semantic_replay_errors(lineage), [])


if __name__ == "__main__":
    unittest.main()
