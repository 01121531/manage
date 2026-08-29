from __future__ import annotations

import copy
from types import SimpleNamespace
import unittest
from unittest import mock

import scripts.target_intake_validator_contract as contract


class TargetIntakeValidatorContractTests(unittest.TestCase):
    def test_current_contract_is_closed_deterministic_and_exact(self) -> None:
        first = contract.current_validator_contract()
        second = contract.current_validator_contract()

        self.assertEqual(first, second)
        self.assertEqual(contract.validator_contract_shape_errors(first), [])
        self.assertEqual(
            [item["path"] for item in first["source_files"]],
            list(contract.SOURCE_FILES),
        )
        self.assertEqual(contract.validator_contract_errors(first, second), [])

    def test_closed_shape_rejects_identity_inventory_and_digest_drift(self) -> None:
        valid = contract.current_validator_contract()
        mutations = []
        for key, value in (
            ("schema_version", 2),
            ("kind", "other"),
            ("production_acceptance", True),
            ("authoring_entrypoint", "other:author"),
            ("replay_entrypoint", "other:replay"),
        ):
            mutated = copy.deepcopy(valid)
            mutated[key] = value
            mutations.append(mutated)
        missing = copy.deepcopy(valid)
        missing.pop("replay_entrypoint")
        mutations.append(missing)
        extra = copy.deepcopy(valid)
        extra["extra"] = False
        mutations.append(extra)
        reordered = copy.deepcopy(valid)
        reordered["source_files"][:2] = reversed(reordered["source_files"][:2])
        mutations.append(reordered)
        bad_digest = copy.deepcopy(valid)
        bad_digest["source_files"][0]["sha256"] = "A" * 64
        mutations.append(bad_digest)

        for mutated in mutations:
            with self.subTest(mutated=mutated):
                self.assertTrue(contract.validator_contract_shape_errors(mutated))
                self.assertTrue(contract.validator_contract_errors(mutated, valid))

    def test_exact_comparison_rejects_one_source_digest_change(self) -> None:
        current = contract.current_validator_contract()
        claimed = copy.deepcopy(current)
        claimed["source_files"][0]["sha256"] = "0" * 64

        self.assertTrue(contract.validator_contract_errors(claimed, current))

    def test_capture_fails_closed_for_unreadable_or_multi_link_source(self) -> None:
        with mock.patch.object(
            contract,
            "read_stable_bytes_with_metadata",
            side_effect=OSError("unavailable"),
        ):
            with self.assertRaises(contract.ValidatorContractError):
                contract.current_validator_contract()

        with mock.patch.object(
            contract,
            "read_stable_bytes_with_metadata",
            return_value=(b"source", SimpleNamespace(st_nlink=2)),
        ):
            with self.assertRaises(contract.ValidatorContractError):
                contract.current_validator_contract()


if __name__ == "__main__":
    unittest.main()
