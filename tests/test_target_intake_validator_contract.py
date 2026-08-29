from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
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
            ("schema_version", 1),
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
        runtime_extra = copy.deepcopy(valid)
        runtime_extra["runtime_environment"]["extra"] = False
        mutations.append(runtime_extra)
        dependency_reordered = copy.deepcopy(valid)
        dependency_reordered["runtime_environment"]["distributions"][:2] = reversed(
            dependency_reordered["runtime_environment"]["distributions"][:2]
        )
        mutations.append(dependency_reordered)
        runtime_digest = copy.deepcopy(valid)
        runtime_digest["runtime_environment"]["distributions"][0][
            "record_sha256"
        ] = "A" * 64
        mutations.append(runtime_digest)

        for mutated in mutations:
            with self.subTest(mutated=mutated):
                self.assertTrue(contract.validator_contract_shape_errors(mutated))
                self.assertTrue(contract.validator_contract_errors(mutated, valid))

    def test_exact_comparison_rejects_one_source_digest_change(self) -> None:
        current = contract.current_validator_contract()
        claimed = copy.deepcopy(current)
        claimed["source_files"][0]["sha256"] = "0" * 64

        self.assertTrue(contract.validator_contract_errors(claimed, current))

    def test_exact_comparison_rejects_interpreter_os_and_dependency_drift(self) -> None:
        current = contract.current_validator_contract()
        mutations = []
        for section, key, value in (
            ("python", "version", "0.0.0"),
            ("operating_system", "machine", "other-machine"),
        ):
            changed = copy.deepcopy(current)
            changed["runtime_environment"][section][key] = value
            mutations.append(changed)
        dependency = copy.deepcopy(current)
        dependency["runtime_environment"]["distributions"][0]["version"] = "0"
        mutations.append(dependency)

        for changed in mutations:
            with self.subTest(changed=changed):
                self.assertEqual(contract.validator_contract_shape_errors(changed), [])
                self.assertTrue(contract.validator_contract_errors(changed, current))

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

    def test_capture_fails_closed_when_runtime_fingerprint_is_unavailable(self) -> None:
        with mock.patch.object(
            contract,
            "_current_runtime_environment",
            side_effect=contract.ValidatorContractError("unavailable"),
        ):
            with self.assertRaises(contract.ValidatorContractError):
                contract.current_validator_contract()

    def test_loaded_module_can_differ_from_later_on_disk_contract_capture(self) -> None:
        runtime_environment = contract._current_runtime_environment()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "validator.py"
            source.write_text('VALUE = "loaded-a"\n', encoding="utf-8")
            specification = importlib.util.spec_from_file_location(
                "temporary_loaded_validator", source
            )
            self.assertIsNotNone(specification)
            self.assertIsNotNone(specification.loader)
            module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
            source.write_text('VALUE = "disk-b"\n', encoding="utf-8")

            with (
                mock.patch.object(contract, "ROOT", root),
                mock.patch.object(contract, "SOURCE_FILES", ("validator.py",)),
                mock.patch.object(
                    contract,
                    "_current_runtime_environment",
                    return_value=runtime_environment,
                ),
            ):
                captured = contract.current_validator_contract()

            self.assertEqual(module.VALUE, "loaded-a")
            self.assertEqual(
                captured["source_files"][0]["sha256"],
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

    def test_source_inventory_capture_is_not_a_multi_file_atomic_snapshot(self) -> None:
        runtime_environment = contract._current_runtime_environment()
        reads = iter((b"epoch-a", b"epoch-b"))

        with (
            mock.patch.object(contract, "SOURCE_FILES", ("first.py", "second.py")),
            mock.patch.object(
                contract,
                "read_stable_bytes_with_metadata",
                side_effect=lambda *args, **kwargs: (
                    next(reads),
                    SimpleNamespace(st_nlink=1),
                ),
            ),
            mock.patch.object(
                contract,
                "_current_runtime_environment",
                return_value=runtime_environment,
            ),
        ):
            captured = contract.current_validator_contract()

        self.assertEqual(
            [item["sha256"] for item in captured["source_files"]],
            [
                hashlib.sha256(b"epoch-a").hexdigest(),
                hashlib.sha256(b"epoch-b").hexdigest(),
            ],
        )

if __name__ == "__main__":
    unittest.main()
