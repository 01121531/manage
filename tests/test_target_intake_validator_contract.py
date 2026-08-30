from __future__ import annotations

import copy
import hashlib
import importlib.util
import importlib.machinery
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
        self.assertEqual(
            first["execution_profile"]["mode"],
            contract.DIRECT_EXECUTION_MODE,
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
        stdlib_digest = copy.deepcopy(valid)
        stdlib_digest["runtime_environment"]["python"][
            "stdlib_payload_tree_sha256"
        ] = "A" * 64
        mutations.append(stdlib_digest)
        invalid_closure_name = copy.deepcopy(valid)
        invalid_closure_name["runtime_environment"]["distribution_closure"][
            "metadata_closure_names"
        ][0] = "---"
        mutations.append(invalid_closure_name)
        execution_mode = copy.deepcopy(valid)
        execution_mode["execution_profile"]["mode"] = (
            contract.SNAPSHOT_EXECUTION_MODE
        )
        mutations.append(execution_mode)

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

    def test_runtime_binds_stdlib_and_native_payload_trees(self) -> None:
        current = contract.current_validator_contract()
        stdlib_path = Path(contract.sysconfig.get_path("stdlib")) / "platform.py"
        python = current["runtime_environment"]["python"]
        self.assertGreater(python["stdlib_payload_file_count"], 1)
        self.assertGreater(python["stdlib_payload_size_bytes"], 1)
        self.assertRegex(python["stdlib_payload_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(python["native_payload_file_count"], 1)
        self.assertGreater(python["native_payload_size_bytes"], 1)
        self.assertRegex(python["native_payload_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            Path(contract.runtime_platform.python_implementation.__code__.co_filename),
            stdlib_path,
        )

    def test_runtime_binds_metadata_closure_and_selected_loaded_owner_union(self) -> None:
        direct = contract._current_runtime_environment()
        direct_closure = direct["distribution_closure"]
        self.assertEqual(direct_closure["root_names"], list(contract.DEPENDENCY_ROOT_NAMES))
        self.assertIn("annotated-types", direct_closure["metadata_closure_names"])
        self.assertNotIn("pip", direct_closure["union_names"])

        selected = {
            "owner_names": ["pip"],
            "origin_file_count": 1,
            "origin_map_sha256": "a" * 64,
        }
        loaded = contract._current_runtime_environment(selected)
        loaded_closure = loaded["distribution_closure"]
        self.assertIn("pip", loaded_closure["loaded_owner_names"])
        self.assertIn("pip", loaded_closure["union_names"])
        self.assertIn("packaging", loaded_closure["union_names"])
        self.assertEqual(
            [item["name"] for item in loaded["distributions"]],
            loaded_closure["union_names"],
        )

    def test_loaded_distribution_selection_rejects_sourceless_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            origin = root / "poison.pyc"
            origin.write_bytes(b"pyc")
            module = SimpleNamespace(
                __spec__=SimpleNamespace(
                    origin=str(origin),
                    loader=importlib.machinery.SourcelessFileLoader(
                        "poison", str(origin)
                    ),
                    submodule_search_locations=None,
                ),
                __file__=str(origin),
            )
            with (
                mock.patch.object(contract, "_site_package_roots", return_value=(root,)),
                mock.patch.object(contract, "_distribution_installation_index", return_value={}),
                mock.patch.object(contract.sys, "modules", {"poison": module}),
                self.assertRaises(contract.ValidatorContractError),
            ):
                contract._loaded_distribution_selection()

    def test_distribution_secondary_payload_drift_changes_tree_root(self) -> None:
        class Entry:
            def __init__(self, value: str) -> None:
                self.value = value
                self.hash = None

            def __str__(self) -> str:
                return self.value

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "fakepkg"
            dist_info = root / "fakepkg-1.0.dist-info"
            package.mkdir()
            dist_info.mkdir()
            (package / "__init__.py").write_text("from . import helper\n")
            helper = package / "helper.py"
            helper.write_text('VALUE = "a"\n')
            (dist_info / "METADATA").write_text("Name: fakepkg\nVersion: 1.0\n")
            (dist_info / "RECORD").write_text("record\n")
            entries = [
                Entry("fakepkg/__init__.py"),
                Entry("fakepkg/helper.py"),
                Entry("fakepkg-1.0.dist-info/METADATA"),
                Entry("fakepkg-1.0.dist-info/RECORD"),
            ]
            distribution = SimpleNamespace(
                files=entries,
                version="1.0",
                locate_file=lambda entry: root / str(entry),
            )
            specification = SimpleNamespace(
                origin=str(package / "__init__.py"),
                submodule_search_locations=[str(package)],
            )
            with (
                mock.patch.object(
                    contract.importlib.metadata,
                    "distribution",
                    return_value=distribution,
                ),
                mock.patch.object(
                    contract.importlib.util,
                    "find_spec",
                    return_value=specification,
                ),
            ):
                first = contract._distribution_fingerprint("fakepkg", "fakepkg")
                helper.write_text('VALUE = "b"\n')
                second = contract._distribution_fingerprint("fakepkg", "fakepkg")

            self.assertNotEqual(
                first["payload_tree_sha256"], second["payload_tree_sha256"]
            )

    def test_distribution_rejects_record_omitted_importable_file(self) -> None:
        class Entry:
            def __init__(self, value: str) -> None:
                self.value = value
                self.hash = None

            def __str__(self) -> str:
                return self.value

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "fakepkg"
            dist_info = root / "fakepkg-1.0.dist-info"
            package.mkdir()
            dist_info.mkdir()
            (package / "__init__.py").write_text("from . import hidden\n")
            (package / "hidden.py").write_text('VALUE = "unrecorded"\n')
            (dist_info / "METADATA").write_text("Name: fakepkg\nVersion: 1.0\n")
            (dist_info / "RECORD").write_text("record\n")
            entries = [
                Entry("fakepkg/__init__.py"),
                Entry("fakepkg-1.0.dist-info/METADATA"),
                Entry("fakepkg-1.0.dist-info/RECORD"),
            ]
            distribution = SimpleNamespace(
                files=entries,
                version="1.0",
                locate_file=lambda entry: root / str(entry),
            )
            specification = SimpleNamespace(
                origin=str(package / "__init__.py"),
                submodule_search_locations=[str(package)],
            )
            with (
                mock.patch.object(
                    contract.importlib.metadata,
                    "distribution",
                    return_value=distribution,
                ),
                mock.patch.object(
                    contract.importlib.util,
                    "find_spec",
                    return_value=specification,
                ),
                self.assertRaises(contract.ValidatorContractError),
            ):
                contract._distribution_fingerprint("fakepkg", "fakepkg")

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
