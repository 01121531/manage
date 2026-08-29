from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_vault_broker_contract


class VaultBrokerAssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.contract_text,
            self.policies,
            self.configure_text,
        ) = verify_vault_broker_contract.load_assets()

    @staticmethod
    def _run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_vault_broker_contract.main()
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def _fixed_failure() -> tuple[int, str, str]:
        return (1, "", "Unable to load Vault broker assets\n")

    @staticmethod
    def _policy_names() -> tuple[str, ...]:
        return tuple(
            service["issuer_policy_file"]
            for service in verify_vault_broker_contract.EXPECTED_SERVICES
        )

    def _repository_assets(self) -> list[tuple[Path, str]]:
        return [
            (verify_vault_broker_contract.CONTRACT, self.contract_text),
            *[
                (
                    verify_vault_broker_contract.POLICY_DIR / name,
                    self.policies[name],
                )
                for name in self._policy_names()
            ],
            (verify_vault_broker_contract.CONFIGURE, self.configure_text),
        ]

    def _write_workspace(self, root: Path) -> list[tuple[Path, str]]:
        contract = root / "broker-contract.json"
        policy_dir = root / "policies"
        configure = root / "configure-broker-issuer-policies.sh"
        policy_dir.mkdir(parents=True)
        contract.write_text(self.contract_text, encoding="utf-8")
        for name, text in self.policies.items():
            (policy_dir / name).write_text(text, encoding="utf-8")
        configure.write_text(self.configure_text, encoding="utf-8")
        return [
            (contract, self.contract_text),
            *[
                (policy_dir / name, self.policies[name])
                for name in self._policy_names()
            ],
            (configure, self.configure_text),
        ]

    @staticmethod
    def _path_patches(root: Path):
        return (
            mock.patch.object(
                verify_vault_broker_contract,
                "CONTRACT",
                root / "broker-contract.json",
            ),
            mock.patch.object(
                verify_vault_broker_contract,
                "POLICY_DIR",
                root / "policies",
            ),
            mock.patch.object(
                verify_vault_broker_contract,
                "CONFIGURE",
                root / "configure-broker-issuer-policies.sh",
            ),
        )

    @staticmethod
    def _padded_source(path: Path, text: str, limit: int) -> bytes:
        source = text.encode("utf-8")
        if not source.endswith(b"\n"):
            source += b"\n"
        padding = limit - len(source)
        if path.suffix == ".json":
            return source + b" " * padding
        return source + b"#" + b"x" * (padding - 1)

    def _selective_loader(
        self,
        target: Path,
        assets: list[tuple[Path, str]],
    ):
        defaults = dict(assets)

        def load(path: Path, *, max_bytes: int) -> str:
            if path == target:
                return external_text.load_stable_text(
                    path,
                    max_bytes=max_bytes,
                )
            return defaults[path]

        return load

    def test_all_five_assets_are_loaded_once_without_path_read_text(self) -> None:
        assets = self._repository_assets()
        protected = {path for path, _ in assets}
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in protected:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_vault_broker_contract,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            self.assertEqual(
                self._run_main(),
                (
                    0,
                    "vault-broker-contract-ok issuers=3 production_acceptance=false "
                    "revocation=external-approved-rotator\n",
                    "",
                ),
            )

        self.assertEqual(
            stable_read.call_args_list,
            [
                mock.call(
                    path,
                    max_bytes=(
                        verify_vault_broker_contract.MAX_VAULT_BROKER_ASSET_BYTES
                    ),
                )
                for path, _ in assets
            ],
        )

    def test_each_asset_accepts_the_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        limit = 64 * 1024
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = self._write_workspace(root)
            for path, text in assets:
                exact = self._padded_source(path, text, limit)
                self.assertEqual(len(exact), limit)
                with self.subTest(asset=path.name):
                    path.write_bytes(exact)
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2]:
                        loaded = verify_vault_broker_contract.load_assets()
                        self.assertEqual(
                            verify_vault_broker_contract.broker_contract_errors(
                                *loaded
                            ),
                            [],
                        )
                    path.write_bytes(exact + b"x")
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2]:
                        with self.assertRaises(external_json.StableFileError):
                            verify_vault_broker_contract.load_assets()
                    path.write_text(text, encoding="utf-8")

    def test_invalid_utf8_for_each_asset_uses_the_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = self._write_workspace(root)
            for path, text in assets:
                with self.subTest(asset=path.name):
                    path.write_bytes(b"\xff")
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2]:
                        self.assertEqual(self._run_main(), self._fixed_failure())
                    path.write_text(text, encoding="utf-8")

    def test_contract_rejects_duplicate_keys_from_file_and_injected_text(
        self,
    ) -> None:
        duplicate = self.contract_text.replace(
            "{",
            '{"schema_version": 1,',
            1,
        )
        self.assertEqual(
            verify_vault_broker_contract.broker_contract_errors(
                duplicate,
                self.policies,
                self.configure_text,
            ),
            ["Vault broker contract must be valid JSON"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_workspace(root)[0][0].write_text(
                duplicate,
                encoding="utf-8",
            )
            patches = self._path_patches(root)
            with patches[0], patches[1], patches[2]:
                result = self._run_main()
        self.assertEqual(result[0], 1)
        self.assertEqual(
            result[2],
            "vault-broker-contract-error: Vault broker contract must be valid JSON\n",
        )

    def test_link_or_reparse_assets_are_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = self._write_workspace(root)
            for target, _ in assets:
                with self.subTest(asset=target.name):
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2], mock.patch.object(
                        verify_vault_broker_contract,
                        "load_stable_text",
                        side_effect=self._selective_loader(target, assets),
                        create=True,
                    ), mock.patch.object(
                        external_json,
                        "has_link_or_reparse_ancestor",
                        return_value=True,
                    ), mock.patch.object(external_json.os, "open") as open_file:
                        self.assertEqual(self._run_main(), self._fixed_failure())
                    open_file.assert_not_called()

    def test_non_regular_open_assets_are_rejected(self) -> None:
        real_fstat = os.fstat

        def non_regular_fstat(descriptor: int):
            metadata = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFIFO | 0o600,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = self._write_workspace(root)
            for target, _ in assets:
                with self.subTest(asset=target.name):
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2], mock.patch.object(
                        verify_vault_broker_contract,
                        "load_stable_text",
                        side_effect=self._selective_loader(target, assets),
                        create=True,
                    ), mock.patch.object(
                        external_json.os,
                        "fstat",
                        side_effect=non_regular_fstat,
                    ):
                        self.assertEqual(self._run_main(), self._fixed_failure())

    def test_read_shape_drift_is_rejected_for_each_asset(self) -> None:
        real_fstat = os.fstat
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = self._write_workspace(root)
            for target, _ in assets:
                calls = 0

                def drifting_fstat(descriptor: int):
                    nonlocal calls
                    calls += 1
                    metadata = real_fstat(descriptor)
                    if calls == 2:
                        return SimpleNamespace(
                            st_mode=metadata.st_mode,
                            st_dev=metadata.st_dev,
                            st_ino=metadata.st_ino,
                            st_nlink=metadata.st_nlink,
                            st_size=metadata.st_size + 1,
                            st_mtime_ns=metadata.st_mtime_ns,
                            st_ctime_ns=metadata.st_ctime_ns,
                            st_file_attributes=getattr(
                                metadata,
                                "st_file_attributes",
                                0,
                            ),
                        )
                    return metadata

                with self.subTest(asset=target.name):
                    patches = self._path_patches(root)
                    with patches[0], patches[1], patches[2], mock.patch.object(
                        verify_vault_broker_contract,
                        "load_stable_text",
                        side_effect=self._selective_loader(target, assets),
                        create=True,
                    ), mock.patch.object(
                        external_json.os,
                        "fstat",
                        side_effect=drifting_fstat,
                    ):
                        self.assertEqual(self._run_main(), self._fixed_failure())
                    self.assertEqual(calls, 2)

    def test_loader_failures_do_not_disclose_paths_or_reasons(self) -> None:
        assets = self._repository_assets()
        defaults = dict(assets)
        for target, _ in assets:
            def failed_loader(path: Path, *, max_bytes: int) -> str:
                if path == target:
                    raise external_json.StableFileError("private-target-path")
                return defaults[path]

            with self.subTest(asset=target.name), mock.patch.object(
                verify_vault_broker_contract,
                "load_stable_text",
                side_effect=failed_loader,
                create=True,
            ):
                result = self._run_main()
            self.assertEqual(result, self._fixed_failure())
            self.assertNotIn(str(target), result[2])
            self.assertNotIn("private-target-path", result[2])
            self.assertNotIn("file cannot be read safely", result[2])

    def test_source_uses_one_explicit_stable_boundary_per_asset(self) -> None:
        source = Path(verify_vault_broker_contract.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn("MAX_VAULT_BROKER_ASSET_BYTES = 64 * 1024", source)
        self.assertIn("ISSUER_POLICY_NAMES", source)
        self.assertIn("parse_unique_json_bytes", source)
        self.assertIn("load_stable_text(", source)
        self.assertIn("max_bytes=MAX_VAULT_BROKER_ASSET_BYTES", source)
        self.assertNotIn("Unable to load Vault broker assets: {error}", source)


if __name__ == "__main__":
    unittest.main()
