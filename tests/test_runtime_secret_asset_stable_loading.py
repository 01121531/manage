from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import external_yaml
from scripts import verify_runtime_secrets


class RuntimeSecretAssetStableLoadingTests(unittest.TestCase):
    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_runtime_secrets.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_default_text_assets_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in verify_runtime_secrets.ASSET_PATHS:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_runtime_secrets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (0, "runtime-secrets-ok file-only=postgres,platform,redis,keycloak\n", ""),
        )
        self.assertEqual(
            [call.args[0] for call in stable_read.call_args_list],
            list(verify_runtime_secrets.ASSET_PATHS),
        )
        self.assertTrue(all(not call.kwargs for call in stable_read.call_args_list))

    def test_text_loader_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.txt"
            path.write_bytes(b"x" * external_text.MAX_REPOSITORY_TEXT_BYTES)
            with mock.patch.object(verify_runtime_secrets, "ASSET_PATHS", (path,)):
                self.assertEqual(
                    len(verify_runtime_secrets.load_text_assets()[path]),
                    external_text.MAX_REPOSITORY_TEXT_BYTES,
                )

                path.write_bytes(
                    b"x" * (external_text.MAX_REPOSITORY_TEXT_BYTES + 1)
                )
                with self.assertRaises(external_json.StableFileError):
                    verify_runtime_secrets.load_text_assets()

    def test_link_or_reparse_failure_is_fixed_and_precedes_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", "Cannot inspect runtime secret assets\n"))
        open_file.assert_not_called()

    def test_asset_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_runtime_secrets,
            "load_text_assets",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(result, (1, "", "Cannot inspect runtime secret assets\n"))
        self.assertNotIn("file cannot be read safely", result[2])

    def test_fully_injected_text_contract_reads_no_default_text_assets(self) -> None:
        assets = {
            path: external_text.load_stable_text(path)
            for path in verify_runtime_secrets.ASSET_PATHS
        }
        compose_text = external_yaml.read_stable_yaml_text(
            verify_runtime_secrets.COMPOSE
        )
        with mock.patch.object(
            verify_runtime_secrets,
            "load_stable_text",
            side_effect=AssertionError("injected asset was read"),
            create=True,
        ) as stable_read:
            errors = verify_runtime_secrets.verification_errors(
                compose_text=compose_text,
                env_text=assets[verify_runtime_secrets.ENV_EXAMPLE],
                postgres_init_text=assets[verify_runtime_secrets.POSTGRES_INIT],
                postgres_healthcheck_text=assets[
                    verify_runtime_secrets.POSTGRES_HEALTHCHECK
                ],
                redis_healthcheck_text=assets[
                    verify_runtime_secrets.REDIS_HEALTHCHECK
                ],
                config_text=assets[verify_runtime_secrets.CONFIG],
                migration_text=assets[verify_runtime_secrets.MIGRATION],
            )

        self.assertEqual(errors, [])
        stable_read.assert_not_called()

    def test_partial_injection_loads_only_the_missing_default_asset(self) -> None:
        assets = {
            path: external_text.load_stable_text(path)
            for path in verify_runtime_secrets.ASSET_PATHS
        }
        compose_text = external_yaml.read_stable_yaml_text(
            verify_runtime_secrets.COMPOSE
        )
        with mock.patch.object(
            verify_runtime_secrets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            errors = verify_runtime_secrets.verification_errors(
                compose_text=compose_text,
                env_text=assets[verify_runtime_secrets.ENV_EXAMPLE],
                postgres_init_text=assets[verify_runtime_secrets.POSTGRES_INIT],
                postgres_healthcheck_text=assets[
                    verify_runtime_secrets.POSTGRES_HEALTHCHECK
                ],
                redis_healthcheck_text=assets[
                    verify_runtime_secrets.REDIS_HEALTHCHECK
                ],
                config_text=assets[verify_runtime_secrets.CONFIG],
            )

        self.assertEqual(errors, [])
        stable_read.assert_called_once_with(verify_runtime_secrets.MIGRATION)

    def test_source_has_one_stable_default_text_boundary(self) -> None:
        source = Path(verify_runtime_secrets.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("default_assets = load_text_assets(missing_paths)", source)
        self.assertIn("load_stable_text", source)


if __name__ == "__main__":
    unittest.main()
