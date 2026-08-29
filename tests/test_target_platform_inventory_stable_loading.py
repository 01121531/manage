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
from scripts import target_platform_inventory


class TargetPlatformInventoryStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = external_json.load_unique_json(
            target_platform_inventory.INVENTORY
        )
        self.compose_text = external_yaml.read_stable_yaml_text(
            target_platform_inventory.COMPOSE
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = target_platform_inventory.main(["verify-repository"])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_environment_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == target_platform_inventory.ENV_EXAMPLE:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            target_platform_inventory,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            errors = target_platform_inventory.runtime_alignment_errors(
                self.inventory,
                compose_text=self.compose_text,
            )

        self.assertEqual(errors, [])
        stable_read.assert_called_once_with(target_platform_inventory.ENV_EXAMPLE)

    def test_environment_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        source = external_text.load_stable_text(
            target_platform_inventory.ENV_EXAMPLE
        ).encode("utf-8")
        if not source.endswith(b"\n"):
            source += b"\n"
        padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(source)
        self.assertGreater(padding, 1)
        exact = source + b"#" + b"x" * (padding - 1)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env.example"
            path.write_bytes(exact)
            with mock.patch.object(
                target_platform_inventory,
                "ENV_EXAMPLE",
                path,
            ):
                self.assertEqual(
                    target_platform_inventory.runtime_alignment_errors(
                        self.inventory,
                        compose_text=self.compose_text,
                    ),
                    [],
                )

                path.write_bytes(exact + b"x")
                self.assertEqual(
                    target_platform_inventory.runtime_alignment_errors(
                        self.inventory,
                        compose_text=self.compose_text,
                    ),
                    ["repository deployment input contract is unavailable"],
                )

    def test_link_or_reparse_environment_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env.example"
            path.write_text("unused", encoding="utf-8")
            with mock.patch.object(
                target_platform_inventory,
                "ENV_EXAMPLE",
                path,
            ), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file:
                errors = target_platform_inventory.runtime_alignment_errors(
                    self.inventory,
                    compose_text=self.compose_text,
                )

        self.assertEqual(
            errors,
            ["repository deployment input contract is unavailable"],
        )
        open_file.assert_not_called()

    def test_loader_failure_keeps_cli_error_fixed_and_exit_code_one(self) -> None:
        with mock.patch.object(
            target_platform_inventory,
            "load_stable_text",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "repository deployment input contract is unavailable\n"),
        )
        self.assertNotIn("file cannot be read safely", result[2])

    def test_injected_environment_reads_no_default_text_asset(self) -> None:
        env_text = external_text.load_stable_text(
            target_platform_inventory.ENV_EXAMPLE
        )
        with mock.patch.object(
            target_platform_inventory,
            "load_stable_text",
            side_effect=AssertionError("injected environment was read"),
            create=True,
        ) as stable_read:
            errors = target_platform_inventory.runtime_alignment_errors(
                self.inventory,
                compose_text=self.compose_text,
                env_text=env_text,
            )

        self.assertEqual(errors, [])
        stable_read.assert_not_called()

    def test_source_has_one_stable_default_environment_boundary(self) -> None:
        source = Path(target_platform_inventory.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn("load_stable_text(ENV_EXAMPLE)", source)


if __name__ == "__main__":
    unittest.main()
