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
from scripts import verify_container_hardening


class ContainerHardeningStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = external_yaml.load_unique_yaml(
            verify_container_hardening.COMPOSE
        )
        self.runtime_role_text = external_text.load_stable_text(
            verify_container_hardening.RUNTIME_ROLE_INIT
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_container_hardening.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_runtime_role_asset_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_container_hardening.RUNTIME_ROLE_INIT:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_container_hardening,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "container-hardening-ok "
                "migrate-api-workers-web=read-only-no-new-privileges\n",
                "",
            ),
        )
        stable_read.assert_called_once_with(
            verify_container_hardening.RUNTIME_ROLE_INIT
        )

    def test_asset_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        raw = self.runtime_role_text.encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
        padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(raw)
        self.assertGreater(padding, 1)
        exact = raw + b"#" + b"x" * (padding - 1)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime-role.sh"
            path.write_bytes(exact)
            with mock.patch.object(
                verify_container_hardening,
                "RUNTIME_ROLE_INIT",
                path,
            ):
                self.assertEqual(self.run_main()[0], 0)
                path.write_bytes(exact + b"x")
                self.assertEqual(
                    self.run_main(),
                    (1, "", "Cannot inspect container hardening assets\n"),
                )

    def test_invalid_utf8_is_reported_with_the_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime-role.sh"
            path.write_bytes(b"\xff")
            with mock.patch.object(
                verify_container_hardening,
                "RUNTIME_ROLE_INIT",
                path,
            ):
                result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "Cannot inspect container hardening assets\n"),
        )

    def test_link_or_reparse_asset_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            verify_container_hardening,
            "load_unique_yaml",
            return_value=self.compose,
        ), mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "Cannot inspect container hardening assets\n"),
        )
        open_file.assert_not_called()

    def test_loader_failure_keeps_cli_error_fixed(self) -> None:
        with mock.patch.object(
            verify_container_hardening,
            "load_stable_text",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "Cannot inspect container hardening assets\n"),
        )
        self.assertNotIn("file cannot be read safely", result[2])

    def test_source_has_one_stable_runtime_role_boundary(self) -> None:
        source = Path(verify_container_hardening.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn("load_stable_text(RUNTIME_ROLE_INIT)", source)


if __name__ == "__main__":
    unittest.main()
