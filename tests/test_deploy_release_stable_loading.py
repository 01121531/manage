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
from scripts import verify_deploy_release


FIXED_ASSET_ERROR = (
    "deploy-release-assets-error: Cannot inspect deployment assets\n"
)
TEXT_ASSET_NAMES = (
    "ENV_EXAMPLE",
    "DEV_ENV_EXAMPLE",
    "DEPLOY_SCRIPT",
    "UPSTREAM_SCAN_SCRIPT",
)


class DeployReleaseStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_texts = (
            external_yaml.read_stable_yaml_text(verify_deploy_release.COMPOSE),
            external_yaml.read_stable_yaml_text(
                verify_deploy_release.DEV_COMPOSE
            ),
        )
        self.asset_paths = tuple(
            getattr(verify_deploy_release, name) for name in TEXT_ASSET_NAMES
        )
        self.asset_texts = tuple(
            external_text.load_stable_text(path) for path in self.asset_paths
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_deploy_release.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_text_assets_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in self.asset_paths:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_deploy_release,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "deploy-release-assets-ok immutable-forward-release=verified\n",
                "",
            ),
        )
        self.assertEqual(
            [call.args for call in stable_read.call_args_list],
            [(path,) for path in self.asset_paths],
        )

    def test_each_text_asset_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for name, source in zip(TEXT_ASSET_NAMES, self.asset_texts):
                with self.subTest(asset=name):
                    raw = source.encode("utf-8")
                    if not raw.endswith(b"\n"):
                        raw += b"\n"
                    prefix = raw + b"#"
                    padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(
                        prefix
                    )
                    self.assertGreaterEqual(padding, 0)
                    exact = prefix + b"x" * padding
                    path = Path(temporary) / name.lower()
                    path.write_bytes(exact)

                    with mock.patch.object(verify_deploy_release, name, path):
                        self.assertEqual(self.run_main()[0], 0)
                        path.write_bytes(exact + b"x")
                        self.assertEqual(
                            self.run_main(),
                            (1, FIXED_ASSET_ERROR, ""),
                        )

    def test_invalid_utf8_for_each_text_asset_uses_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for name in TEXT_ASSET_NAMES:
                with self.subTest(asset=name):
                    path = Path(temporary) / f"{name.lower()}-invalid"
                    path.write_bytes(b"\xff")

                    with mock.patch.object(verify_deploy_release, name, path):
                        self.assertEqual(
                            self.run_main(),
                            (1, FIXED_ASSET_ERROR, ""),
                        )

    def test_link_or_reparse_asset_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            verify_deploy_release,
            "read_stable_yaml_text",
            side_effect=self.compose_texts,
        ), mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, FIXED_ASSET_ERROR, ""))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_cli_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_deploy_release,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, FIXED_ASSET_ERROR, ""))
            self.assertNotIn(reason, result[1])
            stable_read.assert_called_once_with(self.asset_paths[0])

    def test_source_has_one_shared_stable_boundary_for_all_text_assets(
        self,
    ) -> None:
        source = Path(verify_deploy_release.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        for name in TEXT_ASSET_NAMES:
            self.assertIn(name, source)
        self.assertIn("load_stable_text(path)", source)


if __name__ == "__main__":
    unittest.main()
