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
from scripts import verify_compose_env


class ComposeEnvAssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_text = external_yaml.read_stable_yaml_text(
            verify_compose_env.COMPOSE
        )
        self.env_text = external_text.load_stable_text(
            verify_compose_env.ENV_EXAMPLE
        )
        self.init_text = external_text.load_stable_text(
            verify_compose_env.POSTGRES_INIT
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_compose_env.main()
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def exact_limit(source: str) -> bytes:
        raw = source.encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
        padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(raw)
        if padding <= 1:
            raise AssertionError("asset leaves no room for a comment padding line")
        return raw + b"#" + b"x" * (padding - 1)

    def test_default_text_assets_are_loaded_once_without_path_read_text(self) -> None:
        watched = {
            verify_compose_env.ENV_EXAMPLE,
            verify_compose_env.POSTGRES_INIT,
        }
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in watched:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_compose_env,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            errors = verify_compose_env.verification_errors(
                compose_text=self.compose_text
            )

        self.assertEqual(errors, [])
        self.assertEqual(
            [call.args[0] for call in stable_read.call_args_list],
            [verify_compose_env.ENV_EXAMPLE, verify_compose_env.POSTGRES_INIT],
        )
        self.assertTrue(all(not call.kwargs for call in stable_read.call_args_list))

    def test_each_text_asset_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        cases = (
            (
                "environment",
                "ENV_EXAMPLE",
                self.env_text,
                {"init_text": self.init_text},
            ),
            (
                "postgres-init",
                "POSTGRES_INIT",
                self.init_text,
                {"env_text": self.env_text},
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for label, attribute, source, injected in cases:
                with self.subTest(asset=label):
                    path = Path(temporary) / f"{label}.txt"
                    exact = self.exact_limit(source)
                    path.write_bytes(exact)
                    with mock.patch.object(verify_compose_env, attribute, path):
                        self.assertEqual(
                            verify_compose_env.verification_errors(
                                compose_text=self.compose_text,
                                **injected,
                            ),
                            [],
                        )
                        path.write_bytes(exact + b"x")
                        self.assertEqual(
                            verify_compose_env.verification_errors(
                                compose_text=self.compose_text,
                                **injected,
                            ),
                            ["Cannot inspect compose database roles"],
                        )

    def test_each_link_or_reparse_asset_is_rejected_before_open(self) -> None:
        cases = (
            ("ENV_EXAMPLE", {"init_text": self.init_text}),
            ("POSTGRES_INIT", {"env_text": self.env_text}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.txt"
            path.write_text("unused", encoding="utf-8")
            for attribute, injected in cases:
                with self.subTest(asset=attribute), mock.patch.object(
                    verify_compose_env,
                    attribute,
                    path,
                ), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    errors = verify_compose_env.verification_errors(
                        compose_text=self.compose_text,
                        **injected,
                    )

                self.assertEqual(
                    errors,
                    ["Cannot inspect compose database roles"],
                )
                open_file.assert_not_called()

    def test_text_loader_failure_keeps_cli_error_fixed(self) -> None:
        with mock.patch.object(
            verify_compose_env,
            "load_stable_text",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "Cannot inspect compose database roles\n"),
        )
        self.assertNotIn("file cannot be read safely", result[2])

    def test_fully_injected_contract_reads_no_default_text_assets(self) -> None:
        with mock.patch.object(
            verify_compose_env,
            "load_stable_text",
            side_effect=AssertionError("injected asset was read"),
            create=True,
        ) as stable_read:
            errors = verify_compose_env.verification_errors(
                compose_text=self.compose_text,
                env_text=self.env_text,
                init_text=self.init_text,
            )

        self.assertEqual(errors, [])
        stable_read.assert_not_called()

    def test_partial_injection_loads_only_the_missing_default_asset(self) -> None:
        cases = (
            ({"env_text": self.env_text}, verify_compose_env.POSTGRES_INIT),
            ({"init_text": self.init_text}, verify_compose_env.ENV_EXAMPLE),
        )
        for injected, expected_path in cases:
            with self.subTest(path=expected_path), mock.patch.object(
                verify_compose_env,
                "load_stable_text",
                wraps=external_text.load_stable_text,
                create=True,
            ) as stable_read:
                errors = verify_compose_env.verification_errors(
                    compose_text=self.compose_text,
                    **injected,
                )

            self.assertEqual(errors, [])
            stable_read.assert_called_once_with(expected_path)

    def test_source_has_one_stable_default_text_boundary(self) -> None:
        source = Path(verify_compose_env.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("load_stable_text(ENV_EXAMPLE)", source)
        self.assertIn("load_stable_text(POSTGRES_INIT)", source)


if __name__ == "__main__":
    unittest.main()
