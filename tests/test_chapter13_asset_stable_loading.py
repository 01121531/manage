from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import external_yaml
from scripts import verify_chapter13_defaults


class Chapter13AssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = external_json.load_unique_json(
            verify_chapter13_defaults.DECISIONS,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        self.compose_text = external_yaml.read_stable_yaml_text(
            verify_chapter13_defaults.COMPOSE
        )
        _, realm_bytes = external_json.load_unique_json_with_bytes(
            verify_chapter13_defaults.REALM,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        self.realm_text = realm_bytes.decode("utf-8")
        self.env_text = external_text.load_stable_text(
            verify_chapter13_defaults.ENV_EXAMPLE
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_chapter13_defaults.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_assets_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in (
                verify_chapter13_defaults.REALM,
                verify_chapter13_defaults.ENV_EXAMPLE,
            ):
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            wraps=external_json.load_unique_json_with_bytes,
            create=True,
        ) as realm_read, mock.patch.object(
            verify_chapter13_defaults,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as env_read:
            errors = verify_chapter13_defaults.decision_errors(
                self.document,
                compose_text=self.compose_text,
            )

        self.assertEqual(errors, [])
        realm_read.assert_called_once_with(
            verify_chapter13_defaults.REALM,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        env_read.assert_called_once_with(verify_chapter13_defaults.ENV_EXAMPLE)

    def test_environment_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        source = self.env_text.encode("utf-8")
        if not source.endswith(b"\n"):
            source += b"\n"
        padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(source)
        self.assertGreater(padding, 1)
        exact = source + b"#" + b"x" * (padding - 1)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env.example"
            path.write_bytes(exact)
            with mock.patch.object(verify_chapter13_defaults, "ENV_EXAMPLE", path):
                self.assertEqual(
                    verify_chapter13_defaults.decision_errors(
                        self.document,
                        compose_text=self.compose_text,
                        realm_text=self.realm_text,
                    ),
                    [],
                )
                path.write_bytes(exact + b"x")
                with self.assertRaises(external_json.StableFileError):
                    verify_chapter13_defaults.decision_errors(
                        self.document,
                        compose_text=self.compose_text,
                        realm_text=self.realm_text,
                    )

    def test_realm_accepts_exact_limit_and_rejects_extra_or_duplicate_key(self) -> None:
        source = self.realm_text.encode("utf-8")
        padding = external_json.MAX_INTAKE_JSON_BYTES - len(source)
        self.assertGreater(padding, 0)
        exact = source + b" " * padding

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "realm.json"
            path.write_bytes(exact)
            with mock.patch.object(verify_chapter13_defaults, "REALM", path):
                self.assertEqual(
                    verify_chapter13_defaults.decision_errors(
                        self.document,
                        compose_text=self.compose_text,
                        env_text=self.env_text,
                    ),
                    [],
                )
                path.write_bytes(exact + b" ")
                with self.assertRaises(external_json.StableFileError):
                    verify_chapter13_defaults.decision_errors(
                        self.document,
                        compose_text=self.compose_text,
                        env_text=self.env_text,
                    )

                path.write_text(
                    '{"duplicate": 1, "duplicate": 2}',
                    encoding="utf-8",
                )
                with self.assertRaises(json.JSONDecodeError):
                    verify_chapter13_defaults.decision_errors(
                        self.document,
                        compose_text=self.compose_text,
                        env_text=self.env_text,
                    )

    def test_injected_realm_rejects_duplicate_key_without_default_reads(self) -> None:
        with mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            side_effect=AssertionError("injected realm was read"),
            create=True,
        ) as realm_read, mock.patch.object(
            verify_chapter13_defaults,
            "load_stable_text",
            side_effect=AssertionError("injected environment was read"),
            create=True,
        ) as env_read:
            with self.assertRaises(json.JSONDecodeError):
                verify_chapter13_defaults.decision_errors(
                    self.document,
                    compose_text=self.compose_text,
                    realm_text='{"duplicate": 1, "duplicate": 2}',
                    env_text=self.env_text,
                )

        realm_read.assert_not_called()
        env_read.assert_not_called()

    def test_link_or_reparse_assets_are_rejected_before_open(self) -> None:
        cases = (
            ("REALM", {"env_text": self.env_text}),
            ("ENV_EXAMPLE", {"realm_text": self.realm_text}),
        )
        for attribute, injected in cases:
            with self.subTest(attribute=attribute), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "asset"
                path.write_text("unused", encoding="utf-8")
                with mock.patch.object(
                    verify_chapter13_defaults,
                    attribute,
                    path,
                ), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    with self.assertRaises(external_json.StableFileError):
                        verify_chapter13_defaults.decision_errors(
                            self.document,
                            compose_text=self.compose_text,
                            **injected,
                        )
                open_file.assert_not_called()

    def test_asset_failure_keeps_cli_error_fixed(self) -> None:
        with mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "chapter-13 default decisions are unreadable\n"),
        )
        self.assertNotIn("file cannot be read safely", result[2])

    def test_fully_injected_assets_read_no_default_text(self) -> None:
        with mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            side_effect=AssertionError("injected realm was read"),
            create=True,
        ) as realm_read, mock.patch.object(
            verify_chapter13_defaults,
            "load_stable_text",
            side_effect=AssertionError("injected environment was read"),
            create=True,
        ) as env_read:
            errors = verify_chapter13_defaults.decision_errors(
                self.document,
                compose_text=self.compose_text,
                realm_text=self.realm_text,
                env_text=self.env_text,
            )

        self.assertEqual(errors, [])
        realm_read.assert_not_called()
        env_read.assert_not_called()

    def test_partial_injection_loads_only_the_missing_default_asset(self) -> None:
        with mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            side_effect=AssertionError("injected realm was read"),
            create=True,
        ) as realm_read, mock.patch.object(
            verify_chapter13_defaults,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as env_read:
            errors = verify_chapter13_defaults.decision_errors(
                self.document,
                compose_text=self.compose_text,
                realm_text=self.realm_text,
            )
        self.assertEqual(errors, [])
        realm_read.assert_not_called()
        env_read.assert_called_once_with(verify_chapter13_defaults.ENV_EXAMPLE)

        with mock.patch.object(
            verify_chapter13_defaults,
            "load_unique_json_with_bytes",
            wraps=external_json.load_unique_json_with_bytes,
            create=True,
        ) as realm_read, mock.patch.object(
            verify_chapter13_defaults,
            "load_stable_text",
            side_effect=AssertionError("injected environment was read"),
            create=True,
        ) as env_read:
            errors = verify_chapter13_defaults.decision_errors(
                self.document,
                compose_text=self.compose_text,
                env_text=self.env_text,
            )
        self.assertEqual(errors, [])
        realm_read.assert_called_once_with(
            verify_chapter13_defaults.REALM,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        env_read.assert_not_called()

    def test_source_has_stable_default_asset_boundaries(self) -> None:
        source = Path(verify_chapter13_defaults.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn("load_unique_json_with_bytes", source)
        self.assertIn("load_stable_text", source)


if __name__ == "__main__":
    unittest.main()
