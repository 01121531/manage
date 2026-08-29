from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_openapi_client


FIXED_CONTRACT_ERROR = "Cannot inspect OpenAPI contract artifacts"
MAX_OPENAPI_CONTRACT_BYTES = 256 * 1024


class OpenApiClientStableLoadingTests(unittest.TestCase):
    @staticmethod
    def _write_contracts(root: Path) -> tuple[Path, Path, Path, Path]:
        generated_schema = root / "generated.json"
        checked_in_schema = root / "checked-in.json"
        generated_types = root / "generated.ts"
        checked_in_types = root / "checked-in.ts"
        generated_schema.write_bytes(b'{"openapi":"3.1.0"}\n')
        checked_in_schema.write_bytes(b'{"openapi":"3.1.0"}\r\n')
        generated_types.write_bytes(b"export interface A {}\n")
        checked_in_types.write_bytes(b"export interface A {}\r\n")
        return (
            generated_schema,
            checked_in_schema,
            generated_types,
            checked_in_types,
        )

    def _run_main(
        self,
        root: Path,
        *,
        checked_in_schema: bytes = b'{"openapi":"3.1.0"}\n',
    ) -> tuple[BaseException | None, str, str]:
        frontend = root / "frontend"
        executable = frontend / "node_modules" / ".bin" / (
            "openapi-typescript.cmd" if os.name == "nt" else "openapi-typescript"
        )
        expected_schema = frontend / "openapi.json"
        expected_types = frontend / "src" / "generated" / "openapi.ts"
        executable.parent.mkdir(parents=True)
        expected_types.parent.mkdir(parents=True)
        executable.write_bytes(b"placeholder")
        expected_schema.write_bytes(checked_in_schema)
        expected_types.write_bytes(b"export interface A {}\n")

        def fake_export(path: Path) -> None:
            path.write_bytes(b'{"openapi":"3.1.0"}\n')

        def fake_generate(command, **kwargs) -> None:
            Path(command[-1]).write_bytes(b"export interface A {}\n")

        stdout = io.StringIO()
        stderr = io.StringIO()
        error: BaseException | None = None
        with mock.patch.object(
            verify_openapi_client,
            "REPOSITORY_ROOT",
            root,
        ), mock.patch.object(
            verify_openapi_client,
            "export_openapi",
            side_effect=fake_export,
        ), mock.patch.object(
            verify_openapi_client.subprocess,
            "run",
            side_effect=fake_generate,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                verify_openapi_client.main()
            except BaseException as caught:
                error = caught
        return error, stdout.getvalue(), stderr.getvalue()

    def test_all_four_contracts_are_loaded_once_without_path_read_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_contracts(Path(temporary))
            real_read_text = Path.read_text

            def guarded_read_text(path: Path, *args, **kwargs):
                if path in paths:
                    raise AssertionError("Path.read_text bypassed stable loading")
                return real_read_text(path, *args, **kwargs)

            with mock.patch.object(
                Path,
                "read_text",
                guarded_read_text,
            ), mock.patch.object(
                verify_openapi_client,
                "load_stable_text",
                wraps=external_text.load_stable_text,
                create=True,
            ) as stable_read:
                current = verify_openapi_client.checked_in_contracts_are_current(
                    generated_schema=paths[0],
                    checked_in_schema=paths[1],
                    generated_types=paths[2],
                    checked_in_types=paths[3],
                )

        self.assertTrue(current)
        self.assertEqual(
            stable_read.call_args_list,
            [
                mock.call(path, max_bytes=MAX_OPENAPI_CONTRACT_BYTES)
                for path in paths
            ],
        )

    def test_contract_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = Path(temporary) / "contract.ts"
            contract.write_bytes(b"x" * MAX_OPENAPI_CONTRACT_BYTES)
            self.assertEqual(
                len(verify_openapi_client.normalized_contract(contract)),
                MAX_OPENAPI_CONTRACT_BYTES,
            )
            contract.write_bytes(b"x" * (MAX_OPENAPI_CONTRACT_BYTES + 1))
            with self.assertRaises(external_json.StableFileError):
                verify_openapi_client.normalized_contract(contract)

    def test_invalid_utf8_uses_fixed_contract_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run_main(
                Path(temporary),
                checked_in_schema=b"\xff",
            )

        self.assertIsInstance(result[0], SystemExit)
        self.assertEqual(str(result[0]), FIXED_CONTRACT_ERROR)
        self.assertEqual(result[1:], ("", ""))
        self.assertNotIn("utf-8", str(result[0]))

    def test_link_or_reparse_contract_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = Path(temporary) / "contract.ts"
            contract.write_bytes(b"export interface A {}\n")
            with mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file:
                with self.assertRaises(external_json.StableFileError):
                    verify_openapi_client.normalized_contract(contract)

        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_contract_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                with mock.patch.object(
                    verify_openapi_client,
                    "load_stable_text",
                    side_effect=external_json.StableFileError(reason),
                    create=True,
                ):
                    result = self._run_main(Path(temporary))

            self.assertIsInstance(result[0], SystemExit)
            self.assertEqual(str(result[0]), FIXED_CONTRACT_ERROR)
            self.assertNotIn(reason, str(result[0]))
            self.assertEqual(result[1:], ("", ""))

    def test_stale_contract_keeps_existing_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                verify_openapi_client,
                "checked_in_contracts_are_current",
                return_value=False,
            ):
                result = self._run_main(root)

        self.assertIsInstance(result[0], SystemExit)
        self.assertEqual(
            str(result[0]),
            "checked-in OpenAPI schema or generated client is stale; "
            "run npm run generate:api",
        )
        self.assertEqual(result[1:], ("", ""))

    def test_source_uses_bounded_stable_contract_snapshots(self) -> None:
        source = Path(verify_openapi_client.__file__).read_text(encoding="utf-8")
        self.assertNotIn("path.read_text(", source)
        self.assertIn("MAX_OPENAPI_CONTRACT_BYTES = 256 * 1024", source)
        self.assertIn(
            "load_stable_text(\n        path,\n"
            "        max_bytes=MAX_OPENAPI_CONTRACT_BYTES,\n    )",
            source,
        )


if __name__ == "__main__":
    unittest.main()
