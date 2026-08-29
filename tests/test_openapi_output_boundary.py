from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import export_openapi as export_module
from scripts import external_json


ROOT = Path(__file__).resolve().parents[1]


def fake_app(schema: dict[str, object]) -> tuple[SimpleNamespace, mock.Mock]:
    engine = mock.Mock()
    app = SimpleNamespace(
        openapi=mock.Mock(return_value=schema),
        state=SimpleNamespace(engine=engine),
    )
    return app, engine


class OpenApiOutputBoundaryTests(unittest.TestCase):
    def test_export_delegates_exact_deterministic_utf8_bytes(self) -> None:
        schema = {
            "paths": {"/测试": {"get": {}}},
            "info": {"title": "邮箱平台", "version": "1.2.3"},
        }
        app, engine = fake_app(schema)
        settings = object()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "openapi.json"
            with mock.patch.object(
                export_module, "Settings", return_value=settings
            ) as settings_factory, mock.patch.object(
                export_module, "create_app", return_value=app
            ) as create_app, mock.patch.object(
                export_module, "write_atomic_bytes", create=True
            ) as writer:
                export_module.export_openapi(output)

        settings_factory.assert_called_once_with(
            app_name="email-platform-contract",
            environment="test",
            auth_mode="local",
            database_url="sqlite+pysqlite:///:memory:",
        )
        create_app.assert_called_once_with(settings)
        writer.assert_called_once_with(
            output,
            (
                json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8"),
        )
        engine.dispose.assert_called_once_with()

    def test_replace_failure_preserves_existing_schema_and_cleans_temporary(
        self,
    ) -> None:
        app, engine = fake_app({"openapi": "3.1.0"})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "openapi.json"
            output.write_bytes(b"old-schema")
            with mock.patch.object(
                export_module, "create_app", return_value=app
            ), mock.patch.object(
                external_json.os, "replace", side_effect=OSError("replace sentinel")
            ):
                with self.assertRaises(OSError):
                    export_module.export_openapi(output)

            self.assertEqual(output.read_bytes(), b"old-schema")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])
        engine.dispose.assert_called_once_with()

    def test_export_creates_missing_parent_and_replaces_complete_schema(self) -> None:
        schema = {"openapi": "3.1.0", "info": {"title": "contract"}}
        app, _ = fake_app(schema)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "openapi.json"
            with mock.patch.object(export_module, "create_app", return_value=app):
                export_module.export_openapi(output)

            self.assertEqual(
                output.read_bytes(),
                (
                    json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8"),
            )
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_direct_script_entrypoint_remains_available_from_frontend(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_openapi.py"),
                "--help",
            ],
            cwd=ROOT / "frontend",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_cli_resolves_output_but_prints_the_original_argument(self) -> None:
        output = Path("nested") / "openapi.json"
        stdout = io.StringIO()
        with mock.patch.object(
            export_module.sys,
            "argv",
            ["export_openapi.py", "--output", str(output)],
        ), mock.patch.object(export_module, "export_openapi") as exporter, redirect_stdout(
            stdout
        ):
            result = export_module.main()

        self.assertEqual(result, 0)
        exporter.assert_called_once_with(output.resolve())
        self.assertEqual(stdout.getvalue().strip(), f"openapi-export-ok output={output}")

    def test_export_source_has_no_direct_text_output_write(self) -> None:
        source = Path(export_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".write_text(", source)
        self.assertIn("write_atomic_bytes(", source)


if __name__ == "__main__":
    unittest.main()
