from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import create_container_release_manifest
from scripts import create_update_manifest
from scripts import external_json
from scripts import release_manifest


ROOT = Path(__file__).resolve().parents[1]


class ManifestOutputBoundaryTests(unittest.TestCase):
    def test_update_manifest_delegates_exact_utf8_bytes(self) -> None:
        manifest = {"version": "1.2.3", "label": "更新"}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "update-manifest.json"
            with mock.patch.object(
                create_update_manifest, "build_manifest", return_value=manifest
            ), mock.patch.object(
                create_update_manifest, "write_atomic_bytes", create=True
            ) as writer:
                result = create_update_manifest.main(
                    [
                        "--exe",
                        "unused.exe",
                        "--version",
                        "1.2.3",
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(result, 0)
        writer.assert_called_once_with(
            output,
            (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            ),
        )

    def test_container_manifest_delegates_exact_utf8_bytes(self) -> None:
        manifest = {"schema_version": 1, "label": "容器"}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "container-release-manifest.json"
            stdout = io.StringIO()
            with mock.patch.object(
                create_container_release_manifest,
                "build_manifest",
                return_value=manifest,
            ), mock.patch.object(
                create_container_release_manifest,
                "write_atomic_bytes",
                create=True,
            ) as writer, redirect_stdout(stdout):
                result = create_container_release_manifest.main(
                    [
                        "--input-dir",
                        "unused",
                        "--tag",
                        "v1.2.3",
                        "--commit",
                        "a" * 40,
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue().strip(), str(output))
        writer.assert_called_once_with(
            output,
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def test_repository_snapshot_delegates_exact_utf8_bytes(self) -> None:
        manifest = {"release_id": "1.2.3", "label": "发布"}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-manifest.json"
            stdout = io.StringIO()
            with mock.patch.object(
                release_manifest, "build_release_manifest", return_value=manifest
            ), mock.patch.object(
                release_manifest, "write_atomic_bytes", create=True
            ) as writer, redirect_stdout(stdout):
                result = release_manifest.main(
                    ["snapshot", "--output", str(output)]
                )

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        writer.assert_called_once_with(
            output,
            (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            ),
        )

    def test_update_manifest_replace_failure_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "update-manifest.json"
            output.write_bytes(b"old-update")
            with mock.patch.object(
                create_update_manifest,
                "build_manifest",
                return_value={"version": "1.2.3"},
            ), mock.patch.object(
                external_json.os, "replace", side_effect=OSError("replace sentinel")
            ):
                with self.assertRaises(OSError):
                    create_update_manifest.main(
                        [
                            "--exe",
                            "unused.exe",
                            "--version",
                            "1.2.3",
                            "--output",
                            str(output),
                        ]
                    )

            self.assertEqual(output.read_bytes(), b"old-update")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_container_manifest_replace_failure_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "container-release-manifest.json"
            output.write_bytes(b"old-container")
            with mock.patch.object(
                create_container_release_manifest,
                "build_manifest",
                return_value={"schema_version": 1},
            ), mock.patch.object(
                external_json.os, "replace", side_effect=OSError("replace sentinel")
            ):
                with self.assertRaises(OSError):
                    create_container_release_manifest.main(
                        [
                            "--input-dir",
                            "unused",
                            "--tag",
                            "v1.2.3",
                            "--commit",
                            "a" * 40,
                            "--output",
                            str(output),
                        ]
                    )

            self.assertEqual(output.read_bytes(), b"old-container")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_repository_snapshot_replace_failure_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-manifest.json"
            output.write_bytes(b"old-release")
            with mock.patch.object(
                release_manifest,
                "build_release_manifest",
                return_value={"release_id": "1.2.3"},
            ), mock.patch.object(
                external_json.os, "replace", side_effect=OSError("replace sentinel")
            ):
                with self.assertRaises(OSError):
                    release_manifest.main(["snapshot", "--output", str(output)])

            self.assertEqual(output.read_bytes(), b"old-release")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_container_manifest_supports_the_release_workflow_script_entrypoint(
        self,
    ) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "create_container_release_manifest.py"),
                "--help",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_manifest_producers_have_no_direct_text_output_write(self) -> None:
        for module in (
            create_update_manifest,
            create_container_release_manifest,
            release_manifest,
        ):
            with self.subTest(module=module.__name__):
                source = Path(module.__file__).read_text(encoding="utf-8")
                self.assertNotIn(".write_text(", source)
                self.assertIn("write_atomic_bytes(", source)


if __name__ == "__main__":
    unittest.main()
