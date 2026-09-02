from contextlib import redirect_stderr, redirect_stdout
import io
import importlib.util
import json
import os
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import scripts.external_json as external_json


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "release_manifest.py"
SPEC = importlib.util.spec_from_file_location("release_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_manifest = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = release_manifest
SPEC.loader.exec_module(release_manifest)

VERIFY_MODULE_PATH = ROOT / "scripts" / "verify_release_manifest.py"
VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_release_manifest", VERIFY_MODULE_PATH
)
assert VERIFY_SPEC is not None and VERIFY_SPEC.loader is not None
verify_release_manifest = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(verify_release_manifest)


class ReleaseManifestTests(unittest.TestCase):
    @staticmethod
    def _build_with_fixed_non_compose_sources() -> dict[str, object]:
        with mock.patch.object(
            release_manifest, "_read_backend_version", return_value="0.1.3"
        ), mock.patch.object(
            release_manifest, "_read_frontend_version", return_value="0.1.3"
        ), mock.patch.object(
            release_manifest,
            "_read_migration_head",
            return_value="0028_operational_policy_governance",
        ):
            return release_manifest.build_release_manifest()

    def test_manifest_matches_repository_state(self) -> None:
        manifest = release_manifest.build_release_manifest()
        errors = release_manifest.verify_manifest(manifest)
        self.assertEqual(errors, [])
        self.assertEqual(manifest["release_id"], "0.1.3")
        self.assertEqual(
            manifest["migration_head"], "0041_card_claim_mutation_ledger"
        )
        self.assertIn("worker-mail", manifest["compose_images"])
        third_party = {
            "postgres",
            "redis",
            "keycloak",
            "alertmanager",
            "prometheus",
        }
        self.assertTrue(third_party.issubset(manifest["compose_images"]))
        for service in third_party:
            image = manifest["compose_images"][service]
            self.assertIn("@sha256:${", image)
            self.assertNotIn(":-", image)

    def test_manifest_loader_accepts_exact_limit_and_rejects_oversize(self) -> None:
        manifest = release_manifest.build_release_manifest()
        rendered = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
        self.assertLess(len(rendered), 64 * 1024)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            path.write_bytes(rendered + b" " * (64 * 1024 - len(rendered)))
            self.assertEqual(release_manifest.load_manifest(path), manifest)

            path.write_bytes(rendered + b" " * (64 * 1024 + 1 - len(rendered)))
            with self.assertRaises((OSError, ValueError)):
                release_manifest.load_manifest(path)

    def test_manifest_loader_rejects_duplicate_keys_at_any_depth(self) -> None:
        values = (
            '{"release_id":"0.1.3","release_id":"0.1.3"}',
            '{"compose_images":{"api":"image","api":"image"}}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            for value in values:
                with self.subTest(value=value):
                    path.write_text(value, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        release_manifest.load_manifest(path)

    def test_manifest_loader_rejects_link_or_reparse_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            path.write_text("{}", encoding="utf-8")

            with mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file:
                with self.assertRaises((OSError, ValueError)):
                    release_manifest.load_manifest(path)
            open_file.assert_not_called()

    def test_manifest_loader_rejects_open_file_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            path.write_text("{}", encoding="utf-8")
            real_fstat = os.fstat
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
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch("os.fstat", side_effect=drifting_fstat):
                with self.assertRaises((OSError, ValueError)):
                    release_manifest.load_manifest(path)
            self.assertEqual(calls, 2)

    def test_verify_cli_maps_invalid_manifest_to_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            path.write_text(
                '{"release_id":"0.1.3","release_id":"0.1.3"}',
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                result = release_manifest.main(
                    ["verify", "--manifest", str(path)]
                )

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue().strip(), "release-manifest-invalid")

    def test_committed_snapshot_verifier_uses_the_same_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-manifest.json"
            path.write_text(
                '{"release_id":"0.1.3","release_id":"0.1.3"}',
                encoding="utf-8",
            )
            stderr = io.StringIO()

            with mock.patch.object(verify_release_manifest, "MANIFEST", path), \
                    redirect_stderr(stderr):
                result = verify_release_manifest.main()

            self.assertEqual(result, 1)
            self.assertEqual(stderr.getvalue().strip(), "release-manifest-invalid")

    def test_backend_source_accepts_exact_limit_and_rejects_oversize(self) -> None:
        prefix = b'__version__ = "0.1.3"\n#'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "__init__.py"
            with mock.patch.object(release_manifest, "BACKEND_INIT", path):
                path.write_bytes(prefix + b"x" * (64 * 1024 - len(prefix)))
                self.assertEqual(release_manifest._read_backend_version(), "0.1.3")

                path.write_bytes(
                    prefix + b"x" * (64 * 1024 + 1 - len(prefix))
                )
                with self.assertRaises((OSError, ValueError)):
                    release_manifest._read_backend_version()

    def test_compose_source_is_bounded_and_rejects_duplicate_keys(self) -> None:
        source = release_manifest.COMPOSE.read_bytes()
        self.assertLess(len(source), 64 * 1024)
        padding_prefix = b"\n#"
        duplicate_api_image = (
            "  api:\n"
            "    image: ${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}\n"
        )
        duplicate_values = (
            b"services: {}\n" + source,
            source.decode("utf-8")
            .replace("  api:\n", duplicate_api_image, 1)
            .encode("utf-8"),
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "docker-compose.yml"
            with mock.patch.object(release_manifest, "COMPOSE", path):
                path.write_bytes(
                    source
                    + padding_prefix
                    + b"x" * (64 * 1024 - len(source) - len(padding_prefix))
                )
                self.assertEqual(
                    self._build_with_fixed_non_compose_sources()["release_id"],
                    "0.1.3",
                )

                for value in duplicate_values:
                    with self.subTest(value=value[:40]):
                        path.write_bytes(value)
                        with self.assertRaises(ValueError):
                            self._build_with_fixed_non_compose_sources()

                path.write_bytes(
                    source
                    + padding_prefix
                    + b"x" * (64 * 1024 + 1 - len(source) - len(padding_prefix))
                )
                with self.assertRaises((OSError, ValueError)):
                    self._build_with_fixed_non_compose_sources()

    def test_backend_and_compose_sources_reject_links_before_open(self) -> None:
        compose_source = release_manifest.COMPOSE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = root / "__init__.py"
            backend.write_text('__version__ = "0.1.3"\n', encoding="utf-8")
            compose = root / "docker-compose.yml"
            compose.write_bytes(compose_source)
            cases = (
                (
                    "backend",
                    "BACKEND_INIT",
                    backend,
                    release_manifest._read_backend_version,
                ),
                (
                    "compose",
                    "COMPOSE",
                    compose,
                    self._build_with_fixed_non_compose_sources,
                ),
            )

            for name, attribute, path, reader in cases:
                with self.subTest(name=name), mock.patch.object(
                    release_manifest, attribute, path
                ), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    with self.assertRaises((OSError, ValueError)):
                        reader()
                    open_file.assert_not_called()

    def test_backend_and_compose_sources_reject_read_shape_drift(self) -> None:
        compose_source = release_manifest.COMPOSE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = root / "__init__.py"
            backend.write_text('__version__ = "0.1.3"\n', encoding="utf-8")
            compose = root / "docker-compose.yml"
            compose.write_bytes(compose_source)
            cases = (
                (
                    "backend",
                    "BACKEND_INIT",
                    backend,
                    release_manifest._read_backend_version,
                ),
                (
                    "compose",
                    "COMPOSE",
                    compose,
                    self._build_with_fixed_non_compose_sources,
                ),
            )

            for name, attribute, path, reader in cases:
                real_fstat = os.fstat
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
                                metadata, "st_file_attributes", 0
                            ),
                        )
                    return metadata

                with self.subTest(name=name), mock.patch.object(
                    release_manifest, attribute, path
                ), mock.patch("os.fstat", side_effect=drifting_fstat):
                    with self.assertRaises((OSError, ValueError)):
                        reader()
                    self.assertEqual(calls, 2)

    def test_migration_candidates_are_bounded_regular_stable_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            migrations = Path(temporary) / "versions"
            migrations.mkdir()
            candidate = migrations / "9999_test.py"
            with mock.patch.object(release_manifest, "MIGRATIONS", migrations):
                candidate.write_bytes(b"#" + b"x" * (64 * 1024 - 1))
                self.assertEqual(release_manifest._read_migration_head(), "9999_test")

                candidate.write_bytes(b"#" + b"x" * (64 * 1024))
                with self.subTest(shape="oversized"):
                    with self.assertRaises((OSError, ValueError)):
                        release_manifest._read_migration_head()

                candidate.unlink()
                candidate.mkdir()
                with self.subTest(shape="directory"):
                    with self.assertRaises((OSError, ValueError)):
                        release_manifest._read_migration_head()

                candidate.rmdir()
                candidate.write_text("# migration\n", encoding="utf-8")
                with self.subTest(shape="link-or-reparse"), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    with self.assertRaises((OSError, ValueError)):
                        release_manifest._read_migration_head()
                    open_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
