from __future__ import annotations

import importlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from platform import config
from platform.config import Settings


class RuntimeFileBoundaryTests(unittest.TestCase):
    @staticmethod
    def _boundary():
        return importlib.import_module("platform.file_boundary")

    @staticmethod
    def _cases(root: Path):
        return (
            (
                "database",
                root / "database-url",
                b"postgresql://platform:password@postgres/platform",
                lambda path: Settings(
                    _env_file=None,
                    database_url_file=str(path),
                ).resolved_database_url(),
                "postgresql://platform:password@postgres/platform",
                "Cannot read PLATFORM_DATABASE_URL_FILE",
                "MAX_RUNTIME_SECRET_BYTES",
            ),
            (
                "redis",
                root / "redis-url",
                b"rediss://platform:password@redis:6379/0",
                lambda path: Settings(
                    _env_file=None,
                    redis_url_file=str(path),
                ).resolved_redis_url(),
                "rediss://platform:password@redis:6379/0",
                "Cannot read PLATFORM_REDIS_URL_FILE",
                "MAX_RUNTIME_SECRET_BYTES",
            ),
            (
                "sub2",
                root / "sub2-origins",
                b"https://sub2.example,https://sub2-backup.example:8443",
                lambda path: Settings(
                    _env_file=None,
                    sub2_allowed_origins_file=str(path),
                ).resolved_sub2_allowed_origins(),
                ("https://sub2.example", "https://sub2-backup.example:8443"),
                "Sub2 allowed origins policy is unavailable",
                "MAX_ORIGIN_POLICY_BYTES",
            ),
            (
                "mail",
                root / "mail-origins",
                b"https://mail.example,https://mail-backup.example:8443",
                lambda path: Settings(
                    _env_file=None,
                    mail_allowed_origins_file=str(path),
                ).resolved_mail_allowed_origins(),
                ("https://mail.example", "https://mail-backup.example:8443"),
                "Mail allowed origins policy is unavailable",
                "MAX_ORIGIN_POLICY_BYTES",
            ),
        )

    def test_each_runtime_input_uses_one_domain_bounded_snapshot(self) -> None:
        boundary = self._boundary()
        with tempfile.TemporaryDirectory() as directory:
            for label, path, raw, load, expected, _, limit_name in self._cases(
                Path(directory)
            ):
                path.write_bytes(raw)
                reader_name = (
                    "read_stable_runtime_bytes_with_metadata"
                    if label in {"database", "redis"}
                    else "read_stable_runtime_text"
                )
                reader = (
                    boundary.read_stable_runtime_bytes_with_metadata
                    if label in {"database", "redis"}
                    else boundary.read_stable_runtime_text
                )
                with self.subTest(label=label), mock.patch.object(
                    config,
                    reader_name,
                    wraps=reader,
                    create=True,
                ) as stable_read:
                    self.assertEqual(load(path), expected)
                stable_read.assert_called_once_with(
                    path,
                    max_bytes=getattr(config, limit_name),
                    allow_empty=True,
                )

    def test_secret_urls_bind_permissions_to_the_authenticated_snapshot(self) -> None:
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o620,
            st_size=len(b"postgresql://stable"),
        )
        cases = (
            (
                Settings(_env_file=None, database_url_file="/run/secrets/database-url"),
                "resolved_database_url",
                b"postgresql://stable",
                "Cannot read PLATFORM_DATABASE_URL_FILE",
            ),
            (
                Settings(_env_file=None, redis_url_file="/run/secrets/redis-url"),
                "resolved_redis_url",
                b"rediss://stable",
                "Cannot read PLATFORM_REDIS_URL_FILE",
            ),
        )
        for settings, method, raw, error in cases:
            metadata.st_size = len(raw)
            with self.subTest(method=method), mock.patch.object(
                config,
                "read_stable_runtime_bytes_with_metadata",
                return_value=(raw, metadata),
                create=True,
            ) as stable_read, mock.patch.object(
                config.os,
                "name",
                "posix",
                create=True,
            ), self.assertRaisesRegex(RuntimeError, error):
                getattr(settings, method)()
            stable_read.assert_called_once()

    def test_exact_domain_limits_are_accepted_and_one_extra_byte_is_unavailable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for label, path, _, load, _, read_error, limit_name in self._cases(
                Path(directory)
            ):
                limit = getattr(config, limit_name)
                prefix = (
                    b"postgresql://platform@postgres/"
                    if label == "database"
                    else b"rediss://platform@redis/0"
                    if label == "redis"
                    else b"https://allowed.example"
                )
                exact = prefix + (b" " * (limit - len(prefix)))
                self.assertEqual(len(exact), limit)
                path.write_bytes(exact)
                result = load(path)
                if isinstance(result, tuple):
                    self.assertEqual(result, (prefix.decode("ascii"),))
                else:
                    self.assertEqual(result, prefix.decode("ascii"))
                path.write_bytes(exact + b"x")
                with self.assertRaisesRegex(RuntimeError, read_error):
                    load(path)

    def test_empty_and_multiline_files_keep_existing_content_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "database"
            database.write_bytes(b"")
            with self.assertRaisesRegex(
                RuntimeError,
                "PLATFORM_DATABASE_URL_FILE must contain one non-empty line",
            ):
                Settings(
                    _env_file=None,
                    database_url_file=str(database),
                ).resolved_database_url()

            redis = root / "redis"
            redis.write_text("redis://one\nredis://two\n", encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError,
                "PLATFORM_REDIS_URL_FILE must contain one non-empty line",
            ):
                Settings(
                    _env_file=None,
                    redis_url_file=str(redis),
                ).resolved_redis_url()

            for field, method, message in (
                (
                    "sub2_allowed_origins_file",
                    "resolved_sub2_allowed_origins",
                    "Sub2 allowed origins policy is invalid",
                ),
                (
                    "mail_allowed_origins_file",
                    "resolved_mail_allowed_origins",
                    "Mail allowed origins policy is invalid",
                ),
            ):
                policy = root / field
                policy.write_bytes(b"")
                settings = Settings(_env_file=None, **{field: str(policy)})
                with self.assertRaisesRegex(RuntimeError, message):
                    getattr(settings, method)()

    def test_invalid_utf8_is_mapped_to_fixed_unavailable_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for label, path, _, load, _, read_error, _ in self._cases(Path(directory)):
                path.write_bytes(b"private-prefix-\xff-private-suffix")
                with self.subTest(label=label), self.assertRaisesRegex(
                    RuntimeError,
                    read_error,
                ) as raised:
                    load(path)
                self.assertNotIn("private-prefix", str(raised.exception))
                self.assertNotIn(str(path), str(raised.exception))

    def test_stable_projected_link_snapshot_is_supported(self) -> None:
        boundary = self._boundary()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projected = root / "projected"
            target = root / "..2026_08_27" / "database-url"
            target.parent.mkdir()
            target.write_text("postgresql://stable", encoding="utf-8")
            with mock.patch.object(
                boundary.Path,
                "resolve",
                autospec=True,
                return_value=target,
            ) as resolve:
                self.assertEqual(
                    boundary.read_stable_runtime_text(projected, max_bytes=1024),
                    "postgresql://stable",
                )
            self.assertEqual(resolve.call_count, 2)

    def test_projected_target_switch_during_read_is_rejected(self) -> None:
        boundary = self._boundary()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projected = root / "projected"
            first = root / "..old" / "database-url"
            second = root / "..new" / "database-url"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_text("postgresql://first", encoding="utf-8")
            second.write_text("postgresql://second", encoding="utf-8")
            with mock.patch.object(
                boundary.Path,
                "resolve",
                autospec=True,
                side_effect=(first, second),
            ), self.assertRaises(boundary.RuntimeFileError):
                boundary.read_stable_runtime_text(projected, max_bytes=1024)

    def test_open_descriptor_rejects_projected_switch_during_consumer_use(self) -> None:
        boundary = self._boundary()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projected = root / "projected"
            first = root / "..old" / "tls.key"
            second = root / "..new" / "tls.key"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"first-private-key")
            second.write_bytes(b"second-private-key")
            with mock.patch.object(
                boundary.Path,
                "resolve",
                autospec=True,
                side_effect=(first, second),
            ), self.assertRaises(boundary.RuntimeFileError):
                with boundary.open_stable_runtime_descriptor(
                    projected,
                    max_bytes=1024,
                ) as (descriptor, metadata):
                    self.assertGreaterEqual(descriptor, 0)
                    self.assertEqual(metadata.st_size, len(b"first-private-key"))

    def test_non_regular_open_file_is_rejected_and_redacted(self) -> None:
        boundary = self._boundary()
        real_fstat = os.fstat

        def non_regular_fstat(descriptor: int):
            metadata = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFIFO | 0o600,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        with tempfile.TemporaryDirectory() as directory:
            for label, path, raw, load, _, read_error, _ in self._cases(Path(directory)):
                path.write_bytes(raw)
                with self.subTest(label=label), mock.patch.object(
                    boundary.os,
                    "fstat",
                    side_effect=non_regular_fstat,
                ), self.assertRaisesRegex(RuntimeError, read_error) as raised:
                    load(path)
                self.assertNotIn(str(path), str(raised.exception))

    def test_read_shape_drift_is_rejected_and_redacted(self) -> None:
        boundary = self._boundary()
        real_fstat = os.fstat
        with tempfile.TemporaryDirectory() as directory:
            for label, path, raw, load, _, read_error, _ in self._cases(Path(directory)):
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
                            st_file_attributes=getattr(
                                metadata,
                                "st_file_attributes",
                                0,
                            ),
                        )
                    return metadata

                path.write_bytes(raw)
                with self.subTest(label=label), mock.patch.object(
                    boundary.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ), self.assertRaisesRegex(RuntimeError, read_error) as raised:
                    load(path)
                self.assertEqual(calls, 2)
                self.assertNotIn(str(path), str(raised.exception))

    def test_missing_files_keep_existing_unavailable_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for label, path, _, load, _, read_error, _ in self._cases(Path(directory)):
                with self.subTest(label=label), self.assertRaisesRegex(
                    RuntimeError,
                    read_error,
                ) as raised:
                    load(path)
                self.assertNotIn(str(path), str(raised.exception))

    def test_sources_use_platform_local_boundary_without_direct_text_reads(self) -> None:
        config_source = Path(config.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", config_source)
        self.assertIn("from platform.file_boundary import", config_source)
        self.assertIn("MAX_RUNTIME_SECRET_BYTES = 8 * 1024", config_source)
        self.assertIn("MAX_ORIGIN_POLICY_BYTES = 8 * 1024", config_source)
        self.assertEqual(
            config_source.count("read_stable_runtime_bytes_with_metadata("),
            1,
        )
        self.assertGreaterEqual(config_source.count("read_stable_runtime_text("), 2)

        boundary = self._boundary()
        boundary_source = Path(boundary.__file__).read_text(encoding="utf-8")
        self.assertNotIn("scripts.", boundary_source)
        self.assertGreaterEqual(boundary_source.count("source.resolve(strict=True)"), 2)
        self.assertIn("stream.read(max_bytes + 1)", boundary_source)


if __name__ == "__main__":
    unittest.main()
