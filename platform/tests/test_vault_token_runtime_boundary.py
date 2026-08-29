from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from platform import file_boundary
from platform import secrets
from platform.secrets import SecretResolverUnavailable, VaultSecretResolver


FIXED_ERROR = "Vault token file is unavailable"


class VaultTokenRuntimeBoundaryTests(unittest.TestCase):
    def test_shared_reader_returns_authenticated_final_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_bytes(b"stable-token")
            raw, metadata = file_boundary.read_stable_runtime_bytes_with_metadata(
                token_file,
                max_bytes=4096,
            )
        self.assertEqual(raw, b"stable-token")
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_size, len(raw))

    def test_vault_token_uses_one_shared_snapshot_with_exact_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_bytes(b"v" * 4096)
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
            )
            with mock.patch.object(
                secrets,
                "read_stable_runtime_bytes_with_metadata",
                wraps=file_boundary.read_stable_runtime_bytes_with_metadata,
                create=True,
            ) as stable_read:
                self.assertIsNone(resolver.validate_token_source())
            stable_read.assert_called_once_with(
                token_file.resolve(),
                max_bytes=secrets._MAX_VAULT_TOKEN_BYTES,
            )

    def test_stable_projected_token_target_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projected = root / "token"
            target = root / "..2026_08_27" / "vault-token"
            target.parent.mkdir()
            target.write_text("projected-token", encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(projected.absolute()),
            )
            with mock.patch.object(
                file_boundary.Path,
                "resolve",
                autospec=True,
                return_value=target,
            ) as resolve:
                self.assertIsNone(resolver.validate_token_source())
            self.assertEqual(resolve.call_count, 2)

    def test_projected_target_switch_is_fixed_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projected = root / "token"
            first = root / "..old" / "vault-token"
            second = root / "..new" / "vault-token"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_text("first-token", encoding="utf-8")
            second.write_text("second-token", encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(projected.absolute()),
            )
            with mock.patch.object(
                file_boundary.Path,
                "resolve",
                autospec=True,
                side_effect=(first, second),
            ), self.assertRaises(SecretResolverUnavailable) as raised:
                resolver.validate_token_source()
        self.assertEqual(str(raised.exception), FIXED_ERROR)
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn(str(projected), str(raised.exception))

    def test_authenticated_group_or_world_writable_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_text("valid-token", encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
            )
            for mode in (0o620, 0o602):
                metadata = SimpleNamespace(
                    st_mode=stat.S_IFREG | mode,
                    st_size=len(b"valid-token"),
                )
                with self.subTest(mode=oct(mode)), mock.patch.object(
                    secrets,
                    "read_stable_runtime_bytes_with_metadata",
                    return_value=(b"valid-token", metadata),
                    create=True,
                ), mock.patch.object(
                    secrets.os,
                    "name",
                    "posix",
                ), self.assertRaises(SecretResolverUnavailable) as raised:
                    resolver.validate_token_source()
                self.assertEqual(str(raised.exception), FIXED_ERROR)
                self.assertIsNone(raised.exception.__cause__)

    def test_shared_boundary_failures_are_fixed_without_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "private-token-path"
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.absolute()),
            )
            with mock.patch.object(
                secrets,
                "read_stable_runtime_bytes_with_metadata",
                side_effect=file_boundary.RuntimeFileError("private-boundary-detail"),
                create=True,
            ), self.assertRaises(SecretResolverUnavailable) as raised:
                resolver.validate_token_source()
        self.assertEqual(str(raised.exception), FIXED_ERROR)
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn("private-boundary-detail", str(raised.exception))
        self.assertNotIn(str(token_file), str(raised.exception))

    def test_each_token_request_reloads_the_current_projected_snapshot(self) -> None:
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_size=5)
        resolver = VaultSecretResolver(
            "https://vault.example",
            token_file="/run/secrets/vault-token",
        )
        with mock.patch.object(
            secrets,
            "read_stable_runtime_bytes_with_metadata",
            side_effect=((b"first", metadata), (b"next1", metadata)),
            create=True,
        ) as stable_read:
            self.assertEqual(resolver._token(), "first")
            self.assertEqual(resolver._token(), "next1")
        self.assertEqual(stable_read.call_count, 2)

    def test_source_reuses_runtime_boundary_without_direct_descriptor_read(self) -> None:
        source = Path(secrets.__file__).read_text(encoding="utf-8")
        token_source = source.split("    def _token(self) -> str:", 1)[1].split(
            "    def validate_token_source", 1
        )[0]
        self.assertIn("read_stable_runtime_bytes_with_metadata(", token_source)
        for marker in ("os.open(", "os.read(", "os.fstat(", "O_NOFOLLOW"):
            self.assertNotIn(marker, token_source)
        boundary_source = Path(file_boundary.__file__).read_text(encoding="utf-8")
        self.assertIn("def read_stable_runtime_bytes_with_metadata(", boundary_source)
        self.assertIn("return raw, final_opened", boundary_source)


if __name__ == "__main__":
    unittest.main()
