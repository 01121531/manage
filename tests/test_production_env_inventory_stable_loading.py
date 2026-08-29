from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import check_internal_tls_expiry as internal_tls
from scripts import external_json
from scripts import validate_edge_tls as edge_tls
from scripts import vault_token_sinks


MAX_ENV_INVENTORY_BYTES = 64 * 1024


class ProductionEnvInventoryStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def consumers(self):
        return (
            (
                "internal-tls",
                internal_tls,
                internal_tls._load_env_file,
                "PLATFORM_INTERNAL_CA_FILE=/external/ca.pem\n",
                (internal_tls.CertificateInputError,),
            ),
            (
                "edge-tls",
                edge_tls,
                edge_tls._read_inventory,
                (
                    "PLATFORM_TLS_CERT_FILE=/external/fullchain.pem\n"
                    "PLATFORM_TLS_KEY_FILE=/external/privkey.pem\n"
                ),
                (edge_tls.EdgeTlsError,),
            ),
            (
                "vault-token-sinks",
                vault_token_sinks,
                vault_token_sinks._read_inventory,
                "".join(
                    f"{name}=/external/{index}\n"
                    for index, name in enumerate(
                        vault_token_sinks.TOKEN_DIRECTORY_VARIABLES
                    )
                ),
                (OSError, UnicodeError, vault_token_sinks._InvalidSink),
            ),
        )

    @staticmethod
    def exact_size_payload(base: str, size: int) -> bytes:
        encoded = base.encode("utf-8")
        return encoded + b"#" + b"x" * (size - len(encoded) - 1)

    def test_inventory_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        for name, _, loader, base, errors in self.consumers():
            with self.subTest(consumer=name, size="limit"):
                path = self.root / f"{name}.env"
                path.write_bytes(self.exact_size_payload(base, MAX_ENV_INVENTORY_BYTES))
                loader(path)
            with self.subTest(consumer=name, size="limit-plus-one"):
                path.write_bytes(path.read_bytes() + b"x")
                with self.assertRaises(errors):
                    loader(path)

    def test_inventory_uses_one_stable_read_without_path_read_text(self) -> None:
        for name, module, loader, base, _ in self.consumers():
            with self.subTest(consumer=name):
                path = self.root / f"{name}.env"
                path.write_text(base, encoding="utf-8")
                with mock.patch.object(
                    Path,
                    "read_text",
                    side_effect=AssertionError("Path.read_text bypassed stable loading"),
                ), mock.patch.object(
                    module,
                    "read_stable_bytes",
                    wraps=external_json.read_stable_bytes,
                    create=True,
                ) as stable_read:
                    loader(path)
                stable_read.assert_called_once_with(
                    path,
                    max_bytes=MAX_ENV_INVENTORY_BYTES,
                )

    def test_link_or_reparse_inventory_is_rejected_before_open(self) -> None:
        for name, _, loader, base, errors in self.consumers():
            with self.subTest(consumer=name):
                path = self.root / f"{name}.env"
                path.write_text(base, encoding="utf-8")
                with mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    with self.assertRaises(errors):
                        loader(path)
                open_file.assert_not_called()

    def test_non_regular_open_inventory_is_rejected(self) -> None:
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

        for name, _, loader, base, errors in self.consumers():
            with self.subTest(consumer=name):
                path = self.root / f"{name}.env"
                path.write_text(base, encoding="utf-8")
                with mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=False,
                ), mock.patch.object(external_json.os, "fstat", non_regular_fstat):
                    with self.assertRaises(errors):
                        loader(path)

    def test_named_inventory_replacement_during_read_is_rejected(self) -> None:
        real_lstat = Path.lstat
        for name, _, loader, base, errors in self.consumers():
            with self.subTest(consumer=name):
                path = self.root / f"{name}.env"
                path.write_text(base, encoding="utf-8")
                calls = 0

                def drifting_lstat(candidate: Path):
                    nonlocal calls
                    metadata = real_lstat(candidate)
                    if candidate == path:
                        calls += 1
                        if calls == 2:
                            return SimpleNamespace(
                                st_mode=metadata.st_mode,
                                st_dev=metadata.st_dev,
                                st_ino=metadata.st_ino,
                                st_nlink=metadata.st_nlink,
                                st_size=metadata.st_size + 1,
                                st_mtime_ns=metadata.st_mtime_ns,
                                st_file_attributes=getattr(
                                    metadata, "st_file_attributes", 0
                                ),
                            )
                    return metadata

                with mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=False,
                ), mock.patch.object(Path, "lstat", drifting_lstat):
                    with self.assertRaises(errors):
                        loader(path)
                self.assertEqual(calls, 2)

    def test_invalid_utf8_keeps_fixed_public_error_mapping(self) -> None:
        path = self.root / "invalid.env"
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(
            internal_tls.CertificateInputError,
            "^inventory: env file is unreadable UTF-8$",
        ):
            internal_tls._load_env_file(path)
        with self.assertRaisesRegex(
            edge_tls.EdgeTlsError,
            "^edge TLS inventory is invalid$",
        ):
            edge_tls._read_inventory(path)

    def test_sources_keep_shared_bounded_inventory_reads(self) -> None:
        for module in (internal_tls, edge_tls, vault_token_sinks):
            with self.subTest(module=module.__name__):
                source = Path(module.__file__).read_text(encoding="utf-8")
                self.assertIn("MAX_ENV_INVENTORY_BYTES = 64 * 1024", source)
                self.assertNotIn("env_file.read_text(", source)
                self.assertNotIn("path.read_text(encoding=\"utf-8\")", source)


if __name__ == "__main__":
    unittest.main()
