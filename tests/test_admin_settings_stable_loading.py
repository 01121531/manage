from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import admin_oauth
from scripts import external_json


class AdminSettingsStableLoadingTests(unittest.TestCase):
    @staticmethod
    def _stores(directory: str):
        root = Path(directory)
        return (
            (
                admin_oauth.AccountNameStore(root / "account_name.txt"),
                "账号",
                "账号".encode("utf-8"),
                admin_oauth.AccountNameStoreError,
                "无法读取已保存的账号名称",
            ),
            (
                admin_oauth.ProxyIdStore(root / "proxy_id.txt"),
                3100,
                b"3100",
                admin_oauth.ProxyIdStoreError,
                "无法读取已保存的代理 ID",
            ),
        )

    def test_missing_and_empty_files_keep_existing_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")
            self.assertIsNone(account.load())
            self.assertEqual(proxy.load(), admin_oauth.PROXY_ID)

            account.path.write_bytes(b"")
            proxy.path.write_bytes(b"")
            self.assertIsNone(account.load())
            with self.assertRaisesRegex(
                admin_oauth.ProxyIdStoreError,
                "代理 ID 必须是正整数",
            ):
                proxy.load()

    def test_each_store_uses_one_bounded_shared_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for store, expected, raw, _, _ in self._stores(directory):
                store.path.write_bytes(raw)
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    admin_oauth,
                    "read_stable_bytes",
                    wraps=external_json.read_stable_bytes,
                    create=True,
                ) as stable_read:
                    self.assertEqual(store.load(), expected)
                stable_read.assert_called_once_with(
                    store.path,
                    max_bytes=(
                        admin_oauth.MAX_ACCOUNT_NAME_BYTES
                        if isinstance(store, admin_oauth.AccountNameStore)
                        else admin_oauth.MAX_PROXY_ID_BYTES
                    ),
                    allow_empty=True,
                )

    def test_exact_valid_boundaries_are_accepted_and_one_extra_byte_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            exact_account = "😀" * 200
            self.assertEqual(
                len(exact_account.encode("utf-8")),
                admin_oauth.MAX_ACCOUNT_NAME_BYTES,
            )
            account.path.write_text(exact_account, encoding="utf-8")
            self.assertEqual(account.load(), exact_account)
            account.path.write_bytes(exact_account.encode("utf-8") + b"a")
            with self.assertRaisesRegex(
                admin_oauth.AccountNameStoreError,
                "无法读取已保存的账号名称",
            ):
                account.load()

            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")
            exact_proxy = "9" * admin_oauth.MAX_PROXY_ID_BYTES
            proxy.path.write_text(exact_proxy, encoding="ascii")
            self.assertEqual(proxy.load(), int(exact_proxy))
            proxy.path.write_bytes(exact_proxy.encode("ascii") + b"9")
            with self.assertRaisesRegex(
                admin_oauth.ProxyIdStoreError,
                "无法读取已保存的代理 ID",
            ):
                proxy.load()

    def test_invalid_encoding_keeps_reviewed_read_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            account.path.write_bytes(b"\xff")
            with self.assertRaisesRegex(
                admin_oauth.AccountNameStoreError,
                "无法读取已保存的账号名称",
            ):
                account.load()

            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")
            proxy.path.write_bytes("代理".encode("utf-8"))
            with self.assertRaisesRegex(
                admin_oauth.ProxyIdStoreError,
                "无法读取已保存的代理 ID",
            ):
                proxy.load()

    def test_link_or_reparse_is_rejected_before_open(self) -> None:
        real_open = os.open
        with tempfile.TemporaryDirectory() as directory:
            for store, _, raw, error_type, error_message in self._stores(directory):
                store.path.write_bytes(raw)
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(
                    external_json.os,
                    "open",
                    wraps=real_open,
                ) as open_file:
                    with self.assertRaisesRegex(error_type, error_message):
                        store.load()
                open_file.assert_not_called()

    def test_non_regular_open_file_is_rejected(self) -> None:
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
            for store, _, raw, error_type, error_message in self._stores(directory):
                store.path.write_bytes(raw)
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=non_regular_fstat,
                ):
                    with self.assertRaisesRegex(error_type, error_message):
                        store.load()

    def test_read_shape_drift_is_rejected(self) -> None:
        real_fstat = os.fstat
        with tempfile.TemporaryDirectory() as directory:
            for store, _, raw, error_type, error_message in self._stores(directory):
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

                store.path.write_bytes(raw)
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ):
                    with self.assertRaisesRegex(error_type, error_message):
                        store.load()
                self.assertEqual(calls, 2)

    def test_only_initial_open_missing_uses_store_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")
            with mock.patch.object(
                admin_oauth,
                "read_stable_bytes",
                side_effect=external_json.StableFileError("missing"),
                create=True,
            ):
                self.assertIsNone(account.load())
                self.assertEqual(proxy.load(), admin_oauth.PROXY_ID)

            for reason in ("read", "size"):
                with self.subTest(reason=reason), mock.patch.object(
                    admin_oauth,
                    "read_stable_bytes",
                    side_effect=external_json.StableFileError(reason),
                    create=True,
                ):
                    with self.assertRaisesRegex(
                        admin_oauth.AccountNameStoreError,
                        "无法读取已保存的账号名称",
                    ):
                        account.load()
                    with self.assertRaisesRegex(
                        admin_oauth.ProxyIdStoreError,
                        "无法读取已保存的代理 ID",
                    ):
                        proxy.load()

    def test_stable_reader_classifies_only_initial_missing_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.txt"
            with self.assertRaises(external_json.StableFileError) as raised:
                external_json.read_stable_bytes(
                    missing,
                    max_bytes=1,
                    allow_empty=True,
                )
        self.assertEqual(raised.exception.reason, "missing")

    def test_source_has_no_direct_or_exists_then_read_boundary(self) -> None:
        source = Path(admin_oauth.__file__).read_text(encoding="utf-8")
        account_source = source.split("class AccountNameStore:", 1)[1].split(
            "def normalize_proxy_id", 1
        )[0]
        proxy_source = source.split("class ProxyIdStore:", 1)[1].split(
            "class AdminTokenStore:", 1
        )[0]
        for store_source in (account_source, proxy_source):
            self.assertNotIn(".read_text(", store_source)
            self.assertNotIn(".exists()", store_source)
            self.assertIn("read_stable_bytes(", store_source)
            self.assertIn("allow_empty=True", store_source)
        self.assertIn("MAX_ACCOUNT_NAME_BYTES = 4 * 200", source)
        self.assertIn("MAX_PROXY_ID_BYTES = 4300", source)


if __name__ == "__main__":
    unittest.main()
