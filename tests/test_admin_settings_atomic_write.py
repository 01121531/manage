from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import admin_oauth
from scripts import external_json


class AdminSettingsAtomicWriteTests(unittest.TestCase):
    def test_each_store_delegates_exact_normalized_bytes_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            admin_oauth,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")

            account.save("  账号  ")
            self.assertEqual(proxy.save(" 003100 "), 3100)

        self.assertEqual(
            atomic_write.call_args_list,
            [
                mock.call(account.path, "账号".encode("utf-8")),
                mock.call(proxy.path, b"3100"),
            ],
        )

    def test_save_failures_keep_fixed_errors_without_private_details(self) -> None:
        private_detail = "private-path-and-setting-value"
        with tempfile.TemporaryDirectory() as directory:
            cases = (
                (
                    admin_oauth.AccountNameStore(Path(directory) / "account.txt"),
                    "account-value",
                    admin_oauth.AccountNameStoreError,
                    "无法保存账号名称",
                ),
                (
                    admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt"),
                    3100,
                    admin_oauth.ProxyIdStoreError,
                    "无法保存代理 ID",
                ),
            )
            for store, value, error_type, message in cases:
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    admin_oauth,
                    "write_atomic_bytes",
                    side_effect=OSError(private_detail),
                    create=True,
                ):
                    with self.assertRaisesRegex(error_type, f"^{message}$"):
                        store.save(value)

    def test_validation_happens_before_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            admin_oauth,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")

            for value in ("", "x" * 201, "first\nsecond"):
                with self.subTest(account=value), self.assertRaises(
                    admin_oauth.AccountNameStoreError
                ):
                    account.save(value)
            for value in ("", 0, -1, "not-an-integer"):
                with self.subTest(proxy=value), self.assertRaises(
                    admin_oauth.ProxyIdStoreError
                ):
                    proxy.save(value)

        atomic_write.assert_not_called()

    def test_existing_character_and_proxy_boundaries_are_preserved(self) -> None:
        account_value = "😀" * 200
        proxy_value = int("9" * admin_oauth.MAX_PROXY_ID_BYTES)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            admin_oauth,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            account = admin_oauth.AccountNameStore(Path(directory) / "account.txt")
            proxy = admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt")

            account.save(account_value)
            self.assertEqual(proxy.save(proxy_value), proxy_value)

        self.assertEqual(
            atomic_write.call_args_list,
            [
                mock.call(account.path, account_value.encode("utf-8")),
                mock.call(proxy.path, str(proxy_value).encode("ascii")),
            ],
        )

    def test_replace_failure_preserves_old_value_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cases = (
                (
                    admin_oauth.AccountNameStore(Path(directory) / "account.txt"),
                    "new-account",
                    b"old-account",
                    admin_oauth.AccountNameStoreError,
                ),
                (
                    admin_oauth.ProxyIdStore(Path(directory) / "proxy.txt"),
                    3100,
                    b"2940",
                    admin_oauth.ProxyIdStoreError,
                ),
            )
            for store, value, old_value, error_type in cases:
                store.path.write_bytes(old_value)
                with self.subTest(store=type(store).__name__), mock.patch.object(
                    external_json.os,
                    "replace",
                    side_effect=OSError("replace-private-detail"),
                ):
                    with self.assertRaises(error_type):
                        store.save(value)
                self.assertEqual(store.path.read_bytes(), old_value)
                self.assertEqual(
                    list(store.path.parent.glob(f".{store.path.name}.*.tmp")),
                    [],
                )

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support is required")
    def test_each_store_replaces_leaf_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (admin_oauth.AccountNameStore(root / "account.txt"), "new", b"old"),
                (admin_oauth.ProxyIdStore(root / "proxy.txt"), 3100, b"2940"),
            )
            for index, (store, value, old_value) in enumerate(cases):
                target = root / f"target-{index}.txt"
                target.write_bytes(old_value)
                store.path.symlink_to(target)

                store.save(value)

                self.assertFalse(store.path.is_symlink())
                self.assertEqual(target.read_bytes(), old_value)

    def test_sources_have_no_fixed_temporary_or_direct_text_write(self) -> None:
        source = Path(admin_oauth.__file__).read_text(encoding="utf-8")
        account_source = source.split("class AccountNameStore:", 1)[1].split(
            "def normalize_proxy_id", 1
        )[0]
        proxy_source = source.split("class ProxyIdStore:", 1)[1].split(
            "class AdminTokenStore:", 1
        )[0]
        for store_source in (account_source, proxy_source):
            self.assertIn("write_atomic_bytes(", store_source)
            self.assertNotIn("with_suffix(", store_source)
            self.assertNotIn(".write_text(", store_source)
            self.assertNotIn("os.replace(", store_source)


if __name__ == "__main__":
    unittest.main()
