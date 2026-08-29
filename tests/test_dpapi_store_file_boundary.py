from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import admin_oauth
import session_store
from scripts import external_json


class DpapiStoreFileBoundaryTests(unittest.TestCase):
    @staticmethod
    def _session_store(path: Path) -> session_store.WindowsDpapiSessionStore:
        with mock.patch.object(session_store.os, "name", "nt"):
            return session_store.WindowsDpapiSessionStore(
                path,
                device_binding_id="t116-device",
            )

    def test_each_store_loads_one_domain_bounded_stable_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin_path = root / "admin-token.bin"
            admin_path.write_bytes(b"admin-ciphertext")
            admin_store = admin_oauth.AdminTokenStore(admin_path)
            with mock.patch.object(
                admin_oauth,
                "read_stable_bytes",
                wraps=external_json.read_stable_bytes,
            ) as stable_read, mock.patch.object(
                admin_oauth,
                "_unprotect_data",
                return_value=b"admin-token",
            ):
                self.assertEqual(admin_store.load(), "admin-token")
            stable_read.assert_called_once_with(
                admin_path,
                max_bytes=admin_oauth.MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES,
                allow_empty=True,
            )

            session_path = root / "session-token.bin"
            session_path.write_bytes(b"session-ciphertext")
            saved_session = self._session_store(session_path)
            with mock.patch.object(
                session_store,
                "read_stable_bytes",
                wraps=external_json.read_stable_bytes,
                create=True,
            ) as stable_read, mock.patch.object(
                session_store,
                "_unprotect_data",
                return_value=b"refresh-token",
            ):
                self.assertEqual(saved_session.load(), "refresh-token")
            stable_read.assert_called_once_with(
                session_path,
                max_bytes=session_store.MAX_SESSION_CIPHERTEXT_BYTES,
                allow_empty=True,
            )

    def test_stable_missing_classification_returns_none_without_decrypting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth,
                    admin_oauth.AdminTokenStore(root / "missing-admin"),
                ),
                (
                    session_store,
                    self._session_store(root / "missing-session"),
                ),
            )
            for module, store in cases:
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    "read_stable_bytes",
                    side_effect=external_json.StableFileError("missing"),
                    create=True,
                ) as stable_read, mock.patch.object(
                    module,
                    "_unprotect_data",
                ) as decrypt:
                    self.assertIsNone(store.load())
                stable_read.assert_called_once()
                decrypt.assert_not_called()

    def test_exact_ciphertext_limits_are_accepted_and_one_extra_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth,
                    admin_oauth.AdminTokenStore(root / "admin-token"),
                    admin_oauth.MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES,
                    b"admin-token",
                    admin_oauth.TokenStoreError,
                    "无法读取已保存的管理令牌",
                ),
                (
                    session_store,
                    self._session_store(root / "session-token"),
                    session_store.MAX_SESSION_CIPHERTEXT_BYTES,
                    b"refresh-token",
                    session_store.SessionStoreError,
                    "无法读取已加密的平台会话",
                ),
            )
            for module, store, limit, plaintext, error_type, fixed_error in cases:
                with self.subTest(module=module.__name__):
                    store.path.write_bytes(b"c" * limit)
                    with mock.patch.object(
                        module,
                        "_unprotect_data",
                        return_value=plaintext,
                    ) as decrypt:
                        self.assertEqual(store.load(), plaintext.decode("ascii"))
                        store.path.write_bytes(b"c" * (limit + 1))
                        with self.assertRaisesRegex(
                            error_type,
                            f"^{fixed_error}$",
                        ):
                            store.load()
                    decrypt.assert_called_once()

    def test_unstable_reads_use_fixed_errors_without_path_or_ciphertext(self) -> None:
        private_ciphertext = b"private-ciphertext-marker"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth,
                    admin_oauth.AdminTokenStore(root / "private-admin-path"),
                    admin_oauth.TokenStoreError,
                    "无法读取已保存的管理令牌",
                ),
                (
                    session_store,
                    self._session_store(root / "private-session-path"),
                    session_store.SessionStoreError,
                    "无法读取已加密的平台会话",
                ),
            )
            for module, store, error_type, fixed_error in cases:
                boundary_error = external_json.StableFileError("read")
                boundary_error.__cause__ = OSError(
                    private_ciphertext.decode("ascii")
                )
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    "read_stable_bytes",
                    side_effect=boundary_error,
                    create=True,
                ), self.assertRaises(error_type) as raised:
                    store.load()
                self.assertEqual(str(raised.exception), fixed_error)
                self.assertNotIn(str(store.path), str(raised.exception))
                self.assertNotIn(
                    private_ciphertext.decode("ascii"),
                    str(raised.exception),
                )

    def test_empty_ciphertext_keeps_existing_domain_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin_path = root / "admin-token"
            admin_path.write_bytes(b"")
            with self.assertRaisesRegex(
                admin_oauth.TokenStoreError,
                "^已保存的管理令牌数据为空$",
            ):
                admin_oauth.AdminTokenStore(admin_path).load()

            session_path = root / "session-token"
            session_path.write_bytes(b"")
            with self.assertRaisesRegex(
                session_store.SessionStoreError,
                "^已保存的平台会话无效$",
            ):
                self._session_store(session_path).load()

    def test_invalid_decrypted_utf8_keeps_existing_domain_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth,
                    admin_oauth.AdminTokenStore(root / "admin-token"),
                    admin_oauth.TokenStoreError,
                    "无法读取已保存的管理令牌",
                ),
                (
                    session_store,
                    self._session_store(root / "session-token"),
                    session_store.SessionStoreError,
                    "已保存的平台会话内容无效",
                ),
            )
            for module, store, error_type, fixed_error in cases:
                store.path.write_bytes(b"ciphertext")
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    "_unprotect_data",
                    return_value=b"private-prefix-\xff-private-suffix",
                ), self.assertRaises(error_type) as raised:
                    store.load()
                self.assertEqual(str(raised.exception), fixed_error)
                self.assertNotIn("private-prefix", str(raised.exception))

    def test_plaintext_token_limits_are_byte_exact(self) -> None:
        admin_exact = "a" * admin_oauth.MAX_ADMIN_TOKEN_BYTES
        self.assertEqual(admin_oauth.validate_admin_token(admin_exact), admin_exact)
        with self.assertRaisesRegex(
            admin_oauth.TokenValidationError,
            "管理令牌格式无效",
        ):
            admin_oauth.validate_admin_token(admin_exact + "a")
        admin_multibyte = "😀" * (admin_oauth.MAX_ADMIN_TOKEN_BYTES // 4)
        self.assertEqual(
            len(admin_multibyte.encode("utf-8")),
            admin_oauth.MAX_ADMIN_TOKEN_BYTES,
        )
        self.assertEqual(
            admin_oauth.validate_admin_token(admin_multibyte),
            admin_multibyte,
        )
        with self.assertRaisesRegex(
            admin_oauth.TokenValidationError,
            "管理令牌格式无效",
        ):
            admin_oauth.validate_admin_token(admin_multibyte + "😀")

        session_exact = "r" * session_store.MAX_REFRESH_TOKEN_BYTES
        self.assertEqual(
            session_store._validate_refresh_token(session_exact),
            session_exact,
        )
        session_extra = session_exact + "r"
        self.assertEqual(
            session_store._validate_refresh_token(session_extra),
            session_extra,
        )
        saved_session = self._session_store(Path("session-token"))
        with mock.patch.object(session_store, "_protect_data") as protect:
            with self.assertRaisesRegex(ValueError, "refresh token 格式无效"):
                saved_session.save(session_extra)
        protect.assert_not_called()
        session_multibyte = "😀" * (session_store.MAX_REFRESH_TOKEN_BYTES // 4)
        self.assertEqual(
            len(session_multibyte.encode("utf-8")),
            session_store.MAX_REFRESH_TOKEN_BYTES,
        )
        with mock.patch.object(
            session_store,
            "_protect_data",
            return_value=b"ciphertext",
        ) as protect, mock.patch.object(session_store, "write_atomic_bytes"):
            saved_session.save(session_multibyte)
        protect.assert_called_once_with(
            session_multibyte.encode("utf-8"),
            saved_session._entropy,
        )
        with mock.patch.object(session_store, "_protect_data") as protect:
            with self.assertRaisesRegex(ValueError, "refresh token 格式无效"):
                saved_session.save(session_multibyte + "😀")
        protect.assert_not_called()

    def test_nonregular_store_paths_use_fixed_read_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth.AdminTokenStore(root),
                    admin_oauth.TokenStoreError,
                    "无法读取已保存的管理令牌",
                ),
                (
                    self._session_store(root),
                    session_store.SessionStoreError,
                    "无法读取已加密的平台会话",
                ),
            )
            for store, error_type, fixed_error in cases:
                with self.subTest(error_type=error_type.__name__), self.assertRaises(
                    error_type
                ) as raised:
                    store.load()
                self.assertEqual(str(raised.exception), fixed_error)

    def test_each_store_delegates_one_ciphertext_to_atomic_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin_path = root / "admin-token"
            with mock.patch.object(
                admin_oauth,
                "_protect_data",
                return_value=b"admin-ciphertext",
            ), mock.patch.object(
                admin_oauth,
                "write_atomic_bytes",
                create=True,
            ) as atomic_write:
                admin_oauth.AdminTokenStore(admin_path).save("admin-token")
            atomic_write.assert_called_once_with(admin_path, b"admin-ciphertext")

            session_path = root / "session-token"
            saved_session = self._session_store(session_path)
            with mock.patch.object(
                session_store,
                "_protect_data",
                return_value=b"session-ciphertext",
            ), mock.patch.object(
                session_store,
                "write_atomic_bytes",
                create=True,
            ) as atomic_write:
                saved_session.save("refresh-token")
            atomic_write.assert_called_once_with(session_path, b"session-ciphertext")

    def test_store_rejects_invalid_ciphertext_size_before_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin_path = root / "admin-token"
            for encrypted in (
                b"",
                b"x" * (admin_oauth.MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES + 1),
            ):
                with self.subTest(store="admin", size=len(encrypted)), mock.patch.object(
                    admin_oauth,
                    "_protect_data",
                    return_value=encrypted,
                ), mock.patch.object(
                    admin_oauth,
                    "write_atomic_bytes",
                ) as atomic_write, self.assertRaisesRegex(
                    admin_oauth.TokenStoreError,
                    "^无法保存已加密的管理令牌$",
                ):
                    admin_oauth.AdminTokenStore(admin_path).save("admin-token")
                atomic_write.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
    def test_max_plaintext_dpapi_outputs_fit_and_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin_token = "a" * admin_oauth.MAX_ADMIN_TOKEN_BYTES
            admin_store = admin_oauth.AdminTokenStore(root / "admin-token")
            admin_store.save(admin_token)
            self.assertLessEqual(
                admin_store.path.stat().st_size,
                admin_oauth.MAX_ADMIN_TOKEN_CIPHERTEXT_BYTES,
            )
            self.assertEqual(admin_store.load(), admin_token)

            refresh_token = "r" * session_store.MAX_REFRESH_TOKEN_BYTES
            saved_session = self._session_store(root / "session-token")
            saved_session.save(refresh_token)
            self.assertLessEqual(
                saved_session.path.stat().st_size,
                session_store.MAX_SESSION_CIPHERTEXT_BYTES,
            )
            self.assertEqual(saved_session.load(), refresh_token)

    def test_atomic_write_failures_are_mapped_without_private_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    admin_oauth,
                    admin_oauth.AdminTokenStore(root / "admin-token"),
                    "admin-token",
                    b"admin-ciphertext",
                    admin_oauth.TokenStoreError,
                    "无法保存已加密的管理令牌",
                ),
                (
                    session_store,
                    self._session_store(root / "session-token"),
                    "refresh-token",
                    b"session-ciphertext",
                    session_store.SessionStoreError,
                    "无法保存已加密的平台会话",
                ),
            )
            for module, store, token, encrypted, error_type, fixed_error in cases:
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    "_protect_data",
                    return_value=encrypted,
                ), mock.patch.object(
                    module,
                    "write_atomic_bytes",
                    side_effect=OSError("private-write-detail"),
                ), self.assertRaises(error_type) as raised:
                    store.save(token)
                self.assertEqual(str(raised.exception), fixed_error)
                self.assertNotIn("private-write-detail", str(raised.exception))

            session_path = root / "session-token"
            saved_session = self._session_store(session_path)
            for encrypted in (
                b"",
                b"x" * (session_store.MAX_SESSION_CIPHERTEXT_BYTES + 1),
            ):
                with self.subTest(store="session", size=len(encrypted)), mock.patch.object(
                    session_store,
                    "_protect_data",
                    return_value=encrypted,
                ), mock.patch.object(
                    session_store,
                    "write_atomic_bytes",
                ) as atomic_write, self.assertRaisesRegex(
                    session_store.SessionStoreError,
                    "^无法保存已加密的平台会话$",
                ):
                    saved_session.save("refresh-token")
                atomic_write.assert_not_called()

    def test_atomic_writer_uses_unique_same_directory_fsynced_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "ciphertext.bin"
            with mock.patch.object(
                external_json.os,
                "fsync",
                wraps=os.fsync,
            ) as fsync, mock.patch.object(
                external_json.os,
                "replace",
                wraps=os.replace,
            ) as replace:
                external_json.write_atomic_bytes(destination, b"first")
                external_json.write_atomic_bytes(destination, b"second")

            self.assertEqual(fsync.call_count, 2)
            self.assertEqual(replace.call_count, 2)
            sources = [Path(call.args[0]) for call in replace.call_args_list]
            destinations = [Path(call.args[1]) for call in replace.call_args_list]
            self.assertEqual(len(set(sources)), 2)
            self.assertTrue(all(path.parent == destination.parent for path in sources))
            self.assertEqual(destinations, [destination, destination])
            self.assertEqual(destination.read_bytes(), b"second")
            self.assertEqual(list(destination.parent.iterdir()), [destination])

    def test_atomic_replace_failure_preserves_old_file_and_cleans_temporary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ciphertext.bin"
            destination.write_bytes(b"old")
            with mock.patch.object(
                external_json.os,
                "replace",
                side_effect=OSError("replace-private-detail"),
            ), self.assertRaisesRegex(OSError, "replace-private-detail"):
                external_json.write_atomic_bytes(destination, b"new")
            self.assertEqual(destination.read_bytes(), b"old")
            self.assertEqual(list(root.iterdir()), [destination])

    def test_cleanup_failure_does_not_mask_atomic_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "ciphertext.bin"
            destination.write_bytes(b"old")
            with mock.patch.object(
                external_json.os,
                "replace",
                side_effect=OSError("replace-detail"),
            ), mock.patch.object(
                external_json.Path,
                "unlink",
                side_effect=PermissionError("cleanup-detail"),
            ), self.assertRaisesRegex(OSError, "replace-detail"):
                external_json.write_atomic_bytes(destination, b"new")

    @unittest.skipIf(os.name == "nt", "POSIX symlink support is required")
    def test_atomic_writer_replaces_leaf_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_bytes(b"do-not-touch")
            destination = root / "ciphertext.bin"
            destination.symlink_to(victim)

            external_json.write_atomic_bytes(destination, b"ciphertext")

            self.assertEqual(victim.read_bytes(), b"do-not-touch")
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_bytes(), b"ciphertext")

    def test_sources_have_no_exists_then_read_or_fixed_temporary_bypass(self) -> None:
        for module, class_marker in (
            (admin_oauth, "class AdminTokenStore:"),
            (session_store, "class WindowsDpapiSessionStore"),
        ):
            source = Path(module.__file__).read_text(encoding="utf-8")
            store_source = source.split(class_marker, 1)[1].split(
                "    def clear(self)", 1
            )[0]
            with self.subTest(module=module.__name__):
                self.assertNotIn(".exists(", store_source)
                self.assertNotIn(".read_bytes(", store_source)
                self.assertNotIn(".write_bytes(", store_source)
                self.assertNotIn("with_suffix(", store_source)
                self.assertIn("read_stable_bytes(", store_source)
                self.assertIn("write_atomic_bytes(", store_source)


if __name__ == "__main__":
    unittest.main()
