from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

from scripts import private_secret_materialization as materialization
from scripts.private_secret_file import read_private_secret_bytes


RAW = b"apiVersion: v1\nkind: Config\n"
DIGEST = hashlib.sha256(RAW).hexdigest()


class PrivateSecretMaterializationTests(unittest.TestCase):
    def test_digest_and_input_are_closed_before_materialization(self) -> None:
        for raw, digest in (
            (b"", hashlib.sha256(b"").hexdigest()),
            (bytearray(RAW), DIGEST),
            (RAW, "f" * 64),
            (RAW, "not-a-digest"),
        ):
            with self.subTest(raw=type(raw).__name__, digest=digest), self.assertRaisesRegex(
                materialization.PrivateSecretMaterializationError,
                "^private secret materialization failed$",
            ):
                materialization.materialize_private_secret_bytes(raw, digest)

    def test_context_manager_verifies_and_closes_idempotently(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        path = value.path
        self.assertTrue(path.is_absolute())
        self.assertEqual(value.source_sha256, DIGEST)
        with self.assertRaises(AttributeError):
            value.path = Path("C:/replacement")
        with value as opened:
            self.assertIs(opened, value)
            self.assertEqual(path.read_bytes(), RAW)
            opened.verify()
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())
        value.close()
        with self.assertRaises(materialization.PrivateSecretMaterializationError):
            value.verify()

    def test_materialization_publishes_one_sealed_claim_and_lease(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        directory = value.path.parent
        runtime_root = directory.parent
        try:
            self.assertRegex(directory.name, r"^[0-9a-f]{32}$")
            self.assertEqual(
                {entry.name for entry in directory.iterdir()},
                {"secret", "claim.json", "lease"},
            )
            claim_raw = (directory / "claim.json").read_bytes()
            self.assertLessEqual(len(claim_raw), materialization._CLAIM_MAX_BYTES)
            claim = json.loads(claim_raw)
            self.assertEqual(claim["claim_id"], directory.name)
            self.assertEqual(claim["secret"]["source_sha256"], DIGEST)
            self.assertEqual((directory / "lease").stat().st_size, 0)
        finally:
            value.close()
        self.assertFalse(directory.exists())
        self.assertTrue(runtime_root.exists())

    def test_extra_child_blocks_normal_cleanup_before_any_unlink(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        directory = value.path.parent
        extra = directory / "operator-owned"
        extra.write_bytes(b"preserve")
        before = {entry.name: entry.read_bytes() for entry in directory.iterdir()}
        with self.assertRaises(materialization.PrivateSecretMaterializationError):
            value.verify()
        with self.assertRaises(materialization.PrivateSecretMaterializationError):
            value.close()
        self.assertEqual(before, {entry.name: entry.read_bytes() for entry in directory.iterdir()})
        for entry in directory.iterdir():
            entry.chmod(stat.S_IWRITE | stat.S_IREAD)
            entry.unlink()
        directory.rmdir()

    def test_error_messages_do_not_disclose_paths_or_bytes(self) -> None:
        marker = "TOP-SECRET-MARKER"
        with self.assertRaises(materialization.PrivateSecretMaterializationError) as raised:
            materialization.materialize_private_secret_bytes(
                marker.encode(), "0" * 64
            )
        self.assertEqual(str(raised.exception), "private secret materialization failed")
        self.assertNotIn(marker, str(raised.exception))

    def test_runtime_root_dot_segments_cannot_alias_back_into_repository(self) -> None:
        repository = Path(materialization.__file__).resolve().parents[1]
        aliased_root = repository / "scripts" / ".." / "private-runtime"
        with mock.patch.dict(
            os.environ,
            {materialization._RUNTIME_ROOT_ENV: str(aliased_root)},
        ), self.assertRaisesRegex(
            materialization.PrivateSecretMaterializationError,
            "^private secret materialization failed$",
        ):
            materialization.materialize_private_secret_bytes(RAW, DIGEST)
        self.assertFalse((repository / "private-runtime").exists())

    def test_cleanup_failure_does_not_mask_the_active_exception(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        real_close = value.close
        try:
            with mock.patch.object(
                value,
                "close",
                side_effect=materialization.PrivateSecretMaterializationError(
                    "private secret materialization failed"
                ),
            ), self.assertRaisesRegex(RuntimeError, "^PRIMARY$") as raised:
                with value:
                    raise RuntimeError("PRIMARY")
            self.assertIn(
                "private secret cleanup was not confirmed",
                getattr(raised.exception, "__notes__", []),
            )
        finally:
            real_close()

    def test_post_factory_verify_failure_closes_without_masking_primary(self) -> None:
        result = mock.Mock(spec=materialization.MaterializedPrivateSecret)
        primary = materialization.PrivateSecretMaterializationError(
            "private secret materialization failed"
        )
        result.verify.side_effect = primary
        result.close.side_effect = RuntimeError("cleanup detail")
        factory = "_materialize_windows" if os.name == "nt" else "_materialize_posix"
        with mock.patch.object(materialization, factory, return_value=result), self.assertRaises(
            materialization.PrivateSecretMaterializationError
        ) as raised:
            materialization.materialize_private_secret_bytes(RAW, DIGEST)
        self.assertIs(raised.exception, primary)
        result.close.assert_called_once_with()
        self.assertEqual(
            getattr(raised.exception, "__notes__", []),
            ["private secret cleanup was not confirmed"],
        )

    def test_source_contains_no_post_creation_acl_hardening(self) -> None:
        source = Path(materialization.__file__).read_text(encoding="utf-8")
        for forbidden in ("Set-Acl", "SetNamedSecurityInfo", "SetFileSecurity"):
            self.assertNotIn(forbidden, source)
        if os.name == "nt":
            self.assertIn("ConvertStringSecurityDescriptorToSecurityDescriptorW", source)
            self.assertIn("CreateDirectoryW", source)
            self.assertIn("_CREATE_NEW", source)


@unittest.skipUnless(os.name == "nt", "Windows private materialization tests")
class WindowsPrivateSecretMaterializationTests(unittest.TestCase):
    def test_security_attributes_are_final_and_handles_are_non_inheritable(self) -> None:
        sid = materialization._current_windows_sid()
        attributes, descriptor = materialization._security_attributes(sid)
        try:
            self.assertTrue(attributes.lpSecurityDescriptor)
            self.assertFalse(attributes.bInheritHandle)
        finally:
            materialization._KERNEL32.LocalFree(
                materialization.wintypes.HLOCAL(descriptor)
            )

    def test_windows_write_loop_handles_partial_and_zero_progress(self) -> None:
        calls = 0

        def partial(handle, buffer, size, written, overlapped):
            nonlocal calls
            calls += 1
            materialization.ctypes.cast(
                written,
                materialization.ctypes.POINTER(materialization.wintypes.DWORD),
            ).contents.value = max(1, size // 2)
            return True

        with mock.patch.object(materialization._KERNEL32, "WriteFile", side_effect=partial):
            materialization._write_all_windows(123, RAW)
        self.assertGreater(calls, 1)

        def zero(handle, buffer, size, written, overlapped):
            materialization.ctypes.cast(
                written,
                materialization.ctypes.POINTER(materialization.wintypes.DWORD),
            ).contents.value = 0
            return True

        with mock.patch.object(
            materialization._KERNEL32, "WriteFile", side_effect=zero
        ), self.assertRaisesRegex(
            materialization.PrivateSecretMaterializationError,
            "^private secret materialization failed$",
        ):
            materialization._write_all_windows(123, RAW)

    def test_real_windows_acl_readonly_identity_and_delete_share(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        path = value.path
        try:
            value.verify()
            metadata = os.stat(path)
            readonly = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
            self.assertTrue(metadata.st_file_attributes & readonly)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(path.read_bytes(), RAW)
            self.assertEqual(
                read_private_secret_bytes(
                    path,
                    max_bytes=1024,
                    require_read_only=True,
                ),
                RAW,
            )
            with self.assertRaises(PermissionError):
                path.unlink()
        finally:
            value.close()
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())

    def test_partial_factory_failure_removes_claimed_directory(self) -> None:
        token = "f" * 32
        root = materialization._windows_runtime_root(
            materialization._current_windows_sid()
        )
        path = root / token
        with mock.patch.object(materialization.secrets, "token_hex", return_value=token), mock.patch.object(
            materialization, "_write_all_windows", side_effect=OSError("private detail")
        ), self.assertRaisesRegex(
            materialization.PrivateSecretMaterializationError,
            "^private secret materialization failed$",
        ):
            materialization.materialize_private_secret_bytes(RAW, DIGEST)
        self.assertFalse(path.exists())

    def test_claimed_paths_are_random_and_create_new(self) -> None:
        first = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        second = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        try:
            self.assertNotEqual(first.path.parent, second.path.parent)
            first.verify()
            second.verify()
        finally:
            first.close()
            second.close()

    def test_directory_name_collision_never_reuses_or_deletes_existing(self) -> None:
        token = "e" * 32
        with mock.patch.object(materialization.secrets, "token_hex", return_value=token):
            first = materialization.materialize_private_secret_bytes(RAW, DIGEST)
            try:
                with self.assertRaisesRegex(
                    materialization.PrivateSecretMaterializationError,
                    "^private secret materialization failed$",
                ):
                    materialization.materialize_private_secret_bytes(RAW, DIGEST)
                first.verify()
                self.assertEqual(first.path.read_bytes(), RAW)
            finally:
                first.close()

    def test_close_authenticates_all_delete_handles_before_first_mutation(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        directory = value.path.parent
        before = {entry.name: entry.read_bytes() for entry in directory.iterdir()}
        real_open = materialization._open_verified_windows_delete_handle
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise materialization.PrivateSecretMaterializationError()
            return real_open(*args, **kwargs)

        with mock.patch.object(
            materialization,
            "_open_verified_windows_delete_handle",
            side_effect=fail_second,
        ), mock.patch.object(
            materialization,
            "_mark_windows_delete",
            wraps=materialization._mark_windows_delete,
        ) as mark, self.assertRaises(materialization.PrivateSecretMaterializationError):
            value.close()
        mark.assert_not_called()
        self.assertEqual(
            before, {entry.name: entry.read_bytes() for entry in directory.iterdir()}
        )
        records = __import__(
            "scripts.private_secret_residue", fromlist=["inventory_private_secret_residues"]
        ).inventory_private_secret_residues(directory.parent)
        record = next(item for item in records if item.get("claim_id") == directory.name)
        __import__(
            "scripts.private_secret_residue", fromlist=["_cleanup_private_secret_residue"]
        )._cleanup_private_secret_residue(
            directory.name, record["approval_sha256"], directory.parent
        )

    def test_closehandle_failure_cannot_report_cleanup_success(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        directory = value.path.parent
        state = value._state
        self.assertIsInstance(state, materialization._WindowsState)
        assert isinstance(state, materialization._WindowsState)
        target = state.file_handle
        real_close = materialization._close_handle
        failed = False

        def close_but_report_failure(handle):
            nonlocal failed
            result = real_close(handle)
            if handle == target and not failed:
                failed = True
                return False
            return result

        with mock.patch.object(
            materialization, "_close_handle", side_effect=close_but_report_failure
        ), self.assertRaises(materialization.PrivateSecretMaterializationError):
            value.close()
        self.assertTrue(directory.exists())
        residue = __import__("scripts.private_secret_residue", fromlist=["x"])
        record = next(
            item
            for item in residue.inventory_private_secret_residues(directory.parent)
            if item.get("claim_id") == directory.name
        )
        residue._cleanup_private_secret_residue(
            directory.name, record["approval_sha256"], directory.parent
        )


@unittest.skipIf(os.name == "nt", "POSIX private materialization tests")
class PosixPrivateSecretMaterializationTests(unittest.TestCase):
    def test_real_posix_modes_identity_and_cleanup(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        path = value.path
        try:
            value.verify()
            self.assertEqual(stat.S_IMODE(os.stat(path.parent).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o400)
            self.assertEqual(os.stat(path).st_nlink, 1)
            self.assertEqual(path.read_bytes(), RAW)
        finally:
            value.close()
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())

    def test_cleanup_fsyncs_claim_directory_before_runtime_root(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        state = value._state
        self.assertIsInstance(state, materialization._PosixState)
        assert isinstance(state, materialization._PosixState)
        with mock.patch.object(
            materialization.os, "fsync", wraps=os.fsync
        ) as fsync:
            value.close()
        calls = [call.args[0] for call in fsync.call_args_list]
        self.assertIn(state.directory_fd, calls)
        self.assertIn(state.root_fd, calls)
        self.assertLess(calls.index(state.directory_fd), calls.index(state.root_fd))

    def test_partial_write_loop_and_factory_cleanup(self) -> None:
        real_write = os.write
        calls = 0

        def partial(descriptor, value):
            nonlocal calls
            calls += 1
            return real_write(descriptor, bytes(value[: max(1, len(value) // 2)]))

        with mock.patch.object(materialization.os, "write", side_effect=partial):
            value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        try:
            self.assertGreater(calls, 1)
            value.verify()
        finally:
            value.close()

    def test_path_replacement_is_detected_and_not_deleted(self) -> None:
        value = materialization.materialize_private_secret_bytes(RAW, DIGEST)
        path = value.path
        path.unlink()
        path.write_bytes(b"replacement")
        path.chmod(0o400)
        try:
            with self.assertRaises(materialization.PrivateSecretMaterializationError):
                value.verify()
            with self.assertRaises(materialization.PrivateSecretMaterializationError):
                value.close()
            self.assertEqual(path.read_bytes(), b"replacement")
        finally:
            if path.exists():
                path.chmod(0o600)
                path.unlink()
            if path.parent.exists():
                for name in ("claim.json", "lease"):
                    candidate = path.parent / name
                    if candidate.exists():
                        candidate.chmod(0o600)
                        candidate.unlink()
                path.parent.rmdir()


if __name__ == "__main__":
    unittest.main()
