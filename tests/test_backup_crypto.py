import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import backup_crypto


KEY = b"A" * 32
OTHER_KEY = b"B" * 32
PLAINTEXT = b"pg-dump-secret-sentinel" * 200


def _encrypt(
    plaintext: bytes = PLAINTEXT,
    *,
    key: bytes = KEY,
    logical_name: str = "platform",
    source_database: str = "email_platform",
) -> bytes:
    destination = io.BytesIO()
    backup_crypto.encrypt_stream(
        io.BytesIO(plaintext),
        destination,
        key,
        logical_name=logical_name,
        source_database=source_database,
    )
    return destination.getvalue()


def _decrypt(envelope: bytes, *, key: bytes = KEY) -> bytes:
    destination = io.BytesIO()
    backup_crypto.decrypt_stream(
        io.BytesIO(envelope),
        destination,
        key,
        len(envelope),
        expected_logical_name="platform",
        expected_source_database="email_platform",
    )
    return destination.getvalue()


class BackupCryptoTests(unittest.TestCase):
    def test_streaming_round_trip_hides_plaintext_and_authenticates_identity(self) -> None:
        envelope = _encrypt()
        self.assertNotIn(b"pg-dump-secret-sentinel", envelope)
        self.assertEqual(_decrypt(envelope), PLAINTEXT)
        with self.assertRaisesRegex(
            backup_crypto.BackupCryptoError,
            "database identity",
        ):
            backup_crypto.decrypt_stream(
                io.BytesIO(envelope),
                None,
                KEY,
                len(envelope),
                expected_logical_name="keycloak",
                expected_source_database="email_platform",
            )

    def test_wrong_key_nonce_tag_and_truncation_are_rejected(self) -> None:
        envelope = _encrypt()
        with self.assertRaises(backup_crypto.BackupCryptoError):
            _decrypt(envelope, key=OTHER_KEY)

        header_length = struct.unpack(
            ">I", envelope[len(backup_crypto.MAGIC) : len(backup_crypto.MAGIC) + 4]
        )[0]
        header_start = len(backup_crypto.MAGIC) + 4
        header_end = header_start + header_length
        header = json.loads(envelope[header_start:header_end])
        nonce = bytearray(__import__("base64").b64decode(header["nonce"]))
        nonce[0] ^= 1
        header["nonce"] = __import__("base64").b64encode(nonce).decode("ascii")
        encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(len(encoded), header_length)
        bad_nonce = envelope[:header_start] + encoded + envelope[header_end:]
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "authentication"):
            _decrypt(bad_nonce)

        bad_tag = bytearray(envelope)
        bad_tag[-1] ^= 1
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "authentication"):
            _decrypt(bytes(bad_tag))
        with self.assertRaises(backup_crypto.BackupCryptoError):
            _decrypt(envelope[:-20])

    def test_mixed_valid_ciphertext_is_rejected_by_aad_identity(self) -> None:
        keycloak = _encrypt(
            logical_name="keycloak",
            source_database="keycloak",
        )
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "database identity"):
            backup_crypto.decrypt_stream(
                io.BytesIO(keycloak),
                None,
                KEY,
                len(keycloak),
                expected_logical_name="platform",
                expected_source_database="keycloak",
            )
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "encrypted envelope"):
            _decrypt(b"PGDMP-plaintext" + _encrypt())
        envelope = _encrypt()
        mixed = envelope[:-backup_crypto.TAG_BYTES] + b"plaintext" + envelope[-backup_crypto.TAG_BYTES:]
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "authentication"):
            _decrypt(mixed)

    def test_key_file_rejects_relative_non_regular_wrong_size_and_symlink(self) -> None:
        with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "absolute"):
            backup_crypto.load_key_file("relative.key")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong_size = root / "wrong.key"
            wrong_size.write_bytes(b"short")
            with mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "32 raw bytes"):
                    backup_crypto.load_key_file(wrong_size)
            with mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with self.assertRaisesRegex(
                    backup_crypto.BackupCryptoError,
                    "regular file|opened safely",
                ):
                    backup_crypto.load_key_file(root)
            target = root / "target.key"
            target.write_bytes(KEY)
            actual = target.lstat()
            symlink_metadata = mock.Mock(
                st_mode=stat.S_IFLNK | 0o777,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
            )
            with mock.patch.object(
                backup_crypto,
                "has_link_or_reparse_ancestor",
                return_value=False,
            ), mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with mock.patch.object(Path, "lstat", return_value=symlink_metadata):
                    with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "changed"):
                        backup_crypto.load_key_file(target)

    def test_key_file_permissions_and_replace_race_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.key"
            path.write_bytes(KEY)
            with mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                side_effect=backup_crypto.BackupCryptoError("permissions"),
            ):
                with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "permissions"):
                    backup_crypto.load_key_file(path)

            actual = path.lstat()
            replaced = mock.Mock(
                st_mode=actual.st_mode,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino + 1,
                st_file_attributes=0,
            )
            with mock.patch.object(
                backup_crypto,
                "has_link_or_reparse_ancestor",
                return_value=False,
            ), mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with mock.patch.object(Path, "lstat", side_effect=[actual, replaced]):
                    with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "changed"):
                        backup_crypto.load_key_file(path)

    def test_key_file_rejects_hard_link_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "backup.key"
            linked = root / "linked.key"
            original.write_bytes(KEY)
            os.link(original, linked)
            with mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with self.assertRaisesRegex(
                    backup_crypto.BackupCryptoError,
                    "exactly one link",
                ):
                    backup_crypto.load_key_file(linked.resolve())

    def test_key_file_rejects_same_inode_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "backup.key").resolve()
            path.write_bytes(KEY)
            actual = path.lstat()
            changed = mock.Mock(
                st_mode=actual.st_mode ^ stat.S_IWUSR,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
                st_nlink=actual.st_nlink,
                st_size=actual.st_size,
                st_mtime_ns=actual.st_mtime_ns,
                st_file_attributes=0,
            )
            with mock.patch.object(
                backup_crypto,
                "has_link_or_reparse_ancestor",
                return_value=False,
            ), mock.patch.object(backup_crypto, "_validate_key_permissions"):
                with mock.patch.object(Path, "lstat", side_effect=[actual, changed]):
                    with self.assertRaisesRegex(
                        backup_crypto.BackupCryptoError,
                        "changed",
                    ):
                        backup_crypto.load_key_file(path)

    def test_key_file_rejects_reparse_boundary_before_open(self) -> None:
        path = Path("C:/external/key.bin")
        with mock.patch.object(
            backup_crypto,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(backup_crypto.os, "open") as open_file:
            with self.assertRaisesRegex(
                backup_crypto.BackupCryptoError,
                "cannot be opened safely",
            ):
                backup_crypto.load_key_file(path)
        open_file.assert_not_called()

    def test_key_file_rejects_non_symlink_reparse_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "backup.key").resolve()
            path.write_bytes(KEY)
            actual = path.lstat()
            reparse = mock.Mock(
                st_mode=actual.st_mode,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
                st_nlink=actual.st_nlink,
                st_size=actual.st_size,
                st_mtime_ns=actual.st_mtime_ns,
                st_file_attributes=getattr(
                    stat,
                    "FILE_ATTRIBUTE_REPARSE_POINT",
                    0x400,
                ),
            )
            with mock.patch.object(
                backup_crypto,
                "has_link_or_reparse_ancestor",
                return_value=False,
            ), mock.patch.object(Path, "lstat", return_value=reparse):
                with self.assertRaisesRegex(
                    backup_crypto.BackupCryptoError,
                    "changed during secure open",
                ):
                    backup_crypto.load_key_file(path)

    def test_key_file_rejects_permission_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "backup.key").resolve()
            path.write_bytes(KEY)
            with mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                side_effect=[("acl-a",), ("acl-b",)],
            ):
                with self.assertRaisesRegex(
                    backup_crypto.BackupCryptoError,
                    "permissions changed",
                ):
                    backup_crypto.load_key_file(path)

    def test_windows_acl_rejects_inheritance_and_broad_principals(self) -> None:
        current = "S-1-5-21-1000"
        current_rule = {
            "sid": current,
            "type": "Allow",
            "rights": "FullControl",
            "inherited": False,
            "inheritance_flags": "None",
            "propagation_flags": "None",
        }
        inherited = {
            "protected": False,
            "dacl_present": True,
            "current": current,
            "owner": current,
            "sddl": f"O:{current}G:SYD:(A;;FA;;;{current})",
            "rules": current_rule,
        }
        broad = {
            "protected": True,
            "dacl_present": True,
            "current": current,
            "owner": current,
            "sddl": f"O:{current}G:SYD:P(A;;FA;;;WD)",
            "rules": {**current_rule, "sid": "S-1-1-0"},
        }
        for acl, message in ((inherited, "disable inheritance"), (broad, "unapproved")):
            with mock.patch.object(backup_crypto, "_read_windows_acl", return_value=acl):
                with self.assertRaisesRegex(backup_crypto.BackupCryptoError, message):
                    backup_crypto._validate_windows_acl(123)

    @unittest.skipUnless(os.name == "nt", "inherited handle lists are Windows-only")
    def test_windows_acl_is_bound_to_an_inherited_open_file_handle(self) -> None:
        current = "S-1-5-21-1000"
        acl = {
            "protected": True,
            "dacl_present": True,
            "current": current,
            "owner": current,
            "sddl": f"O:{current}G:SYD:P(A;;FA;;;{current})",
            "rules": {
                "sid": current,
                "type": "Allow",
                "rights": "FullControl",
                "inherited": False,
                "inheritance_flags": "None",
                "propagation_flags": "None",
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.key"
            path.write_bytes(KEY)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                completed = mock.Mock(stdout=json.dumps(acl))
                with mock.patch.object(
                    backup_crypto.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
                    backup_crypto._read_windows_acl(descriptor)
            finally:
                os.close(descriptor)

        command = run.call_args.args[0]
        options = run.call_args.kwargs
        startupinfo = options.get("startupinfo")
        self.assertIsNotNone(startupinfo)
        inherited = startupinfo.lpAttributeList.get("handle_list")
        self.assertEqual(inherited, [int(options["input"])])
        self.assertIn("SafeFileHandle", command[-1])
        self.assertNotIn("FileStream", command[-1])
        self.assertNotIn("Get-Acl -LiteralPath", command[-1])
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertEqual(set(options["env"]), {"SystemRoot", "WINDIR", "PATH"})

    @unittest.skipUnless(os.name == "nt", "Windows ACL smoke test")
    def test_windows_protected_acl_loads_through_the_real_handle_path(self) -> None:
        configure_acl = r"""
$path = [Console]::In.ReadToEnd()
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($current.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
}
[IO.File]::SetAccessControl($path, $acl)
"""
        powershell = (
            Path(os.environ["SystemRoot"])
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "backup.key").resolve()
            path.write_bytes(KEY)
            subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    configure_acl,
                ],
                input=str(path),
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(backup_crypto.load_key_file(path), KEY)

    def test_windows_acl_rejects_malformed_identity_and_empty_dacl(self) -> None:
        malformed = (
            {
                "protected": True,
                "dacl_present": False,
                "current": None,
                "owner": "S-1-5-18",
                "sddl": "O:SYG:SYD:P",
                "rules": [],
            },
            {
                "protected": True,
                "dacl_present": True,
                "current": "not-a-sid",
                "owner": "S-1-5-18",
                "sddl": "O:SYG:SYD:P",
                "rules": [],
            },
            {
                "protected": True,
                "dacl_present": True,
                "current": "S-1-5-21-1000",
                "owner": "S-1-5-21-1000",
                "sddl": "O:S-1-5-21-1000G:SYD:P",
                "rules": [],
            },
            {
                "protected": True,
                "dacl_present": False,
                "current": "S-1-5-21-1000",
                "owner": "S-1-5-21-1000",
                "sddl": "O:S-1-5-21-1000G:SYD:NO_ACCESS_CONTROL",
                "rules": [
                    {
                        "sid": "S-1-5-21-1000",
                        "type": "Allow",
                        "rights": "FullControl",
                        "inherited": False,
                        "inheritance_flags": "None",
                        "propagation_flags": "None",
                    }
                ],
            },
        )
        for acl in malformed:
            with self.subTest(acl=acl), mock.patch.object(
                backup_crypto,
                "_read_windows_acl",
                return_value=acl,
            ):
                with self.assertRaises(backup_crypto.BackupCryptoError):
                    backup_crypto._validate_windows_acl(123)

    @unittest.skipUnless(os.name == "nt", "Windows ACL drift test")
    def test_windows_acl_broadening_during_key_read_fails_closed(self) -> None:
        current = "S-1-5-21-1000"
        safe_rule = {
            "sid": current,
            "type": "Allow",
            "rights": "FullControl",
            "inherited": False,
            "inheritance_flags": "None",
            "propagation_flags": "None",
        }
        safe = {
            "protected": True,
            "dacl_present": True,
            "current": current,
            "owner": current,
            "sddl": f"O:{current}G:SYD:P(A;;FA;;;{current})",
            "rules": safe_rule,
        }
        broad = {
            **safe,
            "sddl": f"O:{current}G:SYD:P(A;;FA;;;WD)",
            "rules": {**safe_rule, "sid": "S-1-1-0"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "backup.key").resolve()
            path.write_bytes(KEY)
            with mock.patch.object(
                backup_crypto,
                "_read_windows_acl",
                side_effect=[safe, broad],
            ):
                with self.assertRaisesRegex(
                    backup_crypto.BackupCryptoError,
                    "unapproved principal",
                ):
                    backup_crypto.load_key_file(path)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not authoritative on Windows")
    def test_posix_key_file_rejects_group_or_world_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.key"
            path.write_bytes(KEY)
            path.chmod(0o644)
            with self.assertRaisesRegex(backup_crypto.BackupCryptoError, "0600"):
                backup_crypto.load_key_file(path)

    def test_key_id_is_only_a_non_secret_fingerprint(self) -> None:
        identifier = backup_crypto.key_id(KEY)
        self.assertEqual(len(identifier), 16)
        self.assertNotIn(KEY.decode("ascii"), identifier)


if __name__ == "__main__":
    unittest.main()
