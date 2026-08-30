"""Versioned streaming encryption for database backup artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from scripts.external_json import has_link_or_reparse_ancestor, stable_file_identity
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import has_link_or_reparse_ancestor, stable_file_identity


MAGIC = b"EMLBKP01"
FORMAT_VERSION = 1
ALGORITHM = "AES-256-GCM"
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
CHUNK_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 4096
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_READ_CONTROL = 0x00020000
_SID = re.compile(r"^S-\d-(?:\d+-){1,14}\d+$")


class BackupCryptoError(ValueError):
    """An encrypted backup or its key did not satisfy the closed format."""


def _read_windows_acl(descriptor: int) -> dict[str, object]:
    script = r"""
$rawHandle = [Console]::In.ReadToEnd()
$safeHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new(
    [IntPtr]([Int64]::Parse($rawHandle)),
    $false
)
try {
    $flags = [Reflection.BindingFlags]'Instance,NonPublic'
    $types = [Type[]]@(
        [Microsoft.Win32.SafeHandles.SafeFileHandle],
        [String],
        [Security.AccessControl.AccessControlSections]
    )
    $constructor = [Security.AccessControl.FileSecurity].GetConstructor(
        $flags,
        $null,
        $types,
        $null
    )
    if ($null -eq $constructor) {
        throw 'Safe file ACL constructor is unavailable'
    }
    $sections = [Security.AccessControl.AccessControlSections]'Access,Owner,Group'
    $acl = $constructor.Invoke(@($safeHandle, 'C:\redacted\backup.key', $sections))
} finally {
    $safeHandle.Dispose()
}
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = $acl.GetSecurityDescriptorSddlForm($sections)
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [PSCustomObject]@{
        sid = $_.IdentityReference.Value
        type = $_.AccessControlType.ToString()
        rights = $_.FileSystemRights.ToString()
        inherited = $_.IsInherited
        inheritance_flags = $_.InheritanceFlags.ToString()
        propagation_flags = $_.PropagationFlags.ToString()
    }
})
[PSCustomObject]@{
    protected = $acl.AreAccessRulesProtected
    dacl_present = $sddl.Contains('D:') -and -not $sddl.Contains('NO_ACCESS_CONTROL')
    current = $current
    owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    sddl = $sddl
    rules = $rules
} | ConvertTo-Json -Compress -Depth 4
"""
    inherited_handle: int | None = None
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.DuplicateHandle.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.DuplicateHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        current_process = kernel32.GetCurrentProcess()
        duplicated_handle = wintypes.HANDLE()
        if not kernel32.DuplicateHandle(
            current_process,
            wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
            current_process,
            ctypes.byref(duplicated_handle),
            _WINDOWS_READ_CONTROL,
            True,
            0,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        inherited_handle = int(duplicated_handle.value)

        windows_directory_buffer = ctypes.create_unicode_buffer(32768)
        kernel32.GetWindowsDirectoryW.argtypes = (
            wintypes.LPWSTR,
            wintypes.UINT,
        )
        kernel32.GetWindowsDirectoryW.restype = wintypes.UINT
        windows_directory_length = kernel32.GetWindowsDirectoryW(
            windows_directory_buffer,
            len(windows_directory_buffer),
        )
        if (
            windows_directory_length == 0
            or windows_directory_length >= len(windows_directory_buffer)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        windows_directory = Path(windows_directory_buffer.value)
        powershell = (
            windows_directory
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.lpAttributeList = {"handle_list": [inherited_handle]}
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            input=str(inherited_handle),
            text=True,
            capture_output=True,
            check=True,
            close_fds=True,
            startupinfo=startupinfo,
            env={
                "SystemRoot": str(windows_directory),
                "WINDIR": str(windows_directory),
                "PATH": str(powershell.parent),
            },
            timeout=60,
        )
        acl = json.loads(result.stdout)
    except (
        ImportError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
        ValueError,
        AttributeError,
    ) as error:
        raise BackupCryptoError("cannot verify backup key file ACL") from error
    finally:
        if inherited_handle is not None:
            try:
                kernel32.CloseHandle(wintypes.HANDLE(inherited_handle))
            except (NameError, OSError):
                pass
    if not isinstance(acl, dict):
        raise BackupCryptoError("cannot verify backup key file ACL")
    return acl


def _validate_windows_acl(
    descriptor: int,
) -> tuple[str, str, str]:
    acl = _read_windows_acl(descriptor)
    if set(acl) != {
        "protected",
        "dacl_present",
        "current",
        "owner",
        "sddl",
        "rules",
    }:
        raise BackupCryptoError("cannot verify backup key file ACL")
    current = acl.get("current")
    owner = acl.get("owner")
    sddl = acl.get("sddl")
    if (
        not isinstance(current, str)
        or _SID.fullmatch(current) is None
        or not isinstance(owner, str)
        or _SID.fullmatch(owner) is None
        or not isinstance(sddl, str)
        or not sddl
        or "NO_ACCESS_CONTROL" in sddl
    ):
        raise BackupCryptoError("cannot verify backup key file ACL")
    allowed = {current, "S-1-5-18", "S-1-5-32-544"}
    rules = acl.get("rules")
    if isinstance(rules, dict):
        rules = [rules]
    if (
        acl.get("protected") is not True
        or acl.get("dacl_present") is not True
        or owner not in allowed
        or not isinstance(rules, list)
        or not rules
    ):
        raise BackupCryptoError("backup key file ACL must disable inheritance")
    if any(
        not isinstance(rule, dict)
        or set(rule)
        != {
            "sid",
            "type",
            "rights",
            "inherited",
            "inheritance_flags",
            "propagation_flags",
        }
        or rule.get("type") != "Allow"
        or rule.get("sid") not in allowed
        or rule.get("inherited") is not False
        or not isinstance(rule.get("rights"), str)
        or not isinstance(rule.get("inheritance_flags"), str)
        or not isinstance(rule.get("propagation_flags"), str)
        for rule in rules
    ):
        raise BackupCryptoError("backup key file ACL grants an unapproved principal")
    if not any(rule.get("sid") == current for rule in rules):
        raise BackupCryptoError("backup key file ACL excludes the current operator")
    return current, owner, sddl


def _validate_key_permissions(
    descriptor: int,
    metadata: os.stat_result,
    *,
    require_read_only: bool,
) -> object:
    if os.name == "nt":
        permission_identity: object = _validate_windows_acl(descriptor)
    elif stat.S_IMODE(metadata.st_mode) & 0o077:
        raise BackupCryptoError("backup key file permissions must be 0600 or stricter")
    else:
        permission_identity = stat.S_IMODE(metadata.st_mode)
    if not require_read_only:
        return permission_identity
    if os.name == "nt":
        readonly_flag = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
        if not getattr(metadata, "st_file_attributes", 0) & readonly_flag:
            raise BackupCryptoError("backup key file must be read-only")
    elif stat.S_IMODE(metadata.st_mode) & 0o222:
        raise BackupCryptoError("backup key file must be read-only")
    return permission_identity


def validate_private_file_permissions(
    descriptor: int,
    metadata: os.stat_result,
    *,
    require_read_only: bool = False,
) -> object:
    """Return a permission fingerprint for one already-open private file."""

    return _validate_key_permissions(
        descriptor,
        metadata,
        require_read_only=require_read_only,
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def load_key_file(
    key_file: Path | str,
    *,
    require_read_only: bool = False,
) -> bytes:
    path = Path(key_file)
    if not path.is_absolute():
        raise BackupCryptoError("backup key file path must be absolute")
    if has_link_or_reparse_ancestor(path):
        raise BackupCryptoError("backup key file cannot be opened safely")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BackupCryptoError("backup key file cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupCryptoError("backup key file must be a regular file")
        path_metadata = path.lstat()
        if (
            stat.S_ISLNK(path_metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
            or bool(
                getattr(path_metadata, "st_file_attributes", 0) & _REPARSE_POINT
            )
            or not _same_file(metadata, path_metadata)
            or stable_file_identity(metadata) != stable_file_identity(path_metadata)
        ):
            raise BackupCryptoError("backup key file changed during secure open")
        if metadata.st_nlink != 1:
            raise BackupCryptoError("backup key file must have exactly one link")
        permission_identity = _validate_key_permissions(
            descriptor,
            metadata,
            require_read_only=require_read_only,
        )
        chunks: list[bytes] = []
        remaining = KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        final_path_metadata = path.lstat()
        final_permission_identity = _validate_key_permissions(
            descriptor,
            final_metadata,
            require_read_only=require_read_only,
        )
        if (
            has_link_or_reparse_ancestor(path)
            or stat.S_ISLNK(final_path_metadata.st_mode)
            or bool(
                getattr(final_metadata, "st_file_attributes", 0) & _REPARSE_POINT
            )
            or bool(
                getattr(final_path_metadata, "st_file_attributes", 0)
                & _REPARSE_POINT
            )
            or not _same_file(metadata, final_path_metadata)
            or stable_file_identity(final_metadata) != stable_file_identity(metadata)
            or stable_file_identity(final_path_metadata) != stable_file_identity(metadata)
        ):
            raise BackupCryptoError("backup key file changed while being read")
        if final_permission_identity != permission_identity:
            raise BackupCryptoError("backup key file permissions changed while being read")
    except OSError as error:
        raise BackupCryptoError("backup key file cannot be read safely") from error
    finally:
        os.close(descriptor)
    if len(key) != KEY_BYTES:
        raise BackupCryptoError("backup key file must contain exactly 32 raw bytes")
    return key


def key_id(key: bytes) -> str:
    if len(key) != KEY_BYTES:
        raise BackupCryptoError("AES-256-GCM requires a 32-byte key")
    return hashlib.sha256(key).hexdigest()[:16]


def _header_bytes(
    key: bytes,
    nonce: bytes,
    *,
    logical_name: str,
    source_database: str,
) -> tuple[bytes, dict[str, object]]:
    header = {
        "algorithm": ALGORITHM,
        "format_version": FORMAT_VERSION,
        "key_id": key_id(key),
        "logical_name": logical_name,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "source_database": source_database,
    }
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return MAGIC + struct.pack(">I", len(encoded)) + encoded, header


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    key: bytes,
    *,
    logical_name: str,
    source_database: str,
) -> dict[str, object]:
    nonce = os.urandom(NONCE_BYTES)
    prefix, header = _header_bytes(
        key,
        nonce,
        logical_name=logical_name,
        source_database=source_database,
    )
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    destination.write(prefix)
    while True:
        chunk = source.read(CHUNK_BYTES)
        if not chunk:
            break
        destination.write(encryptor.update(chunk))
    destination.write(encryptor.finalize())
    destination.write(encryptor.tag)
    return header


def _read_header(
    source: BinaryIO,
    key: bytes,
    total_size: int,
    *,
    expected_logical_name: str,
    expected_source_database: str,
) -> tuple[bytes, bytes, int]:
    fixed = source.read(len(MAGIC) + 4)
    if len(fixed) != len(MAGIC) + 4 or fixed[: len(MAGIC)] != MAGIC:
        raise BackupCryptoError("backup artifact is not an encrypted envelope")
    header_size = struct.unpack(">I", fixed[len(MAGIC) :])[0]
    if header_size <= 0 or header_size > MAX_HEADER_BYTES:
        raise BackupCryptoError("encrypted backup header length is invalid")
    encoded = source.read(header_size)
    if len(encoded) != header_size:
        raise BackupCryptoError("encrypted backup header is truncated")
    try:
        header = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackupCryptoError("encrypted backup header is invalid") from error
    expected_fields = {
        "algorithm",
        "format_version",
        "key_id",
        "logical_name",
        "nonce",
        "source_database",
    }
    if not isinstance(header, dict) or set(header) != expected_fields:
        raise BackupCryptoError("encrypted backup header fields are invalid")
    if header.get("algorithm") != ALGORITHM or header.get("format_version") != FORMAT_VERSION:
        raise BackupCryptoError("encrypted backup format is unsupported")
    if header.get("key_id") != key_id(key):
        raise BackupCryptoError("backup encryption key does not match key_id")
    if (
        header.get("logical_name") != expected_logical_name
        or header.get("source_database") != expected_source_database
    ):
        raise BackupCryptoError("encrypted backup database identity does not match")
    try:
        nonce = base64.b64decode(header.get("nonce"), validate=True)
    except (TypeError, ValueError) as error:
        raise BackupCryptoError("encrypted backup nonce is invalid") from error
    if len(nonce) != NONCE_BYTES:
        raise BackupCryptoError("encrypted backup nonce is invalid")
    prefix = fixed + encoded
    ciphertext_size = total_size - len(prefix) - TAG_BYTES
    if ciphertext_size <= 0:
        raise BackupCryptoError("encrypted backup payload is truncated")
    return prefix, nonce, ciphertext_size


def decrypt_stream(
    source: BinaryIO,
    destination: BinaryIO | None,
    key: bytes,
    total_size: int,
    *,
    expected_logical_name: str,
    expected_source_database: str,
) -> None:
    prefix, nonce, ciphertext_size = _read_header(
        source,
        key,
        total_size,
        expected_logical_name=expected_logical_name,
        expected_source_database=expected_source_database,
    )
    source.seek(total_size - TAG_BYTES)
    tag = source.read(TAG_BYTES)
    if len(tag) != TAG_BYTES:
        raise BackupCryptoError("encrypted backup authentication tag is truncated")
    source.seek(len(prefix))
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(prefix)
    remaining = ciphertext_size
    try:
        while remaining:
            chunk = source.read(min(CHUNK_BYTES, remaining))
            if not chunk:
                raise BackupCryptoError("encrypted backup payload is truncated")
            remaining -= len(chunk)
            plaintext = decryptor.update(chunk)
            if destination is not None:
                destination.write(plaintext)
        plaintext = decryptor.finalize()
        if destination is not None:
            destination.write(plaintext)
    except InvalidTag as error:
        raise BackupCryptoError("encrypted backup authentication failed") from error


def authenticate_file(
    path: Path | str,
    key: bytes,
    *,
    expected_logical_name: str,
    expected_source_database: str,
) -> None:
    artifact = Path(path)
    try:
        size = artifact.stat().st_size
        with artifact.open("rb") as source:
            decrypt_stream(
                source,
                None,
                key,
                size,
                expected_logical_name=expected_logical_name,
                expected_source_database=expected_source_database,
            )
    except OSError as error:
        raise BackupCryptoError("encrypted backup artifact cannot be read") from error


def decrypt_file_to_stream(
    path: Path | str,
    destination: BinaryIO,
    key: bytes,
    *,
    expected_logical_name: str,
    expected_source_database: str,
) -> None:
    artifact = Path(path)
    try:
        size = artifact.stat().st_size
        with artifact.open("rb") as source:
            decrypt_stream(
                source,
                destination,
                key,
                size,
                expected_logical_name=expected_logical_name,
                expected_source_database=expected_source_database,
            )
    except OSError as error:
        raise BackupCryptoError("encrypted backup artifact cannot be read") from error
