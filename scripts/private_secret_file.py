"""Stable, permission-bound reads for strict standalone secret files."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from scripts import backup_crypto
    from scripts.external_json import (
        StableFileError,
        open_stable_binary,
        stable_file_identity,
    )
except (ImportError, ModuleNotFoundError):  # Direct script loading from scripts/.
    import backup_crypto  # type: ignore[no-redef]
    from external_json import (  # type: ignore[no-redef]
        StableFileError,
        open_stable_binary,
        stable_file_identity,
    )


class PrivateSecretFileError(OSError):
    """A standalone secret file could not be authenticated and read safely."""


def read_private_secret_bytes(
    path_value: Path | str,
    *,
    max_bytes: int,
    allow_empty: bool = False,
    require_read_only: bool = False,
) -> bytes:
    path = Path(path_value)
    if not path.is_absolute() or max_bytes < 1:
        raise PrivateSecretFileError("private secret file is invalid")
    try:
        with open_stable_binary(path) as (stream, opened):
            if opened.st_nlink != 1:
                raise PrivateSecretFileError("private secret file is invalid")
            permission_identity = backup_crypto.validate_private_file_permissions(
                stream.fileno(),
                opened,
                require_read_only=require_read_only,
            )
            raw = stream.read(max_bytes + 1)
            final_opened = os.fstat(stream.fileno())
            final_permission_identity = backup_crypto.validate_private_file_permissions(
                stream.fileno(),
                final_opened,
                require_read_only=require_read_only,
            )
            if (
                len(raw) != opened.st_size
                or len(raw) > max_bytes
                or (not raw and not allow_empty)
                or stable_file_identity(final_opened) != stable_file_identity(opened)
                or final_permission_identity != permission_identity
            ):
                raise PrivateSecretFileError("private secret file changed during read")
    except PrivateSecretFileError:
        raise
    except (OSError, StableFileError, backup_crypto.BackupCryptoError) as error:
        raise PrivateSecretFileError("private secret file is invalid") from error
    return raw
