"""Validate production Sub2 endpoint and egress allowlist before release."""

from __future__ import annotations

from pathlib import Path

from platform.config import Settings
from platform.uploads import (
    sub2_unknown_reconciliation_configured,
    validate_generic_sub2_upload_endpoint,
)
from scripts.external_json import read_stable_bytes


ROOT = Path(__file__).resolve().parents[1]
MAX_ENV_BYTES = 64 * 1024
_VARIABLES = {
    "PLATFORM_SUB2_UPLOAD_URL",
    "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE",
}


class Sub2EgressPreflightError(RuntimeError):
    """The target Sub2 egress policy is not deployable."""


class _InvalidPolicy(RuntimeError):
    pass


def _read_inventory(env_file: Path) -> dict[str, str]:
    raw = read_stable_bytes(env_file, max_bytes=MAX_ENV_BYTES)
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name not in _VARIABLES:
            continue
        cleaned = value.strip()
        if name in values or not cleaned or any(
            character in cleaned for character in "$'\""
        ):
            raise _InvalidPolicy
        values[name] = cleaned
    if set(values) != _VARIABLES:
        raise _InvalidPolicy
    return values


def validate_sub2_egress_policy(
    env_file: Path,
    *,
    repository_root: Path = ROOT,
) -> None:
    """Fail closed without returning or logging either target locator."""

    try:
        repository = repository_root.resolve(strict=True)
        if env_file.resolve(strict=True) != repository / ".env":
            raise _InvalidPolicy
        inventory = _read_inventory(env_file)
        policy_path = Path(inventory["PLATFORM_SUB2_ALLOWED_ORIGINS_FILE"])
        if (
            not policy_path.is_absolute()
            or ".." in policy_path.parts
            or "~" in policy_path.parts
        ):
            raise _InvalidPolicy
        resolved_policy = policy_path.resolve(strict=True)
        if resolved_policy.is_relative_to(repository):
            raise _InvalidPolicy
        origins = Settings(
            _env_file=None,
            sub2_allowed_origins_file=str(policy_path),
        ).resolved_sub2_allowed_origins()
        validate_generic_sub2_upload_endpoint(
            inventory["PLATFORM_SUB2_UPLOAD_URL"],
            origins,
        )
        if not sub2_unknown_reconciliation_configured():
            raise _InvalidPolicy
    except (OSError, RuntimeError, UnicodeError, ValueError):
        raise Sub2EgressPreflightError(
            "production Sub2 egress policy preflight failed"
        ) from None
