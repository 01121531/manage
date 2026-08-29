"""Fail when the checked-in TypeScript OpenAPI contract is stale."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

try:
    from .export_openapi import REPOSITORY_ROOT, export_openapi
    from .external_text import load_stable_text
except ImportError:  # Direct script execution from scripts/.
    from export_openapi import REPOSITORY_ROOT, export_openapi
    from external_text import load_stable_text


MAX_OPENAPI_CONTRACT_BYTES = 256 * 1024


def normalized_contract(path: Path) -> str:
    """Compare generated source independent of the runner's newline policy."""

    return load_stable_text(
        path,
        max_bytes=MAX_OPENAPI_CONTRACT_BYTES,
    ).replace("\r\n", "\n")


def checked_in_contracts_are_current(
    *,
    generated_schema: Path,
    checked_in_schema: Path,
    generated_types: Path,
    checked_in_types: Path,
) -> bool:
    """Require both generated artifacts to come from the current runtime schema."""

    generated_schema_text = normalized_contract(generated_schema)
    checked_in_schema_text = normalized_contract(checked_in_schema)
    generated_types_text = normalized_contract(generated_types)
    checked_in_types_text = normalized_contract(checked_in_types)
    return (
        generated_schema_text == checked_in_schema_text
        and generated_types_text == checked_in_types_text
    )


def main() -> int:
    frontend = REPOSITORY_ROOT / "frontend"
    executable = frontend / "node_modules" / ".bin" / (
        "openapi-typescript.cmd" if os.name == "nt" else "openapi-typescript"
    )
    expected = frontend / "src" / "generated" / "openapi.ts"
    expected_schema = frontend / "openapi.json"
    if not executable.exists():
        raise SystemExit("openapi-typescript is not installed; run npm ci in frontend")
    if not expected.exists():
        raise SystemExit("generated OpenAPI client is missing; run npm run generate:api")
    if not expected_schema.exists():
        raise SystemExit("checked-in OpenAPI schema is missing; run npm run generate:api")
    with tempfile.TemporaryDirectory(prefix="email-platform-openapi-") as directory:
        temporary = Path(directory)
        schema = temporary / "openapi.json"
        generated = temporary / "openapi.ts"
        export_openapi(schema)
        subprocess.run(
            [str(executable), str(schema), "-o", str(generated)],
            cwd=frontend,
            check=True,
        )
        try:
            contracts_are_current = checked_in_contracts_are_current(
                generated_schema=schema,
                checked_in_schema=expected_schema,
                generated_types=generated,
                checked_in_types=expected,
            )
        except (OSError, UnicodeError):
            raise SystemExit("Cannot inspect OpenAPI contract artifacts") from None
        if not contracts_are_current:
            raise SystemExit(
                "checked-in OpenAPI schema or generated client is stale; "
                "run npm run generate:api"
            )
    print("openapi-client-ok generated-contract-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
