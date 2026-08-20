"""Fail when the checked-in TypeScript OpenAPI contract is stale."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

try:
    from .export_openapi import REPOSITORY_ROOT, export_openapi
except ImportError:  # Direct script execution from scripts/.
    from export_openapi import REPOSITORY_ROOT, export_openapi


def normalized_contract(path: Path) -> str:
    """Compare generated source independent of the runner's newline policy."""

    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def main() -> int:
    frontend = REPOSITORY_ROOT / "frontend"
    executable = frontend / "node_modules" / ".bin" / (
        "openapi-typescript.cmd" if os.name == "nt" else "openapi-typescript"
    )
    expected = frontend / "src" / "generated" / "openapi.ts"
    if not executable.exists():
        raise SystemExit("openapi-typescript is not installed; run npm ci in frontend")
    if not expected.exists():
        raise SystemExit("generated OpenAPI client is missing; run npm run generate:api")
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
        if normalized_contract(generated) != normalized_contract(expected):
            raise SystemExit(
                "generated OpenAPI client is stale; run npm run generate:api"
            )
    print("openapi-client-ok generated-contract-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
