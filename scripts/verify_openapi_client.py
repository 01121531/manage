"""Fail when the checked-in TypeScript OpenAPI contract is stale."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from export_openapi import REPOSITORY_ROOT, export_openapi


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
        if generated.read_bytes() != expected.read_bytes():
            raise SystemExit(
                "generated OpenAPI client is stale; run npm run generate:api"
            )
    print("openapi-client-ok generated-contract-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
