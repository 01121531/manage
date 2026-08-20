"""Export the platform OpenAPI contract deterministically for client generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from platform.app import create_app  # noqa: E402
from platform.config import Settings  # noqa: E402


def export_openapi(output: Path) -> None:
    app = create_app(
        Settings(
            app_name="email-platform-contract",
            environment="test",
            auth_mode="local",
            database_url="sqlite+pysqlite:///:memory:",
        )
    )
    try:
        schema = app.openapi()
    finally:
        app.state.engine.dispose()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export_openapi(args.output.resolve())
    print(f"openapi-export-ok output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
