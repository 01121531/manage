"""Verify docker-compose variables are documented in .env.example."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"


def main() -> int:
    compose_text = COMPOSE.read_text(encoding="utf-8")
    env_text = ENV_EXAMPLE.read_text(encoding="utf-8")
    variables = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", compose_text))
    documented = {
        line.split("=", 1)[0]
        for line in env_text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }
    missing = sorted(variables - documented)
    if missing:
        print("Missing .env.example variables: " + ", ".join(missing), file=sys.stderr)
        return 1
    print(
        f"compose-env-ok variables={len(variables)} file={COMPOSE.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
