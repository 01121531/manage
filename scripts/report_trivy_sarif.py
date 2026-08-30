"""Emit concise GitHub annotations from a Trivy SARIF report.

The scanner remains the fail-closed gate. This helper exits zero after
reporting findings so the original Trivy step remains authoritative while the
workflow summary identifies the affected rule and package.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.external_json import load_unique_json
except ModuleNotFoundError:  # Direct script execution from scripts/.
    from external_json import load_unique_json


_MAX_SARIF_BYTES = 32 * 1024 * 1024


def _github_escape(value: object) -> str:
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def findings(path: Path) -> list[tuple[str, str]]:
    payload: Any = load_unique_json(path, max_bytes=_MAX_SARIF_BYTES)
    runs = payload.get("runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise ValueError("SARIF runs must be a list")
    output: list[tuple[str, str]] = []
    for run in runs:
        results = run.get("results", []) if isinstance(run, dict) else []
        if not isinstance(results, list):
            raise ValueError("SARIF results must be a list")
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "unknown-rule")[:160]
            message_block = result.get("message")
            message = (
                message_block.get("text")
                if isinstance(message_block, dict)
                else None
            )
            output.append((rule_id, str(message or "Trivy finding")[:2_000]))
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", type=Path)
    args = parser.parse_args()
    if not args.sarif.is_file():
        print("::warning::Trivy SARIF report was not created")
        return 0
    try:
        results = findings(args.sarif)
    except (OSError, ValueError, json.JSONDecodeError):
        print("::warning::Trivy SARIF report could not be summarized")
        return 0
    if not results:
        print("::notice::Trivy reported no HIGH/CRITICAL findings")
        return 0
    for rule_id, message in results:
        print(
            f"::error title=Trivy {_github_escape(rule_id)}::"
            f"{_github_escape(message)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
