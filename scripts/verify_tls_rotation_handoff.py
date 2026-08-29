"""Statically verify the read-only TLS rotation manual-handoff boundary."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "scripts" / "tls_rotation_handoff.py"


def validate_source(source: str) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["TLS rotation handoff is not valid Python"]
    forbidden_names = {
        "act",
        "contain",
        "force_recreate_compose_service",
        "restart_kubernetes_deployment",
        "pause_kubernetes_deployment",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in forbidden_names)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_names)
        ):
            errors.append("TLS rotation handoff must not mutate a runtime")
            break
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    if any("compose_tls_rotation_backend" in name or "kubernetes_tls_rotation_backend" in name for name in imports):
        errors.append("TLS rotation handoff must not import a mutation-capable backend")
    publish_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "publish_write_once_file"
    ]
    if len(publish_calls) != 1:
        errors.append("TLS rotation handoff must publish one write-once output")
    for marker in (
        "with release_control_lock():",
        "read_stable_bytes_with_metadata(",
        "expected_identity=stable_file_identity(first_metadata)",
        "assert_expected_rotation(first, projection)",
        "assert_expected_rotation(second, projection)",
        '"state": "committed"',
        '"state": "unknown"',
        '"production_acceptance": False',
        '"manual_review_required": True',
        "prepare_write_once_file(_external_path(handoff_output))",
    ):
        if marker not in source:
            errors.append(f"TLS rotation handoff is missing {marker}")
    for forbidden in (
        '"not_committed"',
        "unlink(execution_evidence",
        "write_evidence(",
        "shell=True",
        "subprocess",
    ):
        if forbidden in source:
            errors.append(f"TLS rotation handoff contains forbidden operation {forbidden}")
    return errors


def main() -> int:
    try:
        errors = validate_source(load_stable_text(HANDOFF, max_bytes=64 * 1024))
    except (OSError, ValueError):
        print("TLS rotation handoff asset cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("tls-rotation-handoff-ok production_acceptance=false manual_review_required=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
