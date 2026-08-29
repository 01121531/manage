"""Fail closed if the target-intake clean snapshot launch contract drifts."""

from __future__ import annotations

import ast
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
_STDLIB_ROOTS = {
    "__future__", "argparse", "hashlib", "hmac", "json", "os", "pathlib",
    "stat", "subprocess", "sys", "typing",
}


def snapshot_launcher_gate_errors(root: Path = ROOT) -> list[str]:
    paths = {
        "launcher": root / "scripts" / "target_intake_snapshot_launcher.py",
        "snapshot": root / "scripts" / "target_intake_source_snapshot.py",
        "contract": root / "scripts" / "target_intake_validator_contract.py",
        "generation": root / "scripts" / "target_intake_generation.py",
        "preflight": root / "scripts" / "target_intake_preflight.py",
        "quality": root / "scripts" / "quality_gate.ps1",
    }
    try:
        texts = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
        launcher_tree = ast.parse(texts["launcher"])
    except (OSError, UnicodeError, SyntaxError):
        return ["target intake snapshot launcher assets cannot be loaded"]

    errors: list[str] = []
    for node in launcher_tree.body:
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module.split(".")[0]]
        if any(name not in _STDLIB_ROOTS for name in names):
            errors.append("launcher top level must remain standard-library-only")
            break

    launcher_markers = (
        'MANIFEST_FILENAME = "target-intake-validator-source-snapshot.json"',
        'SNAPSHOT_KIND = "target_intake_validator_source_snapshot_v1"',
        '"raise SystemExit(_child_main(sys.argv[1:]))"',
        '"-I",\n            "-B",\n            "-S",\n            "-P",\n            "-c",',
        "executable = Path(sys.executable).resolve(strict=True)",
        "env=_minimal_environment()",
        "stdin=subprocess.DEVNULL",
        "shell=False",
        "timeout=_CHILD_TIMEOUT_SECONDS",
        "cwd=snapshot_root",
        "resolved_snapshot.relative_to(resolved_repository)",
        "_audit_loaded_local_modules(snapshot_root, document)",
        "document = snapshot.manifest",
        "recheck_source_snapshot(snapshot)",
        "with snapshot_execution_profile(payload_sha256, file_sha256):",
        "recovery-snapshot-mutation=not-performed",
    )
    for marker in launcher_markers:
        if marker not in texts["launcher"]:
            errors.append(f"launcher contract marker is missing: {marker}")

    child = next(
        (
            node for node in launcher_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_child_main"
        ),
        None,
    )
    if child is None or any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
        for node in ast.walk(child) if child is not None
    ):
        errors.append("clean child must not launch another process")

    snapshot_markers = (
        "with ExitStack() as stack:",
        "for relative_path in SOURCE_MEMBERS:",
        "open_stable_binary(",
        "for relative_path, stream, metadata in opened:",
        "destination must be absent",
        "allow_module_root=True",
        "_require_exact_tree(root)",
        "require_single_link=True",
        "not _is_read_only",
        "expected_payload_sha256",
        "expected_file_sha256",
        "recheck_source_snapshot(loaded)",
    )
    for marker in snapshot_markers:
        if marker not in texts["snapshot"]:
            errors.append(f"source snapshot contract marker is missing: {marker}")

    contract_markers = (
        'VALIDATOR_CONTRACT_KIND = "target_intake_generation_validator_contract_v3"',
        '"platform/api/__init__.py"',
        '"platform/api/v1/__init__.py"',
        '"stdlib_platform_sha256"',
        '"execution_profile"',
        'SNAPSHOT_EXECUTION_MODE = "clean_isolated_external_snapshot_subprocess_v1"',
        "flags.isolated != 1",
        "flags.ignore_environment != 1",
        "flags.no_site != 1",
        "flags.no_user_site != 1",
        "flags.dont_write_bytecode != 1",
    )
    for marker in contract_markers:
        if marker not in texts["contract"]:
            errors.append(f"validator contract marker is missing: {marker}")

    if texts["contract"].count('    "platform/') != 31:
        errors.append("validator platform source inventory must contain 31 files")
    if texts["contract"].count('    "scripts/') < 34:
        errors.append("validator script source inventory is incomplete")
    if 'RECEIPT_KIND = "target_intake_generation_receipt_v6"' not in texts["generation"]:
        errors.append("generation receipt must remain schema v6")
    if (
        'if not argv or argv[0] != "verify-requirements":' not in texts["preflight"]
        or "target-intake-validator-snapshot-launcher-required" not in texts["preflight"]
    ):
        errors.append("direct operational preflight entrypoint must remain blocked")
    if "python scripts/verify_target_intake_snapshot_launcher.py" not in texts["quality"]:
        errors.append("snapshot launcher verifier is missing from the quality gate")
    return errors


def main() -> int:
    errors = snapshot_launcher_gate_errors()
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "target-intake-snapshot-launcher-gate-ok "
        "production_acceptance=false source-files=65 snapshot-members=91 "
        "clean-child-flags=-I,-B,-S,-P direct-operational-entrypoint=blocked "
        "source-authority=unverified snapshot-atomicity=unverified "
        "interpreter-native-runtime-identity=unverified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
