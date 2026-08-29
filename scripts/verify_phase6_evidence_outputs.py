"""Verify Phase 6 evidence writers keep the shared external write-once contract."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script execution from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
PHASE6_SCRIPT = ROOT / "scripts" / "phase6_rehearsal.py"
TRAINING_SCRIPT = ROOT / "scripts" / "training_evidence.py"
OUTPUT_POLICY_SCRIPT = ROOT / "scripts" / "backup_output_policy.py"
MAX_PHASE6_SOURCE_BYTES = 64 * 1024


def _functions(module: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
    }


def _qualified_name(value: ast.expr) -> str:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        parent = _qualified_name(value.value)
        return f"{parent}.{value.attr}" if parent else value.attr
    return ""


def _call_name(call: ast.Call) -> str:
    return _qualified_name(call.func)


def _call_lines(function: ast.FunctionDef, name: str) -> list[int]:
    return sorted(
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == name
    )


def _ordered_calls(function: ast.FunctionDef, names: tuple[str, ...]) -> bool:
    matching = [_call_lines(function, name) for name in names]
    if any(len(lines) != 1 for lines in matching):
        return False
    lines = [matches[0] for matches in matching]
    return all(line is not None for line in lines) and lines == sorted(lines)


def _unsafe_mutation_errors(
    function: ast.FunctionDef, *, allowed_unlink_receiver: str | None = None
) -> list[str]:
    errors: list[str] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name == "os.replace":
            errors.append(f"{function.name} must not replace evidence output")
        if name.endswith(".mkdir"):
            errors.append(f"{function.name} must not create evidence output parents")
        if name.endswith(".unlink"):
            receiver = name.removesuffix(".unlink")
            if receiver != allowed_unlink_receiver:
                errors.append(f"{function.name} must not unlink final evidence output")
    return errors


def phase6_output_contract_errors(
    phase6_source: str, training_source: str, policy_source: str
) -> list[str]:
    try:
        phase6 = ast.parse(phase6_source)
        training = ast.parse(training_source)
        policy = ast.parse(policy_source)
    except SyntaxError:
        return ["Phase 6 evidence output assets must parse as Python"]

    errors: list[str] = []
    phase6_functions = _functions(phase6)
    training_functions = _functions(training)
    policy_functions = _functions(policy)

    phase6_prepare = phase6_functions.get("prepare_evidence_output")
    phase6_writer = phase6_functions.get("write_evidence")
    phase6_main = phase6_functions.get("main")
    if phase6_prepare is None or not _call_lines(
        phase6_prepare, "prepare_write_once_file"
    ):
        errors.append("Phase 6 rehearsal must use the shared output preflight")
    if phase6_writer is None or not _ordered_calls(
        phase6_writer,
        (
            "prepare_evidence_output",
            "tempfile.NamedTemporaryFile",
            "os.fsync",
            "publish_write_once_file",
            "verify_evidence",
        ),
    ):
        errors.append("Phase 6 rehearsal writer must preflight, fsync, publish once, and verify")
    elif phase6_writer is not None:
        errors.extend(
            _unsafe_mutation_errors(
                phase6_writer, allowed_unlink_receiver="temporary_path"
            )
        )
    if phase6_main is None or not _ordered_calls(
        phase6_main,
        ("prepare_evidence_output", "run_rehearsal", "write_evidence"),
    ):
        errors.append("Phase 6 rehearsal output preflight must precede the rehearsal")
    elif phase6_main is not None:
        errors.extend(_unsafe_mutation_errors(phase6_main))

    training_writer = training_functions.get("write_evidence")
    training_private_writer = training_functions.get("_write_evidence")
    training_create = training_functions.get("create_evidence")
    training_main = training_functions.get("main")
    if training_writer is None or not _ordered_calls(
        training_writer, ("prepare_write_once_file", "_write_evidence")
    ):
        errors.append("training writer must use the shared output preflight")
    elif training_writer is not None:
        errors.extend(_unsafe_mutation_errors(training_writer))
    if training_private_writer is None or not _ordered_calls(
        training_private_writer,
        (
            "tempfile.NamedTemporaryFile",
            "os.fsync",
            "publish_write_once_file",
            "verify_evidence",
        ),
    ):
        errors.append("training writer must fsync, publish once, and verify")
    elif training_private_writer is not None:
        errors.extend(
            _unsafe_mutation_errors(
                training_private_writer, allowed_unlink_receiver="temporary_path"
            )
        )
    if training_create is None or not _ordered_calls(
        training_create,
        ("prepare_write_once_file", "_read_json", "_write_evidence"),
    ):
        errors.append("training output preflight must precede input access")
    elif training_create is not None:
        errors.extend(_unsafe_mutation_errors(training_create))
    if training_main is None:
        errors.append("training evidence CLI is missing")
    else:
        errors.extend(_unsafe_mutation_errors(training_main))

    publisher = policy_functions.get("publish_write_once_file")
    if publisher is None or not _ordered_calls(
        publisher, ("os.link", "temporary_path.unlink")
    ):
        errors.append("shared output publication must commit with os.link before cleanup")
    elif not any(
        isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Name)
        and node.type.id == "OSError"
        and len(node.body) == 1
        and isinstance(node.body[0], ast.Pass)
        for node in ast.walk(publisher)
    ):
        errors.append("temporary cleanup failure must not reverse a committed publication")
    if any(
        isinstance(node, ast.Call) and _call_name(node) == "os.replace"
        for node in ast.walk(policy)
    ):
        errors.append("shared output policy must not use replace semantics")
    return errors


def main() -> int:
    try:
        phase6_source = load_stable_text(
            PHASE6_SCRIPT,
            max_bytes=MAX_PHASE6_SOURCE_BYTES,
        )
        training_source = load_stable_text(
            TRAINING_SCRIPT,
            max_bytes=MAX_PHASE6_SOURCE_BYTES,
        )
        policy_source = load_stable_text(
            OUTPUT_POLICY_SCRIPT,
            max_bytes=MAX_PHASE6_SOURCE_BYTES,
        )
    except (OSError, UnicodeError):
        print("phase6-evidence-output-error: required file cannot be read", file=sys.stderr)
        return 1
    errors = phase6_output_contract_errors(
        phase6_source,
        training_source,
        policy_source,
    )
    if errors:
        for error in errors:
            print(f"phase6-evidence-output-error: {error}", file=sys.stderr)
        return 1
    print("phase6-evidence-output-ok external-write-once-preflight-publish-verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
