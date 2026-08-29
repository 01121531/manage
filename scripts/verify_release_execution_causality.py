"""Statically lock the release-ledger causality chain used by strict intake."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "scripts" / "release_execution_binding.py"
INTAKE = ROOT / "scripts" / "target_intake_preflight.py"
CONSUMERS = {
    name: ROOT / "scripts" / name
    for name in (
        "target_phase_artifacts.py",
        "sub2_execution_evidence.py",
        "vault_egress_evidence.py",
        "phase6_pilot_evidence.py",
        "phase6_operations_evidence.py",
    )
}
MAX_SOURCE_BYTES = 128 * 1024
RELEASE_BOUNDARY_MARKERS = (
    "release-reviewer-authentication=unverified",
    "release-review-trusted-time=unverified",
    "release-review-replay-protection=unverified",
    "release-storage-provider-native=unverified",
    "release-storage-retention=unverified",
    "release-storage-delete-denial=unverified",
    "release-storage-readback=unverified",
)


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _dict_projection(function: ast.FunctionDef) -> dict[str, ast.AST]:
    candidates: list[dict[str, ast.AST]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        keys = [
            key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
            for key in node.value.keys
        ]
        if "ledger_type" in keys:
            candidates.append(
                {
                    key: value
                    for key, value in zip(keys, node.value.values, strict=True)
                    if key is not None
                }
            )
    return max(candidates, key=len, default={})


def _is_evidence_field(node: ast.AST | None, field: str) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "evidence"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == field
    )


def _has_compare(
    function: ast.FunctionDef,
    left: str,
    operator: type[ast.cmpop],
    right: str,
) -> bool:
    return any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == left
        and len(node.ops) == 1
        and isinstance(node.ops[0], operator)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == right
        for node in ast.walk(function)
    )


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _requires_kwonly(function: ast.FunctionDef, names: set[str]) -> bool:
    defaults = {
        argument.arg: default
        for argument, default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
            strict=True,
        )
    }
    return all(name in defaults and defaults[name] is None for name in names)


def _contains_string(node: ast.AST | None, value: str) -> bool:
    return node is not None and any(
        isinstance(item, ast.Constant) and item.value == value
        for item in ast.walk(node)
    )


def _review_call_is_selector_bound(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node) == "release_execution_reviewed_at"
        and len(node.args) == 2
        and _contains_string(node.args[1], "release_execution")
    )


def _has_release_boundary_output(tree: ast.Module) -> bool:
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return all(
        any(marker in value for value in strings)
        for marker in RELEASE_BOUNDARY_MARKERS
    )


def causality_errors(
    binding_source: str,
    intake_source: str,
    consumer_sources: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        binding_tree = ast.parse(binding_source)
        intake_tree = ast.parse(intake_source)
    except SyntaxError:
        return ["release execution causality sources are not valid Python"]

    identity = _function(binding_tree, "release_execution_identity")
    opaque_reference = _function(binding_tree, "_opaque_execution_reference")
    selector_validation = _function(binding_tree, "selector_errors")
    reviewed_at = _function(binding_tree, "release_execution_reviewed_at")
    alignment = _function(
        binding_tree,
        "release_execution_identity_alignment_errors",
    )
    path_alignment = _function(binding_tree, "release_execution_alignment_errors")
    if (
        identity is None
        or opaque_reference is None
        or selector_validation is None
        or reviewed_at is None
        or alignment is None
        or path_alignment is None
    ):
        errors.append("release execution identity alignment contract is missing")
    else:
        opaque_doc = ast.get_docstring(opaque_reference) or ""
        if (
            "only" not in opaque_doc.casefold()
            or "never worm semantics" not in opaque_doc.casefold()
        ):
            errors.append("release execution storage reference must remain explicitly opaque")
        if not any(
            isinstance(node, ast.Call)
            and _call_name(node) == "_opaque_execution_reference"
            and _contains_string(node, "evidence_object_reference")
            for node in ast.walk(selector_validation)
        ):
            errors.append("release execution selector must use the opaque storage validator")
        if not any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and _contains_string(node, "sha256")
            and _contains_string(node, "evidence_sha256")
            for node in ast.walk(reviewed_at)
        ):
            errors.append("ledger review time must select the exact ledger digest")
        if not any(
            isinstance(node, ast.Call)
            and _call_name(node) == "_reviewer_reference"
            and _contains_string(node, "reviewed_by")
            for node in ast.walk(reviewed_at)
        ):
            errors.append("ledger review time must carry an opaque reviewer reference")
        projection = _dict_projection(identity)
        if not all(
            _is_evidence_field(projection.get(field), field)
            for field in ("started_at", "finished_at")
        ):
            errors.append("release execution identity must preserve exact start and finish")
        ordering_arguments = {
            "release_reviewed_at",
            "consumer_started_at",
        }
        if not _requires_kwonly(alignment, ordering_arguments) or not all(
            (
                _has_compare(alignment, "consumer_started", ast.Lt, "finished_at"),
                _has_compare(alignment, "reviewed_at", ast.Lt, "finished_at"),
                _has_compare(alignment, "consumer_started", ast.Lt, "reviewed_at"),
            )
        ):
            errors.append("release review and consumer start ordering is incomplete")
        forwarded = [
            node
            for node in ast.walk(path_alignment)
            if isinstance(node, ast.Call)
            and _call_name(node) == "release_execution_identity_alignment_errors"
        ]
        if not _requires_kwonly(path_alignment, ordering_arguments) or not (
            len(forwarded) == 1
            and isinstance(
                _keyword_value(forwarded[0], "release_reviewed_at"),
                ast.Name,
            )
            and _keyword_value(forwarded[0], "release_reviewed_at").id
            == "release_reviewed_at"
            and isinstance(
                _keyword_value(forwarded[0], "consumer_started_at"),
                ast.Name,
            )
            and _keyword_value(forwarded[0], "consumer_started_at").id
            == "consumer_started_at"
        ):
            errors.append("path-based release alignment must require and forward ordering")

    artifact_errors = _function(intake_tree, "_artifact_errors")
    intake_errors = _function(intake_tree, "intake_errors")
    if artifact_errors is None or intake_errors is None:
        errors.append("strict intake causality contract is missing")
        return errors
    if not _has_release_boundary_output(intake_tree):
        errors.append(
            "strict intake must report the release-review and storage trust boundaries"
        )
    if not _has_compare(
        artifact_errors,
        "reviewed_at",
        ast.Lt,
        "finished_at",
    ) or not _has_compare(
        artifact_errors,
        "reviewed_at",
        ast.Gt,
        "evaluated_at",
    ):
        errors.append("ledger selection review must follow finish and precede evaluation")

    consumer_calls = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call)
        and _call_name(node) == "release_execution_identity_alignment_errors"
    ]
    if not (
        len(consumer_calls) == 5
        and all(
            _review_call_is_selector_bound(
                _keyword_value(call, "release_reviewed_at")
            )
            and _contains_string(
                _keyword_value(call, "consumer_started_at"), "started_at"
            )
            for call in consumer_calls
        )
    ):
        errors.append("all Phase 1-6 release consumers must pass their window start")

    replay_calls = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call) and _call_name(node) == "contains_release_start"
    ]
    if not (
        len(replay_calls) == 1
        and len(replay_calls[0].args) == 1
        and _contains_string(replay_calls[0].args[0], "started_at")
    ):
        errors.append("final strict intake must replay ledger start against Phase 0")

    for name, source in (consumer_sources or {}).items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            errors.append(f"{name} is not valid Python")
            continue
        if not _has_release_boundary_output(tree):
            errors.append(
                f"{name} must report the release-review and storage trust boundaries"
            )
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _call_name(node) == "release_execution_alignment_errors"
        ]
        if not (
            len(calls) == 1
            and _review_call_is_selector_bound(
                _keyword_value(calls[0], "release_reviewed_at")
            )
            and _contains_string(
                _keyword_value(calls[0], "consumer_started_at"),
                "started_at",
            )
        ):
            errors.append(f"{name} must pass its execution-window start")
    return errors


def main() -> int:
    try:
        binding_source = load_stable_text(BINDING, max_bytes=MAX_SOURCE_BYTES)
        intake_source = load_stable_text(INTAKE, max_bytes=MAX_SOURCE_BYTES)
        consumer_sources = {
            name: load_stable_text(path, max_bytes=MAX_SOURCE_BYTES)
            for name, path in CONSUMERS.items()
        }
    except (OSError, UnicodeError, ValueError):
        print("release execution causality assets cannot be read", file=sys.stderr)
        return 1
    errors = causality_errors(binding_source, intake_source, consumer_sources)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "release-execution-causality-ok "
        "start-replay=final-strict-intake review-consumer-order=locked "
        "release-review-claim=opaque authentication=unverified "
        "trusted-time=unverified replay-protection=unverified "
        "release-storage-reference=opaque provider-native=unverified "
        "retention=unverified delete-denial=unverified readback=unverified "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
