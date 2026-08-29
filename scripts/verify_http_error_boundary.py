"""Verify the fail-safe boundary for ordinary HTTP exceptions."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from external_text import load_stable_text  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
ERRORS = ROOT / "platform" / "errors.py"
APP = ROOT / "platform" / "app.py"
ROUTES = (
    ROOT / "platform" / "auth.py",
    ROOT / "platform" / "api" / "v1" / "routes.py",
)
MAX_HTTP_BOUNDARY_SOURCE_BYTES = 256 * 1024
EXPECTED_ALLOW_METHODS = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
}


def _parse(source: str, label: str, errors: list[str]) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        errors.append(f"syntax:{label}")
        return None


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _exc_attribute(node: ast.AST, attribute: str) -> bool:
    return any(
        isinstance(item, ast.Attribute)
        and isinstance(item.value, ast.Name)
        and item.value.id == "exc"
        and item.attr == attribute
        for item in ast.walk(node)
    )


def _is_business_guard(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isinstance"
        and len(node.args) == 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "exc"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "BusinessHTTPException"
    )


def _literal_assignment(tree: ast.Module, name: str) -> object | None:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            continue
        value = node.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
        ):
            value = value.args[0]
        try:
            return ast.literal_eval(value)
        except (ValueError, TypeError):
            return None
    return None


def http_error_boundary_errors(
    errors_source: str,
    app_source: str,
    route_sources: tuple[str, ...],
) -> list[str]:
    """Return stable verifier error codes for unsafe boundary changes."""

    errors: list[str] = []
    errors_tree = _parse(errors_source, "errors", errors)
    app_tree = _parse(app_source, "app", errors)
    route_trees = [
        _parse(source, f"routes-{index}", errors)
        for index, source in enumerate(route_sources)
    ]
    if errors_tree is None or app_tree is None or any(tree is None for tree in route_trees):
        return errors

    registrations = [
        node
        for node in ast.walk(app_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_exception_handler"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "StarletteHTTPException"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "http_exception_handler"
    ]
    if len(registrations) != 1:
        errors.append("handler-registration")

    handler = _function(errors_tree, "http_exception_handler")
    if handler is None or not handler.body or not isinstance(handler.body[0], ast.If):
        errors.append("business-type-guard")
    else:
        guard = handler.body[0]
        if not _is_business_guard(guard.test):
            errors.append("business-type-guard")
        ordinary_nodes: list[ast.AST] = [*guard.orelse, *handler.body[1:]]
        if any(_exc_attribute(node, "detail") for node in ordinary_nodes):
            errors.append("ordinary-detail-flow")
        header_refs = [
            node
            for node in ast.walk(handler)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "exc"
            and node.attr == "headers"
        ]
        safe_header_calls = [
            node
            for node in ast.walk(handler)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_safe_http_exception_headers"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Attribute)
            and isinstance(node.args[1].value, ast.Name)
            and node.args[1].value.id == "exc"
            and node.args[1].attr == "headers"
        ]
        if len(header_refs) != 1 or len(safe_header_calls) != 1:
            errors.append("arbitrary-header-flow")

    for name, value_type in (
        ("_HTTP_ERROR_CODES", str),
        ("_HTTP_ERROR_MESSAGES", str),
        ("_HTTP_ERROR_RECOVERY_HINTS", str),
    ):
        mapping = _literal_assignment(errors_tree, name)
        if (
            not isinstance(mapping, dict)
            or not mapping
            or any(not isinstance(key, int) for key in mapping)
            or any(not isinstance(value, value_type) for value in mapping.values())
        ):
            errors.append("nonliteral-error-contract")
            break

    methods = _literal_assignment(errors_tree, "_ALLOWED_HTTP_METHODS")
    if methods != EXPECTED_ALLOW_METHODS:
        errors.append("unsafe-header-allowlist")

    header_helper = _function(errors_tree, "_safe_http_exception_headers")
    if header_helper is None:
        errors.append("unsafe-header-validation")
    else:
        comparisons = [node for node in ast.walk(header_helper) if isinstance(node, ast.Compare)]
        exact_bearer = any(
            len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == "Bearer"
            for node in comparisons
        )
        status_values = {
            comparator.value
            for node in comparisons
            for comparator in node.comparators
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, int)
        }
        returned_header_names = {
            key.value
            for node in ast.walk(header_helper)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
            for key in node.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        uses_method_allowlist = any(
            isinstance(node, ast.Name) and node.id == "_ALLOWED_HTTP_METHODS"
            for node in ast.walk(header_helper)
        )
        if (
            not exact_bearer
            or not {401, 405}.issubset(status_values)
            or returned_header_names != {"WWW-Authenticate", "Allow"}
            or not uses_method_allowlist
        ):
            errors.append("unsafe-header-validation")

    business_class = next(
        (
            node
            for node in errors_tree.body
            if isinstance(node, ast.ClassDef) and node.name == "BusinessHTTPException"
        ),
        None,
    )
    business_init = (
        next(
            (
                node
                for node in business_class.body
                if isinstance(node, ast.FunctionDef) and node.name == "__init__"
            ),
            None,
        )
        if business_class is not None
        else None
    )
    if business_init is None or "headers" in {
        argument.arg for argument in (*business_init.args.args, *business_init.args.kwonlyargs)
    }:
        errors.append("business-arbitrary-headers")

    for tree in route_trees:
        assert tree is not None
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "HTTPException"
            ):
                continue
            detail = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "detail"),
                None,
            )
            if not isinstance(detail, ast.Constant) or not isinstance(detail.value, str):
                errors.append("dynamic-ordinary-detail")
                break

    return sorted(set(errors))


def main() -> int:
    try:
        sources = tuple(
            load_stable_text(
                path,
                max_bytes=MAX_HTTP_BOUNDARY_SOURCE_BYTES,
            )
            for path in (ERRORS, APP, *ROUTES)
        )
        errors = http_error_boundary_errors(
            sources[0],
            sources[1],
            sources[2:],
        )
    except (OSError, UnicodeError):
        print(
            "http-error-boundary-read: "
            "Cannot inspect HTTP error boundary sources",
            file=sys.stderr,
        )
        return 1
    if errors:
        print("HTTP error boundary verification failed: " + ", ".join(errors), file=sys.stderr)
        return 1
    print("http-error-boundary-ok fixed-contract-and-reviewed-headers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
