"""Verify that the platform desktop release cannot carry legacy direct clients."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Iterable

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "build.ps1"
MAX_DESKTOP_SOURCE_BYTES = 256 * 1024
FORBIDDEN_MODULES = frozenset({"legacy_app", "admin_oauth", "oauth_dialog"})
REQUIRED_MODULES = frozenset(
    {
        "app_version",
        "platform_clipboard",
        "platform_client",
        "platform_desktop",
        "platform_login_dialog",
        "session_store",
        "scripts.external_json",
        "update_client",
    }
)
FORBIDDEN_SOURCE_MARKERS = (
    "MailApiClient",
    "OAuthAuthorizationDialog",
    "parse_credentials",
    "subscriber-api.qnxie.com",
    "email111.6ltd.ltd",
)
FORBIDDEN_SIBLINGS = frozenset(
    {"account_name.txt", "proxy_id.txt", "admin_token.bin"}
)


def _local_module_path(module: str) -> Path | None:
    relative = Path(*module.split("."))
    source = ROOT / relative.with_suffix(".py")
    if source.is_file():
        return source
    package = ROOT / relative / "__init__.py"
    return package if package.is_file() else None


def _reachable_local_module_sources(
    entry: str = "app",
) -> tuple[dict[str, Path], dict[str, str]]:
    pending = [entry]
    found: dict[str, Path] = {}
    sources: dict[str, str] = {}
    while pending:
        module = pending.pop()
        if module in found:
            continue
        path = _local_module_path(module)
        if path is None:
            continue
        found[module] = path
        source = load_stable_text(
            path,
            max_bytes=MAX_DESKTOP_SOURCE_BYTES,
        )
        sources[module] = source
        tree = ast.parse(source, filename=str(path))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module)
        for imported in imports:
            if _local_module_path(imported) is not None:
                pending.append(imported)
    return found, sources


def reachable_local_modules(entry: str = "app") -> dict[str, Path]:
    reachable, _ = _reachable_local_module_sources(entry)
    return reachable


def source_boundary_errors() -> list[str]:
    errors: list[str] = []
    build_text = load_stable_text(
        BUILD_SCRIPT,
        max_bytes=MAX_DESKTOP_SOURCE_BYTES,
    )
    if '"release\\windows"' not in build_text:
        errors.append("build output is not isolated under release/windows")
    for module in sorted(FORBIDDEN_MODULES):
        if f"--exclude-module {module}" not in build_text:
            errors.append(f"build does not explicitly exclude {module}")
    if "verify_desktop_package.py --exe" not in build_text:
        errors.append("build does not verify the completed EXE archive")

    reachable, sources = _reachable_local_module_sources()
    missing = REQUIRED_MODULES.difference(reachable)
    if missing:
        errors.append("platform entry modules are not reachable: " + ", ".join(sorted(missing)))
    forbidden = FORBIDDEN_MODULES.intersection(reachable)
    if forbidden:
        errors.append("legacy modules are reachable from app.py: " + ", ".join(sorted(forbidden)))
    for module, source in sources.items():
        for marker in FORBIDDEN_SOURCE_MARKERS:
            if marker in source:
                errors.append(f"{module} contains forbidden legacy marker {marker}")
    return errors


def archive_boundary_errors(
    module_names: Iterable[str], sibling_names: Iterable[str]
) -> list[str]:
    modules = set(module_names)
    errors: list[str] = []
    missing = REQUIRED_MODULES.difference(modules)
    if missing:
        errors.append("EXE is missing platform modules: " + ", ".join(sorted(missing)))
    present_forbidden = {
        name
        for name in modules
        if any(name == item or name.startswith(f"{item}.") for item in FORBIDDEN_MODULES)
    }
    if present_forbidden:
        errors.append("EXE contains legacy modules: " + ", ".join(sorted(present_forbidden)))
    unsafe_siblings = {
        name.lower() for name in sibling_names if name.lower() in FORBIDDEN_SIBLINGS
    }
    if unsafe_siblings:
        errors.append(
            "release directory contains legacy configuration files: "
            + ", ".join(sorted(unsafe_siblings))
        )
    return errors


def inspect_executable(path: Path) -> list[str]:
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except ImportError:
        return ["PyInstaller is required to inspect the packaged EXE"]
    if not path.is_file():
        return [f"EXE does not exist: {path}"]
    try:
        archive = CArchiveReader(str(path))
        pyz = archive.open_embedded_archive("PYZ.pyz")
    except Exception:
        return [f"EXE is not a readable PyInstaller archive: {path}"]
    siblings = [item.name for item in path.parent.iterdir() if item != path]
    return archive_boundary_errors(pyz.toc.keys(), siblings)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    try:
        errors = source_boundary_errors()
    except (OSError, UnicodeError, SyntaxError):
        print("desktop-package-error: Cannot inspect desktop package sources")
        return 1
    if args.exe is not None:
        errors.extend(inspect_executable(args.exe.resolve()))
    if errors:
        for error in errors:
            print(f"desktop-package-error: {error}")
        return 1
    suffix = " source-and-archive" if args.exe is not None else " source"
    print(f"desktop-package-ok{suffix} platform-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
