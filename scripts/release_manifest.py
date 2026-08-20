"""Generate and verify a release manifest for the compose stack."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
BACKEND_INIT = ROOT / "platform" / "__init__.py"
FRONTEND_PACKAGE = ROOT / "frontend" / "package.json"
MIGRATIONS = ROOT / "platform" / "migrations" / "versions"
COMPOSE = ROOT / "docker-compose.yml"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_backend_version() -> str:
    text = BACKEND_INIT.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None:
        raise RuntimeError("Unable to read backend version")
    return match.group(1)


def _read_frontend_version() -> str:
    package = _read_json(FRONTEND_PACKAGE)
    version = package.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError("Unable to read frontend version")
    return version.strip()


def _read_migration_head() -> str:
    candidates: list[tuple[str, str]] = []
    for path in MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.py"):
        name = path.stem
        prefix, _, _ = name.partition("_")
        if prefix.isdigit():
            candidates.append((prefix, name))
    if not candidates:
        raise RuntimeError("No migration files were found")
    candidates.sort()
    return candidates[-1][1]


def build_release_manifest() -> dict[str, Any]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose.get("services", {})
    if not isinstance(services, dict):
        raise RuntimeError("Compose services block is invalid")
    compose_images: dict[str, str] = {}
    for service_name in (
        "migrate",
        "api",
        "worker-mail",
        "worker-sub2",
        "web",
        "edge",
        "prometheus",
    ):
        service = services.get(service_name)
        if not isinstance(service, dict):
            raise RuntimeError(f"Missing compose service: {service_name}")
        image = service.get("image")
        if not isinstance(image, str) or not image.strip():
            raise RuntimeError(f"Service {service_name} is missing an image tag")
        compose_images[service_name] = image.strip()
    backend_version = _read_backend_version()
    frontend_version = _read_frontend_version()
    migration_head = _read_migration_head()
    release_id = backend_version
    return {
        "release_id": release_id,
        "backend_version": backend_version,
        "frontend_version": frontend_version,
        "migration_head": migration_head,
        "compose_images": compose_images,
        "rollback_policy": (
            "Use scripts.rollback_release with an immutable container manifest "
            "and its release-bound platform plus Keycloak backup bundle."
        ),
    }


def load_manifest(path: Path) -> dict[str, Any]:
    return _read_json(path)


def verify_manifest(manifest: dict[str, Any]) -> list[str]:
    expected = build_release_manifest()
    errors: list[str] = []
    for key in ("release_id", "backend_version", "frontend_version", "migration_head", "rollback_policy"):
        if manifest.get(key) != expected.get(key):
            errors.append(f"{key} mismatch")
    compose_images = manifest.get("compose_images")
    if compose_images != expected["compose_images"]:
        errors.append("compose_images mismatch")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m scripts.release_manifest")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="Print the current release manifest.")
    snapshot_parser.add_argument("--output", help="Optional path to write the manifest JSON.")

    verify_parser = subparsers.add_parser("verify", help="Verify a release manifest matches the repo.")
    verify_parser.add_argument("--manifest", required=True, help="Path to the manifest JSON.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "snapshot":
        manifest = build_release_manifest()
        rendered = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            output = Path(args.output)
            output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    if args.command == "verify":
        manifest = load_manifest(Path(args.manifest))
        errors = verify_manifest(manifest)
        if errors:
            print("Release manifest verification failed: " + ", ".join(errors))
            return 1
        print("release-manifest-ok locked-release-state")
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
