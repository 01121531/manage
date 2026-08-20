"""Verify hardening flags on runtime services in compose."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _service(compose: dict[str, object], name: str) -> dict[str, object] | None:
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return None
    service = services.get(name)
    return service if isinstance(service, dict) else None


def _tmpfs(service: dict[str, object]) -> set[str]:
    raw = service.get("tmpfs", [])
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw}


def _cap_drop(service: dict[str, object]) -> set[str]:
    raw = service.get("cap_drop", [])
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw}


def main() -> int:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    targets = {
        "api": {"/tmp"},
        "worker-mail": {"/tmp"},
        "worker-sub2": {"/tmp"},
        "web": {"/tmp", "/var/run", "/var/cache/nginx"},
    }
    for name, required_tmpfs in targets.items():
        service = _service(compose, name)
        if service is None:
            return _fail(f"Missing service {name}")
        if service.get("read_only") is not True:
            return _fail(f"{name} must be read_only")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            return _fail(f"{name} must set no-new-privileges:true")
        if _cap_drop(service) != {"ALL"}:
            return _fail(f"{name} must drop all capabilities")
        if not required_tmpfs.issubset(_tmpfs(service)):
            return _fail(f"{name} is missing tmpfs mounts: {sorted(required_tmpfs - _tmpfs(service))}")
    print("container-hardening-ok api-workers-web=read-only-no-new-privileges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
