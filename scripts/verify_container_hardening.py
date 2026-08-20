"""Verify hardening flags on runtime services in compose."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
RUNTIME_ROLE_INIT = ROOT / "infra" / "postgres" / "init" / "02-create-platform-runtime-role.sh"


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
        "migrate": {"/tmp"},
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

    migrate = _service(compose, "migrate")
    if migrate is None:
        return _fail("Missing service migrate")
    if migrate.get("command") != ["alembic", "-c", "/app/alembic.ini", "upgrade", "head"]:
        return _fail("migrate must run alembic upgrade head")
    environment = migrate.get("environment", {})
    if not isinstance(environment, dict) or "ALEMBIC_DATABASE_URL" not in environment:
        return _fail("migrate must use ALEMBIC_DATABASE_URL")
    for name in ("api", "worker-mail", "worker-sub2"):
        service = _service(compose, name)
        if service is None:
            return _fail(f"Missing service {name}")
        dependencies = service.get("depends_on", {})
        if not isinstance(dependencies, dict) or dependencies.get("migrate") != {
            "condition": "service_completed_successfully"
        }:
            return _fail(f"{name} must wait for a successful migration")
    postgres = _service(compose, "postgres")
    postgres_environment = postgres.get("environment", {}) if postgres else {}
    if not isinstance(postgres_environment, dict) or not {
        "POSTGRES_APP_USER",
        "POSTGRES_APP_PASSWORD",
    }.issubset(postgres_environment):
        return _fail("postgres must receive the separate runtime role bootstrap values")
    runtime_role_text = RUNTIME_ROLE_INIT.read_text(encoding="utf-8")
    for required in (
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
        "GRANT SELECT, INSERT, UPDATE, DELETE",
        "ALTER DEFAULT PRIVILEGES",
    ):
        if required not in runtime_role_text:
            return _fail(f"runtime database role bootstrap is missing: {required}")
    for forbidden in ("GRANT CREATE", "GRANT TRIGGER", "GRANT ALL"):
        if forbidden in runtime_role_text:
            return _fail(f"runtime database role bootstrap grants forbidden DDL: {forbidden}")
    print("container-hardening-ok migrate-api-workers-web=read-only-no-new-privileges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
