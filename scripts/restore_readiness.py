"""Verify restored internal services while keeping the public edge closed."""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path
import subprocess
import sys
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from scripts.production_docker_environment import (
    ProductionDockerEnvironmentError,
    validate_production_docker_environment as _validate_production_docker_environment,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE_PREFIX = (
    "docker",
    "compose",
    "--project-directory",
    str(REPOSITORY_ROOT),
    "--env-file",
    str(REPOSITORY_ROOT / ".env"),
    "--project-name",
    "email-platform",
    "--file",
    str(REPOSITORY_ROOT / "docker-compose.yml"),
)
CA_FILE = "/run/secrets/internal-tls/ca.crt"
PROBE_CONTAINER = "api"
EDGE_STOP_COMMAND = (*PRODUCTION_COMPOSE_PREFIX, "stop", "edge")
PROBES = (
    "https://api:8443/readyz",
    "https://web:8443/",
    "https://keycloak:9000/health/ready",
    "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
    "https://worker-mail:9101/metrics",
    "https://worker-sub2:9102/metrics",
    "https://prometheus:9090/-/ready",
)
TLS_PROBE_PROGRAM = (
    "import ssl,sys,urllib.request; "
    "context=ssl.create_default_context("
    "cafile='/run/secrets/internal-tls/ca.crt'); "
    "context.minimum_version=ssl.TLSVersion.TLSv1_2; "
    "response=urllib.request.urlopen(sys.argv[1],context=context,timeout=5); "
    "response.getcode()==200 or sys.exit(2); "
    "response.geturl()==sys.argv[1] or sys.exit(3); "
    "response.read(1048576)"
)


def _probe_command(url: str) -> tuple[str, ...]:
    return (
        *PRODUCTION_COMPOSE_PREFIX,
        "exec",
        "-T",
        PROBE_CONTAINER,
        "python",
        "-c",
        TLS_PROBE_PROGRAM,
        url,
    )


class RestoreReadinessError(RuntimeError):
    pass


def restore_contract_errors(
    program: str = TLS_PROBE_PROGRAM,
    probes: Sequence[str] = PROBES,
) -> list[str]:
    """Validate that probes cannot silently downgrade TLS verification."""

    errors: list[str] = []
    if tuple(probes) != PROBES:
        errors.append("restore probes must match the reviewed service HTTPS endpoints")
    for url in probes:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            errors.append(f"restore probe must use HTTPS and a DNS host: {url}")
            continue
        try:
            if ipaddress.ip_address(parsed.hostname).is_loopback:
                errors.append(f"restore probe must not use loopback: {url}")
        except ValueError:
            if parsed.hostname in {"localhost", "localhost.localdomain"}:
                errors.append(f"restore probe must not use loopback: {url}")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            errors.append(f"restore probe URL must not contain credentials or parameters: {url}")

    try:
        tree = ast.parse(program)
    except SyntaxError as exc:
        return [*errors, f"restore TLS probe is invalid Python: {exc}"]
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    contexts = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ssl"
        and node.func.attr == "create_default_context"
    ]
    if len(contexts) != 1 or not any(
        keyword.arg == "cafile"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value == CA_FILE
        for keyword in (contexts[0].keywords if contexts else [])
    ):
        errors.append("restore TLS probe must create one context with the internal CA")

    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    tls12 = any(
        any(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "context"
            and target.attr == "minimum_version"
            for target in assignment.targets
        )
        and isinstance(assignment.value, ast.Attribute)
        and isinstance(assignment.value.value, ast.Attribute)
        and isinstance(assignment.value.value.value, ast.Name)
        and assignment.value.value.value.id == "ssl"
        and assignment.value.value.attr == "TLSVersion"
        and assignment.value.attr == "TLSv1_2"
        for assignment in assignments
    )
    if not tls12:
        errors.append("restore TLS probe must require TLS 1.2 or newer")

    unsafe = any(
        isinstance(node, ast.Attribute)
        and node.attr in {"CERT_NONE", "_create_unverified_context"}
        for node in ast.walk(tree)
    ) or any(
        isinstance(target, ast.Attribute)
        and target.attr in {"check_hostname", "verify_mode"}
        and not (
            target.attr == "check_hostname"
            and isinstance(assignment.value, ast.Constant)
            and assignment.value.value is True
        )
        and not (
            target.attr == "verify_mode"
            and isinstance(assignment.value, ast.Attribute)
            and isinstance(assignment.value.value, ast.Name)
            and assignment.value.value.id == "ssl"
            and assignment.value.attr == "CERT_REQUIRED"
        )
        for assignment in assignments
        for target in assignment.targets
    )
    if unsafe:
        errors.append("restore TLS probe must not disable certificate or hostname verification")

    urlopen = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "urlopen"
    ]
    if len(urlopen) != 1 or not any(
        keyword.arg == "context"
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == "context"
        for keyword in (urlopen[0].keywords if urlopen else [])
    ):
        errors.append("restore HTTPS request must use the verified TLS context")
    if "response.geturl()==sys.argv[1] or sys.exit(3)" not in program:
        errors.append("restore TLS probe must reject redirect host or scheme changes")
    if "response.getcode()==200 or sys.exit(2)" not in program:
        errors.append("restore TLS probe must require HTTP 200")
    return errors


def _run(command: Sequence[str]) -> None:
    subprocess.run(list(command), check=True)


def verify_restored_services(
    runner: Callable[[Sequence[str]], None] = _run,
) -> None:
    try:
        _validate_production_docker_environment()
    except ProductionDockerEnvironmentError as error:
        raise RestoreReadinessError(
            "restore readiness Docker environment preflight failed"
        ) from error
    contract_errors = restore_contract_errors()
    if contract_errors:
        raise RestoreReadinessError("; ".join(contract_errors))
    try:
        runner(EDGE_STOP_COMMAND)
        for url in PROBES:
            runner(_probe_command(url))
        runner(EDGE_STOP_COMMAND)
    except Exception as probe_error:
        try:
            runner(EDGE_STOP_COMMAND)
        except Exception as stop_error:
            raise RestoreReadinessError(
                "restore probe failed and edge closure could not be confirmed"
            ) from stop_error
        raise probe_error


def main() -> int:
    try:
        verify_restored_services()
    except (OSError, subprocess.SubprocessError, RestoreReadinessError) as exc:
        print(f"restore-readiness-error: {exc}", file=sys.stderr)
        return 1
    print("restore-readiness-ok internal-tls=verified edge=stopped production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
