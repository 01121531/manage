"""Execute a release-bound, fail-closed platform rollback."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping, Protocol, Sequence

from scripts.create_container_release_manifest import EXPECTED_IMAGES, load_manifest
from scripts.postgres_maintenance import verify_bundle_release_binding


STOP_SERVICES = ("edge", "api", "worker-mail", "worker-sub2", "web", "keycloak")
BACKEND_SERVICES = ("keycloak", "migrate", "api", "worker-mail", "worker-sub2", "web")
RUNNING_BACKEND_SERVICES = ("keycloak", "api", "worker-mail", "worker-sub2", "web")
RUNTIME_IMAGE_SERVICES = {
    "api": "api",
    "worker-mail": "api",
    "worker-sub2": "api",
    "web": "web",
    "edge": "edge",
}
_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class RollbackError(RuntimeError):
    """A safe rollback invariant was not satisfied."""


class Runner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        capture_output: bool = False,
    ) -> str: ...


class SubprocessRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        capture_output: bool = False,
    ) -> str:
        result = subprocess.run(
            list(command),
            check=True,
            capture_output=capture_output,
            text=True,
            env=dict(env) if env is not None else None,
        )
        return result.stdout if capture_output else ""


@dataclass(frozen=True)
class RollbackPlan:
    tag: str
    commit: str
    migration_head: str
    container_manifest_sha256: str
    backup_dir: Path
    images: dict[str, str]
    signature_identities: dict[str, str]
    signature_issuer: str
    repository: str

    def compose_environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        environment.update(
            {
                "PLATFORM_API_IMAGE": self.images["api"],
                "PLATFORM_WEB_IMAGE": self.images["web"],
                "PLATFORM_EDGE_IMAGE": self.images["edge"],
            }
        )
        return environment


def _manifest_sha256(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RollbackError("container manifest cannot be read") from error
    if not data:
        raise RollbackError("container manifest is empty")
    return hashlib.sha256(data).hexdigest()


def _repository_from_image(image: str, image_name: str) -> str:
    prefix = "ghcr.io/"
    suffix = f"-{image_name}"
    if not image.startswith(prefix) or not image.endswith(suffix):
        raise RollbackError("container image repository is invalid")
    repository = image[len(prefix) : -len(suffix)]
    if repository.count("/") != 1:
        raise RollbackError("container image repository is invalid")
    return repository


def load_rollback_plan(
    container_manifest_path: Path,
    backup_dir: Path,
) -> RollbackPlan:
    manifest = load_manifest(container_manifest_path)
    manifest_sha256 = _manifest_sha256(container_manifest_path)
    images: dict[str, str] = {}
    identities: dict[str, str] = {}
    repositories: set[str] = set()
    for name in EXPECTED_IMAGES:
        metadata = manifest["images"][name]
        images[name] = f"{metadata['image']}@{metadata['digest']}"
        identities[name] = metadata["signature"]["identity"]
        repositories.add(_repository_from_image(metadata["image"], name))
    if len(repositories) != 1:
        raise RollbackError("container images do not belong to one repository")
    repository = repositories.pop()
    expected_identity_prefix = f"https://github.com/{repository}/"
    if any(not identity.startswith(expected_identity_prefix) for identity in identities.values()):
        raise RollbackError("signature identity does not match image repository")

    verify_bundle_release_binding(
        backup_dir,
        release_tag=manifest["tag"],
        release_commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
    )
    return RollbackPlan(
        tag=manifest["tag"],
        commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
        backup_dir=backup_dir,
        images=images,
        signature_identities=identities,
        signature_issuer="https://token.actions.githubusercontent.com",
        repository=repository,
    )


def plan_summary(plan: RollbackPlan) -> dict[str, object]:
    return {
        "schema_version": 1,
        "production_acceptance": False,
        "release_tag": plan.tag,
        "release_commit": plan.commit,
        "migration_head": plan.migration_head,
        "container_manifest_sha256": plan.container_manifest_sha256,
        "images": dict(plan.images),
        "database_bundle": "platform+keycloak",
        "execution_order": [
            "verify-signatures-and-attestations",
            "pull-digests",
            "stop-edge-and-writers",
            "restore-release-bound-dual-database-bundle",
            "start-and-verify-internal-services",
            "start-and-verify-edge",
        ],
    }


def _compose(command: str, *arguments: str) -> list[str]:
    return ["docker", "compose", command, *arguments]


def _verify_supply_chain(plan: RollbackPlan, runner: Runner) -> None:
    for name in EXPECTED_IMAGES:
        image = plan.images[name]
        identity = plan.signature_identities[name]
        common = [
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            plan.signature_issuer,
        ]
        runner.run(["cosign", "verify", *common, image])
        runner.run(
            [
                "cosign",
                "verify-attestation",
                "--type",
                "spdxjson",
                *common,
                image,
            ]
        )
        runner.run(
            [
                "gh",
                "attestation",
                "verify",
                f"oci://{image}",
                "--repo",
                plan.repository,
            ]
        )


def _pull_images(plan: RollbackPlan, runner: Runner) -> None:
    for name in EXPECTED_IMAGES:
        runner.run(["docker", "pull", plan.images[name]])


def _restore_command(
    plan: RollbackPlan,
    *,
    platform_target_db: str,
    keycloak_target_db: str,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "scripts.postgres_maintenance",
        "restore-bundle",
        "--input-dir",
        str(plan.backup_dir),
        "--platform-target-db",
        platform_target_db,
        "--keycloak-target-db",
        keycloak_target_db,
        "--release-tag",
        plan.tag,
        "--release-commit",
        plan.commit,
        "--migration-head",
        plan.migration_head,
        "--container-manifest-sha256",
        plan.container_manifest_sha256,
    ]


def _assert_runtime_image(
    service: str,
    expected_image: str,
    *,
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    container_id = runner.run(
        _compose("ps", "-q", service),
        env=environment,
        capture_output=True,
    ).strip()
    if not container_id or "\n" in container_id:
        raise RollbackError("runtime container identity is invalid")
    actual_image = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", container_id],
        env=environment,
        capture_output=True,
    ).strip()
    if actual_image != expected_image:
        raise RollbackError("runtime image does not match release digest")


def _assert_running_services(
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    output = runner.run(
        _compose("ps", "--status", "running", "--services"),
        env=environment,
        capture_output=True,
    )
    running = {line.strip() for line in output.splitlines() if line.strip()}
    missing = set(RUNNING_BACKEND_SERVICES) - running
    if missing:
        raise RollbackError("required backend services are not running")


def _internal_smoke(runner: Runner, environment: Mapping[str, str]) -> None:
    checks = (
        (
            "api",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=5).read()",
        ),
        (
            "worker-mail",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9101/metrics', timeout=5).read()",
        ),
        (
            "worker-sub2",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9102/metrics', timeout=5).read()",
        ),
    )
    for service, program in checks:
        runner.run(
            _compose("exec", "-T", service, "python", "-c", program),
            env=environment,
        )


def _external_smoke(domain: str, runner: Runner) -> None:
    program = (
        "import sys,urllib.request; "
        "urllib.request.urlopen(sys.argv[1], timeout=10).read(1048576)"
    )
    runner.run([sys.executable, "-c", program, f"https://{domain}/readyz"])
    runner.run(
        [
            sys.executable,
            "-c",
            program,
            f"https://identity.{domain}/realms/email-platform/.well-known/openid-configuration",
        ]
    )


def _validate_execution_inputs(
    *,
    platform_target_db: str,
    keycloak_target_db: str,
    domain: str,
) -> None:
    for database in (platform_target_db, keycloak_target_db):
        if _DATABASE_NAME.fullmatch(database) is None:
            raise RollbackError("target database name is invalid")
    normalized_domain = domain.lower()
    labels = normalized_domain.split(".")
    if (
        not normalized_domain
        or len(normalized_domain) > 253
        or len(labels) < 2
        or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise RollbackError("platform domain is invalid")


def execute_rollback(
    plan: RollbackPlan,
    *,
    confirm_release_tag: str,
    platform_target_db: str,
    keycloak_target_db: str,
    domain: str,
    runner: Runner | None = None,
) -> None:
    if confirm_release_tag != plan.tag:
        raise RollbackError("release confirmation does not match rollback plan")
    _validate_execution_inputs(
        platform_target_db=platform_target_db,
        keycloak_target_db=keycloak_target_db,
        domain=domain,
    )
    command_runner = runner or SubprocessRunner()
    environment = plan.compose_environment()

    _verify_supply_chain(plan, command_runner)
    _pull_images(plan, command_runner)
    command_runner.run(_compose("stop", *STOP_SERVICES), env=environment)
    command_runner.run(
        _restore_command(
            plan,
            platform_target_db=platform_target_db,
            keycloak_target_db=keycloak_target_db,
        ),
        env=environment,
    )
    command_runner.run(
        _compose("up", "-d", "--no-build", "--pull", "never", *BACKEND_SERVICES),
        env=environment,
    )
    _assert_running_services(command_runner, environment)
    for service, image_name in RUNTIME_IMAGE_SERVICES.items():
        if service == "edge":
            continue
        _assert_runtime_image(
            service,
            plan.images[image_name],
            runner=command_runner,
            environment=environment,
        )
    _internal_smoke(command_runner, environment)

    edge_verified = False
    try:
        command_runner.run(
            _compose("up", "-d", "--no-build", "--pull", "never", "edge"),
            env=environment,
        )
        _assert_runtime_image(
            "edge",
            plan.images["edge"],
            runner=command_runner,
            environment=environment,
        )
        _external_smoke(domain, command_runner)
        edge_verified = True
    finally:
        if not edge_verified:
            try:
                command_runner.run(_compose("stop", "edge"), env=environment)
            except (OSError, subprocess.SubprocessError):
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "execute"):
        command = subparsers.add_parser(name)
        command.add_argument("--container-manifest", type=Path, required=True)
        command.add_argument("--backup-dir", type=Path, required=True)
        if name == "execute":
            command.add_argument("--confirm-release-tag", required=True)
            command.add_argument("--platform-target-db", default="email_platform")
            command.add_argument("--keycloak-target-db", default="keycloak")
            command.add_argument("--domain", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        plan = load_rollback_plan(options.container_manifest, options.backup_dir)
        if options.command == "plan":
            print(json.dumps(plan_summary(plan), sort_keys=True))
        else:
            execute_rollback(
                plan,
                confirm_release_tag=options.confirm_release_tag,
                platform_target_db=options.platform_target_db,
                keycloak_target_db=options.keycloak_target_db,
                domain=options.domain,
            )
            print("rollback-release-ok")
        return 0
    except (RollbackError, ValueError, OSError, subprocess.SubprocessError):
        print("rollback-release-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
