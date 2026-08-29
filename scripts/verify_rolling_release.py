"""Verify the repository's Web/API blue-green release contract."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import load_unique_yaml_with_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text
    from external_yaml import load_unique_yaml_with_text


ROOT = Path(__file__).resolve().parents[1]
MAX_ROLLING_ASSET_BYTES = 64 * 1024
ROLLING_ASSET_READ_ERROR = "Cannot inspect rolling release assets"


def verification_errors(root: Path = ROOT) -> list[str]:
    required = {
        "docker-compose.rolling.yml": (
            "PLATFORM_ROLLING_WORKER_MAIL_IMAGE",
            "PLATFORM_ROLLING_WORKER_SUB2_IMAGE",
            "api-green:",
            "web-green:",
            "PLATFORM_ROLLING_MIGRATION_IMAGE",
            "PLATFORM_ROLLING_ROUTE_DIR",
            "create_host_path: false",
            "https://api-green:8443/readyz",
        ),
        "infra/nginx/email-platform.conf.template": (
            "include /etc/nginx/edge-routing/active-slot.conf;",
            "proxy_pass https://active_api/readyz;",
            "proxy_pass https://active_api/releasez;",
            "proxy_pass https://active_web;",
            "proxy_ssl_name $active_api_tls_name;",
            "proxy_ssl_name $active_web_tls_name;",
        ),
        "scripts/rolling_release.py": (
            '"rolling_release": True',
            '"production_acceptance": False',
            '"source_retained_after_switch": True',
            "os.replace(temporary, path)",
            '"nginx", "-t", "-q"',
            '"nginx", "-s", "reload"',
            "release_control_lock()",
            "_validate_route_dir(plan.route_dir, plan.active_slot)",
            '("worker-mail", "worker_mail")',
            '("worker-sub2", "worker_sub2")',
            'service, plan.source.images["api"]',
            '"run", "--rm", "--no-deps", "migrate"',
            '"up", "-d", "--no-deps", "--no-build", "--pull", "never"',
            '"--evidence-output"',
            "RollingReleaseEvidenceRecorder",
            '_record_workers(plan, "before"',
            '_record_workers(plan, "after"',
            "evidence.public_releasez(",
            "_publish_evidence(plan, evidence, evidence_output)",
            '"--target-intake-manifest"',
            '"--target-environment"',
            "load_phase_checkpoint(",
            "MAX_ROUTE_BYTES = 16 * 1024",
            "read_stable_bytes_with_metadata(",
            "_read_route_snapshot(plan.route_dir / ROUTE_NAME)",
            'RollingReleaseError("active rolling route changed before switch")',
            "started_at=checkpoint.evaluated_at",
        ),
        "scripts/rolling_release_evidence.py": (
            'EVIDENCE_KIND = "web_api_rolling_execution"',
            'TERMINAL_COMPLETE = "complete_source_retained"',
            'TERMINAL_SWITCHED_BACK = "switched_back"',
            'TERMINAL_ROUTE_UNCONFIRMED = "route_unconfirmed"',
            'TERMINAL_PRE_SWITCH_FAILED = "pre_switch_failed"',
            '"production_acceptance": False',
            '"payload_sha256"',
            '"--expected-source-container-manifest-sha256"',
            '"--expected-target-container-manifest-sha256"',
            '"target_intake"',
            '"--expected-target-environment"',
            '"--expected-target-intake-manifest-sha256"',
            '"--expected-target-intake-requirements-sha256"',
            "prepare_write_once_file",
            "publish_write_once_file(temporary_path, destination)",
        ),
        "scripts/deploy_release.py": (
            '"rolling_release": False',
            '_compose("stop", "edge")',
            "release_control_lock()",
        ),
        "scripts/rollback_release.py": ("release_control_lock()",),
        "platform/migrations/versions/0024_schema_compatibility.py": (
            "platform_schema_compatibility",
            "minimum_app_revision",
        ),
    }
    errors: list[str] = []
    rolling_compose = None
    texts: dict[str, str] = {}
    for name, markers in required.items():
        path = root / name
        if not path.is_file():
            errors.append(f"missing rolling release asset: {name}")
            continue
        if name == "docker-compose.rolling.yml":
            try:
                rolling_compose, text = load_unique_yaml_with_text(path)
            except (OSError, UnicodeError):
                return [ROLLING_ASSET_READ_ERROR]
            except yaml.YAMLError:
                continue
        else:
            try:
                text = load_stable_text(
                    path,
                    max_bytes=MAX_ROLLING_ASSET_BYTES,
                )
            except (OSError, UnicodeError):
                return [ROLLING_ASSET_READ_ERROR]
            texts[name] = text
        errors.extend(
            f"{name} is missing rolling control: {marker}"
            for marker in markers
            if marker not in text
        )
    blue = root / "infra/nginx/slots/blue.conf"
    green = root / "infra/nginx/slots/green.conf"
    for name, path, slot_services in (
        ("infra/nginx/slots/blue.conf", blue, ("api:8443", "web:8443")),
        (
            "infra/nginx/slots/green.conf",
            green,
            ("api-green:8443", "web-green:8443"),
        ),
    ):
        if not path.is_file():
            errors.append(f"missing canonical route: {path.name}")
            continue
        try:
            text = load_stable_text(
                path,
                max_bytes=MAX_ROLLING_ASSET_BYTES,
            )
        except (OSError, UnicodeError):
            return [ROLLING_ASSET_READ_ERROR]
        texts[name] = text
        if any(service not in text for service in slot_services):
            errors.append(f"canonical route pair is incomplete: {path.name}")
        if "${" in text:
            errors.append(f"canonical route must not interpolate input: {path.name}")
    edge_name = "infra/nginx/email-platform.conf.template"
    rolling_name = "scripts/rolling_release.py"
    if edge_name not in texts or rolling_name not in texts:
        return errors
    edge = texts["infra/nginx/email-platform.conf.template"]
    if "proxy_pass https://api:8443" in edge or "proxy_pass https://web:8443" in edge:
        errors.append("edge bypasses the atomic active-slot pair")
    rolling_source = texts["scripts/rolling_release.py"]
    try:
        rolling_tree = ast.parse(rolling_source)
    except SyntaxError:
        errors.append("rolling executor is not valid Python")
        return errors
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_bytes"
        for node in ast.walk(rolling_tree)
    ):
        errors.append("rolling route reads must use the bounded stable snapshot")
    execute_locked = next(
        (
            node
            for node in rolling_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_execute_locked"
        ),
        None,
    )
    execute = next(
        (
            node
            for node in rolling_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "execute_rolling_release"
        ),
        None,
    )
    if execute is None or not execute.body:
        errors.append("rolling executor is missing its public execution body")
    else:
        capture = execute.body[0] if execute.body else None
        first = execute.body[1] if len(execute.body) > 1 else None
        intake_calls = [
            node
            for node in (ast.walk(first) if isinstance(first, ast.AST) else ())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "load_phase_checkpoint"
        ]
        keywords = (
            {keyword.arg: keyword.value for keyword in intake_calls[0].keywords}
            if len(intake_calls) == 1
            else {}
        )
        arguments = {argument.arg for argument in execute.args.kwonlyargs}
        if not (
            isinstance(first, ast.Try)
            and isinstance(capture, ast.Assign)
            and len(capture.targets) == 1
            and isinstance(capture.targets[0], ast.Name)
            and capture.targets[0].id == "release_started_at"
            and len(intake_calls) == 1
            and isinstance(keywords.get("through_phase"), ast.Constant)
            and keywords["through_phase"].value == 0
            and isinstance(keywords.get("evaluated_at"), ast.Name)
            and keywords["evaluated_at"].id == "release_started_at"
            and {"target_intake_manifest", "target_environment"}.issubset(arguments)
            and intake_calls[0].lineno
            < min(
                (
                    node.lineno
                    for node in ast.walk(execute)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "prepare_evidence_output"
                ),
                default=0,
            )
        ):
            errors.append(
                "rolling executor must validate the strict Phase 0 target intake first"
            )
    if execute_locked is None or not execute_locked.body:
        errors.append("rolling executor is missing its locked execution body")
    else:
        first = execute_locked.body[0]
        if not (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Call)
            and isinstance(first.value.func, ast.Name)
            and first.value.func.id == "_validate_route_dir"
        ):
            errors.append("rolling executor must revalidate the active route first under lock")
    if "switched = route_path.read_bytes()" in rolling_source:
        errors.append("rolling executor must not treat an unauthenticated target route as resumable")
    if rolling_compose is None:
        errors.append("rolling Compose is not valid YAML")
        return errors
    services = rolling_compose.get("services", {}) if isinstance(rolling_compose, dict) else {}
    expected_tls = {
        "api-green": {
            "/run/secrets/internal-tls/ca.crt": "PLATFORM_INTERNAL_CA_FILE",
            "/run/secrets/internal-tls/tls.crt": "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
            "/run/secrets/internal-tls/tls.key": "PLATFORM_ROLLING_GREEN_API_KEY_FILE",
        },
        "web-green": {
            "/run/secrets/internal-tls/ca.crt": "PLATFORM_INTERNAL_CA_FILE",
            "/run/secrets/internal-tls/tls.crt": "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
            "/run/secrets/internal-tls/tls.key": "PLATFORM_ROLLING_GREEN_WEB_KEY_FILE",
        },
    }
    for service_name, mounts in expected_tls.items():
        service = services.get(service_name, {}) if isinstance(services, dict) else {}
        volumes = service.get("volumes", []) if isinstance(service, dict) else []
        by_target = {
            volume.get("target"): volume
            for volume in volumes
            if isinstance(volume, dict) and isinstance(volume.get("target"), str)
        }
        for target, variable in mounts.items():
            volume = by_target.get(target)
            source = volume.get("source") if isinstance(volume, dict) else None
            bind = volume.get("bind") if isinstance(volume, dict) else None
            if (
                not isinstance(source, str)
                or not source.startswith("${" + variable + ":")
                or volume.get("read_only") is not True
                or not isinstance(bind, dict)
                or bind.get("create_host_path") is not False
            ):
                errors.append(
                    f"{service_name} green TLS mount is not exact and read-only: {target}"
                )
    return errors


def main() -> int:
    errors = verification_errors()
    if errors:
        for error in errors:
            print(f"rolling-release-error: {error}", file=sys.stderr)
        return 1
    print("rolling-release-ok web-api-blue-green-preflight production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
