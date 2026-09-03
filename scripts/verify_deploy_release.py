"""Verify immutable forward-deployment assets and fail-closed command ordering."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import parse_unique_yaml, read_stable_yaml_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text
    from external_yaml import parse_unique_yaml, read_stable_yaml_text


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DEV_COMPOSE = ROOT / "docker-compose.dev.yml"
ENV_EXAMPLE = ROOT / ".env.example"
DEV_ENV_EXAMPLE = ROOT / ".env.development.example"
DEPLOY_SCRIPT = ROOT / "scripts" / "deploy_release.py"
UPSTREAM_SCAN_SCRIPT = ROOT / "scripts" / "scan_third_party_images.py"

PRODUCTION_IMAGES = {
    "migrate": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "api": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "worker-mail": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "worker-sub2": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "web": "${PLATFORM_WEB_IMAGE:?set immutable PLATFORM_WEB_IMAGE in .env}",
    "edge": "${PLATFORM_EDGE_IMAGE:?set immutable PLATFORM_EDGE_IMAGE in .env}",
}
THIRD_PARTY_IMAGES = {
    "postgres": "postgres@sha256:${POSTGRES_IMAGE_SHA256:?set reviewed 64-hex POSTGRES_IMAGE_SHA256 in .env}",
    "redis": "redis@sha256:${REDIS_IMAGE_SHA256:?set reviewed 64-hex REDIS_IMAGE_SHA256 in .env}",
    "keycloak": "quay.io/keycloak/keycloak@sha256:${KEYCLOAK_IMAGE_SHA256:?set reviewed 64-hex KEYCLOAK_IMAGE_SHA256 in .env}",
    "alertmanager": "prom/alertmanager@sha256:${ALERTMANAGER_IMAGE_SHA256:?set reviewed 64-hex ALERTMANAGER_IMAGE_SHA256 in .env}",
    "prometheus": "prom/prometheus@sha256:${PROMETHEUS_IMAGE_SHA256:?set reviewed 64-hex PROMETHEUS_IMAGE_SHA256 in .env}",
}
DEV_BUILDS = {
    "migrate": "infra/Dockerfile",
    "api": "infra/Dockerfile",
    "worker-mail": "infra/Dockerfile",
    "worker-sub2": "infra/Dockerfile",
    "web": "infra/frontend.Dockerfile",
    "edge": "infra/edge.Dockerfile",
}
DEV_IMAGES = {
    "PLATFORM_API_IMAGE": "email-platform-api:local",
    "PLATFORM_WEB_IMAGE": "email-platform-web:local",
    "PLATFORM_EDGE_IMAGE": "email-platform-edge:local",
}
REUSED_ROLLBACK_CONTROLS = {
    "_assert_operational_services",
    "_assert_release_checkout",
    "_assert_running_services",
    "_assert_runtime_image",
    "_external_smoke",
    "_internal_smoke",
    "_pull_images",
    "_verify_supply_chain",
}
ROLLBACK_PLAN_LOADER = "load_rollback_plan"
ROLLBACK_CLI_FLAGS = {
    "--rollback-container-manifest",
    "--rollback-backup-dir",
    "--rollback-key-file",
    "--evidence-output",
}
EVIDENCE_IMPORTS = {
    "DeploymentReleaseEvidenceError",
    "DeploymentReleaseEvidenceRecorder",
    "TERMINAL_EDGE_CLOSED_FAILURE",
    "TERMINAL_EDGE_UNCONFIRMED",
    "TERMINAL_PREFLIGHT_FAILED",
    "TERMINAL_SUCCEEDED",
    "prepare_evidence_output",
}
VAULT_DEV_IMAGE = "hashicorp/vault:1.18"
UPSTREAM_SCAN_INVENTORY = (
    ("postgres", "postgres", "POSTGRES_IMAGE_SHA256"),
    ("redis", "redis", "REDIS_IMAGE_SHA256"),
    ("keycloak", "quay.io/keycloak/keycloak", "KEYCLOAK_IMAGE_SHA256"),
    ("alertmanager", "prom/alertmanager", "ALERTMANAGER_IMAGE_SHA256"),
    ("prometheus", "prom/prometheus", "PROMETHEUS_IMAGE_SHA256"),
)
UPSTREAM_TRIVY_COMMAND = (
    "trivy",
    "image",
    "--exit-code",
    "1",
    "--ignore-unfixed=false",
    "--severity",
    "HIGH,CRITICAL",
    "--scanners",
    "vuln",
    "--pkg-types",
    "os,library",
    "--format",
    "sarif",
)


def _env_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _literal_strings(call: ast.Call) -> list[str]:
    return [
        argument.value
        for argument in call.args
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
    ]


def _compose_calls(nodes: Iterable[ast.AST]) -> list[tuple[int, tuple[str, ...]]]:
    calls: list[tuple[int, tuple[str, ...]]] = []
    for node in nodes:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and _call_name(child) == "_compose":
                calls.append((child.lineno, tuple(_literal_strings(child))))
    return sorted(set(calls))


def _literal_assignment(module: ast.Module, name: str) -> object:
    assignment = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ),
        None,
    )
    if assignment is None:
        return None
    try:
        return ast.literal_eval(assignment.value)
    except (ValueError, TypeError):
        return None


def _upstream_scan_errors(source: str) -> list[str]:
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        return [f"upstream scan script is invalid Python: {error}"]
    errors: list[str] = []
    if _literal_assignment(module, "THIRD_PARTY_IMAGES") != UPSTREAM_SCAN_INVENTORY:
        errors.append("upstream scan must use the fixed five-image inventory")
    if _literal_assignment(module, "_TRIVY_COMMAND") != UPSTREAM_TRIVY_COMMAND:
        errors.append("upstream scan Trivy command must fail closed on HIGH/CRITICAL")
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "scan_third_party_images"
        ),
        None,
    )
    call_names = {
        _call_name(node)
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
    } if function is not None else set()
    if function is None or "TemporaryDirectory" not in call_names:
        errors.append("upstream scan reports require an automatically cleaned temporary directory")
    if "run" not in call_names:
        errors.append("upstream scan must invoke Trivy through the reviewed runner")
    runner_calls = (
        [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "runner"
            and node.func.attr == "run"
        ]
        if function is not None
        else []
    )
    if not (
        len(runner_calls) == 1
        and len([keyword for keyword in runner_calls[0].keywords if keyword.arg == "env"])
        == 1
        and isinstance(
            next(keyword.value for keyword in runner_calls[0].keywords if keyword.arg == "env"),
            ast.Name,
        )
        and next(
            keyword.value for keyword in runner_calls[0].keywords if keyword.arg == "env"
        ).id
        == "environment"
    ):
        errors.append("upstream scan runner must receive the validated environment")
    if "_validate_sarif" not in call_names:
        errors.append("upstream scan report binding must be validated")
    return errors


def _executor_errors(source: str) -> list[str]:
    shared_start_errors = (
        []
        if "started_at=checkpoint.evaluated_at" in source
        else ["deployment evidence must share the Phase 0 evaluation instant"]
    )
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        return [*shared_start_errors, f"deploy_release.py is invalid Python: {error}"]
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "execute_deployment"
        ),
        None,
    )
    if function is None:
        return ["deploy_release.py is missing execute_deployment"]
    loader = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "load_deployment_plan"
        ),
        None,
    )

    errors: list[str] = list(shared_start_errors)
    rollback_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.rollback_release"
        for alias in node.names
    }
    missing_reuse = sorted(REUSED_ROLLBACK_CONTROLS - rollback_imports)
    if missing_reuse:
        errors.append("deployment must reuse reviewed rollback controls: " + ", ".join(missing_reuse))
    if ROLLBACK_PLAN_LOADER not in rollback_imports:
        errors.append("deployment must reuse the reviewed rollback plan loader")
    if "_validated_third_party_image_environment" not in rollback_imports:
        errors.append("deployment must reuse third-party digest validation")
    if not {"PRODUCTION_COMPOSE", "PRODUCTION_ENV_FILE"}.issubset(rollback_imports):
        errors.append("deployment preflights must use the fixed production Compose inventory")
    scan_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.scan_third_party_images"
        for alias in node.names
    }
    if not {"ThirdPartyScanError", "scan_third_party_images"}.issubset(scan_imports):
        errors.append("deployment must import the upstream image scan gate")
    edge_tls_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.validate_edge_tls"
        for alias in node.names
    }
    if not {"EdgeTlsError", "validate_edge_tls"}.issubset(edge_tls_imports):
        errors.append("deployment must import the public edge TLS preflight")
    vault_sink_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.vault_token_sinks"
        for alias in node.names
    }
    if not {"VaultTokenSinkError", "validate_vault_token_sinks"}.issubset(
        vault_sink_imports
    ):
        errors.append("deployment must import the shared Vault token sink preflight")
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "validate_vault_token_sinks"
        for node in module.body
    ) or any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "validate_vault_token_sinks"
        for node in ast.walk(module)
    ):
        errors.append("deployment must not replace the shared Vault token sink preflight")
    sub2_egress_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.sub2_egress_preflight"
        for alias in node.names
    }
    if not {
        "Sub2EgressPreflightError",
        "validate_sub2_egress_policy",
    }.issubset(sub2_egress_imports):
        errors.append("deployment must import the shared Sub2 egress preflight")
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "validate_sub2_egress_policy"
        for node in module.body
    ) or any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "validate_sub2_egress_policy"
        for node in ast.walk(module)
    ):
        errors.append("deployment must not replace the shared Sub2 egress preflight")
    intake_imported = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "scripts.target_intake_preflight"
        and any(alias.name == "load_phase_checkpoint" for alias in node.names)
        for node in module.body
    )
    serialized = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_serialized_release_control"
        ),
        None,
    )
    serialized_calls = (
        [
            node
            for node in ast.walk(serialized)
            if isinstance(node, ast.Call)
        ]
        if serialized is not None
        else []
    )
    intake_calls = [
        node
        for node in serialized_calls
        if _call_name(node) == "load_phase_checkpoint"
    ]
    intake_keywords = (
        {keyword.arg: keyword.value for keyword in intake_calls[0].keywords}
        if len(intake_calls) == 1
        else {}
    )
    serialized_lines = {
        name: min(
            (
                node.lineno
                for node in serialized_calls
                if _call_name(node) == name
            ),
            default=None,
        )
        for name in (
            "load_phase_checkpoint",
            "prepare_evidence_output",
            "release_control_lock",
        )
    }
    capture_lines = [
        node.lineno
        for node in ast.walk(serialized)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "release_started_at"
            for target in node.targets
        )
    ] if serialized is not None else []
    if not (
        intake_imported
        and len(intake_calls) == 1
        and isinstance(intake_keywords.get("through_phase"), ast.Constant)
        and intake_keywords["through_phase"].value == 0
        and isinstance(intake_keywords.get("environment"), ast.Subscript)
        and isinstance(intake_keywords.get("evaluated_at"), ast.Name)
        and intake_keywords["evaluated_at"].id == "release_started_at"
        and len(capture_lines) == 1
        and capture_lines[0] < serialized_lines["load_phase_checkpoint"]
        and all(value is not None for value in serialized_lines.values())
        and list(serialized_lines.values()) == sorted(serialized_lines.values())
    ):
        errors.append(
            "deployment must validate the strict Phase 0 target intake before evidence and lock access"
        )
    evidence_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.deploy_release_evidence"
        for alias in node.names
    }
    if not EVIDENCE_IMPORTS.issubset(evidence_imports):
        errors.append("deployment must use the reviewed terminal evidence contract")
    if loader is None or not any(
        isinstance(node, ast.Call) and _call_name(node) == ROLLBACK_PLAN_LOADER
        for node in ast.walk(loader)
    ):
        errors.append("deployment plan must load an authenticated rollback point")
    plan_class = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.ClassDef) and node.name == "DeploymentPlan"
        ),
        None,
    )
    compose_environment = next(
        (
            node
            for node in (plan_class.body if plan_class is not None else [])
            if isinstance(node, ast.FunctionDef)
            and node.name == "compose_environment"
        ),
        None,
    )
    if compose_environment is None or not any(
        isinstance(node, ast.Call)
        and _call_name(node) == "_validated_third_party_image_environment"
        for node in ast.walk(compose_environment)
    ):
        errors.append("deployment Compose environment must validate third-party digests")
    validator_calls = (
        [
            node
            for node in ast.walk(compose_environment)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_validated_third_party_image_environment"
        ]
        if compose_environment is not None
        else []
    )
    if not (
        len(validator_calls) == 1
        and len(validator_calls[0].args) == 1
        and isinstance(validator_calls[0].args[0], ast.Attribute)
        and isinstance(validator_calls[0].args[0].value, ast.Name)
        and validator_calls[0].args[0].value.id == "os"
        and validator_calls[0].args[0].attr == "environ"
    ):
        errors.append("deployment must validate the caller process environment")
    manifest_imported = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "scripts.create_container_release_manifest"
        and any(alias.name == "load_manifest" for alias in node.names)
        for node in module.body
    )
    if not manifest_imported:
        errors.append("deployment must reuse the strict container release manifest loader")

    named_calls = sorted(
        (node.lineno, _call_name(node))
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
    )
    call_lines: dict[str, list[int]] = {}
    for line, name in named_calls:
        if name is not None:
            call_lines.setdefault(name, []).append(line)
    for name in REUSED_ROLLBACK_CONTROLS:
        if name not in call_lines:
            errors.append(f"deployment executor is missing {name}")
    compose_environment_preflight = call_lines.get("compose_environment", [None])[0]
    runner_access = min(
        (
            node.lineno
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and any(
                isinstance(child, ast.Name) and child.id == "command_runner"
                for child in ast.walk(node)
            )
        ),
        default=None,
    )
    if not (
        compose_environment_preflight is not None
        and runner_access is not None
        and compose_environment_preflight < runner_access
    ):
        errors.append(
            "deployment Docker target environment preflight must precede every runner access"
        )

    edge_tls_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == "validate_edge_tls"
    ]
    edge_tls_preflight = edge_tls_calls[0].lineno if len(edge_tls_calls) == 1 else None
    if not (
        len(edge_tls_calls) == 1
        and len(edge_tls_calls[0].args) == 2
        and isinstance(edge_tls_calls[0].args[0], ast.Name)
        and edge_tls_calls[0].args[0].id == "PRODUCTION_ENV_FILE"
        and isinstance(edge_tls_calls[0].args[1], ast.Name)
        and edge_tls_calls[0].args[1].id == "domain"
    ):
        errors.append(
            "deployment public edge TLS preflight must use the fixed env and requested domain"
        )

    vault_sink_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _call_name(node) == "validate_vault_token_sinks"
    ]
    vault_sink_calls.sort(key=lambda node: node.lineno)
    vault_sink_lines = (
        [node.lineno for node in vault_sink_calls]
        if len(vault_sink_calls) == 2
        and all(
            len(node.args) == 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "PRODUCTION_ENV_FILE"
            and isinstance(node.args[1], ast.Name)
            and node.args[1].id == "PRODUCTION_COMPOSE"
            and not node.keywords
            for node in vault_sink_calls
        )
        else []
    )
    if len(vault_sink_lines) != 2:
        errors.append(
            "deployment must run the exact shared Vault token sink preflight twice"
        )
    sub2_egress_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _call_name(node) == "validate_sub2_egress_policy"
    ]
    sub2_egress_line = (
        sub2_egress_calls[0].lineno
        if len(sub2_egress_calls) == 1
        and len(sub2_egress_calls[0].args) == 1
        and isinstance(sub2_egress_calls[0].args[0], ast.Name)
        and sub2_egress_calls[0].args[0].id == "PRODUCTION_ENV_FILE"
        and not sub2_egress_calls[0].keywords
        else None
    )
    if sub2_egress_line is None:
        errors.append("deployment must run the exact shared Sub2 egress preflight")

    checkout_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == "_assert_release_checkout"
    ]
    checkout = checkout_calls[0] if len(checkout_calls) == 1 else None
    checkout_keywords = {
        keyword.arg: keyword.value
        for keyword in (checkout.keywords if checkout is not None else [])
    }
    if not (
        checkout is not None
        and checkout.args
        and isinstance(checkout.args[0], ast.Attribute)
        and isinstance(checkout.args[0].value, ast.Name)
        and checkout.args[0].value.id == "plan"
        and checkout.args[0].attr == "commit"
        and isinstance(checkout_keywords.get("runner"), ast.Name)
        and checkout_keywords["runner"].id == "command_runner"
        and isinstance(checkout_keywords.get("environment"), ast.Name)
        and checkout_keywords["environment"].id == "environment"
        and isinstance(checkout_keywords.get("shell_environment"), ast.Attribute)
        and isinstance(checkout_keywords["shell_environment"].value, ast.Name)
        and checkout_keywords["shell_environment"].value.id == "os"
        and checkout_keywords["shell_environment"].attr == "environ"
    ):
        errors.append("deployment checkout preflight must verify plan.commit")

    direct_compose = [
        node
        for node in ast.walk(module)
        if isinstance(node, (ast.List, ast.Tuple))
        and len(node.elts) >= 2
        and all(isinstance(item, ast.Constant) for item in node.elts[:2])
        and [item.value for item in node.elts[:2]] == ["docker", "compose"]
    ]
    if direct_compose:
        errors.append("deployment must not bypass the pinned Compose helper")

    supply_calls = sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and _call_name(node) == "_verify_supply_chain"
        ),
        key=lambda node: node.lineno,
    )
    if not (
        len(supply_calls) == 2
        and len(supply_calls[0].args) == 3
        and isinstance(supply_calls[0].args[0], ast.Attribute)
        and isinstance(supply_calls[0].args[0].value, ast.Name)
        and supply_calls[0].args[0].value.id == "plan"
        and supply_calls[0].args[0].attr == "rollback"
        and isinstance(supply_calls[0].args[1], ast.Name)
        and supply_calls[0].args[1].id == "command_runner"
        and isinstance(supply_calls[0].args[2], ast.Name)
        and supply_calls[0].args[2].id == "rollback_environment"
        and len(supply_calls[1].args) == 3
        and isinstance(supply_calls[1].args[0], ast.Name)
        and supply_calls[1].args[0].id == "plan"
        and isinstance(supply_calls[1].args[1], ast.Name)
        and supply_calls[1].args[1].id == "command_runner"
        and isinstance(supply_calls[1].args[2], ast.Name)
        and supply_calls[1].args[2].id == "environment"
    ):
        errors.append(
            "deployment supply-chain checks must receive only their validated environments"
        )
    rollback_supply = next(
        (
            node.lineno
            for node in supply_calls
            if node.args
            and isinstance(node.args[0], ast.Attribute)
            and isinstance(node.args[0].value, ast.Name)
            and node.args[0].value.id == "plan"
            and node.args[0].attr == "rollback"
        ),
        None,
    )
    target_supply = next(
        (
            node.lineno
            for node in supply_calls
            if node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "plan"
        ),
        None,
    )
    current_runtime_calls = sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_assert_runtime_image"
            and any(
                isinstance(child, ast.Attribute)
                and child.attr == "rollback"
                and isinstance(child.value, ast.Name)
                and child.value.id == "plan"
                for child in ast.walk(node)
            )
        ),
        key=lambda node: node.lineno,
    )
    current_runtime = next(
        (
            node.lineno
            for node in current_runtime_calls
        ),
        None,
    )
    operational_calls = sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_assert_operational_services"
        ),
        key=lambda node: node.lineno,
    )
    operational_environments = [
        node.args[1].id
        for node in operational_calls
        if len(node.args) == 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "command_runner"
        and isinstance(node.args[1], ast.Name)
    ]
    if operational_environments != ["rollback_environment", "environment"]:
        errors.append(
            "deployment must verify the exact operational service contract before mutation and final success"
        )
    operational_preflight = operational_calls[0].lineno if len(operational_calls) == 2 else None
    operational_final = operational_calls[1].lineno if len(operational_calls) == 2 else None

    scan_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == "scan_third_party_images"
    ]
    upstream_scan = scan_calls[0].lineno if len(scan_calls) == 1 else None
    if not (
        len(scan_calls) == 1
        and len(scan_calls[0].args) == 2
        and isinstance(scan_calls[0].args[0], ast.Name)
        and scan_calls[0].args[0].id == "environment"
        and isinstance(scan_calls[0].args[1], ast.Name)
        and scan_calls[0].args[1].id == "command_runner"
    ):
        errors.append("deployment upstream scan must use validated digests and reviewed runner")

    pull_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == "_pull_images"
    ]
    external_smoke_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) == "_external_smoke"
    ]
    if not (
        len(pull_calls) == 1
        and len(pull_calls[0].args) == 3
        and all(isinstance(argument, ast.Name) for argument in pull_calls[0].args)
        and [argument.id for argument in pull_calls[0].args]
        == ["plan", "command_runner", "environment"]
        and len(external_smoke_calls) == 1
        and len(external_smoke_calls[0].args) == 5
        and all(
            isinstance(argument, ast.Name) for argument in external_smoke_calls[0].args
        )
        and [argument.id for argument in external_smoke_calls[0].args]
        == [
            "domain",
            "command_runner",
            "environment",
            "edge_fingerprint",
            "evidence",
        ]
    ):
        errors.append(
            "deployment pull and external smoke stages must receive the validated environment"
        )

    command_runner_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "command_runner"
        and node.func.attr == "run"
    ]
    if any(
        len([keyword for keyword in call.keywords if keyword.arg == "env"]) != 1
        or not isinstance(
            next(keyword.value for keyword in call.keywords if keyword.arg == "env"),
            ast.Name,
        )
        or next(keyword.value for keyword in call.keywords if keyword.arg == "env").id
        != "environment"
        for call in command_runner_calls
    ):
        errors.append("every deployment runner call must receive the validated environment")

    compose_calls = _compose_calls([function])
    if any(
        args
        and args[0] == "stop"
        and {"prometheus", "alertmanager"}.intersection(args[1:])
        for _, args in compose_calls
    ):
        errors.append("deployment must keep Prometheus and Alertmanager running")
    up_calls = [(line, args) for line, args in compose_calls if args and args[0] == "up"]
    for _, args in up_calls:
        if not {"--no-build", "--pull", "never"}.issubset(args):
            errors.append("every production compose up must use --no-build --pull never")
    stop_edge = next(
        (line for line, args in compose_calls if args[:2] == ("stop", "edge")),
        None,
    )
    backend_up = next(
        (line for line, args in up_calls if "edge" not in args),
        None,
    )
    edge_up = next(
        (line for line, args in up_calls if "edge" in args),
        None,
    )
    required_positions = {
        "public edge TLS preflight": edge_tls_preflight,
        "initial Vault token sink preflight": (
            vault_sink_lines[0] if len(vault_sink_lines) == 2 else None
        ),
        "Sub2 egress preflight": sub2_egress_line,
        "third-party digest injection": call_lines.get(
            "compose_environment", [None]
        )[0],
        "command runner construction": call_lines.get("SubprocessRunner", [None])[0],
        "release checkout verification": call_lines.get(
            "_assert_release_checkout", [None]
        )[0],
        "current operational-service verification": operational_preflight,
        "rollback supply-chain verification": rollback_supply,
        "current runtime digest verification": current_runtime,
        "third-party vulnerability scan": upstream_scan,
        "target supply-chain verification": target_supply,
        "immutable pulls": call_lines.get("_pull_images", [None])[0],
        "edge stop": stop_edge,
        "backend start": backend_up,
        "internal TLS smoke": call_lines.get("_internal_smoke", [None])[0],
        "Vault token sink recheck": (
            vault_sink_lines[1] if len(vault_sink_lines) == 2 else None
        ),
        "edge start": edge_up,
        "external smoke": call_lines.get("_external_smoke", [None])[0],
        "final operational-service verification": operational_final,
    }
    if any(value is None for value in required_positions.values()):
        errors.append("deployment executor is missing a required release stage")
    elif list(required_positions.values()) != sorted(required_positions.values()):
        errors.append("deployment stages are not in the reviewed fail-closed order")

    stop_helper = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_stop_edge_for_failure"
        ),
        None,
    )
    helper_stops_edge = stop_helper is not None and any(
        args[:2] == ("stop", "edge")
        for _, args in _compose_calls([stop_helper])
    )
    has_final_edge_stop = helper_stops_edge and any(
        isinstance(node, ast.Try)
        and any(
            isinstance(child, ast.Call)
            and _call_name(child) == "_stop_edge_for_failure"
            for final_node in node.finalbody
            for child in ast.walk(final_node)
        )
        for node in ast.walk(function)
    )
    if not has_final_edge_stop:
        errors.append("deployment failure must stop edge in a finally block")

    evidence_argument = next(
        (
            argument
            for argument in function.args.kwonlyargs
            if argument.arg == "evidence_output"
        ),
        None,
    )
    evidence_calls = {
        name: call_lines.get(name, [])
        for name in (
            "prepare_evidence_output",
            "_new_evidence",
            "_record_third_party_images",
            "_publish_evidence",
        )
    }
    if (
        evidence_argument is None
        or any(not lines for lines in evidence_calls.values())
        or evidence_calls["prepare_evidence_output"][0]
        >= (compose_environment_preflight or 0)
        or len(evidence_calls["_publish_evidence"]) < 2
    ):
        errors.append(
            "deployment evidence must preflight before runner access and publish every terminal branch"
        )
    terminal_names = {
        node.id
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id.startswith("TERMINAL_")
    }
    if not {
        "TERMINAL_SUCCEEDED",
        "TERMINAL_PREFLIGHT_FAILED",
        "TERMINAL_EDGE_CLOSED_FAILURE",
        "TERMINAL_EDGE_UNCONFIRMED",
    }.issubset(terminal_names):
        errors.append("deployment evidence must preserve all four terminal states")

    argument_flags = {
        node.args[0].value
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and _call_name(node) == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    missing_flags = sorted(ROLLBACK_CLI_FLAGS - argument_flags)
    if missing_flags:
        errors.append(
            "deployment CLI is missing rollback inputs: " + ", ".join(missing_flags)
        )
    intake_flags = {"--target-intake-manifest", "--target-environment"}
    if not intake_flags.issubset(argument_flags) or not intake_flags.issubset(
        {f"--{argument.arg.replace('_', '-')}" for argument in function.args.kwonlyargs}
    ):
        errors.append("deployment CLI and executor must require target intake identity")
    return errors


def deployment_asset_errors(
    compose_text: str,
    dev_compose_text: str,
    env_text: str,
    dev_env_text: str,
    deploy_text: str,
    upstream_scan_text: str,
) -> list[str]:
    errors: list[str] = []
    try:
        compose = parse_unique_yaml(compose_text)
        dev_compose = parse_unique_yaml(dev_compose_text)
    except yaml.YAMLError as error:
        return [f"Compose YAML is invalid: {error}"]
    services = compose.get("services") if isinstance(compose, dict) else None
    dev_services = dev_compose.get("services") if isinstance(dev_compose, dict) else None
    if not isinstance(services, dict) or not isinstance(dev_services, dict):
        return ["production and development Compose files require services mappings"]

    for service_name, expected_image in PRODUCTION_IMAGES.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            errors.append(f"production Compose is missing {service_name}")
            continue
        if service.get("image") != expected_image:
            errors.append(f"{service_name} must require its immutable production image variable")
        if "build" in service:
            errors.append(f"{service_name} production service must not contain build")

    for service_name, expected_image in THIRD_PARTY_IMAGES.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            errors.append(f"production Compose is missing {service_name}")
            continue
        if service.get("image") != expected_image:
            errors.append(
                f"{service_name} must require its reviewed sha256 digest fragment"
            )
        if "build" in service:
            errors.append(f"{service_name} production service must not contain build")

    vault = services.get("vault")
    if not isinstance(vault, dict) or vault.get("profiles") != ["vault-dev"]:
        errors.append("vault mutable image exception must remain in the exact vault-dev profile")
    elif vault.get("image") != VAULT_DEV_IMAGE:
        errors.append("vault-dev image exception must remain explicit and development-only")

    if set(dev_services) != set(DEV_BUILDS):
        errors.append("development overlay must contain exactly the six application services")
    for service_name, dockerfile in DEV_BUILDS.items():
        service = dev_services.get(service_name)
        build = service.get("build") if isinstance(service, dict) else None
        if not isinstance(build, dict) or build.get("context") != "." or build.get("dockerfile") != dockerfile:
            errors.append(f"development overlay build is invalid: {service_name}")

    production_env = _env_values(env_text)
    for name in DEV_IMAGES:
        if production_env.get(name) != "":
            errors.append(f"production env example must leave {name} empty")
    for expected_image in THIRD_PARTY_IMAGES.values():
        name = expected_image.split("${", 1)[1].split(":?", 1)[0]
        if production_env.get(name) != "":
            errors.append(f"production env example must leave {name} empty")
    development_env = _env_values(dev_env_text)
    for name, expected in DEV_IMAGES.items():
        if development_env.get(name) != expected:
            errors.append(f"development env example is invalid: {name}")

    errors.extend(_executor_errors(deploy_text))
    errors.extend(_upstream_scan_errors(upstream_scan_text))
    return errors


def main() -> int:
    try:
        compose_text = read_stable_yaml_text(COMPOSE)
        dev_compose_text = read_stable_yaml_text(DEV_COMPOSE)
        text_assets = tuple(
            load_stable_text(path)
            for path in (
                ENV_EXAMPLE,
                DEV_ENV_EXAMPLE,
                DEPLOY_SCRIPT,
                UPSTREAM_SCAN_SCRIPT,
            )
        )
    except (OSError, UnicodeError):
        print(
            "deploy-release-assets-error: Cannot inspect deployment assets"
        )
        return 1
    errors = deployment_asset_errors(
        compose_text,
        dev_compose_text,
        *text_assets,
    )
    if errors:
        for error in errors:
            print(f"deploy-release-assets-error: {error}")
        return 1
    print("deploy-release-assets-ok immutable-forward-release=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
