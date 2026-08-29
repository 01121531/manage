"""Verify Compose uses rollback-safe shared image overrides."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.restore_readiness import restore_contract_errors
from scripts.external_text import load_stable_text
from scripts.external_yaml import parse_unique_yaml, read_stable_yaml_text
from scripts.verify_deploy_release import THIRD_PARTY_IMAGES, VAULT_DEV_IMAGE


COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
ROLLBACK_SCRIPT = ROOT / "scripts/rollback_release.py"
ROLLBACK_EVIDENCE = ROOT / "scripts/rollback_release_evidence.py"
MAX_ROLLBACK_ASSET_BYTES = 64 * 1024
ROLLBACK_ASSET_READ_ERROR = "Cannot inspect rollback assets"

EXPECTED_IMAGES = {
    "migrate": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "api": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "worker-mail": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "worker-sub2": "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
    "web": "${PLATFORM_WEB_IMAGE:?set immutable PLATFORM_WEB_IMAGE in .env}",
    "edge": "${PLATFORM_EDGE_IMAGE:?set immutable PLATFORM_EDGE_IMAGE in .env}",
}
REQUIRED_IMAGE_VARIABLES = {
    "PLATFORM_API_IMAGE",
    "PLATFORM_WEB_IMAGE",
    "PLATFORM_EDGE_IMAGE",
}
REQUIRED_IMAGE_VARIABLES.update(
    expected.split("${", 1)[1].split(":?", 1)[0]
    for expected in THIRD_PARTY_IMAGES.values()
)
VARIABLE_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-?][^}]*)?}")
DEFAULT_COMPOSE_OVERRIDES = {
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
}
FORBIDDEN_COMPOSE_CONTROL_VARIABLES = {
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_PROFILES",
    "COMPOSE_ENV_FILES",
}
EXPECTED_DOCKER_TARGET_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
)
EXPECTED_DOCKER_TLS_VARIABLES = (
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)
EXPECTED_PRODUCTION_CREDENTIAL_VARIABLES = (
    "VAULT_TOKEN",
    "PLATFORM_VAULT_TOKEN",
    "PLATFORM_VAULT_API_TOKEN",
    "PLATFORM_VAULT_MAIL_TOKEN",
    "PLATFORM_VAULT_SUB2_TOKEN",
    "PLATFORM_VAULT_API_SECRET_ID",
    "PLATFORM_VAULT_MAIL_SECRET_ID",
    "PLATFORM_VAULT_SUB2_SECRET_ID",
    "VAULT_DEV_ROOT_TOKEN_ID",
    "ALEMBIC_DATABASE_URL",
    "PLATFORM_MIGRATION_DATABASE_URL",
    "PLATFORM_DATABASE_URL",
    "PLATFORM_REDIS_URL",
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "POSTGRES_BOOTSTRAP_PASSWORD",
    "KEYCLOAK_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "KC_DB_PASSWORD",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "REDIS_PASSWORD",
    "REDIS_HEALTHCHECK_PASSWORD",
    "REDISCLI_AUTH",
    "PGPASSWORD",
)
EXPECTED_SUBPROCESS_BASE_ENVIRONMENT_VARIABLES = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
)
EXPECTED_OPERATIONAL_SERVICES = (
    "postgres",
    "redis",
    "keycloak",
    "api",
    "worker-mail",
    "worker-sub2",
    "web",
    "edge",
    "prometheus",
    "alertmanager",
)


def _env_keys(text: str) -> set[str]:
    return {
        line.split("=", 1)[0].strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }


def _is_worker_image_variable(name: str) -> bool:
    upper_name = name.upper()
    return "WORKER" in upper_name and "IMAGE" in upper_name


def _rollback_evidence_errors(
    rollback_source: str,
    evidence_source: str | None,
) -> list[str]:
    required = (
        (
            ROLLBACK_SCRIPT,
            rollback_source,
            (
                '"--evidence-output"',
                "prepare_evidence_output(evidence_output)",
                "RollbackReleaseEvidenceRecorder",
                "TERMINAL_SUCCEEDED",
                "TERMINAL_PREFLIGHT_FAILED",
                "TERMINAL_EDGE_CLOSED_FAILURE",
                "TERMINAL_EDGE_UNCONFIRMED",
                "evidence.observed_image(",
                "_publish_evidence(evidence, evidence_output)",
                "rollback evidence publication failed; public edge was closed",
                "rollback evidence publication failed and public edge closure could not be confirmed",
            ),
        ),
        (
            ROLLBACK_EVIDENCE,
            evidence_source,
            (
                'EVIDENCE_KIND = "release_bound_rollback_execution"',
                'TERMINAL_SUCCEEDED = "succeeded"',
                'TERMINAL_PREFLIGHT_FAILED = "preflight_failed"',
                'TERMINAL_EDGE_CLOSED_FAILURE = "edge_closed_failure"',
                'TERMINAL_EDGE_UNCONFIRMED = "edge_unconfirmed"',
                '"production_acceptance": False',
                '"payload_sha256"',
                "execution_fingerprint(release, recovery)",
                "_MAX_RECOVERY_POINT_SKEW_SECONDS = 300",
                'expected_stops = 1 if edge["start_attempted"] else 0',
                "prepare_write_once_file",
                "publish_write_once_file(temporary_path, destination)",
                '"--expected-container-manifest-sha256"',
                '"--expected-postgres-manifest-sha256"',
                '"--expected-redis-manifest-sha256"',
                '"--expected-recovery-set"',
            ),
        ),
    )
    errors: list[str] = []
    for path, source, markers in required:
        if source is None:
            errors.append(f"missing rollback evidence asset: {path.name}")
            continue
        for marker in markers:
            if marker not in source:
                errors.append(f"{path.name} is missing rollback evidence control: {marker}")
    if rollback_source is not None:
        source = rollback_source
        if source.find("prepare_evidence_output(evidence_output)") > source.find(
            "command_runner = runner or SubprocessRunner()"
        ):
            errors.append("rollback evidence output must be validated before runner construction")
        try:
            module = ast.parse(source)
        except SyntaxError as error:
            errors.append(f"rollback evidence AST is invalid Python: {error}")
            return errors

        functions = {
            node.name: node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        execute = functions.get("execute_rollback")
        decorator = functions.get("_serialized_release_control")
        if execute is None:
            errors.append("rollback evidence AST is missing execute_rollback")
            return errors
        if decorator is None:
            errors.append("rollback evidence AST is missing the release-control decorator")
            return errors

        def call_name(node: ast.AST) -> str | None:
            if not isinstance(node, ast.Call):
                return None
            if isinstance(node.func, ast.Name):
                return node.func.id
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
            return None

        def calls(node: ast.AST, name: str) -> list[ast.Call]:
            return [
                candidate
                for candidate in ast.walk(node)
                if isinstance(candidate, ast.Call) and call_name(candidate) == name
            ]

        decorators = [
            candidate.id
            for candidate in execute.decorator_list
            if isinstance(candidate, ast.Name)
        ]
        if decorators != ["_serialized_release_control"]:
            errors.append(
                "rollback evidence AST must apply the release-control decorator exactly once"
            )

        serialized = next(
            (
                node
                for node in decorator.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "serialized"
            ),
            None,
        )
        if serialized is None:
            errors.append("rollback evidence AST decorator is missing serialized control")
        else:
            serialized_prepare = calls(serialized, "prepare_evidence_output")
            lock_calls = calls(serialized, "release_control_lock")
            wrapped_calls = calls(serialized, "function")
            if (
                len(serialized_prepare) != 1
                or len(lock_calls) != 1
                or len(wrapped_calls) != 1
                or not (
                    serialized_prepare[0].lineno
                    < lock_calls[0].lineno
                    < wrapped_calls[0].lineno
                )
            ):
                errors.append(
                    "rollback evidence AST must validate output before lock and wrapped execution"
                )

        execute_prepare = calls(execute, "prepare_evidence_output")
        runner_construction = calls(execute, "SubprocessRunner")
        action_construction = calls(execute, "_compose")
        first_statement = execute.body[0] if execute.body else None
        first_statement_prepares = bool(
            first_statement
            and isinstance(first_statement, ast.Try)
            and first_statement.body
            and isinstance(first_statement.body[0], ast.Expr)
            and call_name(first_statement.body[0].value) == "prepare_evidence_output"
        )
        later_actions = runner_construction + action_construction
        if (
            len(execute_prepare) != 1
            or not first_statement_prepares
            or any(execute_prepare[0].lineno >= action.lineno for action in later_actions)
        ):
            errors.append(
                "rollback evidence AST must preflight output before runner or service actions"
            )

        publications = calls(execute, "_publish_evidence")
        base_handlers = [
            node
            for node in ast.walk(execute)
            if isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name)
            and node.type.id == "BaseException"
        ]
        failure_publications = (
            calls(base_handlers[0], "_publish_evidence")
            if len(base_handlers) == 1
            else []
        )
        if len(base_handlers) != 1 or len(failure_publications) != 1:
            errors.append(
                "rollback evidence AST must publish once from the BaseException failure branch"
            )

        success_publish_tries = [
            node
            for node in execute.body
            if isinstance(node, ast.Try)
            and sum(
                len(calls(statement, "_publish_evidence"))
                for statement in node.body
            )
            == 1
            and any(calls(handler, "_stop_edge_for_failure") for handler in node.handlers)
        ]
        if len(success_publish_tries) != 1:
            errors.append(
                "rollback evidence AST success publication failure must stop the public edge"
            )
        if len(publications) != 2:
            errors.append(
                "rollback evidence AST must retain exactly one failure and one success publication"
            )
    return errors


def _internal_smoke_errors(source: str) -> list[str]:
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        return [f"rollback script is invalid Python: {error}"]
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "_internal_smoke"
        ),
        None,
    )
    if function is None:
        return ["rollback script is missing _internal_smoke"]

    errors: list[str] = []
    required_imports = {
        "PROBE_CONTAINER",
        "PROBES",
        "restore_contract_errors",
    }
    imported_names = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.restore_readiness"
        for alias in node.names
        if alias.asname is None
    }
    if not required_imports <= imported_names:
        errors.append(
            "rollback internal smoke must import the shared strict restore readiness contract"
        )
    required_tls_imports = {
        "INTERNAL_ENDPOINT_SERVICES",
        "TLS_HTTP_PROBE_PROGRAM",
        "parse_tls_probe_observation",
        "probe_arguments",
        "tls_probe_contract_errors",
    }
    imported_tls_names = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.tls_runtime_identity"
        for alias in node.names
        if alias.asname is None
    }
    if not required_tls_imports <= imported_tls_names:
        errors.append(
            "rollback internal smoke must import the shared TLS runtime identity contract"
        )

    contract_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "restore_contract_errors"
        and not node.args
        and not node.keywords
    ]
    if len(contract_calls) != 1:
        errors.append("rollback internal smoke must validate the shared probe contract")
    tls_contract_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "tls_probe_contract_errors"
        and not node.args
        and not node.keywords
    ]
    if len(tls_contract_calls) != 1:
        errors.append("rollback internal smoke must validate the shared TLS probe contract")

    probe_loops = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Tuple)
        and [item.id for item in node.target.elts if isinstance(item, ast.Name)]
        == ["endpoint", "url"]
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and node.iter.func.id == "zip"
        and len(node.iter.args) >= 2
        and isinstance(node.iter.args[0], ast.Name)
        and node.iter.args[0].id == "endpoints"
        and isinstance(node.iter.args[1], ast.Name)
        and node.iter.args[1].id == "PROBES"
    ]
    if len(probe_loops) != 1:
        errors.append(
            "rollback internal smoke must execute all seven shared service HTTPS URLs"
        )

    compose_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_compose"
    ]
    exact_compose = [
        call
        for call in compose_calls
        if len(call.args) >= 7
        and [argument.value for argument in call.args[:2] if isinstance(argument, ast.Constant)]
        == ["exec", "-T"]
        and isinstance(call.args[2], ast.Name)
        and call.args[2].id == "PROBE_CONTAINER"
        and isinstance(call.args[3], ast.Constant)
        and call.args[3].value == "python"
        and isinstance(call.args[4], ast.Constant)
        and call.args[4].value == "-c"
        and isinstance(call.args[5], ast.Name)
        and call.args[5].id == "TLS_HTTP_PROBE_PROGRAM"
        and isinstance(call.args[6], ast.Starred)
        and isinstance(call.args[6].value, ast.Call)
        and isinstance(call.args[6].value.func, ast.Name)
        and call.args[6].value.func.id == "probe_arguments"
    ]
    runner_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "runner"
        and node.func.attr == "run"
    ]
    exact_runner = [
        call
        for call in runner_calls
        if len(call.args) == 1
        and call.args[0] in exact_compose
        and {keyword.arg for keyword in call.keywords} == {"env", "capture_output"}
        and any(
            keyword.arg == "env"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "environment"
            for keyword in call.keywords
        )
        and any(
            keyword.arg == "capture_output"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
    ]
    if len(exact_compose) != 1 or len(exact_runner) != 1:
        errors.append(
            "rollback internal smoke must run the shared strict TLS probe through the API container"
        )

    shared_errors = restore_contract_errors()
    if shared_errors:
        errors.append(
            "shared restore readiness contract must enforce seven HTTPS probes, internal CA, "
            "hostname verification, TLS 1.2, exact HTTP 200, and no redirect"
        )
    return errors


def _release_topology_errors(source: str) -> list[str]:
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        return [f"rollback script is invalid Python: {error}"]
    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
    }
    assignments = {
        target.id: node.value
        for node in module.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    errors: list[str] = []
    operational_value = assignments.get("REQUIRED_OPERATIONAL_SERVICES")
    operational_services = (
        tuple(
            item.value
            for item in operational_value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(operational_value, ast.Tuple)
        else ()
    )
    if (
        operational_services != EXPECTED_OPERATIONAL_SERVICES
        or not isinstance(operational_value, ast.Tuple)
        or len(operational_services) != len(operational_value.elts)
    ):
        errors.append(
            "rollback operational service contract must contain exactly the reviewed ten services"
        )
    stop_services_value = assignments.get("STOP_SERVICES")
    stop_services = {
        item.value
        for item in stop_services_value.elts
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    } if isinstance(stop_services_value, ast.Tuple) else set()
    if {"prometheus", "alertmanager"}.intersection(stop_services):
        errors.append("rollback must keep Prometheus and Alertmanager running")

    docker_target_value = assignments.get("FORBIDDEN_DOCKER_TARGET_VARIABLES")
    docker_target_variables = (
        tuple(
            item.value
            for item in docker_target_value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(docker_target_value, ast.Tuple)
        else ()
    )
    if (
        docker_target_variables != EXPECTED_DOCKER_TARGET_VARIABLES
        or not isinstance(docker_target_value, ast.Tuple)
        or len(docker_target_variables) != len(docker_target_value.elts)
    ):
        errors.append(
            "production Docker target override contract must contain exactly the reviewed three variables"
        )
    docker_tls_value = assignments.get("FORBIDDEN_DOCKER_TLS_VARIABLES")
    docker_tls_variables = (
        tuple(
            item.value
            for item in docker_tls_value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(docker_tls_value, ast.Tuple)
        else ()
    )
    if (
        docker_tls_variables != EXPECTED_DOCKER_TLS_VARIABLES
        or not isinstance(docker_tls_value, ast.Tuple)
        or len(docker_tls_variables) != len(docker_tls_value.elts)
    ):
        errors.append(
            "production Docker TLS override contract must contain exactly the reviewed three variables"
        )
    credential_value = assignments.get("FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES")
    credential_variables = (
        tuple(
            item.value
            for item in credential_value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(credential_value, ast.Tuple)
        else ()
    )
    if (
        credential_variables != EXPECTED_PRODUCTION_CREDENTIAL_VARIABLES
        or not isinstance(credential_value, ast.Tuple)
        or len(credential_variables) != len(credential_value.elts)
    ):
        errors.append(
            "production plaintext credential contract must contain exactly the reviewed variables"
        )
    base_environment_value = assignments.get("SUBPROCESS_BASE_ENVIRONMENT_VARIABLES")
    base_environment_variables = (
        tuple(
            item.value
            for item in base_environment_value.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(base_environment_value, ast.Tuple)
        else ()
    )
    if (
        base_environment_variables != EXPECTED_SUBPROCESS_BASE_ENVIRONMENT_VARIABLES
        or not isinstance(base_environment_value, ast.Tuple)
        or len(base_environment_variables) != len(base_environment_value.elts)
    ):
        errors.append(
            "production subprocess base environment must contain exactly the reviewed OS variables"
        )

    operational_helper = functions.get("_assert_operational_services")
    helper_calls = (
        [
            node
            for node in ast.walk(operational_helper)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_assert_running_services"
        ]
        if operational_helper is not None
        else []
    )
    if not (
        len(helper_calls) == 1
        and any(
            keyword.arg == "required_services"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "REQUIRED_OPERATIONAL_SERVICES"
            for keyword in helper_calls[0].keywords
        )
    ):
        errors.append(
            "rollback operational gate must use the exact operational service contract"
        )
    edge_tls_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.validate_edge_tls"
        for alias in node.names
    }
    if not {"EdgeTlsError", "validate_edge_tls"}.issubset(edge_tls_imports):
        errors.append("rollback must import the public edge TLS preflight")
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
        errors.append("rollback must import the shared Vault token sink preflight")
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
        errors.append("rollback must not replace the shared Vault token sink preflight")
    external_yaml_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "scripts.external_yaml"
        for alias in node.names
    }
    compose_inputs_value = assignments.get("COMPOSE_INPUT_VARIABLES")
    compose_inputs_loader = functions.get("_load_compose_input_variables")
    loader_names = (
        {
            node.id
            for node in ast.walk(compose_inputs_loader)
            if isinstance(node, ast.Name)
        }
        if compose_inputs_loader is not None
        else set()
    )
    loader_attributes = (
        {
            node.attr
            for node in ast.walk(compose_inputs_loader)
            if isinstance(node, ast.Attribute)
        }
        if compose_inputs_loader is not None
        else set()
    )
    assignment_calls_loader = (
        isinstance(compose_inputs_value, ast.Call)
        and isinstance(compose_inputs_value.func, ast.Name)
        and compose_inputs_value.func.id == "_load_compose_input_variables"
        and len(compose_inputs_value.args) == 1
        and isinstance(compose_inputs_value.args[0], ast.Name)
        and compose_inputs_value.args[0].id == "PRODUCTION_COMPOSE"
    )
    if not (
        "load_unique_yaml_with_text" in external_yaml_imports
        and assignment_calls_loader
        and {
            "_COMPOSE_INPUT_VARIABLE",
            "load_unique_yaml_with_text",
        }.issubset(loader_names)
        and "findall" in loader_attributes
    ):
        errors.append(
            "Compose inputs must be parsed from the authoritative production Compose file"
        )
    validator = functions.get("_validated_third_party_image_environment")
    credential_guards = [
        node
        for node in ast.walk(validator)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Name)
        and node.test.func.id == "any"
        and any(
            isinstance(child, ast.Name)
            and child.id == "FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES"
            for child in ast.walk(node.test)
        )
    ] if validator is not None else []
    credential_guard = credential_guards[0] if len(credential_guards) == 1 else None
    credential_presence_check = credential_guard is not None and any(
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "environment"
        for node in ast.walk(credential_guard.test)
    )
    credential_uses_get = credential_guard is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        for node in ast.walk(credential_guard.test)
    )
    credential_rejection = credential_guard is not None and any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ComposeEnvironmentError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "production Compose environment preflight failed"
        for statement in credential_guard.body
        for node in ast.walk(statement)
    )
    docker_target_guard = next(
        (
            node
            for node in ast.walk(validator)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Name)
            and node.test.func.id == "any"
            and any(
                isinstance(child, ast.Name)
                and child.id == "FORBIDDEN_DOCKER_TARGET_VARIABLES"
                for child in ast.walk(node.test)
            )
        ),
        None,
    ) if validator is not None else None
    docker_target_presence_check = docker_target_guard is not None and any(
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "environment"
        for node in ast.walk(docker_target_guard.test)
    )
    docker_target_uses_get = docker_target_guard is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        for node in ast.walk(docker_target_guard.test)
    )
    docker_target_rejection = docker_target_guard is not None and any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ComposeEnvironmentError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "production Compose environment preflight failed"
        for statement in docker_target_guard.body
        for node in ast.walk(statement)
    )
    validated_environment_assignment = next(
        (
            node
            for node in ast.walk(validator)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "validated"
                for target in node.targets
            )
        ),
        None,
    ) if validator is not None else None
    validated_secret_injection = validator is not None and any(
        isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Name)
        and node.value.id == "validated"
        for node in ast.walk(validator)
    )
    validated_value = (
        validated_environment_assignment.value
        if validated_environment_assignment is not None
        else None
    )
    validated_generator = (
        validated_value.generators[0]
        if isinstance(validated_value, ast.DictComp)
        and len(validated_value.generators) == 1
        else None
    )
    validated_iter_names = (
        [
            item.value.id
            for item in validated_generator.iter.elts
            if isinstance(item, ast.Starred)
            and isinstance(item.value, ast.Name)
        ]
        if validated_generator is not None
        and isinstance(validated_generator.iter, ast.Tuple)
        else []
    )
    validated_is_exact_allowlist = (
        isinstance(validated_value, ast.DictComp)
        and isinstance(validated_value.key, ast.Name)
        and validated_value.key.id == "name"
        and isinstance(validated_value.value, ast.Subscript)
        and isinstance(validated_value.value.value, ast.Name)
        and validated_value.value.value.id == "environment"
        and isinstance(validated_value.value.slice, ast.Name)
        and validated_value.value.slice.id == "name"
        and validated_generator is not None
        and isinstance(validated_generator.target, ast.Name)
        and validated_generator.target.id == "name"
        and validated_iter_names
        == [
            "SUBPROCESS_BASE_ENVIRONMENT_VARIABLES",
            "THIRD_PARTY_IMAGE_DIGEST_VARIABLES",
        ]
        and len(validated_generator.ifs) == 1
        and isinstance(validated_generator.ifs[0], ast.Compare)
        and isinstance(validated_generator.ifs[0].left, ast.Name)
        and validated_generator.ifs[0].left.id == "name"
        and len(validated_generator.ifs[0].ops) == 1
        and isinstance(validated_generator.ifs[0].ops[0], ast.In)
        and len(validated_generator.ifs[0].comparators) == 1
        and isinstance(validated_generator.ifs[0].comparators[0], ast.Name)
        and validated_generator.ifs[0].comparators[0].id == "environment"
    )
    copies_full_environment = validator is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dict"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "environment"
        for node in ast.walk(validator)
    )
    if not validated_is_exact_allowlist or copies_full_environment:
        errors.append(
            "production subprocess environment must be rebuilt from the reviewed allowlist"
        )
    if not (
        credential_presence_check
        and not credential_uses_get
        and credential_rejection
        and validated_environment_assignment is not None
        and credential_guard.lineno < validated_environment_assignment.lineno
        and not validated_secret_injection
    ):
        errors.append(
            "production plaintext credentials must fail closed by key presence before environment or runner use"
        )
    if not (
        docker_target_presence_check
        and not docker_target_uses_get
        and docker_target_rejection
        and validated_environment_assignment is not None
        and docker_target_guard.lineno < validated_environment_assignment.lineno
    ):
        errors.append(
            "production Docker target overrides must fail closed by key presence before environment use"
        )
    docker_tls_guard = next(
        (
            node
            for node in ast.walk(validator)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Name)
            and node.test.func.id == "any"
            and any(
                isinstance(child, ast.Name)
                and child.id == "FORBIDDEN_DOCKER_TLS_VARIABLES"
                for child in ast.walk(node.test)
            )
        ),
        None,
    ) if validator is not None else None
    docker_tls_presence_check = docker_tls_guard is not None and any(
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "environment"
        for node in ast.walk(docker_tls_guard.test)
    )
    docker_tls_uses_get = docker_tls_guard is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        for node in ast.walk(docker_tls_guard.test)
    )
    docker_tls_rejection = docker_tls_guard is not None and any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ComposeEnvironmentError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "production Compose environment preflight failed"
        for statement in docker_tls_guard.body
        for node in ast.walk(statement)
    )
    if not (
        docker_tls_presence_check
        and not docker_tls_uses_get
        and docker_tls_rejection
        and validated_environment_assignment is not None
        and docker_tls_guard.lineno < validated_environment_assignment.lineno
    ):
        errors.append(
            "production Docker TLS overrides must fail closed by key presence before environment use"
        )
    validator_has_strict_digest = validator is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
        and node.func.attr == "fullmatch"
        and any(
            isinstance(argument, ast.Constant)
            and argument.value == r"[0-9a-f]{64}"
            for argument in node.args
        )
        for node in ast.walk(validator)
    )
    inherited_input_assignment = next(
        (
            node
            for node in ast.walk(validator)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "inherited_compose_inputs"
                for target in node.targets
            )
        ),
        None,
    ) if validator is not None else None
    inherited_input_names = (
        {
            node.id
            for node in ast.walk(inherited_input_assignment.value)
            if isinstance(node, ast.Name)
        }
        if inherited_input_assignment is not None
        else set()
    )
    inherited_input_rejection = validator is not None and any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "inherited_compose_inputs"
        and any(
            isinstance(child, ast.Raise)
            and isinstance(child.exc, ast.Call)
            and isinstance(child.exc.func, ast.Name)
            and child.exc.func.id == "ComposeEnvironmentError"
            for statement in node.body
            for child in ast.walk(statement)
        )
        for node in ast.walk(validator)
    )
    validator_rejects_inherited_inputs = (
        inherited_input_assignment is not None
        and {
            "COMPOSE_INPUT_VARIABLES",
            "THIRD_PARTY_IMAGE_DIGEST_VARIABLES",
            "environment",
        }.issubset(inherited_input_names)
        and inherited_input_rejection
    )
    plan_class = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.ClassDef) and node.name == "RollbackPlan"
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
    plan_uses_validator = compose_environment is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_validated_third_party_image_environment"
        for node in ast.walk(compose_environment)
    )
    if not validator_has_strict_digest or not plan_uses_validator:
        errors.append(
            "rollback Compose environment must fail closed on third-party digest injection"
        )
    if not validator_rejects_inherited_inputs:
        errors.append(
            "rollback Compose inputs from the process environment must fail closed"
        )

    runner_class = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.ClassDef) and node.name == "SubprocessRunner"
        ),
        None,
    )
    runner_method = next(
        (
            node
            for node in (runner_class.body if runner_class is not None else [])
            if isinstance(node, ast.FunctionDef) and node.name == "run"
        ),
        None,
    )
    missing_environment_guard = next(
        (
            node
            for node in ast.walk(runner_method)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "env"
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.Is)
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value is None
        ),
        None,
    ) if runner_method is not None else None
    missing_environment_rejection = missing_environment_guard is not None and any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "RollbackError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "explicit subprocess environment is required"
        for statement in missing_environment_guard.body
        for node in ast.walk(statement)
    )
    subprocess_calls = (
        [
            node
            for node in ast.walk(runner_method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
        ]
        if runner_method is not None
        else []
    )
    subprocess_environment = (
        next(
            (keyword.value for keyword in subprocess_calls[0].keywords if keyword.arg == "env"),
            None,
        )
        if len(subprocess_calls) == 1
        else None
    )
    if not (
        missing_environment_rejection
        and isinstance(subprocess_environment, ast.Call)
        and isinstance(subprocess_environment.func, ast.Name)
        and subprocess_environment.func.id == "dict"
        and len(subprocess_environment.args) == 1
        and isinstance(subprocess_environment.args[0], ast.Name)
        and subprocess_environment.args[0].id == "env"
    ):
        errors.append(
            "production subprocess runner must reject missing environments and pass only an explicit copy"
        )

    reviewed_runner_calls = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"runner", "command_runner"}
        and node.func.attr == "run"
    ]
    if any(
        len([keyword for keyword in call.keywords if keyword.arg == "env"]) != 1
        or isinstance(
            next(keyword.value for keyword in call.keywords if keyword.arg == "env"),
            ast.Constant,
        )
        for call in reviewed_runner_calls
    ):
        errors.append("every production runner call must receive an explicit environment")

    supply_chain = functions.get("_verify_supply_chain")
    supply_runner_calls = sorted(
        (
            node
            for node in ast.walk(supply_chain)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "runner"
            and node.func.attr == "run"
        ),
        key=lambda node: node.lineno,
    ) if supply_chain is not None else []
    supply_programs: list[str | None] = []
    supply_environments: list[str | None] = []
    for call in supply_runner_calls:
        command = call.args[0] if call.args else None
        supply_programs.append(
            command.elts[0].value
            if isinstance(command, ast.List)
            and command.elts
            and isinstance(command.elts[0], ast.Constant)
            else None
        )
        environment_keyword = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "env"),
            None,
        )
        supply_environments.append(
            environment_keyword.id if isinstance(environment_keyword, ast.Name) else None
        )
    os_environment_subscripts = (
        [
            node
            for node in ast.walk(supply_chain)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
        ]
        if supply_chain is not None
        else []
    )
    if not (
        supply_programs == ["cosign", "cosign", "gh"]
        and supply_environments == ["environment", "environment", "gh_environment"]
        and len(os_environment_subscripts) == 1
        and isinstance(os_environment_subscripts[0].slice, ast.Constant)
        and os_environment_subscripts[0].slice.value == "GH_TOKEN"
    ):
        errors.append(
            "supply-chain credentials must be scoped only to GitHub attestation verification"
        )
    compose = functions.get("_compose")
    compose_return = next(
        (
            node.value
            for node in ast.walk(compose)
            if isinstance(node, ast.Return)
        ),
        None,
    ) if compose is not None else None
    expected_compose = (
        isinstance(compose_return, ast.List)
        and len(compose_return.elts) == 12
        and [
            item.value if isinstance(item, ast.Constant) else None
            for item in compose_return.elts[:3]
        ] == ["docker", "compose", "--project-directory"]
        and isinstance(compose_return.elts[3], ast.Call)
        and isinstance(compose_return.elts[3].func, ast.Name)
        and compose_return.elts[3].func.id == "str"
        and isinstance(compose_return.elts[3].args[0], ast.Name)
        and compose_return.elts[3].args[0].id == "ROOT"
        and isinstance(compose_return.elts[4], ast.Constant)
        and compose_return.elts[4].value == "--env-file"
        and isinstance(compose_return.elts[5], ast.Call)
        and isinstance(compose_return.elts[5].func, ast.Name)
        and compose_return.elts[5].func.id == "str"
        and isinstance(compose_return.elts[5].args[0], ast.Name)
        and compose_return.elts[5].args[0].id == "PRODUCTION_ENV_FILE"
        and isinstance(compose_return.elts[6], ast.Constant)
        and compose_return.elts[6].value == "--project-name"
        and isinstance(compose_return.elts[7], ast.Name)
        and compose_return.elts[7].id == "PRODUCTION_PROJECT_NAME"
        and isinstance(compose_return.elts[8], ast.Constant)
        and compose_return.elts[8].value == "-f"
        and isinstance(compose_return.elts[9], ast.Call)
        and isinstance(compose_return.elts[9].func, ast.Name)
        and compose_return.elts[9].func.id == "str"
        and isinstance(compose_return.elts[9].args[0], ast.Name)
        and compose_return.elts[9].args[0].id == "PRODUCTION_COMPOSE"
        and isinstance(compose_return.elts[10], ast.Name)
        and compose_return.elts[10].id == "command"
        and isinstance(compose_return.elts[11], ast.Starred)
        and isinstance(compose_return.elts[11].value, ast.Name)
        and compose_return.elts[11].value.id == "arguments"
    )
    if not expected_compose:
        errors.append(
            "rollback Compose commands must pin the production file and project directory"
        )
    direct_compose = [
        node
        for node in ast.walk(module)
        if isinstance(node, (ast.List, ast.Tuple))
        and len(node.elts) >= 2
        and all(isinstance(item, ast.Constant) for item in node.elts[:2])
        and [item.value for item in node.elts[:2]] == ["docker", "compose"]
    ]
    if compose_return is None or direct_compose != [compose_return]:
        errors.append("rollback must not bypass the pinned Compose helper")

    preflight = functions.get("_assert_release_checkout")
    if preflight is None:
        errors.append("rollback script is missing release checkout preflight")
    else:
        constants = {
            node.value
            for node in ast.walk(module)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        missing_overrides = sorted(DEFAULT_COMPOSE_OVERRIDES - constants)
        if missing_overrides:
            errors.append("release checkout preflight must reject every default Compose override")
        preflight_constants = {
            node.value
            for node in ast.walk(preflight)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        missing_controls = sorted(
            FORBIDDEN_COMPOSE_CONTROL_VARIABLES - constants
        )
        if missing_controls:
            errors.append(
                "release checkout preflight is missing: " + ", ".join(missing_controls)
            )
        preflight_names = {
            node.id for node in ast.walk(preflight) if isinstance(node, ast.Name)
        }
        compose_control_guard = next(
            (
                node
                for node in ast.walk(preflight)
                if isinstance(node, ast.If)
                and any(
                    isinstance(child, ast.Name)
                    and child.id == "FORBIDDEN_COMPOSE_CONTROL_VARIABLES"
                    for child in ast.walk(node.test)
                )
            ),
            None,
        )
        control_uses_shell_environment = compose_control_guard is not None and any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Name)
            and node.comparators[0].id == "shell_environment"
            for node in ast.walk(compose_control_guard.test)
        )
        if (
            "FORBIDDEN_COMPOSE_CONTROL_VARIABLES" not in preflight_names
            or not control_uses_shell_environment
        ):
            errors.append("release checkout preflight must reject Compose control variables")
        for required in (
            "rev-parse",
            "HEAD",
            "diff",
            "--cached",
            "--quiet",
            "release checkout preflight failed",
        ):
            if required not in preflight_constants:
                errors.append(f"release checkout preflight is missing: {required}")

    executor = functions.get("execute_rollback")
    if executor is None:
        errors.append("rollback script is missing execute_rollback")
    else:
        call_lines: dict[str, list[int]] = {}
        checkout_calls: list[ast.Call] = []
        for node in ast.walk(executor):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if name is not None:
                call_lines.setdefault(name, []).append(node.lineno)
            if name == "_assert_release_checkout":
                checkout_calls.append(node)
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
            errors.append("rollback checkout preflight must verify plan.commit")
        supply_calls = [
            node
            for node in ast.walk(executor)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_verify_supply_chain"
        ]
        pull_calls = [
            node
            for node in ast.walk(executor)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_pull_images"
        ]
        external_smoke_calls = [
            node
            for node in ast.walk(executor)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_external_smoke"
        ]
        if not (
            len(supply_calls) == 1
            and len(supply_calls[0].args) == 3
            and all(isinstance(argument, ast.Name) for argument in supply_calls[0].args)
            and [argument.id for argument in supply_calls[0].args]
            == ["plan", "command_runner", "environment"]
            and len(pull_calls) == 1
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
                "rollback supply-chain, pull, and external smoke stages must receive the validated environment"
            )
        operational_calls = sorted(
            (
                node
                for node in ast.walk(executor)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_assert_operational_services"
                and len(node.args) == 2
                and all(isinstance(argument, ast.Name) for argument in node.args)
                and node.args[0].id == "command_runner"
                and node.args[1].id == "environment"
            ),
            key=lambda node: node.lineno,
        )
        if len(operational_calls) != 2:
            errors.append(
                "rollback must verify operational services before destructive restore and final success"
            )
        edge_tls_calls = [
            node
            for node in ast.walk(executor)
            if isinstance(node, ast.Call)
            and (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            ) == "validate_edge_tls"
        ]
        edge_tls = edge_tls_calls[0] if len(edge_tls_calls) == 1 else None
        if not (
            edge_tls is not None
            and len(edge_tls.args) == 2
            and isinstance(edge_tls.args[0], ast.Name)
            and edge_tls.args[0].id == "PRODUCTION_ENV_FILE"
            and isinstance(edge_tls.args[1], ast.Name)
            and edge_tls.args[1].id == "domain"
        ):
            errors.append(
                "rollback public edge TLS preflight must use the fixed env and requested domain"
            )
        vault_sink_calls = sorted(
            (
                node
                for node in ast.walk(executor)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "validate_vault_token_sinks"
            ),
            key=lambda node: node.lineno,
        )
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
                "rollback must run the exact shared Vault token sink preflight twice"
            )
        positions = [
            edge_tls.lineno if edge_tls is not None else 10**9,
            vault_sink_lines[0] if len(vault_sink_lines) == 2 else 10**9,
            min(call_lines.get("compose_environment", [10**9])),
            min(call_lines.get("SubprocessRunner", [10**9])),
            min(call_lines.get("_assert_release_checkout", [10**9])),
            operational_calls[0].lineno if len(operational_calls) == 2 else 10**9,
            min(call_lines.get("_verify_supply_chain", [10**9])),
            min(call_lines.get("_pull_images", [10**9])),
            min(call_lines.get("_compose", [10**9])),
        ]
        if 10**9 in positions:
            errors.append(
                "rollback executor is missing public edge TLS preflight or deployment stages"
            )
        elif positions != sorted(positions):
            errors.append("rollback checkout preflight must run before supply chain and Compose")
        internal_smoke = min(call_lines.get("_internal_smoke", [10**9]))
        edge_up = min(
            (
                node.lineno
                for node in ast.walk(executor)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_compose"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "up"
                and any(
                    isinstance(argument, ast.Constant)
                    and argument.value == "edge"
                    for argument in node.args[1:]
                )
            ),
            default=10**9,
        )
        sink_recheck_positions = [
            internal_smoke,
            vault_sink_lines[1] if len(vault_sink_lines) == 2 else 10**9,
            edge_up,
        ]
        if 10**9 in sink_recheck_positions or sink_recheck_positions != sorted(
            sink_recheck_positions
        ):
            errors.append(
                "rollback Vault token sink recheck must run after internal smoke and before edge start"
            )
        external_smoke = min(call_lines.get("_external_smoke", [10**9]))
        success_outcomes = [
            node
            for node in ast.walk(executor)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "evidence"
            and node.func.attr == "outcome"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "TERMINAL_SUCCEEDED"
        ]
        final_positions = [
            external_smoke,
            operational_calls[1].lineno if len(operational_calls) == 2 else 10**9,
            success_outcomes[0].lineno if len(success_outcomes) == 1 else 10**9,
        ]
        if 10**9 in final_positions or final_positions != sorted(final_positions):
            errors.append(
                "rollback final operational gate must run after smoke and before success"
            )
    return errors


def rollback_asset_errors(
    compose_text: str,
    env_text: str,
    rollback_text: str | None = None,
    evidence_text: str | None = None,
) -> list[str]:
    try:
        compose = parse_unique_yaml(compose_text)
    except yaml.YAMLError as error:
        return [f"docker-compose.yml is invalid YAML: {error}"]
    if not isinstance(compose, dict) or not isinstance(compose.get("services"), dict):
        return ["docker-compose.yml must contain a services mapping"]

    try:
        if rollback_text is None:
            rollback_text = load_stable_text(
                ROLLBACK_SCRIPT,
                max_bytes=MAX_ROLLBACK_ASSET_BYTES,
            )
        if evidence_text is None and ROLLBACK_EVIDENCE.is_file():
            evidence_text = load_stable_text(
                ROLLBACK_EVIDENCE,
                max_bytes=MAX_ROLLBACK_ASSET_BYTES,
            )
    except (OSError, UnicodeError):
        return [ROLLBACK_ASSET_READ_ERROR]

    services = compose["services"]
    errors: list[str] = []
    image_variables: set[str] = set()
    for service_name, expected_image in EXPECTED_IMAGES.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            errors.append(f"missing service: {service_name}")
            continue
        image = service.get("image")
        if image != expected_image:
            errors.append(
                f"{service_name} image must be {expected_image}, got {image!r}"
            )
        if isinstance(image, str):
            image_variables.update(VARIABLE_PATTERN.findall(image))

    for service_name, expected_image in THIRD_PARTY_IMAGES.items():
        service = services.get(service_name)
        image = service.get("image") if isinstance(service, dict) else None
        if image != expected_image:
            errors.append(
                f"{service_name} image must require the reviewed sha256 digest fragment"
            )
        if isinstance(image, str):
            image_variables.update(VARIABLE_PATTERN.findall(image))

    vault = services.get("vault")
    if not isinstance(vault, dict) or vault.get("profiles") != ["vault-dev"]:
        errors.append("vault mutable image exception must remain vault-dev only")
    elif vault.get("image") != VAULT_DEV_IMAGE:
        errors.append("vault-dev image exception must remain explicit")

    env_keys = _env_keys(env_text)
    missing_variables = sorted(REQUIRED_IMAGE_VARIABLES - env_keys)
    if missing_variables:
        errors.append(
            ".env.example is missing image variables: "
            + ", ".join(missing_variables)
        )
    independent_worker_variables = sorted(
        name
        for name in image_variables | env_keys
        if _is_worker_image_variable(name)
    )
    if independent_worker_variables:
        errors.append(
            "independent worker image variables are forbidden: "
            + ", ".join(independent_worker_variables)
        )
    errors.extend(_internal_smoke_errors(rollback_text))
    errors.extend(_release_topology_errors(rollback_text))
    errors.extend(_rollback_evidence_errors(rollback_text, evidence_text))
    return errors


def main() -> int:
    try:
        compose_text = read_stable_yaml_text(COMPOSE)
        env_text = load_stable_text(
            ENV_EXAMPLE,
            max_bytes=MAX_ROLLBACK_ASSET_BYTES,
        )
        rollback_text = load_stable_text(
            ROLLBACK_SCRIPT,
            max_bytes=MAX_ROLLBACK_ASSET_BYTES,
        )
    except (OSError, UnicodeError):
        errors = [ROLLBACK_ASSET_READ_ERROR]
    else:
        errors = rollback_asset_errors(compose_text, env_text, rollback_text)
    if errors:
        for error in errors:
            print(f"rollback-assets-error: {error}")
        return 1
    print(
        "rollback-assets-ok image-overrides=required internal-tls-smoke=verified "
        "write-once-evidence=verified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
