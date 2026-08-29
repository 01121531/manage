"""Verify the two-database backup/restore contract and operator guidance."""

from __future__ import annotations

import ast
from pathlib import Path
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text

README = ROOT / "platform" / "README.md"
SCRIPT = ROOT / "scripts" / "postgres_maintenance.py"
CRYPTO_SCRIPT = ROOT / "scripts" / "backup_crypto.py"
OUTPUT_POLICY_SCRIPT = ROOT / "scripts" / "backup_output_policy.py"
AUDIT_ARCHIVE_SCRIPT = ROOT / "scripts" / "audit_archive.py"
RUNBOOK = ROOT / "deploy" / "runbooks" / "restore.md"
VAULT_SCRIPT = ROOT / "scripts" / "vault_maintenance.py"
REDIS_SCRIPT = ROOT / "scripts" / "redis_maintenance.py"
PRODUCTION_DOCKER_ENVIRONMENT = ROOT / "scripts" / "production_docker_environment.py"
VAULT_RUNBOOK = ROOT / "deploy" / "runbooks" / "vault-restore.md"
RESTORE_READINESS = ROOT / "scripts" / "restore_readiness.py"
PRIVATE_SECRET_FILE = ROOT / "scripts" / "private_secret_file.py"
EDGE_TLS_VALIDATOR = ROOT / "scripts" / "validate_edge_tls.py"
INTERNAL_TLS_EXPIRY = ROOT / "scripts" / "check_internal_tls_expiry.py"
ASSET_PATHS = (
    README,
    SCRIPT,
    CRYPTO_SCRIPT,
    OUTPUT_POLICY_SCRIPT,
    AUDIT_ARCHIVE_SCRIPT,
    RUNBOOK,
    VAULT_SCRIPT,
    REDIS_SCRIPT,
    PRODUCTION_DOCKER_ENVIRONMENT,
    VAULT_RUNBOOK,
    RESTORE_READINESS,
    PRIVATE_SECRET_FILE,
    EDGE_TLS_VALIDATOR,
    INTERNAL_TLS_EXPIRY,
)
EXPECTED_RESTORE_PROBES = (
    "https://api:8443/readyz",
    "https://web:8443/",
    "https://keycloak:9000/health/ready",
    "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
    "https://worker-mail:9101/metrics",
    "https://worker-sub2:9102/metrics",
    "https://prometheus:9090/-/ready",
)
EXPECTED_PRODUCTION_DOCKER_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)
POSTGRES_DOCKER_ENTRYPOINTS = (
    "count_tables",
    "count_rows",
    "critical_row_counts",
    "backup_database",
    "restore_database",
    "run_backup",
    "backup_bundle",
    "restore_bundle",
    "run_restore",
    "run_drill",
    "drill_bundle",
)
REDIS_DOCKER_ENTRYPOINTS = ("backup_release", "restore_release")


def load_assets() -> dict[Path, str]:
    return {path: load_stable_text(path) for path in ASSET_PATHS}


def _first_executable_statement(function: ast.FunctionDef) -> ast.stmt | None:
    statements = list(function.body)
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        statements = statements[1:]
    return statements[0] if statements else None


def _is_production_docker_preflight(statement: ast.stmt | None) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "_validate_production_docker_environment"
        and not statement.value.args
        and not statement.value.keywords
    )


def production_docker_environment_contract_errors(
    helper_source: str,
    postgres_source: str,
    redis_source: str,
) -> list[str]:
    errors: list[str] = []
    try:
        helper_module = ast.parse(helper_source)
        postgres_module = ast.parse(postgres_source)
        redis_module = ast.parse(redis_source)
    except SyntaxError:
        return ["production Docker environment assets must parse as Python"]

    helper_assignments = {
        target.id: statement.value
        for statement in helper_module.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    inventory = helper_assignments.get("FORBIDDEN_PRODUCTION_DOCKER_VARIABLES")
    inventory_values = (
        tuple(
            item.value
            for item in inventory.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if isinstance(inventory, ast.Tuple)
        else ()
    )
    if (
        inventory_values != EXPECTED_PRODUCTION_DOCKER_VARIABLES
        or not isinstance(inventory, ast.Tuple)
        or len(inventory_values) != len(inventory.elts)
    ):
        errors.append(
            "production Docker environment contract must contain exactly the reviewed six variables"
        )

    helper_functions = {
        node.name: node
        for node in helper_module.body
        if isinstance(node, ast.FunctionDef)
    }
    validator = helper_functions.get("validate_production_docker_environment")
    guard = next(
        (
            node
            for node in ast.walk(validator)
            if isinstance(node, ast.If)
            and any(
                isinstance(child, ast.Name)
                and child.id == "FORBIDDEN_PRODUCTION_DOCKER_VARIABLES"
                for child in ast.walk(node.test)
            )
        ),
        None,
    ) if validator is not None else None
    presence_check = guard is not None and any(
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.In)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "environment"
        for node in ast.walk(guard.test)
    )
    uses_get = guard is not None and any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        for node in ast.walk(guard.test)
    )
    fixed_rejection = guard is not None and any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ProductionDockerEnvironmentError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value
        == "production backup Docker environment preflight failed"
        for statement in guard.body
        for node in ast.walk(statement)
    )
    if not (presence_check and not uses_get and fixed_rejection):
        errors.append(
            "production Docker environment must fail closed by key presence with a fixed error"
        )

    for label, module, expected_entrypoints in (
        ("PostgreSQL", postgres_module, POSTGRES_DOCKER_ENTRYPOINTS),
        ("Redis", redis_module, REDIS_DOCKER_ENTRYPOINTS),
    ):
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "scripts.production_docker_environment"
            and any(
                alias.name == "validate_production_docker_environment"
                and alias.asname == "_validate_production_docker_environment"
                for alias in node.names
            )
            for node in module.body
        )
        if not imported:
            errors.append(f"{label} maintenance must import the shared Docker environment gate")
        functions = {
            node.name: node for node in module.body if isinstance(node, ast.FunctionDef)
        }
        for name in expected_entrypoints:
            function = functions.get(name)
            if function is None or not _is_production_docker_preflight(
                _first_executable_statement(function)
            ):
                errors.append(
                    f"{label} {name} must run the Docker environment gate first"
                )
    return errors


def restore_readiness_docker_environment_contract_errors(source: str) -> list[str]:
    """Require restore readiness to reject Docker redirection before all work."""

    try:
        module = ast.parse(source)
    except SyntaxError:
        return ["restore readiness Docker environment contract must parse as Python"]

    imported = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "scripts.production_docker_environment"
        and {
            (alias.name, alias.asname)
            for alias in node.names
        }
        >= {
            ("ProductionDockerEnvironmentError", None),
            (
                "validate_production_docker_environment",
                "_validate_production_docker_environment",
            ),
        }
        for node in module.body
    )
    functions = {
        node.name: node for node in module.body if isinstance(node, ast.FunctionDef)
    }
    verifier = functions.get("verify_restored_services")
    first = _first_executable_statement(verifier) if verifier is not None else None

    gate_call: ast.Call | None = None
    fixed_wrapper = False
    if (
        isinstance(first, ast.Try)
        and len(first.body) == 1
        and not first.orelse
        and not first.finalbody
        and len(first.handlers) == 1
    ):
        expression = first.body[0]
        if (
            isinstance(expression, ast.Expr)
            and isinstance(expression.value, ast.Call)
            and isinstance(expression.value.func, ast.Name)
            and expression.value.func.id == "_validate_production_docker_environment"
            and not expression.value.args
            and not expression.value.keywords
        ):
            gate_call = expression.value
        handler = first.handlers[0]
        raised = handler.body[0] if len(handler.body) == 1 else None
        fixed_wrapper = (
            isinstance(handler.type, ast.Name)
            and handler.type.id == "ProductionDockerEnvironmentError"
            and handler.name == "error"
            and isinstance(raised, ast.Raise)
            and isinstance(raised.exc, ast.Call)
            and isinstance(raised.exc.func, ast.Name)
            and raised.exc.func.id == "RestoreReadinessError"
            and len(raised.exc.args) == 1
            and isinstance(raised.exc.args[0], ast.Constant)
            and raised.exc.args[0].value
            == "restore readiness Docker environment preflight failed"
            and isinstance(raised.cause, ast.Name)
            and raised.cause.id == "error"
        )

    later_calls = [
        node
        for node in (ast.walk(verifier) if verifier is not None else ())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"restore_contract_errors", "runner"}
    ]
    gate_is_first = gate_call is not None and all(
        gate_call.lineno < call.lineno for call in later_calls
    )
    if not (imported and fixed_wrapper and gate_is_first and later_calls):
        return [
            "restore readiness must run the shared Docker environment gate first with a fixed error"
        ]
    return []
PRODUCTION_COMPOSE_PREFIX = (
    "docker",
    "compose",
    "--project-directory",
    str(ROOT),
    "--env-file",
    str(ROOT / ".env"),
    "--project-name",
    "email-platform",
    "--file",
    str(ROOT / "docker-compose.yml"),
)


def production_compose_identity_errors(
    commands: tuple[list[str], ...],
    label: str,
) -> list[str]:
    errors: list[str] = []
    for index, command in enumerate(commands):
        if tuple(command[: len(PRODUCTION_COMPOSE_PREFIX)]) != PRODUCTION_COMPOSE_PREFIX:
            errors.append(
                f"{label} backup command {index + 1} does not pin the production Compose project"
            )
    return errors


def backup_output_contract_errors(
    policy_source: str,
    postgres_source: str,
    vault_source: str,
    redis_source: str | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        policy_module = ast.parse(policy_source)
        postgres_module = ast.parse(postgres_source)
    except SyntaxError:
        return ["backup output policy and PostgreSQL maintenance must parse as Python"]

    policy_functions = {
        node.name: node
        for node in policy_module.body
        if isinstance(node, ast.FunctionDef)
    }
    strict_publisher = policy_functions.get("publish_bundle_write_once_file")
    strict_statements = list(strict_publisher.body) if strict_publisher is not None else []
    if (
        strict_statements
        and isinstance(strict_statements[0], ast.Expr)
        and isinstance(strict_statements[0].value, ast.Constant)
        and isinstance(strict_statements[0].value.value, str)
    ):
        strict_statements = strict_statements[1:]
    strict_calls = [
        statement.value
        for statement in strict_statements
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
    ]
    strict_call_targets = [
        (
            call.func.value.id,
            call.func.attr,
            [argument.id for argument in call.args if isinstance(argument, ast.Name)],
            call.keywords,
        )
        for call in strict_calls
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
    ]
    if (
        len(strict_statements) != 2
        or len(strict_calls) != 2
        or strict_call_targets
        != [
            ("os", "link", ["temporary_path", "output_path"], []),
            ("temporary_path", "unlink", [], []),
        ]
    ):
        errors.append(
            "bundle publisher must directly hard-link then strictly unlink the private name"
        )
    for required_control in (
        "path.is_absolute()",
        "os.lstat(path)",
        "st_file_attributes",
        "relative_to(REPOSITORY_ROOT.resolve())",
        "directory.mkdir()",
        "tempfile.NamedTemporaryFile(",
        "stream.flush()",
        "os.fsync(stream.fileno())",
        "os.link(temporary_path, output_path)",
        "def publish_bundle_write_once_file(",
        "class ClaimedDirectory:",
        "metadata.st_dev != claim.device",
        "metadata.st_ino != claim.inode",
        "shutil.rmtree(claim.path)",
        "def cleanup_created_directory_after_failure(",
        "primary_error.add_note(CLEANUP_UNCONFIRMED_NOTE)",
        "def require_exact_regular_files(",
        "{entry.name for entry in entries} != expected_names",
        "not stat.S_ISREG(metadata.st_mode)",
        "metadata.st_nlink != 1",
        "identities[entry.name] = stable_file_identity(metadata)",
    ):
        if required_control not in policy_source:
            errors.append(f"backup output policy is missing: {required_control}")

    cleanup_function = policy_functions.get("cleanup_created_directory")
    cleanup_helper = policy_functions.get("cleanup_created_directory_after_failure")
    cleanup_calls = [
        node
        for node in ast.walk(cleanup_function)
        if isinstance(node, ast.Call)
    ] if cleanup_function is not None else []
    removes_claim_path = any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "shutil"
        and call.func.attr == "rmtree"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Attribute)
        and isinstance(call.args[0].value, ast.Name)
        and call.args[0].value.id == "claim"
        and call.args[0].attr == "path"
        for call in cleanup_calls
    )
    helper_handlers = [
        node
        for node in ast.walk(cleanup_helper)
        if isinstance(node, ast.ExceptHandler)
    ] if cleanup_helper is not None else []
    helper_catches_base = any(
        isinstance(handler.type, ast.Name) and handler.type.id == "BaseException"
        for handler in helper_handlers
    )
    if not removes_claim_path or not helper_catches_base:
        errors.append(
            "claimed-directory rollback must authenticate the exact target and preserve every primary failure"
        )

    try:
        database_source = postgres_source[
            postgres_source.index("def backup_database("):
            postgres_source.index("def restore_database(")
        ]
        if not (
            database_source.index("prepare_write_once_file(output_path)")
            < database_source.index("load_key_file(key_file)")
            < database_source.index("subprocess.Popen(")
        ) or "publish_write_once_file(temporary_path, path)" not in database_source:
            errors.append("single-database backup is not write-once before secret/process access")
        database_function = next(
            (
                node
                for node in postgres_module.body
                if isinstance(node, ast.FunctionDef) and node.name == "backup_database"
            ),
            None,
        )
        ownership_branch = next(
            (
                node
                for node in ast.walk(database_function)
                if isinstance(node, ast.If)
                and isinstance(node.test, ast.Name)
                and node.test.id == "_bundle_owned"
            ),
            None,
        ) if database_function is not None else None

        def branch_calls(statements: list[ast.stmt]) -> list[ast.Call]:
            return [
                node
                for statement in statements
                for node in ast.walk(statement)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            ]

        owned_calls = branch_calls(ownership_branch.body) if ownership_branch else []
        standalone_calls = branch_calls(ownership_branch.orelse) if ownership_branch else []
        owned_publish = [
            call
            for call in owned_calls
            if call.func.id == "publish_bundle_write_once_file"
        ]
        standalone_publish = [
            call
            for call in standalone_calls
            if call.func.id == "publish_write_once_file"
        ]
        owned_relinquishes_temp = any(
            isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "temporary_path"
                for target in statement.targets
            )
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is None
            and owned_publish
            and statement.lineno < owned_publish[0].lineno
            for statement in (ownership_branch.body if ownership_branch else [])
        )
        if (
            "_bundle_owned: bool = False" not in database_source
            or len(owned_publish) != 1
            or len(standalone_publish) != 1
            or any(call.func.id == "publish_write_once_file" for call in owned_calls)
            or any(
                call.func.id == "publish_bundle_write_once_file"
                for call in standalone_calls
            )
            or not owned_relinquishes_temp
            or "discard_claimed_temporary_file(temporary_path)" not in database_source
        ):
            errors.append("single-database backup does not distinguish bundle ownership")
        if not (
            database_source.index("return_code = process.wait()")
            < database_source.index("stream.flush()")
            < database_source.index("os.fsync(stream.fileno())")
            < database_source.index("stream.seek(0)")
            < database_source.index("digest.update(chunk)")
            < database_source.index("publish_write_once_file(temporary_path, path)")
        ) or 'with path.open("rb")' in database_source:
            errors.append(
                "single-database backup must fsync and hash the staged artifact before publication"
            )
    except ValueError:
        errors.append("single-database write-once control is missing")

    try:
        bundle_source = postgres_source[
            postgres_source.index("def backup_bundle("):
            postgres_source.index("def _verify_bundle_details(")
        ]
        if not (
            bundle_source.index("create_write_once_directory(output_dir)")
            < bundle_source.index("backup_database(")
        ) or any(
            control not in bundle_source
            for control in (
                "write_fsynced_temporary_bytes(",
                "_bundle_owned=True",
                "publish_bundle_write_once_file(temporary_manifest, manifest_path)",
                "cleanup_created_directory_after_failure(directory_claim, error)",
            )
        ):
            errors.append("PostgreSQL bundle output is not atomically claimed and safely cleaned")
    except ValueError:
        errors.append("PostgreSQL bundle write-once control is missing")
    try:
        postgres_verify_source = postgres_source[
            postgres_source.index("def _verify_bundle_details("):
            postgres_source.index("def verify_bundle(")
        ]
        if not (
            postgres_verify_source.index(
                "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)"
            )
            < postgres_verify_source.index("load_key_file(key_file)")
            < postgres_verify_source.index("open_stable_binary(")
            < postgres_verify_source.index("decrypt_stream(")
            and "expected_identity=identities[artifact]" in postgres_verify_source
            and "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities"
            in postgres_verify_source
            and "authenticate_file(" not in postgres_verify_source
        ):
            errors.append(
                "PostgreSQL bundle verification must bind exact leaves to one stable stream"
            )
    except ValueError:
        errors.append("PostgreSQL bundle exact-leaf verification is missing")

    try:
        vault_request_source = vault_source[
            vault_source.index("def _snapshot_request_inputs("):
            vault_source.index("def _open_connection(")
        ]
        skip_verify_check = 'if "VAULT_SKIP_VERIFY" in os.environ:'
        if not (
            skip_verify_check in vault_request_source
            and vault_request_source.index(skip_verify_check)
            < vault_request_source.index("_validated_address(")
            < vault_request_source.index("_validated_ca_file(")
            < vault_request_source.index("_read_token_file(token_file)")
            and 'raise ValueError("inherited Vault TLS verification override is forbidden")'
            in vault_request_source
        ):
            errors.append(
                "Vault TLS skip-verify environment must fail closed before token access"
            )
    except ValueError:
        errors.append("Vault TLS skip-verify environment control is missing")

    try:
        offline_source = vault_source[
            vault_source.index("def _offline_environment("):
            vault_source.index("def _validated_ca_file(")
        ]
        inspect_source = vault_source[
            vault_source.index("def _inspect_snapshot("):
            vault_source.index("def _hash_and_size(")
        ]
        forbidden_environment_controls = (
            "os.environ.copy()",
            'environment["VAULT_TOKEN"]',
            'environment["VAULT_ADDR"]',
            'environment["VAULT_CACERT"]',
        )
        if (
            any(control in vault_source for control in forbidden_environment_controls)
            or "env=_offline_environment()" not in inspect_source
            or "os.environ[name]" not in offline_source
            or "if name in os.environ" not in offline_source
        ):
            errors.append("Vault offline inspection must use a rebuilt token-free environment")
    except ValueError:
        errors.append("Vault offline inspection environment control is missing")

    try:
        download_source = vault_source[
            vault_source.index("def _download_snapshot("):
            vault_source.index("def _upload_snapshot(")
        ]
        upload_source = vault_source[
            vault_source.index("def _upload_snapshot("):
            vault_source.index("def _inspect_snapshot(")
        ]
        if not (
            '"GET",\n            _RAFT_SNAPSHOT_PATH' in download_source
            and "response.status != 200" in download_source
            and 'output_path.open("xb")' in download_source
            and download_source.index("stream.write(chunk)")
            < download_source.index("stream.flush()")
            < download_source.index("os.fsync(stream.fileno())")
            and '"POST",\n            _RAFT_SNAPSHOT_PATH' in upload_source
            and "response.status not in (200, 204)" in upload_source
            and 'headers["Content-Length"] = str(size_bytes)' in upload_source
            and "snapshot-force" not in vault_source
            and '"-force"' not in vault_source
        ):
            errors.append("Vault snapshot API must stream over the fixed non-force endpoint")
    except ValueError:
        errors.append("Vault snapshot HTTPS streaming control is missing")

    try:
        create_snapshot_source = vault_source[
            vault_source.index("def create_snapshot("):
            vault_source.index("def verify_snapshot(")
        ]
        if not (
            create_snapshot_source.index("create_write_once_directory(output_dir)")
            < create_snapshot_source.index("_snapshot_binding_inputs(")
            < create_snapshot_source.index("_snapshot_request_inputs(")
            < create_snapshot_source.index("_download_snapshot(")
        ) or any(
            control not in create_snapshot_source
            for control in (
                "write_fsynced_temporary_bytes(",
                "publish_bundle_write_once_file(publishing_path, snapshot_path)",
                "publish_bundle_write_once_file(temporary_manifest, manifest_path)",
                "cleanup_created_directory_after_failure(directory_claim, error)",
                "discard_claimed_temporary_file(temporary_path)",
            )
        ) or not (
            create_snapshot_source.index("_inspect_snapshot(temporary_path")
            < create_snapshot_source.index(
                "publish_bundle_write_once_file(publishing_path, snapshot_path)"
            )
            < create_snapshot_source.index("_manifest_payload(")
            < create_snapshot_source.index(
                "publish_bundle_write_once_file(temporary_manifest, manifest_path)"
            )
        ) or "os.replace(temporary_path, snapshot_path)" in create_snapshot_source:
            errors.append("Vault output is not claimed before secret/process access")
    except ValueError:
        errors.append("Vault snapshot write-once control is missing")
    try:
        vault_verify_source = vault_source[
            vault_source.index("def _verified_snapshot("):
            vault_source.index("def verify_snapshot(")
        ]
        if not (
            vault_verify_source.index(
                "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)"
            )
            < vault_verify_source.index("_snapshot_binding_inputs(")
            < vault_verify_source.index("open_stable_binary(")
            < vault_verify_source.index("_inspect_snapshot(")
            and "expected_identity=identities[SNAPSHOT_NAME]"
            in vault_verify_source
            and "tempfile.NamedTemporaryFile(" in vault_verify_source
            and "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities"
            in vault_verify_source
        ):
            errors.append(
                "Vault verification must bind exact leaves to one inspected staged stream"
            )
    except ValueError:
        errors.append("Vault exact-leaf verification is missing")

    if redis_source is not None:
        try:
            archive_source = redis_source[
                redis_source.index("def _write_encrypted_archive("):
                redis_source.index("def backup_release(")
            ]
            if not (
                archive_source.index("return_code = process.wait()")
                < archive_source.index("destination.flush()")
                < archive_source.index("os.fsync(destination.fileno())")
                < archive_source.index(
                    "publish_bundle_write_once_file(publishing_path, path)"
                )
            ):
                errors.append(
                    "Redis backup must fsync the staged artifact before publication"
                )
            if "discard_claimed_temporary_file(temporary_path)" not in archive_source:
                errors.append("Redis staged artifact cleanup can replace its primary error")
        except ValueError:
            errors.append("Redis staged artifact durability control is missing")
        try:
            redis_release_source = redis_source[
                redis_source.index("def backup_release("):
                redis_source.index("def _verify_release_backup_details(")
            ]
            for control in (
                "directory_claim = create_write_once_directory(output_dir)",
                "cleanup_created_directory_after_failure(",
                "rollback_unconfirmed = not cleanup_created_directory_after_failure(",
                "raise fatal_error from restart_error",
            ):
                if control not in redis_release_source:
                    errors.append(f"Redis rollback/restart priority is missing: {control}")
            if "cleanup_created_directory(directory)" in redis_release_source:
                errors.append("Redis rollback bypasses claimed-directory diagnostics")
        except ValueError:
            errors.append("Redis rollback/restart priority control is missing")
        try:
            redis_verify_source = redis_source[
                redis_source.index("def _verify_release_backup_details("):
                redis_source.index("def verify_release_backup(")
            ]
            if not (
                redis_verify_source.index(
                    "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)"
                )
                < redis_verify_source.index("load_key_file(key_file)")
                < redis_verify_source.index("open_stable_binary(")
                < redis_verify_source.index("decrypt_stream(")
                and "expected_identity=identities[ARTIFACT_NAME]"
                in redis_verify_source
                and "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities"
                in redis_verify_source
                and "authenticate_file(" not in redis_verify_source
            ):
                errors.append(
                    "Redis verification must bind exact leaves to one stable stream"
                )
        except ValueError:
            errors.append("Redis exact-leaf verification is missing")
    return errors


def backup_key_contract_errors(
    crypto_source: str,
    postgres_source: str,
    redis_source: str,
    vault_source: str,
    audit_source: str,
) -> list[str]:
    """Keep one stable, least-privilege key snapshot per backup operation."""

    errors: list[str] = []
    try:
        ast.parse(crypto_source)
        ast.parse(postgres_source)
        ast.parse(redis_source)
        ast.parse(vault_source)
        ast.parse(audit_source)
    except SyntaxError:
        return ["backup key tooling must parse as Python"]

    try:
        acl_source = crypto_source[
            crypto_source.index("def _read_windows_acl("):
            crypto_source.index("def _validate_windows_acl(")
        ]
        required_acl_controls = (
            "DuplicateHandle",
            "_WINDOWS_READ_CONTROL",
            "SafeFileHandle",
            "FileSecurity",
            '"handle_list": [inherited_handle]',
            "close_fds=True",
            "timeout=15",
            '"System32"',
            '"WindowsPowerShell"',
            '"powershell.exe"',
            '"SystemRoot": str(windows_directory)',
            "dacl_present",
            "owner",
            "sddl",
            "inherited",
        )
        if (
            any(control not in acl_source for control in required_acl_controls)
            or acl_source.count("SafeFileHandle") < 2
            or "Get-Acl" in acl_source
            or "FileStream" in acl_source
        ):
            errors.append(
                "Windows backup key ACL must use one least-privilege inherited handle and closed evidence"
            )
    except ValueError:
        errors.append("Windows backup key handle ACL contract is missing")

    try:
        permission_source = crypto_source[
            crypto_source.index("def _validate_windows_acl("):
            crypto_source.index("def key_id(")
        ]
        loader_source = permission_source[
            permission_source.index("def load_key_file("):
        ]
        if (
            'set(acl) != {' not in permission_source
            or '"dacl_present",' not in permission_source
            or 'acl.get("dacl_present") is not True' not in permission_source
            or 'owner not in allowed' not in permission_source
            or 'rule.get("inherited") is not False' not in permission_source
            or 'return current, owner, sddl' not in permission_source
            or "_validate_windows_acl(descriptor)" not in permission_source
            or loader_source.count("has_link_or_reparse_ancestor(path)") < 2
            or "metadata.st_nlink != 1" not in loader_source
            or loader_source.count("_REPARSE_POINT") < 4
            or loader_source.count("stable_file_identity(") < 4
            or "stable_file_identity(final_metadata) != stable_file_identity(metadata)"
            not in loader_source
            or loader_source.count("_validate_key_permissions(") != 2
            or "final_permission_identity != permission_identity" not in loader_source
            or "require_read_only: bool = False" not in loader_source
        ):
            errors.append(
                "backup key loader must bind bytes, shape, reparse and permission identity to one descriptor"
            )
    except ValueError:
        errors.append("stable backup key loader contract is missing")

    try:
        vault_loader = vault_source[
            vault_source.index("def _load_manifest_key_file("):
            vault_source.index("def _postgres_manifest_binding(")
        ]
        if (
            vault_loader.count("load_key_file(") != 1
            or "require_read_only=True" not in vault_loader
            or "_validate_manifest_key_read_only" in vault_source
        ):
            errors.append(
                "Vault manifest key read-only policy must be part of one stable key load"
            )
    except ValueError:
        errors.append("Vault manifest key loader contract is missing")

    try:
        postgres_backup = postgres_source[
            postgres_source.index("def backup_bundle("):
            postgres_source.index("def _verify_bundle_details(")
        ]
        postgres_verify = postgres_source[
            postgres_source.index("def _verify_bundle_details("):
            postgres_source.index("def verify_bundle(")
        ]
        postgres_restore = postgres_source[
            postgres_source.index("def restore_bundle("):
            postgres_source.index("def run_restore(")
        ]
        if (
            postgres_backup.count("load_key_file(key_file)") != 1
            or postgres_backup.count("_loaded_key=key") != 1
            or "_manifest_hmac_sha256(\n                manifest,\n                key," not in postgres_backup
            or postgres_verify.count("load_key_file(key_file)") != 1
            or "identities,\n        key," not in postgres_verify
            or "manifest, verified, _, identities, key" not in postgres_restore
            or postgres_restore.count("_loaded_key=key") != 1
            or "load_key_file(" in postgres_restore
        ):
            errors.append(
                "PostgreSQL bundle backup and restore must each use one private key snapshot"
            )
    except ValueError:
        errors.append("PostgreSQL operation-local key contract is missing")

    try:
        redis_verify = redis_source[
            redis_source.index("def _verify_release_backup_details("):
            redis_source.index("def verify_release_backup(")
        ]
        redis_restore = redis_source[
            redis_source.index("def restore_release("):
            redis_source.index("def _add_release_arguments(")
        ]
        if (
            redis_verify.count("load_key_file(key_file)") != 1
            or "identities, key" not in redis_verify
            or "manifest, _, _, identities, key = _verify_release_backup_details(" not in redis_restore
            or "load_key_file(" in redis_restore
        ):
            errors.append("Redis restore must use the verifier's private key snapshot")
    except ValueError:
        errors.append("Redis operation-local key contract is missing")

    try:
        audit_create = audit_source[
            audit_source.index("def _archive_events_in_claimed_directory("):
            audit_source.index("def archive_events(")
        ]
        audit_verify = audit_source[
            audit_source.index("def verify_archive("):
            audit_source.index("def _read_database_url_file(")
        ]
        if (
            audit_create.count("load_key_file(key_file)") != 1
            or audit_verify.count("load_key_file(key_file)") != 1
        ):
            errors.append("audit archive operations must each load one key snapshot")
    except ValueError:
        errors.append("audit archive operation-local key contract is missing")
    return errors


def private_secret_contract_errors(
    private_source: str,
    crypto_source: str,
    vault_source: str,
    audit_source: str,
    edge_source: str,
    expiry_source: str,
) -> list[str]:
    errors: list[str] = []
    try:
        for source in (
            private_source,
            crypto_source,
            vault_source,
            audit_source,
            edge_source,
            expiry_source,
        ):
            ast.parse(source)
    except SyntaxError:
        return ["private secret tooling must parse as Python"]
    try:
        reader = private_source[
            private_source.index("def read_private_secret_bytes("):
        ]
        if (
            "not path.is_absolute()" not in reader
            or "with open_stable_binary(path) as (stream, opened):" not in reader
            or "opened.st_nlink != 1" not in reader
            or reader.count("validate_private_file_permissions(") != 2
            or "stream.read(max_bytes + 1)" not in reader
            or "os.fstat(stream.fileno())" not in reader
            or "stable_file_identity(final_opened) != stable_file_identity(opened)"
            not in reader
            or "final_permission_identity != permission_identity" not in reader
            or ".read_bytes(" in reader
        ):
            errors.append(
                "strict private secret reader must bind bytes, identity and permissions to one descriptor"
            )
    except ValueError:
        errors.append("strict private secret reader is missing")
    try:
        permission_wrapper = crypto_source[
            crypto_source.index("def validate_private_file_permissions("):
            crypto_source.index("def _same_file(")
        ]
        if (
            "return _validate_key_permissions(" not in permission_wrapper
            or "descriptor," not in permission_wrapper
            or "require_read_only=require_read_only" not in permission_wrapper
        ):
            errors.append("private secret permission wrapper must reuse descriptor ACL policy")
    except ValueError:
        errors.append("private secret permission wrapper is missing")
    callers = (
        (
            "Vault maintenance token",
            vault_source,
            "def _read_token_file(",
            "def _offline_environment(",
            4096,
        ),
        (
            "audit database URL",
            audit_source,
            "def _read_database_url_file(",
            "def _cli_datetime(",
            "MAX_DATABASE_URL_BYTES",
        ),
        (
            "Edge TLS private key",
            edge_source,
            "def _validate_material(",
            "def validate_edge_tls(",
            "MAX_PRIVATE_KEY_BYTES",
        ),
        (
            "internal TLS private key",
            expiry_source,
            "def _load_private_key(",
            "def _public_key_bytes(",
            "MAX_PRIVATE_KEY_BYTES",
        ),
    )
    for label, source, start, end, limit in callers:
        try:
            caller = source[source.index(start):source.index(end)]
            expected_limit = str(limit)
            if (
                caller.count("read_private_secret_bytes(") != 1
                or f"max_bytes={expected_limit}" not in caller
                or "os.open(" in caller
                or "os.read(" in caller
                or ".read_bytes(" in caller
            ):
                errors.append(f"{label} must use one strict private secret snapshot")
        except ValueError:
            errors.append(f"{label} private secret contract is missing")
    return errors


def _load_module(path: Path, name: str, source: str) -> ModuleType:
    module = ModuleType(name)
    module.__file__ = str(path)
    parent_name, _, child_name = name.rpartition(".")
    module.__package__ = parent_name
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    if parent_name:
        parent = sys.modules[parent_name]
        setattr(parent, child_name, module)
    return module


def _load_verified_modules(
    assets: dict[Path, str],
) -> tuple[ModuleType, ModuleType, ModuleType, ModuleType, ModuleType, ModuleType]:
    import scripts as scripts_package

    names = (
        "scripts.production_docker_environment",
        "scripts.backup_crypto",
        "scripts.backup_output_policy",
        "scripts.postgres_maintenance",
        "scripts.audit_archive",
        "scripts.vault_maintenance",
        "scripts.redis_maintenance",
        "scripts.restore_readiness",
    )
    missing = object()
    previous_modules = {name: sys.modules.get(name, missing) for name in names}
    previous_attributes = {
        name.rpartition(".")[2]: getattr(
            scripts_package, name.rpartition(".")[2], missing
        )
        for name in names
    }
    try:
        _load_module(
            PRODUCTION_DOCKER_ENVIRONMENT,
            names[0],
            assets[PRODUCTION_DOCKER_ENVIRONMENT],
        )
        _load_module(CRYPTO_SCRIPT, names[1], assets[CRYPTO_SCRIPT])
        output_policy = _load_module(
            OUTPUT_POLICY_SCRIPT,
            names[2],
            assets[OUTPUT_POLICY_SCRIPT],
        )
        maintenance = _load_module(SCRIPT, names[3], assets[SCRIPT])
        audit_archive = _load_module(
            AUDIT_ARCHIVE_SCRIPT,
            names[4],
            assets[AUDIT_ARCHIVE_SCRIPT],
        )
        vault = _load_module(VAULT_SCRIPT, names[5], assets[VAULT_SCRIPT])
        redis = _load_module(REDIS_SCRIPT, names[6], assets[REDIS_SCRIPT])
        readiness = _load_module(
            RESTORE_READINESS,
            names[7],
            assets[RESTORE_READINESS],
        )
        return output_policy, maintenance, audit_archive, vault, redis, readiness
    finally:
        for name, previous in previous_modules.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        for attribute, previous in previous_attributes.items():
            if previous is missing:
                try:
                    delattr(scripts_package, attribute)
                except AttributeError:
                    pass
            else:
                setattr(scripts_package, attribute, previous)


def _command_destinations(parser, command: str) -> dict[str, object]:
    subparsers = next(
        (
            action.choices
            for action in parser._actions
            if hasattr(action, "choices") and action.choices
        ),
        {},
    )
    selected = subparsers.get(command)
    if selected is None:
        return {}
    return {action.dest: action for action in selected._actions}


def audit_archive_contract_errors(audit_archive, source: str, backup_output_policy) -> list[str]:
    """Verify the read-only encrypted platform-audit archive contract."""

    errors: list[str] = []
    expected_record_fields = (
        "schema_version", "redaction_version", "id", "tenant_id", "created_at",
        "actor_id", "user_id", "device_id", "event_type", "action", "result",
        "entity_type", "entity_id", "trace_id", "policy_version", "ip_address",
        "user_agent", "details",
    )
    if tuple(getattr(audit_archive, "RECORD_FIELDS", ())) != expected_record_fields:
        errors.append("audit archive record schema is not the reviewed 18-field projection")
    if (
        getattr(audit_archive, "ARTIFACT_NAME", None) != "audit-events.v1.jsonl.enc"
        or getattr(audit_archive, "MANIFEST_NAME", None) != "manifest.json"
        or getattr(audit_archive, "PRODUCTION_ACCEPTANCE", None) is not False
        or getattr(audit_archive, "MANIFEST_HKDF_INFO", None)
        != b"email-platform/audit-archive-manifest/v1/hmac-sha256"
    ):
        errors.append("audit archive envelope or production-acceptance contract drifted")
    for function_name in ("archive_events", "verify_archive", "project_audit_event"):
        if not callable(getattr(audit_archive, function_name, None)):
            errors.append(f"audit archive function is missing: {function_name}")
    for function_name in (
        "create_write_once_directory",
        "prepare_write_once_file",
        "publish_bundle_write_once_file",
        "cleanup_created_directory_after_failure",
        "discard_claimed_temporary_file",
        "require_exact_regular_files",
    ):
        if getattr(audit_archive, function_name, None) is not getattr(
            backup_output_policy, function_name, None
        ):
            errors.append(f"audit archive does not reuse output policy: {function_name}")

    parser = audit_archive.build_parser()
    actions = [
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    ]
    commands = set(actions[0].choices) if actions else set()
    if commands != {"archive", "verify"}:
        errors.append("audit archive CLI must expose only archive and verify")
    required = {
        "archive": {
            "output_dir", "key_file", "database_url_file", "tenant_id",
            "from_created_at", "until_created_at", "tool_source_commit",
        },
        "verify": {
            "input_dir", "key_file", "expected_tenant_id",
            "expected_from_created_at", "expected_until_created_at",
        },
    }
    if actions:
        for command, destinations in required.items():
            parser_action = actions[0].choices.get(command)
            present = {
                item.dest
                for item in getattr(parser_action, "_actions", ())
                if getattr(item, "required", False) is True
            }
            if not destinations.issubset(present):
                errors.append(f"audit archive {command} arguments are incomplete")

    try:
        cli_archive = source[source.index('if args.command == "archive":'):source.index("summary = verify_archive(")]
        if not (
            cli_archive.index("create_write_once_directory(args.output_dir)")
            < cli_archive.index("_read_database_url_file(args.database_url_file)")
            < cli_archive.index("create_engine(database_url)")
        ):
            errors.append("audit archive CLI must claim output before database secret access")
        archive_writer = source[
            source.index("def _archive_events_in_claimed_directory("):
            source.index("def archive_events(")
        ]
        archive_owner = source[
            source.index("def archive_events("):
            source.index("def _read_manifest(")
        ]
        if (
            archive_writer.count("discard_claimed_temporary_file(") != 2
            or "cleanup_created_directory_after_failure(directory_claim, error)"
            not in archive_owner
            or "cleanup_created_directory_after_failure(directory_claim, error)"
            not in cli_archive
        ):
            errors.append("audit archive cleanup can replace its primary failure")
        verifier = source[source.index("def verify_archive("):source.index("def _read_database_url_file(")]
        if not (
            verifier.index("require_exact_regular_files(")
            < verifier.index("_read_manifest(")
            < verifier.index("hmac.compare_digest(")
            < verifier.index("_validate_manifest_structure(")
            < verifier.index("decrypt_stream(\n            encrypted,\n            None,")
            < verifier.index("decrypt_stream(\n            encrypted,\n            verifier,")
            < verifier.index("verifier.finish()")
            and "expected_identity=identities[MANIFEST_NAME]" in verifier
            and "expected_identity=identities[ARTIFACT_NAME]" in verifier
            and "require_exact_regular_files(" in verifier[verifier.index("verifier.finish()"):]
            and "_hash_file(artifact_path)" not in verifier
        ):
            errors.append("audit archive verification order is not authenticate-before-parse")
        export = source[source.index("def _event_chunks("):source.index("def _hash_file(")]
        for required_control in (
            "AuditEvent.tenant_id == tenant_id",
            "AuditEvent.created_at >= created_from",
            "AuditEvent.created_at < created_to",
            "AuditEvent.id > last_id",
            "order_by(AuditEvent.created_at, AuditEvent.id)",
        ):
            if required_control not in export:
                errors.append(f"audit archive keyset/window control is missing: {required_control}")
    except ValueError:
        errors.append("audit archive structural ordering controls are missing")
    for forbidden in ("prune_events", "delete_events", "restore_events", "truncate_events"):
        if forbidden in source:
            errors.append(f"audit archive exposes forbidden source mutation: {forbidden}")
    return errors


def redis_backup_contract_errors(redis) -> list[str]:
    """Validate the release-bound Redis artifact and CLI surface."""

    errors: list[str] = []
    for helper in ("_stop_command", "_start_command", "_status_command", "_health_command"):
        if not callable(getattr(redis, helper, None)):
            errors.append(f"Redis backup lifecycle helper is missing: {helper}")
    if callable(getattr(redis, "_start_command", None)) and redis._start_command()[-6:] != [
        "up", "-d", "--no-build", "--pull", "never", "redis"
    ]:
        errors.append("Redis backup restart must forbid builds and pulls")
    if callable(getattr(redis, "_health_command", None)) and redis._health_command()[-4:] != [
        "exec", "-T", "redis", "/usr/local/bin/redis-healthcheck"
    ]:
        errors.append("Redis backup restart must run the reviewed healthcheck")
    if (
        getattr(redis, "ARTIFACT_NAME", None) != "redis-data.tar.enc"
        or getattr(redis, "MANIFEST_NAME", None) != "redis-manifest.json"
        or getattr(redis, "MANIFEST_SCHEMA", None) != 1
        or getattr(redis, "MANIFEST_HMAC_FIELD", None) != "manifest_hmac_sha256"
    ):
        errors.append("Redis release artifact names/schema are not fixed")
    if set(
        getattr(
            redis,
            "RELEASE_BINDING_FIELDS",
            getattr(redis, "_RELEASE_FIELDS", ()),
        )
    ) != {
        "release_tag",
        "release_commit",
        "migration_head",
        "container_manifest_sha256",
    }:
        errors.append("Redis release binding fields are incomplete")

    parser = redis.build_parser()
    commands = {
        command
        for action in parser._actions
        if hasattr(action, "choices") and action.choices
        for command in action.choices
    }
    if commands != {"backup-release", "verify-release", "restore-release"}:
        errors.append("Redis maintenance commands are incomplete")
        return errors
    common = {
        "key_file",
        "release_tag",
        "release_commit",
        "migration_head",
        "container_manifest_sha256",
        "recovery_set",
    }
    required_by_command = {
        "backup-release": common | {"output_dir", "postgres_manifest"},
        "verify-release": common | {"input_dir", "postgres_manifest_sha256"},
        "restore-release": common | {"input_dir", "confirm_release_tag"},
    }
    subparsers = next(
        action.choices
        for action in parser._actions
        if hasattr(action, "choices") and action.choices
    )
    for command, required in required_by_command.items():
        destinations = _command_destinations(parser, command)
        missing = required - destinations.keys()
        if missing:
            errors.append(f"Redis {command} arguments are missing: {sorted(missing)}")
        group_only = (
            {"postgres_manifest", "postgres_manifest_sha256"}
            if command == "restore-release"
            else set()
        )
        for destination in required - group_only:
            argument = destinations.get(destination)
            if argument is not None and getattr(argument, "required", False) is not True:
                errors.append(f"Redis {command} must require --{destination.replace('_', '-')}")
        forbidden = {"redis_url", "redis_url_file", "password", "password_file"}
        if forbidden & destinations.keys():
            errors.append(f"Redis {command} must not accept Redis credential/URL arguments")
    restore_parser = subparsers["restore-release"]
    binding_groups = [
        group
        for group in restore_parser._mutually_exclusive_groups
        if {action.dest for action in group._group_actions}
        == {"postgres_manifest", "postgres_manifest_sha256"}
    ]
    if not binding_groups or binding_groups[0].required is not True:
        errors.append(
            "Redis restore-release must require exactly one PostgreSQL manifest path or SHA"
        )
    return errors


def main() -> int:
    try:
        assets = load_assets()
    except OSError:
        print("Cannot load backup tooling assets", file=sys.stderr)
        return 1
    maintenance_source = assets[SCRIPT]
    crypto_source = assets[CRYPTO_SCRIPT]
    output_policy_source = assets[OUTPUT_POLICY_SCRIPT]
    audit_archive_source = assets[AUDIT_ARCHIVE_SCRIPT]
    vault_source = assets[VAULT_SCRIPT]
    redis_source = assets[REDIS_SCRIPT]
    readiness_source = assets[RESTORE_READINESS]
    private_secret_source = assets[PRIVATE_SECRET_FILE]
    edge_tls_source = assets[EDGE_TLS_VALIDATOR]
    internal_tls_expiry_source = assets[INTERNAL_TLS_EXPIRY]
    docker_environment_errors = production_docker_environment_contract_errors(
        assets[PRODUCTION_DOCKER_ENVIRONMENT],
        maintenance_source,
        redis_source,
    )
    if docker_environment_errors:
        print("; ".join(docker_environment_errors), file=sys.stderr)
        return 1
    try:
        (
            backup_output_policy,
            maintenance,
            audit_archive,
            vault,
            redis,
            readiness,
        ) = _load_verified_modules(assets)
        parser = maintenance.build_parser()
    except Exception:
        print("Cannot load backup tooling", file=sys.stderr)
        return 1
    postgres_commands = (
        maintenance.backup_command(),
        maintenance.restore_command(target_db="restore_verifier"),
        maintenance.create_database_command(target_db="restore_verifier"),
        maintenance.drop_database_command(target_db="restore_verifier"),
    )
    compose_errors = production_compose_identity_errors(
        postgres_commands,
        "PostgreSQL",
    )
    if compose_errors:
        print("; ".join(compose_errors), file=sys.stderr)
        return 1
    subparser_actions = [
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    ]
    commands = set(subparser_actions[0].choices) if subparser_actions else set()
    required_commands = {
        "backup-bundle",
        "verify-bundle",
        "restore-bundle",
        "drill-bundle",
    }
    if not required_commands.issubset(commands):
        print(f"Missing backup bundle commands: {sorted(required_commands - commands)}", file=sys.stderr)
        return 1
    if tuple(maintenance.BACKUP_BUNDLE_DATABASES) != ("platform", "keycloak"):
        print("Backup bundle must require platform and keycloak databases", file=sys.stderr)
        return 1
    if maintenance.RESTORE_OWNER_ENV != {
        "platform": "POSTGRES_USER",
        "keycloak": "KEYCLOAK_DB_USER",
    }:
        print("Backup restore owners must isolate platform and Keycloak roles", file=sys.stderr)
        return 1
    keycloak_restore = maintenance.restore_command(
        target_db="keycloak_restore",
        owner_env=maintenance.RESTORE_OWNER_ENV["keycloak"],
    )[-1]
    keycloak_create = maintenance.create_database_command(
        target_db="keycloak_restore",
        owner_env=maintenance.RESTORE_OWNER_ENV["keycloak"],
    )[-1]
    if '--role="$KEYCLOAK_DB_USER"' not in keycloak_restore:
        print("Keycloak restore must set the dedicated database role", file=sys.stderr)
        return 1
    if '--owner="$KEYCLOAK_DB_USER"' not in keycloak_create:
        print("Keycloak restore database must use the dedicated owner", file=sys.stderr)
        return 1
    if "PASSWORD" in keycloak_restore or "PASSWORD" in keycloak_create:
        print("Database maintenance commands must not carry passwords", file=sys.stderr)
        return 1
    if maintenance.CRITICAL_TABLES != {
        "platform": ("users", "devices", "audit_events"),
        "keycloak": (
            "realm",
            "user_entity",
            "credential",
            "event_entity",
            "admin_event_entity",
        ),
    }:
        print("Backup drill critical-table whitelist is incomplete", file=sys.stderr)
        return 1
    for function_name in (
        "backup_bundle",
        "verify_bundle",
        "verify_bundle_release_binding",
        "restore_bundle",
        "drill_bundle",
    ):
        if not callable(getattr(maintenance, function_name, None)):
            print(f"Missing backup function: {function_name}", file=sys.stderr)
            return 1
    if (
        maintenance.BACKUP_MANIFEST_SCHEMA != 3
        or maintenance.BACKUP_RELEASE_MANIFEST_SCHEMA != 5
    ):
        print("Authenticated release-bound backup schema v5 is required", file=sys.stderr)
        return 1
    if (
        maintenance.BACKUP_MANIFEST_HMAC_FIELD != "manifest_hmac_sha256"
        or maintenance.BACKUP_MANIFEST_HKDF_INFO
        != b"email-platform/postgres-backup-manifest/v5/hmac-sha256"
    ):
        print("Release-bound backup manifest MAC domain is not fixed to v5", file=sys.stderr)
        return 1
    for required_control in (
        "hmac.compare_digest(actual_mac, expected_mac)",
        "_canonical_manifest_bytes(manifest)",
        "HKDF(",
    ):
        if required_control not in maintenance_source:
            print(
                f"Release-bound backup manifest authentication is missing: {required_control}",
                file=sys.stderr,
            )
            return 1
    if not callable(getattr(maintenance, "_manifest_hmac_sha256", None)):
        print("Release-bound backup manifest MAC helper is missing", file=sys.stderr)
        return 1
    for function_name in (
        "create_write_once_directory",
        "prepare_write_once_file",
        "publish_bundle_write_once_file",
        "publish_write_once_file",
        "cleanup_created_directory",
        "write_fsynced_temporary_bytes",
    ):
        if not callable(getattr(backup_output_policy, function_name, None)):
            print(f"Missing backup output policy function: {function_name}", file=sys.stderr)
            return 1
    if maintenance.create_write_once_directory is not backup_output_policy.create_write_once_directory:
        print("PostgreSQL bundle does not use the shared output policy", file=sys.stderr)
        return 1
    if (
        maintenance.publish_bundle_write_once_file
        is not backup_output_policy.publish_bundle_write_once_file
    ):
        print("PostgreSQL bundle does not use strict shared publication", file=sys.stderr)
        return 1
    if (
        maintenance.write_fsynced_temporary_bytes
        is not backup_output_policy.write_fsynced_temporary_bytes
    ):
        print("PostgreSQL manifest does not use stable temporary output", file=sys.stderr)
        return 1
    try:
        audit_archive_errors = audit_archive_contract_errors(
            audit_archive,
            audit_archive_source,
            backup_output_policy,
        )
    except Exception as error:
        print(f"Cannot load audit archive tooling: {error}", file=sys.stderr)
        return 1
    if audit_archive_errors:
        print("; ".join(audit_archive_errors), file=sys.stderr)
        return 1
    for command in required_commands:
        action = subparser_actions[0].choices[command]
        key_file = next(
            (item for item in action._actions if item.dest == "key_file"),
            None,
        )
        if key_file is None or key_file.required is not True:
            print(f"Backup command must require --key-file: {command}", file=sys.stderr)
            return 1
    if set(maintenance.RELEASE_BINDING_FIELDS) != {
        "release_tag",
        "release_commit",
        "migration_head",
        "container_manifest_sha256",
    }:
        print("Release-bound backup fields are incomplete", file=sys.stderr)
        return 1

    vault_parser_actions = [
        action
        for action in vault.build_parser()._actions
        if hasattr(action, "choices") and action.choices
    ]
    vault_commands = {
        command
        for action in vault_parser_actions
        for command in action.choices
    }
    if vault_commands != {"backup", "verify", "restore"}:
        print("Vault maintenance commands are incomplete", file=sys.stderr)
        return 1
    if (
        vault.MANIFEST_SCHEMA != 2
        or vault.MANIFEST_HMAC_FIELD != "manifest_hmac_sha256"
        or vault.MANIFEST_HKDF_INFO
        != b"email-platform/vault-snapshot-manifest/v2/hmac-sha256"
    ):
        print("Vault snapshot manifest authentication must be fixed to schema v2", file=sys.stderr)
        return 1
    for required_control in (
        "hmac.compare_digest(actual_mac, expected_mac)",
        "_canonical_manifest_bytes(manifest)",
        "postgres_manifest_sha256",
        "key_id(manifest_key)",
        "_load_manifest_key_file(manifest_key_file)",
        "HKDF(",
        "ssl.PROTOCOL_TLS_CLIENT",
        "ssl.TLSVersion.TLSv1_2",
        "context.check_hostname = True",
        "context.verify_mode = ssl.CERT_REQUIRED",
    ):
        if required_control not in vault_source:
            print(f"Vault snapshot manifest control is missing: {required_control}", file=sys.stderr)
            return 1
    vault_subparsers = vault_parser_actions[0].choices if vault_parser_actions else {}
    for command in ("backup", "verify", "restore"):
        action = vault_subparsers.get(command)
        destinations = {
            item.dest: item
            for item in action._actions
        } if action is not None else {}
        for destination in ("manifest_key_file", "recovery_set", "postgres_manifest"):
            argument = destinations.get(destination)
            if argument is None or argument.required is not True:
                print(
                    f"Vault {command} must require --{destination.replace('_', '-')}",
                    file=sys.stderr,
                )
                return 1
        if command in ("backup", "restore"):
            ca_argument = destinations.get("ca_file")
            if ca_argument is None or ca_argument.required is not True:
                print(
                    f"Vault {command} must require --ca-file",
                    file=sys.stderr,
                )
                return 1
    for function_name in ("create_snapshot", "verify_snapshot", "restore_snapshot"):
        if not callable(getattr(vault, function_name, None)):
            print(f"Missing Vault snapshot function: {function_name}", file=sys.stderr)
            return 1
    if tuple(vault._OFFLINE_ENVIRONMENT_VARIABLES) != (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    ):
        print("Vault offline inspection environment allowlist has drifted", file=sys.stderr)
        return 1
    if vault.create_write_once_directory is not backup_output_policy.create_write_once_directory:
        print("Vault snapshot does not use the shared output policy", file=sys.stderr)
        return 1
    if (
        vault.publish_bundle_write_once_file
        is not backup_output_policy.publish_bundle_write_once_file
    ):
        print("Vault snapshot does not use strict shared publication", file=sys.stderr)
        return 1
    if (
        vault.write_fsynced_temporary_bytes
        is not backup_output_policy.write_fsynced_temporary_bytes
    ):
        print("Vault manifest does not use stable temporary output", file=sys.stderr)
        return 1
    output_errors = backup_output_contract_errors(
        output_policy_source,
        maintenance_source,
        vault_source,
        redis_source,
    )
    if output_errors:
        print("; ".join(output_errors), file=sys.stderr)
        return 1
    key_errors = backup_key_contract_errors(
        crypto_source,
        maintenance_source,
        redis_source,
        vault_source,
        audit_archive_source,
    )
    if key_errors:
        print("; ".join(key_errors), file=sys.stderr)
        return 1
    private_secret_errors = private_secret_contract_errors(
        private_secret_source,
        crypto_source,
        vault_source,
        audit_archive_source,
        edge_tls_source,
        internal_tls_expiry_source,
    )
    if private_secret_errors:
        print("; ".join(private_secret_errors), file=sys.stderr)
        return 1

    try:
        redis_errors = redis_backup_contract_errors(redis)
    except Exception as error:
        print(f"Cannot load Redis backup tooling: {error}", file=sys.stderr)
        return 1
    if redis_errors:
        print("; ".join(redis_errors), file=sys.stderr)
        return 1
    redis_commands = (
        redis._stop_command(),
        redis._start_command(),
        redis._status_command(),
        redis._health_command(),
        redis._archive_command(),
        redis._restore_command(),
    )
    compose_errors = production_compose_identity_errors(redis_commands, "Redis")
    if compose_errors:
        print("; ".join(compose_errors), file=sys.stderr)
        return 1
    for function_name in (
        "backup_release",
        "verify_release_backup",
        "restore_release",
    ):
        if not callable(getattr(redis, function_name, None)):
            print(f"Missing Redis backup function: {function_name}", file=sys.stderr)
            return 1
    if (
        redis.MANIFEST_HKDF_INFO
        != b"email-platform/redis-backup-manifest/v1/hmac-sha256"
        or not callable(getattr(redis, "_manifest_hmac_sha256", None))
    ):
        print("Redis manifest MAC domain/helper is not fixed to schema 1", file=sys.stderr)
        return 1
    if redis.create_write_once_directory is not backup_output_policy.create_write_once_directory:
        print("Redis backup does not use the shared write-once output policy", file=sys.stderr)
        return 1
    if (
        redis.publish_bundle_write_once_file
        is not backup_output_policy.publish_bundle_write_once_file
    ):
        print("Redis backup does not use strict shared publication", file=sys.stderr)
        return 1
    if (
        redis.write_fsynced_temporary_bytes
        is not backup_output_policy.write_fsynced_temporary_bytes
    ):
        print("Redis manifest does not use stable temporary output", file=sys.stderr)
        return 1
    for required_control in (
        "hmac.compare_digest(actual_mac, expected_mac)",
        "_canonical_manifest_bytes(manifest)",
        "create_write_once_directory(output_dir)",
        "cleanup_created_directory_after_failure(",
        "write_fsynced_temporary_bytes(",
        "publish_bundle_write_once_file(publishing_path, path)",
        "publish_bundle_write_once_file(temporary_manifest, manifest_path)",
        "_restore_running_redis_after_backup()",
        "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)",
        "finally:",
        "PRODUCTION_COMPOSE_FILE = REPOSITORY_ROOT / \"docker-compose.yml\"",
        "REDIS_SERVICE = \"redis\"",
    ):
        if required_control not in redis_source:
            print(f"Redis backup control is missing: {required_control}", file=sys.stderr)
            return 1
    restore_source = redis_source[
        redis_source.index("def restore_release("):
        redis_source.index("def _add_release_arguments(")
    ]
    if not (
        restore_source.index("_verify_release_backup_details(")
        < restore_source.index("_validate_tar_archive(")
        < restore_source.index("_redis_is_running()")
        < restore_source.index("subprocess.Popen(")
    ):
        print("Redis restore must authenticate and validate before process mutation", file=sys.stderr)
        return 1

    readiness_environment_errors = restore_readiness_docker_environment_contract_errors(
        readiness_source
    )
    if readiness_environment_errors:
        print("; ".join(readiness_environment_errors), file=sys.stderr)
        return 1
    if tuple(readiness.PROBES) != EXPECTED_RESTORE_PROBES:
        print("Restore readiness must probe every reviewed internal HTTPS endpoint", file=sys.stderr)
        return 1
    if (
        readiness.PROBE_CONTAINER != "api"
        or tuple(readiness.PRODUCTION_COMPOSE_PREFIX) != PRODUCTION_COMPOSE_PREFIX
        or tuple(readiness.EDGE_STOP_COMMAND)
        != (*PRODUCTION_COMPOSE_PREFIX, "stop", "edge")
        or tuple(readiness._probe_command(readiness.PROBES[0]))
        != (
            *PRODUCTION_COMPOSE_PREFIX,
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            readiness.TLS_PROBE_PROGRAM,
            readiness.PROBES[0],
        )
    ):
        print(
            "Restore readiness must pin the production Compose project and probe from api with edge stopped",
            file=sys.stderr,
        )
        return 1
    contract_errors = readiness.restore_contract_errors()
    if contract_errors:
        print("Restore readiness TLS contract is unsafe: " + "; ".join(contract_errors), file=sys.stderr)
        return 1
    if not callable(readiness.verify_restored_services):
        print("Restore readiness verifier is missing", file=sys.stderr)
        return 1

    documents = {
        "README": assets[README],
        "restore runbook": assets[RUNBOOK],
    }
    for label, document in documents.items():
        for command in required_commands:
            needle = f"python -m scripts.postgres_maintenance {command}"
            if needle not in document:
                print(f"{label} is missing: {needle}", file=sys.stderr)
                return 1
        for needle in (
            "platform.dump.enc",
            "keycloak.dump.enc",
            "manifest.json",
            "SHA-256",
            "AES-256-GCM",
            "--key-file",
        ):
            if needle not in document:
                print(f"{label} is missing: {needle}", file=sys.stderr)
                return 1
        for table in (
            "users",
            "devices",
            "audit_events",
            "realm",
            "user_entity",
            "credential",
            "event_entity",
            "admin_event_entity",
        ):
            if table not in document:
                print(f"{label} is missing critical-table evidence guidance: {table}", file=sys.stderr)
                return 1
        for needle in (
            "python -m scripts.redis_maintenance backup-release",
            "python -m scripts.redis_maintenance verify-release",
            "python -m scripts.redis_maintenance restore-release",
            "redis-data.tar.enc",
            "redis-manifest.json",
            "PostgreSQL manifest SHA-256",
            "recovery set",
            "DBSIZE",
            "PTTL",
        ):
            if needle not in document:
                print(f"{label} is missing Redis recovery guidance: {needle}", file=sys.stderr)
                return 1
    restore_runbook = documents["restore runbook"]
    for needle in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "docker context show",
        "docker context inspect",
        "do not prove the real Docker",
        "TLS identity",
        "socket ACL",
        "remote TLS/mTLS",
        "production_acceptance=false",
    ):
        if needle not in restore_runbook:
            print(f"restore runbook is missing Docker environment guidance: {needle}", file=sys.stderr)
            return 1
    for needle in (
        "authenticated schema-v5 evidence",
        "HKDF-derived",
        "complete canonical manifest",
        "unauthenticated release",
        "schema v4",
        "Vault schema v2",
        "--manifest-key-file",
        "--recovery-set",
        "--postgres-manifest",
    ):
        if needle not in documents["README"]:
            print(f"README is missing release manifest authentication guidance: {needle}", file=sys.stderr)
            return 1
    vault_runbook = assets[VAULT_RUNBOOK]
    for needle in (
        "python -m scripts.postgres_maintenance verify-bundle",
        "python -m scripts.vault_maintenance backup",
        "python -m scripts.vault_maintenance verify",
        "python -m scripts.vault_maintenance restore",
        "--manifest-key-file",
        "--recovery-set",
        "--postgres-manifest",
        "schema v2",
        "HKDF-SHA256",
        "HMAC-SHA256",
        "PostgreSQL manifest SHA-256",
        "--confirm-restore",
        "--ca-file",
        "token-free environment",
        "TLS 1.2",
        "POST /v1/sys/storage/raft/snapshot",
        "consistency rejection is a stop condition",
        "does not expose a force-restore mode",
        "vault.snap",
        "vault-manifest.json",
        "SHA-256",
        "isolated",
        "Remove-Item Env:VAULT_SKIP_VERIFY",
        "empty string or `0`",
    ):
        if needle not in vault_runbook:
            print(f"Vault restore runbook is missing: {needle}", file=sys.stderr)
            return 1
    for forbidden in ("snapshot-force", "restore -force"):
        if forbidden in vault_runbook:
            print(
                f"Vault restore runbook enables an unreviewed force restore: {forbidden}",
                file=sys.stderr,
            )
            return 1
    postgres_verify_lines = [
        index
        for index, line in enumerate(vault_runbook.splitlines())
        if "python -m scripts.postgres_maintenance verify-bundle" in line
    ]
    vault_verify_lines = [
        index
        for index, line in enumerate(vault_runbook.splitlines())
        if "python -m scripts.vault_maintenance verify" in line
    ]
    preceding_vault_verify = -1
    for vault_verify_line in vault_verify_lines:
        if not any(
            preceding_vault_verify < postgres_line < vault_verify_line
            for postgres_line in postgres_verify_lines
        ):
            print(
                "Vault restore runbook must verify PostgreSQL v5 before every Vault binding",
                file=sys.stderr,
            )
            return 1
        preceding_vault_verify = vault_verify_line
    print(
        "backup-tools-ok encrypted-write-once-platform-keycloak-redis-vault-"
        "audit-archive-validated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
