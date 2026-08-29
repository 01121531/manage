"""Statically verify the controlled TLS rotation coordinator contract."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "scripts" / "tls_rotation_executor.py"
RUNTIME = ROOT / "scripts" / "tls_rotation_runtime.py"
EVIDENCE = ROOT / "scripts" / "tls_rotation_evidence.py"
CLI = ROOT / "scripts" / "tls_rotation_execute.py"
RUNNER = ROOT / "scripts" / "tls_rotation_runner.py"
COMPOSE_BACKEND = ROOT / "scripts" / "compose_tls_rotation_backend.py"
KUBERNETES_BACKEND = ROOT / "scripts" / "kubernetes_tls_rotation_backend.py"
PRIVATE_MATERIALIZATION = ROOT / "scripts" / "private_secret_materialization.py"
PRIVATE_RESIDUE = ROOT / "scripts" / "private_secret_residue.py"
PRIVATE_RESIDUE_MAX_BYTES = 64 * 1024


def _reachable_functions(source: str, entries: set[str]) -> list[ast.FunctionDef]:
    tree = ast.parse(source)
    definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    pending = list(entries)
    reached: dict[str, ast.FunctionDef] = {}
    while pending:
        name = pending.pop()
        function = definitions.get(name)
        if function is None or name in reached:
            continue
        reached[name] = function
        for call in (
            node for node in ast.walk(function) if isinstance(node, ast.Call)
        ):
            called = None
            if isinstance(call.func, ast.Name):
                called = call.func.id
            elif isinstance(call.func, ast.Attribute):
                called = call.func.attr
            if called in definitions and called not in reached:
                pending.append(called)
    return list(reached.values())


def _read_only_reconcile_errors(source: str, name: str) -> list[str]:
    functions = _reachable_functions(
        source, {"reconcile_action", "classify_kubernetes_reconcile_inventory"}
    )
    forbidden_calls = {
        "act",
        "contain",
        "force_recreate_compose_service",
        "restart_kubernetes_deployment",
        "pause_kubernetes_deployment",
    }
    forbidden_argv = {
        "rollout", "patch", "apply", "replace", "delete", "scale",
        "set", "annotate", "label",
    }
    for function in functions:
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id in forbidden_calls)
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in forbidden_calls
                )
            ):
                return [f"{name} action reconciliation must remain read-only"]
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in forbidden_argv
            ):
                return [f"{name} action reconciliation contains a mutation verb"]
    return []


def _private_residue_errors(source: str) -> list[str]:
    """Require one bounded, identity-bound residue inventory/cleanup contract."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["Private residue tool is not valid Python"]
    errors: list[str] = []
    required = (
        "materialization._posix_runtime_root(create=False)",
        "materialization._windows_runtime_root(",
        "materialization._validate_posix_base(root.parent)",
        "materialization._validate_windows_base(root.parent)",
        "materialization._identity(metadata) != materialization._identity(named)",
        "_EXPECTED_ENTRY_NAMES",
        "_load_claim(claim_bytes, claim_id)",
        "fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        "os.open(claim_id, flags, dir_fd=root_fd)",
        "os.stat(name, dir_fd=directory_fd, follow_symlinks=False)",
        "os.rmdir(claim_id, dir_fd=root_fd)",
        "materialization._mark_windows_delete(handle)",
        "materialization._mark_windows_delete(directory_handle)",
        "materialization._require_outside_repository(path)",
        "parent_handle, parent_identity = _open_output_parent(path)",
        "_verify_output_parent(path, parent_handle, parent_identity)",
        "read_stable_bytes(path, max_bytes=_INVENTORY_MAX_BYTES)",
        "verified = _read_inventory(output, payload_sha256)",
        "materialization._canonical_json(verified), raw",
        "_read_inventory(inventory, expected_payload_sha256)",
        "if len(matches) != 1",
        'matches[0].get("state") != "cleanup_candidate"',
        "hmac.compare_digest(claimed_sha256, expected_payload_sha256)",
        'cleanup.add_argument("--inventory", required=True, type=Path)',
        'cleanup.add_argument("--expected-payload-sha256", required=True)',
        'cleanup.add_argument("--claim-id", required=True)',
        'cleanup.add_argument("--confirm-residue-cleanup", action="store_true")',
        "cleanup_private_secret_residue_from_inventory(",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"Private residue tool is missing {marker}")
    if source.count("set(os.listdir(directory_fd)) != _EXPECTED_ENTRY_NAMES") != 4:
        errors.append("POSIX residue inspection must recheck the exact entry set")
    if source.count("{entry.name for entry in directory_path.iterdir()} != _EXPECTED_ENTRY_NAMES") != 3:
        errors.append("Windows residue inspection must recheck the exact entry set")
    if source.count("with release_control_lock():") != 4:
        errors.append("Private residue inventory and cleanup must hold the release lock")
    if source.count("hmac.compare_digest(approval, confirmation)") != 2:
        errors.append("Private residue approval must be compared in constant time")

    definitions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    capture_reachable = {
        function.name
        for function in _reachable_functions(
            source, {"capture_private_secret_residue_inventory"}
        )
    }
    if not {
        "capture_private_secret_residue_inventory",
        "_write_once",
        "_open_output_parent",
        "_verify_output_parent",
        "_read_inventory",
    }.issubset(capture_reachable):
        errors.append("Private residue publication call graph is incomplete")

    write_once = definitions.get("_write_once")
    publisher_calls: list[tuple[str, str, int]] = []
    if write_once is not None:
        for call in (
            node for node in ast.walk(write_once) if isinstance(node, ast.Call)
        ):
            called = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else ""
            )
            publisher_calls.append((called, ast.unparse(call), call.lineno))
    expected_publisher_calls = {
        "prepare_write_once_file": ["prepare_write_once_file(path)"],
        "write_fsynced_temporary_bytes": [
            "write_fsynced_temporary_bytes(destination, raw)"
        ],
        "publish_write_once_file": [
            "publish_write_once_file(temporary, destination)"
        ],
        "discard_claimed_temporary_file": [
            "discard_claimed_temporary_file(temporary)",
            "discard_claimed_temporary_file(temporary)",
        ],
        "read_stable_bytes": [
            "read_stable_bytes(path, max_bytes=_INVENTORY_MAX_BYTES)"
        ],
    }
    for name, expected in expected_publisher_calls.items():
        actual = [text for called, text, _ in publisher_calls if called == name]
        if actual != expected:
            errors.append(f"Private residue publisher call has drifted: {name}")
    ordered_publish = [
        min(line for called, _, line in publisher_calls if called == name)
        if any(called == name for called, _, _ in publisher_calls)
        else -1
        for name in (
            "prepare_write_once_file",
            "write_fsynced_temporary_bytes",
            "publish_write_once_file",
            "discard_claimed_temporary_file",
            "read_stable_bytes",
        )
    ]
    if (
        any(line < 0 for line in ordered_publish)
        or ordered_publish != sorted(ordered_publish)
    ):
        errors.append("Private residue publisher ordering has drifted")
    parent_open_calls = [
        text
        for called, text, _ in publisher_calls
        if called == "_open_output_parent"
    ]
    parent_verify_calls = [
        text
        for called, text, _ in publisher_calls
        if called == "_verify_output_parent"
    ]
    if parent_open_calls != ["_open_output_parent(path)"] or parent_verify_calls != [
        "_verify_output_parent(path, parent_handle, parent_identity)"
    ] * 3:
        errors.append("Private residue output parent identity checks have drifted")
    if any(
        called in {"unlink", "remove", "removedirs", "DeleteFileW", "RemoveDirectoryW"}
        for called, _, _ in publisher_calls
    ):
        errors.append("Private residue publisher must not roll back a committed artifact")

    verify_parent = definitions.get("_verify_output_parent")
    parent_fsync = [] if verify_parent is None else [
        ast.unparse(call)
        for call in ast.walk(verify_parent)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "fsync"
    ]
    if parent_fsync != ["os.fsync(handle)"]:
        errors.append("POSIX residue publication must fsync the held parent directory")

    output_parent_contract = "\n".join(
        ast.unparse(function)
        for function in (
            definitions.get("_open_output_parent"),
            definitions.get("_verify_output_parent"),
        )
        if function is not None
    )
    for comparison in (
        "materialization._identity(opened) != materialization._identity(named)",
        "materialization._identity(opened) != identity",
        "materialization._identity(named) != identity",
        "materialization._win_identity(handle, directory=True) != identity",
        "materialization._win_identity(named, directory=True) != identity",
    ):
        if comparison not in output_parent_contract:
            errors.append("Private residue output parent path identity is incomplete")

    capture = definitions.get("capture_private_secret_residue_inventory")
    capture_calls: list[tuple[str, str, int]] = []
    if capture is not None:
        for call in (
            node for node in ast.walk(capture) if isinstance(node, ast.Call)
        ):
            called = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else ""
            )
            capture_calls.append((called, ast.unparse(call), call.lineno))
    for name, expected in (
        ("_write_once", "_write_once(output, raw)"),
        ("_read_inventory", "_read_inventory(output, payload_sha256)"),
        (
            "compare_digest",
            "hmac.compare_digest(materialization._canonical_json(verified), raw)",
        ),
    ):
        actual = [text for called, text, _ in capture_calls if called == name]
        if actual != [expected]:
            errors.append(f"Private residue canonical publication readback is missing {name}")
    capture_order = [
        min(line for called, _, line in capture_calls if called == name)
        if any(called == name for called, _, _ in capture_calls)
        else -1
        for name in ("_write_once", "_read_inventory", "compare_digest")
    ]
    if any(line < 0 for line in capture_order) or capture_order != sorted(capture_order):
        errors.append("Private residue canonical publication readback order has drifted")

    if "cleanup_private_secret_residue" in definitions:
        errors.append("Private residue tool must not expose cleanup without inventory")

    main_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    ]
    main_calls: list[str] = []
    if len(main_functions) == 1:
        for call in (
            node for node in ast.walk(main_functions[0]) if isinstance(node, ast.Call)
        ):
            if isinstance(call.func, ast.Name):
                main_calls.append(call.func.id)
            elif isinstance(call.func, ast.Attribute):
                main_calls.append(call.func.attr)
    if (
        main_calls.count("cleanup_private_secret_residue_from_inventory") != 1
        or "cleanup_private_secret_residue" in main_calls
    ):
        errors.append("Private residue CLI must clean exactly one inventory-bound claim")

    producer_names = {
        "_inspect_posix",
        "_inventory_posix",
        "_inspect_windows",
        "_inventory_windows",
        "_inventory_document",
    }
    forbidden_projection_keys = {
        "ip",
        "materialized_path",
        "path",
        "runtime_root",
        "secret",
        "secret_bytes",
        "source",
        "source_path",
        "source_sha256",
        "url",
    }
    for function in (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in producer_names
    ):
        for node in ast.walk(function):
            projected_keys: set[str] = set()
            if isinstance(node, ast.Dict):
                projected_keys.update(
                    key.value
                    for key in node.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and isinstance(target.slice.value, str)
                    ):
                        projected_keys.add(target.slice.value)
            if projected_keys.intersection(forbidden_projection_keys):
                errors.append("Private residue inventory projection contains sensitive fields")
                break

    forbidden_calls = {"glob", "rglob", "rmtree", "removedirs", "walk"}
    heuristic_names = {"getpid", "kill", "pid", "st_ctime", "st_mtime"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if called in forbidden_calls:
                errors.append("Private residue tool contains recursive or glob deletion")
            if called in {"DeleteFileW", "RemoveDirectoryW"}:
                errors.append("Windows residue cleanup must delete by authenticated handle")
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            if name in heuristic_names:
                errors.append("Private residue tool contains an age or PID heuristic")
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in {"--all", "--force", "--age", "--older-than"}
        ):
            errors.append(f"Private residue CLI exposes forbidden input {node.value}")
    return errors


def validate_sources(
    executor: str,
    runtime: str,
    evidence: str,
    cli: str = "",
    runner: str = "",
    compose_backend: str = "",
    kubernetes_backend: str = "",
    private_materialization: str = "",
    private_residue: str = "",
) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(executor)
    except SyntaxError:
        return ["TLS rotation executor is not valid Python"]
    public = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "execute_tls_rotation"
    ]
    if len(public) != 1:
        errors.append("TLS rotation executor must expose one coordinator")
    elif sum(
        1
        for node in ast.walk(public[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "backend"
        and node.func.attr == "act"
    ) != 1:
        errors.append("TLS rotation executor must request the mutation exactly once")

    ordered = (
        "prepare_write_once_file(evidence_output)",
        "load_projection(_external_projection_path(projection_path))",
        "hmac.compare_digest(",
        "with release_control_lock(), _BackendLifecycle() as lifecycle:",
        "backend = lifecycle.bind(backend_factory(projection))",
        'action["requested_at"] = clock()',
        "backend.act()",
        "final_first = list(backend.snapshot())",
        "final_second = list(backend.snapshot())",
        "return _publish(payload, output, clock=clock)",
    )
    positions = [executor.find(marker) for marker in ordered]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append("TLS rotation executor safety order has drifted")

    for marker in (
        "except BaseException as error:",
        "_contain_after_mutation(",
        "confirm_rotation_plan_sha256: str",
        'production_acceptance": False',
        '"compose_service_stop"',
        '"kubernetes_rollout_pause"',
        "assert_generation_replaced(",
        "_reconcile_unknown_action(",
        'action["return_state"] = "unknown"',
        'candidate.result in {"verified_old", "verified_new", "unknown"}',
        "class _BackendLifecycle(",
        "self.backend.close()",
        "TLS rotation backend cleanup failed",
        "if backend is not None:\n            raise",
        "def close(self) -> None: ...",
    ):
        if marker not in executor:
            errors.append(f"TLS rotation executor is missing {marker}")
    for forbidden in (
        "shell=True",
        "os.system(",
        "subprocess.Popen(",
        "rollout undo",
        "docker compose down",
        "verify_evidence(output)",
    ):
        if forbidden in executor:
            errors.append(f"TLS rotation executor contains forbidden operation {forbidden}")

    for marker in (
        '"--force-recreate"',
        'f"--revision={revision}"',
        '"pause"',
        'replica_metadata.get("uid") != replica_owner["uid"]',
        'owner.get("uid") == deployment_uid',
        '[*kubectl_prefix, "get", "pod",',
        '"imageID"',
        "target_replicaset_uid",
        "assert_kubernetes_uids_absent(",
        "TLS_STDIN_HTTP_PROBE_PROGRAM",
        "input_text=command.input_text",
    ):
        if marker not in runtime:
            errors.append(f"TLS rotation runtime is missing {marker}")
    if '"--revision=' not in runtime or '"--timeout=10m"' not in runtime:
        errors.append("Kubernetes rollout status must bind a revision and timeout")
    if 'f"deployment/{_name(observer' in runtime:
        errors.append("Kubernetes probes must bind an exact Pod instead of a Deployment")

    for marker in (
        "SCHEMA_VERSION = 5",
        '"reason_code"',
        '"containment"',
        '"return_state"',
        '"reconciliation"',
        '"action_reconcile_old"',
        '"action_reconcile_new"',
        "old peer observation followed rotation action",
        "new peer observation predates rotation completion",
        "route peer observation attempts are out of order",
        "verify_evidence(destination)",
        'separators=(",", ":")',
    ):
        if marker not in evidence:
            errors.append(f"TLS rotation evidence is missing {marker}")

    if cli:
        for marker in (
            '"--projection"',
            '"--runtime-profile"',
            '"--evidence-output"',
            '"--confirm-rotation-plan-sha256"',
            '"compose": build_compose_rotation_backend',
            '"kubernetes": build_kubernetes_rotation_backend',
            'TlsRotationCliError("TLS rotation CLI input is invalid")',
        ):
            if marker not in cli:
                errors.append(f"TLS rotation CLI is missing {marker}")
        for forbidden in ('add_argument("--url"', 'add_argument("--service"', 'add_argument("--command"'):
            if forbidden in cli:
                errors.append(f"TLS rotation CLI exposes forbidden input {forbidden}")

    if runner:
        for marker in (
            "FORBIDDEN_ROTATION_ENVIRONMENT.intersection(shell_environment)",
            "shell=False",
            "stderr=subprocess.DEVNULL",
            'errors="strict"',
            "timeout=COMMAND_TIMEOUT_SECONDS",
            "MAX_CAPTURE_BYTES",
            "MAX_INPUT_BYTES",
            '"KUBECONFIG"',
        ):
            if marker not in runner:
                errors.append(f"TLS rotation runner is missing {marker}")

    if compose_backend:
        for marker in (
            '"--project-directory"',
            '"--env-file"',
            '"--project-name"',
            '"config", "--images"',
            '"stop", "--timeout", "30"',
            "profile.blocked_observers",
            "def reconcile_action(",
            'reason_code="runtime_read_failed"',
            "def close(self) -> None:",
        ):
            if marker not in compose_backend:
                errors.append(f"Compose TLS rotation backend is missing {marker}")
        if compose_backend.count('"config", "--images"') != 3:
            errors.append(
                "Compose target, direct and route probe executor images must be reviewed"
            )

    if kubernetes_backend:
        for marker in (
            '"--kubeconfig"',
            '"--context"',
            '"--request-timeout=30s"',
            '"--namespace"',
            "get_kubernetes_namespace_uid(",
            "restart_kubernetes_deployment(",
            "discovered = get_kubernetes_deployment_snapshot(",
            "revision=discovered.revision",
            "target_replicaset_uid",
            "assert_kubernetes_uids_absent(",
            "pause_kubernetes_deployment(",
            '"jsonpath={.data.tls\\\\.crt}"',
            "profile.blocked_observers",
            "def reconcile_action(",
            "def _reconciliation_generation(",
            "read_private_secret_bytes(",
            "max_bytes=1024 * 1024",
            "require_read_only=True",
            "def close(self) -> None:",
            "materialize_private_secret_bytes(",
            "self._materialized.path",
            "self._materialized.verify()",
        ):
            if marker not in kubernetes_backend:
                errors.append(f"Kubernetes TLS rotation backend is missing {marker}")
        if kubernetes_backend.count("read_private_secret_bytes(") != 1:
            errors.append("Kubernetes backend must perform exactly one private kubeconfig read")
        if "kubectl_prefix(self.profile," in kubernetes_backend:
            errors.append("Kubernetes backend must not pass the source profile to kubectl")
        materialization_order = [
            kubernetes_backend.find(marker)
            for marker in (
                "kubeconfig = read_private_secret_bytes(",
                "kubeconfig_sha256 = validate_self_contained_kubeconfig(",
                "self._materialized = materialize_private_secret_bytes(",
                "self._assert_namespace(self.profile.namespace",
            )
        ]
        if (
            any(position < 0 for position in materialization_order)
            or materialization_order != sorted(materialization_order)
        ):
            errors.append("Kubernetes kubeconfig materialization order has drifted")
        action_positions = [
            kubernetes_backend.find(marker)
            for marker in (
                "restart_kubernetes_deployment(",
                "discovered = get_kubernetes_deployment_snapshot(",
                "wait_kubernetes_rollout_revision(",
            )
        ]
        if any(position < 0 for position in action_positions) or action_positions != sorted(action_positions):
            errors.append("Kubernetes TLS rotation action order has drifted")
    for name, source in (
        ("Compose", compose_backend),
        ("Kubernetes", kubernetes_backend),
    ):
        if not source:
            continue
        try:
            backend_tree = ast.parse(source)
        except SyntaxError:
            errors.append(f"{name} TLS rotation backend is not valid Python")
            continue
        methods = [node for node in ast.walk(backend_tree) if isinstance(node, ast.FunctionDef) and node.name == "reconcile_action"]
        if len(methods) != 1:
            errors.append(f"{name} action reconciliation contract is missing")
            continue
        errors.extend(_read_only_reconcile_errors(source, name))
    if runtime:
        errors.extend(_read_only_reconcile_errors(runtime, "Runtime helper"))
    for marker in (
        "network_identity",
        "get_compose_probe_executor(",
        '"docker",\n        "exec",\n        "-i"',
        "expected_network_identity",
    ):
        if marker not in runtime:
            errors.append(f"Compose exact-container probe runtime is missing {marker}")
    if runtime.count("expected_network_identity") != 3:
        errors.append("Compose exact probe executor network binding has drifted")
    for marker in (
        "docker_probe_command(",
        "connect_host=instance.connect_host",
        "expected_network_identity=instance.network_identity",
        "connect_host=target.connect_host",
        "expected_network_identity=target.network_identity",
    ):
        if marker not in compose_backend:
            errors.append(f"Compose exact-container probe backend is missing {marker}")
    if compose_backend.count("docker_probe_command(") != 3:
        errors.append("Compose direct and route probes must all use exact containers")
    if private_materialization:
        for marker in (
            "class MaterializedPrivateSecret:",
            "def materialize_private_secret_bytes(",
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            'D:P',
            "CreateDirectoryW",
            "_CREATE_NEW = 1",
            "FlushFileBuffers",
            "SetFileInformationByHandle",
            "_SE_DACL_PROTECTED",
            "_FILE_PERSISTENT_ACLS",
            "os.mkdir(candidate, 0o700, dir_fd=root_fd)",
            "path.resolve(strict=False).relative_to(_REPOSITORY_ROOT.resolve(strict=True))",
            "os.O_EXCL",
            "os.fchmod(writer_fd, 0o400)",
            "_verify_windows(path, expected_sha256, state)",
            "_verify_posix(path, expected_sha256, state)",
            "does not claim crash cleanup",
        ):
            if marker not in private_materialization:
                errors.append(f"Private materialization is missing {marker}")
        for forbidden in (
            "import tempfile",
            "NamedTemporaryFile",
            "TemporaryDirectory",
            "SetNamedSecurityInfo",
            "SetFileSecurity",
            "Set-Acl",
            "shutil.rmtree",
            "_FILE_SHARE_DELETE",
        ):
            if forbidden in private_materialization:
                errors.append(
                    f"Private materialization contains forbidden operation {forbidden}"
                )
    if private_residue:
        errors.extend(_private_residue_errors(private_residue))
    return errors


def main() -> int:
    try:
        errors = validate_sources(
            load_stable_text(EXECUTOR, max_bytes=64 * 1024),
            load_stable_text(RUNTIME, max_bytes=64 * 1024),
            load_stable_text(EVIDENCE, max_bytes=64 * 1024),
            load_stable_text(CLI, max_bytes=64 * 1024),
            load_stable_text(RUNNER, max_bytes=64 * 1024),
            load_stable_text(COMPOSE_BACKEND, max_bytes=64 * 1024),
            load_stable_text(KUBERNETES_BACKEND, max_bytes=64 * 1024),
            load_stable_text(PRIVATE_MATERIALIZATION, max_bytes=128 * 1024),
            load_stable_text(PRIVATE_RESIDUE, max_bytes=PRIVATE_RESIDUE_MAX_BYTES),
        )
    except (OSError, ValueError):
        print("TLS rotation executor assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("tls-rotation-executor-ok production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
