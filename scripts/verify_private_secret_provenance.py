"""Statically guard the two private-secret provenance trust boundaries."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

try:
    from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from external_json import parse_unique_json_bytes, read_stable_bytes  # type: ignore[no-redef]
    from external_text import load_stable_text  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
GITHUB_TOOL = ROOT / "scripts" / "private_secret_github_attestation.py"
TARGET_TOOL = ROOT / "scripts" / "private_secret_target_provenance.py"
T140_TOOL = ROOT / "scripts" / "private_secret_crash_evidence.py"
GITHUB_POLICY = ROOT / "deploy" / "github-attestation-trust-policy.synthetic.json"
GITHUB_TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-github-origin.synthetic.json"
)
TARGET_POLICY = ROOT / "deploy" / "private-secret-target-provenance-policy.json"
TARGET_TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-target-origin.synthetic.json"
)

MAX_SOURCE_BYTES = 128 * 1024
MAX_ASSET_BYTES = 16 * 1024

_NETWORK_IMPORTS = {
    "aiohttp",
    "ftplib",
    "http.client",
    "httpx",
    "requests",
    "smtplib",
    "socket",
    "urllib",
    "urllib.request",
}
_PRIVATE_KEY_FRAGMENTS = {
    "Ed25519PrivateKey",
    "EllipticCurvePrivateKey",
    "RSAPrivateKey",
    "load_der_private_key",
    "load_pem_private_key",
}
_MUTATION_CALLS = {
    "cleanup_private_secret_residue_from_inventory",
    "link",
    "materialize_private_secret_bytes",
    "mkdir",
    "publish_write_once_file",
    "rename",
    "replace",
    "unlink",
    "write_bytes",
    "write_text",
}
_TARGET_FORBIDDEN_PROCESS_CALLS = {
    "Popen",
    "check_call",
    "check_output",
    "run",
    "spawn",
    "system",
}

_TARGET_DOMAIN = b"email-platform/private-secret-target-origin/target-signer/v1\0"
_STORAGE_DOMAIN = b"email-platform/private-secret-target-origin/storage-signer/v1\0"
_TARGET_PUBLICATION_FIELDS = {
    "storage_identity_fingerprint_sha256",
    "object_reference",
    "immutable_version_reference",
    "provider_receipt_artifact_sha256",
    "delete_probe_artifact_sha256",
    "evidence_readback_sha256",
}
_TARGET_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}
_TARGET_SIGNATURES_FIELDS = {"target_signer", "storage_signer"}

_GH_ARGUMENT_STRINGS = [
    "attestation",
    "verify",
    "--repo",
    "--bundle",
    "--custom-trusted-root",
    "--cert-oidc-issuer",
    "--cert-identity",
    "--signer-digest",
    "--source-digest",
    "--source-ref",
    "--deny-self-hosted-runners",
    "--predicate-type",
    "--format",
    "json",
]
_GH_FORBIDDEN_ARGUMENTS = {
    "--bundle-from-oci",
    "--cert-identity-regex",
    "--hostname",
    "--owner",
    "--signer-repo",
    "--signer-workflow",
}

_GITHUB_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "repository",
    "identity",
    "trusted_root",
    "verifier",
    "review",
    "integrity",
}
_GITHUB_TEMPLATE_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "production_acceptance",
    "subject",
    "bundle",
    "trust_policy",
    "verification",
    "review",
    "prohibited_content",
    "integrity",
}
_TARGET_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "executor_integration_enabled",
    "handoff_integration_enabled",
    "state",
    "target_signer",
    "storage_signer",
    "custody_requirements",
    "time_constraints",
}
_TARGET_TEMPLATE_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "provider_receipt_authentication",
    "production_acceptance",
    "not_committed_eligible",
    "payload",
    "signatures",
    "integrity",
}


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _assignment_literal(tree: ast.AST, name: str) -> object | None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            value = node.value
            if value is None:
                return None
            try:
                return ast.literal_eval(value)
            except (TypeError, ValueError):
                return None
    return None


def _required_kwonly(function: ast.FunctionDef | ast.AsyncFunctionDef | None, name: str) -> bool:
    if function is None:
        return False
    for argument, default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
        strict=True,
    ):
        if argument.arg == name:
            return default is None
    return False


def _imports(tree: ast.AST) -> set[str]:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.add(module)
            imports.update(alias.name for alias in node.names)
    return imports


def _called_names(tree: ast.AST) -> list[str]:
    return [
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (name := _qualified_name(node.func)) is not None
    ]


def _subprocess_errors(tree: ast.AST) -> list[str]:
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _qualified_name(node.func) == "subprocess.run"
    ]
    if len(calls) != 1:
        return ["GitHub verifier must contain exactly one subprocess.run call"]
    call = calls[0]
    if len(call.args) != 1:
        return ["GitHub subprocess must receive one exact argv value"]
    first = call.args[0]
    if not (
        isinstance(first, ast.Call)
        and _qualified_name(first.func) == "list"
        and len(first.args) == 1
        and isinstance(first.args[0], ast.Name)
        and first.args[0].id == "arguments"
    ):
        return ["GitHub subprocess must execute only list(arguments)"]
    keywords = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
    if set(keywords) != {
        "stdin",
        "stdout",
        "stderr",
        "shell",
        "check",
        "env",
        "timeout",
        "pass_fds",
    }:
        return ["GitHub subprocess keyword boundary has drifted"]
    expected_attributes = {
        "stdin": "subprocess.DEVNULL",
        "stdout": "subprocess.PIPE",
        "stderr": "subprocess.PIPE",
    }
    for field, expected in expected_attributes.items():
        if _qualified_name(keywords[field]) != expected:
            return ["GitHub subprocess stdio boundary has drifted"]
    for field in ("shell", "check"):
        if not isinstance(keywords[field], ast.Constant) or keywords[field].value is not False:
            return ["GitHub subprocess must remain non-shell and fail-closed"]
    env = keywords["env"]
    timeout = keywords["timeout"]
    pass_fds = keywords["pass_fds"]
    if not (
        isinstance(env, ast.Call)
        and _qualified_name(env.func) == "dict"
        and len(env.args) == 1
        and isinstance(env.args[0], ast.Name)
        and env.args[0].id == "environment"
        and isinstance(timeout, ast.Name)
        and timeout.id == "timeout_seconds"
        and isinstance(pass_fds, ast.Call)
        and _qualified_name(pass_fds.func) == "tuple"
        and len(pass_fds.args) == 1
        and isinstance(pass_fds.args[0], ast.Name)
        and pass_fds.args[0].id == "pass_fds"
    ):
        return ["GitHub subprocess environment or timeout is not caller-bounded"]
    return []


def _github_argv_errors(tree: ast.AST) -> list[str]:
    verify = _function(tree, "verify_authenticated")
    if verify is None:
        return ["GitHub authenticated entrypoint is missing"]
    candidates: list[ast.List] = []
    for node in ast.walk(verify):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "arguments"
            for target in node.targets
        ) and isinstance(node.value, ast.List):
            candidates.append(node.value)
    if len(candidates) != 1:
        return ["GitHub exact gh argv declaration is missing or ambiguous"]
    values = candidates[0].elts
    if not values or not (
        isinstance(values[0], ast.Call)
        and _qualified_name(values[0].func) == "str"
        and len(values[0].args) == 1
        and _qualified_name(values[0].args[0]) == "snapshot.executable"
    ):
        return ["GitHub argv must start with the sealed executable snapshot"]
    snapshot_positions = {
        3: "snapshot.subject",
        7: "snapshot.bundle",
        9: "snapshot.trusted_root",
    }
    if any(
        index >= len(values)
        or not isinstance(values[index], ast.Call)
        or _qualified_name(values[index].func) != "str"
        or len(values[index].args) != 1
        or _qualified_name(values[index].args[0]) != expected
        for index, expected in snapshot_positions.items()
    ):
        return ["GitHub gh must consume only sealed subject, bundle, and root snapshots"]
    strings = [node.value for node in values if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    if strings != _GH_ARGUMENT_STRINGS:
        return ["GitHub gh attestation argv has drifted"]
    if set(strings).intersection(_GH_FORBIDDEN_ARGUMENTS):
        return ["GitHub gh attestation argv uses a forbidden broad selector"]
    return []


def _github_snapshot_capability_errors(tree: ast.AST) -> list[str]:
    counts: dict[str, int] = {}
    for name in _called_names(tree):
        counts[name] = counts.get(name, 0) + 1
    expected = {
        "fcntl.fcntl": 2,
        "os.chmod": 3,
        "os.close": 3,
        "os.fchmod": 1,
        "os.fstat": 1,
        "os.lseek": 1,
        "os.memfd_create": 1,
        "os.open": 2,
        "os.symlink": 1,
        "os.write": 1,
        "tempfile.gettempdir": 1,
        "tempfile.mkdtemp": 1,
        "unlink": 1,
        "directory.rmdir": 1,
    }
    if any(counts.get(name, 0) != count for name, count in expected.items()):
        return ["GitHub sealed snapshot capability set has drifted"]
    return []


def _source_common_errors(
    source: str,
    tree: ast.AST,
    *,
    label: str,
    allowed_mutations: frozenset[str] = frozenset(),
) -> list[str]:
    errors: list[str] = []
    imported = _imports(tree)
    if imported.intersection(_NETWORK_IMPORTS):
        errors.append(f"{label} imports a network capability")
    if imported.intersection(_PRIVATE_KEY_FRAGMENTS) or any(
        fragment in source for fragment in _PRIVATE_KEY_FRAGMENTS
    ):
        errors.append(f"{label} imports a private signing capability")
    calls = _called_names(tree)
    if any(name.rsplit(".", 1)[-1] == "sign" for name in calls):
        errors.append(f"{label} contains a signing call")
    if any(
        name.rsplit(".", 1)[-1] in _MUTATION_CALLS - allowed_mutations
        for name in calls
    ):
        errors.append(f"{label} contains a mutation capability")
    if "production_acceptance=true" in source or "production_acceptance=True" in source:
        errors.append(f"{label} enables production acceptance")
    return errors


def _github_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["GitHub provenance verifier is not valid Python"]
    errors = _source_common_errors(
        source,
        tree,
        label="GitHub provenance verifier",
        allowed_mutations=frozenset({"unlink"}),
    )
    imported = _imports(tree)
    if "subprocess" not in imported:
        errors.append("GitHub provenance verifier is missing its controlled subprocess wrapper")
    errors.extend(_subprocess_errors(tree))
    errors.extend(_github_argv_errors(tree))
    errors.extend(_github_snapshot_capability_errors(tree))
    verify = _function(tree, "verify_authenticated")
    for parameter in ("expected_policy_sha256", "expected_gh_sha256"):
        if not _required_kwonly(verify, parameter):
            errors.append(f"GitHub authenticated entrypoint must require caller {parameter}")
    parser = _function(tree, "_parser")
    parser_source = ast.get_source_segment(source, parser) if parser is not None else ""
    if "--expected-policy-sha256" not in (parser_source or ""):
        errors.append("GitHub CLI must require the caller policy digest")
    required_markers = (
        'EVIDENCE_KIND = "private_secret_github_origin_intake"',
        'origin["trust_policy"]["artifact_sha256"]',
        "policy_blob.sha256",
        "_digest(expected_policy_sha256)",
        'verify.add_argument("--expected-policy-sha256", required=True)',
        "_clean_environment(environment)",
        "class LinuxSealedSnapshotFactory:",
        'sys.platform != "linux"',
        'hasattr(os, "memfd_create")',
        'getattr(os, "MFD_ALLOW_SEALING", None)',
        'getattr(os, "MFD_CLOEXEC", None)',
        "fcntl.F_SEAL_WRITE",
        "fcntl.F_SEAL_GROW",
        "fcntl.F_SEAL_SHRINK",
        "fcntl.F_SEAL_SEAL",
        "fcntl.F_ADD_SEALS",
        "fcntl.F_GET_SEALS",
        "os.memfd_create(",
        "flags=allow_sealing | close_on_exec",
        "tempfile.mkdtemp(",
        'os.symlink(f"/proc/self/fd/{bundle_fd}", bundle_link)',
        "os.chmod(directory, 0o500)",
        'Path(f"/proc/self/fd/{executable_fd}")',
        'Path(f"/proc/self/fd/{subject_fd}")',
        'Path(f"/proc/self/fd/{directory_fd}/bundle.jsonl")',
        'Path(f"/proc/self/fd/{trusted_root_fd}")',
        "executable=executable_blob.raw",
        "subject=subject_blob.raw",
        "bundle=bundle_blob.raw",
        "trusted_root=root_blob.raw",
        "pass_fds=snapshot.pass_fds",
        "completed.returncode != 0",
        "_verify_gh_output(",
        "crash_evidence.verify_evidence_snapshot(",
        "t140_snapshot.evidence_artifact_sha256",
        'subject["scope"].get("kind") != "github_actions_linux_ci"',
        "runtime-facts=reviewed-assertion target-host=unverified",
        "freshness=unverified replay-protection=unverified ",
        "durability=unverified reviewer-independence=unverified ",
        "job-binding=unverified rest-snapshot=unverified ",
        "production_acceptance=false",
    )
    for marker in required_markers:
        if marker not in source:
            errors.append(f"GitHub provenance verifier is missing {marker}")
    for axis in (
        "freshness",
        "replay-protection",
        "durability",
        "reviewer-independence",
        "job-binding",
        "rest-snapshot",
    ):
        if source.count(f"{axis}=unverified") != 2 or f"{axis}=verified" in source:
            errors.append(f"GitHub provenance verifier overstates {axis}")
    if "private_secret_target_provenance" in source:
        errors.append("GitHub provenance verifier crosses into the target trust domain")
    return errors


def _signature_roles(tree: ast.AST) -> list[str]:
    roles: list[str] = []
    verify = _function(tree, "verify_target_origin_bytes")
    if verify is None:
        return roles
    for node in ast.walk(verify):
        if not isinstance(node, ast.Call) or _qualified_name(node.func) != "_verify_signature":
            continue
        for keyword in node.keywords:
            if keyword.arg == "role" and isinstance(keyword.value, ast.Constant):
                roles.append(keyword.value.value)
    return roles


def _target_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["target provenance verifier is not valid Python"]
    errors = _source_common_errors(source, tree, label="target provenance verifier")
    imported = _imports(tree)
    if "subprocess" in imported:
        errors.append("target provenance verifier imports subprocess")
    calls = _called_names(tree)
    if any(name.rsplit(".", 1)[-1] in _TARGET_FORBIDDEN_PROCESS_CALLS for name in calls):
        errors.append("target provenance verifier calls a process capability")
    if _assignment_literal(tree, "_TARGET_DOMAIN") != _TARGET_DOMAIN:
        errors.append("target signer domain separator has drifted")
    if _assignment_literal(tree, "_STORAGE_DOMAIN") != _STORAGE_DOMAIN:
        errors.append("storage signer domain separator has drifted")
    if _TARGET_DOMAIN == _STORAGE_DOMAIN:
        errors.append("target signer domains are not distinct")
    if _assignment_literal(tree, "_PUBLICATION_FIELDS") != _TARGET_PUBLICATION_FIELDS:
        errors.append("target WORM publication binding fields have drifted")
    if _assignment_literal(tree, "_SIGNATURE_FIELDS") != _TARGET_SIGNATURE_FIELDS:
        errors.append("target signature schema permits key or algorithm fallback")
    if _assignment_literal(tree, "_SIGNATURES_FIELDS") != _TARGET_SIGNATURES_FIELDS:
        errors.append("target signature roles have drifted")
    if _signature_roles(tree) != ["target_signer", "storage_signer"]:
        errors.append("target verifier must authenticate both independent signer roles")
    verify = _function(tree, "verify_target_origin")
    for parameter in (
        "expected_policy_sha256",
        "expected_cluster_fingerprint_sha256",
        "verification_time",
    ):
        if not _required_kwonly(verify, parameter):
            errors.append(f"target authenticated entrypoint must require caller {parameter}")
    core = _function(tree, "verify_target_origin_bytes")
    if core is None:
        errors.append("target provenance bytes core is missing")
    else:
        forbidden = {
            "read_stable_bytes", "read_stable_bytes_with_metadata", "open",
            "Path.read_bytes", "Path.read_text",
        }
        if any(name in forbidden for name in _called_names(core)):
            errors.append("target provenance bytes core performs filesystem I/O")
    if verify is None or _called_names(verify).count("verify_target_origin_bytes") != 1:
        errors.append("target path entrypoint must call the bytes core exactly once")
    parser = _function(tree, "_parser")
    parser_source = ast.get_source_segment(source, parser) if parser is not None else ""
    if "--expected-policy-sha256" not in (parser_source or ""):
        errors.append("target CLI must require the caller policy digest")
    required_markers = (
        'POLICY_KIND = "private_secret_target_provenance_trust_policy"',
        'RECORD_TYPE = "private_secret_target_origin_intake"',
        'anchor["algorithm"] != "Ed25519"',
        'signature["algorithm"] != "Ed25519"',
        'policy["state"] != "pinned"',
        "_digest(expected_policy_sha256)",
        "policy_digest",
        "return policy, hashlib.sha256(raw).hexdigest()",
        "not hmac.compare_digest(policy_digest, expected_policy_sha256)",
        'verify.add_argument("--expected-policy-sha256", required=True)',
        'hmac.compare_digest(target_signature["key_id"], storage_signature["key_id"])',
        "external_signers_bound_target_crash_artifacts_and_provider_receipt",
        "authenticated-external-signer-assertion",
        "provider-receipt-authenticated=true",
        "freshness=unverified replay-protection=unverified ",
        "durability=unverified reviewer-independence=unverified",
        "production_acceptance=false not_committed_eligible=false",
    )
    for marker in required_markers:
        if marker not in source:
            errors.append(f"target provenance verifier is missing {marker}")
    for axis in (
        "freshness",
        "replay-protection",
        "durability",
        "reviewer-independence",
    ):
        if source.count(f"{axis}=unverified") != 2 or f"{axis}=verified" in source:
            errors.append(f"target provenance verifier overstates {axis}")
    if "private_secret_github_attestation" in source:
        errors.append("target provenance verifier crosses into the GitHub trust domain")
    return errors


def _parse_json(raw: bytes, label: str) -> tuple[object | None, list[str]]:
    try:
        return parse_unique_json_bytes(raw), []
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None, [f"{label} is not unique valid JSON"]


def _sealed_pending(value: object, fields: set[str], label: str) -> list[str]:
    if not isinstance(value, dict) or set(value) != fields:
        return [f"{label} schema has drifted"]
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        return [f"{label} integrity schema has drifted"]
    payload = {key: item for key, item in value.items() if key != "integrity"}
    if integrity["payload_sha256"] != _canonical_digest(payload):
        return [f"{label} canonical seal has drifted"]
    return []


def _github_policy_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "GitHub trust policy")
    if errors:
        return errors
    errors.extend(_sealed_pending(value, _GITHUB_POLICY_FIELDS, "GitHub trust policy"))
    if errors or not isinstance(value, dict):
        return errors
    if value != {
        "schema_version": 1,
        "policy_kind": "github_artifact_attestation_trust_policy",
        "synthetic": True,
        "policy_status": "pending",
        "policy_effect": "offline_origin_authentication_only",
        "production_acceptance": False,
        "repository": None,
        "identity": None,
        "trusted_root": None,
        "verifier": None,
        "review": None,
        "integrity": value["integrity"],
    }:
        errors.append("GitHub trust policy must remain synthetic and unconfigured")
    return errors


def _github_template_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "GitHub origin template")
    if errors:
        return errors
    errors.extend(_sealed_pending(value, _GITHUB_TEMPLATE_FIELDS, "GitHub origin template"))
    if errors or not isinstance(value, dict):
        return errors
    if (
        value.get("schema_version") != 1
        or value.get("evidence_kind") != "private_secret_github_origin_intake"
        or value.get("synthetic") is not True
        or value.get("evidence_status") != "pending"
        or value.get("origin_authentication") != "unverified"
        or value.get("production_acceptance") is not False
        or any(
            value.get(field) is not None
            for field in ("subject", "bundle", "trust_policy", "verification", "review")
        )
        or not isinstance(value.get("prohibited_content"), dict)
        or any(item is not False for item in value["prohibited_content"].values())
    ):
        errors.append("GitHub origin template must remain pending and unverified")
    return errors


def _target_policy_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "target trust policy")
    if errors:
        return errors
    if not isinstance(value, dict) or set(value) != _TARGET_POLICY_FIELDS:
        return [*errors, "target trust policy schema has drifted"]
    target = value.get("target_signer")
    storage = value.get("storage_signer")
    if (
        value.get("schema_version") != 1
        or value.get("policy_kind") != "private_secret_target_provenance_trust_policy"
        or value.get("policy_effect") != "authentication_prerequisite_only"
        or value.get("state") != "unconfigured"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or value.get("executor_integration_enabled") is not False
        or value.get("handoff_integration_enabled") is not False
        or not isinstance(target, dict)
        or not isinstance(storage, dict)
        or target.get("state") != "unconfigured"
        or storage.get("state") != "unconfigured"
        or target.get("algorithm") != "Ed25519"
        or storage.get("algorithm") != "Ed25519"
        or target.get("key_id") is not None
        or storage.get("key_id") is not None
        or target.get("public_key_b64url") is not None
        or storage.get("public_key_b64url") is not None
        or target.get("usage_scope") != "private_secret_target_crash_origin_v1_only"
        or storage.get("usage_scope") != "private_secret_target_storage_receipt_v1_only"
        or value.get("custody_requirements")
        != {
            "dedicated_distinct_keys_required": True,
            "private_keys_in_repository": "forbidden",
            "private_key_cli_environment_transport": "forbidden",
            "external_custody_evidence_required": True,
            "independent_review_required": True,
        }
    ):
        errors.append("target trust policy must remain closed and unconfigured")
    return errors


def _target_template_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "target origin template")
    if errors:
        return errors
    errors.extend(_sealed_pending(value, _TARGET_TEMPLATE_FIELDS, "target origin template"))
    if errors or not isinstance(value, dict):
        return errors
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != "private_secret_target_origin_intake"
        or value.get("synthetic") is not True
        or value.get("evidence_status") != "pending"
        or value.get("origin_authentication") != "unverified"
        or value.get("provider_receipt_authentication") != "unverified"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or value.get("payload") is not None
        or value.get("signatures") is not None
    ):
        errors.append("target origin template must remain pending and unverified")
    return errors


def _t140_errors(source: str) -> list[str]:
    required = (
        'payload["origin_authentication"] != "unverified"',
        "status=reviewed-assertion origin-authentication=unverified",
        "production_acceptance=false",
    )
    errors = [f"T140 evidence boundary is missing {marker}" for marker in required if marker not in source]
    if "origin-authentication=authenticated" in source:
        errors.append("T140 evidence boundary was upgraded in place")
    return errors


def validate_assets(
    github_source: str,
    target_source: str,
    t140_source: str,
    github_policy_raw: bytes,
    github_template_raw: bytes,
    target_policy_raw: bytes,
    target_template_raw: bytes,
) -> list[str]:
    errors = _github_errors(github_source)
    errors.extend(_target_errors(target_source))
    errors.extend(_t140_errors(t140_source))
    errors.extend(_github_policy_errors(github_policy_raw))
    errors.extend(_github_template_errors(github_template_raw))
    errors.extend(_target_policy_errors(target_policy_raw))
    errors.extend(_target_template_errors(target_template_raw))
    return errors


def main() -> int:
    try:
        errors = validate_assets(
            load_stable_text(GITHUB_TOOL, max_bytes=MAX_SOURCE_BYTES),
            load_stable_text(TARGET_TOOL, max_bytes=MAX_SOURCE_BYTES),
            load_stable_text(T140_TOOL, max_bytes=MAX_SOURCE_BYTES),
            read_stable_bytes(GITHUB_POLICY, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(GITHUB_TEMPLATE, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(TARGET_POLICY, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(TARGET_TEMPLATE, max_bytes=MAX_ASSET_BYTES),
        )
    except (OSError, UnicodeError, ValueError):
        print("private-secret-provenance-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"private-secret-provenance-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-provenance-static-ok "
        "github-policy=unconfigured target-policy=unconfigured "
        "origin-authentication=unverified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
