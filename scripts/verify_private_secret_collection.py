"""Statically guard the two offline private-secret collection handoffs."""

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
GITHUB_TOOL = ROOT / "scripts" / "private_secret_github_rest_collection.py"
WORM_TOOL = ROOT / "scripts" / "private_secret_worm_collection.py"
BACKED_TOOL = ROOT / "scripts" / "private_secret_collection_backed_acceptance.py"
GITHUB_POLICY = ROOT / "deploy" / "github-rest-collection-policy.synthetic.json"
WORM_POLICY = ROOT / "deploy" / "private-secret-worm-collection-policy.synthetic.json"
GITHUB_TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-github-rest-collection.synthetic.json"
)
WORM_TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-worm-collection.synthetic.json"
)

MAX_SOURCE_BYTES = 128 * 1024
MAX_ASSET_BYTES = 32 * 1024

_GITHUB_COLLECTOR_DOMAIN = "email-platform/private-secret-github-rest-collector/v1"
_GITHUB_LEDGER_DOMAIN = "email-platform/private-secret-github-rest-replay-ledger/v1"
_WORM_PROVIDER_DOMAIN = b"email-platform/private-secret-worm-audit/provider-observation/v1\0"
_WORM_LEDGER_DOMAIN = b"email-platform/private-secret-worm-audit/replay-checkpoint/v1\0"
_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}

_NETWORK_IMPORTS = {
    "aiohttp",
    "azure.storage",
    "boto3",
    "botocore",
    "ftplib",
    "github",
    "google.cloud.storage",
    "http.client",
    "httpx",
    "requests",
    "smtplib",
    "socket",
    "urllib.request",
}
_PROCESS_CALLS = {"Popen", "check_call", "check_output", "run", "spawn", "system"}
_MUTATION_CALLS = {
    "create",
    "delete",
    "execute",
    "generate",
    "handoff",
    "link",
    "makedirs",
    "mkdir",
    "open",
    "publish",
    "put",
    "remove",
    "rename",
    "replace",
    "rmdir",
    "symlink",
    "unlink",
    "upload",
    "write",
    "write_bytes",
    "write_text",
}
_PRIVATE_KEY_MARKERS = {
    "Ed25519PrivateKey",
    "EllipticCurvePrivateKey",
    "RSAPrivateKey",
    "load_der_private_key",
    "load_pem_private_key",
}

_GITHUB_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "repository",
    "allowed_workflow_paths",
    "allowed_job_names",
    "source",
    "api",
    "collector",
    "replay_ledger",
    "time_constraints",
    "review",
    "integrity",
}
_GITHUB_TEMPLATE_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "production_acceptance",
    "not_committed_eligible",
    "collection_payload",
    "collector_signature",
    "replay_head",
    "claim_boundary",
    "prohibited_content",
}
_GITHUB_CLAIM_BOUNDARY = {
    "job_artifact_causality": "unverified",
    "provider_native": "unverified",
    "trusted_time": "unverified",
    "freshness": "unverified",
    "replay_protection": "unverified",
    "durability": "unverified",
    "reviewer_independence": "unverified",
}
_WORM_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "not_committed_eligible",
    "executor_integration_enabled",
    "handoff_integration_enabled",
    "provider_contract",
    "provider_observer",
    "ledger_signer",
    "requirements",
    "time_constraints",
    "integrity",
}
_WORM_TEMPLATE_FIELDS = {
    "schema_version",
    "record_type",
    "synthetic",
    "collection_status",
    "provider_observation_authentication",
    "checkpoint_authentication",
    "production_acceptance",
    "not_committed_eligible",
    "observation",
    "checkpoint",
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
            if node.value is None:
                return None
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError):
                return None
    return None


def _required_kwonly(
    function: ast.FunctionDef | ast.AsyncFunctionDef | None, name: str
) -> bool:
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
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            values.add(node.module or "")
    return values


def _calls(tree: ast.AST) -> list[str]:
    return [
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (name := _qualified_name(node.func)) is not None
    ]


def _matches_import(value: str, forbidden: str) -> bool:
    return value == forbidden or value.startswith(forbidden + ".")


def _common_source_errors(source: str, tree: ast.AST, *, label: str) -> list[str]:
    errors: list[str] = []
    imported = _imports(tree)
    if any(
        _matches_import(value, forbidden)
        for value in imported
        for forbidden in _NETWORK_IMPORTS
    ):
        errors.append(f"{label} imports a network or provider SDK capability")
    if "subprocess" in imported:
        errors.append(f"{label} imports subprocess")
    if any(marker in source for marker in _PRIVATE_KEY_MARKERS):
        errors.append(f"{label} contains a private-key capability")
    for name in _calls(tree):
        suffix = name.rsplit(".", 1)[-1]
        if suffix in _PROCESS_CALLS:
            errors.append(f"{label} contains a process capability")
            break
    for name in _calls(tree):
        suffix = name.rsplit(".", 1)[-1]
        if suffix in _MUTATION_CALLS or suffix == "sign":
            errors.append(f"{label} contains a signing or mutation capability")
            break
    if "production_acceptance=true" in source or "not_committed_eligible=true" in source:
        errors.append(f"{label} enables an acceptance state")
    return errors


def _parser_requires(tree: ast.AST, option: str) -> bool:
    parser = _function(tree, "_parser")
    if parser is None:
        return False
    for node in ast.walk(parser):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if _qualified_name(node.func) not in {"verify.add_argument", "parser.add_argument"}:
            continue
        first = node.args[0]
        if not isinstance(first, ast.Constant) or first.value != option:
            continue
        return any(
            keyword.arg == "required"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
    return False


def _pin_errors(
    source: str,
    tree: ast.AST,
    *,
    label: str,
    parameters: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    verify = _function(tree, "verify_collection")
    for parameter in parameters:
        if not _required_kwonly(verify, parameter):
            errors.append(f"{label} must require caller {parameter}")
        elif any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == parameter
            for node in ast.walk(verify)
        ):
            errors.append(f"{label} overwrites caller {parameter}")
        option = "--" + parameter.replace("_", "-")
        if not _parser_requires(tree, option):
            errors.append(f"{label} CLI must require caller {parameter}")
    return errors


def _stable_boundary_errors(
    source: str,
    tree: ast.AST,
    *,
    label: str,
    reader_name: str,
) -> list[str]:
    errors: list[str] = []
    reader = _function(tree, reader_name)
    reader_source = ast.get_source_segment(source, reader) or "" if reader is not None else ""
    required = (
        "read_stable_bytes_with_metadata(",
        "metadata.st_nlink != 1",
        "_external_path(",
    )
    for marker in required:
        if marker not in reader_source:
            errors.append(f"{label} stable external reader is missing {marker}")
    verify = _function(tree, "verify_collection")
    if verify is None:
        errors.append(f"{label} collection entrypoint is missing")
        return errors
    direct_reads = [
        name
        for name in _calls(verify)
        if name.rsplit(".", 1)[-1]
        in {"open", "read_bytes", "read_text", "read_stable_bytes", "read_stable_bytes_with_metadata"}
    ]
    if direct_reads:
        errors.append(f"{label} bypasses its stable external reader")
    verify_source = ast.get_source_segment(source, verify) or ""
    if "len(normalized) != len(paths)" not in verify_source:
        errors.append(f"{label} does not reject aliased external paths")
    return errors


def _exact_call_count(
    tree: ast.AST,
    *,
    function_name: str,
    called_name: str,
    expected: int,
    label: str,
) -> list[str]:
    function = _function(tree, function_name)
    if function is None:
        return [f"{label} is missing {function_name}"]
    count = sum(name == called_name for name in _calls(function))
    if count != expected:
        return [f"{label} must call {called_name} exactly {expected} times"]
    return []


def _has_exact_compare(
    tree: ast.AST, *, function_name: str, expression: str
) -> bool:
    function = _function(tree, function_name)
    if function is None:
        return False
    return any(
        isinstance(node, ast.Compare) and ast.unparse(node) == expression
        for node in ast.walk(function)
    )


def _signature_roles(tree: ast.AST, *, function_name: str) -> list[str]:
    function = _function(tree, function_name)
    if function is None:
        return []
    roles: list[str] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "role" and isinstance(keyword.value, ast.Constant):
                roles.append(str(keyword.value.value))
    return roles


def _status_errors(source: str, *, label: str, axes: tuple[str, ...]) -> list[str]:
    errors: list[str] = []
    for axis in axes:
        if source.count(f"{axis}=unverified") != 2 or f"{axis}=verified" in source:
            errors.append(f"{label} overstates {axis}")
    if source.count("production_acceptance=false") != 2:
        errors.append(f"{label} must keep production acceptance false in both outputs")
    if source.count("not_committed_eligible=false") != 2:
        errors.append(f"{label} must keep not-committed eligibility false in both outputs")
    return errors


def _github_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["GitHub REST collection verifier is not valid Python"]
    errors = _common_source_errors(source, tree, label="GitHub REST collection verifier")
    pin_parameters = (
        "expected_receipt_sha256",
        "expected_policy_sha256",
        "expected_request_sha256",
        "expected_previous_head_sha256",
        "expected_github_origin_sha256",
        "expected_deployment_policy_sha256",
        "expected_readiness_sha256",
        "expected_archive_sha256",
        "expected_bundle_sha256",
        "expected_current_worm_collection_head_sha256",
        "expected_ledger_id",
        "expected_sequence",
    )
    errors.extend(
        _pin_errors(
            source,
            tree,
            label="GitHub REST collection verifier",
            parameters=pin_parameters,
        )
    )
    bytes_core = _function(tree, "verify_collection_bytes")
    for parameter in pin_parameters:
        if not _required_kwonly(bytes_core, parameter):
            errors.append(
                f"GitHub REST collection bytes core must require caller {parameter}"
            )
        elif any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == parameter
            for node in ast.walk(bytes_core)
        ):
            errors.append(
                f"GitHub REST collection bytes core overwrites caller {parameter}"
            )
    errors.extend(
        _stable_boundary_errors(
            source,
            tree,
            label="GitHub REST collection verifier",
            reader_name="_read_blob",
        )
    )
    errors.extend(
        _exact_call_count(
            tree,
            function_name="verify_collection",
            called_name="_read_blob",
            expected=9,
            label="GitHub REST collection verifier",
        )
    )
    errors.extend(
        _exact_call_count(
            tree,
            function_name="verify_collection",
            called_name="_unchanged",
            expected=1,
            label="GitHub REST collection verifier",
        )
    )
    errors.extend(
        _exact_call_count(
            tree,
            function_name="verify_collection",
            called_name="verify_collection_bytes",
            expected=1,
            label="GitHub REST collection verifier",
        )
    )
    if _assignment_literal(tree, "COLLECTOR_DOMAIN") != _GITHUB_COLLECTOR_DOMAIN:
        errors.append("GitHub collector signer domain has drifted")
    if _assignment_literal(tree, "LEDGER_DOMAIN") != _GITHUB_LEDGER_DOMAIN:
        errors.append("GitHub replay-ledger signer domain has drifted")
    if _assignment_literal(tree, "_SIGNATURE_FIELDS") != _SIGNATURE_FIELDS:
        errors.append("GitHub signature schema permits embedded-key fallback")
    if source.count('signature["algorithm"] != "Ed25519"') != 2:
        errors.append("GitHub signature algorithm checks have drifted")
    if _assignment_literal(tree, "_CLAIM_BOUNDARY_FIELDS") != set(_GITHUB_CLAIM_BOUNDARY):
        errors.append("GitHub unproved claim-boundary schema has drifted")
    required = (
        'POLICY_KIND = "github_rest_collection_trust_policy"',
        'REQUEST_KIND = "private_secret_github_rest_collection_request"',
        'EVIDENCE_KIND = "private_secret_github_rest_collection"',
        'CHECKPOINT_KIND = "github_rest_collection_replay_checkpoint"',
        'anchor["algorithm"] != "Ed25519"',
        'signature["algorithm"] != "Ed25519"',
        'if any(item != "unverified" for item in claim_boundary.values())',
        "collector = _anchor(policy[\"collector\"], expected_domain=COLLECTOR_DOMAIN)",
        "ledger = _anchor(policy[\"replay_ledger\"], expected_domain=LEDGER_DOMAIN)",
        "hmac.compare_digest(collector.key_id, ledger.key_id)",
        "expected_policy_sha256, policy_blob.sha256",
        "expected_request_sha256, request_blob.sha256",
        "expected_previous_head_sha256, previous_blob.sha256",
        "expected_github_origin_sha256, github_origin_blob.sha256",
        "expected_deployment_policy_sha256, deployment_policy_blob.sha256",
        "expected_readiness_sha256, readiness_blob.sha256",
        "expected_archive_sha256, archive_blob.sha256",
        "expected_bundle_sha256, bundle_blob.sha256",
        'request["trust_policy_sha256"] != policy_blob.sha256',
        'request["github_origin"]["artifact_sha256"] != github_origin_blob.sha256',
        'request["previous_head"]["ledger_id"] != expected_ledger_id',
        'request["previous_head"]["expected_sequence"] != expected_sequence',
        'request["previous_head"]["artifact_sha256"] != previous_blob.sha256',
        '"github_origin_artifact_sha256": github_origin_blob.sha256',
        "github_attestation.validate_origin_envelope(",
        "collector_deployment.verify_readiness_preflight(",
        '"collector_readiness_artifact_sha256": readiness.readiness_sha256',
        'archive_download["raw_body_sha256"] != archive_blob.sha256',
        'bundle_download["raw_body_sha256"] != bundle_blob.sha256',
        'redirect["location_origin"] not in readiness.artifact_redirect_origins',
        'previous_checkpoint["sequence"] != expected_sequence - 1',
        'checkpoint["sequence"] != expected_sequence',
        "_verify_signature(payload, evidence[\"collector_signature\"], collector_anchor)",
        "_verify_signature(checkpoint, replay_head[\"signature\"], ledger_anchor)",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"GitHub REST collection verifier is missing {marker}")
    if not _has_exact_compare(
        tree,
        function_name="verify_collection_bytes",
        expression="checkpoint['sequence'] != expected_sequence",
    ):
        errors.append("GitHub current checkpoint sequence is not caller-bound")
    core = _function(tree, "verify_collection_bytes")
    if core is None:
        errors.append("GitHub REST collection bytes core is missing")
    else:
        forbidden = {
            "_read_blob", "_unchanged", "read_stable_bytes",
            "read_stable_bytes_with_metadata", "open", "Path.read_bytes",
            "Path.read_text",
        }
        if any(name in forbidden for name in _calls(core)):
            errors.append("GitHub REST collection bytes core performs filesystem I/O")
    errors.extend(
        _status_errors(
            source,
            label="GitHub REST collection verifier",
            axes=(
                "job-artifact-causality",
                "provider-native",
                "trusted-time",
                "freshness",
                "replay-protection",
                "durability",
                "reviewer-independence",
            ),
        )
    )
    if "private_secret_worm_collection" in source:
        errors.append("GitHub REST verifier crosses into the WORM trust domain")
    return errors


def _worm_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["WORM collection verifier is not valid Python"]
    errors = _common_source_errors(source, tree, label="WORM collection verifier")
    pin_parameters = (
        "expected_collection_sha256",
        "expected_policy_sha256",
        "expected_target_policy_sha256",
        "expected_cluster_fingerprint_sha256",
        "expected_ledger_id",
        "expected_sequence",
        "expected_prior_head_sha256",
        "verification_time",
    )
    errors.extend(
        _pin_errors(
            source,
            tree,
            label="WORM collection verifier",
            parameters=pin_parameters,
        )
    )
    bytes_core = _function(tree, "verify_collection_bytes")
    for parameter in pin_parameters:
        if not _required_kwonly(bytes_core, parameter):
            errors.append(f"WORM bytes core must require caller {parameter}")
        elif any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == parameter
            for node in ast.walk(bytes_core)
        ):
            errors.append(f"WORM bytes core overwrites caller {parameter}")
    errors.extend(
        _stable_boundary_errors(
            source,
            tree,
            label="WORM collection verifier",
            reader_name="_read_external_bytes",
        )
    )
    for called_name, expected in (
        ("_read_external_bytes", 19),
        ("_read_runtime_policy_bytes", 1),
        ("verify_collection_bytes", 1),
    ):
        errors.extend(
            _exact_call_count(
                tree,
                function_name="verify_collection",
                called_name=called_name,
                expected=expected,
                label="WORM collection verifier",
            )
        )
    if _assignment_literal(tree, "_PROVIDER_DOMAIN") != _WORM_PROVIDER_DOMAIN:
        errors.append("WORM provider-observer signer domain has drifted")
    if _assignment_literal(tree, "_LEDGER_DOMAIN") != _WORM_LEDGER_DOMAIN:
        errors.append("WORM replay-ledger signer domain has drifted")
    if _assignment_literal(tree, "_SIGNATURE_FIELDS") != _SIGNATURE_FIELDS:
        errors.append("WORM signature schema permits embedded-key fallback")
    if _signature_roles(
        tree, function_name="_verify_collection_signatures"
    ) != ["provider_observer", "ledger_signer"]:
        errors.append("WORM verifier must authenticate both distinct signer roles")
    if _signature_roles(tree, function_name="_validate_collection") != [
        "provider_observer",
        "ledger_signer",
    ]:
        errors.append("WORM verifier validates signatures under the wrong role schema")
    required = (
        'POLICY_KIND = "private_secret_worm_collection_trust_policy"',
        'RECORD_TYPE = "private_secret_worm_collection"',
        'OBSERVATION_KIND = "private_secret_worm_provider_observation"',
        'CHECKPOINT_KIND = "private_secret_worm_replay_checkpoint"',
        'anchor["algorithm"] != "Ed25519"',
        'signature["algorithm"] != "Ed25519"',
        'usage_scope="private_secret_worm_provider_observation_v1_only"',
        'usage_scope="private_secret_worm_replay_checkpoint_v1_only"',
        "hmac.compare_digest(provider_key or b\"\", ledger_key or b\"\")",
        "hashlib.sha256(policy_raw).hexdigest(), expected_policy_sha256",
        "hashlib.sha256(input_raw).hexdigest(), expected_collection_sha256",
        'contract["ledger_id"] != expected_ledger_id',
        'checkpoint["ledger_id"] != expected_ledger_id',
        'checkpoint["sequence"] != expected_sequence',
        'provider["storage_identity_fingerprint_sha256"]',
        "target_origin.storage_identity_fingerprint_sha256",
        'observed_object["object_reference"] != target_origin.object_reference',
        'observed_object["immutable_version_reference"]',
        "target_origin.immutable_version_reference",
        'observed_object["content_sha256"] != target_origin.evidence_readback_sha256',
        'deletion["post_denial_readback_sha256"]',
        "hashlib.sha256(readback_raw).hexdigest()",
        "target_origin.evidence_readback_sha256",
        "expected_prior_head_sha256 != ZERO_SHA256",
        "hashlib.sha256(prior_checkpoint_raw).hexdigest(), expected_prior_head_sha256",
        'prior_checkpoint["sequence"] != expected_sequence - 1',
        '"artifact_sha256": expected_prior_head_sha256',
        "verify_target_origin_bytes(",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"WORM collection verifier is missing {marker}")
    if not _has_exact_compare(
        tree,
        function_name="verify_collection_bytes",
        expression="checkpoint['sequence'] != expected_sequence",
    ):
        errors.append("WORM current checkpoint sequence is not caller-bound")
    core = _function(tree, "verify_collection_bytes")
    if core is None:
        errors.append("WORM bytes core is missing")
    else:
        forbidden = {
            "_read_external_bytes", "_read_runtime_policy_bytes", "read_stable_bytes",
            "read_stable_bytes_with_metadata", "open", "Path.read_bytes", "Path.read_text",
        }
        if any(name in forbidden for name in _calls(core)):
            errors.append("WORM bytes core performs filesystem I/O")
    errors.extend(
        _status_errors(
            source,
            label="WORM collection verifier",
            axes=(
                "provider-native",
                "trusted-time",
                "freshness",
                "replay-protection",
                "durability",
                "reviewer-independence",
            ),
        )
    )
    if "private_secret_github_rest_collection" in source:
        errors.append("WORM verifier crosses into the GitHub REST trust domain")
    return errors


def _backed_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["collection-backed acceptance verifier is not valid Python"]
    errors = _common_source_errors(
        source, tree, label="collection-backed acceptance verifier"
    )
    if _assignment_literal(tree, "_MANIFEST_FIELDS") != {
        "schema_version", "manifest_kind", "policy_path", "readiness_path",
        "execution_path", "acceptance_pins", "github_inputs", "worm_inputs",
    }:
        errors.append("collection-backed input manifest schema is not closed")
    if "expected_runtime_policy_sha256" not in (
        _assignment_literal(tree, "_WORM_PINS") or set()
    ):
        errors.append("collection-backed runtime policy is not caller-pinned")
    for called_name, expected in (
        ("github.verify_collection_bytes", 1),
        ("worm.verify_collection_bytes", 1),
        ("github.verify_collection", 0),
        ("worm.verify_collection", 0),
    ):
        errors.extend(
            _exact_call_count(
                tree,
                function_name="_verify_collection_backed_acceptance",
                called_name=called_name,
                expected=expected,
                label="collection-backed acceptance verifier",
            )
        )
    for function_name in (
        "verify_collection_backed_acceptance",
        "verify_input_manifest_projection",
    ):
        errors.extend(
            _exact_call_count(
                tree,
                function_name=function_name,
                called_name="_verify_collection_backed_acceptance",
                expected=1,
                label="collection-backed acceptance verifier",
            )
        )
    required = (
        "read_stable_bytes_with_metadata(path, max_bytes=max_bytes)",
        "metadata.st_nlink != 1",
        "expected_identity=blob.identity",
        "_reject_duplicate_identities(all_blobs)",
        "runtime_policy_blob.sha256",
        'worm_values["expected_runtime_policy_sha256"]',
        "for blob in all_blobs:",
        "_unchanged(blob)",
        "parse_input_manifest(manifest_blob.raw)",
        "_unchanged(manifest_blob)",
        "manifest-authentication=caller-pinned-raw-sha256",
        "production_acceptance=false",
        "not_committed_eligible=false",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"collection-backed acceptance verifier is missing {marker}")
    stable_reader = _function(tree, "_stable_input")
    unchanged = _function(tree, "_unchanged")
    for function, label in (
        (stable_reader, "stable reader"),
        (unchanged, "terminal recheck"),
    ):
        function_source = ast.get_source_segment(source, function) or ""
        if "metadata.st_nlink != 1" not in function_source:
            errors.append(
                f"collection-backed acceptance {label} permits hardlinks"
            )
    if "verified_readiness" in source:
        errors.append("collection-backed acceptance permits a constructed readiness bypass")
    return errors


def _parse_json(raw: bytes, label: str) -> tuple[object | None, list[str]]:
    try:
        return parse_unique_json_bytes(raw), []
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None, [f"{label} is not unique-key JSON"]


def _sealed_errors(value: object, fields: set[str], label: str) -> list[str]:
    if not isinstance(value, dict) or set(value) != fields:
        return [f"{label} schema is not closed"]
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        return [f"{label} integrity is not closed"]
    payload = {key: item for key, item in value.items() if key != "integrity"}
    if integrity.get("payload_sha256") != _canonical_digest(payload):
        return [f"{label} canonical integrity has drifted"]
    return []


def _github_policy_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "GitHub REST collection policy")
    if errors:
        return errors
    errors.extend(_sealed_errors(value, _GITHUB_POLICY_FIELDS, "GitHub REST collection policy"))
    if errors or not isinstance(value, dict):
        return errors
    optional = (
        "repository",
        "allowed_workflow_paths",
        "allowed_job_names",
        "source",
        "api",
        "collector",
        "replay_ledger",
        "time_constraints",
        "review",
    )
    if (
        value.get("schema_version") != 1
        or value.get("policy_kind") != "github_rest_collection_trust_policy"
        or value.get("synthetic") is not True
        or value.get("policy_status") != "pending"
        or value.get("policy_effect") != "offline_external_collection_authentication_only"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or any(value.get(field) is not None for field in optional)
    ):
        errors.append("GitHub REST collection policy must remain pending and unconfigured")
    return errors


def _github_template_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "GitHub REST collection template")
    if errors or not isinstance(value, dict):
        return errors
    if set(value) != _GITHUB_TEMPLATE_FIELDS:
        errors.append("GitHub REST collection template schema is not closed")
        return errors
    prohibited = value.get("prohibited_content")
    if (
        value.get("schema_version") != 1
        or value.get("evidence_kind") != "private_secret_github_rest_collection"
        or value.get("synthetic") is not True
        or value.get("evidence_status") != "pending"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or value.get("claim_boundary") != _GITHUB_CLAIM_BOUNDARY
        or any(value.get(field) is not None for field in ("collection_payload", "collector_signature", "replay_head"))
        or not isinstance(prohibited, dict)
        or not prohibited
        or any(item is not False for item in prohibited.values())
    ):
        errors.append("GitHub REST collection template must remain pending and unverified")
    return errors


def _worm_policy_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "WORM collection policy")
    if errors:
        return errors
    errors.extend(_sealed_errors(value, _WORM_POLICY_FIELDS, "WORM collection policy"))
    if errors or not isinstance(value, dict):
        return errors
    contract = value.get("provider_contract")
    provider = value.get("provider_observer")
    ledger = value.get("ledger_signer")
    requirements = value.get("requirements")
    expected_anchor = {
        "state": "unconfigured",
        "algorithm": "Ed25519",
        "key_id": None,
        "public_key_b64url": None,
        "source": "release_governed_external_configuration",
    }
    if (
        value.get("schema_version") != 1
        or value.get("policy_kind") != "private_secret_worm_collection_trust_policy"
        or value.get("synthetic") is not True
        or value.get("policy_status") != "unconfigured"
        or value.get("policy_effect") != "authentication_prerequisite_only"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or value.get("executor_integration_enabled") is not False
        or value.get("handoff_integration_enabled") is not False
        or contract
        != {
            "state": "unconfigured",
            "provider_kind": None,
            "ledger_id": None,
            "required_retention_mode": None,
            "denied_delete_reason_code": None,
        }
        or not isinstance(provider, dict)
        or not isinstance(ledger, dict)
        or provider
        != {**expected_anchor, "usage_scope": "private_secret_worm_provider_observation_v1_only"}
        or ledger
        != {**expected_anchor, "usage_scope": "private_secret_worm_replay_checkpoint_v1_only"}
        or not isinstance(requirements, dict)
        or set(requirements)
        != {
            "configuration_snapshot_required",
            "object_metadata_snapshot_required",
            "denied_delete_observation_required",
            "post_denial_readback_required",
            "trusted_time_artifact_required",
            "caller_head_pin_required",
        }
        or any(item is not True for item in requirements.values())
    ):
        errors.append("WORM collection policy must remain closed and unconfigured")
    return errors


def _worm_template_errors(raw: bytes) -> list[str]:
    value, errors = _parse_json(raw, "WORM collection template")
    if errors:
        return errors
    errors.extend(_sealed_errors(value, _WORM_TEMPLATE_FIELDS, "WORM collection template"))
    if errors or not isinstance(value, dict):
        return errors
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != "private_secret_worm_collection"
        or value.get("synthetic") is not True
        or value.get("collection_status") != "pending"
        or value.get("provider_observation_authentication") != "unverified"
        or value.get("checkpoint_authentication") != "unverified"
        or value.get("production_acceptance") is not False
        or value.get("not_committed_eligible") is not False
        or value.get("observation") is not None
        or value.get("checkpoint") is not None
    ):
        errors.append("WORM collection template must remain pending and unverified")
    return errors


def validate_assets(
    github_source: str,
    worm_source: str,
    backed_source: str,
    github_policy_raw: bytes,
    github_template_raw: bytes,
    worm_policy_raw: bytes,
    worm_template_raw: bytes,
) -> list[str]:
    errors = _github_errors(github_source)
    errors.extend(_worm_errors(worm_source))
    errors.extend(_backed_errors(backed_source))
    errors.extend(_github_policy_errors(github_policy_raw))
    errors.extend(_github_template_errors(github_template_raw))
    errors.extend(_worm_policy_errors(worm_policy_raw))
    errors.extend(_worm_template_errors(worm_template_raw))
    return errors


def main() -> int:
    try:
        errors = validate_assets(
            load_stable_text(GITHUB_TOOL, max_bytes=MAX_SOURCE_BYTES),
            load_stable_text(WORM_TOOL, max_bytes=MAX_SOURCE_BYTES),
            load_stable_text(BACKED_TOOL, max_bytes=MAX_SOURCE_BYTES),
            read_stable_bytes(GITHUB_POLICY, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(GITHUB_TEMPLATE, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(WORM_POLICY, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(WORM_TEMPLATE, max_bytes=MAX_ASSET_BYTES),
        )
    except (OSError, UnicodeError, ValueError):
        print("private-secret-collection-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"private-secret-collection-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-static-ok "
        "github-policy=unconfigured worm-policy=unconfigured "
        "provider-native=unverified trusted-time=unverified "
        "freshness=unverified replay-protection=unverified "
        "durability=unverified reviewer-independence=unverified "
        "job-artifact-causality=unverified production_acceptance=false "
        "not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
