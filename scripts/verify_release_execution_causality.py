"""Statically lock the release-ledger causality chain used by strict intake."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "scripts" / "release_execution_binding.py"
INTAKE = ROOT / "scripts" / "target_intake_preflight.py"
GENERATION = ROOT / "scripts" / "target_intake_generation.py"
ACCEPTANCE = ROOT / "scripts" / "target_intake_acceptance.py"
INTAKE_MANIFEST = ROOT / "scripts" / "target_intake_manifest.py"
EXTERNAL_JSON = ROOT / "scripts" / "external_json.py"
CONSUMERS = {
    name: ROOT / "scripts" / name
    for name in (
        "target_phase_artifacts.py",
        "sub2_execution_evidence.py",
        "vault_egress_evidence.py",
        "phase6_pilot_evidence.py",
        "phase6_operations_evidence.py",
    )
}
INTAKE_ONLY_CONSUMERS = {
    name: ROOT / "scripts" / name
    for name in (
        "phase0_boundary_approval.py",
        "phase6_pilot_inputs.py",
    )
}
MAX_SOURCE_BYTES = 128 * 1024
RELEASE_BOUNDARY_MARKERS = (
    "release-review-selector-subject=manifest-exact",
    "release-reviewer-authentication=unverified",
    "release-review-trusted-time=unverified",
    "release-review-replay-protection=unverified",
    "release-storage-provider-native=unverified",
    "release-storage-retention=unverified",
    "release-storage-delete-denial=unverified",
    "release-storage-readback=unverified",
    "release-storage-namespace-authority=unverified",
    "release-storage-version-identity=unverified",
    "release-storage-cross-manifest-rebinding=unverified",
)
FINAL_MANIFEST_BOUNDARY_MARKERS = (
    "final-manifest-caller-pin=",
    "final-manifest-custody=unverified",
    "final-manifest-pin-authority=unverified",
    "final-manifest-rollback-protection=unverified",
)
AUTHORING_GENERATION_BOUNDARY_MARKERS = (
    "generation-acceptance=write-once-receipt",
    "generation-receipt-locator=self-bound-v3",
    "generation-history-semantic-replay=every-generation",
    "generation-receipt-evaluation-time=recorded-host-utc",
    "authoring-validation-context-authority=unverified",
    "authoring-trusted-time=unverified",
    "authoring-validator-version=unverified",
    "selected-lineage=caller-pinned-local-receipt-chain-validated",
    "authoring-publication=local-no-replace-readback",
    "authoring-generation-fork-protection=unverified",
    "authoring-latest-head=unverified",
    "authoring-pin-authority=unverified",
    "authoring-receipt-authority=unverified",
    "authoring-rollback-protection=unverified",
    "authoring-locator-continuity=unverified",
    "authoring-parent-directory-race-protection=unverified",
    "authoring-publication-crash-durability=unverified",
    "authoring-post-publication-custody=unverified",
)
ACCEPTANCE_BOUNDARY_MARKERS = (
    "snapshot-acceptance=write-once-receipt",
    "snapshot-receipt-locator=self-bound-v2",
    "snapshot-receipt-authority=unverified",
    "snapshot-parent-directory-race-protection=unverified",
    "snapshot-publication-crash-durability=unverified",
    "snapshot-post-publication-custody=unverified",
    "phase0-snapshot-acceptance=caller-pinned-local-receipt-validated",
    "finalization-acceptance=write-once-receipt",
    "finalization-receipt-locator=self-bound-v2",
    "finalization-receipt-caller-pin=",
    "finalization-receipt-authority=unverified",
    "finalization-parent-directory-race-protection=unverified",
    "finalization-publication-crash-durability=unverified",
    "selected-finalization-lineage=",
)
INTAKE_CALLER_BOUNDARY_MARKERS = (
    "intake-manifest-caller-pin=payload-and-file-matched",
    "intake-artifact-whole-file-binding=matched",
    "intake-artifact-path-binding=absolute-single-link-matched",
    "intake-manifest-schema=closed-v2-inventory-exact",
    "intake-manifest-custody=unverified",
    "intake-manifest-pin-authority=unverified",
    "intake-manifest-rollback-protection=unverified",
)
EXPECTED_INTAKE_IDS = (
    "sub2_contract",
    "mail_contract",
    "card_pci_boundary",
    "oidc_deployment_identity",
    "phase0_boundary_approval",
    "target_platform_inventory",
    "phase1_platform_evidence",
    "phase2_mail_evidence",
    "phase3_card_evidence",
    "sub2_execution_evidence",
    "vault_egress_evidence",
    "windows_pilot_inputs",
    "phase5_windows_evidence",
    "release_execution_evidence",
    "phase6_pilot_inputs",
    "phase6_pilot_evidence",
    "phase6_operations_evidence",
)


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )


def _literal_assignment(tree: ast.Module, name: str) -> object | None:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            try:
                return ast.literal_eval(node.value)
            except (ValueError, TypeError):
                return None
    return None


def _call_name(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _dict_projection(function: ast.FunctionDef) -> dict[str, ast.AST]:
    candidates: list[dict[str, ast.AST]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        keys = [
            key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
            for key in node.value.keys
        ]
        if "ledger_type" in keys:
            candidates.append(
                {
                    key: value
                    for key, value in zip(keys, node.value.values, strict=True)
                    if key is not None
                }
            )
    return max(candidates, key=len, default={})


def _is_evidence_field(node: ast.AST | None, field: str) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "evidence"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == field
    )


def _has_compare(
    function: ast.FunctionDef,
    left: str,
    operator: type[ast.cmpop],
    right: str,
) -> bool:
    return any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == left
        and len(node.ops) == 1
        and isinstance(node.ops[0], operator)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == right
        for node in ast.walk(function)
    )


def _has_item_get_compare(
    function: ast.FunctionDef,
    key: str,
    operator: type[ast.cmpop],
    right: str,
) -> bool:
    return any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Call)
        and isinstance(node.left.func, ast.Attribute)
        and isinstance(node.left.func.value, ast.Name)
        and node.left.func.value.id == "item"
        and node.left.func.attr == "get"
        and len(node.left.args) == 1
        and isinstance(node.left.args[0], ast.Constant)
        and node.left.args[0].value == key
        and len(node.ops) == 1
        and isinstance(node.ops[0], operator)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == right
        for node in ast.walk(function)
    )


def _has_dict_constant(
    function: ast.FunctionDef,
    key: str,
    value: object,
) -> bool:
    return any(
        isinstance(node, ast.Dict)
        and any(
            isinstance(item_key, ast.Constant)
            and item_key.value == key
            and isinstance(item_value, ast.Constant)
            and item_value.value == value
            for item_key, item_value in zip(node.keys, node.values, strict=True)
        )
        for node in ast.walk(function)
    )


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _requires_kwonly(function: ast.FunctionDef, names: set[str]) -> bool:
    defaults = {
        argument.arg: default
        for argument, default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
            strict=True,
        )
    }
    return all(name in defaults and defaults[name] is None for name in names)


def _contains_string(node: ast.AST | None, value: str) -> bool:
    return node is not None and any(
        isinstance(item, ast.Constant) and item.value == value
        for item in ast.walk(node)
    )


def _contains_marker(node: ast.AST | None, value: str) -> bool:
    return node is not None and any(
        isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and value in item.value
        for item in ast.walk(node)
    )


def _contains_name(node: ast.AST | None, value: str) -> bool:
    return node is not None and any(
        isinstance(item, ast.Name) and item.id == value
        for item in ast.walk(node)
    )


def _command_branch(function: ast.FunctionDef, command: str) -> ast.If | None:
    return next(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.Eq)
            and _contains_string(node.test, command)
            and any(
                isinstance(item, ast.Attribute)
                and item.attr == "command"
                for item in ast.walk(node.test)
            )
        ),
        None,
    )


def _required_parser_argument(
    function: ast.FunctionDef,
    receiver: str,
    option: str,
) -> bool:
    return any(
        isinstance(node, ast.Call)
        and _call_name(node) == "add_argument"
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == receiver
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == option
        and isinstance(_keyword_value(node, "required"), ast.Constant)
        and _keyword_value(node, "required").value is True
        for node in ast.walk(function)
    )


def _has_parser_command(
    function: ast.FunctionDef,
    receiver: str,
    command: str,
) -> bool:
    return any(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == receiver
        and isinstance(node.value, ast.Call)
        and _call_name(node.value) == "add_parser"
        and node.value.args
        and isinstance(node.value.args[0], ast.Constant)
        and node.value.args[0].value == command
        for node in ast.walk(function)
    )


def _review_call_is_selector_bound(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node) == "release_execution_reviewed_at"
        and len(node.args) == 2
        and _contains_string(node.args[1], "release_execution")
    )


def _has_release_boundary_output(tree: ast.Module) -> bool:
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return all(
        any(marker in value for value in strings)
        for marker in RELEASE_BOUNDARY_MARKERS
    )


def _has_final_manifest_boundary_output(tree: ast.Module) -> bool:
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return all(
        any(marker in value for value in strings)
        for marker in FINAL_MANIFEST_BOUNDARY_MARKERS
    )


def _compare_digest_call(
    function: ast.FunctionDef,
    expected_name: str,
    actual_name: str,
) -> bool:
    return any(
        isinstance(node, ast.Call)
        and _call_name(node) == "compare_digest"
        and len(node.args) == 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == expected_name
        and _contains_name(node.args[1], actual_name)
        for node in ast.walk(function)
    )


def _intake_consumer_errors(name: str, source: str, tree: ast.Module) -> list[str]:
    errors: list[str] = []
    if not all(marker in source for marker in INTAKE_CALLER_BOUNDARY_MARKERS):
        errors.append(f"{name} must report the intake caller-pin trust boundary")
    main_function = _function(tree, "main")
    pinned_calls = [
        node
        for node in ast.walk(main_function)
        if main_function is not None
        and isinstance(node, ast.Call)
        and _call_name(node) == "load_pinned_intake_manifest"
    ]
    if not (
        "--expected-intake-manifest-payload-sha256" in source
        and "--expected-intake-manifest-file-sha256" in source
        and len(pinned_calls) == 1
        and _contains_name(
            _keyword_value(pinned_calls[0], "expected_payload_sha256"),
            "arguments",
        )
        and _contains_name(
            _keyword_value(pinned_calls[0], "expected_file_sha256"),
            "arguments",
        )
    ):
        errors.append(f"{name} must require both external intake manifest pins")
    if main_function is not None and pinned_calls:
        other_reads = [
            node
            for node in ast.walk(main_function)
            if isinstance(node, ast.Call)
            and _call_name(node)
            in {
                "_load",
                "load_unique_json",
                "load_unique_json_with_bytes",
                "load_unique_json_with_bytes_and_metadata",
            }
            and _contains_name(node, "arguments")
        ]
        if any(node.lineno < pinned_calls[0].lineno for node in other_reads):
            errors.append(f"{name} must validate intake pins before other evidence reads")
    artifact_binding_calls = [
        node
        for node in ast.walk(main_function)
        if main_function is not None
        and isinstance(node, ast.Call)
        and _call_name(node) == "manifest_artifact_sha256_matches"
    ]
    if not (
        len(artifact_binding_calls) == 1
        and any(
            isinstance(node, ast.Name) and node.id.endswith("_raw")
            for node in ast.walk(artifact_binding_calls[0])
        )
    ):
        errors.append(f"{name} must bind its stable input bytes to its intake item")
    locator_assignments = [
        node
        for node in ast.walk(main_function)
        if main_function is not None
        and isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "document_path"
        and isinstance(node.value, ast.Call)
        and _call_name(node.value) == "manifest_artifact_path"
    ]
    document_reads = [
        node
        for node in ast.walk(main_function)
        if main_function is not None
        and isinstance(node, ast.Call)
        and _call_name(node) == "load_unique_json_with_bytes_and_metadata"
    ]
    rechecks = [
        node
        for node in ast.walk(main_function)
        if main_function is not None
        and isinstance(node, ast.Call)
        and _call_name(node) == "recheck_stable_bytes"
    ]
    if not (
        len(pinned_calls) == 1
        and len(artifact_binding_calls) == 1
        and len(locator_assignments) == 1
        and _contains_name(locator_assignments[0].value, "manifest")
        and _contains_name(locator_assignments[0].value, "arguments")
        and len(document_reads) == 1
        and len(document_reads[0].args) == 1
        and _contains_name(document_reads[0].args[0], "document_path")
        and len(rechecks) == 1
        and len(rechecks[0].args) == 3
        and _contains_name(rechecks[0].args[0], "document_path")
        and _contains_name(rechecks[0].args[1], "document_raw")
        and _contains_name(rechecks[0].args[2], "document_metadata")
        and isinstance(_keyword_value(rechecks[0], "require_single_link"), ast.Constant)
        and _keyword_value(rechecks[0], "require_single_link").value is True
        and pinned_calls[0].lineno < locator_assignments[0].lineno
        and locator_assignments[0].lineno < document_reads[0].lineno
        and artifact_binding_calls[0].lineno < rechecks[0].lineno
    ):
        errors.append(
            f"{name} must read and finally recheck its exact single-link intake locator"
        )
    return errors


def causality_errors(
    binding_source: str,
    intake_source: str,
    consumer_sources: dict[str, str] | None = None,
    intake_manifest_source: str | None = None,
    intake_only_sources: dict[str, str] | None = None,
    external_json_source: str | None = None,
    generation_source: str | None = None,
    acceptance_source: str | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        binding_tree = ast.parse(binding_source)
        intake_tree = ast.parse(intake_source)
        manifest_tree = ast.parse(intake_manifest_source or "")
        external_json_tree = ast.parse(external_json_source or "")
        generation_tree = ast.parse(generation_source or "")
        acceptance_tree = ast.parse(acceptance_source or "")
    except SyntaxError:
        return ["release execution causality sources are not valid Python"]

    manifest_loader = _function(manifest_tree, "load_pinned_intake_manifest")
    manifest_shape = _function(manifest_tree, "manifest_shape_errors")
    manifest_canonical = _function(manifest_tree, "canonical_payload_sha256")
    manifest_artifact = _function(
        manifest_tree,
        "manifest_artifact_sha256_matches",
    )
    manifest_artifact_path_function = _function(
        manifest_tree,
        "manifest_artifact_path",
    )
    stable_json_loader = _function(
        external_json_tree,
        "load_unique_json_with_bytes_and_metadata",
    )
    stable_recheck = _function(external_json_tree, "recheck_stable_bytes")
    if (
        manifest_loader is None
        or manifest_shape is None
        or manifest_canonical is None
        or manifest_artifact is None
        or manifest_artifact_path_function is None
        or stable_json_loader is None
        or stable_recheck is None
    ):
        errors.append("shared closed intake manifest caller binding is missing")
    else:
        loader_calls = [_call_name(node) for node in ast.walk(manifest_loader)]
        stable_reads = [name for name in loader_calls if name == "load_unique_json_with_bytes"]
        digest_compares = [
            node
            for node in ast.walk(manifest_loader)
            if isinstance(node, ast.Call) and _call_name(node) == "compare_digest"
        ]
        if not (
            len(stable_reads) == 1
            and len(digest_compares) == 2
            and any(
                _contains_name(node, "expected_payload_sha256")
                for node in digest_compares
            )
            and any(
                _contains_name(node, "expected_file_sha256")
                for node in digest_compares
            )
            and "canonical_payload_sha256" in loader_calls
            and "manifest_shape_errors" in loader_calls
            and _contains_name(manifest_loader, "expected_payload_sha256")
            and _contains_name(manifest_loader, "expected_file_sha256")
        ):
            errors.append("shared intake loader must bind one stable read to both caller pins")
        if _literal_assignment(manifest_tree, "REQUIRED_IDS") != EXPECTED_INTAKE_IDS:
            errors.append("shared intake loader must lock the ordered 17-item inventory")
        artifact_calls = [_call_name(node) for node in ast.walk(manifest_artifact)]
        if not (
            artifact_calls.count("sha256") == 1
            and artifact_calls.count("compare_digest") == 1
            and _contains_name(manifest_artifact, "identifier")
            and _contains_name(manifest_artifact, "raw")
        ):
            errors.append(
                "shared intake artifact binding must compare one raw SHA-256 digest"
            )
        locator_calls = [
            _call_name(node) for node in ast.walk(manifest_artifact_path_function)
        ]
        if not (
            locator_calls.count("abspath") == 2
            and "normcase" not in locator_calls
            and _contains_name(manifest_artifact_path_function, "identifier")
            and _contains_name(manifest_artifact_path_function, "supplied_path")
            and _contains_string(manifest_artifact_path_function, "artifact_path")
            and any(
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Call)
                and _call_name(node.value) == "Path"
                and _contains_name(node.value, "expected")
                for node in ast.walk(manifest_artifact_path_function)
            )
        ):
            errors.append(
                "shared intake artifact locator must use exact case-preserving absolute normalization"
            )
        stable_loader_calls = [
            _call_name(node) for node in ast.walk(stable_json_loader)
        ]
        recheck_calls = [_call_name(node) for node in ast.walk(stable_recheck)]
        recheck_reads = [
            node
            for node in ast.walk(stable_recheck)
            if isinstance(node, ast.Call)
            and _call_name(node) == "read_stable_bytes_with_metadata"
        ]
        if not (
            stable_loader_calls.count("read_stable_bytes_with_metadata") == 1
            and stable_loader_calls.count("parse_unique_json_bytes") == 1
            and len(recheck_reads) == 1
            and _contains_name(
                _keyword_value(recheck_reads[0], "expected_identity"),
                "metadata",
            )
            and recheck_calls.count("stable_file_identity") == 1
            and recheck_calls.count("compare_digest") == 1
            and recheck_calls.count("sha256") == 2
            and _contains_name(stable_recheck, "require_single_link")
            and sum(
                isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Attribute)
                and node.left.attr == "st_nlink"
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.NotEq)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value == 1
                for node in ast.walk(stable_recheck)
            ) == 2
        ):
            errors.append(
                "shared stable JSON locator recheck must lock identity, single-link count, and bytes"
            )
        if not all(
            value in (intake_manifest_source or "")
            for value in (
                '"schema_version"',
                '"production_acceptance"',
                '"requirements_sha256"',
                '"release_execution_evidence"',
                "identifiers != list(REQUIRED_IDS)",
                "set(item) != expected_keys",
            )
        ):
            errors.append("shared intake loader must enforce the closed v2 inventory")

    if not all(
        value in intake_source
        for value in (
            "REQUIRED_IDS as _REQUIRED_IDS",
            "MANIFEST_KEYS as _MANIFEST_KEYS",
            "ITEM_KEYS as _ITEM_KEYS",
            "RELEASE_ITEM_KEYS as _RELEASE_ITEM_KEYS",
            "canonical_payload_sha256",
            "manifest_file_sha256=",
        )
    ):
        errors.append("strict intake must share schema constants and emit both manifest digests")

    identity = _function(binding_tree, "release_execution_identity")
    opaque_reference = _function(binding_tree, "_opaque_execution_reference")
    selector_validation = _function(binding_tree, "selector_errors")
    reviewed_at = _function(binding_tree, "release_execution_reviewed_at")
    review_subject = _function(binding_tree, "release_execution_review_subject")
    review_subject_validation = _function(
        binding_tree,
        "release_execution_review_subject_errors",
    )
    alignment = _function(
        binding_tree,
        "release_execution_identity_alignment_errors",
    )
    path_alignment = _function(binding_tree, "release_execution_alignment_errors")
    if (
        identity is None
        or opaque_reference is None
        or selector_validation is None
        or reviewed_at is None
        or review_subject is None
        or review_subject_validation is None
        or alignment is None
        or path_alignment is None
    ):
        errors.append("release execution identity alignment contract is missing")
    else:
        opaque_doc = ast.get_docstring(opaque_reference) or ""
        if (
            "only" not in opaque_doc.casefold()
            or "never worm semantics" not in opaque_doc.casefold()
        ):
            errors.append("release execution storage reference must remain explicitly opaque")
        if not any(
            isinstance(node, ast.Call)
            and _call_name(node) == "_opaque_execution_reference"
            and _contains_string(node, "evidence_object_reference")
            for node in ast.walk(selector_validation)
        ):
            errors.append("release execution selector must use the opaque storage validator")
        if not any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and _contains_string(node, "sha256")
            and _contains_string(node, "evidence_sha256")
            for node in ast.walk(reviewed_at)
        ):
            errors.append("ledger review time must select the exact ledger digest")
        if not (
            any(
                isinstance(node, ast.Call)
                and _call_name(node) == "release_execution_review_subject"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "selector"
                for node in ast.walk(reviewed_at)
            )
            and _has_item_get_compare(
                reviewed_at,
                "release_execution_review_subject",
                ast.Eq,
                "expected_subject",
            )
            and all(
                _contains_string(review_subject, field)
                for field in (
                    "kind",
                    "selector",
                    "ledger_type",
                    "evidence_object_reference",
                    "evidence_sha256",
                    "target_intake",
                )
            )
            and any(
                isinstance(node, ast.Call)
                and _call_name(node) == "selector_errors"
                and _contains_string(node, "selector")
                for node in ast.walk(review_subject_validation)
            )
        ):
            errors.append("ledger review must bind the exact full release selector")
        if not any(
            isinstance(node, ast.Call)
            and _call_name(node) == "_reviewer_reference"
            and _contains_string(node, "reviewed_by")
            for node in ast.walk(reviewed_at)
        ):
            errors.append("ledger review time must carry an opaque reviewer reference")
        projection = _dict_projection(identity)
        if not all(
            _is_evidence_field(projection.get(field), field)
            for field in ("started_at", "finished_at")
        ):
            errors.append("release execution identity must preserve exact start and finish")
        ordering_arguments = {
            "release_reviewed_at",
            "consumer_started_at",
        }
        if not _requires_kwonly(alignment, ordering_arguments) or not all(
            (
                _has_compare(alignment, "consumer_started", ast.Lt, "finished_at"),
                _has_compare(alignment, "reviewed_at", ast.Lt, "finished_at"),
                _has_compare(alignment, "consumer_started", ast.Lt, "reviewed_at"),
            )
        ):
            errors.append("release review and consumer start ordering is incomplete")
        forwarded = [
            node
            for node in ast.walk(path_alignment)
            if isinstance(node, ast.Call)
            and _call_name(node) == "release_execution_identity_alignment_errors"
        ]
        if not _requires_kwonly(path_alignment, ordering_arguments) or not (
            len(forwarded) == 1
            and isinstance(
                _keyword_value(forwarded[0], "release_reviewed_at"),
                ast.Name,
            )
            and _keyword_value(forwarded[0], "release_reviewed_at").id
            == "release_reviewed_at"
            and isinstance(
                _keyword_value(forwarded[0], "consumer_started_at"),
                ast.Name,
            )
            and _keyword_value(forwarded[0], "consumer_started_at").id
            == "consumer_started_at"
        ):
            errors.append("path-based release alignment must require and forward ordering")

    artifact_errors = _function(intake_tree, "_artifact_errors")
    create_manifest = _function(intake_tree, "create_intake_manifest")
    selector_alignment = _function(
        intake_tree,
        "_release_execution_consumer_selector_errors",
    )
    intake_errors = _function(intake_tree, "intake_errors")
    if (
        artifact_errors is None
        or create_manifest is None
        or selector_alignment is None
        or intake_errors is None
    ):
        errors.append("strict intake causality contract is missing")
        return errors
    if not _has_release_boundary_output(intake_tree):
        errors.append(
            "strict intake must report the release-review and storage trust boundaries"
        )
    main_function = _function(intake_tree, "main")
    final_bytes = _function(intake_tree, "_final_manifest_bytes")
    if main_function is None or final_bytes is None:
        errors.append("final target-intake custody contract is missing")
    else:
        finalize_branch = _command_branch(main_function, "finalize")
        main_calls = {
            _call_name(node)
            for node in ast.walk(finalize_branch)
            if isinstance(node, ast.Call)
        }
        if finalize_branch is None or not {
            "prepare_write_once_file",
            "write_fsynced_temporary_bytes",
            "publish_write_once_file",
            "_load_unique_json_with_bytes_and_metadata",
            "create_finalization_receipt",
            "load_finalization_acceptance",
            "recheck_finalization_acceptance",
        }.issubset(main_calls) or not _contains_string(main_function, "finalize"):
            errors.append("final target-intake publication must be fsynced and no-replace")
        final_acceptance_loads = [
            node
            for node in ast.walk(main_function)
            if isinstance(node, ast.Call)
            and _call_name(node) == "load_finalization_acceptance"
        ]
        if not (
            len(final_acceptance_loads) >= 2
            and any(
                all(
                    (
                        _contains_name(_keyword_value(call, keyword), expected_name)
                        or (
                            isinstance(_keyword_value(call, keyword), ast.Attribute)
                            and _keyword_value(call, keyword).attr == expected_name
                        )
                    )
                    for keyword, expected_name in (
                        ("expected_receipt_payload_sha256", "expected_finalization_receipt_payload_sha256"),
                        ("expected_receipt_file_sha256", "expected_finalization_receipt_file_sha256"),
                        ("expected_manifest_payload_sha256", "expected_payload_sha256"),
                        ("expected_manifest_file_sha256", "expected_file_sha256"),
                    )
                )
                for call in final_acceptance_loads
            )
        ):
            errors.append(
                "final strict intake must require manifest and finalization receipt caller pins"
            )
        if not _has_final_manifest_boundary_output(intake_tree):
            errors.append("final strict intake must report manifest custody boundaries")
    parser_function = _function(intake_tree, "_parser")
    registration = _function(generation_tree, "manifest_registration_item_id")
    receipt_validation = _function(generation_tree, "receipt_errors")
    receipt_selector = _function(generation_tree, "_receipt_selector")
    genesis_creator = _function(generation_tree, "create_genesis_receipt")
    registration_creator = _function(
        generation_tree,
        "create_registration_receipt",
    )
    lineage_loader = _function(generation_tree, "load_generation_lineage")
    lineage_recheck = _function(generation_tree, "recheck_generation_lineage")
    generation_semantic_replay = _function(
        intake_tree, "_generation_semantic_replay_errors"
    )
    init_branch = (
        _command_branch(main_function, "init") if main_function is not None else None
    )
    register_branch = (
        _command_branch(main_function, "register") if main_function is not None else None
    )
    verify_generation_branch = (
        _command_branch(main_function, "verify-generation-lineage")
        if main_function is not None
        else None
    )
    if (
        parser_function is None
        or registration is None
        or receipt_validation is None
        or receipt_selector is None
        or genesis_creator is None
        or registration_creator is None
        or lineage_loader is None
        or lineage_recheck is None
        or generation_semantic_replay is None
        or init_branch is None
        or register_branch is None
        or verify_generation_branch is None
    ):
        errors.append("immutable authoring generation registration contract is missing")
    else:
        if not (
            _contains_name(receipt_validation, "RECEIPT_KIND")
            and _contains_string(receipt_validation, "receipt_path")
            and _contains_string(genesis_creator, "receipt_path")
            and _contains_string(registration_creator, "receipt_path")
            and "target_intake_generation_receipt_v3" in (generation_source or "")
            and 'document.get("schema_version") != 3'
            in (generation_source or "")
            and (generation_source or "").count('"schema_version": 3') == 2
            and _contains_string(receipt_validation, "validation_context")
            and _contains_string(receipt_validation, "evaluated_at")
            and _contains_string(receipt_validation, "requirements")
            and _contains_string(receipt_validation, "phase_acceptance_matrix")
            and (generation_source or "").count(
                '"receipt_path": os.path.abspath(receipt_path)'
            )
            == 2
            and (generation_source or "").count(
                'receipt.get("receipt_path")'
            )
            >= 2
            and 'os.path.abspath(path) != receipt.get("receipt_path")'
            in (generation_source or "")
            and 'os.path.abspath(current_receipt_path)\n                != receipt.get("receipt_path")'
            in (generation_source or "")
            and _contains_name(genesis_creator, "receipt_errors")
        ):
            errors.append(
                "generation receipts must use closed schema-v3 self-bound validation contexts"
            )
        semantic_calls = {
            _call_name(node)
            for node in ast.walk(generation_semantic_replay)
            if isinstance(node, ast.Call)
        }
        if not (
            "parse_unique_json_bytes" in semantic_calls
            and "requirements_errors" in semantic_calls
            and "intake_errors" in semantic_calls
            and "compare_digest" in semantic_calls
            and _contains_string(generation_semantic_replay, "evaluated_at")
            and _contains_string(generation_semantic_replay, "validation_context")
            and _contains_name(generation_semantic_replay, "snapshots")
        ):
            errors.append(
                "generation history must replay every receipt-bound semantic context"
            )
        required_options = {
            "--input",
            "--input-receipt",
            "--candidate",
            "--output",
            "--receipt-output",
            "--expected-input-manifest-payload-sha256",
            "--expected-input-manifest-file-sha256",
            "--expected-input-receipt-payload-sha256",
            "--expected-input-receipt-file-sha256",
        }
        if not _contains_string(parser_function, "register") or not all(
            _required_parser_argument(parser_function, "register", option)
            for option in required_options
        ):
            errors.append("authoring generation registration must require base pins and paths")
        changed_len_guard = any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)
            and isinstance(node.left, ast.Call)
            and _call_name(node.left) == "len"
            and _contains_name(node.left, "changed")
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == 1
            for node in ast.walk(registration)
        )
        exact_change_guard = any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)
            and _contains_name(node, "before")
            and _contains_name(node, "after")
            for node in ast.walk(registration)
        )
        top_level_guard = any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)
            and _contains_name(node, "base")
            and _contains_name(node, "candidate")
            and _contains_name(node, "key")
            for node in ast.walk(registration)
        )
        missing_metadata_guard = any(
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.IsNot)
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value is None
            and _contains_name(node, "before")
            and _contains_name(node, "key")
            for node in ast.walk(registration)
        )
        if not (
            changed_len_guard
            and exact_change_guard
            and top_level_guard
            and missing_metadata_guard
            and _contains_name(registration, "REQUIRED_IDS")
            and _contains_string(registration, "missing")
            and _contains_string(registration, "provided")
            and _contains_string(registration, "items")
            and _contains_string(registration, "id")
            and _contains_string(registration, "status")
        ):
            errors.append("authoring generation must change exactly one missing item to provided")
        register_calls = [
            _call_name(node)
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
        ]
        single_link_rechecks = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_recheck_stable_bytes"
            and isinstance(_keyword_value(node, "require_single_link"), ast.Constant)
            and _keyword_value(node, "require_single_link").value is True
        ]
        artifact_digest_checks = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "compare_digest"
            and _contains_name(node, "artifact_raw")
            and _contains_string(node, "sha256")
        ]
        output_claims = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "prepare_write_once_file"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Attribute)
            and node.args[0].attr == "output"
        ]
        candidate_validations = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "intake_errors"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "candidate"
            and isinstance(_keyword_value(node, "require_complete"), ast.Constant)
            and _keyword_value(node, "require_complete").value is False
        ]
        candidate_publications = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_final_manifest_bytes"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "candidate"
        ]
        if not (
            register_calls.count("load_generation_lineage") == 1
            and register_calls.count("intake_errors") >= 2
            and register_calls.count("_read_stable_bytes_with_metadata") >= 3
            and len(single_link_rechecks) >= 6
            and len(artifact_digest_checks) >= 1
            and len(output_claims) == 1
            and len(candidate_validations) == 1
            and len(candidate_publications) == 1
            and {
                "prepare_write_once_file",
                "write_fsynced_temporary_bytes",
                "publish_write_once_file",
                "create_registration_receipt",
                "receipt_bytes",
                "recheck_generation_lineage",
            }.issubset(register_calls)
        ):
            errors.append(
                "authoring generation must pin, validate, recheck and publish without replace"
            )
        if not all(
            _contains_marker(register_branch, marker)
            for marker in AUTHORING_GENERATION_BOUNDARY_MARKERS
        ) or sum(
            1
            for node in ast.walk(intake_tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "authoring-latest-head=unverified" in node.value
        ) < 2:
            errors.append("authoring generation trust boundaries must remain unverified")
        lineage_calls = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "load_generation_lineage"
        ]
        if not (
            len(lineage_calls) == 1
            and all(
                isinstance(_keyword_value(lineage_calls[0], keyword), ast.Attribute)
                for keyword in (
                    "expected_receipt_payload_sha256",
                    "expected_receipt_file_sha256",
                    "expected_manifest_payload_sha256",
                    "expected_manifest_file_sha256",
                )
            )
            and _contains_marker(register_branch, "orphaned-unaccepted")
            and _contains_marker(register_branch, "commit-state=unknown")
            and all(
                sum(
                    1
                    for node in ast.walk(intake_tree)
                    if isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and marker in node.value
                )
                >= 4
                for marker in ("orphaned-unaccepted", "commit-state=unknown")
            )
        ):
            errors.append("authoring receipt must pin lineage and separate orphan/unknown states")
        init_calls = [
            _call_name(node)
            for node in ast.walk(init_branch)
            if isinstance(node, ast.Call)
        ]
        init_single_link_rechecks = [
            node
            for node in ast.walk(init_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "_recheck_stable_bytes"
            and isinstance(_keyword_value(node, "require_single_link"), ast.Constant)
            and _keyword_value(node, "require_single_link").value is True
        ]
        registration_receipt_calls = [
            node
            for node in ast.walk(register_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "create_registration_receipt"
        ]
        genesis_receipt_calls = [
            node
            for node in ast.walk(init_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "create_genesis_receipt"
        ]
        if not (
            init_calls.count("publish_write_once_file") == 2
            and init_calls.count("_read_stable_bytes_with_metadata") >= 2
            and len(init_single_link_rechecks) == 2
            and len(genesis_receipt_calls) == 1
            and len(genesis_receipt_calls[0].args) >= 2
            and isinstance(genesis_receipt_calls[0].args[1], ast.Attribute)
            and genesis_receipt_calls[0].args[1].attr == "receipt_output"
            and len(registration_receipt_calls) == 1
            and isinstance(
                _keyword_value(registration_receipt_calls[0], "receipt_path"),
                ast.Attribute,
            )
            and _keyword_value(
                registration_receipt_calls[0],
                "receipt_path",
            ).attr
            == "receipt_output"
            and all(
                _contains_marker(branch, marker)
                for branch in (init_branch, register_branch)
                for marker in (
                    "manifest_payload_sha256=",
                    "manifest_file_sha256=",
                    "receipt_payload_sha256=",
                    "receipt_file_sha256=",
                )
            )
            and all(
                _contains_marker(branch, "verify-generation-lineage-required")
                for branch in (init_branch, register_branch)
            )
        ):
            errors.append(
                "generation acceptance must bind receipt outputs, recheck genesis and expose recovery pins"
            )
        verify_generation_required = {
            "--manifest",
            "--receipt",
            "--expected-manifest-payload-sha256",
            "--expected-manifest-file-sha256",
            "--expected-receipt-payload-sha256",
            "--expected-receipt-file-sha256",
        }
        verify_generation_calls = {
            _call_name(node)
            for node in ast.walk(verify_generation_branch)
            if isinstance(node, ast.Call)
        }
        verify_generation_loads = [
            node
            for node in ast.walk(verify_generation_branch)
            if isinstance(node, ast.Call)
            and _call_name(node) == "load_generation_lineage"
        ]
        if not (
            _has_parser_command(
                parser_function,
                "verify_generation_lineage",
                "verify-generation-lineage",
            )
            and all(
                _required_parser_argument(
                    parser_function,
                    "verify_generation_lineage",
                    option,
                )
                for option in verify_generation_required
            )
            and len(verify_generation_loads) == 1
            and all(
                isinstance(
                    _keyword_value(verify_generation_loads[0], keyword),
                    ast.Attribute,
                )
                for keyword in (
                    "expected_receipt_payload_sha256",
                    "expected_receipt_file_sha256",
                    "expected_manifest_payload_sha256",
                    "expected_manifest_file_sha256",
                )
            )
            and "recheck_generation_lineage" in verify_generation_calls
            and "_generation_semantic_replay_errors" in verify_generation_calls
            and not {
                "prepare_write_once_file",
                "write_fsynced_temporary_bytes",
                "publish_write_once_file",
                "discard_claimed_temporary_file",
                "unlink",
                "replace",
            }.intersection(verify_generation_calls)
            and all(
                _contains_marker(verify_generation_branch, marker)
                for marker in (
                    "production_acceptance=false",
                    "generation-receipt-locator=self-bound-v3",
                    "generation-history-semantic-replay=every-generation",
                    "generation-receipt-evaluation-time=recorded-host-utc",
                    "authoring-validation-context-authority=unverified",
                    "authoring-trusted-time=unverified",
                    "authoring-validator-version=unverified",
                    "recovery=read-only-local-revalidation",
                    "authoring-receipt-authority=unverified",
                    "authoring-pin-authority=unverified",
                    "authoring-latest-head=unverified",
                    "authoring-generation-fork-protection=unverified",
                    "authoring-rollback-protection=unverified",
                    "authoring-locator-continuity=unverified",
                    "authoring-parent-directory-race-protection=unverified",
                    "authoring-publication-crash-durability=unverified",
                    "authoring-post-verification-custody=unverified",
                )
            )
        ):
            errors.append(
                "generation recovery must be four-pin read-only local lineage revalidation"
            )
        if not (
            _contains_string(receipt_validation, "predecessor")
            and _contains_string(receipt_validation, "registered_item")
            and _contains_string(receipt_validation, "sequence")
            and all(
                any(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == seen_name
                    for node in ast.walk(lineage_loader)
                )
                for seen_name in ("seen_manifests", "seen_receipts")
            )
            and _contains_name(lineage_loader, "manifest_registration_item_id")
            and _contains_name(lineage_loader, "recheck_generation_lineage")
            and any(
                isinstance(node, ast.Call)
                and isinstance(
                    _keyword_value(node, "require_single_link"), ast.Constant
                )
                and _keyword_value(node, "require_single_link").value is True
                for node in ast.walk(lineage_recheck)
            )
        ):
            errors.append("generation receipt lineage must be closed, replayed and rechecked")
        downstream_required = {
            "--input-receipt",
            "--expected-input-receipt-payload-sha256",
            "--expected-input-receipt-file-sha256",
        }
        if not all(
            _required_parser_argument(parser_function, command, option)
            for command in ("snapshot", "finalize")
            for option in downstream_required
        ) or not all(
            _contains_string(parser_function, option)
            for option in downstream_required
        ):
            errors.append("snapshot/finalize/progress must select a terminal receipt")
        lineage_consumers = [
            node
            for node in ast.walk(main_function)
            if isinstance(node, ast.Call)
            and _call_name(node) == "load_generation_lineage"
        ]
        if not (
            len(lineage_consumers) == 5
            and _contains_marker(
                main_function,
                "caller-pinned terminal generation receipt is required",
            )
            and _contains_marker(
                main_function,
                "selected-lineage=caller-pinned-local-receipt-chain-validated",
            )
        ):
            errors.append("all non-final generation consumers must validate lineage")
    snapshot_validation = _function(acceptance_tree, "snapshot_receipt_errors")
    finalization_validation = _function(
        acceptance_tree,
        "finalization_receipt_errors",
    )
    snapshot_loader = _function(acceptance_tree, "load_snapshot_acceptance")
    finalization_loader = _function(
        acceptance_tree,
        "load_finalization_acceptance",
    )
    snapshot_creator = _function(
        acceptance_tree,
        "create_snapshot_receipt",
    )
    finalization_creator = _function(
        acceptance_tree,
        "create_finalization_receipt",
    )
    snapshot_recheck = _function(
        acceptance_tree,
        "recheck_snapshot_acceptance",
    )
    finalization_recheck = _function(
        acceptance_tree,
        "recheck_finalization_acceptance",
    )
    ancestry = _function(generation_tree, "generation_lineage_contains")
    snapshot_identity = _function(
        intake_tree,
        "_snapshot_acceptance_identity_errors",
    )
    finalization_identity = _function(
        intake_tree,
        "_finalization_acceptance_identity_errors",
    )
    snapshot_branch = (
        _command_branch(main_function, "snapshot")
        if main_function is not None
        else None
    )
    verify_receipt_branch = (
        _command_branch(main_function, "verify-receipt")
        if main_function is not None
        else None
    )
    if any(
        value is None
        for value in (
            snapshot_validation,
            finalization_validation,
            snapshot_loader,
            finalization_loader,
            snapshot_creator,
            finalization_creator,
            snapshot_recheck,
            finalization_recheck,
            ancestry,
            snapshot_identity,
            finalization_identity,
            snapshot_branch,
            verify_receipt_branch,
            finalize_branch if main_function is not None else None,
        )
    ):
        errors.append("snapshot/finalization acceptance receipt contract is missing")
    else:
        if not (
            _contains_name(snapshot_validation, "SNAPSHOT_RECEIPT_KIND")
            and _contains_string(snapshot_validation, "result_checkpoint")
            and _contains_string(snapshot_validation, "source_generation")
            and _contains_string(snapshot_validation, "evaluated_at")
            and _contains_string(snapshot_validation, "valid_from")
            and _contains_string(snapshot_validation, "valid_until")
            and _contains_string(snapshot_validation, "receipt_path")
            and _contains_name(finalization_validation, "FINALIZATION_RECEIPT_KIND")
            and _contains_string(finalization_validation, "phase0_snapshot")
            and _contains_string(finalization_validation, "result_final_manifest")
            and _contains_string(finalization_validation, "source_generation")
            and _contains_string(finalization_validation, "receipt_path")
            and _contains_string(finalization_validation, "evaluated_at")
            and "target_intake_phase0_snapshot_receipt_v2"
            in (acceptance_source or "")
            and "target_intake_finalization_receipt_v2"
            in (acceptance_source or "")
            and (acceptance_source or "").count(
                'document.get("schema_version") != 2'
            )
            == 2
            and (acceptance_source or "").count('"schema_version": 2') == 2
            and (acceptance_source or "").count(
                'os.path.abspath(receipt_path) != receipt.get("receipt_path")'
            )
            == 2
            and _contains_string(snapshot_creator, "receipt_path")
            and _contains_string(finalization_creator, "receipt_path")
            and _contains_string(finalization_creator, "evaluated_at")
        ):
            errors.append(
                "acceptance receipts must use closed typed self-bound selectors"
            )
        acceptance_functions = (
            snapshot_loader,
            finalization_loader,
            snapshot_recheck,
            finalization_recheck,
        )
        if not (
            all(
                _contains_name(function, "recheck_stable_bytes")
                or _contains_name(function, "recheck_snapshot_acceptance")
                or _contains_name(function, "recheck_finalization_acceptance")
                for function in acceptance_functions
            )
            and _contains_name(snapshot_loader, "load_generation_lineage")
            and _contains_name(finalization_loader, "load_generation_lineage")
            and _contains_name(finalization_loader, "load_snapshot_acceptance")
            and _contains_name(finalization_loader, "generation_lineage_contains")
            and _contains_name(finalization_creator, "generation_lineage_contains")
            and _contains_name(ancestry, "parse_unique_json_bytes")
            and _contains_name(snapshot_identity, "_load_validated_phase_checkpoint")
            and _contains_string(snapshot_identity, "evaluated_at")
            and _contains_string(snapshot_identity, "valid_from")
            and _contains_string(snapshot_identity, "valid_until")
            and _contains_name(finalization_identity, "_parse_utc")
            and _contains_name(finalization_identity, "intake_errors")
            and _contains_string(finalization_identity, "evaluated_at")
            and _contains_string(finalization_identity, "phase0_snapshot")
            and sum(
                1
                for node in ast.walk(main_function)
                if isinstance(node, ast.Call)
                and _call_name(node)
                == "_finalization_acceptance_identity_errors"
            )
            == 2
            and all(
                any(
                    isinstance(node, ast.Call)
                    and isinstance(
                        _keyword_value(node, "require_single_link"),
                        ast.Constant,
                    )
                    and _keyword_value(node, "require_single_link").value is True
                    for node in ast.walk(function)
                )
                for function in (snapshot_recheck, finalization_recheck)
            )
        ):
            errors.append("acceptance receipt lineage must be replayed and rechecked")
        snapshot_calls = [
            _call_name(node)
            for node in ast.walk(snapshot_branch)
            if isinstance(node, ast.Call)
        ]
        finalize_calls = [
            _call_name(node)
            for node in ast.walk(finalize_branch)
            if isinstance(node, ast.Call)
        ]
        if not (
            snapshot_calls.count("publish_write_once_file") == 2
            and {
                "create_snapshot_receipt",
                "load_snapshot_acceptance",
                "recheck_snapshot_acceptance",
            }.issubset(snapshot_calls)
            and finalize_calls.count("publish_write_once_file") == 2
            and {
                "load_snapshot_acceptance",
                "create_finalization_receipt",
                "load_finalization_acceptance",
                "recheck_finalization_acceptance",
            }.issubset(finalize_calls)
            and sum(
                1
                for node in ast.walk(main_function)
                if isinstance(node, ast.Call)
                and _call_name(node) == "_snapshot_acceptance_identity_errors"
            )
            == 4
            and all(
                _contains_marker(main_function, marker)
                for marker in (
                    "target-intake-snapshot-orphaned-unaccepted",
                    "target-intake-snapshot-commit-state=unknown",
                    "target-intake-final-orphaned-unaccepted",
                    "target-intake-finalization-commit-state=unknown",
                )
            )
        ):
            errors.append("acceptance receipts must be the write-once commit points")
        snapshot_required = {"--receipt-output"}
        finalize_required = {
            "--receipt-output",
            "--phase0-checkpoint-receipt",
            "--expected-phase0-checkpoint-receipt-payload-sha256",
            "--expected-phase0-checkpoint-receipt-file-sha256",
        }
        final_strict_options = {
            "--finalization-receipt",
            "--expected-finalization-receipt-payload-sha256",
            "--expected-finalization-receipt-file-sha256",
        }
        verify_receipt_required = {
            "--kind",
            "--manifest",
            "--receipt",
            "--expected-manifest-payload-sha256",
            "--expected-manifest-file-sha256",
            "--expected-receipt-payload-sha256",
            "--expected-receipt-file-sha256",
        }
        verify_receipt_calls = {
            _call_name(node)
            for node in ast.walk(verify_receipt_branch)
            if isinstance(node, ast.Call)
        }
        if not (
            _has_parser_command(
                parser_function,
                "verify_receipt",
                "verify-receipt",
            )
            and all(
                _required_parser_argument(
                    parser_function,
                    "verify_receipt",
                    option,
                )
                for option in verify_receipt_required
            )
            and {
                "load_snapshot_acceptance",
                "recheck_snapshot_acceptance",
                "load_finalization_acceptance",
                "recheck_finalization_acceptance",
                "_snapshot_acceptance_identity_errors",
                "_finalization_acceptance_identity_errors",
            }.issubset(verify_receipt_calls)
            and not {
                "prepare_write_once_file",
                "write_fsynced_temporary_bytes",
                "publish_write_once_file",
            }.intersection(verify_receipt_calls)
            and all(
                _contains_marker(verify_receipt_branch, marker)
                for marker in (
                    "recovery=read-only-local-revalidation",
                    "receipt-locator=self-bound-v2",
                    "receipt-authority=unverified",
                    "trusted-time=unverified",
                    "rollback-protection=unverified",
                    "locator-continuity=unverified",
                    "parent-directory-race-protection=unverified",
                    "publication-crash-durability=unverified",
                    "post-verification-custody=unverified",
                    "production_acceptance=false",
                )
            )
        ):
            errors.append(
                "acceptance receipt recovery must be pinned read-only local revalidation"
            )
        if not (
            all(
                _required_parser_argument(parser_function, "snapshot", option)
                for option in snapshot_required
            )
            and all(
                _required_parser_argument(parser_function, "finalize", option)
                for option in finalize_required
            )
            and all(
                _contains_string(parser_function, option)
                for option in final_strict_options
            )
            and _contains_marker(
                main_function,
                "finalization receipt pins are only valid for final strict preflight",
            )
            and all(
                _contains_marker(main_function, marker)
                for marker in ACCEPTANCE_BOUNDARY_MARKERS
            )
            and all(
                _contains_marker(branch, marker)
                for branch in (snapshot_branch, finalize_branch)
                for marker in (
                    "manifest_payload_sha256=",
                    "manifest_file_sha256=",
                    "receipt_payload_sha256=",
                    "receipt_file_sha256=",
                )
            )
            and sum(
                1
                for node in ast.walk(main_function)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "finalization-receipt-authority=unverified" in node.value
            )
            >= 2
        ):
            errors.append("downstream intake must caller-pin acceptance receipts")
    if not (
        _has_dict_constant(create_manifest, "schema_version", 2)
        and _contains_string(create_manifest, "release_execution_review_subject")
        and _contains_string(create_manifest, "release_execution_evidence")
        and _contains_string(intake_errors, "schema_version")
        and _contains_string(intake_errors, "release_execution_review_subject")
        and any(
            isinstance(node, ast.Call)
            and _call_name(node) == "release_execution_review_subject_errors"
            for node in ast.walk(artifact_errors)
        )
    ):
        errors.append("strict intake schema v2 must carry one closed release review subject")
    if not _has_compare(
        artifact_errors,
        "reviewed_at",
        ast.Lt,
        "finished_at",
    ) or not _has_compare(
        artifact_errors,
        "reviewed_at",
        ast.Gt,
        "evaluated_at",
    ):
        errors.append("ledger selection review must follow finish and precede evaluation")

    if not _has_compare(selector_alignment, "selector", ast.NotEq, "baseline"):
        errors.append("strict intake must reject conflicting release selector claims")
    if not (
        _requires_kwonly(selector_alignment, {"review_subject"})
        and _has_compare(
            selector_alignment,
            "review_subject",
            ast.NotEq,
            "expected_subject",
        )
    ):
        errors.append("strict intake must match the release review subject to consumers")
    selector_alignment_calls = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call)
        and _call_name(node) == "_release_execution_consumer_selector_errors"
    ]
    if not (
        len(selector_alignment_calls) == 1
        and len(selector_alignment_calls[0].args) == 1
        and isinstance(selector_alignment_calls[0].args[0], ast.Name)
        and selector_alignment_calls[0].args[0].id == "release_execution_consumers"
        and isinstance(
            _keyword_value(selector_alignment_calls[0], "review_subject"),
            ast.Name,
        )
        and _keyword_value(selector_alignment_calls[0], "review_subject").id
        == "release_review_subject"
    ):
        errors.append("strict intake must compare all release consumer selectors once")
    collector_assignments = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "release_execution_consumers"
            for target in node.targets
        )
    ]
    collector_extensions = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "extend"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "release_execution_consumers"
    ]
    required_selector_consumers = {
        "sub2_evidence",
        "vault_egress_evidence",
        "phase6_pilot_evidence",
        "phase6_operations_evidence",
    }
    if not (
        len(collector_assignments) == 1
        and _contains_name(collector_assignments[0], "target_phase_artifacts")
        and _contains_string(collector_assignments[0], "windows_pilot_inputs")
        and len(collector_extensions) == 1
        and all(
            _contains_name(collector_extensions[0], consumer)
            for consumer in required_selector_consumers
        )
    ):
        errors.append("strict intake release selector consumer inventory is incomplete")

    consumer_calls = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call)
        and _call_name(node) == "release_execution_identity_alignment_errors"
    ]
    if not (
        len(consumer_calls) == 5
        and all(
            _review_call_is_selector_bound(
                _keyword_value(call, "release_reviewed_at")
            )
            and _contains_string(
                _keyword_value(call, "consumer_started_at"), "started_at"
            )
            for call in consumer_calls
        )
    ):
        errors.append("all Phase 1-6 release consumers must pass their window start")

    replay_calls = [
        node
        for node in ast.walk(intake_errors)
        if isinstance(node, ast.Call) and _call_name(node) == "contains_release_start"
    ]
    if not (
        len(replay_calls) == 1
        and len(replay_calls[0].args) == 1
        and _contains_string(replay_calls[0].args[0], "started_at")
    ):
        errors.append("final strict intake must replay ledger start against Phase 0")

    for name, source in (consumer_sources or {}).items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            errors.append(f"{name} is not valid Python")
            continue
        if not _has_release_boundary_output(tree):
            errors.append(
                f"{name} must report the release-review and storage trust boundaries"
            )
        errors.extend(_intake_consumer_errors(name, source, tree))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _call_name(node) == "release_execution_alignment_errors"
        ]
        if not (
            len(calls) == 1
            and _review_call_is_selector_bound(
                _keyword_value(calls[0], "release_reviewed_at")
            )
            and _contains_string(
                _keyword_value(calls[0], "consumer_started_at"),
                "started_at",
            )
        ):
            errors.append(f"{name} must pass its execution-window start")
    for name, source in (intake_only_sources or {}).items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            errors.append(f"{name} is not valid Python")
            continue
        errors.extend(_intake_consumer_errors(name, source, tree))
    return errors


def main() -> int:
    try:
        binding_source = load_stable_text(BINDING, max_bytes=MAX_SOURCE_BYTES)
        intake_source = load_stable_text(INTAKE, max_bytes=MAX_SOURCE_BYTES)
        generation_source = load_stable_text(
            GENERATION, max_bytes=MAX_SOURCE_BYTES
        )
        acceptance_source = load_stable_text(
            ACCEPTANCE, max_bytes=MAX_SOURCE_BYTES
        )
        intake_manifest_source = load_stable_text(
            INTAKE_MANIFEST, max_bytes=MAX_SOURCE_BYTES
        )
        external_json_source = load_stable_text(
            EXTERNAL_JSON, max_bytes=MAX_SOURCE_BYTES
        )
        consumer_sources = {
            name: load_stable_text(path, max_bytes=MAX_SOURCE_BYTES)
            for name, path in CONSUMERS.items()
        }
        intake_only_sources = {
            name: load_stable_text(path, max_bytes=MAX_SOURCE_BYTES)
            for name, path in INTAKE_ONLY_CONSUMERS.items()
        }
    except (OSError, UnicodeError, ValueError):
        print("release execution causality assets cannot be read", file=sys.stderr)
        return 1
    errors = causality_errors(
        binding_source,
        intake_source,
        consumer_sources,
        intake_manifest_source,
        intake_only_sources,
        external_json_source,
        generation_source,
        acceptance_source,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "release-execution-causality-ok "
        "start-replay=final-strict-intake review-consumer-order=locked "
        "release-review-selector-subject=manifest-exact "
        "release-review-claim=opaque authentication=unverified "
        "trusted-time=unverified replay-protection=unverified "
        "release-storage-reference=opaque provider-native=unverified "
        "retention=unverified delete-denial=unverified readback=unverified "
        "namespace-authority=unverified version-identity=unverified "
        "cross-manifest-rebinding=unverified "
        "final-manifest-publication=local-no-replace-readback "
        "final-manifest-caller-pin=payload-and-file "
        "final-manifest-custody=unverified pin-authority=unverified "
        "rollback-protection=unverified "
        "authoring-publication=local-no-replace-readback "
        "generation-receipt-locator=self-bound-v3 "
        "generation-history-semantic-replay=every-generation "
        "generation-receipt-evaluation-time=recorded-host-utc "
        "authoring-validation-context-authority=unverified "
        "authoring-trusted-time=unverified "
        "authoring-validator-version=unverified "
        "authoring-generation-fork-protection=unverified "
        "authoring-latest-head=unverified authoring-pin-authority=unverified "
        "authoring-receipt-authority=unverified "
        "authoring-receipt-recovery=read-only-local-revalidation "
        "authoring-rollback-protection=unverified "
        "authoring-locator-continuity=unverified "
        "authoring-parent-directory-race-protection=unverified "
        "authoring-publication-crash-durability=unverified "
        "authoring-post-publication-custody=unverified "
        "snapshot-acceptance=write-once-receipt "
        "snapshot-receipt-locator=self-bound-v2 "
        "snapshot-receipt-authority=unverified "
        "snapshot-trusted-time=unverified "
        "snapshot-parent-directory-race-protection=unverified "
        "snapshot-publication-crash-durability=unverified "
        "snapshot-post-publication-custody=unverified "
        "finalization-acceptance=write-once-receipt "
        "finalization-receipt-locator=self-bound-v2 "
        "finalization-receipt-caller-pin=payload-and-file "
        "finalization-receipt-authority=unverified "
        "finalization-parent-directory-race-protection=unverified "
        "finalization-publication-crash-durability=unverified "
        "finalization-post-publication-custody=unverified "
        "acceptance-receipt-recovery=read-only-local-revalidation "
        "acceptance-receipt-rollback-protection=unverified "
        "standalone-intake-manifest-consumers=seven "
        "standalone-intake-manifest-schema=closed-v2-inventory-exact "
        "standalone-intake-manifest-caller-pin=payload-and-file "
        "standalone-intake-artifact-locator=absolute-single-link-stable-rechecked "
        "standalone-intake-manifest-custody=unverified "
        "standalone-intake-manifest-pin-authority=unverified "
        "standalone-intake-manifest-rollback-protection=unverified "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
