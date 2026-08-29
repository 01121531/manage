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
INTAKE_MANIFEST = ROOT / "scripts" / "target_intake_manifest.py"
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
INTAKE_CALLER_BOUNDARY_MARKERS = (
    "intake-manifest-caller-pin=payload-and-file-matched",
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


def _contains_name(node: ast.AST | None, value: str) -> bool:
    return node is not None and any(
        isinstance(item, ast.Name) and item.id == value
        for item in ast.walk(node)
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


def causality_errors(
    binding_source: str,
    intake_source: str,
    consumer_sources: dict[str, str] | None = None,
    intake_manifest_source: str | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        binding_tree = ast.parse(binding_source)
        intake_tree = ast.parse(intake_source)
        manifest_tree = ast.parse(intake_manifest_source or "")
    except SyntaxError:
        return ["release execution causality sources are not valid Python"]

    manifest_loader = _function(manifest_tree, "load_pinned_intake_manifest")
    manifest_shape = _function(manifest_tree, "manifest_shape_errors")
    manifest_canonical = _function(manifest_tree, "canonical_payload_sha256")
    if manifest_loader is None or manifest_shape is None or manifest_canonical is None:
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
        main_calls = {
            _call_name(node)
            for node in ast.walk(main_function)
            if isinstance(node, ast.Call)
        }
        if not {
            "prepare_write_once_file",
            "write_fsynced_temporary_bytes",
            "publish_write_once_file",
            "_read_stable_bytes",
        }.issubset(main_calls) or not _contains_string(main_function, "finalize"):
            errors.append("final target-intake publication must be fsynced and no-replace")
        if not (
            _compare_digest_call(
                main_function,
                "expected_payload_sha256",
                "manifest",
            )
            and _compare_digest_call(
                main_function,
                "expected_file_sha256",
                "manifest_raw",
            )
        ):
            errors.append("final strict intake must require both caller-pinned digests")
        if not _has_final_manifest_boundary_output(intake_tree):
            errors.append("final strict intake must report manifest custody boundaries")
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
        if not all(marker in source for marker in INTAKE_CALLER_BOUNDARY_MARKERS):
            errors.append(f"{name} must report the intake caller-pin trust boundary")
        main_function = _function(tree, "main")
        pinned_calls = [
            node
            for node in ast.walk(main_function) if main_function is not None
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
                and _call_name(node) in {
                    "_load",
                    "load_unique_json",
                    "load_unique_json_with_bytes",
                }
                and _contains_name(node, "arguments")
            ]
            if any(node.lineno < pinned_calls[0].lineno for node in other_reads):
                errors.append(f"{name} must validate intake pins before other evidence reads")
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
    return errors


def main() -> int:
    try:
        binding_source = load_stable_text(BINDING, max_bytes=MAX_SOURCE_BYTES)
        intake_source = load_stable_text(INTAKE, max_bytes=MAX_SOURCE_BYTES)
        intake_manifest_source = load_stable_text(
            INTAKE_MANIFEST, max_bytes=MAX_SOURCE_BYTES
        )
        consumer_sources = {
            name: load_stable_text(path, max_bytes=MAX_SOURCE_BYTES)
            for name, path in CONSUMERS.items()
        }
    except (OSError, UnicodeError, ValueError):
        print("release execution causality assets cannot be read", file=sys.stderr)
        return 1
    errors = causality_errors(
        binding_source,
        intake_source,
        consumer_sources,
        intake_manifest_source,
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
        "standalone-intake-manifest-schema=closed-v2-inventory-exact "
        "standalone-intake-manifest-caller-pin=payload-and-file "
        "standalone-intake-manifest-custody=unverified "
        "standalone-intake-manifest-pin-authority=unverified "
        "standalone-intake-manifest-rollback-protection=unverified "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
