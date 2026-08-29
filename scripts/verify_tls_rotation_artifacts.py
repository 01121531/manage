"""Statically verify TLS rotation profile and assessment artifact boundaries."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.external_json import read_stable_bytes
    from scripts.external_text import load_stable_text
    from scripts.tls_rotation_publisher_policy import (
        TlsRotationPublisherPolicyError,
        parse_publisher_policy,
    )
except ModuleNotFoundError:
    from external_json import read_stable_bytes
    from external_text import load_stable_text
    from tls_rotation_publisher_policy import (
        TlsRotationPublisherPolicyError,
        parse_publisher_policy,
    )


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "scripts" / "tls_rotation_profile.py"
CAPTURE = ROOT / "scripts" / "tls_rotation_profile_capture.py"
LIVE_CAPTURE = ROOT / "scripts" / "tls_rotation_profile_live.py"
KUBECONFIG_INTAKE = ROOT / "scripts" / "kubernetes_kubeconfig_intake.py"
KUBERNETES_BACKEND = ROOT / "scripts" / "kubernetes_tls_rotation_backend.py"
ATTEMPT_RECEIPT = ROOT / "scripts" / "tls_rotation_attempt_receipt.py"
PUBLISHER_POLICY_SOURCE = ROOT / "scripts" / "tls_rotation_publisher_policy.py"
PUBLISHER_POLICY = ROOT / "deploy" / "tls-rotation-attempt-publisher-policy.json"
ASSESSMENT = ROOT / "scripts" / "tls_rotation_assessment.py"
HANDOFF = ROOT / "scripts" / "tls_rotation_handoff.py"
SUPPORT = ROOT / "scripts" / "tls_rotation_support.py"


def _mutation_error(source: str, label: str) -> str | None:
    tree = ast.parse(source)
    forbidden = {
        "act", "contain", "force_recreate_compose_service",
        "restart_kubernetes_deployment", "pause_kubernetes_deployment",
        "ComposeRotationBackend", "KubernetesRotationBackend",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in forbidden)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in forbidden)
        ):
            return f"{label} must not construct or mutate a runtime"
    return None


def validate_sources(
    profile: str,
    assessment: str,
    handoff: str,
    support: str | None = None,
    capture: str | None = None,
    live_capture: str | None = None,
    attempt_receipt: str | None = None,
    kubeconfig_intake: str | None = None,
    kubernetes_backend: str | None = None,
    publisher_policy_source: str | None = None,
    publisher_policy: bytes | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        profile_tree = ast.parse(profile)
        assessment_tree = ast.parse(assessment)
        ast.parse(handoff)
        support_tree = ast.parse(SUPPORT.read_text(encoding="utf-8") if support is None else support)
        capture_source = CAPTURE.read_text(encoding="utf-8") if capture is None else capture
        live_capture_source = LIVE_CAPTURE.read_text(encoding="utf-8") if live_capture is None else live_capture
        receipt_source = ATTEMPT_RECEIPT.read_text(encoding="utf-8") if attempt_receipt is None else attempt_receipt
        intake_source = KUBECONFIG_INTAKE.read_text(encoding="utf-8") if kubeconfig_intake is None else kubeconfig_intake
        backend_source = KUBERNETES_BACKEND.read_text(encoding="utf-8") if kubernetes_backend is None else kubernetes_backend
        policy_source = PUBLISHER_POLICY_SOURCE.read_text(encoding="utf-8") if publisher_policy_source is None else publisher_policy_source
        capture_tree = ast.parse(capture_source)
        ast.parse(live_capture_source)
        receipt_tree = ast.parse(receipt_source)
        intake_tree = ast.parse(intake_source)
        ast.parse(backend_source)
        policy_tree = ast.parse(policy_source)
    except SyntaxError:
        return ["TLS rotation artifact tools are not valid Python"]
    try:
        parse_publisher_policy(
            PUBLISHER_POLICY.read_bytes() if publisher_policy is None else publisher_policy
        )
    except (OSError, TlsRotationPublisherPolicyError):
        errors.append("TLS rotation publisher prerequisite policy is invalid")
    support_source = SUPPORT.read_text(encoding="utf-8") if support is None else support
    for label, source in (
        ("Profile tool", profile), ("Assessment tool", assessment),
        ("Support tool", support_source), ("Capture tool", capture_source),
    ):
        error = _mutation_error(source, label)
        if error:
            errors.append(error)
        if "subprocess" in source or "shell=True" in source:
            errors.append(f"{label} must not start a child process")
    for label, tree in (
        ("Profile tool", profile_tree), ("Assessment tool", assessment_tree),
        ("Support tool", support_tree), ("Capture tool", capture_tree),
    ):
        publishes = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "publish_write_once_file"
        ]
        if len(publishes) != 1:
            errors.append(f"{label} must publish exactly one write-once output")
    for marker in (
        "def review_profile(",
        "def verify_profile(",
        "load_capture_request(request_source)",
        "load_capture(capture_source, request)",
        "reviewed_profile_from_capture(capture)",
        "confirm_live_capture_sha256",
        "with release_control_lock():",
        "discard_claimed_temporary_file(temporary)",
        '"tls-rotation-profile-ok production_acceptance=false "',
    ):
        if marker not in profile:
            errors.append(f"Profile tool is missing {marker}")
    for marker in (
        "def validate_capture_request(",
        "def validate_capture(",
        "def capture_profile(",
        "capture_request_sha256",
        '"production_acceptance": False',
        "with release_control_lock():",
        "publish_write_once_file(temporary, output)",
        "load_capture(output, request)",
    ):
        if marker not in capture_source:
            errors.append(f"Capture tool is missing {marker}")
    for marker in (
        "class ReadOnlyCaptureRunner:",
        "def capture_runtime_profile(",
        "collect_compose_generation(",
        "collect_kubernetes_generation(",
        "def _allowed_kubernetes_get(",
        "_KUBERNETES_SELECTOR.fullmatch(",
        'require_read_only=True',
        'Kubernetes target ReplicaSet identity is ambiguous',
    ):
        if marker not in live_capture_source:
            errors.append(f"Live capture tool is missing {marker}")
    if live_capture_source.count("read_private_secret_bytes(") != 2:
        errors.append("Live capture must perform exactly two private kubeconfig reads")
    if live_capture_source.count("validate_self_contained_kubeconfig(") != 2:
        errors.append("Live capture must validate exactly two kubeconfig snapshots")
    if live_capture_source.count("materialize_private_secret_bytes(") != 1:
        errors.append("Live capture must create exactly one private kubeconfig materialization")
    if live_capture_source.count("materialized.verify()") != 3:
        errors.append("Live capture must bracket both snapshots with materialized identity checks")
    for marker in (
        "materialized.path",
        "with materialize_private_secret_bytes(",
        "Kubernetes kubeconfig materialization failed",
    ):
        if marker not in live_capture_source:
            errors.append(f"Live capture materialization boundary is missing {marker}")
    if backend_source.count("validate_self_contained_kubeconfig(") != 1:
        errors.append("Kubernetes backend must validate one kubeconfig snapshot")
    intake_markers = (
        "def validate_self_contained_kubeconfig(",
        "parse_unique_yaml(text)",
        "MAX_KUBECONFIG_BYTES = 1024 * 1024",
        'config["current-context"] != expected_context',
        'context["namespace"] != expected_namespace',
        'parsed.scheme != "https"',
        "x509.load_pem_x509_certificates(raw)",
        "serialization.load_pem_private_key(key_raw, password=None)",
    )
    for marker in intake_markers:
        if marker not in intake_source:
            errors.append(f"Kubeconfig intake is missing {marker}")
    forbidden_intake_modules = {
        "os", "subprocess", "socket", "requests", "urllib.request",
        "scripts.private_secret_file", "scripts.tls_rotation_runner",
        "scripts.tls_rotation_executor", "scripts.kubernetes_tls_rotation_backend",
    }
    forbidden_intake_calls = {
        "open", "write_bytes", "write_text", "unlink", "link", "replace",
        "rename", "run", "Popen", "read_private_secret_bytes",
    }
    for node in ast.walk(intake_tree):
        if isinstance(node, ast.Import) and any(
            alias.name in forbidden_intake_modules for alias in node.names
        ):
            errors.append("Kubeconfig intake must remain pure")
            break
        if isinstance(node, ast.ImportFrom) and node.module in forbidden_intake_modules:
            errors.append("Kubeconfig intake must remain pure")
            break
        if isinstance(node, ast.Call):
            called = (
                node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute)
                else None
            )
            if called in forbidden_intake_calls:
                errors.append("Kubeconfig intake must remain pure")
                break
    for forbidden in (
        "force_recreate_compose_service(",
        "restart_kubernetes_deployment(",
        "pause_kubernetes_deployment(",
        "compose_probe_command(",
        "kubernetes_probe_command(",
    ):
        if forbidden in live_capture_source:
            errors.append(f"Live capture tool exposes forbidden operation {forbidden}")
    receipt_markers = (
        "class PinnedEd25519TrustAnchor:",
        "def verify_authenticated_attempt(",
        "Ed25519PublicKey.from_public_bytes",
        ".verify(",
        '"normalized_absolute_path"',
        "canonical_signature = base64.urlsafe_b64encode(signature_bytes)",
        'payload["not_committed_eligible"] is not False',
        '"before_ready_receipt": "unknown"',
        '"after_ready_before_link": "unknown"',
        '"during_link": "unknown"',
        '"after_link_before_readback": "unknown"',
        '"after_verified_stable_readback": "committed"',
    )
    for marker in receipt_markers:
        if marker not in receipt_source:
            errors.append(f"Attempt receipt verifier is missing {marker}")
    forbidden_receipt_modules = {
        "os", "subprocess", "scripts.backup_output_policy",
        "scripts.private_secret_file", "scripts.release_control_lock",
        "scripts.tls_rotation_executor", "scripts.tls_rotation_handoff",
        "scripts.compose_tls_rotation_backend", "scripts.kubernetes_tls_rotation_backend",
    }
    forbidden_receipt_calls = {
        "open", "write_bytes", "write_text", "unlink", "link", "replace", "rename",
        "sign", "prepare_write_once_file", "publish_write_once_file",
        "read_stable_bytes", "read_private_secret_bytes",
    }
    for node in ast.walk(receipt_tree):
        if isinstance(node, ast.Import) and any(
            alias.name in forbidden_receipt_modules for alias in node.names
        ):
            errors.append("Attempt receipt verifier must remain pure")
            break
        if isinstance(node, ast.ImportFrom) and node.module in forbidden_receipt_modules:
            errors.append("Attempt receipt verifier must remain pure")
            break
        if isinstance(node, ast.Call):
            called = (
                node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute)
                else None
            )
            if called in forbidden_receipt_calls:
                errors.append("Attempt receipt verifier must remain pure")
                break
    policy_markers = (
        "def parse_publisher_policy(",
        "def validate_publisher_policy(",
        'policy["policy_effect"] != "declaration_only"',
        'policy["publisher_integration_enabled"] is not False',
        'policy["not_committed_eligible"] is not False',
        'ordering["state"] != "not_implemented"',
        'durability["state"] != "unverified"',
        "Ed25519PublicKey.from_public_bytes(raw)",
    )
    for marker in policy_markers:
        if marker not in policy_source:
            errors.append(f"Publisher prerequisite policy verifier is missing {marker}")
    forbidden_policy_modules = forbidden_receipt_modules | {
        "argparse", "scripts.release_control_lock",
    }
    forbidden_policy_calls = forbidden_receipt_calls | {
        "prepare_write_once_file", "acquire", "run",
    }
    for node in ast.walk(policy_tree):
        if isinstance(node, ast.Import) and any(
            alias.name in forbidden_policy_modules for alias in node.names
        ):
            errors.append("Publisher prerequisite policy verifier must remain pure")
            break
        if isinstance(node, ast.ImportFrom) and node.module in forbidden_policy_modules:
            errors.append("Publisher prerequisite policy verifier must remain pure")
            break
        if isinstance(node, ast.Call):
            called = (
                node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute)
                else None
            )
            if called in forbidden_policy_calls:
                errors.append("Publisher prerequisite policy verifier must remain pure")
                break
    for marker in (
        "def generate_assessment(",
        "def verify_assessment(",
        "verify_profile(",
        "load_support(",
        "load_assessment(output, projection, support)",
        "_confirm(projection, confirm_rotation_plan_sha256)",
        "with release_control_lock():",
        "discard_claimed_temporary_file(temporary)",
        '"tls-rotation-assessment-ok production_acceptance=false "',
    ):
        if marker not in assessment:
            errors.append(f"Assessment tool is missing {marker}")
    if assessment.count("_confirm(projection, confirm_rotation_plan_sha256)") != 2:
        errors.append("Assessment generate and verify paths must both confirm the plan")
    for marker in (
        "def derive_runtime_state(",
        "validate_evidence(dict(evidence))",
        "assert_expected_rotation(validated, projection)",
        "def validate_support(",
        "load_support(output, projection, evidence)",
        "publish_write_once_file(temporary, output)",
    ):
        if marker not in support_source:
            errors.append(f"Support tool is missing {marker}")
    for forbidden in (
        'add_argument("--runtime-state"',
        'add_argument("--url"',
        'add_argument("--pod"',
        'add_argument("--kubeconfig"',
        "print(profile",
        "print(assessment",
        "print(options.profile",
        "print(options.assessment",
        "print(options.capture",
    ):
        if forbidden in profile or forbidden in assessment or forbidden in support_source:
            errors.append(f"TLS rotation artifact CLI exposes forbidden data {forbidden}")
    for marker in (
        "verify_profile(",
        "support = load_support(",
        "assessment = load_assessment(",
        "MAX_HANDOFF_DELAY",
    ):
        if marker not in handoff:
            errors.append(f"TLS rotation handoff assessment contract is missing {marker}")
    return errors


def main() -> int:
    try:
        errors = validate_sources(
            load_stable_text(PROFILE, max_bytes=64 * 1024),
            load_stable_text(ASSESSMENT, max_bytes=64 * 1024),
            load_stable_text(HANDOFF, max_bytes=64 * 1024),
            load_stable_text(SUPPORT, max_bytes=64 * 1024),
            load_stable_text(CAPTURE, max_bytes=64 * 1024),
            load_stable_text(LIVE_CAPTURE, max_bytes=64 * 1024),
            load_stable_text(ATTEMPT_RECEIPT, max_bytes=64 * 1024),
            load_stable_text(KUBECONFIG_INTAKE, max_bytes=64 * 1024),
            load_stable_text(KUBERNETES_BACKEND, max_bytes=128 * 1024),
            load_stable_text(PUBLISHER_POLICY_SOURCE, max_bytes=64 * 1024),
            read_stable_bytes(PUBLISHER_POLICY, max_bytes=16 * 1024),
        )
    except (OSError, ValueError):
        print("TLS rotation artifact assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("tls-rotation-artifacts-ok production_acceptance=false derived_support=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
