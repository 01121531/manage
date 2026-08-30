"""Verify the non-secret Vault broker issuer contract and policy bootstrap."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import parse_unique_json_bytes
from scripts.external_text import load_stable_text


VAULT_DIR = ROOT / "infra" / "vault"
CONTRACT = VAULT_DIR / "broker-contract.json"
CONFIGURE = VAULT_DIR / "configure-broker-issuer-policies.sh"
POLICY_DIR = VAULT_DIR / "policies"
MAX_VAULT_BROKER_ASSET_BYTES = 64 * 1024

ROTATION_SEQUENCE = [
    "issue_new_secret_id",
    "exchange_new_token",
    "validate_new_token_contract",
    "atomic_sink_replace",
    "consumer_canary",
    "revoke_old_token_by_accessor",
    "verify_old_token_invalid",
]
TARGET_EVIDENCE = [
    "three_distinct_external_principals",
    "exact_effective_capabilities_by_accessor",
    "cross_service_issuance_denied",
    "single_use_secret_id_consumed",
    "new_token_exact_service_policy_no_default",
    "atomic_sink_replacement",
    "consumer_canary_succeeded",
    "old_token_revoked_by_external_rotator",
    "old_token_rejected",
    "vault_audit_trace_reviewed",
]
SERVICE_DEFINITIONS = (
    ("api", "email-platform-api-cards", "API"),
    ("mail", "email-platform-mail", "MAIL"),
    ("sub2", "email-platform-sub2", "SUB2"),
)
ROOT_KEYS = {
    "schema_version",
    "production_acceptance",
    "auth_method",
    "revocation_actor",
    "rotation_sequence",
    "services",
    "required_target_evidence",
}
SERVICE_KEYS = {
    "service",
    "approle",
    "service_policy",
    "issuer_policy",
    "issuer_policy_file",
    "role_id_path",
    "secret_id_path",
    "token_sink_directory_variable",
    "token_sink_leaf",
    "secret_id_num_uses",
    "secret_id_ttl_seconds",
    "token_ttl_seconds",
    "token_explicit_max_ttl_seconds",
    "positive_capabilities",
    "denied_probe_paths",
}
FORBIDDEN_VALUE_KEYS = {
    "role_id",
    "secret_id",
    "token",
    "token_accessor",
    "secret_id_accessor",
}


def _service_contract(service: str, role: str, environment_label: str) -> dict[str, Any]:
    issuer_policy = f"email-platform-broker-issuer-{service}"
    role_id_path = f"auth/approle/role/{role}/role-id"
    secret_id_path = f"auth/approle/role/{role}/secret-id"
    denied = [f"auth/approle/role/{role}"]
    for _, other_role, _ in SERVICE_DEFINITIONS:
        if other_role != role:
            denied.extend(
                (
                    f"auth/approle/role/{other_role}/role-id",
                    f"auth/approle/role/{other_role}/secret-id",
                )
            )
    denied.extend(
        (
            "auth/token/revoke-accessor",
            "secret/data/cards/canary",
            "secret/data/mailboxes/canary",
            "secret/data/sub2/credential",
            f"sys/policies/acl/{issuer_policy}",
        )
    )
    return {
        "service": service,
        "approle": role,
        "service_policy": role,
        "issuer_policy": issuer_policy,
        "issuer_policy_file": f"{issuer_policy}.hcl",
        "role_id_path": role_id_path,
        "secret_id_path": secret_id_path,
        "token_sink_directory_variable": (
            f"PLATFORM_VAULT_{environment_label}_TOKEN_DIR"
        ),
        "token_sink_leaf": "token",
        "secret_id_num_uses": 1,
        "secret_id_ttl_seconds": 600,
        "token_ttl_seconds": 900,
        "token_explicit_max_ttl_seconds": 3600,
        "positive_capabilities": {
            role_id_path: ["read"],
            secret_id_path: ["update"],
        },
        "denied_probe_paths": denied,
    }


EXPECTED_SERVICES = [
    _service_contract(service, role, environment_label)
    for service, role, environment_label in SERVICE_DEFINITIONS
]
ISSUER_POLICY_NAMES = tuple(
    service["issuer_policy_file"] for service in EXPECTED_SERVICES
)


def _forbidden_value_fields(value: object) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_VALUE_KEYS:
                errors.append(key)
            errors.extend(_forbidden_value_fields(child))
    elif isinstance(value, list):
        for child in value:
            errors.extend(_forbidden_value_fields(child))
    return errors


def _parse_policy(source: str) -> dict[str, set[str]] | None:
    blocks = list(
        re.finditer(
            r'^path\s+"([^"\r\n]+)"\s*\{(?P<body>.*?)^\}',
            source,
            re.MULTILINE | re.DOTALL,
        )
    )
    paths: dict[str, set[str]] = {}
    for block in blocks:
        path = block.group(1)
        body = block.group("body")
        capability = re.fullmatch(
            r'\s*capabilities\s*=\s*\[\s*"([^"\r\n]+)"\s*\]\s*',
            body,
        )
        if capability is None or path in paths:
            return None
        paths[path] = {capability.group(1)}
    remainder = source
    for block in reversed(blocks):
        remainder = remainder[: block.start()] + remainder[block.end() :]
    remainder = "\n".join(
        line for line in remainder.splitlines() if not line.lstrip().startswith("#")
    )
    if remainder.strip():
        return None
    return paths


def broker_contract_errors(
    contract_text: str,
    policies: dict[str, str],
    configure_text: str,
) -> list[str]:
    errors: list[str] = []
    try:
        contract = parse_unique_json_bytes(contract_text.encode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return ["Vault broker contract must be valid JSON"]
    if not isinstance(contract, dict) or set(contract) != ROOT_KEYS:
        errors.append("Vault broker contract root schema must be exact")
        return errors
    if (
        contract.get("schema_version") != 1
        or contract.get("production_acceptance") is not False
        or contract.get("auth_method") != "approle"
        or contract.get("revocation_actor") != "external-approved-rotator"
    ):
        errors.append(
            "Vault broker contract must remain preflight-only AppRole with an external rotator"
        )
    if contract.get("rotation_sequence") != ROTATION_SEQUENCE:
        errors.append("Vault broker rotation sequence must remain fail-closed")
    if contract.get("required_target_evidence") != TARGET_EVIDENCE:
        errors.append("Vault broker target evidence contract must remain exact")
    services = contract.get("services")
    if not isinstance(services, list) or services != EXPECTED_SERVICES:
        errors.append(
            "Vault broker services must exactly bind issuer, AppRole, policy, sink, TTL, and deny probes"
        )
    elif any(not isinstance(service, dict) or set(service) != SERVICE_KEYS for service in services):
        errors.append("Vault broker service schema must remain closed")
    forbidden_fields = sorted(set(_forbidden_value_fields(contract)))
    if forbidden_fields:
        errors.append(
            "Vault broker contract must not contain credential or accessor values: "
            + ", ".join(forbidden_fields)
        )

    expected_policy_names = {
        service["issuer_policy_file"] for service in EXPECTED_SERVICES
    }
    if set(policies) != expected_policy_names:
        errors.append("Vault broker must contain exactly three issuer policy files")
    for service in EXPECTED_SERVICES:
        filename = service["issuer_policy_file"]
        parsed = _parse_policy(policies.get(filename, ""))
        expected = {
            service["role_id_path"]: {"read"},
            service["secret_id_path"]: {"update"},
        }
        if parsed != expected:
            errors.append(
                f"{filename} must only read its RoleID and create its one-use SecretID"
            )

    uncommented = "\n".join(
        line for line in configure_text.splitlines() if not line.lstrip().startswith("#")
    )
    folded = re.sub(r"\\\r?\n[ \t]*", " ", uncommented)
    folded = "\n".join(
        re.sub(r"[ \t]+", " ", line).strip()
        for line in folded.splitlines()
        if line.strip()
    )
    expected_calls = [
        (
            service["issuer_policy"],
            service["issuer_policy_file"],
        )
        for service in EXPECTED_SERVICES
    ]
    call_pattern = re.compile(
        r'^configure_policy ([^\s]+) "\$script_dir/policies/([^"\s]+)"$'
    )
    observed_calls = [
        match.groups()
        for line in folded.splitlines()
        if (match := call_pattern.fullmatch(line)) is not None
    ]
    if observed_calls != expected_calls:
        errors.append("Vault broker policy helper must configure exactly three issuer policies")
    required_helper_controls = (
        'case "$VAULT_ADDR" in',
        "https://*)",
        "command -v \"$tool\"",
        "vault policy write \"$policy_name\" \"$policy_file\"",
        'vault read -format=json "sys/policies/acl/$policy_name"',
        "jq -ej '.data.policy'",
        'vault policy fmt "$local_copy"',
        'vault policy fmt "$remote_copy"',
        'cmp -s "$local_copy" "$remote_copy"',
        "Vault broker issuer policy configuration failed",
    )
    if any(fragment not in configure_text for fragment in required_helper_controls):
        errors.append("Vault broker policy helper must write and read back exact policies over HTTPS")
    if folded.count('vault policy write "$policy_name" "$policy_file"') != 1:
        errors.append("Vault broker policy helper must use one reviewed generic policy write")
    if folded.count('vault read -format=json "sys/policies/acl/$policy_name"') != 1:
        errors.append("Vault broker policy helper must use one reviewed generic policy readback")
    expected_vault_commands = [
        "for tool in vault jq cmp mktemp; do",
        'vault policy write "$policy_name" "$policy_file" >/dev/null 2>&1 ||',
        'policy_json=$(vault read -format=json "sys/policies/acl/$policy_name" 2>/dev/null) ||',
        'vault policy fmt "$local_copy" >/dev/null 2>&1 || policy_failed',
        'vault policy fmt "$remote_copy" >/dev/null 2>&1 || policy_failed',
    ]
    observed_vault_commands = [
        line for line in folded.splitlines() if re.search(r"(?<![A-Za-z0-9_$])vault(?:\s|$)", line)
    ]
    if observed_vault_commands != expected_vault_commands:
        errors.append("Vault broker policy helper Vault command inventory must remain exact")
    lowered = folded.lower()
    forbidden_helper_fragments = (
        "auth/approle/login",
        "role-id",
        "secret-id",
        "token lookup",
        "token create",
        "revoke-accessor",
        "vault login",
        "set -x",
        "vault policy delete",
    )
    if any(fragment in lowered for fragment in forbidden_helper_fragments):
        errors.append(
            "Vault broker policy helper must not handle credentials, identity bindings, or deletion"
        )
    https_position = configure_text.find('case "$VAULT_ADDR" in')
    first_vault_position = configure_text.find('vault policy write "$policy_name"')
    if (
        https_position < 0
        or first_vault_position < 0
        or https_position > first_vault_position
    ):
        errors.append("Vault broker policy helper must reject non-HTTPS before Vault access")
    return errors


def load_assets() -> tuple[str, dict[str, str], str]:
    return (
        load_stable_text(
            CONTRACT,
            max_bytes=MAX_VAULT_BROKER_ASSET_BYTES,
        ),
        {
            name: load_stable_text(
                POLICY_DIR / name,
                max_bytes=MAX_VAULT_BROKER_ASSET_BYTES,
            )
            for name in ISSUER_POLICY_NAMES
        },
        load_stable_text(
            CONFIGURE,
            max_bytes=MAX_VAULT_BROKER_ASSET_BYTES,
        ),
    )


def main() -> int:
    try:
        errors = broker_contract_errors(*load_assets())
    except (OSError, UnicodeError):
        print("Unable to load Vault broker assets", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"vault-broker-contract-error: {error}", file=sys.stderr)
        return 1
    print(
        "vault-broker-contract-ok issuers=3 production_acceptance=false "
        "revocation=external-approved-rotator"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
