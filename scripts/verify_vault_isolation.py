"""Verify Vault credentials and policies are isolated by runtime service."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
import sys

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text
    from external_yaml import load_unique_yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
VAULT_DIR = ROOT / "infra" / "vault"

SERVICE_TOKEN_DIRECTORIES = {
    "api": "${PLATFORM_VAULT_API_TOKEN_DIR:?set PLATFORM_VAULT_API_TOKEN_DIR in .env}",
    "worker-mail": "${PLATFORM_VAULT_MAIL_TOKEN_DIR:?set PLATFORM_VAULT_MAIL_TOKEN_DIR in .env}",
    "worker-sub2": "${PLATFORM_VAULT_SUB2_TOKEN_DIR:?set PLATFORM_VAULT_SUB2_TOKEN_DIR in .env}",
}
TOKEN_DIRECTORY_TARGET = "/run/secrets/email-platform-vault"
TOKEN_FILE_TARGET = f"{TOKEN_DIRECTORY_TARGET}/token"
VAULT_ADDR_INPUT = "${PLATFORM_VAULT_ADDR:?set PLATFORM_VAULT_ADDR in .env}"
POLICY_PATHS = {
    "email-platform-api-cards.hcl": {"secret/data/cards/*"},
    "email-platform-mail.hcl": {"secret/data/mailboxes/*"},
    "email-platform-sub2.hcl": {
        "secret/data/cards/*",
        "secret/data/sub2/credential",
        "secret/data/sub2/proxy",
    },
}
APPROLE_BOOTSTRAP = VAULT_DIR / "configure-approles.sh"
AUDIT_CONFIG = VAULT_DIR / "configure-audit.sh"
ASSET_PATHS = (
    ENV_EXAMPLE,
    *(VAULT_DIR / "policies" / name for name in POLICY_PATHS),
    APPROLE_BOOTSTRAP,
    AUDIT_CONFIG,
)
DEPLOYMENT_CREDENTIALS = {
    f"PLATFORM_VAULT_{service}_{kind}"
    for service in ("API", "MAIL", "SUB2")
    for kind in ("TOKEN", "ROLE_ID", "SECRET_ID")
}
DEPLOYMENT_TOKEN_DIRECTORIES = {
    f"PLATFORM_VAULT_{service}_TOKEN_DIR" for service in ("API", "MAIL", "SUB2")
}
AUDIT_ASSIGNMENTS = {
    "primary_device": "email-platform-primary",
    "secondary_device": "email-platform-secondary",
    "primary_file": "/var/log/vault-audit/email-platform-primary.json",
    "secondary_file": "/var/lib/vault-audit/email-platform-secondary.json",
}


def _service_environment(service: object) -> dict[str, object]:
    if not isinstance(service, dict):
        return {}
    environment = service.get("environment", {})
    return environment if isinstance(environment, dict) else {}


def _env_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = value
    return values


def load_text_assets(paths: tuple[Path, ...] | None = None) -> dict[Path, str]:
    selected_paths = ASSET_PATHS if paths is None else paths
    return {path: load_stable_text(path) for path in selected_paths}


def load_assets() -> tuple[dict[str, object], str, dict[str, str], str, str]:
    compose = load_unique_yaml(COMPOSE)
    text_assets = load_text_assets()
    policies = {
        name: text_assets[VAULT_DIR / "policies" / name]
        for name in POLICY_PATHS
    }
    return (
        compose,
        text_assets[ENV_EXAMPLE],
        policies,
        text_assets[APPROLE_BOOTSTRAP],
        text_assets[AUDIT_CONFIG],
    )


def validate_vault_isolation(
    compose: dict[str, object],
    env_text: str,
    policies: dict[str, str],
    bootstrap: str,
    audit_config: str,
) -> list[str]:
    errors: list[str] = []
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return ["Compose services block is invalid"]

    vault_consumers = set(SERVICE_TOKEN_DIRECTORIES)
    for service_name, service in services.items():
        environment = _service_environment(service)
        serialized_environment = yaml.safe_dump(environment)
        vault_addr_references = serialized_environment.count(
            "${PLATFORM_VAULT_ADDR"
        )
        if service_name in vault_consumers:
            if (
                environment.get("PLATFORM_VAULT_ADDR") != VAULT_ADDR_INPUT
                or vault_addr_references != 1
            ):
                errors.append(
                    f"{service_name} Vault address contract is invalid"
                )
        elif (
            "PLATFORM_VAULT_ADDR" in environment
            or vault_addr_references
        ):
            errors.append(
                f"{service_name} must not receive the application Vault address"
            )

    for service_name, expected_directory in SERVICE_TOKEN_DIRECTORIES.items():
        service = services.get(service_name)
        environment = _service_environment(service)
        if environment.get("PLATFORM_VAULT_TOKEN_FILE") != TOKEN_FILE_TARGET:
            errors.append(
                f"{service_name} must use the reviewed PLATFORM_VAULT_TOKEN_FILE"
            )
        if "PLATFORM_VAULT_TOKEN" in environment:
            errors.append(f"{service_name} must not receive an environment Vault token")
        leaked = sorted(DEPLOYMENT_CREDENTIALS.intersection(environment))
        if leaked:
            errors.append(
                f"{service_name} must not receive deployment AppRole variables: "
                + ", ".join(leaked)
            )
        serialized_service = yaml.safe_dump(service)
        referenced_variables = set(
            re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", serialized_service)
        )
        unexpected_sources = sorted(
            name
            for name in DEPLOYMENT_CREDENTIALS
            if name in referenced_variables
        )
        if unexpected_sources:
            errors.append(
                f"{service_name} references another service/AppRole credential: "
                + ", ".join(unexpected_sources)
            )
        volumes = service.get("volumes", []) if isinstance(service, dict) else []
        matching_mounts = [
            volume
            for volume in volumes
            if isinstance(volume, dict) and volume.get("target") == TOKEN_DIRECTORY_TARGET
        ] if isinstance(volumes, list) else []
        if len(matching_mounts) != 1:
            errors.append(f"{service_name} must mount exactly one Vault token directory")
        else:
            mount = matching_mounts[0]
            bind = mount.get("bind", {})
            if (
                mount.get("type") != "bind"
                or mount.get("source") != expected_directory
                or mount.get("read_only") is not True
                or not isinstance(bind, dict)
                or bind.get("create_host_path") is not False
            ):
                errors.append(
                    f"{service_name} Vault token directory must be isolated, read-only, "
                    "and fail when absent"
                )

    for service_name in ("migrate", "web", "edge"):
        environment = _service_environment(services.get(service_name))
        leaked = sorted(name for name in environment if name.startswith("PLATFORM_VAULT_"))
        if leaked:
            errors.append(f"{service_name} must not receive Vault credentials")

    env_values = _env_values(env_text)
    vault_addr_lines = [
        line
        for line in env_text.splitlines()
        if line.split("=", 1)[0] == "PLATFORM_VAULT_ADDR"
        and "=" in line
    ]
    if vault_addr_lines != ["PLATFORM_VAULT_ADDR="]:
        errors.append(
            ".env.example must contain one empty PLATFORM_VAULT_ADDR input"
        )
    if "PLATFORM_VAULT_TOKEN" in env_values:
        errors.append("Shared PLATFORM_VAULT_TOKEN must not be declared")
    required_env = DEPLOYMENT_CREDENTIALS | DEPLOYMENT_TOKEN_DIRECTORIES
    missing = sorted(required_env - env_values.keys())
    if missing:
        errors.append("Missing per-service Vault variables: " + ", ".join(missing))
    for name in DEPLOYMENT_CREDENTIALS:
        value = env_values.get(name, "")
        if value and not value.startswith("CHANGE_ME_"):
            errors.append(f"{name} must be empty or an unusable placeholder")
    for name in DEPLOYMENT_TOKEN_DIRECTORIES:
        value = env_values.get(name, "")
        if not value.startswith("/"):
            errors.append(f"{name} must document an absolute host directory")
    documented_directories = {
        env_values.get(name, "") for name in DEPLOYMENT_TOKEN_DIRECTORIES
    }
    if len(documented_directories) != len(DEPLOYMENT_TOKEN_DIRECTORIES):
        errors.append("Per-service Vault token directories must be distinct")

    for policy_name, allowed_paths in POLICY_PATHS.items():
        policy = policies.get(policy_name, "")
        paths = set(re.findall(r'^path\s+"([^"]+)"', policy, re.MULTILINE))
        if paths != allowed_paths:
            errors.append(
                f"{policy_name} paths must be exactly {sorted(allowed_paths)}"
            )
        capabilities = re.findall(r"capabilities\s*=\s*\[([^]]*)\]", policy)
        if len(capabilities) != len(allowed_paths) or any(
            set(re.findall(r'"([^"]+)"', item)) != {"read"}
            for item in capabilities
        ):
            errors.append(f"{policy_name} must grant read only on every path")

    uncommented_bootstrap = "\n".join(
        line for line in bootstrap.splitlines() if not line.lstrip().startswith("#")
    )
    folded_bootstrap = re.sub(r"\\\r?\n[ \t]*", " ", uncommented_bootstrap)
    folded_bootstrap = "\n".join(
        re.sub(r"[ \t]+", " ", line).strip()
        for line in folded_bootstrap.splitlines()
        if line.strip()
    )

    expected_role_calls = [
        (
            "email-platform-api-cards",
            "email-platform-api-cards",
            "email-platform-api-cards.hcl",
        ),
        ("email-platform-mail", "email-platform-mail", "email-platform-mail.hcl"),
        ("email-platform-sub2", "email-platform-sub2", "email-platform-sub2.hcl"),
    ]
    role_call_pattern = re.compile(
        r'^configure_role ([^\s]+) ([^\s]+) "\$script_dir/policies/([^"\s]+)"$'
    )
    observed_role_calls = [
        match.groups()
        for line in folded_bootstrap.splitlines()
        if (match := role_call_pattern.fullmatch(line)) is not None
    ]
    if observed_role_calls != expected_role_calls:
        errors.append("AppRole helper must configure exactly three reviewed roles")

    function_match = re.search(
        r"^configure_role\(\) \{\n(?P<body>.*?)^\}$",
        folded_bootstrap,
        re.MULTILINE | re.DOTALL,
    )
    function_body = function_match.group("body") if function_match else ""
    role_write_lines = [
        line for line in function_body.splitlines() if line.startswith('vault write "auth/approle/role/')
    ]
    expected_write_tokens = [
        "vault",
        "write",
        "auth/approle/role/$role_name",
        "bind_secret_id=true",
        "token_policies=$policy_name",
        "token_no_default_policy=true",
        "token_num_uses=0",
        "token_type=service",
        "secret_id_ttl=10m",
        "secret_id_num_uses=1",
        "token_ttl=15m",
        "token_max_ttl=1h",
        "token_explicit_max_ttl=1h",
        "token_period=0",
        ">/dev/null",
        "2>&1",
        "||",
        "configuration_failed",
    ]
    exact_role_write = False
    if len(role_write_lines) == 1:
        try:
            exact_role_write = shlex.split(role_write_lines[0]) == expected_write_tokens
        except ValueError:
            exact_role_write = False
    if not exact_role_write:
        errors.append("AppRole helper role write must use the exact reviewed options")
    if len(re.findall(r'vault\s+write\s+"?auth/approle/role/', folded_bootstrap)) != 1:
        errors.append("AppRole helper must not add direct or unreviewed role writes")

    expected_jq_predicate = " ".join(
        (
            ".data as $role",
            "| ($role.bind_secret_id == true)",
            "and ($role.local_secret_ids == false)",
            "and ($role.secret_id_num_uses == 1)",
            "and ($role.secret_id_ttl == 600)",
            "and ($role.secret_id_bound_cidrs == [])",
            "and ($role.token_policies == [$policy])",
            "and ($role.token_no_default_policy == true)",
            'and ($role.token_type == "service")',
            "and ($role.token_ttl == 900)",
            "and ($role.token_max_ttl == 3600)",
            "and ($role.token_explicit_max_ttl == 3600)",
            "and ($role.token_period == 0)",
            "and ($role.token_num_uses == 0)",
            "and ($role.token_bound_cidrs == [])",
            "and (($role.alias_metadata // {}) == {})",
        )
    )
    jq_match = re.search(
        r'jq -e --arg policy "\$policy_name" \'(?P<body>.*?)\' >/dev/null 2>&1; then',
        folded_bootstrap,
        re.DOTALL,
    )
    observed_jq_predicate = (
        " ".join(jq_match.group("body").split()) if jq_match is not None else ""
    )
    if observed_jq_predicate != expected_jq_predicate:
        errors.append("AppRole helper must verify the exact structured target state")
    if (
        "command -v jq >/dev/null 2>&1 || {" not in folded_bootstrap.splitlines()
        or 'role_json=$(vault read -format=json "auth/approle/role/$role_name" 2>/dev/null) ||'
        not in folded_bootstrap.splitlines()
    ):
        errors.append("AppRole helper must verify the exact structured target state")

    expected_failure_bodies = {
        "configuration_failed": 'echo "Vault AppRole configuration failed" >&2\nexit 1',
        "verification_failed": (
            'echo "Vault AppRole configuration verification failed" >&2\nexit 1'
        ),
    }
    for function_name, expected_body in expected_failure_bodies.items():
        failure_match = re.search(
            rf"^{function_name}\(\) \{{\n(?P<body>.*?)^\}}$",
            folded_bootstrap,
            re.MULTILINE | re.DOTALL,
        )
        if failure_match is None or failure_match.group("body").strip() != expected_body:
            errors.append("AppRole helper failure functions must remain fail-closed")

    expected_https_case = (
        'case "$VAULT_ADDR" in\n'
        "https://*) ;;\n"
        "*)\n"
        'echo "Vault AppRole configuration preflight failed" >&2\n'
        "exit 1\n"
        ";;\n"
        "esac"
    )
    https_match = re.search(
        r'^case "\$VAULT_ADDR" in\n.*?^esac$',
        folded_bootstrap,
        re.MULTILINE | re.DOTALL,
    )
    if https_match is None or https_match.group(0) != expected_https_case:
        errors.append("AppRole helper must verify the exact structured target state")

    expected_vault_commands = [
        "command -v vault >/dev/null 2>&1 || {",
        'vault policy write "$policy_name" "$policy_file" >/dev/null 2>&1 ||',
        (
            'vault write "auth/approle/role/$role_name" bind_secret_id=true '
            'token_policies="$policy_name" token_no_default_policy=true '
            "token_num_uses=0 token_type=service secret_id_ttl=10m "
            "secret_id_num_uses=1 token_ttl=15m token_max_ttl=1h "
            "token_explicit_max_ttl=1h token_period=0 >/dev/null 2>&1 || "
            "configuration_failed"
        ),
        'role_json=$(vault read -format=json "auth/approle/role/$role_name" 2>/dev/null) ||',
    ]
    observed_vault_commands = [
        line
        for line in folded_bootstrap.splitlines()
        if re.search(r"(?<![A-Za-z0-9_$])vault(?:\s|$)", line)
    ]
    if observed_vault_commands != expected_vault_commands:
        errors.append("AppRole helper Vault command inventory must remain exact")
    expected_success = (
        'echo "Vault policies and AppRoles match reviewed configuration; '
        'no credentials were generated or read."'
    )
    if not folded_bootstrap.splitlines() or folded_bootstrap.splitlines()[-1] != expected_success:
        errors.append("AppRole helper success must be the final executable statement")
    if re.search(r"(^|[;\n])(?:curl|wget|eval|source)\b", folded_bootstrap):
        errors.append("AppRole helper must not add unreviewed shell or HTTP behavior")

    forbidden_bootstrap = (
        "auth/approle/login",
        "secret-id/lookup",
        "-field=secret_id",
        "auth/approle/role/email-platform-mail/role-id",
        "auth/approle/role/email-platform-mail/secret-id",
    )
    if any(fragment in folded_bootstrap for fragment in forbidden_bootstrap):
        errors.append("AppRole helper must not retrieve or exchange deployment credentials")

    for name, expected in AUDIT_ASSIGNMENTS.items():
        match = re.search(rf"^{name}=([^\s#]+)$", audit_config, re.MULTILINE)
        if match is None or match.group(1) != expected:
            errors.append(f"Vault audit assignment {name} must be {expected}")

    if 'case "$VAULT_ADDR" in' not in audit_config or "https://*)" not in audit_config:
        errors.append("Vault audit configuration must reject non-HTTPS addresses")
    required_reconciliation = (
        "command -v jq",
        "audit_devices_json=$(vault audit list -format=json)",
        "jq -e --arg key",
        'if device_exists "$target_key"; then',
        'if ! device_matches "$target_key" "$target_file"; then',
        'ensure_device "$primary_device" "$primary_file"',
        'ensure_device "$secondary_device" "$secondary_file"',
        'device_matches "$primary_device/" "$primary_file"',
        'device_matches "$secondary_device/" "$secondary_file"',
    )
    if any(fragment not in audit_config for fragment in required_reconciliation):
        errors.append(
            "Vault audit configuration must reconcile each device and verify final state"
        )
    if audit_config.count(
        'if ! device_matches "$target_key" "$target_file"; then'
    ) != 2:
        errors.append(
            "Vault audit configuration must reconcile each device and verify final state"
        )

    folded_audit = re.sub(r"\\\r?\n[ \t]*", " ", audit_config)
    folded_audit = "\n".join(
        re.sub(r"[ \t]+", " ", line).strip()
        for line in folded_audit.splitlines()
    )
    expected_options = (
        "mode=0600 format=json log_raw=false hmac_accessor=true "
        "elide_list_responses=true"
    )
    expected_command = (
        'vault audit enable -path="$target_device" file '
        f'file_path="$target_file" {expected_options}'
    )
    if expected_command not in folded_audit:
        errors.append("Vault audit device enable is missing reviewed safe options")
    if folded_audit.count("vault audit enable ") != 1:
        errors.append("Vault audit helper must use one reviewed per-device enable path")
    if audit_config.count('ensure_device "$') != 2:
        errors.append("Vault must reconcile exactly two named audit devices")

    required_device_fields = (
        '$device.type == "file"',
        "$device.options.file_path == $file_path",
        '$device.options.mode == "0600"',
        '$device.options.format == "json"',
        '$device.options.log_raw == "false"',
        '$device.options.hmac_accessor == "true"',
        '$device.options.elide_list_responses == "true"',
    )
    if any(fragment not in audit_config for fragment in required_device_fields):
        errors.append("Vault existing audit devices must match every reviewed field")

    forbidden_audit = (
        "vault_token",
        "vault login",
        "auth/approle/login",
        "secret-id",
        "role-id",
        "-field=token",
        "token lookup",
    )
    lowered_audit = audit_config.lower()
    if any(fragment in lowered_audit for fragment in forbidden_audit):
        errors.append("Vault audit helper must not read, print, or exchange credentials")
    if any(
        fragment in lowered_audit
        for fragment in ("vault audit disable", "vault audit tune")
    ):
        errors.append("Vault audit helper must not disable or tune existing devices")

    return errors


def main() -> int:
    try:
        assets = load_assets()
    except (OSError, yaml.YAMLError):
        print("Unable to load Vault isolation assets", file=sys.stderr)
        return 1
    errors = validate_vault_isolation(*assets)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "vault-isolation-ok api=cards-only mail=mailboxes-only "
        "sub2=sub2-and-cards-only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
