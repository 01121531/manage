"""Verify every production cross-container HTTP endpoint uses authenticated TLS."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from types import ModuleType
from typing import Any

import yaml

try:
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_yaml import load_unique_yaml

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
PROMETHEUS = ROOT / "infra" / "prometheus" / "prometheus.yml"
ENV_EXAMPLE = ROOT / ".env.example"
PROMETHEUS_WEB = ROOT / "infra" / "prometheus" / "prometheus-web.yml"
ALERTMANAGER_WEB = ROOT / "infra" / "prometheus" / "alertmanager-web.yml"
EDGE_TEMPLATE = ROOT / "infra" / "nginx" / "email-platform.conf.template"
WEB_CONFIG = ROOT / "infra" / "nginx" / "web.conf"
EXPIRY_MONITOR = ROOT / "scripts/check_internal_tls_expiry.py"
RUNBOOK = ROOT / "deploy/runbooks/internal-tls.md"
ASSET_PATHS = (
    ENV_EXAMPLE,
    PROMETHEUS_WEB,
    ALERTMANAGER_WEB,
    EDGE_TEMPLATE,
    WEB_CONFIG,
    EXPIRY_MONITOR,
    RUNBOOK,
)
CA_TARGET = "/run/secrets/internal-tls/ca.crt"
CERT_TARGET = "/run/secrets/internal-tls/tls.crt"
KEY_TARGET = "/run/secrets/internal-tls/tls.key"
TLS_SERVICES = {
    "api": ("PLATFORM_INTERNAL_API_CERT_FILE", "PLATFORM_INTERNAL_API_KEY_FILE"),
    "web": ("PLATFORM_INTERNAL_WEB_CERT_FILE", "PLATFORM_INTERNAL_WEB_KEY_FILE"),
    "keycloak": (
        "PLATFORM_INTERNAL_KEYCLOAK_CERT_FILE",
        "PLATFORM_INTERNAL_KEYCLOAK_KEY_FILE",
    ),
    "worker-mail": (
        "PLATFORM_INTERNAL_WORKER_MAIL_CERT_FILE",
        "PLATFORM_INTERNAL_WORKER_MAIL_KEY_FILE",
    ),
    "worker-sub2": (
        "PLATFORM_INTERNAL_WORKER_SUB2_CERT_FILE",
        "PLATFORM_INTERNAL_WORKER_SUB2_KEY_FILE",
    ),
    "prometheus": (
        "PLATFORM_INTERNAL_PROMETHEUS_CERT_FILE",
        "PLATFORM_INTERNAL_PROMETHEUS_KEY_FILE",
    ),
    "alertmanager": (
        "PLATFORM_INTERNAL_ALERTMANAGER_CERT_FILE",
        "PLATFORM_INTERNAL_ALERTMANAGER_KEY_FILE",
    ),
}
EXPECTED_EXPIRY_CERTIFICATE_ENV = {
    "api": "PLATFORM_INTERNAL_API_CERT_FILE",
    "web": "PLATFORM_INTERNAL_WEB_CERT_FILE",
    "api-green": "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
    "web-green": "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
    "keycloak": "PLATFORM_INTERNAL_KEYCLOAK_CERT_FILE",
    "worker-mail": "PLATFORM_INTERNAL_WORKER_MAIL_CERT_FILE",
    "worker-sub2": "PLATFORM_INTERNAL_WORKER_SUB2_CERT_FILE",
    "prometheus": "PLATFORM_INTERNAL_PROMETHEUS_CERT_FILE",
    "alertmanager": "PLATFORM_INTERNAL_ALERTMANAGER_CERT_FILE",
}
EXPECTED_EXPIRY_KEY_ENV = {
    "api": "PLATFORM_INTERNAL_API_KEY_FILE",
    "web": "PLATFORM_INTERNAL_WEB_KEY_FILE",
    "api-green": "PLATFORM_ROLLING_GREEN_API_KEY_FILE",
    "web-green": "PLATFORM_ROLLING_GREEN_WEB_KEY_FILE",
    "keycloak": "PLATFORM_INTERNAL_KEYCLOAK_KEY_FILE",
    "worker-mail": "PLATFORM_INTERNAL_WORKER_MAIL_KEY_FILE",
    "worker-sub2": "PLATFORM_INTERNAL_WORKER_SUB2_KEY_FILE",
    "prometheus": "PLATFORM_INTERNAL_PROMETHEUS_KEY_FILE",
    "alertmanager": "PLATFORM_INTERNAL_ALERTMANAGER_KEY_FILE",
}
EXPECTED_EXPIRY_CA_ENV = "PLATFORM_INTERNAL_CA_FILE"
EXPECTED_JWKS = (
    "https://keycloak:8443/realms/email-platform/protocol/openid-connect/certs"
)
EXPECTED_SCRAPES = {
    "api": ("api:8443", "api"),
    "keycloak": ("keycloak:9000", "keycloak"),
    "worker-mail": ("worker-mail:9101", "worker-mail"),
    "worker-sub2": ("worker-sub2:9102", "worker-sub2"),
}


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _env_values(text: str) -> dict[str, str]:
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }


def load_text_assets() -> dict[Path, str]:
    return {path: load_stable_text(path) for path in ASSET_PATHS}


def load_assets() -> tuple[
    dict[str, Any], dict[str, Any], str, str, str, str, str, str, str
]:
    compose = load_unique_yaml(COMPOSE)
    prometheus = load_unique_yaml(PROMETHEUS)
    if not isinstance(compose, dict) or not isinstance(prometheus, dict):
        raise ValueError("Compose and Prometheus assets must be YAML mappings")
    text_assets = load_text_assets()
    return (
        compose,
        prometheus,
        text_assets[ENV_EXAMPLE],
        text_assets[PROMETHEUS_WEB],
        text_assets[ALERTMANAGER_WEB],
        text_assets[EDGE_TEMPLATE],
        text_assets[WEB_CONFIG],
        text_assets[EXPIRY_MONITOR],
        text_assets[RUNBOOK],
    )


def _mount_for_target(service: dict[str, Any], target: str) -> dict[str, Any]:
    matches = [
        mount
        for mount in _list(service.get("volumes"))
        if isinstance(mount, dict) and mount.get("target") == target
    ]
    return matches[0] if len(matches) == 1 else {}


def _mount_is_read_only_bind(mount: dict[str, Any], source: str) -> bool:
    bind = _mapping(mount.get("bind"))
    return (
        mount.get("type") == "bind"
        and mount.get("source") == source
        and mount.get("read_only") is True
        and bind.get("create_host_path") is False
    )


def _strict_client_errors(
    client: dict[str, Any], *, label: str, server_name: str
) -> list[str]:
    tls = _mapping(client.get("tls_config"))
    errors: list[str] = []
    if client.get("scheme") != "https":
        errors.append(f"{label} must use scheme=https")
    if tls.get("ca_file") != CA_TARGET:
        errors.append(f"{label} must trust only the mounted internal CA")
    if tls.get("server_name") != server_name:
        errors.append(f"{label} must verify server_name={server_name}")
    if tls.get("insecure_skip_verify") is not False:
        errors.append(f"{label} must explicitly keep certificate verification enabled")
    if tls.get("min_version") != "TLS12":
        errors.append(f"{label} must require at least TLS 1.2")
    return errors


def validate_expiry_monitor_contract(
    *,
    certificate_env: dict[str, str],
    key_env: dict[str, str],
    ca_env: str,
    thresholds_days: tuple[int, ...],
    page_below_days: int,
    script_text: str,
    runbook_text: str,
) -> list[str]:
    errors: list[str] = []
    if certificate_env != EXPECTED_EXPIRY_CERTIFICATE_ENV:
        errors.append("Internal TLS expiry inventory must contain the exact nine leaf services")
    if key_env != EXPECTED_EXPIRY_KEY_ENV:
        errors.append("Internal TLS expiry inventory must contain the exact nine private keys")
    if ca_env != EXPECTED_EXPIRY_CA_ENV:
        errors.append("Internal TLS expiry inventory must contain the internal CA bundle")
    if thresholds_days != (30, 14, 7):
        errors.append("Internal TLS expiry alert thresholds must be exactly 30, 14 and 7 days")
    if page_below_days != 7:
        errors.append("Internal TLS expiry page threshold must be below seven days")
    for marker in (
        "path.is_symlink()",
        "x509.load_pem_x509_certificate",
        "serialization.load_pem_private_key",
        "x509.SubjectAlternativeName",
        "verify_directly_issued_by",
        "private_key.public_key()",
        "not_valid_before_utc",
        "not_valid_after_utc",
        '"fingerprint_sha256"',
        '"certificate_input_invalid"',
        "separators=(\",\", \":\")",
        "MAX_CA_BUNDLE_BYTES = 256 * 1024",
        "MAX_LEAF_CERTIFICATE_BYTES = 64 * 1024",
        "MAX_PRIVATE_KEY_BYTES = 64 * 1024",
        "read_stable_bytes(",
    ):
        if marker not in script_text:
            errors.append(f"Internal TLS expiry checker is missing: {marker}")
    if ".read_bytes()" in script_text:
        errors.append("Internal TLS expiry checker must use stable bounded PEM reads")
    for marker in (
        "python scripts/check_internal_tls_expiry.py --env-file",
        "at least once every 24 hours",
        "Exit `1`",
        "Exit `2`",
        "Exit `3`",
        "less than seven days",
        "production_acceptance=false",
        "external scheduler and notification delivery",
    ):
        if marker not in runbook_text:
            errors.append(f"Internal TLS expiry runbook is missing: {marker}")
    return errors


def validate_internal_tls(
    compose: dict[str, Any],
    prometheus: dict[str, Any],
    env_text: str,
    prometheus_web_text: str,
    alertmanager_web_text: str,
    edge_template: str,
    web_config: str,
) -> list[str]:
    errors: list[str] = []
    services = _mapping(compose.get("services"))
    env_values = _env_values(env_text)
    ca_source = "${PLATFORM_INTERNAL_CA_FILE:?set PLATFORM_INTERNAL_CA_FILE in .env}"

    required_env = {"PLATFORM_INTERNAL_CA_FILE"}
    for cert_name, key_name in TLS_SERVICES.values():
        required_env.update((cert_name, key_name))
    missing_env = sorted(required_env - set(env_values))
    if missing_env:
        errors.append("Missing internal TLS path variables: " + ", ".join(missing_env))
    for name in required_env:
        value = env_values.get(name, "")
        if value and not value.startswith("/"):
            errors.append(f"{name} must document an absolute external path")
    cert_paths = [env_values.get(pair[0], "") for pair in TLS_SERVICES.values()]
    key_paths = [env_values.get(pair[1], "") for pair in TLS_SERVICES.values()]
    if len(set(cert_paths)) != len(cert_paths):
        errors.append("Every internal TLS service must use a distinct certificate path")
    if len(set(key_paths)) != len(key_paths):
        errors.append("Every internal TLS service must use a distinct private-key path")
    if env_values.get("PLATFORM_INTERNAL_CA_FILE") in cert_paths + key_paths:
        errors.append("The internal CA file must not be used as a leaf certificate or key")
    if set(cert_paths).intersection(key_paths):
        errors.append("Internal certificate and private-key host paths must be separate")
    if env_values.get("PLATFORM_TLS_CERT_FILE") in cert_paths:
        errors.append("Internal services must not reuse the public edge certificate")
    if env_values.get("PLATFORM_TLS_KEY_FILE") in key_paths:
        errors.append("Internal services must not reuse the public edge private key")

    for name, (cert_name, key_name) in TLS_SERVICES.items():
        service = _mapping(services.get(name))
        if not service:
            errors.append(f"Compose is missing internal TLS service {name}")
            continue
        expected_sources = {
            CA_TARGET: ca_source,
            CERT_TARGET: f"${{{cert_name}:?set {cert_name} in .env}}",
            KEY_TARGET: f"${{{key_name}:?set {key_name} in .env}}",
        }
        for target, source in expected_sources.items():
            mount = _mount_for_target(service, target)
            if not _mount_is_read_only_bind(mount, source):
                errors.append(
                    f"{name} must mount {target} read-only from its reviewed external path"
                )

    edge = _mapping(services.get("edge"))
    if not _mount_is_read_only_bind(_mount_for_target(edge, CA_TARGET), ca_source):
        errors.append("edge must mount the internal CA read-only")

    for name, service_value in services.items():
        service = _mapping(service_value)
        if service.get("network_mode") == "host":
            errors.append(f"{name} must not use host networking")
        if name == "vault":
            if service.get("profiles") != ["vault-dev"]:
                errors.append("Plaintext Vault is allowed only in the vault-dev profile")
            continue
        serialized = yaml.safe_dump(service)
        if "http://" in serialized:
            errors.append(f"{name} contains a plaintext production HTTP endpoint")

    api = _mapping(services.get("api"))
    api_command = [str(item) for item in _list(api.get("command"))]
    for required in (
        "--port",
        "8443",
        "--ssl-certfile",
        CERT_TARGET,
        "--ssl-keyfile",
        KEY_TARGET,
    ):
        if required not in api_command:
            errors.append(f"api HTTPS command is missing {required}")
    health = " ".join(str(item) for item in _list(_mapping(api.get("healthcheck")).get("test")))
    if "https://api:8443/readyz" not in health or CA_TARGET not in health:
        errors.append("api healthcheck must verify HTTPS using the internal CA")

    keycloak = _mapping(services.get("keycloak"))
    keycloak_command = [str(item) for item in _list(keycloak.get("command"))]
    keycloak_env = _mapping(keycloak.get("environment"))
    if "--http-enabled=false" not in keycloak_command or "--http-enabled=true" in keycloak_command:
        errors.append("Keycloak business HTTP must be disabled")
    if "--https-port=8443" not in keycloak_command:
        errors.append("Keycloak must listen for HTTPS on port 8443")
    expected_keycloak_env = {
        "KC_HTTPS_CERTIFICATE_FILE": CERT_TARGET,
        "KC_HTTPS_CERTIFICATE_KEY_FILE": KEY_TARGET,
        "KC_HTTP_MANAGEMENT_SCHEME": "inherited",
        "KC_HTTPS_CERTIFICATES_RELOAD_PERIOD": "1h",
    }
    for setting, expected in expected_keycloak_env.items():
        if keycloak_env.get(setting) != expected:
            errors.append(f"Keycloak must set {setting}={expected}")

    for name in ("api", "worker-mail", "worker-sub2"):
        environment = _mapping(_mapping(services.get(name)).get("environment"))
        if environment.get("PLATFORM_OIDC_JWKS_URL") != EXPECTED_JWKS:
            errors.append(f"{name} must fetch JWKS over verified internal HTTPS")
        if environment.get("PLATFORM_INTERNAL_CA_FILE") != CA_TARGET:
            errors.append(f"{name} must trust the mounted internal CA for JWKS")
        if "SSL_CERT_FILE" in environment:
            errors.append(
                f"{name} must not replace the public trust store with SSL_CERT_FILE"
            )
    for name in ("worker-mail", "worker-sub2"):
        environment = _mapping(_mapping(services.get(name)).get("environment"))
        if environment.get("PLATFORM_WORKER_METRICS_TLS_CERT_FILE") != CERT_TARGET:
            errors.append(f"{name} metrics must use its mounted TLS certificate")
        if environment.get("PLATFORM_WORKER_METRICS_TLS_KEY_FILE") != KEY_TARGET:
            errors.append(f"{name} metrics must use its mounted TLS private key")

    scrape_by_name = {
        str(_mapping(item).get("job_name")): _mapping(item)
        for item in _list(prometheus.get("scrape_configs"))
    }
    for name, (target, server_name) in EXPECTED_SCRAPES.items():
        scrape = scrape_by_name.get(name, {})
        static = _list(scrape.get("static_configs"))
        targets = _list(_mapping(static[0]).get("targets")) if len(static) == 1 else []
        if targets != [target]:
            errors.append(f"Prometheus {name} scrape target must be {target}")
        errors.extend(
            _strict_client_errors(scrape, label=f"Prometheus {name} scrape", server_name=server_name)
        )

    alertmanagers = _list(_mapping(prometheus.get("alerting")).get("alertmanagers"))
    alertmanager_client = _mapping(alertmanagers[0]) if len(alertmanagers) == 1 else {}
    alertmanager_static = _list(alertmanager_client.get("static_configs"))
    alertmanager_targets = (
        _list(_mapping(alertmanager_static[0]).get("targets"))
        if len(alertmanager_static) == 1
        else []
    )
    if alertmanager_targets != ["alertmanager:9093"]:
        errors.append("Prometheus must send alerts only to alertmanager:9093")
    errors.extend(
        _strict_client_errors(
            alertmanager_client,
            label="Prometheus Alertmanager client",
            server_name="alertmanager",
        )
    )

    expected_web = {
        "cert_file": CERT_TARGET,
        "key_file": KEY_TARGET,
        "min_version": "TLS12",
    }
    for label, text in (
        ("Prometheus", prometheus_web_text),
        ("Alertmanager", alertmanager_web_text),
    ):
        web_yaml = yaml.safe_load(text)
        tls_server = _mapping(_mapping(web_yaml).get("tls_server_config"))
        if tls_server != expected_web:
            errors.append(f"{label} web endpoint must use the reviewed TLS server config")

    web_server_assets = {
        "prometheus": (
            "--web.config.file=/etc/prometheus/web.yml",
            "./infra/prometheus/prometheus-web.yml:/etc/prometheus/web.yml:ro",
        ),
        "alertmanager": (
            "--web.config.file=/etc/alertmanager/web.yml",
            "./infra/prometheus/alertmanager-web.yml:/etc/alertmanager/web.yml:ro",
        ),
    }
    for name, (flag, mount) in web_server_assets.items():
        service = _mapping(services.get(name))
        command = [str(item) for item in _list(service.get("command"))]
        volumes = [str(item) for item in _list(service.get("volumes"))]
        if flag not in command or mount not in volumes:
            errors.append(f"{name} must load its reviewed TLS web configuration")

    if re.search(r"proxy_pass\s+http://", edge_template):
        errors.append("edge must not proxy to a plaintext internal service")
    if "proxy_ssl_verify off;" in edge_template:
        errors.append("edge must not disable upstream certificate verification")
    for proxy, tls_name, label in (
        ("active_api", "$active_api_tls_name", "active API slot"),
        ("active_web", "$active_web_tls_name", "active Web slot"),
        ("keycloak:8443", "keycloak", "keycloak"),
    ):
        if f"proxy_pass https://{proxy}" not in edge_template:
            errors.append(f"edge must proxy to {label} over HTTPS")
        if f"proxy_ssl_name {tls_name};" not in edge_template:
            errors.append(f"edge must verify the {label} certificate hostname")
    if edge_template.count(f"proxy_ssl_trusted_certificate {CA_TARGET};") < 4:
        errors.append("every edge upstream location must trust the internal CA")
    if edge_template.count("proxy_ssl_verify on;") < 4:
        errors.append("every edge upstream location must enable certificate verification")
    for required in (
        "listen 8443 ssl;",
        f"ssl_certificate {CERT_TARGET};",
        f"ssl_certificate_key {KEY_TARGET};",
    ):
        if required not in web_config:
            errors.append(f"web internal TLS config is missing {required}")

    combined = "\n".join(
        (
            yaml.safe_dump(compose),
            yaml.safe_dump(prometheus),
            env_text,
            prometheus_web_text,
            alertmanager_web_text,
            edge_template,
            web_config,
        )
    )
    if re.search(r"insecure_skip_verify\s*:\s*true", combined, re.IGNORECASE):
        errors.append("Internal TLS must never skip certificate verification")
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", combined):
        errors.append("Internal TLS assets must never contain a private key")
    return errors


def _load_expiry_monitor(path: Path, source: str) -> ModuleType:
    module = ModuleType("verified_internal_tls_expiry")
    module.__file__ = str(path)
    module.__package__ = ""
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def main() -> int:
    try:
        (
            compose,
            prometheus,
            env_text,
            prometheus_web_text,
            alertmanager_web_text,
            edge_template,
            web_config,
            expiry_monitor_source,
            runbook_text,
        ) = load_assets()
        errors = validate_internal_tls(
            compose,
            prometheus,
            env_text,
            prometheus_web_text,
            alertmanager_web_text,
            edge_template,
            web_config,
        )
    except (OSError, ValueError, yaml.YAMLError):
        print("Internal TLS asset load failed", file=sys.stderr)
        return 1
    try:
        check_internal_tls_expiry = _load_expiry_monitor(
            EXPIRY_MONITOR, expiry_monitor_source
        )
        errors.extend(
            validate_expiry_monitor_contract(
                certificate_env=check_internal_tls_expiry.CERTIFICATE_ENV,
                key_env=check_internal_tls_expiry.KEY_ENV,
                ca_env=check_internal_tls_expiry.CA_ENV,
                thresholds_days=check_internal_tls_expiry.THRESHOLDS_DAYS,
                page_below_days=check_internal_tls_expiry.PAGE_BELOW_DAYS,
                script_text=expiry_monitor_source,
                runbook_text=runbook_text,
            )
        )
    except Exception:
        print("Internal TLS expiry monitor load failed", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("internal-tls-ok cross-container-https-ca-hostname-verification-enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
