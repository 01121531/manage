"""Validate Prometheus and Alertmanager wiring for the compose stack."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text
    from external_yaml import load_unique_yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
PROMETHEUS = ROOT / "infra" / "prometheus" / "prometheus.yml"
ALERTS = ROOT / "infra" / "prometheus" / "alerts.yml"
ALERTMANAGER = ROOT / "infra" / "prometheus" / "alertmanager.yml"
ENV_EXAMPLE = ROOT / ".env.example"
MAX_MONITORING_ENV_BYTES = 64 * 1024

EXPECTED_SCRAPE_TARGETS = {
    "prometheus": "prometheus:9090",
    "alertmanager": "alertmanager:9093",
    "api": "api:8443",
    "keycloak": "keycloak:9000",
    "worker-mail": "worker-mail:9101",
    "worker-sub2": "worker-sub2:9102",
}
REQUIRED_ALERTS = {
    "PlatformAlertmanagerDown",
    "PlatformMonitoringWatchdog",
    "PlatformApiDown",
    "PlatformKeycloakDown",
    "PlatformKeycloakLoginFailures",
    "PlatformMailWorkerStalled",
    "PlatformMailConnectorUnavailable",
    "PlatformSub2WorkerStalled",
    "PlatformUnknownUploadsPresent",
    "PlatformApi5xxRateElevated",
}
EXPECTED_CONTROL_PLANE_SCRAPES = {
    "prometheus": "prometheus:9090",
    "alertmanager": "alertmanager:9093",
}
INTERNAL_CA_FILE = "/run/secrets/internal-tls/ca.crt"
MAX_HEARTBEAT_INTERVAL_SECONDS = 120
EXPECTED_ALERTMANAGER_DOWN_EXPRESSION = 'up{job="alertmanager"} == 0'
EXPECTED_WATCHDOG_EXPRESSION = "vector(1)"
EXPECTED_API_5XX_EXPRESSION = (
    'sum(rate(platform_http_requests_total{status_code=~"5.."}[5m])) > 0.1'
)
EXPECTED_KEYCLOAK_DOWN_EXPRESSION = 'up{job="keycloak"} == 0'
EXPECTED_KEYCLOAK_LOGIN_FAILURE_EXPRESSION = (
    'sum(increase(keycloak_user_events_total{job="keycloak",realm="email-platform",'
    'event="login",error!=""}[5m])) >= 5'
)
EXPECTED_MAIL_CONNECTOR_UNAVAILABLE_EXPRESSION = (
    'increase(platform_worker_batch_results_total{job="worker-mail",worker="mail",'
    'result="connector_unavailable"}[5m]) >= 3'
)
EXPECTED_WORKER_ALERT_EXPRESSIONS = {
    "PlatformMailWorkerStalled": (
        'up{job="worker-mail"} == 0 or '
        'time() - platform_worker_last_batch_timestamp_seconds{job="worker-mail"} > 120'
    ),
    "PlatformSub2WorkerStalled": (
        'up{job="worker-sub2"} == 0 or '
        'time() - platform_worker_heartbeat_timestamp_seconds{job="worker-sub2"} > 120'
    ),
}


def _load_document(path: Path) -> dict[str, Any]:
    value = load_unique_yaml(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return value


def load_assets() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        _load_document(COMPOSE),
        _load_document(PROMETHEUS),
        _load_document(ALERTS),
        _load_document(ALERTMANAGER),
    )


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _compact_expression(value: object) -> str:
    return " ".join(str(value).split())


def _is_absolute_host_path(value: str) -> bool:
    return value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value) is not None


def validate_alertmanager_production_boundary(
    compose: dict[str, Any], env_example_text: str
) -> list[str]:
    errors: list[str] = []
    services = _mapping(compose.get("services"))
    service = _mapping(services.get("alertmanager"))
    config_mounts = [
        _mapping(item)
        for item in _list(service.get("volumes"))
        if _mapping(item).get("target") == "/etc/alertmanager/alertmanager.yml"
    ]
    if len(config_mounts) != 1:
        errors.append("Alertmanager must have exactly one structured production config bind")
    else:
        mount = config_mounts[0]
        source = mount.get("source")
        if (
            mount.get("type") != "bind"
            or not isinstance(source, str)
            or not source.startswith("${ALERTMANAGER_CONFIG_FILE:?")
            or not source.endswith("}")
            or ":-" in source
        ):
            errors.append(
                "Alertmanager config source must require ALERTMANAGER_CONFIG_FILE with no fallback"
            )
        if mount.get("read_only") is not True:
            errors.append("Alertmanager production config bind must be read-only")
        if _mapping(mount.get("bind")).get("create_host_path") is not False:
            errors.append("Alertmanager config bind must set create_host_path=false")

    env_match = re.search(
        r"(?m)^ALERTMANAGER_CONFIG_FILE=([^\r\n]+)$", env_example_text
    )
    env_value = env_match.group(1).strip() if env_match else ""
    if not _is_absolute_host_path(env_value):
        errors.append(".env.example Alertmanager config must use an absolute host path")
    normalized = env_value.replace("\\", "/").lower()
    if (
        normalized.startswith("./")
        or "/infra/prometheus/alertmanager.yml" in normalized
        or normalized == str(ALERTMANAGER).replace("\\", "/").lower()
    ):
        errors.append(".env.example must not select the repository development placeholder")
    return errors


def _route_matches_page(route: dict[str, Any]) -> bool:
    return _route_matches_severity(route, "page")


def _route_matches_severity(route: dict[str, Any], severity: str) -> bool:
    match = _mapping(route.get("match"))
    if match.get("severity") == severity:
        return True
    return any(
        re.fullmatch(
            rf'\s*severity\s*=\s*"?{re.escape(severity)}"?\s*',
            str(matcher),
        )
        is not None
        for matcher in _list(route.get("matchers"))
    )


def _route_matches_only_severity(route: dict[str, Any], severity: str) -> bool:
    match = _mapping(route.get("match"))
    matchers = _list(route.get("matchers"))
    if match:
        return match == {"severity": severity} and not matchers
    return len(matchers) == 1 and _route_matches_severity(route, severity)


def _duration_seconds(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([1-9]\d*)(ms|s|m|h)", value.strip())
    if match is None:
        return None
    amount = int(match.group(1))
    multiplier = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[match.group(2)]
    return amount * multiplier


def _is_safe_external_https_url(value: object) -> bool:
    parsed = urlsplit(value) if isinstance(value, str) else None
    hostname = parsed.hostname if parsed is not None else None
    loopback = hostname in {"localhost", "localhost.localdomain"}
    if hostname:
        try:
            loopback = loopback or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            pass
    return not (
        parsed is None
        or parsed.scheme != "https"
        or not hostname
        or loopback
        or hostname.endswith(".localhost")
        or hostname.endswith(".invalid")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    )


def _contains_inline_receiver_secret(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"password", "credentials", "client_secret", "bearer_token"}:
                return True
            if _contains_inline_receiver_secret(child):
                return True
    elif isinstance(value, list):
        return any(_contains_inline_receiver_secret(item) for item in value)
    return False


def validate_production_alertmanager_config(config: dict[str, Any]) -> list[str]:
    """Validate the reviewed HTTPS webhook contract without sending an alert."""
    errors: list[str] = []
    route = _mapping(config.get("route"))
    if not {"alertname", "severity"}.issubset(
        {str(item) for item in _list(route.get("group_by"))}
    ):
        errors.append("Production Alertmanager must group alerts by alertname and severity")
    for key in ("group_wait", "group_interval", "repeat_interval"):
        if not isinstance(route.get(key), str) or not route[key]:
            errors.append(f"Production Alertmanager route is missing {key}")

    page_routes = [
        _mapping(item)
        for item in _list(route.get("routes"))
        if _route_matches_page(_mapping(item))
    ]
    if not page_routes:
        errors.append("Production Alertmanager must define an explicit severity=page route")

    heartbeat_routes = [
        _mapping(item)
        for item in _list(route.get("routes"))
        if _route_matches_severity(_mapping(item), "watchdog")
    ]
    if len(heartbeat_routes) != 1 or not _route_matches_only_severity(
        heartbeat_routes[0] if heartbeat_routes else {}, "watchdog"
    ):
        errors.append(
            "Production Alertmanager must define one exact severity=watchdog heartbeat route"
        )
    elif not _route_matches_only_severity(
        _mapping(_list(route.get("routes"))[0]), "watchdog"
    ):
        errors.append(
            "Production watchdog route must be first so broader routes cannot intercept it"
        )

    receivers = {
        item["name"]: item
        for raw in _list(config.get("receivers"))
        if (item := _mapping(raw)) and isinstance(item.get("name"), str)
    }
    for page_route in page_routes:
        receiver_name = page_route.get("receiver")
        receiver = _mapping(receivers.get(receiver_name))
        if not receiver:
            errors.append(f"Production page receiver is missing: {receiver_name}")
            continue
        webhooks = [_mapping(item) for item in _list(receiver.get("webhook_configs"))]
        if not webhooks:
            errors.append("Production page receiver must contain an HTTPS webhook")
            continue
        if _contains_inline_receiver_secret(receiver):
            errors.append("Production page receiver secrets must use *_file fields")
        for webhook in webhooks:
            if not _is_safe_external_https_url(webhook.get("url")):
                errors.append(
                    "Production page webhook must use a credential-free HTTPS URL on a non-placeholder host"
                )
            if webhook.get("send_resolved") is not True:
                errors.append("Production page webhook must send resolved notifications")

    page_receivers = {item.get("receiver") for item in page_routes}
    root_receiver = route.get("receiver")
    for heartbeat_route in heartbeat_routes:
        heartbeat_receiver_name = heartbeat_route.get("receiver")
        if (
            not isinstance(heartbeat_receiver_name, str)
            or not heartbeat_receiver_name
            or heartbeat_receiver_name == root_receiver
            or heartbeat_receiver_name in page_receivers
        ):
            errors.append(
                "Production watchdog must use a dedicated receiver distinct from page and default"
            )
            continue
        if heartbeat_route.get("continue") not in (None, False):
            errors.append("Production watchdog route must not continue into another route")
        for key in ("group_interval", "repeat_interval"):
            seconds = _duration_seconds(heartbeat_route.get(key))
            if seconds is None or seconds > MAX_HEARTBEAT_INTERVAL_SECONDS:
                errors.append(
                    f"Production watchdog {key} must be explicit and no longer than 2m"
                )
        heartbeat_receiver = _mapping(receivers.get(heartbeat_receiver_name))
        if not heartbeat_receiver:
            errors.append(
                f"Production watchdog receiver is missing: {heartbeat_receiver_name}"
            )
            continue
        heartbeat_webhooks = [
            _mapping(item)
            for item in _list(heartbeat_receiver.get("webhook_configs"))
        ]
        if not heartbeat_webhooks:
            errors.append("Production watchdog receiver must contain an HTTPS webhook")
            continue
        if _contains_inline_receiver_secret(heartbeat_receiver):
            errors.append("Production watchdog receiver secrets must use *_file fields")
        for webhook in heartbeat_webhooks:
            if not _is_safe_external_https_url(webhook.get("url")):
                errors.append(
                    "Production watchdog webhook must use a credential-free HTTPS URL on a non-placeholder host"
                )
            if webhook.get("send_resolved") is not True:
                errors.append("Production watchdog webhook must send resolved notifications")
    return errors


def validate_monitoring_assets(
    compose: dict[str, Any],
    prometheus: dict[str, Any],
    alerts: dict[str, Any],
    alertmanager: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    services = _mapping(compose.get("services"))
    prometheus_service = _mapping(services.get("prometheus"))
    alertmanager_service = _mapping(services.get("alertmanager"))
    if not prometheus_service:
        errors.append("Compose is missing prometheus service")
    if not alertmanager_service:
        errors.append("Compose is missing alertmanager service")

    prometheus_ports = {str(item) for item in _list(prometheus_service.get("ports"))}
    if "127.0.0.1:9090:9090" not in prometheus_ports:
        errors.append("Prometheus must bind only localhost port 9090")
    alertmanager_ports = {str(item) for item in _list(alertmanager_service.get("ports"))}
    if "127.0.0.1:9093:9093" not in alertmanager_ports:
        errors.append("Alertmanager must bind only localhost port 9093")

    for key, expected in (
        ("read_only", True),
        ("cap_drop", ["ALL"]),
        ("security_opt", ["no-new-privileges:true"]),
    ):
        if alertmanager_service.get(key) != expected:
            errors.append(f"Alertmanager hardening mismatch: {key}")
    config_mounts = [
        _mapping(item)
        for item in _list(alertmanager_service.get("volumes"))
        if _mapping(item).get("target") == "/etc/alertmanager/alertmanager.yml"
    ]
    if len(config_mounts) != 1:
        errors.append("Alertmanager must mount one external production config")
    prometheus_dependencies = _mapping(prometheus_service.get("depends_on"))
    if "alertmanager" not in prometheus_dependencies:
        errors.append("Prometheus must depend on alertmanager startup")

    keycloak_service = _mapping(services.get("keycloak"))
    keycloak_environment = _mapping(keycloak_service.get("environment"))
    for setting in ("KC_METRICS_ENABLED", "KC_HEALTH_ENABLED"):
        if keycloak_environment.get(setting) != "true":
            errors.append(f"Keycloak must set {setting}=true for internal monitoring")
    expected_event_metrics = {
        "KC_EVENT_METRICS_USER_ENABLED": "true",
        "KC_EVENT_METRICS_USER_EVENTS": "login",
        "KC_EVENT_METRICS_USER_TAGS": "realm",
    }
    for setting, expected in expected_event_metrics.items():
        if keycloak_environment.get(setting) != expected:
            errors.append(
                f"Keycloak {setting} must be {expected!r} for low-cardinality login metrics"
            )
    keycloak_healthcheck = _mapping(keycloak_service.get("healthcheck"))
    keycloak_health_test = " ".join(
        str(item) for item in _list(keycloak_healthcheck.get("test"))
    )
    if "/dev/tcp/127.0.0.1/9000" not in keycloak_health_test:
        errors.append("Keycloak healthcheck must use its management port 9000")

    for name, port in (("worker-mail", "9101"), ("worker-sub2", "9102")):
        service = _mapping(services.get(name))
        if port not in {str(item) for item in _list(service.get("expose"))}:
            errors.append(f"{name} must expose metrics port {port}")

    targets: dict[str, str] = {}
    for scrape in _list(prometheus.get("scrape_configs")):
        scrape_config = _mapping(scrape)
        static_configs = _list(scrape_config.get("static_configs"))
        static = _mapping(static_configs[0]) if static_configs else {}
        target_values = _list(static.get("targets"))
        if isinstance(scrape_config.get("job_name"), str) and target_values:
            targets[scrape_config["job_name"]] = str(target_values[0])
    if targets != EXPECTED_SCRAPE_TARGETS:
        errors.append("Prometheus scrape targets do not match compose services")
    for job_name, expected_target in EXPECTED_CONTROL_PLANE_SCRAPES.items():
        matching_scrapes = [
            _mapping(scrape)
            for scrape in _list(prometheus.get("scrape_configs"))
            if _mapping(scrape).get("job_name") == job_name
        ]
        scrape = matching_scrapes[0] if len(matching_scrapes) == 1 else {}
        static_configs = _list(scrape.get("static_configs"))
        static = _mapping(static_configs[0]) if len(static_configs) == 1 else {}
        tls_config = _mapping(scrape.get("tls_config"))
        if (
            len(matching_scrapes) != 1
            or scrape.get("scheme") != "https"
            or scrape.get("metrics_path") != "/metrics"
            or _list(static.get("targets")) != [expected_target]
            or tls_config.get("ca_file") != INTERNAL_CA_FILE
            or tls_config.get("server_name") != job_name
            or tls_config.get("insecure_skip_verify") is not False
            or tls_config.get("min_version") != "TLS12"
        ):
            errors.append(
                f"Prometheus {job_name} self-monitoring must use strict internal TLS"
            )
    keycloak_scrape = next(
        (
            _mapping(scrape)
            for scrape in _list(prometheus.get("scrape_configs"))
            if _mapping(scrape).get("job_name") == "keycloak"
        ),
        {},
    )
    keycloak_static_configs = _list(keycloak_scrape.get("static_configs"))
    keycloak_static = (
        _mapping(keycloak_static_configs[0])
        if len(keycloak_static_configs) == 1
        else {}
    )
    if (
        keycloak_scrape.get("metrics_path") != "/metrics"
        or _list(keycloak_static.get("targets")) != ["keycloak:9000"]
    ):
        errors.append("Keycloak scrape must use only keycloak:9000/metrics")

    alertmanager_targets: list[str] = []
    alerting = _mapping(prometheus.get("alerting"))
    for manager in _list(alerting.get("alertmanagers")):
        for static in _list(_mapping(manager).get("static_configs")):
            alertmanager_targets.extend(
                str(item) for item in _list(_mapping(static).get("targets"))
            )
    if alertmanager_targets != ["alertmanager:9093"]:
        errors.append("Prometheus must route alerts to alertmanager:9093")

    rules: dict[str, dict[str, Any]] = {}
    for group in _list(alerts.get("groups")):
        for rule in _list(_mapping(group).get("rules")):
            rule_data = _mapping(rule)
            name = rule_data.get("alert")
            if isinstance(name, str):
                if name in rules:
                    errors.append(f"Duplicate monitoring alert: {name}")
                rules[name] = rule_data
    for name in sorted(REQUIRED_ALERTS - set(rules)):
        errors.append(f"Missing monitoring alert: {name}")

    alertmanager_down = rules.get("PlatformAlertmanagerDown", {})
    if (
        _compact_expression(alertmanager_down.get("expr"))
        != EXPECTED_ALERTMANAGER_DOWN_EXPRESSION
        or alertmanager_down.get("for") != "2m"
        or _mapping(alertmanager_down.get("labels")).get("severity") != "page"
    ):
        errors.append(
            "PlatformAlertmanagerDown must page after alertmanager is down for 2m"
        )

    watchdog = rules.get("PlatformMonitoringWatchdog", {})
    if (
        _compact_expression(watchdog.get("expr")) != EXPECTED_WATCHDOG_EXPRESSION
        or _mapping(watchdog.get("labels")) != {"severity": "watchdog"}
        or "for" in watchdog
    ):
        errors.append(
            "PlatformMonitoringWatchdog must be an immediate low-cardinality constant heartbeat"
        )

    for name, expected_expression in EXPECTED_WORKER_ALERT_EXPRESSIONS.items():
        expression = _compact_expression(rules.get(name, {}).get("expr"))
        if expression != expected_expression:
            errors.append(
                f"{name} must detect its scrape target being down and its batch loop stalling"
            )

    keycloak_down = rules.get("PlatformKeycloakDown", {})
    if (
        _compact_expression(keycloak_down.get("expr"))
        != EXPECTED_KEYCLOAK_DOWN_EXPRESSION
        or keycloak_down.get("for") != "2m"
        or _mapping(keycloak_down.get("labels")).get("severity") != "page"
    ):
        errors.append(
            "PlatformKeycloakDown must page after keycloak:9000 is down for 2m"
        )

    keycloak_login_failures = rules.get("PlatformKeycloakLoginFailures", {})
    if (
        _compact_expression(keycloak_login_failures.get("expr"))
        != EXPECTED_KEYCLOAK_LOGIN_FAILURE_EXPRESSION
        or keycloak_login_failures.get("for") != "2m"
        or _mapping(keycloak_login_failures.get("labels")).get("severity") != "page"
    ):
        errors.append(
            "PlatformKeycloakLoginFailures must page after five non-empty login "
            "errors in five minutes persist for 2m"
        )

    mail_connector_unavailable = rules.get("PlatformMailConnectorUnavailable", {})
    if (
        _compact_expression(mail_connector_unavailable.get("expr"))
        != EXPECTED_MAIL_CONNECTOR_UNAVAILABLE_EXPRESSION
        or mail_connector_unavailable.get("for") != "2m"
        or _mapping(mail_connector_unavailable.get("labels")).get("severity") != "page"
    ):
        errors.append(
            "PlatformMailConnectorUnavailable must page after sustained connector failures"
        )

    five_xx = _compact_expression(rules.get("PlatformApi5xxRateElevated", {}).get("expr"))
    if five_xx != EXPECTED_API_5XX_EXPRESSION:
        errors.append(
            "PlatformApi5xxRateElevated must use the reviewed status_code rate expression"
        )
    if re.search(r'\bstatus\s*=~', five_xx):
        errors.append("PlatformApi5xxRateElevated must not use the obsolete status label")

    route = _mapping(alertmanager.get("route"))
    receiver_name = route.get("receiver")
    if not isinstance(receiver_name, str) or not receiver_name:
        errors.append("Alertmanager root route must name a receiver")
    if not {"alertname", "severity"}.issubset(
        {str(item) for item in _list(route.get("group_by"))}
    ):
        errors.append("Alertmanager must group alerts by alertname and severity")
    for key in ("group_wait", "group_interval", "repeat_interval"):
        if not isinstance(route.get(key), str) or not route[key]:
            errors.append(f"Alertmanager route is missing {key}")

    receivers = {
        item["name"]: item
        for raw in _list(alertmanager.get("receivers"))
        if (item := _mapping(raw)) and isinstance(item.get("name"), str)
    }
    receiver = _mapping(receivers.get(receiver_name))
    webhooks = _list(receiver.get("webhook_configs"))
    webhook = _mapping(webhooks[0]) if len(webhooks) == 1 else {}
    if len(webhooks) != 1:
        errors.append("Repository development Alertmanager file must contain one placeholder webhook")
    webhook_url = webhook.get("url")
    parsed = urlsplit(webhook_url) if isinstance(webhook_url, str) else None
    try:
        parsed_port = parsed.port if parsed is not None else None
    except ValueError:
        parsed_port = None
    if (
        parsed is None
        or parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed_port != 9
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        errors.append(
            "Repository development Alertmanager file must remain the credential-free loopback placeholder"
        )
    if webhook.get("send_resolved") is not True:
        errors.append("Alertmanager webhook must send resolved notifications")
    return errors


def _optional_native_checks(production_config: Path | None = None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    statuses: list[str] = []
    promtool = shutil.which("promtool")
    if promtool is None:
        statuses.append("promtool=not-found(static-validation-only)")
    else:
        result = subprocess.run(
            [promtool, "check", "rules", str(ALERTS)],
            capture_output=True,
            text=True,
            check=False,
        )
        statuses.append("promtool=ok" if result.returncode == 0 else "promtool=failed")
        if result.returncode != 0:
            errors.append("promtool rule validation failed: " + result.stderr.strip())

    amtool = shutil.which("amtool")
    if amtool is None:
        statuses.append("amtool=not-found(static-validation-only)")
    else:
        result = subprocess.run(
            [amtool, "check-config", str(ALERTMANAGER)],
            capture_output=True,
            text=True,
            check=False,
        )
        statuses.append("amtool=ok" if result.returncode == 0 else "amtool=failed")
        if result.returncode != 0:
            errors.append("amtool config validation failed: " + result.stderr.strip())
        if production_config is not None:
            result = subprocess.run(
                [amtool, "check-config", str(production_config)],
                capture_output=True,
                text=True,
                check=False,
            )
            statuses.append(
                "production-amtool=ok"
                if result.returncode == 0
                else "production-amtool=failed"
            )
            if result.returncode != 0:
                errors.append(
                    "production amtool config validation failed: " + result.stderr.strip()
                )
    return errors, statuses


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--production-alertmanager-config",
        help="Absolute path outside the repository to the production Alertmanager config.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    production_path: Path | None = None
    try:
        assets = load_assets()
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Monitoring asset load failed: {error}", file=sys.stderr)
        return 1
    try:
        env_example_text = load_stable_text(
            ENV_EXAMPLE,
            max_bytes=MAX_MONITORING_ENV_BYTES,
        )
    except (OSError, UnicodeError):
        print(
            "Monitoring asset load failed: "
            "Cannot inspect monitoring environment example",
            file=sys.stderr,
        )
        return 1
    errors = validate_monitoring_assets(*assets)
    errors.extend(validate_alertmanager_production_boundary(assets[0], env_example_text))
    if args.production_alertmanager_config:
        raw_path = args.production_alertmanager_config
        production_path = Path(raw_path)
        if not _is_absolute_host_path(raw_path):
            errors.append("Production Alertmanager config path must be absolute")
        elif not production_path.is_file():
            errors.append("Production Alertmanager config path must be an existing file")
        else:
            try:
                production_path.resolve().relative_to(ROOT.resolve())
            except ValueError:
                pass
            else:
                errors.append("Production Alertmanager config must be stored outside the repository")
            try:
                production_config = _load_document(production_path)
            except (OSError, ValueError, yaml.YAMLError) as error:
                errors.append(f"Production Alertmanager config load failed: {error}")
            else:
                errors.extend(validate_production_alertmanager_config(production_config))
    native_errors, statuses = _optional_native_checks(production_path)
    errors.extend(native_errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    scope = (
        "production-alertmanager-config=static-validated"
        if production_path is not None
        else "production-alertmanager-config=not-supplied"
    )
    print(
        "monitoring-assets-ok prometheus-rules=validated "
        "repository-alertmanager-placeholder=development-only "
        "production-alertmanager-mount=required-external "
        f"{scope} "
        + " ".join(statuses)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
