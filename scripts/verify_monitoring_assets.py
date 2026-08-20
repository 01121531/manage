"""Validate Prometheus and Alertmanager wiring for the compose stack."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
PROMETHEUS = ROOT / "infra" / "prometheus" / "prometheus.yml"
ALERTS = ROOT / "infra" / "prometheus" / "alerts.yml"
ALERTMANAGER = ROOT / "infra" / "prometheus" / "alertmanager.yml"

EXPECTED_SCRAPE_TARGETS = {
    "api": "api:8000",
    "worker-mail": "worker-mail:9101",
    "worker-sub2": "worker-sub2:9102",
}
REQUIRED_ALERTS = {
    "PlatformApiDown",
    "PlatformMailWorkerStalled",
    "PlatformSub2WorkerStalled",
    "PlatformUnknownUploadsPresent",
    "PlatformApi5xxRateElevated",
}
EXPECTED_API_5XX_EXPRESSION = (
    'sum(rate(platform_http_requests_total{status_code=~"5.."}[5m])) > 0.1'
)


def _load_document(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
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
    mounts = [str(item) for item in _list(alertmanager_service.get("volumes"))]
    if not any(
        mount.endswith(":/etc/alertmanager/alertmanager.yml:ro")
        and "ALERTMANAGER_CONFIG_FILE" in mount
        for mount in mounts
    ):
        errors.append("Alertmanager must mount its configurable config read-only")
    prometheus_dependencies = _mapping(prometheus_service.get("depends_on"))
    if "alertmanager" not in prometheus_dependencies:
        errors.append("Prometheus must depend on alertmanager startup")

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
        errors.append("Default Alertmanager receiver must contain one placeholder webhook")
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
        errors.append("Default Alertmanager webhook must be the credential-free loopback placeholder")
    if webhook.get("send_resolved") is not True:
        errors.append("Alertmanager webhook must send resolved notifications")
    return errors


def _optional_native_checks() -> tuple[list[str], list[str]]:
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
    return errors, statuses


def main() -> int:
    try:
        assets = load_assets()
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Monitoring asset load failed: {error}", file=sys.stderr)
        return 1
    errors = validate_monitoring_assets(*assets)
    native_errors, statuses = _optional_native_checks()
    errors.extend(native_errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "monitoring-assets-ok prometheus-alertmanager-routing-validated "
        + " ".join(statuses)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
