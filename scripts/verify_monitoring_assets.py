"""Verify monitoring assets and scrape targets are wired for the compose stack."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
PROMETHEUS = ROOT / "infra" / "prometheus" / "prometheus.yml"
ALERTS = ROOT / "infra" / "prometheus" / "alerts.yml"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return _fail("Compose services block is invalid")
    prometheus_service = services.get("prometheus")
    if not isinstance(prometheus_service, dict):
        return _fail("Compose is missing prometheus service")
    if "9090" not in ",".join(prometheus_service.get("ports", [])):
        return _fail("Prometheus must expose localhost port 9090")

    worker_mail = services.get("worker-mail")
    worker_sub2 = services.get("worker-sub2")
    if not isinstance(worker_mail, dict) or not isinstance(worker_sub2, dict):
        return _fail("Compose missing worker-mail or worker-sub2 service")
    for name, port in (("worker-mail", "9101"), ("worker-sub2", "9102")):
        ports = services[name].get("expose", [])
        if port not in ports:
            return _fail(f"{name} must expose metrics port {port}")

    prometheus = yaml.safe_load(PROMETHEUS.read_text(encoding="utf-8"))
    targets = {
        item["job_name"]: item["static_configs"][0]["targets"][0]
        for item in prometheus.get("scrape_configs", [])
    }
    expected_targets = {
        "api": "api:8000",
        "worker-mail": "worker-mail:9101",
        "worker-sub2": "worker-sub2:9102",
    }
    if targets != expected_targets:
        return _fail("Prometheus scrape targets do not match compose services")

    alerts = yaml.safe_load(ALERTS.read_text(encoding="utf-8"))
    alert_names = {
        rule["alert"]
        for group in alerts.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }
    for name in (
        "PlatformApiDown",
        "PlatformMailWorkerStalled",
        "PlatformSub2WorkerStalled",
        "PlatformUnknownUploadsPresent",
        "PlatformApi5xxRateElevated",
    ):
        if name not in alert_names:
            return _fail(f"Missing monitoring alert: {name}")

    print("monitoring-assets-ok prometheus-scrapes-and-alerts-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
