import copy
from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts.verify_monitoring_assets import (
    ENV_EXAMPLE,
    load_assets,
    main as monitoring_main,
    validate_alertmanager_production_boundary,
    validate_monitoring_assets,
    validate_production_alertmanager_config,
)


class MonitoringAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose, self.prometheus, self.alerts, self.alertmanager = load_assets()
        self.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def validate(self) -> list[str]:
        errors = validate_monitoring_assets(
            self.compose,
            self.prometheus,
            self.alerts,
            self.alertmanager,
        )
        errors.extend(
            validate_alertmanager_production_boundary(self.compose, self.env_example)
        )
        return errors

    @staticmethod
    def production_config() -> dict:
        return {
            "route": {
                "receiver": "operations-page",
                "group_by": ["alertname", "severity"],
                "group_wait": "30s",
                "group_interval": "5m",
                "repeat_interval": "4h",
                "routes": [
                    {
                        "matchers": ['severity="watchdog"'],
                        "receiver": "operations-heartbeat",
                        "group_interval": "1m",
                        "repeat_interval": "1m",
                    },
                    {
                        "matchers": ['severity="page"'],
                        "receiver": "operations-page",
                    },
                ],
            },
            "receivers": [
                {
                    "name": "operations-page",
                    "webhook_configs": [
                        {
                            "url": "https://alerts.example.com/v1/alertmanager",
                            "send_resolved": True,
                        }
                    ],
                },
                {
                    "name": "operations-heartbeat",
                    "webhook_configs": [
                        {
                            "url": "https://heartbeat.example.com/v1/watchdog",
                            "send_resolved": True,
                        }
                    ],
                },
            ],
        }

    def test_repository_monitoring_assets_are_wired_and_safe(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_legacy_5xx_status_label_is_rejected(self) -> None:
        self.alerts = copy.deepcopy(self.alerts)
        rules = self.alerts["groups"][0]["rules"]
        rule = next(item for item in rules if item["alert"] == "PlatformApi5xxRateElevated")
        rule["expr"] = 'sum(rate(platform_http_requests_total{status=~"5.."}[5m])) > 0.1'

        errors = self.validate()

        self.assertTrue(any("status_code" in error for error in errors), errors)
        self.assertTrue(any("obsolete status" in error for error in errors), errors)

    def test_repository_development_placeholder_cannot_become_external(self) -> None:
        self.alertmanager = copy.deepcopy(self.alertmanager)
        self.alertmanager["receivers"][0]["webhook_configs"][0]["url"] = (
            "https://alerts.example.com/v1/alertmanager"
        )

        errors = self.validate()

        self.assertTrue(
            any("development Alertmanager" in error for error in errors), errors
        )

    def test_reviewed_production_https_receiver_is_accepted(self) -> None:
        self.assertEqual(
            validate_production_alertmanager_config(self.production_config()), []
        )

    def test_production_mount_rejects_fallback_and_unsafe_bind(self) -> None:
        volumes = self.compose["services"]["alertmanager"]["volumes"]
        mount = next(
            item
            for item in volumes
            if isinstance(item, dict)
            and item.get("target") == "/etc/alertmanager/alertmanager.yml"
        )
        mutations = {
            "fallback": lambda value: value.update(
                source="${ALERTMANAGER_CONFIG_FILE:-./infra/prometheus/alertmanager.yml}"
            ),
            "writable": lambda value: value.update(read_only=False),
            "auto_create": lambda value: value["bind"].update(create_host_path=True),
            "not_bind": lambda value: value.update(type="volume"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                compose = copy.deepcopy(self.compose)
                candidate = next(
                    item
                    for item in compose["services"]["alertmanager"]["volumes"]
                    if isinstance(item, dict)
                    and item.get("target") == "/etc/alertmanager/alertmanager.yml"
                )
                mutate(candidate)
                errors = validate_alertmanager_production_boundary(
                    compose, self.env_example
                )
                self.assertTrue(errors)
        self.assertIsInstance(mount, dict)

    def test_env_example_rejects_relative_or_repository_placeholder(self) -> None:
        for value in (
            "./alertmanager.yml",
            "./infra/prometheus/alertmanager.yml",
            "/srv/email-platform/infra/prometheus/alertmanager.yml",
        ):
            with self.subTest(value=value):
                env_text = self.env_example.replace(
                    "/CHANGE_ME/alertmanager/alertmanager.yml", value
                )
                errors = validate_alertmanager_production_boundary(
                    self.compose, env_text
                )
                self.assertTrue(errors)

    def test_production_receiver_rejects_unsafe_urls(self) -> None:
        urls = (
            "http://alerts.example.com/v1/alertmanager",
            "https://127.0.0.1/alerts",
            "https://hooks.example.invalid/alerts",
            "https://user:secret@alerts.example.com/alerts",
            "https://alerts.example.com/alerts?token=secret",
        )
        for url in urls:
            with self.subTest(url=url):
                config = self.production_config()
                config["receivers"][0]["webhook_configs"][0]["url"] = url
                errors = validate_production_alertmanager_config(config)
                self.assertTrue(any("HTTPS URL" in error for error in errors), errors)

    def test_production_receiver_rejects_missing_page_route_or_resolution(self) -> None:
        no_page_route = self.production_config()
        no_page_route["route"]["routes"] = []
        no_resolved = self.production_config()
        no_resolved["receivers"][0]["webhook_configs"][0]["send_resolved"] = False
        inline_secret = self.production_config()
        inline_secret["receivers"][0]["webhook_configs"][0]["http_config"] = {
            "authorization": {"credentials": "secret"}
        }

        self.assertTrue(
            any(
                "severity=page" in error
                for error in validate_production_alertmanager_config(no_page_route)
            )
        )
        self.assertTrue(
            any(
                "resolved" in error
                for error in validate_production_alertmanager_config(no_resolved)
            )
        )
        self.assertTrue(
            any(
                "*_file" in error
                for error in validate_production_alertmanager_config(inline_secret)
            )
        )

    def test_production_preflight_requires_existing_absolute_external_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "alertmanager.yml"
            config_path.write_text(
                yaml.safe_dump(self.production_config(), sort_keys=False),
                encoding="utf-8",
            )
            self.assertEqual(
                monitoring_main(
                    ["--production-alertmanager-config", str(config_path)]
                ),
                0,
            )
        with redirect_stderr(io.StringIO()):
            self.assertEqual(
                monitoring_main(
                    ["--production-alertmanager-config", "alertmanager.yml"]
                ),
                1,
            )

    def test_malformed_5xx_expression_with_correct_label_is_rejected(self) -> None:
        self.alerts = copy.deepcopy(self.alerts)
        rules = self.alerts["groups"][0]["rules"]
        rule = next(item for item in rules if item["alert"] == "PlatformApi5xxRateElevated")
        rule["expr"] = 'platform_http_requests_total{status_code=~"5.."} > 0'

        errors = self.validate()

        self.assertTrue(any("reviewed status_code rate" in error for error in errors), errors)

    def test_control_plane_self_scrapes_require_strict_internal_tls(self) -> None:
        for job_name in ("prometheus", "alertmanager"):
            for mutation in (
                "missing_scrape",
                "http",
                "missing_ca",
                "wrong_sni",
                "skip_verify",
                "old_tls",
            ):
                with self.subTest(job=job_name, mutation=mutation):
                    prometheus = copy.deepcopy(self.prometheus)
                    scrapes = prometheus["scrape_configs"]
                    scrape = next(item for item in scrapes if item["job_name"] == job_name)
                    if mutation == "missing_scrape":
                        scrapes.remove(scrape)
                    elif mutation == "http":
                        scrape["scheme"] = "http"
                    elif mutation == "missing_ca":
                        scrape["tls_config"].pop("ca_file")
                    elif mutation == "wrong_sni":
                        scrape["tls_config"]["server_name"] = "api"
                    elif mutation == "skip_verify":
                        scrape["tls_config"]["insecure_skip_verify"] = True
                    else:
                        scrape["tls_config"]["min_version"] = "TLS11"

                    errors = validate_monitoring_assets(
                        self.compose,
                        prometheus,
                        self.alerts,
                        self.alertmanager,
                    )

                    self.assertTrue(
                        any(f"{job_name} self-monitoring" in error for error in errors),
                        errors,
                    )

    def test_alertmanager_down_alert_is_pageable_and_sustained(self) -> None:
        for mutation in (
            "missing",
            "wrong_job",
            "wrong_comparison",
            "missing_duration",
            "lower_severity",
        ):
            with self.subTest(mutation=mutation):
                alerts = copy.deepcopy(self.alerts)
                rules = alerts["groups"][0]["rules"]
                rule = next(
                    item for item in rules if item["alert"] == "PlatformAlertmanagerDown"
                )
                if mutation == "missing":
                    rules.remove(rule)
                elif mutation == "wrong_job":
                    rule["expr"] = 'up{job="prometheus"} == 0'
                elif mutation == "wrong_comparison":
                    rule["expr"] = 'up{job="alertmanager"} == 1'
                elif mutation == "missing_duration":
                    rule.pop("for")
                else:
                    rule["labels"]["severity"] = "ticket"

                errors = validate_monitoring_assets(
                    self.compose, self.prometheus, alerts, self.alertmanager
                )

                self.assertTrue(
                    any("PlatformAlertmanagerDown" in error for error in errors),
                    errors,
                )

    def test_watchdog_rejects_weak_or_high_cardinality_rules(self) -> None:
        for mutation in (
            "missing",
            "not_constant_true",
            "high_cardinality",
            "page_severity",
            "delayed",
        ):
            with self.subTest(mutation=mutation):
                alerts = copy.deepcopy(self.alerts)
                rules = alerts["groups"][0]["rules"]
                rule = next(
                    item
                    for item in rules
                    if item["alert"] == "PlatformMonitoringWatchdog"
                )
                if mutation == "missing":
                    rules.remove(rule)
                elif mutation == "not_constant_true":
                    rule["expr"] = "vector(0)"
                elif mutation == "high_cardinality":
                    rule["labels"]["instance"] = "{{ $labels.instance }}"
                elif mutation == "page_severity":
                    rule["labels"]["severity"] = "page"
                else:
                    rule["for"] = "10m"

                errors = validate_monitoring_assets(
                    self.compose, self.prometheus, alerts, self.alertmanager
                )

                self.assertTrue(
                    any("PlatformMonitoringWatchdog" in error for error in errors),
                    errors,
                )

    def test_production_watchdog_route_is_dedicated_safe_and_frequent(self) -> None:
        mutations = (
            "missing_route",
            "intercepted_by_prior_route",
            "broad_matcher",
            "default_receiver",
            "page_receiver",
            "continues",
            "slow_group_interval",
            "slow_repeat_interval",
            "http_receiver",
            "loopback_receiver",
            "placeholder_receiver",
            "inline_secret",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                config = self.production_config()
                heartbeat_route = config["route"]["routes"][0]
                heartbeat_receiver = config["receivers"][1]
                if mutation == "missing_route":
                    config["route"]["routes"].remove(heartbeat_route)
                elif mutation == "intercepted_by_prior_route":
                    config["route"]["routes"].insert(
                        0,
                        {"matchers": ['severity=~".*"'], "receiver": "operations-page"},
                    )
                elif mutation == "broad_matcher":
                    heartbeat_route["matchers"] = ['severity=~".*"']
                elif mutation in {"default_receiver", "page_receiver"}:
                    heartbeat_route["receiver"] = "operations-page"
                elif mutation == "continues":
                    heartbeat_route["continue"] = True
                elif mutation == "slow_group_interval":
                    heartbeat_route["group_interval"] = "5m"
                elif mutation == "slow_repeat_interval":
                    heartbeat_route["repeat_interval"] = "4h"
                elif mutation == "http_receiver":
                    heartbeat_receiver["webhook_configs"][0]["url"] = (
                        "http://heartbeat.example.com/watchdog"
                    )
                elif mutation == "loopback_receiver":
                    heartbeat_receiver["webhook_configs"][0]["url"] = (
                        "https://127.0.0.1/watchdog"
                    )
                elif mutation == "placeholder_receiver":
                    heartbeat_receiver["webhook_configs"][0]["url"] = (
                        "https://heartbeat.example.invalid/watchdog"
                    )
                else:
                    heartbeat_receiver["webhook_configs"][0]["http_config"] = {
                        "authorization": {"credentials": "secret"}
                    }

                errors = validate_production_alertmanager_config(config)

                self.assertTrue(
                    any("watchdog" in error.lower() for error in errors),
                    errors,
                )

    def test_worker_alerts_reject_target_and_stall_regressions(self) -> None:
        workers = {
            "PlatformMailWorkerStalled": ("worker-mail", "worker-sub2"),
            "PlatformSub2WorkerStalled": ("worker-sub2", "worker-mail"),
        }
        for alert_name, (job, wrong_job) in workers.items():
            stalled = (
                "time() - platform_worker_last_batch_timestamp_seconds"
                f'{{job="{job}"}} > 120'
            )
            mutations = {
                "removed_up_metric": f"vector(0) == 0 or {stalled}",
                "wrong_job": (
                    f'up{{job="{wrong_job}"}} == 0 or {stalled}'
                ),
                "wrong_up_comparison": f'up{{job="{job}"}} == 1 or {stalled}',
                "only_up": f'up{{job="{job}"}} == 0',
                "only_stalled": stalled,
            }
            for mutation, expression in mutations.items():
                with self.subTest(alert=alert_name, mutation=mutation):
                    alerts = copy.deepcopy(self.alerts)
                    rules = alerts["groups"][0]["rules"]
                    rule = next(item for item in rules if item["alert"] == alert_name)
                    rule["expr"] = expression

                    errors = validate_monitoring_assets(
                        self.compose,
                        self.prometheus,
                        alerts,
                        self.alertmanager,
                    )

                    self.assertTrue(
                        any(alert_name in error for error in errors),
                        errors,
                    )

    def test_keycloak_scrape_and_compose_monitoring_are_fail_closed(self) -> None:
        mutations = (
            "missing_scrape",
            "wrong_target",
            "wrong_metrics_path",
            "metrics_disabled",
            "health_disabled",
            "event_metrics_disabled",
            "event_metrics_too_broad",
            "client_and_idp_tags",
            "user_tag",
            "ip_tag",
            "wrong_health_port",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                compose = copy.deepcopy(self.compose)
                prometheus = copy.deepcopy(self.prometheus)
                scrapes = prometheus["scrape_configs"]
                keycloak_scrape = next(
                    item for item in scrapes if item["job_name"] == "keycloak"
                )
                if mutation == "missing_scrape":
                    scrapes.remove(keycloak_scrape)
                elif mutation == "wrong_target":
                    keycloak_scrape["static_configs"][0]["targets"] = [
                        "keycloak:8080"
                    ]
                elif mutation == "wrong_metrics_path":
                    keycloak_scrape["metrics_path"] = "/health"
                elif mutation == "metrics_disabled":
                    compose["services"]["keycloak"]["environment"][
                        "KC_METRICS_ENABLED"
                    ] = "false"
                elif mutation == "health_disabled":
                    compose["services"]["keycloak"]["environment"][
                        "KC_HEALTH_ENABLED"
                    ] = "false"
                elif mutation == "event_metrics_disabled":
                    compose["services"]["keycloak"]["environment"][
                        "KC_EVENT_METRICS_USER_ENABLED"
                    ] = "false"
                elif mutation == "event_metrics_too_broad":
                    compose["services"]["keycloak"]["environment"][
                        "KC_EVENT_METRICS_USER_EVENTS"
                    ] = "login,logout,refresh_token"
                elif mutation == "client_and_idp_tags":
                    compose["services"]["keycloak"]["environment"][
                        "KC_EVENT_METRICS_USER_TAGS"
                    ] = "realm,clientId,idp"
                elif mutation == "user_tag":
                    compose["services"]["keycloak"]["environment"][
                        "KC_EVENT_METRICS_USER_TAGS"
                    ] = "realm,user"
                elif mutation == "ip_tag":
                    compose["services"]["keycloak"]["environment"][
                        "KC_EVENT_METRICS_USER_TAGS"
                    ] = "realm,ip"
                else:
                    compose["services"]["keycloak"]["healthcheck"]["test"] = [
                        "CMD-SHELL",
                        "exec 3<>/dev/tcp/127.0.0.1/8080",
                    ]

                errors = validate_monitoring_assets(
                    compose,
                    prometheus,
                    self.alerts,
                    self.alertmanager,
                )

                self.assertTrue(
                    any(
                        "Keycloak" in error or "scrape targets" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_keycloak_down_alert_rejects_silent_or_low_priority_regressions(self) -> None:
        mutations = (
            "missing_alert",
            "wrong_job",
            "wrong_comparison",
            "missing_duration",
            "lower_severity",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                alerts = copy.deepcopy(self.alerts)
                rules = alerts["groups"][0]["rules"]
                rule = next(
                    item for item in rules if item["alert"] == "PlatformKeycloakDown"
                )
                if mutation == "missing_alert":
                    rules.remove(rule)
                elif mutation == "wrong_job":
                    rule["expr"] = 'up{job="api"} == 0'
                elif mutation == "wrong_comparison":
                    rule["expr"] = 'up{job="keycloak"} == 1'
                elif mutation == "missing_duration":
                    rule.pop("for")
                else:
                    rule["labels"]["severity"] = "ticket"

                errors = validate_monitoring_assets(
                    self.compose,
                    self.prometheus,
                    alerts,
                    self.alertmanager,
                )

                self.assertTrue(
                    any("PlatformKeycloakDown" in error for error in errors),
                    errors,
                )

    def test_keycloak_login_failure_alert_is_narrow_and_pageable(self) -> None:
        mutations = (
            "missing_alert",
            "wrong_event",
            "accepts_empty_error",
            "wrong_window",
            "missing_duration",
            "lower_severity",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                alerts = copy.deepcopy(self.alerts)
                rules = alerts["groups"][0]["rules"]
                rule = next(
                    item
                    for item in rules
                    if item["alert"] == "PlatformKeycloakLoginFailures"
                )
                if mutation == "missing_alert":
                    rules.remove(rule)
                elif mutation == "wrong_event":
                    rule["expr"] = rule["expr"].replace(
                        'event="login"', 'event="logout"'
                    )
                elif mutation == "accepts_empty_error":
                    rule["expr"] = rule["expr"].replace('error!=""', 'error=~".*"')
                elif mutation == "wrong_window":
                    rule["expr"] = rule["expr"].replace("[5m]", "[1h]")
                elif mutation == "missing_duration":
                    rule.pop("for")
                else:
                    rule["labels"]["severity"] = "ticket"

                errors = validate_monitoring_assets(
                    self.compose,
                    self.prometheus,
                    alerts,
                    self.alertmanager,
                )

                self.assertTrue(
                    any("PlatformKeycloakLoginFailures" in error for error in errors),
                    errors,
                )

    def test_mail_connector_alert_rejects_non_sustained_or_low_priority_regressions(self) -> None:
        mutations = (
            "missing_alert",
            "wrong_result",
            "single_failure",
            "missing_duration",
            "lower_severity",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                alerts = copy.deepcopy(self.alerts)
                rules = alerts["groups"][0]["rules"]
                rule = next(
                    item
                    for item in rules
                    if item["alert"] == "PlatformMailConnectorUnavailable"
                )
                if mutation == "missing_alert":
                    rules.remove(rule)
                elif mutation == "wrong_result":
                    rule["expr"] = rule["expr"].replace(
                        'result="connector_unavailable"', 'result="waiting"'
                    )
                elif mutation == "single_failure":
                    rule["expr"] = rule["expr"].replace(">= 3", ">= 1")
                elif mutation == "missing_duration":
                    rule.pop("for")
                else:
                    rule["labels"]["severity"] = "ticket"

                errors = validate_monitoring_assets(
                    self.compose,
                    self.prometheus,
                    alerts,
                    self.alertmanager,
                )

                self.assertTrue(
                    any("PlatformMailConnectorUnavailable" in error for error in errors),
                    errors,
                )

    def test_missing_prometheus_alertmanager_target_is_rejected(self) -> None:
        self.prometheus = copy.deepcopy(self.prometheus)
        self.prometheus["alerting"]["alertmanagers"][0]["static_configs"][0][
            "targets"
        ] = []

        errors = self.validate()

        self.assertTrue(any("alertmanager:9093" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
