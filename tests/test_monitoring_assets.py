import copy
import unittest

from scripts.verify_monitoring_assets import load_assets, validate_monitoring_assets


class MonitoringAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose, self.prometheus, self.alerts, self.alertmanager = load_assets()

    def validate(self) -> list[str]:
        return validate_monitoring_assets(
            self.compose,
            self.prometheus,
            self.alerts,
            self.alertmanager,
        )

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

    def test_external_default_webhook_is_rejected(self) -> None:
        self.alertmanager = copy.deepcopy(self.alertmanager)
        self.alertmanager["receivers"][0]["webhook_configs"][0]["url"] = (
            "https://hooks.example.invalid/alerts"
        )

        errors = self.validate()

        self.assertTrue(any("loopback placeholder" in error for error in errors), errors)

    def test_malformed_5xx_expression_with_correct_label_is_rejected(self) -> None:
        self.alerts = copy.deepcopy(self.alerts)
        rules = self.alerts["groups"][0]["rules"]
        rule = next(item for item in rules if item["alert"] == "PlatformApi5xxRateElevated")
        rule["expr"] = 'platform_http_requests_total{status_code=~"5.."} > 0'

        errors = self.validate()

        self.assertTrue(any("reviewed status_code rate" in error for error in errors), errors)

    def test_missing_prometheus_alertmanager_target_is_rejected(self) -> None:
        self.prometheus = copy.deepcopy(self.prometheus)
        self.prometheus["alerting"]["alertmanagers"][0]["static_configs"][0][
            "targets"
        ] = []

        errors = self.validate()

        self.assertTrue(any("alertmanager:9093" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
