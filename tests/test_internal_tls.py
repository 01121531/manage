import copy
import unittest

from scripts.verify_internal_tls import load_assets, validate_internal_tls


class InternalTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.compose,
            self.prometheus,
            self.env_text,
            self.prometheus_web,
            self.alertmanager_web,
            self.edge_template,
            self.web_config,
            _expiry_monitor_source,
            _runbook_text,
        ) = load_assets()

    def validate(self) -> list[str]:
        return validate_internal_tls(
            self.compose,
            self.prometheus,
            self.env_text,
            self.prometheus_web,
            self.alertmanager_web,
            self.edge_template,
            self.web_config,
        )

    def test_repository_internal_endpoints_use_verified_tls(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_plaintext_jwks_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["api"]["environment"]["PLATFORM_OIDC_JWKS_URL"] = (
            "http://keycloak:8080/realms/email-platform/protocol/openid-connect/certs"
        )

        errors = self.validate()

        self.assertTrue(any("api" in error and "JWKS" in error for error in errors), errors)

    def test_business_service_cannot_replace_public_trust_store(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["worker-sub2"]["environment"]["SSL_CERT_FILE"] = (
            "/run/secrets/internal-tls/ca.crt"
        )

        errors = self.validate()

        self.assertTrue(any("public trust store" in error for error in errors), errors)

    def test_writable_private_key_mount_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        key_mount = next(
            mount
            for mount in self.compose["services"]["worker-mail"]["volumes"]
            if isinstance(mount, dict) and mount.get("target", "").endswith("tls.key")
        )
        key_mount["read_only"] = False

        errors = self.validate()

        self.assertTrue(any("worker-mail" in error and "tls.key" in error for error in errors), errors)

    def test_shared_private_key_path_is_rejected(self) -> None:
        self.env_text = self.env_text.replace(
            "PLATFORM_INTERNAL_WEB_KEY_FILE=/CHANGE_ME/internal-tls/web/tls.key",
            "PLATFORM_INTERNAL_WEB_KEY_FILE=/CHANGE_ME/internal-tls/api/tls.key",
        )

        errors = self.validate()

        self.assertTrue(any("distinct private-key" in error for error in errors), errors)

    def test_public_edge_private_key_cannot_be_reused_internally(self) -> None:
        self.env_text = self.env_text.replace(
            "PLATFORM_INTERNAL_API_KEY_FILE=/CHANGE_ME/internal-tls/api/tls.key",
            "PLATFORM_INTERNAL_API_KEY_FILE=/run/secrets/email-platform-privkey.pem",
        )

        errors = self.validate()

        self.assertTrue(any("public edge private key" in error for error in errors), errors)

    def test_host_network_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["prometheus"]["network_mode"] = "host"

        errors = self.validate()

        self.assertTrue(any("host networking" in error for error in errors), errors)

    def test_keycloak_http_downgrade_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        command = self.compose["services"]["keycloak"]["command"]
        command[command.index("--http-enabled=false")] = "--http-enabled=true"
        self.compose["services"]["keycloak"]["environment"][
            "KC_HTTP_MANAGEMENT_SCHEME"
        ] = "http"

        errors = self.validate()

        self.assertTrue(any("Keycloak business HTTP" in error for error in errors), errors)
        self.assertTrue(any("KC_HTTP_MANAGEMENT_SCHEME" in error for error in errors), errors)

    def test_api_without_ssl_command_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        command = self.compose["services"]["api"]["command"]
        index = command.index("--ssl-keyfile")
        del command[index : index + 2]

        errors = self.validate()

        self.assertTrue(any("--ssl-keyfile" in error for error in errors), errors)

    def test_prometheus_client_cannot_drop_tls_controls(self) -> None:
        for mutation in ("scheme", "ca", "server_name", "skip_verify"):
            with self.subTest(mutation=mutation):
                prometheus = copy.deepcopy(self.prometheus)
                scrape = next(
                    item for item in prometheus["scrape_configs"] if item["job_name"] == "api"
                )
                if mutation == "scheme":
                    scrape["scheme"] = "http"
                elif mutation == "ca":
                    scrape["tls_config"].pop("ca_file")
                elif mutation == "server_name":
                    scrape["tls_config"]["server_name"] = "wrong-service"
                else:
                    scrape["tls_config"]["insecure_skip_verify"] = True
                errors = validate_internal_tls(
                    self.compose,
                    prometheus,
                    self.env_text,
                    self.prometheus_web,
                    self.alertmanager_web,
                    self.edge_template,
                    self.web_config,
                )
                self.assertTrue(any("Prometheus api scrape" in error for error in errors), errors)

    def test_alertmanager_server_without_certificate_is_rejected(self) -> None:
        self.alertmanager_web = self.alertmanager_web.replace(
            "  cert_file: /run/secrets/internal-tls/tls.crt\n", ""
        )

        errors = self.validate()

        self.assertTrue(any("Alertmanager web endpoint" in error for error in errors), errors)

    def test_alertmanager_tls_web_config_must_be_loaded(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["alertmanager"]["command"].remove(
            "--web.config.file=/etc/alertmanager/web.yml"
        )

        errors = self.validate()

        self.assertTrue(any("alertmanager must load" in error for error in errors), errors)

    def test_prometheus_alertmanager_target_is_exact(self) -> None:
        self.prometheus = copy.deepcopy(self.prometheus)
        self.prometheus["alerting"]["alertmanagers"][0]["static_configs"][0][
            "targets"
        ] = ["other:9093"]

        errors = self.validate()

        self.assertTrue(any("alertmanager:9093" in error for error in errors), errors)

    def test_plaintext_or_unverified_edge_upstream_is_rejected(self) -> None:
        for safe, unsafe in (
            ("proxy_pass https://active_api", "proxy_pass http://active_api"),
            ("proxy_ssl_verify on;", "proxy_ssl_verify off;"),
        ):
            with self.subTest(unsafe=unsafe):
                errors = validate_internal_tls(
                    self.compose,
                    self.prometheus,
                    self.env_text,
                    self.prometheus_web,
                    self.alertmanager_web,
                    self.edge_template.replace(safe, unsafe, 1),
                    self.web_config,
                )
                self.assertTrue(any("edge" in error for error in errors), errors)

    def test_private_key_material_is_rejected(self) -> None:
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.prometheus_web += f"\n# {private_key_marker}\n# not-a-key\n"

        errors = self.validate()

        self.assertTrue(any("never contain a private key" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
