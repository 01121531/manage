import copy
import unittest

from scripts.verify_edge_assets import load_assets, validate_edge_assets


class EdgeAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.compose,
            self.dev_compose,
            self.dockerfile,
            self.renderer,
            self.template,
            self.env_example,
            self.web_dockerfile,
            self.web_config,
            self.web_validator,
        ) = load_assets()

    def validate(self) -> list[str]:
        return validate_edge_assets(
            self.compose,
            self.dev_compose,
            self.dockerfile,
            self.renderer,
            self.template,
            self.env_example,
            self.web_dockerfile,
            self.web_config,
            self.web_validator,
        )

    def set_mount_read_only(self, service: str, target: str, read_only: bool) -> None:
        volumes = self.compose["services"][service]["volumes"]
        for index, mount in enumerate(volumes):
            if isinstance(mount, dict) and mount.get("target") == target:
                mount["read_only"] = read_only
                return
            if isinstance(mount, str) and f":{target}" in mount:
                volumes[index] = mount.removesuffix(":ro") + (":ro" if read_only else ":rw")
                return
        self.fail(f"missing test mount: {service}:{target}")

    def mount_source(self, service: str, target: str) -> str:
        volumes = self.compose["services"][service]["volumes"]
        for mount in volumes:
            if isinstance(mount, dict) and mount.get("target") == target:
                return mount["source"]
            if isinstance(mount, str) and f":{target}" in mount:
                return mount.split(f":{target}", 1)[0]
        self.fail(f"missing test mount: {service}:{target}")

    def set_mount_source(self, service: str, target: str, source: str) -> None:
        volumes = self.compose["services"][service]["volumes"]
        for index, mount in enumerate(volumes):
            if isinstance(mount, dict) and mount.get("target") == target:
                mount["source"] = source
                return
            if isinstance(mount, str) and f":{target}" in mount:
                _, suffix = mount.rsplit(f":{target}", 1)
                volumes[index] = f"{source}:{target}{suffix}"
                return
        self.fail(f"missing test mount: {service}:{target}")

    def structured_mount(self, service: str, target: str) -> dict:
        for mount in self.compose["services"][service]["volumes"]:
            if isinstance(mount, dict) and mount.get("target") == target:
                return mount
        self.fail(f"missing structured test mount: {service}:{target}")

    def replace_mount_with_short_form(self, service: str, target: str) -> None:
        volumes = self.compose["services"][service]["volumes"]
        for index, mount in enumerate(volumes):
            if isinstance(mount, dict) and mount.get("target") == target:
                volumes[index] = f"{mount['source']}:{target}:ro"
                return
            if isinstance(mount, str) and f":{target}" in mount:
                volumes[index] = mount.removesuffix(":rw")
                return
        self.fail(f"missing test mount: {service}:{target}")

    def test_repository_edge_is_non_root_and_tls_only(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_production_build_or_missing_development_build_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.dev_compose = copy.deepcopy(self.dev_compose)
        self.compose["services"]["edge"]["build"] = {
            "context": ".",
            "dockerfile": "infra/edge.Dockerfile",
        }
        del self.dev_compose["services"]["edge"]["build"]

        errors = self.validate()

        self.assertTrue(any("production edge" in error for error in errors), errors)
        self.assertTrue(any("development edge" in error for error in errors), errors)

    def test_api_host_port_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["api"]["ports"] = ["8000:8000"]

        errors = self.validate()

        self.assertTrue(any("api must not publish" in error for error in errors), errors)

    def test_writable_private_key_mount_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.set_mount_read_only("edge", "/etc/nginx/tls/privkey.pem", False)

        errors = self.validate()

        self.assertTrue(any("private key" in error and "read-only" in error for error in errors), errors)

    def test_short_form_public_tls_mount_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.replace_mount_with_short_form("edge", "/etc/nginx/tls/fullchain.pem")

        errors = self.validate()

        self.assertTrue(any("fullchain.pem" in error and "fail-closed" in error for error in errors), errors)

    def test_public_tls_mount_must_disable_host_path_creation(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        mount = self.structured_mount("edge", "/etc/nginx/tls/privkey.pem")
        mount["bind"]["create_host_path"] = True

        errors = self.validate()

        self.assertTrue(any("privkey.pem" in error and "create_host_path" in error for error in errors), errors)

    def test_public_tls_mount_must_be_a_bind(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        mount = self.structured_mount("edge", "/etc/nginx/tls/privkey.pem")
        mount["type"] = "volume"

        errors = self.validate()

        self.assertTrue(any("privkey.pem" in error and "fail-closed" in error for error in errors), errors)

    def test_public_tls_mount_source_is_exact_required_env(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        mount = self.structured_mount("edge", "/etc/nginx/tls/fullchain.pem")
        mount["source"] = "/tmp/unreviewed-certificate.pem"

        errors = self.validate()

        self.assertTrue(any("fullchain.pem" in error and "source" in error for error in errors), errors)

    def test_writable_web_private_key_mount_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.set_mount_read_only("web", "/run/secrets/internal-tls/tls.key", False)

        errors = self.validate()

        self.assertTrue(any("web TLS private key" in error and "read-only" in error for error in errors), errors)

    def test_shared_edge_and_web_private_key_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        edge_source = self.mount_source("edge", "/etc/nginx/tls/privkey.pem")
        self.set_mount_source("web", "/run/secrets/internal-tls/tls.key", edge_source)

        errors = self.validate()

        self.assertTrue(any("must not share" in error for error in errors), errors)

    def test_plaintext_upstream_is_rejected(self) -> None:
        self.template = self.template.replace(
            "proxy_pass https://active_api;",
            "proxy_pass http://active_api;",
            1,
        )

        errors = self.validate()

        self.assertTrue(any("must use HTTPS" in error for error in errors), errors)

    def test_api_request_body_limit_cannot_be_removed_or_weakened(self) -> None:
        for replacement in ("", "client_max_body_size 20m;"):
            with self.subTest(replacement=replacement):
                original = self.template
                self.template = original.replace(
                    "client_max_body_size 2m;",
                    replacement,
                    1,
                )

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("request body" in error for error in errors),
                    errors,
                )

    def test_api_and_identity_rate_limits_cannot_be_removed_or_weakened(self) -> None:
        api_zone = (
            "limit_req_zone $binary_remote_addr zone=platform_api:10m rate=10r/s;"
        )
        identity_zone = (
            "limit_req_zone $binary_remote_addr zone=platform_identity:10m rate=10r/s;"
        )
        api_limit = "limit_req zone=platform_api burst=20 nodelay;"
        identity_limit = "limit_req zone=platform_identity burst=20 nodelay;"
        self.assertEqual(self.template.count(api_zone), 1)
        self.assertEqual(self.template.count(identity_zone), 1)
        self.assertEqual(self.template.count(api_limit), 1)
        self.assertEqual(self.template.count(identity_limit), 1)

        mutations = (
            (api_zone, ""),
            (identity_zone, ""),
            (api_zone, api_zone.replace("rate=10r/s", "rate=1000r/s")),
            (
                identity_zone,
                identity_zone.replace("rate=10r/s", "rate=1000r/s"),
            ),
            (api_limit, ""),
            (identity_limit, ""),
            (api_limit, api_limit.replace("burst=20", "burst=2000")),
            (identity_limit, identity_limit.replace("burst=20", "burst=2000")),
            (identity_limit, api_limit),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                original = self.template
                self.template = original.replace(old, new, 1)

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("rate limit" in error for error in errors),
                    errors,
                )

    def test_edge_rate_limit_rejections_use_http_429(self) -> None:
        for replacement in ("", "limit_req_status 503;"):
            with self.subTest(replacement=replacement):
                original = self.template
                self.template = original.replace(
                    "limit_req_status 429;",
                    replacement,
                    1,
                )

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("429" in error and "rate limit" in error for error in errors),
                    errors,
                )

    def test_rate_limit_cannot_be_dry_run_or_trust_unreviewed_client_ip(self) -> None:
        mutations = (
            "limit_req_dry_run on;\n",
            "set_real_ip_from 0.0.0.0/0;\nreal_ip_header X-Forwarded-For;\n",
            "real_ip_recursive on;\n",
            "listen 8443 ssl http2 proxy_protocol;\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                original = self.template
                self.template = mutation + original

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("client IP" in error or "dry run" in error for error in errors),
                    errors,
                )

    def test_edge_generated_api_errors_are_fixed_safe_json(self) -> None:
        required = (
            "error_page 413 = @api_request_too_large;",
            "error_page 429 = @api_rate_limited;",
            "error_page 502 504 = @api_upstream_unavailable;",
            "error_page 429 = @identity_rate_limited;",
            "proxy_intercept_errors on;",
            "location @api_request_too_large {",
            "location @api_rate_limited {",
            "location @api_upstream_unavailable {",
            "location @identity_rate_limited {",
            'add_header Retry-After "1" always;',
            '"code":"request_too_large"',
            '"code":"rate_limited"',
            '"code":"service_unavailable"',
            '"recovery_hint"',
            '"trace_id":"$request_id"',
            'add_header X-Trace-Id "$request_id" always;',
            '"error":"rate_limited"',
            '"error_description"',
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.template)
        self.assertEqual(
            self.template.count('add_header Retry-After "1" always;'),
            2,
        )
        self.assertEqual(self.template.count('"trace_id":"$request_id"'), 4)
        self.assertEqual(
            self.template.count('add_header X-Trace-Id "$request_id" always;'),
            3,
        )
        self.assertEqual(self.template.count("proxy_intercept_errors on;"), 1)

        mutations = (
            ("error_page 413 = @api_request_too_large;", ""),
            ("error_page 429 = @api_rate_limited;", ""),
            ("error_page 502 504 = @api_upstream_unavailable;", ""),
            (
                "error_page 502 504 = @api_upstream_unavailable;",
                "error_page 502 503 504 = @api_upstream_unavailable;",
            ),
            ("error_page 429 = @identity_rate_limited;", ""),
            ("proxy_intercept_errors on;", ""),
            ("default_type application/json;", "default_type text/html;"),
            ('add_header Retry-After "1" always;', ""),
            ('add_header Retry-After "1" always;', 'add_header Retry-After "0";'),
            ('"code":"request_too_large"', '"code":"raw_upstream_error"'),
            ('"recovery_hint"', '"raw_details"'),
            ('"trace_id":"$request_id"', '"trace_id":"$http_x_trace_id"'),
            ('add_header X-Trace-Id "$request_id" always;', ''),
            ("Request body too large", "$request_body"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                original = self.template
                self.template = original.replace(old, new, 1)

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("safe edge error" in error for error in errors),
                    errors,
                )

        for mutation in (
            "proxy_intercept_errors on;\n",
            "recursive_error_pages on;\n",
        ):
            with self.subTest(mutation=mutation):
                original = self.template
                self.template = mutation + original
                errors = self.validate()
                self.template = original
                self.assertTrue(
                    any("safe edge error" in error for error in errors),
                    errors,
                )

        original = self.template
        self.template = original.replace(
            "return 413 '{\"error\"",
            "rewrite ^ /api/ last;\n        return 413 '{\"error\"",
            1,
        )
        errors = self.validate()
        self.template = original
        self.assertTrue(
            any("safe edge error" in error for error in errors),
            errors,
        )

    def test_normal_responses_retain_exact_hsts_and_csp(self) -> None:
        hsts = (
            'add_header Strict-Transport-Security '
            '"max-age=31536000; includeSubDomains" always;'
        )
        strict_csp = (
            'add_header Content-Security-Policy "default-src \'none\'; '
            'frame-ancestors \'none\'; base-uri \'none\'" always;'
        )
        web_csp = (
            'add_header Content-Security-Policy "default-src \'self\'; '
            "connect-src 'self' https://identity.${PLATFORM_DOMAIN}; "
            "img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self' https://identity.${PLATFORM_DOMAIN}\" always;"
        )
        identity_csp = (
            'add_header Content-Security-Policy "default-src \'self\' '
            "'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'\" always;"
        )
        mutations = (
            ("location /api/ {", hsts),
            ("location /api/ {", strict_csp),
            ("server_name ${PLATFORM_DOMAIN};", web_csp),
            ("server_name identity.${PLATFORM_DOMAIN};", hsts),
            ("server_name identity.${PLATFORM_DOMAIN};", identity_csp),
        )
        for anchor, header in mutations:
            with self.subTest(anchor=anchor, header=header):
                original = self.template
                anchor_start = original.index(anchor)
                suffix = original[anchor_start:]
                self.assertIn(header, suffix)
                self.template = (
                    original[:anchor_start] + suffix.replace(header, "", 1)
                )

                errors = self.validate()
                self.template = original

                self.assertTrue(
                    any("normal responses" in error for error in errors),
                    errors,
                )

    def test_disabled_upstream_verification_is_rejected(self) -> None:
        self.template = self.template.replace("proxy_ssl_verify on;", "proxy_ssl_verify off;", 1)

        errors = self.validate()

        self.assertTrue(any("verification must never be disabled" in error for error in errors), errors)

    def test_missing_upstream_ca_is_rejected(self) -> None:
        self.template = self.template.replace(
            "proxy_ssl_trusted_certificate /run/secrets/internal-tls/ca.crt;",
            "",
            1,
        )

        errors = self.validate()

        self.assertTrue(any("trusted_certificate" in error for error in errors), errors)

    def test_missing_upstream_server_name_is_rejected(self) -> None:
        self.template = self.template.replace(
            "proxy_ssl_name $active_api_tls_name;", "", 1
        )

        errors = self.validate()

        self.assertTrue(
            any("proxy_ssl_name $active_api_tls_name" in error for error in errors),
            errors,
        )

    def test_missing_upstream_tls_protocol_floor_is_rejected(self) -> None:
        self.template = self.template.replace(
            "proxy_ssl_protocols TLSv1.2 TLSv1.3;",
            "proxy_ssl_protocols TLSv1;",
            1,
        )

        errors = self.validate()

        self.assertTrue(any("proxy_ssl_protocols" in error for error in errors), errors)

    def test_plaintext_web_listener_is_rejected(self) -> None:
        self.web_config = self.web_config.replace("listen 8443 ssl;", "listen 8080;", 1)

        errors = self.validate()

        self.assertTrue(any("plaintext listener" in error for error in errors), errors)

    def test_broad_environment_renderer_is_rejected(self) -> None:
        self.renderer = self.renderer.replace(
            'sed "s/\\${PLATFORM_DOMAIN}/${PLATFORM_DOMAIN}/g"',
            "envsubst",
        )

        errors = self.validate()

        self.assertTrue(any("broad environment substitution" in error for error in errors), errors)

    def test_privileged_container_https_port_is_rejected(self) -> None:
        self.template = self.template.replace("listen 8443 ssl http2;", "listen 443 ssl http2;")

        errors = self.validate()

        self.assertTrue(any("privileged container ports" in error for error in errors), errors)

    def test_missing_unknown_host_default_servers_is_rejected(self) -> None:
        self.template = self.template.replace(" default_server", "")

        errors = self.validate()

        self.assertTrue(
            any("default_server" in error or "fail closed" in error for error in errors),
            errors,
        )

    def test_wildcard_business_host_is_rejected(self) -> None:
        self.template = self.template.replace(
            "server_name ${PLATFORM_DOMAIN};",
            "server_name _;",
            1,
        )

        errors = self.validate()

        self.assertTrue(any("fail closed" in error for error in errors), errors)

    def test_root_edge_user_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["edge"]["user"] = "0:0"

        errors = self.validate()

        self.assertTrue(any("non-root" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
