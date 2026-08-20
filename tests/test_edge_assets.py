import copy
import unittest

from scripts.verify_edge_assets import load_assets, validate_edge_assets


class EdgeAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose, self.dockerfile, self.renderer, self.template, self.env_example = (
            load_assets()
        )

    def validate(self) -> list[str]:
        return validate_edge_assets(
            self.compose,
            self.dockerfile,
            self.renderer,
            self.template,
            self.env_example,
        )

    def test_repository_edge_is_non_root_and_tls_only(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_api_host_port_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["api"]["ports"] = ["8000:8000"]

        errors = self.validate()

        self.assertTrue(any("api must not publish" in error for error in errors), errors)

    def test_writable_private_key_mount_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        volumes = self.compose["services"]["edge"]["volumes"]
        volumes[1] = volumes[1].removesuffix(":ro")

        errors = self.validate()

        self.assertTrue(any("PLATFORM_TLS_KEY_FILE" in error for error in errors), errors)

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
