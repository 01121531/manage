import unittest

from scripts.production_docker_environment import (
    FORBIDDEN_PRODUCTION_DOCKER_VARIABLES,
    ProductionDockerEnvironmentError,
    validate_production_docker_environment,
)


class ProductionDockerEnvironmentTests(unittest.TestCase):
    def test_forbidden_inventory_is_exact(self) -> None:
        self.assertEqual(
            FORBIDDEN_PRODUCTION_DOCKER_VARIABLES,
            (
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_CONFIG",
                "DOCKER_TLS",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            ),
        )

    def test_forbidden_variables_fail_by_presence_without_value_disclosure(self) -> None:
        for name in FORBIDDEN_PRODUCTION_DOCKER_VARIABLES:
            for value in ("1", "0", "", "operator-decoy"):
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(
                        ProductionDockerEnvironmentError,
                        "^production backup Docker environment preflight failed$",
                    ) as raised:
                        validate_production_docker_environment({name: value})
                    self.assertNotIn(name, str(raised.exception))
                    if value:
                        self.assertNotIn(value, str(raised.exception))

    def test_unrelated_environment_is_allowed(self) -> None:
        validate_production_docker_environment({"PATH": "reviewed"})


if __name__ == "__main__":
    unittest.main()
