import copy
import unittest

from scripts.verify_container_logging import (
    REQUIRED_SERVICES,
    REVIEWED_POLICY,
    load_compose,
    validate_container_logging,
)


class ContainerLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = load_compose()

    def test_repository_uses_one_bounded_policy_for_every_production_service(self) -> None:
        self.assertEqual(validate_container_logging(self.compose), [])
        policy = self.compose["x-platform-logging"]
        self.assertEqual(policy, REVIEWED_POLICY)
        for name in REQUIRED_SERVICES:
            self.assertIs(self.compose["services"][name]["logging"], policy)
        self.assertNotIn("logging", self.compose["services"]["vault"])

    def test_missing_logging_is_rejected_for_every_production_service(self) -> None:
        for name in sorted(REQUIRED_SERVICES):
            with self.subTest(service=name):
                compose = copy.deepcopy(self.compose)
                compose["services"][name].pop("logging")
                errors = validate_container_logging(compose)
                self.assertTrue(any(name in error for error in errors), errors)

    def test_inline_or_overridden_service_policy_is_rejected(self) -> None:
        mutations = (
            {"driver": "json-file", "options": {"max-size": "10m", "max-file": "5"}},
            {"driver": "none", "options": {"max-size": "10m", "max-file": "5"}},
            {"driver": "syslog", "options": {"max-size": "10m", "max-file": "5"}},
            {"options": {"max-size": "10m", "max-file": "5"}},
            {"driver": "json-file", "options": {"max-size": "20m", "max-file": "5"}},
        )
        for logging in mutations:
            with self.subTest(logging=logging):
                compose = copy.deepcopy(self.compose)
                compose["services"]["api"]["logging"] = logging
                errors = validate_container_logging(compose)
                self.assertTrue(any("api" in error for error in errors), errors)

    def test_unbounded_or_wrong_typed_options_are_rejected(self) -> None:
        mutations = (
            {"max-file": "5"},
            {"max-size": "10m"},
            {"max-size": "0", "max-file": "5"},
            {"max-size": "10m", "max-file": "0"},
            {"max-size": 10, "max-file": "5"},
            {"max-size": "10m", "max-file": 5},
            {"max-size": "1g", "max-file": "100"},
        )
        for options in mutations:
            with self.subTest(options=options):
                compose = copy.deepcopy(self.compose)
                compose["services"]["worker-mail"]["logging"] = {
                    "driver": "json-file",
                    "options": options,
                }
                errors = validate_container_logging(compose)
                self.assertTrue(any("worker-mail" in error for error in errors), errors)

    def test_anchor_drift_and_new_unprotected_service_are_rejected(self) -> None:
        drifted = copy.deepcopy(self.compose)
        drifted["x-platform-logging"]["options"]["max-size"] = "100m"
        self.assertTrue(validate_container_logging(drifted))

        extra = copy.deepcopy(self.compose)
        extra["services"]["future-service"] = {"image": "example.invalid/future"}
        errors = validate_container_logging(extra)
        self.assertTrue(any("future-service" in error for error in errors), errors)

    def test_vault_exception_cannot_expand_beyond_vault_dev(self) -> None:
        for profiles in (None, [], ["production"], ["vault-dev", "production"], "vault-dev"):
            with self.subTest(profiles=profiles):
                compose = copy.deepcopy(self.compose)
                vault = compose["services"]["vault"]
                if profiles is None:
                    vault.pop("profiles")
                else:
                    vault["profiles"] = profiles
                errors = validate_container_logging(compose)
                self.assertTrue(any("vault-dev" in error for error in errors), errors)

        extra_exception = copy.deepcopy(self.compose)
        extra_exception["services"]["future-dev"] = {
            "image": "example.invalid/dev",
            "profiles": ["vault-dev"],
        }
        errors = validate_container_logging(extra_exception)
        self.assertTrue(any("future-dev" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
