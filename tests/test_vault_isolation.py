import copy
import unittest

from scripts.verify_vault_isolation import load_assets, validate_vault_isolation


class VaultIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose, self.env_text, self.policies, self.bootstrap = load_assets()

    def validate(self) -> list[str]:
        return validate_vault_isolation(
            self.compose,
            self.env_text,
            self.policies,
            self.bootstrap,
        )

    def test_repository_vault_assets_are_isolated(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_shared_runtime_token_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["worker-mail"]["environment"][
            "PLATFORM_VAULT_TOKEN"
        ] = "${PLATFORM_VAULT_API_TOKEN:-}"

        errors = self.validate()

        self.assertTrue(any("worker-mail" in error for error in errors), errors)

    def test_cross_service_policy_path_is_rejected(self) -> None:
        self.policies = dict(self.policies)
        self.policies["email-platform-mail.hcl"] += (
            '\npath "secret/data/cards/*" { capabilities = ["read"] }\n'
        )

        errors = self.validate()

        self.assertTrue(any("email-platform-mail.hcl paths" in error for error in errors), errors)

    def test_sub2_policy_requires_card_path_for_upload_payload(self) -> None:
        self.policies = dict(self.policies)
        self.policies["email-platform-sub2.hcl"] = self.policies[
            "email-platform-sub2.hcl"
        ].replace('path "secret/data/cards/*"', 'path "secret/data/not-cards/*"')

        errors = self.validate()

        self.assertTrue(any("email-platform-sub2.hcl paths" in error for error in errors), errors)

    def test_sub2_mailbox_permission_is_rejected(self) -> None:
        self.policies = dict(self.policies)
        self.policies["email-platform-sub2.hcl"] += (
            '\npath "secret/data/mailboxes/*" { capabilities = ["read"] }\n'
        )

        errors = self.validate()

        self.assertTrue(any("email-platform-sub2.hcl paths" in error for error in errors), errors)

    def test_approle_secret_id_injection_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["api"]["environment"][
            "UNRELATED_ALIAS"
        ] = "${PLATFORM_VAULT_API_SECRET_ID:-}"

        errors = self.validate()

        self.assertTrue(any("AppRole credential" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
