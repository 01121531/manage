from __future__ import annotations

import copy
import json
import unittest

from scripts.verify_vault_broker_contract import (
    broker_contract_errors,
    load_assets,
)


class VaultBrokerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract_text, self.policies, self.configure = load_assets()

    def validate(
        self,
        *,
        contract_text: str | None = None,
        policies: dict[str, str] | None = None,
        configure: str | None = None,
    ) -> list[str]:
        return broker_contract_errors(
            self.contract_text if contract_text is None else contract_text,
            self.policies if policies is None else policies,
            self.configure if configure is None else configure,
        )

    def mutate_contract(self, mutate: object) -> str:
        contract = json.loads(self.contract_text)
        mutate(contract)  # type: ignore[operator]
        return json.dumps(contract)

    def test_repository_contract_is_closed_and_preflight_only(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_production_acceptance_and_rotation_cannot_be_faked(self) -> None:
        mutations = (
            lambda value: value.__setitem__("production_acceptance", True),
            lambda value: value["rotation_sequence"].pop(),
            lambda value: value["rotation_sequence"].reverse(),
            lambda value: value["required_target_evidence"].pop(),
            lambda value: value.__setitem__("revocation_actor", "routine-issuer"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assertTrue(self.validate(contract_text=self.mutate_contract(mutate)))

    def test_service_identity_sink_ttl_and_deny_matrix_are_exact(self) -> None:
        def cross_bind(value: dict[str, object]) -> None:
            services = value["services"]
            services[0]["issuer_policy"] = services[1]["issuer_policy"]

        def duplicate_sink(value: dict[str, object]) -> None:
            services = value["services"]
            services[1]["token_sink_directory_variable"] = services[0][
                "token_sink_directory_variable"
            ]

        def weaken_ttl(value: dict[str, object]) -> None:
            value["services"][2]["token_ttl_seconds"] = 7200

        def remove_deny(value: dict[str, object]) -> None:
            value["services"][0]["denied_probe_paths"].remove(
                "auth/token/revoke-accessor"
            )

        for mutate in (cross_bind, duplicate_sink, weaken_ttl, remove_deny):
            with self.subTest(mutate=mutate):
                self.assertTrue(self.validate(contract_text=self.mutate_contract(mutate)))

    def test_contract_cannot_contain_raw_credentials_or_accessors(self) -> None:
        for key in ("role_id", "secret_id", "token", "token_accessor"):
            with self.subTest(key=key):
                def add_value(value: dict[str, object], field: str = key) -> None:
                    value["services"][0][field] = "SENSITIVE_VALUE"

                errors = self.validate(contract_text=self.mutate_contract(add_value))
                self.assertTrue(errors)

    def test_issuer_policy_paths_and_capabilities_are_exact(self) -> None:
        filename = "email-platform-broker-issuer-api.hcl"
        mutations = (
            self.policies[filename].replace(
                "email-platform-api-cards/role-id",
                "email-platform-mail/role-id",
                1,
            ),
            self.policies[filename].replace(
                "email-platform-api-cards/role-id",
                "*/role-id",
                1,
            ),
            self.policies[filename].replace('["read"]', '["read", "list"]', 1),
            self.policies[filename]
            + '\npath "auth/token/revoke-accessor" { capabilities = ["update"] }\n',
            self.policies[filename]
            + '\npath "secret/data/cards/*" { capabilities = ["read"] }\n',
        )
        for source in mutations:
            with self.subTest(source=source):
                policies = copy.deepcopy(self.policies)
                policies[filename] = source
                errors = self.validate(policies=policies)
                self.assertTrue(any(filename in error for error in errors), errors)

    def test_exactly_three_issuer_policy_files_are_required(self) -> None:
        policies = copy.deepcopy(self.policies)
        policies.pop("email-platform-broker-issuer-mail.hcl")
        self.assertTrue(self.validate(policies=policies))
        policies = copy.deepcopy(self.policies)
        policies["backdoor.hcl"] = 'path "*" { capabilities = ["sudo"] }\n'
        self.assertTrue(self.validate(policies=policies))

    def test_policy_helper_controls_cannot_be_removed_or_bypassed(self) -> None:
        mutations = (
            self.configure.replace('case "$VAULT_ADDR" in', 'case "https://$VAULT_ADDR" in', 1),
            self.configure.replace(
                'vault read -format=json "sys/policies/acl/$policy_name"',
                'vault read "sys/policies/acl/$policy_name"',
                1,
            ),
            self.configure.replace('cmp -s "$local_copy" "$remote_copy"', "true", 1),
            self.configure
            + '\nvault policy write backdoor "$script_dir/policies/email-platform-broker-issuer-api.hcl"\n',
            self.configure + '\nvault write auth/approle/role/backdoor token_policies=root\n',
            self.configure + '\nvault read auth/approle/role/email-platform-mail/role-id\n',
            self.configure + '\nvault policy delete email-platform-broker-issuer-api\n',
        )
        for configure in mutations:
            with self.subTest(configure=configure):
                self.assertTrue(self.validate(configure=configure))


if __name__ == "__main__":
    unittest.main()
