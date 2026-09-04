import copy
import unittest

from scripts.verify_vault_isolation import load_assets, validate_vault_isolation


class VaultIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.compose,
            self.env_text,
            self.policies,
            self.bootstrap,
            self.audit_config,
        ) = load_assets()

    def validate(self) -> list[str]:
        return validate_vault_isolation(
            self.compose,
            self.env_text,
            self.policies,
            self.bootstrap,
            self.audit_config,
        )

    def test_repository_vault_assets_are_isolated(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_managed_services_require_the_exact_vault_address_input(self) -> None:
        expected = "${PLATFORM_VAULT_ADDR:?set PLATFORM_VAULT_ADDR in .env}"
        mutations = (
            None,
            "",
            "${PLATFORM_VAULT_ADDR:-}",
            "${PLATFORM_VAULT_ADDR?set PLATFORM_VAULT_ADDR in .env}",
            "http://vault:8200",
            "https://vault.production.internal",
        )
        for service in ("api", "worker-mail", "worker-sub2"):
            self.assertEqual(
                self.compose["services"][service]["environment"][
                    "PLATFORM_VAULT_ADDR"
                ],
                expected,
            )
            for mutation in mutations:
                with self.subTest(service=service, mutation=mutation):
                    compose = copy.deepcopy(self.compose)
                    environment = compose["services"][service]["environment"]
                    if mutation is None:
                        environment.pop("PLATFORM_VAULT_ADDR")
                    else:
                        environment["PLATFORM_VAULT_ADDR"] = mutation
                    errors = validate_vault_isolation(
                        compose,
                        self.env_text,
                        self.policies,
                        self.bootstrap,
                        self.audit_config,
                    )
                    self.assertTrue(
                        any("Vault address contract" in error for error in errors),
                        errors,
                    )

    def test_non_consumers_cannot_receive_or_alias_the_vault_address(self) -> None:
        for name, value in (
            ("PLATFORM_VAULT_ADDR", "${PLATFORM_VAULT_ADDR:?set PLATFORM_VAULT_ADDR in .env}"),
            ("UNRELATED_ALIAS", "${PLATFORM_VAULT_ADDR:?set PLATFORM_VAULT_ADDR in .env}"),
        ):
            with self.subTest(name=name):
                compose = copy.deepcopy(self.compose)
                compose["services"]["keycloak"]["environment"][name] = value
                errors = validate_vault_isolation(
                    compose,
                    self.env_text,
                    self.policies,
                    self.bootstrap,
                    self.audit_config,
                )
                self.assertTrue(
                    any("must not receive" in error for error in errors),
                    errors,
                )

    def test_env_example_keeps_one_empty_vault_address_input(self) -> None:
        for env_text in (
            self.env_text.replace("PLATFORM_VAULT_ADDR=\n", "", 1),
            self.env_text.replace(
                "PLATFORM_VAULT_ADDR=",
                "PLATFORM_VAULT_ADDR=https://vault.production.internal",
                1,
            ),
            self.env_text + "\nPLATFORM_VAULT_ADDR=\n",
        ):
            with self.subTest():
                errors = validate_vault_isolation(
                    self.compose,
                    env_text,
                    self.policies,
                    self.bootstrap,
                    self.audit_config,
                )
                self.assertTrue(
                    any("one empty PLATFORM_VAULT_ADDR" in error for error in errors),
                    errors,
                )

    def test_shared_runtime_token_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        self.compose["services"]["worker-mail"]["environment"][
            "PLATFORM_VAULT_TOKEN"
        ] = "${PLATFORM_VAULT_API_TOKEN:-}"

        errors = self.validate()

        self.assertTrue(any("worker-mail" in error for error in errors), errors)

    def test_cross_service_token_directory_is_rejected(self) -> None:
        self.compose = copy.deepcopy(self.compose)
        vault_token_volume = next(
            volume
            for volume in self.compose["services"]["worker-mail"]["volumes"]
            if volume.get("target") == "/run/secrets/email-platform-vault"
        )
        vault_token_volume["source"] = (
            "${PLATFORM_VAULT_API_TOKEN_DIR:?set PLATFORM_VAULT_API_TOKEN_DIR in .env}"
        )

        errors = self.validate()

        self.assertTrue(any("worker-mail Vault token directory" in error for error in errors), errors)

    def test_duplicate_documented_token_directories_are_rejected(self) -> None:
        self.env_text = self.env_text.replace(
            "PLATFORM_VAULT_MAIL_TOKEN_DIR=/CHANGE_ME/vault-agent/mail",
            "PLATFORM_VAULT_MAIL_TOKEN_DIR=/CHANGE_ME/vault-agent/api",
        )

        errors = self.validate()

        self.assertIn("Per-service Vault token directories must be distinct", errors)

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

    def test_sub2_policy_requires_exclusive_admin_key_path(self) -> None:
        original_policies = dict(self.policies)
        self.policies = dict(self.policies)
        self.policies["email-platform-sub2.hcl"] = self.policies[
            "email-platform-sub2.hcl"
        ].replace(
            'path "secret/data/sub2/admin" {\n  capabilities = ["read"]\n}\n',
            "",
        )
        errors = self.validate()
        self.assertTrue(
            any("email-platform-sub2.hcl paths" in error for error in errors),
            errors,
        )

        self.policies = original_policies
        self.policies["email-platform-api-cards.hcl"] += (
            '\npath "secret/data/sub2/admin" {\n'
            '  capabilities = ["read"]\n'
            '}\n'
        )
        errors = self.validate()
        self.assertTrue(
            any("email-platform-api-cards.hcl paths" in error for error in errors),
            errors,
        )

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

    def test_approle_helper_requires_exact_role_bindings(self) -> None:
        mutations = (
            self.bootstrap.replace(
                "configure_role \\\n  email-platform-mail \\\n  email-platform-mail \\\n  \"$script_dir/policies/email-platform-mail.hcl\"\n",
                "",
                1,
            ),
            self.bootstrap.replace(
                "  email-platform-mail \\\n  email-platform-mail \\\n  \"$script_dir/policies/email-platform-mail.hcl\"",
                "  email-platform-api-cards \\\n  email-platform-mail \\\n  \"$script_dir/policies/email-platform-mail.hcl\"",
                1,
            ),
            self.bootstrap.replace(
                "  email-platform-mail \\\n  \"$script_dir/policies/email-platform-mail.hcl\"",
                "  email-platform-api-cards \\\n  \"$script_dir/policies/email-platform-mail.hcl\"",
                1,
            ),
            self.bootstrap
            + "\nconfigure_role email-platform-backdoor root \"$script_dir/policies/email-platform-mail.hcl\"\n",
        )
        for bootstrap in mutations:
            with self.subTest():
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    bootstrap,
                    self.audit_config,
                )
                self.assertTrue(any("exactly three reviewed roles" in error for error in errors), errors)

    def test_approle_helper_requires_structured_target_state_readback(self) -> None:
        mutations = {
            'case "$VAULT_ADDR" in': 'case "https://$VAULT_ADDR" in',
            "command -v jq": "command -v grep",
            'vault read -format=json "auth/approle/role/$role_name"':
                'vault read "auth/approle/role/$role_name"',
            ".token_policies == [$policy]": ".token_policies | index($policy)",
            ".local_secret_ids == false": ".local_secret_ids != true",
            ".token_period == 0": ".token_period >= 0",
            ".token_explicit_max_ttl == 3600": ".token_explicit_max_ttl <= 3600",
            ".secret_id_bound_cidrs == []": ".secret_id_bound_cidrs != null",
            ".token_bound_cidrs == []": ".token_bound_cidrs != null",
            "(($role.alias_metadata // {}) == {})": "($role.alias_metadata != null)",
        }
        for safe, unsafe in mutations.items():
            with self.subTest(safe=safe):
                bootstrap = self.bootstrap.replace(safe, unsafe, 1)
                self.assertNotEqual(bootstrap, self.bootstrap)
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    bootstrap,
                    self.audit_config,
                )
                self.assertTrue(any("target state" in error for error in errors), errors)

    def test_approle_helper_rejects_fail_open_predicates_and_comment_masking(self) -> None:
        mutations = (
            self.bootstrap.replace(
                "and ($role.token_policies == [$policy])",
                "and (($role.token_policies == [$policy]) or true)",
                1,
            ),
            self.bootstrap.replace(
                "and ($role.token_period == 0)",
                "and ($role.token_period >= 0)\n      # and ($role.token_period == 0)",
                1,
            ),
        )
        for bootstrap in mutations:
            with self.subTest():
                self.assertNotEqual(bootstrap, self.bootstrap)
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    bootstrap,
                    self.audit_config,
                )
                self.assertTrue(any("target state" in error for error in errors), errors)

    def test_approle_helper_rejects_failure_transport_and_command_bypasses(self) -> None:
        mutations = (
            self.bootstrap.replace(
                'verification_failed() {\n  echo "Vault AppRole configuration verification failed" >&2\n  exit 1\n}',
                'verification_failed() {\n  echo "Vault AppRole configuration verification failed" >&2\n  return 0\n}',
                1,
            ),
            self.bootstrap.replace("  https://*) ;;", "  https://*) ;;\n  http://*) ;;", 1),
            self.bootstrap
            + '\nunsafe_role_path="auth/approle/role/email-platform-mail"\n'
            + 'vault write "$unsafe_role_path" token_policies=root\n',
            self.bootstrap + "\ntrue\n",
        )
        for bootstrap in mutations:
            with self.subTest():
                self.assertNotEqual(bootstrap, self.bootstrap)
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    bootstrap,
                    self.audit_config,
                )
                self.assertTrue(errors)

    def test_approle_helper_cannot_add_direct_role_writes_or_credential_reads(self) -> None:
        mutations = (
            self.bootstrap + '\nvault write "auth/approle/role/backdoor" token_policies=root\n',
            self.bootstrap + '\nvault read "auth/approle/role/email-platform-mail/role-id"\n',
            self.bootstrap + '\nvault write "auth/approle/role/email-platform-mail/secret-id"\n',
        )
        for bootstrap in mutations:
            with self.subTest():
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    bootstrap,
                    self.audit_config,
                )
                self.assertTrue(errors)

    def test_vault_requires_exactly_two_audit_devices(self) -> None:
        self.audit_config = self.audit_config.replace(
            'ensure_device "$secondary_device" "$secondary_file"\n', ""
        )

        errors = self.validate()

        self.assertTrue(any("two named audit devices" in error for error in errors), errors)

    def test_vault_audit_device_names_must_be_distinct(self) -> None:
        self.audit_config = self.audit_config.replace(
            "secondary_device=email-platform-secondary",
            "secondary_device=email-platform-primary",
        )

        errors = self.validate()

        self.assertTrue(any("secondary_device" in error for error in errors), errors)

    def test_vault_audit_devices_must_have_distinct_persistent_paths(self) -> None:
        self.audit_config = self.audit_config.replace(
            "secondary_file=/var/lib/vault-audit/email-platform-secondary.json",
            "secondary_file=/var/log/vault-audit/email-platform-primary.json",
        )

        errors = self.validate()

        self.assertTrue(any("secondary_file" in error for error in errors), errors)

    def test_vault_audit_stdout_and_discard_are_rejected(self) -> None:
        for unsafe_path in ("stdout", "discard"):
            with self.subTest(unsafe_path=unsafe_path):
                audit_config = self.audit_config.replace(
                    "secondary_file=/var/lib/vault-audit/email-platform-secondary.json",
                    f"secondary_file={unsafe_path}",
                )
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    self.bootstrap,
                    audit_config,
                )
                self.assertTrue(any("secondary_file" in error for error in errors), errors)

    def test_vault_audit_security_options_cannot_be_weakened(self) -> None:
        mutations = {
            "log_raw=false": "log_raw=true",
            "elide_list_responses=true": "elide_list_responses=false",
            "mode=0600": "mode=0644",
            "hmac_accessor=true": "hmac_accessor=false",
        }
        for safe, unsafe in mutations.items():
            with self.subTest(unsafe=unsafe):
                audit_config = self.audit_config.replace(safe, unsafe, 1)
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    self.bootstrap,
                    audit_config,
                )
                self.assertTrue(
                    any(
                        "safe options" in error or "every reviewed field" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_vault_audit_partial_configuration_is_safely_reconciled(self) -> None:
        self.audit_config = self.audit_config.replace(
            'if device_exists "$target_key"; then',
            'if device_exists "$primary_device/"; then',
        )

        errors = self.validate()

        self.assertTrue(any("reconcile each device" in error for error in errors), errors)

    def test_vault_audit_drift_is_not_replaced(self) -> None:
        for unsafe in (
            'vault audit disable "$target_device"',
            'vault audit tune -path="$target_device" mode=0600',
        ):
            with self.subTest(unsafe=unsafe):
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    self.bootstrap,
                    self.audit_config + f"\n{unsafe}\n",
                )
                self.assertTrue(any("disable or tune" in error for error in errors), errors)

    def test_vault_audit_existing_drift_must_fail_closed(self) -> None:
        self.audit_config = self.audit_config.replace(
            'if ! device_matches "$target_key" "$target_file"; then',
            "if false; then",
            1,
        )

        errors = self.validate()

        self.assertTrue(any("reconcile each device" in error for error in errors), errors)

    def test_vault_audit_requires_structured_existing_device_check(self) -> None:
        self.audit_config = self.audit_config.replace("command -v jq", "command -v grep")

        errors = self.validate()

        self.assertTrue(any("reconcile each device" in error for error in errors), errors)

    def test_vault_audit_rejects_non_https_address(self) -> None:
        self.audit_config = self.audit_config.replace("https://*)", "http://*)")

        errors = self.validate()

        self.assertTrue(any("non-HTTPS" in error for error in errors), errors)

    def test_vault_audit_helper_must_not_handle_credentials(self) -> None:
        for forbidden in (
            "vault login",
            "vault read auth/approle/role/example/secret-id",
            "echo $VAULT_TOKEN",
        ):
            with self.subTest(forbidden=forbidden):
                errors = validate_vault_isolation(
                    self.compose,
                    self.env_text,
                    self.policies,
                    self.bootstrap,
                    self.audit_config + f"\n{forbidden}\n",
                )
                self.assertTrue(any("credentials" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
