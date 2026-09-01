import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SecureImportVaultContractTests(unittest.TestCase):
    @staticmethod
    def _rules(policy: str) -> dict[str, set[str]]:
        return {
            path: set(re.findall(r'"([^"]+)"', capabilities.group(1)))
            for path, body in re.findall(
                r'^path\s+"([^"]+)"\s*\{([^}]*)\}',
                policy,
                re.MULTILINE | re.DOTALL,
            )
            if (capabilities := re.search(
                r"capabilities\s*=\s*\[([^]]*)\]", body
            )) is not None
        }

    def test_roles_are_pool_isolated_and_api_cannot_sign(self) -> None:
        contract = json.loads(
            (ROOT / "infra" / "vault" / "secure-import-contract.json").read_text()
        )
        self.assertEqual(contract["schema_version"], 9)
        self.assertFalse(contract["production_acceptance"])
        self.assertEqual(
            contract["ingestion_boundary"],
            {
                "operator_action": "administrator_manual_upload",
                "automatic_collection": False,
                "raw_source_transport": "approved_intake_workstation_to_vault_only",
                "browser_input": "secret-free-signed-bundle_only",
                "mailbox_display_format": (
                    "one_visible_ascii_local_character_then_three_asterisks_"
                    "and_dns_domain"
                ),
                "card_security_codes": "rejected_at_import_and_runtime_resolution",
                "pools": {
                    "card": "credit_card_pool",
                    "mailbox": "mailbox_pool",
                },
            },
        )
        self.assertEqual(contract["bundle_schema_version"], 3)
        self.assertEqual(
            contract["credential_exchange"],
            {
                "auth_method": "approle",
                "preissued_token_file_allowed": False,
                "token_persistence": "process_memory_only",
                "role_id_file": "required_separate_absolute_restricted_file",
                "secret_id_file": "required_separate_absolute_restricted_file",
                "secret_id_num_uses": 1,
                "secret_id_ttl_seconds": 600,
                "initial_token_ttl_max_seconds": 900,
                "token_explicit_max_ttl_seconds": 3600,
                "revocation_endpoint": (
                    "POST /v1/auth/token/revoke-self"
                ),
                "revocation_acknowledgement": "empty_http_204",
                "revocation_attempt_scope": (
                    "every_controlled_exit_after_token_exchange"
                ),
                "authentication_validation_failure_revocation": (
                    "attempt_for_visible_ascii_issued_token"
                ),
                "unsafe_authentication_token_header_reuse": False,
                "primary_failure_precedence": True,
                "revocation_attempt_survives_evidence_failure": True,
                "raw_import_revocation_evidence": (
                    "write_once_intent_then_confirmation"
                ),
                "receipt_reissue_revocation_evidence": (
                    "cli_result_only_original_execution_immutable"
                ),
                "ttl_expiry_is_revocation_backstop": True,
                "default_policy_allowed": False,
                "identity_policy_count": 0,
                "pool_bindings": {
                    "card": {
                        "issuer_policy": "email-platform-secure-import-card-issuer",
                        "approle": "email-platform-card-importer",
                        "token_policy": "email-platform-card-importer",
                    },
                    "mailbox": {
                        "issuer_policy": "email-platform-secure-import-mailbox-issuer",
                        "approle": "email-platform-mailbox-importer",
                        "token_policy": "email-platform-mailbox-importer",
                    },
                },
            },
        )
        self.assertEqual(
            contract["target_import_context"],
            {
                "authority": "authenticated-target-platform-api",
                "request_fields": [
                    "pool_type",
                    "ordered_manifest_digest",
                    "item_count",
                ],
                "server_authoritative_fields": [
                    "receipt_id",
                    "tenant_id",
                    "audience",
                ],
                "default_ttl_seconds": 900,
                "maximum_ttl_seconds": 3600,
                "renewal_endpoint": (
                    "POST /api/v1/admin/pool-import-contexts/renew"
                ),
                "renewal_token_rotation": False,
                "renewal_requires_same_user_device_tenant_audience": True,
                "default_renewal_window_seconds": 86_400,
                "maximum_renewal_window_seconds": 604_800,
                "renewal_rejects_consumed_context": True,
                "post_write_pre_sign_renewal": True,
                "storage": "sha256-token-only",
                "first_vault_write_requires_validated_context": True,
                "final_submission_header": "Secure-Import-Context",
                "atomic_one_time_consumption": "same-transaction-as-pool-import",
            },
        )
        self.assertEqual(contract["execution_record_schema_version"], 1)
        self.assertEqual(contract["smoke_plan_schema_version"], 1)
        self.assertEqual(contract["cleanup_receipt_schema_version"], 1)
        self.assertEqual(
            contract["recovery"],
            {
                "states": [
                    "unwritten",
                    "partial_written",
                    "commit_unknown",
                    "completed",
                ],
                "assessment": "read_only",
                "automatic_resume_allowed": False,
                "existing_create_only_secret_equivalence_assumed": False,
                "completed_receipt_reissue": "transit_sign_only_no_kv_rewrite",
                "reissue_requires_completed_execution": True,
                "original_execution_record_mutation": False,
            },
        )
        self.assertEqual(
            contract["canary_cleanup"],
            {
                "policy_scope": "exact_per_run_paths_only",
                "wildcards_allowed": False,
                "data_capabilities": ["read"],
                "metadata_capabilities": ["read", "delete"],
                "permanent_delete": "kv_v2_metadata_delete",
                "preflight_both_canaries_before_delete": True,
                "write_once_secret_free_receipt": True,
            },
        )
        self.assertEqual(
            contract["submission_key_binding"],
            "spi:<vault-transit-signed-receipt-uuid>",
        )
        roles = {item["role"]: item for item in contract["roles"]}
        self.assertEqual(set(roles), {"card-importer", "mailbox-importer", "api-verifier"})
        self.assertEqual(
            {name: item["approle"] for name, item in roles.items()},
            {
                "card-importer": "email-platform-card-importer",
                "mailbox-importer": "email-platform-mailbox-importer",
                "api-verifier": "email-platform-api-cards",
            },
        )
        self.assertEqual(contract["target_smoke_check_count"], 24)
        self.assertEqual(
            contract["transit_keys"],
            [
                {
                    "key": "email-platform-card-import-receipt",
                    "type": "ed25519",
                    "derived": False,
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "deletion_allowed": False,
                    "auto_rotate_seconds": 2_592_000,
                },
                {
                    "key": "email-platform-mailbox-import-receipt",
                    "type": "ed25519",
                    "derived": False,
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "deletion_allowed": False,
                    "auto_rotate_seconds": 2_592_000,
                },
            ],
        )
        card_policy = (ROOT / "infra" / "vault" / "policies" / "email-platform-card-importer.hcl").read_text()
        mailbox_policy = (ROOT / "infra" / "vault" / "policies" / "email-platform-mailbox-importer.hcl").read_text()
        api_policy = (ROOT / "infra" / "vault" / "policies" / "email-platform-api-cards.hcl").read_text()
        card_issuer_policy = (
            ROOT / "infra" / "vault" / "policies"
            / "email-platform-secure-import-card-issuer.hcl"
        ).read_text()
        mailbox_issuer_policy = (
            ROOT / "infra" / "vault" / "policies"
            / "email-platform-secure-import-mailbox-issuer.hcl"
        ).read_text()
        self.assertEqual(self._rules(card_policy), {
            "secret/data/cards/imports/*": {"create"},
            "transit/sign/email-platform-card-import-receipt": {"update"},
        })
        self.assertEqual(self._rules(mailbox_policy), {
            "secret/data/mailboxes/imports/*": {"create"},
            "transit/sign/email-platform-mailbox-import-receipt": {"update"},
        })
        self.assertEqual(self._rules(card_issuer_policy), {
            "auth/approle/role/email-platform-card-importer/role-id": {"read"},
            "auth/approle/role/email-platform-card-importer/secret-id": {"update"},
        })
        self.assertEqual(self._rules(mailbox_issuer_policy), {
            "auth/approle/role/email-platform-mailbox-importer/role-id": {"read"},
            "auth/approle/role/email-platform-mailbox-importer/secret-id": {"update"},
        })
        self.assertNotIn("required_parameters", card_policy)
        self.assertNotIn("required_parameters", mailbox_policy)
        self.assertEqual(
            contract["required_target_evidence"],
            [
                "three_distinct_external_principals",
                "importer_create_only_effective_capability_and_cli_cas_zero_observed",
                "cross_pool_access_denied",
                "api_sign_denied",
                "importer_verify_denied",
                "transit_keys_non_exportable_and_rotated",
                "vault_audit_trace_reviewed",
                "database_concurrent_receipt_consumption_verified",
                "target_context_wrong_tenant_and_audience_prewrite_denial_verified",
                "exact_run_canary_cleanup_receipt_verified",
                "administrator_card_pool_batch_committed",
                "administrator_mailbox_pool_batch_committed",
                "dual_pool_execution_records_read_only_recovery_assessed_without_automatic_resume",
            ],
        )
        self.assertIn("transit/verify/email-platform-card-import-receipt", api_policy)
        self.assertIn("transit/verify/email-platform-mailbox-import-receipt", api_policy)
        self.assertNotIn("transit/sign/", api_policy)

    def test_bootstrap_is_exact_non_exportable_and_never_handles_credentials(self) -> None:
        helper = (
            ROOT / "infra" / "vault" / "configure-secure-import.sh"
        ).read_text(encoding="utf-8")
        uncommented = "\n".join(
            line for line in helper.splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertIn('case "$VAULT_ADDR" in', uncommented)
        self.assertEqual(
            re.findall(r"^configure_role ([^\s]+) ([^\s]+)$", uncommented, re.MULTILINE),
            [
                ("email-platform-card-importer", "email-platform-card-importer"),
                ("email-platform-mailbox-importer", "email-platform-mailbox-importer"),
                ("email-platform-api-cards", "email-platform-api-cards"),
            ],
        )
        self.assertEqual(
            re.findall(r"^configure_key ([^\s]+)$", uncommented, re.MULTILINE),
            [
                "email-platform-card-import-receipt",
                "email-platform-mailbox-import-receipt",
            ],
        )
        for required in (
            "type=ed25519",
            "derived=false",
            "exportable=false",
            "allow_plaintext_backup=false",
            "auto_rotate_period=720h",
            "($key.exportable == false)",
            "($key.allow_plaintext_backup == false)",
            "($key.deletion_allowed == false)",
            "($key.auto_rotate_period == 2592000)",
        ):
            self.assertIn(required, uncommented)
        for forbidden in (
            "role-id",
            "secret-id",
            "auth/approle/login",
            "auth/token/",
            "transit/export/",
            "transit/backup/",
        ):
            self.assertNotIn(forbidden, uncommented.lower())


if __name__ == "__main__":
    unittest.main()
