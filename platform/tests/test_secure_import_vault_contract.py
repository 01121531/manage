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
        self.assertEqual(contract["schema_version"], 2)
        self.assertFalse(contract["production_acceptance"])
        self.assertEqual(contract["bundle_schema_version"], 2)
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
        self.assertEqual(self._rules(card_policy), {
            "secret/data/cards/imports/*": {"create"},
            "transit/sign/email-platform-card-import-receipt": {"update"},
        })
        self.assertEqual(self._rules(mailbox_policy), {
            "secret/data/mailboxes/imports/*": {"create"},
            "transit/sign/email-platform-mailbox-import-receipt": {"update"},
        })
        self.assertNotIn("required_parameters", card_policy)
        self.assertNotIn("required_parameters", mailbox_policy)
        self.assertIn(
            "importer_create_only_effective_capability_and_cli_cas_zero_observed",
            contract["required_target_evidence"],
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
