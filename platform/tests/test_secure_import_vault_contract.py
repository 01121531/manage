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
        self.assertFalse(contract["production_acceptance"])
        roles = {item["role"]: item for item in contract["roles"]}
        self.assertEqual(set(roles), {"card-importer", "mailbox-importer", "api-verifier"})
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
        self.assertIn('required_parameters = ["data", "options"]', card_policy)
        self.assertIn('required_parameters = ["data", "options"]', mailbox_policy)
        self.assertIn("transit/verify/email-platform-card-import-receipt", api_policy)
        self.assertIn("transit/verify/email-platform-mailbox-import-receipt", api_policy)
        self.assertNotIn("transit/sign/", api_policy)


if __name__ == "__main__":
    unittest.main()
