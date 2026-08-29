import unittest
from pathlib import Path

from scripts.verify_backup_tools import private_secret_contract_errors


ROOT = Path(__file__).resolve().parents[1]


class PrivateSecretContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private = (ROOT / "scripts/private_secret_file.py").read_text(encoding="utf-8")
        cls.crypto = (ROOT / "scripts/backup_crypto.py").read_text(encoding="utf-8")
        cls.vault = (ROOT / "scripts/vault_maintenance.py").read_text(encoding="utf-8")
        cls.audit = (ROOT / "scripts/audit_archive.py").read_text(encoding="utf-8")
        cls.edge = (ROOT / "scripts/validate_edge_tls.py").read_text(encoding="utf-8")
        cls.expiry = (ROOT / "scripts/check_internal_tls_expiry.py").read_text(encoding="utf-8")

    def errors(self, **overrides: str) -> list[str]:
        return private_secret_contract_errors(
            overrides.get("private", self.private),
            overrides.get("crypto", self.crypto),
            overrides.get("vault", self.vault),
            overrides.get("audit", self.audit),
            overrides.get("edge", self.edge),
            overrides.get("expiry", self.expiry),
        )

    def test_current_contract_is_valid(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_reader_identity_and_permission_downgrades_are_rejected(self) -> None:
        mutations = (
            self.private.replace("opened.st_nlink != 1", "False", 1),
            self.private.replace("open_stable_binary(path)", "open(path, 'rb')", 1),
            self.private.replace(
                "final_permission_identity != permission_identity",
                "False",
                1,
            ),
            self.private.replace(
                "stable_file_identity(final_opened) != stable_file_identity(opened)",
                "False",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertNotEqual(changed, self.private)
                self.assertTrue(self.errors(private=changed))

    def test_descriptor_acl_reuse_downgrade_is_rejected(self) -> None:
        changed = self.crypto.replace(
            "return _validate_key_permissions(",
            "return None or _validate_key_permissions(",
            1,
        )
        self.assertNotEqual(changed, self.crypto)
        self.assertTrue(self.errors(crypto=changed))

    def test_all_four_callers_must_use_the_shared_reader(self) -> None:
        mutations = (
            ("vault", self.vault.replace("read_private_secret_bytes(path, max_bytes=4096)", "path.read_bytes()", 1)),
            ("audit", self.audit.replace("read_private_secret_bytes(path, max_bytes=MAX_DATABASE_URL_BYTES)", "path.read_bytes()", 1)),
            ("edge", self.edge.replace("read_private_secret_bytes(\n            private_key_path,", "read_stable_bytes(\n            private_key_path,", 1)),
            ("expiry", self.expiry.replace("read_private_secret_bytes(path, max_bytes=MAX_PRIVATE_KEY_BYTES)", "read_stable_bytes(path, max_bytes=MAX_PRIVATE_KEY_BYTES)", 1)),
        )
        for argument, changed in mutations:
            with self.subTest(argument=argument):
                self.assertTrue(self.errors(**{argument: changed}))


if __name__ == "__main__":
    unittest.main()
