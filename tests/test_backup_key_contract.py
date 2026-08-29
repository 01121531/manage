import unittest
from pathlib import Path

from scripts.verify_backup_tools import backup_key_contract_errors


ROOT = Path(__file__).resolve().parents[1]


class BackupKeyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.crypto = (ROOT / "scripts" / "backup_crypto.py").read_text(
            encoding="utf-8"
        )
        cls.postgres = (ROOT / "scripts" / "postgres_maintenance.py").read_text(
            encoding="utf-8"
        )
        cls.redis = (ROOT / "scripts" / "redis_maintenance.py").read_text(
            encoding="utf-8"
        )
        cls.vault = (ROOT / "scripts" / "vault_maintenance.py").read_text(
            encoding="utf-8"
        )
        cls.audit = (ROOT / "scripts" / "audit_archive.py").read_text(
            encoding="utf-8"
        )

    def errors(
        self,
        *,
        crypto: str | None = None,
        postgres: str | None = None,
        redis: str | None = None,
        vault: str | None = None,
        audit: str | None = None,
    ) -> list[str]:
        return backup_key_contract_errors(
            self.crypto if crypto is None else crypto,
            self.postgres if postgres is None else postgres,
            self.redis if redis is None else redis,
            self.vault if vault is None else vault,
            self.audit if audit is None else audit,
        )

    def test_current_key_contract_is_valid(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_windows_handle_acl_downgrades_are_rejected(self) -> None:
        mutations = (
            self.crypto.replace("_WINDOWS_READ_CONTROL", "0x001F01FF", 1),
            self.crypto.replace("SafeFileHandle", "PathHandle"),
            self.crypto.replace('"handle_list": [inherited_handle]', '"handle_list": []', 1),
            self.crypto.replace("close_fds=True", "close_fds=False", 1),
            self.crypto.replace("timeout=15", "timeout=None", 1),
            self.crypto.replace(
                "$rawHandle = [Console]::In.ReadToEnd()",
                "$path = [Console]::In.ReadToEnd()\n$acl = Get-Acl -LiteralPath $path",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertNotEqual(changed, self.crypto)
                self.assertTrue(self.errors(crypto=changed))

    def test_acl_schema_and_descriptor_binding_downgrades_are_rejected(self) -> None:
        mutations = (
            self.crypto.replace('"dacl_present",', ""),
            self.crypto.replace("owner not in allowed", "False", 1),
            self.crypto.replace('rule.get("inherited") is not False', "False", 1),
            self.crypto.replace(
                "_validate_windows_acl(descriptor)",
                "_validate_windows_acl(0)",
                1,
            ),
            self.crypto.replace("return current, owner, sddl", "return current", 1),
        )
        for changed in mutations:
            with self.subTest():
                self.assertNotEqual(changed, self.crypto)
                self.assertTrue(self.errors(crypto=changed))

    def test_stable_key_loader_downgrades_are_rejected(self) -> None:
        mutations = (
            self.crypto.replace("has_link_or_reparse_ancestor(path)", "False", 1),
            self.crypto.replace("metadata.st_nlink != 1", "False", 1),
            self.crypto.replace("_REPARSE_POINT", "0", 4),
            self.crypto.replace(
                "final_permission_identity != permission_identity",
                "False",
                1,
            ),
            self.crypto.replace(
                "stable_file_identity(final_metadata) != stable_file_identity(metadata)",
                "False",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertNotEqual(changed, self.crypto)
                self.assertTrue(self.errors(crypto=changed))

    def test_vault_read_only_key_downgrades_are_rejected(self) -> None:
        changed = self.vault.replace("require_read_only=True", "require_read_only=False", 1)
        self.assertNotEqual(changed, self.vault)
        self.assertTrue(self.errors(vault=changed))

    def test_postgres_operation_key_reload_downgrades_are_rejected(self) -> None:
        mutations = (
            self.postgres.replace("_loaded_key=key", "_loaded_key=None", 1),
            self.postgres.replace(
                "                key,\n            )",
                "                load_key_file(key_file),\n            )",
                1,
            ),
            self.postgres.replace(
                "manifest, verified, _, identities, key",
                "manifest, verified, _, identities, _",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertNotEqual(changed, self.postgres)
                self.assertTrue(self.errors(postgres=changed))

    def test_redis_and_audit_operation_key_reload_downgrades_are_rejected(self) -> None:
        redis_changed = self.redis.replace(
            "manifest, _, _, identities, key = _verify_release_backup_details(",
            "key = load_key_file(key_file)\n    manifest, _, _, identities, _ = _verify_release_backup_details(",
            1,
        )
        audit_changed = self.audit.replace("    key = load_key_file(key_file)\n", "", 1)
        self.assertNotEqual(redis_changed, self.redis)
        self.assertNotEqual(audit_changed, self.audit)
        self.assertTrue(self.errors(redis=redis_changed))
        self.assertTrue(self.errors(audit=audit_changed))


if __name__ == "__main__":
    unittest.main()
