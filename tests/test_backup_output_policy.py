import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from scripts import backup_output_policy
from scripts.verify_backup_tools import backup_output_contract_errors


class BackupOutputPolicyTests(unittest.TestCase):
    def test_directory_must_be_absolute_external_and_new(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute"):
            backup_output_policy.create_write_once_directory("relative/bundle")
        with self.assertRaisesRegex(ValueError, "outside the repository"):
            backup_output_policy.create_write_once_directory(
                backup_output_policy.REPOSITORY_ROOT / "forbidden-bundle"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                backup_output_policy.create_write_once_directory(existing)

    def test_symlink_and_reparse_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(ValueError, "symlink or reparse"):
                    backup_output_policy.create_write_once_directory(link / "bundle")

            original = backup_output_policy._is_link_or_reparse
            with mock.patch(
                "scripts.backup_output_policy._is_link_or_reparse",
                side_effect=lambda path: path == target or original(path),
            ):
                with self.assertRaisesRegex(ValueError, "symlink or reparse"):
                    backup_output_policy.create_write_once_directory(target / "bundle")

    def test_concurrent_directory_claim_has_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "bundle"
            barrier = threading.Barrier(2)

            def claim() -> str:
                barrier.wait()
                try:
                    backup_output_policy.create_write_once_directory(output)
                except ValueError:
                    return "rejected"
                return "created"

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: claim(), range(2)))
            self.assertEqual(sorted(results), ["created", "rejected"])

    def test_single_file_publish_never_replaces_a_racing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = backup_output_policy.prepare_write_once_file(root / "backup.enc")
            temporary = root / ".backup.tmp"
            temporary.write_bytes(b"new")
            output.write_bytes(b"old")
            with self.assertRaises(FileExistsError):
                backup_output_policy.publish_write_once_file(temporary, output)
            self.assertEqual(output.read_bytes(), b"old")
            self.assertEqual(temporary.read_bytes(), b"new")

    def test_single_file_rejects_an_existing_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "backup.enc"
            output.write_bytes(b"old")
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                backup_output_policy.prepare_write_once_file(output)
            self.assertEqual(output.read_bytes(), b"old")

    def test_exact_leaf_gate_rejects_hardlinks_and_binds_later_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "bundle"
            bundle.mkdir()
            leaf = bundle / "manifest.json"
            leaf.write_bytes(b"{}")
            alias = root / "manifest-alias.json"
            try:
                os.link(leaf, alias)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaisesRegex(ValueError, "leaf set"):
                backup_output_policy.require_exact_regular_files(
                    bundle,
                    frozenset({leaf.name}),
                )

            alias.unlink()
            identities = backup_output_policy.require_exact_regular_files(
                bundle,
                frozenset({leaf.name}),
            )
            replacement = bundle / ".replacement"
            replacement.write_bytes(leaf.read_bytes())
            os.replace(replacement, leaf)
            from scripts.external_json import StableFileError, open_stable_binary

            with self.assertRaises(StableFileError):
                with open_stable_binary(
                    leaf,
                    expected_identity=identities[leaf.name],
                ):
                    pass

    def test_static_contract_rejects_downgrades_and_wrong_order(self) -> None:
        root = backup_output_policy.REPOSITORY_ROOT
        policy = (root / "scripts" / "backup_output_policy.py").read_text(encoding="utf-8")
        postgres = (root / "scripts" / "postgres_maintenance.py").read_text(encoding="utf-8")
        vault = (root / "scripts" / "vault_maintenance.py").read_text(encoding="utf-8")
        redis = (root / "scripts" / "redis_maintenance.py").read_text(encoding="utf-8")
        self.assertEqual(
            backup_output_contract_errors(policy, postgres, vault, redis),
            [],
        )
        strict_body = (
            "    os.link(temporary_path, output_path)\n"
            "    temporary_path.unlink()"
        )
        semantic_mutations = (
            (
                policy.replace(
                    strict_body,
                    "    publish_write_once_file(temporary_path, output_path)",
                    1,
                ),
                postgres,
            ),
            (
                policy,
                postgres.replace(
                    "publish_bundle_write_once_file(publishing_path, path)",
                    "publish_write_once_file(publishing_path, path)",
                    1,
                ),
            ),
            (
                policy,
                postgres.replace(
                    "publish_write_once_file(temporary_path, path)",
                    "publish_bundle_write_once_file(temporary_path, path)",
                    1,
                ),
            ),
        )
        for changed_policy, changed_postgres in semantic_mutations:
            with self.subTest(contract="bundle publisher semantics"):
                self.assertNotEqual((changed_policy, changed_postgres), (policy, postgres))
                self.assertTrue(
                    backup_output_contract_errors(
                        changed_policy,
                        changed_postgres,
                        vault,
                        redis,
                    )
                )
        mutations = (
            (policy.replace("os.link(temporary_path, output_path)", "os.replace(temporary_path, output_path)"), postgres, vault),
            (policy, postgres.replace("prepare_write_once_file(output_path)", "Path(output_path)", 1), vault),
            (policy, postgres.replace("create_write_once_directory(output_dir)", "Path(output_dir)", 1), vault),
            (policy, postgres, vault.replace("create_write_once_directory(output_dir)", "Path(output_dir)", 1)),
            (
                policy,
                postgres,
                vault.replace(
                    "cleanup_created_directory_after_failure(directory_claim, error)",
                    "directory.rmdir()",
                    1,
                ),
            ),
            (policy.replace("os.fsync(stream.fileno())", "pass", 1), postgres, vault),
            (
                policy,
                postgres.replace(
                    "write_fsynced_temporary_bytes(", "Path.write_bytes(", 1
                ),
                vault,
            ),
            (
                policy,
                postgres,
                vault.replace(
                    "write_fsynced_temporary_bytes(", "Path.write_bytes(", 1
                ),
            ),
            (
                policy,
                postgres,
                vault.replace(
                    'if "VAULT_SKIP_VERIFY" in os.environ:',
                    'if os.environ.get("VAULT_SKIP_VERIFY"):',
                    1,
                ),
            ),
            (
                policy,
                postgres,
                vault.replace(
                    '    if "VAULT_SKIP_VERIFY" in os.environ:\n'
                    '        raise ValueError("inherited Vault TLS verification override is forbidden")\n',
                    "",
                    1,
                ),
            ),
            (
                policy,
                postgres,
                vault.replace(
                    "def _offline_environment() -> dict[str, str]:\n    return {",
                    "def _offline_environment() -> dict[str, str]:\n    environment = os.environ.copy()\n    return {",
                    1,
                ),
            ),
            (
                policy,
                postgres,
                vault.replace("        env=_offline_environment(),\n", "", 1),
            ),
            (
                policy,
                postgres,
                vault.replace(
                    '_RAFT_SNAPSHOT_PATH = "/v1/sys/storage/raft/snapshot"',
                    '_RAFT_SNAPSHOT_PATH = "/v1/sys/storage/raft/snapshot-force"',
                    1,
                ),
            ),
            (
                policy,
                postgres,
                vault.replace("response.status != 200", "response.status < 400", 1),
            ),
            (
                policy,
                postgres,
                vault.replace("_download_snapshot(\n", "subprocess.run(\n", 1),
            ),
        )
        for changed_policy, changed_postgres, changed_vault in mutations:
            with self.subTest():
                self.assertTrue(
                    backup_output_contract_errors(
                        changed_policy,
                        changed_postgres,
                        changed_vault,
                    )
                )

        artifact_mutations = (
            postgres.replace("            stream.flush()\n", "", 1),
            postgres.replace("            os.fsync(stream.fileno())\n", "", 1),
            postgres.replace("            stream.seek(0)\n", "", 1),
        )
        for changed_postgres in artifact_mutations:
            with self.subTest(artifact="postgres"):
                self.assertTrue(
                    backup_output_contract_errors(
                        policy,
                        changed_postgres,
                        vault,
                        redis,
                    )
                )

        vault_mutations = (
            vault.replace("            stream.flush()\n", "", 1),
            vault.replace("            os.fsync(stream.fileno())\n", "", 1),
            vault.replace(
                "publish_bundle_write_once_file(publishing_path, snapshot_path)",
                "os.replace(publishing_path, snapshot_path)",
                1,
            ),
        )
        for changed_vault in vault_mutations:
            with self.subTest(artifact="vault"):
                self.assertTrue(
                    backup_output_contract_errors(
                        policy,
                        postgres,
                        changed_vault,
                        redis,
                    )
                )

        redis_mutations = (
            redis.replace("            destination.flush()\n", "", 1),
            redis.replace("            os.fsync(destination.fileno())\n", "", 1),
        )
        for changed_redis in redis_mutations:
            with self.subTest(artifact="redis"):
                self.assertTrue(
                    backup_output_contract_errors(
                        policy,
                        postgres,
                        vault,
                        changed_redis,
                    )
                )

        rollback_mutations = (
            (
                policy.replace(
                    "shutil.rmtree(claim.path)",
                    "shutil.rmtree(claim.path.parent)",
                    1,
                ),
                postgres,
                vault,
                redis,
            ),
            (
                policy.replace(
                    "metadata.st_ino != claim.inode",
                    "metadata.st_ino == claim.inode",
                    1,
                ),
                postgres,
                vault,
                redis,
            ),
            (
                policy.replace(
                    "except BaseException:\n        notes = getattr(primary_error",
                    "except Exception:\n        notes = getattr(primary_error",
                    1,
                ),
                postgres,
                vault,
                redis,
            ),
            (
                policy,
                postgres.replace(
                    "cleanup_created_directory_after_failure(directory_claim, error)",
                    "raise error",
                    1,
                ),
                vault,
                redis,
            ),
            (
                policy,
                postgres,
                vault.replace(
                    "cleanup_created_directory_after_failure(directory_claim, error)",
                    "raise error",
                    1,
                ),
                redis,
            ),
            (
                policy,
                postgres,
                vault,
                redis.replace(
                    "raise fatal_error from restart_error",
                    "raise fatal_error from error",
                    1,
                ),
            ),
            (
                policy,
                postgres.replace(
                    "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)",
                    "pass",
                    1,
                ),
                vault,
                redis,
            ),
            (
                policy,
                postgres,
                vault.replace(
                    "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)",
                    "pass",
                    1,
                ),
                redis,
            ),
            (
                policy,
                postgres,
                vault,
                redis.replace(
                    "require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)",
                    "pass",
                    1,
                ),
            ),
        )
        for changed_policy, changed_postgres, changed_vault, changed_redis in rollback_mutations:
            with self.subTest(contract="claimed rollback and exact leaves"):
                self.assertNotEqual(
                    (changed_policy, changed_postgres, changed_vault, changed_redis),
                    (policy, postgres, vault, redis),
                )
                self.assertTrue(
                    backup_output_contract_errors(
                        changed_policy,
                        changed_postgres,
                        changed_vault,
                        changed_redis,
                    )
                )

        identity_mutations = (
            (
                policy.replace("or metadata.st_nlink != 1", "or False", 1),
                postgres,
                vault,
                redis,
            ),
            (
                policy,
                postgres.replace(
                    "expected_identity=identities[artifact]",
                    "expected_identity=None",
                    1,
                ),
                vault,
                redis,
            ),
            (
                policy,
                postgres,
                vault.replace(
                    "expected_identity=identities[SNAPSHOT_NAME]",
                    "expected_identity=None",
                    1,
                ),
                redis,
            ),
            (
                policy,
                postgres,
                vault,
                redis.replace(
                    "expected_identity=identities[ARTIFACT_NAME]",
                    "expected_identity=None",
                    1,
                ),
            ),
        )
        for changed_policy, changed_postgres, changed_vault, changed_redis in identity_mutations:
            with self.subTest(contract="stable leaf identity"):
                self.assertNotEqual(
                    (changed_policy, changed_postgres, changed_vault, changed_redis),
                    (policy, postgres, vault, redis),
                )
                self.assertTrue(
                    backup_output_contract_errors(
                        changed_policy,
                        changed_postgres,
                        changed_vault,
                        changed_redis,
                    )
                )


if __name__ == "__main__":
    unittest.main()
