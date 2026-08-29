import importlib.util
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "postgres_maintenance.py"
SPEC = importlib.util.spec_from_file_location("postgres_maintenance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
postgres_maintenance = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = postgres_maintenance
SPEC.loader.exec_module(postgres_maintenance)


RELEASE_BINDING = {
    "release_tag": "v1.2.3",
    "release_commit": "a" * 40,
    "migration_head": "0014_audit_evidence_fields",
    "container_manifest_sha256": "b" * 64,
}


class _NonClosingBytesIO(io.BytesIO):
    def close(self) -> None:
        pass


class _OpenProcessBackedByRun:
    def __init__(self, command, *, stdout=None, stdin=None, **kwargs):
        self.command = list(command)
        self.returncode: int | None = None
        self.stdout = None
        self.stdin = None
        if stdout is subprocess.PIPE:
            self.stdout = io.BytesIO()
            result = subprocess.run(self.command, check=True, stdout=self.stdout)
            self.returncode = result.returncode
            self.stdout.seek(0)
        elif stdin is subprocess.PIPE:
            self.stdin = _NonClosingBytesIO()

    def wait(self):
        if self.returncode is None and self.stdin is not None:
            self.stdin.seek(0)
            result = subprocess.run(self.command, check=True, stdin=self.stdin)
            self.returncode = result.returncode
        return self.returncode or 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class PostgresMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.key_directory.cleanup)
        self.key_file = Path(self.key_directory.name) / "backup.key"
        self.key_file.write_bytes(b"k" * 32)
        permission_patch = mock.patch(
            "scripts.backup_crypto._validate_key_permissions",
            return_value=None,
        )
        permission_patch.start()
        self.addCleanup(permission_patch.stop)
        popen_patch = mock.patch(
            "subprocess.Popen",
            side_effect=_OpenProcessBackedByRun,
        )
        popen_patch.start()
        self.addCleanup(popen_patch.stop)
        for name in (
            "backup_database",
            "restore_database",
            "run_backup",
            "run_restore",
            "run_drill",
            "backup_bundle",
            "verify_bundle",
            "verify_bundle_release_binding",
            "restore_bundle",
            "drill_bundle",
        ):
            original = getattr(postgres_maintenance, name)

            def with_key(*args, _original=original, **kwargs):
                kwargs.setdefault("key_file", self.key_file)
                return _original(*args, **kwargs)

            setattr(postgres_maintenance, name, with_key)
            self.addCleanup(setattr, postgres_maintenance, name, original)
    def test_command_builders_keep_database_name_safe(self) -> None:
        backup = postgres_maintenance.backup_command()
        self.assertIn('pg_dump -Fc --no-owner --no-privileges', backup[-1])
        restore = postgres_maintenance.restore_command(target_db="email_platform_restore")
        self.assertIn('pg_restore --clean --if-exists', restore[-1])
        self.assertIn('--role="$POSTGRES_USER"', restore[-1])
        self.assertIn('"email_platform_restore"', restore[-1])
        with self.assertRaises(ValueError):
            postgres_maintenance.restore_command(target_db="bad-name;rm -rf")

    def test_compose_commands_pin_the_production_project_identity(self) -> None:
        expected_prefix = [
            "docker",
            "compose",
            "--project-directory",
            str(ROOT),
            "--env-file",
            str(ROOT / ".env"),
            "--project-name",
            "email-platform",
            "--file",
            str(ROOT / "docker-compose.yml"),
        ]
        commands = (
            postgres_maintenance.backup_command(),
            postgres_maintenance.restore_command(target_db="email_platform_restore"),
            postgres_maintenance.create_database_command(target_db="scratch"),
            postgres_maintenance.drop_database_command(target_db="scratch"),
        )

        for command in commands:
            self.assertEqual(command[: len(expected_prefix)], expected_prefix)

    def test_docker_environment_fails_before_backup_and_restore_access(self) -> None:
        variables = (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        )
        for name in variables:
            for value in ("1", "0", "", "operator-decoy"):
                with self.subTest(operation="backup", name=name, value=value):
                    with (
                        mock.patch.dict(os.environ, {name: value}),
                        mock.patch.object(
                            postgres_maintenance,
                            "prepare_write_once_file",
                            side_effect=AssertionError("output claim was reached"),
                        ) as output_claim,
                        mock.patch.object(postgres_maintenance, "load_key_file") as load_key,
                        mock.patch.object(postgres_maintenance.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "^production backup Docker environment preflight failed$",
                        ):
                            postgres_maintenance.backup_database(
                                "unused.dump.enc",
                                key_file="unused.key",
                            )
                    output_claim.assert_not_called()
                    load_key.assert_not_called()
                    popen.assert_not_called()

                with self.subTest(operation="restore", name=name, value=value):
                    with (
                        mock.patch.dict(os.environ, {name: value}),
                        mock.patch.object(
                            postgres_maintenance,
                            "load_key_file",
                            side_effect=AssertionError("key reader was reached"),
                        ) as load_key,
                        mock.patch.object(postgres_maintenance.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "^production backup Docker environment preflight failed$",
                        ):
                            postgres_maintenance.restore_database(
                                "unused.dump.enc",
                                key_file="unused.key",
                                target_db="email_platform",
                            )
                    load_key.assert_not_called()
                    popen.assert_not_called()

    def test_keycloak_restore_uses_dedicated_owner_without_password_arguments(self) -> None:
        restore = postgres_maintenance.restore_command(
            target_db="keycloak_restore",
            owner_env="KEYCLOAK_DB_USER",
        )[-1]
        create = postgres_maintenance.create_database_command(
            target_db="keycloak_restore",
            owner_env="KEYCLOAK_DB_USER",
        )[-1]
        self.assertIn('--role="$KEYCLOAK_DB_USER"', restore)
        self.assertIn('--owner="$KEYCLOAK_DB_USER"', create)
        self.assertNotIn("PASSWORD", restore)
        self.assertNotIn("PASSWORD", create)
        with self.assertRaisesRegex(ValueError, "approved database role"):
            postgres_maintenance.restore_command(
                target_db="keycloak_restore",
                owner_env="UNTRUSTED_ROLE; echo unsafe",
            )

    def test_backup_and_restore_use_subprocess_with_expected_commands(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"custom-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"custom-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir) / "snapshot.dump"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result = postgres_maintenance.run_backup(backup_path)
                self.assertGreater(result.size_bytes, len(b"custom-backup"))
                self.assertNotIn(b"custom-backup", backup_path.read_bytes())
                postgres_maintenance.run_restore(
                    backup_path, target_db="email_platform_restore"
                )

        self.assertEqual(len(calls), 2)
        self.assertIn("pg_dump", " ".join(calls[0]))
        self.assertIn("pg_restore", " ".join(calls[1]))

    def test_drill_creates_and_cleans_scratch_database(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"snapshot")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"snapshot")
            return subprocess.CompletedProcess(command, 0, stdout="3\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir) / "drill.dump"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result, scratch_db = postgres_maintenance.run_drill(
                    backup_path, scratch_db="email_platform_restore_drill"
                )

        self.assertEqual(scratch_db, "email_platform_restore_drill")
        self.assertEqual(result.path, backup_path)
        rendered = [" ".join(command) for command in calls]
        self.assertTrue(any("createdb" in line for line in rendered))
        self.assertTrue(any("pg_restore" in line for line in rendered))
        self.assertTrue(any("psql" in line for line in rendered))
        self.assertTrue(any("dropdb" in line for line in rendered))

    def test_bundle_contains_and_verifies_both_databases(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            rendered = " ".join(command)
            if stdout is not None:
                payload = b"keycloak-backup" if '"keycloak"' in rendered else b"platform-backup"
                stdout.write(payload)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result = postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )

            verified = postgres_maintenance.verify_bundle(bundle_dir)
            self.assertEqual(set(verified), {"platform", "keycloak"})
            self.assertEqual(verified["platform"]["database"], "email_platform")
            self.assertEqual(verified["keycloak"]["database"], "keycloak")
            self.assertTrue(result.manifest_path.exists())

            (bundle_dir / "keycloak.dump.enc").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "size mismatch|hash mismatch"):
                postgres_maintenance.verify_bundle(bundle_dir)

        dumps = [" ".join(command) for command in calls if "pg_dump" in " ".join(command)]
        self.assertEqual(len(dumps), 2)
        self.assertTrue(any('"email_platform"' in command for command in dumps))
        self.assertTrue(any('"keycloak"' in command for command in dumps))

    def test_release_bound_bundle_uses_authenticated_schema_v5_and_verifies_binding(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )

            manifest = json.loads(
                (bundle_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["schema_version"], 5)
            self.assertRegex(manifest["manifest_hmac_sha256"], r"^[0-9a-f]{64}$")
            for field, expected in RELEASE_BINDING.items():
                self.assertEqual(manifest[field], expected)
            self.assertEqual(
                postgres_maintenance.verify_bundle_release_binding(
                    bundle_dir, **RELEASE_BINDING
                ),
                RELEASE_BINDING,
            )

    def test_release_binding_digest_uses_the_authenticated_manifest_bytes(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest_path = bundle_dir / "manifest.json"
            original = manifest_path.read_bytes()
            stable_loader = postgres_maintenance.load_unique_json_with_bytes

            def replace_after_read(candidate: Path, *, max_bytes: int, **kwargs):
                value, raw = stable_loader(candidate, max_bytes=max_bytes, **kwargs)
                if candidate == manifest_path:
                    candidate.write_bytes(raw + b" ")
                return value, raw

            with mock.patch.object(
                postgres_maintenance,
                "load_unique_json_with_bytes",
                side_effect=replace_after_read,
            ):
                with self.assertRaisesRegex(ValueError, "changed"):
                    postgres_maintenance.verify_bundle_release_binding(
                        bundle_dir,
                        _include_created_at=True,
                        _include_manifest_sha256=True,
                        **RELEASE_BINDING,
                    )
            self.assertNotEqual(original, manifest_path.read_bytes())

    def test_bundle_manifest_and_commands_never_contain_key_material(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"secret-database-dump")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            manifest_text = (bundle_dir / "manifest.json").read_text(encoding="utf-8")
            self.assertNotIn((b"k" * 32).decode(), manifest_text)
            self.assertIn('"key_id"', manifest_text)
            self.assertTrue(
                all((b"k" * 32).decode() not in " ".join(command) for command in calls)
            )

    def test_verify_rejects_same_bytes_manifest_replacement_after_leaf_gate(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            exact_gate = postgres_maintenance.require_exact_regular_files
            replaced = False

            def replace_after_gate(directory, expected_names):
                nonlocal replaced
                identities = exact_gate(directory, expected_names)
                if not replaced:
                    replaced = True
                    manifest = directory / "manifest.json"
                    replacement = directory / ".manifest-replacement"
                    replacement.write_bytes(manifest.read_bytes())
                    os.replace(replacement, manifest)
                return identities

            with mock.patch.object(
                postgres_maintenance,
                "require_exact_regular_files",
                side_effect=replace_after_gate,
            ):
                with self.assertRaisesRegex(ValueError, "invalid backup manifest"):
                    postgres_maintenance.verify_bundle_release_binding(
                        bundle_dir,
                        **RELEASE_BINDING,
                    )

    def test_tamper_and_database_identity_swap_fail_before_pg_restore(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                payload = b"keycloak-secret" if '"keycloak"' in " ".join(command) else b"platform-secret"
                stdout.write(payload)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            manifest_path = bundle_dir / "manifest.json"
            original_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            platform_path = bundle_dir / "platform.dump.enc"
            tampered = bytearray(platform_path.read_bytes())
            tampered[-1] ^= 1
            platform_path.write_bytes(tampered)
            original_manifest["databases"]["platform"]["sha256"] = __import__(
                "hashlib"
            ).sha256(tampered).hexdigest()
            manifest_path.write_text(json.dumps(original_manifest), encoding="utf-8")
            with mock.patch("subprocess.Popen") as popen:
                with self.assertRaisesRegex(ValueError, "authentication"):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                    )
                popen.assert_not_called()

            swapped_bundle_dir = Path(temp_dir) / "swapped-bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    swapped_bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            bundle_dir = swapped_bundle_dir
            manifest_path = bundle_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            platform_bytes = (bundle_dir / "platform.dump.enc").read_bytes()
            keycloak_bytes = (bundle_dir / "keycloak.dump.enc").read_bytes()
            (bundle_dir / "platform.dump.enc").write_bytes(keycloak_bytes)
            (bundle_dir / "keycloak.dump.enc").write_bytes(platform_bytes)
            manifest["databases"]["platform"].update(
                {
                    "database": "keycloak",
                    "sha256": __import__("hashlib").sha256(keycloak_bytes).hexdigest(),
                    "size_bytes": len(keycloak_bytes),
                }
            )
            manifest["databases"]["keycloak"].update(
                {
                    "database": "email_platform",
                    "sha256": __import__("hashlib").sha256(platform_bytes).hexdigest(),
                    "size_bytes": len(platform_bytes),
                }
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with mock.patch("subprocess.Popen") as popen:
                with self.assertRaisesRegex(ValueError, "database identity"):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                    )
                popen.assert_not_called()

    def test_release_binding_requires_all_fields_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError, "release binding requires all four fields"
                ):
                    postgres_maintenance.backup_bundle(
                        Path(temp_dir) / "bundle",
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                        release_tag=RELEASE_BINDING["release_tag"],
                    )
                run.assert_not_called()

    def test_verify_rejects_incomplete_or_malformed_v5_binding(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            manifest_path = bundle_dir / "manifest.json"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("migration_head")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires all release binding fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            manifest["migration_head"] = RELEASE_BINDING["migration_head"]
            manifest["release_commit"] = "not-a-commit"
            manifest["manifest_hmac_sha256"] = (
                postgres_maintenance._manifest_hmac_sha256(
                    manifest,
                    self.key_file.read_bytes(),
                )
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid release commit"):
                postgres_maintenance.verify_bundle(bundle_dir)

    def test_release_manifest_tampering_fails_before_pg_restore(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        mutations = {
            "schema": lambda manifest: manifest.update(schema_version=4),
            "created_at": lambda manifest: manifest.update(
                created_at="2026-08-19T00:00:00+00:00"
            ),
            "release_tag": lambda manifest: manifest.update(release_tag="v1.2.4"),
            "release_commit": lambda manifest: manifest.update(release_commit="c" * 40),
            "migration_head": lambda manifest: manifest.update(
                migration_head="0015_tampered"
            ),
            "container_manifest": lambda manifest: manifest.update(
                container_manifest_sha256="d" * 64
            ),
            "platform_algorithm": lambda manifest: manifest["databases"][
                "platform"
            ].update(algorithm="AES-128-GCM"),
            "platform_key_id": lambda manifest: manifest["databases"][
                "platform"
            ].update(key_id="e" * 16),
            "keycloak_sha256": lambda manifest: manifest["databases"][
                "keycloak"
            ].update(sha256="f" * 64),
            "keycloak_size": lambda manifest: manifest["databases"][
                "keycloak"
            ].update(size_bytes=1),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest_path = bundle_dir / "manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))

            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    tampered = json.loads(json.dumps(original))
                    mutate(tampered)
                    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
                    with mock.patch("subprocess.Popen") as popen:
                        with self.assertRaisesRegex(
                            ValueError,
                            "authentication|schema v4",
                        ):
                            postgres_maintenance.restore_bundle(
                                bundle_dir,
                                platform_target_db="email_platform_restore",
                                keycloak_target_db="keycloak_restore",
                                **RELEASE_BINDING,
                            )
                        popen.assert_not_called()

    def test_release_manifest_missing_or_wrong_mac_and_v4_fail_before_restore(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest_path = bundle_dir / "manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))
            cases = {
                "missing": {
                    key: value
                    for key, value in original.items()
                    if key != "manifest_hmac_sha256"
                },
                "wrong": {**original, "manifest_hmac_sha256": "0" * 64},
                "v4": {
                    **{
                        key: value
                        for key, value in original.items()
                        if key != "manifest_hmac_sha256"
                    },
                    "schema_version": 4,
                },
            }
            for label, manifest in cases.items():
                with self.subTest(label=label):
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with mock.patch("subprocess.Popen") as popen:
                        with self.assertRaisesRegex(
                            ValueError,
                            "authentication|schema v4",
                        ):
                            postgres_maintenance.restore_bundle(
                                bundle_dir,
                                platform_target_db="email_platform_restore",
                                keycloak_target_db="keycloak_restore",
                                **RELEASE_BINDING,
                            )
                        popen.assert_not_called()

    def test_release_binding_check_rejects_generic_schema_and_mismatch(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy = root / "legacy"
            bound = root / "bound"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    legacy,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
                postgres_maintenance.backup_bundle(
                    bound,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )

            self.assertEqual(
                set(postgres_maintenance.verify_bundle(legacy)),
                {"platform", "keycloak"},
            )
            with self.assertRaisesRegex(ValueError, "not release-bound"):
                postgres_maintenance.verify_bundle_release_binding(
                    legacy, **RELEASE_BINDING
                )
            mismatched = dict(RELEASE_BINDING)
            mismatched["release_tag"] = "v1.2.4"
            with self.assertRaisesRegex(ValueError, "release binding mismatch: release_tag"):
                postgres_maintenance.verify_bundle_release_binding(
                    bound, **mismatched
                )

    def test_bundle_manifest_rejects_unknown_fields_and_naive_timestamp(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest_path = bundle_dir / "manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))

            tampered = dict(original)
            tampered["notes"] = "not part of the closed evidence schema"
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            tampered = json.loads(json.dumps(original))
            tampered["databases"]["platform"]["notes"] = "unexpected"
            tampered["manifest_hmac_sha256"] = (
                postgres_maintenance._manifest_hmac_sha256(
                    tampered,
                    self.key_file.read_bytes(),
                )
            )
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected manifest entry fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            tampered = dict(original)
            tampered["created_at"] = "2026-08-20T12:00:00"
            tampered["manifest_hmac_sha256"] = (
                postgres_maintenance._manifest_hmac_sha256(
                    tampered,
                    self.key_file.read_bytes(),
                )
            )
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "creation time"):
                postgres_maintenance.verify_bundle(bundle_dir)

    def test_restore_bundle_verifies_integrity_before_restoring_both_databases(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"database-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
                postgres_maintenance.restore_bundle(
                    bundle_dir,
                    platform_target_db="email_platform_restore",
                    keycloak_target_db="keycloak_restore",
                )

        restores = [
            " ".join(command) for command in calls if "pg_restore" in " ".join(command)
        ]
        self.assertEqual(len(restores), 2)
        self.assertTrue(any('"email_platform_restore"' in command for command in restores))
        self.assertTrue(any('"keycloak_restore"' in command for command in restores))
        platform_restore = next(
            command for command in restores if '"email_platform_restore"' in command
        )
        keycloak_restore = next(
            command for command in restores if '"keycloak_restore"' in command
        )
        self.assertIn('--role="$POSTGRES_USER"', platform_restore)
        self.assertIn('--role="$KEYCLOAK_DB_USER"', keycloak_restore)
        self.assertNotIn("PASSWORD", keycloak_restore)

    def test_bundle_backup_and_restore_each_use_one_key_snapshot(self) -> None:
        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run), mock.patch.object(
                postgres_maintenance,
                "load_key_file",
                return_value=b"k" * 32,
            ) as load_key:
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
                self.assertEqual(load_key.call_count, 1)
                load_key.reset_mock()
                postgres_maintenance.restore_bundle(
                    bundle_dir,
                    platform_target_db="email_platform_restore",
                    keycloak_target_db="keycloak_restore",
                    **RELEASE_BINDING,
                )
                self.assertEqual(load_key.call_count, 1)

    def test_release_bound_restore_verifies_manifest_once_for_both_databases(self) -> None:
        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
                with mock.patch.object(
                    postgres_maintenance,
                    "_verify_bundle_details",
                    wraps=postgres_maintenance._verify_bundle_details,
                ) as verify_details:
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        **RELEASE_BINDING,
                    )
            self.assertEqual(verify_details.call_count, 1)

    def test_release_bound_restore_rejects_mismatch_before_restore(self) -> None:
        def fake_backup(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_backup):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            mismatched = dict(RELEASE_BINDING)
            mismatched["container_manifest_sha256"] = "c" * 64
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError,
                    "release binding mismatch: container_manifest_sha256",
                ):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        **mismatched,
                    )
                run.assert_not_called()
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError, "release binding requires all four fields"
                ):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        release_tag=RELEASE_BINDING["release_tag"],
                    )
                run.assert_not_called()

    def test_bundle_cli_parses_release_binding_for_generation_and_restore(self) -> None:
        parser = postgres_maintenance.build_parser()
        flags = [
            "--key-file",
            str(self.key_file),
            "--release-tag",
            RELEASE_BINDING["release_tag"],
            "--release-commit",
            RELEASE_BINDING["release_commit"],
            "--migration-head",
            RELEASE_BINDING["migration_head"],
            "--container-manifest-sha256",
            RELEASE_BINDING["container_manifest_sha256"],
        ]
        for command in ("backup-bundle", "drill-bundle", "restore-bundle"):
            directory_flag = (
                "--input-dir" if command == "restore-bundle" else "--output-dir"
            )
            args = parser.parse_args([command, directory_flag, "bundle", *flags])
            for field, expected in RELEASE_BINDING.items():
                self.assertEqual(getattr(args, field), expected)

    def test_existing_bundle_is_refused_without_key_or_database_access(self) -> None:
        def successful_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=successful_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            original = {
                path.name: path.read_bytes()
                for path in bundle_dir.iterdir()
            }
            with mock.patch("subprocess.run") as run, mock.patch.object(
                postgres_maintenance, "load_key_file"
            ) as load_key:
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    postgres_maintenance.backup_bundle(
                        bundle_dir,
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                    )
                run.assert_not_called()
                load_key.assert_not_called()
            self.assertEqual(
                {path.name: path.read_bytes() for path in bundle_dir.iterdir()},
                original,
            )

    def test_failed_new_bundle_removes_only_the_claimed_directory(self) -> None:
        call_count = 0

        def failing_run(command, check, stdout=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise subprocess.CalledProcessError(1, command)
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=failing_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    postgres_maintenance.backup_bundle(
                        bundle_dir,
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                    )
            self.assertFalse(bundle_dir.exists())

    def test_existing_empty_bundle_is_refused_before_key_or_database_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            bundle_dir.mkdir()
            with mock.patch("subprocess.run") as run, mock.patch.object(
                postgres_maintenance, "load_key_file"
            ) as load_key:
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    postgres_maintenance.backup_bundle(
                        bundle_dir,
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                    )
                run.assert_not_called()
                load_key.assert_not_called()
            self.assertEqual(list(bundle_dir.iterdir()), [])

    def test_single_database_target_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "single.dump.enc"
            output.write_bytes(b"existing-backup")
            with mock.patch("subprocess.run") as run, mock.patch.object(
                postgres_maintenance, "load_key_file"
            ) as load_key:
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    postgres_maintenance.backup_database(output)
                run.assert_not_called()
                load_key.assert_not_called()
            self.assertEqual(output.read_bytes(), b"existing-backup")

    def test_bundle_drill_compares_nonzero_source_and_restored_table_counts(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            rendered = " ".join(command)
            if stdout is not None:
                stdout.write(b"database-backup")
            if "psql" in rendered:
                return subprocess.CompletedProcess(command, 0, stdout="4\n")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run", side_effect=fake_run):
                drill = postgres_maintenance.drill_bundle(
                    Path(temp_dir) / "bundle",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    platform_scratch_db="email_platform_restore_drill",
                    keycloak_scratch_db="keycloak_restore_drill",
                    **RELEASE_BINDING,
                )
            manifest = json.loads(
                drill.bundle.manifest_path.read_text(encoding="utf-8")
            )

        self.assertEqual(manifest["schema_version"], 5)
        self.assertEqual(manifest["release_tag"], RELEASE_BINDING["release_tag"])
        self.assertEqual(
            set(drill.critical_row_counts["platform"]),
            {"users", "devices", "audit_events"},
        )
        self.assertEqual(
            set(drill.critical_row_counts["keycloak"]),
            {
                "realm",
                "user_entity",
                "credential",
                "event_entity",
                "admin_event_entity",
            },
        )
        self.assertEqual(
            drill.critical_row_counts["keycloak"]["credential"],
            {"source": 4, "restored": 4},
        )

        rendered = [" ".join(command) for command in calls]
        self.assertEqual(sum("pg_dump" in line for line in rendered), 2)
        self.assertEqual(sum("pg_restore" in line for line in rendered), 2)
        self.assertEqual(sum("createdb" in line for line in rendered), 2)
        self.assertEqual(sum("dropdb" in line for line in rendered), 2)
        self.assertEqual(sum("psql" in line for line in rendered), 20)
        keycloak_create = next(
            line
            for line in rendered
            if "createdb" in line and '"keycloak_restore_drill"' in line
        )
        keycloak_restore = next(
            line
            for line in rendered
            if "pg_restore" in line and '"keycloak_restore_drill"' in line
        )
        self.assertIn('--owner="$KEYCLOAK_DB_USER"', keycloak_create)
        self.assertIn('--role="$KEYCLOAK_DB_USER"', keycloak_restore)

    def test_bundle_drill_rejects_critical_row_count_mismatch(self) -> None:
        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            rendered = " ".join(command)
            if stdout is not None:
                stdout.write(b"database-backup")
            if "psql" in rendered:
                row_count = "5\n"
                if (
                    'keycloak_restore_drill' in rendered
                    and 'public."credential"' in rendered
                ):
                    row_count = "4\n"
                return subprocess.CompletedProcess(command, 0, stdout=row_count)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaisesRegex(
                    ValueError,
                    r"restored row count mismatch: keycloak\.credential source=5 restored=4",
                ):
                    postgres_maintenance.drill_bundle(
                        Path(temp_dir) / "bundle",
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                        platform_scratch_db="email_platform_restore_drill",
                        keycloak_scratch_db="keycloak_restore_drill",
                    )

    def test_critical_row_count_rejects_unknown_table_and_invalid_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "disaster-recovery whitelist"):
            postgres_maintenance.count_rows_command(
                target_db="email_platform",
                table="unreviewed_table",
            )
        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="not-an-integer\n"),
        ):
            with self.assertRaisesRegex(ValueError, "invalid row count"):
                postgres_maintenance.count_rows(
                    target_db="email_platform",
                    table="users",
                )

    def test_table_count_rejects_empty_database(self) -> None:
        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="0\n"),
        ):
            with self.assertRaisesRegex(ValueError, "no public tables"):
                postgres_maintenance.count_tables(target_db="empty_restore")


if __name__ == "__main__":
    unittest.main()
