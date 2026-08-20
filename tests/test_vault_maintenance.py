import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import vault_maintenance


class VaultMaintenanceTests(unittest.TestCase):
    def _token_file(self, directory: Path) -> Path:
        path = directory / "vault-token"
        path.write_text("test-token", encoding="utf-8")
        return path.resolve()

    def _successful_vault(self, calls: list[tuple[list[str], dict]]):
        def fake_run(command, check, **kwargs):
            captured = dict(kwargs)
            if isinstance(captured.get("env"), dict):
                captured["env"] = dict(captured["env"])
            calls.append((list(command), captured))
            if "save" in command:
                Path(command[-1]).write_bytes(b"raft-snapshot")
            return subprocess.CompletedProcess(command, 0, stdout="ok")

        return fake_run

    def test_backup_is_atomic_integrity_checked_and_token_is_not_an_argument(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                manifest_path = vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["artifact"], "vault.snap")
            self.assertEqual(manifest["size_bytes"], len(b"raft-snapshot"))
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                verified_path = vault_maintenance.verify_snapshot(output)
            self.assertEqual(verified_path.name, "vault.snap")

        rendered = [" ".join(command) for command, _ in calls]
        self.assertTrue(any("snapshot save" in command for command in rendered))
        self.assertTrue(any("snapshot inspect" in command for command in rendered))
        self.assertTrue(all("test-token" not in command for command in rendered))
        save_environment = next(kwargs["env"] for command, kwargs in calls if "save" in command)
        self.assertEqual(save_environment["VAULT_TOKEN"], "test-token")

    def test_verify_rejects_tampering_before_invoking_vault(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                )
            (output / "vault.snap").write_bytes(b"tampered")
            calls.clear()
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    vault_maintenance.verify_snapshot(output)
                run.assert_not_called()

    def test_restore_requires_confirmation_and_uses_verified_snapshot(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                )
                with self.assertRaisesRegex(ValueError, "confirm-restore"):
                    vault_maintenance.restore_snapshot(
                        output,
                        address="https://isolated-vault.example.invalid",
                        token_file=token_file,
                        confirm_restore=False,
                    )
                vault_maintenance.restore_snapshot(
                    output,
                    address="https://isolated-vault.example.invalid",
                    token_file=token_file,
                    confirm_restore=True,
                )

        restore_call = next(item for item in calls if "restore" in item[0])
        self.assertIn("-force", restore_call[0])
        self.assertEqual(restore_call[1]["env"]["VAULT_TOKEN"], "test-token")
        self.assertNotIn("test-token", " ".join(restore_call[0]))

    def test_address_and_token_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="http://vault.example.invalid",
                    token_file=token_file,
                )
            with self.assertRaisesRegex(ValueError, "absolute"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="https://vault.example.invalid",
                    token_file="relative-token",
                )
            token_file.write_text("token with whitespace", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="https://vault.example.invalid",
                    token_file=token_file,
                )

    def test_failed_backup_invalidates_previous_manifest(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                )
            self.assertTrue((output / "vault-manifest.json").exists())
            with mock.patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(1, ["vault"]),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    vault_maintenance.create_snapshot(
                        output,
                        address="https://vault.example.invalid",
                        token_file=token_file,
                    )
            self.assertFalse((output / "vault-manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
