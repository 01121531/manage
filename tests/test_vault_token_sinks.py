import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.vault_token_sinks import (
    TOKEN_DIRECTORY_VARIABLES,
    VaultTokenSinkError,
    validate_vault_token_sinks,
)


class VaultTokenSinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.compose_file = self.repository / "docker-compose.yml"
        self.compose_file.write_text(
            (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )
        self.sink_root = self.root / "vault-sinks"
        self.sink_root.mkdir()
        self.env_file = self.repository / ".env"
        self.directories = {
            name: self.sink_root / name.lower() for name in TOKEN_DIRECTORY_VARIABLES
        }
        for directory in self.directories.values():
            directory.mkdir()
            token_file = directory / "token"
            token_file.write_bytes(b"opaque-token")
            if os.name != "nt":
                token_file.chmod(0o400)
        self._write_inventory()

        if os.name != "nt":
            uid_patch = mock.patch("scripts.vault_token_sinks.CONTAINER_UID", os.getuid())
            gid_patch = mock.patch("scripts.vault_token_sinks.CONTAINER_GID", os.getgid())
            uid_patch.start()
            gid_patch.start()
            self.addCleanup(uid_patch.stop)
            self.addCleanup(gid_patch.stop)

    def _write_inventory(self) -> None:
        self.env_file.write_text(
            "\n".join(
                f"{name}={self.directories[name]}"
                for name in TOKEN_DIRECTORY_VARIABLES
            )
            + "\n",
            encoding="utf-8",
        )

    def _assert_invalid(self, *sensitive_values: str) -> None:
        with self.assertRaises(VaultTokenSinkError) as raised:
            validate_vault_token_sinks(
                self.env_file,
                self.compose_file,
                repository_root=self.repository,
            )
        self.assertEqual(
            str(raised.exception), "Vault token sink metadata is invalid"
        )
        self.assertIsNone(raised.exception.__cause__)
        for value in sensitive_values:
            self.assertNotIn(value, str(raised.exception))

    def test_validates_metadata_without_reading_token_contents(self) -> None:
        with mock.patch.object(
            Path,
            "read_bytes",
            side_effect=AssertionError("token contents must not be read"),
        ):
            self.assertIsNone(
                validate_vault_token_sinks(
                    self.env_file,
                    self.compose_file,
                    repository_root=self.repository,
                )
            )

    def test_rechecks_fresh_metadata_after_atomic_replacement(self) -> None:
        self.assertIsNone(
            validate_vault_token_sinks(
                self.env_file,
                self.compose_file,
                repository_root=self.repository,
            )
        )
        token_file = next(iter(self.directories.values())) / "token"
        replacement = token_file.with_name("token.next")
        replacement.write_bytes(b"")
        if os.name != "nt":
            replacement.chmod(0o400)
        os.replace(replacement, token_file)
        self._assert_invalid("opaque-token")

    def test_rejects_compose_contract_drift(self) -> None:
        original = self.compose_file.read_text(encoding="utf-8")
        for old, new in (
            ("user: \"10001:10001\"", "user: \"0:0\""),
            ("read_only: true", "read_only: false"),
            ("create_host_path: false", "create_host_path: true"),
        ):
            with self.subTest(contract=old):
                self.compose_file.write_text(
                    original.replace(old, new),
                    encoding="utf-8",
                )
                self._assert_invalid(old)
                self.compose_file.write_text(original, encoding="utf-8")

    def test_rejects_missing_nonregular_empty_and_oversized_leaf(self) -> None:
        mutations = ("missing", "directory", "empty", "oversized")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                token_file = next(iter(self.directories.values())) / "token"
                if mutation == "missing":
                    token_file.unlink()
                elif mutation == "directory":
                    token_file.unlink()
                    token_file.mkdir()
                elif mutation == "empty":
                    if os.name != "nt":
                        token_file.chmod(0o600)
                    token_file.write_bytes(b"")
                else:
                    if os.name != "nt":
                        token_file.chmod(0o600)
                    token_file.write_bytes(b"x" * 4097)
                self._assert_invalid(str(token_file), "opaque-token")

    def test_rejects_duplicate_directory_or_hardlinked_leaf(self) -> None:
        names = list(TOKEN_DIRECTORY_VARIABLES)
        self.directories[names[1]] = self.directories[names[0]]
        self._write_inventory()
        self._assert_invalid(str(self.directories[names[0]]))

        self.setUp()
        first = self.directories[names[0]] / "token"
        second = self.directories[names[1]] / "token"
        second.unlink()
        os.link(first, second)
        self._assert_invalid(str(first), str(second))

    def test_rejects_relative_repository_local_and_symlink_paths(self) -> None:
        name = TOKEN_DIRECTORY_VARIABLES[0]
        self.directories[name] = Path("relative-vault-sink")
        self._write_inventory()
        self._assert_invalid("relative-vault-sink")

        self.setUp()
        local_directory = self.repository / "vault-sink"
        local_directory.mkdir()
        local_token = local_directory / "token"
        local_token.write_bytes(b"opaque-token")
        if os.name != "nt":
            local_token.chmod(0o400)
        self.directories[name] = local_directory
        self._write_inventory()
        self._assert_invalid(str(local_directory), "opaque-token")

        self.setUp()
        link = self.root / "linked-sink"
        try:
            link.symlink_to(self.directories[name], target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlink is unavailable: {error}")
        self.directories[name] = link
        self._write_inventory()
        self._assert_invalid(str(link), "opaque-token")

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode bits are required")
    def test_rejects_unreadable_identity_or_nonexact_mode(self) -> None:
        token_file = next(iter(self.directories.values())) / "token"
        token_file.chmod(0o600)
        self._assert_invalid(str(token_file), "opaque-token")

        token_file.chmod(0o400)
        with mock.patch(
            "scripts.vault_token_sinks.CONTAINER_UID",
            os.getuid() + 100_000,
        ):
            self._assert_invalid(str(token_file), "opaque-token")


if __name__ == "__main__":
    unittest.main()
