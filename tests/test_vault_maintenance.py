import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import backup_crypto, vault_maintenance
from scripts.backup_crypto import key_id


class VaultMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._validate_key_permissions = backup_crypto._validate_key_permissions
        permission_patch = mock.patch(
            "scripts.backup_crypto._validate_key_permissions",
            return_value=None,
        )
        permission_patch.start()
        self.addCleanup(permission_patch.stop)
        self.snapshot_requests: list[tuple[str, dict[str, object]]] = []
        self._download_snapshot = vault_maintenance._download_snapshot
        self._upload_snapshot = vault_maintenance._upload_snapshot

        def fake_download(output_path: Path, **kwargs) -> None:
            self.snapshot_requests.append(("GET", dict(kwargs)))
            output_path.write_bytes(b"raft-snapshot")

        def fake_upload(snapshot, **kwargs) -> None:
            captured = dict(kwargs)
            captured["body"] = snapshot.read()
            self.snapshot_requests.append(("POST", captured))

        download_patch = mock.patch(
            "scripts.vault_maintenance._download_snapshot",
            side_effect=fake_download,
        )
        upload_patch = mock.patch(
            "scripts.vault_maintenance._upload_snapshot",
            side_effect=fake_upload,
        )
        download_patch.start()
        upload_patch.start()
        self.addCleanup(download_patch.stop)
        self.addCleanup(upload_patch.stop)

    def _token_file(self, directory: Path) -> Path:
        path = directory / "vault-token"
        path.write_text("test-token", encoding="utf-8")
        return path.resolve()

    def _ca_file(self, directory: Path) -> Path:
        path = directory / "vault-ca.pem"
        path.write_text("test-ca", encoding="utf-8")
        return path.resolve()

    def _snapshot_inputs(self, directory: Path) -> dict[str, object]:
        key_file = directory / "vault-manifest.key"
        key_file.write_bytes(b"m" * 32)
        postgres_dir = directory / "postgres-bundle"
        postgres_dir.mkdir()
        postgres_manifest = postgres_dir / "manifest.json"
        postgres_manifest.write_text(
            json.dumps(
                {
                    "schema_version": 5,
                    "created_at": "2026-08-21T00:00:00+00:00",
                    "databases": {
                        "platform": {"key_id": key_id(b"p" * 32)},
                        "keycloak": {"key_id": key_id(b"p" * 32)},
                    },
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "migration_head": "0017_mail_token_hash_unique",
                    "container_manifest_sha256": "b" * 64,
                    "manifest_hmac_sha256": "c" * 64,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return {
            "manifest_key_file": key_file.resolve(),
            "recovery_set": "release-v1.2.3-20260821T000000Z",
            "postgres_manifest": postgres_manifest,
        }

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

    def test_snapshot_api_streams_on_fixed_non_force_path_and_rejects_redirects(self) -> None:
        class FakeResponse:
            def __init__(self, status: int, chunks: list[bytes]) -> None:
                self.status = status
                self._chunks = iter(chunks)
                self.read_calls = 0

            def read(self, _size: int = -1) -> bytes:
                self.read_calls += 1
                return next(self._chunks, b"")

        class FakeConnection:
            def __init__(self, response: FakeResponse) -> None:
                self.response = response
                self.requests: list[tuple[str, str, object, dict[str, str]]] = []
                self.closed = False

            def request(self, method, path, body=None, headers=None) -> None:
                if hasattr(body, "read"):
                    body = body.read()
                self.requests.append((method, path, body, dict(headers or {})))

            def getresponse(self) -> FakeResponse:
                return self.response

            def close(self) -> None:
                self.closed = True

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ca_file = self._ca_file(root)
            output = root / "snapshot.tmp"
            download_connection = FakeConnection(
                FakeResponse(200, [b"raft-", b"snapshot"])
            )
            with mock.patch.object(
                vault_maintenance,
                "_open_connection",
                return_value=download_connection,
            ):
                self._download_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token="header-only-token",
                    ca_file=ca_file,
                    namespace=None,
                )
            self.assertEqual(output.read_bytes(), b"raft-snapshot")
            method, path, body, headers = download_connection.requests[0]
            self.assertEqual((method, path, body), ("GET", "/v1/sys/storage/raft/snapshot", None))
            self.assertEqual(headers["X-Vault-Token"], "header-only-token")
            self.assertTrue(download_connection.closed)

            upload_connection = FakeConnection(FakeResponse(204, []))
            with mock.patch.object(
                vault_maintenance,
                "_open_connection",
                return_value=upload_connection,
            ):
                self._upload_snapshot(
                    io.BytesIO(b"raft-snapshot"),
                    size_bytes=len(b"raft-snapshot"),
                    address="https://vault.example.invalid",
                    token="header-only-token",
                    ca_file=ca_file,
                    namespace=None,
                )
            method, path, body, headers = upload_connection.requests[0]
            self.assertEqual(
                (method, path, body),
                ("POST", "/v1/sys/storage/raft/snapshot", b"raft-snapshot"),
            )
            self.assertNotIn("force", path)
            self.assertEqual(headers["Content-Length"], str(len(b"raft-snapshot")))

            redirect_response = FakeResponse(307, [b"sensitive response body"])
            redirect_connection = FakeConnection(redirect_response)
            redirected_output = root / "redirected.tmp"
            with mock.patch.object(
                vault_maintenance,
                "_open_connection",
                return_value=redirect_connection,
            ):
                with self.assertRaisesRegex(ValueError, "snapshot request failed") as caught:
                    self._download_snapshot(
                        redirected_output,
                        address="https://vault.example.invalid",
                        token="header-only-token",
                        ca_file=ca_file,
                        namespace=None,
                    )
            self.assertNotIn("header-only-token", str(caught.exception))
            self.assertNotIn("sensitive response body", str(caught.exception))
            self.assertEqual(redirect_response.read_calls, 0)
            self.assertFalse(redirected_output.exists())

    def test_offline_inspection_receives_only_reviewed_environment_without_token(self) -> None:
        inherited = {
            "PATH": "reviewed-path",
            "VAULT_TOKEN": "must-not-leak",
            "VAULT_ADDR": "https://attacker.invalid",
            "VAULT_CACERT": "attacker-ca",
            "HTTPS_PROXY": "https://proxy.invalid",
            "HOME": "attacker-home",
            "PYTHONPATH": "attacker-pythonpath",
        }
        with mock.patch.dict(os.environ, inherited, clear=True), mock.patch(
            "subprocess.run"
        ) as run:
            vault_maintenance._inspect_snapshot(Path("snapshot"), vault_bin="vault")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment, {"PATH": "reviewed-path"})
        self.assertNotIn("VAULT_TOKEN", environment)

    def test_https_requires_explicit_ca_before_token_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            with mock.patch.object(
                vault_maintenance,
                "_read_token_file",
                wraps=vault_maintenance._read_token_file,
            ) as token_reader:
                with self.assertRaisesRegex(ValueError, "explicit CA file"):
                    vault_maintenance._snapshot_request_inputs(
                        address="https://vault.example.invalid",
                        token_file=token_file,
                        ca_file=None,
                        namespace=None,
                        allow_loopback_http=False,
                    )
            token_reader.assert_not_called()

    def test_maintenance_token_uses_the_shared_private_secret_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            token_file = Path(temp_dir) / "vault-token"
            with mock.patch.object(
                vault_maintenance,
                "read_private_secret_bytes",
                return_value=b"stable-token",
                create=True,
            ) as stable_read:
                self.assertEqual(
                    vault_maintenance._read_token_file(token_file.resolve()),
                    "stable-token",
                )
        stable_read.assert_called_once_with(token_file.resolve(), max_bytes=4096)

    def test_backup_is_atomic_integrity_checked_and_token_is_not_an_argument(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                manifest_path = vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["artifact"], "vault.snap")
            self.assertEqual(manifest["size_bytes"], len(b"raft-snapshot"))
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["recovery_set"], snapshot_inputs["recovery_set"])
            self.assertEqual(
                manifest["postgres_manifest_sha256"],
                hashlib.sha256(
                    Path(snapshot_inputs["postgres_manifest"]).read_bytes()
                ).hexdigest(),
            )
            self.assertRegex(manifest["manifest_hmac_sha256"], r"^[0-9a-f]{64}$")
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                verified_path = vault_maintenance.verify_snapshot(
                    output,
                    **snapshot_inputs,
                )
            self.assertEqual(verified_path.name, "vault.snap")

        rendered = [" ".join(command) for command, _ in calls]
        self.assertTrue(any("snapshot inspect" in command for command in rendered))
        self.assertTrue(all("test-token" not in command for command in rendered))
        self.assertTrue(all((b"m" * 32).decode() not in command for command in rendered))
        self.assertEqual([method for method, _ in self.snapshot_requests], ["GET"])
        self.assertEqual(self.snapshot_requests[0][1]["token"], "test-token")
        self.assertTrue(all("VAULT_TOKEN" not in kwargs["env"] for _, kwargs in calls))

    def test_verify_rejects_tampering_before_invoking_vault(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            (output / "vault.snap").write_bytes(b"tampered")
            calls.clear()
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    vault_maintenance.verify_snapshot(output, **snapshot_inputs)
                run.assert_not_called()

    def test_verify_rejects_snapshot_replacement_during_external_inspection(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            snapshot = output / "vault.snap"

            def replace_bundle_snapshot(_path: Path, *, vault_bin: str) -> None:
                replacement = output / ".snapshot-replacement"
                replacement.write_bytes(snapshot.read_bytes())
                os.replace(replacement, snapshot)

            with mock.patch.object(
                vault_maintenance,
                "_inspect_snapshot",
                side_effect=replace_bundle_snapshot,
            ):
                with self.assertRaisesRegex(ValueError, "changed during inspection"):
                    vault_maintenance.verify_snapshot(output, **snapshot_inputs)

    def test_manifest_relabel_and_field_tampering_fail_before_vault_inspect(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            manifest_path = output / "vault-manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))
            old_snapshot = b"older-valid-raft-snapshot"
            cases: dict[str, dict[str, object]] = {}

            relabeled = dict(original)
            relabeled.update(
                {
                    "created_at": "2026-08-21T01:00:00+00:00",
                    "size_bytes": len(old_snapshot),
                    "sha256": hashlib.sha256(old_snapshot).hexdigest(),
                }
            )
            cases["relabeled-old-snapshot"] = relabeled
            cases["time"] = {**original, "created_at": "2020-01-01T00:00:00+00:00"}
            signed_invalid_time = {
                **original,
                "created_at": "2026-08-21T01:00:00",
            }
            signed_invalid_time["manifest_hmac_sha256"] = (
                vault_maintenance._manifest_hmac_sha256(
                    signed_invalid_time,
                    b"m" * 32,
                )
            )
            cases["signed-invalid-time"] = signed_invalid_time
            wrong_postgres_binding = {
                **original,
                "postgres_manifest_sha256": "d" * 64,
            }
            wrong_postgres_binding["manifest_hmac_sha256"] = (
                vault_maintenance._manifest_hmac_sha256(
                    wrong_postgres_binding,
                    b"m" * 32,
                )
            )
            cases["postgres-binding"] = wrong_postgres_binding
            cases["missing-mac"] = {
                key: value
                for key, value in original.items()
                if key != "manifest_hmac_sha256"
            }
            cases["wrong-mac"] = {**original, "manifest_hmac_sha256": "0" * 64}
            cases["unknown-field"] = {**original, "notes": "unreviewed"}

            for label, manifest in cases.items():
                with self.subTest(label=label):
                    (output / "vault.snap").write_bytes(
                        old_snapshot if label == "relabeled-old-snapshot" else b"raft-snapshot"
                    )
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with mock.patch("subprocess.run") as run:
                        with self.assertRaises(ValueError):
                            vault_maintenance.verify_snapshot(
                                output,
                                **snapshot_inputs,
                            )
                        run.assert_not_called()

    def test_wrong_key_postgres_binding_and_schema_v1_fail_before_vault(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            manifest_path = output / "vault-manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))

            wrong_key = root / "wrong-manifest.key"
            wrong_key.write_bytes(b"w" * 32)
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "authentication"):
                    vault_maintenance.verify_snapshot(
                        output,
                        **{**snapshot_inputs, "manifest_key_file": wrong_key.resolve()},
                    )
                run.assert_not_called()

            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "recovery set binding"):
                    vault_maintenance.verify_snapshot(
                        output,
                        **{
                            **snapshot_inputs,
                            "recovery_set": "release-v1.2.4-20260821T000000Z",
                        },
                    )
                run.assert_not_called()

            postgres_manifest = Path(snapshot_inputs["postgres_manifest"])
            postgres_payload = json.loads(postgres_manifest.read_text(encoding="utf-8"))
            for entry in postgres_payload["databases"].values():
                entry["key_id"] = key_id(b"m" * 32)
            postgres_manifest.write_text(json.dumps(postgres_payload), encoding="utf-8")
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "independent"):
                    vault_maintenance.create_snapshot(
                        root / "reused-key-bundle",
                        address="https://vault.example.invalid",
                        token_file=token_file,
                        ca_file=self._ca_file(root),
                        **snapshot_inputs,
                    )
                run.assert_not_called()

            for entry in postgres_payload["databases"].values():
                entry["key_id"] = key_id(b"p" * 32)
            postgres_payload["release_tag"] = "v1.2.4"
            postgres_manifest.write_text(json.dumps(postgres_payload), encoding="utf-8")
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "PostgreSQL manifest binding"):
                    vault_maintenance.verify_snapshot(output, **snapshot_inputs)
                run.assert_not_called()

            postgres_payload["release_tag"] = "v1.2.3"
            postgres_manifest.write_text(
                json.dumps(postgres_payload, sort_keys=True), encoding="utf-8"
            )
            schema_v1 = {
                key: value
                for key, value in original.items()
                if key
                not in {
                    "manifest_hmac_sha256",
                    "recovery_set",
                    "postgres_manifest_sha256",
                }
            }
            schema_v1["schema_version"] = 1
            manifest_path.write_text(json.dumps(schema_v1), encoding="utf-8")
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "schema v2"):
                    vault_maintenance.restore_snapshot(
                        output,
                        address="https://isolated-vault.example.invalid",
                        token_file=token_file,
                        ca_file=self._ca_file(root),
                        confirm_restore=True,
                        **snapshot_inputs,
                    )
                run.assert_not_called()

    def test_restore_requires_confirmation_and_uses_verified_snapshot(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
                with self.assertRaisesRegex(ValueError, "confirm-restore"):
                    vault_maintenance.restore_snapshot(
                        output,
                        address="https://isolated-vault.example.invalid",
                        token_file=token_file,
                        ca_file=self._ca_file(root),
                        confirm_restore=False,
                        **snapshot_inputs,
                    )
                vault_maintenance.restore_snapshot(
                    output,
                    address="https://isolated-vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    confirm_restore=True,
                    **snapshot_inputs,
                )

        restore_request = next(item for item in self.snapshot_requests if item[0] == "POST")
        self.assertEqual(restore_request[1]["body"], b"raft-snapshot")
        self.assertEqual(restore_request[1]["token"], "test-token")
        self.assertTrue(all("restore" not in command for command, _ in calls))
        self.assertTrue(all("test-token" not in " ".join(command) for command, _ in calls))

    def test_address_and_token_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="http://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            with self.assertRaisesRegex(ValueError, "absolute"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="https://vault.example.invalid",
                    token_file="relative-token",
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            token_file.write_text("token with whitespace", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid"):
                vault_maintenance.create_snapshot(
                    root / "bundle",
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )

    def test_inherited_tls_skip_verify_fails_before_token_or_vault_access(self) -> None:
        for label, value in (("enabled", "1"), ("empty", ""), ("zero", "0")):
            with self.subTest(value=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                token_file = self._token_file(root)
                snapshot_inputs = self._snapshot_inputs(root)
                output = root / "bundle"
                calls: list[tuple[list[str], dict]] = []
                error: ValueError | None = None
                with mock.patch.dict(
                    os.environ,
                    {"VAULT_SKIP_VERIFY": value},
                    clear=False,
                ), mock.patch.object(
                    vault_maintenance,
                    "_read_token_file",
                    wraps=vault_maintenance._read_token_file,
                ) as token_reader, mock.patch(
                    "subprocess.run",
                    side_effect=self._successful_vault(calls),
                ) as run:
                    try:
                        vault_maintenance.create_snapshot(
                            output,
                            address="https://vault.example.invalid",
                            token_file=token_file,
                            ca_file=self._ca_file(root),
                            **snapshot_inputs,
                        )
                    except ValueError as caught:
                        error = caught

                self.assertEqual(
                    (token_reader.called, run.called, isinstance(error, ValueError)),
                    (False, False, True),
                )
                self.assertEqual(
                    str(error),
                    "inherited Vault TLS verification override is forbidden",
                )
                self.assertFalse(output.exists())

    def test_manifest_key_requires_absolute_32_byte_read_only_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            key_file = root / "manifest.key"
            key_file.write_bytes(b"m" * 32)
            with mock.patch(
                "scripts.backup_crypto._validate_key_permissions",
                side_effect=self._validate_key_permissions,
            ), mock.patch.object(backup_crypto, "_validate_windows_acl"):
                with self.assertRaisesRegex(ValueError, "read-only"):
                    vault_maintenance._load_manifest_key_file(key_file.resolve())
                try:
                    key_file.chmod(stat.S_IREAD)
                    vault_maintenance._load_manifest_key_file(key_file.resolve())
                finally:
                    key_file.chmod(stat.S_IREAD | stat.S_IWRITE)

            with self.assertRaisesRegex(ValueError, "absolute"):
                vault_maintenance._load_manifest_key_file("relative.key")
            key_file.write_bytes(b"short")
            with self.assertRaisesRegex(ValueError, "32 raw bytes"):
                vault_maintenance._load_manifest_key_file(key_file.resolve())

    def test_manifest_key_read_only_check_is_part_of_stable_key_load(self) -> None:
        path = Path("C:/restricted/vault-manifest.key")
        with mock.patch.object(
            vault_maintenance,
            "load_key_file",
            return_value=b"m" * 32,
        ) as load_key:
            self.assertEqual(
                vault_maintenance._load_manifest_key_file(path),
                b"m" * 32,
            )

        load_key.assert_called_once_with(path, require_read_only=True)

    def test_existing_snapshot_is_refused_without_key_token_or_vault_access(self) -> None:
        calls: list[tuple[list[str], dict]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch("subprocess.run", side_effect=self._successful_vault(calls)):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.example.invalid",
                    token_file=token_file,
                    ca_file=self._ca_file(root),
                    **snapshot_inputs,
                )
            original = {path.name: path.read_bytes() for path in output.iterdir()}
            with mock.patch("subprocess.run") as run, mock.patch.object(
                vault_maintenance, "_snapshot_binding_inputs"
            ) as binding, mock.patch.object(
                vault_maintenance, "_snapshot_request_inputs"
            ) as request_inputs:
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    vault_maintenance.create_snapshot(
                        output,
                        address="https://vault.example.invalid",
                        token_file=token_file,
                        ca_file=self._ca_file(root),
                        **snapshot_inputs,
                    )
                run.assert_not_called()
                binding.assert_not_called()
                request_inputs.assert_not_called()
            self.assertEqual(
                {path.name: path.read_bytes() for path in output.iterdir()},
                original,
            )

    def test_failed_new_snapshot_removes_only_the_claimed_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token_file = self._token_file(root)
            snapshot_inputs = self._snapshot_inputs(root)
            output = root / "bundle"
            with mock.patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(1, ["vault"]),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    vault_maintenance.create_snapshot(
                        output,
                        address="https://vault.example.invalid",
                        token_file=token_file,
                        ca_file=self._ca_file(root),
                        **snapshot_inputs,
                    )
            self.assertFalse(output.exists())

    def test_existing_empty_snapshot_dir_is_refused_before_secret_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "bundle"
            output.mkdir()
            with mock.patch("subprocess.run") as run, mock.patch.object(
                vault_maintenance, "_snapshot_binding_inputs"
            ) as binding, mock.patch.object(
                vault_maintenance, "_snapshot_request_inputs"
            ) as request_inputs:
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    vault_maintenance.create_snapshot(
                        output,
                        address="https://vault.example.invalid",
                        token_file=root / "missing-token",
                        ca_file=root / "missing-ca",
                        manifest_key_file=root / "missing-key",
                        recovery_set="release-v1",
                        postgres_manifest=root / "missing-manifest",
                    )
                run.assert_not_called()
                binding.assert_not_called()
                request_inputs.assert_not_called()
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
