from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from sqlalchemy import create_engine, insert, select
from sqlalchemy.engine import URL

from platform.models import AuditEvent
from scripts import audit_archive, backup_crypto


ROOT = Path(__file__).resolve().parents[1]
TENANT = "tenant-archive"
OTHER_TENANT = "tenant-other"
CREATED_FROM = datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)
CREATED_TO = CREATED_FROM + timedelta(hours=1)
SAME_TIMESTAMP = CREATED_FROM + timedelta(minutes=5)
SOURCE_COMMIT = "a" * 40
KEY = b"A" * 32
OTHER_KEY = b"B" * 32
SAME_TIMESTAMP_ROWS = 10_005
EXPECTED_ROWS = SAME_TIMESTAMP_ROWS + 1
VERIFY_ERRORS = (audit_archive.AuditArchiveError, backup_crypto.BackupCryptoError)


def _secure_write(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    if os.name != "nt":
        path.chmod(0o600)


class AuditArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._acl_patch = mock.patch("scripts.backup_crypto._validate_windows_acl")
        if os.name == "nt":
            cls._acl_patch.start()
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name).resolve()
        cls.database_path = cls.root / "audit-source.sqlite3"
        cls.engine = create_engine(
            URL.create("sqlite+pysqlite", database=str(cls.database_path))
        )
        AuditEvent.__table__.create(cls.engine)
        cls.key_file = cls.root / "archive.key"
        cls.other_key_file = cls.root / "other.key"
        _secure_write(cls.key_file, KEY)
        _secure_write(cls.other_key_file, OTHER_KEY)

        rows = []
        for index in range(SAME_TIMESTAMP_ROWS):
            details = {"batch_index": index, "safe": "ordinary evidence"}
            event_type = "task.completed"
            action = "task.complete"
            entity_type = "task"
            entity_id = f"task-{index:05d}"
            actor_id = "archive-operator"
            trace_id = f"trace-{index:05d}"
            ip_address = "2001:0db8::1"
            user_agent = "archive-test-agent/1.0"
            if index == 0:
                details = {
                    "password": "DETAIL_PASSWORD_SECRET",
                    "safe_authorization": "Authorization: Basic DETAIL_AUTH_SECRET",
                    "nested": {
                        "token": "DETAIL_TOKEN_SECRET",
                        "free": "prefix Bearer DETAIL_BEARER_SECRET",
                    },
                    "vault_reference": "prefix vault://secret/archive",
                    "card_note": "legacy PAN 4111111111111111",
                    "ordinary": "retained evidence",
                }
                event_type = "Bearer EVENT_TYPE_SECRET"
                action = "vault://ACTION_SECRET"
                entity_type = "Authorization: Basic ENTITY_TYPE_SECRET"
                entity_id = "4111111111111111"
                actor_id = "Bearer ACTOR_SECRET"
                trace_id = "vault://TRACE_SECRET"
                ip_address = "not-an-ip Authorization: IP_SECRET"
                user_agent = "browser Bearer USER_AGENT_SECRET"
            rows.append(
                {
                    "id": f"event-{index:05d}",
                    "tenant_id": TENANT,
                    "user_id": None,
                    "device_id": None,
                    "actor_id": actor_id,
                    "event_type": event_type,
                    "action": action,
                    "result": "success",
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "trace_id": trace_id,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "policy_version": None,
                    "details_json": json.dumps(details),
                    "created_at": SAME_TIMESTAMP,
                }
            )
        rows.extend(
            (
                cls._row("event-at-from", TENANT, CREATED_FROM),
                cls._row("event-at-to", TENANT, CREATED_TO),
                cls._row("event-other-tenant", OTHER_TENANT, SAME_TIMESTAMP),
            )
        )
        with cls.engine.begin() as connection:
            connection.execute(insert(AuditEvent.__table__), rows)
        cls.baseline_dir = cls.root / "baseline-archive"
        cls.baseline_manifest = audit_archive.archive_events(
            cls.baseline_dir,
            engine=cls.engine,
            key_file=cls.key_file,
            tenant_id=TENANT,
            created_from=CREATED_FROM,
            created_to=CREATED_TO,
            page_size=31,
            tool_source_commit=SOURCE_COMMIT,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.dispose()
        cls._temporary.cleanup()
        if os.name == "nt":
            cls._acl_patch.stop()

    @staticmethod
    def _row(identifier: str, tenant_id: str, created_at: datetime) -> dict[str, object]:
        return {
            "id": identifier,
            "tenant_id": tenant_id,
            "user_id": None,
            "device_id": None,
            "actor_id": "archive-operator",
            "event_type": "archive.boundary",
            "action": "archive.boundary",
            "result": "success",
            "entity_type": "audit_test",
            "entity_id": identifier,
            "trace_id": f"trace-{identifier}",
            "ip_address": "192.0.2.10",
            "user_agent": "archive-test-agent/1.0",
            "policy_version": None,
            "details_json": "{}",
            "created_at": created_at,
        }

    def _archive(self, name: str, *, page_size: int = 37) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        manifest = audit_archive.archive_events(
            output,
            engine=self.engine,
            key_file=self.key_file,
            tenant_id=TENANT,
            created_from=CREATED_FROM,
            created_to=CREATED_TO,
            page_size=page_size,
            tool_source_commit=SOURCE_COMMIT,
        )
        return output, manifest

    @staticmethod
    def _decrypt_payload(directory: Path, key: bytes = KEY) -> bytes:
        encrypted = (directory / audit_archive.ARTIFACT_NAME).read_bytes()
        plaintext = io.BytesIO()
        backup_crypto.decrypt_stream(
            io.BytesIO(encrypted),
            plaintext,
            key,
            len(encrypted),
            expected_logical_name=audit_archive.ARCHIVE_LOGICAL_NAME,
            expected_source_database=audit_archive.ARCHIVE_SOURCE_DATABASE,
        )
        return plaintext.getvalue()

    @classmethod
    def _records(cls, directory: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in cls._decrypt_payload(directory).splitlines()
            if line
        ]

    @staticmethod
    def _manifest(directory: Path) -> dict[str, object]:
        return json.loads((directory / audit_archive.MANIFEST_NAME).read_text("utf-8"))

    @staticmethod
    def _write_manifest(directory: Path, manifest: dict[str, object]) -> None:
        manifest[audit_archive.MANIFEST_HMAC_FIELD] = audit_archive._manifest_hmac(
            manifest, KEY
        )
        (directory / audit_archive.MANIFEST_NAME).write_bytes(
            audit_archive._canonical_json(manifest) + b"\n"
        )

    @classmethod
    def _rewrite_records(
        cls,
        directory: Path,
        records: list[dict[str, object]],
        *,
        refresh_record_evidence: bool = False,
    ) -> None:
        plaintext = b"".join(
            audit_archive._canonical_json(record) + b"\n" for record in records
        )
        encrypted = io.BytesIO()
        backup_crypto.encrypt_stream(
            io.BytesIO(plaintext),
            encrypted,
            KEY,
            logical_name=audit_archive.ARCHIVE_LOGICAL_NAME,
            source_database=audit_archive.ARCHIVE_SOURCE_DATABASE,
        )
        encrypted_bytes = encrypted.getvalue()
        (directory / audit_archive.ARTIFACT_NAME).write_bytes(encrypted_bytes)
        manifest = cls._manifest(directory)
        artifact = manifest["artifact"]
        assert isinstance(artifact, dict)
        artifact["sha256"] = hashlib.sha256(encrypted_bytes).hexdigest()
        artifact["size_bytes"] = len(encrypted_bytes)
        artifact["plaintext_sha256"] = hashlib.sha256(plaintext).hexdigest()
        if refresh_record_evidence:
            artifact["row_count"] = len(records)
            artifact["first"] = (
                {"created_at": records[0]["created_at"], "id": records[0]["id"]}
                if records
                else None
            )
            artifact["last"] = (
                {"created_at": records[-1]["created_at"], "id": records[-1]["id"]}
                if records
                else None
            )
        cls._write_manifest(directory, manifest)

    @staticmethod
    def _nonce(directory: Path) -> str:
        encrypted = (directory / audit_archive.ARTIFACT_NAME).read_bytes()
        header_size = struct.unpack(">I", encrypted[len(backup_crypto.MAGIC) : 12])[0]
        header = json.loads(encrypted[12 : 12 + header_size])
        return header["nonce"]

    def _verify(self, directory: Path, **overrides: object) -> dict[str, object]:
        arguments = {
            "key_file": self.key_file,
            "expected_tenant_id": TENANT,
            "expected_created_from": CREATED_FROM,
            "expected_created_to": CREATED_TO,
        }
        arguments.update(overrides)
        return audit_archive.verify_archive(directory, **arguments)

    def _source_snapshot(self) -> list[tuple[object, ...]]:
        columns = tuple(AuditEvent.__table__.columns)
        with self.engine.connect() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    select(*columns).order_by(AuditEvent.created_at, AuditEvent.id)
                )
            ]

    def test_keyset_pagination_window_tenant_and_source_are_complete(self) -> None:
        before = self._source_snapshot()
        before_count = len(before)

        directory = self.baseline_dir
        manifest = self.baseline_manifest
        records = self._records(directory)
        identifiers = [record["id"] for record in records]

        self.assertEqual(len(records), EXPECTED_ROWS)
        self.assertEqual(len(set(identifiers)), EXPECTED_ROWS)
        self.assertEqual(identifiers[0], "event-at-from")
        self.assertNotIn("event-at-to", identifiers)
        self.assertNotIn("event-other-tenant", identifiers)
        self.assertEqual(
            identifiers[1:],
            [f"event-{index:05d}" for index in range(SAME_TIMESTAMP_ROWS)],
        )
        self.assertEqual(manifest["artifact"]["row_count"], EXPECTED_ROWS)
        self.assertEqual(self._verify(directory)["row_count"], EXPECTED_ROWS)

        after = self._source_snapshot()
        self.assertEqual(len(after), before_count)
        self.assertEqual(after, before)

    def test_verify_rejects_same_bytes_artifact_replacement_after_manifest_read(self) -> None:
        directory = self.root / "artifact-identity-race"
        shutil.copytree(self.baseline_dir, directory)
        artifact = directory / audit_archive.ARTIFACT_NAME
        read_manifest = audit_archive._read_manifest
        replaced = False

        def replace_after_manifest(*args, **kwargs):
            nonlocal replaced
            manifest = read_manifest(*args, **kwargs)
            if not replaced:
                replaced = True
                replacement = directory / ".artifact-replacement"
                replacement.write_bytes(artifact.read_bytes())
                os.replace(replacement, artifact)
            return manifest

        with mock.patch.object(
            audit_archive,
            "_read_manifest",
            side_effect=replace_after_manifest,
        ):
            with self.assertRaisesRegex(
                audit_archive.AuditArchiveError,
                "archive file is invalid",
            ):
                self._verify(directory)

    def test_projection_redacts_historical_metadata_and_free_strings(self) -> None:
        directory = self.baseline_dir
        dirty = next(
            record for record in self._records(directory) if record["id"] == "event-00000"
        )

        self.assertEqual(dirty["ip_address"], None)
        self.assertEqual(dirty["user_agent"], "[REDACTED]")
        for field in ("event_type", "action", "entity_type", "actor_id", "trace_id"):
            self.assertEqual(dirty[field], "[REDACTED]")
        self.assertEqual(dirty["entity_id"], "[REDACTED_CARD]")
        self.assertEqual(
            dirty["details"],
            {
                "nested": {"free": "[REDACTED]"},
                "vault_reference": "[REDACTED]",
                "card_note": "legacy PAN [REDACTED_CARD]",
                "ordinary": "retained evidence",
            },
        )
        serialized = json.dumps(dirty)
        for secret in (
            "DETAIL_PASSWORD_SECRET",
            "DETAIL_AUTH_SECRET",
            "DETAIL_TOKEN_SECRET",
            "DETAIL_BEARER_SECRET",
            "ACTION_SECRET",
            "USER_AGENT_SECRET",
            "4111111111111111",
        ):
            self.assertNotIn(secret, serialized)

    def test_plaintext_evidence_is_deterministic_but_cipher_nonce_is_random(self) -> None:
        first_dir, first = self.baseline_dir, self.baseline_manifest
        second_dir, second = self._archive("random-nonce-second")

        self.assertEqual(
            first["artifact"]["plaintext_sha256"],
            second["artifact"]["plaintext_sha256"],
        )
        self.assertNotEqual(first["artifact"]["sha256"], second["artifact"]["sha256"])
        self.assertNotEqual(self._nonce(first_dir), self._nonce(second_dir))
        self.assertEqual(self._decrypt_payload(first_dir), self._decrypt_payload(second_dir))

    def test_manifest_is_closed_preflight_and_expected_identity_is_mandatory(self) -> None:
        directory, manifest = self.baseline_dir, self.baseline_manifest
        summary = self._verify(directory)

        self.assertEqual(set(manifest), audit_archive._TOP_LEVEL_FIELDS)
        self.assertEqual(set(manifest["artifact"]), audit_archive._ARTIFACT_FIELDS)
        self.assertIs(manifest["production_acceptance"], False)
        self.assertIs(summary["production_acceptance"], False)

        with self.assertRaises(VERIFY_ERRORS):
            self._verify(directory, key_file=self.other_key_file)
        for override in (
            {"expected_tenant_id": OTHER_TENANT},
            {"expected_created_from": CREATED_FROM + timedelta(microseconds=1)},
            {"expected_created_to": CREATED_TO + timedelta(microseconds=1)},
        ):
            with self.subTest(override=override), self.assertRaises(VERIFY_ERRORS):
                self._verify(directory, **override)

        mutations = {
            "bad-hmac": lambda value: value.__setitem__(
                audit_archive.MANIFEST_HMAC_FIELD, "0" * 64
            ),
            "unknown-field": lambda value: value.__setitem__("notes", "not closed"),
            "production-claim": lambda value: value.__setitem__(
                "production_acceptance", True
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                changed = self.root / f"manifest-{name}"
                shutil.copytree(directory, changed)
                changed_manifest = self._manifest(changed)
                mutate(changed_manifest)
                if name != "bad-hmac":
                    self._write_manifest(changed, changed_manifest)
                else:
                    (changed / audit_archive.MANIFEST_NAME).write_bytes(
                        audit_archive._canonical_json(changed_manifest) + b"\n"
                    )
                with self.assertRaises(VERIFY_ERRORS):
                    self._verify(changed)

    def test_cipher_bitflip_truncation_size_and_hash_tampering_fail(self) -> None:
        directory = self.baseline_dir
        for mutation in ("bitflip", "truncate", "size", "hash"):
            with self.subTest(mutation=mutation):
                changed = self.root / f"cipher-{mutation}"
                shutil.copytree(directory, changed)
                artifact_path = changed / audit_archive.ARTIFACT_NAME
                if mutation in {"bitflip", "truncate"}:
                    data = bytearray(artifact_path.read_bytes())
                    if mutation == "bitflip":
                        data[len(data) // 2] ^= 0x01
                    else:
                        del data[-1]
                    artifact_path.write_bytes(data)
                else:
                    manifest = self._manifest(changed)
                    artifact = manifest["artifact"]
                    assert isinstance(artifact, dict)
                    if mutation == "size":
                        artifact["size_bytes"] = int(artifact["size_bytes"]) + 1
                    else:
                        artifact["sha256"] = "0" * 64
                    self._write_manifest(changed, manifest)
                with self.assertRaises(VERIFY_ERRORS):
                    self._verify(changed)

    def test_deleted_reordered_and_duplicate_records_fail_after_resigning(self) -> None:
        directory = self.baseline_dir
        original = self._records(directory)
        mutations = {
            "deleted": original[1:],
            "reordered": [original[1], original[0], *original[2:]],
            "duplicate": [original[0], original[0], *original[1:]],
        }
        for name, records in mutations.items():
            with self.subTest(mutation=name):
                changed = self.root / f"record-{name}"
                shutil.copytree(directory, changed)
                self._rewrite_records(changed, records)
                with self.assertRaises(VERIFY_ERRORS):
                    self._verify(changed)

        unknown_records = [dict(record) for record in original]
        unknown_records[1]["unknown_field"] = "closed-schema-bypass"
        changed = self.root / "record-unknown-field"
        shutil.copytree(directory, changed)
        self._rewrite_records(
            changed,
            unknown_records,
            refresh_record_evidence=True,
        )
        with self.assertRaises(VERIFY_ERRORS):
            self._verify(changed)

    def test_output_is_external_write_once_and_failure_leaves_no_partial(self) -> None:
        existing = self.root / "existing-output"
        existing.mkdir()
        sentinel = existing / "operator-owned.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaises(Exception):
            audit_archive.archive_events(
                existing,
                engine=self.engine,
                key_file=self.key_file,
                tenant_id=TENANT,
                created_from=CREATED_FROM,
                created_to=CREATED_TO,
                tool_source_commit=SOURCE_COMMIT,
            )
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

        relative = Path("relative-audit-output")
        with self.assertRaises(Exception):
            audit_archive.archive_events(
                relative,
                engine=self.engine,
                key_file=self.key_file,
                tenant_id=TENANT,
                created_from=CREATED_FROM,
                created_to=CREATED_TO,
                tool_source_commit=SOURCE_COMMIT,
            )
        self.assertFalse(relative.exists())

        repository_output = ROOT / ".audit-archive-output-must-not-exist"
        self.assertFalse(repository_output.exists())
        with self.assertRaises(Exception):
            audit_archive.archive_events(
                repository_output,
                engine=self.engine,
                key_file=self.key_file,
                tenant_id=TENANT,
                created_from=CREATED_FROM,
                created_to=CREATED_TO,
                tool_source_commit=SOURCE_COMMIT,
            )
        self.assertFalse(repository_output.exists())

        failed = self.root / "failed-output"
        with self.assertRaises(Exception):
            audit_archive.archive_events(
                failed,
                engine=self.engine,
                key_file=self.root / "missing-key",
                tenant_id=TENANT,
                created_from=CREATED_FROM,
                created_to=CREATED_TO,
                tool_source_commit=SOURCE_COMMIT,
            )
        self.assertFalse(failed.exists())
        self.assertEqual(list(self.root.rglob("*.tmp")), [])

    def test_cli_failure_is_fixed_and_does_not_leak_inputs(self) -> None:
        database_url_file = self.root / "dsn-path-secret.txt"
        database_url = (
            URL.create("sqlite+pysqlite", database=str(self.database_path)).render_as_string(
                hide_password=False
            )
            + "?audit_secret=DSN_CONTENT_SECRET"
        )
        _secure_write(database_url_file, database_url.encode("utf-8"))
        output = self.root / "OUTPUT_PATH_SECRET"
        key_path = self.root / "KEY_PATH_SECRET.bin"
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = audit_archive.main(
                [
                    "archive",
                    "--output-dir",
                    str(output),
                    "--key-file",
                    str(key_path),
                    "--database-url-file",
                    str(database_url_file),
                    "--tenant-id",
                    "EVENT_VALUE_SECRET",
                    "--from-created-at",
                    "2026-08-24T08:00:00.000000Z",
                    "--until-created-at",
                    "2026-08-24T09:00:00.000000Z",
                    "--tool-source-commit",
                    SOURCE_COMMIT,
                ]
            )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "audit-archive-error: archive failed\n")
        rendered = stdout.getvalue() + stderr.getvalue()
        for secret in (
            "DSN_CONTENT_SECRET",
            "dsn-path-secret",
            "OUTPUT_PATH_SECRET",
            "KEY_PATH_SECRET",
            "EVENT_VALUE_SECRET",
        ):
            self.assertNotIn(secret, rendered)
        self.assertFalse(output.exists())

    def test_database_url_uses_the_shared_private_secret_boundary(self) -> None:
        database_url_file = self.root / "stable-database-url"
        with mock.patch.object(
            audit_archive,
            "read_private_secret_bytes",
            return_value=b"postgresql://stable",
            create=True,
        ) as stable_read:
            self.assertEqual(
                audit_archive._read_database_url_file(database_url_file),
                "postgresql://stable",
            )
        stable_read.assert_called_once_with(
            database_url_file,
            max_bytes=audit_archive.MAX_DATABASE_URL_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
