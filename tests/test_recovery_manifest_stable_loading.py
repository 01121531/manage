from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import postgres_maintenance
from scripts import redis_maintenance
from scripts import vault_maintenance
from scripts.backup_crypto import encrypt_stream, key_id


_MANIFEST_LIMIT = 64 * 1024
_POSTGRES_KEY = b"p" * 32
_REDIS_KEY = b"r" * 32
_VAULT_KEY = b"v" * 32
_RELEASE = {
    "release_tag": "v1.2.3",
    "release_commit": "a" * 40,
    "migration_head": "0028_operational_policy_governance",
    "container_manifest_sha256": "b" * 64,
}
_RECOVERY_SET = "release-v1.2.3-20260826T000000Z"


def _write_key(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    return path.resolve()


def _encrypted_artifact(
    path: Path,
    *,
    key: bytes,
    logical_name: str,
    source_database: str,
) -> tuple[str, int]:
    with path.open("wb") as destination:
        encrypt_stream(
            io.BytesIO((logical_name + "-backup").encode("ascii")),
            destination,
            key,
            logical_name=logical_name,
            source_database=source_database,
        )
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _write_postgres_bundle(root: Path) -> tuple[Path, Path, Path]:
    directory = root / "postgres-bundle"
    directory.mkdir()
    key_file = _write_key(root / "postgres.key", _POSTGRES_KEY)
    databases: dict[str, object] = {}
    for logical_name, database in (
        ("platform", "email_platform"),
        ("keycloak", "keycloak"),
    ):
        artifact = directory / f"{logical_name}.dump.enc"
        digest, size_bytes = _encrypted_artifact(
            artifact,
            key=_POSTGRES_KEY,
            logical_name=logical_name,
            source_database=database,
        )
        databases[logical_name] = {
            "database": database,
            "artifact": artifact.name,
            "sha256": digest,
            "size_bytes": size_bytes,
            "algorithm": postgres_maintenance.BACKUP_ENCRYPTION_ALGORITHM,
            "format_version": postgres_maintenance.BACKUP_ENCRYPTION_FORMAT,
            "key_id": key_id(_POSTGRES_KEY),
        }
    manifest: dict[str, object] = {
        "schema_version": postgres_maintenance.BACKUP_RELEASE_MANIFEST_SCHEMA,
        "created_at": "2026-08-26T00:00:00+00:00",
        "databases": databases,
        **_RELEASE,
    }
    manifest[postgres_maintenance.BACKUP_MANIFEST_HMAC_FIELD] = (
        postgres_maintenance._manifest_hmac_sha256(manifest, _POSTGRES_KEY)
    )
    manifest_path = directory / postgres_maintenance.BACKUP_MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return directory, manifest_path, key_file


def _write_redis_bundle(
    root: Path,
    *,
    postgres_manifest_sha256: str,
) -> tuple[Path, Path, Path]:
    directory = root / "redis-bundle"
    directory.mkdir()
    key_file = _write_key(root / "redis.key", _REDIS_KEY)
    artifact = directory / redis_maintenance.ARTIFACT_NAME
    digest, size_bytes = _encrypted_artifact(
        artifact,
        key=_REDIS_KEY,
        logical_name=redis_maintenance.LOGICAL_NAME,
        source_database=redis_maintenance.SOURCE_VOLUME,
    )
    manifest: dict[str, object] = {
        "schema_version": redis_maintenance.MANIFEST_SCHEMA,
        "created_at": "2026-08-26T00:00:00+00:00",
        "artifact": artifact.name,
        "sha256": digest,
        "size_bytes": size_bytes,
        "algorithm": redis_maintenance.BACKUP_ENCRYPTION_ALGORITHM,
        "format_version": redis_maintenance.BACKUP_ENCRYPTION_FORMAT,
        "key_id": key_id(_REDIS_KEY),
        **_RELEASE,
        "postgres_manifest_sha256": postgres_manifest_sha256,
        "recovery_set": _RECOVERY_SET,
    }
    manifest[redis_maintenance.MANIFEST_HMAC_FIELD] = (
        redis_maintenance._manifest_hmac_sha256(manifest, _REDIS_KEY)
    )
    manifest_path = directory / redis_maintenance.MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return directory, manifest_path, key_file


def _write_vault_bundle(
    root: Path,
    *,
    postgres_manifest: Path,
) -> tuple[Path, Path, Path]:
    directory = root / "vault-bundle"
    directory.mkdir()
    key_file = _write_key(root / "vault.key", _VAULT_KEY)
    snapshot = directory / vault_maintenance.SNAPSHOT_NAME
    snapshot.write_bytes(b"vault-raft-snapshot")
    snapshot_bytes = snapshot.read_bytes()
    manifest: dict[str, object] = {
        "schema_version": vault_maintenance.MANIFEST_SCHEMA,
        "created_at": "2026-08-26T00:00:00+00:00",
        "artifact": snapshot.name,
        "size_bytes": len(snapshot_bytes),
        "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "recovery_set": _RECOVERY_SET,
        "postgres_manifest_sha256": hashlib.sha256(
            postgres_manifest.read_bytes()
        ).hexdigest(),
    }
    manifest[vault_maintenance.MANIFEST_HMAC_FIELD] = (
        vault_maintenance._manifest_hmac_sha256(manifest, _VAULT_KEY)
    )
    manifest_path = directory / vault_maintenance.MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return directory, manifest_path, key_file


class RecoveryManifestStableLoadingTests(unittest.TestCase):
    def _fixture(self, root: Path) -> dict[str, Path]:
        postgres_dir, postgres_manifest, postgres_key = _write_postgres_bundle(root)
        postgres_sha256 = hashlib.sha256(postgres_manifest.read_bytes()).hexdigest()
        redis_dir, redis_manifest, redis_key = _write_redis_bundle(
            root,
            postgres_manifest_sha256=postgres_sha256,
        )
        vault_dir, vault_manifest, vault_key = _write_vault_bundle(
            root,
            postgres_manifest=postgres_manifest,
        )
        return {
            "postgres_dir": postgres_dir,
            "postgres_manifest": postgres_manifest,
            "postgres_key": postgres_key,
            "redis_dir": redis_dir,
            "redis_manifest": redis_manifest,
            "redis_key": redis_key,
            "vault_dir": vault_dir,
            "vault_manifest": vault_manifest,
            "vault_key": vault_key,
        }

    def _verify_postgres(self, fixture: dict[str, Path]) -> None:
        postgres_maintenance.verify_bundle_release_binding(
            fixture["postgres_dir"],
            key_file=fixture["postgres_key"],
            **_RELEASE,
        )

    def _verify_redis(self, fixture: dict[str, Path]) -> None:
        redis_maintenance.verify_release_backup(
            fixture["redis_dir"],
            key_file=fixture["redis_key"],
            postgres_manifest_sha256=hashlib.sha256(
                fixture["postgres_manifest"].read_bytes()
            ).hexdigest(),
            recovery_set=_RECOVERY_SET,
            **_RELEASE,
        )

    def _verify_vault(self, fixture: dict[str, Path]) -> None:
        vault_maintenance.verify_snapshot(
            fixture["vault_dir"],
            manifest_key_file=fixture["vault_key"],
            recovery_set=_RECOVERY_SET,
            postgres_manifest=fixture["postgres_manifest"],
        )

    def _verification_patches(self):
        return (
            mock.patch(
                "scripts.backup_crypto._validate_key_permissions",
                return_value=None,
            ),
            mock.patch.object(vault_maintenance, "_inspect_snapshot"),
        )

    def _refresh_vault_postgres_binding(self, fixture: dict[str, Path]) -> None:
        path = fixture["vault_manifest"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["postgres_manifest_sha256"] = hashlib.sha256(
            fixture["postgres_manifest"].read_bytes()
        ).hexdigest()
        manifest[vault_maintenance.MANIFEST_HMAC_FIELD] = (
            vault_maintenance._manifest_hmac_sha256(manifest, _VAULT_KEY)
        )
        path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    def test_postgres_manifest_rejects_same_value_duplicate_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            path = fixture["postgres_manifest"]
            manifest = json.loads(path.read_text(encoding="utf-8"))
            raw = json.dumps(manifest, separators=(",", ":"))
            path.write_text(
                "{" + '"release_tag":' + json.dumps(_RELEASE["release_tag"]) + "," + raw[1:],
                encoding="utf-8",
            )
            patches = self._verification_patches()
            with patches[0], patches[1], self.assertRaisesRegex(
                ValueError,
                "invalid backup manifest",
            ):
                self._verify_postgres(fixture)

    def test_all_four_manifest_reads_reject_files_over_64_kib(self) -> None:
        cases = (
            ("postgres", "postgres_manifest", self._verify_postgres, "invalid backup manifest"),
            ("redis", "redis_manifest", self._verify_redis, "Redis manifest is invalid"),
            (
                "vault-postgres",
                "postgres_manifest",
                self._verify_vault,
                "PostgreSQL release manifest is invalid",
            ),
            ("vault", "vault_manifest", self._verify_vault, "Vault snapshot manifest is invalid"),
        )
        for label, path_key, verifier, error in cases:
            with self.subTest(manifest=label), tempfile.TemporaryDirectory() as temporary:
                fixture = self._fixture(Path(temporary))
                path = fixture[path_key]
                raw = path.read_bytes()
                path.write_bytes(raw + b" " * (_MANIFEST_LIMIT + 1 - len(raw)))
                if label == "vault-postgres":
                    self._refresh_vault_postgres_binding(fixture)
                patches = self._verification_patches()
                with patches[0], patches[1], self.assertRaisesRegex(
                    ValueError,
                    error,
                ):
                    verifier(fixture)

    def test_all_four_manifest_reads_reject_link_or_reparse_paths(self) -> None:
        cases = (
            ("postgres", "postgres_manifest", self._verify_postgres, "invalid backup manifest"),
            ("redis", "redis_manifest", self._verify_redis, "Redis manifest is invalid"),
            (
                "vault-postgres",
                "postgres_manifest",
                self._verify_vault,
                "PostgreSQL release manifest is invalid",
            ),
            ("vault", "vault_manifest", self._verify_vault, "Vault snapshot manifest is invalid"),
        )
        for label, path_key, verifier, error in cases:
            with self.subTest(manifest=label), tempfile.TemporaryDirectory() as temporary:
                fixture = self._fixture(Path(temporary))
                rejected = fixture[path_key]
                patches = self._verification_patches()
                with patches[0], patches[1], mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    side_effect=lambda path, rejected=rejected: path == rejected,
                ), self.assertRaisesRegex(ValueError, error):
                    verifier(fixture)

    def test_all_four_manifest_reads_reject_open_file_shape_drift(self) -> None:
        cases = (
            ("postgres", self._verify_postgres, 2, "invalid backup manifest"),
            ("redis", self._verify_redis, 2, "Redis manifest is invalid"),
            (
                "vault-postgres",
                self._verify_vault,
                2,
                "PostgreSQL release manifest is invalid",
            ),
            ("vault", self._verify_vault, 4, "Vault snapshot manifest is invalid"),
        )
        for label, verifier, drift_call, error in cases:
            with self.subTest(manifest=label), tempfile.TemporaryDirectory() as temporary:
                fixture = self._fixture(Path(temporary))
                calls = 0
                real_fstat = external_json.os.fstat

                def drifting_fstat(descriptor: int):
                    nonlocal calls
                    calls += 1
                    metadata = real_fstat(descriptor)
                    if calls == drift_call:
                        return SimpleNamespace(
                            st_mode=metadata.st_mode,
                            st_dev=metadata.st_dev,
                            st_ino=metadata.st_ino,
                            st_nlink=metadata.st_nlink,
                            st_size=metadata.st_size + 1,
                            st_mtime_ns=metadata.st_mtime_ns,
                            st_file_attributes=getattr(
                                metadata,
                                "st_file_attributes",
                                0,
                            ),
                        )
                    return metadata

                patches = self._verification_patches()
                with patches[0], patches[1], mock.patch.object(
                    postgres_maintenance,
                    "load_key_file",
                    return_value=_POSTGRES_KEY,
                ), mock.patch.object(
                    redis_maintenance,
                    "load_key_file",
                    return_value=_REDIS_KEY,
                ), mock.patch.object(
                    vault_maintenance,
                    "_load_manifest_key_file",
                    return_value=_VAULT_KEY,
                ), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ), self.assertRaisesRegex(ValueError, error):
                    verifier(fixture)
                self.assertEqual(calls, drift_call)


if __name__ == "__main__":
    unittest.main()
