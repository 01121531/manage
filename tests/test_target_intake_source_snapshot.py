from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import scripts.target_intake_source_snapshot as snapshot
from scripts.target_intake_validator_contract import SOURCE_FILES


EXPECTED_REPOSITORY_INPUT_FILES = (
    "deploy/phase-acceptance-matrix.json",
    "deploy/target-intake-requirements.json",
    "deploy/decision-envelopes/card-pci.synthetic.json",
    "deploy/decision-envelopes/oidc-deployment-identity.synthetic.json",
    "deploy/decision-envelopes/phase0-boundary-approval.synthetic.json",
    "deploy/provider-contracts/mail.synthetic.json",
    "deploy/provider-contracts/sub2.synthetic.json",
    "deploy/provider-observations/sub2-case-2026-09-01.json",
    "deploy/evidence-index-envelopes/phase1-platform.synthetic.json",
    "deploy/evidence-index-envelopes/phase2-mail.synthetic.json",
    "deploy/evidence-index-envelopes/phase3-card.synthetic.json",
    "deploy/evidence-index-envelopes/phase5-windows.synthetic.json",
    "deploy/evidence-index-envelopes/phase6-pilot.synthetic.json",
    "deploy/evidence-index-envelopes/phase6-operations.synthetic.json",
    "deploy/evidence-index-envelopes/sub2-execution.synthetic.json",
    "deploy/evidence-index-envelopes/vault-egress.synthetic.json",
    "deploy/inventory-envelopes/target-platform.synthetic.json",
    "deploy/inventory-envelopes/windows-pilot-inputs.synthetic.json",
    "deploy/inventory-envelopes/phase6-pilot-inputs.synthetic.json",
    "docker-compose.yml",
    ".env.example",
    "infra/keycloak/email-platform-realm.json",
    "infra/vault/policies/email-platform-api-cards.hcl",
    "infra/vault/policies/email-platform-mail.hcl",
    "infra/vault/policies/email-platform-sub2.hcl",
    "infra/vault/configure-approles.sh",
    "infra/vault/configure-audit.sh",
    "platform/requirements.txt",
)


class TargetIntakeSourceSnapshotTests(unittest.TestCase):
    def _make_repository(self, parent: Path) -> Path:
        parent.mkdir(parents=True, exist_ok=True)
        repository = parent / "repository"
        repository.mkdir()
        for index, relative_path in enumerate(snapshot.SOURCE_MEMBERS):
            path = repository.joinpath(*PurePosixPath(relative_path).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            source = snapshot.ROOT.joinpath(*PurePosixPath(relative_path).parts)
            raw = (
                source.read_bytes()
                if source.is_file()
                else f"fixture-{index}\n".encode()
            )
            path.write_bytes(raw)
        return repository

    def _prepare(self, parent: Path) -> snapshot.LoadedSourceSnapshot:
        repository = self._make_repository(parent)
        with mock.patch.object(snapshot, "ROOT", repository):
            return snapshot.prepare_source_snapshot(parent / "source-snapshot")

    def _rewrite_manifest(
        self,
        loaded: snapshot.LoadedSourceSnapshot,
        document: dict[str, object],
    ) -> tuple[str, str]:
        payload_sha256 = snapshot._payload_sha256(document)
        document["integrity"] = {"payload_sha256": payload_sha256}
        raw = snapshot._canonical_bytes(document) + b"\n"
        path = loaded.directory / snapshot.MANIFEST_FILENAME
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        path.write_bytes(raw)
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return payload_sha256, hashlib.sha256(raw).hexdigest()

    def test_inventory_is_exact_and_explicit(self) -> None:
        self.assertEqual(
            snapshot.MANIFEST_FILENAME,
            "target-intake-validator-source-snapshot.json",
        )
        self.assertEqual(
            snapshot.REPOSITORY_INPUT_FILES,
            EXPECTED_REPOSITORY_INPUT_FILES,
        )
        self.assertEqual(
            snapshot.SOURCE_MEMBERS,
            tuple(SOURCE_FILES) + EXPECTED_REPOSITORY_INPUT_FILES,
        )
        self.assertEqual(
            len(snapshot.SOURCE_MEMBERS),
            len(set(snapshot.SOURCE_MEMBERS)),
        )

    def test_prepare_load_and_recheck_closed_read_only_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            loaded = self._prepare(parent)

            self.assertEqual(
                snapshot.source_snapshot_manifest_errors(loaded.manifest),
                [],
            )
            self.assertEqual(
                set(loaded.manifest),
                snapshot.MANIFEST_KEYS,
            )
            self.assertFalse(loaded.manifest["production_acceptance"])
            self.assertEqual(loaded.manifest["source_authority"], "unverified")
            self.assertEqual(loaded.manifest["snapshot_atomicity"], "unverified")
            self.assertEqual(
                [item["path"] for item in loaded.manifest["members"]],
                list(snapshot.SOURCE_MEMBERS),
            )
            for relative_path in (
                *snapshot.SOURCE_MEMBERS,
                snapshot.MANIFEST_FILENAME,
            ):
                metadata = loaded.directory.joinpath(
                    *PurePosixPath(relative_path).parts
                ).stat()
                self.assertEqual(metadata.st_nlink, 1)
                self.assertEqual(
                    metadata.st_mode
                    & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH),
                    0,
                )

            reloaded = snapshot.load_source_snapshot(
                loaded.directory,
                expected_payload_sha256=loaded.payload_sha256,
                expected_file_sha256=loaded.file_sha256,
            )
            snapshot.recheck_source_snapshot(reloaded)

    def test_prepare_requires_absent_repository_external_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self._make_repository(parent)
            existing = parent / "existing"
            existing.mkdir()
            with mock.patch.object(snapshot, "ROOT", repository):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.prepare_source_snapshot(existing)
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.prepare_source_snapshot(repository / "inside")

    def test_prepare_opens_entire_source_set_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = parent / "repository"
            repository.mkdir()
            (repository / "one.py").write_bytes(b"one\n")
            (repository / "two.json").write_bytes(b"two\n")
            real_open = snapshot.open_stable_binary
            opened = 0

            @contextmanager
            def tracking_open(path: Path):
                nonlocal opened
                with real_open(path) as (stream, metadata):
                    opened += 1

                    class TrackedStream:
                        def read(self, size: int = -1) -> bytes:
                            self_test.assertEqual(opened, 2)
                            return stream.read(size)

                        def seek(self, offset: int) -> int:
                            return stream.seek(offset)

                    try:
                        yield TrackedStream(), metadata
                    finally:
                        opened -= 1

            self_test = self
            with (
                mock.patch.object(snapshot, "ROOT", repository),
                mock.patch.object(snapshot, "SOURCE_MEMBERS", ("one.py", "two.json")),
                mock.patch.object(snapshot, "open_stable_binary", tracking_open),
            ):
                loaded = snapshot.prepare_source_snapshot(parent / "source-snapshot")
                snapshot.recheck_source_snapshot(loaded)

    def test_prepare_rejects_multi_link_source_and_does_not_publish_manifest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self._make_repository(parent)
            source = repository.joinpath(
                *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
            )
            link = parent / "source-hardlink"
            try:
                os.link(source, link)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            destination = parent / "source-snapshot"
            with mock.patch.object(snapshot, "ROOT", repository):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.prepare_source_snapshot(destination)
            self.assertTrue(destination.is_dir())
            self.assertFalse((destination / snapshot.MANIFEST_FILENAME).exists())

    def test_prepare_rejects_member_change_between_capture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = parent / "repository"
            repository.mkdir()
            reads = iter((b"epoch-a", b"epoch-b"))

            class DriftingStream:
                def read(self, size: int = -1) -> bytes:
                    return next(reads)

                def seek(self, offset: int) -> int:
                    return offset

            @contextmanager
            def drifting_open(path: Path):
                yield DriftingStream(), SimpleNamespace(st_nlink=1, st_size=7)

            destination = parent / "source-snapshot"
            with (
                mock.patch.object(snapshot, "ROOT", repository),
                mock.patch.object(snapshot, "SOURCE_MEMBERS", ("source.py",)),
                mock.patch.object(snapshot, "open_stable_binary", drifting_open),
            ):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.prepare_source_snapshot(destination)
            self.assertFalse((destination / snapshot.MANIFEST_FILENAME).exists())

    def test_prepare_removes_manifest_if_readback_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self._make_repository(parent)
            destination = parent / "source-snapshot"
            with (
                mock.patch.object(snapshot, "ROOT", repository),
                mock.patch.object(
                    snapshot,
                    "load_source_snapshot",
                    side_effect=snapshot.SourceSnapshotError("readback failed"),
                ),
            ):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.prepare_source_snapshot(destination)
            self.assertTrue(destination.is_dir())
            self.assertFalse((destination / snapshot.MANIFEST_FILENAME).exists())

    def test_load_requires_both_exact_caller_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = self._prepare(Path(temporary))
            for payload_pin, file_pin in (
                ("0" * 64, loaded.file_sha256),
                (loaded.payload_sha256, "0" * 64),
                ("invalid", loaded.file_sha256),
                (loaded.payload_sha256, "invalid"),
            ):
                with self.subTest(payload_pin=payload_pin, file_pin=file_pin):
                    with self.assertRaises(snapshot.SourceSnapshotError):
                        snapshot.load_source_snapshot(
                            loaded.directory,
                            expected_payload_sha256=payload_pin,
                            expected_file_sha256=file_pin,
                        )

    def test_load_allows_only_exact_module_root_for_snapshot_self_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            loaded = self._prepare(parent)
            with mock.patch.object(snapshot, "ROOT", loaded.directory):
                reloaded = snapshot.load_source_snapshot(
                    loaded.directory,
                    expected_payload_sha256=loaded.payload_sha256,
                    expected_file_sha256=loaded.file_sha256,
                )
                snapshot.recheck_source_snapshot(reloaded)
            with mock.patch.object(snapshot, "ROOT", parent):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.load_source_snapshot(
                        loaded.directory,
                        expected_payload_sha256=loaded.payload_sha256,
                        expected_file_sha256=loaded.file_sha256,
                    )

    def test_load_rejects_closed_schema_and_path_drift(self) -> None:
        mutations = []
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for mutation in ("extra", "traversal"):
                loaded = self._prepare(parent / mutation)
                document = copy.deepcopy(loaded.manifest)
                if mutation == "extra":
                    document["extra"] = False
                else:
                    document["members"][0]["path"] = "../escape.py"
                payload_pin, file_pin = self._rewrite_manifest(loaded, document)
                mutations.append((loaded.directory, payload_pin, file_pin))

            for directory, payload_pin, file_pin in mutations:
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.load_source_snapshot(
                        directory,
                        expected_payload_sha256=payload_pin,
                        expected_file_sha256=file_pin,
                    )

    def test_load_rejects_extra_file_directory_and_writable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for mutation in (
                "file",
                "directory",
                "writable-member",
                "writable-manifest",
            ):
                loaded = self._prepare(parent / mutation)
                if mutation == "file":
                    (loaded.directory / "extra.txt").write_text(
                        "extra",
                        encoding="utf-8",
                    )
                elif mutation == "directory":
                    (loaded.directory / "extra-directory").mkdir()
                elif mutation == "writable-member":
                    member = loaded.directory.joinpath(
                        *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
                    )
                    member.chmod(stat.S_IRUSR | stat.S_IWUSR)
                else:
                    (loaded.directory / snapshot.MANIFEST_FILENAME).chmod(
                        stat.S_IRUSR | stat.S_IWUSR
                    )
                with self.subTest(mutation=mutation):
                    with self.assertRaises(snapshot.SourceSnapshotError):
                        snapshot.load_source_snapshot(
                            loaded.directory,
                            expected_payload_sha256=loaded.payload_sha256,
                            expected_file_sha256=loaded.file_sha256,
                        )

    def test_load_rejects_expected_member_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = self._prepare(Path(temporary))
            member = loaded.directory.joinpath(
                *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
            )
            replacement = Path(temporary) / "replacement"
            replacement.write_bytes(member.read_bytes())
            member.chmod(stat.S_IRUSR | stat.S_IWUSR)
            member.unlink()
            try:
                member.symlink_to(replacement)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaises(snapshot.SourceSnapshotError):
                snapshot.load_source_snapshot(
                    loaded.directory,
                    expected_payload_sha256=loaded.payload_sha256,
                    expected_file_sha256=loaded.file_sha256,
                )

    def test_load_rechecks_early_member_after_whole_set_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = self._prepare(Path(temporary))
            first = loaded.directory.joinpath(
                *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
            )
            original = first.read_bytes()
            real_read = snapshot._read_member
            calls = 0

            def mutate_after_second_read(path: Path, expected_size: int):
                nonlocal calls
                result = real_read(path, expected_size)
                calls += 1
                if calls == 2:
                    first.chmod(stat.S_IRUSR | stat.S_IWUSR)
                    first.write_bytes(b"X" + original[1:])
                    first.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                return result

            with mock.patch.object(snapshot, "_read_member", mutate_after_second_read):
                with self.assertRaises(snapshot.SourceSnapshotError):
                    snapshot.load_source_snapshot(
                        loaded.directory,
                        expected_payload_sha256=loaded.payload_sha256,
                        expected_file_sha256=loaded.file_sha256,
                    )

    def test_load_rejects_snapshot_member_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = self._prepare(Path(temporary))
            member = loaded.directory.joinpath(
                *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
            )
            link = Path(temporary) / "snapshot-hardlink"
            try:
                os.link(member, link)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            with self.assertRaises(snapshot.SourceSnapshotError):
                snapshot.load_source_snapshot(
                    loaded.directory,
                    expected_payload_sha256=loaded.payload_sha256,
                    expected_file_sha256=loaded.file_sha256,
                )

    def test_recheck_rejects_same_byte_member_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = self._prepare(Path(temporary))
            member = loaded.directory.joinpath(
                *PurePosixPath(snapshot.SOURCE_MEMBERS[0]).parts
            )
            raw = member.read_bytes()
            member.chmod(stat.S_IRUSR | stat.S_IWUSR)
            member.unlink()
            member.write_bytes(raw)
            member.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

            with self.assertRaises(snapshot.SourceSnapshotError):
                snapshot.recheck_source_snapshot(loaded)


if __name__ == "__main__":
    unittest.main()
