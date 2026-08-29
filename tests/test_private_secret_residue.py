from __future__ import annotations

from contextlib import nullcontext, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from scripts import private_secret_materialization as materialization
from scripts import private_secret_residue as residue


RAW = b"apiVersion: v1\nkind: Config\n"
DIGEST = hashlib.sha256(RAW).hexdigest()


def _abandon(value: materialization.MaterializedPrivateSecret) -> None:
    state = value._state
    if os.name == "nt":
        assert isinstance(state, materialization._WindowsState)
        for handle in (
            state.lease_handle,
            state.file_handle,
            state.claim_handle,
            state.directory_handle,
            state.root_handle,
        ):
            materialization._close_handle(handle)
    else:
        assert isinstance(state, materialization._PosixState)
        for descriptor in (
            state.lease_fd,
            state.file_fd,
            state.claim_fd,
            state.directory_fd,
            state.root_fd,
        ):
            os.close(descriptor)
    value._state = None
    value._closed = True


def _snapshot(directory: Path) -> dict[str, tuple[object, ...]]:
    result: dict[str, tuple[object, ...]] = {}
    for entry in directory.iterdir():
        metadata = entry.lstat()
        result[entry.name] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mode,
            metadata.st_mtime_ns,
            getattr(metadata, "st_file_attributes", None),
            hashlib.sha256(entry.read_bytes()).hexdigest(),
        )
    return result


def _inventory_artifact_bytes(
    records: list[object],
) -> tuple[bytes, str]:
    payload = {
        "kind": residue._INVENTORY_KIND,
        "records": records,
        "schema_version": 1,
    }
    payload_sha256 = hashlib.sha256(
        materialization._canonical_json(payload)
    ).hexdigest()
    payload["payload_sha256"] = payload_sha256
    return materialization._canonical_json(payload), payload_sha256


class _PrivateSecretResidueContract:
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "private-runtime"
        self.environment = mock.patch.dict(
            os.environ,
            {materialization._RUNTIME_ROOT_ENV: str(self.root)},
        )
        self.environment.start()
        self.lock = mock.patch.object(
            residue, "release_control_lock", side_effect=lambda: nullcontext()
        )
        self.release_lock = self.lock.start()

    def tearDown(self) -> None:
        self.lock.stop()
        self.environment.stop()
        self.temporary.cleanup()

    def materialize(self) -> materialization.MaterializedPrivateSecret:
        return materialization.materialize_private_secret_bytes(RAW, DIGEST)

    def candidate(self) -> tuple[materialization.MaterializedPrivateSecret, dict[str, str | None]]:
        value = self.materialize()
        _abandon(value)
        records = residue.inventory_private_secret_residues(self.root)
        record = next(
            item for item in records if item.get("claim_id") == value.path.parent.name
        )
        self.assertEqual(record["state"], "cleanup_candidate")
        return value, record

    def test_inventory_distinguishes_active_from_crash_candidate_and_is_redacted(self) -> None:
        value = self.materialize()
        try:
            active = residue.inventory_private_secret_residues(self.root)
            self.assertEqual(active, [{"claim_id": value.path.parent.name, "state": "active"}])
            rendered = json.dumps(active, sort_keys=True)
            self.assertNotIn(str(self.root), rendered)
            self.assertNotIn(RAW.decode(), rendered)
        finally:
            value.close()
        self.assertGreaterEqual(self.release_lock.call_count, 1)

        crashed, candidate = self.candidate()
        self.assertEqual(candidate["claim_id"], crashed.path.parent.name)
        self.assertRegex(str(candidate["approval_sha256"]), r"^[0-9a-f]{64}$")

    def test_wrong_approval_has_zero_mutation_then_exact_approval_cleans_one_claim(self) -> None:
        value, candidate = self.candidate()
        directory = value.path.parent
        before = _snapshot(directory)
        with self.assertRaisesRegex(
            residue.PrivateSecretResidueError,
            "^private secret residue operation failed$",
        ):
            residue._cleanup_private_secret_residue(
                directory.name, "0" * 64, self.root
            )
        self.assertEqual(before, _snapshot(directory))
        residue._cleanup_private_secret_residue(
            directory.name, str(candidate["approval_sha256"]), self.root
        )
        self.assertFalse(directory.exists())
        self.assertTrue(self.root.exists())

    def test_stale_approval_and_content_drift_are_refused_without_deletion(self) -> None:
        value, candidate = self.candidate()
        path = value.path
        path.chmod(stat.S_IWRITE | stat.S_IREAD)
        path.write_bytes(b"changed")
        if os.name != "nt":
            path.chmod(0o400)
        before = _snapshot(path.parent)
        with self.assertRaisesRegex(
            residue.PrivateSecretResidueError,
            "^private secret residue operation failed$",
        ):
            residue._cleanup_private_secret_residue(
                path.parent.name, str(candidate["approval_sha256"]), self.root
            )
        self.assertEqual(before, _snapshot(path.parent))

    def test_cleanup_preserves_sibling_claim_and_unexpected_entry_is_not_disclosed(self) -> None:
        first, first_candidate = self.candidate()
        second, _ = self.candidate()
        unexpected = self.root / "operator-private-name"
        unexpected.write_text("private", encoding="utf-8")
        records = residue.inventory_private_secret_residues(self.root)
        unknown = [record for record in records if record["state"] == "unknown"]
        self.assertEqual(
            unknown,
            [{"claim_id": None, "state": "unknown", "reason": "unexpected_entry"}],
        )
        self.assertNotIn(unexpected.name, json.dumps(records))
        residue._cleanup_private_secret_residue(
            first.path.parent.name,
            str(first_candidate["approval_sha256"]),
            self.root,
        )
        self.assertFalse(first.path.parent.exists())
        self.assertTrue(second.path.parent.exists())
        self.assertEqual(second.path.read_bytes(), RAW)
        self.assertTrue(unexpected.exists())

    def test_unauthenticated_hex_entry_never_projects_claim_id(self) -> None:
        seed = self.materialize()
        seed.close()
        invalid_name = "d" * 32
        invalid = self.root / invalid_name
        invalid.mkdir()
        (invalid / "private-name").write_bytes(b"private")
        records = residue.inventory_private_secret_residues(self.root)
        self.assertEqual(
            records,
            [{"claim_id": None, "state": "unknown", "reason": "verification_failed"}],
        )
        self.assertNotIn(invalid_name, json.dumps(records))

    def test_surface_has_no_bulk_or_heuristic_cleanup_switches(self) -> None:
        source = Path(residue.__file__).read_text(encoding="utf-8")
        for forbidden in ('"--all"', '"--force"', "getpid", "st_mtime"):
            self.assertNotIn(forbidden, source)
        self.assertIn("with release_control_lock():", source)
        self.assertIn("hmac.compare_digest(approval, confirmation)", source)
        for required in (
            '"--output"',
            '"--inventory"',
            '"--expected-payload-sha256"',
            '"--claim-id"',
            '"--confirm-residue-cleanup"',
        ):
            self.assertIn(required, source)
        self.assertFalse(hasattr(residue, "cleanup_private_secret_residue"))

    def test_cli_requires_boolean_confirmation_and_binds_inventory_digest(self) -> None:
        inventory_path = Path(self.temporary.name) / "inventory.json"
        with mock.patch.object(
            residue,
            "capture_private_secret_residue_inventory",
            return_value="a" * 64,
        ) as capture, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(
                residue.main(
                    [
                        "inventory",
                        "--runtime-root",
                        str(self.root),
                        "--output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
        capture.assert_called_once_with(inventory_path, self.root)
        self.assertIn("a" * 64, stdout.getvalue())

        cleanup_args = [
            "cleanup",
            "--runtime-root",
            str(self.root),
            "--inventory",
            str(inventory_path),
            "--expected-payload-sha256",
            "b" * 64,
            "--claim-id",
            "c" * 32,
        ]
        with mock.patch.object(
            residue, "cleanup_private_secret_residue_from_inventory"
        ) as cleanup, redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(residue.main(cleanup_args), 1)
            cleanup.assert_not_called()
            self.assertEqual(
                residue.main(cleanup_args + ["--confirm-residue-cleanup"]), 0
            )
        cleanup.assert_called_once_with(
            inventory_path, "b" * 64, "c" * 32, self.root
        )

    def test_write_once_inventory_artifact_binds_two_step_cleanup(self) -> None:
        value, _ = self.candidate()
        output = Path(self.temporary.name) / "inventory.json"
        payload_sha256 = residue.capture_private_secret_residue_inventory(
            output, self.root
        )
        raw = output.read_bytes()
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertNotIn(RAW, raw)
        with self.assertRaises(residue.PrivateSecretResidueError):
            residue.capture_private_secret_residue_inventory(output, self.root)
        self.assertEqual(output.read_bytes(), raw)
        with self.assertRaises(residue.PrivateSecretResidueError):
            residue.cleanup_private_secret_residue_from_inventory(
                output, "0" * 64, value.path.parent.name, self.root
            )
        self.assertTrue(value.path.parent.exists())
        residue.cleanup_private_secret_residue_from_inventory(
            output, payload_sha256, value.path.parent.name, self.root
        )
        self.assertFalse(value.path.parent.exists())

    def test_inventory_reader_rejects_non_producer_records_duplicates_and_order(self) -> None:
        claim_a = "a" * 32
        claim_b = "b" * 32
        invalid_records = (
            [{"claim_id": [claim_a], "state": "active"}],
            [{"claim_id": None, "state": "active"}],
            [{"claim_id": claim_a, "state": "unknown", "reason": "unexpected_entry"}],
            [{"claim_id": None, "state": "unknown", "reason": str(self.root)}],
            [{"claim_id": claim_a, "state": "cleanup_candidate", "approval_sha256": "x" * 64}],
            [
                {"claim_id": claim_a, "state": "active"},
                {"claim_id": claim_a, "state": "cleanup_candidate", "approval_sha256": "1" * 64},
            ],
            [
                {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
                {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
            ],
            [
                {"claim_id": claim_b, "state": "active"},
                {"claim_id": claim_a, "state": "active"},
            ],
        )
        artifact = Path(self.temporary.name) / "strict-inventory.json"
        for records in invalid_records:
            with self.subTest(records=records):
                raw, payload_sha256 = _inventory_artifact_bytes(records)
                artifact.write_bytes(raw)
                with self.assertRaisesRegex(
                    residue.PrivateSecretResidueError,
                    "^private secret residue operation failed$",
                ):
                    residue._read_inventory(artifact, payload_sha256)

        raw, payload_sha256 = residue._inventory_document(
            [
                {"claim_id": claim_b, "state": "active"},
                {"claim_id": claim_a, "state": "active"},
            ]
        )
        artifact.write_bytes(raw)
        self.assertEqual(
            residue._read_inventory(artifact, payload_sha256)["records"],
            [
                {"claim_id": claim_a, "state": "active"},
                {"claim_id": claim_b, "state": "active"},
            ],
        )

    def test_cleanup_inventory_must_be_outside_repository_and_runtime_root(self) -> None:
        value, candidate = self.candidate()
        before = _snapshot(value.path.parent)
        with mock.patch.object(residue, "_read_inventory") as read_inventory:
            for inventory in (
                Path(residue.__file__).resolve(),
                self.root / "reviewed-inventory.json",
            ):
                with self.subTest(inventory=inventory), self.assertRaisesRegex(
                    residue.PrivateSecretResidueError,
                    "^private secret residue operation failed$",
                ):
                    residue.cleanup_private_secret_residue_from_inventory(
                        inventory,
                        "1" * 64,
                        str(candidate["claim_id"]),
                        self.root,
                    )
        read_inventory.assert_not_called()
        self.assertEqual(before, _snapshot(value.path.parent))

    def test_write_once_committed_readback_failure_is_closed_and_not_rolled_back(self) -> None:
        output = Path(self.temporary.name) / "committed.json"
        raw = b'{"redacted":true}'
        with mock.patch.object(residue, "read_stable_bytes", return_value=b"drift"), self.assertRaisesRegex(
            residue.PrivateSecretResidueError,
            "^private secret residue operation failed$",
        ):
            residue._write_once(output, raw)
        self.assertEqual(output.read_bytes(), raw)

    def test_write_once_uses_shared_claim_publish_discard_and_stable_readback(self) -> None:
        output = Path(self.temporary.name) / "trusted-flow.json"
        raw = b'{"redacted":true}'
        with mock.patch.object(
            residue,
            "prepare_write_once_file",
            wraps=residue.prepare_write_once_file,
        ) as prepare, mock.patch.object(
            residue,
            "write_fsynced_temporary_bytes",
            wraps=residue.write_fsynced_temporary_bytes,
        ) as write, mock.patch.object(
            residue,
            "publish_write_once_file",
            wraps=residue.publish_write_once_file,
        ) as publish, mock.patch.object(
            residue,
            "discard_claimed_temporary_file",
            wraps=residue.discard_claimed_temporary_file,
        ) as discard, mock.patch.object(
            residue,
            "read_stable_bytes",
            wraps=residue.read_stable_bytes,
        ) as readback, mock.patch.object(
            residue,
            "_verify_output_parent",
            wraps=residue._verify_output_parent,
        ) as verify_parent:
            residue._write_once(output, raw)
        prepare.assert_called_once_with(output)
        write.assert_called_once()
        publish.assert_called_once()
        self.assertGreaterEqual(discard.call_count, 1)
        readback.assert_called_once_with(output, max_bytes=residue._INVENTORY_MAX_BYTES)
        self.assertGreaterEqual(verify_parent.call_count, 3)
        self.assertEqual(output.read_bytes(), raw)

    def test_real_cli_round_trip_is_inventory_bound_and_has_fixed_stderr(self) -> None:
        value, _ = self.candidate()
        output = Path(self.temporary.name) / "cli-inventory.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            self.assertEqual(
                residue.main(
                    [
                        "inventory",
                        "--runtime-root",
                        str(self.root),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
        digest = stdout.getvalue().strip().removeprefix(
            "private-secret-residue-inventory-sha256="
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        cleanup_args = [
            "cleanup",
            "--runtime-root",
            str(self.root),
            "--inventory",
            str(output),
            "--expected-payload-sha256",
            digest,
            "--claim-id",
            value.path.parent.name,
        ]
        before = _snapshot(value.path.parent)
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            self.assertEqual(residue.main(cleanup_args), 1)
        self.assertEqual(stderr.getvalue(), "private secret residue operation failed\n")
        self.assertNotIn(str(self.root), stderr.getvalue())
        self.assertEqual(before, _snapshot(value.path.parent))
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            self.assertEqual(
                residue.main(cleanup_args + ["--confirm-residue-cleanup"]), 0
            )
        self.assertEqual(stdout.getvalue(), "private-secret-residue-cleanup-ok\n")
        self.assertFalse(value.path.parent.exists())

    def test_extra_claim_child_is_unknown_and_cleanup_has_zero_mutation(self) -> None:
        value, candidate = self.candidate()
        extra = value.path.parent / "operator-owned"
        extra.write_bytes(b"preserve")
        records = residue.inventory_private_secret_residues(self.root)
        unknown = [item for item in records if item.get("state") == "unknown"]
        self.assertIn(
            {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
            unknown,
        )
        self.assertNotIn(value.path.parent.name, json.dumps(records))
        before = _snapshot(value.path.parent)
        with self.assertRaises(residue.PrivateSecretResidueError):
            residue._cleanup_private_secret_residue(
                value.path.parent.name, str(candidate["approval_sha256"]), self.root
            )
        self.assertEqual(before, _snapshot(value.path.parent))


@unittest.skipUnless(os.name == "nt", "Windows residue tests")
class WindowsPrivateSecretResidueTests(
    _PrivateSecretResidueContract, unittest.TestCase
):
    def test_runtime_root_and_claim_objects_have_protected_acl(self) -> None:
        value = self.materialize()
        try:
            state = value._state
            self.assertIsInstance(state, materialization._WindowsState)
            assert isinstance(state, materialization._WindowsState)
            for handle in (
                state.root_handle,
                state.directory_handle,
                state.file_handle,
                state.claim_handle,
                state.lease_handle,
            ):
                materialization._win_acl(handle, state.current_sid)
            self.assertEqual(value.path.parent.parent, self.root)
            self.assertEqual(set(entry.name for entry in value.path.parent.iterdir()), {"secret", "claim.json", "lease"})
        finally:
            value.close()

    def test_cleanup_closehandle_failure_is_never_reported_as_success(self) -> None:
        value, candidate = self.candidate()
        real_close = materialization._close_handle
        real_mark = materialization._mark_windows_delete
        marks = 0

        def close_directory_but_report_failure(handle):
            result = real_close(handle)
            return False if marks == 4 else result

        def track_mark(handle):
            nonlocal marks
            real_mark(handle)
            marks += 1

        with mock.patch.object(
            materialization,
            "_close_handle",
            side_effect=close_directory_but_report_failure,
        ), mock.patch.object(
            materialization,
            "_mark_windows_delete",
            side_effect=track_mark,
        ), self.assertRaisesRegex(
            residue.PrivateSecretResidueError,
            "^private secret residue operation failed$",
        ):
            residue._cleanup_private_secret_residue(
                value.path.parent.name,
                str(candidate["approval_sha256"]),
                self.root,
            )
        self.assertFalse(value.path.parent.exists())


@unittest.skipIf(os.name == "nt", "POSIX residue tests")
class PosixPrivateSecretResidueTests(
    _PrivateSecretResidueContract, unittest.TestCase
):
    def test_runtime_root_and_claim_modes_are_strict(self) -> None:
        value = self.materialize()
        try:
            self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(value.path.parent).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(value.path).st_mode), 0o400)
            self.assertEqual(
                stat.S_IMODE(os.stat(value.path.parent / "claim.json").st_mode), 0o400
            )
            self.assertEqual(
                stat.S_IMODE(os.stat(value.path.parent / "lease").st_mode), 0o600
            )
        finally:
            value.close()


if __name__ == "__main__":
    unittest.main()
