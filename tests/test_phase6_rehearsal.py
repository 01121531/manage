import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.backup_output_policy import publish_write_once_file
from scripts.phase6_rehearsal import (
    REPOSITORY_ROOT,
    RehearsalError,
    SCHEMA_VERSION,
    _assert_no_secret,
    _seal_evidence,
    main,
    run_rehearsal,
    verify_evidence,
    write_evidence,
)


def fixture_evidence(commit: str) -> dict[str, object]:
    """Build valid sealed evidence without repeating the business-flow rehearsal."""

    return _seal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": "phase6_ci_rehearsal",
            "pilot_id": f"phase6-ci-rehearsal-{commit[:12]}",
            "production_acceptance": False,
            "source_commit": commit,
            "identity_mode": "local_test",
            "scenario": "login-task-card-mail-code-upload-close-audit",
            "status": "passed",
            "task_trace_id": "00000000-0000-4000-8000-000000000006",
            "checks": {
                "audit_resource_replay": True,
                "audit_trace_replay": True,
                "authenticated_platform_session": True,
                "authorization_isolation": True,
                "full_business_flow": True,
                "one_time_verification": True,
                "persistent_secret_scan": True,
                "resource_cleanup": True,
                "server_side_upload": True,
            },
            "resource_states": {
                "card_allocation": "released",
                "mail_session": "revoked_and_erased",
                "outbox": "processed",
                "task": "completed",
                "upload_job": "succeeded",
            },
            "audit_event_types": [
                "card.allocated",
                "card.released",
                "mail_session.code_checked",
                "mail_session.code_consumed",
                "mail_session.code_ready",
                "mail_session.created",
                "mail_session.revoked",
                "mail_session.watermark_initialized",
                "mailbox.health_changed",
                "task.completed",
                "task.created",
                "upload.preflight_started",
                "upload.provider_result_received",
                "upload.provider_submit_started",
                "upload.queued",
                "upload.succeeded",
            ],
            "security": {
                "ephemeral_secret_origins_excluded": [
                    "auth.login.access_token",
                    "mail_session.code.consume",
                    "mail_session.create.session_token",
                ],
                "forbidden_sentinels_found": 0,
                "persistent_surfaces": [
                    "admin_audit_csv",
                    "admin_audit_json",
                    "application_logs",
                    "database_rows",
                    "metrics",
                    "non_ephemeral_http_responses",
                ],
            },
        }
    )


class Phase6RehearsalTests(unittest.TestCase):
    def test_secret_scan_catches_encoded_and_card_field_variants(self) -> None:
        cases = (
            ("Bearer TOKEN_VALUE_0123456789abcdef", "TOKEN_VALUE_0123456789abcdef"),
            ("MAIL_PASSWORD_SENTINEL_abc%2Fdef", "MAIL_PASSWORD_SENTINEL_abc/def"),
            ('{"cvv":"731"}', "731"),
            ("4242-4242-4242-4242", "4242424242424242"),
        )
        for surface, sentinel in cases:
            with self.subTest(surface=surface), self.assertRaises(RehearsalError):
                _assert_no_secret([surface], [sentinel])

    def test_full_flow_is_deterministic_redacted_ci_evidence(self) -> None:
        commit = "a" * 40
        first = run_rehearsal(commit)
        second = run_rehearsal(commit)
        self.assertEqual(first, second)
        self.assertEqual(first, fixture_evidence(commit))
        self.assertEqual(first["schema_version"], SCHEMA_VERSION)
        self.assertEqual(first["status"], "passed")
        self.assertFalse(first["production_acceptance"])
        self.assertTrue(all(first["checks"].values()))
        self.assertIn("mailbox.health_changed", first["audit_event_types"])
        serialized = json.dumps(first)
        for forbidden in (
            "SENTINEL",
            "73918426",
            "4242424242424242",
            "phase6-upstream-7c0bd3@example.invalid",
        ):
            self.assertNotIn(forbidden, serialized)

        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            write_evidence(evidence_path, first)
            self.assertEqual(verify_evidence(evidence_path), first)
            self.assertEqual(list(evidence_path.parent.glob("*.tmp")), [])

    def test_verifier_rejects_tampering_and_unknown_fields(self) -> None:
        evidence = fixture_evidence("b" * 40)
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            write_evidence(evidence_path, evidence)
            tampered = json.loads(evidence_path.read_text(encoding="utf-8"))
            tampered["status"] = "failed"
            evidence_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(RehearsalError):
                verify_evidence(evidence_path)

            tampered = dict(evidence)
            tampered["unexpected"] = "value"
            invalid_path = Path(directory) / "invalid-evidence.json"
            with self.assertRaises(RehearsalError):
                write_evidence(invalid_path, tampered)
            self.assertFalse(invalid_path.exists())

    def test_verifier_binds_evidence_to_expected_release_commit(self) -> None:
        commit = "c" * 40
        evidence = fixture_evidence(commit)
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            write_evidence(evidence_path, evidence)
            self.assertEqual(
                verify_evidence(evidence_path, expected_commit=commit),
                evidence,
            )
            with self.assertRaises(RehearsalError):
                verify_evidence(evidence_path, expected_commit="d" * 40)
            with self.assertRaises(RehearsalError):
                verify_evidence(evidence_path, expected_commit="not-a-commit")
            self.assertEqual(
                main(
                    [
                        "verify",
                        "--input",
                        str(evidence_path),
                        "--expected-commit",
                        "d" * 40,
                    ]
                ),
                1,
            )

    def test_output_policy_rejects_relative_repository_and_existing_paths_before_run(
        self,
    ) -> None:
        evidence = fixture_evidence("e" * 40)
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing.json"
            existing.write_bytes(b"stale-evidence")
            repository_path = REPOSITORY_ROOT / "tests" / "phase6-output-forbidden.json"
            paths = (Path("relative.json"), repository_path, existing)
            with mock.patch(
                "scripts.phase6_rehearsal.run_rehearsal", return_value=evidence
            ) as rehearsal:
                for output in paths:
                    with self.subTest(output=output):
                        self.assertEqual(
                            main(
                                [
                                    "run",
                                    "--output",
                                    str(output),
                                    "--commit",
                                    "e" * 40,
                                ]
                            ),
                            1,
                        )
            rehearsal.assert_not_called()
            self.assertEqual(existing.read_bytes(), b"stale-evidence")

    def test_second_run_does_not_overwrite_committed_evidence(self) -> None:
        evidence = fixture_evidence("f" * 40)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase6-evidence.json"
            with mock.patch(
                "scripts.phase6_rehearsal.run_rehearsal", return_value=evidence
            ) as rehearsal:
                self.assertEqual(
                    main(
                        [
                            "run",
                            "--output",
                            str(output),
                            "--commit",
                            "f" * 40,
                        ]
                    ),
                    0,
                )
                original = output.read_bytes()
                self.assertEqual(
                    main(
                        [
                            "run",
                            "--output",
                            str(output),
                            "--commit",
                            "f" * 40,
                        ]
                    ),
                    1,
                )
            self.assertEqual(rehearsal.call_count, 1)
            self.assertEqual(output.read_bytes(), original)

    def test_publish_race_preserves_target_winner_and_cleans_temporary_file(self) -> None:
        evidence = fixture_evidence("1" * 40)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase6-evidence.json"

            def publish_after_race(temporary_path: Path, destination: Path) -> None:
                destination.write_bytes(b"race-winner")
                publish_write_once_file(temporary_path, destination)

            with mock.patch(
                "scripts.phase6_rehearsal.publish_write_once_file",
                side_effect=publish_after_race,
            ):
                with self.assertRaises(FileExistsError):
                    write_evidence(output, evidence)
            self.assertEqual(output.read_bytes(), b"race-winner")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_publish_cleanup_failure_is_a_committed_success(self) -> None:
        evidence = fixture_evidence("2" * 40)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase6-evidence.json"
            with mock.patch(
                "scripts.backup_output_policy.Path.unlink",
                side_effect=PermissionError("temporary cleanup denied"),
            ):
                self.assertEqual(write_evidence(output, evidence), evidence)
            self.assertEqual(verify_evidence(output), evidence)

    def test_prepublication_failure_leaves_no_final_or_temporary_file(self) -> None:
        evidence = fixture_evidence("3" * 40)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase6-evidence.json"
            with mock.patch(
                "scripts.phase6_rehearsal.os.fsync",
                side_effect=OSError("fsync failed"),
            ):
                with self.assertRaises(OSError):
                    write_evidence(output, evidence)
            self.assertFalse(output.exists())
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_unexpected_exception_and_base_exception_propagate_without_output(self) -> None:
        failures: tuple[BaseException, ...] = (
            RuntimeError("unexpected rehearsal failure"),
            KeyboardInterrupt(),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, failure in enumerate(failures):
                with self.subTest(failure=type(failure).__name__):
                    output = Path(directory) / f"phase6-evidence-{index}.json"
                    with mock.patch(
                        "scripts.phase6_rehearsal.run_rehearsal",
                        side_effect=failure,
                    ):
                        with self.assertRaises(type(failure)) as raised:
                            main(
                                [
                                    "run",
                                    "--output",
                                    str(output),
                                    "--commit",
                                    "4" * 40,
                                ]
                            )
                    self.assertIs(raised.exception, failure)
                    self.assertFalse(output.exists())

    def test_handled_run_failure_leaves_no_partial_final_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase6-evidence.json"
            self.assertEqual(
                main(
                    [
                        "run",
                        "--output",
                        str(output),
                        "--commit",
                        "not-a-commit",
                    ]
                ),
                1,
            )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
