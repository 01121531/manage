from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.release_execution_binding import (
    release_execution_alignment_errors,
    release_execution_identity,
    release_execution_review_subject,
    release_execution_review_subject_errors,
    release_execution_reviewed_at,
    selector_errors,
)
from scripts.deploy_release_evidence import TERMINAL_PREFLIGHT_FAILED
from scripts.rolling_release_evidence import (
    RollingReleaseEvidenceRecorder,
    TERMINAL_COMPLETE,
)
from tests.test_deploy_release_evidence import _complete_success, _recorder


TARGET_INTAKE = {
    "environment": "staging",
    "manifest_payload_sha256": "9" * 64,
    "requirements_sha256": "a" * 64,
    "checkpoint_phase": 0,
}
TARGET_RELEASE = {
    "tag": "v1.2.3",
    "commit": "a" * 40,
    "container_manifest_sha256": "b" * 64,
}
ALIGNMENT_TIMES = {
    "release_reviewed_at": "2099-08-26T08:30:00Z",
    "consumer_started_at": "2099-08-26T08:30:01Z",
}


def _selector(path: Path, ledger_type: str = "forward") -> dict[str, object]:
    return {
        "ledger_type": ledger_type,
        "evidence_object_reference": "worm-release-execution:record-53a",
        "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "target_intake": dict(TARGET_INTAKE),
    }


def _write_rolling_evidence(path: Path) -> None:
    source = {
        "slot": "blue",
        "tag": "v1.2.2",
        "commit": "c" * 40,
        "migration_head": "0027_card_allocation_reason",
        "container_manifest_sha256": "d" * 64,
    }
    target = {
        "slot": "green",
        "tag": TARGET_RELEASE["tag"],
        "commit": TARGET_RELEASE["commit"],
        "migration_head": "0028_operational_policy_governance",
        "container_manifest_sha256": TARGET_RELEASE[
            "container_manifest_sha256"
        ],
    }
    edge = "ghcr.io/example/manage-edge@sha256:" + "3" * 64
    worker = "ghcr.io/example/manage-api@sha256:" + "1" * 64
    recorder = RollingReleaseEvidenceRecorder(
        plan_fingerprint="7" * 64,
        source=source,
        target=target,
        source_images={
            "api": "ghcr.io/example/manage-api@sha256:" + "4" * 64,
            "web": "ghcr.io/example/manage-web@sha256:" + "5" * 64,
            "edge": edge,
        },
        target_images={
            "api": "ghcr.io/example/manage-api@sha256:" + "6" * 64,
            "web": "ghcr.io/example/manage-web@sha256:" + "7" * 64,
            "edge": edge,
        },
        expected_worker_digest=worker,
        route_before_sha256="8" * 64,
        source_route_sha256="8" * 64,
        target_route_sha256="9" * 64,
        target_intake=TARGET_INTAKE,
    )
    recorder.phase("PREFLIGHTED")
    recorder.phase("SCHEMA_EXPANDED")
    for moment in ("before", "after"):
        for service in ("worker_mail", "worker_sub2"):
            recorder.worker(moment, service, worker)
    recorder.phase("INACTIVE_VERIFIED")
    tls_observation = {
        "expected_sha256": "e" * 64,
        "peer_sha256": "e" * 64,
        "tls_version": "TLSv1.3",
    }
    for role, release in (("source", source), ("target", target)):
        for service in ("api", "web"):
            recorder.internal_tls(role, service, release["slot"], tls_observation)
    recorder.nginx("test", "green", "passed")
    recorder.nginx("reload", "green", "passed")
    recorder.phase("TRAFFIC_SWITCHED")
    for attempt in (1, 2, 3):
        recorder.public_releasez(
            release_role="target",
            attempt=attempt,
            release=target,
            result="passed",
            expected_sha256="e" * 64,
            observation=tls_observation,
        )
    recorder.outcome(TERMINAL_COMPLETE)
    recorder.write(path, "9" * 64)


class ReleaseExecutionBindingTests(unittest.TestCase):
    def test_identity_preserves_execution_window_and_consumers_follow_completion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forward.json"
            recorder = _recorder(started_at="2026-08-26T08:00:00Z")
            with mock.patch(
                "scripts.deploy_release_evidence.utc_now",
                return_value="2026-08-26T08:30:00Z",
            ):
                _complete_success(recorder)
                recorder.write(path)
            identity = release_execution_identity(path.read_bytes())
            self.assertEqual(identity["started_at"], "2026-08-26T08:00:00Z")
            self.assertEqual(identity["finished_at"], "2026-08-26T08:30:00Z")
            selector = _selector(path)
            expected = {
                "environment": "staging",
                "release_tag": TARGET_RELEASE["tag"],
                "release_commit": TARGET_RELEASE["commit"],
                "container_manifest_sha256": TARGET_RELEASE[
                    "container_manifest_sha256"
                ],
            }
            self.assertEqual(
                release_execution_alignment_errors(
                    selector,
                    path,
                    **expected,
                    release_reviewed_at="2026-08-26T08:30:00Z",
                    consumer_started_at="2026-08-26T08:30:00Z",
                ),
                [],
            )
            self.assertIn(
                "release execution must finish before its consuming evidence starts",
                release_execution_alignment_errors(
                    selector,
                    path,
                    **expected,
                    release_reviewed_at="2026-08-26T08:30:00Z",
                    consumer_started_at="2026-08-26T08:29:59Z",
                ),
            )
            self.assertIn(
                "release execution must be reviewed before its consuming evidence starts",
                release_execution_alignment_errors(
                    selector,
                    path,
                    **expected,
                    release_reviewed_at="2026-08-26T08:30:01Z",
                    consumer_started_at="2026-08-26T08:30:00Z",
                ),
            )

    def test_synthetic_and_reviewed_selector_schemas_are_closed(self) -> None:
        synthetic = {
            "ledger_type": None,
            "evidence_object_reference": None,
            "evidence_sha256": None,
            "target_intake": {
                "environment": None,
                "manifest_payload_sha256": None,
                "requirements_sha256": None,
                "checkpoint_phase": None,
            },
        }
        self.assertEqual(selector_errors(synthetic, synthetic=True), [])
        reviewed = copy.deepcopy(synthetic)
        reviewed.update(
            {
                "ledger_type": "forward",
                "evidence_object_reference": "worm-release-execution:record-53a",
                "evidence_sha256": "c" * 64,
                "target_intake": dict(TARGET_INTAKE),
            }
        )
        self.assertEqual(
            selector_errors(reviewed, synthetic=False, environment="staging"), []
        )
        reviewed["path"] = "D:/protected/release.json"
        self.assertTrue(selector_errors(reviewed, synthetic=False, environment="staging"))

    def test_review_time_is_bound_to_the_exact_selected_ledger(self) -> None:
        selector = {
            "ledger_type": "forward",
            "evidence_object_reference": "worm-release-execution:record-42a",
            "evidence_sha256": "a" * 64,
            "target_intake": dict(TARGET_INTAKE),
        }
        manifest = {
            "items": [
                {
                    "id": "release_execution_evidence",
                    "status": "provided",
                    "sha256": "a" * 64,
                    "release_execution_review_subject": {
                        "kind": "release_execution_selector_v1",
                        "selector": copy.deepcopy(selector),
                    },
                    "reviewed_by": "release-review-ticket-42",
                    "reviewed_at": "2026-08-26T08:30:00Z",
                }
            ]
        }
        self.assertEqual(
            release_execution_reviewed_at(manifest, selector),
            "2026-08-26T08:30:00Z",
        )
        wrong_digest = copy.deepcopy(manifest)
        wrong_digest["items"][0]["sha256"] = "b" * 64
        self.assertIsNone(release_execution_reviewed_at(wrong_digest, selector))
        rebound_locator = copy.deepcopy(selector)
        rebound_locator["evidence_object_reference"] = (
            "worm-release-execution:record-99b"
        )
        self.assertIsNone(
            release_execution_reviewed_at(manifest, rebound_locator)
        )
        missing_projection = copy.deepcopy(manifest)
        missing_projection["items"][0].pop(
            "release_execution_review_subject"
        )
        self.assertIsNone(
            release_execution_reviewed_at(missing_projection, selector)
        )
        duplicate = copy.deepcopy(manifest)
        duplicate["items"].append(copy.deepcopy(duplicate["items"][0]))
        self.assertIsNone(release_execution_reviewed_at(duplicate, selector))
        for invalid_reviewer in (None, "tbd", " release-review-ticket-42"):
            with self.subTest(invalid_reviewer=invalid_reviewer):
                invalid = copy.deepcopy(manifest)
                invalid["items"][0]["reviewed_by"] = invalid_reviewer
                self.assertIsNone(release_execution_reviewed_at(invalid, selector))

    def test_review_subject_is_a_closed_full_selector_projection(self) -> None:
        selector = {
            "ledger_type": "forward",
            "evidence_object_reference": "worm-release-execution:record-42a",
            "evidence_sha256": "a" * 64,
            "target_intake": dict(TARGET_INTAKE),
        }
        subject = release_execution_review_subject(selector)
        self.assertEqual(
            subject,
            {
                "kind": "release_execution_selector_v1",
                "selector": selector,
            },
        )
        self.assertEqual(release_execution_review_subject_errors(subject), [])
        for mutation in (
            {**subject, "digest_only": True},
            {**subject, "kind": "release_execution_digest_v1"},
            {**subject, "selector": None},
        ):
            with self.subTest(mutation=mutation):
                self.assertTrue(release_execution_review_subject_errors(mutation))

    def test_forward_success_is_parsed_and_bound_to_release_and_intake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forward.json"
            recorder = _recorder()
            _complete_success(recorder)
            recorder.write(path)
            selector = _selector(path)
            self.assertEqual(
                release_execution_alignment_errors(
                    selector,
                    path,
                    environment="staging",
                    release_tag=TARGET_RELEASE["tag"],
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                    **ALIGNMENT_TIMES,
                ),
                [],
            )
            selector["target_intake"]["environment"] = "production"
            self.assertTrue(
                release_execution_alignment_errors(
                    selector,
                    path,
                    environment="staging",
                    release_tag=TARGET_RELEASE["tag"],
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                    **ALIGNMENT_TIMES,
                )
            )

    def test_whole_file_digest_wrong_terminal_and_wrong_release_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forward.json"
            recorder = _recorder()
            _complete_success(recorder)
            recorder.write(path)
            selector = _selector(path)
            selector["evidence_sha256"] = "f" * 64
            self.assertTrue(
                release_execution_alignment_errors(
                    selector,
                    path,
                    environment="staging",
                    release_tag=TARGET_RELEASE["tag"],
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                    **ALIGNMENT_TIMES,
                )
            )
            selector = _selector(path)
            self.assertTrue(
                release_execution_alignment_errors(
                    selector,
                    path,
                    environment="staging",
                    release_tag="v9.9.9",
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                    **ALIGNMENT_TIMES,
                )
            )
            failed_path = Path(temporary) / "failed-forward.json"
            failed = _recorder()
            failed.outcome(TERMINAL_PREFLIGHT_FAILED)
            failed.write(failed_path)
            failed_selector = _selector(failed_path)
            terminal_errors = release_execution_alignment_errors(
                failed_selector,
                failed_path,
                environment="staging",
                release_tag=TARGET_RELEASE["tag"],
                release_commit=TARGET_RELEASE["commit"],
                container_manifest_sha256=TARGET_RELEASE[
                    "container_manifest_sha256"
                ],
                **ALIGNMENT_TIMES,
            )
            self.assertIn(
                "release execution terminal state is not successful",
                terminal_errors,
            )

    def test_rolling_selector_uses_the_rolling_v3_validator_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rolling.json"
            _write_rolling_evidence(path)
            selector = _selector(path, ledger_type="rolling")
            self.assertEqual(
                release_execution_alignment_errors(
                    selector,
                    path,
                    environment="staging",
                    release_tag=TARGET_RELEASE["tag"],
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                    **ALIGNMENT_TIMES,
                ),
                [],
            )


if __name__ == "__main__":
    unittest.main()
