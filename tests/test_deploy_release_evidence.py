from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.backup_output_policy import publish_write_once_file
from scripts.deploy_release_evidence import (
    DeploymentReleaseEvidenceError,
    DeploymentReleaseEvidenceRecorder,
    TERMINAL_EDGE_CLOSED_FAILURE,
    TERMINAL_EDGE_UNCONFIRMED,
    TERMINAL_PREFLIGHT_FAILED,
    TERMINAL_SUCCEEDED,
    assert_expected_release,
    main,
    prepare_evidence_output,
    seal_evidence,
    utc_now,
    validate_evidence,
    verify_evidence,
)
from scripts.tls_runtime_identity import EXTERNAL_ENDPOINTS, INTERNAL_ENDPOINT_SERVICES


TARGET_RELEASE = {
    "tag": "v1.2.3",
    "commit": "a" * 40,
    "migration_head": "0025_oidc_session_revocations",
    "container_manifest_sha256": "b" * 64,
}
ROLLBACK = {
    "release_tag": "v1.2.2",
    "release_commit": "c" * 40,
    "migration_head": "0024_schema_compatibility",
    "container_manifest_sha256": "d" * 64,
    "postgres_manifest_sha256": "e" * 64,
    "redis_manifest_sha256": "f" * 64,
    "recovery_set": "release-v1.2.2-20260820T000000Z",
    "postgres_created_at": "2026-08-20T00:00:00Z",
    "redis_created_at": "2026-08-20T00:04:59Z",
}
IMAGES = {
    "api": "ghcr.io/example/manage-api@sha256:" + "1" * 64,
    "worker_mail": "ghcr.io/example/manage-api@sha256:" + "1" * 64,
    "worker_sub2": "ghcr.io/example/manage-api@sha256:" + "1" * 64,
    "web": "ghcr.io/example/manage-web@sha256:" + "2" * 64,
    "edge": "ghcr.io/example/manage-edge@sha256:" + "3" * 64,
}
THIRD_PARTY_IMAGES = {
    "postgres": "postgres@sha256:" + "4" * 64,
    "redis": "redis@sha256:" + "5" * 64,
    "keycloak": "quay.io/keycloak/keycloak@sha256:" + "6" * 64,
    "alertmanager": "prom/alertmanager@sha256:" + "7" * 64,
    "prometheus": "prom/prometheus@sha256:" + "8" * 64,
}
TARGET_INTAKE = {
    "environment": "staging",
    "manifest_payload_sha256": "9" * 64,
    "requirements_sha256": "a" * 64,
    "checkpoint_phase": 0,
}


def _recorder(
    *,
    third_party_images: dict[str, str | None] | None = None,
    started_at: str | None = None,
) -> DeploymentReleaseEvidenceRecorder:
    recorder = DeploymentReleaseEvidenceRecorder(
        target_release=TARGET_RELEASE,
        rollback=ROLLBACK,
        images=IMAGES,
        target_intake=TARGET_INTAKE,
        third_party_images=third_party_images,
        started_at=started_at,
    )
    recorder.validate_initial()
    return recorder


def _complete_preflight(recorder: DeploymentReleaseEvidenceRecorder) -> None:
    for service, image in THIRD_PARTY_IMAGES.items():
        recorder.third_party_image(service, image)
    recorder.check("rollback_readiness_verified", True)
    recorder.check("upstream_images_scanned", True)
    recorder.check("target_supply_chain_verified", True)
    recorder.check("images_pulled", True)
    recorder.check("vault_sink_checks_passed", 1)
    recorder.check("operational_checks_passed", 1)
    recorder.phase("PREFLIGHTED")


def _complete_success(recorder: DeploymentReleaseEvidenceRecorder) -> None:
    _complete_preflight(recorder)
    recorder.edge_stop_confirmed()
    recorder.phase("EDGE_STOPPED")
    recorder.phase("BACKENDS_STARTED")
    for service in ("api", "worker_mail", "worker_sub2", "web"):
        recorder.observed_image(service, IMAGES[service])
    observation = {
        "expected_sha256": "b" * 64,
        "peer_sha256": "b" * 64,
        "tls_version": "TLSv1.3",
    }
    for endpoint in INTERNAL_ENDPOINT_SERVICES:
        recorder.tls_observation("internal", endpoint, observation)
    recorder.check("internal_probes_passed", 7)
    recorder.phase("INTERNAL_VERIFIED")
    recorder.check("vault_sink_checks_passed", 2)
    recorder.edge_start_attempted()
    recorder.phase("EDGE_STARTED")
    recorder.observed_image("edge", IMAGES["edge"])
    for endpoint in EXTERNAL_ENDPOINTS:
        recorder.tls_observation("external", endpoint, observation)
    recorder.check("external_probes_passed", 2)
    recorder.phase("EXTERNAL_VERIFIED")
    recorder.check("operational_checks_passed", 2)
    recorder.outcome(TERMINAL_SUCCEEDED)


def _seal_recorder(
    recorder: DeploymentReleaseEvidenceRecorder,
) -> dict[str, object]:
    recorder.payload["finished_at"] = utc_now()
    return seal_evidence(recorder.payload)


class DeploymentReleaseEvidenceTests(unittest.TestCase):
    def test_success_is_closed_release_bound_and_independently_verified(self) -> None:
        recorder = _recorder()
        with self.assertRaisesRegex(
            DeploymentReleaseEvidenceError, "repository"
        ):
            recorder.third_party_image("postgres", THIRD_PARTY_IMAGES["redis"])
        initial_fingerprint = recorder.payload["execution_fingerprint"]
        _complete_success(recorder)
        self.assertNotEqual(
            recorder.payload["execution_fingerprint"], initial_fingerprint
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deploy-evidence.json"
            evidence = recorder.write(output)
            self.assertEqual(evidence, verify_evidence(output))
            self.assertEqual(evidence["terminal_state"], TERMINAL_SUCCEEDED)
            self.assertIsNone(evidence["error_code"])
            self.assertFalse(evidence["production_acceptance"])
            self.assertFalse(evidence["rolling_release"])
            self.assertEqual(evidence["images"]["observed"], IMAGES)
            self.assertEqual(evidence["third_party_images"], THIRD_PARTY_IMAGES)
            self.assertEqual(evidence["target_intake"], TARGET_INTAKE)
            self.assertRegex(evidence["integrity"]["payload_sha256"], r"^[0-9a-f]{64}$")
            assert_expected_release(
                evidence,
                target_release=TARGET_RELEASE,
                rollback=ROLLBACK,
                images=IMAGES,
                target_intake=TARGET_INTAKE,
                third_party_images=THIRD_PARTY_IMAGES,
            )

    def test_preflight_failure_accepts_null_third_party_inventory(self) -> None:
        recorder = _recorder()
        recorder.outcome(TERMINAL_PREFLIGHT_FAILED)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "preflight.json"
            evidence = recorder.write(output)
        self.assertEqual(evidence["terminal_state"], TERMINAL_PREFLIGHT_FAILED)
        self.assertEqual(evidence["error_code"], "deployment_preflight_failed")
        self.assertEqual(
            evidence["third_party_images"],
            {service: None for service in THIRD_PARTY_IMAGES},
        )
        assert_expected_release(
            evidence,
            target_release=TARGET_RELEASE,
            rollback=ROLLBACK,
            images=IMAGES,
            target_intake=TARGET_INTAKE,
            third_party_images={service: None for service in THIRD_PARTY_IMAGES},
        )

    def test_execution_terminals_require_complete_third_party_inventory(self) -> None:
        recorder = _recorder()
        recorder.check("rollback_readiness_verified", True)
        recorder.check("upstream_images_scanned", True)
        recorder.check("target_supply_chain_verified", True)
        recorder.check("images_pulled", True)
        recorder.check("vault_sink_checks_passed", 1)
        recorder.check("operational_checks_passed", 1)
        recorder.phase("PREFLIGHTED")
        recorder.outcome(TERMINAL_EDGE_UNCONFIRMED)
        recorder.payload["finished_at"] = utc_now()
        with self.assertRaisesRegex(
            DeploymentReleaseEvidenceError, "preflight|third-party"
        ):
            seal_evidence(recorder.payload)

    def test_closed_and_unconfirmed_execution_failure_terminals(self) -> None:
        cases = (
            (TERMINAL_EDGE_CLOSED_FAILURE, "deployment_execution_failed", True),
            (TERMINAL_EDGE_UNCONFIRMED, "edge_unconfirmed", False),
        )
        for terminal, error_code, close_confirmed in cases:
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as directory:
                recorder = _recorder()
                _complete_preflight(recorder)
                if close_confirmed:
                    recorder.edge_stop_confirmed()
                recorder.outcome(terminal)
                output = Path(directory) / f"{terminal}.json"
                evidence = recorder.write(output)
                self.assertEqual(evidence["terminal_state"], terminal)
                self.assertEqual(evidence["error_code"], error_code)
                self.assertEqual(
                    evidence["edge"]["final_state"],
                    "closed_confirmed" if close_confirmed else "unconfirmed",
                )

    def test_schema_integrity_fingerprint_and_phase_mutations_fail_closed(self) -> None:
        recorder = _recorder()
        _complete_success(recorder)
        sealed = _seal_recorder(recorder)

        unknown = json.loads(json.dumps(sealed))
        unknown["host_path"] = "forbidden"
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "schema"):
            validate_evidence(unknown)

        payload = json.loads(json.dumps(sealed))
        payload.pop("integrity")
        payload["target_release"]["commit"] = "9" * 40
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "fingerprint"):
            seal_evidence(payload)

        payload = json.loads(json.dumps(sealed))
        payload.pop("integrity")
        payload["target_intake"]["environment"] = "production"
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "fingerprint"):
            seal_evidence(payload)

        payload = json.loads(json.dumps(sealed))
        payload.pop("integrity")
        payload["images"]["observed"]["api"] = (
            "ghcr.io/example/wrong@sha256:" + "9" * 64
        )
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "observed"):
            seal_evidence(payload)

        mutations = (
            (("checks", "rollback_readiness_verified"), False, "preflight"),
            (("edge", "stop_confirmations"), 0, "edge stop|successful"),
            (("checks", "internal_probes_passed"), 6, "internal"),
            (("edge", "start_attempted"), False, "edge start|successful"),
            (("checks", "external_probes_passed"), 1, "external"),
            (("third_party_images", "redis"), None, "preflight|third-party"),
        )
        for keys, value, expected_error in mutations:
            with self.subTest(keys=keys):
                payload = json.loads(json.dumps(sealed))
                payload.pop("integrity")
                payload[keys[0]][keys[1]] = value
                if keys[0] == "third_party_images":
                    from scripts.deploy_release_evidence import execution_fingerprint

                    payload["execution_fingerprint"] = execution_fingerprint(
                        payload["target_release"],
                        payload["target_intake"],
                        payload["rollback"],
                        payload["images"]["expected"],
                        payload["third_party_images"],
                    )
                with self.assertRaisesRegex(
                    DeploymentReleaseEvidenceError, expected_error
                ):
                    seal_evidence(payload)

    def test_recovery_skew_and_cross_release_assertion_fail_closed(self) -> None:
        changed_rollback = {
            **ROLLBACK,
            "redis_created_at": "2026-08-20T00:05:01Z",
        }
        recorder = DeploymentReleaseEvidenceRecorder(
            target_release=TARGET_RELEASE,
            rollback=changed_rollback,
            images=IMAGES,
            target_intake=TARGET_INTAKE,
        )
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "too far apart"):
            recorder.validate_initial()

        recorder = _recorder()
        _complete_success(recorder)
        evidence = _seal_recorder(recorder)
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "target release"):
            assert_expected_release(
                evidence,
                target_release={**TARGET_RELEASE, "tag": "v9.9.9"},
                rollback=ROLLBACK,
                images=IMAGES,
                target_intake=TARGET_INTAKE,
                third_party_images=THIRD_PARTY_IMAGES,
            )
        with self.assertRaisesRegex(DeploymentReleaseEvidenceError, "target intake"):
            assert_expected_release(
                evidence,
                target_release=TARGET_RELEASE,
                rollback=ROLLBACK,
                images=IMAGES,
                target_intake={**TARGET_INTAKE, "environment": "production"},
                third_party_images=THIRD_PARTY_IMAGES,
            )

    def test_verifier_rejects_duplicate_keys(self) -> None:
        recorder = _recorder()
        _complete_success(recorder)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deploy-evidence.json"
            recorder.write(output)
            duplicated = output.read_text(encoding="utf-8").replace(
                '"schema_version": 3,',
                '"schema_version": 3, "schema_version": 3,',
                1,
            )
            duplicate_path = Path(directory) / "duplicate.json"
            duplicate_path.write_text(duplicated, encoding="utf-8")
            with self.assertRaisesRegex(
                DeploymentReleaseEvidenceError, "duplicate keys"
            ):
                verify_evidence(duplicate_path)

    def test_external_write_once_policy_preserves_existing_and_racing_target(self) -> None:
        recorder = _recorder()
        _complete_success(recorder)
        with self.assertRaises(DeploymentReleaseEvidenceError):
            prepare_evidence_output(Path("relative.json"))
        repository_output = Path(__file__).resolve().parents[1] / "deploy-evidence.json"
        with self.assertRaises(DeploymentReleaseEvidenceError):
            prepare_evidence_output(repository_output)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.json"
            existing.write_bytes(b"existing-wins")
            with self.assertRaises(DeploymentReleaseEvidenceError):
                recorder.write(existing)
            self.assertEqual(existing.read_bytes(), b"existing-wins")

            race = root / "race.json"

            def publish_after_race(temporary_path: Path, destination: Path) -> None:
                destination.write_bytes(b"race-wins")
                publish_write_once_file(temporary_path, destination)

            with mock.patch(
                "scripts.deploy_release_evidence.publish_write_once_file",
                side_effect=publish_after_race,
            ):
                with self.assertRaises(FileExistsError):
                    recorder.write(race)
            self.assertEqual(race.read_bytes(), b"race-wins")
            self.assertEqual(list(root.glob(f".{race.name}.*.tmp")), [])

    def test_hardlink_cleanup_failure_keeps_committed_evidence_successful(self) -> None:
        recorder = _recorder()
        _complete_success(recorder)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deploy-evidence.json"
            with mock.patch(
                "scripts.backup_output_policy.Path.unlink",
                side_effect=PermissionError("temporary cleanup denied"),
            ):
                evidence = recorder.write(output)
            self.assertEqual(evidence, verify_evidence(output))

    def test_independent_cli_verifies_expected_bindings(self) -> None:
        recorder = _recorder()
        _complete_success(recorder)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "deploy-evidence.json"
            target = root / "target.json"
            rollback = root / "rollback.json"
            recorder.write(output)
            target.write_text(json.dumps(TARGET_RELEASE), encoding="utf-8")
            rollback.write_text(json.dumps(ROLLBACK), encoding="utf-8")
            arguments = [
                "--input",
                str(output),
                "--expected-target-release",
                str(target),
                "--expected-target-environment",
                TARGET_INTAKE["environment"],
                "--expected-target-intake-manifest-sha256",
                TARGET_INTAKE["manifest_payload_sha256"],
                "--expected-target-intake-requirements-sha256",
                TARGET_INTAKE["requirements_sha256"],
                "--expected-rollback",
                str(rollback),
            ]
            for service, image in {**IMAGES, **THIRD_PARTY_IMAGES}.items():
                arguments.extend(
                    [f"--expected-{service.replace('_', '-')}-image", image]
                )
            self.assertEqual(main(arguments), 0)
            arguments[-1] = "prom/prometheus@sha256:" + "9" * 64
            self.assertEqual(main(arguments), 1)


if __name__ == "__main__":
    unittest.main()
