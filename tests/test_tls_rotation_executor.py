from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.tls_rotation_evidence import rotation_plan_digest, verify_evidence, write_evidence
from scripts.tls_rotation_executor import (
    TlsRotationExecutionError,
    _same_generation,
    execute_tls_rotation,
)
from scripts.tls_rotation_runtime import ActionReconciliation, RuntimeInstanceSnapshot
from scripts.release_control_lock import ReleaseControlLocked


OLD_LEAF = "a" * 64
NEW_LEAF = "b" * 64


def _projection() -> dict[str, object]:
    return {
        "target_environment": "staging",
        "runtime_kind": "compose",
        "service": "api",
        "expected_instance_count": 1,
        "required_observers": ["edge", "prometheus"],
        "runtime_profile_sha256": "e" * 64,
        "old_leaf_sha256": OLD_LEAF,
        "new_leaf_sha256": NEW_LEAF,
        "old_spki_sha256": "c" * 64,
        "new_spki_sha256": "d" * 64,
    }


def _instance(identifier: str, started_at: str) -> RuntimeInstanceSnapshot:
    return RuntimeInstanceSnapshot(
        evidence={
            "instance_id": identifier,
            "container_id": identifier,
            "started_at": started_at,
        }
    )


class Backend:
    runtime_kind = "compose"

    def __init__(
        self,
        *,
        fail_at: str | None = None,
        contain_fails: bool = False,
        final_drift: bool = False,
        interrupt: bool = False,
        system_exit: bool = False,
        reconciliation: str = "unknown",
        close_fails: bool = False,
    ) -> None:
        self.fail_at = fail_at
        self.contain_fails = contain_fails
        self.final_drift = final_drift
        self.interrupt = interrupt
        self.system_exit = system_exit
        self.reconciliation = reconciliation
        self.close_fails = close_fails
        self.events: list[str] = []
        self.snapshots = 0
        self.before = _instance("1" * 64, "2026-08-26T00:00:00Z")
        self.after = _instance("2" * 64, "2026-08-27T00:00:03Z")

    def preflight(self, projection) -> None:
        self.events.append("preflight")
        if self.fail_at == "preflight":
            raise RuntimeError("private preflight detail")

    def snapshot(self):
        self.events.append("snapshot")
        self.snapshots += 1
        if self.fail_at == "generation" and self.snapshots >= 2:
            return [self.before]
        if self.final_drift and self.snapshots >= 3:
            return [_instance("3" * 64, "2026-08-27T00:00:09Z")]
        return [self.before] if self.snapshots == 1 else [self.after]

    def probe_instance(self, instance, *, expected_sha256, phase, observed_at):
        self.events.append(f"probe:{phase}")
        if self.fail_at == "peer" and phase == "after_instance":
            if self.interrupt:
                if self.system_exit:
                    raise SystemExit(7)
                raise KeyboardInterrupt
            raise RuntimeError("private peer detail")
        return {
            "phase": phase,
            "observer": "direct-instance",
            "instance_id": instance.evidence["instance_id"],
            "attempt": 1,
            "expected_sha256": expected_sha256,
            "peer_sha256": expected_sha256,
            "tls_version": "TLSv1.3",
            "observed_at": observed_at,
        }

    def act(self) -> None:
        self.events.append("act")
        if self.fail_at == "action":
            raise RuntimeError("private action detail")

    def reconcile_action(self, before, *, old_sha256, new_sha256, observed_at):
        self.events.append("reconcile")
        if self.reconciliation == "unknown":
            return ActionReconciliation("unknown")
        instance = self.before if self.reconciliation == "verified_old" else self.after
        fingerprint = old_sha256 if self.reconciliation == "verified_old" else new_sha256
        phase = (
            "action_reconcile_old"
            if self.reconciliation == "verified_old"
            else "action_reconcile_new"
        )
        observation = self.probe_instance(
            instance,
            expected_sha256=fingerprint,
            phase=phase,
            observed_at=observed_at,
        )
        return ActionReconciliation(self.reconciliation, (instance,), (observation,))

    def probe_route(self, observer, *, attempt, expected_sha256, observed_at):
        self.events.append(f"route:{observer}:{attempt}")
        return {
            "phase": "retirement_route",
            "observer": observer,
            "instance_id": None,
            "attempt": attempt,
            "expected_sha256": expected_sha256,
            "peer_sha256": expected_sha256,
            "tls_version": "TLSv1.3",
            "observed_at": observed_at,
        }

    def contain(self) -> None:
        self.events.append("contain")
        if self.contain_fails:
            raise RuntimeError("private containment detail")

    def close(self) -> None:
        self.events.append("close")
        if self.close_fails:
            raise RuntimeError("private cleanup detail")


class Clock:
    def __init__(self) -> None:
        self.second = 0

    def __call__(self) -> str:
        value = f"2026-08-27T00:00:{self.second:02d}Z"
        self.second += 1
        return value


class TlsRotationExecutorTests(unittest.TestCase):
    def execute(self, backend: Backend, directory: Path) -> Path:
        projection = _projection()
        projection_path = directory / "projection.json"
        projection_path.write_text(json.dumps(projection), encoding="utf-8")
        output = directory / "rotation-evidence.json"
        with mock.patch(
            "scripts.tls_rotation_executor.release_control_lock",
            return_value=nullcontext(),
        ):
            execute_tls_rotation(
                projection_path,
                evidence_output=output,
                backend_factory=lambda value: backend,
                clock=Clock(),
                confirm_rotation_plan_sha256=rotation_plan_digest(projection),
            )
        return output

    def test_success_orders_every_instance_route_and_final_stable_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = Backend()
            output = self.execute(backend, Path(raw))
            evidence = verify_evidence(output)
        self.assertEqual(evidence["terminal_state"], "completed")
        self.assertEqual(evidence["rotation_plan_sha256"], rotation_plan_digest(_projection()))
        self.assertEqual(backend.events[:4], ["preflight", "snapshot", "probe:before_instance", "act"])
        self.assertEqual(backend.events.count("snapshot"), 4)
        self.assertEqual(len([item for item in backend.events if item.startswith("route:")]), 6)
        self.assertEqual(backend.events[-1], "close")
        self.assertEqual(backend.events.count("close"), 1)
        self.assertEqual(evidence["containment"]["result"], "not_required")
        serialized = json.dumps(evidence).casefold()
        for forbidden in ("url", "path", "pod_name", "pod_ip", "secret", "private_key"):
            self.assertNotIn(forbidden, serialized)

    def test_projection_and_output_preflight_precede_backend_construction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            projection = directory / "projection.json"
            projection.write_text("{}", encoding="utf-8")
            constructed = []
            with self.assertRaises(TlsRotationExecutionError):
                execute_tls_rotation(
                    projection,
                    evidence_output=directory / "evidence.json",
                    backend_factory=lambda value: constructed.append(value),
                    clock=Clock(),
                    confirm_rotation_plan_sha256="0" * 64,
                )
            self.assertEqual(constructed, [])
            self.assertFalse((directory / "evidence.json").exists())

            valid = directory / "valid.json"
            valid.write_text(json.dumps(_projection()), encoding="utf-8")
            existing = directory / "existing.json"
            existing.write_text("reserved", encoding="utf-8")
            with self.assertRaises(TlsRotationExecutionError):
                execute_tls_rotation(
                    valid,
                    evidence_output=existing,
                    backend_factory=lambda value: constructed.append(value),
                    clock=Clock(),
                    confirm_rotation_plan_sha256=rotation_plan_digest(_projection()),
                )
            self.assertEqual(constructed, [])
            self.assertEqual(existing.read_text(encoding="utf-8"), "reserved")

    def test_lock_contention_publishes_preflight_without_backend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            projection = directory / "projection.json"
            projection.write_text(json.dumps(_projection()), encoding="utf-8")
            output = directory / "evidence.json"
            constructed = []
            with mock.patch(
                "scripts.tls_rotation_executor.release_control_lock",
                side_effect=ReleaseControlLocked("private lock path"),
            ), self.assertRaises(TlsRotationExecutionError):
                execute_tls_rotation(
                    projection,
                    evidence_output=output,
                    backend_factory=lambda value: constructed.append(value),
                    clock=Clock(),
                    confirm_rotation_plan_sha256=rotation_plan_digest(_projection()),
                )
            evidence = verify_evidence(output)
        self.assertEqual(constructed, [])
        self.assertEqual(evidence["terminal_state"], "preflight_failed")

    def test_plan_confirmation_mismatch_precedes_lock_and_backend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            projection = directory / "projection.json"
            projection.write_text(json.dumps(_projection()), encoding="utf-8")
            output = directory / "evidence.json"
            constructed = []
            with mock.patch("scripts.tls_rotation_executor.release_control_lock") as locked:
                with self.assertRaisesRegex(TlsRotationExecutionError, "confirmation"):
                    execute_tls_rotation(
                        projection,
                        evidence_output=output,
                        backend_factory=lambda value: constructed.append(value),
                        clock=Clock(),
                        confirm_rotation_plan_sha256="f" * 64,
                    )
            locked.assert_not_called()
            self.assertEqual(constructed, [])
            self.assertFalse(output.exists())

    def test_each_failure_stage_publishes_one_closed_terminal(self) -> None:
        cases = (
            ("preflight", "preflight_failed", "not_required"),
            ("action", "action_failed", "confirmed"),
            ("generation", "generation_unconfirmed", "confirmed"),
            ("peer", "peer_verification_failed", "confirmed"),
        )
        for fail_at, terminal, containment in cases:
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as raw:
                backend = Backend(fail_at=fail_at)
                with self.assertRaisesRegex(TlsRotationExecutionError, "TLS rotation execution failed"):
                    self.execute(backend, Path(raw))
                evidence = verify_evidence(Path(raw) / "rotation-evidence.json")
                self.assertEqual(evidence["terminal_state"], terminal)
                self.assertEqual(evidence["containment"]["result"], containment)
                self.assertFalse(evidence["production_acceptance"])
                self.assertEqual(backend.events.count("close"), 1)

    def test_action_return_unknown_is_reconciled_read_only_without_retry(self) -> None:
        for result in ("verified_old", "verified_new", "unknown"):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as raw:
                backend = Backend(fail_at="action", reconciliation=result)
                with self.assertRaises(TlsRotationExecutionError):
                    self.execute(backend, Path(raw))
                evidence = verify_evidence(Path(raw) / "rotation-evidence.json")
                action = evidence["action"]
                self.assertEqual(action["return_state"], "unknown")
                self.assertEqual(action["reconciliation"]["result"], result)
                self.assertEqual(backend.events.count("act"), 1)
                self.assertEqual(backend.events.count("reconcile"), 1)
                self.assertEqual(backend.events.count("contain"), 1)
                self.assertEqual(backend.events[-1], "close")
                self.assertEqual(evidence["terminal_state"], "action_failed")

    def test_final_inventory_drift_revokes_success_and_requires_containment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = Backend(final_drift=True)
            with self.assertRaises(TlsRotationExecutionError):
                self.execute(backend, Path(raw))
            evidence = verify_evidence(Path(raw) / "rotation-evidence.json")
        self.assertEqual(evidence["terminal_state"], "generation_unconfirmed")
        self.assertIn("contain", backend.events)
        self.assertEqual(evidence["old_fingerprint_retirement"]["status"], "unconfirmed")

    def test_runtime_only_address_controller_or_image_drift_is_not_stable(self) -> None:
        evidence = {
            "instance_id": "11111111-1111-4111-8111-111111111111",
            "container_id": "containerd://" + "1" * 64,
            "started_at": "2026-08-27T00:00:03Z",
        }
        original = RuntimeInstanceSnapshot(
            evidence=evidence,
            connect_host="10.0.0.11",
            runtime_name="api-a",
            controller_id="22222222-2222-4222-8222-222222222222",
            image_identity="registry/api@sha256:" + "a" * 64,
        )
        mutations = (
            {"connect_host": "10.0.0.12"},
            {"controller_id": "33333333-3333-4333-8333-333333333333"},
            {"image_identity": "registry/api@sha256:" + "b" * 64},
        )
        for changed in mutations:
            with self.subTest(changed=changed):
                candidate = RuntimeInstanceSnapshot(
                    evidence=evidence,
                    connect_host=changed.get("connect_host", original.connect_host),
                    runtime_name=original.runtime_name,
                    controller_id=changed.get("controller_id", original.controller_id),
                    image_identity=changed.get("image_identity", original.image_identity),
                )
                self.assertFalse(_same_generation([original], [candidate]))

    def test_containment_failure_has_priority_and_keyboard_interrupt_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = Backend(fail_at="action", contain_fails=True)
            with self.assertRaises(TlsRotationExecutionError):
                self.execute(backend, Path(raw))
            evidence = verify_evidence(Path(raw) / "rotation-evidence.json")
            self.assertEqual(evidence["terminal_state"], "containment_unconfirmed")

        with tempfile.TemporaryDirectory() as raw:
            backend = Backend(fail_at="peer", interrupt=True)
            with mock.patch(
                "scripts.tls_rotation_executor.write_evidence", wraps=write_evidence
            ) as publish, self.assertRaises(KeyboardInterrupt):
                self.execute(backend, Path(raw))
            evidence = verify_evidence(Path(raw) / "rotation-evidence.json")
            self.assertEqual(evidence["terminal_state"], "peer_verification_failed")
            publish.assert_called_once()
            self.assertEqual(backend.events.count("close"), 1)

        with tempfile.TemporaryDirectory() as raw:
            backend = Backend(fail_at="peer", interrupt=True, system_exit=True)
            with mock.patch(
                "scripts.tls_rotation_executor.write_evidence", wraps=write_evidence
            ) as publish, self.assertRaises(SystemExit) as raised:
                self.execute(backend, Path(raw))
            self.assertEqual(raised.exception.code, 7)
            publish.assert_called_once()
            self.assertEqual(backend.events.count("close"), 1)

    def test_publication_failure_contains_but_never_retries_write_once_sink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            backend = Backend()
            with mock.patch(
                "scripts.tls_rotation_executor.write_evidence",
                side_effect=OSError("private output path"),
            ) as publish, self.assertRaisesRegex(
                TlsRotationExecutionError, "publication failed"
            ):
                self.execute(backend, Path(raw))
        publish.assert_called_once()
        self.assertEqual(backend.events.count("contain"), 1)
        self.assertEqual(backend.events[-1], "close")

    def test_cleanup_failure_is_fixed_and_never_masks_primary_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            backend = Backend(close_fails=True)
            with self.assertRaisesRegex(
                TlsRotationExecutionError, "^TLS rotation backend cleanup failed$"
            ):
                self.execute(backend, directory)
            self.assertTrue((directory / "rotation-evidence.json").exists())
            self.assertEqual(backend.events.count("close"), 1)

        with tempfile.TemporaryDirectory() as raw:
            backend = Backend(fail_at="preflight", close_fails=True)
            with self.assertRaisesRegex(
                TlsRotationExecutionError, "^TLS rotation execution failed$"
            ) as raised:
                self.execute(backend, Path(raw))
            self.assertEqual(backend.events.count("close"), 1)
            self.assertIn(
                "TLS rotation backend cleanup was not confirmed",
                getattr(raised.exception, "__notes__", []),
            )


if __name__ == "__main__":
    unittest.main()
