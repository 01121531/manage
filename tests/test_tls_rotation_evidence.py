from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.tls_rotation_evidence import (
    TERMINAL_COMPLETED,
    TlsRotationEvidenceError,
    assert_expected_rotation,
    rotation_plan_digest,
    seal_evidence,
    validate_evidence,
    verify_evidence,
)


OLD_LEAF = "a" * 64
NEW_LEAF = "b" * 64
OLD_SPKI = "c" * 64
NEW_SPKI = "d" * 64
PROFILE_SHA256 = "e" * 64


def _observation(
    phase: str,
    attempt: int,
    fingerprint: str,
    second: int,
    *,
    observer: str,
    instance_id: str | None,
) -> dict[str, object]:
    return {
        "phase": phase,
        "observer": observer,
        "instance_id": instance_id,
        "attempt": attempt,
        "expected_sha256": fingerprint,
        "peer_sha256": fingerprint,
        "tls_version": "TLSv1.3",
        "observed_at": f"2026-08-27T00:00:{second:02d}Z",
    }


def _payload(*, runtime_kind: str = "compose") -> dict[str, object]:
    if runtime_kind == "compose":
        before = [{"instance_id": "1" * 64, "container_id": "1" * 64, "started_at": "2026-08-26T00:00:00Z"}]
        after = [{"instance_id": "2" * 64, "container_id": "2" * 64, "started_at": "2026-08-27T00:00:02Z"}]
        action_kind = "compose_force_recreate"
    else:
        before = [
            {"instance_id": "11111111-1111-4111-8111-111111111111", "container_id": "containerd://" + "1" * 64, "started_at": "2026-08-26T00:00:00Z"},
            {"instance_id": "22222222-2222-4222-8222-222222222222", "container_id": "containerd://" + "2" * 64, "started_at": "2026-08-26T00:00:01Z"},
        ]
        after = [
            {"instance_id": "33333333-3333-4333-8333-333333333333", "container_id": "containerd://" + "3" * 64, "started_at": "2026-08-27T00:00:02Z"},
            {"instance_id": "44444444-4444-4444-8444-444444444444", "container_id": "containerd://" + "4" * 64, "started_at": "2026-08-27T00:00:03Z"},
        ]
        action_kind = "kubernetes_rollout"
    projection = {
        "target_environment": "staging",
        "runtime_kind": runtime_kind,
        "service": "worker-mail",
        "expected_instance_count": len(before),
        "required_observers": ["api", "worker-mail"],
        "runtime_profile_sha256": PROFILE_SHA256,
        "old_leaf_sha256": OLD_LEAF,
        "new_leaf_sha256": NEW_LEAF,
        "old_spki_sha256": OLD_SPKI,
        "new_spki_sha256": NEW_SPKI,
    }
    observations = [
        *[
            _observation("before_instance", 1, OLD_LEAF, index, observer="direct-instance", instance_id=item["instance_id"])
            for index, item in enumerate(before)
        ],
        *[
            _observation("after_instance", 1, NEW_LEAF, 5 + index, observer="direct-instance", instance_id=item["instance_id"])
            for index, item in enumerate(after)
        ],
        *[
            _observation("retirement_route", attempt, NEW_LEAF, 7 + observer_index * 3 + attempt, observer=observer, instance_id=None)
            for observer_index, observer in enumerate(projection["required_observers"])
            for attempt in (1, 2, 3)
        ],
    ]
    return {
        "schema_version": 5,
        "evidence_kind": "tls_leaf_rotation_execution",
        "production_acceptance": False,
        "target_environment": "staging",
        "runtime_kind": runtime_kind,
        "service": "worker-mail",
        "expected_instance_count": len(before),
        "required_observers": projection["required_observers"],
        "rotation_plan_sha256": rotation_plan_digest(projection),
        "runtime_profile_sha256": PROFILE_SHA256,
        "terminal_state": TERMINAL_COMPLETED,
        "error_code": None,
        "started_at": "2026-08-27T00:00:00Z",
        "finished_at": "2026-08-27T00:00:20Z",
        "reviewed_identity": {
            "old_leaf_sha256": OLD_LEAF,
            "new_leaf_sha256": NEW_LEAF,
            "old_spki_sha256": OLD_SPKI,
            "new_spki_sha256": NEW_SPKI,
        },
        "instances": {"before": before, "after": after},
        "action": {
            "kind": action_kind,
            "requested_at": "2026-08-27T00:00:01Z",
            "completed_at": "2026-08-27T00:00:04Z",
            "return_state": "confirmed",
            "reconciliation": {
                "result": "not_required",
                "reason_code": None,
                "checked_at": None,
                "instances": [],
                "peer_observations": [],
            },
        },
        "containment": {
            "kind": "none",
            "result": "not_required",
            "attempted_at": None,
            "completed_at": None,
        },
        "peer_observations": observations,
        "old_fingerprint_retirement": {
            "status": "absent_from_final_inventory_and_sampled_routes",
            "checked_at": "2026-08-27T00:00:17Z",
        },
    }


def _action_failure_payload(result: str) -> dict[str, object]:
    payload = _payload()
    before = copy.deepcopy(payload["instances"]["before"])
    candidate = (
        before
        if result == "verified_old"
        else copy.deepcopy(payload["instances"]["after"])
        if result == "verified_new"
        else []
    )
    observations = []
    if result in {"verified_old", "verified_new"}:
        fingerprint = OLD_LEAF if result == "verified_old" else NEW_LEAF
        phase = "action_reconcile_old" if result == "verified_old" else "action_reconcile_new"
        observations = [
            _observation(
                phase, 1, fingerprint, 5,
                observer="direct-instance", instance_id=candidate[0]["instance_id"],
            )
        ]
    payload["terminal_state"] = "action_failed"
    payload["error_code"] = "rotation_action_failed"
    payload["instances"]["after"] = []
    payload["action"].update({
        "completed_at": None,
        "return_state": "unknown",
        "reconciliation": {
            "result": result,
            "reason_code": "runtime_read_failed" if result == "unknown" else None,
            "checked_at": "2026-08-27T00:00:06Z",
            "instances": candidate,
            "peer_observations": observations,
        },
    })
    payload["containment"] = {
        "kind": "compose_service_stop",
        "result": "confirmed",
        "attempted_at": "2026-08-27T00:00:07Z",
        "completed_at": "2026-08-27T00:00:08Z",
    }
    payload["peer_observations"] = [
        item for item in payload["peer_observations"] if item["phase"] == "before_instance"
    ]
    payload["old_fingerprint_retirement"] = {"status": "unconfirmed", "checked_at": None}
    return payload


class TlsRotationEvidenceTests(unittest.TestCase):
    def test_action_return_unknown_requires_closed_reconciliation(self) -> None:
        for result in ("verified_old", "verified_new", "unknown"):
            with self.subTest(result=result):
                evidence = seal_evidence(_action_failure_payload(result))
                self.assertEqual(evidence["action"]["reconciliation"]["result"], result)

        reused = _action_failure_payload("verified_new")
        reused["action"]["reconciliation"]["instances"][0] = copy.deepcopy(
            reused["instances"]["before"][0]
        )
        with self.assertRaisesRegex(TlsRotationEvidenceError, "reconciliation"):
            seal_evidence(reused)

        late = _action_failure_payload("verified_new")
        late["action"]["reconciliation"]["instances"][0]["started_at"] = (
            "2026-08-27T00:00:07Z"
        )
        with self.assertRaisesRegex(TlsRotationEvidenceError, "reconciliation"):
            seal_evidence(late)

        arbitrary = _action_failure_payload("unknown")
        arbitrary["action"]["reconciliation"]["reason_code"] = "private-detail"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "reconciliation"):
            seal_evidence(arbitrary)

        verified_with_reason = _action_failure_payload("verified_old")
        verified_with_reason["action"]["reconciliation"]["reason_code"] = "runtime_read_failed"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "reconciliation"):
            seal_evidence(verified_with_reason)

    def test_completed_compose_and_kubernetes_evidence_are_closed(self) -> None:
        for runtime_kind in ("compose", "kubernetes"):
            with self.subTest(runtime_kind=runtime_kind):
                evidence = seal_evidence(_payload(runtime_kind=runtime_kind))
                self.assertEqual(validate_evidence(evidence), evidence)
                serialized = json.dumps(evidence, sort_keys=True)
                for forbidden in ("url", "path", "pem", "secret", "pod_name", "private_key"):
                    self.assertNotIn(forbidden, serialized.casefold())

    def test_completed_evidence_requires_distinct_reviewed_leaf_and_spki(self) -> None:
        mutations = (
            ("new_leaf_sha256", OLD_LEAF),
            ("new_spki_sha256", OLD_SPKI),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                payload = _payload()
                payload["reviewed_identity"][field] = value
                with self.assertRaisesRegex(TlsRotationEvidenceError, "distinct"):
                    seal_evidence(payload)

    def test_completed_evidence_requires_a_fully_replaced_runtime_generation(self) -> None:
        same_instance = _payload()
        same_instance["instances"]["after"][0]["instance_id"] = "1" * 64
        same_instance["instances"]["after"][0]["container_id"] = "1" * 64
        same_instance["peer_observations"][1]["instance_id"] = "1" * 64
        with self.assertRaisesRegex(TlsRotationEvidenceError, "instance generation"):
            seal_evidence(same_instance)

        early_instance = _payload()
        early_instance["instances"]["after"][0]["started_at"] = "2026-08-27T00:00:00Z"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "start time"):
            seal_evidence(early_instance)

        changed_replica_count = _payload(runtime_kind="kubernetes")
        changed_replica_count["instances"]["after"].pop()
        changed_replica_count["peer_observations"].pop(3)
        with self.assertRaisesRegex(TlsRotationEvidenceError, "replica count"):
            seal_evidence(changed_replica_count)

    def test_completed_evidence_requires_per_instance_and_per_observer_probes(self) -> None:
        missing = _payload()
        missing["peer_observations"].pop()
        with self.assertRaisesRegex(TlsRotationEvidenceError, "sampled routes"):
            seal_evidence(missing)

        old_peer = _payload()
        old_peer["peer_observations"][1]["expected_sha256"] = OLD_LEAF
        old_peer["peer_observations"][1]["peer_sha256"] = OLD_LEAF
        with self.assertRaisesRegex(TlsRotationEvidenceError, "per-instance"):
            seal_evidence(old_peer)

        unsupported = _payload()
        unsupported["peer_observations"][1]["tls_version"] = "TLSv1.1"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "peer observation"):
            seal_evidence(unsupported)

        not_retired = _payload()
        not_retired["old_fingerprint_retirement"] = {
            "status": "unconfirmed",
            "checked_at": None,
        }
        with self.assertRaisesRegex(TlsRotationEvidenceError, "retirement"):
            seal_evidence(not_retired)

        repeated_instance = _payload(runtime_kind="kubernetes")
        repeated_instance["peer_observations"][1]["instance_id"] = repeated_instance["peer_observations"][0]["instance_id"]
        with self.assertRaisesRegex(TlsRotationEvidenceError, "per-instance"):
            seal_evidence(repeated_instance)

        missing_observer = _payload()
        missing_observer["peer_observations"] = [
            item for item in missing_observer["peer_observations"] if item["observer"] != "worker-mail"
        ]
        with self.assertRaisesRegex(TlsRotationEvidenceError, "sampled routes"):
            seal_evidence(missing_observer)

    def test_runtime_kind_and_action_kind_cannot_be_crossed(self) -> None:
        payload = _payload()
        payload["action"]["kind"] = "kubernetes_rollout"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "action kind"):
            seal_evidence(payload)

    def test_evidence_enforces_action_probe_and_route_order(self) -> None:
        late_before = _payload()
        late_before["peer_observations"][0]["observed_at"] = "2026-08-27T00:00:02Z"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "followed rotation action"):
            seal_evidence(late_before)

        early_after = _payload()
        early_after["peer_observations"][1]["observed_at"] = "2026-08-27T00:00:03Z"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "predates rotation completion"):
            seal_evidence(early_after)

        future_start = _payload()
        future_start["instances"]["after"][0]["started_at"] = "2026-08-27T00:00:05Z"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "start time"):
            seal_evidence(future_start)

        unordered = _payload()
        routes = unordered["peer_observations"][2:5]
        routes[0]["attempt"], routes[2]["attempt"] = 3, 1
        with self.assertRaisesRegex(TlsRotationEvidenceError, "out of order"):
            seal_evidence(unordered)

    def test_failed_terminal_cannot_carry_complete_success_proof(self) -> None:
        payload = _payload()
        payload["terminal_state"] = "peer_verification_failed"
        payload["error_code"] = "peer_verification_failed"
        payload["containment"] = {
            "kind": "compose_service_stop",
            "result": "confirmed",
            "attempted_at": "2026-08-27T00:00:18Z",
            "completed_at": "2026-08-27T00:00:19Z",
        }
        payload["old_fingerprint_retirement"] = {
            "status": "unconfirmed",
            "checked_at": None,
        }
        with self.assertRaisesRegex(TlsRotationEvidenceError, "complete success proof"):
            seal_evidence(payload)

    def test_schema_rejects_extra_secret_bearing_fields_and_integrity_drift(self) -> None:
        payload = _payload()
        payload["private_key_path"] = "D:/secret/tls.key"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "schema"):
            seal_evidence(payload)

        evidence = seal_evidence(_payload())
        evidence["service"] = "api"
        with self.assertRaisesRegex(TlsRotationEvidenceError, "integrity"):
            validate_evidence(evidence)

    def test_verifier_uses_independent_projection_and_stable_closed_json(self) -> None:
        evidence = seal_evidence(_payload())
        projection = {
            "target_environment": "staging",
            "runtime_kind": "compose",
            "service": "worker-mail",
            "expected_instance_count": 1,
            "required_observers": ["api", "worker-mail"],
            "runtime_profile_sha256": PROFILE_SHA256,
            "old_leaf_sha256": OLD_LEAF,
            "new_leaf_sha256": NEW_LEAF,
            "old_spki_sha256": OLD_SPKI,
            "new_spki_sha256": NEW_SPKI,
        }
        self.assertIsNone(assert_expected_rotation(evidence, projection))
        wrong = dict(projection, new_leaf_sha256="e" * 64)
        with self.assertRaisesRegex(TlsRotationEvidenceError, "reviewed projection"):
            assert_expected_rotation(evidence, wrong)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
            self.assertEqual(verify_evidence(path), evidence)
            duplicate = path.read_text(encoding="utf-8").replace(
                '"schema_version": 5',
                '"schema_version": 5, "schema_version": 5',
                1,
            )
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(TlsRotationEvidenceError, "duplicate"):
                verify_evidence(path)


if __name__ == "__main__":
    unittest.main()
