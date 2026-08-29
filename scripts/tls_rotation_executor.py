"""Execute one reviewed TLS leaf rotation and publish one closed terminal record.

Runtime-specific commands and connection details belong to the supplied backend.
This coordinator deliberately handles only ordering, generation proof, containment,
and write-once evidence publication.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
import hmac
from pathlib import Path
import re
from typing import Callable, Mapping, Protocol, Sequence

from scripts.backup_output_policy import REPOSITORY_ROOT, prepare_write_once_file
from scripts.release_control_lock import release_control_lock
from scripts.tls_rotation_evidence import (
    ACTION_KIND,
    EVIDENCE_KIND,
    SCHEMA_VERSION,
    TERMINAL_ACTION_FAILED,
    TERMINAL_COMPLETED,
    TERMINAL_CONTAINMENT_UNCONFIRMED,
    TERMINAL_GENERATION_UNCONFIRMED,
    TERMINAL_PEER_VERIFICATION_FAILED,
    TERMINAL_PREFLIGHT_FAILED,
    load_projection,
    rotation_plan_digest,
    write_evidence,
)
from scripts.tls_rotation_runtime import (
    ACTION_RECONCILIATION_REASON_CODES,
    ActionReconciliation,
    RuntimeInstanceSnapshot,
    assert_generation_replaced,
)


class TlsRotationExecutionError(RuntimeError):
    """The controlled rotation did not produce a completed terminal record."""


class RotationBackend(Protocol):
    runtime_kind: str

    def preflight(self, projection: Mapping[str, object]) -> None: ...
    def snapshot(self) -> Sequence[RuntimeInstanceSnapshot]: ...
    def probe_instance(
        self,
        instance: RuntimeInstanceSnapshot,
        *,
        expected_sha256: str,
        phase: str,
        observed_at: str,
    ) -> dict[str, object]: ...
    def act(self) -> None: ...
    def reconcile_action(
        self,
        before: Sequence[RuntimeInstanceSnapshot],
        *,
        old_sha256: str,
        new_sha256: str,
        observed_at: str,
    ) -> ActionReconciliation: ...
    def probe_route(
        self,
        observer: str,
        *,
        attempt: int,
        expected_sha256: str,
        observed_at: str,
    ) -> dict[str, object]: ...
    def contain(self) -> None: ...
    def close(self) -> None: ...


BackendFactory = Callable[[Mapping[str, object]], RotationBackend]
Clock = Callable[[], str]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _BackendLifecycle(AbstractContextManager["_BackendLifecycle"]):
    """Close one constructed backend after all publish/containment handling."""

    def __init__(self) -> None:
        self.backend: RotationBackend | None = None

    def __enter__(self) -> "_BackendLifecycle":
        return self

    def bind(self, backend: RotationBackend) -> RotationBackend:
        if self.backend is not None:
            raise TlsRotationExecutionError("TLS rotation backend lifecycle is invalid")
        self.backend = backend
        return backend

    def __exit__(self, error_type, error, traceback) -> bool:
        if self.backend is None:
            return False
        try:
            self.backend.close()
        except BaseException:
            if error is not None:
                if hasattr(error, "add_note"):
                    error.add_note("TLS rotation backend cleanup was not confirmed")
                return False
            raise TlsRotationExecutionError(
                "TLS rotation backend cleanup failed"
            ) from None
        return False


def _external_projection_path(path: Path) -> Path:
    if not path.is_absolute():
        raise TlsRotationExecutionError("TLS rotation input preflight failed")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise TlsRotationExecutionError("TLS rotation input preflight failed")


def _base_payload(projection: Mapping[str, object], *, started_at: str) -> dict[str, object]:
    runtime_kind = str(projection["runtime_kind"])
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "production_acceptance": False,
        "target_environment": projection["target_environment"],
        "runtime_kind": runtime_kind,
        "service": projection["service"],
        "expected_instance_count": projection["expected_instance_count"],
        "required_observers": list(projection["required_observers"]),
        "rotation_plan_sha256": rotation_plan_digest(projection),
        "runtime_profile_sha256": projection["runtime_profile_sha256"],
        "terminal_state": TERMINAL_PREFLIGHT_FAILED,
        "error_code": "rotation_preflight_failed",
        "started_at": started_at,
        "finished_at": started_at,
        "reviewed_identity": {
            "old_leaf_sha256": projection["old_leaf_sha256"],
            "new_leaf_sha256": projection["new_leaf_sha256"],
            "old_spki_sha256": projection["old_spki_sha256"],
            "new_spki_sha256": projection["new_spki_sha256"],
        },
        "instances": {"before": [], "after": []},
        "action": {
            "kind": ACTION_KIND[runtime_kind],
            "requested_at": None,
            "completed_at": None,
            "return_state": "not_requested",
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
        "peer_observations": [],
        "old_fingerprint_retirement": {"status": "unconfirmed", "checked_at": None},
    }


def _set_terminal(payload: dict[str, object], terminal: str) -> None:
    payload["terminal_state"] = terminal
    payload["error_code"] = {
        TERMINAL_COMPLETED: None,
        TERMINAL_PREFLIGHT_FAILED: "rotation_preflight_failed",
        TERMINAL_ACTION_FAILED: "rotation_action_failed",
        TERMINAL_GENERATION_UNCONFIRMED: "runtime_generation_unconfirmed",
        TERMINAL_PEER_VERIFICATION_FAILED: "peer_verification_failed",
        TERMINAL_CONTAINMENT_UNCONFIRMED: "rotation_containment_unconfirmed",
    }[terminal]


def _publish(
    payload: dict[str, object], output: Path, *, clock: Clock
) -> dict[str, object]:
    payload["finished_at"] = clock()
    return write_evidence(payload, output)


def _failure_terminal(stage: str) -> str:
    return {
        "preflight": TERMINAL_PREFLIGHT_FAILED,
        "action": TERMINAL_ACTION_FAILED,
        "generation": TERMINAL_GENERATION_UNCONFIRMED,
        "peer": TERMINAL_PEER_VERIFICATION_FAILED,
    }[stage]


def _contain_after_mutation(
    backend: RotationBackend,
    payload: dict[str, object],
    *,
    clock: Clock,
) -> bool:
    containment = payload["containment"]
    assert isinstance(containment, dict)
    containment.update(
        {
            "kind": (
                "compose_service_stop"
                if backend.runtime_kind == "compose"
                else "kubernetes_rollout_pause"
            ),
            "result": "unconfirmed",
            "attempted_at": clock(),
            "completed_at": None,
        }
    )
    try:
        backend.contain()
    except BaseException:
        return False
    containment["result"] = "confirmed"
    containment["completed_at"] = clock()
    return True


def _handle_failure(
    error: BaseException,
    *,
    stage: str,
    backend: RotationBackend | None,
    payload: dict[str, object],
    output: Path,
    clock: Clock,
) -> None:
    terminal = _failure_terminal(stage)
    action = payload["action"]
    assert isinstance(action, dict)
    observations = payload["peer_observations"]
    instances = payload["instances"]
    assert isinstance(observations, list) and isinstance(instances, dict)
    payload["old_fingerprint_retirement"] = {
        "status": "unconfirmed",
        "checked_at": None,
    }
    if stage == "preflight":
        action["requested_at"] = None
        action["completed_at"] = None
        action["return_state"] = "not_requested"
        action["reconciliation"] = {
            "result": "not_required",
            "reason_code": None,
            "checked_at": None,
            "instances": [],
            "peer_observations": [],
        }
        instances["after"] = []
        observations[:] = [
            item for item in observations if item.get("phase") == "before_instance"
        ]
    elif stage == "action":
        action["completed_at"] = None
        instances["after"] = []
        observations[:] = [
            item for item in observations if item.get("phase") == "before_instance"
        ]
    elif stage == "generation":
        observations[:] = [
            item for item in observations if item.get("phase") != "retirement_route"
        ]
    if action["requested_at"] is not None and backend is not None:
        if not _contain_after_mutation(backend, payload, clock=clock):
            terminal = TERMINAL_CONTAINMENT_UNCONFIRMED
    _set_terminal(payload, terminal)
    try:
        _publish(payload, output, clock=clock)
    except BaseException:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise error
        raise TlsRotationExecutionError("TLS rotation evidence publication failed") from None
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        raise error
    raise TlsRotationExecutionError("TLS rotation execution failed") from None


def _same_generation(
    left: Sequence[RuntimeInstanceSnapshot],
    right: Sequence[RuntimeInstanceSnapshot],
) -> bool:
    return list(left) == list(right)


def _reconcile_unknown_action(
    backend: RotationBackend,
    before: Sequence[RuntimeInstanceSnapshot],
    projection: Mapping[str, object],
    payload: dict[str, object],
    *,
    clock: Clock,
) -> None:
    """Record one read-only assessment without retrying the mutation."""

    action = payload["action"]
    assert isinstance(action, dict)
    action["return_state"] = "unknown"
    result = ActionReconciliation(
        "unknown", reason_code="reconcile_contract_invalid"
    )
    try:
        candidate = backend.reconcile_action(
            before,
            old_sha256=str(projection["old_leaf_sha256"]),
            new_sha256=str(projection["new_leaf_sha256"]),
            observed_at=clock(),
        )
        if (
            isinstance(candidate, ActionReconciliation)
            and candidate.result in {"verified_old", "verified_new", "unknown"}
            and (
                (
                    candidate.result == "unknown"
                    and candidate.reason_code in ACTION_RECONCILIATION_REASON_CODES
                    and not candidate.instances
                    and not candidate.peer_observations
                )
                or (
                    candidate.result != "unknown"
                    and candidate.reason_code is None
                )
            )
        ):
            result = candidate
    except BaseException:
        result = ActionReconciliation("unknown", reason_code="runtime_read_failed")
    action["reconciliation"] = {
        "result": result.result,
        "reason_code": result.reason_code,
        "checked_at": clock(),
        "instances": [dict(item.evidence) for item in result.instances],
        "peer_observations": [dict(item) for item in result.peer_observations],
    }


def execute_tls_rotation(
    projection_path: Path,
    *,
    evidence_output: Path,
    backend_factory: BackendFactory,
    clock: Clock,
    confirm_rotation_plan_sha256: str,
) -> dict[str, object]:
    """Execute one plan under the shared release lock.

    Invalid/unsafe input and output paths fail before a backend exists. Once both
    are safe, every catchable execution failure is best-effort published exactly
    once. Publication failure, process death, and host loss are explicit limits of
    a single write-once sink.
    """

    try:
        output = prepare_write_once_file(evidence_output)
        projection = load_projection(_external_projection_path(projection_path))
        actual_plan_sha256 = rotation_plan_digest(projection)
        if (
            not isinstance(confirm_rotation_plan_sha256, str)
            or _SHA256.fullmatch(confirm_rotation_plan_sha256) is None
            or not hmac.compare_digest(
                confirm_rotation_plan_sha256,
                actual_plan_sha256,
            )
        ):
            raise TlsRotationExecutionError("TLS rotation plan confirmation failed")
    except (OSError, TypeError, ValueError):
        raise TlsRotationExecutionError("TLS rotation input preflight failed") from None

    payload = _base_payload(projection, started_at=clock())
    backend: RotationBackend | None = None
    stage = "preflight"
    try:
        with release_control_lock(), _BackendLifecycle() as lifecycle:
            try:
                backend = lifecycle.bind(backend_factory(projection))
                if backend.runtime_kind != projection["runtime_kind"]:
                    raise TlsRotationExecutionError("TLS rotation backend mismatch")
                backend.preflight(projection)
                before = list(backend.snapshot())
                instances = payload["instances"]
                assert isinstance(instances, dict)
                instances["before"] = [dict(item.evidence) for item in before]
                observations = payload["peer_observations"]
                assert isinstance(observations, list)
                for instance in before:
                    observations.append(
                        backend.probe_instance(
                            instance,
                            expected_sha256=str(projection["old_leaf_sha256"]),
                            phase="before_instance",
                            observed_at=clock(),
                        )
                    )

                stage = "action"
                action = payload["action"]
                assert isinstance(action, dict)
                action["requested_at"] = clock()
                try:
                    backend.act()
                except BaseException:
                    _reconcile_unknown_action(
                        backend,
                        before,
                        projection,
                        payload,
                        clock=clock,
                    )
                    raise
                completed_at = clock()
                action.update({"completed_at": completed_at, "return_state": "confirmed"})

                stage = "generation"
                after = list(backend.snapshot())
                assert_generation_replaced(
                    before,
                    after,
                    expected_count=int(projection["expected_instance_count"]),
                )
                instances["after"] = [dict(item.evidence) for item in after]

                stage = "peer"
                for instance in after:
                    observations.append(
                        backend.probe_instance(
                            instance,
                            expected_sha256=str(projection["new_leaf_sha256"]),
                            phase="after_instance",
                            observed_at=clock(),
                        )
                    )
                for observer in projection["required_observers"]:
                    for attempt in (1, 2, 3):
                        observations.append(
                            backend.probe_route(
                                str(observer),
                                attempt=attempt,
                                expected_sha256=str(projection["new_leaf_sha256"]),
                                observed_at=clock(),
                            )
                        )

                stage = "generation"
                final_first = list(backend.snapshot())
                final_second = list(backend.snapshot())
                if not _same_generation(after, final_first) or not _same_generation(
                    final_first, final_second
                ):
                    raise TlsRotationExecutionError("final runtime generation drifted")

                payload["old_fingerprint_retirement"] = {
                    "status": "absent_from_final_inventory_and_sampled_routes",
                    "checked_at": clock(),
                }
                _set_terminal(payload, TERMINAL_COMPLETED)
                execution_complete = True
            except BaseException as error:
                _handle_failure(
                    error,
                    stage=stage,
                    backend=backend,
                    payload=payload,
                    output=output,
                    clock=clock,
                )
            assert execution_complete
            try:
                return _publish(payload, output, clock=clock)
            except BaseException as error:
                action = payload["action"]
                assert isinstance(action, dict)
                if action["requested_at"] is not None and backend is not None:
                    _contain_after_mutation(backend, payload, clock=clock)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                raise TlsRotationExecutionError(
                    "TLS rotation evidence publication failed"
                ) from None
    except TlsRotationExecutionError:
        raise
    except BaseException as error:
        if backend is not None:
            raise
        _handle_failure(
            error,
            stage="preflight",
            backend=None,
            payload=payload,
            output=output,
            clock=clock,
        )
    raise AssertionError("unreachable")
