"""Seal and independently verify one TLS leaf-rotation execution record."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Mapping

from scripts.backup_output_policy import prepare_write_once_file, publish_write_once_file
from scripts.external_json import StableFileError, parse_unique_json_bytes, read_stable_bytes
from scripts.tls_rotation_runtime import ACTION_RECONCILIATION_REASON_CODES
from scripts.tls_runtime_identity import valid_evidence_observation


SCHEMA_VERSION = 5
EVIDENCE_KIND = "tls_leaf_rotation_execution"
TERMINAL_COMPLETED = "completed"
TERMINAL_PREFLIGHT_FAILED = "preflight_failed"
TERMINAL_ACTION_FAILED = "action_failed"
TERMINAL_GENERATION_UNCONFIRMED = "generation_unconfirmed"
TERMINAL_PEER_VERIFICATION_FAILED = "peer_verification_failed"
TERMINAL_CONTAINMENT_UNCONFIRMED = "containment_unconfirmed"
TERMINAL_STATES = frozenset(
    {
        TERMINAL_COMPLETED,
        TERMINAL_PREFLIGHT_FAILED,
        TERMINAL_ACTION_FAILED,
        TERMINAL_GENERATION_UNCONFIRMED,
        TERMINAL_PEER_VERIFICATION_FAILED,
        TERMINAL_CONTAINMENT_UNCONFIRMED,
    }
)
_ERROR_CODES = {
    TERMINAL_COMPLETED: None,
    TERMINAL_PREFLIGHT_FAILED: "rotation_preflight_failed",
    TERMINAL_ACTION_FAILED: "rotation_action_failed",
    TERMINAL_GENERATION_UNCONFIRMED: "runtime_generation_unconfirmed",
    TERMINAL_PEER_VERIFICATION_FAILED: "peer_verification_failed",
    TERMINAL_CONTAINMENT_UNCONFIRMED: "rotation_containment_unconfirmed",
}
RUNTIME_KINDS = frozenset({"compose", "kubernetes"})
ACTION_KIND = {
    "compose": "compose_force_recreate",
    "kubernetes": "kubernetes_rollout",
}
SERVICES = frozenset(
    {
        "edge",
        "api",
        "web",
        "api-green",
        "web-green",
        "keycloak",
        "worker-mail",
        "worker-sub2",
        "prometheus",
        "alertmanager",
    }
)
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "target_environment",
    "runtime_kind",
    "service",
    "expected_instance_count",
    "required_observers",
    "rotation_plan_sha256",
    "runtime_profile_sha256",
    "terminal_state",
    "error_code",
    "started_at",
    "finished_at",
    "reviewed_identity",
    "instances",
    "action",
    "containment",
    "peer_observations",
    "old_fingerprint_retirement",
}
_SEALED_FIELDS = _TOP_LEVEL_FIELDS | {"integrity"}
_IDENTITY_FIELDS = {
    "old_leaf_sha256",
    "new_leaf_sha256",
    "old_spki_sha256",
    "new_spki_sha256",
}
_PROJECTION_FIELDS = {
    "target_environment",
    "runtime_kind",
    "service",
    "expected_instance_count",
    "required_observers",
    "runtime_profile_sha256",
    *_IDENTITY_FIELDS,
}
_INSTANCE_FIELDS = {"instance_id", "container_id", "started_at"}
_ACTION_FIELDS = {
    "kind",
    "requested_at",
    "completed_at",
    "return_state",
    "reconciliation",
}
_RECONCILIATION_FIELDS = {
    "result",
    "reason_code",
    "checked_at",
    "instances",
    "peer_observations",
}
_CONTAINMENT_FIELDS = {"kind", "result", "attempted_at", "completed_at"}
_OBSERVATION_FIELDS = {
    "phase",
    "observer",
    "instance_id",
    "attempt",
    "expected_sha256",
    "peer_sha256",
    "tls_version",
    "observed_at",
}
_RETIREMENT_FIELDS = {"status", "checked_at"}
_RETIREMENT_CONFIRMED = "absent_from_final_inventory_and_sampled_routes"
_RETIREMENT_UNCONFIRMED = "unconfirmed"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMPOSE_ID = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^(?:containerd|docker|cri-o)://[0-9a-f]{64}$")
_KUBERNETES_UID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_OBSERVER = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_MAX_EVIDENCE_BYTES = 64 * 1024
_MAX_PROJECTION_BYTES = 16 * 1024


class TlsRotationEvidenceError(ValueError):
    """The rotation record cannot be accepted as evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TlsRotationEvidenceError(f"invalid {context} schema")
    return value


def _timestamp(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise TlsRotationEvidenceError(f"invalid {context} timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TlsRotationEvidenceError(f"invalid {context} timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise TlsRotationEvidenceError(f"invalid {context} timestamp")
    return parsed


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TlsRotationEvidenceError(f"invalid {context}")
    return value


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def rotation_plan_digest(projection: Mapping[str, Any]) -> str:
    """Return the canonical digest that binds evidence to reviewed rotation input."""
    expected = validate_projection(dict(projection))
    return _canonical_digest(expected)


def _validate_observers(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 16
        or any(
            not isinstance(item, str) or _OBSERVER.fullmatch(item) is None
            for item in value
        )
        or value != sorted(set(value))
    ):
        raise TlsRotationEvidenceError("TLS rotation observer inventory is invalid")
    return value


def validate_projection(value: Any) -> dict[str, Any]:
    projection = _exact_mapping(
        value, _PROJECTION_FIELDS, "TLS rotation projection"
    )
    environment = projection["target_environment"]
    runtime_kind = projection["runtime_kind"]
    count = projection["expected_instance_count"]
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
        or runtime_kind not in RUNTIME_KINDS
        or projection["service"] not in SERVICES
        or type(count) is not int
        or not 1 <= count <= 16
        or (runtime_kind == "compose" and count != 1)
    ):
        raise TlsRotationEvidenceError("TLS rotation projection identity is invalid")
    _validate_observers(projection["required_observers"])
    _digest(projection["runtime_profile_sha256"], "runtime profile digest")
    for field in _IDENTITY_FIELDS:
        _digest(projection[field], f"projection {field}")
    if (
        hmac.compare_digest(
            projection["old_leaf_sha256"], projection["new_leaf_sha256"]
        )
        or hmac.compare_digest(
            projection["old_spki_sha256"], projection["new_spki_sha256"]
        )
    ):
        raise TlsRotationEvidenceError("projection leaf and SPKI identities must be distinct")
    return projection


def _validate_instances(
    value: Any,
    *,
    runtime_kind: str,
    context: str,
) -> tuple[list[dict[str, Any]], list[datetime]]:
    if not isinstance(value, list):
        raise TlsRotationEvidenceError(f"invalid {context} instance schema")
    identifier_pattern = _COMPOSE_ID if runtime_kind == "compose" else _KUBERNETES_UID
    result: list[dict[str, Any]] = []
    starts: list[datetime] = []
    seen_instances: set[str] = set()
    seen_containers: set[str] = set()
    for item in value:
        instance = _exact_mapping(item, _INSTANCE_FIELDS, f"{context} instance")
        instance_id = instance["instance_id"]
        container_id = instance["container_id"]
        if (
            not isinstance(instance_id, str)
            or identifier_pattern.fullmatch(instance_id) is None
            or instance_id in seen_instances
        ):
            raise TlsRotationEvidenceError(f"invalid {context} runtime identity")
        if runtime_kind == "compose":
            valid_container = container_id == instance_id
        else:
            valid_container = (
                isinstance(container_id, str)
                and _CONTAINER_ID.fullmatch(container_id) is not None
            )
        if not valid_container or container_id in seen_containers:
            raise TlsRotationEvidenceError(f"invalid {context} container identity")
        seen_instances.add(instance_id)
        seen_containers.add(container_id)
        starts.append(_timestamp(instance["started_at"], f"{context} instance"))
        result.append(instance)
    if runtime_kind == "compose" and len(result) not in {0, 1}:
        raise TlsRotationEvidenceError("Compose rotation must identify one instance")
    return result, starts


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_mapping(value, _TOP_LEVEL_FIELDS, "TLS rotation evidence")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
    ):
        raise TlsRotationEvidenceError("TLS rotation evidence identity is invalid")
    environment = payload["target_environment"]
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        raise TlsRotationEvidenceError("TLS rotation target environment is invalid")
    runtime_kind = payload["runtime_kind"]
    if runtime_kind not in RUNTIME_KINDS or payload["service"] not in SERVICES:
        raise TlsRotationEvidenceError("TLS rotation target identity is invalid")
    expected_count = payload["expected_instance_count"]
    if (
        type(expected_count) is not int
        or expected_count < 1
        or expected_count > 16
        or (runtime_kind == "compose" and expected_count != 1)
    ):
        raise TlsRotationEvidenceError("TLS rotation expected instance count is invalid")
    observers = _validate_observers(payload["required_observers"])
    terminal = payload["terminal_state"]
    if terminal not in TERMINAL_STATES or payload["error_code"] != _ERROR_CODES[terminal]:
        raise TlsRotationEvidenceError("TLS rotation terminal identity is invalid")
    started = _timestamp(payload["started_at"], "evidence start")
    finished = _timestamp(payload["finished_at"], "evidence finish")
    if finished < started:
        raise TlsRotationEvidenceError("TLS rotation evidence window is invalid")

    identity = _exact_mapping(
        payload["reviewed_identity"], _IDENTITY_FIELDS, "reviewed identity"
    )
    for field in _IDENTITY_FIELDS:
        _digest(identity[field], f"reviewed {field}")
    if (
        hmac.compare_digest(identity["old_leaf_sha256"], identity["new_leaf_sha256"])
        or hmac.compare_digest(identity["old_spki_sha256"], identity["new_spki_sha256"])
    ):
        raise TlsRotationEvidenceError("reviewed leaf and SPKI identities must be distinct")
    projection = {
        "target_environment": environment,
        "runtime_kind": runtime_kind,
        "service": payload["service"],
        "expected_instance_count": expected_count,
        "required_observers": observers,
        "runtime_profile_sha256": payload["runtime_profile_sha256"],
        **identity,
    }
    rotation_digest = _digest(payload["rotation_plan_sha256"], "rotation plan digest")
    if not hmac.compare_digest(rotation_digest, rotation_plan_digest(projection)):
        raise TlsRotationEvidenceError("TLS rotation plan digest is invalid")

    instances = _exact_mapping(payload["instances"], {"before", "after"}, "instances")
    before, before_starts = _validate_instances(
        instances["before"], runtime_kind=runtime_kind, context="before"
    )
    after, after_starts = _validate_instances(
        instances["after"], runtime_kind=runtime_kind, context="after"
    )
    before_ids = {item["instance_id"] for item in before}
    after_ids = {item["instance_id"] for item in after}
    before_containers = {item["container_id"] for item in before}
    after_containers = {item["container_id"] for item in after}

    action = _exact_mapping(payload["action"], _ACTION_FIELDS, "rotation action")
    if action["kind"] != ACTION_KIND[runtime_kind]:
        raise TlsRotationEvidenceError("TLS rotation action kind is invalid")
    requested = (
        None
        if action["requested_at"] is None
        else _timestamp(action["requested_at"], "action request")
    )
    completed = (
        None
        if action["completed_at"] is None
        else _timestamp(action["completed_at"], "action completion")
    )
    if requested is not None and (requested < started or requested > finished):
        raise TlsRotationEvidenceError("TLS rotation action window is invalid")
    if completed is not None and (
        requested is None or completed < requested or completed > finished
    ):
        raise TlsRotationEvidenceError("TLS rotation action window is invalid")
    return_state = action["return_state"]
    reconciliation = _exact_mapping(
        action["reconciliation"],
        _RECONCILIATION_FIELDS,
        "rotation action reconciliation",
    )
    reconciliation_result = reconciliation["result"]
    reconciliation_reason = reconciliation["reason_code"]
    if reconciliation_result not in {
        "not_required",
        "verified_old",
        "verified_new",
        "unknown",
    }:
        raise TlsRotationEvidenceError("TLS rotation action reconciliation is invalid")
    reconciliation_checked = (
        None
        if reconciliation["checked_at"] is None
        else _timestamp(reconciliation["checked_at"], "action reconciliation")
    )
    reconciled_instances, reconciled_starts = _validate_instances(
        reconciliation["instances"],
        runtime_kind=runtime_kind,
        context="reconciliation",
    )
    reconciled_ids = {item["instance_id"] for item in reconciled_instances}
    reconciled_containers = {item["container_id"] for item in reconciled_instances}
    reconciled_observations = reconciliation["peer_observations"]
    if not isinstance(reconciled_observations, list):
        raise TlsRotationEvidenceError("invalid action reconciliation observation schema")
    reconciliation_times: list[datetime] = []
    for item in reconciled_observations:
        observation = _exact_mapping(
            item, _OBSERVATION_FIELDS, "action reconciliation observation"
        )
        phase = observation["phase"]
        if (
            phase not in {"action_reconcile_old", "action_reconcile_new"}
            or observation["observer"] != "direct-instance"
            or observation["instance_id"] not in reconciled_ids
            or observation["attempt"] != 1
            or not valid_evidence_observation(
                {
                    "expected_sha256": observation["expected_sha256"],
                    "peer_sha256": observation["peer_sha256"],
                    "tls_version": observation["tls_version"],
                }
            )
        ):
            raise TlsRotationEvidenceError("invalid action reconciliation observation")
        reconciliation_times.append(
            _timestamp(observation["observed_at"], "action reconciliation observation")
        )
    if reconciliation_times != sorted(reconciliation_times) or any(
        observed < started or observed > finished for observed in reconciliation_times
    ):
        raise TlsRotationEvidenceError("action reconciliation observation timestamps are invalid")
    if return_state == "not_requested":
        valid_action_state = requested is None and completed is None
    elif return_state == "confirmed":
        valid_action_state = requested is not None and completed is not None
    elif return_state == "unknown":
        valid_action_state = requested is not None and completed is None
    else:
        valid_action_state = False
    if not valid_action_state:
        raise TlsRotationEvidenceError("TLS rotation action return state is invalid")
    if reconciliation_result == "not_required":
        valid_reconciliation = (
            return_state in {"not_requested", "confirmed"}
            and reconciliation_reason is None
            and reconciliation_checked is None
            and not reconciled_instances
            and not reconciled_observations
        )
    elif reconciliation_result == "unknown":
        valid_reconciliation = (
            return_state == "unknown"
            and reconciliation_reason in ACTION_RECONCILIATION_REASON_CODES
            and reconciliation_checked is not None
            and not reconciled_instances
            and not reconciled_observations
        )
    else:
        expected_phase = (
            "action_reconcile_old"
            if reconciliation_result == "verified_old"
            else "action_reconcile_new"
        )
        expected_fingerprint = (
            identity["old_leaf_sha256"]
            if reconciliation_result == "verified_old"
            else identity["new_leaf_sha256"]
        )
        valid_reconciliation = (
            return_state == "unknown"
            and reconciliation_reason is None
            and reconciliation_checked is not None
            and len(reconciled_instances) == expected_count
            and len(reconciled_observations) == expected_count
            and {
                (
                    item["phase"],
                    item["instance_id"],
                    item["attempt"],
                    item["expected_sha256"],
                    item["peer_sha256"],
                )
                for item in reconciled_observations
            }
            == {
                (expected_phase, instance_id, 1, expected_fingerprint, expected_fingerprint)
                for instance_id in reconciled_ids
            }
        )
        if reconciliation_result == "verified_old":
            valid_reconciliation = valid_reconciliation and reconciled_instances == before
        else:
            valid_reconciliation = (
                valid_reconciliation
                and not before_ids.intersection(reconciled_ids)
                and not before_containers.intersection(reconciled_containers)
                and requested is not None
                and all(start >= requested for start in reconciled_starts)
                and reconciliation_checked is not None
                and all(start <= reconciliation_checked for start in reconciled_starts)
            )
    if (
        not valid_reconciliation
        or (
            reconciliation_checked is not None
            and (
                requested is None
                or reconciliation_checked < requested
                or reconciliation_checked > finished
                or (
                    reconciliation_times
                    and reconciliation_checked < reconciliation_times[-1]
                )
            )
        )
    ):
        raise TlsRotationEvidenceError("TLS rotation action reconciliation is invalid")

    observations = payload["peer_observations"]
    if not isinstance(observations, list):
        raise TlsRotationEvidenceError("invalid peer observation schema")
    observation_times: list[datetime] = []
    for item in observations:
        observation = _exact_mapping(item, _OBSERVATION_FIELDS, "peer observation")
        phase = observation["phase"]
        if phase not in {"before_instance", "after_instance", "retirement_route"} or type(
            observation["attempt"]
        ) is not int or observation["attempt"] < 1:
            raise TlsRotationEvidenceError("invalid peer observation")
        observer = observation["observer"]
        instance_id = observation["instance_id"]
        if not isinstance(observer, str) or _OBSERVER.fullmatch(observer) is None:
            raise TlsRotationEvidenceError("invalid peer observation")
        if phase == "retirement_route":
            if instance_id is not None or observer not in observers:
                raise TlsRotationEvidenceError("invalid retirement route observation")
        elif (
            observer != "direct-instance"
            or not isinstance(instance_id, str)
            or (phase == "before_instance" and instance_id not in before_ids)
            or (phase == "after_instance" and instance_id not in after_ids)
        ):
            raise TlsRotationEvidenceError("invalid per-instance peer observation")
        if not valid_evidence_observation(
            {
                "expected_sha256": observation["expected_sha256"],
                "peer_sha256": observation["peer_sha256"],
                "tls_version": observation["tls_version"],
            }
        ):
            raise TlsRotationEvidenceError("invalid peer observation")
        observation_times.append(
            _timestamp(observation["observed_at"], "peer observation")
        )
    if observation_times != sorted(observation_times) or any(
        observed < started or observed > finished for observed in observation_times
    ):
        raise TlsRotationEvidenceError("peer observation timestamps are invalid")
    before_observations = [
        item for item in observations if item["phase"] == "before_instance"
    ]
    after_observations = [
        item for item in observations if item["phase"] == "after_instance"
    ]
    route_observations = [
        item for item in observations if item["phase"] == "retirement_route"
    ]
    expected_before_observations = {
        (item, 1, identity["old_leaf_sha256"]) for item in before_ids
    }
    actual_before_observations = {
        (item["instance_id"], item["attempt"], item["expected_sha256"])
        for item in before_observations
    }

    if requested is not None and any(
        _timestamp(item["observed_at"], "before peer observation") > requested
        for item in before_observations
    ):
        raise TlsRotationEvidenceError("old peer observation followed rotation action")
    if completed is not None:
        after_starts_by_id = {
            item["instance_id"]: started_at
            for item, started_at in zip(after, after_starts)
        }
        for item in after_observations:
            observed_at = _timestamp(item["observed_at"], "after peer observation")
            if observed_at < completed or observed_at < after_starts_by_id[item["instance_id"]]:
                raise TlsRotationEvidenceError("new peer observation predates rotation completion")
        if any(
            _timestamp(item["observed_at"], "route peer observation") < completed
            for item in route_observations
        ):
            raise TlsRotationEvidenceError("route peer observation predates rotation completion")
    for observer in observers:
        ordered_attempts = [
            item["attempt"]
            for item in route_observations
            if item["observer"] == observer
        ]
        if ordered_attempts and ordered_attempts != sorted(ordered_attempts):
            raise TlsRotationEvidenceError("route peer observation attempts are out of order")

    containment = _exact_mapping(
        payload["containment"], _CONTAINMENT_FIELDS, "rotation containment"
    )
    expected_containment_kind = {
        "compose": "compose_service_stop",
        "kubernetes": "kubernetes_rollout_pause",
    }[runtime_kind]
    containment_attempted = (
        None
        if containment["attempted_at"] is None
        else _timestamp(containment["attempted_at"], "containment attempt")
    )
    containment_completed = (
        None
        if containment["completed_at"] is None
        else _timestamp(containment["completed_at"], "containment completion")
    )
    if containment["kind"] == "none":
        valid_containment = (
            containment["result"] == "not_required"
            and containment_attempted is None
            and containment_completed is None
        )
    else:
        valid_containment = (
            containment["kind"] == expected_containment_kind
            and containment["result"] in {"confirmed", "unconfirmed"}
            and containment_attempted is not None
            and started <= containment_attempted <= finished
            and (
                (
                    containment["result"] == "confirmed"
                    and containment_completed is not None
                    and containment_attempted <= containment_completed <= finished
                )
                or (
                    containment["result"] == "unconfirmed"
                    and containment_completed is None
                )
            )
        )
    if not valid_containment:
        raise TlsRotationEvidenceError("TLS rotation containment is invalid")
    if containment_attempted is not None and (
        requested is None
        or containment_attempted < requested
        or (completed is not None and containment_attempted < completed)
        or (
            reconciliation_checked is not None
            and containment_attempted < reconciliation_checked
        )
    ):
        raise TlsRotationEvidenceError("TLS rotation containment window is invalid")
    retirement = _exact_mapping(
        payload["old_fingerprint_retirement"],
        _RETIREMENT_FIELDS,
        "TLS fingerprint retirement",
    )
    if retirement["status"] not in {
        _RETIREMENT_CONFIRMED,
        _RETIREMENT_UNCONFIRMED,
    }:
        raise TlsRotationEvidenceError("TLS fingerprint retirement is invalid")
    retirement_checked = (
        None
        if retirement["checked_at"] is None
        else _timestamp(retirement["checked_at"], "fingerprint retirement")
    )

    if terminal == TERMINAL_COMPLETED:
        if len(before) != expected_count or len(after) != expected_count:
            raise TlsRotationEvidenceError("runtime replica count changed during rotation")
        if before_ids.intersection(after_ids) or before_containers.intersection(
            after_containers
        ):
            raise TlsRotationEvidenceError("runtime instance generation was not replaced")
        if requested is None or completed is None:
            raise TlsRotationEvidenceError("TLS rotation action is incomplete")
        if return_state != "confirmed" or reconciliation_result != "not_required":
            raise TlsRotationEvidenceError("completed rotation action return is invalid")
        if any(start < requested or start > completed for start in after_starts):
            raise TlsRotationEvidenceError("new runtime start time predates rotation action")
        if any(start > started for start in before_starts):
            raise TlsRotationEvidenceError("old runtime start time is invalid")
        if len(before_observations) != expected_count or actual_before_observations != expected_before_observations:
            raise TlsRotationEvidenceError("old per-instance peer observations are incomplete")
        if len(after_observations) != expected_count or {
            (item["instance_id"], item["attempt"], item["expected_sha256"])
            for item in after_observations
        } != {(item, 1, identity["new_leaf_sha256"]) for item in after_ids}:
            raise TlsRotationEvidenceError("new per-instance peer observations are incomplete")
        expected_routes = {
            (observer, attempt, identity["new_leaf_sha256"])
            for observer in observers
            for attempt in (1, 2, 3)
        }
        if {
            (item["observer"], item["attempt"], item["expected_sha256"])
            for item in route_observations
        } != expected_routes or len(route_observations) != len(expected_routes):
            raise TlsRotationEvidenceError("three sampled routes per observer are required")
        if (
            retirement["status"] != _RETIREMENT_CONFIRMED
            or retirement_checked is None
        ):
            raise TlsRotationEvidenceError("old fingerprint retirement is unconfirmed")
        if (
            not observation_times
            or observation_times[-1] < completed
            or retirement_checked < observation_times[-1]
            or retirement_checked > finished
        ):
            raise TlsRotationEvidenceError("post-rotation peer observations are incomplete")
        if containment["kind"] != "none":
            raise TlsRotationEvidenceError("completed rotation cannot claim containment")
    elif terminal == TERMINAL_PREFLIGHT_FAILED:
        if (
            requested is not None
            or completed is not None
            or return_state != "not_requested"
            or reconciliation_result != "not_required"
            or after
            or after_observations
            or route_observations
            or containment["kind"] != "none"
        ):
            raise TlsRotationEvidenceError("preflight failure stage is invalid")
    else:
        if (
            len(before) != expected_count
            or len(before_observations) != expected_count
            or actual_before_observations != expected_before_observations
            or requested is None
            or containment["kind"] != expected_containment_kind
        ):
            raise TlsRotationEvidenceError("post-action failure stage is invalid")
        if terminal == TERMINAL_ACTION_FAILED and (
            completed is not None
            or return_state != "unknown"
            or reconciliation_result == "not_required"
            or after
            or after_observations
            or route_observations
        ):
            raise TlsRotationEvidenceError("action failure stage is invalid")
        if terminal in {
            TERMINAL_GENERATION_UNCONFIRMED,
            TERMINAL_PEER_VERIFICATION_FAILED,
        } and (completed is None or return_state != "confirmed" or reconciliation_result != "not_required"):
            raise TlsRotationEvidenceError("post-action failure stage is invalid")
        if terminal == TERMINAL_PEER_VERIFICATION_FAILED and (
            len(after) != expected_count
            or before_ids.intersection(after_ids)
            or before_containers.intersection(after_containers)
        ):
            raise TlsRotationEvidenceError("peer failure generation is invalid")
        if terminal == TERMINAL_GENERATION_UNCONFIRMED and route_observations:
            raise TlsRotationEvidenceError("generation failure stage is invalid")
        if terminal == TERMINAL_PEER_VERIFICATION_FAILED:
            expected_after = {
                (item, 1, identity["new_leaf_sha256"]) for item in after_ids
            }
            expected_routes = {
                (observer, attempt, identity["new_leaf_sha256"])
                for observer in observers
                for attempt in (1, 2, 3)
            }
            actual_after = {
                (item["instance_id"], item["attempt"], item["expected_sha256"])
                for item in after_observations
            }
            actual_routes = {
                (item["observer"], item["attempt"], item["expected_sha256"])
                for item in route_observations
            }
            if actual_after == expected_after and actual_routes == expected_routes:
                raise TlsRotationEvidenceError("peer failure has complete success proof")
        if terminal == TERMINAL_CONTAINMENT_UNCONFIRMED:
            if containment["result"] != "unconfirmed":
                raise TlsRotationEvidenceError("containment failure stage is invalid")
        elif containment["result"] != "confirmed":
            raise TlsRotationEvidenceError("post-action containment is unconfirmed")
    if terminal != TERMINAL_COMPLETED and (
        retirement["status"] != _RETIREMENT_UNCONFIRMED
        or retirement_checked is not None
    ):
        raise TlsRotationEvidenceError("failed rotation cannot claim fingerprint retirement")
    return payload


def seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_payload(payload)
    sealed = json.loads(json.dumps(validated))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(validated)}
    return sealed


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact_mapping(value, _SEALED_FIELDS, "sealed TLS rotation evidence")
    integrity = _exact_mapping(evidence["integrity"], {"payload_sha256"}, "integrity")
    digest = _digest(integrity["payload_sha256"], "payload digest")
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    if not hmac.compare_digest(digest, _canonical_digest(payload)):
        raise TlsRotationEvidenceError("TLS rotation evidence integrity check failed")
    _validate_payload(payload)
    return evidence


def _read_json(path: Path, *, max_bytes: int, context: str) -> Any:
    try:
        raw = read_stable_bytes(path, max_bytes=max_bytes)
    except StableFileError as error:
        if error.reason == "size":
            raise TlsRotationEvidenceError(f"{context} size is invalid") from error
        raise TlsRotationEvidenceError(f"{context} cannot be read") from error
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if isinstance(error, json.JSONDecodeError) and error.msg == "duplicate JSON key":
            raise TlsRotationEvidenceError(f"{context} JSON has duplicate keys") from error
        raise TlsRotationEvidenceError(f"{context} JSON is invalid") from error


def verify_evidence(path: Path) -> dict[str, Any]:
    return validate_evidence(
        _read_json(path, max_bytes=_MAX_EVIDENCE_BYTES, context="TLS rotation evidence")
    )


def load_projection(path: Path) -> dict[str, Any]:
    return validate_projection(
        _read_json(
            path,
            max_bytes=_MAX_PROJECTION_BYTES,
            context="TLS rotation projection",
        ),
    )


def assert_expected_rotation(
    evidence: Mapping[str, Any],
    projection: Mapping[str, Any],
) -> None:
    expected = validate_projection(dict(projection))
    actual = {
        "target_environment": evidence["target_environment"],
        "runtime_kind": evidence["runtime_kind"],
        "service": evidence["service"],
        "expected_instance_count": evidence["expected_instance_count"],
        "required_observers": evidence["required_observers"],
        "runtime_profile_sha256": evidence["runtime_profile_sha256"],
        **dict(evidence["reviewed_identity"]),
    }
    if actual != expected:
        raise TlsRotationEvidenceError(
            "TLS rotation evidence does not match the reviewed projection"
        )


def write_evidence(payload: dict[str, Any], output_path: Path) -> dict[str, Any]:
    sealed = seal_evidence(payload)
    raw = (
        json.dumps(
            sealed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(raw) > _MAX_EVIDENCE_BYTES:
        raise TlsRotationEvidenceError("TLS rotation evidence size is invalid")
    destination = prepare_write_once_file(output_path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        publish_write_once_file(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    verified = verify_evidence(destination)
    if verified != sealed:
        raise TlsRotationEvidenceError("TLS rotation evidence read-back is invalid")
    return verified


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-projection", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        evidence = verify_evidence(options.input)
        projection = load_projection(options.expected_projection)
        assert_expected_rotation(evidence, projection)
        if evidence["terminal_state"] != TERMINAL_COMPLETED:
            raise TlsRotationEvidenceError("TLS rotation did not complete")
    except (OSError, TypeError, TlsRotationEvidenceError, ValueError):
        print("tls-rotation-evidence-failed", file=sys.stderr)
        return 1
    print(
        "tls-rotation-evidence-ok production_acceptance=false "
        f"runtime_kind={evidence['runtime_kind']} service={evidence['service']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
