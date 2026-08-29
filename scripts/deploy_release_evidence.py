"""Seal and independently verify write-once forward-deployment evidence."""

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

from scripts.backup_output_policy import (
    prepare_write_once_file,
    publish_write_once_file,
)
from scripts.external_json import (
    StableFileError,
    load_unique_json,
    parse_unique_json_bytes,
    read_stable_bytes,
)
from scripts.tls_runtime_identity import (
    EXTERNAL_ENDPOINTS,
    INTERNAL_ENDPOINT_SERVICES,
    valid_evidence_observation,
)


SCHEMA_VERSION = 3
EVIDENCE_KIND = "release_bound_forward_deployment_execution"
TERMINAL_SUCCEEDED = "succeeded"
TERMINAL_PREFLIGHT_FAILED = "preflight_failed"
TERMINAL_EDGE_CLOSED_FAILURE = "edge_closed_failure"
TERMINAL_EDGE_UNCONFIRMED = "edge_unconfirmed"
TERMINAL_STATES = frozenset(
    {
        TERMINAL_SUCCEEDED,
        TERMINAL_PREFLIGHT_FAILED,
        TERMINAL_EDGE_CLOSED_FAILURE,
        TERMINAL_EDGE_UNCONFIRMED,
    }
)
_TERMINAL_PHASE = {
    TERMINAL_SUCCEEDED: "SUCCEEDED",
    TERMINAL_PREFLIGHT_FAILED: "PREFLIGHT_FAILED",
    TERMINAL_EDGE_CLOSED_FAILURE: "EDGE_CLOSED_FAILURE",
    TERMINAL_EDGE_UNCONFIRMED: "EDGE_UNCONFIRMED",
}
_TERMINAL_ERROR = {
    TERMINAL_SUCCEEDED: None,
    TERMINAL_PREFLIGHT_FAILED: "deployment_preflight_failed",
    TERMINAL_EDGE_CLOSED_FAILURE: "deployment_execution_failed",
    TERMINAL_EDGE_UNCONFIRMED: "edge_unconfirmed",
}
_EXECUTION_PHASES = (
    "STARTED",
    "PREFLIGHTED",
    "EDGE_STOPPED",
    "BACKENDS_STARTED",
    "INTERNAL_VERIFIED",
    "EDGE_STARTED",
    "EXTERNAL_VERIFIED",
)
PHASES = frozenset(_EXECUTION_PHASES) | frozenset(_TERMINAL_PHASE.values())
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "rolling_release",
    "execution_fingerprint",
    "terminal_state",
    "error_code",
    "started_at",
    "finished_at",
    "target_release",
    "target_intake",
    "rollback",
    "images",
    "third_party_images",
    "checks",
    "tls_observations",
    "edge",
    "phases",
}
_SEALED_FIELDS = _TOP_LEVEL_FIELDS | {"integrity"}
_TARGET_RELEASE_FIELDS = {
    "tag",
    "commit",
    "migration_head",
    "container_manifest_sha256",
}
_TARGET_INTAKE_FIELDS = {
    "environment",
    "manifest_payload_sha256",
    "requirements_sha256",
    "checkpoint_phase",
}
_ROLLBACK_FIELDS = {
    "release_tag",
    "release_commit",
    "migration_head",
    "container_manifest_sha256",
    "postgres_manifest_sha256",
    "redis_manifest_sha256",
    "recovery_set",
    "postgres_created_at",
    "redis_created_at",
}
_IMAGE_FIELDS = {"api", "worker_mail", "worker_sub2", "web", "edge"}
_THIRD_PARTY_FIELDS = {
    "postgres",
    "redis",
    "keycloak",
    "alertmanager",
    "prometheus",
}
_THIRD_PARTY_REPOSITORIES = {
    "postgres": "postgres",
    "redis": "redis",
    "keycloak": "quay.io/keycloak/keycloak",
    "alertmanager": "prom/alertmanager",
    "prometheus": "prom/prometheus",
}
_CHECK_FIELDS = {
    "rollback_readiness_verified",
    "upstream_images_scanned",
    "target_supply_chain_verified",
    "images_pulled",
    "vault_sink_checks_passed",
    "operational_checks_passed",
    "internal_probes_passed",
    "external_probes_passed",
}
_EDGE_FIELDS = {"start_attempted", "stop_confirmations", "final_state"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_MIGRATION = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_RECOVERY_SET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
_OCI_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_MAX_RECOVERY_POINT_SKEW_SECONDS = 300
_MAX_EVIDENCE_BYTES = 64 * 1024


class DeploymentReleaseEvidenceError(ValueError):
    """The forward-deployment record cannot be accepted as evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise DeploymentReleaseEvidenceError(
            "deployment recovery timestamp must be aware"
        )
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DeploymentReleaseEvidenceError(f"invalid {context} schema")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence timestamp must be UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence timestamp is invalid"
        ) from error
    if parsed.tzinfo != timezone.utc:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence timestamp must be UTC"
        )
    return parsed


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DeploymentReleaseEvidenceError(f"invalid {context}")
    return value


def _image(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or _OCI_DIGEST.fullmatch(value) is None
    ):
        raise DeploymentReleaseEvidenceError(f"invalid {context}")
    return value


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(canonical)


def execution_fingerprint(
    target_release: Mapping[str, str],
    target_intake: Mapping[str, str | int],
    rollback: Mapping[str, str],
    images: Mapping[str, str],
    third_party_images: Mapping[str, str | None],
) -> str:
    binding = {
        "target_release": dict(target_release),
        "target_intake": dict(target_intake),
        "rollback": dict(rollback),
        "images": {key: images[key] for key in sorted(images)},
        "third_party_images": {
            key: third_party_images[key] for key in sorted(third_party_images)
        },
    }
    return _canonical_digest(binding)


def _validate_release(release: dict[str, Any]) -> None:
    if not isinstance(release["tag"], str) or _TAG.fullmatch(release["tag"]) is None:
        raise DeploymentReleaseEvidenceError("invalid target release tag")
    if (
        not isinstance(release["commit"], str)
        or _COMMIT.fullmatch(release["commit"]) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid target release commit")
    if (
        not isinstance(release["migration_head"], str)
        or len(release["migration_head"]) > 128
        or _MIGRATION.fullmatch(release["migration_head"]) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid target migration head")
    _digest(release["container_manifest_sha256"], "target manifest digest")


def _validate_target_intake(target_intake: dict[str, Any]) -> None:
    environment = target_intake["environment"]
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        raise DeploymentReleaseEvidenceError("invalid target intake environment")
    _digest(
        target_intake["manifest_payload_sha256"],
        "target intake manifest payload digest",
    )
    _digest(
        target_intake["requirements_sha256"],
        "target intake requirements digest",
    )
    if target_intake["checkpoint_phase"] != 0:
        raise DeploymentReleaseEvidenceError("invalid target intake checkpoint phase")


def _validate_rollback(rollback: dict[str, Any], started: datetime) -> None:
    if (
        not isinstance(rollback["release_tag"], str)
        or _TAG.fullmatch(rollback["release_tag"]) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid rollback release tag")
    if (
        not isinstance(rollback["release_commit"], str)
        or _COMMIT.fullmatch(rollback["release_commit"]) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid rollback release commit")
    if (
        not isinstance(rollback["migration_head"], str)
        or len(rollback["migration_head"]) > 128
        or _MIGRATION.fullmatch(rollback["migration_head"]) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid rollback migration head")
    for name in (
        "container_manifest_sha256",
        "postgres_manifest_sha256",
        "redis_manifest_sha256",
    ):
        _digest(rollback[name], f"rollback {name}")
    recovery_set = rollback["recovery_set"]
    if (
        not isinstance(recovery_set, str)
        or _RECOVERY_SET.fullmatch(recovery_set) is None
    ):
        raise DeploymentReleaseEvidenceError("invalid rollback recovery set")
    postgres_created = _timestamp(rollback["postgres_created_at"])
    redis_created = _timestamp(rollback["redis_created_at"])
    if postgres_created > started or redis_created > started:
        raise DeploymentReleaseEvidenceError("rollback recovery point follows deploy start")
    if (
        abs((redis_created - postgres_created).total_seconds())
        > _MAX_RECOVERY_POINT_SKEW_SECONDS
    ):
        raise DeploymentReleaseEvidenceError(
            "rollback recovery points are too far apart"
        )


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_mapping(value, _TOP_LEVEL_FIELDS, "deployment evidence")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
        or payload["rolling_release"] is not False
    ):
        raise DeploymentReleaseEvidenceError("deployment evidence identity is invalid")
    fingerprint = _digest(payload["execution_fingerprint"], "execution fingerprint")
    terminal = payload["terminal_state"]
    if (
        terminal not in TERMINAL_STATES
        or payload["error_code"] != _TERMINAL_ERROR[terminal]
    ):
        raise DeploymentReleaseEvidenceError("deployment terminal identity is invalid")
    started = _timestamp(payload["started_at"])
    finished = _timestamp(payload["finished_at"])
    if finished < started:
        raise DeploymentReleaseEvidenceError("deployment evidence window is invalid")

    target_release = _exact_mapping(
        payload["target_release"], _TARGET_RELEASE_FIELDS, "target release"
    )
    _validate_release(target_release)
    target_intake = _exact_mapping(
        payload["target_intake"], _TARGET_INTAKE_FIELDS, "target intake"
    )
    _validate_target_intake(target_intake)
    rollback = _exact_mapping(payload["rollback"], _ROLLBACK_FIELDS, "rollback")
    _validate_rollback(rollback, started)

    images = _exact_mapping(payload["images"], {"expected", "observed"}, "images")
    expected_images = _exact_mapping(
        images["expected"], _IMAGE_FIELDS, "expected application images"
    )
    observed_images = _exact_mapping(
        images["observed"], _IMAGE_FIELDS, "observed application images"
    )
    for service in _IMAGE_FIELDS:
        _image(expected_images[service], f"expected {service} image")
        observed = observed_images[service]
        if observed is not None:
            _image(observed, f"observed {service} image")
            if not hmac.compare_digest(observed, expected_images[service]):
                raise DeploymentReleaseEvidenceError(
                    "observed deployment image is invalid"
                )

    third_party_images = _exact_mapping(
        payload["third_party_images"],
        _THIRD_PARTY_FIELDS,
        "third-party images",
    )
    for service in _THIRD_PARTY_FIELDS:
        image = third_party_images[service]
        if image is not None:
            _image(image, f"third-party {service} image")
            if not image.startswith(
                f"{_THIRD_PARTY_REPOSITORIES[service]}@sha256:"
            ):
                raise DeploymentReleaseEvidenceError(
                    "third-party deployment image repository is invalid"
                )

    expected_fingerprint = execution_fingerprint(
        target_release,
        target_intake,
        rollback,
        expected_images,
        third_party_images,
    )
    if not hmac.compare_digest(fingerprint, expected_fingerprint):
        raise DeploymentReleaseEvidenceError(
            "deployment execution fingerprint is invalid"
        )

    checks = _exact_mapping(payload["checks"], _CHECK_FIELDS, "checks")
    for name in (
        "rollback_readiness_verified",
        "upstream_images_scanned",
        "target_supply_chain_verified",
        "images_pulled",
    ):
        if type(checks[name]) is not bool:
            raise DeploymentReleaseEvidenceError("deployment check result is invalid")
    limits = {
        "vault_sink_checks_passed": 2,
        "operational_checks_passed": 2,
        "internal_probes_passed": 7,
        "external_probes_passed": 2,
    }
    for name, maximum in limits.items():
        if type(checks[name]) is not int or not 0 <= checks[name] <= maximum:
            raise DeploymentReleaseEvidenceError("deployment check count is invalid")

    tls_observations = _exact_mapping(
        payload["tls_observations"], {"internal", "external"}, "TLS observations"
    )
    internal_tls = tls_observations["internal"]
    external_tls = tls_observations["external"]
    if (
        not isinstance(internal_tls, dict)
        or not set(internal_tls).issubset(INTERNAL_ENDPOINT_SERVICES)
        or not isinstance(external_tls, dict)
        or not set(external_tls).issubset(EXTERNAL_ENDPOINTS)
        or any(not valid_evidence_observation(item) for item in internal_tls.values())
        or any(not valid_evidence_observation(item) for item in external_tls.values())
    ):
        raise DeploymentReleaseEvidenceError("deployment TLS observation is invalid")

    edge = _exact_mapping(payload["edge"], _EDGE_FIELDS, "edge")
    if type(edge["start_attempted"]) is not bool:
        raise DeploymentReleaseEvidenceError("edge start observation is invalid")
    if (
        type(edge["stop_confirmations"]) is not int
        or not 0 <= edge["stop_confirmations"] <= 2
    ):
        raise DeploymentReleaseEvidenceError("edge stop observation is invalid")
    if edge["final_state"] not in {
        "not_mutated",
        "open_verified",
        "closed_confirmed",
        "unconfirmed",
    }:
        raise DeploymentReleaseEvidenceError("edge final state is invalid")

    phases = payload["phases"]
    if not isinstance(phases, list) or not phases:
        raise DeploymentReleaseEvidenceError("deployment phases are incomplete")
    phase_names: list[str] = []
    phase_times: list[datetime] = []
    for item in phases:
        phase = _exact_mapping(item, {"phase", "at"}, "phase")
        if phase["phase"] not in PHASES:
            raise DeploymentReleaseEvidenceError("deployment phase is invalid")
        phase_names.append(phase["phase"])
        phase_times.append(_timestamp(phase["at"]))
    if phase_names[0] != "STARTED" or phase_names[-1] != _TERMINAL_PHASE[terminal]:
        raise DeploymentReleaseEvidenceError("deployment terminal phase is invalid")
    non_terminal = phase_names[:-1]
    if non_terminal != list(_EXECUTION_PHASES[: len(non_terminal)]):
        raise DeploymentReleaseEvidenceError("deployment phase sequence is invalid")
    if (
        phase_times != sorted(phase_times)
        or phase_times[0] < started
        or phase_times[-1] > finished
    ):
        raise DeploymentReleaseEvidenceError(
            "deployment phase timestamps are invalid"
        )

    if "PREFLIGHTED" in non_terminal and (
        checks["rollback_readiness_verified"] is not True
        or checks["upstream_images_scanned"] is not True
        or checks["target_supply_chain_verified"] is not True
        or checks["images_pulled"] is not True
        or checks["vault_sink_checks_passed"] < 1
        or checks["operational_checks_passed"] < 1
        or any(image is None for image in third_party_images.values())
    ):
        raise DeploymentReleaseEvidenceError(
            "deployment preflight evidence is incomplete"
        )
    if "EDGE_STOPPED" in non_terminal and edge["stop_confirmations"] < 1:
        raise DeploymentReleaseEvidenceError("edge stop evidence is incomplete")
    if "INTERNAL_VERIFIED" in non_terminal and (
        any(
            observed_images[service] != expected_images[service]
            for service in ("api", "worker_mail", "worker_sub2", "web")
        )
        or checks["internal_probes_passed"] != 7
        or set(internal_tls) != set(INTERNAL_ENDPOINT_SERVICES)
    ):
        raise DeploymentReleaseEvidenceError(
            "internal deployment verification evidence is incomplete"
        )
    if "EDGE_STARTED" in non_terminal and edge["start_attempted"] is not True:
        raise DeploymentReleaseEvidenceError("edge start evidence is incomplete")
    if "EXTERNAL_VERIFIED" in non_terminal and (
        observed_images["edge"] != expected_images["edge"]
        or checks["external_probes_passed"] != 2
        or set(external_tls) != set(EXTERNAL_ENDPOINTS)
    ):
        raise DeploymentReleaseEvidenceError(
            "external deployment verification evidence is incomplete"
        )

    if terminal == TERMINAL_SUCCEEDED:
        if (
            non_terminal != list(_EXECUTION_PHASES)
            or observed_images != expected_images
            or checks
            != {
                "rollback_readiness_verified": True,
                "upstream_images_scanned": True,
                "target_supply_chain_verified": True,
                "images_pulled": True,
                "vault_sink_checks_passed": 2,
                "operational_checks_passed": 2,
                "internal_probes_passed": 7,
                "external_probes_passed": 2,
            }
            or edge
            != {
                "start_attempted": True,
                "stop_confirmations": 1,
                "final_state": "open_verified",
            }
        ):
            raise DeploymentReleaseEvidenceError(
                "successful deployment evidence is incomplete"
            )
    elif terminal == TERMINAL_PREFLIGHT_FAILED:
        if (
            non_terminal != ["STARTED"]
            or any(value is not None for value in observed_images.values())
            or edge
            != {
                "start_attempted": False,
                "stop_confirmations": 0,
                "final_state": "not_mutated",
            }
        ):
            raise DeploymentReleaseEvidenceError(
                "deployment preflight failure evidence is invalid"
            )
    elif terminal == TERMINAL_EDGE_CLOSED_FAILURE:
        if (
            "PREFLIGHTED" not in non_terminal
            or edge["final_state"] != "closed_confirmed"
            or edge["stop_confirmations"] < 1
        ):
            raise DeploymentReleaseEvidenceError(
                "closed-edge deployment failure evidence is invalid"
            )
    else:
        if (
            "PREFLIGHTED" not in non_terminal
            or edge["final_state"] != "unconfirmed"
            or (edge["start_attempted"] and edge["stop_confirmations"] != 1)
        ):
            raise DeploymentReleaseEvidenceError(
                "unconfirmed-edge deployment evidence is invalid"
            )
    if terminal != TERMINAL_PREFLIGHT_FAILED and any(
        image is None for image in third_party_images.values()
    ):
        raise DeploymentReleaseEvidenceError(
            "terminal deployment evidence is missing third-party images"
        )
    return payload


def seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_payload(payload)
    sealed = json.loads(json.dumps(validated))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(validated)}
    return sealed


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact_mapping(value, _SEALED_FIELDS, "sealed deployment evidence")
    integrity = _exact_mapping(evidence["integrity"], {"payload_sha256"}, "integrity")
    digest = _digest(integrity["payload_sha256"], "payload digest")
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    _validate_payload(payload)
    if not hmac.compare_digest(digest, _canonical_digest(payload)):
        raise DeploymentReleaseEvidenceError(
            "deployment evidence integrity check failed"
        )
    return evidence


def verify_evidence(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_bytes(path, max_bytes=_MAX_EVIDENCE_BYTES)
    except StableFileError as error:
        if error.reason == "size":
            raise DeploymentReleaseEvidenceError(
                "deployment evidence size is invalid"
            ) from error
        raise DeploymentReleaseEvidenceError(
            "deployment evidence cannot be read"
        ) from error
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if isinstance(error, json.JSONDecodeError) and error.msg == "duplicate JSON key":
            raise DeploymentReleaseEvidenceError(
                "deployment evidence JSON has duplicate keys"
            ) from error
        raise DeploymentReleaseEvidenceError(
            "deployment evidence JSON is invalid"
        ) from error
    return validate_evidence(value)


def prepare_evidence_output(path: Path) -> Path:
    try:
        return prepare_write_once_file(path)
    except ValueError as error:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence output path is unsafe"
        ) from error


def assert_expected_release(
    evidence: Mapping[str, Any],
    *,
    target_release: Mapping[str, str],
    target_intake: Mapping[str, str | int],
    rollback: Mapping[str, str],
    images: Mapping[str, str],
    third_party_images: Mapping[str, str | None],
) -> None:
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    _validate_payload(payload)
    if dict(target_release) != evidence["target_release"]:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence target release binding is invalid"
        )
    if dict(target_intake) != evidence["target_intake"]:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence target intake binding is invalid"
        )
    if dict(rollback) != evidence["rollback"]:
        raise DeploymentReleaseEvidenceError(
            "deployment evidence rollback binding is invalid"
        )
    if set(images) != _IMAGE_FIELDS or any(
        not hmac.compare_digest(evidence["images"]["expected"][service], images[service])
        for service in _IMAGE_FIELDS
    ):
        raise DeploymentReleaseEvidenceError(
            "deployment evidence application image binding is invalid"
        )
    if set(third_party_images) != _THIRD_PARTY_FIELDS or any(
        evidence["third_party_images"][service] != third_party_images[service]
        for service in _THIRD_PARTY_FIELDS
    ):
        raise DeploymentReleaseEvidenceError(
            "deployment evidence third-party image binding is invalid"
        )


class DeploymentReleaseEvidenceRecorder:
    def __init__(
        self,
        *,
        target_release: Mapping[str, str],
        target_intake: Mapping[str, str | int],
        rollback: Mapping[str, str],
        images: Mapping[str, str],
        third_party_images: Mapping[str, str | None] | None = None,
        started_at: str | None = None,
    ) -> None:
        recorded_started_at = utc_now() if started_at is None else started_at
        _timestamp(recorded_started_at)
        recorded_third_party_images = (
            {service: None for service in _THIRD_PARTY_FIELDS}
            if third_party_images is None
            else dict(third_party_images)
        )
        self.payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "production_acceptance": False,
            "rolling_release": False,
            "execution_fingerprint": execution_fingerprint(
                target_release,
                target_intake,
                rollback,
                images,
                recorded_third_party_images,
            ),
            "terminal_state": TERMINAL_PREFLIGHT_FAILED,
            "error_code": _TERMINAL_ERROR[TERMINAL_PREFLIGHT_FAILED],
            "started_at": recorded_started_at,
            "finished_at": recorded_started_at,
            "target_release": dict(target_release),
            "target_intake": dict(target_intake),
            "rollback": dict(rollback),
            "images": {
                "expected": dict(images),
                "observed": {service: None for service in _IMAGE_FIELDS},
            },
            "third_party_images": recorded_third_party_images,
            "checks": {
                "rollback_readiness_verified": False,
                "upstream_images_scanned": False,
                "target_supply_chain_verified": False,
                "images_pulled": False,
                "vault_sink_checks_passed": 0,
                "operational_checks_passed": 0,
                "internal_probes_passed": 0,
                "external_probes_passed": 0,
            },
            "tls_observations": {"internal": {}, "external": {}},
            "edge": {
                "start_attempted": False,
                "stop_confirmations": 0,
                "final_state": "not_mutated",
            },
            "phases": [{"phase": "STARTED", "at": recorded_started_at}],
        }

    def validate_initial(self) -> None:
        candidate = {
            **self.payload,
            "phases": [
                *self.payload["phases"],
                {
                    "phase": _TERMINAL_PHASE[TERMINAL_PREFLIGHT_FAILED],
                    "at": self.payload["finished_at"],
                },
            ],
        }
        _validate_payload(candidate)

    def phase(self, phase: str) -> None:
        if phase not in PHASES:
            raise DeploymentReleaseEvidenceError("deployment phase is invalid")
        if self.payload["phases"][-1]["phase"] != phase:
            self.payload["phases"].append({"phase": phase, "at": utc_now()})

    def check(self, name: str, value: bool | int) -> None:
        if name not in _CHECK_FIELDS:
            raise DeploymentReleaseEvidenceError("deployment check is invalid")
        self.payload["checks"][name] = value

    def tls_observation(
        self,
        scope: str,
        endpoint: str,
        observation: Mapping[str, str],
    ) -> None:
        allowed = (
            set(INTERNAL_ENDPOINT_SERVICES)
            if scope == "internal"
            else set(EXTERNAL_ENDPOINTS)
            if scope == "external"
            else set()
        )
        if endpoint not in allowed or not valid_evidence_observation(observation):
            raise DeploymentReleaseEvidenceError("deployment TLS observation is invalid")
        if endpoint in self.payload["tls_observations"][scope]:
            raise DeploymentReleaseEvidenceError("deployment TLS observation is duplicated")
        self.payload["tls_observations"][scope][endpoint] = dict(observation)

    def observed_image(self, service: str, image: str) -> None:
        if service not in _IMAGE_FIELDS:
            raise DeploymentReleaseEvidenceError(
                "deployment image observation is invalid"
            )
        self.payload["images"]["observed"][service] = image

    def third_party_image(self, service: str, image: str) -> None:
        if service not in _THIRD_PARTY_FIELDS:
            raise DeploymentReleaseEvidenceError(
                "third-party image observation is invalid"
            )
        _image(image, f"third-party {service} image")
        if not image.startswith(f"{_THIRD_PARTY_REPOSITORIES[service]}@sha256:"):
            raise DeploymentReleaseEvidenceError(
                "third-party deployment image repository is invalid"
            )
        self.payload["third_party_images"][service] = image
        self.payload["execution_fingerprint"] = execution_fingerprint(
            self.payload["target_release"],
            self.payload["target_intake"],
            self.payload["rollback"],
            self.payload["images"]["expected"],
            self.payload["third_party_images"],
        )

    def edge_start_attempted(self) -> None:
        self.payload["edge"]["start_attempted"] = True

    def edge_stop_confirmed(self) -> None:
        self.payload["edge"]["stop_confirmations"] += 1

    def outcome(self, terminal_state: str) -> None:
        if terminal_state not in TERMINAL_STATES:
            raise DeploymentReleaseEvidenceError(
                "deployment terminal state is invalid"
            )
        self.payload["terminal_state"] = terminal_state
        self.payload["error_code"] = _TERMINAL_ERROR[terminal_state]
        self.payload["edge"]["final_state"] = {
            TERMINAL_SUCCEEDED: "open_verified",
            TERMINAL_PREFLIGHT_FAILED: "not_mutated",
            TERMINAL_EDGE_CLOSED_FAILURE: "closed_confirmed",
            TERMINAL_EDGE_UNCONFIRMED: "unconfirmed",
        }[terminal_state]
        self.phase(_TERMINAL_PHASE[terminal_state])

    def write(self, output_path: Path) -> dict[str, Any]:
        self.payload["finished_at"] = utc_now()
        sealed = seal_evidence(self.payload)
        serialized = (
            json.dumps(sealed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if len(serialized) > _MAX_EVIDENCE_BYTES:
            raise DeploymentReleaseEvidenceError(
                "deployment evidence size is invalid"
            )
        destination = prepare_evidence_output(output_path)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                if os.name != "nt":
                    os.chmod(temporary_path, 0o600)
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            publish_write_once_file(temporary_path, destination)
            temporary_path = None
            return verify_evidence(destination)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-target-release", type=Path, required=True)
    parser.add_argument("--expected-target-environment", required=True)
    parser.add_argument("--expected-target-intake-manifest-sha256", required=True)
    parser.add_argument("--expected-target-intake-requirements-sha256", required=True)
    parser.add_argument("--expected-rollback", type=Path, required=True)
    for service in sorted(_IMAGE_FIELDS):
        parser.add_argument(
            f"--expected-{service.replace('_', '-')}-image", required=True
        )
    for service in sorted(_THIRD_PARTY_FIELDS):
        parser.add_argument(f"--expected-{service}-image")
    options = parser.parse_args(arguments)
    try:
        evidence = verify_evidence(options.input)
        target_release = load_unique_json(
            options.expected_target_release,
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        rollback = load_unique_json(
            options.expected_rollback,
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        assert_expected_release(
            evidence,
            target_release=target_release,
            target_intake={
                "environment": options.expected_target_environment,
                "manifest_payload_sha256": options.expected_target_intake_manifest_sha256,
                "requirements_sha256": options.expected_target_intake_requirements_sha256,
                "checkpoint_phase": 0,
            },
            rollback=rollback,
            images={
                service: getattr(options, f"expected_{service}_image")
                for service in _IMAGE_FIELDS
            },
            third_party_images={
                service: getattr(options, f"expected_{service}_image")
                for service in _THIRD_PARTY_FIELDS
            },
        )
    except (DeploymentReleaseEvidenceError, OSError, json.JSONDecodeError):
        print("deploy-release-evidence-failed", file=sys.stderr)
        return 1
    print(
        "deploy-release-evidence-ok production_acceptance=false rolling_release=false "
        f"terminal_state={evidence['terminal_state']} "
        f"payload_sha256={evidence['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
