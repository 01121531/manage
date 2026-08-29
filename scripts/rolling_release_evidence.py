"""Seal write-once Web/API rolling-release execution evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hmac
import hashlib
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
    parse_unique_json_bytes,
    read_stable_bytes,
)
from scripts.tls_runtime_identity import valid_evidence_observation


SCHEMA_VERSION = 3
EVIDENCE_KIND = "web_api_rolling_execution"
TERMINAL_COMPLETE = "complete_source_retained"
TERMINAL_SWITCHED_BACK = "switched_back"
TERMINAL_ROUTE_UNCONFIRMED = "route_unconfirmed"
TERMINAL_PRE_SWITCH_FAILED = "pre_switch_failed"
TERMINAL_STATES = frozenset(
    {
        TERMINAL_COMPLETE,
        TERMINAL_SWITCHED_BACK,
        TERMINAL_ROUTE_UNCONFIRMED,
        TERMINAL_PRE_SWITCH_FAILED,
    }
)
PHASES = frozenset(
    {
        "STARTED",
        "PREFLIGHTED",
        "SCHEMA_EXPANDED",
        "INACTIVE_VERIFIED",
        "TRAFFIC_SWITCHED",
        "COMPLETE_SOURCE_RETAINED",
        "SWITCHED_BACK",
        "ROUTE_UNCONFIRMED",
        "PRE_SWITCH_FAILED",
    }
)
_TERMINAL_PHASE = {
    TERMINAL_COMPLETE: "COMPLETE_SOURCE_RETAINED",
    TERMINAL_SWITCHED_BACK: "SWITCHED_BACK",
    TERMINAL_ROUTE_UNCONFIRMED: "ROUTE_UNCONFIRMED",
    TERMINAL_PRE_SWITCH_FAILED: "PRE_SWITCH_FAILED",
}
_TERMINAL_ERROR = {
    TERMINAL_COMPLETE: None,
    TERMINAL_SWITCHED_BACK: "target_observation_failed",
    TERMINAL_ROUTE_UNCONFIRMED: "route_unconfirmed",
    TERMINAL_PRE_SWITCH_FAILED: "rolling_execution_failed",
}
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "plan_fingerprint",
    "terminal_state",
    "error_code",
    "started_at",
    "finished_at",
    "source",
    "target",
    "target_intake",
    "images",
    "workers",
    "routes",
    "phases",
    "nginx_operations",
    "tls_observations",
    "public_releasez",
}
_SEALED_FIELDS = _TOP_LEVEL_FIELDS | {"integrity"}
_RELEASE_FIELDS = {
    "slot",
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
_IMAGE_FIELDS = {"api", "web", "edge"}
_WORKER_OBSERVATION_FIELDS = {"worker_mail", "worker_sub2"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_PLACEHOLDERS = {"development", "example", "local", "placeholder", "tbd", "test"}
_MIGRATION = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_OCI_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_MAX_EVIDENCE_BYTES = 64 * 1024


class RollingReleaseEvidenceError(ValueError):
    """The rolling execution record cannot be accepted as evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RollingReleaseEvidenceError(f"invalid {context} schema")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise RollingReleaseEvidenceError("rolling evidence timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RollingReleaseEvidenceError("rolling evidence timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise RollingReleaseEvidenceError("rolling evidence timestamp must be UTC")
    return parsed


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RollingReleaseEvidenceError(f"invalid {context}")
    return value


def _image(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or _OCI_DIGEST.fullmatch(value) is None
    ):
        raise RollingReleaseEvidenceError(f"invalid {context}")
    return value


def _validate_release(value: Any, context: str) -> dict[str, Any]:
    release = _exact_mapping(value, _RELEASE_FIELDS, context)
    if release["slot"] not in {"blue", "green"}:
        raise RollingReleaseEvidenceError(f"invalid {context} slot")
    if (
        not isinstance(release["tag"], str)
        or len(release["tag"]) > 128
        or _TAG.fullmatch(release["tag"]) is None
    ):
        raise RollingReleaseEvidenceError(f"invalid {context} tag")
    if (
        not isinstance(release["commit"], str)
        or _COMMIT.fullmatch(release["commit"]) is None
    ):
        raise RollingReleaseEvidenceError(f"invalid {context} commit")
    if (
        not isinstance(release["migration_head"], str)
        or len(release["migration_head"]) > 128
        or _MIGRATION.fullmatch(release["migration_head"]) is None
    ):
        raise RollingReleaseEvidenceError(f"invalid {context} migration head")
    _digest(release["container_manifest_sha256"], f"{context} manifest digest")
    return release


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(canonical)


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_mapping(value, _TOP_LEVEL_FIELDS, "rolling evidence")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
    ):
        raise RollingReleaseEvidenceError("rolling evidence identity is invalid")
    _digest(payload["plan_fingerprint"], "plan fingerprint")
    terminal = payload["terminal_state"]
    if terminal not in TERMINAL_STATES or payload["error_code"] != _TERMINAL_ERROR[terminal]:
        raise RollingReleaseEvidenceError("rolling evidence terminal identity is invalid")
    started = _timestamp(payload["started_at"])
    finished = _timestamp(payload["finished_at"])
    if finished < started:
        raise RollingReleaseEvidenceError("rolling evidence window is invalid")

    source = _validate_release(payload["source"], "source release")
    target = _validate_release(payload["target"], "target release")
    if source["slot"] == target["slot"]:
        raise RollingReleaseEvidenceError("rolling release slots must differ")

    target_intake = _exact_mapping(
        payload["target_intake"], _TARGET_INTAKE_FIELDS, "target intake"
    )
    environment = target_intake["environment"]
    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        raise RollingReleaseEvidenceError("invalid target intake environment")
    _digest(
        target_intake["manifest_payload_sha256"],
        "target intake manifest payload digest",
    )
    _digest(
        target_intake["requirements_sha256"],
        "target intake requirements digest",
    )
    if target_intake["checkpoint_phase"] != 0:
        raise RollingReleaseEvidenceError("invalid target intake checkpoint phase")

    images = _exact_mapping(payload["images"], {"source", "target"}, "images")
    for role in ("source", "target"):
        image_set = _exact_mapping(images[role], _IMAGE_FIELDS, f"{role} images")
        for service in _IMAGE_FIELDS:
            _image(image_set[service], f"{role} {service} image")
    if images["source"]["edge"] != images["target"]["edge"]:
        raise RollingReleaseEvidenceError("rolling edge digest changed")

    workers = _exact_mapping(
        payload["workers"], {"expected_digest", "before", "after", "unchanged"}, "workers"
    )
    expected_worker = _image(workers["expected_digest"], "expected worker image")
    for moment in ("before", "after"):
        observation = _exact_mapping(
            workers[moment], _WORKER_OBSERVATION_FIELDS, f"worker {moment} observation"
        )
        for service in _WORKER_OBSERVATION_FIELDS:
            value = observation[service]
            if value is not None:
                _image(value, f"worker {moment} image")
    observed = [
        workers[moment][service]
        for moment in ("before", "after")
        for service in _WORKER_OBSERVATION_FIELDS
    ]
    expected_unchanged = all(value == expected_worker for value in observed)
    if workers["unchanged"] is not expected_unchanged:
        raise RollingReleaseEvidenceError("worker digest conclusion is invalid")
    if terminal in {TERMINAL_COMPLETE, TERMINAL_SWITCHED_BACK} and not expected_unchanged:
        raise RollingReleaseEvidenceError("terminal evidence lacks unchanged worker digests")

    routes = _exact_mapping(
        payload["routes"],
        {"before_sha256", "after_sha256", "source_sha256", "target_sha256"},
        "routes",
    )
    for name in ("before_sha256", "source_sha256", "target_sha256"):
        _digest(routes[name], f"route {name}")
    if routes["after_sha256"] is not None:
        _digest(routes["after_sha256"], "route after_sha256")
    if terminal == TERMINAL_COMPLETE and routes["after_sha256"] != routes["target_sha256"]:
        raise RollingReleaseEvidenceError("successful route digest is invalid")
    if terminal == TERMINAL_SWITCHED_BACK and routes["after_sha256"] != routes["source_sha256"]:
        raise RollingReleaseEvidenceError("restored route digest is invalid")

    phases = payload["phases"]
    if not isinstance(phases, list) or not phases:
        raise RollingReleaseEvidenceError("rolling phases are incomplete")
    phase_times: list[datetime] = []
    for item in phases:
        phase = _exact_mapping(item, {"phase", "at"}, "phase")
        if phase["phase"] not in PHASES:
            raise RollingReleaseEvidenceError("rolling phase is invalid")
        phase_times.append(_timestamp(phase["at"]))
    if phases[0]["phase"] != "STARTED" or phases[-1]["phase"] != _TERMINAL_PHASE[terminal]:
        raise RollingReleaseEvidenceError("rolling terminal phase is invalid")
    execution_order = [
        "STARTED",
        "PREFLIGHTED",
        "SCHEMA_EXPANDED",
        "INACTIVE_VERIFIED",
        "TRAFFIC_SWITCHED",
    ]
    non_terminal = [item["phase"] for item in phases[:-1]]
    if non_terminal != execution_order[: len(non_terminal)]:
        raise RollingReleaseEvidenceError("rolling phase sequence is invalid")
    if terminal in {TERMINAL_COMPLETE, TERMINAL_SWITCHED_BACK} and non_terminal != execution_order:
        raise RollingReleaseEvidenceError("rolling terminal sequence is incomplete")
    if terminal == TERMINAL_PRE_SWITCH_FAILED and "TRAFFIC_SWITCHED" in non_terminal:
        raise RollingReleaseEvidenceError("pre-switch failure followed a traffic switch")
    if (
        phase_times != sorted(phase_times)
        or phase_times[0] < started
        or phase_times[-1] > finished
    ):
        raise RollingReleaseEvidenceError("rolling phase timestamps are invalid")

    nginx = payload["nginx_operations"]
    if not isinstance(nginx, list):
        raise RollingReleaseEvidenceError("invalid nginx operation schema")
    nginx_times: list[datetime] = []
    for item in nginx:
        operation = _exact_mapping(item, {"action", "slot", "result", "at"}, "nginx operation")
        if (
            operation["action"] not in {"test", "reload"}
            or operation["slot"] not in {"blue", "green"}
            or operation["result"] not in {"passed", "failed"}
        ):
            raise RollingReleaseEvidenceError("invalid nginx operation")
        nginx_times.append(_timestamp(operation["at"]))
    if nginx_times != sorted(nginx_times) or any(
        observed < started or observed > finished for observed in nginx_times
    ):
        raise RollingReleaseEvidenceError("nginx operation timestamps are invalid")
    passed_nginx = [
        (item["action"], item["slot"])
        for item in nginx
        if item["result"] == "passed"
    ]
    if terminal == TERMINAL_COMPLETE and passed_nginx != [
        ("test", target["slot"]),
        ("reload", target["slot"]),
    ]:
        raise RollingReleaseEvidenceError("successful nginx switch evidence is incomplete")
    if terminal == TERMINAL_SWITCHED_BACK and passed_nginx != [
        ("test", target["slot"]),
        ("reload", target["slot"]),
        ("test", source["slot"]),
        ("reload", source["slot"]),
    ]:
        raise RollingReleaseEvidenceError("restored nginx route evidence is incomplete")

    observations = payload["public_releasez"]
    if not isinstance(observations, list):
        raise RollingReleaseEvidenceError("invalid public releasez schema")
    observation_times: list[datetime] = []
    for item in observations:
        observation = _exact_mapping(
            item,
            {
                "release_role", "attempt", "slot", "tag", "commit",
                "migration_head", "result", "expected_sha256", "peer_sha256",
                "tls_version", "at",
            },
            "public releasez observation",
        )
        if (
            observation["release_role"] not in {"source", "target"}
            or type(observation["attempt"]) is not int
            or observation["attempt"] not in {1, 2, 3}
            or observation["slot"] not in {"blue", "green"}
            or observation["result"] not in {"passed", "failed"}
        ):
            raise RollingReleaseEvidenceError("invalid public releasez observation")
        release = source if observation["release_role"] == "source" else target
        if any(
            observation[key] != release[key]
            for key in ("slot", "tag", "commit", "migration_head")
        ):
            raise RollingReleaseEvidenceError("public releasez identity is invalid")
        tls_identity = {
            "expected_sha256": observation["expected_sha256"],
            "peer_sha256": observation["peer_sha256"],
            "tls_version": observation["tls_version"],
        }
        if observation["result"] == "passed":
            if not valid_evidence_observation(tls_identity):
                raise RollingReleaseEvidenceError("public TLS identity is invalid")
        elif (
            not isinstance(observation["expected_sha256"], str)
            or _SHA256.fullmatch(observation["expected_sha256"]) is None
            or observation["peer_sha256"] is not None
            or observation["tls_version"] is not None
        ):
            raise RollingReleaseEvidenceError("failed public TLS identity is invalid")
        observation_times.append(_timestamp(observation["at"]))
    if observation_times != sorted(observation_times) or any(
        observed < started or observed > finished for observed in observation_times
    ):
        raise RollingReleaseEvidenceError("public releasez timestamps are invalid")
    if terminal == TERMINAL_COMPLETE:
        target_passes = [
            item for item in observations
            if item["release_role"] == "target" and item["result"] == "passed"
        ]
        if (
            len(observations) != 3
            or [item["attempt"] for item in target_passes] != [1, 2, 3]
        ):
            raise RollingReleaseEvidenceError("three target releasez observations are required")
    if terminal == TERMINAL_SWITCHED_BACK:
        source_passes = [
            item for item in observations
            if item["release_role"] == "source" and item["result"] == "passed"
        ]
        if [item["attempt"] for item in source_passes] != [1, 2, 3]:
            raise RollingReleaseEvidenceError("three restored-source observations are required")
        if not any(
            item["release_role"] == "target" and item["result"] == "failed"
            for item in observations
        ):
            raise RollingReleaseEvidenceError("target releasez failure is missing")

    internal_tls = payload["tls_observations"]
    if not isinstance(internal_tls, list):
        raise RollingReleaseEvidenceError("invalid internal TLS observation schema")
    tls_times: list[datetime] = []
    seen_tls: set[tuple[str, str, str]] = set()
    for item in internal_tls:
        observation = _exact_mapping(
            item,
            {
                "release_role", "service", "slot", "expected_sha256",
                "peer_sha256", "tls_version", "at",
            },
            "internal TLS observation",
        )
        role = observation["release_role"]
        service = observation["service"]
        release = source if role == "source" else target if role == "target" else None
        if (
            release is None
            or service not in {"api", "web"}
            or observation["slot"] != release["slot"]
            or not valid_evidence_observation(
                {
                    "expected_sha256": observation["expected_sha256"],
                    "peer_sha256": observation["peer_sha256"],
                    "tls_version": observation["tls_version"],
                }
            )
        ):
            raise RollingReleaseEvidenceError("internal TLS identity is invalid")
        key = (role, service, observation["slot"])
        if key in seen_tls:
            raise RollingReleaseEvidenceError("duplicate internal TLS observation")
        seen_tls.add(key)
        tls_times.append(_timestamp(observation["at"]))
    if tls_times != sorted(tls_times) or any(
        observed < started or observed > finished for observed in tls_times
    ):
        raise RollingReleaseEvidenceError("internal TLS timestamps are invalid")
    if terminal in {
        TERMINAL_COMPLETE,
        TERMINAL_SWITCHED_BACK,
        TERMINAL_ROUTE_UNCONFIRMED,
    } and seen_tls != {
        ("source", "api", source["slot"]),
        ("source", "web", source["slot"]),
        ("target", "api", target["slot"]),
        ("target", "web", target["slot"]),
    }:
        raise RollingReleaseEvidenceError("terminal internal TLS evidence is incomplete")
    return payload


def seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_payload(payload)
    sealed = json.loads(json.dumps(validated))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(validated)}
    return sealed


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact_mapping(value, _SEALED_FIELDS, "sealed rolling evidence")
    integrity = _exact_mapping(evidence["integrity"], {"payload_sha256"}, "integrity")
    digest = _digest(integrity["payload_sha256"], "payload digest")
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    _validate_payload(payload)
    if not hmac.compare_digest(digest, _canonical_digest(payload)):
        raise RollingReleaseEvidenceError("rolling evidence integrity check failed")
    return evidence


def verify_evidence(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_bytes(path, max_bytes=_MAX_EVIDENCE_BYTES)
    except StableFileError as error:
        if error.reason == "size":
            raise RollingReleaseEvidenceError(
                "rolling evidence size is invalid"
            ) from error
        raise RollingReleaseEvidenceError("rolling evidence cannot be read") from error
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if isinstance(error, json.JSONDecodeError) and error.msg == "duplicate JSON key":
            raise RollingReleaseEvidenceError(
                "rolling evidence JSON has duplicate keys"
            ) from error
        raise RollingReleaseEvidenceError("rolling evidence JSON is invalid") from error
    return validate_evidence(value)


def prepare_evidence_output(path: Path) -> Path:
    """Fail before release mutation unless a safe external write-once file is available."""

    try:
        return prepare_write_once_file(path)
    except ValueError as error:
        raise RollingReleaseEvidenceError("rolling evidence output path is unsafe") from error


def assert_expected_releases(
    evidence: Mapping[str, Any],
    *,
    source_tag: str,
    source_commit: str,
    source_manifest_sha256: str,
    target_tag: str,
    target_commit: str,
    target_manifest_sha256: str,
    target_environment: str,
    target_intake_manifest_sha256: str,
    target_intake_requirements_sha256: str,
) -> None:
    """Reject a valid ledger reused for a different reviewed release pair."""

    expected = {
        "source": {
            "tag": source_tag,
            "commit": source_commit,
            "container_manifest_sha256": source_manifest_sha256.lower(),
        },
        "target": {
            "tag": target_tag,
            "commit": target_commit,
            "container_manifest_sha256": target_manifest_sha256.lower(),
        },
    }
    for role in ("source", "target"):
        release = evidence[role]
        candidate = expected[role]
        if (
            not isinstance(candidate["tag"], str)
            or len(candidate["tag"]) > 128
            or _TAG.fullmatch(candidate["tag"]) is None
            or not isinstance(candidate["commit"], str)
            or _COMMIT.fullmatch(candidate["commit"]) is None
        ):
            raise RollingReleaseEvidenceError("expected rolling release identity is invalid")
        _digest(candidate["container_manifest_sha256"], "expected manifest digest")
        if any(
            not hmac.compare_digest(release[field], candidate[field])
            for field in ("tag", "commit", "container_manifest_sha256")
        ):
            raise RollingReleaseEvidenceError("rolling evidence release binding is invalid")
    expected_intake = {
        "environment": target_environment,
        "manifest_payload_sha256": target_intake_manifest_sha256.lower(),
        "requirements_sha256": target_intake_requirements_sha256.lower(),
        "checkpoint_phase": 0,
    }
    if evidence["target_intake"] != expected_intake:
        raise RollingReleaseEvidenceError("rolling evidence target intake binding is invalid")


class RollingReleaseEvidenceRecorder:
    def __init__(
        self,
        *,
        plan_fingerprint: str,
        source: Mapping[str, str],
        target: Mapping[str, str],
        source_images: Mapping[str, str],
        target_images: Mapping[str, str],
        expected_worker_digest: str,
        route_before_sha256: str,
        source_route_sha256: str,
        target_route_sha256: str,
        target_intake: Mapping[str, str | int],
        started_at: str | None = None,
    ) -> None:
        recorded_started_at = utc_now() if started_at is None else started_at
        _timestamp(recorded_started_at)
        self.payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "production_acceptance": False,
            "plan_fingerprint": plan_fingerprint,
            "terminal_state": TERMINAL_PRE_SWITCH_FAILED,
            "error_code": _TERMINAL_ERROR[TERMINAL_PRE_SWITCH_FAILED],
            "started_at": recorded_started_at,
            "finished_at": recorded_started_at,
            "source": dict(source),
            "target": dict(target),
            "target_intake": dict(target_intake),
            "images": {"source": dict(source_images), "target": dict(target_images)},
            "workers": {
                "expected_digest": expected_worker_digest,
                "before": {"worker_mail": None, "worker_sub2": None},
                "after": {"worker_mail": None, "worker_sub2": None},
                "unchanged": False,
            },
            "routes": {
                "before_sha256": route_before_sha256,
                "after_sha256": None,
                "source_sha256": source_route_sha256,
                "target_sha256": target_route_sha256,
            },
            "phases": [{"phase": "STARTED", "at": recorded_started_at}],
            "nginx_operations": [],
            "tls_observations": [],
            "public_releasez": [],
        }

    def phase(self, phase: str) -> None:
        if phase not in PHASES:
            raise RollingReleaseEvidenceError("rolling phase is invalid")
        if self.payload["phases"][-1]["phase"] != phase:
            self.payload["phases"].append({"phase": phase, "at": utc_now()})

    def worker(self, moment: str, service: str, digest: str) -> None:
        if moment not in {"before", "after"} or service not in _WORKER_OBSERVATION_FIELDS:
            raise RollingReleaseEvidenceError("worker observation is invalid")
        self.payload["workers"][moment][service] = digest

    def nginx(self, action: str, slot: str, result: str) -> None:
        self.payload["nginx_operations"].append(
            {"action": action, "slot": slot, "result": result, "at": utc_now()}
        )

    def internal_tls(
        self,
        release_role: str,
        service: str,
        slot: str,
        observation: Mapping[str, str],
    ) -> None:
        self.payload["tls_observations"].append(
            {
                "release_role": release_role,
                "service": service,
                "slot": slot,
                **dict(observation),
                "at": utc_now(),
            }
        )

    def public_releasez(
        self,
        *,
        release_role: str,
        attempt: int,
        release: Mapping[str, str],
        result: str,
        expected_sha256: str,
        observation: Mapping[str, str] | None = None,
    ) -> None:
        peer_sha256 = None if observation is None else observation["peer_sha256"]
        tls_version = None if observation is None else observation["tls_version"]
        self.payload["public_releasez"].append(
            {
                "release_role": release_role,
                "attempt": attempt,
                "slot": release["slot"],
                "tag": release["tag"],
                "commit": release["commit"],
                "migration_head": release["migration_head"],
                "result": result,
                "expected_sha256": expected_sha256,
                "peer_sha256": peer_sha256,
                "tls_version": tls_version,
                "at": utc_now(),
            }
        )

    def outcome(self, terminal_state: str) -> None:
        if terminal_state not in TERMINAL_STATES:
            raise RollingReleaseEvidenceError("rolling terminal state is invalid")
        self.payload["terminal_state"] = terminal_state
        self.payload["error_code"] = _TERMINAL_ERROR[terminal_state]
        self.phase(_TERMINAL_PHASE[terminal_state])

    def write(self, output_path: Path, route_after_sha256: str | None) -> dict[str, Any]:
        self.payload["routes"]["after_sha256"] = route_after_sha256
        observations = [
            self.payload["workers"][moment][service]
            for moment in ("before", "after")
            for service in _WORKER_OBSERVATION_FIELDS
        ]
        self.payload["workers"]["unchanged"] = all(
            value == self.payload["workers"]["expected_digest"] for value in observations
        )
        self.payload["finished_at"] = utc_now()
        sealed = seal_evidence(self.payload)
        serialized = (
            json.dumps(sealed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if len(serialized) > _MAX_EVIDENCE_BYTES:
            raise RollingReleaseEvidenceError("rolling evidence size is invalid")
        destination = prepare_evidence_output(output_path)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                if os.name != "nt":
                    os.chmod(temporary_path, 0o600)
                stream.write(serialized.decode("utf-8"))
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
    parser.add_argument("--expected-source-tag", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-container-manifest-sha256", required=True)
    parser.add_argument("--expected-target-tag", required=True)
    parser.add_argument("--expected-target-commit", required=True)
    parser.add_argument("--expected-target-container-manifest-sha256", required=True)
    parser.add_argument("--expected-target-environment", required=True)
    parser.add_argument("--expected-target-intake-manifest-sha256", required=True)
    parser.add_argument("--expected-target-intake-requirements-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        evidence = verify_evidence(options.input)
        assert_expected_releases(
            evidence,
            source_tag=options.expected_source_tag,
            source_commit=options.expected_source_commit,
            source_manifest_sha256=options.expected_source_container_manifest_sha256,
            target_tag=options.expected_target_tag,
            target_commit=options.expected_target_commit,
            target_manifest_sha256=options.expected_target_container_manifest_sha256,
            target_environment=options.expected_target_environment,
            target_intake_manifest_sha256=options.expected_target_intake_manifest_sha256,
            target_intake_requirements_sha256=options.expected_target_intake_requirements_sha256,
        )
    except RollingReleaseEvidenceError:
        print("rolling-release-evidence-failed", file=sys.stderr)
        return 1
    print(
        "rolling-release-evidence-ok production_acceptance=false "
        f"terminal_state={evidence['terminal_state']} "
        f"payload_sha256={evidence['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
