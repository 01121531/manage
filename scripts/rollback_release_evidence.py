"""Seal and independently verify write-once rollback execution evidence."""

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
    parse_unique_json_bytes,
    read_stable_bytes,
)
from scripts.tls_runtime_identity import (
    EXTERNAL_ENDPOINTS,
    INTERNAL_ENDPOINT_SERVICES,
    valid_evidence_observation,
)


SCHEMA_VERSION = 2
EVIDENCE_KIND = "release_bound_rollback_execution"
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
    TERMINAL_PREFLIGHT_FAILED: "rollback_preflight_failed",
    TERMINAL_EDGE_CLOSED_FAILURE: "rollback_execution_failed",
    TERMINAL_EDGE_UNCONFIRMED: "edge_unconfirmed",
}
_EXECUTION_PHASES = (
    "STARTED",
    "PREFLIGHTED",
    "WRITERS_STOPPED",
    "POSTGRES_RESTORED",
    "REDIS_RESTORED",
    "REDIS_VERIFIED",
    "INTERNAL_VERIFIED",
    "EDGE_STARTED",
    "EXTERNAL_VERIFIED",
)
PHASES = frozenset(_EXECUTION_PHASES) | frozenset(_TERMINAL_PHASE.values())
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "evidence_kind",
    "production_acceptance",
    "execution_fingerprint",
    "terminal_state",
    "error_code",
    "started_at",
    "finished_at",
    "release",
    "recovery",
    "images",
    "checks",
    "tls_observations",
    "edge",
    "phases",
}
_SEALED_FIELDS = _TOP_LEVEL_FIELDS | {"integrity"}
_RELEASE_FIELDS = {
    "tag",
    "commit",
    "migration_head",
    "container_manifest_sha256",
}
_RECOVERY_FIELDS = {
    "recovery_set",
    "postgres_manifest_sha256",
    "redis_manifest_sha256",
    "postgres_created_at",
    "redis_created_at",
}
_IMAGE_FIELDS = {"api", "worker_mail", "worker_sub2", "web", "edge"}
_CHECK_FIELDS = {
    "supply_chain_verified",
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
_OCI_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_MAX_EVIDENCE_BYTES = 64 * 1024
_MAX_RECOVERY_POINT_SKEW_SECONDS = 300


class RollbackReleaseEvidenceError(ValueError):
    """The rollback execution record cannot be accepted as evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise RollbackReleaseEvidenceError("rollback recovery timestamp must be aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RollbackReleaseEvidenceError(f"invalid {context} schema")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise RollbackReleaseEvidenceError("rollback evidence timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RollbackReleaseEvidenceError("rollback evidence timestamp is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise RollbackReleaseEvidenceError("rollback evidence timestamp must be UTC")
    return parsed


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RollbackReleaseEvidenceError(f"invalid {context}")
    return value


def _image(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) > 512 or _OCI_DIGEST.fullmatch(value) is None:
        raise RollbackReleaseEvidenceError(f"invalid {context}")
    return value


def _recovery_set(value: Any) -> str:
    if not isinstance(value, str) or _RECOVERY_SET.fullmatch(value) is None:
        raise RollbackReleaseEvidenceError("invalid recovery set")
    return value


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(canonical)


def execution_fingerprint(
    release: Mapping[str, str], recovery: Mapping[str, str]
) -> str:
    value = "\n".join(
        (
            release["tag"],
            release["commit"],
            release["migration_head"],
            release["container_manifest_sha256"],
            recovery["postgres_manifest_sha256"],
            recovery["redis_manifest_sha256"],
            recovery["recovery_set"],
        )
    )
    return sha256_bytes(value.encode("utf-8"))


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_mapping(value, _TOP_LEVEL_FIELDS, "rollback evidence")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload["evidence_kind"] != EVIDENCE_KIND
        or payload["production_acceptance"] is not False
    ):
        raise RollbackReleaseEvidenceError("rollback evidence identity is invalid")
    fingerprint = _digest(payload["execution_fingerprint"], "execution fingerprint")
    terminal = payload["terminal_state"]
    if terminal not in TERMINAL_STATES or payload["error_code"] != _TERMINAL_ERROR[terminal]:
        raise RollbackReleaseEvidenceError("rollback terminal identity is invalid")
    started = _timestamp(payload["started_at"])
    finished = _timestamp(payload["finished_at"])
    if finished < started:
        raise RollbackReleaseEvidenceError("rollback evidence window is invalid")

    release = _exact_mapping(payload["release"], _RELEASE_FIELDS, "release")
    if not isinstance(release["tag"], str) or _TAG.fullmatch(release["tag"]) is None:
        raise RollbackReleaseEvidenceError("invalid release tag")
    if not isinstance(release["commit"], str) or _COMMIT.fullmatch(release["commit"]) is None:
        raise RollbackReleaseEvidenceError("invalid release commit")
    if (
        not isinstance(release["migration_head"], str)
        or len(release["migration_head"]) > 128
        or _MIGRATION.fullmatch(release["migration_head"]) is None
    ):
        raise RollbackReleaseEvidenceError("invalid migration head")
    _digest(release["container_manifest_sha256"], "container manifest digest")

    recovery = _exact_mapping(payload["recovery"], _RECOVERY_FIELDS, "recovery")
    _recovery_set(recovery["recovery_set"])
    _digest(recovery["postgres_manifest_sha256"], "PostgreSQL manifest digest")
    _digest(recovery["redis_manifest_sha256"], "Redis manifest digest")
    postgres_created = _timestamp(recovery["postgres_created_at"])
    redis_created = _timestamp(recovery["redis_created_at"])
    if postgres_created > started or redis_created > started:
        raise RollbackReleaseEvidenceError("recovery point follows rollback start")
    if abs((redis_created - postgres_created).total_seconds()) > _MAX_RECOVERY_POINT_SKEW_SECONDS:
        raise RollbackReleaseEvidenceError("rollback recovery points are too far apart")
    if not hmac.compare_digest(fingerprint, execution_fingerprint(release, recovery)):
        raise RollbackReleaseEvidenceError("rollback execution fingerprint is invalid")

    images = _exact_mapping(payload["images"], {"expected", "observed"}, "images")
    expected_images = _exact_mapping(images["expected"], _IMAGE_FIELDS, "expected images")
    observed_images = _exact_mapping(images["observed"], _IMAGE_FIELDS, "observed images")
    for service in _IMAGE_FIELDS:
        _image(expected_images[service], f"expected {service} image")
        observed = observed_images[service]
        if observed is not None:
            _image(observed, f"observed {service} image")
            if not hmac.compare_digest(observed, expected_images[service]):
                raise RollbackReleaseEvidenceError("observed rollback image is invalid")

    checks = _exact_mapping(payload["checks"], _CHECK_FIELDS, "checks")
    for name in ("supply_chain_verified", "images_pulled"):
        if type(checks[name]) is not bool:
            raise RollbackReleaseEvidenceError("rollback check result is invalid")
    limits = {
        "vault_sink_checks_passed": 2,
        "operational_checks_passed": 2,
        "internal_probes_passed": 7,
        "external_probes_passed": 2,
    }
    for name, maximum in limits.items():
        if type(checks[name]) is not int or not 0 <= checks[name] <= maximum:
            raise RollbackReleaseEvidenceError("rollback check count is invalid")

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
        raise RollbackReleaseEvidenceError("rollback TLS observation is invalid")

    edge = _exact_mapping(payload["edge"], _EDGE_FIELDS, "edge")
    if type(edge["start_attempted"]) is not bool:
        raise RollbackReleaseEvidenceError("edge start observation is invalid")
    if type(edge["stop_confirmations"]) is not int or not 0 <= edge["stop_confirmations"] <= 2:
        raise RollbackReleaseEvidenceError("edge stop observation is invalid")
    if edge["final_state"] not in {
        "not_mutated",
        "open_verified",
        "closed_confirmed",
        "unconfirmed",
    }:
        raise RollbackReleaseEvidenceError("edge final state is invalid")

    phases = payload["phases"]
    if not isinstance(phases, list) or not phases:
        raise RollbackReleaseEvidenceError("rollback phases are incomplete")
    phase_times: list[datetime] = []
    phase_names: list[str] = []
    for item in phases:
        phase = _exact_mapping(item, {"phase", "at"}, "phase")
        if phase["phase"] not in PHASES:
            raise RollbackReleaseEvidenceError("rollback phase is invalid")
        phase_names.append(phase["phase"])
        phase_times.append(_timestamp(phase["at"]))
    if phase_names[0] != "STARTED" or phase_names[-1] != _TERMINAL_PHASE[terminal]:
        raise RollbackReleaseEvidenceError("rollback terminal phase is invalid")
    non_terminal = phase_names[:-1]
    if non_terminal != list(_EXECUTION_PHASES[: len(non_terminal)]):
        raise RollbackReleaseEvidenceError("rollback phase sequence is invalid")
    if phase_times != sorted(phase_times) or phase_times[0] < started or phase_times[-1] > finished:
        raise RollbackReleaseEvidenceError("rollback phase timestamps are invalid")

    if "PREFLIGHTED" in non_terminal and (
        checks["supply_chain_verified"] is not True
        or checks["images_pulled"] is not True
        or checks["vault_sink_checks_passed"] < 1
        or checks["operational_checks_passed"] < 1
    ):
        raise RollbackReleaseEvidenceError("preflight phase evidence is incomplete")
    if "INTERNAL_VERIFIED" in non_terminal and (
        any(observed_images[service] != expected_images[service] for service in (
            "api", "worker_mail", "worker_sub2", "web"
        ))
        or checks["internal_probes_passed"] != 7
        or set(internal_tls) != set(INTERNAL_ENDPOINT_SERVICES)
    ):
        raise RollbackReleaseEvidenceError("internal verification evidence is incomplete")
    if "EDGE_STARTED" in non_terminal and edge["start_attempted"] is not True:
        raise RollbackReleaseEvidenceError("edge start evidence is incomplete")
    if "EXTERNAL_VERIFIED" in non_terminal and (
        observed_images["edge"] != expected_images["edge"]
        or checks["external_probes_passed"] != 2
        or set(external_tls) != set(EXTERNAL_ENDPOINTS)
    ):
        raise RollbackReleaseEvidenceError("external verification evidence is incomplete")

    if terminal == TERMINAL_SUCCEEDED:
        if (
            non_terminal != list(_EXECUTION_PHASES)
            or observed_images != expected_images
            or checks
            != {
                "supply_chain_verified": True,
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
            raise RollbackReleaseEvidenceError("successful rollback evidence is incomplete")
    elif terminal == TERMINAL_PREFLIGHT_FAILED:
        if non_terminal != ["STARTED"] or edge != {
            "start_attempted": False,
            "stop_confirmations": 0,
            "final_state": "not_mutated",
        }:
            raise RollbackReleaseEvidenceError("preflight failure evidence is invalid")
    elif terminal == TERMINAL_EDGE_CLOSED_FAILURE:
        if "PREFLIGHTED" not in non_terminal or edge["final_state"] != "closed_confirmed" or edge["stop_confirmations"] < 1:
            raise RollbackReleaseEvidenceError("closed-edge failure evidence is invalid")
    else:
        expected_stops = 1 if edge["start_attempted"] else 0
        if (
            "PREFLIGHTED" not in non_terminal
            or edge["final_state"] != "unconfirmed"
            or edge["stop_confirmations"] != expected_stops
        ):
            raise RollbackReleaseEvidenceError("unconfirmed-edge evidence is invalid")
    return payload


def seal_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_payload(payload)
    sealed = json.loads(json.dumps(validated))
    sealed["integrity"] = {"payload_sha256": _canonical_digest(validated)}
    return sealed


def validate_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact_mapping(value, _SEALED_FIELDS, "sealed rollback evidence")
    integrity = _exact_mapping(evidence["integrity"], {"payload_sha256"}, "integrity")
    digest = _digest(integrity["payload_sha256"], "payload digest")
    payload = {key: item for key, item in evidence.items() if key != "integrity"}
    _validate_payload(payload)
    if not hmac.compare_digest(digest, _canonical_digest(payload)):
        raise RollbackReleaseEvidenceError("rollback evidence integrity check failed")
    return evidence


def verify_evidence(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_bytes(path, max_bytes=_MAX_EVIDENCE_BYTES)
    except StableFileError as error:
        if error.reason == "size":
            raise RollbackReleaseEvidenceError(
                "rollback evidence size is invalid"
            ) from error
        raise RollbackReleaseEvidenceError("rollback evidence cannot be read") from error
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if isinstance(error, json.JSONDecodeError) and error.msg == "duplicate JSON key":
            raise RollbackReleaseEvidenceError(
                "rollback evidence JSON has duplicate keys"
            ) from error
        raise RollbackReleaseEvidenceError("rollback evidence JSON is invalid") from error
    return validate_evidence(value)


def prepare_evidence_output(path: Path) -> Path:
    try:
        return prepare_write_once_file(path)
    except ValueError as error:
        raise RollbackReleaseEvidenceError("rollback evidence output path is unsafe") from error


def assert_expected_release(
    evidence: Mapping[str, Any],
    *,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    postgres_manifest_sha256: str,
    redis_manifest_sha256: str,
    recovery_set: str,
    images: Mapping[str, str],
) -> None:
    expected_release = {
        "tag": release_tag,
        "commit": release_commit,
        "migration_head": migration_head,
        "container_manifest_sha256": container_manifest_sha256.lower(),
    }
    expected_recovery = {
        "postgres_manifest_sha256": postgres_manifest_sha256.lower(),
        "redis_manifest_sha256": redis_manifest_sha256.lower(),
        "recovery_set": recovery_set,
    }
    _validate_payload({key: value for key, value in evidence.items() if key != "integrity"})
    if any(
        not hmac.compare_digest(evidence["release"][field], expected_release[field])
        for field in _RELEASE_FIELDS
    ) or any(
        not hmac.compare_digest(evidence["recovery"][field], expected_recovery[field])
        for field in expected_recovery
    ):
        raise RollbackReleaseEvidenceError("rollback evidence release binding is invalid")
    if set(images) != _IMAGE_FIELDS or any(
        not hmac.compare_digest(evidence["images"]["expected"][service], images[service])
        for service in _IMAGE_FIELDS
    ):
        raise RollbackReleaseEvidenceError("rollback evidence image binding is invalid")


class RollbackReleaseEvidenceRecorder:
    def __init__(
        self,
        *,
        execution_fingerprint: str,
        release: Mapping[str, str],
        recovery: Mapping[str, str],
        images: Mapping[str, str],
    ) -> None:
        started_at = utc_now()
        self.payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "production_acceptance": False,
            "execution_fingerprint": execution_fingerprint,
            "terminal_state": TERMINAL_PREFLIGHT_FAILED,
            "error_code": _TERMINAL_ERROR[TERMINAL_PREFLIGHT_FAILED],
            "started_at": started_at,
            "finished_at": started_at,
            "release": dict(release),
            "recovery": dict(recovery),
            "images": {
                "expected": dict(images),
                "observed": {service: None for service in _IMAGE_FIELDS},
            },
            "checks": {
                "supply_chain_verified": False,
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
            "phases": [{"phase": "STARTED", "at": started_at}],
        }

    def phase(self, phase: str) -> None:
        if phase not in PHASES:
            raise RollbackReleaseEvidenceError("rollback phase is invalid")
        if self.payload["phases"][-1]["phase"] != phase:
            self.payload["phases"].append({"phase": phase, "at": utc_now()})

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

    def check(self, name: str, value: bool | int) -> None:
        if name not in _CHECK_FIELDS:
            raise RollbackReleaseEvidenceError("rollback check is invalid")
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
            raise RollbackReleaseEvidenceError("rollback TLS observation is invalid")
        if endpoint in self.payload["tls_observations"][scope]:
            raise RollbackReleaseEvidenceError("rollback TLS observation is duplicated")
        self.payload["tls_observations"][scope][endpoint] = dict(observation)

    def observed_image(self, service: str, image: str) -> None:
        if service not in _IMAGE_FIELDS:
            raise RollbackReleaseEvidenceError("rollback image observation is invalid")
        self.payload["images"]["observed"][service] = image

    def edge_start_attempted(self) -> None:
        self.payload["edge"]["start_attempted"] = True

    def edge_stop_confirmed(self) -> None:
        self.payload["edge"]["stop_confirmations"] += 1

    def outcome(self, terminal_state: str) -> None:
        if terminal_state not in TERMINAL_STATES:
            raise RollbackReleaseEvidenceError("rollback terminal state is invalid")
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
            raise RollbackReleaseEvidenceError("rollback evidence size is invalid")
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
    parser.add_argument("--expected-release-tag", required=True)
    parser.add_argument("--expected-release-commit", required=True)
    parser.add_argument("--expected-migration-head", required=True)
    parser.add_argument("--expected-container-manifest-sha256", required=True)
    parser.add_argument("--expected-postgres-manifest-sha256", required=True)
    parser.add_argument("--expected-redis-manifest-sha256", required=True)
    parser.add_argument("--expected-recovery-set", required=True)
    for service in sorted(_IMAGE_FIELDS):
        parser.add_argument(f"--expected-{service.replace('_', '-')}-image", required=True)
    options = parser.parse_args(arguments)
    try:
        evidence = verify_evidence(options.input)
        assert_expected_release(
            evidence,
            release_tag=options.expected_release_tag,
            release_commit=options.expected_release_commit,
            migration_head=options.expected_migration_head,
            container_manifest_sha256=options.expected_container_manifest_sha256,
            postgres_manifest_sha256=options.expected_postgres_manifest_sha256,
            redis_manifest_sha256=options.expected_redis_manifest_sha256,
            recovery_set=options.expected_recovery_set,
            images={
                service: getattr(options, f"expected_{service}_image")
                for service in _IMAGE_FIELDS
            },
        )
    except RollbackReleaseEvidenceError:
        print("rollback-release-evidence-failed", file=sys.stderr)
        return 1
    print(
        "rollback-release-evidence-ok production_acceptance=false "
        f"terminal_state={evidence['terminal_state']} "
        f"payload_sha256={evidence['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
