"""Authenticate one T140 Linux evidence subject with an offline GitHub bundle.

The GitHub attestation authenticates only the origin and integrity of the exact
subject bytes.  Runtime observations inside that subject remain reviewed
assertions, target-host authentication remains separate, and production
acceptance always remains false.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, ContextManager, Iterator, Mapping, Protocol, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    parse_unique_json_bytes,
    read_stable_bytes_with_metadata,
    stable_file_identity,
)
from scripts import private_secret_crash_evidence as crash_evidence


TRUST_POLICY = ROOT / "deploy" / "github-attestation-trust-policy.synthetic.json"
SYNTHETIC = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-github-origin.synthetic.json"
)
SCHEMA_VERSION = 1
POLICY_KIND = "github_artifact_attestation_trust_policy"
EVIDENCE_KIND = "private_secret_github_origin_intake"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"

MAX_JSON_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_TRUSTED_ROOT_BYTES = 2 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_WORKFLOW = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml$"
)
_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_NUMERIC_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_API_VERSION = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}$")
_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_PLACEHOLDERS = frozenset(
    {"development", "example", "local", "placeholder", "tbd", "test", "unknown"}
)

_POLICY_FIELDS = {
    "schema_version",
    "policy_kind",
    "synthetic",
    "policy_status",
    "policy_effect",
    "production_acceptance",
    "repository",
    "identity",
    "trusted_root",
    "verifier",
    "review",
}
_REPOSITORY_FIELDS = {"name", "repository_id", "repository_owner_id", "visibility"}
_IDENTITY_FIELDS = {
    "oidc_issuer",
    "cert_identity",
    "signer_workflow",
    "source_ref",
    "build_trigger",
    "runner_environment",
    "predicate_type",
}
_TRUSTED_ROOT_FIELDS = {"artifact_sha256", "acquired_at", "custody_reference"}
_VERIFIER_POLICY_FIELDS = {
    "gh_executable_sha256",
    "timeout_seconds",
    "max_stdout_bytes",
}
_POLICY_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}

_EVIDENCE_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "production_acceptance",
    "subject",
    "bundle",
    "trust_policy",
    "verification",
    "review",
    "prohibited_content",
}
_SUBJECT_FIELDS = {"artifact_sha256", "payload_sha256", "attempt_id"}
_BUNDLE_FIELDS = {"artifact_sha256", "acquired_at", "api_version", "predicate_type"}
_TRUST_POLICY_BINDING_FIELDS = {"artifact_sha256"}
_VERIFICATION_FIELDS = {
    "expected_commit",
    "expected_workflow_sha256",
    "expected_runtime_policy_sha256",
    "gh_executable_sha256",
}
_EVIDENCE_REVIEW_FIELDS = {"reviewer_reference", "reviewed_at", "decision"}
_PROHIBITED_FIELDS = {
    "contains_secret_values",
    "contains_bundle_url",
    "contains_token_values",
    "contains_raw_rest_response",
    "contains_runtime_paths",
    "contains_raw_logs",
    "contains_personal_data",
}

_SAFE_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)


class GitHubAttestationError(ValueError):
    """The origin evidence cannot be authenticated safely."""


def _invalid() -> GitHubAttestationError:
    return GitHubAttestationError("private secret GitHub origin evidence is invalid")


@dataclass(frozen=True)
class StableBlob:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str],
        timeout_seconds: int,
        max_stdout_bytes: int,
        pass_fds: Sequence[int],
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    def run(
        self,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str],
        timeout_seconds: int,
        max_stdout_bytes: int,
        pass_fds: Sequence[int],
    ) -> CommandResult:
        completed = subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            env=dict(environment),
            timeout=timeout_seconds,
            pass_fds=tuple(pass_fds),
        )
        stdout = bytes(completed.stdout)
        stderr = bytes(completed.stderr)
        if len(stdout) > max_stdout_bytes or len(stderr) > MAX_STDERR_BYTES:
            raise _invalid()
        return CommandResult(completed.returncode, stdout, stderr)


@dataclass(frozen=True)
class InvocationSnapshot:
    executable: Path
    subject: Path
    bundle: Path
    trusted_root: Path
    pass_fds: tuple[int, ...]


class SnapshotFactory(Protocol):
    def open(
        self,
        *,
        executable: bytes,
        subject: bytes,
        bundle: bytes,
        trusted_root: bytes,
    ) -> ContextManager[InvocationSnapshot]: ...


class LinuxSealedSnapshotFactory:
    """Expose immutable memfd snapshots to one Linux child process."""

    @contextmanager
    def open(
        self,
        *,
        executable: bytes,
        subject: bytes,
        bundle: bytes,
        trusted_root: bytes,
    ) -> Iterator[InvocationSnapshot]:
        if sys.platform != "linux" or not hasattr(os, "memfd_create"):
            raise _invalid()
        try:
            import fcntl
        except ImportError as error:
            raise _invalid() from error
        required_constants = (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_GROW",
            "F_SEAL_SEAL",
            "F_SEAL_SHRINK",
            "F_SEAL_WRITE",
        )
        if any(not hasattr(fcntl, name) for name in required_constants):
            raise _invalid()
        allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
        close_on_exec = getattr(os, "MFD_CLOEXEC", None)
        if allow_sealing is None or close_on_exec is None:
            raise _invalid()

        descriptors: list[int] = []
        directory_fd: int | None = None
        directory: Path | None = None

        def sealed(name: str, raw: bytes, mode: int) -> int:
            try:
                writable_descriptor = os.memfd_create(
                    f"email-platform-{name}",
                    flags=allow_sealing | close_on_exec,
                )
                descriptors.append(writable_descriptor)
                offset = 0
                while offset < len(raw):
                    written = os.write(writable_descriptor, raw[offset:])
                    if written < 1:
                        raise _invalid()
                    offset += written
                os.fchmod(writable_descriptor, mode)
                os.lseek(writable_descriptor, 0, os.SEEK_SET)
                seals = (
                    fcntl.F_SEAL_WRITE
                    | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_SEAL
                )
                fcntl.fcntl(writable_descriptor, fcntl.F_ADD_SEALS, seals)
                if (
                    fcntl.fcntl(writable_descriptor, fcntl.F_GET_SEALS) & seals
                ) != seals:
                    raise _invalid()
                readonly_descriptor = os.open(
                    f"/proc/self/fd/{writable_descriptor}",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
                descriptors.append(readonly_descriptor)
                os.close(writable_descriptor)
                descriptors.remove(writable_descriptor)
                return readonly_descriptor
            except (OSError, ValueError) as error:
                raise _invalid() from error

        try:
            executable_fd = sealed("gh", executable, 0o500)
            subject_fd = sealed("subject", subject, 0o400)
            bundle_fd = sealed("bundle", bundle, 0o400)
            trusted_root_fd = sealed("trusted-root", trusted_root, 0o400)
            base = _absolute_external(Path(tempfile.gettempdir()).resolve(strict=True))
            directory = Path(tempfile.mkdtemp(prefix="email-platform-gh-origin-", dir=base))
            os.chmod(directory, 0o700)
            bundle_link = directory / "bundle.jsonl"
            os.symlink(f"/proc/self/fd/{bundle_fd}", bundle_link)
            directory_fd = os.open(
                directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            os.chmod(directory, 0o500)
            directory_metadata = os.fstat(directory_fd)
            named_metadata = directory.lstat()
            if (
                directory_metadata.st_dev != named_metadata.st_dev
                or directory_metadata.st_ino != named_metadata.st_ino
                or directory_metadata.st_nlink != named_metadata.st_nlink
                or directory_metadata.st_mode & 0o777 != 0o500
            ):
                raise _invalid()
            passed = (
                executable_fd,
                subject_fd,
                bundle_fd,
                trusted_root_fd,
                directory_fd,
            )
            yield InvocationSnapshot(
                executable=Path(f"/proc/self/fd/{executable_fd}"),
                subject=Path(f"/proc/self/fd/{subject_fd}"),
                bundle=Path(f"/proc/self/fd/{directory_fd}/bundle.jsonl"),
                trusted_root=Path(f"/proc/self/fd/{trusted_root_fd}"),
                pass_fds=passed,
            )
        except (OSError, ValueError) as error:
            raise _invalid() from error
        finally:
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
            if directory is not None:
                try:
                    os.chmod(directory, 0o700)
                    (directory / "bundle.jsonl").unlink(missing_ok=True)
                    directory.rmdir()
                except OSError:
                    pass
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _invalid()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _reference(value: object) -> str:
    if (
        not isinstance(value, str)
        or _REFERENCE.fullmatch(value) is None
        or value.casefold() in _PLACEHOLDERS
    ):
        raise _invalid()
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _invalid() from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _invalid()
    return parsed


def _sealed(value: object, fields: set[str]) -> dict[str, Any]:
    document = _closed(value, {*fields, "integrity"})
    integrity = _closed(document["integrity"], {"payload_sha256"})
    payload = {key: item for key, item in document.items() if key != "integrity"}
    if not hmac.compare_digest(_digest(integrity["payload_sha256"]), _canonical_digest(payload)):
        raise _invalid()
    return document


def _absolute_external(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _invalid()
    try:
        path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return path
    raise _invalid()


def _read_blob(path: Path | str, *, max_bytes: int, external: bool = True) -> StableBlob:
    target = _absolute_external(path) if external else Path(path)
    try:
        raw, metadata = read_stable_bytes_with_metadata(target, max_bytes=max_bytes)
    except (OSError, StableFileError, ValueError) as error:
        raise _invalid() from error
    if metadata.st_nlink != 1:
        raise _invalid()
    return StableBlob(
        target,
        raw,
        stable_file_identity(metadata),
        hashlib.sha256(raw).hexdigest(),
    )


def _unchanged(blob: StableBlob, *, max_bytes: int) -> None:
    current = _read_blob(blob.path, max_bytes=max_bytes)
    if current.identity != blob.identity or not hmac.compare_digest(current.sha256, blob.sha256):
        raise _invalid()


def _unique_document(blob: StableBlob) -> object:
    try:
        return parse_unique_json_bytes(blob.raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error


def validate_trust_policy(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    policy = _sealed(value, _POLICY_FIELDS)
    if (
        policy["schema_version"] != SCHEMA_VERSION
        or type(policy["schema_version"]) is not int
        or policy["policy_kind"] != POLICY_KIND
        or policy["policy_effect"] != "offline_origin_authentication_only"
        or policy["production_acceptance"] is not False
    ):
        raise _invalid()
    optional = ("repository", "identity", "trusted_root", "verifier", "review")
    if policy["synthetic"] is True:
        if (
            not allow_synthetic
            or policy["policy_status"] != "pending"
            or any(policy[field] is not None for field in optional)
        ):
            raise _invalid()
        return dict(policy)
    if policy["synthetic"] is not False or policy["policy_status"] != "reviewed":
        raise _invalid()

    repository = _closed(policy["repository"], _REPOSITORY_FIELDS)
    if (
        not isinstance(repository["name"], str)
        or _REPOSITORY.fullmatch(repository["name"]) is None
        or not isinstance(repository["repository_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_id"]) is None
        or not isinstance(repository["repository_owner_id"], str)
        or _NUMERIC_ID.fullmatch(repository["repository_owner_id"]) is None
        or repository["visibility"] not in {"public", "private", "internal"}
    ):
        raise _invalid()

    identity = _closed(policy["identity"], _IDENTITY_FIELDS)
    expected_identity = (
        f"https://github.com/{identity['signer_workflow']}@{identity['source_ref']}"
    )
    if (
        identity["oidc_issuer"] != OIDC_ISSUER
        or not isinstance(identity["signer_workflow"], str)
        or _WORKFLOW.fullmatch(identity["signer_workflow"]) is None
        or not identity["signer_workflow"].startswith(repository["name"] + "/")
        or not isinstance(identity["source_ref"], str)
        or _REF.fullmatch(identity["source_ref"]) is None
        or identity["cert_identity"] != expected_identity
        or identity["build_trigger"] != "push"
        or identity["runner_environment"] != "github-hosted"
        or identity["predicate_type"] != PREDICATE_TYPE
    ):
        raise _invalid()

    trusted_root = _closed(policy["trusted_root"], _TRUSTED_ROOT_FIELDS)
    _digest(trusted_root["artifact_sha256"])
    _timestamp(trusted_root["acquired_at"])
    _reference(trusted_root["custody_reference"])

    verifier = _closed(policy["verifier"], _VERIFIER_POLICY_FIELDS)
    _digest(verifier["gh_executable_sha256"])
    if (
        type(verifier["timeout_seconds"]) is not int
        or not 5 <= verifier["timeout_seconds"] <= 120
        or type(verifier["max_stdout_bytes"]) is not int
        or not 1024 <= verifier["max_stdout_bytes"] <= 4 * 1024 * 1024
    ):
        raise _invalid()

    review = _closed(policy["review"], _POLICY_REVIEW_FIELDS)
    _reference(review["reviewer_reference"])
    reviewed_at = _timestamp(review["reviewed_at"])
    if review["decision"] != "approved_for_offline_origin_authentication" or reviewed_at < _timestamp(
        trusted_root["acquired_at"]
    ):
        raise _invalid()
    return dict(policy)


def validate_origin_envelope(value: object, *, allow_synthetic: bool = False) -> dict[str, Any]:
    envelope = _sealed(value, _EVIDENCE_FIELDS)
    if (
        envelope["schema_version"] != SCHEMA_VERSION
        or type(envelope["schema_version"]) is not int
        or envelope["evidence_kind"] != EVIDENCE_KIND
        or envelope["production_acceptance"] is not False
    ):
        raise _invalid()
    prohibited = _closed(envelope["prohibited_content"], _PROHIBITED_FIELDS)
    if any(item is not False for item in prohibited.values()):
        raise _invalid()
    optional = ("subject", "bundle", "trust_policy", "verification", "review")
    if envelope["synthetic"] is True:
        if (
            not allow_synthetic
            or envelope["evidence_status"] != "pending"
            or envelope["origin_authentication"] != "unverified"
            or any(envelope[field] is not None for field in optional)
        ):
            raise _invalid()
        return dict(envelope)
    if (
        envelope["synthetic"] is not False
        or envelope["evidence_status"] != "ready_for_verification"
        or envelope["origin_authentication"] != "pending_cryptographic_verification"
    ):
        raise _invalid()

    subject = _closed(envelope["subject"], _SUBJECT_FIELDS)
    _digest(subject["artifact_sha256"])
    _digest(subject["payload_sha256"])
    try:
        import uuid

        attempt = uuid.UUID(subject["attempt_id"], version=4)
    except (AttributeError, TypeError, ValueError):
        raise _invalid() from None
    if str(attempt) != subject["attempt_id"]:
        raise _invalid()

    bundle = _closed(envelope["bundle"], _BUNDLE_FIELDS)
    _digest(bundle["artifact_sha256"])
    acquired_at = _timestamp(bundle["acquired_at"])
    if not isinstance(bundle["api_version"], str) or _API_VERSION.fullmatch(bundle["api_version"]) is None:
        raise _invalid()
    if bundle["predicate_type"] != PREDICATE_TYPE:
        raise _invalid()

    policy_binding = _closed(envelope["trust_policy"], _TRUST_POLICY_BINDING_FIELDS)
    _digest(policy_binding["artifact_sha256"])
    verification = _closed(envelope["verification"], _VERIFICATION_FIELDS)
    if not isinstance(verification["expected_commit"], str) or _COMMIT.fullmatch(
        verification["expected_commit"]
    ) is None:
        raise _invalid()
    for field in (
        "expected_workflow_sha256",
        "expected_runtime_policy_sha256",
        "gh_executable_sha256",
    ):
        _digest(verification[field])

    review = _closed(envelope["review"], _EVIDENCE_REVIEW_FIELDS)
    _reference(review["reviewer_reference"])
    if (
        review["decision"] != "approved_for_offline_verification"
        or _timestamp(review["reviewed_at"]) < acquired_at
    ):
        raise _invalid()
    return dict(envelope)


def _clean_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    values = os.environ if source is None else source
    return {key: values[key] for key in _SAFE_ENVIRONMENT_KEYS if key in values}


def _certificate_extensions(certificate: object) -> dict[str, Any]:
    if not isinstance(certificate, dict):
        raise _invalid()
    extensions = certificate.get("extensions")
    if not isinstance(extensions, dict):
        raise _invalid()
    return extensions


def _extension(extensions: Mapping[str, object], lower: str, acronym: str) -> object:
    present = [key for key in (lower, acronym) if key in extensions]
    if len(present) != 1:
        raise _invalid()
    return extensions[present[0]]


def _verify_gh_output(
    raw: bytes,
    *,
    policy: Mapping[str, Any],
    subject_sha256: str,
    expected_commit: str,
    run_id: int,
    run_attempt: int,
) -> None:
    if len(raw) > policy["verifier"]["max_stdout_bytes"]:
        raise _invalid()
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise _invalid()
    result = value[0].get("verificationResult")
    if not isinstance(result, dict):
        raise _invalid()
    timestamps = result.get("verifiedTimestamps")
    statement = result.get("statement")
    signature = result.get("signature")
    if not isinstance(timestamps, list) or not timestamps or not isinstance(statement, dict) or not isinstance(signature, dict):
        raise _invalid()
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise _invalid()
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        raise _invalid()
    digest = subjects[0].get("digest")
    if not isinstance(digest, dict) or digest.get("sha256") != subject_sha256:
        raise _invalid()

    repository = policy["repository"]
    identity = policy["identity"]
    extensions = _certificate_extensions(signature.get("certificate"))
    expected_run = (
        f"https://github.com/{repository['name']}/actions/runs/{run_id}/attempts/{run_attempt}"
    )
    expected_values = (
        (_extension(extensions, "sourceRepositoryUri", "SourceRepositoryURI"), f"https://github.com/{repository['name']}"),
        (_extension(extensions, "sourceRepositoryIdentifier", "SourceRepositoryIdentifier"), repository["repository_id"]),
        (_extension(extensions, "sourceRepositoryOwnerIdentifier", "SourceRepositoryOwnerIdentifier"), repository["repository_owner_id"]),
        (_extension(extensions, "sourceRepositoryVisibility", "SourceRepositoryVisibility"), repository["visibility"]),
        (_extension(extensions, "sourceRepositoryDigest", "SourceRepositoryDigest"), expected_commit),
        (_extension(extensions, "sourceRepositoryRef", "SourceRepositoryRef"), identity["source_ref"]),
        (_extension(extensions, "buildSignerUri", "BuildSignerURI"), identity["cert_identity"]),
        (_extension(extensions, "buildSignerDigest", "BuildSignerDigest"), expected_commit),
        (_extension(extensions, "runnerEnvironment", "RunnerEnvironment"), identity["runner_environment"]),
        (_extension(extensions, "runnerInvocationUri", "RunnerInvocationURI"), expected_run),
        (_extension(extensions, "buildTrigger", "BuildTrigger"), identity["build_trigger"]),
    )
    if any(actual != expected for actual, expected in expected_values):
        raise _invalid()


def verify_authenticated(
    input_path: Path | str,
    subject_path: Path | str,
    before_inventory_path: Path | str,
    after_inventory_path: Path | str,
    bundle_path: Path | str,
    trusted_root_path: Path | str,
    policy_path: Path | str,
    gh_executable_path: Path | str,
    *,
    expected_policy_sha256: str,
    expected_gh_sha256: str,
    runner: CommandRunner | None = None,
    snapshot_factory: SnapshotFactory | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    paths = [
        input_path,
        subject_path,
        before_inventory_path,
        after_inventory_path,
        bundle_path,
        trusted_root_path,
        policy_path,
        gh_executable_path,
    ]
    normalized = {str(_absolute_external(path).resolve(strict=False)).casefold() for path in paths}
    if len(normalized) != len(paths):
        raise _invalid()

    origin_blob = _read_blob(input_path, max_bytes=MAX_JSON_BYTES)
    subject_blob = _read_blob(subject_path, max_bytes=MAX_JSON_BYTES)
    bundle_blob = _read_blob(bundle_path, max_bytes=MAX_BUNDLE_BYTES)
    root_blob = _read_blob(trusted_root_path, max_bytes=MAX_TRUSTED_ROOT_BYTES)
    policy_blob = _read_blob(policy_path, max_bytes=MAX_JSON_BYTES)
    executable_blob = _read_blob(gh_executable_path, max_bytes=MAX_EXECUTABLE_BYTES)
    origin = validate_origin_envelope(_unique_document(origin_blob))
    policy = validate_trust_policy(_unique_document(policy_blob))
    verification = origin["verification"]
    if (
        not hmac.compare_digest(origin["subject"]["artifact_sha256"], subject_blob.sha256)
        or not hmac.compare_digest(origin["bundle"]["artifact_sha256"], bundle_blob.sha256)
        or not hmac.compare_digest(origin["trust_policy"]["artifact_sha256"], policy_blob.sha256)
        or not hmac.compare_digest(_digest(expected_policy_sha256), policy_blob.sha256)
        or not hmac.compare_digest(policy["trusted_root"]["artifact_sha256"], root_blob.sha256)
        or not hmac.compare_digest(_digest(expected_gh_sha256), executable_blob.sha256)
        or not hmac.compare_digest(verification["gh_executable_sha256"], executable_blob.sha256)
        or not hmac.compare_digest(policy["verifier"]["gh_executable_sha256"], executable_blob.sha256)
        or origin["review"]["reviewer_reference"]
        == policy["review"]["reviewer_reference"]
    ):
        raise _invalid()

    try:
        subject = crash_evidence.validate_envelope(_unique_document(subject_blob))
    except (crash_evidence.PrivateSecretCrashEvidenceError, TypeError, ValueError) as error:
        raise _invalid() from error
    if (
        subject["scope"].get("kind") != "github_actions_linux_ci"
        or subject["attempt_id"] != origin["subject"]["attempt_id"]
        or not hmac.compare_digest(subject["integrity"]["payload_sha256"], origin["subject"]["payload_sha256"])
        or subject["scope"]["commit_sha"] != verification["expected_commit"]
    ):
        raise _invalid()
    try:
        t140_snapshot = crash_evidence.verify_evidence_snapshot(
            subject_path,
            before_inventory_path,
            after_inventory_path,
            expected_runtime_policy_sha256=verification["expected_runtime_policy_sha256"],
            expected_commit=verification["expected_commit"],
            expected_workflow_sha256=verification["expected_workflow_sha256"],
        )
    except (crash_evidence.PrivateSecretCrashEvidenceError, OSError, TypeError, ValueError) as error:
        raise _invalid() from error
    if not hmac.compare_digest(
        t140_snapshot.evidence_artifact_sha256,
        subject_blob.sha256,
    ):
        raise _invalid()

    command_runner = SubprocessCommandRunner() if runner is None else runner
    factory = LinuxSealedSnapshotFactory() if snapshot_factory is None else snapshot_factory
    identity = policy["identity"]
    try:
        with factory.open(
            executable=executable_blob.raw,
            subject=subject_blob.raw,
            bundle=bundle_blob.raw,
            trusted_root=root_blob.raw,
        ) as snapshot:
            arguments = [
                str(snapshot.executable),
                "attestation",
                "verify",
                str(snapshot.subject),
                "--repo",
                policy["repository"]["name"],
                "--bundle",
                str(snapshot.bundle),
                "--custom-trusted-root",
                str(snapshot.trusted_root),
                "--cert-oidc-issuer",
                identity["oidc_issuer"],
                "--cert-identity",
                identity["cert_identity"],
                "--signer-digest",
                verification["expected_commit"],
                "--source-digest",
                verification["expected_commit"],
                "--source-ref",
                identity["source_ref"],
                "--deny-self-hosted-runners",
                "--predicate-type",
                identity["predicate_type"],
                "--format",
                "json",
            ]
            completed = command_runner.run(
                arguments,
                environment=_clean_environment(environment),
                timeout_seconds=policy["verifier"]["timeout_seconds"],
                max_stdout_bytes=policy["verifier"]["max_stdout_bytes"],
                pass_fds=snapshot.pass_fds,
            )
            if (
                type(completed.returncode) is not int
                or completed.returncode != 0
                or not isinstance(completed.stdout, bytes)
                or not isinstance(completed.stderr, bytes)
                or len(completed.stdout) > policy["verifier"]["max_stdout_bytes"]
                or len(completed.stderr) > MAX_STDERR_BYTES
            ):
                raise _invalid()
            _verify_gh_output(
                completed.stdout,
                policy=policy,
                subject_sha256=subject_blob.sha256,
                expected_commit=verification["expected_commit"],
                run_id=subject["scope"]["run_id"],
                run_attempt=subject["scope"]["run_attempt"],
            )
    except (OSError, subprocess.SubprocessError, TimeoutError, TypeError, ValueError) as error:
        raise _invalid() from error

    for blob, limit in (
        (origin_blob, MAX_JSON_BYTES),
        (subject_blob, MAX_JSON_BYTES),
        (bundle_blob, MAX_BUNDLE_BYTES),
        (root_blob, MAX_TRUSTED_ROOT_BYTES),
        (policy_blob, MAX_JSON_BYTES),
        (executable_blob, MAX_EXECUTABLE_BYTES),
    ):
        _unchanged(blob, max_bytes=limit)
    return origin


def verify_repository_assets() -> tuple[dict[str, Any], dict[str, Any]]:
    policy_blob = _read_blob(TRUST_POLICY, max_bytes=MAX_JSON_BYTES, external=False)
    origin_blob = _read_blob(SYNTHETIC, max_bytes=MAX_JSON_BYTES, external=False)
    return (
        validate_trust_policy(_unique_document(policy_blob), allow_synthetic=True),
        validate_origin_envelope(_unique_document(origin_blob), allow_synthetic=True),
    )


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GitHubAttestationError("private secret GitHub origin arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository", allow_abbrev=False)
    verify = commands.add_parser("verify-authenticated", allow_abbrev=False)
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--subject", type=Path, required=True)
    verify.add_argument("--before-inventory", type=Path, required=True)
    verify.add_argument("--after-inventory", type=Path, required=True)
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--trusted-root", type=Path, required=True)
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--gh-executable", type=Path, required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--expected-gh-sha256", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(arguments)
        if options.command == "verify-repository":
            verify_repository_assets()
            print(
                "private-secret-github-origin-template-ok "
                "github-origin=unverified t140-consistency=template-only "
                "runtime-facts=unverified target-host=unverified "
                "freshness=unverified replay-protection=unverified "
                "durability=unverified reviewer-independence=unverified "
                "job-binding=unverified rest-snapshot=unverified "
                "production_acceptance=false"
            )
            return 0
        origin = verify_authenticated(
            options.input,
            options.subject,
            options.before_inventory,
            options.after_inventory,
            options.bundle,
            options.trusted_root,
            options.policy,
            options.gh_executable,
            expected_policy_sha256=options.expected_policy_sha256,
            expected_gh_sha256=options.expected_gh_sha256,
        )
    except (GitHubAttestationError, OSError, TypeError, ValueError):
        print("private-secret-github-origin-failed", file=sys.stderr)
        return 1
    print(
        "private-secret-github-origin-ok "
        "github-origin=verified t140-consistency=verified "
        "runtime-facts=reviewed-assertion target-host=unverified "
        "freshness=unverified replay-protection=unverified "
        "durability=unverified reviewer-independence=unverified "
        "job-binding=unverified rest-snapshot=unverified "
        "production_acceptance=false "
        f"payload_sha256={origin['integrity']['payload_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
