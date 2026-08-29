"""Write-once encrypted audit-event archives and offline verification."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import BinaryIO, Iterable, Iterator, Mapping, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Engine, and_, or_, select
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import Session

from platform.audit import (
    AUDIT_ARCHIVE_SCHEMA_VERSION,
    AUDIT_REDACTION_VERSION,
    project_audit_event,
)
from platform.models import AuditEvent
from scripts.backup_crypto import (
    ALGORITHM,
    FORMAT_VERSION,
    decrypt_stream,
    encrypt_stream,
    key_id,
    load_key_file,
)
from scripts.backup_output_policy import (
    CLEANUP_UNCONFIRMED_NOTE,
    cleanup_created_directory_after_failure,
    cleanup_unconfirmed,
    create_write_once_directory,
    discard_claimed_temporary_file,
    prepare_write_once_file,
    publish_bundle_write_once_file,
    require_exact_regular_files,
)
from scripts.external_json import StableFileError, StableFileIdentity, open_stable_binary
from scripts.private_secret_file import (
    PrivateSecretFileError,
    read_private_secret_bytes,
)


ARTIFACT_NAME = "audit-events.v1.jsonl.enc"
MANIFEST_NAME = "manifest.json"
ARCHIVE_MANIFEST_SCHEMA = 1
ARCHIVE_TYPE = "audit_events"
ARCHIVE_LOGICAL_NAME = "audit-events.v1.jsonl"
ARCHIVE_SOURCE_DATABASE = "platform"
MANIFEST_HMAC_FIELD = "manifest_hmac_sha256"
MANIFEST_HKDF_INFO = b"email-platform/audit-archive-manifest/v1/hmac-sha256"
PRODUCTION_ACCEPTANCE = False
MAX_MANIFEST_BYTES = 64 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_DATABASE_URL_BYTES = 16 * 1024
MAX_PAGE_SIZE = 10_000
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")

RECORD_FIELDS = (
    "schema_version",
    "redaction_version",
    "id",
    "tenant_id",
    "created_at",
    "actor_id",
    "user_id",
    "device_id",
    "event_type",
    "action",
    "result",
    "entity_type",
    "entity_id",
    "trace_id",
    "policy_version",
    "ip_address",
    "user_agent",
    "details",
)
_RECORD_FIELD_SET = frozenset(RECORD_FIELDS)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "archive_type",
        "production_acceptance",
        "created_at",
        "tenant_id",
        "created_from",
        "created_to",
        "ordering",
        "record_schema_version",
        "redaction_version",
        "tool_source_commit",
        "artifact",
        MANIFEST_HMAC_FIELD,
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "name",
        "content_type",
        "sha256",
        "size_bytes",
        "plaintext_sha256",
        "row_count",
        "first",
        "last",
        "algorithm",
        "format_version",
        "key_id",
    }
)
_BOUNDARY_FIELDS = frozenset({"created_at", "id"})


class AuditArchiveError(ValueError):
    """The archive operation did not satisfy the closed safety contract."""


def _utc_text(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AuditArchiveError("archive time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc_text(value: object) -> datetime:
    if not isinstance(value, str):
        raise AuditArchiveError("archive timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuditArchiveError("archive timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None or _utc_text(parsed) != value:
        raise AuditArchiveError("archive timestamp is invalid")
    return parsed.astimezone(timezone.utc)


def _validated_window(created_from: datetime, created_to: datetime) -> tuple[datetime, datetime]:
    from_text = _utc_text(created_from)
    to_text = _utc_text(created_to)
    normalized_from = _parse_utc_text(from_text)
    normalized_to = _parse_utc_text(to_text)
    if normalized_from >= normalized_to:
        raise AuditArchiveError("archive time range is invalid")
    return normalized_from, normalized_to


def _validated_tenant(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise AuditArchiveError("archive tenant is invalid")
    if value != value.strip() or any(ord(character) < 0x20 for character in value):
        raise AuditArchiveError("archive tenant is invalid")
    return value


def _validated_page_size(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_PAGE_SIZE:
        raise AuditArchiveError("archive page size is invalid")
    return value


def _validated_source_commit(value: object) -> str:
    if not isinstance(value, str) or _SOURCE_COMMIT.fullmatch(value) is None:
        raise AuditArchiveError("archive tool source commit is invalid")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _assert_safe_input_directory(path: Path) -> None:
    if not path.is_absolute():
        raise AuditArchiveError("archive input directory is invalid")
    current = path
    while True:
        if _is_link_or_reparse(current):
            raise AuditArchiveError("archive input directory is invalid")
        if current.parent == current:
            break
        current = current.parent
    try:
        metadata = path.stat()
    except OSError as error:
        raise AuditArchiveError("archive input directory is invalid") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise AuditArchiveError("archive input directory is invalid")


@contextmanager
def _open_regular_file(
    path: Path,
    *,
    expected_identity: StableFileIdentity | None = None,
) -> Iterator[BinaryIO]:
    try:
        with open_stable_binary(
            path,
            expected_identity=expected_identity,
        ) as (stream, _):
            yield stream
    except StableFileError as error:
        raise AuditArchiveError("archive file is invalid") from error


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for field, value in pairs:
        if field in result:
            raise AuditArchiveError("archive JSON contains duplicate fields")
        result[field] = value
    return result


def _reject_json_constant(_: str) -> object:
    raise AuditArchiveError("archive JSON contains a non-finite value")


def _json_loads(data: bytes) -> object:
    try:
        return json.loads(
            data,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditArchiveError("archive JSON is invalid") from error


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise AuditArchiveError("archive value is not JSON-safe") from error


def _manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    return _canonical_json(
        {field: value for field, value in manifest.items() if field != MANIFEST_HMAC_FIELD}
    )


def _manifest_hmac(manifest: Mapping[str, object], key: bytes) -> str:
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=MANIFEST_HKDF_INFO,
    ).derive(key)
    return hmac.new(mac_key, _manifest_bytes(manifest), hashlib.sha256).hexdigest()


class IteratorReader:
    """Expose a byte-chunk iterator as the bounded ``read`` API used by encrypt_stream."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._buffer = bytearray()
        self._finished = False
        self.sha256 = hashlib.sha256()
        self.size_bytes = 0

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        while not self._finished and (size < 0 or len(self._buffer) < size):
            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._finished = True
                break
            if not isinstance(chunk, bytes) or not chunk:
                raise AuditArchiveError("archive plaintext stream is invalid")
            self._buffer.extend(chunk)
        if size < 0:
            data = bytes(self._buffer)
            self._buffer.clear()
        else:
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
        self.sha256.update(data)
        self.size_bytes += len(data)
        return data


def _project(value: AuditEvent | Mapping[str, object]) -> dict[str, object]:
    try:
        projected = dict(project_audit_event(value))  # type: ignore[arg-type]
    except Exception as error:
        raise AuditArchiveError("audit event projection failed") from error
    if frozenset(projected) != _RECORD_FIELD_SET:
        raise AuditArchiveError("audit event projection fields are invalid")
    if projected.get("schema_version") != AUDIT_ARCHIVE_SCHEMA_VERSION:
        raise AuditArchiveError("audit event projection schema is invalid")
    if projected.get("redaction_version") != AUDIT_REDACTION_VERSION:
        raise AuditArchiveError("audit event projection redaction is invalid")
    if not isinstance(projected.get("details"), dict):
        raise AuditArchiveError("audit event projection details are invalid")
    _canonical_json(projected)
    return projected


def _boundary(record: Mapping[str, object]) -> dict[str, str]:
    identifier = record.get("id")
    created_at = record.get("created_at")
    if not isinstance(identifier, str) or not identifier:
        raise AuditArchiveError("audit event id is invalid")
    _parse_utc_text(created_at)
    assert isinstance(created_at, str)
    return {"created_at": created_at, "id": identifier}


@contextmanager
def _read_only_snapshot(engine: Engine) -> Iterator[Session]:
    dialect = engine.dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        raise AuditArchiveError("archive database dialect is unsupported")
    connection = engine.connect()
    sqlite_original: int | None = None
    transaction = None
    try:
        if dialect == "sqlite":
            sqlite_original = int(connection.exec_driver_sql("PRAGMA query_only").scalar_one())
            connection.commit()
            connection.exec_driver_sql("PRAGMA query_only = ON")
            connection.commit()
            transaction = connection.begin()
        else:
            transaction = connection.begin()
            connection.exec_driver_sql(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
        with Session(bind=connection, autoflush=False, expire_on_commit=False) as session:
            yield session
        transaction.commit()
        transaction = None
    finally:
        if transaction is not None and transaction.is_active:
            transaction.rollback()
        if dialect == "sqlite" and sqlite_original is not None:
            try:
                if connection.in_transaction():
                    connection.rollback()
                connection.exec_driver_sql(f"PRAGMA query_only = {sqlite_original}")
                connection.commit()
            except Exception:
                connection.invalidate()
        connection.close()


def _event_chunks(
    session: Session,
    *,
    tenant_id: str,
    created_from: datetime,
    created_to: datetime,
    page_size: int,
    state: dict[str, object],
) -> Iterator[bytes]:
    last_created_at: datetime | None = None
    last_id: str | None = None
    while True:
        statement = select(AuditEvent).where(
            AuditEvent.tenant_id == tenant_id,
            AuditEvent.created_at >= created_from,
            AuditEvent.created_at < created_to,
        )
        if last_created_at is not None and last_id is not None:
            statement = statement.where(
                or_(
                    AuditEvent.created_at > last_created_at,
                    and_(AuditEvent.created_at == last_created_at, AuditEvent.id > last_id),
                )
            )
        rows = list(
            session.execute(
                statement.order_by(AuditEvent.created_at, AuditEvent.id).limit(page_size)
            ).scalars()
        )
        if not rows:
            break
        for event in rows:
            record = _project(event)
            if record.get("tenant_id") != tenant_id:
                raise AuditArchiveError("audit event tenant is invalid")
            record_time = _parse_utc_text(record.get("created_at"))
            if not created_from <= record_time < created_to:
                raise AuditArchiveError("audit event timestamp is outside the archive range")
            boundary = _boundary(record)
            previous = state.get("last")
            if isinstance(previous, dict):
                previous_key = (_parse_utc_text(previous.get("created_at")), previous.get("id"))
                current_key = (record_time, boundary["id"])
                if not current_key > previous_key:
                    raise AuditArchiveError("audit event ordering is invalid")
            if state.get("first") is None:
                state["first"] = boundary
            state["last"] = boundary
            state["row_count"] = int(state["row_count"]) + 1
            encoded = _canonical_json(record)
            if len(encoded) > MAX_RECORD_BYTES:
                raise AuditArchiveError("audit event projection is too large")
            yield encoded + b"\n"
        last_created_at = rows[-1].created_at
        last_id = rows[-1].id
        if len(rows) < page_size:
            break
    if int(state["row_count"]) == 0:
        # backup_crypto deliberately rejects a zero-byte payload. A single empty
        # JSONL line is the closed representation of an empty archive.
        yield b"\n"


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _open_regular_file(path) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    if size <= 0:
        raise AuditArchiveError("archive artifact is empty")
    return digest.hexdigest(), size


def _archive_events_in_claimed_directory(
    directory: Path,
    *,
    engine: Engine,
    key_file: Path | str,
    tenant_id: str,
    created_from: datetime,
    created_to: datetime,
    page_size: int,
    tool_source_commit: str,
) -> dict[str, object]:
    key = load_key_file(key_file)
    artifact_path = prepare_write_once_file(directory / ARTIFACT_NAME)
    state: dict[str, object] = {"row_count": 0, "first": None, "last": None}
    temporary_artifact: Path | None = None
    try:
        with _read_only_snapshot(engine) as session:
            chunks = _event_chunks(
                session,
                tenant_id=tenant_id,
                created_from=created_from,
                created_to=created_to,
                page_size=page_size,
                state=state,
            )
            reader = IteratorReader(chunks)
            with tempfile.NamedTemporaryFile(
                dir=directory,
                prefix=f".{ARTIFACT_NAME}.",
                suffix=".tmp",
                delete=False,
            ) as destination:
                temporary_artifact = Path(destination.name)
                encrypt_stream(
                    reader,
                    destination,
                    key,
                    logical_name=ARCHIVE_LOGICAL_NAME,
                    source_database=ARCHIVE_SOURCE_DATABASE,
                )
                destination.flush()
                os.fsync(destination.fileno())
        publishing_artifact = temporary_artifact
        temporary_artifact = None
        publish_bundle_write_once_file(publishing_artifact, artifact_path)
    finally:
        discard_claimed_temporary_file(temporary_artifact)

    ciphertext_sha256, ciphertext_size = _hash_file(artifact_path)
    manifest: dict[str, object] = {
        "schema_version": ARCHIVE_MANIFEST_SCHEMA,
        "archive_type": ARCHIVE_TYPE,
        "production_acceptance": PRODUCTION_ACCEPTANCE,
        "created_at": _utc_text(datetime.now(timezone.utc)),
        "tenant_id": tenant_id,
        "created_from": _utc_text(created_from),
        "created_to": _utc_text(created_to),
        "ordering": ["created_at", "id"],
        "record_schema_version": AUDIT_ARCHIVE_SCHEMA_VERSION,
        "redaction_version": AUDIT_REDACTION_VERSION,
        "tool_source_commit": tool_source_commit,
        "artifact": {
            "name": ARTIFACT_NAME,
            "content_type": "application/octet-stream",
            "sha256": ciphertext_sha256,
            "size_bytes": ciphertext_size,
            "plaintext_sha256": reader.sha256.hexdigest(),
            "row_count": state["row_count"],
            "first": state["first"],
            "last": state["last"],
            "algorithm": ALGORITHM,
            "format_version": FORMAT_VERSION,
            "key_id": key_id(key),
        },
    }
    manifest[MANIFEST_HMAC_FIELD] = _manifest_hmac(manifest, key)
    manifest_path = prepare_write_once_file(directory / MANIFEST_NAME)
    temporary_manifest: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=directory,
            prefix=f".{MANIFEST_NAME}.",
            suffix=".tmp",
            delete=False,
        ) as destination:
            temporary_manifest = Path(destination.name)
            destination.write(_canonical_json(manifest) + b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        publishing_manifest = temporary_manifest
        temporary_manifest = None
        publish_bundle_write_once_file(publishing_manifest, manifest_path)
    finally:
        discard_claimed_temporary_file(temporary_manifest)
    return manifest


def archive_events(
    output_dir: Path | str,
    *,
    engine: Engine,
    key_file: Path | str,
    tenant_id: str,
    created_from: datetime,
    created_to: datetime,
    page_size: int = 1000,
    tool_source_commit: str,
) -> dict[str, object]:
    """Export one tenant/time window without modifying the source database."""

    reviewed_tenant = _validated_tenant(tenant_id)
    reviewed_from, reviewed_to = _validated_window(created_from, created_to)
    reviewed_page_size = _validated_page_size(page_size)
    reviewed_commit = _validated_source_commit(tool_source_commit)
    directory_claim = create_write_once_directory(output_dir)
    directory = directory_claim.path
    try:
        return _archive_events_in_claimed_directory(
            directory,
            engine=engine,
            key_file=key_file,
            tenant_id=reviewed_tenant,
            created_from=reviewed_from,
            created_to=reviewed_to,
            page_size=reviewed_page_size,
            tool_source_commit=reviewed_commit,
        )
    except BaseException as error:
        cleanup_created_directory_after_failure(directory_claim, error)
        raise


def _read_manifest(
    path: Path,
    *,
    expected_identity: StableFileIdentity | None = None,
) -> dict[str, object]:
    with _open_regular_file(path, expected_identity=expected_identity) as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise AuditArchiveError("archive manifest is invalid")
    loaded = _json_loads(data)
    if not isinstance(loaded, dict):
        raise AuditArchiveError("archive manifest is invalid")
    return loaded


def _require_exact_fields(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise AuditArchiveError(f"archive {label} fields are invalid")
    return value


def _validate_boundary(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    boundary = _require_exact_fields(value, _BOUNDARY_FIELDS, "boundary")
    identifier = boundary.get("id")
    created_at = boundary.get("created_at")
    if not isinstance(identifier, str) or not identifier:
        raise AuditArchiveError("archive boundary is invalid")
    _parse_utc_text(created_at)
    assert isinstance(created_at, str)
    return {"created_at": created_at, "id": identifier}


def _validate_manifest_structure(
    manifest: dict[str, object],
    *,
    key: bytes,
    tenant_id: str,
    created_from: datetime,
    created_to: datetime,
) -> dict[str, object]:
    _require_exact_fields(manifest, _TOP_LEVEL_FIELDS, "manifest")
    if (
        manifest.get("schema_version") != ARCHIVE_MANIFEST_SCHEMA
        or manifest.get("archive_type") != ARCHIVE_TYPE
        or manifest.get("production_acceptance") is not False
        or manifest.get("tenant_id") != tenant_id
        or manifest.get("created_from") != _utc_text(created_from)
        or manifest.get("created_to") != _utc_text(created_to)
        or manifest.get("ordering") != ["created_at", "id"]
        or manifest.get("record_schema_version") != AUDIT_ARCHIVE_SCHEMA_VERSION
        or manifest.get("redaction_version") != AUDIT_REDACTION_VERSION
    ):
        raise AuditArchiveError("archive manifest contract is invalid")
    _parse_utc_text(manifest.get("created_at"))
    _validated_source_commit(manifest.get("tool_source_commit"))
    artifact = _require_exact_fields(manifest.get("artifact"), _ARTIFACT_FIELDS, "artifact")
    if (
        artifact.get("name") != ARTIFACT_NAME
        or artifact.get("content_type") != "application/octet-stream"
        or artifact.get("algorithm") != ALGORITHM
        or artifact.get("format_version") != FORMAT_VERSION
        or artifact.get("key_id") != key_id(key)
    ):
        raise AuditArchiveError("archive artifact contract is invalid")
    for field in ("sha256", "plaintext_sha256"):
        if (
            not isinstance(artifact.get(field), str)
            or _SHA256.fullmatch(str(artifact[field])) is None
        ):
            raise AuditArchiveError("archive artifact digest is invalid")
    if (
        not isinstance(artifact.get("size_bytes"), int)
        or isinstance(artifact.get("size_bytes"), bool)
        or int(artifact["size_bytes"]) <= 0
        or not isinstance(artifact.get("row_count"), int)
        or isinstance(artifact.get("row_count"), bool)
        or int(artifact["row_count"]) < 0
    ):
        raise AuditArchiveError("archive artifact counts are invalid")
    first = _validate_boundary(artifact.get("first"))
    last = _validate_boundary(artifact.get("last"))
    if (int(artifact["row_count"]) == 0) != (first is None and last is None):
        raise AuditArchiveError("archive artifact boundaries are invalid")
    if first is not None and last is not None:
        first_key = (_parse_utc_text(first["created_at"]), first["id"])
        last_key = (_parse_utc_text(last["created_at"]), last["id"])
        if first_key > last_key:
            raise AuditArchiveError("archive artifact boundaries are invalid")
    return artifact


class _RecordVerifier:
    def __init__(self, *, tenant_id: str, created_from: datetime, created_to: datetime) -> None:
        self.tenant_id = tenant_id
        self.created_from = created_from
        self.created_to = created_to
        self.buffer = bytearray()
        self.sha256 = hashlib.sha256()
        self.row_count = 0
        self.first: dict[str, str] | None = None
        self.last: dict[str, str] | None = None
        self.empty_sentinel = False

    def write(self, data: bytes) -> int:
        if not isinstance(data, bytes):
            raise AuditArchiveError("archive plaintext is invalid")
        self.sha256.update(data)
        self.buffer.extend(data)
        while True:
            newline = self.buffer.find(b"\n")
            if newline < 0:
                if len(self.buffer) > MAX_RECORD_BYTES:
                    raise AuditArchiveError("archive record is too large")
                break
            line = bytes(self.buffer[:newline])
            del self.buffer[: newline + 1]
            self._line(line)
        return len(data)

    def _line(self, line: bytes) -> None:
        if not line:
            if self.row_count != 0 or self.empty_sentinel:
                raise AuditArchiveError("archive empty sentinel is invalid")
            self.empty_sentinel = True
            return
        if self.empty_sentinel or len(line) > MAX_RECORD_BYTES:
            raise AuditArchiveError("archive record is invalid")
        loaded = _json_loads(line)
        if not isinstance(loaded, dict) or frozenset(loaded) != _RECORD_FIELD_SET:
            raise AuditArchiveError("archive record fields are invalid")
        projected = _project(loaded)
        if projected != loaded:
            raise AuditArchiveError("archive record is not projection-stable")
        if projected.get("tenant_id") != self.tenant_id:
            raise AuditArchiveError("archive record tenant is invalid")
        record_time = _parse_utc_text(projected.get("created_at"))
        if not self.created_from <= record_time < self.created_to:
            raise AuditArchiveError("archive record timestamp is outside the expected range")
        boundary = _boundary(projected)
        if self.last is not None:
            previous_key = (_parse_utc_text(self.last["created_at"]), self.last["id"])
            if not (record_time, boundary["id"]) > previous_key:
                raise AuditArchiveError("archive record ordering is invalid")
        if self.first is None:
            self.first = boundary
        self.last = boundary
        self.row_count += 1

    def finish(self) -> None:
        if self.buffer:
            raise AuditArchiveError("archive JSONL is not newline-terminated")
        if self.row_count == 0 and not self.empty_sentinel:
            raise AuditArchiveError("archive empty payload is invalid")
        if self.row_count > 0 and self.empty_sentinel:
            raise AuditArchiveError("archive empty sentinel is invalid")


def verify_archive(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    expected_tenant_id: str,
    expected_created_from: datetime,
    expected_created_to: datetime,
) -> dict[str, object]:
    """Authenticate and validate an archive without opening a database connection."""

    reviewed_tenant = _validated_tenant(expected_tenant_id)
    reviewed_from, reviewed_to = _validated_window(expected_created_from, expected_created_to)
    directory = Path(input_dir)
    _assert_safe_input_directory(directory)
    try:
        identities = require_exact_regular_files(
            directory,
            frozenset({ARTIFACT_NAME, MANIFEST_NAME}),
        )
    except ValueError as error:
        raise AuditArchiveError("archive directory leaf set is invalid") from error
    manifest_path = directory / MANIFEST_NAME
    manifest = _read_manifest(
        manifest_path,
        expected_identity=identities[MANIFEST_NAME],
    )
    key = load_key_file(key_file)
    actual_hmac = manifest.get(MANIFEST_HMAC_FIELD)
    if (
        not isinstance(actual_hmac, str)
        or _SHA256.fullmatch(actual_hmac) is None
        or not hmac.compare_digest(actual_hmac, _manifest_hmac(manifest, key))
    ):
        raise AuditArchiveError("archive manifest authentication failed")

    artifact = _validate_manifest_structure(
        manifest,
        key=key,
        tenant_id=reviewed_tenant,
        created_from=reviewed_from,
        created_to=reviewed_to,
    )
    artifact_path = directory / ARTIFACT_NAME
    verifier = _RecordVerifier(
        tenant_id=reviewed_tenant,
        created_from=reviewed_from,
        created_to=reviewed_to,
    )
    with _open_regular_file(
        artifact_path,
        expected_identity=identities[ARTIFACT_NAME],
    ) as encrypted:
        encrypted_size = os.fstat(encrypted.fileno()).st_size
        if encrypted_size != artifact["size_bytes"]:
            raise AuditArchiveError("archive artifact digest or size is invalid")
        current_digest = hashlib.sha256()
        while chunk := encrypted.read(1024 * 1024):
            current_digest.update(chunk)
        cipher_sha256 = current_digest.hexdigest()
        if cipher_sha256 != artifact["sha256"]:
            raise AuditArchiveError("archive artifact digest or size is invalid")
        encrypted.seek(0)
        decrypt_stream(
            encrypted,
            None,
            key,
            encrypted_size,
            expected_logical_name=ARCHIVE_LOGICAL_NAME,
            expected_source_database=ARCHIVE_SOURCE_DATABASE,
        )
        encrypted.seek(0)
        decrypt_stream(
            encrypted,
            verifier,
            key,
            encrypted_size,
            expected_logical_name=ARCHIVE_LOGICAL_NAME,
            expected_source_database=ARCHIVE_SOURCE_DATABASE,
        )
    verifier.finish()
    if require_exact_regular_files(
        directory,
        frozenset({ARTIFACT_NAME, MANIFEST_NAME}),
    ) != identities:
        raise AuditArchiveError("archive directory changed during verification")
    if (
        verifier.sha256.hexdigest() != artifact["plaintext_sha256"]
        or verifier.row_count != artifact["row_count"]
        or verifier.first != artifact["first"]
        or verifier.last != artifact["last"]
    ):
        raise AuditArchiveError("archive plaintext evidence is invalid")
    return {
        "schema_version": ARCHIVE_MANIFEST_SCHEMA,
        "production_acceptance": PRODUCTION_ACCEPTANCE,
        "tenant_id": reviewed_tenant,
        "created_from": _utc_text(reviewed_from),
        "created_to": _utc_text(reviewed_to),
        "row_count": verifier.row_count,
        "first": verifier.first,
        "last": verifier.last,
        "sha256": cipher_sha256,
        "plaintext_sha256": verifier.sha256.hexdigest(),
        "tool_source_commit": manifest["tool_source_commit"],
    }


def _read_database_url_file(path_value: Path | str) -> str:
    path = Path(path_value)
    if not path.is_absolute():
        raise AuditArchiveError("database URL file is invalid")
    try:
        data = read_private_secret_bytes(path, max_bytes=MAX_DATABASE_URL_BYTES)
    except PrivateSecretFileError as error:
        raise AuditArchiveError("database URL file is invalid") from error
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditArchiveError("database URL file is invalid") from error
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0].strip() or lines[0] != lines[0].strip():
        raise AuditArchiveError("database URL file is invalid")
    return lines[0]


def _cli_datetime(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuditArchiveError("CLI timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuditArchiveError("CLI timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuditArchiveError("CLI timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m scripts.audit_archive")
    subparsers = parser.add_subparsers(dest="command", required=True)
    archive = subparsers.add_parser("archive")
    archive.add_argument("--output-dir", required=True)
    archive.add_argument("--key-file", required=True, type=Path)
    archive.add_argument("--database-url-file", required=True, type=Path)
    archive.add_argument("--tenant-id", required=True)
    archive.add_argument("--from-created-at", required=True)
    archive.add_argument("--until-created-at", required=True)
    archive.add_argument("--tool-source-commit", required=True)
    archive.add_argument("--page-size", type=int, default=1000)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--input-dir", required=True)
    verify.add_argument("--key-file", required=True, type=Path)
    verify.add_argument("--expected-tenant-id", required=True)
    verify.add_argument("--expected-from-created-at", required=True)
    verify.add_argument("--expected-until-created-at", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "archive":
            reviewed_tenant = _validated_tenant(args.tenant_id)
            reviewed_from, reviewed_to = _validated_window(
                _cli_datetime(args.from_created_at),
                _cli_datetime(args.until_created_at),
            )
            reviewed_page_size = _validated_page_size(args.page_size)
            reviewed_commit = _validated_source_commit(args.tool_source_commit)
            directory_claim = create_write_once_directory(args.output_dir)
            directory = directory_claim.path
            try:
                database_url = _read_database_url_file(args.database_url_file)
                engine = create_engine(database_url)
                try:
                    manifest = _archive_events_in_claimed_directory(
                        directory,
                        engine=engine,
                        key_file=args.key_file,
                        tenant_id=reviewed_tenant,
                        created_from=reviewed_from,
                        created_to=reviewed_to,
                        page_size=reviewed_page_size,
                        tool_source_commit=reviewed_commit,
                    )
                except BaseException:
                    try:
                        engine.dispose()
                    except BaseException:
                        pass
                    raise
                else:
                    engine.dispose()
            except BaseException as error:
                cleanup_created_directory_after_failure(directory_claim, error)
                raise
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "row_count": manifest["artifact"]["row_count"],  # type: ignore[index]
                        "production_acceptance": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        summary = verify_archive(
            args.input_dir,
            key_file=args.key_file,
            expected_tenant_id=args.expected_tenant_id,
            expected_created_from=_cli_datetime(args.expected_from_created_at),
            expected_created_to=_cli_datetime(args.expected_until_created_at),
        )
        print(json.dumps({"status": "ok", **summary}, sort_keys=True))
        return 0
    except Exception as error:
        label = "archive" if args.command == "archive" else "verification"
        suffix = (
            f"; {CLEANUP_UNCONFIRMED_NOTE}" if cleanup_unconfirmed(error) else ""
        )
        print(f"audit-archive-error: {label} failed{suffix}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
