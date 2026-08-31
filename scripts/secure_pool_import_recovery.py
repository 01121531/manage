"""Read-only assessment for a secure pool-import execution record."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.file_boundary import read_stable_runtime_bytes_with_metadata
from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from platform.pool_import_execution import (
    classify_execution,
    execution_event_errors,
    execution_plan_errors,
)
from platform.pool_imports import pool_import_digest
from scripts.external_json import has_link_or_reparse_ancestor


ROOT = REPOSITORY_ROOT
MAX_RECORD_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
_EVENT_NAME = re.compile(
    r"^(?:write-[0-9]{3}\.(?:intent|confirmed)|bundle\.intent|complete)\.json$"
)


class RecoveryFailure(RuntimeError):
    pass


def _external_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise RecoveryFailure("execution_record_invalid")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except FileNotFoundError:
        raise RecoveryFailure("execution_record_invalid") from None
    except ValueError:
        pass
    else:
        raise RecoveryFailure("execution_record_invalid")
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & 0x400
        or has_link_or_reparse_ancestor(path)
    ):
        raise RecoveryFailure("execution_record_invalid")
    return path


def _read_json(path: Path, *, max_bytes: int) -> tuple[object, bytes]:
    try:
        raw, metadata = read_stable_runtime_bytes_with_metadata(path, max_bytes=max_bytes)
        if metadata.st_nlink != 1:
            raise OSError
        return parse_unique_json_bytes(raw), raw
    except (OSError, JsonBoundaryError):
        raise RecoveryFailure("execution_record_invalid") from None


def _unknown(phase: str) -> dict[str, object]:
    return {
        "status": "commit_unknown",
        "phase": phase,
        "confirmed_count": 0,
        "unknown_index": None,
        "production_acceptance": False,
        "automatic_resume_allowed": False,
    }


def assess_execution_directory(
    execution_directory: Path | str,
    receipt_output: Path | str,
) -> dict[str, object]:
    directory = _external_directory(Path(execution_directory))
    try:
        entries = tuple(directory.iterdir())
    except OSError:
        raise RecoveryFailure("execution_record_invalid") from None
    names = {entry.name for entry in entries}
    if "plan.json" not in names:
        return _unknown("no_authoritative_plan")
    try:
        plan_value, _ = _read_json(directory / "plan.json", max_bytes=MAX_RECORD_BYTES)
    except RecoveryFailure:
        return _unknown("plan_invalid")
    if execution_plan_errors(plan_value) or not isinstance(plan_value, dict):
        return _unknown("plan_invalid")
    plan = dict(plan_value)
    item_count = int(plan["item_count"])
    allowed = {"plan.json", "bundle.intent.json", "complete.json"} | {
        name
        for index in range(item_count)
        for name in (
            f"write-{index:03d}.intent.json",
            f"write-{index:03d}.confirmed.json",
        )
    }
    if names - allowed or any(
        name != "plan.json" and _EVENT_NAME.fullmatch(name) is None for name in names
    ):
        return _unknown("record_inventory_invalid")
    events: dict[str, dict[str, object]] = {}
    for name in sorted(names - {"plan.json"}):
        try:
            value, _ = _read_json(directory / name, max_bytes=MAX_RECORD_BYTES)
        except RecoveryFailure:
            return _unknown("event_invalid")
        if (
            execution_event_errors(value, plan)
            or not isinstance(value, dict)
        ):
            return _unknown("event_invalid")
        events[name] = dict(value)

    bundle_path = Path(receipt_output)
    bundle_state = "absent"
    bundle_sha256: str | None = None
    if os.path.lexists(bundle_path):
        try:
            bundle_value, raw = _read_json(bundle_path, max_bytes=MAX_BUNDLE_BYTES)
            if not isinstance(bundle_value, dict) or set(bundle_value) != {
                "schema_version",
                "pool_type",
                "submission_key",
                "receipt_token",
                "items",
            }:
                raise RecoveryFailure("bundle_invalid")
            items = bundle_value.get("items")
            if (
                bundle_value.get("schema_version") != 2
                or bundle_value.get("pool_type") != plan["pool_type"]
                or bundle_value.get("submission_key") != f"spi:{plan['execution_id']}"
                or not isinstance(bundle_value.get("receipt_token"), str)
                or not isinstance(items, list)
                or len(items) != item_count
                or pool_import_digest(plan["pool_type"], items)
                != plan["ordered_manifest_digest"]
            ):
                raise RecoveryFailure("bundle_invalid")
            bundle_sha256 = hashlib.sha256(raw).hexdigest()
            bundle_state = "valid"
        except (RecoveryFailure, TypeError, ValueError):
            bundle_state = "invalid"
    return classify_execution(
        plan,
        events,
        bundle_state=bundle_state,
        bundle_sha256=bundle_sha256,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-directory", required=True)
    parser.add_argument("--receipt-output", required=True)
    return parser


def main() -> int:
    try:
        arguments = build_parser().parse_args()
        assessment = assess_execution_directory(
            arguments.execution_directory,
            arguments.receipt_output,
        )
    except (OSError, ValueError, RecoveryFailure):
        print("secure-pool-import-recovery-failed: execution_record_invalid", file=sys.stderr)
        return 1
    print(
        "secure-pool-import-recovery-ok "
        f"status={assessment['status']} phase={assessment['phase']} "
        f"confirmed_count={assessment['confirmed_count']} "
        "production_acceptance=false automatic_resume_allowed=false"
    )
    return 0 if assessment["status"] in {"unwritten", "completed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
