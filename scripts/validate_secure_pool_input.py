#!/usr/bin/env python3
"""Validate a raw secure-pool import file without contacting Platform or Vault."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Literal


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.secure_pool_import import (  # noqa: E402
    ImportFailure,
    _absolute_file,
    _card_record,
    _mailbox_record,
    _read_json,
    card_provider_refs_are_unique,
)


PoolType = Literal["card", "mailbox"]


def validate_records(pool_type: PoolType, value: object) -> int:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise ImportFailure("Input must contain 1 to 100 records")
    parser = _card_record if pool_type == "card" else _mailbox_record
    manifest = [parser(item)[0] for item in value]
    if pool_type == "card" and not card_provider_refs_are_unique(manifest):
        raise ImportFailure("Card input contains duplicate provider references")
    return len(manifest)


def validate_file(pool_type: PoolType, input_file: str) -> int:
    input_path = _absolute_file(input_file, label="Input file")
    value = _read_json(
        input_path,
        require_single_link=True,
        require_private_permissions=True,
    )
    return validate_records(pool_type, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a raw card or mailbox pool file without network access"
    )
    parser.add_argument("pool_type", choices=("card", "mailbox"))
    parser.add_argument("--input-file", required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        count = validate_file(arguments.pool_type, arguments.input_file)
    except ImportFailure as error:
        print(f"secure-pool-input-invalid: {error}", file=sys.stderr)
        return 1
    print(
        f"secure-pool-input-ok pool_type={arguments.pool_type} count={count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
