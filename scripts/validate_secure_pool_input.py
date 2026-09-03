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


_FORMAT_DESCRIPTIONS: dict[PoolType, str] = {
    "card": "\n".join((
        "card input: JSON array with 1 to 100 records",
        "required fields: provider_ref (string), brand (string), pan (12 to 19 digits, Luhn-valid)",
        "optional fields: pool_key (string), region (string), expiry_month (integer), expiry_year (integer)",
        "expiry_month and expiry_year must be provided together",
        "provider_ref values must be unique after trimming",
        "forbidden fields: cvv, cvc, cid, security_code, card_verification_value",
    )),
    "mailbox": "\n".join((
        "mailbox input: JSON array with 1 to 100 records",
        "required fields: email_masked (string), connector_type (string), secret (non-empty object)",
        "optional fields: task_type (string; defaults to mail_code)",
        "email_masked must use one visible lowercase character followed by three asterisks and a DNS domain",
        "secret object fields are defined by the approved mailbox adapter contract",
    )),
}


def describe_format(pool_type: PoolType) -> str:
    return _FORMAT_DESCRIPTIONS[pool_type]


def validate_records(pool_type: PoolType, value: object) -> int:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise ImportFailure("Input must contain 1 to 100 records")
    parser = _card_record if pool_type == "card" else _mailbox_record
    manifest: list[dict[str, object]] = []
    for index, item in enumerate(value, start=1):
        try:
            manifest.append(parser(item)[0])
        except ImportFailure as error:
            raise ImportFailure(f"record_index={index}: {error}") from None
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
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--input-file")
    action.add_argument("--describe-format", action="store_true")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.describe_format:
        print(describe_format(arguments.pool_type))
        return 0
    try:
        assert arguments.input_file is not None
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
