from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import validate_secure_pool_input
from scripts.secure_pool_import import ImportFailure


class ValidateSecurePoolInputTests(unittest.TestCase):
    def test_card_format_description_contains_constraints_without_values(self) -> None:
        description = validate_secure_pool_input.describe_format("card")

        self.assertIn("required fields: provider_ref", description)
        self.assertIn("forbidden fields: cvv", description)
        self.assertNotIn("4111111111111111", description)

    def test_mailbox_format_description_defers_secret_shape_to_adapter(self) -> None:
        description = validate_secure_pool_input.describe_format("mailbox")

        self.assertIn("required fields: email_masked", description)
        self.assertIn("approved mailbox adapter contract", description)
        self.assertNotIn("private-password", description)

    def test_accepts_card_records_without_exposing_secrets(self) -> None:
        count = validate_secure_pool_input.validate_records("card", [{
            "provider_ref": "provider-card-1",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "pan": "4111 1111 1111 1111",
            "expiry_month": 12,
            "expiry_year": 2030,
        }])

        self.assertEqual(count, 1)

    def test_accepts_mailbox_records(self) -> None:
        count = validate_secure_pool_input.validate_records("mailbox", [{
            "email_masked": "m***@example.invalid",
            "connector_type": "http",
            "task_type": "mail_code",
            "secret": {"username": "private", "password": "private-password"},
        }])

        self.assertEqual(count, 1)

    def test_rejects_duplicate_card_provider_references(self) -> None:
        records = [
            {"provider_ref": "duplicate", "brand": "Visa", "pan": "4111111111111111"},
            {"provider_ref": "duplicate", "brand": "Visa", "pan": "4012888888881881"},
        ]

        with self.assertRaisesRegex(ImportFailure, "duplicate provider references"):
            validate_secure_pool_input.validate_records("card", records)

    def test_rejects_card_security_code_without_echoing_value(self) -> None:
        with self.assertRaises(ImportFailure) as raised:
            validate_secure_pool_input.validate_records("card", [{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
                "cvv": "987",
            }])

        self.assertNotIn("987", str(raised.exception))

    def test_bad_second_record_reports_index_without_echoing_source(self) -> None:
        records = [
            {
                "email_masked": "m***@example.invalid",
                "connector_type": "http",
                "secret": {"credential": "first-private-value"},
            },
            {
                "email_masked": "private-address@example.invalid",
                "connector_type": "http",
                "secret": {"credential": "second-private-value"},
            },
        ]

        with self.assertRaisesRegex(ImportFailure, "record_index=2") as raised:
            validate_secure_pool_input.validate_records("mailbox", records)

        message = str(raised.exception)
        self.assertNotIn("private-address", message)
        self.assertNotIn("second-private-value", message)

    def test_describe_format_does_not_require_input_file(self) -> None:
        arguments = validate_secure_pool_input.build_parser().parse_args([
            "mailbox", "--describe-format",
        ])

        self.assertTrue(arguments.describe_format)
        self.assertIsNone(arguments.input_file)


if __name__ == "__main__":
    unittest.main()
