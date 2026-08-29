from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

from scripts.tls_rotation_publisher_policy import (
    TlsRotationPublisherPolicyError,
    parse_publisher_policy,
    validate_publisher_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "tls-rotation-attempt-publisher-policy.json"
SOURCE = ROOT / "scripts" / "tls_rotation_publisher_policy.py"


class TlsRotationPublisherPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = POLICY.read_bytes()
        self.policy = json.loads(self.raw)

    def assert_invalid(self, value: object) -> None:
        with self.assertRaises(TlsRotationPublisherPolicyError) as raised:
            validate_publisher_policy(value)
        self.assertEqual(str(raised.exception), "TLS rotation publisher policy is invalid")

    def test_repository_policy_is_a_disabled_declaration(self) -> None:
        validated = parse_publisher_policy(self.raw)
        self.assertEqual(validated, self.policy)
        self.assertEqual(validated["policy_effect"], "declaration_only")
        self.assertFalse(validated["production_acceptance"])
        self.assertFalse(validated["publisher_integration_enabled"])
        self.assertFalse(validated["not_committed_eligible"])
        self.assertEqual(validated["trust_anchor"]["state"], "unconfigured")
        self.assertIsNone(validated["trust_anchor"]["key_id"])
        self.assertIsNone(validated["trust_anchor"]["public_key_b64url"])
        self.assertEqual(validated["publisher_ordering"]["state"], "not_implemented")
        self.assertEqual(validated["durability_prerequisites"]["state"], "unverified")

    def test_top_level_and_nested_schema_are_closed_and_fail_disabled(self) -> None:
        mutations: list[dict[str, object]] = []
        for field, value in (
            ("schema_version", True),
            ("policy_effect", "evidence"),
            ("production_acceptance", True),
            ("publisher_integration_enabled", True),
            ("not_committed_eligible", True),
            ("receipt_schema_version", True),
        ):
            changed = copy.deepcopy(self.policy)
            changed[field] = value
            mutations.append(changed)
        extra = copy.deepcopy(self.policy)
        extra["ready"] = True
        mutations.append(extra)
        missing = copy.deepcopy(self.policy)
        del missing["policy_effect"]
        mutations.append(missing)
        nested = copy.deepcopy(self.policy)
        nested["trust_anchor"]["receipt_public_key"] = "self-declared"
        mutations.append(nested)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_invalid(mutation)

    def test_future_pinned_public_key_branch_is_canonical_and_still_disabled(self) -> None:
        public_key = bytes(range(32))
        encoded = base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii")
        pinned = copy.deepcopy(self.policy)
        pinned["trust_anchor"].update({
            "state": "pinned",
            "key_id": "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest(),
            "public_key_b64url": encoded,
        })
        validated = validate_publisher_policy(pinned)
        self.assertEqual(validated["trust_anchor"]["public_key_b64url"], encoded)
        self.assertFalse(validated["publisher_integration_enabled"])
        self.assertFalse(validated["not_committed_eligible"])

        mutations = []
        short_key = base64.urlsafe_b64encode(b"x" * 31).rstrip(b"=").decode()
        for key_id, public_value in (
            ("ed25519-sha256:" + "0" * 64, encoded),
            (pinned["trust_anchor"]["key_id"], encoded + "="),
            (pinned["trust_anchor"]["key_id"], short_key),
        ):
            changed = copy.deepcopy(pinned)
            changed["trust_anchor"]["key_id"] = key_id
            changed["trust_anchor"]["public_key_b64url"] = public_value
            mutations.append(changed)
        source = copy.deepcopy(pinned)
        source["trust_anchor"]["source"] = "receipt_selected"
        mutations.append(source)
        mixed = copy.deepcopy(self.policy)
        mixed["trust_anchor"]["key_id"] = pinned["trust_anchor"]["key_id"]
        mutations.append(mixed)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_invalid(mutation)

    def test_custody_ordering_and_durability_remain_prerequisites(self) -> None:
        mutations = []
        custody = copy.deepcopy(self.policy)
        custody["signer_custody_requirements"]["private_key_in_repository"] = "allowed"
        mutations.append(custody)
        custody_flag = copy.deepcopy(self.policy)
        custody_flag["signer_custody_requirements"]["independent_reviewer_required"] = 1
        mutations.append(custody_flag)
        ordering = copy.deepcopy(self.policy)
        ordering["publisher_ordering"]["state"] = "implemented"
        mutations.append(ordering)
        reordered = copy.deepcopy(self.policy)
        reordered["publisher_ordering"]["required_steps"].reverse()
        mutations.append(reordered)
        retries = copy.deepcopy(self.policy)
        retries["publisher_ordering"]["evidence_link_attempt_limit"] = 2
        mutations.append(retries)
        durability = copy.deepcopy(self.policy)
        durability["durability_prerequisites"]["state"] = "verified"
        mutations.append(durability)
        missing_control = copy.deepcopy(self.policy)
        missing_control["durability_prerequisites"]["deny_delete_required"] = False
        mutations.append(missing_control)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_invalid(mutation)

    def test_parser_is_bounded_unique_keyed_and_errors_are_redacted(self) -> None:
        canary = "https://secret.invalid/token-value"
        cases = (
            b"",
            b"\xff",
            b"x" * (16 * 1024 + 1),
            self.raw.replace(
                b'"schema_version": 1,',
                b'"schema_version": 1, "schema_version": 1,',
                1,
            ),
            json.dumps({"canary": canary}).encode("utf-8"),
        )
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(
                TlsRotationPublisherPolicyError
            ) as raised:
                parse_publisher_policy(raw)
            self.assertEqual(str(raised.exception), "TLS rotation publisher policy is invalid")
            self.assertNotIn(canary, str(raised.exception))

    def test_policy_contains_no_runtime_location_or_secret_value(self) -> None:
        serialized = json.dumps(self.policy, sort_keys=True)
        self.assertNotIn("://", serialized)
        self.assertIsNone(re.search(r"[A-Za-z]:\\\\", serialized))
        self.assertIsNone(self.policy["trust_anchor"]["public_key_b64url"])
        self.assertNotIn("readiness_state", self.policy)

    def test_validator_has_no_signing_publication_cli_or_runtime_authority(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_modules = {
            "argparse",
            "os",
            "subprocess",
            "scripts.backup_output_policy",
            "scripts.private_secret_file",
            "scripts.release_control_lock",
            "scripts.tls_rotation_executor",
            "scripts.tls_rotation_handoff",
        }
        forbidden_calls = {
            "open",
            "sign",
            "write_bytes",
            "write_text",
            "link",
            "unlink",
            "replace",
            "rename",
            "prepare_write_once_file",
            "publish_write_once_file",
            "read_private_secret_bytes",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name not in forbidden_modules for alias in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, forbidden_modules)
            if isinstance(node, ast.Call):
                called = (
                    node.func.id if isinstance(node.func, ast.Name)
                    else node.func.attr if isinstance(node.func, ast.Attribute)
                    else None
                )
                self.assertNotIn(called, forbidden_calls)
        for forbidden in ("Ed25519PrivateKey", "sys.argv", "os.environ", "not_committed\""):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
