import json
import tempfile
import unittest
from pathlib import Path

from scripts.phase6_rehearsal import (
    RehearsalError,
    SCHEMA_VERSION,
    _assert_no_secret,
    main,
    run_rehearsal,
    verify_evidence,
    write_evidence,
)


class Phase6RehearsalTests(unittest.TestCase):
    def test_secret_scan_catches_encoded_and_card_field_variants(self) -> None:
        cases = (
            ("Bearer TOKEN_VALUE_0123456789abcdef", "TOKEN_VALUE_0123456789abcdef"),
            ("MAIL_PASSWORD_SENTINEL_abc%2Fdef", "MAIL_PASSWORD_SENTINEL_abc/def"),
            ('{"cvv":"731"}', "731"),
            ("4242-4242-4242-4242", "4242424242424242"),
        )
        for surface, sentinel in cases:
            with self.subTest(surface=surface), self.assertRaises(RehearsalError):
                _assert_no_secret([surface], [sentinel])

    def test_full_flow_is_deterministic_redacted_ci_evidence(self) -> None:
        commit = "a" * 40
        first = run_rehearsal(commit)
        second = run_rehearsal(commit)
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], SCHEMA_VERSION)
        self.assertEqual(first["status"], "passed")
        self.assertFalse(first["production_acceptance"])
        self.assertTrue(all(first["checks"].values()))
        serialized = json.dumps(first)
        for forbidden in (
            "SENTINEL",
            "73918426",
            "4242424242424242",
            "phase6-upstream-7c0bd3@example.invalid",
        ):
            self.assertNotIn(forbidden, serialized)

        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            write_evidence(evidence_path, first)
            self.assertEqual(verify_evidence(evidence_path), first)
            self.assertEqual(list(evidence_path.parent.glob("*.tmp")), [])

    def test_verifier_rejects_tampering_and_unknown_fields(self) -> None:
        evidence = run_rehearsal("b" * 40)
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            write_evidence(evidence_path, evidence)
            tampered = json.loads(evidence_path.read_text(encoding="utf-8"))
            tampered["status"] = "failed"
            evidence_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(RehearsalError):
                verify_evidence(evidence_path)

            tampered = dict(evidence)
            tampered["unexpected"] = "value"
            evidence_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(RehearsalError):
                verify_evidence(evidence_path)

            write_evidence(evidence_path, evidence)
            with self.assertRaises(RehearsalError):
                write_evidence(evidence_path, tampered)
            self.assertFalse(evidence_path.exists())

    def test_failed_run_invalidates_stale_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "phase6-evidence.json"
            evidence_path.write_text("stale", encoding="utf-8")
            result = main(
                [
                    "run",
                    "--output",
                    str(evidence_path),
                    "--commit",
                    "not-a-commit",
                ]
            )
            self.assertEqual(result, 1)
            self.assertFalse(evidence_path.exists())


if __name__ == "__main__":
    unittest.main()
