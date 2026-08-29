from types import SimpleNamespace
import unittest
from unittest.mock import patch

from platform.audit import safe_audit_details
from platform.card_events import safe_card_event_state


_MAX_PERSISTED_JSON_BYTES = 64 * 1024


def _exact_size_json(prefix: str, suffix: str, size: int) -> str:
    padding = size - len(prefix.encode("utf-8")) - len(suffix.encode("utf-8"))
    assert padding >= 0
    value = prefix + ("x" * padding) + suffix
    assert len(value.encode("utf-8")) == size
    return value


class PersistedJsonBoundaryTests(unittest.TestCase):
    @staticmethod
    def _audit(value: object) -> dict[str, object]:
        return safe_audit_details(SimpleNamespace(details_json=value))

    def test_exact_limit_remains_compatible(self) -> None:
        audit_json = _exact_size_json('{"safe":"', '"}', _MAX_PERSISTED_JSON_BYTES)
        card_json = _exact_size_json(
            '{"card_status":"available","padding":"',
            '"}',
            _MAX_PERSISTED_JSON_BYTES,
        )

        self.assertEqual(self._audit(audit_json), {"safe": audit_json[9:-2]})
        self.assertEqual(
            safe_card_event_state(card_json),
            {"card_status": "available"},
        )

    def test_oversize_is_rejected_before_json_decode(self) -> None:
        audit_json = _exact_size_json(
            '{"safe":"', '"}', _MAX_PERSISTED_JSON_BYTES + 1
        )
        card_json = _exact_size_json(
            '{"card_status":"available","padding":"',
            '"}',
            _MAX_PERSISTED_JSON_BYTES + 1,
        )

        with patch("json.loads", side_effect=AssertionError("JSON decoder called")):
            with self.subTest(projection="audit"):
                self.assertEqual(self._audit(audit_json), {})
            with self.subTest(projection="card"):
                self.assertEqual(safe_card_event_state(card_json), {})

    def test_limit_counts_utf8_bytes(self) -> None:
        oversized_unicode_json = '{"safe":"' + ("界" * 22_000) + '"}'
        self.assertLess(len(oversized_unicode_json), _MAX_PERSISTED_JSON_BYTES)
        self.assertGreater(
            len(oversized_unicode_json.encode("utf-8")),
            _MAX_PERSISTED_JSON_BYTES,
        )

        self.assertEqual(self._audit(oversized_unicode_json), {})
        self.assertEqual(safe_card_event_state(oversized_unicode_json), {})

    def test_duplicate_keys_at_any_depth_are_rejected(self) -> None:
        cases = (
            (
                "audit-top-level",
                self._audit,
                '{"safe":"kept","safe":"kept"}',
            ),
            (
                "audit-nested",
                self._audit,
                '{"nested":{"safe":"kept","safe":"kept"}}',
            ),
            (
                "card-top-level",
                safe_card_event_state,
                '{"card_status":"available","card_status":"available"}',
            ),
            (
                "card-nested",
                safe_card_event_state,
                '{"card_status":"available","nested":{"v":1,"v":1}}',
            ),
        )

        for name, projection, value in cases:
            with self.subTest(name=name):
                self.assertEqual(projection(value), {})

    def test_deep_history_is_rejected_without_recursion_error(self) -> None:
        value = '{"safe":' + ("[" * 3_000) + "0" + ("]" * 3_000) + "}"

        self.assertLess(len(value.encode("utf-8")), _MAX_PERSISTED_JSON_BYTES)
        self.assertEqual(self._audit(value), {})
        self.assertEqual(safe_card_event_state(value), {})


if __name__ == "__main__":
    unittest.main()
