import inspect
import unittest
from unittest import mock

import platform_clipboard
from platform_clipboard import (
    PasteShortcutDetector,
    PasteStage,
    SecurePasteSequence,
    WindowsPasteObserver,
    get_clipboard_sequence_number,
)


class SecurePasteSequenceTests(unittest.TestCase):
    def test_exact_pastes_advance_code_to_authorized_card_and_complete(self) -> None:
        sequence = SecurePasteSequence()
        code = "246810"
        card = "4111111111111111\t12/30"

        start = sequence.start(code, card)
        self.assertEqual(start.value, code)
        self.assertEqual(sequence.stage, PasteStage.CODE_READY)
        self.assertIsNone(sequence.on_paste("unrelated clipboard value"))

        card_action = sequence.on_paste(code)
        self.assertIsNotNone(card_action)
        self.assertEqual(card_action.value, card)
        self.assertEqual(card_action.consumed, "code")
        self.assertEqual(sequence.stage, PasteStage.CARD_READY)

        complete = sequence.on_paste(card)
        self.assertIsNotNone(complete)
        self.assertTrue(complete.completed)
        self.assertEqual(complete.consumed, "card")
        self.assertEqual(sequence.stage, PasteStage.COMPLETE)
        self.assertFalse(sequence.active)

        representation = repr(sequence) + repr(start) + repr(card_action)
        self.assertNotIn(code, representation)
        self.assertNotIn("4111111111111111", representation)

    def test_late_card_waits_without_recopying_code(self) -> None:
        sequence = SecurePasteSequence()
        sequence.start("135790")

        waiting = sequence.on_paste("135790")
        self.assertIsNotNone(waiting)
        self.assertIsNone(waiting.value)
        self.assertEqual(sequence.stage, PasteStage.WAITING_CARD)

        card_action = sequence.offer_card("5555555555554444\t01/31")
        self.assertIsNotNone(card_action)
        self.assertEqual(card_action.value, "5555555555554444\t01/31")
        self.assertEqual(sequence.stage, PasteStage.CARD_READY)

    def test_stop_and_sensitive_expiry_invalidate_pending_generation(self) -> None:
        sequence = SecurePasteSequence()
        sequence.start("112233", "4111111111111111\t12/30")
        generation = sequence.generation

        self.assertTrue(sequence.stop_if_pending("112233"))
        self.assertGreater(sequence.generation, generation)
        self.assertEqual(sequence.stage, PasteStage.STOPPED)
        self.assertIsNone(sequence.on_paste("112233"))

    def test_module_is_platform_only_and_has_no_legacy_import(self) -> None:
        source = inspect.getsource(platform_clipboard)
        self.assertNotIn("from legacy_app", source)
        self.assertNotIn("import legacy_app", source)
        self.assertNotIn("parse_clipboard_record", source)
        self.assertNotIn("cvv", source.lower())


class PasteObserverTests(unittest.TestCase):
    def test_clipboard_sequence_number_is_read_without_opening_clipboard(self) -> None:
        user32 = mock.Mock()
        user32.GetClipboardSequenceNumber.return_value = 42
        with mock.patch.object(platform_clipboard.ctypes, "windll", create=True) as windll:
            windll.user32 = user32
            self.assertEqual(get_clipboard_sequence_number(), 42)
        user32.GetClipboardSequenceNumber.assert_called_once_with()

    def test_clipboard_sequence_number_fails_closed_when_unavailable(self) -> None:
        with mock.patch.object(
            platform_clipboard.ctypes, "windll", create=True
        ) as windll:
            windll.user32.GetClipboardSequenceNumber.side_effect = OSError
            self.assertIsNone(get_clipboard_sequence_number())

    def test_shortcut_detector_debounces_both_supported_shortcuts(self) -> None:
        detector = PasteShortcutDetector()
        self.assertTrue(
            detector.update(control=True, v_key=True, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=True, v_key=True, shift=False, insert=False)
        )
        self.assertFalse(
            detector.update(control=False, v_key=False, shift=False, insert=False)
        )
        self.assertTrue(
            detector.update(control=False, v_key=False, shift=True, insert=True)
        )

    def test_observer_uses_narrow_fallback_and_closes_hook(self) -> None:
        class FakeHook:
            installed = False

            def __init__(self) -> None:
                self.closed = False

            @staticmethod
            def consume() -> bool:
                raise AssertionError("uninstalled hook must not be consumed")

            def close(self) -> None:
                self.closed = True

        pressed = {0x11, 0x56}
        hook = FakeHook()
        observer = WindowsPasteObserver(
            hook=hook, key_reader=lambda key: key in pressed
        )

        self.assertTrue(observer.consume())
        self.assertFalse(observer.consume())
        pressed.clear()
        self.assertFalse(observer.consume())
        pressed.update({0x10, 0x2D})
        self.assertTrue(observer.consume())
        observer.close()
        self.assertTrue(hook.closed)


if __name__ == "__main__":
    unittest.main()
