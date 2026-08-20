import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from session_store import (
    MemorySessionStore,
    SessionStoreError,
    WindowsDpapiSessionStore,
    _session_entropy,
)


class SessionStoreTests(unittest.TestCase):
    def test_memory_store_is_injectable_and_non_persistent(self):
        first = MemorySessionStore()
        first.save("refresh-secret")
        self.assertEqual(first.load(), "refresh-secret")
        self.assertIsNone(MemorySessionStore().load())
        first.clear()
        self.assertIsNone(first.load())

    def test_rejects_invalid_refresh_tokens(self):
        store = MemorySessionStore()
        for token in ("", "  ", "one\ntwo", "one\rtwo"):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    store.save(token)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
    def test_dpapi_store_never_writes_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.bin"
            store = WindowsDpapiSessionStore(path)
            store.save("refresh-secret")
            self.assertNotEqual(path.read_bytes(), b"refresh-secret")
            self.assertNotIn(b"refresh-secret", path.read_bytes())
            self.assertEqual(store.load(), "refresh-secret")
            store.clear()
            self.assertFalse(path.exists())

    def test_dpapi_store_has_no_non_windows_plaintext_fallback(self):
        with mock.patch("session_store.os.name", "posix"):
            with self.assertRaises(SessionStoreError):
                WindowsDpapiSessionStore(Path("session.bin"))

    def test_dpapi_entropy_is_device_bound_and_versioned(self):
        first = _session_entropy("device-a")
        same = _session_entropy("device-a")
        other = _session_entropy("device-b")
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)
        self.assertEqual(len(first), 32)

    def test_dpapi_store_uses_optional_entropy(self):
        source = Path("session_store.py").read_text(encoding="utf-8")
        self.assertIn("optional_entropy", source)
        self.assertIn("_session_entropy", source)
        self.assertIn("MachineGuid", source)


if __name__ == "__main__":
    unittest.main()
