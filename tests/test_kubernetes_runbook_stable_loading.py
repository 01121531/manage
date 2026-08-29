from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_kubernetes_portability


FIXED_RUNBOOK_ERROR = "Kubernetes portability runbook is unavailable"
MAX_RUNBOOK_BYTES = 64 * 1024


class KubernetesRunbookStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = verify_kubernetes_portability.load_documents()
        self.readme_text = external_text.load_stable_text(
            verify_kubernetes_portability.README,
            max_bytes=MAX_RUNBOOK_BYTES,
        )

    def verify(self) -> list[str]:
        with mock.patch.object(
            verify_kubernetes_portability,
            "deployment_alignment_errors",
            return_value=[],
        ), mock.patch.object(
            verify_kubernetes_portability,
            "_contract_errors",
            return_value=[],
        ):
            return verify_kubernetes_portability.verification_errors(
                self.documents
            )

    def test_runbook_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_kubernetes_portability.README:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_kubernetes_portability,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            self.assertEqual(self.verify(), [])

        stable_read.assert_called_once_with(
            verify_kubernetes_portability.README,
            max_bytes=MAX_RUNBOOK_BYTES,
        )

    def test_runbook_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        raw = self.readme_text.encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
        prefix = raw + b"<!--"
        padding = MAX_RUNBOOK_BYTES - len(prefix)
        self.assertGreaterEqual(padding, 0)
        exact = prefix + b"x" * padding

        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "README.md"
            replacement.write_bytes(exact)
            with mock.patch.object(
                verify_kubernetes_portability,
                "README",
                replacement,
            ):
                self.assertEqual(self.verify(), [])
                replacement.write_bytes(exact + b"x")
                self.assertEqual(self.verify(), [FIXED_RUNBOOK_ERROR])

    def test_invalid_utf8_uses_fixed_runbook_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "README.md"
            replacement.write_bytes(b"\xff")
            with mock.patch.object(
                verify_kubernetes_portability,
                "README",
                replacement,
            ):
                self.assertEqual(self.verify(), [FIXED_RUNBOOK_ERROR])

    def test_link_or_reparse_runbook_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            self.assertEqual(self.verify(), [FIXED_RUNBOOK_ERROR])

        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_kubernetes_portability,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                errors = self.verify()

            self.assertEqual(errors, [FIXED_RUNBOOK_ERROR])
            self.assertNotIn(reason, ";".join(errors))
            stable_read.assert_called_once_with(
                verify_kubernetes_portability.README,
                max_bytes=MAX_RUNBOOK_BYTES,
            )

    def test_missing_runbook_marker_keeps_existing_policy_error(self) -> None:
        marker = "server-side dry-run"
        changed = self.readme_text.replace(marker, "client-side validation", 1)
        self.assertNotEqual(changed, self.readme_text)
        with mock.patch.object(
            verify_kubernetes_portability,
            "load_stable_text",
            return_value=changed,
            create=True,
        ):
            self.assertEqual(
                self.verify(),
                [f"Kubernetes portability runbook is missing: {marker}"],
            )

    def test_source_uses_bounded_stable_runbook_snapshot(self) -> None:
        source = Path(verify_kubernetes_portability.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("README.read_text(", source)
        self.assertIn("MAX_RUNBOOK_BYTES = 64 * 1024", source)
        self.assertIn(
            "load_stable_text(\n            README,\n"
            "            max_bytes=MAX_RUNBOOK_BYTES,\n        )",
            source,
        )


if __name__ == "__main__":
    unittest.main()
