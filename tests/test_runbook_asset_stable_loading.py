from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_runbooks


EXPECTED_RUNBOOKS = (
    "secure-pool-import.md",
    "admin-plane-separation.md",
    "nonproduction-data-boundary.md",
    "rolling-release.md",
    "audit-archive.md",
    "restore.md",
    "vault-restore.md",
    "vault-audit.md",
    "phase6-rehearsal.md",
    "keycloak-audit.md",
    "keycloak-mfa.md",
    "internal-tls.md",
    "runtime-secrets.md",
    "private-secret-provenance.md",
    "migration-rollout.md",
    "container-release.md",
    "container-logs.md",
    "deploy.md",
    "dependency-audit.md",
    "ci-token-hygiene.md",
    "alert-delivery.md",
    "rollback.md",
    "role-training.md",
    "device-revocation.md",
    "key-rotation.md",
    "incident-response.md",
)
FIXED_FAILURE = (1, "", "Unable to load operational runbooks\n")


class RunbookAssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = verify_runbooks.ROOT / "deploy" / "runbooks"
        self.documents = {
            name: external_text.load_stable_text(self.base / name)
            for name in EXPECTED_RUNBOOKS
        }

    @staticmethod
    def _run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_runbooks.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def _selective_loader(self, target: Path, replacement: Path | None = None):
        def load(path: Path, *, max_bytes: int) -> str:
            if path == target:
                return external_text.load_stable_text(
                    replacement or path,
                    max_bytes=max_bytes,
                )
            return self.documents[path.name]

        return load

    @staticmethod
    def _exact_limit(source: str) -> bytes:
        raw = source.encode("utf-8")
        prefix = b"\n<!--"
        suffix = b"-->\n"
        padding = 64 * 1024 - len(raw) - len(prefix) - len(suffix)
        if padding < 0:
            raise AssertionError("repository runbook already exceeds the boundary")
        exact = raw + prefix + (b"x" * padding) + suffix
        if len(exact) != 64 * 1024:
            raise AssertionError("invalid exact-limit fixture")
        return exact

    def test_fixed_inventory_is_loaded_once_without_path_read_text(self) -> None:
        self.assertEqual(tuple(verify_runbooks.RUNBOOKS), EXPECTED_RUNBOOKS)
        protected = {self.base / name for name in EXPECTED_RUNBOOKS}
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in protected:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_runbooks,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self._run_main()

        self.assertEqual(result, (0, "runbooks-ok operational-guides-present\n", ""))
        self.assertEqual(
            stable_read.call_args_list,
            [
                mock.call(
                    self.base / name,
                    max_bytes=verify_runbooks.MAX_RUNBOOK_BYTES,
                )
                for name in EXPECTED_RUNBOOKS
            ],
        )

    def test_each_runbook_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        for name in EXPECTED_RUNBOOKS:
            target = self.base / name
            exact = self._exact_limit(self.documents[name])
            with self.subTest(runbook=name), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / name
                replacement.write_bytes(exact)
                with mock.patch.object(
                    verify_runbooks,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(self._run_main()[0], 0)
                    replacement.write_bytes(exact + b"x")
                    self.assertEqual(self._run_main(), FIXED_FAILURE)

    def test_invalid_utf8_for_each_runbook_uses_fixed_error(self) -> None:
        for name in EXPECTED_RUNBOOKS:
            target = self.base / name
            with self.subTest(runbook=name), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / name
                replacement.write_bytes(b"\xff")
                with mock.patch.object(
                    verify_runbooks,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(self._run_main(), FIXED_FAILURE)

    def test_link_or_reparse_runbooks_are_rejected_before_open(self) -> None:
        for name in EXPECTED_RUNBOOKS:
            target = self.base / name
            with self.subTest(runbook=name), mock.patch.object(
                verify_runbooks,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file:
                self.assertEqual(self._run_main(), FIXED_FAILURE)
            open_file.assert_not_called()

    def test_non_regular_open_runbooks_are_rejected(self) -> None:
        real_fstat = os.fstat

        def non_regular_fstat(descriptor: int):
            metadata = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFIFO | 0o600,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        for name in EXPECTED_RUNBOOKS:
            target = self.base / name
            with self.subTest(runbook=name), mock.patch.object(
                verify_runbooks,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=non_regular_fstat,
            ):
                self.assertEqual(self._run_main(), FIXED_FAILURE)

    def test_read_shape_drift_is_rejected_for_each_runbook(self) -> None:
        real_fstat = os.fstat
        for name in EXPECTED_RUNBOOKS:
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata,
                            "st_file_attributes",
                            0,
                        ),
                    )
                return metadata

            target = self.base / name
            with self.subTest(runbook=name), mock.patch.object(
                verify_runbooks,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                self.assertEqual(self._run_main(), FIXED_FAILURE)
            self.assertEqual(calls, 2)

    def test_loader_failures_are_fixed_and_do_not_disclose_reasons(self) -> None:
        for name in EXPECTED_RUNBOOKS:
            target = self.base / name

            def failed_loader(path: Path, *, max_bytes: int) -> str:
                if path == target:
                    raise external_json.StableFileError("private-runbook-path")
                return self.documents[path.name]

            with self.subTest(runbook=name), mock.patch.object(
                verify_runbooks,
                "load_stable_text",
                side_effect=failed_loader,
                create=True,
            ):
                result = self._run_main()
            self.assertEqual(result, FIXED_FAILURE)
            self.assertNotIn("private-runbook-path", result[2])
            self.assertNotIn(str(target), result[2])

    def test_existing_missing_and_policy_diagnostics_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "deploy" / "runbooks").mkdir(parents=True)
            with mock.patch.object(verify_runbooks, "ROOT", root):
                self.assertEqual(
                    self._run_main(),
                    (1, "", f"Missing runbook: {EXPECTED_RUNBOOKS[0]}\n"),
                )

        first = EXPECTED_RUNBOOKS[0]
        required = verify_runbooks.RUNBOOKS[first][0]

        def drifted_loader(path: Path, *, max_bytes: int) -> str:
            text = self.documents[path.name]
            return text.replace(required, "control omitted", 1) if path.name == first else text

        with mock.patch.object(
            verify_runbooks,
            "load_stable_text",
            side_effect=drifted_loader,
            create=True,
        ):
            result = self._run_main()
        self.assertEqual(result[0], 1)
        self.assertIn(f"Runbook {first} is missing: {required}", result[2])

    def test_source_uses_explicit_bounded_stable_text_boundary(self) -> None:
        source = Path(verify_runbooks.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("MAX_RUNBOOK_BYTES = 64 * 1024", source)
        self.assertIn("load_stable_text(", source)
        self.assertIn("max_bytes=MAX_RUNBOOK_BYTES", source)
        self.assertNotIn("Unable to load operational runbooks: {error}", source)


if __name__ == "__main__":
    unittest.main()
