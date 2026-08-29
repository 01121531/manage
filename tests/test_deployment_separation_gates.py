from __future__ import annotations

import contextlib
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from scripts import verify_runbooks, verify_signoff_template


ROOT = Path(__file__).resolve().parents[1]


class DeploymentSeparationGateTests(unittest.TestCase):
    def test_runbook_gate_rejects_each_missing_separation_control(self) -> None:
        for filename in (
            "admin-plane-separation.md",
            "nonproduction-data-boundary.md",
        ):
            source = (ROOT / "deploy" / "runbooks" / filename).read_text(encoding="utf-8")
            for required in verify_runbooks.RUNBOOKS[filename]:
                with self.subTest(filename=filename, required=required), tempfile.TemporaryDirectory() as temporary:
                    self.assertIn(required, source)
                    temporary_root = Path(temporary)
                    shutil.copytree(
                        ROOT / "deploy" / "runbooks",
                        temporary_root / "deploy" / "runbooks",
                    )
                    mutated = source.replace(required, "control omitted")
                    (temporary_root / "deploy" / "runbooks" / filename).write_text(
                        mutated, encoding="utf-8"
                    )
                    with (
                        mock.patch.object(verify_runbooks, "ROOT", temporary_root),
                        contextlib.redirect_stdout(io.StringIO()),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        self.assertEqual(verify_runbooks.main(), 1)

    def test_signoff_gate_rejects_missing_admin_or_data_boundary_evidence(self) -> None:
        source = verify_signoff_template.TEMPLATE.read_text(encoding="utf-8")
        required_fields = (
            "Keycloak/Vault administrator non-overlap and no-shared-credential review:",
            "Cross-control-plane denied-access trace and audit-event evidence:",
            "Non-production source/target environment and synthetic-fixture provenance:",
            "Non-production denial of production backup/snapshot/clone/Vault-path access evidence:",
        )
        for field in required_fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                incomplete = source.replace(field, "Required evidence omitted:", 1)
                self.assertNotEqual(incomplete, source)
                path = Path(temporary) / "production-signoff-template.md"
                path.write_text(incomplete, encoding="utf-8")
                with (
                    mock.patch.object(verify_signoff_template, "TEMPLATE", path),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(verify_signoff_template.main(), 1)


class InternalTlsResiduePolicyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (
            ROOT / "deploy" / "runbooks" / "internal-tls.md"
        ).read_text(encoding="utf-8")

    def test_current_residue_policy_passes(self) -> None:
        self.assertEqual(verify_runbooks.internal_tls_runbook_errors(self.source), [])

    def test_each_required_residue_control_is_enforced(self) -> None:
        normalized = " ".join(self.source.split())
        for required in verify_runbooks.INTERNAL_TLS_RESIDUE_REQUIRED:
            with self.subTest(required=required):
                mutated = normalized.replace(required, "control omitted", 1)
                self.assertNotEqual(mutated, normalized)
                self.assertTrue(
                    verify_runbooks.internal_tls_runbook_errors(mutated)
                )

    def test_residue_overclaims_are_rejected(self) -> None:
        for overclaim in verify_runbooks.INTERNAL_TLS_RESIDUE_FORBIDDEN:
            with self.subTest(overclaim=overclaim):
                self.assertTrue(
                    verify_runbooks.internal_tls_runbook_errors(
                        f"{self.source}\n{overclaim}\n"
                    )
                )

    def test_main_applies_internal_tls_residue_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            shutil.copytree(
                ROOT / "deploy" / "runbooks",
                temporary_root / "deploy" / "runbooks",
            )
            path = temporary_root / "deploy" / "runbooks" / "internal-tls.md"
            path.write_text(
                self.source.replace(
                    "human approval for exactly one reviewed `cleanup_candidate` claim",
                    "automatic cleanup for every candidate",
                    1,
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(verify_runbooks, "ROOT", temporary_root),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verify_runbooks.main(), 1)


if __name__ == "__main__":
    unittest.main()
