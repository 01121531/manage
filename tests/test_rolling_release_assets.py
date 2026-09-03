import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.verify_rolling_release import ROOT, verification_errors


class RollingReleaseAssetTests(unittest.TestCase):
    def test_repository_contract_passes(self) -> None:
        self.assertEqual(verification_errors(), [])

    def test_phase0_intake_gate_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            executor = root / "scripts/rolling_release.py"
            source = executor.read_text(encoding="utf-8").replace(
                "checkpoint = load_phase_checkpoint(",
                "checkpoint = removed_phase_checkpoint(",
                1,
            )
            executor.write_text(source, encoding="utf-8")
            self.assertTrue(
                any("Phase 0 target intake" in error for error in verification_errors(root))
            )

    def test_phase0_evaluation_and_ledger_start_cannot_diverge(self) -> None:
        for old, new in (
            ("evaluated_at=release_started_at,", "evaluated_at=None,"),
            ("started_at=checkpoint.evaluated_at,", "started_at=None,"),
        ):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative in (
                    "docker-compose.rolling.yml",
                    "infra/nginx/email-platform.conf.template",
                    "infra/nginx/slots/blue.conf",
                    "infra/nginx/slots/green.conf",
                    "scripts/rolling_release.py",
                    "scripts/rolling_release_evidence.py",
                    "scripts/deploy_release.py",
                    "scripts/rollback_release.py",
                    "platform/migrations/versions/0024_schema_compatibility.py",
                ):
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, destination)
                executor = root / "scripts/rolling_release.py"
                source = executor.read_text(encoding="utf-8")
                changed = source.replace(old, new, 1)
                self.assertNotEqual(changed, source)
                executor.write_text(changed, encoding="utf-8")
                self.assertTrue(verification_errors(root))

    def test_direct_single_slot_edge_proxy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            edge = root / "infra/nginx/email-platform.conf.template"
            edge.write_text(
                edge.read_text(encoding="utf-8")
                + "\nproxy_pass https://api:8443;\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any("bypasses" in error for error in verification_errors(root))
            )

    def test_lock_scoped_route_revalidation_cannot_move_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            executor = root / "scripts/rolling_release.py"
            source = executor.read_text(encoding="utf-8")
            source = source.replace(
                "    _validate_route_dir(plan.route_dir, plan.active_slot)\n"
                "    if confirm_release_tag != plan.deployment.tag:\n",
                "    if confirm_release_tag != plan.deployment.tag:\n"
                "        raise RollingReleaseError(\"release confirmation does not match rolling plan\")\n"
                "    _validate_route_dir(plan.route_dir, plan.active_slot)\n"
                "    if confirm_release_tag != plan.deployment.tag:\n",
                1,
            )
            executor.write_text(source, encoding="utf-8")
            self.assertTrue(
                any("revalidate" in error for error in verification_errors(root))
            )

    def test_route_reads_cannot_bypass_the_stable_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            executor = root / "scripts/rolling_release.py"
            source = executor.read_text(encoding="utf-8").replace(
                'return _read_route_snapshot(SLOT_DIR / f"{slot}.conf").content',
                'return (SLOT_DIR / f"{slot}.conf").read_bytes()',
                1,
            )
            executor.write_text(source, encoding="utf-8")

            self.assertTrue(
                any("stable snapshot" in error for error in verification_errors(root))
            )

    def test_sub2_egress_preflight_cannot_be_removed_redirected_or_replaced(self) -> None:
        for old, new in (
            ("validate_sub2_egress_policy(PRODUCTION_ENV_FILE)", "pass"),
            (
                "validate_sub2_egress_policy(PRODUCTION_ENV_FILE)",
                "validate_sub2_egress_policy(Path('unreviewed.env'))",
            ),
            (
                "def _execute_locked(",
                "def validate_sub2_egress_policy(*_args):\n    return None\n\n\ndef _execute_locked(",
            ),
        ):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative in (
                    "docker-compose.rolling.yml",
                    "infra/nginx/email-platform.conf.template",
                    "infra/nginx/slots/blue.conf",
                    "infra/nginx/slots/green.conf",
                    "scripts/rolling_release.py",
                    "scripts/rolling_release_evidence.py",
                    "scripts/deploy_release.py",
                    "scripts/rollback_release.py",
                    "platform/migrations/versions/0024_schema_compatibility.py",
                ):
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, destination)
                executor = root / "scripts/rolling_release.py"
                source = executor.read_text(encoding="utf-8")
                changed = source.replace(old, new, 1)
                self.assertNotEqual(changed, source)
                executor.write_text(changed, encoding="utf-8")
                self.assertTrue(
                    any(
                        "Sub2 egress preflight" in error
                        for error in verification_errors(root)
                    )
                )

    def test_green_api_and_web_certificates_cannot_be_swapped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            compose = root / "docker-compose.rolling.yml"
            source = compose.read_text(encoding="utf-8").replace(
                "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
                "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
                1,
            )
            compose.write_text(source, encoding="utf-8")
            self.assertTrue(
                any("green TLS mount" in error for error in verification_errors(root))
            )

    def test_rolling_evidence_cannot_replace_an_existing_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "docker-compose.rolling.yml",
                "infra/nginx/email-platform.conf.template",
                "infra/nginx/slots/blue.conf",
                "infra/nginx/slots/green.conf",
                "scripts/rolling_release.py",
                "scripts/rolling_release_evidence.py",
                "scripts/deploy_release.py",
                "scripts/rollback_release.py",
                "platform/migrations/versions/0024_schema_compatibility.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            evidence = root / "scripts/rolling_release_evidence.py"
            source = evidence.read_text(encoding="utf-8").replace(
                "publish_write_once_file(temporary_path, destination)",
                "os.replace(temporary_path, destination)",
                1,
            )
            evidence.write_text(source, encoding="utf-8")
            self.assertTrue(
                any("write_once" in error for error in verification_errors(root))
            )


if __name__ == "__main__":
    unittest.main()
