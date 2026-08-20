import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_rollback_assets.py"
SPEC = importlib.util.spec_from_file_location("verify_rollback_assets", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_rollback_assets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_rollback_assets
SPEC.loader.exec_module(verify_rollback_assets)


class RollbackAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.env_text = (ROOT / ".env.example").read_text(encoding="utf-8")

    def test_repository_image_mapping_is_valid(self) -> None:
        self.assertEqual(
            verify_rollback_assets.rollback_asset_errors(
                self.compose_text, self.env_text
            ),
            [],
        )

    def test_independent_worker_image_variable_is_rejected(self) -> None:
        changed_compose = self.compose_text.replace(
            "  worker-mail:\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: infra/Dockerfile\n"
            "    image: ${PLATFORM_API_IMAGE:-email-platform-api:local}",
            "  worker-mail:\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: infra/Dockerfile\n"
            "    image: ${PLATFORM_WORKER_MAIL_IMAGE:-email-platform-worker-mail:local}",
            1,
        )
        changed_env = self.env_text + "\nPLATFORM_WORKER_MAIL_IMAGE=worker:local\n"

        errors = verify_rollback_assets.rollback_asset_errors(
            changed_compose, changed_env
        )

        self.assertTrue(any("worker-mail image must be" in error for error in errors))
        self.assertTrue(
            any("independent worker image variables" in error for error in errors)
        )

    def test_migrate_cannot_use_a_different_api_image(self) -> None:
        changed_compose = self.compose_text.replace(
            "image: ${PLATFORM_API_IMAGE:-email-platform-api:local}",
            "image: email-platform-migrate:local",
            1,
        )

        errors = verify_rollback_assets.rollback_asset_errors(
            changed_compose, self.env_text
        )

        self.assertTrue(any("migrate image must be" in error for error in errors))

    def test_required_image_variable_must_be_documented(self) -> None:
        changed_env = self.env_text.replace(
            "PLATFORM_EDGE_IMAGE=email-platform-edge:local\n", ""
        )

        errors = verify_rollback_assets.rollback_asset_errors(
            self.compose_text, changed_env
        )

        self.assertIn(
            ".env.example is missing image variables: PLATFORM_EDGE_IMAGE", errors
        )


if __name__ == "__main__":
    unittest.main()
