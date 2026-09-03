from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts.sub2_egress_preflight import (
    Sub2EgressPreflightError,
    validate_sub2_egress_policy,
)


class Sub2EgressPreflightTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        upload_url: str = "https://sub2-upload.example/api/upload",
        origins: str = "https://sub2-upload.example\n",
    ) -> tuple[Path, Path]:
        repository = root / "repository"
        repository.mkdir()
        policy = root / "sub2-allowed-origins"
        policy.write_text(origins, encoding="utf-8")
        (repository / ".env").write_text(
            "\n".join(
                (
                    f"PLATFORM_SUB2_UPLOAD_URL={upload_url}",
                    f"PLATFORM_SUB2_ALLOWED_ORIGINS_FILE={policy}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        return repository, policy

    def test_matching_external_policy_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, _ = self._fixture(Path(directory))
            with mock.patch(
                "scripts.sub2_egress_preflight."
                "sub2_unknown_reconciliation_configured",
                return_value=True,
            ):
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )

    def test_submit_only_runtime_is_not_releasable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, _ = self._fixture(Path(directory))
            with self.assertRaisesRegex(
                Sub2EgressPreflightError,
                "^production Sub2 egress policy preflight failed$",
            ):
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )

    def test_missing_url_fails_closed_without_locator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, policy = self._fixture(root)
            (repository / ".env").write_text(
                f"PLATFORM_SUB2_ALLOWED_ORIGINS_FILE={policy}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                Sub2EgressPreflightError,
                "^production Sub2 egress policy preflight failed$",
            ) as raised:
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )
            self.assertNotIn(str(policy), str(raised.exception))

    def test_origin_mismatch_fails_closed_without_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_url = "https://private-sub2.example/api/upload"
            repository, _ = self._fixture(
                Path(directory),
                upload_url=private_url,
            )
            with self.assertRaisesRegex(
                Sub2EgressPreflightError,
                "^production Sub2 egress policy preflight failed$",
            ) as raised:
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )
            self.assertNotIn(private_url, str(raised.exception))

    def test_case_control_plane_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, _ = self._fixture(
                Path(directory),
                upload_url=(
                    "https://ai1.aisb.shop/api/v1/admin/openai/exchange-code"
                ),
                origins="https://ai1.aisb.shop\n",
            )
            with self.assertRaises(Sub2EgressPreflightError):
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )

    def test_repository_internal_policy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, policy = self._fixture(Path(directory))
            internal_policy = repository / policy.name
            policy.replace(internal_policy)
            (repository / ".env").write_text(
                "\n".join(
                    (
                        "PLATFORM_SUB2_UPLOAD_URL=https://sub2-upload.example/api/upload",
                        f"PLATFORM_SUB2_ALLOWED_ORIGINS_FILE={internal_policy}",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            with self.assertRaises(Sub2EgressPreflightError):
                validate_sub2_egress_policy(
                    repository / ".env",
                    repository_root=repository,
                )


if __name__ == "__main__":
    unittest.main()
