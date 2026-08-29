from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_keycloak_realm


FIXED_OIDC_ERROR = "Keycloak OIDC client source is invalid\n"
MAX_OIDC_SOURCE_BYTES = 64 * 1024


class KeycloakOidcStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.realm = external_json.load_unique_json(
            verify_keycloak_realm.REALM,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        self.oidc_text = external_text.load_stable_text(
            verify_keycloak_realm.OIDC,
            max_bytes=MAX_OIDC_SOURCE_BYTES,
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_keycloak_realm.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_oidc_source_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_keycloak_realm.OIDC:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_keycloak_realm,
            "load_unique_json",
            return_value=self.realm,
        ) as realm_read, mock.patch.object(
            verify_keycloak_realm,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as oidc_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "keycloak-policy-ok "
                "audit-30d-admin-metadata-only-desktop-pkce-refresh-rotation-"
                "exact-redirects-and-browser-mfa\n",
                "",
            ),
        )
        realm_read.assert_called_once_with(
            verify_keycloak_realm.REALM,
            max_bytes=external_json.MAX_INTAKE_JSON_BYTES,
        )
        oidc_read.assert_called_once_with(
            verify_keycloak_realm.OIDC,
            max_bytes=MAX_OIDC_SOURCE_BYTES,
        )

    def test_oidc_source_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        raw = self.oidc_text.encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
        prefix = raw + b"//"
        padding = MAX_OIDC_SOURCE_BYTES - len(prefix)
        self.assertGreaterEqual(padding, 0)
        exact = prefix + b"x" * padding

        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "oidc.ts"
            replacement.write_bytes(exact)
            with mock.patch.object(
                verify_keycloak_realm,
                "OIDC",
                replacement,
            ), mock.patch.object(
                verify_keycloak_realm,
                "load_unique_json",
                return_value=self.realm,
            ):
                self.assertEqual(self.run_main()[0], 0)
                replacement.write_bytes(exact + b"x")
                self.assertEqual(
                    self.run_main(),
                    (1, "", FIXED_OIDC_ERROR),
                )

    def test_invalid_utf8_uses_fixed_oidc_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "oidc.ts"
            replacement.write_bytes(b"\xff")
            with mock.patch.object(
                verify_keycloak_realm,
                "OIDC",
                replacement,
            ), mock.patch.object(
                verify_keycloak_realm,
                "load_unique_json",
                return_value=self.realm,
            ):
                self.assertEqual(
                    self.run_main(),
                    (1, "", FIXED_OIDC_ERROR),
                )

    def test_link_or_reparse_oidc_source_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            verify_keycloak_realm,
            "load_unique_json",
            return_value=self.realm,
        ), mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_OIDC_ERROR))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_oidc_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_keycloak_realm,
                "load_unique_json",
                return_value=self.realm,
            ), mock.patch.object(
                verify_keycloak_realm,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as oidc_read:
                result = self.run_main()

            self.assertEqual(result, (1, "", FIXED_OIDC_ERROR))
            self.assertNotIn(reason, result[2])
            oidc_read.assert_called_once_with(
                verify_keycloak_realm.OIDC,
                max_bytes=MAX_OIDC_SOURCE_BYTES,
            )

    def test_missing_redirect_contract_keeps_existing_error(self) -> None:
        changed = self.oidc_text.replace(
            "redirect_uri: `${window.location.origin}/callback`",
            "redirect_uri: `${window.location.origin}/unsafe`",
            1,
        )
        self.assertNotEqual(changed, self.oidc_text)
        with mock.patch.object(
            verify_keycloak_realm,
            "load_unique_json",
            return_value=self.realm,
        ), mock.patch.object(
            verify_keycloak_realm,
            "load_stable_text",
            return_value=changed,
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(result[0:2], (1, ""))
        self.assertEqual(
            result[2],
            "frontend/src/oidc.ts is missing "
            "redirect_uri: `${window.location.origin}/callback`\n",
        )

    def test_source_uses_bounded_stable_oidc_snapshot(self) -> None:
        source = Path(verify_keycloak_realm.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("OIDC.read_text(", source)
        self.assertIn("MAX_OIDC_SOURCE_BYTES = 64 * 1024", source)
        self.assertIn(
            "load_stable_text(\n            OIDC,\n"
            "            max_bytes=MAX_OIDC_SOURCE_BYTES,\n        )",
            source,
        )


if __name__ == "__main__":
    unittest.main()
