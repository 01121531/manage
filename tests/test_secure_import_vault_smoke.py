from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.secure_import_vault_smoke import (
    ROOT,
    SmokeFailure,
    VaultResponse,
    evidence_errors,
    execute,
    verify_evidence,
)


class FakeVaultClient:
    def __init__(self, origin: str, token: str, *, ca_file: Path | None) -> None:
        del ca_file
        self.origin = origin.rstrip("/")
        self.role = token
        self.created: set[str] = set()

    @staticmethod
    def _json(data: dict[str, object]) -> bytes:
        return json.dumps({"data": data}, separators=(",", ":")).encode("ascii")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> VaultResponse:
        del body
        if self.role == "CARD_TOKEN_VALUE":
            if path.startswith("secret/data/cards/imports/") and method == "POST":
                if path.endswith("-wrong-cas"):
                    return VaultResponse(400, b"")
                if path in self.created:
                    return VaultResponse(400, b"")
                self.created.add(path)
                return VaultResponse(204, b"")
            if path == "transit/sign/email-platform-card-import-receipt":
                return VaultResponse(
                    200, self._json({"signature": "vault:v1:Y2FyZA=="})
                )
            return VaultResponse(403, b"")
        if self.role == "MAILBOX_TOKEN_VALUE":
            if path.startswith("secret/data/mailboxes/imports/") and method == "POST":
                if path.endswith("-wrong-cas"):
                    return VaultResponse(400, b"")
                if path in self.created:
                    return VaultResponse(400, b"")
                self.created.add(path)
                return VaultResponse(204, b"")
            if path == "transit/sign/email-platform-mailbox-import-receipt":
                return VaultResponse(
                    200, self._json({"signature": "vault:v1:bWFpbGJveA=="})
                )
            return VaultResponse(403, b"")
        if self.role == "API_TOKEN_VALUE":
            if path.startswith("transit/verify/"):
                return VaultResponse(200, self._json({"valid": True}))
            return VaultResponse(403, b"")
        raise AssertionError("unexpected fake token")


class UnsafeApiVaultClient(FakeVaultClient):
    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> VaultResponse:
        if self.role == "API_TOKEN_VALUE" and path.startswith("transit/sign/"):
            return VaultResponse(
                200, self._json({"signature": "vault:v1:dW5zYWZl"})
            )
        return super().request(method, path, body)


class SecureImportVaultSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.card_token = self.directory / "card.token"
        self.mailbox_token = self.directory / "mailbox.token"
        self.api_token = self.directory / "api.token"
        self.card_token.write_text("CARD_TOKEN_VALUE\n", encoding="utf-8")
        self.mailbox_token.write_text("MAILBOX_TOKEN_VALUE\n", encoding="utf-8")
        self.api_token.write_text("API_TOKEN_VALUE\n", encoding="utf-8")
        if hasattr(self.card_token, "chmod"):
            for path in (self.card_token, self.mailbox_token, self.api_token):
                path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            vault_address="https://vault.target.invalid",
            card_token_file=str(self.card_token),
            mailbox_token_file=str(self.mailbox_token),
            api_token_file=str(self.api_token),
            environment="staging",
            evidence_output=str(output),
            ca_file=None,
        )

    def test_exact_boundary_passes_and_evidence_is_redacted_write_once(self) -> None:
        output = self.directory / "evidence.json"

        payload, passed = execute(
            self.arguments(output), client_factory=FakeVaultClient
        )

        self.assertTrue(passed)
        self.assertEqual(payload["result"], "passed")
        self.assertFalse(payload["production_acceptance"])
        self.assertTrue(payload["cleanup_required"])
        self.assertEqual(len(payload["checks"]), 24)
        self.assertTrue(
            all(check["result"] == "passed" for check in payload["checks"].values())
        )
        raw = output.read_text(encoding="ascii")
        self.assertNotIn("CARD_TOKEN_VALUE", raw)
        self.assertNotIn("MAILBOX_TOKEN_VALUE", raw)
        self.assertNotIn("API_TOKEN_VALUE", raw)
        self.assertNotIn("vault:v1:", raw)
        self.assertNotIn("vault.target.invalid", raw)
        document = json.loads(raw)
        self.assertEqual(set(document), set(payload) | {"integrity"})
        self.assertEqual(evidence_errors(document), [])
        self.assertEqual(verify_evidence(str(output))["run_id"], payload["run_id"])
        tampered = copy.deepcopy(document)
        tampered["production_acceptance"] = True
        self.assertTrue(evidence_errors(tampered))
        tampered = copy.deepcopy(document)
        tampered["checks"]["api_card_sign_denied"]["status"] = 200
        self.assertTrue(evidence_errors(tampered))
        with self.assertRaises(ValueError):
            execute(self.arguments(output), client_factory=FakeVaultClient)

    def test_unexpected_api_sign_capability_fails_closed_and_is_recorded(self) -> None:
        output = self.directory / "failed.json"

        payload, passed = execute(
            self.arguments(output), client_factory=UnsafeApiVaultClient
        )

        self.assertFalse(passed)
        self.assertEqual(payload["result"], "failed")
        self.assertEqual(payload["error_code"], "boundary_check_failed")
        self.assertEqual(payload["checks"]["api_card_sign_denied"]["result"], "failed")
        self.assertEqual(payload["checks"]["api_mailbox_sign_denied"]["result"], "not_run")
        self.assertTrue(output.is_file())

    def test_token_files_are_external_regular_and_distinct(self) -> None:
        output = self.directory / "duplicate.json"
        arguments = self.arguments(output)
        arguments.mailbox_token_file = arguments.card_token_file

        with self.assertRaisesRegex(SmokeFailure, "vault_token_files_not_distinct"):
            execute(arguments, client_factory=FakeVaultClient)
        self.assertFalse(output.exists())

        alias = self.directory / "card-alias.token"
        os.link(self.card_token, alias)
        arguments = self.arguments(output)
        arguments.mailbox_token_file = str(alias)
        with self.assertRaisesRegex(SmokeFailure, "card_token_file_invalid"):
            execute(arguments, client_factory=FakeVaultClient)
        self.assertFalse(output.exists())

    def test_repository_evidence_output_is_rejected_before_credentials(self) -> None:
        output = ROOT / "must-not-exist-secure-import-smoke.json"
        output.unlink(missing_ok=True)

        with self.assertRaises(ValueError):
            execute(self.arguments(output), client_factory=FakeVaultClient)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
