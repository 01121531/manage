from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.secure_import_vault_canary_cleanup import (
    CleanupFailure,
    VaultResponse,
    cleanup_receipt_errors,
    execute,
    render_cleanup_policy,
    verify_cleanup_receipt,
)
from scripts.secure_import_vault_smoke import execute as execute_smoke
from tests.test_secure_import_vault_smoke import FakeVaultClient as SmokeVaultClient


class CleanupVaultClient:
    run_id = ""
    policy_name = ""
    present: set[str] = set()
    calls: list[tuple[str, str]] = []
    unsafe_content = False
    fail_delete_path: str | None = None

    def __init__(self, origin: str, token: str, *, ca_file: Path | None) -> None:
        del ca_file
        if token != "CLEANUP_TOKEN_VALUE":
            raise AssertionError("unexpected cleanup token")
        self.origin = origin.rstrip("/")

    @classmethod
    def reset(cls, run_id: str) -> None:
        cls.run_id = run_id
        cls.policy_name = (
            "email-platform-secure-import-cleanup-" + run_id.replace("-", "")
        )
        cls.present = {
            f"secret/data/cards/imports/smoke/{run_id}",
            f"secret/metadata/cards/imports/smoke/{run_id}",
            f"secret/data/mailboxes/imports/smoke/{run_id}",
            f"secret/metadata/mailboxes/imports/smoke/{run_id}",
        }
        cls.calls = []
        cls.unsafe_content = False
        cls.fail_delete_path = None

    @staticmethod
    def _json(data: dict[str, object]) -> bytes:
        return json.dumps({"data": data}, separators=(",", ":")).encode("ascii")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
    ) -> VaultResponse:
        type(self).calls.append((method, path))
        if method == "GET" and path == "auth/token/lookup-self":
            return VaultResponse(200, self._json({"policies": [self.policy_name]}))
        if method == "POST" and path == "sys/capabilities-self":
            assert body is not None
            capabilities = {}
            for candidate in body["paths"]:
                if "/data/" in candidate:
                    capabilities[candidate] = ["read"]
                elif "/metadata/" in candidate:
                    capabilities[candidate] = ["read", "delete"]
                else:
                    raise AssertionError("unexpected capability path")
            return VaultResponse(200, self._json(capabilities))
        if method == "GET" and path in self.present:
            if "/data/" in path:
                value: dict[str, object] = {"smoke_canary": self.run_id}
                if self.unsafe_content:
                    value["unexpected"] = "value"
                return VaultResponse(200, self._json({"data": value, "metadata": {}}))
            return VaultResponse(200, self._json({"current_version": 1}))
        if method == "GET" and (
            path.startswith("secret/data/") or path.startswith("secret/metadata/")
        ):
            return VaultResponse(404, b"")
        if method == "DELETE" and "/metadata/" in path:
            if path == self.fail_delete_path:
                return VaultResponse(500, b"")
            data_path = path.replace("/metadata/", "/data/", 1)
            type(self).present.discard(path)
            type(self).present.discard(data_path)
            return VaultResponse(204, b"")
        raise AssertionError(f"unexpected cleanup request: {method} {path}")


class SecureImportVaultCanaryCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.card_token = self.directory / "card.token"
        self.mailbox_token = self.directory / "mailbox.token"
        self.api_token = self.directory / "api.token"
        self.cleanup_token = self.directory / "cleanup.token"
        self.card_token.write_text("CARD_TOKEN_VALUE\n", encoding="utf-8")
        self.mailbox_token.write_text("MAILBOX_TOKEN_VALUE\n", encoding="utf-8")
        self.api_token.write_text("API_TOKEN_VALUE\n", encoding="utf-8")
        self.cleanup_token.write_text("CLEANUP_TOKEN_VALUE\n", encoding="utf-8")
        for path in (
            self.card_token,
            self.mailbox_token,
            self.api_token,
            self.cleanup_token,
        ):
            path.chmod(0o600)
        self.smoke_evidence = self.directory / "smoke.json"
        self.smoke_plan = self.directory / "smoke-plan.json"
        smoke_args = argparse.Namespace(
            vault_address="https://vault.target.invalid",
            card_token_file=str(self.card_token),
            mailbox_token_file=str(self.mailbox_token),
            api_token_file=str(self.api_token),
            environment="staging",
            plan_output=str(self.smoke_plan),
            evidence_output=str(self.smoke_evidence),
            ca_file=None,
        )
        self.smoke_payload, passed = execute_smoke(
            smoke_args, client_factory=SmokeVaultClient
        )
        self.assertTrue(passed)
        self.smoke_sha256 = hashlib.sha256(self.smoke_evidence.read_bytes()).hexdigest()
        self.smoke_plan_sha256 = hashlib.sha256(self.smoke_plan.read_bytes()).hexdigest()
        self.smoke_plan_payload = json.loads(self.smoke_plan.read_text(encoding="ascii"))
        self.run_id = str(self.smoke_payload["run_id"])
        CleanupVaultClient.reset(self.run_id)
        self.policy_file = self.directory / "cleanup.hcl"
        self.policy_file.write_text(
            render_cleanup_policy(self.smoke_plan_payload), encoding="ascii", newline="\n"
        )
        self.policy_sha256 = hashlib.sha256(self.policy_file.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            vault_address="https://vault.target.invalid",
            cleanup_token_file=str(self.cleanup_token),
            smoke_plan=str(self.smoke_plan),
            expected_smoke_plan_sha256=self.smoke_plan_sha256,
            confirm_run_id=self.run_id,
            policy_file=str(self.policy_file),
            expected_policy_sha256=self.policy_sha256,
            receipt_output=str(output),
            ca_file=None,
        )

    def test_exact_dynamic_policy_and_cleanup_receipt_are_secret_free(self) -> None:
        policy = self.policy_file.read_text(encoding="ascii")
        self.assertNotIn("*", policy)
        self.assertEqual(policy.count('capabilities = ["read"]'), 2)
        self.assertEqual(policy.count('capabilities = ["read", "delete"]'), 2)
        self.assertNotIn('capabilities = ["delete"]', policy)
        output = self.directory / "cleanup-receipt.json"

        payload, passed = execute(
            self.arguments(output), client_factory=CleanupVaultClient
        )

        self.assertTrue(passed)
        self.assertEqual(payload["result"], "confirmed_absent")
        self.assertFalse(payload["cleanup_required"])
        self.assertEqual(cleanup_receipt_errors(json.loads(output.read_text())), [])
        self.assertEqual(verify_cleanup_receipt(str(output))["run_id"], self.run_id)
        raw = output.read_text(encoding="ascii")
        for prohibited in (
            "CLEANUP_TOKEN_VALUE",
            "CARD_TOKEN_VALUE",
            "MAILBOX_TOKEN_VALUE",
            "API_TOKEN_VALUE",
            "smoke_canary",
            "vault.target.invalid",
        ):
            self.assertNotIn(prohibited, raw)
        delete_paths = [path for method, path in CleanupVaultClient.calls if method == "DELETE"]
        self.assertEqual(delete_paths, [
            f"secret/metadata/cards/imports/smoke/{self.run_id}",
            f"secret/metadata/mailboxes/imports/smoke/{self.run_id}",
        ])

    def test_both_canaries_are_preflighted_before_first_delete(self) -> None:
        CleanupVaultClient.unsafe_content = True
        output = self.directory / "unsafe.json"

        payload, passed = execute(
            self.arguments(output), client_factory=CleanupVaultClient
        )

        self.assertFalse(passed)
        self.assertTrue(payload["cleanup_required"])
        self.assertEqual(payload["error_code"], "canary_content_invalid")
        self.assertFalse(any(method == "DELETE" for method, _ in CleanupVaultClient.calls))

    def test_one_already_absent_canary_converges_without_broad_delete(self) -> None:
        card_data = f"secret/data/cards/imports/smoke/{self.run_id}"
        card_metadata = card_data.replace("/data/", "/metadata/", 1)
        CleanupVaultClient.present.remove(card_data)
        CleanupVaultClient.present.remove(card_metadata)
        output = self.directory / "partial-cleanup.json"

        payload, passed = execute(
            self.arguments(output), client_factory=CleanupVaultClient
        )

        self.assertTrue(passed)
        self.assertEqual(payload["checks"]["card"]["pre_state"], "already_absent")
        self.assertEqual(payload["checks"]["mailbox"]["pre_state"], "present")
        deletes = [path for method, path in CleanupVaultClient.calls if method == "DELETE"]
        self.assertEqual(deletes, [
            f"secret/metadata/mailboxes/imports/smoke/{self.run_id}"
        ])

    def test_plan_policy_and_origin_binding_fail_before_delete(self) -> None:
        cases: list[tuple[str, argparse.Namespace]] = []
        bad_pin = self.arguments(self.directory / "bad-pin.json")
        bad_pin.expected_smoke_plan_sha256 = "0" * 64
        cases.append(("plan", bad_pin))
        bad_run = self.arguments(self.directory / "bad-run.json")
        bad_run.confirm_run_id = "00000000-0000-4000-8000-000000000000"
        cases.append(("run", bad_run))
        bad_policy = self.arguments(self.directory / "bad-policy.json")
        bad_policy.expected_policy_sha256 = "0" * 64
        cases.append(("policy", bad_policy))
        bad_origin = self.arguments(self.directory / "bad-origin.json")
        bad_origin.vault_address = "https://other-vault.target.invalid"
        cases.append(("origin", bad_origin))

        for label, arguments in cases:
            with self.subTest(label=label):
                CleanupVaultClient.reset(self.run_id)
                with self.assertRaises(CleanupFailure):
                    execute(arguments, client_factory=CleanupVaultClient)
                self.assertFalse(any(method == "DELETE" for method, _ in CleanupVaultClient.calls))

    def test_cleanup_receipt_tampering_is_rejected(self) -> None:
        output = self.directory / "receipt.json"
        execute(self.arguments(output), client_factory=CleanupVaultClient)
        document = json.loads(output.read_text())
        tampered = copy.deepcopy(document)
        tampered["cleanup_required"] = True
        self.assertTrue(cleanup_receipt_errors(tampered))


if __name__ == "__main__":
    unittest.main()
