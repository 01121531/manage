from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra" / "vault" / "configure-broker-issuer-policies.sh"
POLICY_DIR = ROOT / "infra" / "vault" / "policies"
POLICIES = (
    "email-platform-broker-issuer-api",
    "email-platform-broker-issuer-mail",
    "email-platform-broker-issuer-sub2",
)


@unittest.skipUnless(os.name == "posix", "Vault broker shell behavior runs in the Linux gate")
class VaultBrokerPolicyBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("sh") is None or shutil.which("jq") is None:
            self.skipTest("sh and jq are required")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.state = self.root / "state"
        self.bin.mkdir()
        self.state.mkdir()
        self.log = self.root / "vault-calls.jsonl"
        fake_vault = self.bin / "vault"
        fake_vault.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

with Path(os.environ["FAKE_VAULT_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if len(args) == 4 and args[:2] == ["policy", "write"]:
    raise SystemExit(0)
if len(args) == 3 and args[:2] == ["read", "-format=json"]:
    name = args[2].rsplit("/", 1)[-1]
    policy = (Path(os.environ["FAKE_VAULT_STATE"]) / f"{name}.hcl").read_text(encoding="utf-8")
    print(json.dumps({"data": {"policy": policy}}))
    raise SystemExit(0)
if len(args) == 3 and args[:2] == ["policy", "fmt"]:
    raise SystemExit(0)
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_ACCESSOR")
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_ACCESSOR", file=sys.stderr)
raise SystemExit(41)
""",
            encoding="utf-8",
        )
        fake_vault.chmod(0o755)
        for name in POLICIES:
            shutil.copyfile(
                POLICY_DIR / f"{name}.hcl",
                self.state / f"{name}.hcl",
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_helper(self, address: str = "https://vault.example.invalid") -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": f"{self.bin}{os.pathsep}{environment['PATH']}",
                "VAULT_ADDR": address,
                "FAKE_VAULT_LOG": str(self.log),
                "FAKE_VAULT_STATE": str(self.state),
            }
        )
        return subprocess.run(
            ["sh", str(SCRIPT)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_exact_three_policies_succeed_without_cli_output_leakage(self) -> None:
        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "Vault broker issuer policies match reviewed configuration; no credentials or identity bindings were read or changed.",
        )
        self.assertNotIn("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_ACCESSOR", result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len([call for call in calls if call[:2] == ["policy", "write"]]), 3)
        self.assertEqual(len([call for call in calls if call[:2] == ["read", "-format=json"]]), 3)
        self.assertEqual(len([call for call in calls if call[:2] == ["policy", "fmt"]]), 6)

    def test_non_https_fails_before_any_vault_call(self) -> None:
        result = self.run_helper("http://vault.example.invalid")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(result.stderr.strip(), "Vault broker issuer policy preflight failed")

    def test_any_policy_drift_fails_closed_without_delete_or_credentials(self) -> None:
        target = self.state / "email-platform-broker-issuer-mail.hcl"
        target.write_text(
            target.read_text(encoding="utf-8").replace('["read"]', '["read", "sudo"]', 1),
            encoding="utf-8",
        )

        result = self.run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stderr.strip(),
            "Vault broker issuer policy configuration failed",
        )
        self.assertNotIn("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_ACCESSOR", result.stdout + result.stderr)
        self.assertFalse(any(call and call[0] == "delete" for call in self.calls()))


if __name__ == "__main__":
    unittest.main()
