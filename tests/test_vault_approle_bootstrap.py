import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra" / "vault" / "configure-approles.sh"
SECURE_IMPORT_SCRIPT = ROOT / "infra" / "vault" / "configure-secure-import.sh"
ROLES = (
    "email-platform-api-cards",
    "email-platform-mail",
    "email-platform-sub2",
)
SECURE_IMPORT_ROLES = (
    "email-platform-card-importer",
    "email-platform-mailbox-importer",
    "email-platform-api-cards",
)
SECURE_IMPORT_KEYS = (
    "email-platform-card-import-receipt",
    "email-platform-mailbox-import-receipt",
)


def _role_state(role: str) -> dict[str, object]:
    return {
        "data": {
            "bind_secret_id": True,
            "local_secret_ids": False,
            "secret_id_num_uses": 1,
            "secret_id_ttl": 600,
            "secret_id_bound_cidrs": [],
            "token_policies": [role],
            "token_no_default_policy": True,
            "token_type": "service",
            "token_ttl": 900,
            "token_max_ttl": 3600,
            "token_explicit_max_ttl": 3600,
            "token_period": 0,
            "token_num_uses": 0,
            "token_bound_cidrs": [],
            "alias_metadata": {},
        }
    }


@unittest.skipUnless(os.name == "posix", "AppRole shell behavior runs in the Linux gate")
class VaultAppRoleBootstrapTests(unittest.TestCase):
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
if len(sys.argv) >= 4 and sys.argv[1:3] == ["read", "-format=json"]:
    role = sys.argv[3].rsplit("/", 1)[-1]
    print((Path(os.environ["FAKE_VAULT_STATE"]) / f"{role}.json").read_text(encoding="utf-8"))
    raise SystemExit(0)
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN")
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN", file=sys.stderr)
""",
            encoding="utf-8",
        )
        fake_vault.chmod(0o755)
        self.write_states()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_states(self, overrides: dict[str, dict[str, object]] | None = None) -> None:
        overrides = overrides or {}
        for role in ROLES:
            state = _role_state(role)
            state["data"].update(overrides.get(role, {}))
            (self.state / f"{role}.json").write_text(
                json.dumps(state), encoding="utf-8"
            )

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

    def test_exact_three_role_states_succeed_without_cli_output_leakage(self) -> None:
        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "Vault policies and AppRoles match reviewed configuration; no credentials were generated or read.",
        )
        self.assertNotIn("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN", result.stdout + result.stderr)
        reads = [call for call in self.calls() if call[:2] == ["read", "-format=json"]]
        self.assertEqual(len(reads), 3)

    def test_non_https_fails_before_any_vault_call(self) -> None:
        result = self.run_helper("http://vault.example.invalid")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(result.stderr.strip(), "Vault AppRole configuration preflight failed")

    def test_any_role_drift_fails_closed_without_deleting_role(self) -> None:
        unsafe_states = (
            {"token_policies": ["email-platform-mail", "default"]},
            {"token_period": 300},
            {"token_explicit_max_ttl": 7200},
            {"local_secret_ids": True},
            {"secret_id_bound_cidrs": ["10.0.0.0/8"]},
            {"token_bound_cidrs": ["10.0.0.0/8"]},
            {"alias_metadata": {"environment": "unreviewed"}},
        )
        for unsafe in unsafe_states:
            with self.subTest(unsafe=unsafe):
                self.log.unlink(missing_ok=True)
                self.write_states({"email-platform-mail": unsafe})
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    result.stderr.strip(),
                    "Vault AppRole configuration verification failed",
                )
                self.assertFalse(any(call and call[0] == "delete" for call in self.calls()))


@unittest.skipUnless(os.name == "posix", "secure import shell behavior runs in the Linux gate")
class SecureImportVaultBootstrapTests(unittest.TestCase):
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

arguments = sys.argv[1:]
with Path(os.environ["FAKE_VAULT_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\\n")
state = Path(os.environ["FAKE_VAULT_STATE"])
if len(arguments) >= 3 and arguments[:2] == ["read", "-format=json"]:
    path = arguments[2]
    if path.startswith("sys/policies/acl/"):
        name = path.rsplit("/", 1)[-1]
        source = Path(os.environ["FAKE_VAULT_POLICY_DIR"]) / f"{name}.hcl"
        print(json.dumps({"data": {"policy": source.read_text(encoding="utf-8")}}))
    else:
        name = path.rsplit("/", 1)[-1]
        print((state / f"{name}.json").read_text(encoding="utf-8"))
    raise SystemExit(0)
if len(arguments) == 3 and arguments[:2] == ["policy", "fmt"]:
    raise SystemExit(0)
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_PRIVATE_KEY")
print("SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_PRIVATE_KEY", file=sys.stderr)
""",
            encoding="utf-8",
        )
        fake_vault.chmod(0o755)
        self.policy_dir = self.root / "policies"
        self.policy_dir.mkdir()
        for name in SECURE_IMPORT_ROLES:
            source = ROOT / "infra" / "vault" / "policies" / f"{name}.hcl"
            (self.policy_dir / f"{name}.hcl").write_bytes(source.read_bytes())
        self.write_states()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_states(
        self,
        *,
        role_overrides: dict[str, dict[str, object]] | None = None,
        key_overrides: dict[str, dict[str, object]] | None = None,
    ) -> None:
        role_overrides = role_overrides or {}
        key_overrides = key_overrides or {}
        for role in SECURE_IMPORT_ROLES:
            state = _role_state(role)
            state["data"].update(role_overrides.get(role, {}))
            (self.state / f"{role}.json").write_text(
                json.dumps(state), encoding="utf-8"
            )
        for key in SECURE_IMPORT_KEYS:
            data = {
                "name": key,
                "type": "ed25519",
                "derived": False,
                "exportable": False,
                "allow_plaintext_backup": False,
                "deletion_allowed": False,
                "auto_rotate_period": 2_592_000,
                "supports_signing": True,
                "latest_version": 1,
                "keys": {"1": {"public_key": "REDACTED_PUBLIC_KEY"}},
            }
            data.update(key_overrides.get(key, {}))
            (self.state / f"{key}.json").write_text(
                json.dumps({"data": data}), encoding="utf-8"
            )

    def run_helper(
        self, address: str = "https://vault.example.invalid"
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": f"{self.bin}{os.pathsep}{environment['PATH']}",
                "VAULT_ADDR": address,
                "FAKE_VAULT_LOG": str(self.log),
                "FAKE_VAULT_STATE": str(self.state),
                "FAKE_VAULT_POLICY_DIR": str(self.policy_dir),
            }
        )
        return subprocess.run(
            ["sh", str(SECURE_IMPORT_SCRIPT)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_exact_roles_keys_and_policies_succeed_without_sensitive_output(self) -> None:
        result = self.run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "Vault secure import policies, AppRoles, and non-exportable signing keys "
            "match reviewed configuration; no credentials were generated or read.",
        )
        self.assertNotIn(
            "SENSITIVE_ROLE_ID_SECRET_ID_TOKEN_PRIVATE_KEY",
            result.stdout + result.stderr,
        )
        calls = self.calls()
        self.assertEqual(
            len([call for call in calls if call[:2] == ["policy", "write"]]), 3
        )
        self.assertEqual(
            len(
                [
                    call
                    for call in calls
                    if call[:2] == ["write", "auth/approle/role/email-platform-card-importer"]
                    or call[:2] == ["write", "auth/approle/role/email-platform-mailbox-importer"]
                    or call[:2] == ["write", "auth/approle/role/email-platform-api-cards"]
                ]
            ),
            3,
        )
        key_writes = [
            call
            for call in calls
            if call[:2]
            in (["write", f"transit/keys/{key}"] for key in SECURE_IMPORT_KEYS)
        ]
        self.assertEqual(len(key_writes), 2)
        for call in key_writes:
            self.assertIn("type=ed25519", call)
            self.assertIn("exportable=false", call)
            self.assertIn("allow_plaintext_backup=false", call)
            self.assertIn("auto_rotate_period=720h", call)
        forbidden_fragments = ("role-id", "secret-id", "auth/approle/login", "export/")
        self.assertFalse(
            any(fragment in " ".join(call) for call in calls for fragment in forbidden_fragments)
        )

    def test_non_https_fails_before_any_vault_call(self) -> None:
        result = self.run_helper("http://vault.example.invalid")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(
            result.stderr.strip(),
            "Vault secure import configuration preflight failed",
        )

    def test_role_or_key_drift_fails_closed_without_delete_or_export(self) -> None:
        cases = (
            ({"email-platform-card-importer": {"token_policies": ["default"]}}, {}),
            ({"email-platform-mailbox-importer": {"local_secret_ids": True}}, {}),
            ({}, {"email-platform-card-import-receipt": {"exportable": True}}),
            ({}, {"email-platform-mailbox-import-receipt": {"deletion_allowed": True}}),
            ({}, {"email-platform-mailbox-import-receipt": {"auto_rotate_period": 0}}),
        )
        for role_overrides, key_overrides in cases:
            with self.subTest(role_overrides=role_overrides, key_overrides=key_overrides):
                self.log.unlink(missing_ok=True)
                self.write_states(
                    role_overrides=role_overrides,
                    key_overrides=key_overrides,
                )
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    result.stderr.strip(),
                    "Vault secure import configuration verification failed",
                )
                calls = self.calls()
                self.assertFalse(any(call and call[0] == "delete" for call in calls))
                self.assertFalse(any("export/" in " ".join(call) for call in calls))


if __name__ == "__main__":
    unittest.main()
