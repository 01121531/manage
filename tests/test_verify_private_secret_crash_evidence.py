from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest

from scripts.verify_private_secret_crash_evidence import (
    MAX_ASSET_BYTES,
    MAX_TOOL_BYTES,
    POLICY,
    TEMPLATE,
    TOOL,
    validate_assets,
)


def _render(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _seal(value: dict[str, object]) -> bytes:
    payload = {key: item for key, item in value.items() if key != "integrity"}
    raw = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    value["integrity"] = {"payload_sha256": hashlib.sha256(raw).hexdigest()}
    return _render(value)


class VerifyPrivateSecretCrashEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = TOOL.read_text(encoding="utf-8")
        cls.policy = POLICY.read_bytes()
        cls.template = TEMPLATE.read_bytes()

    def validate(
        self,
        *,
        tool: str | None = None,
        policy: bytes | None = None,
        template: bytes | None = None,
    ) -> list[str]:
        return validate_assets(
            self.tool if tool is None else tool,
            self.policy if policy is None else policy,
            self.template if template is None else template,
        )

    def test_current_assets_pass(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_static_verifier_cli_passes_without_runtime_execution(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TOOL.with_name("verify_private_secret_crash_evidence.py"))],
            cwd=TOOL.parents[1],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.strip(),
            "private-secret-crash-evidence-static-ok "
            "origin-authentication=unverified production_acceptance=false",
        )

    def test_required_offline_capabilities_cannot_be_removed(self) -> None:
        mutations = (
            self.tool.replace("def validate_runtime_policy(", "def unchecked_policy(", 1),
            self.tool.replace("def validate_envelope(", "def unchecked_envelope(", 1),
            self.tool.replace("def verify_evidence(", "def unchecked_evidence(", 1),
            self.tool.replace("parse_unique_json_bytes(raw)", "json.loads(raw)", 1),
            self.tool.replace("read_stable_bytes_with_metadata(", "unchecked_read(", 1),
            self.tool.replace("metadata.st_nlink != 1", "False", 1),
            self.tool.replace(
                'scope.get("kind") == "github_actions_linux_ci"',
                "False",
                1,
            ),
            self.tool.replace(
                'scope.get("kind") == "kubernetes_target_host"',
                "False",
                1,
            ),
            self.tool.replace("before_siblings != after_records", "False", 1),
            self.tool.replace("len(set(references)) != 3", "False", 1),
            self.tool.replace(
                "add_mutually_exclusive_group(required=True)",
                "add_mutually_exclusive_group(required=False)",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assertNotEqual(mutation, self.tool)
                self.assertTrue(self.validate(tool=mutation))

    def test_runtime_and_mutation_capabilities_are_rejected(self) -> None:
        mutations = (
            self.tool + "\nimport subprocess\n",
            self.tool + "\nsubprocess.run(['true'])\n",
            self.tool + "\nkubectl('get', 'pods')\n",
            self.tool + "\ndocker('inspect')\n",
            self.tool + "\nmaterialize_private_secret_bytes(b'x')\n",
            self.tool + "\ncleanup_private_secret_residue_from_inventory('x')\n",
            self.tool + "\ngenerate()\n",
            self.tool + "\ncreate()\n",
            self.tool + "\nPath('x').write_text('x')\n",
        )
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(self.validate(tool=mutation))

    def test_authenticated_or_production_semantic_overclaims_are_rejected(self) -> None:
        for claimed in ("verified", "attested"):
            mutation = self.tool.replace(
                "origin-authentication=unverified", f"origin-authentication={claimed}", 1
            )
            with self.subTest(claimed=claimed):
                self.assertTrue(self.validate(tool=mutation))
        mutation = self.tool.replace(
            "production_acceptance=false", "production_acceptance=True", 1
        )
        self.assertTrue(self.validate(tool=mutation))

    def test_runtime_policy_is_exact_and_declaration_only(self) -> None:
        original = json.loads(self.policy)
        mutations: list[dict[str, object]] = []
        for field, value in (
            ("policy_effect", "runtime_enforced"),
            ("production_acceptance", True),
            ("platform", "any"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["cleanup"]["bulk_cleanup"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["cleanup"]["age_or_pid_heuristics"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["cleanup"]["secure_erasure_claimed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["claim"]["exact_entries"] = ["secret"]
        mutations.append(changed)
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(self.validate(policy=_render(mutation)))

    def test_duplicate_policy_key_is_rejected(self) -> None:
        mutation = self.policy.replace(
            b'"schema_version": 1,',
            b'"schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.assertTrue(self.validate(policy=mutation))

    def test_template_must_be_pending_redacted_and_canonically_sealed(self) -> None:
        original = json.loads(self.template)
        mutations: list[bytes] = []
        for field, value in (
            ("synthetic", False),
            ("evidence_status", "reviewed"),
            ("origin_authentication", "verified"),
            ("production_acceptance", True),
            ("attempt_id", "attempt-claimed"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            mutations.append(_seal(changed))
        changed = copy.deepcopy(original)
        changed["prohibited_content"]["contains_raw_logs"] = True
        mutations.append(_seal(changed))
        changed = copy.deepcopy(original)
        changed["prohibited_content"].pop("contains_kubeconfig")
        mutations.append(_seal(changed))
        changed = copy.deepcopy(original)
        changed["extra"] = False
        mutations.append(_seal(changed))
        changed = copy.deepcopy(original)
        changed["integrity"]["payload_sha256"] = "0" * 64
        mutations.append(_render(changed))
        for mutation in mutations:
            with self.subTest():
                self.assertTrue(self.validate(template=mutation))

    def test_static_assets_have_bounded_load_limits(self) -> None:
        self.assertLessEqual(TOOL.stat().st_size, MAX_TOOL_BYTES)
        self.assertLessEqual(POLICY.stat().st_size, MAX_ASSET_BYTES)
        self.assertLessEqual(TEMPLATE.stat().st_size, MAX_ASSET_BYTES)


if __name__ == "__main__":
    unittest.main()
