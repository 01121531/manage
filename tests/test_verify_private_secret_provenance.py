from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest

from scripts import verify_private_secret_provenance as verifier


ROOT = Path(__file__).resolve().parents[1]


def _raw(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _sealed(document: dict[str, object]) -> bytes:
    value = copy.deepcopy(document)
    payload = {key: item for key, item in value.items() if key != "integrity"}
    value["integrity"] = {"payload_sha256": verifier._canonical_digest(payload)}
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


class PrivateSecretProvenanceStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.github_source = _text("scripts/private_secret_github_attestation.py")
        cls.target_source = _text("scripts/private_secret_target_provenance.py")
        cls.t140_source = _text("scripts/private_secret_crash_evidence.py")
        cls.github_policy = _raw("deploy/github-attestation-trust-policy.synthetic.json")
        cls.github_template = _raw(
            "deploy/evidence-index-envelopes/private-secret-github-origin.synthetic.json"
        )
        cls.target_policy = _raw("deploy/private-secret-target-provenance-policy.json")
        cls.target_template = _raw(
            "deploy/evidence-index-envelopes/private-secret-target-origin.synthetic.json"
        )

    def errors(self, **changes: object) -> list[str]:
        values: dict[str, object] = {
            "github_source": self.github_source,
            "target_source": self.target_source,
            "t140_source": self.t140_source,
            "github_policy_raw": self.github_policy,
            "github_template_raw": self.github_template,
            "target_policy_raw": self.target_policy,
            "target_template_raw": self.target_template,
        }
        values.update(changes)
        return verifier.validate_assets(**values)  # type: ignore[arg-type]

    def assert_mutation_rejected(self, **changes: object) -> None:
        errors = self.errors(**changes)
        self.assertTrue(errors, changes)

    def test_repository_assets_and_cli_are_safe_by_default(self) -> None:
        self.assertEqual([], self.errors())
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = verifier.main()
        self.assertEqual(0, result, stderr.getvalue())
        self.assertEqual(
            "private-secret-provenance-static-ok "
            "github-policy=unconfigured target-policy=unconfigured "
            "origin-authentication=unverified production_acceptance=false\n",
            stdout.getvalue(),
        )

    def test_both_callers_must_pin_the_raw_policy_digest(self) -> None:
        github_mutations = (
            self.github_source.replace("expected_policy_sha256: str,", "expected_policy_sha256: str | None = None,", 1),
            self.github_source.replace("_digest(expected_policy_sha256)", 'origin["trust_policy"]["artifact_sha256"]', 1),
            self.github_source.replace("policy_blob.sha256", "origin_blob.sha256"),
            self.github_source.replace('verify.add_argument("--expected-policy-sha256", required=True)', 'verify.add_argument("--expected-policy-sha256")', 1),
        )
        for changed in github_mutations:
            with self.subTest(scope="github", mutation=changed[:80]):
                self.assert_mutation_rejected(github_source=changed)

        target_mutations = (
            self.target_source.replace("expected_policy_sha256: str,", "expected_policy_sha256: str | None = None,", 1),
            self.target_source.replace("_digest(expected_policy_sha256)", '_digest(payload["trust_policy_sha256"])', 1),
            self.target_source.replace(
                "return policy, hashlib.sha256(raw).hexdigest()",
                "return policy, _canonical_digest(policy)",
                1,
            ),
            self.target_source.replace(
                "not hmac.compare_digest(policy_digest, expected_policy_sha256)",
                'not hmac.compare_digest(policy_digest, payload["trust_policy_sha256"])',
                1,
            ),
            self.target_source.replace('verify.add_argument("--expected-policy-sha256", required=True)', 'verify.add_argument("--expected-policy-sha256")', 1),
        )
        for changed in target_mutations:
            with self.subTest(scope="target", mutation=changed[:80]):
                self.assert_mutation_rejected(target_source=changed)

    def test_scope_schemas_domains_and_entrypoints_cannot_be_confused(self) -> None:
        mutations = (
            {
                "github_source": self.github_source.replace(
                    'EVIDENCE_KIND = "private_secret_github_origin_intake"',
                    'EVIDENCE_KIND = "private_secret_target_origin_intake"',
                    1,
                )
            },
            {
                "target_source": self.target_source.replace(
                    '_STORAGE_DOMAIN = b"email-platform/private-secret-target-origin/storage-signer/v1\\0"',
                    '_STORAGE_DOMAIN = b"email-platform/private-secret-target-origin/target-signer/v1\\0"',
                    1,
                )
            },
            {
                "github_source": self.github_source + "\nimport scripts.private_secret_target_provenance\n"
            },
            {
                "target_source": self.target_source + "\nimport scripts.private_secret_github_attestation\n"
            },
            {
                "github_source": self.github_source.replace(
                    "def verify_authenticated(", "def verify_target_origin(", 1
                )
            },
            {
                "target_source": self.target_source.replace(
                    "def verify_target_origin(", "def verify_authenticated(", 1
                )
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_rejected(**mutation)

    def test_embedded_key_algorithm_selection_and_private_signing_fail(self) -> None:
        signature_fallback = self.target_source.replace(
            '_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}',
            '_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url", "public_key_b64url"}',
            1,
        )
        algorithm_fallback = self.target_source.replace(
            'anchor["algorithm"] != "Ed25519"',
            'anchor["algorithm"] not in {"Ed25519", "ES256"}',
            1,
        )
        signing = self.target_source + (
            "\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 "
            "import Ed25519PrivateKey\n"
            "def _forbidden_signing(payload):\n"
            "    return Ed25519PrivateKey.generate().sign(payload)\n"
        )
        for changed in (signature_fallback, algorithm_fallback, signing):
            with self.subTest(mutation=changed[-120:]):
                self.assert_mutation_rejected(target_source=changed)

    def test_network_and_process_capabilities_are_fail_closed(self) -> None:
        for field, changed in (
            ("github_source", self.github_source + "\nimport socket\n"),
            ("target_source", self.target_source + "\nimport requests\n"),
            (
                "target_source",
                self.target_source
                + "\nimport subprocess\ndef _forbidden_process():\n    subprocess.run(['gh'])\n",
            ),
        ):
            with self.subTest(field=field):
                self.assert_mutation_rejected(**{field: changed})

    def test_github_wrapper_has_one_exact_non_shell_gh_command(self) -> None:
        mutations = (
            self.github_source.replace("shell=False", "shell=True", 1),
            self.github_source.replace('"attestation",\n                "verify",', '"attestation",\n                "download",', 1),
            self.github_source.replace('"--cert-identity",', '"--cert-identity-regex",', 1),
            self.github_source.replace('"--repo",', '"--owner",', 1),
            self.github_source.replace("env=dict(environment)", "env=dict(os.environ)", 1),
            self.github_source.replace("timeout=timeout_seconds", "timeout=None", 1),
            self.github_source.replace(
                "completed = subprocess.run(",
                "subprocess.run(list(arguments), shell=False)\n        completed = subprocess.run(",
                1,
            ),
        )
        for changed in mutations:
            self.assertNotEqual(self.github_source, changed)
            with self.subTest(mutation=changed[changed.find("subprocess.run"):][:100]):
                self.assert_mutation_rejected(github_source=changed)

    def test_github_child_consumes_the_same_sealed_snapshot(self) -> None:
        mutations = (
            self.github_source.replace("fcntl.F_SEAL_WRITE", "0", 1),
            self.github_source.replace(
                "flags=allow_sealing | close_on_exec", "flags=0", 1
            ),
            self.github_source.replace('sys.platform != "linux"', "False", 1),
            self.github_source.replace(
                "os.chmod(directory, 0o500)", "os.chmod(directory, 0o700)", 1
            ),
            self.github_source.replace(
                "executable=executable_blob.raw",
                "executable=executable_blob.path",
                1,
            ),
            self.github_source.replace(
                "str(snapshot.subject)", "str(subject_blob.path)", 1
            ),
            self.github_source.replace(
                "str(snapshot.bundle)", "str(bundle_blob.path)", 1
            ),
            self.github_source.replace(
                "str(snapshot.trusted_root)", "str(root_blob.path)", 1
            ),
            self.github_source.replace("pass_fds=snapshot.pass_fds,", "", 1),
            self.github_source.replace(
                "crash_evidence.verify_evidence_snapshot(",
                "crash_evidence.verify_evidence(",
                1,
            ),
            self.github_source.replace(
                "t140_snapshot.evidence_artifact_sha256",
                "subject_blob.sha256",
                1,
            ),
            self.github_source
            + '\ndef _forbidden_extra_delete(path):\n    Path(path).unlink()\n',
        )
        for changed in mutations:
            self.assertNotEqual(self.github_source, changed)
            with self.subTest(mutation=changed[:80]):
                self.assert_mutation_rejected(github_source=changed)

    def test_target_requires_two_distinct_worm_signer_roles(self) -> None:
        mutations = (
            self.target_source.replace('role="storage_signer"', 'role="target_signer"', 1),
            self.target_source.replace(
                '"provider_receipt_artifact_sha256",\n', "", 1
            ),
            self.target_source.replace(
                '"delete_probe_artifact_sha256",\n', "", 1
            ),
            self.target_source.replace(
                '"immutable_version_reference",\n', "", 1
            ),
            self.target_source.replace(
                'hmac.compare_digest(target_signature["key_id"], storage_signature["key_id"])',
                "False",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest(mutation=changed[:80]):
                self.assert_mutation_rejected(target_source=changed)

        policy = json.loads(self.target_policy)
        policy["storage_signer"]["usage_scope"] = policy["target_signer"]["usage_scope"]
        self.assert_mutation_rejected(
            target_policy_raw=json.dumps(policy).encode("utf-8")
        )

    def test_pending_assets_reject_self_configured_or_fail_open_state(self) -> None:
        target_policy = json.loads(self.target_policy)
        target_policy["state"] = "pinned"
        target_policy["target_signer"].update(
            {
                "state": "pinned",
                "key_id": "ed25519-sha256:" + "1" * 64,
                "public_key_b64url": "A" * 43,
            }
        )
        target_policy["storage_signer"].update(
            {
                "state": "pinned",
                "key_id": "ed25519-sha256:" + "2" * 64,
                "public_key_b64url": "B" * 43,
            }
        )
        self.assert_mutation_rejected(
            target_policy_raw=json.dumps(target_policy).encode("utf-8")
        )

        github_policy = json.loads(self.github_policy)
        github_policy["synthetic"] = False
        github_policy["policy_status"] = "reviewed"
        github_policy["repository"] = {"self_declared": True}
        self.assert_mutation_rejected(github_policy_raw=_sealed(github_policy))

        github_template = json.loads(self.github_template)
        github_template["origin_authentication"] = "verified"
        self.assert_mutation_rejected(github_template_raw=_sealed(github_template))

        target_template = json.loads(self.target_template)
        target_template["production_acceptance"] = True
        self.assert_mutation_rejected(target_template_raw=_sealed(target_template))

    def test_t140_and_status_axes_cannot_be_upgraded_in_place(self) -> None:
        changed_t140 = self.t140_source.replace(
            "status=reviewed-assertion origin-authentication=unverified",
            "status=reviewed-assertion origin-authentication=authenticated",
            1,
        )
        self.assert_mutation_rejected(t140_source=changed_t140)

        github = self.github_source.replace(
            "runtime-facts=reviewed-assertion target-host=unverified",
            "runtime-facts=verified target-host=verified",
            1,
        )
        self.assert_mutation_rejected(github_source=github)
        for axis in (
            "freshness",
            "replay-protection",
            "durability",
            "reviewer-independence",
            "job-binding",
            "rest-snapshot",
        ):
            with self.subTest(scope="github", axis=axis):
                self.assert_mutation_rejected(
                    github_source=self.github_source.replace(
                        f"{axis}=unverified", f"{axis}=verified", 1
                    )
                )

        target = self.target_source.replace(
            "provider-receipt-authenticated=true",
            "provider-receipt-authenticated=false",
            1,
        )
        self.assert_mutation_rejected(target_source=target)
        for axis in (
            "freshness",
            "replay-protection",
            "durability",
            "reviewer-independence",
        ):
            with self.subTest(axis=axis):
                self.assert_mutation_rejected(
                    target_source=self.target_source.replace(
                        f"{axis}=unverified", f"{axis}=verified", 1
                    )
                )
        self.assert_mutation_rejected(
            target_source=self.target_source.replace(
                "production_acceptance=false not_committed_eligible=false",
                "production_acceptance=true not_committed_eligible=true",
                1,
            )
        )

    def test_duplicate_unknown_and_unsealed_json_are_rejected(self) -> None:
        duplicate = self.github_policy.replace(
            b'{\n  "schema_version": 1,',
            b'{\n  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.assert_mutation_rejected(github_policy_raw=duplicate)

        value = json.loads(self.target_template)
        value["authenticated"] = True
        self.assert_mutation_rejected(target_template_raw=_sealed(value))

        value = json.loads(self.github_template)
        value["integrity"]["payload_sha256"] = "0" * 64
        self.assert_mutation_rejected(
            github_template_raw=json.dumps(value).encode("utf-8")
        )


if __name__ == "__main__":
    unittest.main()
