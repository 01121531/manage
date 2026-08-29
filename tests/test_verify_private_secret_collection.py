from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest

from scripts import verify_private_secret_collection as verifier


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _raw(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _sealed(value: dict[str, object]) -> bytes:
    document = copy.deepcopy(value)
    payload = {key: item for key, item in document.items() if key != "integrity"}
    document["integrity"] = {"payload_sha256": verifier._canonical_digest(payload)}
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")


class PrivateSecretCollectionStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.github_source = _text("scripts/private_secret_github_rest_collection.py")
        cls.worm_source = _text("scripts/private_secret_worm_collection.py")
        cls.backed_source = _text(
            "scripts/private_secret_collection_backed_acceptance.py"
        )
        cls.github_policy = _raw("deploy/github-rest-collection-policy.synthetic.json")
        cls.github_template = _raw(
            "deploy/evidence-index-envelopes/private-secret-github-rest-collection.synthetic.json"
        )
        cls.worm_policy = _raw("deploy/private-secret-worm-collection-policy.synthetic.json")
        cls.worm_template = _raw(
            "deploy/evidence-index-envelopes/private-secret-worm-collection.synthetic.json"
        )

    def errors(self, **changes: object) -> list[str]:
        values: dict[str, object] = {
            "github_source": self.github_source,
            "worm_source": self.worm_source,
            "backed_source": self.backed_source,
            "github_policy_raw": self.github_policy,
            "github_template_raw": self.github_template,
            "worm_policy_raw": self.worm_policy,
            "worm_template_raw": self.worm_template,
        }
        values.update(changes)
        return verifier.validate_assets(**values)  # type: ignore[arg-type]

    def assert_mutation_rejected(self, **changes: object) -> None:
        self.assertTrue(self.errors(**changes), changes)

    def test_repository_assets_and_cli_are_fail_closed(self) -> None:
        self.assertEqual([], self.errors())
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = verifier.main()
        self.assertEqual(0, result, stderr.getvalue())
        self.assertEqual(
            "private-secret-collection-static-ok "
            "github-policy=unconfigured worm-policy=unconfigured "
            "provider-native=unverified trusted-time=unverified "
            "freshness=unverified replay-protection=unverified "
            "durability=unverified reviewer-independence=unverified "
            "job-artifact-causality=unverified production_acceptance=false "
            "not_committed_eligible=false\n",
            stdout.getvalue(),
        )

    def test_scopes_domains_and_anchors_cannot_be_confused(self) -> None:
        mutations = (
            {
                "github_source": self.github_source.replace(
                    'COLLECTOR_DOMAIN = "email-platform/private-secret-github-rest-collector/v1"',
                    'COLLECTOR_DOMAIN = "email-platform/private-secret-github-rest-replay-ledger/v1"',
                    1,
                )
            },
            {
                "worm_source": self.worm_source.replace(
                    '_LEDGER_DOMAIN = b"email-platform/private-secret-worm-audit/replay-checkpoint/v1\\0"',
                    '_LEDGER_DOMAIN = b"email-platform/private-secret-worm-audit/provider-observation/v1\\0"',
                    1,
                )
            },
            {
                "github_source": self.github_source.replace(
                    'EVIDENCE_KIND = "private_secret_github_rest_collection"',
                    'EVIDENCE_KIND = "private_secret_worm_collection"',
                    1,
                )
            },
            {
                "worm_source": self.worm_source.replace(
                    'role="ledger_signer"', 'role="provider_observer"', 1
                )
            },
            {
                "github_source": self.github_source.replace(
                    "hmac.compare_digest(collector.key_id, ledger.key_id)", "False", 1
                )
            },
            {
                "worm_source": self.worm_source.replace(
                    'hmac.compare_digest(provider_key or b"", ledger_key or b"")',
                    "False",
                    1,
                )
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = next(iter(mutation.values()))
                self.assertNotIn(changed, (self.github_source, self.worm_source))
                self.assert_mutation_rejected(**mutation)

    def test_all_caller_pins_are_required_and_not_self_derived(self) -> None:
        github_mutations = (
            self.github_source.replace(
                "expected_policy_sha256: str,",
                "expected_policy_sha256: str | None = None,",
                1,
            ),
            self.github_source.replace(
                "expected_policy_sha256, policy_blob.sha256",
                "request[\"trust_policy_sha256\"], policy_blob.sha256",
                1,
            ),
            self.github_source.replace(
                "receipt_blob = _bytes_blob(input_raw)",
                "expected_request_sha256 = request_blob.sha256\n    receipt_blob = _bytes_blob(input_raw)",
                1,
            ),
            self.github_source.replace(
                'verify.add_argument("--expected-previous-head-sha256", required=True)',
                'verify.add_argument("--expected-previous-head-sha256")',
                1,
            ),
            self.github_source.replace(
                'request["previous_head"]["expected_sequence"] != expected_sequence',
                "False",
                1,
            ),
            self.github_source.replace(
                "expected_github_origin_sha256, github_origin_blob.sha256",
                'request["github_origin"]["artifact_sha256"], github_origin_blob.sha256',
                1,
            ),
            self.github_source.replace(
                'request["github_origin"]["artifact_sha256"] != github_origin_blob.sha256',
                "False",
                1,
            ),
        )
        for changed in github_mutations:
            with self.subTest(scope="github"):
                self.assertNotEqual(self.github_source, changed)
                self.assert_mutation_rejected(github_source=changed)

        worm_mutations = (
            self.worm_source.replace(
                "expected_prior_head_sha256: str,",
                "expected_prior_head_sha256: str | None = None,",
                1,
            ),
            self.worm_source.replace(
                "hashlib.sha256(policy_raw).hexdigest(), expected_policy_sha256",
                "policy[\"integrity\"][\"payload_sha256\"], expected_policy_sha256",
                1,
            ),
            self.worm_source.replace(
                "_digest(expected_prior_head_sha256)",
                "expected_prior_head_sha256 = checkpoint[\"previous\"][\"artifact_sha256\"]",
                1,
            ),
            self.worm_source.replace(
                'verify.add_argument("--expected-ledger-id", required=True)',
                'verify.add_argument("--expected-ledger-id")',
                1,
            ),
        )
        for changed in worm_mutations:
            with self.subTest(scope="worm"):
                self.assertNotEqual(self.worm_source, changed)
                self.assert_mutation_rejected(worm_source=changed)

    def test_stable_single_read_and_path_alias_boundaries_are_locked(self) -> None:
        github_mutations = (
            self.github_source.replace("metadata.st_nlink != 1", "False", 1),
            self.github_source.replace(
                "_read_blob(input_path),",
                "_read_blob(input_path),\n        _read_blob(input_path),",
                1,
            ),
            self.github_source.replace("len(normalized) != len(paths)", "False", 1),
        )
        for changed in github_mutations:
            with self.subTest(scope="github"):
                self.assertNotEqual(self.github_source, changed)
                self.assert_mutation_rejected(github_source=changed)

        worm_mutations = (
            self.worm_source.replace("metadata.st_nlink != 1", "False", 1),
            self.worm_source.replace(
                '"policy_raw": _read_external_bytes(',
                '"duplicate_raw": _read_external_bytes(input_path, max_bytes=MAX_INTAKE_JSON_BYTES),\n        "policy_raw": _read_external_bytes(',
                1,
            ),
            self.worm_source.replace("len(normalized) != len(paths)", "False", 1),
        )
        for changed in worm_mutations:
            with self.subTest(scope="worm"):
                self.assertNotEqual(self.worm_source, changed)
                self.assert_mutation_rejected(worm_source=changed)

        backed_mutations = (
            self.backed_source.replace(
                "metadata.st_nlink != 1", "False", 1
            ),
            self.backed_source.replace(
                "_reject_duplicate_identities(all_blobs)", "pass", 1
            ),
            self.backed_source.replace(
                "expected_identity=blob.identity", "expected_identity=None", 1
            ),
            self.backed_source.replace(
                "github.verify_collection_bytes(", "github.verify_collection(", 1
            ),
            self.backed_source.replace(
                'worm_values["expected_runtime_policy_sha256"]', '"0" * 64', 1
            ),
        )
        for changed in backed_mutations:
            with self.subTest(scope="collection-backed"):
                self.assertNotEqual(self.backed_source, changed)
                self.assert_mutation_rejected(backed_source=changed)

    def test_network_process_private_signing_and_writes_are_forbidden(self) -> None:
        mutations = (
            {"github_source": self.github_source + "\nimport requests\n"},
            {"worm_source": self.worm_source + "\nimport boto3\n"},
            {
                "github_source": self.github_source
                + "\nimport subprocess\ndef forbidden():\n    subprocess.run(['gh'])\n"
            },
            {
                "worm_source": self.worm_source
                + "\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
                "def forbidden(raw):\n    return Ed25519PrivateKey.generate().sign(raw)\n"
            },
            {
                "github_source": self.github_source
                + "\ndef forbidden(path):\n    Path(path).write_text('x')\n"
            },
            {
                "worm_source": self.worm_source
                + "\ndef forbidden(client):\n    return client.delete('object')\n"
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_rejected(**mutation)

    def test_embedded_keys_and_algorithm_selection_are_forbidden(self) -> None:
        for field, source in (
            ("github_source", self.github_source),
            ("worm_source", self.worm_source),
        ):
            embedded = source.replace(
                '_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url"}',
                '_SIGNATURE_FIELDS = {"algorithm", "key_id", "value_b64url", "public_key_b64url"}',
                1,
            )
            algorithm = source.replace(
                'signature["algorithm"] != "Ed25519"',
                'signature["algorithm"] not in {"Ed25519", "ES256"}',
                1,
            )
            for changed in (embedded, algorithm):
                with self.subTest(field=field):
                    self.assertNotEqual(source, changed)
                    self.assert_mutation_rejected(**{field: changed})

    def test_replay_head_ledger_and_sequence_binding_cannot_be_removed(self) -> None:
        github_mutations = (
            self.github_source.replace(
                'previous_checkpoint["sequence"] != expected_sequence - 1', "False", 1
            ),
            self.github_source.replace(
                'checkpoint["sequence"] != expected_sequence', "False", 1
            ),
            self.github_source.replace(
                'request["previous_head"]["artifact_sha256"] != previous_blob.sha256',
                "False",
                1,
            ),
        )
        worm_mutations = (
            self.worm_source.replace(
                'checkpoint["sequence"] != expected_sequence', "False", 1
            ),
            self.worm_source.replace(
                "hashlib.sha256(prior_checkpoint_raw).hexdigest(), expected_prior_head_sha256",
                "hashlib.sha256(prior_checkpoint_raw).hexdigest(), previous[\"artifact_sha256\"]",
                1,
            ),
            self.worm_source.replace(
                'prior_checkpoint["sequence"] != expected_sequence - 1', "False", 1
            ),
            self.worm_source.replace(
                '"artifact_sha256": expected_prior_head_sha256',
                '"artifact_sha256": previous["artifact_sha256"]',
                1,
            ),
        )
        for field, source, mutations in (
            ("github_source", self.github_source, github_mutations),
            ("worm_source", self.worm_source, worm_mutations),
        ):
            for changed in mutations:
                with self.subTest(field=field):
                    self.assertNotEqual(source, changed)
                    self.assert_mutation_rejected(**{field: changed})

    def test_worm_object_and_readback_cannot_be_substituted(self) -> None:
        mutations = (
            self.worm_source.replace(
                "target_origin.storage_identity_fingerprint_sha256",
                'provider["storage_identity_fingerprint_sha256"]',
                1,
            ),
            self.worm_source.replace(
                'observed_object["object_reference"] != target_origin.object_reference',
                "False",
                1,
            ),
            self.worm_source.replace(
                "target_origin.immutable_version_reference",
                'observed_object["immutable_version_reference"]',
                1,
            ),
            self.worm_source.replace(
                'observed_object["content_sha256"] != target_origin.evidence_readback_sha256',
                "False",
                1,
            ),
            self.worm_source.replace(
                'deletion["post_denial_readback_sha256"] != target_origin.evidence_readback_sha256',
                "False",
                1,
            ),
            self.worm_source.replace(
                "hashlib.sha256(readback_raw).hexdigest() != target_origin.evidence_readback_sha256",
                "False",
                1,
            ),
        )
        for changed in mutations:
            self.assertNotEqual(self.worm_source, changed)
            self.assert_mutation_rejected(worm_source=changed)

    def test_unproved_axes_and_acceptance_cannot_be_upgraded(self) -> None:
        for axis in (
            "job-artifact-causality",
            "provider-native",
            "trusted-time",
            "freshness",
            "replay-protection",
            "durability",
            "reviewer-independence",
        ):
            changed = self.github_source.replace(f"{axis}=unverified", f"{axis}=verified", 1)
            with self.subTest(scope="github", axis=axis):
                self.assertNotEqual(self.github_source, changed)
                self.assert_mutation_rejected(github_source=changed)
        for axis in (
            "provider-native",
            "trusted-time",
            "freshness",
            "replay-protection",
            "durability",
            "reviewer-independence",
        ):
            changed = self.worm_source.replace(f"{axis}=unverified", f"{axis}=verified", 1)
            with self.subTest(scope="worm", axis=axis):
                self.assertNotEqual(self.worm_source, changed)
                self.assert_mutation_rejected(worm_source=changed)
        for field, source in (
            ("github_source", self.github_source),
            ("worm_source", self.worm_source),
        ):
            changed = source.replace(
                "production_acceptance=false", "production_acceptance=true", 1
            )
            self.assert_mutation_rejected(**{field: changed})
            changed = source.replace(
                "not_committed_eligible=false", "not_committed_eligible=true", 1
            )
            self.assert_mutation_rejected(**{field: changed})

    def test_synthetic_assets_remain_closed_pending_and_unconfigured(self) -> None:
        github_policy = json.loads(self.github_policy)
        github_policy["synthetic"] = False
        github_policy["policy_status"] = "reviewed"
        github_policy["collector"] = {"self_authored": True}
        self.assert_mutation_rejected(github_policy_raw=_sealed(github_policy))

        github_template = json.loads(self.github_template)
        github_template["production_acceptance"] = True
        self.assert_mutation_rejected(
            github_template_raw=json.dumps(github_template).encode("utf-8")
        )
        github_template = json.loads(self.github_template)
        github_template["claim_boundary"]["provider_native"] = "verified"
        self.assert_mutation_rejected(
            github_template_raw=json.dumps(github_template).encode("utf-8")
        )

        worm_policy = json.loads(self.worm_policy)
        worm_policy["provider_observer"].update(
            {
                "state": "pinned",
                "key_id": "ed25519-sha256:" + "1" * 64,
                "public_key_b64url": "A" * 43,
            }
        )
        self.assert_mutation_rejected(worm_policy_raw=_sealed(worm_policy))

        worm_template = json.loads(self.worm_template)
        worm_template["provider_observation_authentication"] = "verified"
        self.assert_mutation_rejected(worm_template_raw=_sealed(worm_template))

    def test_duplicate_unknown_and_integrity_drift_are_rejected(self) -> None:
        duplicate = self.github_policy.replace(
            b'{\n  "schema_version": 1,',
            b'{\n  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.assert_mutation_rejected(github_policy_raw=duplicate)

        worm = json.loads(self.worm_policy)
        worm["unknown"] = True
        self.assert_mutation_rejected(worm_policy_raw=_sealed(worm))

        worm_template = json.loads(self.worm_template)
        worm_template["integrity"]["payload_sha256"] = "0" * 64
        self.assert_mutation_rejected(
            worm_template_raw=json.dumps(worm_template).encode("utf-8")
        )


if __name__ == "__main__":
    unittest.main()
