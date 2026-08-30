from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import create_runtime_attestation_external_evidence_index as creator
from scripts import target_intake_runtime_attestation_external_evidence as external


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def jsonl(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


class RuntimeAttestationExternalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.name = "api"
        self.image = "ghcr.io/example/email-api"
        self.oci_raw = b'{"config":{"digest":"sha256:' + b"1" * 64 + b'"},"schemaVersion":2}\n'
        self.digest = "sha256:" + hashlib.sha256(self.oci_raw).hexdigest()
        self.cosign_payload = canonical({
            "critical": {
                "identity": {"docker-reference": self.image},
                "image": {"docker-manifest-digest": self.digest},
                "type": "cosign container image signature",
            },
            "optional": None,
        })
        statement = canonical({
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {"buildDefinition": {"externalParameters": {}}},
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{
                "digest": {"sha256": self.digest.removeprefix("sha256:")},
                "name": self.image,
            }],
        })
        self.github_bundle = jsonl({
            "dsseEnvelope": {
                "payload": base64.b64encode(statement).decode("ascii"),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"keyid": "", "sig": base64.b64encode(b"signature").decode("ascii")}],
            },
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {},
        })
        contents = {
            "oci_manifest": self.oci_raw,
            "cosign_bundle": b"{}\n",
            "cosign_payload": self.cosign_payload,
            "github_bundle": self.github_bundle,
            "github_sigstore_trusted_root": b"{}\n{}\n",
            "tuf_verify_result": b"exit_code=0\n",
            "cosign_executable_digest": ("a" * 64 + "  /usr/local/bin/cosign\n").encode("ascii"),
            "cosign_version": b"{}\n",
            "cosign_bundle_verify_result": b"Verified OK\n",
            "cosign_verify_result": b"[]\n",
            "cosign_verify_attestation_result": b"[]\n",
            "github_executable_digest": ("b" * 64 + "  /usr/bin/gh\n").encode("ascii"),
            "github_version": b"gh version 2.99.0\n",
            "github_verify_result": b"[]\n",
        }
        for name, suffix, _ in external.ARTIFACT_SPECS:
            (self.root / f"{self.name}.{suffix}").write_bytes(contents[name])
        self.manifest = self.root / f"{self.name}.runtime-attestation.external-evidence-index.json"
        self.args = argparse.Namespace(
            evidence_dir=str(self.root),
            output=str(self.manifest),
            name=self.name,
            image=self.image,
            digest=self.digest,
            repository="example/email-1",
            repository_id="12345",
            owner_id="67890",
            workflow_ref="example/email-1/.github/workflows/release.yml@refs/tags/v1.2.3",
            run_id="10001",
            run_attempt=1,
            commit="c" * 40,
            tag="v1.2.3",
            captured_at="2026-08-30T01:02:03Z",
        )
        self.manifest_raw = creator.create_index(self.args)
        self.manifest.write_bytes(self.manifest_raw)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self):
        return external.verify_external_evidence(
            self.manifest,
            self.root,
            expected_manifest_sha256=hashlib.sha256(self.manifest_raw).hexdigest(),
            expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
        )

    def rewrite_index(self, mutation) -> None:
        value = json.loads(self.manifest_raw)
        mutation(value)
        self.manifest_raw = canonical(value)
        self.manifest.write_bytes(self.manifest_raw)

    def regenerate_index(self) -> None:
        self.manifest.unlink(missing_ok=True)
        self.manifest_raw = creator.create_index(self.args)
        self.manifest.write_bytes(self.manifest_raw)

    def test_real_capture_index_authenticates_exact_subject_bindings_only(self) -> None:
        result = self.verify()
        self.assertTrue(result.exact_subject_bindings_verified)
        self.assertFalse(result.original_execution_verified)
        self.assertFalse(result.runtime_authority_verified)
        self.assertFalse(result.production_acceptance)
        self.assertEqual(result.digest, self.digest)

    def test_manifest_and_policy_pins_fail_before_index_parse(self) -> None:
        with mock.patch.object(external, "_parse_index") as parser:
            with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "manifest pin"):
                external.verify_external_evidence(
                    self.manifest, self.root,
                    expected_manifest_sha256="f" * 64,
                    expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
                )
        parser.assert_not_called()
        with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "policy pin"):
            external.verify_external_evidence(
                self.manifest, self.root,
                expected_manifest_sha256=hashlib.sha256(self.manifest_raw).hexdigest(),
                expected_policy_sha256="f" * 64,
            )

    def test_index_is_closed_canonical_and_cannot_claim_authority(self) -> None:
        for mutation in (
            lambda value: value.update(extra=True),
            lambda value: value.__setitem__("production_acceptance", True),
            lambda value: value["requirements"].__setitem__("runtime_authority", "verified"),
            lambda value: value["capture"].__setitem__("host_clock_trusted", True),
        ):
            with self.subTest(mutation=mutation):
                original = self.manifest_raw
                self.rewrite_index(mutation)
                with self.assertRaises(external.RuntimeAttestationExternalEvidenceError):
                    self.verify()
                self.manifest_raw = original
                self.manifest.write_bytes(original)
        compact = json.dumps(json.loads(self.manifest_raw), separators=(",", ":")).encode("ascii")
        self.manifest_raw = compact
        self.manifest.write_bytes(compact)
        with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "index is invalid"):
            self.verify()

    def test_policy_nested_fields_and_inventories_are_closed(self) -> None:
        policy = json.loads(external.POLICY.read_bytes())
        mutations = (
            lambda value: value["integration"].update(extra=False),
            lambda value: value["integration"].pop("authoring"),
            lambda value: value["provider_custody"].update(extra="unverified"),
            lambda value: value["provider_custody"]["allowed_provider_kinds"].reverse(),
            lambda value: value["provider_custody"]["required_evidence"].pop(),
            lambda value: value["release_evidence"].update(extra=True),
            lambda value: value["target_observer"].update(extra=False),
            lambda value: value["target_observer"]["required_evidence"].pop(),
            lambda value: value["trust_currentness"].update(extra=False),
            lambda value: value["trust_currentness"].pop("tuf_metadata_chain_required"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                drifted = copy.deepcopy(policy)
                mutation(drifted)
                raw = canonical(drifted)
                with self.assertRaises(external.RuntimeAttestationExternalEvidenceError):
                    external.verify_policy_bytes(
                        raw,
                        expected_sha256=hashlib.sha256(raw).hexdigest(),
                    )

    def test_raw_artifact_pin_size_and_identity_are_enforced(self) -> None:
        payload_path = self.root / f"{self.name}.cosign.payload.json"
        payload_path.write_bytes(self.cosign_payload + b" ")
        with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "artifact pin"):
            self.verify()
        payload_path.write_bytes(self.cosign_payload)
        alias = self.root / f"{self.name}.cosign.bundle.json"
        alias.unlink()
        os.link(payload_path, alias)
        self.regenerate_index()
        with self.assertRaises(external.RuntimeAttestationExternalEvidenceError):
            self.verify()

    def test_oci_cosign_and_github_subject_drift_fail(self) -> None:
        drifted_statement = canonical({
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {},
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"digest": {"sha256": self.digest.removeprefix("sha256:")}, "name": "ghcr.io/example/other"}],
        })
        drifted_bundle = jsonl({
            "dsseEnvelope": {
                "payload": base64.b64encode(drifted_statement).decode("ascii"),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [],
            },
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {},
        })
        cases = (
            ("oci_manifest", b"{}\n", "OCI manifest"),
            ("cosign_payload", self.cosign_payload.replace(self.digest.encode(), ("sha256:" + "f" * 64).encode()), "Cosign payload"),
            ("github_bundle", drifted_bundle, "GitHub"),
        )
        for name, raw, message in cases:
            with self.subTest(name=name):
                _, suffix, _ = next(item for item in external.ARTIFACT_SPECS if item[0] == name)
                path = self.root / f"{self.name}.{suffix}"
                original = path.read_bytes()
                path.write_bytes(raw)
                self.regenerate_index()
                with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, message):
                    self.verify()
                path.write_bytes(original)

    def test_manifest_and_evidence_must_be_external_and_direct_children(self) -> None:
        with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "root"):
            external.verify_external_evidence(
                external.POLICY, external.ROOT,
                expected_manifest_sha256="f" * 64,
                expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
            )
        nested = self.root / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(external.RuntimeAttestationExternalEvidenceError, "manifest"):
            external.verify_external_evidence(
                nested / self.manifest.name, self.root,
                expected_manifest_sha256="f" * 64,
                expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
            )

    def test_generator_refuses_existing_output_and_missing_artifact(self) -> None:
        with self.assertRaisesRegex(creator.ExternalEvidenceIndexError, "new direct child"):
            creator.create_index(self.args)
        self.manifest.unlink()
        missing = self.root / f"{self.name}.github.verify.json"
        missing.unlink()
        with self.assertRaises(OSError):
            creator.create_index(self.args)

    def test_cli_outputs_keep_negative_authority_boundary(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = external.main([
                "verify", "--manifest", str(self.manifest), "--evidence-root", str(self.root),
                "--expected-manifest-sha256", hashlib.sha256(self.manifest_raw).hexdigest(),
                "--expected-policy-sha256", external.EXPECTED_POLICY_SHA256,
            ])
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        output = stdout.getvalue()
        self.assertIn("subject-bindings=verified", output)
        self.assertIn("original-execution=unverified", output)
        self.assertIn("runtime-authority=unverified", output)
        self.assertIn("production_acceptance=false", output)


if __name__ == "__main__":
    unittest.main()
