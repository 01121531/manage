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
from scripts import target_intake_runtime_attestation_release_handoff as handoff


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def jsonl(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


class RuntimeAttestationReleaseHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.repository = "example/email-1"
        self.commit = "c" * 40
        self.tag = "v1.2.3"
        self.run_id = "10001"
        self.run_attempt = 2
        self.indexes: dict[str, bytes] = {}
        for ordinal, name in enumerate(handoff.EXPECTED_NAMES, start=1):
            self._write_image(name, ordinal)
        self.handoff_path = self.root / "runtime-attestation.release-handoff.json"
        self.handoff_value = {
            "evidence": [
                {
                    "manifest_path": f"{name}.runtime-attestation.external-evidence-index.json",
                    "manifest_sha256": hashlib.sha256(self.indexes[name]).hexdigest(),
                    "name": name,
                }
                for name in handoff.EXPECTED_NAMES
            ],
            "evidence_kind": handoff.HANDOFF_KIND,
            "production_acceptance": False,
            "release": {
                "commit": self.commit,
                "owner_id": "67890",
                "repository": self.repository,
                "repository_id": "12345",
                "run_attempt": self.run_attempt,
                "run_id": self.run_id,
                "tag": self.tag,
                "workflow_ref": f"{self.repository}/.github/workflows/release.yml@refs/tags/{self.tag}",
            },
            "requirements": copy.deepcopy(handoff._REQUIREMENTS),
            "schema_version": 1,
            "synthetic": False,
        }
        self._write_handoff()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_image(self, name: str, ordinal: int, *, run_id: str | None = None) -> None:
        image = f"ghcr.io/{self.repository}-{name}"
        oci_raw = (
            b'{"config":{"digest":"sha256:'
            + str(ordinal).encode("ascii") * 64
            + b'"},"schemaVersion":2}\n'
        )
        digest = "sha256:" + hashlib.sha256(oci_raw).hexdigest()
        cosign_payload = canonical({
            "critical": {
                "identity": {"docker-reference": image},
                "image": {"docker-manifest-digest": digest},
                "type": "cosign container image signature",
            },
            "optional": None,
        })
        statement = canonical({
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {"buildDefinition": {"externalParameters": {}}},
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{
                "digest": {"sha256": digest.removeprefix("sha256:")},
                "name": image,
            }],
        })
        github_bundle = jsonl({
            "dsseEnvelope": {
                "payload": base64.b64encode(statement).decode("ascii"),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"keyid": "", "sig": base64.b64encode(b"signature").decode("ascii")}],
            },
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {},
        })
        contents = {
            "oci_manifest": oci_raw,
            "cosign_bundle": b"{}\n",
            "cosign_payload": cosign_payload,
            "github_bundle": github_bundle,
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
        for artifact_name, suffix, _ in external.ARTIFACT_SPECS:
            (self.root / f"{name}.{suffix}").write_bytes(contents[artifact_name])
        manifest = self.root / f"{name}.runtime-attestation.external-evidence-index.json"
        manifest.unlink(missing_ok=True)
        args = argparse.Namespace(
            evidence_dir=str(self.root),
            output=str(manifest),
            name=name,
            image=image,
            digest=digest,
            repository=self.repository,
            repository_id="12345",
            owner_id="67890",
            workflow_ref=f"{self.repository}/.github/workflows/release.yml@refs/tags/{self.tag}",
            run_id=self.run_id if run_id is None else run_id,
            run_attempt=self.run_attempt,
            commit=self.commit,
            tag=self.tag,
            captured_at=f"2026-08-30T01:02:0{ordinal}Z",
        )
        raw = creator.create_index(args)
        manifest.write_bytes(raw)
        self.indexes[name] = raw

    def _write_handoff(self) -> bytes:
        raw = canonical(self.handoff_value)
        self.handoff_path.write_bytes(raw)
        self.handoff_raw = raw
        return raw

    def verify(self):
        return handoff.verify_release_handoff(
            self.handoff_path,
            self.root,
            expected_handoff_sha256=hashlib.sha256(self.handoff_raw).hexdigest(),
            expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
        )

    def test_three_indexes_bind_one_release_without_claiming_authority(self) -> None:
        result = self.verify()
        self.assertEqual([item[0] for item in result.images], list(handoff.EXPECTED_NAMES))
        self.assertTrue(result.cross_image_release_binding_verified)
        self.assertFalse(result.original_execution_verified)
        self.assertFalse(result.runtime_authority_verified)
        self.assertFalse(result.production_acceptance)

    def test_handoff_pin_fails_before_child_verification(self) -> None:
        with mock.patch.object(handoff, "verify_external_evidence") as verifier:
            with self.assertRaisesRegex(handoff.RuntimeAttestationReleaseHandoffError, "handoff pin"):
                handoff.verify_release_handoff(
                    self.handoff_path,
                    self.root,
                    expected_handoff_sha256="f" * 64,
                    expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
                )
        verifier.assert_not_called()

    def test_handoff_is_closed_canonical_ordered_and_negative(self) -> None:
        mutations = (
            lambda value: value.update(extra=False),
            lambda value: value.__setitem__("production_acceptance", True),
            lambda value: value["requirements"].__setitem__("runtime_authority", "verified"),
            lambda value: value["evidence"].reverse(),
            lambda value: value["evidence"].pop(),
            lambda value: value["evidence"][0].update(extra=False),
        )
        original = copy.deepcopy(self.handoff_value)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.handoff_value = copy.deepcopy(original)
                mutation(self.handoff_value)
                self._write_handoff()
                with self.assertRaises(handoff.RuntimeAttestationReleaseHandoffError):
                    self.verify()
        self.handoff_value = original
        compact = json.dumps(original, separators=(",", ":")).encode("ascii")
        self.handoff_path.write_bytes(compact)
        self.handoff_raw = compact
        with self.assertRaisesRegex(handoff.RuntimeAttestationReleaseHandoffError, "handoff is invalid"):
            self.verify()

    def test_cross_image_run_drift_fails_even_with_updated_index_pin(self) -> None:
        self._write_image("web", 2, run_id="10002")
        self.handoff_value["evidence"][1]["manifest_sha256"] = hashlib.sha256(
            self.indexes["web"]
        ).hexdigest()
        self._write_handoff()
        with self.assertRaisesRegex(handoff.RuntimeAttestationReleaseHandoffError, "cross-image"):
            self.verify()

    def test_wrong_image_name_and_child_bytes_fail(self) -> None:
        index_path = self.root / "edge.runtime-attestation.external-evidence-index.json"
        value = json.loads(index_path.read_bytes())
        value["release"]["image"] = f"ghcr.io/{self.repository}-api"
        raw = canonical(value)
        index_path.write_bytes(raw)
        self.handoff_value["evidence"][2]["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        self._write_handoff()
        with self.assertRaises(handoff.RuntimeAttestationReleaseHandoffError):
            self.verify()

        self._write_image("edge", 3)
        self.handoff_value["evidence"][2]["manifest_sha256"] = hashlib.sha256(
            self.indexes["edge"]
        ).hexdigest()
        (self.root / "edge.cosign.payload.json").write_bytes(b"{}\n")
        self._write_handoff()
        with self.assertRaisesRegex(handoff.RuntimeAttestationReleaseHandoffError, "index verification"):
            self.verify()

    def test_handoff_must_be_external_single_link_direct_child(self) -> None:
        with self.assertRaisesRegex(handoff.RuntimeAttestationReleaseHandoffError, "root"):
            handoff.verify_release_handoff(
                external.POLICY,
                external.ROOT,
                expected_handoff_sha256="f" * 64,
                expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
            )
        alias = self.root / "alias.json"
        self.handoff_path.unlink()
        os.link(self.root / "api.runtime-attestation.external-evidence-index.json", alias)
        with self.assertRaises(handoff.RuntimeAttestationReleaseHandoffError):
            handoff.verify_release_handoff(
                alias,
                self.root,
                expected_handoff_sha256=hashlib.sha256(alias.read_bytes()).hexdigest(),
                expected_policy_sha256=external.EXPECTED_POLICY_SHA256,
            )

    def test_cli_keeps_external_authority_negative(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = handoff.main([
                "--handoff-manifest", str(self.handoff_path),
                "--evidence-root", str(self.root),
                "--expected-handoff-sha256", hashlib.sha256(self.handoff_raw).hexdigest(),
                "--expected-policy-sha256", external.EXPECTED_POLICY_SHA256,
            ])
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("cross-image-release-binding=verified", stdout.getvalue())
        self.assertIn("target-observer=unverified", stdout.getvalue())
        self.assertIn("runtime-authority=unverified", stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
