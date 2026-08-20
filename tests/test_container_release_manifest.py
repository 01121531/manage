import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.create_container_release_manifest import build_manifest, load_manifest, verify_manifest


TAG = "v1.2.3"
COMMIT = "a" * 40


def write_evidence(directory: Path, name: str) -> None:
    sbom = b'{"spdxVersion":"SPDX-2.3"}\n'
    trivy = b'{"version":"2.1.0","runs":[]}\n'
    (directory / f"{name}.spdx.json").write_bytes(sbom)
    (directory / f"{name}.trivy.sarif").write_bytes(trivy)
    metadata = {
        "schema_version": 1,
        "name": name,
        "image": f"ghcr.io/example/manage-{name}",
        "tag": TAG,
        "commit": COMMIT,
        "digest": "sha256:" + "b" * 64,
        "sbom": {
            "file": f"{name}.spdx.json",
            "sha256": hashlib.sha256(sbom).hexdigest(),
        },
        "scan": {
            "tool": "trivy",
            "severities": ["HIGH", "CRITICAL"],
            "result": "passed",
            "file": f"{name}.trivy.sarif",
            "sha256": hashlib.sha256(trivy).hexdigest(),
        },
        "signature": {
            "issuer": "https://token.actions.githubusercontent.com",
            "identity": f"https://github.com/example/manage/.github/workflows/release.yml@refs/tags/{TAG}",
        },
        "attestations": ["cosign-spdxjson", "github-build-provenance"],
    }
    (directory / f"{name}.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


class ContainerReleaseManifestTests(unittest.TestCase):
    @staticmethod
    def build_complete_manifest(directory: Path) -> dict[str, object]:
        for name in ("api", "web", "edge"):
            write_evidence(directory, name)
        return build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_builds_manifest_only_for_complete_verified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            manifest = self.build_complete_manifest(directory)

        self.assertEqual(set(manifest["images"]), {"api", "web", "edge"})
        self.assertEqual(manifest["images"]["api"]["digest"], "sha256:" + "b" * 64)
        self.assertRegex(manifest["migration_head"], r"^[0-9]{4}_[a-z0-9_]+$")

    def test_loads_manifest_bound_to_expected_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            manifest = self.build_complete_manifest(directory)
            path = directory / "container-release-manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            loaded = load_manifest(
                path,
                expected_tag=TAG,
                expected_commit=COMMIT,
                expected_migration_head=manifest["migration_head"],
            )

        self.assertEqual(loaded, manifest)

    def test_rejects_local_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in ("api", "web", "edge"):
                write_evidence(directory, name)

            with self.assertRaisesRegex(ValueError, "release tag"):
                build_manifest(directory, tag="local/tag", commit=COMMIT)

    def test_verify_rejects_missing_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = self.build_complete_manifest(Path(temp_dir))
            del manifest["images"]["edge"]

            with self.assertRaisesRegex(ValueError, "exactly api, web, and edge"):
                verify_manifest(manifest)

    def test_verify_rejects_wrong_expected_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = self.build_complete_manifest(Path(temp_dir))

            with self.assertRaisesRegex(ValueError, "expected commit"):
                verify_manifest(manifest, expected_commit="c" * 40)

            with self.assertRaisesRegex(ValueError, "expected head"):
                verify_manifest(manifest, expected_migration_head="9999_wrong_head")

    def test_verify_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = self.build_complete_manifest(Path(temp_dir))
            manifest["unexpected"] = True

            with self.assertRaisesRegex(ValueError, "invalid manifest fields"):
                verify_manifest(manifest)

            del manifest["unexpected"]
            manifest["images"]["api"]["signature"]["untrusted"] = True
            with self.assertRaisesRegex(ValueError, "invalid signature metadata: api fields"):
                verify_manifest(manifest)

    def test_rejects_missing_edge_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in ("api", "web"):
                write_evidence(directory, name)

            with self.assertRaisesRegex(ValueError, "exactly api, web, and edge"):
                build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_rejects_tampered_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in ("api", "web", "edge"):
                write_evidence(directory, name)
            (directory / "web.spdx.json").write_bytes(b"tampered")

            with self.assertRaisesRegex(ValueError, "SBOM hash mismatch: web"):
                build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_rejects_tampered_trivy_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in ("api", "web", "edge"):
                write_evidence(directory, name)
            (directory / "edge.trivy.sarif").write_bytes(b"tampered")

            with self.assertRaisesRegex(ValueError, "Trivy scan hash mismatch: edge"):
                build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_rejects_unsigned_or_wrong_workflow_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in ("api", "web", "edge"):
                write_evidence(directory, name)
            path = directory / "api.metadata.json"
            metadata = json.loads(path.read_text(encoding="utf-8"))
            metadata["signature"]["identity"] = "https://github.com/example/other"
            path.write_text(json.dumps(metadata), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid signature identity: api"):
                build_manifest(directory, tag=TAG, commit=COMMIT)


if __name__ == "__main__":
    unittest.main()
