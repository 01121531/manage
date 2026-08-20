import copy
import unittest

from scripts.verify_container_supply_chain import (
    DOCKERFILES,
    load_workflows,
    validate_supply_chain,
)


class ContainerSupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.security, self.release = load_workflows()
        self.dockerfiles = tuple(path.read_text(encoding="utf-8") for path in DOCKERFILES)

    def validate(self) -> list[str]:
        return validate_supply_chain(self.security, self.release, self.dockerfiles)

    @staticmethod
    def step(job, name):
        return next(step for step in job["steps"] if step.get("name") == name)

    def test_repository_supply_chain_is_fail_closed(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_trivy_exit_zero_is_rejected(self) -> None:
        self.security = copy.deepcopy(self.security)
        job = self.security["jobs"]["container-supply-chain"]
        self.step(job, "Trivy HIGH/CRITICAL image gate")["with"]["exit-code"] = "0"

        errors = self.validate()

        self.assertTrue(any("exit-code 1" in error for error in errors), errors)

    def test_release_push_before_scan_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        steps = job["steps"]
        push = self.step(job, "Push the exact scanned image")
        steps.remove(push)
        steps.insert(2, push)

        errors = self.validate()

        self.assertTrue(any("in order" in error for error in errors), errors)

    def test_windows_release_without_container_dependency_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        self.release["jobs"]["verified-windows-release"]["needs"] = ["release-quality-gate"]

        errors = self.validate()

        self.assertTrue(any("Windows release must wait" in error for error in errors), errors)

    def test_unpinned_action_is_rejected(self) -> None:
        self.security = copy.deepcopy(self.security)
        job = self.security["jobs"]["container-supply-chain"]
        self.step(job, "Generate Syft SPDX SBOM")["uses"] = "anchore/sbom-action@v0"

        errors = self.validate()

        self.assertTrue(any("not commit-pinned" in error for error in errors), errors)

    def test_missing_cosign_sbom_attestation_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        step = self.step(job, "Keyless-sign image and attach Syft SBOM")
        step["run"] = step["run"].replace("cosign attest", "echo attest")

        errors = self.validate()

        self.assertTrue(any("cosign attest" in error for error in errors), errors)

    def test_mutable_base_image_is_rejected(self) -> None:
        dockerfiles = list(self.dockerfiles)
        dockerfiles[0] = dockerfiles[0].replace("@sha256:", "#sha256:", 1)
        self.dockerfiles = tuple(dockerfiles)

        errors = self.validate()

        self.assertTrue(any("base images must be pinned" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
