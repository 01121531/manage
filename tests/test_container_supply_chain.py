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

    def test_trivy_continue_on_error_only_accepts_boolean_false(self) -> None:
        for unsafe in ("true", "${{ always() }}", None, 0, [True], {"value": True}):
            self.security = copy.deepcopy(load_workflows()[0])
            job = self.security["jobs"]["container-supply-chain"]
            self.step(job, "Trivy HIGH/CRITICAL image gate")[
                "continue-on-error"
            ] = unsafe

            with self.subTest(unsafe=unsafe):
                errors = self.validate()
                self.assertTrue(
                    any("continue on error" in error for error in errors), errors
                )

    def test_release_push_before_scan_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        steps = job["steps"]
        push = self.step(job, "Push scanned staging digest")
        steps.remove(push)
        steps.insert(2, push)

        errors = self.validate()

        self.assertTrue(any("in order" in error for error in errors), errors)

    def test_stable_release_tag_cannot_be_pushed_from_staging_step(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        staging = self.step(job, "Push scanned staging digest")
        staging["run"] += '\ndocker push "$IMAGE:${GITHUB_REF_NAME}"\n'

        errors = self.validate()

        self.assertTrue(any("must not be pushed" in error for error in errors), errors)

    def test_release_tag_cannot_precede_signature_verification(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        steps = job["steps"]
        promote = self.step(job, "Publish verified release tag")
        steps.remove(promote)
        verify_index = steps.index(
            self.step(job, "Verify keyless image signature and SBOM attestation")
        )
        steps.insert(verify_index, promote)

        errors = self.validate()

        self.assertTrue(any("in order" in error for error in errors), errors)

    def test_release_tag_must_confirm_the_verified_digest(self) -> None:
        self.release = copy.deepcopy(self.release)
        job = self.release["jobs"]["verified-container-release"]
        promote = self.step(job, "Publish verified release tag")
        promote["run"] = promote["run"].replace(
            '[[ "$published_digest" != "$DIGEST" ]]',
            '[[ -z "$published_digest" ]]',
            1,
        )

        errors = self.validate()

        self.assertTrue(any("release-tag promotion" in error for error in errors), errors)

    def test_release_tag_cannot_be_overwritten_or_raced(self) -> None:
        mutations = []
        missing_concurrency = copy.deepcopy(self.release)
        missing_concurrency.pop("concurrency")
        mutations.append(missing_concurrency)

        no_existing_digest_guard = copy.deepcopy(self.release)
        job = no_existing_digest_guard["jobs"]["verified-container-release"]
        promote = self.step(job, "Publish verified release tag")
        promote["run"] = promote["run"].replace(
            '[[ -z "$existing_digest" || "$existing_digest" != "$DIGEST" ]]',
            '[[ -z "$existing_digest" ]]',
            1,
        )
        mutations.append(no_existing_digest_guard)

        fail_open_inspection = copy.deepcopy(self.release)
        job = fail_open_inspection["jobs"]["verified-container-release"]
        promote = self.step(job, "Publish verified release tag")
        promote["run"] = promote["run"].replace(
            "manifest unknown|not found", "anything", 1
        ).replace(
            "Cannot safely determine whether the release tag already exists",
            "Ignoring registry inspection failure",
            1,
        )
        mutations.append(fail_open_inspection)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.release = mutation
                self.assertTrue(self.validate())

    def test_windows_release_without_container_dependency_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        self.release["jobs"]["verified-windows-release"]["needs"] = ["release-quality-gate"]

        errors = self.validate()

        self.assertTrue(any("Windows release must wait" in error for error in errors), errors)

    def test_container_release_without_browser_e2e_dependency_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        self.release["jobs"]["verified-container-release"]["needs"] = ["release-quality-gate"]

        errors = self.validate()

        self.assertTrue(any("container release must wait" in error for error in errors), errors)

    def test_windows_release_without_browser_e2e_dependency_is_rejected(self) -> None:
        self.release = copy.deepcopy(self.release)
        self.release["jobs"]["verified-windows-release"]["needs"] = [
            "release-quality-gate",
            "verified-container-release",
        ]

        errors = self.validate()

        self.assertTrue(any("Windows release must wait" in error for error in errors), errors)

    def test_publication_jobs_cannot_override_success_only_needs_semantics(self) -> None:
        for job_name in ("verified-container-release", "verified-windows-release"):
            with self.subTest(job_name=job_name):
                self.release = copy.deepcopy(load_workflows()[1])
                self.release["jobs"][job_name]["if"] = "${{ always() }}"

                errors = self.validate()

                self.assertTrue(
                    any(
                        "must not override dependency success" in error
                        for error in errors
                    ),
                    errors,
                )

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
