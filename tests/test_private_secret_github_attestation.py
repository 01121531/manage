from __future__ import annotations

import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import private_secret_crash_evidence as crash
from scripts import private_secret_github_attestation as github_origin


CLAIM_ID = "a" * 32
SIBLING_ID = "b" * 32
COMMIT = "c" * 40
WORKFLOW_SHA256 = "d" * 64
APPROVAL_SHA256 = "e" * 64
ATTEMPT_ID = "00000000-0000-4000-8000-000000000141"
REPOSITORY = "octo/email-platform"
REPOSITORY_ID = "14101"
OWNER_ID = "14102"
SOURCE_REF = "refs/heads/main"
SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/private-secret-evidence.yml"
CERT_IDENTITY = f"https://github.com/{SIGNER_WORKFLOW}@{SOURCE_REF}"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _seal(payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "integrity": {"payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest()},
    }


def _write_json(path: Path, value: object) -> bytes:
    raw = _canonical(value)
    path.write_bytes(raw)
    return raw


def _write_residue(path: Path, records: list[dict[str, object]]) -> dict[str, str]:
    payload = {
        "kind": crash.RESIDUE_KIND,
        "records": records,
        "schema_version": 1,
    }
    document = {**payload, "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
    raw = _write_json(path, document)
    return {
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_sha256": document["payload_sha256"],
    }


class FakeRunner:
    def __init__(self, output: bytes, *, returncode: int = 0, mutate=None) -> None:
        self.output = output
        self.returncode = returncode
        self.mutate = mutate
        self.calls: list[tuple[list[str], dict[str, str], int, int, tuple[int, ...]]] = []
        self.consumed: dict[str, bytes] = {}

    def run(
        self,
        arguments,
        *,
        environment,
        timeout_seconds,
        max_stdout_bytes,
        pass_fds,
    ) -> github_origin.CommandResult:
        self.calls.append(
            (
                list(arguments),
                dict(environment),
                timeout_seconds,
                max_stdout_bytes,
                tuple(pass_fds),
            )
        )
        if self.mutate is not None:
            self.mutate()
        argument_list = list(arguments)
        self.consumed = {
            "executable": Path(argument_list[0]).read_bytes(),
            "subject": Path(argument_list[3]).read_bytes(),
            "bundle": Path(argument_list[argument_list.index("--bundle") + 1]).read_bytes(),
            "trusted_root": Path(
                argument_list[argument_list.index("--custom-trusted-root") + 1]
            ).read_bytes(),
        }
        return github_origin.CommandResult(self.returncode, self.output, b"")


class FakeSnapshotFactory:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.count = 0
        self.last: github_origin.InvocationSnapshot | None = None

    @contextmanager
    def open(self, *, executable, subject, bundle, trusted_root):
        self.count += 1
        directory = self.root / f"invocation-snapshot-{self.count}"
        directory.mkdir(mode=0o700)
        paths = {
            "executable": directory / "gh.snapshot",
            "subject": directory / "subject.snapshot",
            "bundle": directory / "bundle.jsonl",
            "trusted_root": directory / "trusted-root.snapshot",
        }
        for name, raw in (
            ("executable", executable),
            ("subject", subject),
            ("bundle", bundle),
            ("trusted_root", trusted_root),
        ):
            paths[name].write_bytes(raw)
        self.last = github_origin.InvocationSnapshot(
            executable=paths["executable"],
            subject=paths["subject"],
            bundle=paths["bundle"],
            trusted_root=paths["trusted_root"],
            pass_fds=(),
        )
        yield self.last


class PrivateSecretGitHubAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.snapshot_factory = FakeSnapshotFactory(self.root)
        self.runtime_policy_sha256 = crash.load_runtime_policy()[1]
        self.before_path = self.root / "before.json"
        self.after_path = self.root / "after.json"
        self.before = _write_residue(
            self.before_path,
            [
                {
                    "approval_sha256": APPROVAL_SHA256,
                    "claim_id": CLAIM_ID,
                    "state": "cleanup_candidate",
                },
                {"claim_id": SIBLING_ID, "state": "active"},
            ],
        )
        self.after = _write_residue(
            self.after_path,
            [{"claim_id": SIBLING_ID, "state": "active"}],
        )
        self.subject_path = self.root / "private-secret-crash.json"
        subject_payload = {
            "schema_version": 1,
            "evidence_kind": crash.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "reviewed",
            "origin_authentication": "unverified",
            "production_acceptance": False,
            "attempt_id": ATTEMPT_ID,
            "scope": {
                "kind": "github_actions_linux_ci",
                "repository_reference": "github-repository-record-141",
                "workflow_path": ".github/workflows/ci.yml",
                "workflow_sha256": WORKFLOW_SHA256,
                "commit_sha": COMMIT,
                "run_id": 141,
                "run_attempt": 2,
                "job_name": "postgres-migration-gate",
                "runner_os": "Linux",
            },
            "runtime_root_policy_sha256": self.runtime_policy_sha256,
            "claim_id": CLAIM_ID,
            "before_inventory": {
                **self.before,
                "captured_at": "2026-08-27T00:01:00Z",
            },
            "cleanup": {
                "result": "succeeded",
                "exit_code": 0,
                "finished_at": "2026-08-27T00:02:00Z",
                "execution_reference": "residue-cleanup-execution-record-141",
            },
            "after_inventory": {
                **self.after,
                "captured_at": "2026-08-27T00:03:00Z",
            },
            "alert": {
                "result": "not_applicable",
                "observed_at": None,
                "delivery_reference": None,
                "artifact_sha256": None,
            },
            "review": {
                "operator_reference": "residue-operator-record-141",
                "cleanup_approver_reference": "residue-approver-record-141",
                "reviewer_reference": "residue-reviewer-record-141",
                "reviewed_at": "2026-08-27T00:04:00Z",
                "decision": "accepted_for_manual_review",
            },
            "prohibited_content": {field: False for field in crash._PROHIBITED_FIELDS},
        }
        self.subject = _seal(subject_payload)
        self.subject_raw = _write_json(self.subject_path, self.subject)

        self.bundle_path = self.root / "sha256-evidence.jsonl"
        self.bundle_path.write_bytes(b'{"offline":"bundle"}\n')
        self.trusted_root_path = self.root / "trusted_root.jsonl"
        self.trusted_root_path.write_bytes(b'{"trusted":"root"}\n')
        self.gh_path = self.root / ("gh.exe" if os.name == "nt" else "gh")
        self.gh_path.write_bytes(b"pinned-fake-gh-binary")
        self.gh_sha256 = hashlib.sha256(self.gh_path.read_bytes()).hexdigest()

        self.policy_path = self.root / "github-policy.json"
        self.policy = self._policy()
        self.policy_raw = _write_json(self.policy_path, self.policy)
        self.policy_sha256 = hashlib.sha256(self.policy_raw).hexdigest()
        self.origin_path = self.root / "github-origin.json"
        self.origin = self._origin()
        _write_json(self.origin_path, self.origin)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _policy(self) -> dict[str, object]:
        payload = {
            "schema_version": 1,
            "policy_kind": github_origin.POLICY_KIND,
            "synthetic": False,
            "policy_status": "reviewed",
            "policy_effect": "offline_origin_authentication_only",
            "production_acceptance": False,
            "repository": {
                "name": REPOSITORY,
                "repository_id": REPOSITORY_ID,
                "repository_owner_id": OWNER_ID,
                "visibility": "private",
            },
            "identity": {
                "oidc_issuer": github_origin.OIDC_ISSUER,
                "cert_identity": CERT_IDENTITY,
                "signer_workflow": SIGNER_WORKFLOW,
                "source_ref": SOURCE_REF,
                "build_trigger": "push",
                "runner_environment": "github-hosted",
                "predicate_type": github_origin.PREDICATE_TYPE,
            },
            "trusted_root": {
                "artifact_sha256": hashlib.sha256(self.trusted_root_path.read_bytes()).hexdigest(),
                "acquired_at": "2026-08-27T00:00:00Z",
                "custody_reference": "github-trusted-root-custody-record-141",
            },
            "verifier": {
                "gh_executable_sha256": self.gh_sha256,
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
            },
            "review": {
                "reviewer_reference": "github-trust-policy-review-record-141",
                "reviewed_at": "2026-08-27T00:01:00Z",
                "decision": "approved_for_offline_origin_authentication",
            },
        }
        return _seal(payload)

    def _origin(self) -> dict[str, object]:
        payload = {
            "schema_version": 1,
            "evidence_kind": github_origin.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "ready_for_verification",
            "origin_authentication": "pending_cryptographic_verification",
            "production_acceptance": False,
            "subject": {
                "artifact_sha256": hashlib.sha256(self.subject_raw).hexdigest(),
                "payload_sha256": self.subject["integrity"]["payload_sha256"],
                "attempt_id": ATTEMPT_ID,
            },
            "bundle": {
                "artifact_sha256": hashlib.sha256(self.bundle_path.read_bytes()).hexdigest(),
                "acquired_at": "2026-08-27T00:02:00Z",
                "api_version": "2026-03-10",
                "predicate_type": github_origin.PREDICATE_TYPE,
            },
            "trust_policy": {"artifact_sha256": self.policy_sha256},
            "verification": {
                "expected_commit": COMMIT,
                "expected_workflow_sha256": WORKFLOW_SHA256,
                "expected_runtime_policy_sha256": self.runtime_policy_sha256,
                "gh_executable_sha256": self.gh_sha256,
            },
            "review": {
                "reviewer_reference": "github-origin-review-record-141",
                "reviewed_at": "2026-08-27T00:03:00Z",
                "decision": "approved_for_offline_verification",
            },
            "prohibited_content": {
                field: False for field in github_origin._PROHIBITED_FIELDS
            },
        }
        return _seal(payload)

    def _output(self, *, subject_sha256: str | None = None) -> bytes:
        extensions = {
            "sourceRepositoryUri": f"https://github.com/{REPOSITORY}",
            "sourceRepositoryIdentifier": REPOSITORY_ID,
            "sourceRepositoryOwnerIdentifier": OWNER_ID,
            "sourceRepositoryVisibility": "private",
            "sourceRepositoryDigest": COMMIT,
            "sourceRepositoryRef": SOURCE_REF,
            "buildSignerUri": CERT_IDENTITY,
            "buildSignerDigest": COMMIT,
            "runnerEnvironment": "github-hosted",
            "runnerInvocationUri": (
                f"https://github.com/{REPOSITORY}/actions/runs/141/attempts/2"
            ),
            "buildTrigger": "push",
        }
        value = [
            {
                "attestation": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
                "verificationResult": {
                    "signature": {"certificate": {"extensions": extensions}},
                    "verifiedTimestamps": [{"type": "transparency-log"}],
                    "statement": {
                        "subject": [
                            {
                                "name": "private-secret-crash.json",
                                "digest": {
                                    "sha256": subject_sha256
                                    or hashlib.sha256(self.subject_raw).hexdigest()
                                },
                            }
                        ],
                        "predicateType": github_origin.PREDICATE_TYPE,
                        "predicate": {},
                    },
                },
            }
        ]
        return _canonical(value)

    def _verify(self, runner: FakeRunner, *, environment=None) -> dict[str, object]:
        return github_origin.verify_authenticated(
            self.origin_path,
            self.subject_path,
            self.before_path,
            self.after_path,
            self.bundle_path,
            self.trusted_root_path,
            self.policy_path,
            self.gh_path,
            expected_policy_sha256=self.policy_sha256,
            expected_gh_sha256=self.gh_sha256,
            runner=runner,
            snapshot_factory=self.snapshot_factory,
            environment=environment,
        )

    def test_repository_assets_are_closed_pending_and_unconfigured(self) -> None:
        policy, envelope = github_origin.verify_repository_assets()
        self.assertTrue(policy["synthetic"])
        self.assertEqual(policy["policy_status"], "pending")
        self.assertTrue(envelope["synthetic"])
        self.assertEqual(envelope["origin_authentication"], "unverified")
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.validate_trust_policy(policy)
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.validate_origin_envelope(envelope)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(github_origin.main(["verify-repository"]), 0)
        self.assertIn("github-origin=unverified", stdout.getvalue())
        for boundary in (
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "job-binding=unverified",
            "rest-snapshot=unverified",
        ):
            self.assertIn(boundary, stdout.getvalue())
        self.assertIn("production_acceptance=false", stdout.getvalue())

    def test_authenticated_output_keeps_unproven_axes_explicitly_unverified(self) -> None:
        stdout = io.StringIO()
        arguments = [
            "verify-authenticated",
            "--input",
            str(self.origin_path),
            "--subject",
            str(self.subject_path),
            "--before-inventory",
            str(self.before_path),
            "--after-inventory",
            str(self.after_path),
            "--bundle",
            str(self.bundle_path),
            "--trusted-root",
            str(self.trusted_root_path),
            "--policy",
            str(self.policy_path),
            "--gh-executable",
            str(self.gh_path),
            "--expected-policy-sha256",
            self.policy_sha256,
            "--expected-gh-sha256",
            self.gh_sha256,
        ]
        with mock.patch.object(
            github_origin, "verify_authenticated", return_value=self.origin
        ), redirect_stdout(stdout):
            self.assertEqual(github_origin.main(arguments), 0)
        output = stdout.getvalue()
        self.assertIn("github-origin=verified", output)
        for boundary in (
            "freshness=unverified",
            "replay-protection=unverified",
            "durability=unverified",
            "reviewer-independence=unverified",
            "job-binding=unverified",
            "rest-snapshot=unverified",
        ):
            self.assertIn(boundary, output)

    @unittest.skipUnless(
        sys.platform == "linux" and hasattr(os, "memfd_create"),
        "Linux sealed memfd integration only",
    )
    def test_linux_snapshot_is_sealed_and_bundle_keeps_jsonl_extension(self) -> None:
        factory = github_origin.LinuxSealedSnapshotFactory()
        executable_bytes = Path("/bin/true").read_bytes()
        raw = {
            "executable": executable_bytes,
            "subject": b"subject-bytes",
            "bundle": b"bundle-bytes",
            "trusted_root": b"root-bytes",
        }
        with factory.open(**raw) as snapshot:
            self.assertEqual(snapshot.bundle.suffix, ".jsonl")
            self.assertEqual(snapshot.executable.read_bytes(), raw["executable"])
            self.assertEqual(snapshot.subject.read_bytes(), raw["subject"])
            self.assertEqual(snapshot.bundle.read_bytes(), raw["bundle"])
            self.assertEqual(snapshot.trusted_root.read_bytes(), raw["trusted_root"])
            self.assertEqual(len(snapshot.pass_fds), 5)
            completed = github_origin.SubprocessCommandRunner().run(
                [str(snapshot.executable)],
                environment={},
                timeout_seconds=5,
                max_stdout_bytes=1024,
                pass_fds=snapshot.pass_fds,
            )
            self.assertEqual(completed.returncode, 0)
            for descriptor in snapshot.pass_fds[:4]:
                with self.assertRaises(OSError):
                    os.write(descriptor, b"replacement")
                with self.assertRaises(OSError):
                    os.ftruncate(descriptor, 0)

    @unittest.skipIf(sys.platform == "linux", "non-Linux fail-closed behavior only")
    def test_default_authenticated_snapshot_factory_fails_closed_off_linux(self) -> None:
        runner = FakeRunner(self._output())
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.verify_authenticated(
                self.origin_path,
                self.subject_path,
                self.before_path,
                self.after_path,
                self.bundle_path,
                self.trusted_root_path,
                self.policy_path,
                self.gh_path,
                expected_policy_sha256=self.policy_sha256,
                expected_gh_sha256=self.gh_sha256,
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_authenticated_wrapper_uses_exact_offline_policy_and_clean_environment(self) -> None:
        runner = FakeRunner(self._output())
        verified = self._verify(
            runner,
            environment={
                "SYSTEMROOT": r"C:\Windows",
                "GH_TOKEN": "sensitive",
                "HTTP_PROXY": "http://proxy.invalid",
                "GIT_CONFIG_GLOBAL": "attacker",
                "SIGSTORE_TUF_ROOT": "attacker",
                "PATH": "attacker",
            },
        )
        self.assertEqual(verified["origin_authentication"], "pending_cryptographic_verification")
        self.assertEqual(len(runner.calls), 1)
        arguments, environment, timeout, maximum, pass_fds = runner.calls[0]
        snapshot = self.snapshot_factory.last
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(
            arguments,
            [
                str(snapshot.executable),
                "attestation",
                "verify",
                str(snapshot.subject),
                "--repo",
                REPOSITORY,
                "--bundle",
                str(snapshot.bundle),
                "--custom-trusted-root",
                str(snapshot.trusted_root),
                "--cert-oidc-issuer",
                github_origin.OIDC_ISSUER,
                "--cert-identity",
                CERT_IDENTITY,
                "--signer-digest",
                COMMIT,
                "--source-digest",
                COMMIT,
                "--source-ref",
                SOURCE_REF,
                "--deny-self-hosted-runners",
                "--predicate-type",
                github_origin.PREDICATE_TYPE,
                "--format",
                "json",
            ],
        )
        self.assertNotIn("--signer-workflow", arguments)
        self.assertEqual(environment, {"SYSTEMROOT": r"C:\Windows"})
        self.assertEqual(timeout, 30)
        self.assertEqual(maximum, 65536)
        self.assertEqual(pass_fds, ())
        self.assertEqual(
            runner.consumed,
            {
                "executable": self.gh_path.read_bytes(),
                "subject": self.subject_raw,
                "bundle": self.bundle_path.read_bytes(),
                "trusted_root": self.trusted_root_path.read_bytes(),
            },
        )
        for original in (
            self.gh_path,
            self.subject_path,
            self.bundle_path,
            self.trusted_root_path,
        ):
            self.assertNotIn(str(original), arguments)

    def test_caller_policy_pin_blocks_joint_policy_and_origin_replacement(self) -> None:
        original_policy_sha256 = self.policy_sha256
        changed_policy = copy.deepcopy(self.policy)
        changed_policy["review"]["reviewer_reference"] = "replacement-policy-review-record-141"
        changed_policy = _seal(
            {key: item for key, item in changed_policy.items() if key != "integrity"}
        )
        changed_policy_raw = _write_json(self.policy_path, changed_policy)
        changed_origin = copy.deepcopy(self.origin)
        changed_origin["trust_policy"]["artifact_sha256"] = hashlib.sha256(
            changed_policy_raw
        ).hexdigest()
        changed_origin = _seal(
            {key: item for key, item in changed_origin.items() if key != "integrity"}
        )
        _write_json(self.origin_path, changed_origin)
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.verify_authenticated(
                self.origin_path,
                self.subject_path,
                self.before_path,
                self.after_path,
                self.bundle_path,
                self.trusted_root_path,
                self.policy_path,
                self.gh_path,
                expected_policy_sha256=original_policy_sha256,
                expected_gh_sha256=self.gh_sha256,
                runner=FakeRunner(self._output()),
            )

    def test_policy_and_origin_reviewers_must_be_independent(self) -> None:
        changed = copy.deepcopy(self.origin)
        changed["review"]["reviewer_reference"] = self.policy["review"][
            "reviewer_reference"
        ]
        changed = _seal({key: item for key, item in changed.items() if key != "integrity"})
        _write_json(self.origin_path, changed)
        with self.assertRaises(github_origin.GitHubAttestationError):
            self._verify(FakeRunner(self._output()))

    def test_exactly_one_complete_verified_result_is_required(self) -> None:
        valid = json.loads(self._output())
        mutations = [
            b"[]",
            _canonical([*valid, *valid]),
            _canonical(
                [
                    {
                        **valid[0],
                        "verificationResult": {
                            **valid[0]["verificationResult"],
                            "verifiedTimestamps": [],
                        },
                    }
                ]
            ),
            self._output(subject_sha256="f" * 64),
        ]
        changed = copy.deepcopy(valid)
        changed[0]["verificationResult"]["signature"]["certificate"]["extensions"][
            "runnerEnvironment"
        ] = "self-hosted"
        mutations.append(_canonical(changed))
        for output in mutations:
            with self.subTest(output=output[:80]), self.assertRaises(
                github_origin.GitHubAttestationError
            ):
                self._verify(FakeRunner(output))

    def test_runner_failure_output_limit_and_post_run_drift_fail_closed(self) -> None:
        with self.assertRaises(github_origin.GitHubAttestationError):
            self._verify(FakeRunner(self._output(), returncode=1))
        with self.assertRaises(github_origin.GitHubAttestationError):
            self._verify(FakeRunner(b"x" * 65537))

        def mutate_bundle() -> None:
            self.bundle_path.write_bytes(b'{"offline":"replacement"}\n')

        drift_runner = FakeRunner(self._output(), mutate=mutate_bundle)
        with self.assertRaises(github_origin.GitHubAttestationError):
            self._verify(drift_runner)
        self.assertEqual(drift_runner.consumed["bundle"], b'{"offline":"bundle"}\n')

    def test_t140_and_attestation_must_consume_the_same_subject_snapshot(self) -> None:
        original_verify = crash.verify_evidence_snapshot
        replacement = copy.deepcopy(self.subject)
        replacement["review"]["reviewer_reference"] = "replacement-review-record-141"
        replacement = _seal(
            {key: item for key, item in replacement.items() if key != "integrity"}
        )

        def swap_then_verify(*arguments, **keywords):
            _write_json(self.subject_path, replacement)
            return original_verify(*arguments, **keywords)

        runner = FakeRunner(self._output())
        with mock.patch.object(
            crash, "verify_evidence_snapshot", side_effect=swap_then_verify
        ), self.assertRaises(github_origin.GitHubAttestationError):
            self._verify(runner)
        self.assertEqual(runner.calls, [])

    def test_hard_links_duplicate_keys_and_non_absolute_paths_are_rejected(self) -> None:
        linked = self.root / "linked-origin.json"
        try:
            os.link(self.origin_path, linked)
        except OSError:
            linked = None
        if linked is not None:
            with self.assertRaises(github_origin.GitHubAttestationError):
                github_origin.verify_authenticated(
                    linked,
                    self.subject_path,
                    self.before_path,
                    self.after_path,
                    self.bundle_path,
                    self.trusted_root_path,
                    self.policy_path,
                    self.gh_path,
                    expected_policy_sha256=self.policy_sha256,
                    expected_gh_sha256=self.gh_sha256,
                    runner=FakeRunner(self._output()),
                )
        duplicate_policy = self.policy_raw.replace(
            b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
        )
        duplicate_path = self.root / "duplicate-policy.json"
        duplicate_path.write_bytes(duplicate_policy)
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.validate_trust_policy(
                github_origin._unique_document(
                    github_origin._read_blob(duplicate_path, max_bytes=github_origin.MAX_JSON_BYTES)
                )
            )
        with self.assertRaises(github_origin.GitHubAttestationError):
            github_origin.verify_authenticated(
                "relative-origin.json",
                self.subject_path,
                self.before_path,
                self.after_path,
                self.bundle_path,
                self.trusted_root_path,
                self.policy_path,
                self.gh_path,
                expected_policy_sha256=self.policy_sha256,
                expected_gh_sha256=self.gh_sha256,
                runner=FakeRunner(self._output()),
            )

    def test_cli_failure_is_fixed_and_redacted(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(github_origin.main(["verify-authenticated"]), 1)
        self.assertEqual(stderr.getvalue(), "private-secret-github-origin-failed\n")


if __name__ == "__main__":
    unittest.main()
