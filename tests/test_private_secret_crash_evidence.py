from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import private_secret_crash_evidence as evidence
from scripts.target_platform_inventory import INVENTORY as TARGET_TEMPLATE


CLAIM_ID = "a" * 32
SIBLING_ID = "b" * 32
COMMIT = "c" * 40
WORKFLOW_SHA256 = "d" * 64
ALERT_SHA256 = "e" * 64
APPROVAL_SHA256 = "f" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _write_residue(path: Path, records: list[dict[str, object]]) -> dict[str, str]:
    payload = {
        "kind": evidence.RESIDUE_KIND,
        "records": records,
        "schema_version": 1,
    }
    document = {
        **payload,
        "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
    }
    raw = _canonical(document)
    path.write_bytes(raw)
    return {
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_sha256": document["payload_sha256"],
    }


def _seal(payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "integrity": {"payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest()},
    }


def _reviewed_target_inventory() -> dict[str, object]:
    value = json.loads(TARGET_TEMPLATE.read_text(encoding="utf-8"))
    value.update(
        {
            "inventory_reference": "target-platform-inventory-record-140",
            "synthetic": False,
            "inventory_status": "reviewed",
            "review_reference": "target-platform-review-record-140",
            "reviewed_at": "2026-08-27T00:00:00Z",
            "valid_until": "2099-08-27T00:00:00Z",
            "environment": "staging",
        }
    )
    value["public_endpoints"] = {
        "platform_domain": "mail.company.net",
        "application_origin": "https://mail.company.net",
        "identity_issuer": "https://identity.mail.company.net/realms/email-platform",
        "external_dns_owner_reference": "public-dns-owner-record-140",
        "external_certificate_owner_reference": "public-tls-owner-record-140",
    }
    value["control_planes"] = {
        "keycloak_owner_reference": "keycloak-owner-record-140",
        "vault_owner_reference": "vault-owner-record-140",
        "internal_dns_owner_reference": "internal-dns-owner-record-140",
    }
    value["certificate_ownership"].update(
        {
            "internal_ca_owner_reference": "internal-ca-owner-record-140",
            "issuance_owner_reference": "certificate-issuance-record-140",
            "rotation_owner_reference": "certificate-rotation-record-140",
        }
    )
    value["runtime_locations"] = {
        "path_policy": "repository_external_target_host_paths_only",
        "repository_external_confirmed": True,
        "secret_files": {
            "POSTGRES_PASSWORD_FILE": "/srv/email-platform/secrets/postgres/superuser-password",
            "POSTGRES_APP_PASSWORD_FILE": "/srv/email-platform/secrets/postgres/platform-password",
            "KEYCLOAK_DB_PASSWORD_FILE": "/srv/email-platform/secrets/postgres/keycloak-password",
            "PLATFORM_MIGRATION_DATABASE_URL_FILE": "/srv/email-platform/secrets/platform/migration-database-url",
            "PLATFORM_DATABASE_URL_FILE": "/srv/email-platform/secrets/platform/database-url",
            "PLATFORM_REDIS_URL_FILE": "/srv/email-platform/secrets/platform/redis-url",
            "REDIS_CONFIG_FILE": "/srv/email-platform/secrets/redis/redis.conf",
            "REDIS_ACL_FILE": "/srv/email-platform/secrets/redis/users.acl",
            "REDIS_HEALTHCHECK_PASSWORD_FILE": "/srv/email-platform/secrets/redis/healthcheck-password",
            "KEYCLOAK_CONFIG_FILE": "/srv/email-platform/secrets/keycloak/keycloak.conf",
        },
        "vault_token_directories": {
            "PLATFORM_VAULT_API_TOKEN_DIR": "/srv/email-platform/vault-agent/api",
            "PLATFORM_VAULT_MAIL_TOKEN_DIR": "/srv/email-platform/vault-agent/mail",
            "PLATFORM_VAULT_SUB2_TOKEN_DIR": "/srv/email-platform/vault-agent/sub2",
        },
        "policy_files": {
            "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE": "/srv/email-platform/policy/mail/allowed-origins",
            "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE": "/srv/email-platform/policy/sub2/allowed-origins",
            "ALERTMANAGER_CONFIG_FILE": "/srv/email-platform/policy/alertmanager/alertmanager.yml",
        },
        "internal_tls_root": "/srv/email-platform/internal-tls",
        "rolling_route_directory": "/srv/email-platform/rolling-edge-routing",
        "evidence_root": "/srv/email-platform/evidence",
    }
    return value


class PrivateSecretCrashEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy_sha256 = evidence.load_runtime_policy()[1]
        self.before_path = self.root / "before.json"
        self.after_path = self.root / "after.json"
        self.before = _write_residue(
            self.before_path,
            [
                {
                    "claim_id": CLAIM_ID,
                    "state": "cleanup_candidate",
                    "approval_sha256": APPROVAL_SHA256,
                },
                {"claim_id": SIBLING_ID, "state": "active"},
            ],
        )
        self.after = _write_residue(
            self.after_path,
            [{"claim_id": SIBLING_ID, "state": "active"}],
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _payload(self, kind: str = "linux") -> dict[str, object]:
        if kind == "linux":
            scope = {
                "kind": "github_actions_linux_ci",
                "repository_reference": "github-repository-record-140",
                "workflow_path": ".github/workflows/ci.yml",
                "workflow_sha256": WORKFLOW_SHA256,
                "commit_sha": COMMIT,
                "run_id": 140,
                "run_attempt": 1,
                "job_name": "postgres-migration-gate",
                "runner_os": "Linux",
            }
            alert = {
                "result": "not_applicable",
                "observed_at": None,
                "delivery_reference": None,
                "artifact_sha256": None,
            }
        else:
            scope = {
                "kind": "kubernetes_target_host",
                "environment": "staging",
                "target_inventory_artifact_sha256": "0" * 64,
                "target_inventory_reference": "target-platform-inventory-record-140",
                "execution_host_reference": "kubernetes-execution-host-record-140",
                "kubernetes_context_reference": "kubernetes-context-record-140",
            }
            alert = {
                "result": "delivered",
                "observed_at": "2026-08-27T00:02:00Z",
                "delivery_reference": "residue-alert-delivery-record-140",
                "artifact_sha256": ALERT_SHA256,
            }
        return {
            "schema_version": 1,
            "evidence_kind": evidence.EVIDENCE_KIND,
            "synthetic": False,
            "evidence_status": "reviewed",
            "origin_authentication": "unverified",
            "production_acceptance": False,
            "attempt_id": "00000000-0000-4000-8000-000000000140",
            "scope": scope,
            "runtime_root_policy_sha256": self.policy_sha256,
            "claim_id": CLAIM_ID,
            "before_inventory": {
                **self.before,
                "captured_at": "2026-08-27T00:01:00Z",
            },
            "cleanup": {
                "result": "succeeded",
                "exit_code": 0,
                "finished_at": "2026-08-27T00:03:00Z",
                "execution_reference": "residue-cleanup-execution-record-140",
            },
            "after_inventory": {
                **self.after,
                "captured_at": "2026-08-27T00:04:00Z",
            },
            "alert": alert,
            "review": {
                "operator_reference": "residue-operator-record-140",
                "cleanup_approver_reference": "residue-approver-record-140",
                "reviewer_reference": "residue-reviewer-record-140",
                "reviewed_at": "2026-08-27T00:05:00Z",
                "decision": "accepted_for_manual_review",
            },
            "prohibited_content": {
                field: False for field in evidence._PROHIBITED_FIELDS
            },
        }

    def _write_envelope(self, payload: dict[str, object], name: str = "evidence.json") -> Path:
        path = self.root / name
        path.write_bytes(_canonical(_seal(payload)))
        return path

    def _verify_linux(self, payload: dict[str, object] | None = None) -> dict[str, object]:
        path = self._write_envelope(payload or self._payload())
        return evidence.verify_evidence(
            path,
            self.before_path,
            self.after_path,
            expected_runtime_policy_sha256=self.policy_sha256,
            expected_commit=COMMIT,
            expected_workflow_sha256=WORKFLOW_SHA256,
        )

    def test_repository_policy_and_synthetic_template_are_closed_and_pending(self) -> None:
        template, policy_sha256 = evidence.verify_repository_assets()
        self.assertTrue(template["synthetic"])
        self.assertEqual(template["evidence_status"], "pending")
        self.assertEqual(template["origin_authentication"], "unverified")
        self.assertFalse(template["production_acceptance"])
        self.assertEqual(policy_sha256, self.policy_sha256)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(evidence.main(["verify-repository"]), 0)
        self.assertIn("status=pending", stdout.getvalue())
        self.assertIn("origin-authentication=unverified", stdout.getvalue())

    def test_linux_reviewed_assertion_binds_commit_workflow_and_exact_transition(self) -> None:
        verified = self._verify_linux()
        self.assertEqual(verified["origin_authentication"], "unverified")
        self.assertFalse(verified["production_acceptance"])
        stdout = io.StringIO()
        path = self.root / "evidence.json"
        with redirect_stdout(stdout):
            self.assertEqual(
                evidence.main(
                    [
                        "verify",
                        "--input",
                        str(path),
                        "--before-inventory",
                        str(self.before_path),
                        "--after-inventory",
                        str(self.after_path),
                        "--expected-runtime-policy-sha256",
                        self.policy_sha256,
                        "--expected-commit",
                        COMMIT,
                        "--expected-workflow-sha256",
                        WORKFLOW_SHA256,
                    ]
                ),
                0,
            )
        output = stdout.getvalue()
        self.assertIn("status=reviewed-assertion", output)
        self.assertIn("origin-authentication=unverified", output)
        self.assertIn("production_acceptance=false", output)
        self.assertNotIn("verified-linux", output)

    def test_bytes_core_matches_path_wrapper_without_filesystem_reads(self) -> None:
        path = self._write_envelope(self._payload())
        expected = evidence.verify_evidence_snapshot(
            path,
            self.before_path,
            self.after_path,
            expected_runtime_policy_sha256=self.policy_sha256,
            expected_commit=COMMIT,
            expected_workflow_sha256=WORKFLOW_SHA256,
        )
        arguments = {
            "input_raw": path.read_bytes(),
            "before_inventory_raw": self.before_path.read_bytes(),
            "after_inventory_raw": self.after_path.read_bytes(),
            "runtime_policy_raw": evidence.POLICY.read_bytes(),
            "expected_runtime_policy_sha256": self.policy_sha256,
            "expected_commit": COMMIT,
            "expected_workflow_sha256": WORKFLOW_SHA256,
        }
        with mock.patch.object(evidence, "_read_external", side_effect=AssertionError("I/O forbidden")), mock.patch.object(evidence, "read_stable_bytes", side_effect=AssertionError("I/O forbidden")):
            actual = evidence.verify_evidence_snapshot_bytes(**arguments)
        self.assertEqual(actual, expected)

    def test_target_scope_binds_reviewed_inventory_and_delivered_alert_assertion(self) -> None:
        target = _reviewed_target_inventory()
        target_path = self.root / "target-inventory.json"
        target_raw = json.dumps(target, sort_keys=True).encode("utf-8")
        target_path.write_bytes(target_raw)
        payload = self._payload("target")
        payload["scope"]["target_inventory_artifact_sha256"] = hashlib.sha256(
            target_raw
        ).hexdigest()
        path = self._write_envelope(payload)
        verified = evidence.verify_evidence(
            path,
            self.before_path,
            self.after_path,
            expected_runtime_policy_sha256=self.policy_sha256,
            target_inventory_path=target_path,
        )
        self.assertEqual(verified["scope"]["kind"], "kubernetes_target_host")
        self.assertEqual(verified["origin_authentication"], "unverified")

    def test_scope_specific_expected_inputs_are_mutually_exclusive(self) -> None:
        path = self._write_envelope(self._payload())
        invalid_calls = (
            {
                "expected_runtime_policy_sha256": self.policy_sha256,
                "expected_commit": COMMIT,
            },
            {
                "expected_runtime_policy_sha256": self.policy_sha256,
                "expected_commit": COMMIT,
                "expected_workflow_sha256": WORKFLOW_SHA256,
                "target_inventory_path": self.root / "target.json",
            },
            {
                "expected_runtime_policy_sha256": self.policy_sha256,
                "target_inventory_path": self.root / "target.json",
            },
        )
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments), self.assertRaises(
                evidence.PrivateSecretCrashEvidenceError
            ):
                evidence.verify_evidence(
                    path, self.before_path, self.after_path, **arguments
                )

    def test_commit_workflow_and_policy_drift_fail_closed(self) -> None:
        path = self._write_envelope(self._payload())
        for commit, workflow, policy in (
            ("1" * 40, WORKFLOW_SHA256, self.policy_sha256),
            (COMMIT, "2" * 64, self.policy_sha256),
            (COMMIT, WORKFLOW_SHA256, "3" * 64),
        ):
            with self.subTest(commit=commit, workflow=workflow, policy=policy), self.assertRaises(
                evidence.PrivateSecretCrashEvidenceError
            ):
                evidence.verify_evidence(
                    path,
                    self.before_path,
                    self.after_path,
                    expected_runtime_policy_sha256=policy,
                    expected_commit=commit,
                    expected_workflow_sha256=workflow,
                )

    def test_transition_rejects_wrong_claim_state_unknown_and_sibling_drift(self) -> None:
        cases = (
            (
                [{"claim_id": CLAIM_ID, "state": "active"}],
                [],
            ),
            (
                [
                    {
                        "claim_id": CLAIM_ID,
                        "state": "cleanup_candidate",
                        "approval_sha256": APPROVAL_SHA256,
                    },
                    {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
                ],
                [],
            ),
            (
                [
                    {
                        "claim_id": CLAIM_ID,
                        "state": "cleanup_candidate",
                        "approval_sha256": APPROVAL_SHA256,
                    }
                ],
                [{"claim_id": CLAIM_ID, "state": "active"}],
            ),
            (
                [
                    {
                        "claim_id": CLAIM_ID,
                        "state": "cleanup_candidate",
                        "approval_sha256": APPROVAL_SHA256,
                    },
                    {"claim_id": SIBLING_ID, "state": "active"},
                ],
                [],
            ),
        )
        for index, (before_records, after_records) in enumerate(cases):
            with self.subTest(index=index):
                before_path = self.root / f"before-{index}.json"
                after_path = self.root / f"after-{index}.json"
                before = _write_residue(before_path, before_records)
                after = _write_residue(after_path, after_records)
                payload = self._payload()
                payload["before_inventory"].update(before)
                payload["after_inventory"].update(after)
                input_path = self._write_envelope(payload, f"evidence-{index}.json")
                with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
                    evidence.verify_evidence(
                        input_path,
                        before_path,
                        after_path,
                        expected_runtime_policy_sha256=self.policy_sha256,
                        expected_commit=COMMIT,
                        expected_workflow_sha256=WORKFLOW_SHA256,
                    )

    def test_inventory_and_envelope_tampering_are_rejected(self) -> None:
        path = self._write_envelope(self._payload())
        original = self.before_path.read_bytes()
        self.before_path.write_bytes(original + b" ")
        with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
            evidence.verify_evidence(
                path,
                self.before_path,
                self.after_path,
                expected_runtime_policy_sha256=self.policy_sha256,
                expected_commit=COMMIT,
                expected_workflow_sha256=WORKFLOW_SHA256,
            )
        self.before_path.write_bytes(original)
        envelope = json.loads(path.read_text(encoding="ascii"))
        envelope["claim_id"] = "9" * 32
        path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
            evidence.verify_evidence(
                path,
                self.before_path,
                self.after_path,
                expected_runtime_policy_sha256=self.policy_sha256,
                expected_commit=COMMIT,
                expected_workflow_sha256=WORKFLOW_SHA256,
            )

    def test_external_input_rejects_hard_links_and_inventory_requires_canonical_bytes(self) -> None:
        path = self._write_envelope(self._payload())
        linked = self.root / "evidence-linked.json"
        os.link(path, linked)
        with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
            evidence.verify_evidence(
                path,
                self.before_path,
                self.after_path,
                expected_runtime_policy_sha256=self.policy_sha256,
                expected_commit=COMMIT,
                expected_workflow_sha256=WORKFLOW_SHA256,
            )
        linked.unlink()

        document = json.loads(self.before_path.read_text(encoding="ascii"))
        pretty_raw = json.dumps(document, indent=2).encode("ascii")
        self.before_path.write_bytes(pretty_raw)
        payload = self._payload()
        payload["before_inventory"]["artifact_sha256"] = hashlib.sha256(
            pretty_raw
        ).hexdigest()
        input_path = self._write_envelope(payload, "pretty-evidence.json")
        with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
            evidence.verify_evidence(
                input_path,
                self.before_path,
                self.after_path,
                expected_runtime_policy_sha256=self.policy_sha256,
                expected_commit=COMMIT,
                expected_workflow_sha256=WORKFLOW_SHA256,
            )

    def test_residue_inventory_rejects_duplicate_and_noncanonical_record_order(self) -> None:
        cases = (
            [
                {"claim_id": SIBLING_ID, "state": "active"},
                {"claim_id": SIBLING_ID, "state": "active"},
            ],
            [
                {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
                {"claim_id": None, "state": "unknown", "reason": "verification_failed"},
            ],
            [
                {"claim_id": SIBLING_ID, "state": "active"},
                {
                    "claim_id": CLAIM_ID,
                    "state": "cleanup_candidate",
                    "approval_sha256": APPROVAL_SHA256,
                },
            ],
        )
        for index, records in enumerate(cases):
            with self.subTest(index=index):
                path = self.root / f"noncanonical-{index}.json"
                binding = _write_residue(path, records)
                with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
                    evidence._load_residue_inventory(path, binding)

    def test_typed_references_reject_sensitive_fragments(self) -> None:
        for fragment in ("secret", "token", "password", "path", "url"):
            payload = self._payload()
            payload["review"]["reviewer_reference"] = f"review-{fragment}-record-140"
            with self.subTest(fragment=fragment), self.assertRaises(
                evidence.PrivateSecretCrashEvidenceError
            ):
                evidence.validate_envelope(_seal(payload))

    def test_authored_fields_cannot_claim_authentication_or_production_acceptance(self) -> None:
        mutations = []
        authenticated = self._payload()
        authenticated["origin_authentication"] = "authenticated"
        mutations.append(authenticated)
        accepted = self._payload()
        accepted["production_acceptance"] = True
        mutations.append(accepted)
        extra = self._payload()
        extra["runner_attested"] = True
        mutations.append(extra)
        windows = self._payload()
        windows["scope"]["runner_os"] = "Windows"
        mutations.append(windows)
        for payload in mutations:
            with self.subTest(payload=payload), self.assertRaises(
                evidence.PrivateSecretCrashEvidenceError
            ):
                evidence.validate_envelope(_seal(payload))

    def test_review_alert_cleanup_and_time_boundaries_fail_closed(self) -> None:
        mutations = []
        repeated_reviewer = self._payload()
        repeated_reviewer["review"]["reviewer_reference"] = repeated_reviewer["review"][
            "operator_reference"
        ]
        mutations.append(repeated_reviewer)
        failed_cleanup = self._payload()
        failed_cleanup["cleanup"].update({"result": "failed", "exit_code": 1})
        mutations.append(failed_cleanup)
        linux_alert = self._payload()
        linux_alert["alert"] = {
            "result": "delivered",
            "observed_at": "2026-08-27T00:02:00Z",
            "delivery_reference": "unexpected-alert-record-140",
            "artifact_sha256": ALERT_SHA256,
        }
        mutations.append(linux_alert)
        reversed_time = self._payload()
        reversed_time["after_inventory"]["captured_at"] = "2026-08-26T23:59:00Z"
        mutations.append(reversed_time)
        for payload in mutations:
            with self.subTest(payload=payload), self.assertRaises(
                evidence.PrivateSecretCrashEvidenceError
            ):
                evidence.validate_envelope(_seal(payload))

    def test_target_inventory_must_be_reviewed_non_synthetic_and_exactly_bound(self) -> None:
        target = _reviewed_target_inventory()
        target_path = self.root / "target.json"
        target_raw = json.dumps(target, sort_keys=True).encode()
        target_path.write_bytes(target_raw)
        payload = self._payload("target")
        payload["scope"]["target_inventory_artifact_sha256"] = hashlib.sha256(
            target_raw
        ).hexdigest()
        path = self._write_envelope(payload)
        synthetic = json.loads(TARGET_TEMPLATE.read_text(encoding="utf-8"))
        target_path.write_text(json.dumps(synthetic), encoding="utf-8")
        with self.assertRaises(evidence.PrivateSecretCrashEvidenceError):
            evidence.verify_evidence(
                path,
                self.before_path,
                self.after_path,
                expected_runtime_policy_sha256=self.policy_sha256,
                target_inventory_path=target_path,
            )

    def test_cli_failures_use_one_fixed_redacted_line(self) -> None:
        path = self._write_envelope(self._payload())
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = evidence.main(
                [
                    "verify",
                    "--input",
                    str(path),
                    "--before-inventory",
                    str(self.before_path),
                    "--after-inventory",
                    str(self.after_path),
                    "--expected-runtime-policy-sha256",
                    self.policy_sha256,
                    "--expected-commit",
                    "1" * 40,
                    "--expected-workflow-sha256",
                    WORKFLOW_SHA256,
                ]
            )
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "private-secret-crash-evidence-failed\n")
        self.assertNotIn(CLAIM_ID, stderr.getvalue())
        self.assertNotIn(str(path), stderr.getvalue())

    def test_verifier_has_no_runtime_or_generation_capability(self) -> None:
        source = Path(evidence.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "os.system",
            "SanitizedSubprocessRunner",
            "materialize_private_secret_bytes",
            "cleanup_private_secret_residue_from_inventory",
            'add_parser("generate"',
            'add_parser("create"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("origin-authentication=unverified", source)
        self.assertNotIn("status=verified", source)


if __name__ == "__main__":
    unittest.main()
