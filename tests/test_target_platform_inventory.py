from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.target_platform_inventory import (
    INVENTORY,
    inventory_errors,
    main,
    runtime_alignment_errors,
)


class TargetPlatformInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.inventory)
        document.update(
            {
                "inventory_reference": "target-platform-inventory-record-42",
                "synthetic": False,
                "inventory_status": "reviewed",
                "review_reference": "target-platform-review-record-42",
                "environment": "staging",
            }
        )
        document["public_endpoints"] = {
            "platform_domain": "mail.company.net",
            "application_origin": "https://mail.company.net",
            "identity_issuer": "https://identity.mail.company.net/realms/email-platform",
            "external_dns_owner_reference": "public-dns-owner-record-42",
            "external_certificate_owner_reference": "public-tls-owner-record-42",
        }
        document["control_planes"] = {
            "keycloak_owner_reference": "keycloak-owner-record-42",
            "vault_owner_reference": "vault-owner-record-42",
            "internal_dns_owner_reference": "internal-dns-owner-record-42",
        }
        document["certificate_ownership"].update(
            {
                "internal_ca_owner_reference": "internal-ca-owner-record-42",
                "issuance_owner_reference": "certificate-issuance-record-42",
                "rotation_owner_reference": "certificate-rotation-record-42",
            }
        )
        document["runtime_locations"] = {
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
        return document

    def test_repository_template_is_safe_closed_aligned_and_in_quality_gate(self) -> None:
        self.assertEqual(inventory_errors(self.inventory), [])
        self.assertEqual(runtime_alignment_errors(self.inventory), [])
        self.assertTrue(self.inventory["synthetic"])
        self.assertEqual(self.inventory["inventory_status"], "pending")
        self.assertFalse(self.inventory["production_acceptance"])
        self.assertFalse(
            self.inventory["runtime_locations"]["repository_external_confirmed"]
        )
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/target_platform_inventory.py verify-repository",
            quality_gate,
        )

    def test_reviewed_inventory_requires_exact_https_endpoints_and_owner_references(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(inventory_errors(reviewed), [])

        mutations = []
        placeholder = copy.deepcopy(reviewed)
        placeholder["public_endpoints"]["platform_domain"] = "platform.example.com"
        mutations.append(placeholder)
        http_origin = copy.deepcopy(reviewed)
        http_origin["public_endpoints"]["application_origin"] = "http://mail.company.net"
        mutations.append(http_origin)
        wrong_issuer = copy.deepcopy(reviewed)
        wrong_issuer["public_endpoints"]["identity_issuer"] = (
            "https://identity.mail.company.net/realms/other"
        )
        mutations.append(wrong_issuer)
        missing_owner = copy.deepcopy(reviewed)
        missing_owner["control_planes"]["vault_owner_reference"] = None
        mutations.append(missing_owner)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(inventory_errors(document))

    def test_runtime_locations_are_exact_absolute_distinct_and_reviewed(self) -> None:
        reviewed = self._reviewed()
        mutations = []
        relative = copy.deepcopy(reviewed)
        relative["runtime_locations"]["secret_files"]["PLATFORM_DATABASE_URL_FILE"] = (
            "secrets/database-url"
        )
        mutations.append(relative)
        placeholder = copy.deepcopy(reviewed)
        placeholder["runtime_locations"]["internal_tls_root"] = "/CHANGE_ME/internal-tls"
        mutations.append(placeholder)
        dot_segment = copy.deepcopy(reviewed)
        dot_segment["runtime_locations"]["evidence_root"] = (
            "/srv/email-platform/../evidence"
        )
        mutations.append(dot_segment)
        duplicate = copy.deepcopy(reviewed)
        duplicate["runtime_locations"]["vault_token_directories"][
            "PLATFORM_VAULT_MAIL_TOKEN_DIR"
        ] = duplicate["runtime_locations"]["vault_token_directories"][
            "PLATFORM_VAULT_API_TOKEN_DIR"
        ]
        mutations.append(duplicate)
        unconfirmed = copy.deepcopy(reviewed)
        unconfirmed["runtime_locations"]["repository_external_confirmed"] = False
        mutations.append(unconfirmed)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(inventory_errors(document))

    def test_leaf_certificate_inventory_is_exactly_the_nine_reviewed_consumers(self) -> None:
        reviewed = self._reviewed()
        missing = copy.deepcopy(reviewed)
        missing["certificate_ownership"]["leaf_dns_sans"].pop("api-green")
        changed = copy.deepcopy(reviewed)
        changed["certificate_ownership"]["leaf_dns_sans"]["worker-mail"] = (
            "mail-worker"
        )
        extra = copy.deepcopy(reviewed)
        extra["certificate_ownership"]["leaf_dns_sans"]["vault"] = "vault"

        for document in (missing, changed, extra):
            with self.subTest(document=document):
                self.assertTrue(inventory_errors(document))

    def test_unknown_fields_acceptance_and_sensitive_claims_fail_closed(self) -> None:
        mutations = []
        accepted = copy.deepcopy(self.inventory)
        accepted["production_acceptance"] = True
        mutations.append(accepted)
        unknown = copy.deepcopy(self.inventory)
        unknown["operator_email"] = "redacted"
        mutations.append(unknown)
        sensitive = copy.deepcopy(self.inventory)
        sensitive["prohibited_content"]["contains_private_key_values"] = True
        mutations.append(sensitive)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(inventory_errors(document))

    def test_runtime_alignment_detects_repository_input_contract_drift(self) -> None:
        compose = Path("docker-compose.yml").read_text(encoding="utf-8")
        env_text = Path(".env.example").read_text(encoding="utf-8")
        missing_env = "\n".join(
            line
            for line in env_text.splitlines()
            if not line.startswith("PLATFORM_VAULT_API_TOKEN_DIR=")
        )
        changed_compose = compose.replace(
            "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE",
            "PLATFORM_MAIL_ORIGIN_POLICY_FILE",
        )

        self.assertIn(
            "repository environment contract is missing inventory inputs",
            runtime_alignment_errors(self.inventory, env_text=missing_env),
        )
        self.assertIn(
            "Compose does not consume the expected inventory inputs",
            runtime_alignment_errors(self.inventory, compose_text=changed_compose),
        )

    def test_cli_rejects_synthetic_and_distinguishes_runtime_gap(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory_path = root / "inventory.json"
            inventory_path.write_text(json.dumps(self.inventory), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path)]), 1)

            inventory_path.write_text(json.dumps(reviewed), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path)]), 0)
            with patch(
                "scripts.target_platform_inventory.runtime_alignment_errors",
                return_value=["runtime gap"],
            ):
                self.assertEqual(main(["check", "--input", str(inventory_path)]), 2)

            inventory_path.write_text('{"kind":"inventory"}', encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path)]), 1)

    def test_runbook_documents_inventory_limits_and_no_sensitive_values(self) -> None:
        rendered = json.dumps(self.inventory, ensure_ascii=False).casefold()
        for forbidden in (
            "4111111111111111",
            "bearer ",
            "client_secret",
            "private_key-----",
            "@example",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

        text = (
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .replace("\n", " ")
        )
        for expected in (
            "target_platform_inventory.py check",
            "synthetic target platform inventory cannot satisfy strict intake",
            "paths and owner references only",
            "does not prove that the target paths exist",
            "exit code 2",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
