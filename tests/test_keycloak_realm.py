import copy
import json
import unittest
from pathlib import Path

from scripts.verify_keycloak_realm import (
    BROWSER_FLOW,
    BROWSER_FORMS_FLOW,
    EVENT_RETENTION_SECONDS,
    REQUIRED_EVENT_TYPES,
    keycloak_audit_errors,
    keycloak_mfa_errors,
)


class KeycloakRealmAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.realm = json.loads(
            Path("infra/keycloak/email-platform-realm.json").read_text(
                encoding="utf-8"
            )
        )

    def validate(self, realm=None) -> list[str]:
        return keycloak_audit_errors(self.realm if realm is None else realm)

    def validate_mfa(self, realm=None) -> list[str]:
        return keycloak_mfa_errors(self.realm if realm is None else realm)

    def flow(self, realm, alias):
        return next(
            item for item in realm["authenticationFlows"] if item["alias"] == alias
        )

    def test_repository_realm_has_reviewed_identity_audit_policy(self) -> None:
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.realm["eventsExpiration"], EVENT_RETENTION_SECONDS)
        self.assertEqual(set(self.realm["enabledEventTypes"]), REQUIRED_EVENT_TYPES)

    def test_repository_realm_has_explicit_password_then_otp_flow(self) -> None:
        self.assertEqual(self.validate_mfa(), [])
        self.assertEqual(self.realm["browserFlow"], BROWSER_FLOW)
        forms = self.flow(self.realm, BROWSER_FORMS_FLOW)
        self.assertEqual(
            [item.get("authenticator") for item in forms["authenticationExecutions"]],
            ["auth-username-password-form", "auth-otp-form"],
        )
        self.assertEqual(
            [item["requirement"] for item in forms["authenticationExecutions"]],
            ["REQUIRED", "REQUIRED"],
        )

    def test_user_and_admin_event_switches_fail_closed(self) -> None:
        mutations = {
            "events_missing": ("eventsEnabled", None),
            "events_disabled": ("eventsEnabled", False),
            "admin_missing": ("adminEventsEnabled", None),
            "admin_disabled": ("adminEventsEnabled", False),
            "admin_details_missing": ("adminEventsDetailsEnabled", None),
            "admin_details_enabled": ("adminEventsDetailsEnabled", True),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                realm = copy.deepcopy(self.realm)
                if value is None:
                    realm.pop(field)
                else:
                    realm[field] = value
                self.assertTrue(self.validate(realm))

    def test_retention_and_listener_are_exact(self) -> None:
        for field, value in (
            ("eventsExpiration", 0),
            ("eventsExpiration", EVENT_RETENTION_SECONDS - 1),
            ("eventsListeners", []),
            ("eventsListeners", ["jboss-logging", "unreviewed-listener"]),
        ):
            with self.subTest(field=field, value=value):
                realm = copy.deepcopy(self.realm)
                realm[field] = value
                self.assertTrue(self.validate(realm))

        for value in (None, "0", str(EVENT_RETENTION_SECONDS - 1)):
            with self.subTest(adminEventsExpiration=value):
                realm = copy.deepcopy(self.realm)
                if value is None:
                    realm["attributes"].pop("adminEventsExpiration")
                else:
                    realm["attributes"]["adminEventsExpiration"] = value
                self.assertTrue(self.validate(realm))

    def test_login_brute_force_lockout_policy_is_required_and_exact(self) -> None:
        mutations = (
            ("bruteForceProtected", None),
            ("bruteForceProtected", False),
            ("bruteForceProtected", 1),
            ("failureFactor", None),
            ("failureFactor", 50),
            ("failureFactor", True),
            ("waitIncrementSeconds", None),
            ("waitIncrementSeconds", 1),
            ("maxFailureWaitSeconds", None),
            ("maxFailureWaitSeconds", 60),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                realm = copy.deepcopy(self.realm)
                if value is None:
                    realm.pop(field)
                else:
                    realm[field] = value

                errors = self.validate(realm)

                self.assertTrue(
                    any("brute-force" in error for error in errors),
                    errors,
                )

    def test_device_authorization_lifetime_and_polling_are_short_and_exact(self) -> None:
        expected = {
            "oauth2DeviceCodeLifespan": 600,
            "oauth2DevicePollingInterval": 5,
        }
        for field, value in expected.items():
            self.assertEqual(self.realm.get(field), value)
            for mutation in (None, value + 1, str(value), True):
                with self.subTest(field=field, mutation=mutation):
                    realm = copy.deepcopy(self.realm)
                    if mutation is None:
                        realm.pop(field)
                    else:
                        realm[field] = mutation
                    errors = self.validate(realm)
                    self.assertTrue(
                        any("device authorization" in error.lower() for error in errors),
                        errors,
                    )

    def test_every_reviewed_success_and_failure_event_is_required(self) -> None:
        for event_type in sorted(REQUIRED_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                realm = copy.deepcopy(self.realm)
                realm["enabledEventTypes"].remove(event_type)
                errors = self.validate(realm)
                self.assertTrue(
                    any(event_type in error for error in errors),
                    errors,
                )

    def test_event_type_list_rejects_implicit_extra_and_duplicate_values(self) -> None:
        for mutation in ("extra", "duplicate", "not_a_list"):
            with self.subTest(mutation=mutation):
                realm = copy.deepcopy(self.realm)
                if mutation == "extra":
                    realm["enabledEventTypes"].append("UNREVIEWED_EVENT")
                elif mutation == "duplicate":
                    realm["enabledEventTypes"].append("LOGIN")
                else:
                    realm["enabledEventTypes"] = "LOGIN"
                self.assertTrue(self.validate(realm))

    def test_browser_flow_binding_is_required_and_exact(self) -> None:
        for value in (None, "browser", "password-only"):
            with self.subTest(browserFlow=value):
                realm = copy.deepcopy(self.realm)
                if value is None:
                    realm.pop("browserFlow")
                else:
                    realm["browserFlow"] = value
                self.assertTrue(self.validate_mfa(realm))

    def test_otp_challenge_cannot_be_missing_or_weakened(self) -> None:
        for requirement in (None, "CONDITIONAL", "ALTERNATIVE", "DISABLED"):
            with self.subTest(requirement=requirement):
                realm = copy.deepcopy(self.realm)
                executions = self.flow(realm, BROWSER_FORMS_FLOW)[
                    "authenticationExecutions"
                ]
                if requirement is None:
                    executions.pop()
                else:
                    executions[1]["requirement"] = requirement
                self.assertTrue(self.validate_mfa(realm))

    def test_password_then_otp_order_and_required_password_are_exact(self) -> None:
        reversed_realm = copy.deepcopy(self.realm)
        executions = self.flow(reversed_realm, BROWSER_FORMS_FLOW)[
            "authenticationExecutions"
        ]
        executions.reverse()
        self.assertTrue(self.validate_mfa(reversed_realm))

        optional_password = copy.deepcopy(self.realm)
        executions = self.flow(optional_password, BROWSER_FORMS_FLOW)[
            "authenticationExecutions"
        ]
        executions[0]["requirement"] = "ALTERNATIVE"
        self.assertTrue(self.validate_mfa(optional_password))

    def test_extra_password_only_or_duplicate_flow_is_rejected(self) -> None:
        password_only = copy.deepcopy(self.realm)
        password_only["authenticationFlows"].append(
            {
                "alias": "password-only",
                "description": "unsafe bypass",
                "providerId": "basic-flow",
                "topLevel": True,
                "builtIn": False,
                "authenticationExecutions": [
                    {
                        "authenticator": "auth-username-password-form",
                        "authenticatorFlow": False,
                        "requirement": "REQUIRED",
                        "priority": 10,
                        "userSetupAllowed": False,
                    }
                ],
            }
        )
        self.assertTrue(self.validate_mfa(password_only))

        duplicate = copy.deepcopy(self.realm)
        duplicate["authenticationFlows"].append(
            copy.deepcopy(duplicate["authenticationFlows"][0])
        )
        self.assertTrue(self.validate_mfa(duplicate))

    def test_duplicate_execution_and_unreviewed_execution_fields_are_rejected(self) -> None:
        duplicate = copy.deepcopy(self.realm)
        executions = self.flow(duplicate, BROWSER_FORMS_FLOW)[
            "authenticationExecutions"
        ]
        executions.append(copy.deepcopy(executions[-1]))
        self.assertTrue(self.validate_mfa(duplicate))

        configured = copy.deepcopy(self.realm)
        otp = self.flow(configured, BROWSER_FORMS_FLOW)["authenticationExecutions"][1]
        otp["authenticatorConfig"] = "unreviewed"
        self.assertTrue(self.validate_mfa(configured))

    def test_totp_enrollment_is_required_but_not_treated_as_challenge(self) -> None:
        for mutation in ("not_default", "duplicate"):
            with self.subTest(mutation=mutation):
                realm = copy.deepcopy(self.realm)
                if mutation == "not_default":
                    realm["requiredActions"][0]["defaultAction"] = False
                else:
                    realm["requiredActions"].append(
                        copy.deepcopy(realm["requiredActions"][0])
                    )
                self.assertTrue(self.validate_mfa(realm))

    def test_interactive_clients_cannot_enable_direct_grants(self) -> None:
        for client_id in ("email-platform-desktop", "email-platform-web"):
            with self.subTest(client_id=client_id):
                realm = copy.deepcopy(self.realm)
                client = next(
                    item for item in realm["clients"] if item["clientId"] == client_id
                )
                client["directAccessGrantsEnabled"] = True
                self.assertTrue(self.validate_mfa(realm))

    def test_only_reviewed_interactive_clients_can_map_the_api_audience(self) -> None:
        extra_client = {
            "clientId": "reporting-client",
            "protocol": "openid-connect",
            "protocolMappers": [],
        }
        allowed_extra = copy.deepcopy(self.realm)
        allowed_extra["clients"].append(extra_client)
        self.assertEqual(self.validate_mfa(allowed_extra), [])

        desktop = next(
            item
            for item in self.realm["clients"]
            if item["clientId"] == "email-platform-desktop"
        )
        api_audience_mapper = next(
            mapper
            for mapper in desktop["protocolMappers"]
            if mapper.get("config", {}).get("included.custom.audience")
            == "email-platform-api"
        )
        rogue = copy.deepcopy(allowed_extra)
        rogue["clients"][-1]["protocolMappers"].append(
            copy.deepcopy(api_audience_mapper)
        )
        errors = self.validate_mfa(rogue)
        self.assertTrue(
            any(
                "reporting-client" in error and "email-platform-api" in error
                for error in errors
            ),
            errors,
        )

        shared_scope = copy.deepcopy(allowed_extra)
        shared_scope["clientScopes"] = [
            {
                "name": "platform-api-audience",
                "protocolMappers": [copy.deepcopy(api_audience_mapper)],
            }
        ]
        shared_scope["clients"][-1]["defaultClientScopes"] = [
            "platform-api-audience"
        ]
        errors = self.validate_mfa(shared_scope)
        self.assertTrue(
            any("reporting-client" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
