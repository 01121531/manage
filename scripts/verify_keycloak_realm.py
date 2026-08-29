"""Verify Keycloak realm export keeps MFA and redirects tightly scoped."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.external_text import load_stable_text

REALM = ROOT / "infra" / "keycloak" / "email-platform-realm.json"
OIDC = ROOT / "frontend" / "src" / "oidc.ts"
MAX_OIDC_SOURCE_BYTES = 64 * 1024
EVENT_RETENTION_SECONDS = 30 * 24 * 60 * 60
BROWSER_FLOW = "email-platform-browser-mfa"
BROWSER_FORMS_FLOW = "email-platform-browser-mfa-forms"
API_AUDIENCE = "email-platform-api"
API_AUDIENCE_CLIENT_IDS = frozenset(
    {"email-platform-desktop", "email-platform-web"}
)
BRUTE_FORCE_POLICY = {
    "bruteForceProtected": True,
    "failureFactor": 5,
    "waitIncrementSeconds": 60,
    "maxFailureWaitSeconds": 900,
}
DEVICE_AUTHORIZATION_POLICY = {
    "oauth2DeviceCodeLifespan": 600,
    "oauth2DevicePollingInterval": 5,
}
REQUIRED_EVENT_TYPES = frozenset(
    {
        "LOGIN",
        "LOGIN_ERROR",
        "LOGOUT",
        "LOGOUT_ERROR",
        "CODE_TO_TOKEN",
        "CODE_TO_TOKEN_ERROR",
        "REFRESH_TOKEN",
        "REFRESH_TOKEN_ERROR",
        "REVOKE_GRANT",
        "REVOKE_GRANT_ERROR",
        "RESET_PASSWORD",
        "RESET_PASSWORD_ERROR",
        "OAUTH2_DEVICE_AUTH",
        "OAUTH2_DEVICE_AUTH_ERROR",
        "OAUTH2_DEVICE_VERIFY_USER_CODE",
        "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR",
        "OAUTH2_DEVICE_CODE_TO_TOKEN",
        "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR",
        "IDENTITY_PROVIDER_LOGIN",
        "IDENTITY_PROVIDER_LOGIN_ERROR",
        "IDENTITY_PROVIDER_FIRST_LOGIN",
        "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
        "UPDATE_CREDENTIAL",
        "UPDATE_CREDENTIAL_ERROR",
        "REMOVE_CREDENTIAL",
        "REMOVE_CREDENTIAL_ERROR",
        "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
        "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR",
        "USER_DISABLED_BY_PERMANENT_LOCKOUT",
        "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR",
    }
)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def keycloak_audit_errors(realm: object) -> list[str]:
    if not isinstance(realm, dict):
        return ["Keycloak realm must be a JSON object"]

    errors: list[str] = []
    for field, expected in BRUTE_FORCE_POLICY.items():
        actual = realm.get(field)
        if type(actual) is not type(expected) or actual != expected:
            errors.append(
                f"Keycloak brute-force policy requires {field}={expected!r}"
            )
    for field, expected in DEVICE_AUTHORIZATION_POLICY.items():
        actual = realm.get(field)
        if type(actual) is not int or actual != expected:
            errors.append(
                f"Keycloak device authorization policy requires {field}={expected}"
            )
    if realm.get("eventsEnabled") is not True:
        errors.append("eventsEnabled must be true")
    if realm.get("eventsExpiration") != EVENT_RETENTION_SECONDS:
        errors.append("eventsExpiration must retain events for exactly 30 days")
    if realm.get("eventsListeners") != ["jboss-logging"]:
        errors.append("eventsListeners must be exactly jboss-logging")
    if realm.get("adminEventsEnabled") is not True:
        errors.append("adminEventsEnabled must be true")
    if realm.get("adminEventsDetailsEnabled") is not False:
        errors.append(
            "adminEventsDetailsEnabled must be false to avoid request representations"
        )
    attributes = realm.get("attributes")
    if (
        not isinstance(attributes, dict)
        or attributes.get("adminEventsExpiration")
        != str(EVENT_RETENTION_SECONDS)
    ):
        errors.append("adminEventsExpiration must retain admin events for exactly 30 days")

    configured_event_types = realm.get("enabledEventTypes")
    if not isinstance(configured_event_types, list) or any(
        not isinstance(item, str) for item in configured_event_types
    ):
        errors.append("enabledEventTypes must be an explicit string list")
    else:
        configured = set(configured_event_types)
        missing = sorted(REQUIRED_EVENT_TYPES - configured)
        unexpected = sorted(configured - REQUIRED_EVENT_TYPES)
        if missing:
            errors.append("enabledEventTypes is missing: " + ", ".join(missing))
        if unexpected:
            errors.append("enabledEventTypes is not reviewed: " + ", ".join(unexpected))
        if len(configured_event_types) != len(configured):
            errors.append("enabledEventTypes must not contain duplicates")
    return errors


def _exact_execution_errors(
    execution: object,
    expected: dict[str, object],
    context: str,
) -> list[str]:
    if not isinstance(execution, dict):
        return [f"{context} must be an execution object"]
    if set(execution) != set(expected):
        return [f"{context} fields are not reviewed"]
    return [
        f"{context} must set {key}={value}"
        for key, value in expected.items()
        if execution.get(key) != value
    ]


def _maps_api_audience(protocol_mappers: object) -> bool:
    return isinstance(protocol_mappers, list) and any(
        isinstance(mapper, dict)
        and mapper.get("protocol") == "openid-connect"
        and mapper.get("protocolMapper") == "oidc-audience-mapper"
        and isinstance(mapper.get("config"), dict)
        and mapper["config"].get("included.custom.audience") == API_AUDIENCE
        for mapper in protocol_mappers
    )


def keycloak_mfa_errors(realm: object) -> list[str]:
    if not isinstance(realm, dict):
        return ["Keycloak realm must be a JSON object"]

    errors: list[str] = []
    required_actions = realm.get("requiredActions")
    if not isinstance(required_actions, list):
        errors.append("requiredActions must be an explicit list")
    else:
        actions = [item for item in required_actions if isinstance(item, dict)]
        otp_actions = [
            item for item in actions if item.get("alias") == "CONFIGURE_TOTP"
        ]
        if len(otp_actions) != 1:
            errors.append("CONFIGURE_TOTP required action must appear exactly once")
        else:
            otp_action = otp_actions[0]
            for key, expected in {
                "providerId": "CONFIGURE_TOTP",
                "enabled": True,
                "defaultAction": True,
            }.items():
                if otp_action.get(key) != expected:
                    errors.append(f"CONFIGURE_TOTP must set {key}={expected}")
    if realm.get("otpPolicyType") != "totp":
        errors.append("Keycloak realm must use TOTP policy")
    if realm.get("browserFlow") != BROWSER_FLOW:
        errors.append(f"browserFlow must be bound to {BROWSER_FLOW}")

    configured_flows = realm.get("authenticationFlows")
    if not isinstance(configured_flows, list):
        errors.append("authenticationFlows must be an explicit list")
        flows: list[dict[str, object]] = []
    else:
        flows = [item for item in configured_flows if isinstance(item, dict)]
        aliases = [item.get("alias") for item in flows]
        valid_aliases = [alias for alias in aliases if isinstance(alias, str)]
        if len(flows) != len(configured_flows) or any(
            not isinstance(alias, str) for alias in aliases
        ):
            errors.append("authenticationFlows must contain named flow objects")
        if len(valid_aliases) != len(set(valid_aliases)):
            errors.append("authenticationFlows must not contain duplicate aliases")
        if set(valid_aliases) != {BROWSER_FLOW, BROWSER_FORMS_FLOW}:
            errors.append("authenticationFlows must contain exactly the reviewed MFA flows")

    flow_by_alias = {
        item["alias"]: item
        for item in flows
        if isinstance(item.get("alias"), str)
    }
    expected_flows = {
        BROWSER_FLOW: {
            "topLevel": True,
            "executions": [
                {
                    "authenticator": "auth-cookie",
                    "authenticatorFlow": False,
                    "requirement": "ALTERNATIVE",
                    "priority": 10,
                    "userSetupAllowed": False,
                },
                {
                    "flowAlias": BROWSER_FORMS_FLOW,
                    "authenticatorFlow": True,
                    "requirement": "ALTERNATIVE",
                    "priority": 20,
                    "userSetupAllowed": False,
                },
            ],
        },
        BROWSER_FORMS_FLOW: {
            "topLevel": False,
            "executions": [
                {
                    "authenticator": "auth-username-password-form",
                    "authenticatorFlow": False,
                    "requirement": "REQUIRED",
                    "priority": 10,
                    "userSetupAllowed": False,
                },
                {
                    "authenticator": "auth-otp-form",
                    "authenticatorFlow": False,
                    "requirement": "REQUIRED",
                    "priority": 20,
                    "userSetupAllowed": False,
                },
            ],
        },
    }
    flow_fields = {
        "alias",
        "description",
        "providerId",
        "topLevel",
        "builtIn",
        "authenticationExecutions",
    }
    for alias, expected_flow in expected_flows.items():
        flow = flow_by_alias.get(alias)
        if flow is None:
            continue
        if set(flow) != flow_fields:
            errors.append(f"{alias} fields are not reviewed")
        if flow.get("providerId") != "basic-flow":
            errors.append(f"{alias} must use providerId=basic-flow")
        if flow.get("builtIn") is not False:
            errors.append(f"{alias} must set builtIn=False")
        if flow.get("topLevel") is not expected_flow["topLevel"]:
            errors.append(
                f"{alias} must set topLevel={expected_flow['topLevel']}"
            )
        executions = flow.get("authenticationExecutions")
        expected_executions = expected_flow["executions"]
        if not isinstance(executions, list) or len(executions) != len(
            expected_executions
        ):
            errors.append(f"{alias} must contain exactly the reviewed executions")
            continue
        for index, (execution, expected) in enumerate(
            zip(executions, expected_executions, strict=True)
        ):
            errors.extend(
                _exact_execution_errors(execution, expected, f"{alias}[{index}]")
            )

    clients = realm.get("clients")
    if not isinstance(clients, list):
        errors.append("clients must be an explicit list")
    else:
        for client_id in ("email-platform-desktop", "email-platform-web"):
            matches = [
                item
                for item in clients
                if isinstance(item, dict) and item.get("clientId") == client_id
            ]
            if len(matches) != 1:
                errors.append(f"{client_id} client must appear exactly once")
            elif matches[0].get("directAccessGrantsEnabled") is not False:
                errors.append(f"{client_id} must disable direct access grants")
        client_scopes = realm.get("clientScopes", [])
        if not isinstance(client_scopes, list):
            errors.append("clientScopes must be an explicit list when configured")
            client_scopes = []
        api_audience_scopes = {
            scope.get("name")
            for scope in client_scopes
            if isinstance(scope, dict)
            and isinstance(scope.get("name"), str)
            and _maps_api_audience(scope.get("protocolMappers", []))
        }
        for client in clients:
            if not isinstance(client, dict):
                continue
            client_id = client.get("clientId")
            assigned_scopes: set[str] = set()
            for field in ("defaultClientScopes", "optionalClientScopes"):
                configured_scopes = client.get(field, [])
                if not isinstance(configured_scopes, list):
                    errors.append(f"{client_id!r} client scopes must be lists")
                    continue
                assigned_scopes.update(
                    scope for scope in configured_scopes if isinstance(scope, str)
                )
            maps_api_audience = _maps_api_audience(
                client.get("protocolMappers", [])
            ) or bool(assigned_scopes & api_audience_scopes)
            if (
                "protocolMappers" in client
                and not isinstance(client["protocolMappers"], list)
            ):
                errors.append(f"{client_id!r} protocolMappers must be a list")
            if maps_api_audience and client_id not in API_AUDIENCE_CLIENT_IDS:
                errors.append(
                    f"{client_id!r} must not map the {API_AUDIENCE} audience"
                )
    return errors


def main() -> int:
    try:
        realm = load_unique_json(
            REALM,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _fail("Keycloak realm is invalid")
    audit_errors = keycloak_audit_errors(realm)
    if audit_errors:
        return _fail("Keycloak audit policy invalid: " + "; ".join(audit_errors))
    mfa_errors = keycloak_mfa_errors(realm)
    if mfa_errors:
        return _fail("Keycloak browser MFA policy invalid: " + "; ".join(mfa_errors))

    for key, expected in {
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "accessTokenLifespan": 900,
    }.items():
        if realm.get(key) != expected:
            return _fail(f"Keycloak realm must set {key}={expected}")

    desktop_client = next(
        (
            item
            for item in realm.get("clients", [])
            if isinstance(item, dict)
            and item.get("clientId") == "email-platform-desktop"
        ),
        None,
    )
    if desktop_client is None:
        return _fail("Keycloak realm is missing email-platform-desktop client")
    for key, expected in {
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
    }.items():
        if desktop_client.get(key) is not expected:
            return _fail(f"email-platform-desktop must set {key}={expected}")
    if desktop_client.get("redirectUris") != ["http://127.0.0.1"]:
        return _fail("desktop redirectUris must use the exact IPv4 loopback URI")
    desktop_attributes = desktop_client.get("attributes", {})
    if not isinstance(desktop_attributes, dict):
        return _fail("email-platform-desktop attributes are invalid")
    if desktop_attributes.get("pkce.code.challenge.method") != "S256":
        return _fail("email-platform-desktop must require PKCE S256")
    if desktop_attributes.get("oauth2.device.authorization.grant.enabled") != "true":
        return _fail("email-platform-desktop must retain explicit Device Flow fallback")
    if desktop_client.get("secret"):
        return _fail("email-platform-desktop must not contain a client secret")

    web_client = next(
        (item for item in realm.get("clients", []) if isinstance(item, dict) and item.get("clientId") == "email-platform-web"),
        None,
    )
    if web_client is None:
        return _fail("Keycloak realm is missing email-platform-web client")
    expected_redirects = [
        "https://${PLATFORM_DOMAIN}/callback",
        "https://${PLATFORM_DOMAIN}/",
    ]
    if web_client.get("redirectUris") != expected_redirects:
        return _fail("email-platform-web redirectUris must be exact callback and root")
    attributes = web_client.get("attributes", {})
    if not isinstance(attributes, dict):
        return _fail("email-platform-web attributes are invalid")
    if attributes.get("post.logout.redirect.uris") != "https://${PLATFORM_DOMAIN}/":
        return _fail("email-platform-web logout redirect must be exact root")
    if web_client.get("webOrigins") != ["https://${PLATFORM_DOMAIN}"]:
        return _fail("email-platform-web webOrigins must be the exact origin")

    try:
        oidc_text = load_stable_text(
            OIDC,
            max_bytes=MAX_OIDC_SOURCE_BYTES,
        )
    except (OSError, UnicodeError):
        return _fail("Keycloak OIDC client source is invalid")
    for needle in (
        "redirect_uri: `${window.location.origin}/callback`",
        "post_logout_redirect_uri: `${window.location.origin}/`",
    ):
        if needle not in oidc_text:
            return _fail(f"frontend/src/oidc.ts is missing {needle}")

    print(
        "keycloak-policy-ok "
        "audit-30d-admin-metadata-only-desktop-pkce-refresh-rotation-"
        "exact-redirects-and-browser-mfa"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
