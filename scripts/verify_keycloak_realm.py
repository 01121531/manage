"""Verify Keycloak realm export keeps MFA and redirects tightly scoped."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "infra" / "keycloak" / "email-platform-realm.json"
OIDC = ROOT / "frontend" / "src" / "oidc.ts"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    realm = json.loads(REALM.read_text(encoding="utf-8"))
    required_actions = {
        item.get("alias"): item
        for item in realm.get("requiredActions", [])
        if isinstance(item, dict)
    }
    otp_action = required_actions.get("CONFIGURE_TOTP")
    if not otp_action:
        return _fail("Keycloak realm is missing CONFIGURE_TOTP required action")
    for key, expected in {"enabled": True, "defaultAction": True}.items():
        if otp_action.get(key) is not expected:
            return _fail(f"CONFIGURE_TOTP must set {key}={expected}")

    if realm.get("otpPolicyType") != "totp":
        return _fail("Keycloak realm must use TOTP policy")

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

    oidc_text = OIDC.read_text(encoding="utf-8")
    for needle in (
        "redirect_uri: `${window.location.origin}/callback`",
        "post_logout_redirect_uri: `${window.location.origin}/`",
    ):
        if needle not in oidc_text:
            return _fail(f"frontend/src/oidc.ts is missing {needle}")

    print("keycloak-policy-ok desktop-pkce-refresh-rotation-exact-redirects-and-totp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
