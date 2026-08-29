import asyncio
import ssl
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import jwt
import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import func, select

from platform.app import create_app
from platform.auth import OidcAccessTokenVerifier
from platform.bootstrap import create_oidc_user_with_device
from platform.config import Settings
from platform.models import AuditEvent, Device, Task


class OidcVerifierTests(unittest.TestCase):
    web_client_id = "email-platform-web"
    desktop_client_id = "email-platform-desktop"

    def setUp(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.issuer = "https://identity.example.test/realms/email-platform"
        self.verifier = OidcAccessTokenVerifier(
            issuer=self.issuer,
            audience="email-platform-api",
            jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
            allowed_client_ids=(self.web_client_id, self.desktop_client_id),
        )
        self.verifier.jwks_client.get_signing_key_from_jwt = lambda _: SimpleNamespace(
            key=self.private_key.public_key()
        )

    def token(self, **overrides: object) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "keycloak-subject-1",
            "iss": self.issuer,
            "aud": "email-platform-api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "tenant_id": "tenant-a",
            "device_id": "device-a",
            "jti": "oidc-test-token-identifier-0001",
            "azp": self.desktop_client_id,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "test"})

    def test_verifies_signature_issuer_audience_and_required_binding_claims(self) -> None:
        claims = self.verifier.verify(self.token())
        self.assertEqual(claims["tenant_id"], "tenant-a")
        self.assertEqual(claims["device_id"], "device-a")
        self.assertEqual(claims["azp"], self.desktop_client_id)
        self.assertEqual(claims["identity_kind"], "oidc")

        web_claims = self.verifier.verify(self.token(azp=self.web_client_id))
        self.assertEqual(web_claims["azp"], self.web_client_id)

    def test_rejects_missing_malformed_and_unreviewed_authorized_party(self) -> None:
        now = datetime.now(timezone.utc)
        claims_without_azp = {
            "sub": "keycloak-subject-1",
            "iss": self.issuer,
            "aud": "email-platform-api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "tenant_id": "tenant-a",
            "device_id": "device-a",
            "jti": "oidc-test-token-identifier-0001",
        }
        missing_azp = jwt.encode(
            claims_without_azp,
            self.private_key,
            algorithm="RS256",
            headers={"kid": "test"},
        )
        with self.assertRaises(ValueError):
            self.verifier.verify(missing_azp)

        for value in (
            None,
            "",
            " email-platform-web",
            [self.web_client_id],
            "email-platform-api",
            "unreviewed-client",
        ):
            with self.subTest(azp=value), self.assertRaises(ValueError):
                self.verifier.verify(self.token(azp=value))

    def test_allows_multiple_audiences_only_for_an_allowed_authorized_party(self) -> None:
        claims = self.verifier.verify(
            self.token(
                aud=["email-platform-api", "profile-service"],
                azp=self.web_client_id,
            )
        )
        self.assertEqual(claims["azp"], self.web_client_id)
        with self.assertRaises(ValueError):
            self.verifier.verify(
                self.token(
                    aud=["email-platform-api", "profile-service"],
                    azp="unreviewed-client",
                )
            )

    def test_constructor_rejects_empty_drifted_and_duplicate_client_ids(self) -> None:
        invalid_allowlists = (
            (),
            [self.web_client_id, self.desktop_client_id],
            self.web_client_id,
            ("",),
            ("   ",),
            (" email-platform-web",),
            ("email-platform-web ",),
            ("x" * 256,),
            (self.web_client_id, self.web_client_id),
        )
        with patch("platform.auth.PyJWKClient") as jwks_client:
            for allowed_client_ids in invalid_allowlists:
                with self.subTest(allowed_client_ids=allowed_client_ids):
                    with self.assertRaises(ValueError):
                        OidcAccessTokenVerifier(
                            issuer=self.issuer,
                            audience="email-platform-api",
                            jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
                            allowed_client_ids=allowed_client_ids,
                        )
            jwks_client.assert_not_called()

    def test_app_wires_the_web_and_desktop_clients_into_the_verifier(self) -> None:
        app = create_app(
            Settings(
                environment="test",
                auth_mode="oidc",
                database_url="sqlite+pysqlite:///:memory:",
                oidc_issuer_url=self.issuer,
                oidc_audience="email-platform-api",
                oidc_client_id=self.web_client_id,
                oidc_desktop_client_id=self.desktop_client_id,
                oidc_jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
            )
        )
        try:
            verifier = app.state.access_token_verifier
            self.assertIsInstance(verifier, OidcAccessTokenVerifier)
            self.assertEqual(
                verifier.allowed_client_ids,
                frozenset((self.web_client_id, self.desktop_client_id)),
            )
        finally:
            app.state.engine.dispose()

    def test_unreviewed_client_is_rejected_before_api_or_device_side_effects(self) -> None:
        app = create_app(
            Settings(
                environment="test",
                auth_mode="oidc",
                database_url="sqlite+pysqlite:///:memory:",
                oidc_issuer_url=self.issuer,
                oidc_audience="email-platform-api",
                oidc_client_id=self.web_client_id,
                oidc_desktop_client_id=self.desktop_client_id,
                oidc_jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
            )
        )
        try:
            identity = create_oidc_user_with_device(
                app.state.session_factory,
                tenant_id="tenant-a",
                email="operator@example.test",
                oidc_subject="keycloak-subject-1",
                device_name="reviewed-device",
            )
            verifier = app.state.access_token_verifier
            verifier.jwks_client.get_signing_key_from_jwt = (
                lambda _: SimpleNamespace(key=self.private_key.public_key())
            )
            token = self.token(
                device_id=identity.device_id,
                azp="unreviewed-client",
            )

            async def request() -> httpx.Response:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as client:
                    return await client.post(
                        "/api/v1/tasks",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"type": "mail_code", "idempotency_key": "rogue-client"},
                    )

            response = asyncio.run(request())
            self.assertEqual(response.status_code, 401, response.text)
            self.assertEqual(response.json()["error"]["code"], "unauthorized")
            with app.state.session_factory() as db:
                self.assertIsNone(db.get(Device, identity.device_id).last_seen_at)
                self.assertEqual(
                    db.scalar(select(func.count()).select_from(Task)), 0
                )
                self.assertEqual(
                    db.scalar(select(func.count()).select_from(AuditEvent)), 0
                )
        finally:
            app.state.engine.dispose()

    def test_rejects_wrong_audience_and_missing_device(self) -> None:
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(aud="another-api"))
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(device_id=""))
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(jti=""))
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(jti="predictable"))

    def test_internal_ca_builds_verified_tls_1_2_jwks_context(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with (
            patch("platform.auth.ssl.create_default_context", return_value=context) as create_context,
            patch("platform.auth.PyJWKClient") as jwks_client,
        ):
            OidcAccessTokenVerifier(
                issuer=self.issuer,
                audience="email-platform-api",
                jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
                allowed_client_ids=(self.web_client_id, self.desktop_client_id),
                internal_ca_file="/run/secrets/internal-tls/ca.crt",
            )

        create_context.assert_called_once_with(
            cafile="/run/secrets/internal-tls/ca.crt"
        )
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        jwks_client.assert_called_once_with(
            f"{self.issuer}/protocol/openid-connect/certs",
            cache_keys=True,
            ssl_context=context,
        )


if __name__ == "__main__":
    unittest.main()
