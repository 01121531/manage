import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from platform.auth import OidcAccessTokenVerifier


class OidcVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.issuer = "https://identity.example.test/realms/email-platform"
        self.verifier = OidcAccessTokenVerifier(
            issuer=self.issuer,
            audience="email-platform-api",
            jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
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
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "test"})

    def test_verifies_signature_issuer_audience_and_required_binding_claims(self) -> None:
        claims = self.verifier.verify(self.token())
        self.assertEqual(claims["tenant_id"], "tenant-a")
        self.assertEqual(claims["device_id"], "device-a")
        self.assertEqual(claims["identity_kind"], "oidc")

    def test_rejects_wrong_audience_and_missing_device(self) -> None:
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(aud="another-api"))
        with self.assertRaises(ValueError):
            self.verifier.verify(self.token(device_id=""))


if __name__ == "__main__":
    unittest.main()
