import base64
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from platform.auth import OidcAccessTokenVerifier, decode_access_token


_MAX_ACCESS_TOKEN_CHARS = 8 * 1024


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _local_claims() -> dict[str, object]:
    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "sub": "local-user",
        "tenant_id": "tenant-a",
        "device_id": "device-a",
        "jti": "local-token-identifier-00000001",
        "exp": now + 300,
    }


def _oidc_claims(issuer: str) -> dict[str, object]:
    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "sub": "oidc-user",
        "iss": issuer,
        "aud": "email-platform-api",
        "iat": now,
        "exp": now + 300,
        "tenant_id": "tenant-a",
        "device_id": "device-a",
        "jti": "oidc-token-identifier-00000001",
        "azp": "email-platform-desktop",
    }


def _hs256_token(header: bytes, payload: bytes, secret: str) -> str:
    unsigned = f"{_b64url(header)}.{_b64url(payload)}"
    signature = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
    return f"{unsigned}.{_b64url(signature)}"


def _rs256_token(
    header: bytes,
    payload: bytes,
    private_key: rsa.RSAPrivateKey,
) -> str:
    unsigned = f"{_b64url(header)}.{_b64url(payload)}"
    signature = private_key.sign(unsigned.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{unsigned}.{_b64url(signature)}"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _payload_for_exact_token_size(
    claims: dict[str, object],
    *,
    header: bytes,
    signature_bytes: int,
    target_chars: int,
) -> bytes:
    signature_chars = len(_b64url(b"\0" * signature_bytes))
    for padding_chars in range(target_chars):
        payload = _json_bytes({**claims, "padding": "x" * padding_chars})
        token_chars = (
            len(_b64url(header)) + 1 + len(_b64url(payload)) + 1 + signature_chars
        )
        if token_chars == target_chars:
            return payload
        if token_chars > target_chars:
            break
    raise AssertionError("Could not construct the requested compact JWT size")


class AccessTokenBoundaryTests(unittest.TestCase):
    secret = "access-token-boundary-secret"
    issuer = "https://identity.example.test/realms/email-platform"

    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def verifier(self) -> tuple[OidcAccessTokenVerifier, Mock]:
        verifier = OidcAccessTokenVerifier(
            issuer=self.issuer,
            audience="email-platform-api",
            jwks_url=f"{self.issuer}/protocol/openid-connect/certs",
            allowed_client_ids=("email-platform-web", "email-platform-desktop"),
        )
        signing_key = Mock(
            return_value=SimpleNamespace(key=self.private_key.public_key())
        )
        verifier.jwks_client.get_signing_key_from_jwt = signing_key
        return verifier, signing_key

    def test_local_accepts_exact_limit_and_rejects_oversize_before_hmac(self) -> None:
        header = b'{"alg":"HS256","typ":"JWT"}'
        exact_payload = _payload_for_exact_token_size(
            _local_claims(),
            header=header,
            signature_bytes=32,
            target_chars=_MAX_ACCESS_TOKEN_CHARS,
        )
        exact_token = _hs256_token(header, exact_payload, self.secret)
        self.assertEqual(len(exact_token), _MAX_ACCESS_TOKEN_CHARS)
        self.assertEqual(decode_access_token(exact_token, self.secret)["sub"], "local-user")

        oversized_payload = _payload_for_exact_token_size(
            _local_claims(),
            header=header,
            signature_bytes=32,
            target_chars=_MAX_ACCESS_TOKEN_CHARS + 1,
        )
        oversized_token = _hs256_token(header, oversized_payload, self.secret)
        with patch("platform.auth.hmac.new") as signer:
            with self.assertRaisesRegex(ValueError, "^Invalid access token$") as raised:
                decode_access_token(oversized_token, self.secret)
        signer.assert_not_called()
        self.assertIsNone(raised.exception.__cause__)

    def test_local_rejects_duplicate_keys_and_invalid_utf8_without_cause(self) -> None:
        claims = _local_claims()
        payload = _json_bytes(claims)
        duplicate_claim = payload[:-1] + b',"jti":"local-token-identifier-00000001"}'
        nested_duplicate = payload[:-1] + b',"context":{"v":1,"v":1}}'
        invalid_utf8 = payload[:-1] + b',"context":"\xff"}'
        deeply_nested = b"[" * 3000 + b"0" + b"]" * 3000
        cases = (
            (
                b'{"alg":"HS256","typ":"JWT","alg":"HS256"}',
                payload,
            ),
            (b'{"alg":"HS256","typ":"JWT"}', duplicate_claim),
            (b'{"alg":"HS256","typ":"JWT"}', nested_duplicate),
            (b'{"alg":"HS256","typ":"JWT"}', invalid_utf8),
            (b'{"alg":"HS256","typ":"JWT"}', deeply_nested),
        )
        for header, candidate_payload in cases:
            token = _hs256_token(header, candidate_payload, self.secret)
            with self.subTest(token_length=len(token)):
                with self.assertRaisesRegex(
                    ValueError, "^Invalid access token$"
                ) as raised:
                    decode_access_token(token, self.secret)
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn(token, str(raised.exception))

    def test_oidc_accepts_exact_access_token_limit(self) -> None:
        header = b'{"alg":"RS256","typ":"JWT","kid":"test"}'
        payload = _payload_for_exact_token_size(
            _oidc_claims(self.issuer),
            header=header,
            signature_bytes=self.private_key.key_size // 8,
            target_chars=_MAX_ACCESS_TOKEN_CHARS,
        )
        token = _rs256_token(header, payload, self.private_key)
        verifier, signing_key = self.verifier()

        self.assertEqual(len(token), _MAX_ACCESS_TOKEN_CHARS)
        self.assertEqual(verifier.verify(token)["sub"], "oidc-user")
        signing_key.assert_called_once_with(token)

    def test_oidc_rejects_ambiguous_or_oversized_tokens_before_jwks(self) -> None:
        header = b'{"alg":"RS256","typ":"JWT","kid":"test"}'
        payload = _json_bytes(_oidc_claims(self.issuer))
        duplicate_claim = payload[:-1] + b',"azp":"email-platform-desktop"}'
        nested_duplicate = payload[:-1] + b',"context":{"v":1,"v":1}}'
        invalid_utf8 = payload[:-1] + b',"context":"\xff"}'
        deeply_nested = b"[" * 3000 + b"0" + b"]" * 3000
        oversized_header = _json_bytes(
            {"alg": "RS256", "typ": "JWT", "kid": "test", "padding": "x" * 2048}
        )
        oversized_payload = _payload_for_exact_token_size(
            _oidc_claims(self.issuer),
            header=header,
            signature_bytes=self.private_key.key_size // 8,
            target_chars=_MAX_ACCESS_TOKEN_CHARS + 1,
        )
        cases = (
            (
                b'{"alg":"RS256","typ":"JWT","kid":"test","alg":"RS256"}',
                payload,
            ),
            (header, duplicate_claim),
            (header, nested_duplicate),
            (header, invalid_utf8),
            (header, deeply_nested),
            (oversized_header, payload),
            (header, oversized_payload),
        )
        verifier, signing_key = self.verifier()
        for candidate_header, candidate_payload in cases:
            token = _rs256_token(candidate_header, candidate_payload, self.private_key)
            with self.subTest(token_length=len(token)):
                with self.assertRaisesRegex(
                    ValueError, "^Invalid OIDC access token$"
                ) as raised:
                    verifier.verify(token)
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn(token, str(raised.exception))
        signing_key.assert_not_called()


if __name__ == "__main__":
    unittest.main()
