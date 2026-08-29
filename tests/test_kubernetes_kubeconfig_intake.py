from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import yaml

from scripts.kubernetes_kubeconfig_intake import (
    MAX_DECODED_CA_BYTES,
    MAX_DECODED_CLIENT_CERT_BYTES,
    MAX_DECODED_CLIENT_KEY_BYTES,
    MAX_KUBECONFIG_BYTES,
    MAX_TOKEN_BYTES,
    KubernetesKubeconfigIntakeError,
    validate_self_contained_kubeconfig,
)


CONTEXT = "production-cluster"
NAMESPACE = "email-platform"
TOKEN = "reviewed-static-token-" + "a" * 32


def _certificate_material() -> tuple[bytes, bytes, bytes, bytes]:
    now = datetime.now(timezone.utc)
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, algorithm=None)
    )

    client_key = ed25519.Ed25519PrivateKey.generate()
    client_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tls-rotation-client")]
    )
    client_certificate = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, algorithm=None)
    )
    return (
        ca_certificate.public_bytes(serialization.Encoding.PEM),
        client_certificate.public_bytes(serialization.Encoding.PEM),
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _encoded(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class KubernetesKubeconfigIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ca_pem, cls.client_pem, cls.client_key_pem, cls.other_key_pem = (
            _certificate_material()
        )

    def _config(self, user: dict[str, object] | None = None) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Config",
            "preferences": {},
            "clusters": [
                {
                    "name": "production",
                    "cluster": {
                        "server": "https://api.production.invalid:6443",
                        "certificate-authority-data": _encoded(self.ca_pem),
                    },
                }
            ],
            "users": [{"name": "rotation", "user": user or {"token": TOKEN}}],
            "contexts": [
                {
                    "name": CONTEXT,
                    "context": {
                        "cluster": "production",
                        "user": "rotation",
                        "namespace": NAMESPACE,
                    },
                }
            ],
            "current-context": CONTEXT,
        }

    @staticmethod
    def _raw(config: dict[str, object]) -> bytes:
        return json.dumps(config, sort_keys=True, separators=(",", ":")).encode()

    def _assert_invalid(self, raw: bytes, *secrets: str) -> None:
        with self.assertRaises(KubernetesKubeconfigIntakeError) as raised:
            validate_self_contained_kubeconfig(
                raw,
                expected_context=CONTEXT,
                expected_namespace=NAMESPACE,
            )
        message = str(raised.exception)
        self.assertEqual(message, "Kubernetes kubeconfig intake is invalid")
        for secret in secrets:
            if secret:
                self.assertNotIn(secret, message)

    def test_valid_high_entropy_token_returns_raw_snapshot_digest(self) -> None:
        config = self._config()
        config["clusters"][0]["cluster"].update(
            {"tls-server-name": "api.production.invalid", "disable-compression": True}
        )
        raw = self._raw(config)
        self.assertEqual(
            validate_self_contained_kubeconfig(
                raw,
                expected_context=CONTEXT,
                expected_namespace=NAMESPACE,
            ),
            hashlib.sha256(raw).hexdigest(),
        )

    def test_valid_matching_ed25519_client_certificate_and_key(self) -> None:
        raw = self._raw(
            self._config(
                {
                    "client-certificate-data": _encoded(self.client_pem),
                    "client-key-data": _encoded(self.client_key_pem),
                }
            )
        )
        self.assertEqual(
            validate_self_contained_kubeconfig(
                raw,
                expected_context=CONTEXT,
                expected_namespace=NAMESPACE,
            ),
            hashlib.sha256(raw).hexdigest(),
        )

    def test_rejects_file_references_and_dynamic_authentication(self) -> None:
        mutations: list[tuple[str, dict[str, object], str]] = []

        ca_path = self._config()
        ca_path["clusters"][0]["cluster"] = {
            "server": "https://api.production.invalid:6443",
            "certificate-authority": "relative/ca.pem",
        }
        mutations.append(("certificate-authority", ca_path, "relative/ca.pem"))

        for label, user in (
            ("client-files", {"client-certificate": "client.pem", "client-key": "client.key"}),
            ("token-file", {"tokenFile": "token.txt"}),
            (
                "exec",
                {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1",
                        "command": "C:/secret/plugin.exe",
                        "interactiveMode": "Never",
                    }
                },
            ),
            ("auth-provider", {"auth-provider": {"name": "oidc", "config": {}}}),
            ("basic-auth", {"username": "operator", "password": "secret-password"}),
            (
                "impersonation",
                {
                    "token": TOKEN,
                    "as": "cluster-admin",
                    "as-uid": "1000",
                    "as-groups": ["system:masters"],
                    "as-user-extra": {"scope": ["all"]},
                },
            ),
        ):
            mutations.append((label, self._config(user), json.dumps(user)))

        for label, config, secret in mutations:
            with self.subTest(case=label):
                self._assert_invalid(self._raw(config), secret)

    def test_rejects_proxy_insecure_tls_and_extensions(self) -> None:
        mutations: list[tuple[str, dict[str, object]]] = []
        for field, value in (
            ("proxy-url", "https://proxy-secret.invalid"),
            ("insecure-skip-tls-verify", True),
            ("extensions", [{"name": "hidden", "extension": {"secret": "value"}}]),
        ):
            config = self._config()
            config["clusters"][0]["cluster"][field] = value
            mutations.append((f"cluster-{field}", config))

        top = self._config()
        top["extensions"] = [{"name": "hidden", "extension": {}}]
        mutations.append(("top-extensions", top))
        user = self._config()
        user["users"][0]["user"]["extensions"] = []
        mutations.append(("user-extensions", user))
        context = self._config()
        context["contexts"][0]["context"]["extensions"] = []
        mutations.append(("context-extensions", context))

        for label, config in mutations:
            with self.subTest(case=label):
                self._assert_invalid(self._raw(config), "proxy-secret.invalid", "hidden")

    def test_rejects_context_namespace_reference_and_https_drift(self) -> None:
        mutations: list[tuple[str, dict[str, object]]] = []
        for label, mutate in (
            ("current-context", lambda value: value.update({"current-context": "other"})),
            ("context-name", lambda value: value["contexts"][0].update({"name": "other"})),
            ("cluster-ref", lambda value: value["contexts"][0]["context"].update({"cluster": "other"})),
            ("user-ref", lambda value: value["contexts"][0]["context"].update({"user": "other"})),
            ("namespace", lambda value: value["contexts"][0]["context"].update({"namespace": "other"})),
            ("http", lambda value: value["clusters"][0]["cluster"].update({"server": "http://api.production.invalid"})),
            ("userinfo", lambda value: value["clusters"][0]["cluster"].update({"server": "https://user:password@api.production.invalid"})),
            ("query", lambda value: value["clusters"][0]["cluster"].update({"server": "https://api.production.invalid?token=secret"})),
            ("fragment", lambda value: value["clusters"][0]["cluster"].update({"server": "https://api.production.invalid/#secret"})),
        ):
            config = self._config()
            mutate(config)
            mutations.append((label, config))

        for label, config in mutations:
            with self.subTest(case=label):
                self._assert_invalid(self._raw(config), "password", "token=secret")

    def test_rejects_invalid_or_noncanonical_base64_and_non_ca_certificate(self) -> None:
        mutations: list[tuple[str, str]] = [
            ("invalid-alphabet", "***not-base64***"),
            ("noncanonical", _encoded(self.ca_pem) + "="),
            ("not-a-certificate", _encoded(b"not a PEM certificate")),
            ("not-a-ca", _encoded(self.client_pem)),
        ]
        for label, authority in mutations:
            config = self._config()
            config["clusters"][0]["cluster"]["certificate-authority-data"] = authority
            with self.subTest(case=label):
                self._assert_invalid(self._raw(config), authority[:24])

    def test_rejects_mismatched_or_encrypted_client_key(self) -> None:
        encrypted = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret-passphrase"),
        )
        for label, key in (("mismatch", self.other_key_pem), ("encrypted", encrypted)):
            raw = self._raw(
                self._config(
                    {
                        "client-certificate-data": _encoded(self.client_pem),
                        "client-key-data": _encoded(key),
                    }
                )
            )
            with self.subTest(case=label):
                self._assert_invalid(raw, "secret-passphrase")

    def test_rejects_duplicate_yaml_key_anchor_alias_and_explicit_tag(self) -> None:
        source = yaml.safe_dump(self._config(), sort_keys=False)
        mutations = {
            "duplicate-key": source.replace(
                "apiVersion: v1\n", "apiVersion: v1\napiVersion: v1\n", 1
            ),
            "anchor": source.replace("preferences: {}\n", "preferences: &prefs {}\n", 1),
            "alias": source.replace(
                "preferences: {}\n",
                "preferences: &prefs {}\nextensions: *prefs\n",
                1,
            ),
            "tag": source.replace("preferences: {}\n", "preferences: !!map {}\n", 1),
        }
        for label, changed in mutations.items():
            self.assertNotEqual(changed, source)
            with self.subTest(case=label):
                self._assert_invalid(changed.encode())

    def test_rejects_oversized_input_material_and_token(self) -> None:
        oversized_ca = self._config()
        oversized_ca["clusters"][0]["cluster"]["certificate-authority-data"] = _encoded(
            b"x" * (MAX_DECODED_CA_BYTES + 1)
        )
        oversized_certificate = self._config(
            {
                "client-certificate-data": _encoded(
                    b"x" * (MAX_DECODED_CLIENT_CERT_BYTES + 1)
                ),
                "client-key-data": _encoded(self.client_key_pem),
            }
        )
        oversized_key = self._config(
            {
                "client-certificate-data": _encoded(self.client_pem),
                "client-key-data": _encoded(
                    b"x" * (MAX_DECODED_CLIENT_KEY_BYTES + 1)
                ),
            }
        )
        oversized_token = self._config({"token": "t" * (MAX_TOKEN_BYTES + 1)})
        for label, raw in (
            ("raw", b"x" * (MAX_KUBECONFIG_BYTES + 1)),
            ("ca", self._raw(oversized_ca)),
            ("certificate", self._raw(oversized_certificate)),
            ("key", self._raw(oversized_key)),
            ("token", self._raw(oversized_token)),
        ):
            with self.subTest(case=label):
                self._assert_invalid(raw)

    def test_rejects_short_non_ascii_whitespace_and_control_tokens(self) -> None:
        tokens = {
            "empty": "",
            "short": "a" * 31,
            "non-ascii": "a" * 31 + "é",
            "space": "a" * 16 + " " + "b" * 16,
            "newline": "a" * 16 + "\n" + "b" * 16,
            "control": "a" * 16 + "\x1f" + "b" * 16,
        }
        for label, token in tokens.items():
            with self.subTest(case=label):
                self._assert_invalid(self._raw(self._config({"token": token})), token)

    def test_rejects_invalid_input_types_and_expected_identity(self) -> None:
        for raw in (b"", b"\xff", bytearray(self._raw(self._config()))):
            with self.subTest(raw_type=type(raw).__name__):
                with self.assertRaisesRegex(
                    KubernetesKubeconfigIntakeError,
                    "^Kubernetes kubeconfig intake is invalid$",
                ):
                    validate_self_contained_kubeconfig(
                        raw,
                        expected_context=CONTEXT,
                        expected_namespace=NAMESPACE,
                    )
        raw = self._raw(self._config())
        for context, namespace in (("", NAMESPACE), (CONTEXT, "Invalid_Namespace")):
            with self.subTest(context=context, namespace=namespace):
                with self.assertRaisesRegex(
                    KubernetesKubeconfigIntakeError,
                    "^Kubernetes kubeconfig intake is invalid$",
                ):
                    validate_self_contained_kubeconfig(
                        raw,
                        expected_context=context,
                        expected_namespace=namespace,
                    )


if __name__ == "__main__":
    unittest.main()
