from __future__ import annotations

import json
import unittest
from unittest import mock

from scripts import tls_runtime_identity


class TlsRuntimeIdentityTests(unittest.TestCase):
    def test_probe_observation_is_closed_and_binds_expected_peer(self) -> None:
        fingerprint = "a" * 64
        output = json.dumps(
            {
                "peer_sha256": fingerprint,
                "tls_version": "TLSv1.3",
            }
        )
        self.assertEqual(
            tls_runtime_identity.parse_tls_probe_observation(
                output,
                expected_sha256=fingerprint,
            ),
            {
                "expected_sha256": fingerprint,
                "peer_sha256": fingerprint,
                "tls_version": "TLSv1.3",
            },
        )

        invalid = (
            output.replace(fingerprint, "b" * 64),
            output.replace("TLSv1.3", "TLSv1.1"),
            output[:-1] + ', "private_key_path": "/secret/key"}',
            '{"peer_sha256":"' + fingerprint + '","peer_sha256":"' + fingerprint + '","tls_version":"TLSv1.3"}',
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(
                tls_runtime_identity.TlsRuntimeIdentityError
            ):
                tls_runtime_identity.parse_tls_probe_observation(
                    candidate,
                    expected_sha256=fingerprint,
                )

    def test_probe_program_observes_and_requests_on_one_verified_connection(self) -> None:
        program = tls_runtime_identity.TLS_HTTP_PROBE_PROGRAM
        self.assertIn("http.client.HTTPSConnection", program)
        self.assertIn("connection.connect()", program)
        self.assertIn("connection.sock.getpeercert(binary_form=True)", program)
        self.assertIn("connection.sock.version()", program)
        self.assertIn("connection.request(\"GET\", request_target)", program)
        self.assertIn("socket.create_connection", program)
        self.assertIn("server_hostname=self.host", program)
        self.assertIn("ssl.TLSVersion.TLSv1_2", program)
        self.assertNotIn("urllib.request.urlopen", program)

    def test_probe_arguments_can_separate_connect_address_from_sni_and_host(self) -> None:
        arguments = tls_runtime_identity.probe_arguments(
            "https://api.email-platform.svc:8443/readyz",
            ca_file="/run/secrets/internal-tls/ca.crt",
            max_body_bytes=1024,
            connect_host="10.0.0.42",
        )
        self.assertEqual(arguments[-1], "10.0.0.42")
        self.assertEqual(arguments[0], "https://api.email-platform.svc:8443/readyz")

    def test_expected_internal_fingerprints_use_preflight_report(self) -> None:
        report = {
            "certificates": [
                {"service": "api", "fingerprint_sha256": "a" * 64},
                {"service": "web", "fingerprint_sha256": "b" * 64},
            ]
        }
        with mock.patch.object(
            tls_runtime_identity,
            "evaluate_inventory",
            return_value=(report, 1),
        ) as evaluate:
            result = tls_runtime_identity.expected_internal_fingerprints(
                mock.sentinel.env_file,
                now=mock.sentinel.now,
            )
        self.assertEqual(result, {"api": "a" * 64, "web": "b" * 64})
        evaluate.assert_called_once_with(mock.sentinel.env_file, now=mock.sentinel.now)


if __name__ == "__main__":
    unittest.main()
