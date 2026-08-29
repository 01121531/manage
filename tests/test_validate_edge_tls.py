from __future__ import annotations

from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts import validate_edge_tls as edge_tls
from scripts import backup_crypto
from scripts import external_json


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
DOMAIN = "platform.example.com"


def certificate_and_key(
    *,
    san: str = DOMAIN,
    additional_sans: tuple[str, ...] = (),
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=30),
    is_ca: bool = False,
) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (san, *additional_sans)]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class EdgeTlsValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.cert = self.root / "fullchain.pem"
        self.key = self.root / "privkey.pem"
        cert_pem, key_pem = certificate_and_key(
            additional_sans=(f"identity.{DOMAIN}",)
        )
        self.cert.write_bytes(cert_pem)
        self.key.write_bytes(key_pem)
        if os.name != "nt":
            self.key.chmod(0o600)
        else:
            permission_patch = mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                return_value="test-acl",
            )
            permission_patch.start()
            self.addCleanup(permission_patch.stop)
        self.env = self.root / "production.env"
        self.write_env()

    def write_env(self, *, cert: Path | None = None, key: Path | None = None) -> None:
        self.env.write_text(
            f"PLATFORM_TLS_CERT_FILE={cert or self.cert}\n"
            f"PLATFORM_TLS_KEY_FILE={key or self.key}\n",
            encoding="utf-8",
        )

    def test_accepts_required_sans_and_matching_key(self) -> None:
        expected = x509.load_pem_x509_certificate(self.cert.read_bytes()).fingerprint(
            hashes.SHA256()
        ).hex()
        self.assertEqual(
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW),
            expected,
        )

    def test_requires_both_platform_and_identity_hostnames(self) -> None:
        cert_pem, key_pem = certificate_and_key()
        self.cert.write_bytes(cert_pem)
        self.key.write_bytes(key_pem)
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

        cert_pem, key_pem = certificate_and_key(
            additional_sans=(f"identity.{DOMAIN}",)
        )
        self.cert.write_bytes(cert_pem)
        self.key.write_bytes(key_pem)
        edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_rejects_missing_duplicate_relative_and_same_path_inputs(self) -> None:
        cases = (
            "PLATFORM_TLS_CERT_FILE=\nPLATFORM_TLS_KEY_FILE=\n",
            (
                f"PLATFORM_TLS_CERT_FILE={self.cert}\n"
                f"PLATFORM_TLS_CERT_FILE={self.cert}\n"
                f"PLATFORM_TLS_KEY_FILE={self.key}\n"
            ),
            "PLATFORM_TLS_CERT_FILE=relative.pem\nPLATFORM_TLS_KEY_FILE=key.pem\n",
            (
                f"PLATFORM_TLS_CERT_FILE={self.cert}\n"
                f"PLATFORM_TLS_KEY_FILE={self.cert}\n"
            ),
        )
        for index, content in enumerate(cases):
            with self.subTest(index=index):
                self.env.write_text(content, encoding="utf-8")
                with self.assertRaises(edge_tls.EdgeTlsError):
                    edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_rejects_wrong_san_ca_expired_future_and_mismatched_key(self) -> None:
        mutations = (
            certificate_and_key(san="wrong.example.com"),
            certificate_and_key(is_ca=True),
            certificate_and_key(not_after=NOW),
            certificate_and_key(not_before=NOW + timedelta(seconds=1)),
            (certificate_and_key()[0], certificate_and_key()[1]),
        )
        for index, (cert_pem, key_pem) in enumerate(mutations):
            with self.subTest(index=index):
                self.cert.write_bytes(cert_pem)
                self.key.write_bytes(key_pem)
                with self.assertRaises(edge_tls.EdgeTlsError):
                    edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_rejects_malformed_directory_repository_and_symlink_files(self) -> None:
        self.cert.write_text("not a certificate", encoding="utf-8")
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

        cert_pem, key_pem = certificate_and_key()
        self.cert.write_bytes(cert_pem)
        self.key.write_text("not a private key", encoding="utf-8")
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

        self.key.unlink()
        self.key.mkdir()
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

        self.key.rmdir()
        self.key.write_bytes(key_pem)
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(
                self.env,
                DOMAIN,
                now=NOW,
                repository_root=self.root,
            )

        link = self.root / "linked-cert.pem"
        try:
            link.symlink_to(self.cert)
        except OSError:
            return
        self.write_env(cert=link)
        with self.assertRaises(edge_tls.EdgeTlsError):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_cli_error_is_redacted(self) -> None:
        leaked = str(self.cert)
        self.env.write_text(
            f"PLATFORM_TLS_CERT_FILE={leaked}\nPLATFORM_TLS_KEY_FILE=missing\n",
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = edge_tls.main(
                ["--env-file", str(self.env), "--domain", DOMAIN],
                now=NOW,
            )
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue().strip(), "edge-tls-input-invalid")
        self.assertNotIn(leaked, stderr.getvalue())

    def test_certificate_chain_and_private_key_are_bounded_by_type(self) -> None:
        cases = ((self.cert, 256 * 1024), (self.key, 64 * 1024))
        for path, limit in cases:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b" " * (limit - len(original)))

                edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

                path.write_bytes(path.read_bytes() + b" ")

                with self.assertRaisesRegex(
                    edge_tls.EdgeTlsError,
                    "^edge TLS material is invalid$",
                ):
                    edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)
                path.write_bytes(original)

    def test_material_does_not_use_path_read_bytes(self) -> None:
        original_read_bytes = Path.read_bytes

        def reject_pem_read_bytes(path: Path) -> bytes:
            if path in {self.cert, self.key}:
                raise AssertionError("PEM Path.read_bytes bypassed stable loading")
            return original_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", reject_pem_read_bytes):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_private_key_uses_the_shared_private_secret_boundary(self) -> None:
        key_bytes = self.key.read_bytes()
        with mock.patch.object(
            edge_tls,
            "read_private_secret_bytes",
            return_value=key_bytes,
            create=True,
        ) as stable_read:
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)
        stable_read.assert_called_once_with(
            self.key.resolve(),
            max_bytes=edge_tls.MAX_PRIVATE_KEY_BYTES,
        )

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_rejects_group_or_world_accessible_private_key(self) -> None:
        self.key.chmod(0o640)
        with self.assertRaisesRegex(
            edge_tls.EdgeTlsError,
            "^edge TLS material is invalid$",
        ):
            edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

    def test_link_or_reparse_material_is_rejected_before_open(self) -> None:
        real_open = os.open
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            side_effect=lambda path: path != self.env,
        ), mock.patch.object(external_json.os, "open", wraps=real_open) as open_file:
            with self.assertRaisesRegex(
                edge_tls.EdgeTlsError,
                "^edge TLS material is invalid$",
            ):
                edge_tls.validate_edge_tls(self.env, DOMAIN, now=NOW)

        self.assertEqual([Path(call.args[0]) for call in open_file.call_args_list], [self.env])

    def test_named_material_replacement_during_read_is_redacted(self) -> None:
        real_lstat = Path.lstat
        calls = 0

        def drifting_lstat(path: Path):
            nonlocal calls
            calls += 1
            metadata = real_lstat(path)
            if calls == 2:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size + 1,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )
            return metadata

        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=False,
        ), mock.patch.object(Path, "lstat", drifting_lstat):
            with self.assertRaisesRegex(
                edge_tls.EdgeTlsError,
                "^edge TLS material is invalid$",
            ) as raised:
                edge_tls._validate_material(self.cert, self.key, DOMAIN, NOW)

        self.assertEqual(calls, 2)
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_repository_source_keeps_stable_bounded_pem_reads(self) -> None:
        source = Path(edge_tls.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_bytes()", source)
        self.assertIn("MAX_CERTIFICATE_CHAIN_BYTES = 256 * 1024", source)
        self.assertIn("MAX_PRIVATE_KEY_BYTES = 64 * 1024", source)
        self.assertGreaterEqual(source.count("read_stable_bytes("), 2)


if __name__ == "__main__":
    unittest.main()
