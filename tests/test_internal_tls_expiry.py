import io
import json
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import check_internal_tls_expiry as expiry
from scripts import backup_crypto
from scripts import external_json
from scripts import private_secret_file
from scripts import verify_internal_tls


FIXED_NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def certificate_pem(*, service: str, not_before: datetime, not_after: datetime) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(service)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def ca_material(*, not_before: datetime, not_after: datetime) -> tuple[bytes, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "email-platform-ca")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key


def signed_leaf_material(
    *,
    service: str,
    san: str,
    not_before: datetime,
    not_after: datetime,
    ca_certificate_pem: bytes,
    ca_key: object,
) -> tuple[bytes, bytes]:
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class InternalTlsExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name == "nt":
            permission_patch = patch.object(
                backup_crypto,
                "_validate_key_permissions",
                return_value="test-acl",
            )
            permission_patch.start()
            self.addCleanup(permission_patch.stop)

    def make_inventory(
        self,
        directory: Path,
        *,
        remaining: dict[str, timedelta] | None = None,
    ) -> Path:
        remaining = remaining or {}
        ca_pem, ca_key = ca_material(
            not_before=FIXED_NOW - timedelta(days=365),
            not_after=FIXED_NOW + timedelta(days=365),
        )
        ca_path = directory / "ca.crt"
        ca_path.write_bytes(ca_pem)
        self.inventory_ca_key = ca_key
        lines = [f"PLATFORM_INTERNAL_CA_FILE={ca_path}"]
        for service, variable in expiry.CERTIFICATE_ENV.items():
            certificate_path = directory / f"{service}.crt"
            key_path = directory / f"{service}.key"
            certificate, private_key = signed_leaf_material(
                service=service,
                san=service,
                not_before=FIXED_NOW - timedelta(days=1),
                not_after=FIXED_NOW + remaining.get(service, timedelta(days=31)),
                ca_certificate_pem=ca_pem,
                ca_key=ca_key,
            )
            certificate_path.write_bytes(certificate)
            key_path.write_bytes(private_key)
            if os.name != "nt":
                key_path.chmod(0o600)
            lines.append(f"{variable}={certificate_path}")
            lines.append(
                f"{expiry.KEY_ENV[service]}={key_path}"
            )
        env_file = directory / "production.env"
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return env_file

    def run_main(self, env_file: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = expiry.main(["--env-file", str(env_file)], now=FIXED_NOW)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_fixed_inventory_and_threshold_boundaries(self) -> None:
        self.assertEqual(
            tuple(expiry.CERTIFICATE_ENV),
            (
                "api",
                "web",
                "api-green",
                "web-green",
                "keycloak",
                "worker-mail",
                "worker-sub2",
                "prometheus",
                "alertmanager",
            ),
        )
        self.assertEqual(expiry.THRESHOLDS_DAYS, (30, 14, 7))
        self.assertEqual(expiry.CA_ENV, "PLATFORM_INTERNAL_CA_FILE")
        self.assertEqual(set(expiry.KEY_ENV), set(expiry.CERTIFICATE_ENV))
        cases = (
            (timedelta(days=30), "alert_30", expiry.EXIT_ALERT),
            (timedelta(days=14), "alert_14", expiry.EXIT_ALERT),
            (timedelta(days=7), "alert_7", expiry.EXIT_ALERT),
            (timedelta(days=7) - timedelta(seconds=1), "page", expiry.EXIT_PAGE),
            (timedelta(0), "expired", expiry.EXIT_PAGE),
            (timedelta(days=31), "ok", expiry.EXIT_OK),
        )
        for remaining, state, exit_code in cases:
            with self.subTest(remaining=remaining):
                self.assertEqual(expiry.classify_remaining(remaining), (state, exit_code))

    def test_cli_emits_redacted_json_and_uses_highest_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(
                directory,
                remaining={"api": timedelta(days=20), "keycloak": timedelta(days=6)},
            )

            code, stdout, stderr = self.run_main(env_file)

            self.assertEqual(code, expiry.EXIT_PAGE)
            self.assertEqual(stderr, "")
            payload = json.loads(stdout)
            self.assertEqual(payload["schema"], 1)
            self.assertEqual(payload["thresholds_days"], [30, 14, 7])
            self.assertEqual(payload["overall"], "page")
            self.assertEqual(len(payload["certificates"]), 9)
            self.assertNotIn(str(directory), stdout)
            self.assertNotIn("BEGIN CERTIFICATE", stdout)
            self.assertNotIn("PRIVATE KEY", stdout)
            by_service = {item["service"]: item for item in payload["certificates"]}
            self.assertEqual(by_service["api"]["state"], "alert_30")
            self.assertEqual(by_service["keycloak"]["state"], "page")
            self.assertRegex(by_service["api"]["fingerprint_sha256"], r"^[0-9a-f]{64}$")

    def test_cli_returns_ok_or_non_page_alert(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            healthy = self.make_inventory(directory)
            code, _, _ = self.run_main(healthy)
            self.assertEqual(code, expiry.EXIT_OK)

            warning = self.make_inventory(
                directory, remaining={"alertmanager": timedelta(days=10)}
            )
            code, stdout, _ = self.run_main(warning)
            self.assertEqual(code, expiry.EXIT_ALERT)
            self.assertEqual(json.loads(stdout)["overall"], "alert")

    def test_staged_dual_ca_trust_bundle_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            replacement_ca, _ = ca_material(
                not_before=FIXED_NOW - timedelta(days=1),
                not_after=FIXED_NOW + timedelta(days=365),
            )
            ca_path = directory / "ca.crt"
            ca_path.write_bytes(ca_path.read_bytes() + replacement_ca)

            code, stdout, stderr = self.run_main(env_file)

            self.assertEqual(code, expiry.EXIT_OK)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["overall"], "ok")

    def test_ca_leaf_and_private_key_inputs_are_bounded_by_type(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            cases = (
                (directory / "ca.crt", 256 * 1024),
                (directory / "api.crt", 64 * 1024),
                (directory / "api.key", 64 * 1024),
            )
            for path, limit in cases:
                with self.subTest(path=path.name):
                    original = path.read_bytes()
                    path.write_bytes(original + b" " * (limit - len(original)))

                    code, _, stderr = self.run_main(env_file)
                    self.assertEqual(code, expiry.EXIT_OK)
                    self.assertEqual(stderr, "")

                    path.write_bytes(path.read_bytes() + b" ")

                    code, stdout, stderr = self.run_main(env_file)

                    self.assertEqual(code, expiry.EXIT_INPUT)
                    self.assertEqual(stdout, "")
                    self.assertNotIn(str(directory), stderr)
                    path.write_bytes(original)

    def test_pem_inputs_do_not_use_path_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            original_read_bytes = Path.read_bytes

            def reject_pem_read_bytes(path: Path) -> bytes:
                if path.suffix in {".crt", ".key"}:
                    raise AssertionError("PEM Path.read_bytes bypassed stable loading")
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", reject_pem_read_bytes):
                payload, code = expiry.evaluate_inventory(env_file, now=FIXED_NOW)

            self.assertEqual(code, expiry.EXIT_OK)
            self.assertEqual(payload["overall"], "ok")

    def test_private_keys_use_the_shared_private_secret_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            with patch.object(
                expiry,
                "read_private_secret_bytes",
                wraps=private_secret_file.read_private_secret_bytes,
            ) as stable_read:
                payload, code = expiry.evaluate_inventory(env_file, now=FIXED_NOW)
        self.assertEqual(code, expiry.EXIT_OK)
        self.assertEqual(payload["overall"], "ok")
        self.assertEqual(stable_read.call_count, len(expiry.KEY_ENV))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_group_or_world_accessible_private_key_is_input_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            (directory / "api.key").chmod(0o640)
            code, stdout, stderr = self.run_main(env_file)
        self.assertEqual(code, expiry.EXIT_INPUT)
        self.assertEqual(stdout, "")
        self.assertNotIn(str(directory), stderr)

    def test_link_or_reparse_pem_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            with patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), patch.object(external_json.os, "open") as open_file:
                code, stdout, stderr = self.run_main(env_file)

            self.assertEqual(code, expiry.EXIT_INPUT)
            self.assertEqual(stdout, "")
            self.assertNotIn(str(directory), stderr)
            open_file.assert_not_called()

    def test_non_regular_open_pem_is_rejected_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            real_fstat = os.fstat

            def non_regular_fstat(descriptor: int):
                metadata = real_fstat(descriptor)
                return SimpleNamespace(
                    st_mode=stat.S_IFIFO | 0o600,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )

            with patch("os.fstat", side_effect=non_regular_fstat):
                code, stdout, stderr = self.run_main(env_file)

            self.assertEqual(code, expiry.EXIT_INPUT)
            self.assertEqual(stdout, "")
            self.assertNotIn(str(directory), stderr)

    def test_rejects_missing_placeholder_relative_or_duplicate_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            original = env_file.read_text(encoding="utf-8")
            api_variable = expiry.CERTIFICATE_ENV["api"]
            web_variable = expiry.CERTIFICATE_ENV["web"]
            api_line = next(line for line in original.splitlines() if line.startswith(api_variable))
            api_path = api_line.split("=", 1)[1]
            mutations = (
                original.replace(api_line + "\n", ""),
                original.replace(api_path, "/CHANGE_ME/internal-tls/api/tls.crt", 1),
                original.replace(api_path, "relative/api.crt", 1),
                original.replace(
                    next(line for line in original.splitlines() if line.startswith(web_variable)),
                    f"{web_variable}={api_path}",
                    1,
                ),
            )
            for index, content in enumerate(mutations):
                with self.subTest(index=index):
                    env_file.write_text(content, encoding="utf-8")
                    code, stdout, stderr = self.run_main(env_file)
                    self.assertEqual(code, expiry.EXIT_INPUT)
                    self.assertEqual(stdout, "")
                    self.assertIn('"error":"certificate_input_invalid"', stderr)
                    self.assertNotIn(str(directory), stderr)

    def test_rejects_symlink_malformed_bundle_and_not_yet_valid_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            env_text = env_file.read_text(encoding="utf-8")
            api_path = Path(
                next(
                    line.split("=", 1)[1]
                    for line in env_text.splitlines()
                    if line.startswith(expiry.CERTIFICATE_ENV["api"])
                )
            )
            valid_pem = api_path.read_bytes()
            mutations = (
                b"not a certificate\n",
                valid_pem + valid_pem,
                certificate_pem(
                    service="api",
                    not_before=FIXED_NOW + timedelta(days=1),
                    not_after=FIXED_NOW + timedelta(days=31),
                ),
            )
            for index, content in enumerate(mutations):
                with self.subTest(index=index):
                    api_path.write_bytes(content)
                    code, _, stderr = self.run_main(env_file)
                    self.assertEqual(code, expiry.EXIT_INPUT)
                    self.assertIn('"error":"certificate_input_invalid"', stderr)

            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(expiry.CertificateInputError):
                    expiry._certificate_path(
                        "api",
                        expiry.CERTIFICATE_ENV["api"],
                        {expiry.CERTIFICATE_ENV["api"]: str(api_path)},
                    )

    def test_rejects_wrong_san_untrusted_leaf_and_mismatched_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            original_env = env_file.read_text(encoding="utf-8")
            api_certificate = directory / "api.crt"
            api_key = directory / "api.key"
            original_certificate = api_certificate.read_bytes()
            original_key = api_key.read_bytes()
            ca_pem = (directory / "ca.crt").read_bytes()

            wrong_san, wrong_san_key = signed_leaf_material(
                service="api",
                san="wrong-api",
                not_before=FIXED_NOW - timedelta(days=1),
                not_after=FIXED_NOW + timedelta(days=31),
                ca_certificate_pem=ca_pem,
                ca_key=self.inventory_ca_key,
            )
            rogue_ca, rogue_ca_key = ca_material(
                not_before=FIXED_NOW - timedelta(days=1),
                not_after=FIXED_NOW + timedelta(days=365),
            )
            untrusted_leaf, untrusted_key = signed_leaf_material(
                service="api",
                san="api",
                not_before=FIXED_NOW - timedelta(days=1),
                not_after=FIXED_NOW + timedelta(days=31),
                ca_certificate_pem=rogue_ca,
                ca_key=rogue_ca_key,
            )
            mutations = (
                (wrong_san, wrong_san_key),
                (untrusted_leaf, untrusted_key),
                (original_certificate, (directory / "web.key").read_bytes()),
            )
            for index, (certificate, private_key) in enumerate(mutations):
                with self.subTest(index=index):
                    env_file.write_text(original_env, encoding="utf-8")
                    api_certificate.write_bytes(certificate)
                    api_key.write_bytes(private_key)
                    code, stdout, stderr = self.run_main(env_file)
                    self.assertEqual(code, expiry.EXIT_INPUT)
                    self.assertEqual(stdout, "")
                    self.assertNotIn(str(directory), stderr)

    def test_rejects_duplicate_or_malformed_key_and_non_ca_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            env_file = self.make_inventory(directory)
            original_env = env_file.read_text(encoding="utf-8")
            api_key_line = next(
                line
                for line in original_env.splitlines()
                if line.startswith("PLATFORM_INTERNAL_API_KEY_FILE=")
            )
            web_key_line = next(
                line
                for line in original_env.splitlines()
                if line.startswith("PLATFORM_INTERNAL_WEB_KEY_FILE=")
            )
            duplicate_key_env = original_env.replace(
                web_key_line,
                "PLATFORM_INTERNAL_WEB_KEY_FILE=" + api_key_line.split("=", 1)[1],
                1,
            )
            cases = (
                (duplicate_key_env, None, None),
                (original_env, directory / "api.key", b"not a private key\n"),
                (original_env, directory / "ca.crt", (directory / "api.crt").read_bytes()),
            )
            original_api_key = (directory / "api.key").read_bytes()
            original_ca = (directory / "ca.crt").read_bytes()
            for index, (env_text, path, content) in enumerate(cases):
                with self.subTest(index=index):
                    env_file.write_text(env_text, encoding="utf-8")
                    (directory / "api.key").write_bytes(original_api_key)
                    (directory / "ca.crt").write_bytes(original_ca)
                    if path is not None and content is not None:
                        path.write_bytes(content)
                    code, stdout, stderr = self.run_main(env_file)
                    self.assertEqual(code, expiry.EXIT_INPUT)
                    self.assertEqual(stdout, "")
                    self.assertNotIn(str(directory), stderr)

    def test_repository_verifier_rejects_expiry_contract_drift(self) -> None:
        script_text = (Path(expiry.__file__)).read_text(encoding="utf-8")
        runbook_text = (
            Path(__file__).resolve().parents[1] / "deploy/runbooks/internal-tls.md"
        ).read_text(encoding="utf-8")
        arguments = {
            "certificate_env": expiry.CERTIFICATE_ENV,
            "key_env": expiry.KEY_ENV,
            "ca_env": expiry.CA_ENV,
            "thresholds_days": expiry.THRESHOLDS_DAYS,
            "page_below_days": expiry.PAGE_BELOW_DAYS,
            "script_text": script_text,
            "runbook_text": runbook_text,
        }
        self.assertEqual(
            verify_internal_tls.validate_expiry_monitor_contract(**arguments), []
        )
        mutations = (
            {**arguments, "certificate_env": {"api": expiry.CERTIFICATE_ENV["api"]}},
            {**arguments, "key_env": {"api": expiry.KEY_ENV["api"]}},
            {**arguments, "ca_env": "REMOVED_CA_FILE"},
            {**arguments, "thresholds_days": (30, 7)},
            {**arguments, "page_below_days": 14},
            {
                **arguments,
                "script_text": script_text.replace("path.is_symlink()", "False"),
            },
            {
                **arguments,
                "script_text": script_text.replace(
                    "verify_directly_issued_by", "removed_issuer_check", 1
                ),
            },
            {
                **arguments,
                "script_text": script_text.replace(
                    "private_key.public_key()", "certificate.public_key()", 1
                ),
            },
            {
                **arguments,
                "script_text": script_text.replace(
                    "read_stable_bytes(path, max_bytes=MAX_LEAF_CERTIFICATE_BYTES)",
                    "path.read_bytes()",
                    1,
                ),
            },
            {
                **arguments,
                "runbook_text": runbook_text.replace(
                    "at least once every 24 hours", "occasionally", 1
                ),
            },
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(
                    verify_internal_tls.validate_expiry_monitor_contract(**mutation)
                )


if __name__ == "__main__":
    unittest.main()
