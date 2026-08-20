import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from update_client import (
    UpdateClient,
    UpdateError,
    apply_downloaded_update,
    apply_update_cli,
    is_newer_version,
    parse_update_manifest,
)


class FakeResponse:
    def __init__(self, body: bytes, url: str) -> None:
        self._body = body
        self._offset = 0
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url


class UpdateClientTests(unittest.TestCase):
    def test_semantic_version_comparison(self) -> None:
        self.assertTrue(is_newer_version("0.1.1", "0.1.0"))
        self.assertFalse(is_newer_version("0.1.0", "0.1.0"))
        self.assertFalse(is_newer_version("0.0.9", "0.1.0"))
        with self.assertRaises(UpdateError):
            is_newer_version("latest", "0.1.0")

    def test_manifest_rejects_non_official_download(self) -> None:
        payload = {
            "version": "0.2.0",
            "download_url": "https://example.com/update.exe",
            "sha256": "a" * 64,
            "size": 1024 * 1024,
        }
        with self.assertRaises(UpdateError):
            parse_update_manifest(payload)

    def test_fetch_and_check_local_test_manifest(self) -> None:
        payload = {
            "version": "0.2.0",
            "download_url": "http://127.0.0.1/update.exe",
            "sha256": "a" * 64,
            "size": 1024 * 1024,
        }
        body = json.dumps(payload).encode()
        client = UpdateClient(
            "http://127.0.0.1/manifest.json",
            open_fn=lambda *_args, **_kwargs: FakeResponse(
                body, "http://127.0.0.1/manifest.json"
            ),
        )
        manifest = client.check()
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.version, "0.2.0")

    def test_download_requires_exact_size_and_sha256(self) -> None:
        package = b"MZ" + b"x" * (1024 * 1024 - 2)
        payload = {
            "version": "0.2.0",
            "download_url": "http://127.0.0.1/update.exe",
            "sha256": hashlib.sha256(package).hexdigest(),
            "size": len(package),
        }
        manifest = parse_update_manifest(payload, allow_loopback_download=True)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            client = UpdateClient(
                "http://127.0.0.1/manifest.json",
                open_fn=lambda *_args, **_kwargs: FakeResponse(
                    package, "http://127.0.0.1/update.exe"
                ),
            )
            downloaded = client.download(manifest)
            self.assertEqual(downloaded.read_bytes(), package)
            downloaded.unlink()

            bad = manifest.__class__(
                version=manifest.version,
                download_url=manifest.download_url,
                sha256="0" * 64,
                size=manifest.size,
            )
            with self.assertRaises(UpdateError):
                client.download(bad)
            self.assertEqual(list(Path(directory).rglob("*.part")), [])

    def test_apply_rechecks_hash_and_replaces_target(self) -> None:
        package_bytes = b"new executable"
        digest = hashlib.sha256(package_bytes).hexdigest()
        launched: list[Path] = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(b"old executable")
            apply_downloaded_update(
                package=package,
                target=target,
                expected_sha256=digest,
                parent_pid=123,
                wait_fn=lambda _pid: True,
                launch_fn=launched.append,
            )
            self.assertEqual(target.read_bytes(), package_bytes)
            self.assertFalse(package.exists())
            self.assertEqual(launched, [target.resolve()])
            self.assertEqual(list(target.parent.glob(".Manage.exe.rollback-*")), [])

    def test_apply_restores_previous_executable_when_launch_fails(self) -> None:
        package_bytes = b"new executable"
        old_bytes = b"old executable"
        digest = hashlib.sha256(package_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(old_bytes)

            with self.assertRaisesRegex(UpdateError, "已恢复原版本") as captured:
                apply_downloaded_update(
                    package=package,
                    target=target,
                    expected_sha256=digest,
                    parent_pid=123,
                    wait_fn=lambda _pid: True,
                    launch_fn=lambda _target: (_ for _ in ()).throw(
                        OSError("SENSITIVE_LAUNCH_DETAIL")
                    ),
                )

            self.assertEqual(target.read_bytes(), old_bytes)
            self.assertTrue(package.exists())
            self.assertNotIn("SENSITIVE_LAUNCH_DETAIL", str(captured.exception))
            self.assertEqual(list(target.parent.glob(".Manage.exe.rollback-*")), [])
            self.assertEqual(list(target.parent.glob(".Manage.exe.update-*")), [])

    def test_apply_cli_records_safe_update_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "updates"
            with patch(
                "update_client.apply_downloaded_update",
                side_effect=UpdateError("新版本启动失败，已恢复原版本"),
            ), patch("update_client.update_cache_dir", return_value=cache):
                result = apply_update_cli(
                    [
                        "--apply-update",
                        "--package",
                        str(cache / "package.exe"),
                        "--target",
                        str(Path(directory) / "Manage.exe"),
                        "--sha256",
                        "a" * 64,
                        "--parent-pid",
                        "123",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertEqual(
                (cache / "update-error.log").read_text(encoding="utf-8"),
                "新版本启动失败，已恢复原版本",
            )


if __name__ == "__main__":
    unittest.main()
