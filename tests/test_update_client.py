import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as desktop_entrypoint

from update_client import (
    _startup_ready_path,
    UpdateClient,
    UpdateError,
    apply_downloaded_update,
    apply_update_cli,
    confirm_update_startup,
    consume_update_notice,
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


class FakeProcess:
    def __init__(self, return_code: int | None = None) -> None:
        self.return_code = return_code
        self.terminated = False

    def poll(self) -> int | None:
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = 1

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.return_code or 0


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


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

    def test_fetch_manifest_rejects_duplicate_json_keys(self) -> None:
        body = (
            '{"version":"0.2.0","version":"0.2.0",'
            '"download_url":"http://127.0.0.1/update.exe",'
            '"sha256":"%s","size":1048576}' % ("a" * 64)
        ).encode("utf-8")
        client = UpdateClient(
            "http://127.0.0.1/manifest.json",
            open_fn=lambda *_args, **_kwargs: FakeResponse(
                body, "http://127.0.0.1/manifest.json"
            ),
        )

        with self.assertRaisesRegex(UpdateError, "更新清单格式无效"):
            client.fetch_manifest()

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
        launched: list[list[str]] = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(b"old executable")

            def launch(arguments: list[str]) -> FakeProcess:
                launched.append(arguments)
                token = arguments[arguments.index("--update-ready-token") + 1]
                self.assertTrue(confirm_update_startup(token))
                return FakeProcess()

            apply_downloaded_update(
                package=package,
                target=target,
                expected_sha256=digest,
                parent_pid=123,
                wait_fn=lambda _pid: True,
                launch_fn=launch,
            )
            self.assertEqual(target.read_bytes(), package_bytes)
            self.assertFalse(package.exists())
            self.assertEqual(launched[0][0], str(target.resolve()))
            self.assertIn("--update-ready-token", launched[0])
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
                    launch_fn=lambda _arguments: (_ for _ in ()).throw(
                        OSError("SENSITIVE_LAUNCH_DETAIL")
                    ),
                )

            self.assertEqual(target.read_bytes(), old_bytes)
            self.assertTrue(package.exists())
            self.assertNotIn("SENSITIVE_LAUNCH_DETAIL", str(captured.exception))
            self.assertEqual(list(target.parent.glob(".Manage.exe.rollback-*")), [])
            self.assertEqual(list(target.parent.glob(".Manage.exe.update-*")), [])

    def test_process_exit_after_spawn_restores_and_relaunches_old_version(self) -> None:
        package_bytes = b"new executable"
        old_bytes = b"old executable"
        digest = hashlib.sha256(package_bytes).hexdigest()
        launches: list[list[str]] = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(old_bytes)

            def launch(arguments: list[str]) -> FakeProcess:
                launches.append(arguments)
                return FakeProcess(1 if len(launches) == 1 else None)

            with self.assertRaisesRegex(UpdateError, "已恢复原版本"):
                apply_downloaded_update(
                    package=package,
                    target=target,
                    expected_sha256=digest,
                    parent_pid=123,
                    wait_fn=lambda _pid: True,
                    launch_fn=launch,
                )

            self.assertEqual(target.read_bytes(), old_bytes)
            self.assertTrue(package.exists())
            self.assertEqual(launches[1], [str(target.resolve())])
            self.assertIn("已恢复原版本", consume_update_notice() or "")
            self.assertIsNone(consume_update_notice())
            self.assertEqual(list(target.parent.glob(".Manage.exe.rollback-*")), [])

    def test_startup_ready_timeout_terminates_new_process_before_restore(self) -> None:
        package_bytes = b"new executable"
        old_bytes = b"old executable"
        digest = hashlib.sha256(package_bytes).hexdigest()
        clock = FakeClock()
        new_process = FakeProcess()
        launches: list[list[str]] = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(old_bytes)

            def launch(arguments: list[str]) -> FakeProcess:
                launches.append(arguments)
                return new_process if len(launches) == 1 else FakeProcess()

            with self.assertRaisesRegex(UpdateError, "已恢复原版本") as captured:
                apply_downloaded_update(
                    package=package,
                    target=target,
                    expected_sha256=digest,
                    parent_pid=123,
                    wait_fn=lambda _pid: True,
                    launch_fn=launch,
                    startup_timeout_seconds=1.0,
                    monotonic_fn=clock.monotonic,
                    sleep_fn=clock.sleep,
                )

            self.assertTrue(new_process.terminated)
            self.assertEqual(target.read_bytes(), old_bytes)
            self.assertNotIn("SENSITIVE_TIMEOUT_DETAIL", str(captured.exception))
            self.assertEqual(launches[1], [str(target.resolve())])

    def test_process_crash_during_ready_stability_window_rolls_back(self) -> None:
        package_bytes = b"new executable"
        old_bytes = b"old executable"
        digest = hashlib.sha256(package_bytes).hexdigest()
        clock = FakeClock()
        launches: list[list[str]] = []

        class CrashingProcess(FakeProcess):
            def __init__(self) -> None:
                super().__init__()
                self.poll_count = 0

            def poll(self) -> int | None:
                self.poll_count += 1
                return None if self.poll_count == 1 else 1

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            package = cache / "package-0.2.0.exe"
            package.write_bytes(package_bytes)
            target = Path(directory) / "Manage.exe"
            target.write_bytes(old_bytes)

            def launch(arguments: list[str]) -> FakeProcess:
                launches.append(arguments)
                if len(launches) == 1:
                    token = arguments[arguments.index("--update-ready-token") + 1]
                    self.assertTrue(confirm_update_startup(token))
                    return CrashingProcess()
                return FakeProcess()

            with self.assertRaisesRegex(UpdateError, "已恢复原版本"):
                apply_downloaded_update(
                    package=package,
                    target=target,
                    expected_sha256=digest,
                    parent_pid=123,
                    wait_fn=lambda _pid: True,
                    launch_fn=launch,
                    monotonic_fn=clock.monotonic,
                    sleep_fn=clock.sleep,
                )

            self.assertEqual(target.read_bytes(), old_bytes)
            self.assertTrue(package.exists())
            self.assertEqual(launches[1], [str(target.resolve())])

    def test_startup_ready_token_is_strict_and_confined_to_update_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            self.assertFalse(confirm_update_startup("../outside"))
            self.assertFalse(confirm_update_startup("A" * 32))
            self.assertFalse((Path(directory) / "outside").exists())
            self.assertEqual(list(Path(directory).rglob("startup-ready-*")), [])

            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            token = "b" * 32
            marker = cache / f"startup-ready-{token}.txt"
            marker.write_text("c" * 32, encoding="ascii")
            self.assertFalse(confirm_update_startup(token))

    def test_existing_startup_ready_marker_is_read_stably(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            token = "d" * 32
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            marker = cache / f"startup-ready-{token}.txt"
            marker.write_text(token, encoding="ascii")

            self.assertTrue(confirm_update_startup(token))

    def test_startup_ready_path_does_not_resolve_marker_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            original_resolve = Path.resolve
            resolved: list[Path] = []

            def record_resolve(path: Path, *args, **kwargs) -> Path:
                resolved.append(path)
                return original_resolve(path, *args, **kwargs)

            with patch.object(Path, "resolve", autospec=True, side_effect=record_resolve):
                marker = _startup_ready_path("e" * 32)

            self.assertIsNotNone(marker)
            self.assertEqual(len(resolved), 1)

    def test_startup_ready_marker_rejects_link_or_reparse_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            token = "f" * 32
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            marker = cache / f"startup-ready-{token}.txt"
            marker.write_text(token, encoding="ascii")

            with patch(
                "scripts.external_json.has_link_or_reparse_ancestor",
                return_value=True,
            ):
                self.assertFalse(confirm_update_startup(token))

    def test_startup_ready_marker_rejects_read_time_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            token = "1" * 32
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            marker = cache / f"startup-ready-{token}.txt"
            marker.write_text(token, encoding="ascii")
            opened = marker.stat()
            drifted = SimpleNamespace(
                st_dev=opened.st_dev,
                st_ino=opened.st_ino,
                st_nlink=opened.st_nlink,
                st_size=opened.st_size + 1,
                st_mode=opened.st_mode,
                st_mtime_ns=opened.st_mtime_ns,
                st_file_attributes=getattr(opened, "st_file_attributes", 0),
            )

            with patch(
                "scripts.external_json.os.fstat",
                side_effect=[opened, drifted],
            ):
                self.assertFalse(confirm_update_startup(token))

    def test_update_notice_rejects_unknown_or_raw_error_payload(self) -> None:
        sentinel = "SENSITIVE_PROCESS_FAILURE"
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            notice = cache / "update-notice.json"
            notice.write_text(json.dumps({"code": sentinel}), encoding="utf-8")
            self.assertIsNone(consume_update_notice())
            self.assertFalse(notice.exists())

    def test_update_notice_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            notice = cache / "update-notice.json"
            notice.write_text(
                '{"code":"startup_failed_rolled_back",'
                '"code":"startup_failed_rolled_back"}',
                encoding="utf-8",
            )

            self.assertIsNone(consume_update_notice())
            self.assertFalse(notice.exists())

    def test_update_notice_rejects_link_or_reparse_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            notice = cache / "update-notice.json"
            notice.write_text(
                json.dumps({"code": "startup_failed_rolled_back"}),
                encoding="utf-8",
            )

            with patch(
                "scripts.external_json.has_link_or_reparse_ancestor",
                return_value=True,
            ):
                self.assertIsNone(consume_update_notice())
            self.assertFalse(notice.exists())

    def test_update_notice_rejects_read_time_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"LOCALAPPDATA": directory}
        ):
            cache = Path(directory) / "MailCodeHelper" / "updates"
            cache.mkdir(parents=True)
            notice = cache / "update-notice.json"
            notice.write_text(
                json.dumps({"code": "startup_failed_rolled_back"}),
                encoding="utf-8",
            )
            opened = notice.stat()
            drifted = SimpleNamespace(
                st_dev=opened.st_dev,
                st_ino=opened.st_ino,
                st_nlink=opened.st_nlink,
                st_size=opened.st_size + 1,
                st_mode=opened.st_mode,
                st_mtime_ns=opened.st_mtime_ns,
                st_file_attributes=getattr(opened, "st_file_attributes", 0),
            )

            with patch(
                "scripts.external_json.os.fstat",
                side_effect=[opened, drifted],
            ):
                self.assertIsNone(consume_update_notice())
            self.assertFalse(notice.exists())

    def test_entrypoint_confirms_update_only_after_ui_and_first_idle(self) -> None:
        order: list[str] = []

        class Root:
            def __init__(self) -> None:
                self.idle_callback = None

            def after_idle(self, callback) -> None:
                order.append("after_idle")
                self.idle_callback = callback

            def mainloop(self) -> None:
                order.append("mainloop")
                self.idle_callback()

        class Desktop:
            def __init__(self, _root) -> None:
                order.append("desktop")

            def show_startup_notice(self, message: str) -> None:
                order.append(f"notice:{message}")

        token = "a" * 32
        with patch.object(sys, "argv", ["app.py", "--update-ready-token", token]), patch.object(
            desktop_entrypoint.tk, "Tk", Root
        ), patch.object(
            desktop_entrypoint, "PlatformDesktopApp", Desktop
        ), patch.object(
            desktop_entrypoint, "cleanup_update_cache"
        ), patch.object(
            desktop_entrypoint,
            "consume_update_notice",
            return_value="更新失败，已恢复原版本。",
        ), patch.object(
            desktop_entrypoint, "confirm_update_startup", side_effect=lambda _token: order.append("ready") or True
        ):
            desktop_entrypoint.main()

        self.assertLess(order.index("desktop"), order.index("after_idle"))
        self.assertLess(order.index("mainloop"), order.index("ready"))
        self.assertLess(order.index("ready"), order.index("notice:更新失败，已恢复原版本。"))

    def test_apply_cli_returns_failure_without_persisting_update_error(self) -> None:
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
            self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
