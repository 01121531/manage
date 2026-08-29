from contextlib import contextmanager
import ssl
import stat
from types import SimpleNamespace
import unittest
from threading import Event
from unittest.mock import Mock, patch

from platform import worker_metrics
from platform.worker_metrics import WorkerMetrics


class WorkerMetricsTests(unittest.TestCase):
    def test_render_prometheus_exposes_worker_and_batch_counts(self) -> None:
        metrics = WorkerMetrics("mail")
        metrics.mark_heartbeat()
        metrics.record_batch({"waiting": 2, "code_ready": 1, "connector_unavailable": 3})
        text = metrics.render_prometheus()
        self.assertIn('platform_worker_info{worker="mail"} 1', text)
        self.assertIn('platform_worker_batch_results_total{worker="mail",result="code_ready"} 1', text)
        self.assertIn('platform_worker_batch_results_total{worker="mail",result="waiting"} 2', text)
        self.assertIn(
            'platform_worker_batch_results_total{worker="mail",result="connector_unavailable"} 3',
            text,
        )
        self.assertIn('platform_worker_heartbeat_timestamp_seconds{worker="mail"}', text)
        self.assertIn('platform_worker_last_batch_timestamp_seconds{worker="mail"}', text)

    def test_production_rejects_missing_or_partial_tls_configuration(self) -> None:
        for certificate, private_key in (
            (None, None),
            ("/run/secrets/internal-tls/tls.crt", None),
            (None, "/run/secrets/internal-tls/tls.key"),
        ):
            with self.subTest(certificate=certificate, private_key=private_key):
                with self.assertRaisesRegex(RuntimeError, "certificate and private key"):
                    worker_metrics.start_worker_metrics_server(
                        WorkerMetrics("mail"),
                        host="0.0.0.0",
                        port=9101,
                        stop_event=Event(),
                        environment="production",
                        tls_cert_file=certificate,
                        tls_key_file=private_key,
                    )

    def test_tls_context_uses_separate_cert_and_key_with_tls_1_2_minimum(self) -> None:
        context = Mock()
        opened = []

        @contextmanager
        def open_snapshot(path, *, max_bytes, allow_empty=False):
            opened.append((path, max_bytes, allow_empty))
            descriptor = 41 if str(path).endswith("tls.crt") else 42
            metadata = SimpleNamespace(
                st_dev=7,
                st_ino=descriptor,
                st_mode=stat.S_IFREG | 0o440,
            )
            yield descriptor, metadata

        with (
            patch.object(ssl, "SSLContext", return_value=context) as context_factory,
            patch.object(
                worker_metrics,
                "open_stable_runtime_descriptor",
                side_effect=open_snapshot,
                create=True,
            ),
            patch.object(
                worker_metrics,
                "_runtime_descriptor_path",
                side_effect=lambda descriptor: f"/proc/self/fd/{descriptor}",
                create=True,
            ),
        ):
            result = worker_metrics._create_worker_metrics_ssl_context(
                "/run/secrets/internal-tls/tls.crt",
                "/run/secrets/internal-tls/tls.key",
            )

        self.assertIs(result, context)
        context_factory.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        context.load_cert_chain.assert_called_once_with(
            certfile="/proc/self/fd/41",
            keyfile="/proc/self/fd/42",
        )
        self.assertEqual(
            opened,
            [
                ("/run/secrets/internal-tls/tls.crt", 64 * 1024, False),
                ("/run/secrets/internal-tls/tls.key", 64 * 1024, False),
            ],
        )

    def test_tls_context_rejects_writable_private_key_before_openssl(self) -> None:
        context = Mock()

        @contextmanager
        def open_snapshot(path, **_kwargs):
            descriptor = 51 if str(path).endswith("tls.crt") else 52
            mode = 0o440 if descriptor == 51 else 0o460
            yield descriptor, SimpleNamespace(
                st_dev=8,
                st_ino=descriptor,
                st_mode=stat.S_IFREG | mode,
            )

        with (
            patch.object(ssl, "SSLContext", return_value=context),
            patch.object(
                worker_metrics,
                "open_stable_runtime_descriptor",
                side_effect=open_snapshot,
                create=True,
            ),
            self.assertRaisesRegex(RuntimeError, "private key permissions"),
        ):
            worker_metrics._create_worker_metrics_ssl_context(
                "/run/secrets/internal-tls/tls.crt",
                "/run/secrets/internal-tls/tls.key",
            )
        context.load_cert_chain.assert_not_called()

    def test_tls_context_rejects_same_open_object_for_cert_and_key(self) -> None:
        @contextmanager
        def open_snapshot(path, **_kwargs):
            descriptor = 61 if str(path).endswith("tls.crt") else 62
            yield descriptor, SimpleNamespace(
                st_dev=9,
                st_ino=99,
                st_mode=stat.S_IFREG | 0o440,
            )

        with (
            patch.object(
                worker_metrics,
                "open_stable_runtime_descriptor",
                side_effect=open_snapshot,
                create=True,
            ),
            self.assertRaisesRegex(RuntimeError, "separate files"),
        ):
            worker_metrics._create_worker_metrics_ssl_context(
                "/run/secrets/internal-tls/tls.crt",
                "/run/secrets/internal-tls/tls.key",
            )

    def test_certificate_and_private_key_must_be_distinct_files(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "separate files"):
            worker_metrics.start_worker_metrics_server(
                WorkerMetrics("sub2"),
                host="0.0.0.0",
                port=9102,
                stop_event=Event(),
                environment="production",
                tls_cert_file="/run/secrets/internal-tls/combined.pem",
                tls_key_file="/run/secrets/internal-tls/combined.pem",
            )

    def test_production_server_wraps_listener_in_tls_without_http_fallback(self) -> None:
        stop_event = Event()
        stop_event.set()
        server = Mock()
        server.socket = object()
        context = Mock()
        wrapped_socket = object()
        context.wrap_socket.return_value = wrapped_socket
        with (
            patch.object(worker_metrics, "ThreadingHTTPServer", return_value=server),
            patch.object(
                worker_metrics,
                "_create_worker_metrics_ssl_context",
                return_value=context,
            ),
        ):
            thread = worker_metrics.start_worker_metrics_server(
                WorkerMetrics("sub2"),
                host="0.0.0.0",
                port=9102,
                stop_event=stop_event,
                environment="production",
                tls_cert_file="/run/secrets/internal-tls/tls.crt",
                tls_key_file="/run/secrets/internal-tls/tls.key",
            )
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        context.wrap_socket.assert_called_once()
        _, kwargs = context.wrap_socket.call_args
        self.assertTrue(kwargs["server_side"])
        self.assertIs(server.socket, wrapped_socket)
        server.server_close.assert_called_once_with()

    def test_development_http_is_limited_to_loopback(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "loopback"):
            worker_metrics.start_worker_metrics_server(
                WorkerMetrics("mail"),
                host="0.0.0.0",
                port=9101,
                stop_event=Event(),
                environment="development",
            )

        stop_event = Event()
        stop_event.set()
        server = Mock()
        with patch.object(worker_metrics, "ThreadingHTTPServer", return_value=server):
            thread = worker_metrics.start_worker_metrics_server(
                WorkerMetrics("mail"),
                host="127.0.0.1",
                port=9101,
                stop_event=stop_event,
                environment="test",
            )
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        server.server_close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
