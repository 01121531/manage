"""Minimal worker metrics exposition for Prometheus scraping."""

from __future__ import annotations

import ssl
import os
import stat
from collections import Counter
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from threading import Event, Lock, Thread
from time import time as epoch_seconds

from platform.file_boundary import RuntimeFileError, open_stable_runtime_descriptor


MAX_TLS_MATERIAL_BYTES = 64 * 1024


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_labels(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    rendered = ",".join(
        f'{key}="{_escape(value)}"' for key, value in sorted(labels.items())
    )
    return f"{{{rendered}}}"


@dataclass
class WorkerMetrics:
    worker: str
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _heartbeat_timestamp: float = field(default=0.0, init=False, repr=False)
    _last_batch_timestamp: float = field(default=0.0, init=False, repr=False)
    _batch_results: Counter[str] = field(default_factory=Counter, init=False, repr=False)

    def mark_heartbeat(self) -> None:
        with self._lock:
            self._heartbeat_timestamp = epoch_seconds()

    def record_batch(self, result_counts: Mapping[str, int]) -> None:
        with self._lock:
            self._last_batch_timestamp = epoch_seconds()
            for result, value in result_counts.items():
                if value > 0:
                    self._batch_results[str(result)] += int(value)

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP platform_worker_info Static worker identity information.",
                "# TYPE platform_worker_info gauge",
                f'platform_worker_info{{worker="{_escape(self.worker)}"}} 1',
                "# HELP platform_worker_heartbeat_timestamp_seconds Last heartbeat written by the worker.",
                "# TYPE platform_worker_heartbeat_timestamp_seconds gauge",
                f'platform_worker_heartbeat_timestamp_seconds{{worker="{_escape(self.worker)}"}} {self._heartbeat_timestamp:.3f}',
                "# HELP platform_worker_last_batch_timestamp_seconds Last successful batch completion time.",
                "# TYPE platform_worker_last_batch_timestamp_seconds gauge",
                f'platform_worker_last_batch_timestamp_seconds{{worker="{_escape(self.worker)}"}} {self._last_batch_timestamp:.3f}',
                "# HELP platform_worker_batch_results_total Worker batch result counts.",
                "# TYPE platform_worker_batch_results_total counter",
            ]
            for result, value in sorted(self._batch_results.items()):
                lines.append(
                    f'platform_worker_batch_results_total{{worker="{_escape(self.worker)}",result="{_escape(result)}"}} {int(value)}'
                )
            lines.append("")
            return "\n".join(lines)


class _MetricsHandler(BaseHTTPRequestHandler):
    metrics: WorkerMetrics | None = None

    def do_GET(self) -> None:  # noqa: N802
        assert self.metrics is not None
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = self.metrics.render_prometheus().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _create_worker_metrics_ssl_context(
    cert_file: str,
    key_file: str,
) -> ssl.SSLContext:
    try:
        with ExitStack() as stack:
            cert_descriptor, cert_metadata = stack.enter_context(
                open_stable_runtime_descriptor(
                    cert_file,
                    max_bytes=MAX_TLS_MATERIAL_BYTES,
                )
            )
            key_descriptor, key_metadata = stack.enter_context(
                open_stable_runtime_descriptor(
                    key_file,
                    max_bytes=MAX_TLS_MATERIAL_BYTES,
                )
            )
            if (cert_metadata.st_dev, cert_metadata.st_ino) == (
                key_metadata.st_dev,
                key_metadata.st_ino,
            ):
                raise RuntimeError(
                    "Worker metrics TLS certificate and private key must be separate files"
                )
            if key_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError("Worker metrics TLS private key permissions are invalid")

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(
                certfile=_runtime_descriptor_path(cert_descriptor),
                keyfile=_runtime_descriptor_path(key_descriptor),
            )
            return context
    except RuntimeFileError as error:
        raise RuntimeError("Worker metrics TLS material is unavailable") from error


def _runtime_descriptor_path(descriptor: int) -> str:
    if os.name != "posix":
        raise RuntimeError("Worker metrics TLS descriptor loading requires Linux")
    path = f"/proc/self/fd/{descriptor}"
    if not os.path.exists(path):
        raise RuntimeError("Worker metrics TLS descriptor loading is unavailable")
    return path


def start_worker_metrics_server(
    metrics: WorkerMetrics,
    *,
    host: str,
    port: int,
    stop_event: Event,
    environment: str = "development",
    tls_cert_file: str | None = None,
    tls_key_file: str | None = None,
) -> Thread:
    if port <= 0:
        raise ValueError("port must be positive")
    cert_file = (tls_cert_file or "").strip()
    key_file = (tls_key_file or "").strip()
    managed_environment = environment.strip().lower() not in {"development", "test"}
    if not cert_file or not key_file:
        if managed_environment or cert_file or key_file:
            raise RuntimeError(
                "Worker metrics TLS certificate and private key are both required"
            )
        if not _is_loopback_host(host):
            raise RuntimeError(
                "Unencrypted worker metrics are limited to a loopback host"
            )
    elif cert_file == key_file:
        raise RuntimeError(
            "Worker metrics TLS certificate and private key must be separate files"
        )

    tls_context = (
        _create_worker_metrics_ssl_context(cert_file, key_file)
        if cert_file and key_file
        else None
    )
    handler = type("WorkerMetricsHandler", (_MetricsHandler,), {"metrics": metrics})
    server = ThreadingHTTPServer((host, port), handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)

    def run() -> None:
        server.timeout = 0.5
        while not stop_event.is_set():
            server.handle_request()
        server.server_close()

    thread = Thread(target=run, name=f"{metrics.worker}-metrics", daemon=True)
    thread.start()
    return thread
