"""Minimal worker metrics exposition for Prometheus scraping."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Lock, Thread
from time import time as epoch_seconds


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


def start_worker_metrics_server(
    metrics: WorkerMetrics,
    *,
    host: str,
    port: int,
    stop_event: Event,
) -> Thread:
    if port <= 0:
        raise ValueError("port must be positive")
    handler = type("WorkerMetricsHandler", (_MetricsHandler,), {"metrics": metrics})
    server = ThreadingHTTPServer((host, port), handler)

    def run() -> None:
        server.timeout = 0.5
        while not stop_event.is_set():
            server.handle_request()
        server.server_close()

    thread = Thread(target=run, name=f"{metrics.worker}-metrics", daemon=True)
    thread.start()
    return thread
