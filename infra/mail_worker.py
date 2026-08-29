"""Mail worker entry point for server-side mailbox polling."""

from __future__ import annotations

import json
import logging
import os
import signal
from threading import Event

from platform.app import create_app
from platform.mail_worker import run_mail_worker
from platform.worker_metrics import WorkerMetrics, start_worker_metrics_server


logging.basicConfig(level=logging.INFO, format="%(message)s")


def _log_mail_batch(result_counts: dict[str, int]) -> None:
    logging.info(
        json.dumps(
            {"event": "mail_worker.batch", "result_counts": result_counts},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main() -> None:
    application = create_app(service_role="worker")
    stop_event = Event()

    def stop(*_: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    metrics = WorkerMetrics("mail")
    environment = application.state.settings.environment
    default_metrics_host = (
        "127.0.0.1"
        if environment.strip().lower() in {"development", "test"}
        else "0.0.0.0"
    )
    start_worker_metrics_server(
        metrics,
        host=os.environ.get("PLATFORM_WORKER_METRICS_HOST", default_metrics_host),
        port=int(os.environ.get("PLATFORM_WORKER_METRICS_PORT", "9101")),
        stop_event=stop_event,
        environment=environment,
        tls_cert_file=os.environ.get("PLATFORM_WORKER_METRICS_TLS_CERT_FILE"),
        tls_key_file=os.environ.get("PLATFORM_WORKER_METRICS_TLS_KEY_FILE"),
    )
    run_mail_worker(
        application.state.session_factory,
        connectors=application.state.mail_connectors,
        stop_event=stop_event,
        poll_seconds=application.state.settings.mail_poll_interval_seconds,
        code_ttl_seconds=application.state.settings.mail_code_ttl_seconds,
        heartbeat_path=os.environ.get(
            "PLATFORM_WORKER_HEARTBEAT_PATH",
            "/tmp/email-platform-mail-worker.heartbeat",
        ),
        batch_reporter=_log_mail_batch,
        metrics=metrics,
    )


if __name__ == "__main__":
    main()
