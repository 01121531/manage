"""Fail-closed upload worker entry point for the container image.

The application owns the Sub2 adapter contract.  Until a production adapter is
injected by the deployment, this worker intentionally marks no external work
as successful: the built-in adapter reports ``adapter_unavailable``.  This
prevents a container started with incomplete secret-manager wiring from
silently sending data to an unintended service.
"""

from __future__ import annotations

import json
import logging
import signal
import os
from threading import Event

from platform.app import create_app
from platform.uploads import HttpSub2Adapter, UnconfiguredSub2Adapter, run_upload_worker
from platform.worker_metrics import WorkerMetrics, start_worker_metrics_server


logging.basicConfig(level=logging.INFO, format="%(message)s")


def _log_upload_status_counts(status_counts: dict[str, int]) -> None:
    logging.info(
        json.dumps(
            {
                "event": "upload_worker.batch",
                "status_counts": status_counts,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main() -> None:
    application = create_app()
    stop_event = Event()

    def stop(*_: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    metrics = WorkerMetrics("sub2")
    start_worker_metrics_server(
        metrics,
        host=os.environ.get("PLATFORM_WORKER_METRICS_HOST", "0.0.0.0"),
        port=int(os.environ.get("PLATFORM_WORKER_METRICS_PORT", "9102")),
        stop_event=stop_event,
    )
    upload_url = application.state.settings.sub2_upload_url
    adapter = (
        HttpSub2Adapter(
            upload_url,
            application.state.secret_resolver,
            timeout=application.state.settings.sub2_timeout_seconds,
        )
        if upload_url
        else UnconfiguredSub2Adapter()
    )
    run_upload_worker(
        application.state.session_factory,
        adapter=adapter,
        policy=application.state.sub2_policy,
        stop_event=stop_event,
        heartbeat_path=os.environ.get(
            "PLATFORM_WORKER_HEARTBEAT_PATH",
            "/tmp/email-platform-upload-worker.heartbeat",
        ),
        batch_reporter=_log_upload_status_counts,
        metrics=metrics,
    )


if __name__ == "__main__":
    main()
