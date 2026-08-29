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
from platform.uploads import (
    HttpSub2Adapter,
    RedisSub2ConcurrencyLimiter,
    UnconfiguredSub2Adapter,
    run_upload_worker,
)
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
    application = create_app(service_role="worker")
    stop_event = Event()

    def stop(*_: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    metrics = WorkerMetrics("sub2")
    environment = application.state.settings.environment
    default_metrics_host = (
        "127.0.0.1"
        if environment.strip().lower() in {"development", "test"}
        else "0.0.0.0"
    )
    start_worker_metrics_server(
        metrics,
        host=os.environ.get("PLATFORM_WORKER_METRICS_HOST", default_metrics_host),
        port=int(os.environ.get("PLATFORM_WORKER_METRICS_PORT", "9102")),
        stop_event=stop_event,
        environment=environment,
        tls_cert_file=os.environ.get("PLATFORM_WORKER_METRICS_TLS_CERT_FILE"),
        tls_key_file=os.environ.get("PLATFORM_WORKER_METRICS_TLS_KEY_FILE"),
    )
    upload_url = application.state.settings.sub2_upload_url
    adapter = (
        HttpSub2Adapter(
            upload_url,
            application.state.secret_resolver,
            allowed_origins=application.state.settings.resolved_sub2_allowed_origins(),
            timeout=application.state.settings.sub2_timeout_seconds,
        )
        if upload_url
        else UnconfiguredSub2Adapter()
    )
    managed_environment = environment.strip().lower() not in {"development", "test"}
    redis_url = application.state.settings.resolved_redis_url(
        require_file=managed_environment
    )
    concurrency_limiter = (
        RedisSub2ConcurrencyLimiter(
            redis_url,
            lease_seconds=max(
                application.state.settings.sub2_timeout_seconds * 2 + 30,
                60,
            ),
        )
        if redis_url
        else None
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
        concurrency_limiter=concurrency_limiter,
        allow_policy_fallback=not managed_environment,
    )


if __name__ == "__main__":
    main()
