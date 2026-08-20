"""Container health check for the upload worker heartbeat file."""

from __future__ import annotations

import os

from platform.uploads import worker_heartbeat_is_fresh


def main() -> int:
    heartbeat_path = os.environ.get(
        "PLATFORM_WORKER_HEARTBEAT_PATH",
        "/tmp/email-platform-upload-worker.heartbeat",
    )
    max_age_seconds = float(
        os.environ.get("PLATFORM_WORKER_HEARTBEAT_MAX_AGE_SECONDS", "30")
    )
    return 0 if worker_heartbeat_is_fresh(
        heartbeat_path, max_age_seconds=max_age_seconds
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
