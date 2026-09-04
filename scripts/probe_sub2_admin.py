"""Read-only Sub2 admin credential probe for the worker runtime."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from platform.config import Settings
from platform.secrets import secret_resolver_from_settings
from platform.sub2_admin import (
    Sub2AdminProbeResult,
    Sub2AdminRejected,
    Sub2AdminUnknown,
    sub2_admin_from_settings,
)


def run_probe() -> Sub2AdminProbeResult:
    settings = Settings()
    resolver = secret_resolver_from_settings(settings)
    configured = sub2_admin_from_settings(settings, resolver)
    if configured is None:
        raise RuntimeError("Sub2 admin configuration is unavailable")
    adapter, _ = configured
    return adapter.probe_credentials()


def _write_result(result: Sub2AdminProbeResult) -> None:
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))


def main() -> int:
    try:
        result = run_probe()
    except Sub2AdminRejected:
        _write_result(Sub2AdminProbeResult(reachable=True, authenticated=False))
        return 1
    except Sub2AdminUnknown:
        _write_result(Sub2AdminProbeResult(reachable=True, authenticated=False))
        return 1
    except Exception:
        _write_result(Sub2AdminProbeResult(reachable=False, authenticated=False))
        return 1
    _write_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
