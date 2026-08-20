"""Verify that compose service boundaries keep secrets on the right side."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"


def _service_env(service: dict[str, object]) -> dict[str, object]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return env
    if isinstance(env, list):
        result: dict[str, object] = {}
        for item in env:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, value = item.split("=", 1)
            result[key] = value
        return result
    return {}


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return _fail("Compose services block is invalid")

    api = services.get("api")
    mail_worker = services.get("worker-mail")
    sub2_worker = services.get("worker-sub2")
    if not isinstance(api, dict) or not isinstance(mail_worker, dict) or not isinstance(sub2_worker, dict):
        return _fail("Missing api, worker-mail or worker-sub2 service")

    api_env = _service_env(api)
    mail_env = _service_env(mail_worker)
    sub2_env = _service_env(sub2_worker)

    forbidden_api = {
        "PLATFORM_MAIL_API_URL",
        "PLATFORM_MAIL_TIMEOUT_SECONDS",
        "PLATFORM_SUB2_UPLOAD_URL",
        "PLATFORM_SUB2_PROXY_REF",
        "PLATFORM_SUB2_CREDENTIAL_REF",
    }
    unexpected_api = sorted(name for name in forbidden_api if name in api_env)
    if unexpected_api:
        return _fail("API service must not carry secret-bearing envs: " + ", ".join(unexpected_api))

    if "PLATFORM_MAIL_API_URL" not in mail_env:
        return _fail("worker-mail must carry PLATFORM_MAIL_API_URL")
    if "PLATFORM_MAIL_POLL_MODE" not in mail_env:
        return _fail("worker-mail must carry PLATFORM_MAIL_POLL_MODE")

    if "PLATFORM_SUB2_UPLOAD_URL" not in sub2_env:
        return _fail("worker-sub2 must carry PLATFORM_SUB2_UPLOAD_URL")
    for name in ("PLATFORM_SUB2_PROXY_REF", "PLATFORM_SUB2_CREDENTIAL_REF"):
        if name not in sub2_env:
            return _fail(f"worker-sub2 must carry {name}")

    print("service-boundaries-ok api=clean mail-worker=mail-only sub2-worker=sub2-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
