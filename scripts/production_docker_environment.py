"""Fail closed on caller-controlled Docker daemon and TLS overrides."""

from __future__ import annotations

import os
from typing import Mapping


FORBIDDEN_PRODUCTION_DOCKER_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


class ProductionDockerEnvironmentError(RuntimeError):
    """The caller environment can redirect the production Docker client."""


def validate_production_docker_environment(
    environment: Mapping[str, str] | None = None,
) -> None:
    """Reject Docker target and TLS overrides without disclosing their values."""

    environment = os.environ if environment is None else environment
    if any(name in environment for name in FORBIDDEN_PRODUCTION_DOCKER_VARIABLES):
        raise ProductionDockerEnvironmentError(
            "production backup Docker environment preflight failed"
        )
