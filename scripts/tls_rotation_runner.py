"""Explicit, redacted subprocess boundary for TLS rotation backends."""

from __future__ import annotations

import os
import subprocess
from typing import Mapping, Sequence

from scripts.rollback_release import (
    COMPOSE_INPUT_VARIABLES,
    FORBIDDEN_COMPOSE_CONTROL_VARIABLES,
    FORBIDDEN_DOCKER_TARGET_VARIABLES,
    FORBIDDEN_DOCKER_TLS_VARIABLES,
    FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES,
    SUBPROCESS_BASE_ENVIRONMENT_VARIABLES,
)
from scripts.tls_rotation_runtime import RotationRuntimeError


FORBIDDEN_ROTATION_ENVIRONMENT = frozenset(
    {
        *FORBIDDEN_COMPOSE_CONTROL_VARIABLES,
        *FORBIDDEN_DOCKER_TARGET_VARIABLES,
        *FORBIDDEN_DOCKER_TLS_VARIABLES,
        *FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES,
        *COMPOSE_INPUT_VARIABLES,
        "DOCKER_API_VERSION",
        "KUBECONFIG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PYTHONPATH",
        "PYTHONHOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
)
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 8 * 1024
MAX_ARGUMENTS = 128
MAX_ARGUMENT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 660


def sanitized_subprocess_environment(
    shell_environment: Mapping[str, str],
) -> dict[str, str]:
    if FORBIDDEN_ROTATION_ENVIRONMENT.intersection(shell_environment):
        raise RotationRuntimeError("TLS rotation environment preflight failed")
    return {
        name: shell_environment[name]
        for name in SUBPROCESS_BASE_ENVIRONMENT_VARIABLES
        if name in shell_environment
    }


class SanitizedSubprocessRunner:
    """Run fixed argv with a frozen allowlisted environment and silent stderr."""

    def __init__(self, shell_environment: Mapping[str, str] | None = None) -> None:
        source = os.environ if shell_environment is None else shell_environment
        self._environment = sanitized_subprocess_environment(source)

    def run(
        self,
        command: Sequence[str],
        *,
        capture_output: bool = False,
        input_text: str | None = None,
    ) -> str:
        if (
            not command
            or len(command) > MAX_ARGUMENTS
            or any(
                not isinstance(argument, str)
                or not argument
                or "\x00" in argument
                or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
                for argument in command
            )
        ):
            raise RotationRuntimeError("runtime command is invalid")
        if input_text is not None:
            try:
                input_size = len(input_text.encode("utf-8"))
            except UnicodeError:
                raise RotationRuntimeError("runtime command input is invalid") from None
            if not input_text or input_size > MAX_INPUT_BYTES:
                raise RotationRuntimeError("runtime command input is invalid")
        try:
            result = subprocess.run(
                list(command),
                check=True,
                shell=False,
                input=input_text or "",
                stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=COMMAND_TIMEOUT_SECONDS,
                env=dict(self._environment),
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise RotationRuntimeError("runtime command failed") from None
        output = result.stdout if capture_output else ""
        if not isinstance(output, str) or len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
            raise RotationRuntimeError("runtime command output is invalid")
        return output
