"""Run one confirmed TLS leaf-rotation plan through a reviewed runtime profile."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

from scripts.compose_tls_rotation_backend import build_compose_rotation_backend
from scripts.kubernetes_tls_rotation_backend import build_kubernetes_rotation_backend
from scripts.tls_rotation_evidence import utc_now
from scripts.tls_rotation_executor import TlsRotationExecutionError, execute_tls_rotation
from scripts.tls_rotation_runner import SanitizedSubprocessRunner


_FLAGS = (
    "--projection",
    "--runtime-profile",
    "--evidence-output",
    "--confirm-rotation-plan-sha256",
)


class TlsRotationCliError(ValueError):
    """The CLI input is not the exact reviewed invocation shape."""


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise TlsRotationCliError("TLS rotation CLI input is invalid") from None


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(description=__doc__, add_help=True)
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--runtime-profile", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--confirm-rotation-plan-sha256", required=True)
    return parser


def _parse(arguments: Sequence[str]) -> argparse.Namespace:
    if "--help" not in arguments and (
        len(arguments) != len(_FLAGS) * 2
        or any(arguments.count(flag) != 1 for flag in _FLAGS)
    ):
        raise TlsRotationCliError("TLS rotation CLI input is invalid")
    return _parser().parse_args(list(arguments))


def main(
    arguments: Sequence[str] | None = None,
    *,
    shell_environment: Mapping[str, str] | None = None,
    runner_factory=SanitizedSubprocessRunner,
) -> int:
    argv = list(sys.argv[1:] if arguments is None else arguments)
    environment = os.environ if shell_environment is None else shell_environment
    try:
        options = _parse(argv)

        def backend_factory(projection):
            builder = {
                "compose": build_compose_rotation_backend,
                "kubernetes": build_kubernetes_rotation_backend,
            }.get(projection.get("runtime_kind"))
            if builder is None:
                raise TlsRotationCliError("TLS rotation CLI input is invalid")
            return builder(
                options.runtime_profile,
                projection,
                shell_environment=environment,
                runner_factory=runner_factory,
            )

        execute_tls_rotation(
            options.projection,
            evidence_output=options.evidence_output,
            backend_factory=backend_factory,
            clock=utc_now,
            confirm_rotation_plan_sha256=options.confirm_rotation_plan_sha256,
        )
    except KeyboardInterrupt:
        print("tls-rotation-execution-failed", file=sys.stderr)
        return 130
    except (OSError, TypeError, ValueError, TlsRotationExecutionError):
        print("tls-rotation-execution-failed", file=sys.stderr)
        return 1
    print("tls-rotation-execution-ok production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
