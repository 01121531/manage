"""Fail closed on HIGH/CRITICAL findings in production upstream images."""

from __future__ import annotations

import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Mapping

from scripts.external_json import load_unique_json
from scripts.rollback_release import Runner


THIRD_PARTY_IMAGES = (
    ("postgres", "postgres", "POSTGRES_IMAGE_SHA256"),
    ("redis", "redis", "REDIS_IMAGE_SHA256"),
    ("keycloak", "quay.io/keycloak/keycloak", "KEYCLOAK_IMAGE_SHA256"),
    ("alertmanager", "prom/alertmanager", "ALERTMANAGER_IMAGE_SHA256"),
    ("prometheus", "prom/prometheus", "PROMETHEUS_IMAGE_SHA256"),
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MAX_SARIF_BYTES = 32 * 1024 * 1024
_TRIVY_COMMAND = (
    "trivy",
    "image",
    "--exit-code",
    "1",
    "--ignore-unfixed=false",
    "--severity",
    "HIGH,CRITICAL",
    "--scanners",
    "vuln",
    "--pkg-types",
    "os,library",
    "--format",
    "sarif",
)


class ThirdPartyScanError(RuntimeError):
    """An upstream image or its scanner report failed validation."""


def _image_references(environment: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    references: list[tuple[str, str]] = []
    for service, repository, variable in THIRD_PARTY_IMAGES:
        digest = environment.get(variable, "")
        if _DIGEST.fullmatch(digest) is None:
            raise ThirdPartyScanError("third-party image digest input is invalid")
        references.append((service, f"{repository}@sha256:{digest}"))
    return tuple(references)


def _validate_sarif(path: Path, expected_image: str) -> None:
    try:
        payload = load_unique_json(path, max_bytes=_MAX_SARIF_BYTES)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ThirdPartyScanError("third-party image scan report is invalid") from error
    runs = payload.get("runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ThirdPartyScanError("third-party image scan report is invalid")
    run = runs[0]
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict) or driver.get("name") != "Trivy":
        raise ThirdPartyScanError("third-party image scan report is invalid")
    properties = run.get("properties")
    if not isinstance(properties, dict):
        raise ThirdPartyScanError("third-party image scan report is invalid")
    repo_digests = properties.get("repoDigests", [])
    if not isinstance(repo_digests, list):
        raise ThirdPartyScanError("third-party image scan report is invalid")
    if properties.get("imageName") != expected_image and expected_image not in repo_digests:
        raise ThirdPartyScanError("third-party image scan report target is invalid")
    results = run.get("results", [])
    if not isinstance(results, list) or results:
        raise ThirdPartyScanError("third-party image scan did not pass")


def scan_third_party_images(
    environment: Mapping[str, str],
    runner: Runner,
) -> None:
    """Scan the fixed production upstream inventory before deployment mutation."""

    references = _image_references(environment)
    with TemporaryDirectory(prefix="email-platform-upstream-scan-") as directory:
        output_dir = Path(directory)
        for service, reference in references:
            report = output_dir / f"{service}.sarif"
            runner.run(
                [*_TRIVY_COMMAND, "--output", str(report), reference],
                env=environment,
                capture_output=True,
            )
            _validate_sarif(report, reference)
