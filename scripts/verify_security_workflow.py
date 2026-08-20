"""Verify the CI security workflow includes the expected supply-chain gates."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    if not WORKFLOW.exists():
        return _fail("Missing security workflow")
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return _fail("Security workflow is invalid")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or "security-gate" not in jobs:
        return _fail("Security workflow missing security-gate job")
    job = jobs["security-gate"]
    if not isinstance(job, dict):
        return _fail("Security workflow job is invalid")
    steps = job.get("steps")
    if not isinstance(steps, list):
        return _fail("Security workflow steps are invalid")
    rendered = "\n".join(
        str(step.get("name", "")) if isinstance(step, dict) else str(step)
        for step in steps
    )
    required = [
        "Secret scan",
        "Verify release manifest",
        "Verify signoff template",
        "Python dependency audit",
        "Frontend dependency audit",
    ]
    missing = [item for item in required if item not in rendered]
    if missing:
        return _fail("Security workflow missing steps: " + ", ".join(missing))
    print("security-workflow-ok supply-chain-gates-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
