"""Verify the Phase 6 role-training package is complete and fail-closed."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import training_evidence  # noqa: E402
from scripts.external_text import load_stable_text


RUNBOOK = ROOT / "deploy" / "runbooks" / "role-training.md"
SIGNOFF = ROOT / "deploy" / "production-signoff-template.md"
MAX_TRAINING_ASSET_BYTES = 64 * 1024


def training_asset_errors(runbook_text: str, signoff_text: str) -> list[str]:
    required_runbook = {
        *training_evidence.REQUIRED_ROLES,
        *training_evidence.REQUIRED_SCENARIOS,
        "production_acceptance=false",
        "python -m scripts.training_evidence create",
        "python -m scripts.training_evidence verify",
        "independent reviewer",
        "outside the repository",
        "no-replace hard-link commit point",
    }
    required_signoff = {
        "Phase 6 role-training evidence file and payload SHA-256:",
        "Training session/environment/release/window:",
        "Operator trainee/reviewer:",
        "Ops administrator trainee/reviewer:",
        "Security auditor trainee/reviewer:",
        "Platform administrator trainee/reviewer:",
        "Required tabletop scenarios and trace IDs:",
        "Phase 6 rehearsal/training external write-once paths and pre-existing-target refusal evidence:",
    }
    errors = [
        f"role-training runbook is missing: {item}"
        for item in sorted(required_runbook)
        if item not in runbook_text
    ]
    errors.extend(
        f"production signoff is missing training field: {item}"
        for item in sorted(required_signoff)
        if item not in signoff_text
    )
    if "production_acceptance=true" in runbook_text:
        errors.append("role-training runbook must not claim production acceptance")
    return errors


def main() -> int:
    try:
        runbook_text = load_stable_text(
            RUNBOOK,
            max_bytes=MAX_TRAINING_ASSET_BYTES,
        )
        signoff_text = load_stable_text(
            SIGNOFF,
            max_bytes=MAX_TRAINING_ASSET_BYTES,
        )
        errors = training_asset_errors(
            runbook_text,
            signoff_text,
        )
    except (OSError, UnicodeError):
        print("training-assets-error: required file cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"training-assets-error: {error}", file=sys.stderr)
        return 1
    print("training-assets-ok roles-scenarios-independent-review-and-sealed-evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
