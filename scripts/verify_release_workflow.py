"""Static fail-closed checks for the online-update release workflow."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def workflow_errors(text: str) -> list[str]:
    required = (
        'tags:',
        '"v*.*.*"',
        "contents: write",
        "actions/setup-node@v4",
        "node-version: \"22\"",
        "npm ci",
        "./scripts/quality_gate.ps1",
        "./build.ps1",
        "verify_desktop_package.py --exe",
        "create_update_manifest.py",
        "email-platform-windows.exe",
        "update-manifest.json",
        "gh release create",
        "--verify-tag",
        "github.token",
    )
    errors = [f"release workflow missing: {marker}" for marker in required if marker not in text]
    if "client_secret" in text.lower():
        errors.append("release workflow must not contain a client secret")
    return errors


def main() -> int:
    if not WORKFLOW.is_file():
        print("release-workflow-error: workflow does not exist")
        return 1
    errors = workflow_errors(WORKFLOW.read_text(encoding="utf-8"))
    if errors:
        for error in errors:
            print(f"release-workflow-error: {error}")
        return 1
    print("release-workflow-ok verified GitHub Release updater assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
