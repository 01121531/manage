"""Lightweight repository secret-pattern scan for CI gates."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {
    ".git",
    ".doc_qa",
    ".doc_qa_scheme",
    ".doc_qa2",
    ".doc_qa3",
    ".doc_qa4",
    ".platform_qa",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
EXCLUDED_FILES = {".env.example", "package-lock.json"}
PATTERNS = {
    "openai-style-key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "bearer-token": re.compile(r"Bearer\s+[A-Za-z0-9._-]{32,}", re.IGNORECASE),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def iter_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(ROOT).parts)
        if parts & EXCLUDED_DIRS:
            continue
        if path.name in EXCLUDED_FILES:
            continue
        files.append(path)
    return files


def main() -> int:
    findings: list[str] = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError as error:
            findings.append(f"{path.relative_to(ROOT)}: cannot read: {error}")
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: matched {name}")
    if findings:
        print("Potential secrets found:", file=sys.stderr)
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("secret-scan-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
