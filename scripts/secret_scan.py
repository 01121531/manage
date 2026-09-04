"""Lightweight repository secret-pattern scan for CI gates."""

from __future__ import annotations

import os
import pathlib
import re
import sys

try:
    from scripts.external_json import read_stable_bytes
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_json import read_stable_bytes


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
MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024
PATTERNS = {
    "openai-style-key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "sub2-admin-key": re.compile(r"\badmin-[0-9a-f]{64}\b", re.IGNORECASE),
    "bearer-token": re.compile(r"Bearer\s+[A-Za-z0-9._-]{32,}", re.IGNORECASE),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def _raise_walk_error(error: OSError) -> None:
    raise error


def iter_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for raw_directory, directories, names in os.walk(
        ROOT,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        directories[:] = [
            name for name in directories if name not in EXCLUDED_DIRS
        ]
        directory = pathlib.Path(raw_directory)
        for name in names:
            path = directory / name
            if name in EXCLUDED_FILES:
                continue
            files.append(path)
    return files


def main() -> int:
    findings: list[str] = []
    try:
        candidates = iter_files()
    except OSError:
        findings.append("repository traversal: cannot scan safely")
        candidates = []
    for path in candidates:
        try:
            raw = read_stable_bytes(
                path,
                max_bytes=MAX_SCANNED_FILE_BYTES,
                allow_empty=True,
            )
        except OSError:
            findings.append(f"{path.relative_to(ROOT)}: cannot scan safely")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
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
