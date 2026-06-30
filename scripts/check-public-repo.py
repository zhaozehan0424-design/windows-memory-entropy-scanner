from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md",
    "CHANGELOG.md",
    "MAINTENANCE.md",
    "REPOSITORY_STATUS.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    ".gitignore",
    ".github/workflows/ci.yml",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/safety_or_docs.md",
    ".github/pull_request_template.md",
    "mem_scanner.py",
    "tools/hold_hex_target.py",
]

REQUIRED_README_SNIPPETS = [
    "Windows Memory Entropy Scanner",
    "OpenProcess",
    "VirtualQueryEx",
    "ReadProcessMemory",
    "authorized",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "tools/hold_hex_target.py",
    "MIT",
]


def main() -> int:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).exists()]
    if missing:
        print(f"missing_files={','.join(missing)}")
        return 1

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing_snippets = [
        snippet for snippet in REQUIRED_README_SNIPPETS if snippet not in readme
    ]
    if missing_snippets:
        print(f"missing_readme_snippets={','.join(missing_snippets)}")
        return 1

    print("public_repo_ok=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
