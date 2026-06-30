# Windows Memory Entropy Scanner
[![CI](https://github.com/zhaozehan0424-design/windows-memory-entropy-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/zhaozehan0424-design/windows-memory-entropy-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[Repository status](./REPOSITORY_STATUS.md) records the latest maintenance checks and release-readiness notes.

Windows-only Python scanner for finding entropy-rich 32-byte values represented
as 64 ASCII hexadecimal characters in readable process memory.

The scanner is designed for authorized local debugging, incident-response labs,
and defensive security experiments. It uses Windows APIs through `ctypes`, so it
does not require third-party runtime dependencies.

## Features

- Scans committed `PAGE_READWRITE` and `PAGE_EXECUTE_READWRITE` regions.
- Uses `OpenProcess`, `VirtualQueryEx`, and `ReadProcessMemory` through `ctypes`.
- Resolves targets by PID or exact process name using Toolhelp32 APIs.
- Optionally enables `SeDebugPrivilege` for authorized inspection.
- Filters candidates with Shannon entropy and distinct-byte thresholds.
- Reads large regions in chunks with page-level fallback on partial failures.
- Includes a local test target that holds a known hex marker in memory.

## Requirements

- Windows
- Python 3.10+

No Python packages are required.

## Quick Start

Start the local test target in one terminal:

```powershell
python .\tools\hold_hex_target.py
```

It prints its PID and a known 64-character hex marker. In another terminal, scan
that PID:

```powershell
python .\mem_scanner.py <PID> --no-debug-privilege --max-matches 5
```

Scan a process by exact executable name:

```powershell
python .\mem_scanner.py notepad.exe --max-matches 10
```

Use stricter or looser filters:

```powershell
python .\mem_scanner.py <PID> --min-entropy 4.2 --min-distinct 18
python .\mem_scanner.py <PID> --embedded
```

## Checks

Run the same checks used by CI:

```powershell
python -m py_compile .\mem_scanner.py .\tools\hold_hex_target.py
python .\scripts\check-public-repo.py
```

## Output

Matches are printed with:

- absolute virtual address
- containing region base address
- region protection
- entropy score
- distinct byte count
- normalized uppercase hex text

The summary line reports scanned regions, bytes read, read failures, skipped
pages, and total matches.

## Safety And Scope

Use this tool only on processes you own or are explicitly authorized to inspect.
The repository does not include credential dumps, real process captures, private
logs, or instructions for bypassing access controls.

The local `tools/hold_hex_target.py` script is provided so the scanner can be
tested without targeting third-party applications.

Security and contribution notes are in [SECURITY.md](./SECURITY.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).

## Maintenance

GitHub Actions runs syntax and public-repository checks on pushes and pull requests.

See [MAINTENANCE.md](./MAINTENANCE.md) and [CHANGELOG.md](./CHANGELOG.md).

## License

MIT. See [LICENSE](./LICENSE).
