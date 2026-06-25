# Maintenance

This repository is maintained as a small defensive systems-programming utility.

## Current Maintainer

- GitHub: `zhaozehan0424-design`

## Maintenance Log

### 2026-06-25

- Split the scanner into its own standalone repository.
- Added public project files and safety boundaries.
- Kept the test target local and synthetic so the scanner can be verified
  without inspecting unrelated processes.

## Release Checklist

- Run the syntax check:

```powershell
python -m py_compile .\mem_scanner.py .\tools\hold_hex_target.py
```

- On Windows, start `tools/hold_hex_target.py` and scan its PID.
- Confirm that no real process captures, credentials, dumps, local state files,
  or generated caches are committed.
