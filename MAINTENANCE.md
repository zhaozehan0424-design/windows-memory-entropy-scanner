# Maintenance

This repository is maintained as a small defensive systems-programming utility.

## Current Maintainer

- GitHub: `zhaozehan0424-design`

## Maintenance Log

### 2026-06-27

- Added security and contribution guidelines focused on authorized defensive use.
- Added issue and pull request templates for bug reports, safety/docs changes, and review notes.
- Extended the public repository check to require collaboration and safety files.

### 2026-06-25

- Added GitHub Actions CI on `windows-latest` for syntax and public repository checks.
- Documented the local check commands in the README.
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

## 2026-06-30 - Cross-repository maintenance audit

- Added `REPOSITORY_STATUS.md` as a quick maintainer/readiness dashboard.
- Re-ran verification checks:
- `python -m py_compile .\mem_scanner.py .\tools\hold_hex_target.py -> ok`
- `python .\scripts\check-public-repo.py -> public_repo_ok=true`
- Confirmed README, changelog, security, contribution, issue-template, PR-template, license, and CI files are present.
- Confirmed public documentation does not require committing private keys or local runtime secrets.

