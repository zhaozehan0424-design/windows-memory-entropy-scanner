# Changelog

## v0.1.3 - 2026-06-30

Cross-repository maintenance audit.

- Added `REPOSITORY_STATUS.md` with current health, verification commands, and next maintenance steps.
- Added README CI/license badges and a status link for faster repository scanning.
- Re-ran the repository verification checks and recorded the results.
- Kept public maintenance, security, and contribution files aligned across the GitHub portfolio.

## v0.1.2 - 2026-06-27

Open-source maintenance templates.

- Added `SECURITY.md` and `CONTRIBUTING.md`.
- Added bug report, safety/docs, and pull request templates.
- Extended the public repository check to require collaboration and safety files.

## v0.1.1 - 2026-06-25

Repository CI and maintenance workflow.

- Added GitHub Actions CI on `windows-latest`.
- Added automated Python syntax checks for the scanner and synthetic test target.
- Added public repository checks to CI.
- Documented the local check commands in the README.

## v0.1.0 - 2026-06-25

Initial public release.

- Added Windows process-memory scanner for high-entropy 32-byte hex values.
- Added process-name and PID target resolution.
- Added region filtering, chunked reads, page-level fallback, entropy scoring,
  and match summaries.
- Added a local test target for authorized self-checks.
- Added public README, license, maintenance notes, and repository checks.
