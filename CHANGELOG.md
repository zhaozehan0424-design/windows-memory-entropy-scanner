# Changelog

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
