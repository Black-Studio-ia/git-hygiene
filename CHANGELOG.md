# Changelog

## 0.1.0 — 2026-10-14

Initial release.

- Read-only audit: ignored-tracked, secret-name, junk-name, big-file,
  big-history, case-conflict, crlf-script, gitignore-encoding.
- Fix commands printed per finding; `--strict`, `--max-kb`, `--history`,
  `--format json`; exit codes 0/1/2.
- 16-test stdlib `unittest` suite (real git fixture repos); CI workflow.
