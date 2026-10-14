# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Design guarantees

- **Read-only, no `--fix` flag.** git-hygiene only reads via git plumbing
  and the worktree `.gitignore`. Deletions and history rewrites are
  destructive, so the tool prints exact commands for a human to review.
- **Paths only, never contents.** Findings contain paths, rule ids, and
  fixed messages. History scanning reads blob sizes, not contents.
- **No network access and no dependencies.**

## What this tool is not

- Not a secret-content scanner. Use `gitleaks` or secret scanning for
  secret shapes inside file contents.
- Filename rules are heuristics; a misnamed secret file will not match.

## Reporting a vulnerability

Open a GitHub issue with the `security` label. Never include real secrets.
