# git-hygiene

One sentence: **git-hygiene audits your repository for the hygiene problems everyone hits once — tracked-but-ignored files, committed secrets and junk, oversized blobs, case conflicts, CRLF shell scripts, unreadable `.gitignore` — and prints the exact fix commands, read-only, with zero dependencies.**

## The problem

`.gitignore` only stops *new* files from being tracked. Files committed before the rule was added stay tracked forever, silently — `node_modules` on the remote, a `.env` in history, a 400 MB dataset from 2021 that every clone still downloads. Stack Overflow's canonical question on this has dozens of answers because everyone discovers it the hard way, and fresh guides are still being written in 2025–2026.

## Why git-hygiene instead of …

| Alternative | What git-hygiene does differently |
|---|---|
| Manual commands (`git ls-files`, `git check-ignore`, `git rm --cached`) | Those *are* the fix — git-hygiene just runs the whole audit and hands you the commands. One invocation instead of a forum thread. |
| `pre-commit-hooks` (case-conflict, large-files, mixed endings) | Excellent, but requires the pre-commit framework and covers pieces. git-hygiene is one stdlib file, no setup, and adds ignored-tracked, secrets, history, and encoding checks. |
| `gitleaks` / secret scanners | Different job: content shapes. git-hygiene catches the structural mistakes (tracked `.env`, junk, blobs). Use both. |
| GitHub's community-standards page | Shows missing *files* (LICENSE, README). Says nothing about tracked junk, blobs, or ignore mistakes. |

> **Honest positioning.** Every individual check here can be done by hand — that is the point. The value is running all of them at once, in CI, before the next accident.

## Features (all implemented and tested)

- **ignored-tracked** (error): tracked files matching your ignore rules, using git's own verdict (`check-ignore --no-index`), each with its `git rm --cached` fix
- **secret-name** (error): tracked `.env*`, `*.pem`, private keys, `*.tfstate`, `credentials.json` … with rotation advice
- **junk-name** (warning): `.DS_Store`, `*.pyc`, `__pycache__/`, `.idea/`, `*.swp` …
- **big-file** (warning): HEAD blobs over `--max-kb` (default 1024)
- **big-history** (warning): top-N largest blobs ever committed (`--history`, default 10) — finds the weight even after deletion
- **case-conflict** (error): paths differing by case only (breaks Windows/macOS checkouts)
- **crlf-script** (error): CRLF in tracked `*.sh` (breaks shebangs on Linux)
- **gitignore-encoding** (error): `.gitignore` git cannot parse (e.g. UTF-16 with BOM — every rule silently dead)
- `--strict`, `--format json`, exit codes 0/1/2; **read-only, no `--fix` flag by design**

## Requirements

- Python 3.9+ (standard library only), git, Windows/macOS/Linux

## Installation

```sh
curl -O https://raw.githubusercontent.com/Black-Studio-ia/git-hygiene/main/githygiene.py
```

Verify: `python githygiene.py --version`

## Quick start

```sh
cd your-repo
python /path/to/githygiene.py
```

Example:

```
git-hygiene: 2 finding(s) across 412 tracked files
  [error] debug.log (ignored-tracked) tracked but matches .gitignore rules
      fix: git rm -r --cached 'debug.log'  # keeps your local copy
  [warning] data/dump.bin (big-file) tracked file is ~184320 KB (over 1024 KB)
      fix: move to Git LFS or release artifacts; existing history still carries it (git filter-repo to purge)
FAIL: 1 error(s); 1 warning(s) (advisory)
```

### GitHub Actions

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml). To audit your own repo on a schedule:

```yaml
- name: Audit repository hygiene
  run: python githygiene.py --history 20
```

## Usage

```
usage: git-hygiene [--root DIR] [--max-kb N] [--history N] [--strict]
                   [--format text|json]

  --max-kb    size threshold in KB (default: 1024)
  --history   report top-N largest historical blobs, 0 disables (default: 10)
  --strict    also fail on warnings
```

## Security and privacy

- **Read-only.** Only git plumbing reads; nothing is written, staged, deleted, or transmitted. No network, no dependencies.
- **Paths only.** Findings never include file contents.
- History scanning reads blob *sizes*, never contents.
- Not a secret-content scanner — pair with `gitleaks`. See [SECURITY.md](SECURITY.md).

## Known limitations

- `.env` detection is by filename; misnamed secret files need content scanning.
- `big-history` walks all reachable blobs — can take a while on giant monorepos (`--history 0` disables it).
- Filenames with unusual quoting are reported git-style; pipes through `git rm` need care with exotic names.
- Case-conflict detection is purely textual (no filesystem probing), so it also works on case-sensitive systems as a pre-flight check for collaborators.

## Running the tests

```sh
python -m unittest discover -s tests -v
```

16 tests, stdlib only (git binary required for fixture repos).

## License

MIT — see [LICENSE](LICENSE).

## Support this project

If this tool saves you a bloated clone or a leaked secret, you may optionally support its continued development with USDT.

Network: TRC20 (Tron)

USDT address: TXQCrX61CceFxX5gnFg9N3ssZEC7MavwBQ

Please verify the network and address carefully before sending — USDT on the wrong network can be lost permanently. Contributions are voluntary and do not guarantee specific features, services, or financial returns. The software remains fully usable under its MIT license regardless.

Contact: ia.creative.tn@gmail.com
