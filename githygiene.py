#!/usr/bin/env python3
"""git-hygiene: audit a git repository for the hygiene problems that
everyone hits once and nobody checks for.

Read-only. Finds, with exact fix commands:

* files that are tracked but match .gitignore (the classic "gitignore
  not working" — almost always already-committed files),
* committed secrets by filename (``.env``, ``*.pem``, private keys …),
* committed junk (``.DS_Store``, ``*.pyc``, ``__pycache__`` …),
* oversized files in HEAD and the largest blobs in history,
* filename case conflicts (break checkouts on Windows/macOS),
* CRLF line endings in shell scripts (breaks shebangs on Linux),
* a ``.gitignore`` that git itself cannot read (e.g. UTF-16 with BOM).

Zero dependencies, offline. Never modifies the repository (no --fix flag
by design: deletions are reviewed by a human). Reports paths only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

__version__ = "0.1.0"

DEFAULT_MAX_KB = 1024
DEFAULT_HISTORY_TOP = 10

SECRET_BASENAMES = {
    ".env", "credentials.json", ".npmrc",
    ".pypirc",
}
SAFE_ENV_TEMPLATES = {
    ".env.example", ".env.sample", ".env.template", ".env.dist",
}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".tfstate")
SECRET_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")

JUNK_BASENAMES = {
    ".DS_Store", "Thumbs.db", "desktop.ini",
}
JUNK_SUFFIXES = (".pyc", ".pyo", ".swp", ".swo")
JUNK_SEGMENTS = {"__pycache__", ".idea", ".vs"}


def _run_git(args: list[str], cwd: str,
             raw_input: bytes | None = None) -> tuple[int, bytes, str]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, timeout=300,
            input=raw_input)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, b"", str(exc)
    return proc.returncode, proc.stdout, proc.stderr.decode(
        "utf-8", "replace").strip()


def tracked_files(root: str) -> list[str]:
    code, out, _ = _run_git(["ls-files", "-z"], root)
    if code != 0:
        return []
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def ignored_but_tracked(root: str, tracked: list[str]) -> list[str]:
    """Tracked paths that match the repo's ignore rules (git's own verdict).

    ``--no-index`` is essential: plain ``check-ignore`` refuses to evaluate
    paths that are already tracked, which is exactly the set we need.
    """
    if not tracked:
        return []
    # Trailing NUL matters: some git versions ignore a final unterminated
    # record on --stdin -z.
    blob = ("\0".join(tracked) + "\0").encode("utf-8", "replace")
    code, out, _ = _run_git(
        ["check-ignore", "--no-index", "--stdin", "-z"], root,
        raw_input=blob)
    if code not in (0, 1):  # 1 simply means "nothing matched"
        return []
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def check_secret_name(path: str) -> str | None:
    segments = path.replace("\\", "/").split("/")
    base = segments[-1]
    if base in SAFE_ENV_TEMPLATES:
        return None
    if base in SECRET_BASENAMES or (
            base.startswith(".env.") and base not in SAFE_ENV_TEMPLATES):
        return (f"{base} is tracked — secrets in history stay readable "
                "even after deletion; rotate them")
    lowered = base.lower()
    if lowered.endswith(SECRET_SUFFIXES):
        return f"{base} looks like a committed secret/key file"
    _, dot, ext = lowered.rpartition(".")
    if lowered.startswith(SECRET_PREFIXES) and (
            not dot or f".{ext}" in {".pem", ".key", ".ppk"}):
        return f"{base} looks like a committed private key"
    return None


def check_junk_name(path: str) -> str | None:
    segments = path.replace("\\", "/").split("/")
    base = segments[-1]
    if base in JUNK_BASENAMES:
        return f"{base} is OS junk that should not be committed"
    if base.lower().endswith(JUNK_SUFFIXES):
        return f"{base} is a build/cache artifact"
    if any(seg in JUNK_SEGMENTS for seg in segments):
        return f"{path} lives in a generated directory"
    return None


def find_case_conflicts(paths: list[str]) -> list[list[str]]:
    """Pure function: groups of tracked paths colliding case-insensitively."""
    seen: dict[str, list[str]] = {}
    for path in paths:
        seen.setdefault(path.lower(), []).append(path)
    return sorted(group for group in seen.values()
                  if len({p for p in group}) > 1)


def tree_sizes(root: str) -> dict[str, int]:
    """Map tracked path -> blob size in bytes (HEAD state)."""
    code, out, _ = _run_git(
        ["ls-tree", "-r", "-l", "--long", "-z", "HEAD", "--", "."], root)
    sizes: dict[str, int] = {}
    if code != 0:
        return sizes
    for entry in out.decode("utf-8", "replace").split("\0"):
        if not entry.strip():
            continue
        try:
            meta, path = entry.split("\t", 1)
            parts = meta.split()
            sizes[path] = int(parts[3])
        except (ValueError, IndexError):
            continue
    return sizes


def largest_blobs(root: str, top: int) -> list[tuple[str, int]]:
    """Largest blobs ever committed: ``[(size, example_path)]``."""
    code, out, _ = _run_git(["rev-list", "--objects", "--all"], root)
    if code != 0:
        return []
    shas: dict[str, str] = {}
    for line in out.decode("utf-8", "replace").splitlines():
        sha, _, path = line.partition(" ")
        if len(sha) == 40 and sha not in shas:
            shas[sha] = path
    if not shas:
        return []
    query = "".join(f"{sha}\n" for sha in shas)
    code, batch, _ = _run_git(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) "
         "%(objectsize)"], root,
        raw_input=query.encode("ascii"))
    sized: list[tuple[int, str]] = []
    if code == 0:
        for line in batch.decode("ascii", "replace").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "blob":
                try:
                    sized.append((int(parts[2]), shas.get(parts[0], "")))
                except ValueError:
                    continue
    sized.sort(reverse=True)
    return [(size, path) for size, path in sized[:top] if size > 0]


def file_head_bytes(root: str, path: str, limit: int = 8192) -> bytes | None:
    code, out, _ = _run_git(["show", f"HEAD:{path}"], root)
    if code != 0:
        return None
    return out[:limit]


def check_gitignore_readable(root: str) -> str | None:
    path = os.path.join(root, ".gitignore")
    if not os.path.isfile(path):
        return None  # absent file is fine; junk rules cover the rest
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return ".gitignore exists but cannot be read"
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return (".gitignore is UTF-16 encoded — git cannot parse it, so "
                "none of its rules apply (save as UTF-8 without BOM)")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return ".gitignore is not valid UTF-8 — git may ignore its rules"
    return None


def audit(root: str, max_kb: int, history_top: int) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    tracked = tracked_files(root)

    for path in sorted(ignored_but_tracked(root, tracked)):
        findings.append({
            "check": "ignored-tracked", "severity": "error", "path": path,
            "message": "tracked but matches .gitignore rules",
            "fix": f"git rm -r --cached {path!r}  # keeps your local copy",
        })
    for path in sorted(tracked):
        msg = check_secret_name(path)
        if msg:
            findings.append({"check": "secret-name", "severity": "error",
                             "path": path, "message": msg,
                             "fix": "rotate the secret, then "
                                    "`git rm --cached` + consider "
                                    "history rewriting (git filter-repo)"})
            continue
        msg = check_junk_name(path)
        if msg:
            findings.append({"check": "junk-name", "severity": "warning",
                             "path": path, "message": msg,
                             "fix": f"git rm -r --cached {path!r} and add "
                                    "a matching .gitignore rule"})
    sizes = tree_sizes(root)
    limit = max_kb * 1024
    for path in sorted(sizes):
        if sizes[path] > limit:
            kb = sizes[path] // 1024
            findings.append({
                "check": "big-file", "severity": "warning", "path": path,
                "message": f"tracked file is ~{kb} KB (over {max_kb} KB)",
                "fix": "move to Git LFS or release artifacts; existing "
                       "history still carries it (git filter-repo to purge)",
            })
    if history_top > 0:
        for size, path in largest_blobs(root, history_top):
            if size > limit:
                kb = size // 1024
                findings.append({
                    "check": "big-history", "severity": "warning",
                    "path": path or "(unknown path)",
                    "message": f"~{kb} KB blob exists in history",
                    "fix": "history rewrite (git filter-repo) is the only "
                           "removal; otherwise leave it and avoid repeats",
                })
    for group in find_case_conflicts(tracked):
        findings.append({
            "check": "case-conflict", "severity": "error",
            "path": ", ".join(group),
            "message": "paths differ by case only — breaks Windows/macOS "
                       "checkouts",
            "fix": "rename one of them",
        })
    for path in sorted(tracked):
        if path.lower().endswith(".sh"):
            head = file_head_bytes(root, path)
            if head and b"\r\n" in head:
                findings.append({
                    "check": "crlf-script", "severity": "error", "path": path,
                    "message": "CRLF line endings break the shebang line "
                               "on Linux",
                    "fix": "convert to LF and set `*.sh text eol=lf` in "
                           ".gitattributes",
                })
    problem = check_gitignore_readable(root)
    if problem:
        findings.append({"check": "gitignore-encoding", "severity": "error",
                         "path": ".gitignore", "message": problem,
                         "fix": "re-save as UTF-8 without BOM"})
    return findings, {"tracked_files": len(tracked)}


def evaluate(findings: list[dict], strict: bool) -> tuple[bool, str]:
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    if errors == 0 and (strict and warnings == 0 or not strict):
        return True, ""
    parts = [f"{errors} error(s)"]
    if warnings:
        parts.append(f"{warnings} warning(s)"
                     + (" (failing under --strict)" if strict
                        else " (advisory)"))
    return False, "; ".join(parts)


def format_text(findings: list[dict], stats: dict, reason: str) -> str:
    out = [f"git-hygiene: {len(findings)} finding(s) "
           f"across {stats.get('tracked_files', 0)} tracked files"]
    for finding in findings:
        out.append(f"  [{finding['severity']}] {finding['path']} "
                   f"({finding['check']}) {finding['message']}")
        if finding.get("fix"):
            out.append(f"      fix: {finding['fix']}")
    out.append("FAIL: " + reason if reason else "PASS: repository is clean")
    return "\n".join(out) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="git-hygiene",
        description="Audit a git repository for tracked-but-ignored files, "
                    "committed secrets/junk, oversized blobs, case "
                    "conflicts, CRLF scripts, and unreadable .gitignore. "
                    "Read-only: prints fix commands, changes nothing.",
    )
    parser.add_argument("--root", default=".",
                        help="repository to audit (default: .)")
    parser.add_argument("--max-kb", type=int, default=DEFAULT_MAX_KB,
                        help=f"size threshold in KB (default: "
                             f"{DEFAULT_MAX_KB})")
    parser.add_argument("--history", type=int, default=DEFAULT_HISTORY_TOP,
                        help=f"report top-N largest historical blobs, "
                             f"0 disables (default: {DEFAULT_HISTORY_TOP})")
    parser.add_argument("--strict", action="store_true",
                        help="also fail on warnings")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="output format (default: text)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_kb < 1:
        parser.error("--max-kb must be at least 1")
    if args.history < 0:
        parser.error("--history must be 0 or more")

    root = os.path.abspath(args.root)
    code, out, _ = _run_git(["rev-parse", "--show-toplevel"], root)
    if code != 0:
        print("git-hygiene: error: not a git repository: "
              f"{args.root}", file=sys.stderr)
        return 2
    shown = out.decode("utf-8", "replace").strip()
    root = shown or root

    findings, stats = audit(root, args.max_kb, args.history)
    ok, reason = evaluate(findings, args.strict)
    if args.format == "json":
        print(json.dumps({"ok": ok, "reason": reason, "stats": stats,
                          "findings": findings}, indent=2))
    else:
        print(format_text(findings, stats, reason), end="")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
