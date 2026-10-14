"""Tests for git-hygiene. Run with: python -m unittest discover -s tests -v"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import githygiene


def git(*args, cwd):
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True)
    assert proc.returncode == 0, (args, proc.stderr[-500:])
    return proc.stdout


def write_bytes(root, rel, content: bytes):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)


def write_text(root, rel, content: str):
    write_bytes(root, rel, content.replace("\n", "\n").encode("utf-8"))


def make_repo():
    root = tempfile.mkdtemp(prefix="git-hygiene-test-")
    git("init", cwd=root)
    git("config", "user.email", "test@example.com", cwd=root)
    git("config", "user.name", "Test", cwd=root)
    git("config", "core.autocrlf", "false", cwd=root)
    git("config", "commit.gpgsign", "false", cwd=root)
    return root


def commit_all(root, message="x"):
    git("add", "-A", cwd=root)
    git("commit", "-m", message, cwd=root)


class UnitTests(unittest.TestCase):
    def test_case_conflicts(self):
        groups = githygiene.find_case_conflicts(
            ["src/App.py", "src/app.py", "README.md", "readme.MD", "ok.py"])
        flat = sorted(p for g in groups for p in g)
        self.assertEqual(len(groups), 2)
        self.assertIn("src/App.py", flat)
        self.assertIn("README.md", flat)

    def test_no_case_conflicts(self):
        self.assertEqual(
            githygiene.find_case_conflicts(["a.py", "b.py", "A/b.py"]), [])

    def test_secret_and_safe_names(self):
        self.assertIsNotNone(githygiene.check_secret_name(".env"))
        self.assertIsNotNone(githygiene.check_secret_name("sub/.env.prod"))
        self.assertIsNotNone(githygiene.check_secret_name("key.pem"))
        self.assertIsNotNone(githygiene.check_secret_name("id_rsa"))
        self.assertIsNone(githygiene.check_secret_name(".env.example"))
        self.assertIsNone(githygiene.check_secret_name("src/app.py"))
        self.assertIsNone(githygiene.check_secret_name("id_rsa.txt"))

    def test_junk_names(self):
        self.assertIsNotNone(githygiene.check_junk_name(".DS_Store"))
        self.assertIsNotNone(githygiene.check_junk_name("a/__pycache__/b.pyc"))
        self.assertIsNone(githygiene.check_junk_name("src/app.py"))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.root = make_repo()
        write_text(self.root, "src/app.py", "x = 1\n")
        write_text(self.root, ".gitignore", "*.log\nbuild/\n")
        commit_all(self.root, "base")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_clean_repo_passes(self):
        findings, stats = githygiene.audit(self.root, 1024, 0)
        self.assertEqual(
            [f for f in findings if f["severity"] == "error"], [])
        ok, _ = githygiene.evaluate(findings, strict=False)
        self.assertTrue(ok)
        self.assertEqual(stats["tracked_files"], 2)

    def test_ignored_but_tracked(self):
        write_text(self.root, "debug.log", "noise\n")
        git("add", "-f", "debug.log", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        hits = [f for f in findings if f["check"] == "ignored-tracked"]
        self.assertEqual(len(hits), 1)
        self.assertIn("git rm", hits[0]["fix"])
        ok, _ = githygiene.evaluate(findings, strict=False)
        self.assertFalse(ok)

    def test_secret_env_tracked(self):
        write_text(self.root, ".env", "SECRET=abc\n")
        git("add", "-f", ".env", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        hits = [f for f in findings if f["check"] == "secret-name"]
        self.assertTrue(hits)
        self.assertIn("rotate", hits[0]["fix"])

    def test_junk_tracked_is_warning(self):
        write_text(self.root, ".DS_Store", "junk\n")
        git("add", "-f", ".DS_Store", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        hits = [f for f in findings if f["check"] == "junk-name"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "warning")
        ok, _ = githygiene.evaluate(findings, strict=False)
        self.assertTrue(ok)
        ok2, _ = githygiene.evaluate(findings, strict=True)
        self.assertFalse(ok2)

    def test_big_file_in_head(self):
        write_bytes(self.root, "data/big.bin", b"0" * (1300 * 1024))
        git("add", "-f", "data/big.bin", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        self.assertTrue(any(f["check"] == "big-file" for f in findings))

    def test_big_blob_in_history_found_after_removal(self):
        write_bytes(self.root, "data/big.bin", b"0" * (1300 * 1024))
        git("add", "-f", "data/big.bin", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        git("rm", "data/big.bin", cwd=self.root)
        git("commit", "-m", "remove", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 10)
        self.assertTrue(any(f["check"] == "big-history" for f in findings))

    def test_crlf_shell_script(self):
        write_bytes(self.root, "run.sh",
                    b"#!/bin/sh\r\necho hi\r\n")
        git("add", "run.sh", cwd=self.root)
        git("commit", "-m", "sh", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        self.assertTrue(any(f["check"] == "crlf-script" for f in findings))

    def test_utf16_gitignore(self):
        os.remove(os.path.join(self.root, ".gitignore"))
        write_bytes(self.root, ".gitignore",
                    "*.log\n".encode("utf-16"))
        git("add", ".gitignore", cwd=self.root)
        git("commit", "-m", "enc", cwd=self.root)
        findings, _ = githygiene.audit(self.root, 1024, 0)
        self.assertTrue(
            any(f["check"] == "gitignore-encoding" for f in findings))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.root = make_repo()
        write_text(self.root, "app.py", "x = 1\n")
        commit_all(self.root, "base")
        self.script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "githygiene.py")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, self.script, *args],
                              capture_output=True, text=True, cwd=self.root)

    def test_cli_clean_passes(self):
        proc = self.run_cli("--root", self.root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_cli_fails_on_ignored_tracked(self):
        write_text(self.root, "x.log", "1\n")
        with open(os.path.join(self.root, ".gitignore"), "w",
                  encoding="utf-8") as handle:
            handle.write("*.log\n")
        git("add", "-A", cwd=self.root)
        git("add", "-f", "x.log", cwd=self.root)
        git("commit", "-m", "oops", cwd=self.root)
        proc = self.run_cli("--root", self.root)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ignored-tracked", proc.stdout)
        self.assertIn("git rm", proc.stdout)

    def test_cli_not_a_repo_exit_2(self):
        empty = tempfile.mkdtemp(prefix="git-hygiene-norepo-")
        self.addCleanup(shutil.rmtree, empty, True)
        proc = self.run_cli("--root", empty)
        self.assertEqual(proc.returncode, 2)

    def test_cli_json_valid(self):
        proc = self.run_cli("--root", self.root, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        self.assertIn("tracked_files", payload["stats"])


if __name__ == "__main__":
    unittest.main()
