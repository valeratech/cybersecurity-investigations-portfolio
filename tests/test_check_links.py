#!/usr/bin/env python3
"""Unit tests for check-links.py.

Locked constraints, as for test_publication_safety.py: fixture documents exist only as
Python string literals in this file, and every test builds a temporary tree outside the
repository containing a byte-identical copy of check-links.py (the checker anchors to
its own directory).

Run from the repository root:
    python3 -m unittest discover -s tests -q
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "check-links.py").read_bytes()
README = "# Portfolio\n\n[A](docs/a.md)\n"
A = "# A\n\nBack to [home](../README.md).\n"


def clean_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def build(td, files):
    (Path(td) / "check-links.py").write_bytes(SOURCE)
    for name, content in files.items():
        p = Path(td) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")


def track(td, paths):
    subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
    subprocess.run(["git", "add", "-f", "--", "check-links.py", *paths], cwd=td, check=True, env=clean_env())


def run_in(td, *args):
    p = subprocess.run([sys.executable, "-B", str(Path(td) / "check-links.py"), *args],
                       capture_output=True, text=True, env=clean_env())
    return p.returncode, p.stdout + p.stderr


def run(files, *args):
    with tempfile.TemporaryDirectory() as td:
        build(td, files)
        return run_in(td, *args)


class FilesystemMode(unittest.TestCase):
    def test_clean_tree_passes_and_says_which_mode_ran(self):
        rc, out = run({"README.md": README, "docs/a.md": A})
        self.assertEqual(rc, 0, out)
        self.assertIn("NOTICE not a Git work tree", out)

    def test_broken_inline_link(self):
        rc, out = run({"README.md": README, "docs/a.md": A + "[x](missing.md)\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("does not exist", out)

    def test_broken_image_link(self):
        rc, out = run({"README.md": README, "docs/a.md": A + "![diagram](missing.png)\n"})
        self.assertEqual(rc, 1, out)

    def test_broken_reference_definition(self):
        rc, out = run({"README.md": README, "docs/a.md": A + "[x][r1]\n\n[r1]: missing-ref.md\n"})
        self.assertEqual(rc, 1, out)

    def test_orphan_is_listed_under_quiet(self):
        rc, out = run({"README.md": README, "docs/a.md": A, "docs/orphan.md": "# O\n"}, "--quiet")
        self.assertEqual(rc, 0, out)
        self.assertIn("docs/orphan.md", out)

    def test_no_markdown_is_fatal(self):
        rc, out = run({})
        self.assertEqual(rc, 2, out)
        self.assertIn("FATAL no Markdown files in scope", out)

    def test_non_utf8_markdown_is_fatal(self):
        rc, out = run({"README.md": README, "docs/a.md": b"# A\n\xff\xfe\n"})
        self.assertEqual(rc, 2, out)


@unittest.skipUnless(shutil.which("git"), "git unavailable")
class TrackedMode(unittest.TestCase):
    def run_tracked(self, files, tracked, *args):
        with tempfile.TemporaryDirectory() as td:
            build(td, files)
            track(td, tracked)
            return run_in(td, *args)

    def test_tracked_tree_passes_in_tracked_mode(self):
        rc, out = self.run_tracked({"README.md": README, "docs/a.md": A}, ["README.md", "docs/a.md"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("NOTICE not a Git work tree", out)

    def test_link_to_an_untracked_file_fails(self):
        files = {"README.md": README + "[L](docs/local.md)\n", "docs/a.md": A, "docs/local.md": "# L\n"}
        rc, out = self.run_tracked(files, ["README.md", "docs/a.md"])
        self.assertEqual(rc, 1, out)
        self.assertIn("is not a tracked file", out)

    def test_link_to_a_directory_without_tracked_files_fails(self):
        files = {"README.md": README + "[D](local-only/)\n", "docs/a.md": A, "local-only/x.txt": "x\n"}
        rc, out = self.run_tracked(files, ["README.md", "docs/a.md"])
        self.assertEqual(rc, 1, out)

    def test_link_to_a_tracked_directory_passes(self):
        files = {"README.md": README + "[Docs](docs/)\n", "docs/a.md": A}
        rc, out = self.run_tracked(files, ["README.md", "docs/a.md"])
        self.assertEqual(rc, 0, out)

    def test_wrong_case_fails(self):
        files = {"README.md": README + "[W](docs/A.md)\n", "docs/a.md": A}
        rc, out = self.run_tracked(files, ["README.md", "docs/a.md"])
        self.assertEqual(rc, 1, out)
        self.assertIn("wrong case", out)

    def test_untracked_markdown_is_not_scanned_and_is_counted(self):
        files = {"README.md": README, "docs/a.md": A, "draft.md": "[x](missing.md)\n"}
        rc, out = self.run_tracked(files, ["README.md", "docs/a.md"], "--quiet")
        self.assertEqual(rc, 0, out)
        self.assertIn("1 untracked Markdown files not scanned", out)


GIT = shutil.which("git")


def nogit_bin(bd):
    """A PATH directory, outside the checked tree, offering python3 but no git."""
    b = Path(bd) / "nogit-bin"
    b.mkdir()
    (b / "python3").symlink_to(sys.executable)
    return str(b)


def fakegit_bin(bd, fail_on):
    """A PATH directory, outside the checked tree, whose git fails one subcommand (exit 3) and passes others through."""
    b = Path(bd) / "fakegit-bin"
    b.mkdir()
    (b / "python3").symlink_to(sys.executable)
    g = b / "git"
    g.write_text(f'#!/bin/sh\n[ "$3" = "{fail_on}" ] && exit 3\nexec "{GIT}" "$@"\n')
    g.chmod(0o755)
    return str(b)


def fakegit_links_enumeration(bd):
    """A PATH directory whose git fails only the link checker's plain enumeration (`git -C <dir> ls-files -z`)."""
    b = Path(bd) / "fakegit-links-bin"
    b.mkdir()
    (b / "python3").symlink_to(sys.executable)
    g = b / "git"
    g.write_text(f'#!/bin/sh\n[ "$3" = ls-files ] && [ "$#" = 4 ] && exit 3\nexec "{GIT}" "$@"\n')
    g.chmod(0o755)
    return str(b)


def gate_tree(td, files):
    """A tree carrying verify-audit.sh and the four checkers, byte-identical to the repository's."""
    for name in ("verify-audit.sh", "check-hygiene.py", "check-links.py", "check-schema.py", "check-publication-safety.py"):
        (Path(td) / name).write_bytes((ROOT / name).read_bytes())
    build(td, files)


def run_env(td, env, *args):
    e = clean_env()
    e.update(env)
    p = subprocess.run([sys.executable, "-B", str(Path(td) / "check-links.py"), *args], capture_output=True, text=True, env=e)
    return p.returncode, p.stdout + p.stderr


@unittest.skipUnless(GIT and hasattr(os, "symlink"), "git or symlinks unavailable")
class GitFailure(unittest.TestCase):
    """A real Git work tree never degrades to filesystem mode (A6-06)."""

    FILES = {"README.md": README + "[L](local-only/)\n", "docs/a.md": A, ".gitignore": "*.zip\n", "local-only/x.zip": b"PK"}

    def worktree(self, td):
        build(td, self.FILES)
        track(td, ["README.md", "docs/a.md", ".gitignore"])

    def test_healthy_git_rejects_the_unpublished_target(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_in(td)
        self.assertEqual(rc, 1, out)

    def test_git_unavailable_in_a_work_tree_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_env(td, {"PATH": nogit_bin(bd)})
        self.assertEqual(rc, 2, out)
        self.assertIn("Git could not be executed", out)
        self.assertNotIn("RESULT: PASS", out)

    def test_rev_parse_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_env(td, {"PATH": fakegit_bin(bd, "rev-parse")})
        self.assertEqual(rc, 2, out)

    def test_ls_files_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_env(td, {"PATH": fakegit_bin(bd, "ls-files")})
        self.assertEqual(rc, 2, out)

    def test_non_git_tree_without_git_uses_filesystem_mode(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            build(td, {"README.md": README, "docs/a.md": A})
            rc, out = run_env(td, {"PATH": nogit_bin(bd)}, "--quiet")
        self.assertEqual(rc, 0, out)
        self.assertIn("NOTICE not a Git work tree", out)

    def test_gate_fails_when_git_state_cannot_be_established(self):
        # The hygiene checker needs Git for its publication scope (A6-19), so this Git fails only the
        # link checker's enumeration: hygiene passes, and the gate must fail through the link checker.
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            gate_tree(td, {"README.md": README, "docs/a.md": A})
            track(td, ["README.md", "docs/a.md"])
            e = clean_env()
            e["PATH"] = fakegit_links_enumeration(bd)
            p = subprocess.run([shutil.which("bash"), "verify-audit.sh"], cwd=td, capture_output=True, text=True, env=e)
        out = p.stdout + p.stderr
        self.assertNotEqual(p.returncode, 0, out)
        self.assertIn("PASS  No CRLF line endings", out)
        self.assertIn("git ls-files failed inside a Git work tree", out)


if __name__ == "__main__":
    unittest.main()
