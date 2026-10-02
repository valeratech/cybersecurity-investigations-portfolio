#!/usr/bin/env python3
"""Unit tests for check-hygiene.py.

Locked constraints, as for test_publication_safety.py: fixture documents exist only as
Python string literals in this file, and every test builds its tree in a temporary
directory outside the repository, so no defective fixture is ever committed and no
repo-wide checker can interact with test material. Denylist values are synthetic.

Run from the repository root:
    python3 -m unittest discover -s tests -q
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "check-hygiene.py"
SYNTH = "synthetic-Value-9Q7x"
DENY = ".local/sensitive-denylist.txt"
BASE = {"README.md": "# Portfolio\n", "docs/a.md": "# A\n\nText.\n"}


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(extra or {})
    return env


def build(td, files):
    for name, content in files.items():
        p = Path(td) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)


def run_in(td, *args, env=None):
    p = subprocess.run([sys.executable, "-B", str(CHECKER), "--root", td, *args],
                       capture_output=True, text=True, env=clean_env(env))
    return p.returncode, p.stdout + p.stderr


def run(files, *args, env=None):
    with tempfile.TemporaryDirectory() as td:
        build(td, files)
        return run_in(td, *args, env=env)


class Checks(unittest.TestCase):
    def assertFail(self, files, label, *args, env=None):
        rc, out = run(files, *args, env=env)
        self.assertEqual(rc, 1, out)
        self.assertIn(f"FAIL  {label}", out)
        return out

    def test_clean_tree_passes_with_a_visible_skip(self):
        rc, out = run(BASE)
        self.assertEqual(rc, 0, out)
        self.assertIn("SKIP  No listed sensitive value (local denylist)", out)
        self.assertIn("6 passed, 0 failed, 1 skipped", out)

    def test_trailing_space_in_name(self):
        self.assertFail({**BASE, "docs/b.md ": "x\n"}, "No whitespace in names")

    def test_internal_space_in_name(self):
        self.assertFail({**BASE, "docs/b c.md": "x\n"}, "No whitespace in names")

    def test_tab_in_directory_name(self):
        self.assertFail({**BASE, "do\tcs/b.md": "x\n"}, "No whitespace in names")

    def test_unbalanced_backtick_fence(self):
        self.assertFail({**BASE, "docs/b.md": "```\nopen\n"}, "Code fences balanced (Markdown)")

    def test_unbalanced_indented_fence(self):
        self.assertFail({**BASE, "docs/b.md": "  ```\nopen\n"}, "Code fences balanced (Markdown)")

    def test_unbalanced_tilde_fence(self):
        self.assertFail({**BASE, "docs/b.md": "~~~\nopen\n"}, "Code fences balanced (Markdown)")

    def test_balanced_fences_pass(self):
        rc, out = run({**BASE, "docs/b.md": "```\nx\n```\n~~~\ny\n~~~\n"})
        self.assertEqual(rc, 0, out)

    def test_smart_quote(self):
        self.assertFail({**BASE, "docs/b.md": "the analyst\u2019s note\n"}, "No smart quotes (Markdown)")

    def test_smart_quote_under_the_c_locale(self):
        self.assertFail({**BASE, "docs/b.md": "the analyst\u2019s note\n"}, "No smart quotes (Markdown)",
                        env={"LC_ALL": "C", "LANG": "C"})

    def test_live_http_url(self):
        self.assertFail({**BASE, "docs/b.md": "see http://example.invalid/x\n"}, "No live http:// URLs (Markdown)")

    def test_https_is_outside_this_check(self):
        rc, out = run({**BASE, "docs/b.md": "see https://example.invalid/x\n"})
        self.assertEqual(rc, 0, out)

    def test_retired_readme_path(self):
        self.assertFail({**BASE, "README.md": "# Portfolio\n0001-macro\n"}, "README free of the retired '0001-macro' path")

    def test_crlf_in_markdown(self):
        self.assertFail({**BASE, "docs/b.md": "one\r\ntwo\r\n"}, "No CRLF line endings")

    def test_crlf_in_a_non_markdown_file(self):
        self.assertFail({**BASE, "scripts/q.sql": "select 1;\r\n"}, "No CRLF line endings")


class FailClosed(unittest.TestCase):
    def test_non_utf8_markdown_is_fatal(self):
        rc, out = run({**BASE, "docs/b.md": b"# x\n\xff\xfe\n"})
        self.assertEqual(rc, 2, out)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_unreadable_file_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            build(td, BASE)
            os.symlink(os.path.join(td, "no-such-target"), os.path.join(td, "docs", "broken.md"))
            rc, out = run_in(td)
        self.assertEqual(rc, 2, out)
        self.assertIn("FATAL cannot read docs/broken.md", out)

    def test_no_markdown_is_fatal(self):
        rc, out = run({"notes.txt": "x\n"})
        self.assertEqual(rc, 2, out)
        self.assertIn("FATAL no Markdown files in scope", out)

    def test_missing_root_readme_is_fatal(self):
        rc, out = run({"docs/a.md": "# A\n"})
        self.assertEqual(rc, 2, out)


class Denylist(unittest.TestCase):
    def test_absent_denylist_fails_when_required(self):
        rc, out = run(BASE, "--require-denylist")
        self.assertEqual(rc, 1, out)

    def test_clean_tree_with_denylist_passes(self):
        rc, out = run({**BASE, DENY: SYNTH + "\n"})
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS  No listed sensitive value (local denylist)", out)
        self.assertIn("7 passed, 0 failed, 0 skipped", out)

    def test_value_in_markdown_is_reported_without_printing_it(self):
        rc, out = run({**BASE, DENY: "# synthetic\n" + SYNTH + "\n", "docs/b.md": f"x {SYNTH}\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("docs/b.md:1", out)
        self.assertNotIn(SYNTH, out)

    def test_value_in_a_non_markdown_file_is_reported(self):
        rc, out = run({**BASE, DENY: SYNTH + "\n", "scripts/q.sql": f"-- {SYNTH}\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("scripts/q.sql:1", out)
        self.assertNotIn(SYNTH, out)

    def test_value_in_a_file_name_is_reported_without_printing_it(self):
        rc, out = run({**BASE, DENY: SYNTH + "\n", f"docs/{SYNTH}.md": "x\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("a file name contains a listed value", out)
        self.assertNotIn(SYNTH, out)

    def test_value_in_both_name_and_content_is_never_printed(self):
        rc, out = run({**BASE, DENY: SYNTH + "\n", f"docs/{SYNTH}.md": f"x {SYNTH}\n"})
        self.assertEqual(rc, 1, out)
        self.assertIn("entry withheld", out)
        self.assertNotIn(SYNTH, out)

    def test_short_entry_is_fatal(self):
        rc, out = run({**BASE, DENY: "abc\n"})
        self.assertEqual(rc, 2, out)

    def test_empty_denylist_is_fatal(self):
        rc, out = run({**BASE, DENY: "# comments only\n"})
        self.assertEqual(rc, 2, out)

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_tracked_denylist_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            build(td, {**BASE, DENY: SYNTH + "\n"})
            subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
            subprocess.run(["git", "add", "-f", "--", DENY], cwd=td, check=True, env=clean_env())
            rc, out = run_in(td)
        self.assertEqual(rc, 2, out)
        self.assertIn("tracked by Git", out)
        self.assertNotIn(SYNTH, out)


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


def gate_tree(td, files):
    """A tree carrying verify-audit.sh and the four checkers, byte-identical to the repository's."""
    for name in ("verify-audit.sh", "check-hygiene.py", "check-links.py", "check-schema.py", "check-publication-safety.py"):
        (Path(td) / name).write_bytes((ROOT / name).read_bytes())
    build(td, files)


@unittest.skipUnless(GIT and hasattr(os, "symlink"), "git or symlinks unavailable")
class GitFailure(unittest.TestCase):
    """A Git work tree whose denylist tracking state cannot be established is fatal (A6-04)."""

    def tracked(self, td):
        build(td, {**BASE, DENY: SYNTH + "\n"})
        subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
        subprocess.run(["git", "add", "-A"], cwd=td, check=True, env=clean_env())
        subprocess.run(["git", "add", "-f", "--", DENY], cwd=td, check=True, env=clean_env())

    def test_tracked_denylist_with_git_unavailable_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.tracked(td)
            rc, out = run_in(td, "--require-denylist", env={"PATH": nogit_bin(bd)})
        self.assertEqual(rc, 2, out)
        # the denylist checker's own message: the publication scope fails on the same broken Git too (A6-19)
        self.assertIn("Git could not be executed in a Git work tree; the denylist tracking state cannot be established", out)
        self.assertNotIn(SYNTH, out)

    def test_tracking_status_query_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.tracked(td)
            rc, out = run_in(td, env={"PATH": fakegit_bin(bd, "ls-files")})
        self.assertEqual(rc, 2, out)
        self.assertIn("git ls-files failed (exit 3); the denylist tracking state cannot be established", out)
        self.assertNotIn(SYNTH, out)

    def test_rev_parse_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.tracked(td)
            rc, out = run_in(td, env={"PATH": fakegit_bin(bd, "rev-parse")})
        self.assertEqual(rc, 2, out)
        self.assertIn("git rev-parse failed (exit 3); the denylist tracking state cannot be established", out)
        self.assertNotIn(SYNTH, out)

    def test_untracked_denylist_in_a_healthy_work_tree_passes(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            build(td, {**BASE, ".gitignore": ".local/\n", DENY: SYNTH + "\n"})
            subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
            subprocess.run(["git", "add", "-A"], cwd=td, check=True, env=clean_env())
            rc, out = run_in(td, "--require-denylist")
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS  No listed sensitive value (local denylist)", out)

    def test_non_git_tree_needs_no_git(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            build(td, {**BASE, DENY: SYNTH + "\n"})
            rc, out = run_in(td, "--require-denylist", env={"PATH": nogit_bin(bd)})
        self.assertEqual(rc, 0, out)

    def test_gate_with_required_denylist_fails_when_tracking_cannot_be_established(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            gate_tree(td, {**BASE, DENY: SYNTH + "\n"})
            subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
            subprocess.run(["git", "add", "-A"], cwd=td, check=True, env=clean_env())
            subprocess.run(["git", "add", "-f", "--", DENY], cwd=td, check=True, env=clean_env())
            p = subprocess.run([shutil.which("bash"), "verify-audit.sh", "--require-denylist"], cwd=td,
                               capture_output=True, text=True, env=clean_env({"PATH": nogit_bin(bd)}))
        out = p.stdout + p.stderr
        self.assertNotEqual(p.returncode, 0, out)
        # the gate stops at its first step, so the failure must be the denylist checker's own
        self.assertIn("the denylist tracking state cannot be established", out)
        self.assertNotIn(SYNTH, out)


@unittest.skipUnless(GIT and hasattr(os, "symlink"), "git or symlinks unavailable")
class PublicationScope(unittest.TestCase):
    """In a Git work tree only tracked and unignored files are in scope (A6-19)."""

    IGNORE = "__pycache__/\n*.pyc\n.local/\nscratch/\n"

    def worktree(self, td, extra=None):
        build(td, {**BASE, ".gitignore": self.IGNORE, **(extra or {})})
        subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
        subprocess.run(["git", "add", "-A"], cwd=td, check=True, env=clean_env())

    def count(self, out):
        return re.search(r"; (\d+) publication-scope files", out).group(1)

    def test_tracked_crlf_fails(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td, {"docs/crlf.txt": b"a\r\nb\r\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL  No CRLF line endings", out)

    def test_untracked_unignored_crlf_fails(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td)
            build(td, {"notes.txt": b"a\r\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL  No CRLF line endings", out)

    def test_ignored_bytecode_with_crlf_is_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td)
            build(td, {"tests/__pycache__/m.cpython-312.pyc": b"\x00\r\n\xff", "loose.pyc": b"\r\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS  No CRLF line endings", out)
        self.assertIn("publication-scope files (tracked and unignored)", out)

    def test_ignored_binary_cache_is_neither_scanned_nor_counted(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td)
            _, before = run_in(td)
            build(td, {"__pycache__/x.cpython-312.pyc": bytes(range(256)) * 4})
            rc, after = run_in(td)
        self.assertEqual(rc, 0, after)
        self.assertEqual(self.count(before), self.count(after))

    def test_ignored_markdown_with_violations_is_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td)
            build(td, {"scratch/draft.md": "the analyst\u2019s note\nsee http://example.invalid/x\n```\nopen\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 0, out)

    def test_ignored_name_with_whitespace_is_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td)
            build(td, {"scratch/a name.txt": "x\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 0, out)

    def test_ignored_file_with_a_listed_value_is_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            self.worktree(td, {DENY: SYNTH + "\n"})
            build(td, {"scratch/raw-notes.txt": SYNTH + "\n"})
            rc, out = run_in(td, "--require-denylist")
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS  No listed sensitive value (local denylist)", out)
        self.assertNotIn(SYNTH, out)

    def test_publishable_local_directory_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            build(td, {**BASE, ".gitignore": "__pycache__/\n", DENY: SYNTH + "\n"})
            subprocess.run(["git", "init", "-q"], cwd=td, check=True, env=clean_env())
            subprocess.run(["git", "add", "README.md", "docs", ".gitignore"], cwd=td, check=True, env=clean_env())
            rc, out = run_in(td)
        self.assertEqual(rc, 2, out)
        self.assertIn("a path under .local/ is publishable by Git", out)
        self.assertNotIn(SYNTH, out)

    def test_scope_with_git_unavailable_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_in(td, env={"PATH": nogit_bin(bd)})
        self.assertEqual(rc, 2, out)
        self.assertIn("the publication scope cannot be established: Git could not be executed", out)

    def test_scope_rev_parse_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_in(td, env={"PATH": fakegit_bin(bd, "rev-parse")})
        self.assertEqual(rc, 2, out)
        self.assertIn("the publication scope cannot be established: git rev-parse failed", out)

    def test_scope_enumeration_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as bd:
            self.worktree(td)
            rc, out = run_in(td, env={"PATH": fakegit_bin(bd, "ls-files")})
        self.assertEqual(rc, 2, out)
        self.assertIn("the publication scope cannot be established: git ls-files failed", out)

    def test_non_git_tree_is_walked_in_full(self):
        with tempfile.TemporaryDirectory() as td:
            build(td, {**BASE, "__pycache__/x.cpython-312.pyc": b"\r\n"})
            rc, out = run_in(td)
        self.assertEqual(rc, 1, out)
        self.assertIn("files (full tree; no Git work tree)", out)

    def test_local_directory_is_outside_the_full_walk(self):
        with tempfile.TemporaryDirectory() as td:
            build(td, {**BASE, DENY: SYNTH + "\n", ".local/other.txt": b"a\r\n"})
            rc, out = run_in(td, "--require-denylist")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(SYNTH, out)


if __name__ == "__main__":
    unittest.main()
