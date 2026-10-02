#!/usr/bin/env python3
"""Repository hygiene checker, run by verify-audit.sh.

Each check reports PASS, FAIL or SKIP:

  No whitespace in names             any whitespace character in any file or directory
                                     name in scope
  Code fences balanced (Markdown)    a fence opens on a line matching ^\\s*(```+|~~~+) and
                                     closes on a line using the same character, mirroring
                                     check-schema.py and check-publication-safety.py
  No listed sensitive value          every file in scope (names and contents) is
  (local denylist)                   scanned for each value in the Owner-local
                                     denylist .local/sensitive-denylist.txt, which is never
                                     committed; the check is SKIPPED when that file is
                                     absent (FAIL with --require-denylist); values are
                                     never printed; a tracked denylist is fatal, and
                                     so is a Git work tree (a .git marker is present)
                                     whose tracking state Git cannot establish
  No live http:// URLs (Markdown)    http:// followed by a letter or digit
  No smart quotes (Markdown)         U+2018, U+2019, U+201C or U+201D
  README free of the retired         the root README does not contain '0001-macro'
  '0001-macro' path
  No CRLF line endings               no file in scope contains a CR LF pair

Scope: in a Git work tree (a .git marker in the checked tree), every check examines the
publication scope: tracked files plus untracked files that Git does not ignore, listed by
Git with NUL separators. Git that cannot be executed, a failed query, or a top level other
than the checked tree is FATAL; the checker never falls back to a full walk there. A tree
without a .git marker (an exported tree) is walked in full. In both modes the Owner-local
.local/ directory, which holds the denylist, is outside the scope, and in a Git work tree a
path under .local/ that Git would publish is FATAL. The denylist is loaded, and its tracking
state established, before the scope. The summary counts the files in scope, not every file
on disk.

Fail-closed: a file that cannot be read, a Markdown file that is not UTF-8, a missing root
README, an unusable denylist, or an empty Markdown scope is FATAL. All matching is done in
Python on decoded text or raw bytes, so the result does not depend on the locale.

Exit status: 0 no FAIL, 1 at least one FAIL, 2 fatal.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DENYLIST = Path(".local") / "sensitive-denylist.txt"
MIN_DENY_LEN = 6
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
HTTP_RE = re.compile(r"http://[0-9a-zA-Z]")
SMART = ("\u2018", "\u2019", "\u201c", "\u201d")
DETAIL_CAP = 20


class Fatal(Exception):
    pass


def walk(root):
    """Yield (relative POSIX path, is_dir) for everything outside .git, sorted."""
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d != ".git")
        rel_dp = Path(dp).relative_to(root)
        for d in dns:
            yield (rel_dp / d).as_posix(), True
        for f in sorted(fns):
            yield (rel_dp / f).as_posix(), False


def git_scope(root):
    """(relative path, is_dir) for the publication scope of a Git work tree, enumerated by Git."""
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if top.returncode:
            raise Fatal(f"the publication scope cannot be established: git rev-parse failed (exit {top.returncode})")
        if Path(top.stdout.strip()).resolve() != root:
            raise Fatal("the publication scope cannot be established: the checked tree is not the top level of its Git work tree")
        ls = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            capture_output=True)
    except OSError:
        raise Fatal("the publication scope cannot be established: Git could not be executed in a Git work tree")
    if ls.returncode:
        raise Fatal(f"the publication scope cannot be established: git ls-files failed (exit {ls.returncode})")
    files = sorted({p.decode("utf-8", "surrogateescape") for p in ls.stdout.split(b"\0") if p})
    if any(f == ".local" or f.startswith(".local/") for f in files):
        raise Fatal("a path under .local/ is publishable by Git (tracked, or untracked and not ignored); it must stay ignored")
    dirs = {"/".join(f.split("/")[:i]) for f in files for i in range(1, f.count("/") + 1)}
    return sorted([(d, True) for d in dirs] + [(f, False) for f in files])


def scope(root):
    """The checked scope and its summary label: the publication scope in a Git work tree, else the full tree."""
    if os.path.lexists(root / ".git"):
        return git_scope(root), "publication-scope files (tracked and unignored)"
    entries = [(rel, d) for rel, d in walk(root) if not (rel == ".local" or rel.startswith(".local/"))]
    return entries, "files (full tree; no Git work tree)"


def read_bytes(root, rel):
    try:
        with open(root / rel, "rb") as fh:
            return fh.read()
    except OSError as ex:
        raise Fatal(f"cannot read {rel}: {ex.__class__.__name__}")


def line_of(data, index):
    return data.count(b"\n", 0, index) + 1


def fences_unbalanced(text):
    fence = None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if m:
            ch = m.group(1)[0]
            if fence is None:
                fence = ch
            elif ch == fence:
                fence = None
    return fence is not None


def denylist_tracked(root):
    """Whether Git tracks the denylist; raise Fatal when that cannot be established.

    A tree without a .git marker (for example an exported archive) cannot track anything.
    A tree with one must answer through Git: failing to run Git, a failed query, or a work
    tree whose top level is not the checked tree is fatal, never read as 'untracked'.
    """
    if not os.path.lexists(root / ".git"):
        return False
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if top.returncode != 0:
            raise Fatal(f"git rev-parse failed (exit {top.returncode}); the denylist tracking state cannot be established")
        if Path(top.stdout.strip()).resolve() != root:
            raise Fatal("the checked tree is not the top level of its Git work tree; the denylist tracking state cannot be established")
        ls = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", DENYLIST.as_posix()], capture_output=True)
    except OSError:
        raise Fatal("Git could not be executed in a Git work tree; the denylist tracking state cannot be established")
    if ls.returncode != 0:
        raise Fatal(f"git ls-files failed (exit {ls.returncode}); the denylist tracking state cannot be established")
    return bool(ls.stdout.strip(b"\0"))


def load_denylist(root):
    path = root / DENYLIST
    if not path.exists():
        return None
    if denylist_tracked(root):
        raise Fatal("the local denylist is tracked by Git; remove it from the index (it must never be committed)")
    raw = read_bytes(root, DENYLIST.as_posix())
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Fatal("the local denylist is not UTF-8")
    values = []
    for n, line in enumerate(text.split("\n"), 1):
        line = line.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        if len(line) < MIN_DENY_LEN:
            raise Fatal(f"denylist entry on line {n} is shorter than {MIN_DENY_LEN} characters")
        values.append(line.encode("utf-8"))
    if not values:
        raise Fatal("the local denylist has no entries")
    return values


def run(root, require_denylist):
    values = load_denylist(root)
    entries, scope_label = scope(root)
    files = [rel for rel, is_dir in entries if not is_dir]
    md = [rel for rel in files if rel.endswith(".md")]
    if not md:
        raise Fatal("no Markdown files in scope")
    content = {rel: read_bytes(root, rel) for rel in files}
    text = {}
    for rel in md:
        try:
            text[rel] = content[rel].decode("utf-8")
        except UnicodeDecodeError:
            raise Fatal(f"{rel} is not valid UTF-8")
    if "README.md" not in content:
        raise Fatal("root README.md missing")

    results = []

    ws = [rel for rel, _ in entries if any(ch.isspace() for ch in rel.split("/")[-1])]
    results.append(("No whitespace in names", ws, None))

    results.append(("Code fences balanced (Markdown)", [rel for rel in md if fences_unbalanced(text[rel])], None))

    label = "No listed sensitive value (local denylist)"
    shown_values = [v.decode("utf-8") for v in values or []]
    if values is None:
        if require_denylist:
            results.append((label, ["no local denylist present (required by --require-denylist)"], None))
        else:
            results.append((label, None, "no local denylist present"))
    else:
        hits = []
        for rel in files:
            if rel.startswith(".local/"):
                continue
            data = content[rel]
            for v in values:
                if v in rel.encode("utf-8", "surrogateescape"):
                    parent = rel.rsplit("/", 1)[0] if "/" in rel else "."
                    hits.append(f"{parent}/<name withheld> (a file name contains a listed value)")
                start = data.find(v)
                while start != -1:
                    hits.append(f"{rel}:{line_of(data, start)}")
                    start = data.find(v, start + 1)
        results.append((label, hits, None))

    http = [f"{rel}:{i}" for rel in md for i, line in enumerate(text[rel].split("\n"), 1) if HTTP_RE.search(line)]
    results.append(("No live http:// URLs (Markdown)", http, None))

    smart = [rel for rel in md if any(q in text[rel] for q in SMART)]
    results.append(("No smart quotes (Markdown)", smart, None))

    readme = [f"README.md:{i}" for i, line in enumerate(text["README.md"].split("\n"), 1) if "0001-macro" in line]
    results.append(("README free of the retired '0001-macro' path", readme, None))

    crlf = [rel for rel in files if b"\r\n" in content[rel]]
    results.append(("No CRLF line endings", crlf, None))

    def mask(entry):
        """Withhold any output entry that would print a listed value."""
        if any(v in entry for v in shown_values):
            return "<entry withheld: it would print a listed value>"
        return entry
    return results, len(files), len(md), mask, scope_label


def main(argv=None):
    ap = argparse.ArgumentParser(description="Repository hygiene checker")
    ap.add_argument("--root", type=Path, default=REPO_ROOT, help="tree to check; defaults to the checker directory")
    ap.add_argument("--require-denylist", action="store_true", help="treat an absent local denylist as a failure")
    ap.add_argument("--quiet", action="store_true", help="accepted for symmetry with the other checkers")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"  FATAL not a directory: {args.root}")
        return 2
    try:
        results, n_files, n_md, mask, scope_label = run(root, args.require_denylist)
    except Fatal as ex:
        print(f"  FATAL {ex}")
        print("  ---- hygiene check could not complete ----")
        return 2
    passed = failed = skipped = 0
    for label, offenders, skip in results:
        if skip is not None:
            skipped += 1
            print(f"  SKIP  {label} ({skip})")
        elif offenders:
            failed += 1
            print(f"  FAIL  {label} ({len(offenders)} offenders)")
            for o in offenders[:DETAIL_CAP]:
                print(f"          {mask(o)}")
            if len(offenders) > DETAIL_CAP:
                print(f"          ... and {len(offenders) - DETAIL_CAP} more")
        else:
            passed += 1
            print(f"  PASS  {label}")
    print(f"\n  ---- {passed} passed, {failed} failed, {skipped} skipped; {n_files} {scope_label}, {n_md} Markdown ----")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
