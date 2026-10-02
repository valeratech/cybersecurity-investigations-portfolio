#!/usr/bin/env python3
"""
Markdown link checker for the investigations portfolio.

Validates every relative target of an inline link, an image, or a link-reference
definition:
  - in a Git work tree whose top level is this directory, the target must be a
    tracked file, or a directory containing tracked files: what GitHub serves.
    Only tracked Markdown files are scanned; untracked Markdown files are counted
    in a NOTICE and not scanned.
  - in a tree without a .git marker (an exported, non-Git tree), the target must
    exist on the local filesystem, and a NOTICE says the check ran in this weaker
    filesystem mode. A tree with a .git marker never falls back: if Git cannot be
    run or queried there, the run is fatal.
  - case matches exactly (GitHub is case-sensitive)
  - anchor fragments resolve to a real heading in the target file
  - no links point outside the repository root

Also reports (never blocking):
  - orphan files: Markdown not reachable by link from the root README, listed even
    with --quiet
  - backticked paths that look like they should be links

Exit status: 0 clean, 1 at least one broken link, 2 fatal (no Markdown file in
scope, or a file that cannot be read or decoded).

Usage:
    python3 check-links.py            # full report
    python3 check-links.py --quiet    # errors, notices and orphans only
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys
from collections import deque

ROOT = pathlib.Path(__file__).resolve().parent

LINK = re.compile(r"!?\[([^\]]*)\]\(([^)]+)\)")
REFDEF = re.compile(r"^ {0,3}\[([^\]]+)\]:[ \t]*<?([^\s>]+)>?", re.M)
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)
BACKTICK_PATH = re.compile(r"`([^`\n]*?\.(?:md|sql|txt|ps1|py|sh))`")


def slug(text):
    """GitHub's heading -> anchor transformation."""
    s = text.strip().lower()
    s = re.sub(r"[`*_~]", "", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    return s


def anchors_for(path):
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return set()
    out, seen = set(), {}
    for _, title in HEADING.findall(text):
        a = slug(title)
        n = seen.get(a, 0)
        seen[a] = n + 1
        out.add(a if n == 0 else f"{a}-{n}")
    return out


TRACKED = None        # set of tracked POSIX paths in tracked mode, else None
TRACKED_DIRS = set()


def fatal(message):
    print(f"  FATAL {message}")
    sys.exit(2)


def tracked_mode():
    """Enter tracked mode when ROOT carries a .git marker; fail closed if Git state cannot be established.

    Without a marker (an exported, non-Git tree) the checker stays in filesystem mode and
    says so. With one, failing to run Git, a failed query, or a work tree whose top level
    is not ROOT is fatal: the checker never degrades a real work tree to filesystem mode.
    """
    global TRACKED
    if not os.path.lexists(ROOT / ".git"):
        return
    try:
        top = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True)
        if top.returncode != 0:
            fatal(f"git rev-parse failed (exit {top.returncode}) in a Git work tree")
        if pathlib.Path(top.stdout.strip()).resolve() != ROOT:
            fatal("the checker directory is not the top level of its Git work tree")
        ls = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True)
    except OSError:
        fatal("Git could not be executed in a Git work tree; tracked state cannot be established")
    if ls.returncode != 0:
        fatal("git ls-files failed inside a Git work tree")
    TRACKED = {p.decode("utf-8", "surrogateescape") for p in ls.stdout.split(b"\0") if p}
    for t in TRACKED:
        parts = t.split("/")
        for i in range(1, len(parts)):
            TRACKED_DIRS.add("/".join(parts[:i]))


def disk_md_files():
    return [p for p in sorted(ROOT.rglob("*.md")) if ".git" not in p.parts]


def md_files():
    if TRACKED is not None:
        return [ROOT / t for t in sorted(TRACKED) if t.endswith(".md")]
    return disk_md_files()


def read_md(path):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as ex:
        print(f"  FATAL cannot read {path.relative_to(ROOT)}: {ex.__class__.__name__}")
        sys.exit(2)


def resolve_ci(target):
    """Return the on-disk path matching target case-insensitively, if any."""
    cur = ROOT
    for part in target.relative_to(ROOT).parts:
        matches = [c for c in cur.iterdir() if c.name.lower() == part.lower()]
        if not matches:
            return None
        cur = matches[0]
    return cur


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    tracked_mode()
    if TRACKED is None:
        print("  NOTICE not a Git work tree at the checker's directory: link targets "
              "are checked on the local filesystem only")
    else:
        untracked = [p for p in disk_md_files()
                     if p.relative_to(ROOT).as_posix() not in TRACKED]
        if untracked:
            print(f"  NOTICE {len(untracked)} untracked Markdown files not scanned "
                  "(not published)")
    if not md_files():
        print("  FATAL no Markdown files in scope")
        sys.exit(2)

    errors, warnings = [], []
    graph = {}
    total = 0

    for src in md_files():
        graph.setdefault(src, set())
        text = read_md(src)
        # strip fenced blocks so example links aren't validated
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        targets = LINK.findall(text) + REFDEF.findall(text)

        for label, target in targets:
            target = target.strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                if target.startswith("#"):
                    total += 1
                    if slug(target[1:]) not in anchors_for(src):
                        errors.append(f"{src.relative_to(ROOT)}: anchor '{target}' not found in own file")
                continue

            total += 1
            frag = ""
            if "#" in target:
                target, frag = target.split("#", 1)
            if not target:
                continue

            dest = (src.parent / target).resolve()

            try:
                dest.relative_to(ROOT)
            except ValueError:
                errors.append(f"{src.relative_to(ROOT)}: '{target}' points outside the repository")
                continue

            if TRACKED is not None:
                rel = dest.relative_to(ROOT).as_posix()
                if rel not in TRACKED and rel not in TRACKED_DIRS and rel != ".":
                    ci = next((t for t in sorted(TRACKED | TRACKED_DIRS)
                               if t.lower() == rel.lower()), None)
                    if ci:
                        errors.append(f"{src.relative_to(ROOT)}: '{target}' wrong case "
                                      f"(tracked: {ci}) - breaks on github.com")
                    else:
                        errors.append(f"{src.relative_to(ROOT)}: '{target}' is not a tracked "
                                      "file or a directory with tracked files - GitHub will not serve it")
                    continue
                if rel in TRACKED:
                    graph[src].add(dest)
            else:
                if not dest.exists():
                    ci = resolve_ci(dest) if dest.parent.exists() or True else None
                    if ci and ci.exists():
                        errors.append(f"{src.relative_to(ROOT)}: '{target}' wrong case "
                                      f"(on disk: {ci.relative_to(ROOT)}) - breaks on github.com")
                    else:
                        errors.append(f"{src.relative_to(ROOT)}: '{target}' does not exist")
                    continue
                if dest.is_file():
                    graph[src].add(dest)

            if frag and dest.suffix == ".md":
                if slug(frag) not in anchors_for(dest):
                    errors.append(f"{src.relative_to(ROOT)}: anchor '#{frag}' not found "
                                  f"in {dest.relative_to(ROOT)}")

    # orphans: unreachable from root README
    root_readme = ROOT / "README.md"
    reachable, q = set(), deque([root_readme])
    while q:
        cur = q.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        for nxt in graph.get(cur, ()):
            if nxt.suffix == ".md":
                q.append(nxt)
    orphans = [p for p in md_files() if p not in reachable]

    # backticked paths that could be links
    candidates = 0
    linked = re.compile(r"\[`[^`]+`\]\([^)]+\)")
    for src in md_files():
        text = re.sub(r"```.*?```", "", read_md(src), flags=re.S)
        for line in text.split("\n"):
            if line.lstrip().startswith("#"):
                continue
            bare = linked.sub("", line)
            for m in BACKTICK_PATH.findall(bare):
                if (src.parent / m).exists() or (ROOT / m).exists():
                    candidates += 1

    if not args.quiet:
        print(f"  mode               : {'tracked files' if TRACKED is not None else 'local filesystem'}")
        print(f"  links checked      : {total}")
        print(f"  broken             : {len(errors)}")
        print(f"  orphan md files    : {len(orphans)} / {len(md_files())}")
        print(f"  backticked paths that resolve to real files: {candidates}")
        print()

    for e in errors:
        print(f"  BROKEN  {e}")
    if errors:
        print()

    if orphans and args.quiet:
        print(f"  WARN  orphan md files (unreachable from root README): {len(orphans)} / {len(md_files())}")
        for o in orphans[:40]:
            print(f"    {o.relative_to(ROOT)}")
    if orphans and not args.quiet:
        print("  Unreachable from root README:")
        for o in orphans[:40]:
            print(f"    {o.relative_to(ROOT)}")
        if len(orphans) > 40:
            print(f"    ... and {len(orphans) - 40} more")
        print()

    print("  RESULT:", "FAIL" if errors else "PASS")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
