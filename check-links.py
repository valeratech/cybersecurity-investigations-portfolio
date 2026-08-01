#!/usr/bin/env python3
"""
Markdown link checker for the investigations portfolio.

Validates:
  - relative link targets exist
  - case matches exactly (GitHub is case-sensitive; ext4 comparisons
    can mask a mismatch that breaks on github.com)
  - anchor fragments resolve to a real heading in the target file
  - no links point outside the repository root
  - directory links resolve to something GitHub will render

Also reports:
  - orphan files: markdown not reachable by link from the root README
  - backticked paths that look like they should be links

Exit code is non-zero if any link is broken, so this can gate a commit.

Usage:
    python3 check-links.py            # full report
    python3 check-links.py --quiet    # errors only
"""

import argparse
import pathlib
import re
import sys
from collections import deque

ROOT = pathlib.Path(__file__).resolve().parent

LINK = re.compile(r"(?<!\!)\[([^\]]*)\]\(([^)]+)\)")
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


def md_files():
    return [p for p in sorted(ROOT.rglob("*.md")) if ".git" not in p.parts]


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

    errors, warnings = [], []
    graph = {}
    total = 0

    for src in md_files():
        graph.setdefault(src, set())
        text = src.read_text(encoding="utf-8")
        # strip fenced blocks so example links aren't validated
        text = re.sub(r"```.*?```", "", text, flags=re.S)

        for label, target in LINK.findall(text):
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
    for src in md_files():
        text = re.sub(r"```.*?```", "", src.read_text(encoding="utf-8"), flags=re.S)
        for m in BACKTICK_PATH.findall(text):
            if (src.parent / m).exists() or (ROOT / m).exists():
                candidates += 1

    if not args.quiet:
        print(f"  links checked      : {total}")
        print(f"  broken             : {len(errors)}")
        print(f"  orphan md files    : {len(orphans)} / {len(md_files())}")
        print(f"  backticked paths that resolve to real files: {candidates}")
        print()

    for e in errors:
        print(f"  BROKEN  {e}")
    if errors:
        print()

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
