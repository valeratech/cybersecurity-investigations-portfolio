#!/usr/bin/env python3
"""Publication-safety checker.

Commit A scope: redaction-marker placement.

Question enforced:
    Is a redaction-family marker exposed outside an inline-code span or
    fenced block?

Placement only. Canonical-vocabulary enforcement (the marker must be exactly
`<REDACTED>`) remains the responsibility of check-schema.py for case-owned
documentation and becomes gate-blocking under --strict in Stage 3.

Behaviour by Markdown context:
    prose / headings / lists / tables : any family token is a finding
    inline code span                  : any family token passes placement
    fenced block (``` or ~~~)         : exempt
    unclosed fence at EOF             : fatal parse finding

Fence semantics deliberately mirror check-schema.py's mask_fences(): a fence
opens on a line matching ^\\s*(```+|~~~+) and closes only on a line using the
same fence character. (CommonMark's closing-length rule is intentionally not
implemented, so the two checkers can never disagree about what is fenced.)

Exit status: 0 clean, 1 findings, 2 fatal parse errors.
"""

import argparse
import re
import sys
from pathlib import Path

FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
REDACTION_RE = re.compile(r"<\s*(redacted|sensitive|masked|not computed)\s*>",
                          re.IGNORECASE)

# Anchor to the checker's own location so invoking it from the wrong working
# directory can never produce a false green over the wrong tree.
REPO_ROOT = Path(__file__).resolve().parent


def mask_fenced_lines(lines):
    """Blank fenced content, preserving line indices.

    Returns (masked_lines, fence_open_at_eof).
    """
    out, fence_char = [], None
    for l in lines:
        m = FENCE_RE.match(l)
        if m:
            ch = m.group(1)[0]
            if fence_char is None:
                fence_char = ch
                out.append("")
                continue
            if ch == fence_char:
                fence_char = None
                out.append("")
                continue
            # a differing fence marker inside an open fence is content
            out.append("")
            continue
        out.append("" if fence_char else l)
    return out, fence_char is not None


def find_redaction_violations(masked_lines):
    """Return [(line_number, token), ...] for family tokens outside inline code.

    Inline-code spans are masked with spaces (positions preserved); every
    family token remaining outside a complete span is a finding. Each
    occurrence is reported individually, including duplicates on one line.
    An unmatched backtick creates no span and therefore exempts nothing.
    """
    findings = []
    for i, line in enumerate(masked_lines, 1):
        if not line:
            continue
        outside = INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), line)
        for m in REDACTION_RE.finditer(outside):
            findings.append((i, m.group(0)))
    return findings


def scan_text(text):
    """Scan one document's text. Returns (findings, fence_open_at_eof)."""
    masked, fence_open = mask_fenced_lines(text.split("\n"))
    return find_redaction_violations(masked), fence_open


def iter_markdown(root):
    for p in sorted(root.rglob("*.md")):
        if ".git" in p.parts:
            continue
        yield p


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publication-safety checker")
    ap.add_argument("--root", type=Path, default=REPO_ROOT,
                    help="repository root to scan; defaults to the checker "
                         "directory")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress success text; findings are always printed")
    args = ap.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    n_files = 0
    n_findings = 0
    n_fatal = 0
    for p in iter_markdown(root):
        rel = p.relative_to(root)
        n_files += 1
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as ex:
            print(f"{rel}: FATAL cannot read file: {ex}")
            n_fatal += 1
            continue
        findings, fence_open = scan_text(text)
        if fence_open:
            print(f"{rel}: FATAL unclosed code fence at end of file")
            n_fatal += 1
        for line_no, tok in findings:
            print(f"{rel}:{line_no}: redaction token '{tok}' appears outside "
                  f"inline code or a fenced block; use backticked `<REDACTED>`")
            n_findings += 1

    if not args.quiet or n_findings or n_fatal:
        print(f"  Publication safety: {n_files} files checked")
        print(f"  Redaction placement findings : {n_findings}")
        print(f"  Fatal parse errors           : {n_fatal}")

    if n_fatal:
        return 2
    if n_findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
