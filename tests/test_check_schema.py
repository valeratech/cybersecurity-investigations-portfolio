#!/usr/bin/env python3
"""Unit tests for check-schema.py.

Locked constraints, as for test_publication_safety.py: fixture documents exist only as
Python string literals in this file, and every test builds a temporary tree outside the
repository containing a byte-identical copy of check-schema.py (the checker anchors to
its own directory). The minimal case below validates cleanly in strict mode.

Run from the repository root:
    python3 -m unittest discover -s tests -q
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "check-schema.py").read_bytes()
CASE = "cyber_range_investigations/001-minimal-case"
FIELDS = [("Document Type", "Case Overview"), ("Case Title", "Minimal Case"), ("Case ID", "001-minimal-case"),
          ("Documentation Started", "2026-01-01"), ("Documentation Last Updated", "2026-01-02"),
          ("Author", "Test Author"), ("Time Standard", "UTC"), ("Source Platform", "CyberDefenders CyberRange")]
BREAK = "\x20\x20"   # two-space Markdown line break, required on every metadata line by the schema
MINIMAL = ("# Minimal Case\n\n" + "".join(f"**{k}:** {v}{BREAK}\n" for k, v in FIELDS)
           + "\n## 1. Case Contents\n\n- [Case overview](README.md)\n\n## 2. Case Status\n\n**Status:** Complete\n")


def run(files, *args, cases_dir=True):
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "check-schema.py").write_bytes(SOURCE)
        if cases_dir:
            (Path(td) / "cyber_range_investigations").mkdir()
        for name, content in files.items():
            p = Path(td) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        p = subprocess.run([sys.executable, "-B", str(Path(td) / "check-schema.py"), *args],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


def with_body(extra):
    return MINIMAL.replace("## 1. Case Contents", extra + "\n\n## 1. Case Contents", 1)


class Schema(unittest.TestCase):
    def test_minimal_case_is_clean_in_strict_mode(self):
        rc, out = run({f"{CASE}/README.md": MINIMAL}, "--strict")
        self.assertEqual(rc, 0, out)
        self.assertIn("Schema violations : 0", out)

    def test_violation_fails_strict_but_not_advisory(self):
        doc = MINIMAL.replace("CyberDefenders CyberRange", "Some Other Platform")
        rc_strict, out = run({f"{CASE}/README.md": doc}, "--strict")
        rc_advisory, _ = run({f"{CASE}/README.md": doc})
        self.assertEqual(rc_strict, 1, out)
        self.assertEqual(rc_advisory, 0)
        self.assertIn("Source Platform", out)

    def test_bracketed_variant_outside_inline_code_is_a_violation(self):
        rc, out = run({f"{CASE}/README.md": with_body("A value <REDACTED - withheld> here.")}, "--strict")
        self.assertEqual(rc, 1, out)
        self.assertIn("outside inline code", out)

    def test_bracketed_variant_inside_inline_code_is_non_canonical(self):
        rc, out = run({f"{CASE}/README.md": with_body("A value `<REDACTED - withheld>` here.")}, "--strict")
        self.assertEqual(rc, 1, out)
        self.assertIn("non-canonical redaction token", out)

    def test_canonical_token_in_inline_code_passes(self):
        rc, out = run({f"{CASE}/README.md": with_body("A value `<REDACTED>` here.")}, "--strict")
        self.assertEqual(rc, 0, out)

    def test_no_case_documents_is_fatal(self):
        rc, out = run({}, "--strict")
        self.assertEqual(rc, 1, out)
        self.assertIn("no case documents found", out)

    def test_missing_cases_directory_fails(self):
        rc, out = run({}, cases_dir=False)
        self.assertNotEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
