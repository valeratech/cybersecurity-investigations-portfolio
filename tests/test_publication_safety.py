#!/usr/bin/env python3
"""Unit tests for check-publication-safety.py (Commit A scope).

Locked constraints:
  - fixture documents exist only as Python string literals in this file;
  - CLI tests write temporary Markdown via tempfile, outside the repository
    tree, so no deliberately defective .md fixture is ever committed and no
    other repo-wide checker (check-links.py, legacy shell checks,
    check-schema.py) can interact with test material.

Run from the repository root:
    python3 -m unittest discover -s tests -q
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_publication_safety", ROOT / "check-publication-safety.py")
cps = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cps)


def findings(text):
    f, _ = cps.scan_text(text)
    return f


def tokens(text):
    return [tok for _, tok in findings(text)]


def lines_hit(text):
    return [ln for ln, _ in findings(text)]


class FenceParsing(unittest.TestCase):
    def test_backtick_fence_ignored(self):
        self.assertEqual(findings("```\n<REDACTED>\n```\n"), [])

    def test_tilde_fence_ignored(self):
        self.assertEqual(findings("~~~\n<REDACTED>\n~~~\n"), [])

    def test_indented_fence_recognized(self):
        self.assertEqual(findings("  ```\n<REDACTED>\n  ```\n"), [])

    def test_longer_backtick_fence_recognized(self):
        self.assertEqual(findings("````\n<REDACTED>\n````\n"), [])

    def test_tilde_inside_open_backtick_fence_does_not_close(self):
        text = "```\n~~~\n<REDACTED>\n```\n"
        self.assertEqual(findings(text), [])

    def test_backtick_inside_open_tilde_fence_does_not_close(self):
        text = "~~~\n```\n<REDACTED>\n~~~\n"
        self.assertEqual(findings(text), [])

    def test_content_after_closing_fence_is_scanned(self):
        text = "```\nsafe\n```\n<REDACTED>\n"
        self.assertEqual(lines_hit(text), [4])

    def test_unclosed_fence_is_fatal(self):
        f, fence_open = cps.scan_text("```\n<REDACTED>\n")
        self.assertTrue(fence_open)
        self.assertEqual(f, [])

    def test_shorter_same_character_fence_closes_for_schema_parity(self):
        # Deliberate non-CommonMark behaviour, locked for byte-parity with
        # check-schema.py's mask_fences(): any same-character fence line
        # closes, regardless of length.
        text = "````\n<REDACTED>\n```\n<REDACTED>\n"
        self.assertEqual(lines_hit(text), [4])

    def test_line_numbers_correct_after_fenced_section(self):
        text = "ok\n```\nx\ny\n```\n<REDACTED>\n"
        self.assertEqual(lines_hit(text), [6])


class RedactionPlacement(unittest.TestCase):
    # Must pass placement
    def test_canonical_inline(self):
        self.assertEqual(findings("username `<REDACTED>`\n"), [])

    def test_embedded_in_span(self):
        self.assertEqual(findings("`admin:<REDACTED>`\n"), [])

    def test_noncanonical_inside_span_passes_placement(self):
        # vocabulary is check-schema.py's finding, not placement's
        self.assertEqual(findings("`prefix-<sensitive>-suffix`\n"), [])

    # Must fail placement
    def test_bare_canonical(self):
        self.assertEqual(tokens("<REDACTED>\n"), ["<REDACTED>"])

    def test_bare_family_variant(self):
        self.assertEqual(tokens("username <sensitive>\n"), ["<sensitive>"])

    def test_bare_in_list(self):
        self.assertEqual(tokens("- password: <masked>\n"), ["<masked>"])

    def test_bare_in_table(self):
        self.assertEqual(tokens("| Result | <not computed> |\n"),
                         ["<not computed>"])

    def test_bare_in_heading(self):
        self.assertEqual(tokens("## Account <REDACTED>\n"), ["<REDACTED>"])

    def test_case_insensitive_family(self):
        self.assertEqual(tokens("<Redacted>\n"), ["<Redacted>"])

    def test_internal_whitespace_tolerated(self):
        self.assertEqual(tokens("< SENSITIVE >\n"), ["< SENSITIVE >"])

    # Mixed and edge cases
    def test_valid_span_plus_bare_token_one_finding(self):
        text = "`<REDACTED>` and <REDACTED>\n"
        self.assertEqual(tokens(text), ["<REDACTED>"])

    def test_multiple_bare_tokens_each_reported(self):
        text = "<REDACTED> then <sensitive>\n"
        self.assertEqual(tokens(text), ["<REDACTED>", "<sensitive>"])

    def test_text_around_span_still_scanned(self):
        text = "<masked> `<REDACTED>` <masked>\n"
        self.assertEqual(tokens(text), ["<masked>", "<masked>"])

    def test_unmatched_backtick_exempts_nothing(self):
        text = "broken ` span <REDACTED>\n"
        self.assertEqual(tokens(text), ["<REDACTED>"])

    def test_ordinary_prose_clean(self):
        self.assertEqual(findings("nothing sensitive here\n"), [])

    def test_html_tags_not_in_family_ignored(self):
        self.assertEqual(findings("<summary> and <br> are fine\n"), [])


class Cli(unittest.TestCase):
    def _run(self, files):
        with tempfile.TemporaryDirectory() as td:
            for name, content in files.items():
                p = Path(td) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            from io import StringIO
            buf, old = StringIO(), sys.stdout
            sys.stdout = buf
            try:
                rc = cps.main(["--root", td, "--quiet"])
            finally:
                sys.stdout = old
            return rc, buf.getvalue()

    def test_clean_tree_exits_zero(self):
        rc, out = self._run({"a.md": "clean `<REDACTED>`\n"})
        self.assertEqual(rc, 0)

    def test_one_violation_exits_one_and_prints_location(self):
        rc, out = self._run({"case/notes.md": "bare <REDACTED>\n"})
        self.assertEqual(rc, 1)
        self.assertIn("notes.md:1:", out)
        self.assertIn("<REDACTED>", out)

    def test_all_findings_printed(self):
        rc, out = self._run({"a.md": "<REDACTED>\n<sensitive>\n"})
        self.assertEqual(rc, 1)
        self.assertIn("a.md:1:", out)
        self.assertIn("a.md:2:", out)

    def test_unclosed_fence_exits_two(self):
        rc, out = self._run({"a.md": "```\nnever closed\n"})
        self.assertEqual(rc, 2)
        self.assertIn("FATAL", out)

    def test_unreadable_file_exits_two(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.md").write_text("clean\n", encoding="utf-8")
            from io import StringIO
            buf, old = StringIO(), sys.stdout
            sys.stdout = buf
            try:
                with mock.patch.object(
                        cps.Path, "read_text",
                        side_effect=OSError("permission denied")):
                    rc = cps.main(["--root", td, "--quiet"])
            finally:
                sys.stdout = old
        self.assertEqual(rc, 2)
        self.assertIn("FATAL cannot read file", buf.getvalue())

    def test_quiet_suppresses_summary_on_success_only(self):
        rc, out = self._run({"a.md": "clean\n"})
        self.assertEqual(out, "")
        rc, out = self._run({"a.md": "<masked>\n"})
        self.assertNotEqual(out, "")

    def test_non_markdown_ignored(self):
        rc, out = self._run({"a.txt": "<REDACTED>\n"})
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
