#!/usr/bin/env python3
"""
Documentation schema validator.

Enforces the objective structural rules in docs/SCHEMA.md. It does not
validate semantic truth: whether an indicator is malicious, a timeline claim
is supported, or an ATT&CK mapping is correct remain manual evidence
reconciliation tasks.

Three result classes, per SCHEMA.md:

  FATAL      the validator cannot proceed reliably. Non-zero in both modes.
  VIOLATION  schema debt. Warning in advisory mode, failure under --strict.
  NOTICE     document profile deviation. Reported, never affects exit status.

Usage:
    python3 check-schema.py            # advisory
    python3 check-schema.py --strict   # gate
    python3 check-schema.py --quiet    # summary only
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
CASES = ROOT / "cyber_range_investigations"

FIELD_RE = re.compile(r"^\*\*([^:*]+):\*\*(.*)$")
# A bold label with no colon, e.g. **Case ID** 002 — malformed only when the
# label is a known metadata field name (bare bold body text is legitimate).
MALFORMED_RE = re.compile(r"^\*\*([^:*]+)\*\*(\s.*)?$")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
NUM_PREFIX_RE = re.compile(r"^\d+(?:\.\d+)*[.)]?\s*")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")

# ---------------------------------------------------------------- vocabulary
DOC_TYPES = {
    "Case Overview", "Case Note", "Timeline", "Analysis", "Findings Summary",
    "IOC Collection", "Evidence Inventory", "Final Report", "Directory Index",
    "Reference",
}
RETIRED_TYPES = {
    "Investigation Summary": "Case Overview or Case Note",
    "Investigation Summary (Root README)": "Case Overview",
    "Findings": "Findings Summary",
    "Report": "Final Report",
    "Evidence Metadata": "Evidence Inventory",
    "Screenshot Index": "Directory Index",
}
RETIRED_FIELDS = {
    "Date Created": "Documentation Started",
    "Last Updated": "Documentation Last Updated",
    "Date Completed": "Documentation Last Updated",
    "Date": "Documentation Last Updated",
    "Analyst": "Author",
    "Case Name": "Case Title",
}

# Metadata values that must move into document body content rather than
# being renamed to another metadata field.
MOVED_FIELDS = {"Evidence Source"}

STATUSES = {"Complete", "In Progress"}
TIME_STANDARDS = {"UTC"}
PLATFORMS = {"CyberDefenders CyberRange", "Security Blue Team CyberRange"}

TIER_FIELDS = {
    1: ["Document Type", "Case Title", "Case ID", "Documentation Started",
        "Documentation Last Updated", "Author", "Time Standard", "Source Platform"],
    2: ["Document Type", "Case Title", "Case ID", "Documentation Started",
        "Documentation Last Updated", "Author", "Time Standard", "Source Platform"],
    3: ["Document Type", "Case ID", "Time Standard", "Source Platform"],
    4: ["Document Type", "Case ID", "Source Platform"],
}
TIER_OPTIONAL_STATUS_AFTER = {3: "Case ID", 4: "Case ID"}

# All names the metadata grammar could ever intend: used only to classify a
# malformed bold line (no colon) as an unparsable field rather than body text.
KNOWN_FIELD_NAMES = (
    {f for fs in TIER_FIELDS.values() for f in fs}
    | set(RETIRED_FIELDS)
    | MOVED_FIELDS
    | {"Status"}
)

TIER_TYPES = {
    1: {"Case Overview"},
    2: {"Final Report"},
    4: {"Directory Index"},
    3: {"Case Note", "Timeline", "Analysis", "Findings Summary",
        "IOC Collection", "Evidence Inventory", "Reference"},
}

CASE_OWNED = ["Case Title", "Documentation Started",
              "Documentation Last Updated", "Author", "Source Platform"]

PENDING_HEADINGS = {"next steps", "planned", "appendix (planned)"}
PENDING_TOKENS = ["TBD", "To Be Determined", "requires further validation",
                  "will be updated", "not yet completed"]

# Case-insensitive redaction family. The canonical token is `<REDACTED>`
# (backticked). Anything from this family surviving outside fenced blocks and
# inline code spans is non-canonical.
REDACTION_RE = re.compile(r"<\s*(redacted|sensitive|masked|not computed)\s*>",
                          re.IGNORECASE)

# profile categories: (label, keyword alternatives) — H2+ headings only
PROFILES = {
    "Case Overview": [("numbered body sections", None),      # special-cased
                      ("terminal Case Status", None)],       # special-cased
    "Final Report": [("executive summary", ["executive summary"]),
                     ("scope/evidence", ["scope", "evidence"]),
                     ("findings", ["finding", "conclusion", "summary"]),
                     ("limitations", ["limitation", "constraint", "notes"])],
    "Timeline": [("evidence basis", ["overview", "evidence", "basis"]),
                 ("observations", ["observation", "timeline", "timestamp"]),
                 ("limitations", ["limitation", "gap", "constraint"])],
    "Findings Summary": [("findings", ["finding"]),
                         ("assessment", ["assessment", "conclusion", "summary"])],
    "IOC Collection": [("classification sections",
                        ["indicator", "asset", "observable", "ioc", "hash",
                         "domain", "address", "url", "file", "command", "detection"])],
    "Evidence Inventory": [("evidence register", ["evidence", "register", "inventory"]),
                           ("usage or handling notes",
                            ["usage", "handling", "limitation", "note", "enrichment"])],
    "Directory Index": [("purpose or availability",
                         ["purpose", "availability", "status", "contents",
                          "access", "retention", "planned", "current"])],
}


class Result:
    def __init__(self):
        self.fatal, self.viol, self.notice = [], [], []

    def F(self, path, msg): self.fatal.append((path, msg))
    def V(self, path, msg): self.viol.append((path, msg))
    def N(self, path, msg): self.notice.append((path, msg))


def norm_heading(line):
    """'## 7. Next Steps' -> 'next steps'."""
    t = line.lstrip("#").strip().rstrip(":")
    t = NUM_PREFIX_RE.sub("", t)
    return t.strip().lower()


def mask_fences(lines):
    """Blank fenced content, preserving indices.

    Supports ``` and ~~~ fences; a fence closes only on the same character.
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


def parse_metadata(masked, res, rel):
    """State machine per SCHEMA.md section 2.

    Returns (state, fields, order, end) with state in {"OK","ABSENT","FATAL"}.
    """
    h1 = [i for i, l in enumerate(masked) if l.startswith("# ")]
    if len(h1) != 1:
        res.V(rel, f"expected exactly one level-one heading outside fences, found {len(h1)}")
    start_search = h1[0] + 1 if h1 else 0

    h2 = next((i for i, l in enumerate(masked) if l.startswith("## ")), len(masked))

    # Malformed bold field lines anywhere in the metadata region are
    # unparsable metadata: fatal per SCHEMA.md section 3.
    for i in range(start_search, min(h2, len(masked))):
        m = MALFORMED_RE.match(masked[i])
        if m and not FIELD_RE.match(masked[i]) and m.group(1).strip() in KNOWN_FIELD_NAMES:
            res.F(rel, f"metadata field line cannot be parsed at line {i+1}: "
                       f"'{masked[i].strip()[:60]}' (missing ':' inside bold label?)")
            return "FATAL", None, None, None

    first = None
    for i in range(start_search, len(masked)):
        if FIELD_RE.match(masked[i]):
            first = i
            break
        if masked[i].strip() == "":
            continue
        break
    if first is None or first >= h2:
        return "ABSENT", None, None, None

    fields, order, end = {}, [], first
    blank_inside = False
    blank_pending = False
    i = first
    while i < len(masked):
        l = masked[i]
        m = FIELD_RE.match(l)
        if m:
            if blank_pending:
                blank_inside = True      # blank BETWEEN two field lines
                blank_pending = False
            name = m.group(1).strip()
            raw = m.group(2)
            if name in fields:
                res.F(rel, f"duplicate metadata field: {name}")
                return "FATAL", None, None, None
            if not raw.endswith("  "):
                res.V(rel, f"field '{name}' missing required two-space line ending")
            if not raw.strip():
                res.V(rel, f"field '{name}' has a blank value")
            fields[name] = raw.strip()
            order.append(name)
            end = i
        elif l.strip() == "":
            blank_pending = True         # only counts if a field follows
        elif l.startswith("## "):
            break
        else:
            break
        i += 1

    if blank_inside:
        res.V(rel, "blank line inside metadata block")

    for j in range(end + 1, min(h2, len(masked))):
        if FIELD_RE.match(masked[j]):
            res.F(rel, f"metadata field at line {j+1} after block ended "
                       f"(line {end+1}) but before first level-two heading — "
                       "block boundaries ambiguous")
            return "FATAL", None, None, None

    return "OK", fields, order, end


def tier_of(rel_parts):
    """rel_parts is the path relative to the case directory."""
    if rel_parts == ("README.md",):
        return 1
    if rel_parts == ("reports", "final-report.md"):
        return 2
    if rel_parts[-1] == "README.md":
        return 4
    return 3


def check_order(order, tier, fields, res, rel):
    expected = list(TIER_FIELDS[tier])
    if "Status" in fields and tier in TIER_OPTIONAL_STATUS_AFTER:
        anchor = TIER_OPTIONAL_STATUS_AFTER[tier]
        expected.insert(expected.index(anchor) + 1, "Status")
    present = [f for f in order if f in expected]
    if present != [f for f in expected if f in order]:
        res.V(rel, f"fields out of order: {present} (expected "
                   f"{[f for f in expected if f in order]})")
    for f in expected:
        if f not in fields:
            res.V(rel, f"missing required tier {tier} field: {f}")
    known = set(expected)   # Status is known only where a tier permits it
    for f in order:
        if f in RETIRED_FIELDS:
            res.V(rel, f"retired field '{f}' — use '{RETIRED_FIELDS[f]}'")
        elif f not in known:
            res.V(rel, f"unexpected metadata field for tier {tier}: {f}")


def check_values(fields, tier, slug, res, rel):
    dt = fields.get("Document Type", "")
    if dt in RETIRED_TYPES:
        res.V(rel, f"retired Document Type '{dt}' — use '{RETIRED_TYPES[dt]}'")
    elif dt and dt not in DOC_TYPES:
        res.V(rel, f"Document Type '{dt}' is not in the closed vocabulary")
    elif dt and dt not in TIER_TYPES[tier]:
        res.V(rel, f"Document Type '{dt}' is not valid for tier {tier}")

    cid = fields.get("Case ID", "")
    if cid and cid != slug:
        res.V(rel, f"Case ID '{cid}' does not match case slug '{slug}'")
    st = fields.get("Status", "")
    if st and st not in STATUSES:
        res.V(rel, f"Status '{st[:50]}' is not in the closed set {sorted(STATUSES)}")
    ts = fields.get("Time Standard", "")
    if ts and ts not in TIME_STANDARDS:
        res.V(rel, f"Time Standard '{ts[:50]}' is not '{sorted(TIME_STANDARDS)[0]}'")
    sp = fields.get("Source Platform", "")
    if sp and sp not in PLATFORMS:
        res.V(rel, f"Source Platform '{sp[:50]}' is not in the closed set")
    for d in ("Documentation Started", "Documentation Last Updated"):
        v = fields.get(d, "")
        if v and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            res.V(rel, f"{d} '{v}' is not ISO 8601 (YYYY-MM-DD)")


def body_status_fields(masked, meta_end):
    """(line_index, value) for every **Status:** field after the metadata block."""
    out = []
    start = (meta_end + 1) if meta_end is not None else 0
    for i in range(start, len(masked)):
        m = FIELD_RE.match(masked[i])
        if m and m.group(1).strip() == "Status":
            out.append((i, m.group(2).strip()))
    return out


def case_status_of(overview_masked, overview_fields, meta_end, res, rel):
    """Dedicated Case Status parser for the case overview.

    Returns the effective status string ("" when undetermined), or None on
    fatal ambiguity.
    """
    found = body_status_fields(overview_masked, meta_end)
    if len(found) > 1:
        res.F(rel, f"case status is ambiguous: {len(found)} body Status fields "
                   f"(lines {', '.join(str(i+1) for i, _ in found)})")
        return None
    if not found:
        # terminal Case Status absence is a profile notice (handled in
        # check_profile); metadata Status on tier 1 is already flagged as an
        # unexpected field, but still usable as a last resort here.
        return overview_fields.get("Status", "")

    idx, val = found[0]
    if val not in STATUSES:
        res.V(rel, f"case Status '{val[:60]}' is not in the closed set "
                   f"{sorted(STATUSES)}")
    # the field must sit under a Case Status section heading
    section = None
    for i in range(idx - 1, -1, -1):
        if overview_masked[i].startswith("## "):
            section = norm_heading(overview_masked[i])
            break
    if section != "case status":
        res.V(rel, "body Status field is not under a '## N. Case Status' section")
    return val


def check_body(masked, text_lines, status, res, rel):
    # pending-work headings and placeholders on Complete cases
    for l in masked:
        if l.startswith("#"):
            if status == "Complete" and norm_heading(l) in PENDING_HEADINGS:
                res.V(rel, f"prohibited pending-work heading on a Complete case: '{l.strip()}'")
    if status == "Complete":
        joined = "\n".join(masked)
        for tok in PENDING_TOKENS:
            if tok.lower() in joined.lower():
                res.V(rel, f"prohibited pending-work placeholder on a Complete case: '{tok}'")
    # redaction: the canonical token is `<REDACTED>` inside inline code.
    # Fenced blocks (already masked) are exempt so indicators stay runnable.
    # Inside inline code spans, any family variant other than the exact
    # canonical token is non-canonical. Outside inline code, every family
    # token is a violation: a bare token is valid HTML tag syntax and
    # GitHub's sanitizer strips it.
    reported = set()
    for l in masked:
        for span in INLINE_CODE_RE.findall(l):
            for m in REDACTION_RE.finditer(span):
                tok = m.group(0)
                if tok != "<REDACTED>" and ("code:" + tok.lower()) not in reported:
                    reported.add("code:" + tok.lower())
                    res.V(rel, f"non-canonical redaction token '{tok}' — "
                               "use `<REDACTED>`")
        outside = INLINE_CODE_RE.sub("", l)
        for m in REDACTION_RE.finditer(outside):
            tok = m.group(0)
            if ("bare:" + tok.lower()) not in reported:
                reported.add("bare:" + tok.lower())
                res.V(rel, f"redaction token '{tok}' outside inline code — "
                           "a bare token is stripped by GitHub's sanitizer; "
                           "use backticked `<REDACTED>`")


def section_bounds(masked, name):
    """(start, end) line span of the H2 section whose normalized title == name."""
    start = None
    for i, l in enumerate(masked):
        if l.startswith("## "):
            if start is not None:
                return start, i
            if norm_heading(l) == name:
                start = i
    if start is not None:
        return start, len(masked)
    return None, None


def check_case_contents(overview_masked, case_dir, res, rel):
    """Required navigation: ## Case Contents linking every case document."""
    start, end = section_bounds(overview_masked, "case contents")
    if start is None:
        res.V(rel, "missing required '## Case Contents' section")
        return
    linked = set()
    for l in overview_masked[start:end]:
        for target in LINK_RE.findall(l):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            t = target.split("#")[0]
            if not t:
                continue
            p = (case_dir / t).resolve()
            try:
                linked.add(p.relative_to(case_dir.resolve()).as_posix())
            except ValueError:
                pass
    expected = {p.relative_to(case_dir).as_posix()
                for p in case_dir.rglob("*.md")} - {"README.md"}
    for missing in sorted(expected - linked):
        res.V(rel, f"Case Contents does not link case document: {missing}")


def check_related_documents(masked, case_docs, res, rel):
    """Required navigation: final report ## Related Documents footer."""
    start, end = section_bounds(masked, "related documents")
    if start is None:
        res.V(rel, "missing required '## Related Documents' footer")
        return
    eor = next((i for i, l in enumerate(masked)
                if l.strip().lower() in ("**end of report**", "end of report")), None)
    if eor is not None and start > eor:
        res.V(rel, "'## Related Documents' footer must precede the "
                   "'**End of Report**' marker")
    linked = set()
    for l in masked[start:end]:
        for target in LINK_RE.findall(l):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            linked.add(target.split("#")[0])
    resolved = set()
    for t in linked:
        # final report lives in reports/, so normalize against that base
        parts = pathlib.PurePosixPath("reports") / t
        try:
            resolved.add(pathlib.PurePosixPath(
                *[p for p in parts.parts]).as_posix())
        except Exception:
            pass
    norm = set()
    for t in resolved:
        pp = []
        for part in pathlib.PurePosixPath(t).parts:
            if part == "..":
                if pp:
                    pp.pop()
            elif part != ".":
                pp.append(part)
        norm.add("/".join(pp))
    if "README.md" not in norm:
        res.V(rel, "Related Documents footer missing link to the case overview")
    categories = {"Timeline": set(), "IOC Collection": set(),
                  "Evidence Inventory": set()}
    for relp, (tier, fields, _, _) in case_docs.items():
        if tier != 3:
            continue
        dt = fields.get("Document Type", "")
        dt = {"Evidence Metadata": "Evidence Inventory",
              "Findings": "Findings Summary"}.get(dt, dt)
        if dt in categories:
            categories[dt].add(relp)
    for label, members in sorted(categories.items()):
        if members and not (members & norm):
            res.V(rel, f"Related Documents footer missing link to the case's "
                       f"{label} ({' or '.join(sorted(members))})")


# Retired Document Types that map unambiguously onto a current profile.
PROFILE_TYPE_MAP = {
    "Evidence Metadata": "Evidence Inventory",
    "Findings": "Findings Summary",
    "Report": "Final Report",
    "Screenshot Index": "Directory Index",
    "Investigation Summary (Root README)": "Case Overview",
}
# Tiers whose profile is implied by document location alone.
TIER_PROFILE = {1: "Case Overview", 2: "Final Report", 4: "Directory Index"}


def profile_type_for(tier, fields):
    """Best-effort profile selection when Document Type is retired or absent.

    Explicit current type wins; unambiguous retired types map to their
    successor; tiers 1, 2 and 4 imply their profile from location. Tier 3
    documents with no usable type get no profile check.
    """
    if tier in TIER_PROFILE:          # location is authoritative for 1, 2, 4
        return TIER_PROFILE[tier]
    dt = fields.get("Document Type", "")
    if dt in PROFILES:
        return dt
    return PROFILE_TYPE_MAP.get(dt, "")


def check_profile(masked, dtype, res, rel, is_overview=False):
    if dtype not in PROFILES:
        return
    heads = [norm_heading(l) for l in masked
             if l.startswith("##")]          # H2 and deeper only, never the H1
    if dtype == "Case Overview":
        h2_raw = [l.lstrip("#").strip() for l in masked if l.startswith("## ")]
        numbered = [h for h in h2_raw if re.match(r"^\d+[.)]", h)]
        if not numbered:
            res.N(rel, "Case Overview profile: no numbered body sections")
        h2_norm = [norm_heading("## " + h) for h in h2_raw]
        if "case status" not in h2_norm:
            res.N(rel, "Case Overview profile: no terminal 'Case Status' section")
        elif h2_norm[-1] != "case status":
            res.N(rel, "Case Overview profile: 'Case Status' section is not terminal")
        return
    for label, keys in PROFILES[dtype]:
        if keys is None:
            continue
        if not any(any(k in h for k in keys) for h in heads):
            res.N(rel, f"{dtype} profile: no section matching '{label}'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not CASES.is_dir():
        sys.exit("error: run from the repository root")

    res = Result()
    checked = 0

    for case in sorted(p for p in CASES.iterdir() if p.is_dir()):
        slug = case.name
        docs = sorted(case.rglob("*.md"))
        parsed = {}

        for p in docs:
            rel = str(p.relative_to(ROOT))
            checked += 1
            try:
                text = p.read_text(encoding="utf-8")
            except Exception as ex:
                res.F(rel, f"cannot read file: {ex}")
                continue
            lines = text.split("\n")
            masked, fence_open = mask_fences(lines)
            if fence_open:
                res.F(rel, "unclosed code fence: structural validation of the "
                           "remainder of the file is unreliable")
                continue
            tier = tier_of(p.relative_to(case).parts)

            state, fields, order, end = parse_metadata(masked, res, rel)
            if state == "FATAL":
                continue
            if state == "ABSENT":
                res.V(rel, "no metadata block found")
                continue

            check_order(order, tier, fields, res, rel)
            check_values(fields, tier, slug, res, rel)
            parsed[p.relative_to(case).as_posix()] = (tier, fields, masked, end)

        overview = parsed.get("README.md")
        if overview is None:
            res.F(f"cyber_range_investigations/{slug}/README.md",
                  "case overview missing or unparsable; "
                  "cross-document validation not possible")
            continue
        ov_tier, ov_fields, ov_masked, ov_end = overview
        ov_rel = f"cyber_range_investigations/{slug}/README.md"

        case_status = case_status_of(ov_masked, ov_fields, ov_end, res, ov_rel)
        if case_status is None:          # fatal ambiguity: skip status-dependent checks
            case_status = ""

        check_case_contents(ov_masked, case, res, ov_rel)

        for relp, (tier, fields, masked, meta_end) in parsed.items():
            rel = f"cyber_range_investigations/{slug}/{relp}"
            for f in CASE_OWNED:
                if f in fields and f in ov_fields and fields[f] != ov_fields[f]:
                    res.V(rel, f"case-owned '{f}' disagrees with case overview "
                               f"({fields[f][:32]!r} vs {ov_fields[f][:32]!r})")
            check_body(masked, None, case_status, res, rel)
            # any body Status field must hold a closed-set value; the overview's
            # is validated by case_status_of, so skip it here
            if relp != "README.md":
                for idx, val in body_status_fields(masked, meta_end):
                    if val not in STATUSES:
                        res.V(rel, f"body Status '{val[:60]}' (line {idx+1}) is "
                                   f"not in the closed set {sorted(STATUSES)}")
            if relp == "reports/final-report.md":
                check_related_documents(masked, parsed, res, rel)
            check_profile(masked, profile_type_for(tier, fields), res, rel,
                          is_overview=(relp == "README.md"))

    if not args.quiet:
        for label, items in (("FATAL", res.fatal), ("VIOLATION", res.viol),
                             ("NOTICE", res.notice)):
            for path, msg in items:
                print(f"  {label:<9} {path}\n            {msg}")
        if res.fatal or res.viol or res.notice:
            print()

    mode = "strict" if args.strict else "advisory"
    print(f"  Schema validation: {checked} files checked")
    print(f"  Fatal errors      : {len(res.fatal)}")
    print(f"  Schema violations : {len(res.viol)}")
    print(f"  Profile notices   : {len(res.notice)}")
    print(f"  Mode              : {mode}")

    if res.fatal:
        sys.exit(1)
    if args.strict and res.viol:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
