# Documentation Schema

**Document Type:** Reference  
**Scope:** All investigation documents under `cyber_range_investigations/`  

This document is the authoritative specification for investigation document
structure in this repository. It governs metadata, document classification,
terminology, and evidence attribution. It does not govern investigative
content: what a case concludes is determined by its evidence, not by this
schema.

> **Standardize structure and terminology, not unsupported content.**
>
> Uniformity does not mean forcing every investigation into identical claims.
> A case without recoverable timestamps still uses the standard timeline
> structure, with explicit limitations. A case without malware artifacts does
> not receive an artifact-analysis section. A case with only network telemetry
> does not claim endpoint evidence. A case with weak ATT&CK support uses fewer
> mappings rather than filling a standard-sized table.

## Migration State

Schema validation currently operates in **advisory mode** during the initial
repository migration. Once all existing investigation documents conform, strict
mode becomes the required repository gate.

Advisory mode must not be used to exempt newly created documents from the
schema. New and modified documents are expected to conform on creation.

```bash
python3 check-schema.py            # advisory: warnings, exit 0
python3 check-schema.py --strict   # gate: violations fail
```

Conformance is checked on every commit. Mechanical conformance corrections
should remain separate from evidence-reconciliation corrections whenever
practical, so that each diff answers a single question.

---

## 1. Document Type Vocabulary

Closed set. A document takes the most specific applicable type; `Analysis` is
the fallback, not the default. A timeline is `Timeline`, an IOC file is
`IOC Collection`.

| Document Type | Intended use |
|---|---|
| `Case Overview` | The primary case-level `README.md` |
| `Case Note` | Scope notes, initial alerts, working context, focused retained notes |
| `Timeline` | Chronological activity and timestamp limitations |
| `Analysis` | Focused technical analysis not covered by a more specific type |
| `Findings Summary` | Consolidated analytical findings |
| `IOC Collection` | Indicators, affected assets, contextual observables |
| `Evidence Inventory` | Evidence sources, provenance, hashes, availability, handling limitations |
| `Final Report` | The principal completed investigation report |
| `Directory Index` | A README explaining the purpose, expected contents, retention policy, or publication limitations of a case subdirectory |
| `Reference` | Supporting reference material that does not make case findings |

### Retired values

| Existing value | Canonical replacement |
|---|---|
| `Investigation Summary` on a case README | `Case Overview` |
| `Investigation Summary (Root README)` | `Case Overview` |
| `Investigation Summary` on a retained note | `Case Note` |
| `Findings` | `Findings Summary` |
| `Report` | `Final Report` |
| `Evidence Metadata` | `Evidence Inventory` |
| `Screenshot Index` | `Directory Index` |

`Investigation Summary (Root README)` is a copy-forward defect and is never
valid.

---

## 2. Metadata Tiers

Fields appear in the order given. Each line ends with two trailing spaces so
the block renders as separate lines.

### Tier 1 — Case Overview (`<case>/README.md`)

```markdown
**Case Title:**
**Case ID:**
**Document Type:** Case Overview
**Status:**
**Documentation Started:**
**Documentation Last Updated:**
**Author:**
**Time Standard:**
**Source Platform:**
```

### Tier 2 — Final Report (`<case>/reports/final-report.md`)

```markdown
**Case Title:**
**Case ID:**
**Document Type:** Final Report
**Documentation Started:**
**Documentation Last Updated:**
**Author:**
**Time Standard:**
**Source Platform:**
```

A report does not carry its own lifecycle status; the case overview owns it.

### Tier 3 — Analytical subdocuments

Timelines, findings, analysis files, IOC collections, evidence inventories,
case notes.

```markdown
**Case ID:**
**Document Type:**
**Time Standard:**
**Source Platform:**
```

Add `Status` only where the document genuinely has an independent lifecycle.
It is not copied mechanically.

### Tier 4 — Directory indexes and placeholders

```markdown
**Case ID:**
**Document Type:** Directory Index
**Source Platform:**
```

Include `Status` only when the directory is intentionally incomplete or
lifecycle-relevant — for example a `reports/` directory whose final report is
not yet written.

### Repository-level documents

`README.md`, `docs/SCHEMA.md`, `CONTRIBUTING.md` and `TEMPLATE_Investigation_Report.md`
are not case documents and are not subject to case metadata tiers.

---

## 3. Field Values

### Case ID

Full directory slug. Bare numbers are not valid.

```markdown
**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration
```

### Status

Closed set: `Complete`, `In Progress`.

- **Complete** — the cyber-range exercise was finished, its final question
  answered, and the portfolio report and supporting documentation finalized.
- **In Progress** — the exercise, analysis, evidence collection, or portfolio
  documentation remains unfinished.

Status describes the state of this repository's documentation, not a formal
closure process within the range platform. A findings statement must never
occupy the status field.

### Time Standard

`UTC`. Qualifying clauses belong in a Limitations section, not the metadata
block.

### Source Platform

Closed set:

- `CyberDefenders CyberRange`
- `Security Blue Team CyberRange`

Module or sub-product detail belongs in the case overview body, not this field.

### Documentation dates

ISO 8601 (`YYYY-MM-DD`). These describe when the portfolio case study was
written. **They are not investigation timestamps.** Where the date of the
underlying range activity was not recorded, it is stated as such rather than
inferred.

---

## 4. Redaction

Single canonical token: `` `<REDACTED>` ``

Always inside backticks — a bare `<REDACTED>` is parsed as an HTML tag and
silently stripped by GitHub's sanitizer.

`<redacted>`, `<sensitive>`, `<not computed>` and similar variants are retired.

Recovered credential material is masked. Password hashes are truncated and
plaintext passwords are redacted. Where password *characteristics* are
analytically relevant they are described rather than reproduced.

---

## 5. Indicator Handling

Indicators are **defanged** in prose, tables and inline references:
`192[.]168[.]1[.]1`, `hxxp://`. Defanging is complete, not partial —
`113[.]26[.]232[.]2`, never `113.26.232[.]2`.

Indicators inside fenced code blocks are left in original form so documented
queries remain runnable. Re-fang deliberately before reuse.

### IOC document sections

An IOC collection distinguishes indicators from context. Not everything
observed is an indicator.

| Section | Contains |
|---|---|
| Malicious Indicators | Attacker-controlled infrastructure, payload hashes, malicious URLs and filenames |
| Affected Assets | Victim hosts, compromised accounts, targeted internal systems |
| Credential-Targeted Services | Legitimate services whose credentials were harvested or targeted |
| Contextual Observables — Not IOCs | Legitimate services used by malware (e.g. external-IP lookup), and capture-specific session details such as ephemeral or passive data ports |

Capture-specific ports are session details, not durable indicators, and are
labelled as such.

---

## 6. Evidence Attribution

Every material claim identifies which category of evidence supports it. These
are not interchangeable and must not be collapsed.

| Category | Meaning |
|---|---|
| **Observed** | Directly evidenced in retained telemetry, logs, captures or extracted artifacts |
| **Range-confirmed** | Established by the CyberRange scenario text or a confirmed question response, not independently observed |
| **External enrichment** | Third-party analysis such as VirusTotal, sandbox output or rule matches |
| **Analyst inference** | Reasoned from the above; explicitly marked as inference |

### Evidence hierarchy

When sources conflict, this is the order of authority:

1. Raw logs, packet excerpts, forensic output, screenshots
2. Contemporaneous analyst notes
3. CyberRange questions and confirmed answers
4. Repository reports and summaries

Conflicts are **documented, not reconciled by plausibility**. Where two
retained values disagree and the original environment is unavailable, neither
is presented as authoritative.

### Correction rule

A correction may not introduce a new factual claim unless that claim is
independently supported by the raw notes or verified repository contents.

---

## 7. Limitations Language

Unavailable evidence is **final, not pending**. Use "not retained", "not
recorded", or "not recoverable from the surviving notes".

Prohibited on a case marked `Complete`:

- `## Next Steps` headings
- `TBD`, `To Be Determined`
- `(Planned)` sections
- "requires further validation"
- "will be updated"
- "not yet completed"

`Interim Conclusion` remains valid in a stage-specific analysis document, where
it means *conclusion at this stage of analysis* rather than *work outstanding*.
It is not valid in a case overview or final report on a `Complete` case.

Work that could still be authored from retained notes — ATT&CK mapping,
detection opportunities, blue-team takeaways — is listed under
**Optional Future Enhancements**, not as unfinished investigation work.

---

## 8. Navigation

- The case overview carries a `## Case Contents` block linking every document
  in the case.
- The final report ends with a `## Related Documents` footer linking the case
  overview, timeline, IOC collection and evidence inventory, where each exists.
- Where an `**End of Report**` marker is used, the footer precedes it.
- Cross-references to repository files are markdown links, not backticked
  paths.
- Relative link targets must match on-disk case exactly; GitHub is
  case-sensitive.

---

## 9. Validator Scope

`check-schema.py` enforces **objective structure only**:

- Required fields by tier, and field order
- Full case slug as `Case ID`
- Closed `Document Type`, `Status`, `Time Standard`, `Source Platform` vocabularies
- No deprecated metadata labels
- Canonical redaction token; no `<redacted>` / `<sensitive>` variants
- No prohibited pending-work headings or placeholders on `Complete` cases
- Required related-document footer where specified

It does **not** validate semantic truth. It cannot determine whether an IP is
malicious, a timeline claim is supported, an ATT&CK mapping is correct, "C2" is
justified, or an observed event proves execution. Those remain manual
evidence-reconciliation tasks.

Broad natural-language detection is deliberately avoided; only the exact
headings and placeholders listed in section 7 are hard failures. Wider phrasing
checks begin as warnings to avoid false positives in historical or limitation
statements.
