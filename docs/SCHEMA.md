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
python3 check-schema.py            # advisory: reports warnings, exits 0
python3 check-schema.py --strict   # gate: exits non-zero on any violation
```

Advisory mode exits `0` even with outstanding warnings, so the repository gate
stays green during migration while the remaining debt is reported on every run.

**Fatal in both modes** — the validator cannot proceed reliably:

- file cannot be read or decoded
- metadata block boundaries are ambiguous or overlap body content
- a metadata field line cannot be parsed
- a metadata field is duplicated within one block
- validator internal failure

**Schema violations** — warnings in advisory mode, failures in strict mode:

- missing required field for the document's tier
- fields out of the specified order
- retired field name or retired Document Type value
- value outside a closed set
- `Case ID` not matching the case directory slug
- case-owned value disagreeing with the Case Overview
- non-canonical redaction token
- prohibited pending-work heading or placeholder on a `Complete` case
- missing required navigation block or footer

**Advisory-only notices** — reported in both modes, never affecting exit
status:

- document profile deviations

When migration completes, selected profile rules may be promoted to schema
violations deliberately. Until then `--strict` stays focused on objectively
enforceable schema debt rather than document-shape recommendations.

Advisory validation is invoked by [`verify-audit.sh`](../verify-audit.sh),
so schema drift is
visible on every run of the repository gate. Mechanical conformance
corrections should remain separate from evidence-reconciliation corrections
whenever practical, so that each diff answers a single question.

---

## 1. Document Type Vocabulary

Closed set. A document takes the most specific applicable type; `Analysis` is
the fallback, not the default. A timeline is `Timeline`, an IOC file is
`IOC Collection`.

| Document Type | Intended use |
|---|---|
| `Case Overview` | The primary case-level `<case>/README.md` |
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

### Retired fields

| Existing field | Canonical replacement |
|---|---|
| `Date Completed` | `Documentation Last Updated` |
| `Date` | `Documentation Last Updated` |
| `Date Created` | `Documentation Started` |
| `Last Updated` | `Documentation Last Updated` |
| `Analyst` | `Author` |
| `Case Name` | `Case Title` |
| `Evidence Source` | Move to the document's Evidence Basis or Overview section |

`Evidence Source` is a structural move, not a rename: its values describe
the analytical evidence basis, not the source platform, and must not be
mapped mechanically to `Source Platform` or any other field.

`Investigation Summary (Root README)` is a copy-forward defect and is never
valid.

---

## 2. Metadata Tiers

### Metadata block boundaries

Every case document begins with exactly one level-one heading. Structural
heading detection ignores fenced code blocks.

The metadata block begins at the first metadata field line after the level-one
heading. A field line matches `**Field Name:** value`. Blank lines may appear
before that first field.

After the block begins:

- metadata field lines belong to the block
- blank lines are tolerated for parsing but are schema violations
- the first nonblank line that is neither a metadata field nor a level-two
  heading ends the block
- the first level-two heading also ends the block
- if another metadata field appears after the block has ended but before the
  first level-two heading, the boundaries are ambiguous and validation is fatal

Where a document has no level-two heading, the first nonblank non-field line
ends the metadata block.

The validator must never absorb body content or a later `**Status:**` field
into metadata. Evidence tables, horizontal rules, and introductory notices
placed after the metadata block and before the first level-two heading are
body content and end the block normally.

### Field order

Fields appear in the order given, beginning with `Document Type` so the
document's form is identifiable before its subject. Each line ends with two
trailing spaces so the block renders as separate lines.

Fields not listed for a tier are not added, except for the explicitly
permitted `Status` variants shown below. Fields listed are not omitted.

### Tier 1 — Case Overview (`<case>/README.md`)

```markdown
**Document Type:** Case Overview
**Case Title:**
**Case ID:**
**Documentation Started:**
**Documentation Last Updated:**
**Author:**
**Time Standard:**
**Source Platform:**
```

Case status is recorded in a `## N. Case Status` section rather than the
metadata block — see [Status](#status) below.

### Tier 2 — Final Report (`<case>/reports/final-report.md`)

```markdown
**Document Type:** Final Report
**Case Title:**
**Case ID:**
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
**Document Type:**
**Case ID:**
**Time Standard:**
**Source Platform:**
```

Where the document genuinely has an independent lifecycle, `Status` is
inserted after `Case ID`:

```markdown
**Document Type:**
**Case ID:**
**Status:**
**Time Standard:**
**Source Platform:**
```

`Status` is not copied mechanically into documents that do not own one.

### Tier 4 — Directory indexes and placeholders

```markdown
**Document Type:** Directory Index
**Case ID:**
**Source Platform:**
```

Where the directory is intentionally incomplete or lifecycle-relevant — for
example a `reports/` directory whose final report is not yet written —
`Status` is inserted after `Case ID`:

```markdown
**Document Type:** Directory Index
**Case ID:**
**Status:**
**Source Platform:**
```

### Repository-level documents

The root README, this schema, CONTRIBUTING, and the investigation report
template are repository-level documents and are not subject to case metadata
tiers.

---

## 3. Field Values

### Case ID

Full directory slug. Bare numbers are not valid.

```markdown
**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration
```

### Status

Recorded in a `## N. Case Status` section at the end of the case overview, not
in the metadata block:

```markdown
## 9. Case Status

**Status:** Complete
**Confidence Level:** High
```

Closed set for `Status`: `Complete`, `In Progress`.

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

### Case-owned metadata

The Case Overview is authoritative for `Case Title`, `Documentation Started`,
`Documentation Last Updated`, `Author` and `Source Platform`.

The Final Report's values for these fields must match the Case Overview
exactly. `Source Platform` in all Tier 3 and Tier 4 documents must also match
the Case Overview.

`Case ID` is derived from the case directory slug. `Time Standard` is `UTC`.

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

## 8. Document Profiles

Minimum heading expectations per document type. Profiles describe structure,
not content: a section is included when the case has something to put in it,
and omitted rather than filled with placeholder text. Profile deviations are
advisory during migration.

| Document Type | Expected sections |
|---|---|
| `Case Overview` | `Case Contents`; numbered body sections; terminal `Case Status` |
| `Final Report` | Executive summary; scope and evidence; findings; limitations; `Related Documents` |
| `Timeline` | Evidence basis or overview; timestamped observations; established events without recovered timestamps (where applicable); limitations |
| `Findings Summary` | Per-finding sections carrying evidence and conclusion; consolidated assessment |
| `IOC Collection` | The classification sections in section 5 that apply to the case |
| `Evidence Inventory` | Evidence register table; usage notes; enrichment (where applicable); handling limitations |
| `Directory Index` | Purpose or availability statement; retention or publication limitation |

A case with no recoverable timestamps still uses the Timeline profile, with its
limitations section carrying the explanation. A case with no observed
indicators still uses the IOC Collection profile, with only the sections its
evidence supports.

## 9. Navigation

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

## 10. Validator Scope

[`check-schema.py`](../check-schema.py) enforces **objective structure only**:

- Required fields by tier, and field order
- Full case slug as `Case ID`
- Closed `Document Type`, `Status`, `Time Standard`, `Source Platform` vocabularies
- No deprecated metadata labels
- Canonical redaction token; no `<redacted>` / `<sensitive>` variants
- No prohibited pending-work headings or placeholders on `Complete` cases
- Metadata block boundaries and duplicate-field detection
- Cross-document consistency of case-owned values
- Required `Case Contents` block in the Case Overview
- Required related-document footer where specified
- Document profile conformance (advisory)

Structural checks ignore content inside fenced code blocks. Fenced examples
must not be interpreted as document headings, metadata fields, navigation
sections or prohibited pending-work language. This is separate from indicator
handling, where runnable indicators inside fences deliberately retain their
original form.

It does **not** validate semantic truth. It cannot determine whether an IP is
malicious, a timeline claim is supported, an ATT&CK mapping is correct, "C2" is
justified, or an observed event proves execution. Those remain manual
evidence-reconciliation tasks.

Broad natural-language detection is deliberately avoided; only the exact
headings and placeholders listed in section 7 are hard failures. Wider phrasing
checks begin as warnings to avoid false positives in historical or limitation
statements.
