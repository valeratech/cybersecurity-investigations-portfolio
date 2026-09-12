# Scripts Directory — Case 004

**Document Type:** Directory Index  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Directory

The `scripts/` directory records the **command and query syntax preserved in
the surviving analyst notes** for Case 004. The syntax itself is preserved;
the surrounding headings and explanatory labels are documentation written for
this repository.

Narrative context and conclusions are documented in `case-notes/` and
`reports/final-report.md`. Analytical logic and filters are documented in
`analysis/`.

## File Index

### `edge-sql-queries.sql`

**Purpose:**  
Records the two Microsoft Edge SQLite statements preserved in the analyst
notes, used to identify:

- Phishing URL access
- Malicious RTF download

**Evidence Sources:**  
Microsoft Edge Chromium databases under:  
`...\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\`

### `mftecmd-command.txt`

**Purpose:**  
Records the exact `MFTECmd` command used to extract NTFS `$MFT` data.

**Used For:**

- File creation and modification timestamps
- Zone.Identifier (Mark-of-the-Web) validation
- Script artifact discovery
- LNK artifact correlation

## Usage Notes

- All timestamps referenced in outputs are treated as **UTC**
- Files in this directory are **non-executable** and safe to store publicly
- Indicators and command strings are **defanged** where applicable

## Reproducibility Statement

Another analyst with access to the same CyberDefenders CyberRange artifacts
should be able to re-run these queries and commands and reach the conclusions
documented in the case notes and final report.
