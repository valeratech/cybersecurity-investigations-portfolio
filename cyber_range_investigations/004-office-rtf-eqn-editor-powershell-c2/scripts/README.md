# Scripts Directory — Case 004

**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless CyberRange explicitly states otherwise)  

## Purpose of This Directory

The `scripts/` directory contains **reproducible commands and queries** used to
derive findings in Case 004. Files here prioritize **exact syntax** over
narrative explanation.

Narrative context and conclusions are documented in `case-notes/` and
`reports/final-report.md`. Analytical logic and filters are documented in
`analysis/`.

## File Index

### `edge-sql-queries.sql`

**Purpose:**  
Reproducible SQLite queries used to validate:

- Phishing URL access
- Malicious RTF download
- Correlation between URL visits and downloads

**Evidence Sources:**  
Microsoft Edge Chromium databases under:  
`...\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\`

### `mftecmd-command.txt`

**Purpose:**  
Records the exact `MFTECmd` command used to extract NTFS `$MFT` data.

**Used For:**

- File creation and modification timestamps
- Zone.Identifier (Mark-of-the-Web) validation
- Script and payload discovery
- LNK artifact correlation

## Usage Notes

- All timestamps referenced in outputs are treated as **UTC**
- Files in this directory are **non-executable** and safe to store publicly
- Indicators and command strings are **defanged** where applicable

## Reproducibility Statement

Another analyst with access to the same CyberDefenders CyberRange artifacts
should be able to re-run these queries and commands and reach the conclusions
documented in the case notes and final report.
