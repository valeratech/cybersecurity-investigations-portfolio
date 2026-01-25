# Analysis Directory — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless CyberRange explicitly states otherwise)

## Purpose of This Directory

The `analysis/` directory contains **reproducible analytical artifacts** used to derive findings in Case 004.  
Files here prioritize **exact commands, queries, and filters** over narrative explanation.

Narrative context and conclusions are documented in:
- `case-notes/`
- `reports/` (final report)

## File Index

### `edge_sql_queries.sql`
**Purpose:**  
Reproducible SQLite queries used to validate:
- Phishing URL access
- Malicious RTF download
- Correlation between URL visits and downloads

**Evidence Sources:**
- Microsoft Edge Chromium databases under:
...\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\

### `mftecmd-command.txt`
**Purpose:**  
Records the exact `MFTECmd` command used to extract NTFS `$MFT` data.

**Used For:**
- File creation and modification timestamps
- Zone.Identifier (Mark-of-the-Web) validation
- Script and payload discovery
- LNK artifact correlation

### `sysmon-filters.md`
**Purpose:**  
Documents Sysmon event IDs, filters, and investigative logic used to isolate:
- Process execution
- Network connections
- Registry-based persistence
- Startup folder persistence

**Event IDs Referenced:**
- 1 (Process Create)
- 3 (Network Connection)
- 11 (File Create)
- 13 (Registry Value Set)

## Usage Notes

- All timestamps referenced in analysis outputs are treated as **UTC**
- Files in this directory are **non-executable** and **safe to store in a public repository**
- Indicators and command strings are **defanged** where applicable to prevent AV/EDR triggers

## Reproducibility Statement

Another analyst with access to the same CyberDefenders CyberRange artifacts should be able to:
1. Re-run the SQL queries
2. Re-extract NTFS metadata using the documented MFTECmd command
3. Apply the Sysmon filters
4. Reach the same conclusions documented in the case notes and final report

## Status

Analysis artifacts for Case 004 are complete for the current scope.
Additional analysis files will be added here if new evidence is introduced.
